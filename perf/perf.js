'use strict';
// Performance harness: real Chromium, 6x CPU throttle, simulated portal page.
// Usage: node perf/perf.js <beacon.js> [label] [iterations]
const http = require('http');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BEACON_FILE = process.argv[2];
const LABEL = process.argv[3] || path.basename(BEACON_FILE);
const N = +(process.argv[4] || 12);
const CPU = 6;
const OUT = process.env.BB_OUT || path.join(__dirname, '..', 'out');
fs.mkdirSync(OUT, { recursive: true });

const beaconSrc = fs.readFileSync(BEACON_FILE, 'utf8').replace('allowPageOverride: false,', 'allowPageOverride: true,');
const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
// ~150 KB "portal app": filler functions plus ~40 ms of busy work at execution.
const appJs = (() => {
  let s = '(function(){var t=performance.now();while(performance.now()-t<40){}\n';
  for (let i = 0; i < 1500; i++) { s += `function f${i}(a,b){var x=a*${i}+b;for(var j=0;j<3;j++){x=(x*31+j)%1000003}return x}\n`; }
  return s + 'window.__app=1;})();';
})();
const rows = Array.from({ length: 300 }, (_, i) => `<tr><td>Item ${i}</td><td>Owner ${i % 17}</td><td>${(i * 7) % 100}%</td><td><a href="#">open</a></td></tr>`).join('');

function page(mode) {
  const cfg = {
    scope: { include: ['127.0.0.0/8'], sources: [{ type: 'url', url: '/bb-ip' }, { type: 'webrtc' }], cacheMinutes: 60 },
    transport: { mode: 'pixel', endpoint: '/browser-beacon.gif' }
  };
  const tag = mode === 'none' ? '' :
    `<script>window.BrowserBeaconConfig=${JSON.stringify(cfg)};</script><script src="/b.js" ${mode}></script>`;
  return `<!doctype html><html><head><meta charset="utf-8"><title>Portal</title>
<style>body{font:14px sans-serif;margin:0}header{background:#123;color:#fff;padding:16px}td{padding:4px 8px;border-bottom:1px solid #ddd}</style>
${tag}<script src="/app.js" defer></script></head>
<body><header><h1>Company Portal</h1></header><main><img src="/img.gif" width="1" height="1" alt=""><table>${rows}</table></main></body></html>`;
}

function server() {
  return new Promise((resolve) => {
    const state = { beacons: 0, scriptRequests: [] };
    const s = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const send = (code, type, body, extra) => { res.writeHead(code, Object.assign({ 'Content-Type': type, 'Cache-Control': 'no-cache' }, extra || {})); res.end(body); };
      if (u.pathname === '/') { return send(200, 'text/html; charset=utf-8', page(u.searchParams.get('mode') || 'none')); }
      if (u.pathname === '/other') { return send(200, 'text/html; charset=utf-8', '<!doctype html><title>other</title><p>other</p>'); }
      if (u.pathname === '/b.js') { return send(200, 'text/javascript; charset=utf-8', beaconSrc); }
      if (u.pathname === '/app.js') { return send(200, 'text/javascript; charset=utf-8', appJs); }
      if (u.pathname === '/img.gif') { return setTimeout(() => send(200, 'image/gif', GIF), 150); } // a slow-ish asset
      if (u.pathname === '/bb-ip') { return send(200, 'text/plain', req.socket.remoteAddress); }
      if (u.pathname === '/browser-beacon.gif') { state.beacons++; return send(200, 'image/gif', GIF); }
      send(404, 'text/plain', '');
    });
    s.listen(0, '127.0.0.1', () => resolve({ s, state, base: 'http://127.0.0.1:' + s.address().port }));
  });
}

const median = (a) => { const b = a.slice().sort((x, y) => x - y); return b.length ? b[Math.floor(b.length / 2)] : NaN; };
const p90 = (a) => { const b = a.slice().sort((x, y) => x - y); return b.length ? b[Math.min(b.length - 1, Math.floor(b.length * 0.9))] : NaN; };

async function newPage(browser) {
  const ctx = await browser.newContext();
  const pg = await ctx.newPage();
  const cdp = await ctx.newCDPSession(pg);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: CPU });
  await pg.addInitScript(() => {
    window.__lt = [];
    try { new PerformanceObserver((l) => { for (const e of l.getEntries()) { window.__lt.push({ start: e.startTime, dur: e.duration }); } }).observe({ type: 'longtask', buffered: true }); } catch (e) {}
  });
  return { ctx, pg, cdp };
}

async function navMetrics(pg) {
  return pg.evaluate(() => {
    const n = performance.getEntriesByType('navigation')[0];
    const fcp = performance.getEntriesByName('first-contentful-paint')[0];
    return { dcl: n.domContentLoadedEventEnd, load: n.loadEventEnd, fcp: fcp ? fcp.startTime : NaN, lt: window.__lt.slice() };
  });
}

async function waitFor(fn, ms) { const end = Date.now() + ms; while (Date.now() < end) { if (await fn()) { return true; } await new Promise((r) => setTimeout(r, 50)); } return false; }

// Attribute main-thread work to b.js from a Chrome trace.
function analyzeTrace(file, loadTs) {
  const ev = JSON.parse(fs.readFileSync(file, 'utf8')).traceEvents || [];
  let mainTid = null, mainPid = null;
  for (const e of ev) { if (e.ph === 'M' && e.name === 'thread_name' && e.args && e.args.name === 'CrRendererMain') { mainTid = e.tid; mainPid = e.pid; } }
  const main = ev.filter((e) => e.tid === mainTid && e.pid === mainPid && e.ph === 'X' && typeof e.dur === 'number');
  const isOurs = (e) => { const d = e.args && (e.args.data || e.args); const url = d && (d.url || (d.stackTrace && d.stackTrace[0] && d.stackTrace[0].url)); return url && /\/b\.js$/.test(url); };
  const ours = main.filter((e) => ['EvaluateScript', 'v8.compile', 'FunctionCall', 'v8.run', 'V8.CompileCode'].includes(e.name) && isOurs(e));
  const tasks = main.filter((e) => e.name === 'RunTask' || e.name === 'ThreadControllerImpl::RunTask');
  const touched = new Set();
  const nav = ev.find((e) => e.name === 'navigationStart' && e.pid === mainPid);
  const t0 = nav ? nav.ts : 0;
  let pre = 0, post = 0;
  const evals = ours.filter((e) => e.name === 'EvaluateScript');
  for (const e of ours) {
    for (const t of tasks) { if (e.ts >= t.ts && e.ts + e.dur <= t.ts + t.dur) { touched.add(t); break; } }
  }
  // top-level our events only (not nested inside another of ours)
  const top = ours.filter((e) => !ours.some((o) => o !== e && o.ts <= e.ts && o.ts + o.dur >= e.ts + e.dur && o.dur > e.dur));
  for (const e of top) { const ms = e.dur / 1000; if ((e.ts - t0) / 1000 < loadTs) { pre += ms; } else { post += ms; } }
  const taskDurs = [...touched].map((t) => t.dur / 1000);
  return {
    evaluateMs: evals.reduce((s, e) => s + e.dur / 1000, 0),
    preLoadMs: pre, postLoadMs: post,
    longestTaskWithBeaconMs: taskDurs.length ? Math.max(...taskDurs) : 0,
    tasksTouched: taskDurs.length
  };
}

(async () => {
  const srv = await server();
  const browser = await chromium.launch();
  const result = { label: LABEL, cpuThrottle: CPU, iterations: N, load: {}, trace: {}, network: {}, bfcache: {}, errors: [] };

  // 1) Page-load impact: none vs defer vs async, cold context each time, interleaved.
  const modes = ['none', 'defer', 'async'];
  const acc = {}; modes.forEach((m) => { acc[m] = { dcl: [], load: [], fcp: [], ltDuringLoad: [] }; });
  for (let i = 0; i < N; i++) {
    for (const m of modes) {
      const { ctx, pg } = await newPage(browser);
      await pg.goto(srv.base + '/?mode=' + m, { waitUntil: 'load' });
      const x = await navMetrics(pg);
      acc[m].dcl.push(x.dcl); acc[m].load.push(x.load); acc[m].fcp.push(x.fcp);
      acc[m].ltDuringLoad.push(x.lt.filter((t) => t.start < x.load).reduce((s, t) => s + Math.max(0, t.dur - 50), 0));
      await ctx.close();
    }
  }
  for (const m of modes) {
    result.load[m] = { dclMedian: +median(acc[m].dcl).toFixed(1), loadMedian: +median(acc[m].load).toFixed(1), fcpMedian: +median(acc[m].fcp).toFixed(1),
      dclP90: +p90(acc[m].dcl).toFixed(1), loadP90: +p90(acc[m].load).toFixed(1), blockingDuringLoadMedian: +median(acc[m].ltDuringLoad).toFixed(1) };
  }

  // 2) Main-thread attribution via trace: first visit (full run) and repeat visit (throttled).
  for (const visit of ['first', 'repeat']) {
    const runs = [];
    for (let i = 0; i < 3; i++) {
      const { ctx, pg } = await newPage(browser);
      if (visit === 'repeat') { // warm: complete one full run first
        srv.state.beacons = 0;
        await pg.goto(srv.base + '/?mode=async', { waitUntil: 'load' });
        await waitFor(async () => srv.state.beacons > 0, 15000);
        await pg.waitForTimeout(500);
      }
      srv.state.beacons = 0;
      const tf = path.join(OUT, `trace-${LABEL}-${visit}-${i}.json`);
      await browser.startTracing(pg, { path: tf, categories: ['devtools.timeline', 'disabled-by-default-devtools.timeline', 'v8', 'blink.user_timing', 'toplevel', 'disabled-by-default-v8.compile'] });
      const errs = [];
      pg.on('pageerror', (e) => errs.push(e.message));
      await pg.goto(srv.base + '/?mode=async', { waitUntil: 'load' });
      const nm = await navMetrics(pg);
      if (visit === 'first') { await waitFor(async () => srv.state.beacons > 0, 15000); } else { await pg.waitForTimeout(4500); }
      await pg.waitForTimeout(1500);
      const lt = await pg.evaluate(() => window.__lt.slice());
      await browser.stopTracing();
      const a = analyzeTrace(tf, nm.load);
      a.beaconsSent = srv.state.beacons; a.longTasksAfterLoad = lt.filter((t) => t.start >= nm.load).map((t) => +t.dur.toFixed(1));
      runs.push(a); result.errors.push(...errs);
      fs.unlinkSync(tf);
      await ctx.close();
    }
    const pick = (k) => +median(runs.map((r) => r[k])).toFixed(2);
    result.trace[visit] = { evaluateMs: pick('evaluateMs'), preLoadMs: pick('preLoadMs'), postLoadMs: pick('postLoadMs'),
      longestTaskWithBeaconMs: pick('longestTaskWithBeaconMs'), beaconsSent: runs.map((r) => r.beaconsSent), longTasksAfterLoad: runs.map((r) => r.longTasksAfterLoad) };
  }

  // 3) Network: requests made by the beacon on a first visit, with priority.
  {
    const { ctx, pg, cdp } = await newPage(browser);
    await cdp.send('Network.enable');
    const reqs = [];
    cdp.on('Network.requestWillBeSent', (e) => { reqs.push({ url: e.request.url.replace(srv.base, ''), prio: e.request.initialPriority, type: e.type, t: e.timestamp }); });
    srv.state.beacons = 0;
    await pg.goto(srv.base + '/?mode=async', { waitUntil: 'load' });
    const loadAt = await pg.evaluate(() => performance.getEntriesByType('navigation')[0].loadEventEnd);
    await waitFor(async () => srv.state.beacons > 0, 15000);
    await pg.waitForTimeout(800);
    result.network.firstVisit = reqs.filter((r) => /\/(b\.js|bb-ip|browser-beacon\.gif)/.test(r.url)).map((r) => ({ path: r.url.split('?')[0], priority: r.prio, type: r.type }));
    result.network.loadEventMs = +loadAt.toFixed(0);
    reqs.length = 0;
    await pg.reload({ waitUntil: 'load' });
    await pg.waitForTimeout(5000);
    result.network.repeatVisit = reqs.filter((r) => /\/(b\.js|bb-ip|browser-beacon\.gif)/.test(r.url)).map((r) => r.url.split('?')[0]);
    await ctx.close();
  }

  // 4) Back/forward cache eligibility after the beacon has run.
  for (const m of ['none', 'async']) {
    const { ctx, pg, cdp } = await newPage(browser);
    await cdp.send('Page.enable');
    let notUsed = null;
    cdp.on('Page.backForwardCacheNotUsed', (e) => { notUsed = (e.notRestoredExplanations || []).map((x) => x.reason); });
    srv.state.beacons = 0;
    await pg.goto(srv.base + '/?mode=' + m, { waitUntil: 'load' });
    if (m !== 'none') { await waitFor(async () => srv.state.beacons > 0, 15000); }
    await pg.waitForTimeout(1000);
    await pg.goto(srv.base + '/other', { waitUntil: 'load' });
    await pg.goBack({ waitUntil: 'load' });
    const restored = await pg.evaluate(() => performance.getEntriesByType('navigation')[0].type);
    result.bfcache[m] = { navigationType: restored, notRestoredReasons: notUsed };
    await ctx.close();
  }

  await browser.close(); srv.s.close();
  fs.writeFileSync(path.join(OUT, `perf-${LABEL}.json`), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
})().catch((e) => { console.error(e); process.exit(1); });

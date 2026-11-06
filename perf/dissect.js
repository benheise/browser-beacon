'use strict';
// Dissect the longest beacon-attributed tasks on a first visit (6x CPU), plus a CPU profile by function.
const http = require('http');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const FILE = process.argv[2];
const OUT = process.env.BB_OUT || path.join(__dirname, '..', 'out');
fs.mkdirSync(OUT, { recursive: true });
const src = fs.readFileSync(FILE, 'utf8').replace('allowPageOverride: false,', 'allowPageOverride: true,');
const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
const cfg = { scope: { include: ['127.0.0.0/8'], sources: [{ type: 'url', url: '/bb-ip' }, { type: 'webrtc' }] }, transport: { mode: 'pixel', endpoint: '/browser-beacon.gif' } };
let beacons = 0;
const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(`<!doctype html><meta charset=utf-8><script>window.BrowserBeaconConfig=${JSON.stringify(cfg)}</script><script async src="/b.js"></script><p>x</p>`); }
  if (u.pathname === '/b.js') { res.writeHead(200, { 'Content-Type': 'text/javascript' }); return res.end(src); }
  if (u.pathname === '/bb-ip') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(req.socket.remoteAddress); }
  if (u.pathname === '/browser-beacon.gif') { beacons++; res.writeHead(200, { 'Content-Type': 'image/gif' }); return res.end(GIF); }
  res.writeHead(404); res.end();
});

(async () => {
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  const pg = await ctx.newPage();
  const cdp = await ctx.newCDPSession(pg);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: 6 });
  await cdp.send('Profiler.enable');
  await cdp.send('Profiler.setSamplingInterval', { interval: 100 });
  const tf = path.join(OUT, 'dissect-trace.json');
  await browser.startTracing(pg, { path: tf, categories: ['devtools.timeline', 'disabled-by-default-devtools.timeline', 'v8', 'toplevel', 'disabled-by-default-v8.compile', 'webrtc'] });
  await cdp.send('Profiler.start');
  await pg.goto(base + '/', { waitUntil: 'load' });
  const end = Date.now() + 15000;
  while (!beacons && Date.now() < end) { await new Promise((r) => setTimeout(r, 50)); }
  await pg.waitForTimeout(1500);
  const { profile } = await cdp.send('Profiler.stop');
  await browser.stopTracing();

  // CPU profile: self time by function for b.js
  const byId = new Map(profile.nodes.map((n) => [n.id, n]));
  const self = new Map();
  const dt = profile.timeDeltas;
  for (let i = 0; i < profile.samples.length; i++) {
    const n = byId.get(profile.samples[i]);
    const cf = n.callFrame;
    const key = (cf.url.endsWith('/b.js') ? 'b.js:' : (cf.url ? path.basename(cf.url) + ':' : '')) + (cf.functionName || '(anon)') + (cf.url.endsWith('/b.js') ? ':' + (cf.lineNumber + 1) : '');
    self.set(key, (self.get(key) || 0) + (dt[i] || 0) / 1000);
  }
  // inclusive time for b.js top functions
  const children = new Map(profile.nodes.map((n) => [n.id, n.children || []]));
  const selfById = new Map();
  for (let i = 0; i < profile.samples.length; i++) { selfById.set(profile.samples[i], (selfById.get(profile.samples[i]) || 0) + (dt[i] || 0) / 1000); }
  const incl = (id) => (selfById.get(id) || 0) + children.get(id).reduce((s, c) => s + incl(c), 0);
  const inclByFn = new Map();
  for (const n of profile.nodes) {
    if (!n.callFrame.url.endsWith('/b.js')) { continue; }
    const k = (n.callFrame.functionName || '(anon)') + ':' + (n.callFrame.lineNumber + 1);
    inclByFn.set(k, Math.max(inclByFn.get(k) || 0, incl(n.id)));
  }
  const top = (m, k) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, k).map(([n, v]) => `${v.toFixed(1).padStart(7)} ms  ${n}`);
  console.log('--- CPU profile: top self time (all) ---'); console.log(top(self, 18).join('\n'));
  console.log('--- CPU profile: top inclusive time (b.js functions) ---'); console.log(top(inclByFn, 25).join('\n'));

  // Trace: children of the longest tasks touching b.js
  const ev = JSON.parse(fs.readFileSync(tf, 'utf8')).traceEvents;
  let tid, pid; for (const e of ev) { if (e.ph === 'M' && e.name === 'thread_name' && e.args.name === 'CrRendererMain') { tid = e.tid; pid = e.pid; } }
  const main = ev.filter((e) => e.tid === tid && e.pid === pid && e.ph === 'X' && e.dur);
  const tasks = main.filter((e) => e.name === 'RunTask' || e.name === 'ThreadControllerImpl::RunTask').sort((a, b) => b.dur - a.dur).slice(0, 4);
  for (const t of tasks) {
    const kids = main.filter((e) => e !== t && e.ts >= t.ts && e.ts + e.dur <= t.ts + t.dur && e.dur > 1500);
    console.log(`--- task ${(t.dur / 1000).toFixed(1)} ms ---`);
    for (const k of kids.sort((a, b) => a.ts - b.ts).slice(0, 25)) {
      const d = (k.args && (k.args.data || k.args)) || {};
      console.log(`  +${((k.ts - t.ts) / 1000).toFixed(1).padStart(6)}  ${(k.dur / 1000).toFixed(1).padStart(6)} ms  ${k.name} ${d.functionName || ''} ${d.url ? path.basename(d.url) : ''}${d.lineNumber !== undefined ? ':' + (d.lineNumber + 1) : ''}`);
    }
  }
  fs.unlinkSync(tf);
  await browser.close(); srv.close();
})().catch((e) => { console.error(e); process.exit(1); });

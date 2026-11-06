'use strict';
// Real Chromium (Playwright) end-to-end: real UA Client Hints, real XHR echo, real image beacon, real WebRTC.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');
const { raw, testScript } = require('./helpers');

const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
const OUT = process.env.BB_OUT || path.join(__dirname, '..', 'out');
fs.mkdirSync(OUT, { recursive: true });

function startServer() {
  return new Promise((resolve) => {
    const beacons = [];
    let pageCfg = {}, script = testScript;
    const s = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      if (u.pathname === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(`<!doctype html><html><head><title>Portal</title>
<script>window.BrowserBeaconConfig = ${JSON.stringify(pageCfg)};</script>
<script src="/browser-beacon.js" defer></script></head>
<body style="font:16px sans-serif;padding:24px"><h1>Company Portal</h1><p>Test page.</p></body></html>`);
      }
      if (u.pathname === '/browser-beacon.js') { res.writeHead(200, { 'Content-Type': 'text/javascript' }); return res.end(script); }
      if (u.pathname === '/bb-ip') { res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }); return res.end(req.socket.remoteAddress); }
      if (u.pathname === '/bb-ip.txt') { res.writeHead(200, { 'X-Client-IP': req.socket.remoteAddress, 'Access-Control-Expose-Headers': 'X-Client-IP' }); return res.end('ok'); }
      if (u.pathname === '/browser-beacon.gif') {
        beacons.push({ q: Object.fromEntries(u.searchParams), referer: req.headers.referer || null, ua: req.headers['user-agent'], len: req.url.length, ip: req.socket.remoteAddress });
        res.writeHead(200, { 'Content-Type': 'image/gif', 'Cache-Control': 'no-store' });
        return res.end(GIF);
      }
      res.writeHead(404); res.end();
    });
    s.listen(0, '127.0.0.1', () => resolve({
      s, beacons, base: 'http://127.0.0.1:' + s.address().port,
      set(cfg, src) { pageCfg = cfg; script = src || testScript; }
    }));
  });
}

const BASE = (extra) => Object.assign({
  autoRun: true,
  scope: { include: ['127.0.0.0/8'], sources: [{ type: 'url', url: '/bb-ip' }], cacheMinutes: 0 },
  report: { startDelayMs: 0 },
  transport: { mode: 'pixel', endpoint: '/browser-beacon.gif' }
}, extra || {});

async function waitFor(fn, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (fn()) { return true; } await new Promise((r) => setTimeout(r, 50)); }
  return false;
}

let browser, srv;
test.before(async () => { browser = await chromium.launch(); srv = await startServer(); });
test.after(async () => { await browser.close(); srv.s.close(); });

async function visit(cfg, opts) {
  opts = opts || {};
  srv.beacons.length = 0;
  srv.set(cfg, opts.script);
  const ctx = await (opts.browser || browser).newContext(opts.ctx || {});
  const page = await ctx.newPage();
  const consoleMsgs = [];
  page.on('console', (m) => consoleMsgs.push(m.type() + ': ' + m.text()));
  page.on('pageerror', (e) => consoleMsgs.push('pageerror: ' + e.message));
  await page.goto(srv.base + '/');
  return { ctx, page, consoleMsgs };
}

test('unmodified file stays off and says why (fail closed)', async () => {
  const v = await visit({}, { script: raw });
  await new Promise((r) => setTimeout(r, 3500)); // validation now runs after load + startDelayMs
  assert.equal(srv.beacons.length, 0);
  assert.ok(v.consoleMsgs.some((m) => /disabled by configuration errors/.test(m) && /scope\.include is empty/.test(m)), v.consoleMsgs.join('\n'));
  await v.ctx.close();
});

test('in scope via URL echo: one beacon with full Client Hints version, no Referer', async () => {
  const v = await visit(BASE());
  assert.ok(await waitFor(() => srv.beacons.length >= 1, 5000), 'beacon received');
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(srv.beacons.length, 1);
  const b = srv.beacons[0], q = b.q;
  const realVersion = browser.version();
  fs.writeFileSync(path.join(OUT, 'beacon-in-scope.json'), JSON.stringify(b, null, 2));
  assert.equal(q.scope, 'in'); assert.equal(q.ip, '127.0.0.1'); assert.equal(q.ipsrc, 'url');
  assert.equal(q.bvs, 'uach'); assert.equal(q.bvp, 'full');
  assert.match(q.cv, /^\d+\.\d+\.\d+\.\d+$/);
  assert.equal(q.cv, realVersion, 'Chromium version from Client Hints matches the real browser');
  assert.equal(q.os, 'Linux');
  assert.ok(['current', 'outdated'].includes(q.vrd));
  assert.equal(q.ua, undefined, 'raw UA left to the access log');
  assert.equal(b.referer, null, 'no Referer header on beacon');
  assert.match(q.did, /^[0-9a-f-]{36}$/);
  assert.ok(b.len < 2000);
  const errors = v.consoleMsgs.filter((m) => /^(error|pageerror)/.test(m));
  assert.deepEqual(errors, []);
  // throttle: reload does not send again
  await v.page.reload();
  await new Promise((r) => setTimeout(r, 1200));
  assert.equal(srv.beacons.length, 1, 'reload throttled');
  // preview from the console API
  const pv = await v.page.evaluate(() => new Promise((res) => window.BrowserBeacon.preview((rec, st) => res({ rec, st }))));
  assert.equal(pv.st, 'dry-run');
  assert.equal(pv.rec.cv, realVersion);
  await v.ctx.close();
});

test('header echo source works', async () => {
  const v = await visit(BASE({ scope: { include: ['127.0.0.0/8'], sources: [{ type: 'url', url: '/bb-ip.txt', header: 'X-Client-IP' }], cacheMinutes: 0 } }));
  assert.ok(await waitFor(() => srv.beacons.length >= 1, 5000));
  assert.equal(srv.beacons[0].q.ip, '127.0.0.1');
  await v.ctx.close();
});

test('out of scope: no beacon, nothing stored', async () => {
  const v = await visit(BASE({ scope: { include: ['10.0.0.0/8'], sources: [{ type: 'url', url: '/bb-ip' }], cacheMinutes: 0 } }));
  await new Promise((r) => setTimeout(r, 2000));
  assert.equal(srv.beacons.length, 0);
  const did = await v.page.evaluate(() => localStorage.getItem('bb_did'));
  assert.equal(did, null);
  const pv = await v.page.evaluate(() => new Promise((res) => window.BrowserBeacon.preview((rec, st) => res(st))));
  assert.equal(pv, 'dry-run-scope-out');
  await v.ctx.close();
});

test('WebRTC: hidden by default (mDNS), real local IPs when exposed', async () => {
  // Default browser: host candidates are *.local, so no IP -> scope unknown -> skip.
  const v1 = await visit(BASE({ scope: { include: ['0.0.0.1/32'], sources: [{ type: 'webrtc' }], cacheMinutes: 0 } }));
  await new Promise((r) => setTimeout(r, 2500));
  assert.equal(srv.beacons.length, 0);
  const st1 = await v1.page.evaluate(() => new Promise((res) => window.BrowserBeacon.preview((rec, st) => res({ st, lip: rec.lip }))));
  assert.equal(st1.st, 'dry-run-scope-unknown');
  await v1.ctx.close();

  // Simulates a managed browser whose policy exposes local IPs to this origin.
  const ifaces = Object.values(os.networkInterfaces()).flat().filter((i) => i.family === 'IPv4' && !i.internal);
  if (!ifaces.length) { return; }
  const ip = ifaces[0].address;
  const exposed = await chromium.launch({ args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] });
  try {
    const v2 = await visit(BASE({ scope: { include: [ip + '/32'], sources: [{ type: 'webrtc' }], cacheMinutes: 0 } }), { browser: exposed });
    assert.ok(await waitFor(() => srv.beacons.length >= 1, 6000), 'beacon via WebRTC scope');
    const q = srv.beacons[0].q;
    assert.equal(q.ipsrc, 'webrtc'); assert.equal(q.ip, ip);
    assert.ok(q.lip.split(',').includes(ip), 'lip=' + q.lip);
    await v2.ctx.close();
  } finally { await exposed.close(); }
});

test('User-Agent override is flagged against Client Hints', async () => {
  const ff = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0';
  const v = await visit(BASE(), { ctx: { userAgent: ff } });
  const pv = await v.page.evaluate(() => new Promise((res) => window.BrowserBeacon.preview((rec, st) => res(rec))));
  fs.writeFileSync(path.join(OUT, 'beacon-ua-override.json'), JSON.stringify(pv, null, 2));
  // Either Client Hints survive the override (spoof=1) or they are suppressed (judged on the UA string).
  assert.ok(pv.spoof === '1' || (pv.bk === 'firefox' && pv.bvs === 'ua'), JSON.stringify(pv));
  await v.ctx.close();
});

test('notice banner for an outdated browser', async () => {
  const v = await visit(BASE({
    policy: { browsers: { chromium: [{ channel: 'engine', minimum: '999' }] } },
    notice: { enabled: true, linkText: 'How to update', linkUrl: '/help/browser' }
  }));
  assert.ok(await waitFor(() => srv.beacons.length >= 1, 5000));
  assert.equal(srv.beacons[0].q.vrd, 'outdated');
  await v.page.waitForSelector('[data-browser-beacon="notice"]', { timeout: 3000 });
  await v.page.setViewportSize({ width: 900, height: 360 });
  await v.page.screenshot({ path: path.join(OUT, 'notice.png') });
  const text = await v.page.textContent('[data-browser-beacon="notice"]');
  assert.match(text, /out of date/);
  await v.ctx.close();
});

/* ---------------- v1.2: receiving HTTP server, local log ---------------- */
function receiver(opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const hits = [];
    const s = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        hits.push({ method: req.method, path: req.url, headers: req.headers, body });
        const cors = opts.cors ? { 'Access-Control-Allow-Origin': opts.cors, 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'Content-Type, X-Portal', 'Access-Control-Allow-Credentials': 'true' } : {};
        if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
        res.writeHead(opts.status || 204, cors); res.end();
      });
    });
    s.listen(0, '127.0.0.1', () => resolve({ s, hits, url: 'http://127.0.0.1:' + s.address().port + '/browser-beacon' }));
  });
}

test('http destination: cross-origin receiver with CORS gets JSON (preflight, keepalive, no Referer); pixel + local in parallel', async () => {
  const rx = await receiver({ cors: srv.base });
  try {
    const v = await visit(BASE({ destinations: [
      { type: 'pixel', url: '/browser-beacon.gif' },
      { type: 'http', url: rx.url, format: 'json', credentials: 'include', headers: { 'X-Portal': 'hr' } },
      { type: 'local' }
    ] }));
    assert.ok(await waitFor(() => rx.hits.some((h) => h.method === 'POST') && srv.beacons.length >= 1, 6000), 'both destinations received');
    const pre = rx.hits.find((h) => h.method === 'OPTIONS'), post = rx.hits.find((h) => h.method === 'POST');
    assert.ok(pre, 'preflight sent for application/json + custom header');
    assert.equal(post.headers.origin, srv.base);
    assert.match(post.headers['content-type'], /^application\/json/);
    assert.equal(post.headers['x-portal'], 'hr');
    assert.equal(post.headers.referer, undefined, 'no Referer');
    const rec = JSON.parse(post.body);
    assert.equal(rec.scope, 'in'); assert.equal(rec.bvs, 'uach'); assert.ok(rec.ua, 'raw UA included in http body');
    assert.equal(srv.beacons[0].q.ua, undefined, 'raw UA still left out of the pixel');
    await v.page.waitForFunction(() => window.BrowserBeacon.log().length === 1, null, { timeout: 3000 });
    const log = await v.page.evaluate(() => window.BrowserBeacon.log());
    assert.equal(log[0]._to, 'pixel#1:ok,http#2:ok'); assert.equal(log[0]._delivered, 1);
    // save the local log as a file
    const [dl] = await Promise.all([v.page.waitForEvent('download'), v.page.evaluate(() => window.BrowserBeacon.downloadLog())]);
    assert.match(dl.suggestedFilename(), /^browser-beacon-127\.0\.0\.1-\d{8}T\d{6}\.jsonl$/);
    const file = path.join(OUT, dl.suggestedFilename());
    await dl.saveAs(file);
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(lines.length, 1); assert.equal(lines[0].rid, rec.rid);
    await v.ctx.close();
  } finally { rx.s.close(); }
});

test('http destination: noCors fire-and-forget reaches a receiver without CORS headers', async () => {
  const rx = await receiver({});
  try {
    const v = await visit(BASE({ destinations: [{ type: 'http', url: rx.url, format: 'text', noCors: true }] }));
    assert.ok(await waitFor(() => rx.hits.some((h) => h.method === 'POST'), 6000));
    assert.equal(rx.hits.filter((h) => h.method === 'OPTIONS').length, 0, 'simple request: no preflight');
    const post = rx.hits.find((h) => h.method === 'POST');
    assert.match(post.headers['content-type'], /^text\/plain/);
    assert.equal(JSON.parse(post.body).scope, 'in');
    const last = await v.page.evaluate(() => JSON.parse(localStorage.getItem('bb_last')));
    assert.equal(last.n, undefined, 'counted as delivered');
    await v.ctx.close();
  } finally { rx.s.close(); }
});

test('http destination: receiver down or without CORS counts as failed and backs off', async () => {
  const rx = await receiver({}); // no CORS headers: browser hides the reply, so delivery cannot be confirmed
  try {
    const v = await visit(BASE({ destinations: [{ type: 'http', url: rx.url, format: 'json' }, { type: 'local' }] }));
    await v.page.waitForFunction(() => { const l = JSON.parse(localStorage.getItem('bb_last') || 'null'); return l && l.n === 1; }, null, { timeout: 8000 });
    const log = await v.page.evaluate(() => window.BrowserBeacon.log());
    assert.equal(log[0]._delivered, 0); assert.equal(log[0]._to, 'http#1:fail');
    await v.ctx.close();
  } finally { rx.s.close(); }
  const closedPort = rx.url; // server now closed: connection refused
  const v2 = await visit(BASE({ destinations: [{ type: 'http', url: closedPort, format: 'text' }] }));
  await v2.page.waitForFunction(() => { const l = JSON.parse(localStorage.getItem('bb_last') || 'null'); return l && l.n === 1; }, null, { timeout: 8000 });
  const errs = v2.consoleMsgs.filter((m) => /^pageerror/.test(m));
  assert.deepEqual(errs, [], 'no uncaught errors');
  await v2.ctx.close();
});

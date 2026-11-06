// Real Chromium -> browser-beacon.js v1.2 -> receiver container (TLS, cross-origin). Not part of the shipped package.
const http = require('http'); const fs = require('fs'); const path = require('path');
const { execFileSync } = require('child_process');
const { chromium } = require('playwright');
const SRC = fs.readFileSync(path.join(__dirname, '..', 'dist', 'browser-beacon.js'), 'utf8').replace('allowPageOverride: false,', 'allowPageOverride: true,');
const RX = 'https://127.0.0.1:18446';
const cfg = { scope: { include: ['127.0.0.0/8'], sources: [{ type: 'url', url: '/bb-ip' }] }, report: { startDelayMs: 0 },
  destinations: [{ type: 'pixel', url: RX + '/browser-beacon.gif' }, { type: 'http', url: RX + '/browser-beacon', format: 'json' }, { type: 'local' }] };
const portal = http.createServer((req, res) => {
  if (req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(`<!doctype html><meta charset=utf-8><script>window.BrowserBeaconConfig=${JSON.stringify(cfg)}</script><script async src="/b.js"></script><h1>Portal</h1>`); }
  if (req.url === '/b.js') { res.writeHead(200, { 'Content-Type': 'text/javascript' }); return res.end(SRC); }
  if (req.url.startsWith('/bb-ip')) { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(req.socket.remoteAddress); }
  res.writeHead(404); res.end();
});
const readLog = () => { try { return execFileSync('docker', ['run', '--rm', '-v', 'rx-e2e-logs:/logs', 'gcr.io/distroless/nodejs26-debian13:nonroot', '-e',
  "const fs=require('fs');for(const f of fs.readdirSync('/logs'))process.stdout.write(fs.readFileSync('/logs/'+f,'utf8'))"], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim().split('\n').filter(Boolean).map(JSON.parse); } catch (e) { return []; } };
(async () => {
  await new Promise((r) => portal.listen(18080, '127.0.0.1', r));
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true }); // self-signed test certificate
  const pg = await ctx.newPage();
  const errs = []; pg.on('pageerror', (e) => errs.push(e.message)); pg.on('console', (m) => { if (m.type() === 'error') { errs.push(m.text()); } });
  await pg.goto('http://127.0.0.1:18080/');
  let log = [];
  for (let i = 0; i < 60 && log.length < 2; i++) { await new Promise((r) => setTimeout(r, 250)); log = readLog(); }
  const local = await pg.evaluate(() => window.BrowserBeacon.log());
  const out = log.map((r) => ({ via: r.rx_via, rid: r.rid, bk: r.bk, bv: r.bv, bvs: r.bvs, vrd: r.vrd, scope: r.scope, rx_ip: r.rx_ip, rx_range: r.rx_range, rx_origin: r.rx_origin, ua_in_body: !!r.ua }));
  console.log(JSON.stringify({ receiverLog: out, beaconLocalLog: local.map((e) => ({ to: e._to, delivered: e._delivered, rid: e.rid })), pageErrors: errs }, null, 2));
  const ok = log.length === 2 && new Set(log.map((r) => r.rid)).size === 1 && log.some((r) => r.rx_via === 'http') && log.some((r) => r.rx_via === 'pixel') &&
    local.length === 1 && local[0]._to === 'pixel#1:ok,http#2:ok' && errs.length === 0;
  console.log(ok ? 'E2E PASS' : 'E2E FAIL');
  await b.close(); portal.close(); process.exit(ok ? 0 : 1);
})();

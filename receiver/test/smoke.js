'use strict';
// Post-deployment smoke test for a running receiver (no dependencies).
//   node test/smoke.js <receiver base URL> [portal origin] [--insecure]
//   node test/smoke.js https://beacon-rx.corp.example:8443 https://portal.corp.example
// Sends a CORS preflight, a POST report and a pixel report, and prints what came back.
// Run it from a machine inside ALLOWED_RANGES, then check today's log file for two
// records with usr "smoke-test". From outside the ranges the receiver still answers
// 204/200 but must not log anything.
const http = require('node:http');
const https = require('node:https');

const [base, origin] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const insecure = process.argv.includes('--insecure');
if (!base) { console.error('usage: node test/smoke.js <receiver base URL> [portal origin] [--insecure]'); process.exit(2); }
const postPath = process.env.POST_PATH || '/browser-beacon';
const pixelPath = process.env.PIXEL_PATH || '/browser-beacon.gif';
const rec = { v: '1', sv: 'smoke', bk: 'chrome', bv: '156.0.8078.80', vrd: 'current', usr: 'smoke-test', rid: 'smoke-' + Date.now() };

function call(method, path, headers, body) {
  return new Promise((resolve) => {
    const u = new URL(path, base);
    const mod = u.protocol === 'https:' ? https : http;
    const r = mod.request(u, { method, headers, rejectUnauthorized: !insecure, timeout: 5000 }, (res) => {
      res.resume(); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    r.on('timeout', () => { r.destroy(new Error('timeout')); });
    r.on('error', (e) => resolve({ error: e.message }));
    r.end(body);
  });
}

(async () => {
  const o = origin ? { Origin: origin } : {};
  const checks = [];
  const health = await call('GET', '/healthz', {});
  checks.push(['GET /healthz', health, health.status === 200]);
  if (origin) {
    const pre = await call('OPTIONS', postPath, Object.assign({ 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' }, o));
    checks.push(['OPTIONS preflight', pre, pre.status === 204 && pre.headers['access-control-allow-origin'] === origin]);
  }
  const post = await call('POST', postPath, Object.assign({ 'Content-Type': 'application/json' }, o), JSON.stringify(rec));
  checks.push(['POST report', post, post.status === 204 && (!origin || post.headers['access-control-allow-origin'] === origin)]);
  const pix = await call('GET', pixelPath + '?' + new URLSearchParams(Object.assign({}, rec, { rid: rec.rid + '-pixel' })), {});
  checks.push(['GET pixel', pix, pix.status === 200 && /image\/gif/.test(pix.headers['content-type'] || '')]);
  let ok = true;
  for (const [name, r, pass] of checks) {
    ok = ok && pass;
    console.log(`${pass ? 'PASS' : 'FAIL'}  ${name.padEnd(18)} ${r.error ? r.error : r.status}${r.headers && r.headers['access-control-allow-origin'] ? '  allow-origin=' + r.headers['access-control-allow-origin'] : ''}`);
  }
  console.log(`report id: ${rec.rid} (look for it in today's log file)`);
  process.exit(ok ? 0 : 1);
})();

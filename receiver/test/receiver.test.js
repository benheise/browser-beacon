'use strict';
// Dependency-free tests (node:test). They also run inside the Docker build, so the image
// is never built from code that fails them.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn, execFileSync } = require('node:child_process');
const R = require('../server.js');

const SERVER = path.join(__dirname, '..', 'server.js');
const PORTAL = 'https://portal.example.com';

function tmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'bbrx-')); }
function cfgFrom(env) {
  const { cfg, errors, warnings } = R.loadConfig(Object.assign({ ALLOWED_RANGES: '127.0.0.0/8', STATS_INTERVAL_SECONDS: '0' }, env));
  assert.deepEqual(errors, []);
  cfg.port = 0; cfg.host = '127.0.0.1';
  return { cfg, warnings };
}
async function start(env, clock) {
  const dir = tmpDir();
  const { cfg } = cfgFrom(Object.assign({ LOG_DIR: dir }, env));
  const rx = R.createReceiver(cfg, { clock });
  const a = await rx.listen();
  return { rx, dir, base: `http://127.0.0.1:${a.port}`, cfg };
}
function req(base, method, p, headers, body) {
  return new Promise((resolve, reject) => {
    const r = http.request(base + p, { method, headers: headers || {} }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    r.on('error', reject); if (body) { r.write(body); } r.end();
  });
}
function lines(dir, day) {
  const f = path.join(dir, `browser-beacon-${day}.jsonl`);
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
}
const today = () => new Date().toISOString().slice(0, 10);

const REC = { v: '1', sv: '1.2.0', bk: 'chrome', bv: '156.0.8078.80', vrd: 'current', did: 'd1', usr: 'CORP\\jdoe' };
const json = (o) => JSON.stringify(o);

/* ---------------- config ---------------- */
test('config: fails closed on missing or bad settings', () => {
  const bad = [
    {},                                                    // no ranges
    { ALLOWED_RANGES: '10.1.2.3/8' },                      // host bits set
    { ALLOWED_RANGES: '010.0.0.0/8' },                     // leading zero
    { ALLOWED_RANGES: '0.0.0.0/0' },
    { ALLOWED_RANGES: '::/0' },
    { ALLOWED_RANGES: '10.0.0.0/33' },
    { ALLOWED_RANGES: 'fe80::1%eth0/128' },
    { ALLOWED_RANGES: '10.0.0.0/8', ALLOWED_ORIGINS: '*' },
    { ALLOWED_RANGES: '10.0.0.0/8', ALLOWED_ORIGINS: 'https://portal.example.com/' },
    { ALLOWED_RANGES: '10.0.0.0/8', ALLOWED_ORIGINS: 'portal.example.com' },
    { ALLOWED_RANGES: '10.0.0.0/8', TLS_CERT_FILE: '/x.crt' },
    { ALLOWED_RANGES: '10.0.0.0/8', PORT: '70000' },
    { ALLOWED_RANGES: '10.0.0.0/8', LOG_PREFIX: '../etc' },
    { ALLOWED_RANGES: '10.0.0.0/8', POST_PATH: '/a', PIXEL_PATH: '/a' },
    { ALLOWED_RANGES: '10.0.0.0/8', ALLOWED_HEADERS: 'X-Ok,Bad@Header' }
  ];
  for (const env of bad) { assert.ok(R.loadConfig(env).errors.length >= 1, JSON.stringify(env)); }
  const ok = R.loadConfig({ ALLOWED_RANGES: '10.0.0.0/8, 172.16.0.0/12 2001:db8:1200::/40,10.1.1.10', ALLOWED_ORIGINS: 'https://portal.example.com,http://intranet:8080', TRUSTED_PROXIES: '10.1.1.10/32' }, { gateway: '172.17.0.1' });
  assert.deepEqual(ok.errors, []);
  assert.deepEqual(ok.cfg.allow.map((r) => r.text), ['10.0.0.0/8', '172.16.0.0/12', '2001:db8:1200::/40', '10.1.1.10/32']);
  assert.ok(ok.warnings.some((w) => /gateway 172\.17\.0\.1 is inside ALLOWED_RANGES/.test(w)), 'gateway warning');
  const excluded = R.loadConfig({ ALLOWED_RANGES: '172.16.0.0/12', EXCLUDED_RANGES: '172.31.254.0/24' }, { gateway: '172.31.254.1' });
  assert.ok(!excluded.warnings.some((w) => /gateway/.test(w)), 'no warning once the gateway is excluded');
  assert.equal(typeof R.defaultGateway(), 'string');
  assert.ok(!ok.warnings.some((w) => /TLS is off/.test(w)), 'no TLS warning when a proxy terminates TLS');
});

test('CIDR matching agrees with an independent BigInt implementation (IPv4 + IPv6, 20k cases)', () => {
  const big = (a) => R.toBytes(a).reduce((n, b) => (n << 8n) | BigInt(b), 0n);
  const rnd = (n) => Math.floor(Math.random() * n);
  const v4 = () => [rnd(256), rnd(256), rnd(256), rnd(256)].join('.');
  const v6 = () => Array.from({ length: 8 }, () => rnd(65536).toString(16)).join(':');
  const net0 = (a, bits) => { // network address string
    const b = R.toBytes(a); for (let i = 0; i < b.length; i++) { const k = Math.max(0, Math.min(8, bits - i * 8)); b[i] &= (0xff << (8 - k)) & 0xff; }
    return b.length === 4 ? b.join('.') : Array.from({ length: 8 }, (_, i) => ((b[2 * i] << 8) | b[2 * i + 1]).toString(16)).join(':');
  };
  let n = 0;
  for (let i = 0; i < 400; i++) {
    const six = i % 2 === 1, max = six ? 128 : 32, bits = 1 + rnd(max);
    const base = net0(six ? v6() : v4(), bits), r = R.parseCidr(`${base}/${bits}`);
    assert.ok(r, `${base}/${bits}`);
    const width = BigInt(max), mask = ((1n << BigInt(bits)) - 1n) << (width - BigInt(bits));
    for (let j = 0; j < 50; j++) {
      let ip = six ? v6() : v4();
      if (j % 3 === 0) { // near the range
        const b = R.toBytes(base); for (let k = Math.floor(bits / 8); k < b.length; k++) { b[k] = rnd(256); }
        ip = b.length === 4 ? b.join('.') : Array.from({ length: 8 }, (_, q) => ((b[2 * q] << 8) | b[2 * q + 1]).toString(16)).join(':');
      }
      const want = (big(ip) & mask) === (big(base) & mask);
      assert.equal(!!R.rangeHit(ip, [r]), want, `${ip} in ${base}/${bits}`);
      n++;
    }
  }
  assert.equal(n, 20000);
  assert.deepEqual(R.toBytes('::ffff:10.1.2.3').slice(10), [255, 255, 10, 1, 2, 3]);
  assert.equal(R.normalizeIp('::ffff:10.1.2.3'), '10.1.2.3');
  assert.equal(R.normalizeIp('[2001:db8::1]:443'), '2001:db8::1');
  assert.equal(R.normalizeIp('10.1.2.3:5555'), '10.1.2.3');
  assert.equal(R.normalizeIp('banana'), '');
});

test('sanitize: flat printable values only; rx_* cannot be supplied by the client', () => {
  const s = R.sanitize({ v: 1, ok: 'a\r\nb', n: 3.5, t: true, nested: { a: 1 }, arr: [1], nul: null, rx_ip: '1.2.3.4', 'bad key': 'x', ['k'.repeat(40)]: 'x', long: 'z'.repeat(5000) });
  assert.deepEqual(Object.keys(s).sort(), ['long', 'n', 'ok', 't', 'v']);
  assert.equal(s.ok, 'a b'); assert.equal(s.long.length, 1024);
  assert.equal(R.sanitize([1, 2]), null);
});

/* ---------------- HTTP behaviour ---------------- */
test('POST JSON from an allowed origin: 204 + CORS, appended with receiver fields', async () => {
  const t = await start({ ALLOWED_ORIGINS: PORTAL, ALLOW_CREDENTIALS: 'true' });
  try {
    const r = await req(t.base, 'POST', '/browser-beacon', { Origin: PORTAL, 'Content-Type': 'application/json', 'User-Agent': 'UA-test' }, json(Object.assign({ rx_ip: '6.6.6.6' }, REC)));
    assert.equal(r.status, 204);
    assert.equal(r.headers['access-control-allow-origin'], PORTAL);
    assert.equal(r.headers['access-control-allow-credentials'], 'true');
    assert.equal(r.headers.vary, 'Origin');
    assert.equal(r.headers['cache-control'], 'no-store');
    const l = lines(t.dir, today());
    assert.equal(l.length, 1);
    assert.equal(l[0].bk, 'chrome'); assert.equal(l[0].usr, 'CORP\\jdoe');
    assert.equal(l[0].rx_ip, '127.0.0.1'); assert.equal(l[0].rx_range, '127.0.0.0/8');
    assert.equal(l[0].rx_via, 'http'); assert.equal(l[0].rx_origin, PORTAL); assert.equal(l[0].rx_ua, 'UA-test');
    assert.ok(l[0].rx_time);
    const mode = fs.statSync(path.join(t.dir, `browser-beacon-${today()}.jsonl`)).mode & 0o777;
    assert.equal(mode & 0o007, 0, 'log file not world-readable');
  } finally { await t.rx.close(); }
});

test('text/plain (sendBeacon) and form bodies are accepted', async () => {
  const t = await start({});
  try {
    assert.equal((await req(t.base, 'POST', '/browser-beacon', { 'Content-Type': 'text/plain;charset=UTF-8' }, json(REC))).status, 204);
    assert.equal((await req(t.base, 'POST', '/browser-beacon', { 'Content-Type': 'application/x-www-form-urlencoded' }, new URLSearchParams(REC).toString())).status, 204);
    const l = lines(t.dir, today());
    assert.equal(l.length, 2); assert.equal(l[1].vrd, 'current');
  } finally { await t.rx.close(); }
});

test('rejections: bad origin 403, preflight rules, malformed 400, wrong type 415, too large 413, not a report 400', async () => {
  const t = await start({ ALLOWED_ORIGINS: PORTAL, ALLOWED_HEADERS: 'X-Portal', MAX_BODY_BYTES: '1024' });
  try {
    const H = { 'Content-Type': 'application/json' };
    assert.equal((await req(t.base, 'POST', '/browser-beacon', Object.assign({ Origin: 'https://evil.example' }, H), json(REC))).status, 403);
    const pre = await req(t.base, 'OPTIONS', '/browser-beacon', { Origin: PORTAL, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Private-Network': 'true' });
    assert.equal(pre.status, 204);
    assert.equal(pre.headers['access-control-allow-methods'], 'POST');
    assert.equal(pre.headers['access-control-allow-headers'], 'Content-Type, X-Portal');
    assert.equal(pre.headers['access-control-allow-private-network'], 'true');
    assert.equal(pre.headers['access-control-allow-credentials'], undefined, 'credentials off by default');
    const preBad = await req(t.base, 'OPTIONS', '/browser-beacon', { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' });
    assert.equal(preBad.status, 403); assert.equal(preBad.headers['access-control-allow-origin'], undefined);
    assert.equal((await req(t.base, 'POST', '/browser-beacon', H, '{nope')).status, 400);
    assert.equal((await req(t.base, 'POST', '/browser-beacon', { 'Content-Type': 'application/xml' }, '<a/>')).status, 415);
    const big = json({ v: 1, pad: 'x'.repeat(2000) });
    assert.equal((await req(t.base, 'POST', '/browser-beacon', H, big)).status, 413, 'chunked upload over the limit');
    assert.equal((await req(t.base, 'POST', '/browser-beacon', Object.assign({ 'Content-Length': Buffer.byteLength(big) }, H), big)).status, 413, 'declared length over the limit');
    assert.equal((await req(t.base, 'POST', '/browser-beacon', H, json({ hello: 'world' }))).status, 400);
    assert.equal((await req(t.base, 'POST', '/browser-beacon', H, json([1, 2]))).status, 400);
    assert.equal((await req(t.base, 'GET', '/browser-beacon')).status, 405);
    assert.equal((await req(t.base, 'GET', '/other')).status, 404);
    assert.equal(lines(t.dir, today()).length, 0, 'nothing logged');
    assert.ok(t.rx.stats.rejected.origin >= 1 && t.rx.stats.rejected.parse >= 1);
  } finally { await t.rx.close(); }
  const strict = await start({ REQUIRE_ORIGIN: 'true', ALLOWED_ORIGINS: PORTAL });
  try {
    assert.equal((await req(strict.base, 'POST', '/browser-beacon', { 'Content-Type': 'application/json' }, json(REC))).status, 403);
  } finally { await strict.rx.close(); }
});

test('source address outside the ranges: accepted (204) but discarded; excluded ranges too', async () => {
  const t = await start({ ALLOWED_RANGES: '10.0.0.0/8', ALLOWED_ORIGINS: PORTAL });
  try {
    const r = await req(t.base, 'POST', '/browser-beacon', { Origin: PORTAL, 'Content-Type': 'application/json' }, json(REC));
    assert.equal(r.status, 204); assert.equal(r.headers['access-control-allow-origin'], PORTAL);
    assert.equal(lines(t.dir, today()).length, 0);
    assert.equal(t.rx.stats.rejected['out-of-range'], 1);
  } finally { await t.rx.close(); }
  const ex = await start({ ALLOWED_RANGES: '127.0.0.0/8', EXCLUDED_RANGES: '127.0.0.1/32' });
  try {
    await req(ex.base, 'POST', '/browser-beacon', { 'Content-Type': 'application/json' }, json(REC));
    assert.equal(lines(ex.dir, today()).length, 0); assert.equal(ex.rx.stats.rejected.excluded, 1);
  } finally { await ex.rx.close(); }
});

test('trusted proxy: X-Forwarded-For walked right to left; spoofing and garbage fail closed', async () => {
  const t = await start({ ALLOWED_RANGES: '10.0.0.0/8', TRUSTED_PROXIES: '127.0.0.1/32, 10.250.0.0/16' });
  const post = (xff) => req(t.base, 'POST', '/browser-beacon', { 'Content-Type': 'application/json', 'X-Forwarded-For': xff }, json(REC));
  try {
    await post('8.8.8.8, 10.9.9.9');                    // client 10.9.9.9 (left entry is client-supplied junk)
    await post('10.9.9.9, 8.8.8.8');                    // client 8.8.8.8 -> out of range
    await post('10.8.8.8, 10.250.0.5');                 // second proxy skipped -> client 10.8.8.8
    await post('10.7.7.7, not-an-ip');                  // garbage from a trusted hop -> fail closed
    await post('');                                     // proxy itself (127.0.0.1) -> out of range
    const l = lines(t.dir, today());
    assert.deepEqual(l.map((x) => x.rx_ip), ['10.9.9.9', '10.8.8.8']);
    assert.equal(l[0].rx_peer, '127.0.0.1');
  } finally { await t.rx.close(); }
  const noProxy = await start({ ALLOWED_RANGES: '10.0.0.0/8' });
  try {
    await req(noProxy.base, 'POST', '/browser-beacon', { 'Content-Type': 'application/json', 'X-Forwarded-For': '10.1.1.1' }, json(REC));
    assert.equal(lines(noProxy.dir, today()).length, 0, 'X-Forwarded-For ignored unless the peer is a trusted proxy');
  } finally { await noProxy.rx.close(); }
});

test('pixel GET: always a GIF; in-scope query logged with rx_via=pixel; cache buster dropped', async () => {
  const t = await start({});
  try {
    const r = await req(t.base, 'GET', '/browser-beacon.gif?' + new URLSearchParams(Object.assign({}, REC, { _: 'abc' })));
    assert.equal(r.status, 200); assert.equal(r.headers['content-type'], 'image/gif');
    assert.equal(r.headers['cross-origin-resource-policy'], 'cross-origin');
    assert.equal(r.body.subarray(0, 6).toString(), 'GIF89a');
    const junk = await req(t.base, 'GET', '/browser-beacon.gif?hello=1');
    assert.equal(junk.status, 200, 'same answer for non-reports');
    const l = lines(t.dir, today());
    assert.equal(l.length, 1); assert.equal(l[0].rx_via, 'pixel'); assert.equal(l[0]._, undefined); assert.equal(l[0].bv, '156.0.8078.80');
  } finally { await t.rx.close(); }
  const out = await start({ ALLOWED_RANGES: '10.0.0.0/8' });
  try {
    const r = await req(out.base, 'GET', '/browser-beacon.gif?' + new URLSearchParams(REC));
    assert.equal(r.status, 200); assert.equal(lines(out.dir, today()).length, 0);
  } finally { await out.rx.close(); }
});

test('rate limit per client address', async () => {
  const t = await start({ RATE_LIMIT_PER_MIN: '3' });
  try {
    const codes = [];
    for (let i = 0; i < 5; i++) { codes.push((await req(t.base, 'POST', '/browser-beacon', { 'Content-Type': 'application/json' }, json(REC))).status); }
    assert.deepEqual(codes, [204, 204, 204, 429, 429]);
    assert.equal(lines(t.dir, today()).length, 3);
  } finally { await t.rx.close(); }
});

test('daily files roll over at UTC midnight; retention prunes only this receiver\'s old files', async () => {
  let now = new Date('2026-11-01T23:59:58.000Z');
  const dir = tmpDir();
  fs.writeFileSync(path.join(dir, 'browser-beacon-2026-09-01.jsonl'), '{}\n');   // older than 30 days
  fs.writeFileSync(path.join(dir, 'browser-beacon-2026-10-15.jsonl'), '{}\n');   // inside 30 days
  fs.writeFileSync(path.join(dir, 'other-2020-01-01.jsonl'), '{}\n');            // not ours
  const { cfg } = cfgFrom({ LOG_DIR: dir, LOG_RETENTION_DAYS: '30' });
  const rx = R.createReceiver(cfg, { clock: () => now });
  const a = await rx.listen();
  const base = `http://127.0.0.1:${a.port}`;
  try {
    await req(base, 'POST', '/browser-beacon', { 'Content-Type': 'application/json' }, json(REC));
    now = new Date('2026-11-02T00:00:01.000Z');
    await req(base, 'POST', '/browser-beacon', { 'Content-Type': 'application/json' }, json(REC));
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(lines(dir, '2026-11-01').length, 1);
    assert.equal(lines(dir, '2026-11-02').length, 1);
    assert.equal(lines(dir, '2026-11-02')[0].rx_time, '2026-11-02T00:00:01.000Z');
    const names = fs.readdirSync(dir).sort();
    assert.deepEqual(names, ['browser-beacon-2026-10-15.jsonl', 'browser-beacon-2026-11-01.jsonl', 'browser-beacon-2026-11-02.jsonl', 'other-2020-01-01.jsonl']);
  } finally { await rx.close(); }
});

test('healthz reflects whether the log directory is writable', async () => {
  const t = await start({});
  try {
    assert.equal((await req(t.base, 'GET', '/healthz')).status, 200);
    fs.rmSync(t.dir, { recursive: true, force: true });
    assert.equal((await req(t.base, 'GET', '/healthz')).status, 503);
  } finally { await t.rx.close(); }
});

/* ---------------- process level ---------------- */
function freePort() { return new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); }); }
function runServer(env) {
  const child = spawn(process.execPath, [SERVER], { env: Object.assign({ PATH: process.env.PATH }, env), stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => { out += d; }); child.stderr.on('data', (d) => { out += d; });
  const ready = new Promise((resolve, reject) => {
    const t = setInterval(() => { if (/"listening"/.test(out)) { clearInterval(t); resolve(); } }, 20);
    child.on('exit', (code) => { clearInterval(t); reject(new Error('exited ' + code + ': ' + out)); });
  });
  ready.catch(() => {}); // callers that expect an exit only await `exited`
  return { child, ready, output: () => out, exited: new Promise((r) => child.on('exit', (code) => r(code))) };
}

test('process: bad config exits 2 with the reasons; unwritable LOG_DIR exits 2', async () => {
  const a = runServer({ ALLOWED_RANGES: '' });
  assert.equal(await a.exited, 2); assert.match(a.output(), /ALLOWED_RANGES is empty/);
  const file = path.join(tmpDir(), 'a-file');
  fs.writeFileSync(file, 'x');
  for (const bad of [file, '/proc/browser-beacon-test', path.join(tmpDir(), 'missing', 'child')]) {
    const b = runServer({ ALLOWED_RANGES: '10.0.0.0/8', LOG_DIR: bad });
    assert.equal(await b.exited, 2, bad); assert.match(b.output(), /LOG_DIR .* not writable/);
  }
});

test('process: --healthcheck succeeds against a running server; SIGTERM flushes and exits 0', async () => {
  const dir = tmpDir(), port = await freePort();
  const env = { ALLOWED_RANGES: '127.0.0.0/8', LOG_DIR: dir, PORT: String(port), HOST: '127.0.0.1' };
  const s = runServer(env);
  await s.ready;
  const hc = spawn(process.execPath, [SERVER, '--healthcheck'], { env: Object.assign({ PATH: process.env.PATH }, env) });
  assert.equal(await new Promise((r) => hc.on('exit', r)), 0);
  await req(`http://127.0.0.1:${port}`, 'POST', '/browser-beacon', { 'Content-Type': 'application/json' }, json(REC));
  s.child.kill('SIGTERM');
  assert.equal(await s.exited, 0);
  assert.match(s.output(), /"stopping"/);
  assert.equal(lines(dir, today()).length, 1);
  const hcDown = spawn(process.execPath, [SERVER, '--healthcheck'], { env: Object.assign({ PATH: process.env.PATH }, env) });
  assert.equal(await new Promise((r) => hcDown.on('exit', r)), 1, 'healthcheck fails when nothing listens');
});

let hasOpenssl = false;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); hasOpenssl = true; } catch (e) {}
test('TLS: serves HTTPS with the given certificate', { skip: !hasOpenssl && 'openssl not available' }, async () => {
  const dir = tmpDir();
  const crt = path.join(dir, 'rx.crt'), key = path.join(dir, 'rx.key');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', key, '-out', crt], { stdio: 'ignore' });
  const t = await start({ TLS_CERT_FILE: crt, TLS_KEY_FILE: key });
  try {
    const port = t.rx.server.address().port;
    const status = await new Promise((resolve, reject) => {
      const r = https.request({ host: '127.0.0.1', port, path: '/browser-beacon', method: 'POST', ca: fs.readFileSync(crt), servername: 'localhost', headers: { 'Content-Type': 'application/json' } }, (res) => { res.resume(); resolve(res.statusCode); });
      r.on('error', reject); r.end(json(REC));
    });
    assert.equal(status, 204);
    assert.equal(lines(t.dir, today()).length, 1);
  } finally { await t.rx.close(); }
});

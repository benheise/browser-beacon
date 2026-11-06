'use strict';
/*
 * browser-beacon receiver v1.0.0
 * Copyright (c) 2026 Ben Heise. MIT License: https://github.com/benheise/browser-beacon/blob/main/LICENSE
 *
 * Accepts reports from browser-beacon.js ("http", "beacon" and "pixel" destinations),
 * keeps only those whose source address is inside ALLOWED_RANGES, and appends each one
 * to a daily JSON Lines file. Node.js 20+ standard library only: no npm dependencies.
 *
 *   POST <POST_PATH>    report body as JSON, JSON-as-text/plain, or form-urlencoded
 *   GET  <PIXEL_PATH>   report as query string; always answers with a 1x1 GIF
 *   OPTIONS <POST_PATH> CORS preflight for origins in ALLOWED_ORIGINS
 *   GET  /healthz       200 "ok" while the log directory is writable, else 503
 *
 *   node server.js               start the receiver
 *   node server.js --healthcheck probe /healthz on this container (for HEALTHCHECK)
 *
 * Configuration is environment variables only (see loadConfig and README.md). Invalid
 * configuration stops the process at startup: it never runs with partial settings.
 */
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const VERSION = '1.0.0';
const GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
const KEY_RE = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;
const MAX_KEYS = 80;
const MAX_VALUE = 1024;

/* ------------------------------------------------------------------ config */

function list(v) { return String(v || '').split(/[\s,]+/).map((s) => s.trim()).filter(Boolean); }
function bool(v, d) { return v === undefined || v === '' ? d : /^(1|true|yes|on)$/i.test(String(v)); }
function int(v, d, min, max, name, errors) {
  if (v === undefined || v === '') { return d; }
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) { errors.push(`${name} must be an integer from ${min} to ${max}`); return d; }
  return n;
}

// Address -> 4 or 16 bytes. Strict: no leading zeros in IPv4, no zone index.
function toBytes(addr) {
  if (net.isIPv4(addr)) { return addr.split('.').map(Number); }
  if (!net.isIPv6(addr) || addr.includes('%')) { return null; }
  let tail = [];
  let a = addr;
  const v4 = /:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (v4) { tail = v4[1].split('.').map(Number); a = a.slice(0, -v4[1].length) + '0:0'; }
  const [head, rest] = a.includes('::') ? a.split('::') : [a, null];
  const h = head ? head.split(':') : [];
  const r = rest === null ? [] : (rest ? rest.split(':') : []);
  const groups = rest === null ? h : h.concat(Array(8 - h.length - r.length).fill('0'), r);
  const bytes = [];
  for (const g of groups) { const n = parseInt(g, 16); bytes.push(n >> 8, n & 255); }
  if (tail.length) { bytes.splice(12, 4, ...tail); }
  return bytes.length === 16 ? bytes : null;
}

// "10.20.0.0/16" -> { text, family, bits, list: BlockList }. Host bits must be zero.
function parseCidr(text) {
  const m = /^([^/\s]+)(?:\/(\d{1,3}))?$/.exec(String(text).trim());
  if (!m) { return null; }
  const addr = m[1];
  const family = net.isIPv4(addr) ? 'ipv4' : (net.isIPv6(addr) && !addr.includes('%') ? 'ipv6' : null);
  if (!family) { return null; }
  const max = family === 'ipv4' ? 32 : 128;
  const bits = m[2] === undefined ? max : Number(m[2]);
  if (bits > max) { return null; }
  const bytes = toBytes(addr);
  if (!bytes) { return null; }
  for (let i = 0; i < bytes.length; i++) {
    const keep = Math.max(0, Math.min(8, bits - i * 8));
    if (bytes[i] & (255 >> keep)) { return null; } // 10.1.2.3/8 is almost always a typo
  }
  const bl = new net.BlockList();
  bl.addSubnet(addr, bits, family);
  return { text: `${addr}/${bits}`, family, bits, list: bl };
}

function compileRanges(items, name, errors, forbidAll) {
  const out = [];
  for (const item of items) {
    const r = parseCidr(item);
    if (!r) { errors.push(`${name}: invalid or non-canonical CIDR "${item}"`); continue; }
    if (forbidAll && r.bits === 0) { errors.push(`${name}: /0 is not allowed ("${item}")`); continue; }
    out.push(r);
  }
  return out;
}

// "::ffff:10.1.2.3" -> "10.1.2.3"; "[2001:db8::1]:443" -> "2001:db8::1"; "10.1.2.3:5555" -> "10.1.2.3"
function normalizeIp(s) {
  if (!s) { return ''; }
  let a = String(s).trim();
  const br = /^\[([^\]]+)\](?::\d+)?$/.exec(a);
  if (br) { a = br[1]; }
  const v4port = /^(\d+\.\d+\.\d+\.\d+):\d+$/.exec(a);
  if (v4port) { a = v4port[1]; }
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(a);
  if (mapped) { a = mapped[1]; }
  return net.isIP(a) ? a : '';
}

function rangeHit(ip, ranges) {
  const family = net.isIPv4(ip) ? 'ipv4' : 'ipv6';
  for (const r of ranges) { if (r.family === family && r.list.check(ip, family)) { return r.text; } }
  return '';
}

// Default gateway from /proc/net/route (Linux). In a bridge-networked container this is the
// address that docker-proxy-relayed connections appear to come from.
function defaultGateway() {
  try {
    for (const line of fs.readFileSync('/proc/net/route', 'utf8').split('\n').slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f[1] === '00000000' && f[2] && f[2] !== '00000000') {
        const n = parseInt(f[2], 16);
        return [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255].join('.');
      }
    }
  } catch (e) { /* not Linux, or /proc unavailable */ }
  return '';
}

function loadConfig(env, opts) {
  opts = opts || {};
  const errors = [], warnings = [];
  const cfg = {
    host: env.HOST || undefined, // unset: :: where IPv6 is available, otherwise 0.0.0.0
    port: int(env.PORT, 8080, 1, 65535, 'PORT', errors),
    tlsCertFile: env.TLS_CERT_FILE || '',
    tlsKeyFile: env.TLS_KEY_FILE || '',
    postPath: env.POST_PATH || '/browser-beacon',
    pixelPath: env.PIXEL_PATH || '/browser-beacon.gif',
    allowedOrigins: list(env.ALLOWED_ORIGINS),
    allowCredentials: bool(env.ALLOW_CREDENTIALS, false),
    allowedHeaders: list(env.ALLOWED_HEADERS),
    requireOrigin: bool(env.REQUIRE_ORIGIN, false),
    logDir: env.LOG_DIR || '/var/log/browser-beacon',
    logPrefix: env.LOG_PREFIX || 'browser-beacon',
    retentionDays: int(env.LOG_RETENTION_DAYS, 0, 0, 36500, 'LOG_RETENTION_DAYS', errors),
    rateLimit: int(env.RATE_LIMIT_PER_MIN, 60, 0, 1000000, 'RATE_LIMIT_PER_MIN', errors),
    maxBody: int(env.MAX_BODY_BYTES, 8192, 512, 1048576, 'MAX_BODY_BYTES', errors),
    statsSeconds: int(env.STATS_INTERVAL_SECONDS, 300, 0, 86400, 'STATS_INTERVAL_SECONDS', errors)
  };
  cfg.allow = compileRanges(list(env.ALLOWED_RANGES), 'ALLOWED_RANGES', errors, true);
  if (!list(env.ALLOWED_RANGES).length) { errors.push('ALLOWED_RANGES is empty: set the company CIDR ranges'); }
  cfg.exclude = compileRanges(list(env.EXCLUDED_RANGES), 'EXCLUDED_RANGES', errors, false);
  cfg.proxies = compileRanges(list(env.TRUSTED_PROXIES), 'TRUSTED_PROXIES', errors, true);
  for (const o of cfg.allowedOrigins) {
    if (!/^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$|^https?:\/\/\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/.test(o)) {
      errors.push(`ALLOWED_ORIGINS: "${o}" must be scheme://host[:port] with no path or trailing slash ("*" is not allowed)`);
    }
  }
  for (const h of cfg.allowedHeaders) { if (!/^[A-Za-z0-9-]+$/.test(h)) { errors.push(`ALLOWED_HEADERS: invalid header name "${h}"`); } }
  for (const [k, p] of [['POST_PATH', cfg.postPath], ['PIXEL_PATH', cfg.pixelPath]]) {
    if (!/^\/[A-Za-z0-9._~/-]*$/.test(p)) { errors.push(`${k} must be a path starting with /`); }
  }
  if (cfg.postPath === cfg.pixelPath) { errors.push('POST_PATH and PIXEL_PATH must differ'); }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(cfg.logPrefix)) { errors.push('LOG_PREFIX may contain only letters, digits, dot, dash and underscore'); }
  if (!!cfg.tlsCertFile !== !!cfg.tlsKeyFile) { errors.push('set both TLS_CERT_FILE and TLS_KEY_FILE, or neither'); }
  const gw = opts.gateway;
  if (gw && cfg.allow.length && rangeHit(gw, cfg.allow) && !rangeHit(gw, cfg.exclude)) {
    warnings.push(`The container's default gateway ${gw} is inside ALLOWED_RANGES. With bridge networking and published ports, ` +
      `connections relayed by docker-proxy arrive from ${gw} and would pass the range check: add it (or the container network) ` +
      'to EXCLUDED_RANGES, or use host networking or a reverse proxy in TRUSTED_PROXIES. Ignore this under host networking.');
  }
  if (!cfg.tlsCertFile && !cfg.proxies.length) {
    warnings.push('TLS is off and no TRUSTED_PROXIES are set: an https portal cannot send to an http receiver (mixed content). ' +
      'Set TLS_CERT_FILE/TLS_KEY_FILE or terminate TLS in a reverse proxy.');
  }
  return { cfg, errors, warnings };
}

/* --------------------------------------------------------------- daily log */

function utcDate(d) { return d.toISOString().slice(0, 10); }

class DailyLog {
  constructor(dir, prefix, retentionDays, clock) {
    this.dir = dir; this.prefix = prefix; this.retentionDays = retentionDays; this.clock = clock;
    this.day = ''; this.stream = null; this.error = null;
    this.pattern = new RegExp('^' + prefix.replace(/[.]/g, '\\.') + '-(\\d{4}-\\d{2}-\\d{2})\\.jsonl$');
  }
  fileFor(day) { return path.join(this.dir, `${this.prefix}-${day}.jsonl`); }
  open(day) {
    if (this.stream) { this.stream.end(); }
    this.day = day;
    this.stream = fs.createWriteStream(this.fileFor(day), { flags: 'a', mode: 0o640 });
    this.stream.on('error', (e) => { this.error = e; log('error', 'log write failed', { file: this.fileFor(day), error: e.message }); });
    this.prune();
  }
  write(obj) {
    return new Promise((resolve, reject) => {
      const day = utcDate(this.clock());
      if (day !== this.day || !this.stream || this.stream.destroyed) { this.error = null; this.open(day); }
      this.stream.write(JSON.stringify(obj) + '\n', (e) => {
        if (e) { this.error = e; return reject(e); }
        this.error = null; resolve();
      });
    });
  }
  // Removes this receiver's own daily files older than LOG_RETENTION_DAYS (0 = keep forever).
  prune() {
    if (!this.retentionDays) { return; }
    const cutoff = utcDate(new Date(this.clock().getTime() - this.retentionDays * 86400000));
    fs.readdir(this.dir, (err, names) => {
      if (err) { return; }
      for (const n of names) {
        const m = this.pattern.exec(n);
        if (m && m[1] < cutoff) { fs.unlink(path.join(this.dir, n), () => {}); }
      }
    });
  }
  writable() {
    try { fs.accessSync(this.dir, fs.constants.W_OK); return !this.error; } catch (e) { return false; }
  }
  close() {
    return new Promise((resolve) => { if (!this.stream) { return resolve(); } this.stream.end(resolve); this.stream = null; });
  }
}

/* ----------------------------------------------------------------- helpers */

function log(level, msg, extra) {
  const line = JSON.stringify(Object.assign({ time: new Date().toISOString(), level, msg }, extra || {}));
  (level === 'error' ? process.stderr : process.stdout).write(line + '\n');
}

// Client-supplied values: flat, short, printable. Receiver fields (rx_*) cannot be spoofed.
function sanitize(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) { return null; }
  const out = {};
  let n = 0;
  for (const k of Object.keys(input)) {
    if (n >= MAX_KEYS) { break; }
    if (!KEY_RE.test(k) || /^rx_/i.test(k)) { continue; }
    const v = input[k];
    if (typeof v === 'string') { out[k] = v.replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, MAX_VALUE); }
    else if (typeof v === 'number' && Number.isFinite(v)) { out[k] = v; }
    else if (typeof v === 'boolean') { out[k] = v; }
    else { continue; }
    n++;
  }
  return out;
}

// Reads at most `limit` bytes. Over the limit: stop reading and reject with 413; the
// response is then sent with Connection: close so the rest of the upload is not read.
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const tooLarge = () => { req.removeAllListeners('data'); req.pause(); reject(Object.assign(new Error('too large'), { status: 413, close: true })); };
    if (Number(req.headers['content-length'] || 0) > limit) { return tooLarge(); }
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { return tooLarge(); }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseReport(contentType, body) {
  const type = String(contentType || '').split(';')[0].trim().toLowerCase();
  if (type === 'application/json' || type === 'text/plain' || type === '') {
    try { return JSON.parse(body); } catch (e) { throw Object.assign(new Error('invalid JSON'), { status: 400 }); }
  }
  if (type === 'application/x-www-form-urlencoded') { return Object.fromEntries(new URLSearchParams(body)); }
  throw Object.assign(new Error('unsupported content type'), { status: 415 });
}

/* ---------------------------------------------------------------- receiver */

function createReceiver(cfg, opts) {
  opts = opts || {};
  const clock = opts.clock || (() => new Date());
  const dailyLog = new DailyLog(cfg.logDir, cfg.logPrefix, cfg.retentionDays, clock);
  const buckets = new Map();
  const stats = { accepted: 0, rejected: {} };
  const reject = (why) => { stats.rejected[why] = (stats.rejected[why] || 0) + 1; };

  function clientAddress(req) {
    const peer = normalizeIp(req.socket.remoteAddress);
    if (!cfg.proxies.length || !peer || !rangeHit(peer, cfg.proxies)) { return { ip: peer, peer }; }
    // From a trusted proxy: walk X-Forwarded-For right to left; the first hop that is not
    // a trusted proxy is the client. Anything unparseable fails closed.
    const hops = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
    let ip = peer;
    for (let i = hops.length - 1; i >= 0; i--) {
      const a = normalizeIp(hops[i]);
      if (!a) { return { ip: '', peer }; }
      ip = a;
      if (!rangeHit(a, cfg.proxies)) { break; }
    }
    return { ip, peer };
  }
  function scope(ip) {
    if (!ip) { return { ok: false, why: 'no-address' }; }
    if (rangeHit(ip, cfg.exclude)) { return { ok: false, why: 'excluded' }; }
    const r = rangeHit(ip, cfg.allow);
    return r ? { ok: true, range: r } : { ok: false, why: 'out-of-range' };
  }
  function limited(ip) {
    if (!cfg.rateLimit) { return false; }
    const now = Date.now();
    let b = buckets.get(ip);
    if (!b || now >= b.reset) {
      if (buckets.size > 100000) { buckets.clear(); }
      b = { count: 0, reset: now + 60000 }; buckets.set(ip, b);
    }
    return ++b.count > cfg.rateLimit;
  }
  function cors(req) {
    const origin = req.headers.origin;
    if (!origin || !cfg.allowedOrigins.includes(origin)) { return null; }
    const h = { 'Access-Control-Allow-Origin': origin };
    if (cfg.allowCredentials) { h['Access-Control-Allow-Credentials'] = 'true'; }
    return h;
  }
  function send(res, status, headers, body) {
    res.writeHead(status, Object.assign({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', Vary: 'Origin' }, headers || {}));
    res.end(body);
  }
  function enrich(rec, req, addr, sc, via) {
    rec.rx_time = clock().toISOString();
    rec.rx_ip = addr.ip;
    if (addr.peer !== addr.ip) { rec.rx_peer = addr.peer; }
    rec.rx_range = sc.range;
    rec.rx_via = via;
    if (req.headers.origin) { rec.rx_origin = String(req.headers.origin).slice(0, 200); }
    if (req.headers['user-agent']) { rec.rx_ua = String(req.headers['user-agent']).replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, 512); }
    return rec;
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://receiver.invalid');
    const p = url.pathname;

    if (p === '/healthz' && (req.method === 'GET' || req.method === 'HEAD')) {
      const ok = dailyLog.writable();
      return send(res, ok ? 200 : 503, { 'Content-Type': 'text/plain' }, ok ? 'ok' : 'log directory not writable');
    }

    if (p === cfg.postPath && req.method === 'OPTIONS') {
      const c = cors(req);
      if (!c) { reject('preflight-origin'); return send(res, 403); }
      const h = Object.assign({}, c, {
        'Access-Control-Allow-Methods': 'POST',
        'Access-Control-Allow-Headers': ['Content-Type'].concat(cfg.allowedHeaders).join(', '),
        'Access-Control-Max-Age': '600'
      });
      if (req.headers['access-control-request-private-network'] === 'true') { h['Access-Control-Allow-Private-Network'] = 'true'; }
      return send(res, 204, h);
    }

    if (p === cfg.postPath && req.method === 'POST') {
      const c = cors(req);
      if (req.headers.origin && !c) { reject('origin'); req.resume(); return send(res, 403); }
      if (!req.headers.origin && cfg.requireOrigin) { reject('no-origin'); req.resume(); return send(res, 403); }
      const addr = clientAddress(req);
      if (limited(addr.ip || addr.peer)) { reject('rate-limit'); req.resume(); return send(res, 429, Object.assign({ 'Retry-After': '60' }, c)); }
      let body;
      try { body = await readBody(req, cfg.maxBody); }
      catch (e) { reject('body'); return send(res, e.status || 400, Object.assign({}, c, e.close ? { Connection: 'close' } : {})); }
      const sc = scope(addr.ip);
      // Out of scope: accepted and discarded, so the client learns nothing and does not retry.
      if (!sc.ok) { reject(sc.why); return send(res, 204, c); }
      let rec;
      try { rec = sanitize(parseReport(req.headers['content-type'], body)); } catch (e) { reject('parse'); return send(res, e.status || 400, c); }
      if (!rec || rec.v === undefined) { reject('not-a-report'); return send(res, 400, c); }
      try { await dailyLog.write(enrich(rec, req, addr, sc, 'http')); } catch (e) { reject('write'); return send(res, 503, c); }
      stats.accepted++;
      return send(res, 204, c);
    }

    if (p === cfg.pixelPath && (req.method === 'GET' || req.method === 'HEAD')) {
      // Always the same GIF, whatever happens, so the response reveals nothing.
      const gif = () => send(res, 200, { 'Content-Type': 'image/gif', 'Content-Length': GIF.length, 'Cross-Origin-Resource-Policy': 'cross-origin' }, req.method === 'HEAD' ? undefined : GIF);
      const addr = clientAddress(req);
      if (limited(addr.ip || addr.peer)) { reject('rate-limit'); return gif(); }
      const sc = scope(addr.ip);
      if (!sc.ok) { reject(sc.why); return gif(); }
      const q = Object.fromEntries(url.searchParams);
      delete q._;
      const rec = sanitize(q);
      if (!rec || rec.v === undefined) { reject('not-a-report'); return gif(); }
      try { await dailyLog.write(enrich(rec, req, addr, sc, 'pixel')); stats.accepted++; } catch (e) { reject('write'); }
      return gif();
    }

    reject('not-found');
    send(res, p === cfg.postPath || p === cfg.pixelPath ? 405 : 404);
  }

  const onRequest = (req, res) => {
    handle(req, res).catch((e) => { log('error', 'request failed', { error: e.message }); if (!res.headersSent) { send(res, 500); } });
  };
  const server = cfg.tlsCertFile
    ? https.createServer({ cert: fs.readFileSync(cfg.tlsCertFile), key: fs.readFileSync(cfg.tlsKeyFile), minVersion: 'TLSv1.2' }, onRequest)
    : http.createServer(onRequest);
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;

  const sweep = setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) { if (now >= b.reset) { buckets.delete(k); } } }, 60000);
  sweep.unref();
  let statsTimer = null;
  if (cfg.statsSeconds) {
    statsTimer = setInterval(() => {
      if (stats.accepted || Object.keys(stats.rejected).length) { log('info', 'stats', { accepted: stats.accepted, rejected: stats.rejected }); }
      stats.accepted = 0; stats.rejected = {};
    }, cfg.statsSeconds * 1000);
    statsTimer.unref();
  }

  return {
    server, dailyLog, stats,
    listen() { return new Promise((resolve, reject2) => { server.once('error', reject2); server.listen(cfg.port, cfg.host, () => resolve(server.address())); }); },
    async close() {
      clearInterval(sweep); if (statsTimer) { clearInterval(statsTimer); }
      await new Promise((resolve) => { server.close(() => resolve()); if (server.closeIdleConnections) { server.closeIdleConnections(); } });
      await dailyLog.close();
    }
  };
}

/* -------------------------------------------------------------------- main */

function healthcheck(env) {
  const port = Number(env.PORT || 8080);
  const tls = !!env.TLS_CERT_FILE;
  const mod = tls ? https : http;
  const req = mod.get({ host: '127.0.0.1', port, path: '/healthz', timeout: 3000, rejectUnauthorized: false }, (res) => {
    res.resume(); process.exit(res.statusCode === 200 ? 0 : 1);
  });
  req.on('timeout', () => { req.destroy(); process.exit(1); });
  req.on('error', () => process.exit(1));
}

async function main() {
  if (process.argv.includes('--healthcheck')) { return healthcheck(process.env); }
  const { cfg, errors, warnings } = loadConfig(process.env, { gateway: defaultGateway() });
  if (errors.length) { for (const e of errors) { log('error', 'config', { error: e }); } process.exit(2); }
  try {
    // Non-recursive on purpose: the parent must exist (it is a mounted volume in the container).
    try { fs.mkdirSync(cfg.logDir); } catch (e) { if (e.code !== 'EEXIST') { throw e; } }
    if (!fs.statSync(cfg.logDir).isDirectory()) { throw new Error('not a directory'); }
    fs.accessSync(cfg.logDir, fs.constants.W_OK);
  }
  catch (e) { log('error', 'config', { error: `LOG_DIR ${cfg.logDir} is not writable by uid ${process.getuid ? process.getuid() : '?'}: ${e.message}` }); process.exit(2); }
  for (const w of warnings) { log('warn', 'config', { warning: w }); }

  const rx = createReceiver(cfg);
  const addr = await rx.listen();
  log('info', 'listening', {
    version: VERSION, node: process.version, address: addr.address, port: addr.port, tls: !!cfg.tlsCertFile,
    postPath: cfg.postPath, pixelPath: cfg.pixelPath, allowedRanges: cfg.allow.map((r) => r.text),
    excludedRanges: cfg.exclude.map((r) => r.text), trustedProxies: cfg.proxies.map((r) => r.text),
    allowedOrigins: cfg.allowedOrigins, logDir: cfg.logDir, retentionDays: cfg.retentionDays
  });

  // As PID 1 in a container, Node gets no default signal handling: handle stop explicitly.
  let stopping = false;
  const stop = async (signal) => {
    if (stopping) { return; }
    stopping = true;
    log('info', 'stopping', { signal });
    setTimeout(() => process.exit(1), 10000).unref();
    await rx.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
}

if (require.main === module) { main().catch((e) => { log('error', 'fatal', { error: e.message }); process.exit(1); }); }

module.exports = { VERSION, loadConfig, defaultGateway, createReceiver, parseCidr, toBytes, normalizeIp, rangeHit, sanitize, parseReport, DailyLog };

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');
const ipaddr2 = require('ipaddr.js'); // 2.5.0, used only as a test oracle
const Bowser = require('bowser');
const { raw, UA, hints, load, run } = require('./helpers');

const OK_CFG = { scope: { include: ['10.0.0.0/8'] } };

/* ------------------------------------------------------------------ */
test('vendored blocks are byte-identical to the npm files', () => {
  const nm = path.join(__dirname, '..', 'node_modules');
  const cases = [
    ['ua-parser-js@1.0.41', path.join(nm, 'ua-parser-js/dist/ua-parser.min.js')],
    ['ipaddr.js@1.9.1', path.join(nm, 'ipaddr1/ipaddr.min.js')]
  ];
  for (const [tag, file] of cases) {
    const re = new RegExp('/\\* @@BEGIN ' + tag.replace(/[.@]/g, '\\$&') + ' \\S+ sha256=([0-9a-f]{64}) \\*/\\n([\\s\\S]*?)\\n/\\* @@END');
    const m = raw.match(re);
    assert.ok(m, 'markers for ' + tag);
    const want = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    assert.equal(crypto.createHash('sha256').update(m[2]).digest('hex'), want, tag + ' block hash');
    assert.equal(m[1], want, tag + ' marker hash');
  }
});

test('everything outside the vendored blocks is plain ASCII (safe under any page encoding)', () => {
  const outside = raw.replace(/\/\* @@BEGIN[\s\S]*?\/\* @@END[^\n]*/g, '');
  assert.ok(!/[^\x00-\x7f]/.test(outside), 'non-ASCII: ' + (outside.match(/[^\x00-\x7f]/g) || []).join(' '));
});

test('shipped config fails closed: empty scope.include disables the script', async () => {
  const env = load({ script: raw, ip: '10.1.2.3' }); // unmodified file, no overrides possible
  assert.ok(env.BB.configErrors.length >= 1);
  assert.match(env.BB.configErrors[0], /scope\.include is empty/);
  assert.ok(env.warnings.some((w) => /disabled by configuration errors/.test(w)));
  const r = await run(env);
  assert.equal(r.status, 'config-error');
});

test('invalid ranges are rejected (octal-looking, host bits set, /0, prefix too long)', () => {
  for (const bad of ['010.0.0.0/8', '10.1.2.3/8', '0.0.0.0/0', '10.0.0.0/33', '::/0', '2001:db8::1/32', 'banana', '10.0.0/8']) {
    const env = load({ config: { scope: { include: [bad] } } });
    assert.ok(env.BB.configErrors.length >= 1, 'should reject ' + bad);
  }
  const good = load({ config: { scope: { include: ['10.0.0.0/8', '192.168.10.0/24', '10.1.1.10', '2001:db8:1200::/40', 'fd00::/8'] } } });
  assert.equal(good.BB.configErrors.length, 0, String(good.BB.configErrors));
  assert.equal(good.BB.util.parseCidr('10.1.1.10').bits, 32);
});

test('other config errors fail closed', () => {
  const cases = [
    { scope: { include: ['10.0.0.0/8'], sources: [{ type: 'nope' }] } },
    { scope: { include: ['10.0.0.0/8'], onUnknown: 'maybe' } },
    { scope: { include: ['10.0.0.0/8'] }, transport: { mode: 'smoke' } },
    { scope: { include: ['10.0.0.0/8'] }, transport: { mode: 'pixel', endpoint: '' } },
    { scope: { include: ['10.0.0.0/8'] }, policy: { browsers: { chrome: [{ channel: 'stable', minimum: 'latest' }] } } },
    { scope: { include: ['10.0.0.0/8'] }, extensions: { watchList: [{ name: 'x', id: 'NOT-AN-ID', resource: 'a.png' }] } },
    { scope: { include: ['10.0.0.0/8'] }, extensions: { watchList: [{ name: 'x', id: 'abcdefghijklmnopabcdefghijklmnop', resource: '../a.png' }] } }
  ];
  for (const c of cases) { assert.ok(load({ config: c }).BB.configErrors.length >= 1, JSON.stringify(c)); }
});

/* ------------------------------------------------------------------ */
function rnd(n) { return Math.floor(Math.random() * n); }
function randV4() { return [rnd(256), rnd(256), rnd(256), rnd(256)].join('.'); }
function randV6() { const p = []; for (let i = 0; i < 8; i++) { p.push(rnd(65536).toString(16)); } return p.join(':'); }
function canon(addr, bits) { return ipaddr2.parseCIDR(addr + '/' + bits) && networkOf(addr, bits) + '/' + bits; }
function networkOf(addr, bits) {
  const a = ipaddr2.parse(addr), b = a.toByteArray();
  for (let i = 0; i < b.length; i++) { const keep = Math.max(0, Math.min(8, bits - i * 8)); b[i] &= (0xff << (8 - keep)) & 0xff; }
  return ipaddr2.fromByteArray(b).toString();
}
function nearby(cidr) { // an address inside, at the edges, or just outside a range
  const [addr, bitsS] = cidr.split('/'); const bits = +bitsS;
  const a = ipaddr2.parse(addr), b = a.toByteArray();
  const mode = rnd(4);
  for (let i = 0; i < b.length; i++) {
    const keep = Math.max(0, Math.min(8, bits - i * 8)), hostMask = 0xff >> keep;
    if (mode === 0) { b[i] |= rnd(256) & hostMask; } else if (mode === 1) { b[i] |= hostMask; }
  }
  let out = ipaddr2.fromByteArray(b).toString();
  if (mode === 3) { // step one address past the end (or before the start)
    const bb = ipaddr2.parse(out).toByteArray();
    for (let i = 0; i < bb.length; i++) { const keep = Math.max(0, Math.min(8, bits - i * 8)); bb[i] |= 0xff >> keep; }
    for (let i = bb.length - 1; i >= 0; i--) { if (bb[i] === 255) { bb[i] = 0; } else { bb[i]++; break; } }
    out = ipaddr2.fromByteArray(bb).toString();
  }
  return out;
}

test('CIDR scope matches ipaddr.js 2.5.0 oracle on 60k random/edge cases (IPv4, IPv6, IPv4-mapped)', () => {
  let checked = 0;
  for (let round = 0; round < 12; round++) {
    const inc = [], exc = [];
    for (let i = 0; i < 30; i++) { inc.push(canon(randV4(), 1 + rnd(32))); }
    for (let i = 0; i < 15; i++) { inc.push(canon(randV6(), 1 + rnd(128))); }
    for (let i = 0; i < 6; i++) { exc.push(canon(randV4(), 8 + rnd(25))); exc.push(canon(randV6(), 16 + rnd(113))); }
    const env = load({ config: { scope: { include: inc, exclude: exc } } });
    assert.equal(env.BB.configErrors.length, 0, String(env.BB.configErrors));
    const oInc = inc.map((c) => ipaddr2.parseCIDR(c)), oExc = exc.map((c) => ipaddr2.parseCIDR(c));
    for (let i = 0; i < 5000; i++) {
      const pickFrom = rnd(3) === 0 ? exc : inc;
      let ipStr = rnd(5) === 0 ? (rnd(2) ? randV4() : randV6()) : nearby(pickFrom[rnd(pickFrom.length)]);
      let mapped = false;
      if (ipStr.indexOf(':') < 0 && rnd(6) === 0) { ipStr = '::ffff:' + ipStr; mapped = true; }
      const o = ipaddr2.process(ipStr);
      const hit = (list) => list.some(([r, b]) => r.kind() === o.kind() && o.match(r, b));
      const want = hit(oExc) ? 'out' : (hit(oInc) ? 'in' : 'out');
      const got = env.BB.util.scopeOf(ipStr).state;
      assert.equal(got, want, `${ipStr}${mapped ? ' (mapped)' : ''} inc=${inc.length}`);
      checked++;
    }
  }
  assert.equal(checked, 60000);
});

test('IP parsing rejects ambiguous forms and strips zone/brackets', () => {
  const env = load(OK_CFG);
  const s = env.BB.util.scopeOf;
  assert.equal(s('10.1.2.3').state, 'in');
  assert.equal(s('010.1.2.3').state, 'unknown');   // octal-looking: refuse rather than misread
  assert.equal(s('0x0a.1.2.3').state, 'unknown');
  assert.equal(s('10.1.2').state, 'unknown');
  assert.equal(s('256.1.2.3').state, 'unknown');
  assert.equal(s('::ffff:10.9.9.9').state, 'in');  // IPv4-mapped IPv6
  assert.equal(s('11.0.0.1').state, 'out');
  assert.equal(s('').state, 'unknown');
  const env6 = load({ config: { scope: { include: ['fe80::/10'] } } });
  assert.equal(env6.BB.util.scopeOf('fe80::1%eth0').state, 'in');
  assert.equal(env6.BB.util.scopeOf('[fe80::1]').state, 'in');
});

/* ------------------------------------------------------------------ */
test('version comparison and channel evaluation', () => {
  const { util } = load(OK_CFG).BB;
  assert.equal(util.compareVersions('156.0.8078.73', '156.0.8078.80'), -1);
  assert.equal(util.compareVersions('27.2', '27.2.0'), 0);
  assert.equal(util.compareVersions('159', '159.0'), 0);
  assert.equal(util.compareVersions('x', '1'), null);
  const tracks = [{ channel: 'stable', minimum: '156.0.8078.73' }, { channel: 'extended', minimum: '152.0.7977.167' }];
  const ev = (v, p) => util.evaluate(tracks, v, p || 'full');
  assert.equal(ev('157.0.8103.26').vrd, 'current');
  assert.equal(ev('157.0.8103.26').rsn, 'newer-major');
  assert.equal(ev('156.0.8078.73').vrd, 'current');
  assert.deepEqual([ev('156.0.8078.60').vrd, ev('156.0.8078.60').rsn, ev('156.0.8078.60').behind], ['outdated', 'below-minimum', 0]);
  assert.deepEqual([ev('152.0.7977.167').vrd, ev('152.0.7977.167').chan], ['current', 'extended']);
  assert.equal(ev('152.0.7977.100').vrd, 'outdated');
  assert.deepEqual([ev('154.0.8000.1').vrd, ev('154.0.8000.1').behind], ['outdated', 2]);
  assert.equal(ev('156.0.0.0', 'major').vrd, 'current');
  assert.equal(ev('156.0.0.0', 'major').rsn, 'major-match-patch-unknown');
  assert.equal(util.evaluate(tracks, '').vrd, 'unknown');
});

const HC = (b, v, o) => hints(b, v, o);
const CASES = [
  // [label, ua, hints, expect {bk, vrd, rsn?, chan?, basis?, os?, spoof?, bvp?}]
  ['Chrome current (hints)', UA.chromeWin, HC('Google Chrome', '156.0.8078.80'), { bk: 'chrome', vrd: 'current', chan: 'stable', os: 'Windows 11', bvp: 'full', spoof: false }],
  ['Chrome patch behind (hints)', UA.chromeWin, HC('Google Chrome', '156.0.8078.60'), { bk: 'chrome', vrd: 'outdated', rsn: 'below-minimum' }],
  ['Chrome extended stable', UA.chromeWin.replace('156.0.0.0', '152.0.0.0'), HC('Google Chrome', '152.0.7977.167', { platformVersion: '10.0.0' }), { bk: 'chrome', vrd: 'current', chan: 'extended', os: 'Windows 10' }],
  ['Chrome 154 (UA only)', UA.chromeWin154, null, { bk: 'chrome', vrd: 'outdated', rsn: 'major-behind', os: 'Windows 10/11', bvp: 'major' }],
  ['Chrome 156 (UA only, patch unknown)', UA.chromeWin, null, { bk: 'chrome', vrd: 'current', rsn: 'major-match-patch-unknown', bvp: 'major' }],
  ['Chrome low-entropy hints only', UA.chromeWin, HC('Google Chrome', '156.0.8078.80', { lowOnly: true }), { bk: 'chrome', vrd: 'current', bvp: 'major' }],
  ['Chrome 109 on Windows 7', UA.chromeWin7, null, { bk: 'chrome', vrd: 'outdated', os: 'Windows 7' }],
  ['Edge current (hints)', UA.edgeWin, HC('Microsoft Edge', '156.0.4314.58', { chromium: '156.0.8078.80' }), { bk: 'edge', vrd: 'current' }],
  ['Edge one update behind', UA.edgeWin, HC('Microsoft Edge', '156.0.4314.50', { chromium: '156.0.8078.73' }), { bk: 'edge', vrd: 'outdated', rsn: 'below-minimum' }],
  ['Edge Legacy', UA.edgeLegacy, null, { bk: 'edge-legacy', vrd: 'unsupported' }],
  ['IE 11', UA.ie11, null, { bk: 'ie', vrd: 'unsupported' }],
  ['Firefox 159', UA.firefox159, null, { bk: 'firefox', vrd: 'current', bvp: 'major' }],
  ['Firefox 158', UA.firefox158, null, { bk: 'firefox', vrd: 'outdated', rsn: 'major-behind' }],
  ['Firefox 153 (ESR or stale release)', UA.firefox153, null, { bk: 'firefox', vrd: 'unverified', chan: 'esr' }],
  ['Firefox 115 on Windows 7', UA.firefox115win7, null, { bk: 'firefox', vrd: 'unverified', chan: 'esr115', os: 'Windows 7' }],
  ['Firefox 160 beta', UA.firefox160beta, null, { bk: 'firefox', vrd: 'current', rsn: 'newer-major' }],
  ['Safari 27.2', UA.safari272, null, { bk: 'safari', vrd: 'current', os: 'macOS' }],
  ['Safari 27.1', UA.safari271, null, { bk: 'safari', vrd: 'outdated', rsn: 'below-minimum' }],
  ['Safari 26.4', UA.safari264, null, { bk: 'safari', vrd: 'outdated', rsn: 'major-behind' }],
  ['Opera (engine 155)', UA.opera, null, { bk: 'opera', vrd: 'current', basis: 'engine' }],
  ['Opera (engine 150)', UA.operaOld, null, { bk: 'opera', vrd: 'outdated', basis: 'engine' }],
  ['Brave (hints, engine current)', UA.chromeWin, HC('Brave', '156', { chromium: '156.0.8078.80' }), { bk: 'brave', vrd: 'current', basis: 'engine', spoof: false }],
  ['Brave (hints, engine 154)', UA.chromeWin154, HC('Brave', '154', { chromium: '154.0.8010.5' }), { bk: 'brave', vrd: 'outdated', basis: 'engine' }],
  ['Unknown Chromium brand', UA.chromeWin, HC('Acme Browser', '9.1.0', { chromium: '156.0.8078.80' }), { bk: 'chromium', vrd: 'current' }],
  ['Spoof: UA says Firefox, hints say Chrome', UA.firefox159, HC('Google Chrome', '150.0.7800.1'), { bk: 'chrome', vrd: 'outdated', spoof: true }],
  ['Spoof: UA Chrome 156, hints Chrome 150', UA.chromeWin, HC('Google Chrome', '150.0.7800.1'), { bk: 'chrome', vrd: 'outdated', spoof: true }],
  ['Spoof: UA Edge, hints Chrome', UA.edgeWin, HC('Google Chrome', '156.0.8078.80'), { bk: 'chrome', spoof: true }]
];

test('browser identity and verdicts across a UA corpus', () => {
  const env = load(OK_CFG);
  for (const [label, ua, h, want] of CASES) {
    const id = env.BB.util.identify(ua, h);
    const j = env.BB.util.judge(ua, h);
    const got = { bk: id.key, vrd: j.vrd, rsn: j.rsn, chan: j.chan, basis: j.basis, os: id.os, spoof: id.spoof, bvp: id.precision };
    for (const k of Object.keys(want)) { assert.equal(got[k], want[k], `${label}: ${k} (got ${JSON.stringify(got)})`); }
  }
});

test('Client Hints fast path gives the same identity as the full UA parser', () => {
  const env = load(OK_CFG);
  let n = 0;
  for (const [label, ua, h] of CASES) {
    if (!h) { continue; }
    const fast = env.BB.util.identify(ua, h), full = env.BB.util.identify(ua, h, true);
    for (const k of ['key', 'name', 'version', 'precision', 'chromium', 'os', 'osv', 'spoof', 'mobile', 'arch', 'bitness']) {
      assert.equal(fast[k], full[k], label + ': ' + k);
    }
    n++;
  }
  assert.ok(n >= 10);
});

test('mobile detection', () => {
  const { util } = load(OK_CFG).BB;
  assert.equal(util.identify(UA.iphone).mobile, true);
  assert.equal(util.identify(UA.android).mobile, true);
  assert.equal(util.identify(UA.chromeWin, hints('Google Chrome', '156.0.8078.80', { mobile: true, platform: 'Android', platformVersion: '15.0.0' })).mobile, true);
  assert.equal(util.identify(UA.chromeWin).mobile, false);
  assert.equal(util.identify(UA.safari272).mobile, false);
});

test('UA parsing agrees with Bowser 2.15 on family and major version', () => {
  const { util } = load(OK_CFG).BB;
  const map = { 'Microsoft Edge': 'edge', Chrome: 'chrome', Firefox: 'firefox', Safari: 'safari', Opera: 'opera', 'Internet Explorer': 'ie', Chromium: 'chromium' };
  for (const key of ['chromeWin', 'chromeWin154', 'edgeWin', 'ie11', 'firefox159', 'firefox153', 'safari272', 'safari264', 'opera', 'iphone', 'android']) {
    const b = Bowser.getParser(UA[key]).getBrowser();
    const ours = util.identify(UA[key]);
    assert.equal(ours.key, map[b.name] || b.name, key + ' family (bowser ' + b.name + ')');
    assert.equal(String(ours.version).split('.')[0], String(b.version).split('.')[0], key + ' major');
  }
});

test('OS verdicts, including Windows 10/11 ambiguity', () => {
  const plain = load(OK_CFG).BB;
  assert.equal(plain.util.identify(UA.firefox159).os, 'Windows 10/11');
  const env = load({ scope: OK_CFG.scope, config: { scope: OK_CFG.scope, policy: { os: { unsupported: ['Windows 7', 'Windows 10'] } } }, ip: '10.1.1.1', ua: UA.firefox159 });
  return run(env, 'preview').then(({ rec }) => {
    assert.equal(rec.os, 'Windows 10/11');
    assert.equal(rec.osvrd, 'unknown'); // could be either
  });
});

test('stale policy downgrades current to unverified', async () => {
  const env = load({ config: { scope: OK_CFG.scope, policy: { issued: '2026-01-01', maxAgeDays: 21 } }, ip: '10.1.1.1', ua: UA.firefox159 });
  const { rec } = await run(env, 'preview');
  assert.equal(rec.vrd, 'unverified');
  assert.equal(rec.rsn, 'policy-stale');
  const env2 = load({ config: { scope: OK_CFG.scope, policy: { issued: '2026-01-01', maxAgeDays: 21 } }, ip: '10.1.1.1', ua: UA.firefox158 });
  assert.equal((await run(env2, 'preview')).rec.vrd, 'outdated'); // outdated stays outdated
});

/* ------------------------------------------------------------------ */
test('in scope (meta): sends one record, creates device id, page query string not sent', async () => {
  const env = load({ ip: '10.20.30.40', ua: UA.edgeWin, hints: hints('Microsoft Edge', '156.0.4314.58', { chromium: '156.0.8078.80' }), config: OK_CFG });
  const { rec, status } = await run(env);
  assert.equal(status, 'sent');
  assert.equal(env.sent.length, 1);
  const r = env.sent[0];
  assert.equal(r.scope, 'in'); assert.equal(r.ip, '10.20.30.40'); assert.equal(r.ipsrc, 'meta');
  assert.equal(r.bk, 'edge'); assert.equal(r.bv, '156.0.4314.58'); assert.equal(r.bvs, 'uach'); assert.equal(r.vrd, 'current');
  assert.equal(r.os, 'Windows 11'); assert.equal(r.osv, '15.0.0'); assert.equal(r.osvrd, 'supported');
  assert.equal(r.cv, '156.0.8078.80'); assert.equal(r.arch, 'x86'); assert.equal(r.bit, '64'); assert.equal(r.wow64, '0');
  assert.equal(r.pg, '/home/index.aspx'); assert.equal(r.host, 'portal.example.com');
  assert.ok(!JSON.stringify(r).includes('SECRET'));
  assert.match(r.did, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(env.w.localStorage.getItem('bb_did'), r.did);
  assert.ok(!env.w.document.cookie.includes('bb_did'), 'cookie is opt-in');
  assert.equal(r.ua, env.w.navigator.userAgent); // non-pixel mode includes raw UA
  assert.equal(r.v, '1'); assert.equal(r.pid, '2026-11-01'); assert.equal(r.psrc, 'embedded');
  assert.equal(rec.rid.length, 36);
});

test('out of scope / excluded / unknown: nothing sent, nothing stored', async () => {
  for (const ip of ['11.1.1.1', '10.250.1.1', '']) {
    const env = load({ ip: ip || undefined, ua: UA.chromeWin, config: OK_CFG.scope ? { scope: { include: ['10.0.0.0/8'], exclude: ['10.250.0.0/16'] } } : {} });
    const { status } = await run(env);
    assert.equal(status, ip === '' ? 'scope-unknown' : 'scope-out', ip);
    assert.equal(env.sent.length, 0);
    assert.equal(env.w.localStorage.getItem('bb_did'), null);
    assert.ok(!env.w.document.cookie.includes('bb_did'));
  }
});

test('onUnknown=report and scope.enabled=false', async () => {
  const a = load({ ua: UA.chromeWin, config: { scope: { include: ['10.0.0.0/8'], onUnknown: 'report' } } });
  assert.equal((await run(a)).status, 'sent'); assert.equal(a.sent[0].scope, 'unknown');
  const b = load({ ua: UA.chromeWin, config: { scope: { enabled: false, include: [] } } });
  assert.equal(b.BB.configErrors.length, 0);
  assert.equal((await run(b)).status, 'sent'); assert.equal(b.sent[0].scope, 'disabled');
});

test('preview never sends or stores', async () => {
  const env = load({ ip: '11.1.1.1', ua: UA.firefox158, config: OK_CFG });
  const { rec, status } = await run(env, 'preview');
  assert.equal(status, 'dry-run-scope-out');
  assert.equal(rec.vrd, 'outdated');
  assert.equal(rec.did, undefined);
  assert.equal(env.sent.length, 0);
  assert.equal(env.w.localStorage.getItem('bb_did'), null);
});

test('hostname allow-list', async () => {
  const a = load({ ip: '10.1.1.1', url: 'https://other.example.org/', config: { scope: OK_CFG.scope, allowedHostnames: ['portal.example.com', '*.intranet.example.com'] } });
  assert.equal((await run(a)).status, 'host-not-allowed');
  const b = load({ ip: '10.1.1.1', url: 'https://hr.intranet.example.com/', config: { scope: OK_CFG.scope, allowedHostnames: ['portal.example.com', '*.intranet.example.com'] } });
  assert.equal((await run(b)).status, 'sent');
});

test('mobile skip and report', async () => {
  const a = load({ ip: '10.1.1.1', ua: UA.iphone, config: OK_CFG });
  assert.equal((await run(a)).status, 'mobile-skip');
  const b = load({ ip: '10.1.1.1', ua: UA.iphone, config: { scope: OK_CFG.scope, mobile: 'report' } });
  assert.equal((await run(b)).status, 'sent'); assert.equal(b.sent[0].mob, '1');
});

test('username sources: meta, dom+pattern, global, cookie, order of precedence', async () => {
  const a = load({ ip: '10.1.1.1', head: '<meta name="portal-user" content="CORP\\jdoe">', config: { scope: OK_CFG.scope, user: { sources: [{ type: 'meta', name: 'portal-user' }] } } });
  await run(a); assert.equal(a.sent[0].usr, 'CORP\\jdoe'); assert.equal(a.sent[0].usrsrc, 'meta');
  const b = load({ ip: '10.1.1.1', body: '<div id="u">Welcome, Jane Doe </div>', config: { scope: OK_CFG.scope, user: { sources: [{ type: 'meta', name: 'missing' }, { type: 'dom', selector: '#u', pattern: 'Welcome,\\s*(.+)' }] } } });
  await run(b); assert.equal(b.sent[0].usr, 'Jane Doe'); assert.equal(b.sent[0].usrsrc, 'dom');
  const c = load({ ip: '10.1.1.1', before: (w) => { w.portalCtx = { user: { login: 'jdoe@corp.example' } }; }, config: { scope: OK_CFG.scope, user: { sources: [{ type: 'global', path: 'portalCtx.user.login' }] } } });
  await run(c); assert.equal(c.sent[0].usr, 'jdoe@corp.example');
  const d = load({ ip: '10.1.1.1', before: (w) => { w.document.cookie = 'username=bsmith; path=/'; }, config: { scope: OK_CFG.scope, user: { sources: [{ type: 'cookie', name: 'username' }] } } });
  await run(d); assert.equal(d.sent[0].usr, 'bsmith');
  const e = load({ ip: '10.1.1.1', config: { scope: OK_CFG.scope, user: { sources: [{ type: 'function', fn: (cb) => setTimeout(() => cb('async-user'), 10) }] } } });
  await run(e); assert.equal(e.sent[0].usr, 'async-user');
});

test('control characters are stripped from reported values', async () => {
  const env = load({ ip: '10.1.1.1', head: '<meta name="portal-user" content="bad&#10;line&#13;injection">', config: { scope: OK_CFG.scope, user: { sources: [{ type: 'meta', name: 'portal-user' }] } } });
  await run(env);
  assert.equal(env.sent[0].usr, 'bad line injection');
});

/* ---- tests that need a same-origin HTTP server (url sources, policy feed) ---- */
function server(routes) {
  return new Promise((resolve) => {
    const hits = [];
    const s = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      hits.push(u.pathname + u.search);
      const h = routes[u.pathname];
      if (!h) { res.writeHead(404); return res.end(); }
      h(req, res);
    });
    s.listen(0, '127.0.0.1', () => resolve({ s, hits, base: 'http://127.0.0.1:' + s.address().port }));
  });
}

test('url sources: IP from body, IP from header, user from JSON; cache-busted', async () => {
  const srv = await server({
    '/bb-ip': (q, r) => { r.writeHead(200, { 'Content-Type': 'text/plain' }); r.end('10.44.0.7\n'); },
    '/bb-ip.txt': (q, r) => { r.writeHead(200, { 'X-Client-IP': '10.44.0.8' }); r.end('x'); },
    '/api/me': (q, r) => { r.writeHead(200, { 'Content-Type': 'application/json' }); r.end(JSON.stringify({ userPrincipalName: 'jdoe@corp.example' })); }
  });
  try {
    const a = load({ url: srv.base + '/', config: { scope: { include: ['10.44.0.0/16'], sources: [{ type: 'url', url: '/bb-ip' }] }, user: { sources: [{ type: 'url', url: '/api/me', jsonPath: 'userPrincipalName' }] } } });
    await run(a);
    assert.equal(a.sent[0].ip, '10.44.0.7'); assert.equal(a.sent[0].ipsrc, 'url'); assert.equal(a.sent[0].usr, 'jdoe@corp.example');
    const b = load({ url: srv.base + '/', config: { scope: { include: ['10.44.0.0/16'], sources: [{ type: 'url', url: '/bb-ip.txt', header: 'X-Client-IP' }] } } });
    await run(b);
    assert.equal(b.sent[0].ip, '10.44.0.8');
    assert.ok(srv.hits.filter((h) => h.startsWith('/bb-ip?_bb=')).length === 1, 'echo request is cache-busted');
    const c = load({ url: srv.base + '/', config: { scope: { include: ['10.44.0.0/16'], sources: [{ type: 'url', url: '/missing' }, { type: 'url', url: '/bb-ip' }] } } });
    await run(c);
    assert.equal(c.sent[0].ip, '10.44.0.7', 'falls through to next source on 404');
  } finally { srv.s.close(); }
});

test('policy feed: overrides embedded floors, cached, falls back when broken', async () => {
  let body = JSON.stringify({ id: 'feed-2026-11-03', issued: new Date().toISOString().slice(0, 10), browsers: { chrome: [{ channel: 'stable', minimum: '157.0.8103.30' }] } });
  const srv = await server({ '/policy.json': (q, r) => { r.writeHead(200, { 'Content-Type': 'application/json' }); r.end(body); } });
  try {
    const h = hints('Google Chrome', '156.0.8078.80');
    const cfg = { scope: OK_CFG.scope, policy: { feedUrl: '/policy.json' } };
    const a = load({ url: srv.base + '/', ip: '10.1.1.1', ua: UA.chromeWin, hints: h, config: cfg });
    await run(a);
    assert.equal(a.sent[0].pid, 'feed-2026-11-03'); assert.equal(a.sent[0].psrc, 'feed');
    assert.equal(a.sent[0].vrd, 'outdated'); assert.equal(a.sent[0].min, '157.0.8103.30');
    await run(a);
    assert.equal(a.sent[1].psrc, 'feed-cache');
    body = '{not json';
    const b = load({ url: srv.base + '/', ip: '10.1.1.1', ua: UA.chromeWin, hints: h, config: cfg });
    await run(b);
    assert.equal(b.sent[0].psrc, 'embedded-fallback'); assert.equal(b.sent[0].vrd, 'current');
    body = JSON.stringify({ id: 'bad', browsers: { chrome: [{ minimum: 'soon' }] } });
    const c = load({ url: srv.base + '/', ip: '10.1.1.1', ua: UA.chromeWin, hints: h, config: cfg });
    await run(c);
    assert.equal(c.sent[0].psrc, 'embedded-fallback', 'invalid feed rejected');
  } finally { srv.s.close(); }
});

/* ------------------------------------------------------------------ */
function stubImage(w, log) {
  w.Image = function () { const img = { set src(v) { log.push({ src: v, rp: img.referrerPolicy }); setTimeout(() => img.onload && img.onload(), 1); } }; return img; };
}

test('pixel transport: query string, no raw UA, referrer suppressed, truncation under maxUrlLength', async () => {
  const log = [];
  const env = load({ ip: '10.1.1.1', ua: UA.firefox158, before: (w) => stubImage(w, log), config: { scope: OK_CFG.scope, transport: { mode: 'pixel', endpoint: '/browser-beacon.gif' } } });
  const { status } = await run(env);
  assert.equal(status, 'sent');
  assert.equal(log.length, 1);
  const u = new URL(log[0].src, 'https://portal.example.com');
  assert.equal(u.pathname, '/browser-beacon.gif');
  assert.equal(u.searchParams.get('v'), '1');
  assert.equal(u.searchParams.get('bk'), 'firefox');
  assert.equal(u.searchParams.get('vrd'), 'outdated');
  assert.equal(u.searchParams.get('ua'), null);
  assert.equal(log[0].rp, 'no-referrer');
  assert.ok(u.searchParams.get('_'));
  // truncation
  const log2 = [];
  const long = 'x'.repeat(120);
  const env2 = load({ ip: '10.1.1.1', ua: UA.chromeWin, hints: hints('Google Chrome', '156.0.8078.80'), head: `<meta name="portal-user" content="${long}">`, before: (w) => stubImage(w, log2),
    config: { scope: OK_CFG.scope, user: { sources: [{ type: 'meta', name: 'portal-user' }] }, collect: { screen: true, hardware: true, rawUserAgent: true }, transport: { mode: 'pixel', endpoint: '/browser-beacon.gif', maxUrlLength: 700 } } });
  await run(env2);
  const u2 = new URL(log2[0].src, 'https://portal.example.com');
  assert.ok(log2[0].src.length <= 700, 'length ' + log2[0].src.length);
  assert.equal(u2.searchParams.get('trunc'), '1');
  assert.equal(u2.searchParams.get('ua'), null, 'ua dropped first');
  assert.equal(u2.searchParams.get('vrd'), 'current', 'essential fields kept');
  assert.equal(u2.searchParams.get('usr'), long);
});

test('beacon transport posts JSON via sendBeacon', async () => {
  const calls = [];
  const env = load({ ip: '10.1.1.1', ua: UA.safari271, before: (w) => { w.navigator.sendBeacon = (url, body) => { calls.push([url, body]); return true; }; },
    config: { scope: OK_CFG.scope, transport: { mode: 'beacon', endpoint: '/collect' } } });
  assert.equal((await run(env)).status, 'sent');
  assert.equal(calls[0][0], '/collect');
  const body = JSON.parse(calls[0][1]);
  assert.equal(body.bk, 'safari'); assert.equal(body.vrd, 'outdated'); assert.ok(body.ua.includes('Version/27.1'));
});

test('throttle: unchanged browser is not re-reported; version change is', async () => {
  const h = hints('Google Chrome', '156.0.8078.80');
  const first = load({ ip: '10.1.1.1', ua: UA.chromeWin, hints: h, config: { scope: OK_CFG.scope, autoRun: true } });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(first.sent.length, 1, 'autorun sent');
  const last = first.w.localStorage.getItem('bb_last');
  assert.ok(last);
  const second = load({ ip: '10.1.1.1', ua: UA.chromeWin, hints: h, before: (w) => w.localStorage.setItem('bb_last', last), config: { scope: OK_CFG.scope, autoRun: true } });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(second.sent.length, 0, 'throttled');
  const third = load({ ip: '10.1.1.1', ua: UA.chromeWin, hints: hints('Google Chrome', '156.0.8078.90'), before: (w) => w.localStorage.setItem('bb_last', last), config: { scope: OK_CFG.scope, autoRun: true } });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(third.sent.length, 1, 'patched browser reports immediately');
});

test('report.include=non-current skips current browsers', async () => {
  const a = load({ ip: '10.1.1.1', ua: UA.firefox159, config: { scope: OK_CFG.scope, report: { include: 'non-current' } } });
  assert.equal((await run(a)).status, 'current-not-reported'); assert.equal(a.sent.length, 0);
  const b = load({ ip: '10.1.1.1', ua: UA.firefox158, config: { scope: OK_CFG.scope, report: { include: 'non-current' } } });
  assert.equal((await run(b)).status, 'sent');
});

test('notice: text only, unsafe link ignored, dismiss remembered', async () => {
  const env = load({ ip: '10.1.1.1', ua: UA.firefox158, config: { scope: OK_CFG.scope, notice: { enabled: true, text: '<b>{browser} {version}</b> is old', linkText: 'Update', linkUrl: 'javascript:alert(1)' } } });
  await run(env);
  const bar = env.w.document.querySelector('[data-browser-beacon="notice"]');
  assert.ok(bar);
  assert.ok(bar.textContent.includes('<b>Firefox 158.0</b> is old'));
  assert.equal(bar.querySelector('b'), null, 'no HTML injection');
  assert.equal(bar.querySelector('a'), null, 'javascript: link refused');
  bar.querySelector('button').click();
  assert.equal(env.w.document.querySelector('[data-browser-beacon="notice"]'), null);
  assert.ok(env.w.localStorage.getItem('bb_notice'));
  const ok = load({ ip: '10.1.1.1', ua: UA.firefox158, config: { scope: OK_CFG.scope, notice: { enabled: true, linkText: 'How to update', linkUrl: '/help/browser' } } });
  await run(ok);
  assert.equal(ok.w.document.querySelector('[data-browser-beacon="notice"] a').getAttribute('href'), '/help/browser');
  const cur = load({ ip: '10.1.1.1', ua: UA.firefox159, config: { scope: OK_CFG.scope, notice: { enabled: true } } });
  await run(cur);
  assert.equal(cur.w.document.querySelector('[data-browser-beacon="notice"]'), null, 'no notice for current');
});

test('extension watch list: DOM and global markers', async () => {
  const env = load({ ip: '10.1.1.1', body: '<div data-example-ext="1"></div>', before: (w) => { w.__RISKY_EXT__ = {}; },
    config: { scope: OK_CFG.scope, extensions: { enabled: true, watchList: [
      { name: 'Example DOM', selector: '[data-example-ext]' }, { name: 'Example Global', global: '__RISKY_EXT__' }, { name: 'Absent', selector: '#nope' }] } } });
  await run(env);
  assert.deepEqual(env.sent[0].ext.split(',').sort(), ['Example DOM', 'Example Global']);
});

test('no globals leak and jQuery is not touched', async () => {
  const env = load({ ip: '10.1.1.1', before: (w) => { w.jQuery = function () {}; w.__before = Object.keys(w); } });
  const added = Object.keys(env.w).filter((k) => !env.w.__before.includes(k) && k !== '__before' && k !== 'BrowserBeaconConfig');
  assert.deepEqual(added.sort(), ['BrowserBeacon']);
  assert.equal(env.w.jQuery.ua, undefined);
  assert.equal(env.w.UAParser, undefined); assert.equal(env.w.ipaddr, undefined);
});

test('calls made while a run is in flight are queued, not dropped', async () => {
  const env = load({ ip: '10.1.1.1', ua: UA.firefox158, config: { scope: OK_CFG.scope, user: { sources: [{ type: 'function', fn: (cb) => setTimeout(() => cb('slow'), 50) }] } } });
  const [a, b] = await Promise.all([run(env), run(env, 'preview')]);
  assert.equal(a.status, 'sent');
  assert.equal(b.status, 'dry-run');
  assert.equal(b.rec.usr, 'slow');
});

test('device cookie is opt-in and restores a cleared localStorage id', async () => {
  const a = load({ ip: '10.1.1.1', config: { scope: OK_CFG.scope, device: { cookie: true } } });
  await run(a);
  const did = a.sent[0].did;
  assert.ok(a.w.document.cookie.includes('bb_did=' + did));
  const b = load({ ip: '10.1.1.1', before: (w) => { w.document.cookie = 'bb_did=' + did + '; path=/'; }, config: { scope: OK_CFG.scope, device: { cookie: true } } });
  await run(b);
  assert.equal(b.sent[0].did, did);
});

test('time zone: UTC offset by default, IANA name only when opted in', async () => {
  const a = load({ ip: '10.1.1.1', config: OK_CFG });
  await run(a);
  assert.ok('tzo' in a.sent[0]); assert.equal(a.sent[0].tz, undefined);
  const b = load({ ip: '10.1.1.1', config: { scope: OK_CFG.scope, collect: { timezoneName: true } } });
  await run(b);
  assert.ok(b.sent[0].tz && b.sent[0].tz.length > 0);
});

test('lease: a second tab inside the lease window stays quiet even if the first send failed', async () => {
  const first = load({ ip: '10.1.1.1', ua: UA.firefox158, config: { scope: OK_CFG.scope, transport: { mode: 'callback', callback: () => { throw new Error('collector down'); } } } });
  assert.equal((await run(first)).status, 'send-failed');
  const last = first.w.localStorage.getItem('bb_last');
  assert.ok(last, 'lease written');
  const second = load({ ip: '10.1.1.1', ua: UA.firefox158, before: (w) => w.localStorage.setItem('bb_last', last), config: { scope: OK_CFG.scope, autoRun: true } });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(second.sent.length, 0, 'held by lease');
  const expired = JSON.parse(last); expired.t -= 121000;
  const third = load({ ip: '10.1.1.1', ua: UA.firefox158, before: (w) => w.localStorage.setItem('bb_last', JSON.stringify(expired)), config: { scope: OK_CFG.scope, autoRun: true } });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(third.sent.length, 1, 'retried after the lease lapsed');
});

test('out-of-scope page views write nothing to localStorage', async () => {
  const env = load({ ip: '11.1.1.1', ua: UA.chromeWin, config: { scope: { include: ['10.0.0.0/8'] }, autoRun: true } });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(env.w.localStorage.length, 0);
});

test('prerendered page waits until it is shown', async () => {
  let prerendering = true;
  const env = load({ ip: '10.1.1.1', before: (w) => { Object.defineProperty(w.document, 'prerendering', { configurable: true, get: () => prerendering }); }, config: { scope: OK_CFG.scope, autoRun: true } });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(env.sent.length, 0, 'nothing while prerendering');
  prerendering = false;
  env.w.document.dispatchEvent(new env.w.Event('prerenderingchange'));
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(env.sent.length, 1);
});

test('starts after maxWaitForLoadMs if window load never fires', async () => {
  const env = load({ ip: '10.1.1.1', before: (w) => {
    Object.defineProperty(w.document, 'readyState', { configurable: true, get: () => 'interactive' });
    const add = w.addEventListener.bind(w); w.addEventListener = (type, fn, o) => { if (type !== 'load') { add(type, fn, o); } };
  }, config: { scope: OK_CFG.scope, autoRun: true, report: { maxWaitForLoadMs: 150 } } });
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(env.sent.length, 0);
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(env.sent.length, 1);
});

test('WebRTC: a browser that hides local IPs is not probed again for localIpsRetryDays', async () => {
  let created = 0;
  function FakePC() { created++; const self = this; this.close = () => {}; this.createDataChannel = () => {};
    this.createOffer = () => Promise.resolve({}); this.setLocalDescription = () => { setTimeout(() => {
      self.onicecandidate && self.onicecandidate({ candidate: { candidate: 'candidate:1 1 udp 2113937151 0b6b9c4e-5d6f-4a2b-9f6e-1a2b3c4d5e6f.local 54321 typ host' } });
      self.onicecandidate && self.onicecandidate({ candidate: null }); }, 5); return Promise.resolve(); }; }
  const a = load({ ip: '10.1.1.1', before: (w) => { w.RTCPeerConnection = FakePC; }, config: OK_CFG });
  await run(a);
  assert.equal(created, 1); assert.equal(a.sent[0].lip, undefined);
  const neg = a.w.localStorage.getItem('bb_rtc');
  assert.ok(neg);
  const b = load({ ip: '10.1.1.1', before: (w) => { w.RTCPeerConnection = FakePC; w.localStorage.setItem('bb_rtc', neg); }, config: OK_CFG });
  await run(b);
  assert.equal(created, 1, 'not created again');
  // a browser that does expose addresses keeps reporting them
  function RealPC() { FakePC.call(this); const self = this; this.setLocalDescription = () => { setTimeout(() => {
    self.onicecandidate({ candidate: { candidate: 'candidate:1 1 udp 2113937151 10.20.30.40 54321 typ host' } }); self.onicecandidate({ candidate: null }); }, 5); return Promise.resolve(); }; }
  const c = load({ ip: '10.1.1.1', before: (w) => { w.RTCPeerConnection = RealPC; }, config: OK_CFG });
  await run(c);
  assert.equal(c.sent[0].lip, '10.20.30.40'); assert.equal(c.w.localStorage.getItem('bb_rtc'), null);
});

/* ---------------- v1.2: destinations, http receiver, local log, backoff ---------------- */
const DCFG = (dests, extra) => Object.assign({ scope: OK_CFG.scope, transport: null, destinations: dests }, extra || {});

test('multiple destinations each receive the report; local log records per-destination result', async () => {
  const got = [];
  const env = load({ ip: '10.1.1.1', ua: UA.firefox158, config: DCFG([
    { type: 'callback', name: 'siem', callback: (r) => got.push(['siem', r]) },
    { type: 'callback', callback: (r) => got.push(['second', r]) },
    { type: 'local' }
  ]) });
  assert.equal(env.BB.configErrors.length, 0, String(env.BB.configErrors));
  assert.equal((await run(env)).status, 'sent');
  assert.deepEqual(got.map((g) => g[0]).sort(), ['second', 'siem']);
  const log = env.BB.log();
  assert.equal(log.length, 1);
  assert.equal(log[0]._delivered, 1);
  assert.equal(log[0]._to, 'siem:ok,callback#2:ok');
  assert.equal(log[0].vrd, 'outdated');
  assert.ok(log[0].ua, 'raw UA kept outside pixel requests');
});

test('successWhen any vs all', async () => {
  const dests = () => [{ type: 'callback', callback: () => {} }, { type: 'callback', callback: () => { throw new Error('down'); } }];
  const a = load({ ip: '10.1.1.1', config: DCFG(dests(), { delivery: { successWhen: 'any' } }) });
  assert.equal((await run(a)).status, 'sent');
  const b = load({ ip: '10.1.1.1', config: DCFG(dests(), { delivery: { successWhen: 'all' } }) });
  assert.equal((await run(b)).status, 'send-failed');
});

test('local-only destination: no network, delivered, log trimmed by count, size and age', async () => {
  const env = load({ ip: '10.1.1.1', config: DCFG([{ type: 'local' }], { localLog: { maxEntries: 3, maxKB: 64, maxDays: 30 } }) });
  const old = { _logged: '2026-01-01T00:00:00.000Z', _delivered: 1, _to: '', vrd: 'current' };
  env.w.localStorage.setItem('bb_log', JSON.stringify([old]));
  for (let i = 0; i < 5; i++) { assert.equal((await run(env)).status, 'sent'); }
  const log = env.BB.log();
  assert.equal(log.length, 3, 'maxEntries');
  assert.ok(log.every((e) => e._logged !== old._logged), 'entries older than maxDays dropped');
  const small = load({ ip: '10.1.1.1', config: DCFG([{ type: 'local' }], { localLog: { maxEntries: 100, maxKB: 2, maxDays: 30 } }) });
  for (let i = 0; i < 6; i++) { await run(small); }
  assert.ok(small.w.localStorage.getItem('bb_log').length <= 2048, 'maxKB');
  assert.ok(small.BB.log().length >= 1);
  small.BB.clearLog();
  assert.equal(small.BB.log().length, 0);
});

test('downloadLog saves one JSON record per line (anchor download and IE msSaveOrOpenBlob)', async () => {
  let blob = null, clicked = null;
  const env = load({ ip: '10.1.1.1', ua: UA.chromeWin, config: DCFG([{ type: 'local' }]), before: (w) => {
    w.URL.createObjectURL = (b) => { blob = b; return 'blob:test'; }; w.URL.revokeObjectURL = () => {};
    w.HTMLAnchorElement.prototype.click = function () { clicked = { href: this.href, download: this.download }; };
  } });
  assert.equal(env.BB.downloadLog(), 0, 'empty log: nothing to save');
  await run(env); await run(env);
  assert.equal(env.BB.downloadLog(), 2);
  assert.match(clicked.download, /^browser-beacon-portal\.example\.com-\d{8}T\d{6}\.jsonl$/);
  const lines = (await blob.text()).trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(lines.length, 2); assert.equal(lines[0].bk, 'chrome'); assert.ok(lines[0]._logged);
  let ie = null;
  const env2 = load({ ip: '10.1.1.1', config: DCFG([{ type: 'local' }]), before: (w) => { w.navigator.msSaveOrOpenBlob = (b, n) => { ie = n; return true; }; } });
  await run(env2);
  assert.equal(env2.BB.downloadLog('custom.jsonl'), 1); assert.equal(ie, 'custom.jsonl');
});

test('backoff: repeated delivery failures wait longer before retrying', async () => {
  const failing = [{ type: 'callback', callback: () => { throw new Error('down'); } }];
  const env = load({ ip: '10.1.1.1', ua: UA.firefox158, config: DCFG(failing, { delivery: { retryMinutes: [2, 10, 30] } }) });
  const hold = () => { const l = JSON.parse(env.w.localStorage.getItem('bb_last')); return { n: l.n, minutes: Math.round((l.t + 24 * 3600000 - Date.now()) / 60000) }; };
  await run(env); assert.deepEqual(hold(), { n: 1, minutes: 2 });
  await run(env); assert.deepEqual(hold(), { n: 2, minutes: 10 });
  await run(env); assert.deepEqual(hold(), { n: 3, minutes: 30 });
  await run(env); assert.deepEqual(hold(), { n: 4, minutes: 30 }, 'stays at the last step');
  env.w.BrowserBeaconConfig = null;
});

test('destination validation: mixed content, bad scheme, noCors rules; secret-looking headers warn', () => {
  const bad = [
    [{ type: 'http', url: 'http://collector.example.com/b' }],            // https page -> mixed content
    [{ type: 'pixel', url: 'javascript:alert(1)' }],
    [{ type: 'http', url: '/b', format: 'xml' }],
    [{ type: 'http', url: '/b', noCors: true }],                          // json + noCors
    [{ type: 'http', url: '/b', format: 'text', noCors: true, headers: { 'X-A': '1' } }],
    [{ type: 'http' }],
    [{ type: 'callback' }],
    [{ type: 'smoke', url: '/b' }],
    []
  ];
  for (const d of bad) { assert.ok(load({ config: DCFG(d) }).BB.configErrors.length >= 1, JSON.stringify(d)); }
  const ok = load({ url: 'http://intranet.example.com/', config: DCFG([{ type: 'http', url: 'http://collector.example.com/b', format: 'text', noCors: true }]) });
  assert.equal(ok.BB.configErrors.length, 0, 'http collector allowed from an http page');
  const w = load({ config: DCFG([{ type: 'http', url: '/b', headers: { Authorization: 'Bearer x' } }]) });
  assert.equal(w.BB.configErrors.length, 0);
  assert.ok(w.warnings.some((m) => /Authorization.*readable by anyone/.test(m)));
});

test('http destination over XHR: json, text and form bodies reach the receiver', async () => {
  const bodies = [];
  const srv = await server({ '/collect': (q, r) => { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { bodies.push({ type: q.headers['content-type'], body: b }); r.writeHead(204); r.end(); }); } });
  try {
    for (const format of ['json', 'text', 'form']) {
      const env = load({ url: srv.base + '/', ip: '10.1.1.1', ua: UA.firefox158, config: DCFG([{ type: 'http', url: '/collect', format }]) });
      assert.equal((await run(env)).status, 'sent', format);
    }
    assert.match(bodies[0].type, /^application\/json/); assert.equal(JSON.parse(bodies[0].body).vrd, 'outdated');
    assert.match(bodies[1].type, /^text\/plain/); assert.equal(JSON.parse(bodies[1].body).bk, 'firefox');
    assert.match(bodies[2].type, /^application\/x-www-form-urlencoded/);
    assert.equal(new URLSearchParams(bodies[2].body).get('vrd'), 'outdated');
    const down = load({ url: srv.base + '/', ip: '10.1.1.1', config: DCFG([{ type: 'http', url: '/nope' }]) });
    assert.equal((await run(down)).status, 'send-failed', '404 is a failed delivery');
  } finally { srv.s.close(); }
});

test('survives storage that throws and loads only once', async () => {
  const env = load({ ip: '10.1.1.1', ua: UA.chromeWin, config: OK_CFG, before: (w) => {
    Object.defineProperty(w, 'localStorage', { get() { throw new Error('denied'); } });
    Object.defineProperty(w, 'sessionStorage', { get() { throw new Error('denied'); } });
  } });
  const { status } = await run(env);
  assert.equal(status, 'sent');
  const first = env.w.BrowserBeacon;
  env.w.eval(require('./helpers').testScript);
  assert.equal(env.w.BrowserBeacon, first, 'second include is a no-op');
});

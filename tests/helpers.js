'use strict';
const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');

const DIST = path.join(__dirname, '..', 'dist', 'browser-beacon.js');
const raw = fs.readFileSync(DIST, 'utf8');
// Test copy: only change is allowing window.BrowserBeaconConfig to override CONFIG.
const needle = 'allowPageOverride: false,';
if (raw.split(needle).length !== 2) { throw new Error('override flag not found exactly once'); }
const testScript = raw.replace(needle, 'allowPageOverride: true,');

const UA = {
  chromeWin: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
  chromeWin154: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36',
  chromeWin7: 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
  edgeWin: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0',
  edgeLegacy: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19041',
  ie11: 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
  firefox159: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0',
  firefox158: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0',
  firefox153: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0',
  firefox115win7: 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0',
  firefox160beta: 'Mozilla/5.0 (X11; Linux x86_64; rv:160.0) Gecko/20100101 Firefox/160.0',
  safari272: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15',
  safari271: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.1 Safari/605.1.15',
  safari264: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.4 Safari/605.1.15',
  opera: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 OPR/141.0.0.0',
  operaOld: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 OPR/136.0.0.0',
  iphone: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Mobile/15E148 Safari/604.1',
  android: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36',
  headless: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/156.0.0.0 Safari/537.36'
};

function fvl(list) { return list.map(([b, v]) => ({ brand: b, version: v })); }
function hints(brand, full, opts) {
  opts = opts || {};
  const chromium = opts.chromium || full;
  const list = [['Not)A;Brand', '99.0.0.0']];
  if (brand !== 'Chromium') { list.push([brand, full]); }
  list.push(['Chromium', chromium]);
  return {
    brands: fvl(list.map(([b, v]) => [b, v.split('.')[0]])),
    mobile: !!opts.mobile,
    platform: opts.platform || 'Windows',
    platformVersion: opts.platformVersion === undefined ? '15.0.0' : opts.platformVersion,
    architecture: 'x86', bitness: '64', model: '', wow64: false,
    fullVersionList: opts.lowOnly ? undefined : fvl(list)
  };
}

const BASE = {
  autoRun: false,
  scope: { include: ['10.0.0.0/8', '2001:db8:1200::/40'], exclude: ['10.250.0.0/16'], sources: [{ type: 'meta', name: 'browser-beacon-client-ip' }], cacheMinutes: 0 },
  report: { startDelayMs: 0, deadlineMs: 3000 },
  transport: { mode: 'callback' }
};

function deepMerge(a, b) {
  const out = Array.isArray(a) ? a.slice() : Object.assign({}, a);
  for (const k of Object.keys(b || {})) {
    if (b[k] && typeof b[k] === 'object' && !Array.isArray(b[k]) && typeof b[k] !== 'function' && a && typeof a[k] === 'object' && !Array.isArray(a[k])) {
      out[k] = deepMerge(a[k], b[k]);
    } else { out[k] = b[k]; }
  }
  return out;
}

// Load the beacon into a fresh jsdom window.
function load(o) {
  o = o || {};
  const warnings = [];
  const vc = new VirtualConsole();
  vc.on('warn', (m) => warnings.push(String(m)));
  vc.on('jsdomError', (e) => warnings.push('jsdomError ' + e.message));
  const meta = o.ip === undefined ? '' : `<meta name="browser-beacon-client-ip" content="${o.ip}">`;
  const dom = new JSDOM(`<!doctype html><html><head>${meta}${o.head || ''}</head><body>${o.body || ''}</body></html>`, {
    url: o.url || 'https://portal.example.com/home/index.aspx?token=SECRET',
    runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc
  });
  const w = dom.window;
  const sent = [];
  if (o.ua) { Object.defineProperty(w.navigator, 'userAgent', { value: o.ua, configurable: true }); }
  if (o.hints) {
    const h = o.hints;
    Object.defineProperty(w.navigator, 'userAgentData', {
      configurable: true,
      value: {
        brands: h.brands, mobile: h.mobile, platform: h.platform,
        getHighEntropyValues: () => Promise.resolve(Object.assign({}, h, { fullVersionList: h.fullVersionList }))
      }
    });
  }
  if (o.before) { o.before(w); }
  const cfg = deepMerge(JSON.parse(JSON.stringify(BASE)), o.config || {});
  if (cfg.transport && cfg.transport.mode === 'callback' && !cfg.transport.callback) { cfg.transport.callback = (r) => sent.push(r); }
  w.BrowserBeaconConfig = cfg;
  w.eval(o.script || testScript);
  return { dom, w, BB: w.BrowserBeacon, sent, warnings };
}

function run(env, method) {
  return new Promise((resolve) => env.BB[method || 'run']((rec, status) => resolve({ rec, status })));
}

module.exports = { raw, testScript, UA, hints, load, run, DIST };

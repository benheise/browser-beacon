/*!
 * browser-beacon.js v1.2.0 (policy 2026-11-01)
 * Outdated-browser telemetry for an internal web portal.
 *
 * One self-contained file. No server-side code, no runtime dependencies, no
 * third-party requests. Written in ES5 so it still runs on the old browsers it
 * exists to find. Every setting lives in the CONFIG block below.
 *
 * ---------------------------------------------------------------------------
 * WHAT HAPPENS ON EACH PAGE LOAD
 *   1. Local checks (no network): hostname allow-list, mobile skip, throttle.
 *   2. Scope: resolves the client IP from scope.sources and stops unless it is
 *      inside scope.include and not inside scope.exclude. Fails closed.
 *   3. Collects browser and OS identity (User-Agent string + User-Agent Client
 *      Hints), username (if a source is configured), a persistent device ID,
 *      local IPs (only when the browser exposes them) and optional extension
 *      watch-list hits.
 *   4. Judges the browser against the version policy and sends one record.
 *
 * DEPLOY
 *   1. Edit CONFIG (at minimum scope.include and scope.sources).
 *   2. Serve this file from the portal and add to the shared page layout:
 *        <script src="/assets/browser-beacon.js" async></script>
 *      Use async, not defer: deferred scripts run before DOMContentLoaded and
 *      hold it back; async scripts do not. Serve it compressed (gzip/br, ~39 KB)
 *      with a cache lifetime, ideally under a versioned name
 *      (browser-beacon.1.2.0.js, Cache-Control: max-age=31536000) so repeat
 *      page views load it from cache and reuse the browser's compiled code.
 *      To keep it out of the page's load event entirely, inject it after load
 *      instead (an inline script: needs a CSP nonce if inline scripts are blocked):
 *        <script>addEventListener('load',function(){var s=document.createElement(
 *        'script');s.src='/assets/browser-beacon.js';s.async=true;
 *        document.head.appendChild(s)})</script>
 *   3. The default destination is a 1x1 image request:
 *        GET /browser-beacon.gif?v=1&bk=chrome&bv=156.0.8078.73&vrd=current&...
 *      Every web server writes that to its access log with the server-observed
 *      client IP, the authenticated user (if the path requires auth), the time
 *      and the User-Agent header. Put any 1x1 GIF at that path to avoid 404
 *      noise; the request is logged either way. Parse the log to get the data.
 *      Other destinations (see "destinations" in CONFIG): POST to a receiving
 *      HTTP server, sendBeacon, a rolling log kept in the browser, a callback.
 *   4. Run BrowserBeacon.preview() in the browser console to see exactly what
 *      would be sent from that browser, without sending it.
 *
 * CLIENT IMPACT
 *   - Before the page finishes loading the script only defines its functions
 *     and registers one listener. Everything else, including config
 *     validation, waits for window load + report.startDelayMs + browser idle
 *     time, and is split into short tasks that yield to the page.
 *   - Page views inside report.intervalHours (the vast majority) stop after a
 *     throttle check: no parsing, no network, under a millisecond.
 *   - Network, all low priority: in scope, at most one IP-echo request (if
 *     configured) and one request per destination per browser per
 *     intervalHours, plus the policy feed once per feedTtlHours if used.
 *     Failed deliveries back off (delivery.retryMinutes). Out of scope, one
 *     echo request per tab per scope.cacheMinutes and nothing else.
 *   - No unload handlers, synchronous requests, document.write, polling,
 *     layout reads, input listeners or third-party requests. The WebRTC
 *     connection is closed as soon as gathering ends.
 *   - Waits while a page is prerendered, and a short cross-tab lease stops
 *     several portal tabs opened together from each running a full report.
 *   - Does not block the back/forward cache.
 *
 * RECEIVING HTTP SERVER (destination type "http")
 *   Receives one POST per report: the record below as a flat JSON object
 *   (format "json" or "text") or as key=value pairs (format "form"), under 4 KB.
 *   Reply with any 2xx. Fetch keepalive is used, so a report already sent
 *   completes even if the user navigates away. A different origin from the
 *   portal needs CORS on the receiver:
 *     OPTIONS -> 204 with Access-Control-Allow-Origin: <portal origin>,
 *                Access-Control-Allow-Methods: POST,
 *                Access-Control-Allow-Headers: Content-Type (plus any custom headers)
 *     POST    -> 2xx with Access-Control-Allow-Origin: <portal origin>
 *     credentials 'include' also needs Access-Control-Allow-Credentials: true.
 *   Format "text" or "form" with no custom headers skips the OPTIONS request.
 *   Take the client IP from the connection (not from the body), apply the
 *   scope ranges again, and treat every field as untrusted input.
 *
 * TRUST
 *   Everything this script reports is client-asserted and can be edited by the
 *   person at the keyboard. The scope check here is a privacy/noise filter, not
 *   a security control: apply the same CIDR list again when ingesting logs, and
 *   prefer the server-logged IP and authenticated user over "ip" and "usr".
 *
 * GETTING THE CLIENT IP (scope.sources)
 *   Page JavaScript cannot see its own address the way the server does, so the
 *   page must be told. Use whichever fits the server:
 *     a) Server-side templating writes it into the page:
 *          <meta name="browser-beacon-client-ip" content="<client address>">
 *     b) A same-origin URL that echoes it (source type "url"). Examples:
 *          nginx : location = /bb-ip { default_type text/plain; return 200 $remote_addr; }
 *          Apache: <Location "/bb-ip.txt">
 *                    Header always set X-Client-IP "expr=%{REMOTE_ADDR}"
 *                  </Location>          (2.4.10+; serve any small file there)
 *          IIS   : file bb-ip.stm containing  <!--#echo var="REMOTE_ADDR"-->
 *                  (needs the Server Side Includes role service)
 *        Behind a load balancer, echo the client address the server resolved
 *        (nginx realip, Apache mod_remoteip), not the raw X-Forwarded-For.
 *     c) WebRTC local addresses. Browsers hide these as random *.local names
 *        unless a managed policy exposes them for this origin, so expect this
 *        to work only on managed devices. Do not rely on it with broad RFC 1918
 *        include ranges: a home network's 192.168.x.x would match.
 *
 * RECORD FIELDS (query-string keys; empty values are omitted)
 *   v       schema version          sv     script version
 *   pid     policy id               psrc   policy source (embedded|feed|...)
 *   ts      client time (ISO 8601)  rid    random report id
 *   did     persistent device id (per browser profile; localStorage + cookie)
 *   host    page hostname           pg     page path (no query string)
 *   scope   in|unknown|disabled     ip     IP used for the scope decision
 *   ipsrc   where ip came from      lip    local IPs seen via WebRTC
 *   usr     username (client-claimed)      usrsrc where usr came from
 *   bk      browser key: chrome|edge|firefox|safari|opera|brave|vivaldi|
 *           yandex|samsung|chromium|ie|edge-legacy|other
 *   bn      browser name            bv     browser version (best available)
 *   bvp     version precision: full|major
 *   bvs     version source: uach (Client Hints) | ua (User-Agent string)
 *   cv      Chromium engine version (Chromium-based browsers)
 *   eng     engine                  brands Client Hints brand list
 *   os      OS name (e.g. Windows 11; "Windows 10/11" when indistinguishable)
 *   osv     OS version              osvrd  supported|unsupported|unknown
 *   arch    CPU architecture        bit    bitness       wow64  1|0
 *   model   device model            mob    1 = mobile
 *   vrd     verdict: current|outdated|unsupported|unverified|unknown
 *   rsn     reason code             chan   matched release channel
 *   min     minimum for that channel        behind majors behind
 *   basis   browser|engine (engine = judged on Chromium version)
 *   spoof   1 = User-Agent and Client Hints disagree
 *   ext     extension watch-list hits
 *   tz/tzo  time zone / UTC offset  lang   browser language
 *   scr     screen (opt-in)         hw     cores/memory (opt-in)
 *   ua      raw User-Agent (left out of pixel requests; the access log has it)
 *   trunc   1 = optional fields dropped to fit delivery.maxUrlLength (pixel)
 *
 * VERDICTS
 *   current      at or above the minimum for its channel
 *   outdated     below the minimum, or a major version that no channel serves
 *   unsupported  browser family listed in policy.unsupported (e.g. IE)
 *   unverified   patch level cannot be confirmed (channels marked
 *                ifPatchUnknown: 'unverified', e.g. Firefox ESR), or the policy
 *                is older than policy.maxAgeDays
 *   unknown      no policy for this browser, or no version detected
 *
 * Third-party code bundled at the end of this file (unmodified, MIT):
 *   UAParser.js 1.0.41 and ipaddr.js 1.9.1. License notices at the end.
 */
;(function (root) {
  if (!root || !root.document || !root.navigator) { return; }
  if (root.BrowserBeacon && root.BrowserBeacon.version) { return; } // loaded twice

  /* =========================================================================
   * CONFIG - the only part of this file that should need editing
   * ========================================================================= */
  var CONFIG = {
    enabled: true,
    autoRun: true,               // run on page load; false = only BrowserBeacon.run()
    debug: false,                // console diagnostics
    allowPageOverride: false,    // true = merge window.BrowserBeaconConfig over CONFIG
                                 // (one copy of this file, per-portal settings)

    // Only run on these hostnames. Exact names or "*.suffix". [] = any host.
    allowedHostnames: [
      // 'portal.example.com', '*.intranet.example.com'
    ],

    // ---- Scope: company IP ranges --------------------------------------
    scope: {
      enabled: true,             // false = report from anywhere (explicit override)
      include: [
        // REQUIRED. Company ranges as IPv4/IPv6 CIDR (a bare address = /32 or /128).
        // The script stays off and warns in the console while this is empty.
        // '10.20.0.0/16', '172.18.0.0/15', '2001:db8:1200::/40'
      ],
      exclude: [
        // '10.20.250.0/24'      // guest Wi-Fi, labs, etc.
      ],
      // Tried in order; the first source that yields a valid IP decides.
      // Types: meta | url | global | dom | cookie | storage | function | webrtc
      sources: [
        { type: 'meta', name: 'browser-beacon-client-ip' },
        // { type: 'url', url: '/bb-ip' },                          // IP in body
        // { type: 'url', url: '/bb-ip.txt', header: 'X-Client-IP' }, // IP in header
        { type: 'webrtc' }
      ],
      onUnknown: 'skip',         // no IP found: 'skip' (fail closed) | 'report' (scope=unknown)
      timeoutMs: 1500,           // per source
      cacheMinutes: 60           // reuse the scope decision this long (sessionStorage, ends with the tab)
    },

    // ---- Username (optional) -------------------------------------------
    // Best source is the server log: protect the pixel/http URL with the same
    // authentication as the portal and the log records the real user. These
    // sources add a client-side claim as well. First non-empty value wins.
    user: {
      sources: [
        // { type: 'meta', name: 'portal-user' },
        // { type: 'url', url: '/api/me', jsonPath: 'userPrincipalName' },
        // { type: 'dom', selector: '#current-user', pattern: 'Welcome,\\s*(.+)' },
        // { type: 'global', path: 'portalContext.user.login' },
        // { type: 'cookie', name: 'username' },
        // { type: 'function', fn: function (cb) { cb(window.myPortal.currentUser()); } }
      ],
      timeoutMs: 1500
    },

    // ---- Device identifier ---------------------------------------------
    device: {
      idKey: 'bb_did',           // localStorage key and cookie name
      cookie: false,             // also keep it in a first-party cookie (survives storage-only
                                 // clears, but the cookie then rides on every portal request)
      cookieDays: 395            // browsers cap cookie lifetime around 400 days
    },

    // ---- Version policy ------------------------------------------------
    // Each browser lists release channels. The first entry is the main channel:
    // any newer major version passes, the same major must meet "minimum".
    // Later entries (extended stable, ESR) apply only to their own major.
    // ifPatchUnknown: verdict when only the major version is known (Firefox
    // never reports more; Chromium does when Client Hints are unavailable).
    policy: {
      id: '2026-11-01',
      issued: '2026-11-01',      // YYYY-MM-DD; "current" becomes "unverified" after maxAgeDays
      maxAgeDays: 21,            // Chrome and Edge now ship a major every two weeks
      feedUrl: '',               // optional JSON with the same shape (id, issued, browsers, ...)
                                 // so floors can change without editing this file
      feedTtlHours: 12,
      browsers: {
        // Chrome 156.0.8078.73/.74 (27 Oct 2026, 52 security fixes). Build .80 followed 29 Oct.
        chrome: [
          { channel: 'stable',   minimum: '156.0.8078.73' },
          { channel: 'extended', minimum: '152.0.7977.167' }   // 13 Oct 2026
        ],
        // Edge 156.0.4314.58 (30 Oct 2026). Add your Extended Stable floor if you use it.
        edge: [
          { channel: 'stable',   minimum: '156.0.4314.58' }
          // , { channel: 'extended', minimum: '' }
        ],
        // Firefox puts only the major version in its User-Agent (159.0.1 reads "159.0").
        // ESR 153 cannot be told apart from an un-updated Release 153, hence unverified.
        firefox: [
          { channel: 'release', minimum: '159' },                              // 27 Oct 2026
          { channel: 'esr',     minimum: '153', ifPatchUnknown: 'unverified' }, // 153.6.0
          { channel: 'esr115',  minimum: '115', ifPatchUnknown: 'unverified' }  // Win 7-8.1 / old macOS, to Mar 2027
        ],
        safari: [
          { channel: 'release', minimum: '27.2' }                               // 26 Oct 2026
        ],
        // Fallback for other Chromium-based browsers (Brave, Vivaldi, Opera, Chromium,
        // unknown brands): judged on the Chromium engine version.
        chromium: [
          { channel: 'engine', minimum: '155' }
        ]
      },
      unsupported: ['ie', 'edge-legacy'],  // always "unsupported"
      unknownBrowser: 'unknown',           // verdict when no policy matches
      os: {
        unsupported: ['Windows XP', 'Windows Vista', 'Windows 7', 'Windows 8', 'Windows 8.1']
        // add 'Windows 10' if you are not enrolled in Extended Security Updates
      }
    },

    // ---- What to report ------------------------------------------------
    report: {
      include: 'all',            // 'all' (needed to see remediation) | 'non-current'
      intervalHours: 24,         // re-report an unchanged browser at most this often;
                                 // a version or policy change reports on the next visit
      startDelayMs: 2000,        // wait after window load before doing anything
      deadlineMs: 6000,          // overall time budget for collection
      maxWaitForLoadMs: 30000    // start anyway if window load has not fired by then
    },
    mobile: 'skip',              // phones/tablets: 'skip' | 'report'
    collect: {
      localIps: true,            // WebRTC local addresses (real values only where policy allows)
      localIpsRetryDays: 7,      // after a browser shows it hides them, skip WebRTC this long
      timezone: true,            // UTC offset (free)
      timezoneName: false,       // IANA zone name; opt-in because the first Intl call on a
                                 // page blocks the main thread for ~10 ms (60+ ms on slow PCs)
      language: true,
      screen: false,             // opt-in: helps tell apart devices behind one NAT address
      hardware: false,           // opt-in: CPU cores / device memory
      rawUserAgent: 'auto'       // 'auto' = include except in pixel requests (access log has it) | true | false
    },

    // ---- Extension watch list (optional, off by default) ---------------
    // Web pages cannot list installed extensions. This only checks for specific
    // extensions you name, and only those that expose something a page can see.
    // "Not detected" means unknown, not absent. Probing is a fingerprinting
    // technique: disclose it in the portal's monitoring notice before enabling.
    extensions: {
      enabled: false,
      timeoutMs: 1500,
      watchList: [
        // Chromium web-accessible resource (works only for resources without use_dynamic_url):
        // { name: 'Example Extension', id: 'abcdefghijklmnopabcdefghijklmnop', resource: 'img/icon.png' },
        // Element the extension injects into pages:
        // { name: 'Example Injector', selector: '[data-example-extension]' },
        // Global variable the extension defines in the page:
        // { name: 'Example Global', global: '__EXAMPLE_EXTENSION__' }
      ]
    },

    // ---- Where reports go ------------------------------------------------
    // Every report goes to each destination listed, in parallel. Types:
    //   pixel     image GET to url; any web server's access log records it
    //   http      POST to a receiving HTTP server (same origin, or another origin with CORS)
    //   beacon    navigator.sendBeacon POST of the JSON as text/plain (no custom headers)
    //   local     rolling log in this browser; save it with BrowserBeacon.downloadLog()
    //   callback  your function (record) { ... }   (in the destination: callback: fn)
    //   console   the browser's developer console
    destinations: [
      { type: 'pixel', url: '/browser-beacon.gif' }
      // , { type: 'http', url: 'https://collector.example.com/browser-beacon',
      //     format: 'json',              // 'json' | 'text' (JSON as text/plain) | 'form' (urlencoded)
      //     credentials: 'same-origin',  // 'include' also sends the user's cookies to another origin
      //     headers: {},                 // extra headers. This file is public: never put secrets here
      //     noCors: false }              // true: fire-and-forget to a receiver without CORS
      //                                  // (text/form only, no custom headers; reply not checked)
      // , { type: 'local' }
    ],
    delivery: {
      successWhen: 'any',        // a report counts as delivered when 'any' or 'all' of the
                                 // pixel/http/beacon/callback destinations succeed
      timeoutMs: 5000,           // per destination
      maxUrlLength: 2000,        // pixel; IIS rejects query strings over 2048 by default
      retryMinutes: [2, 10, 30, 60] // after a failed delivery wait this long before the next
                                 // attempt (1st, 2nd, 3rd, then every 60 min), so a collector
                                 // outage does not make every page view retry
    },

    // ---- Local log (used when destinations include { type: 'local' }) ----
    // Browsers do not let a web page write files to disk by itself. The log is kept
    // in this site's browser storage and saved as a file on request, e.g. from the
    // console:  BrowserBeacon.downloadLog()  ->  browser-beacon-<host>-<time>.jsonl
    // (one JSON record per line). Entries include username and IPs and are readable
    // by any script on this site.
    localLog: {
      maxEntries: 30,
      maxKB: 64,                 // keeps well inside the ~5 MB storage the site shares
      maxDays: 30
    },

    // ---- Optional notice to the user (off by default) -------------------
    notice: {
      enabled: false,
      verdicts: ['outdated', 'unsupported'],
      text: 'Your browser ({browser} {version}) is out of date. Please update it or contact the service desk.',
      linkText: '',              // e.g. 'How to update'
      linkUrl: '',               // http(s) or site-relative URL
      dismissHours: 24
    }
  };
  /* =========================================================================
   * END OF CONFIG
   * ========================================================================= */

  (function main() {
    'use strict';

    var VERSION = '1.2.0';
    var SCHEMA = 1;
    var doc = root.document;
    var nav = root.navigator;
    var loc = root.location || {};
    var KEY_LAST = 'bb_last', KEY_POLICY = 'bb_policy', KEY_SCOPE = 'bb_scope', KEY_NOTICE = 'bb_notice';
    var KEY_RTC = 'bb_rtc', KEY_LOG = 'bb_log';
    var LEASE_MS = 120000; // another tab that started a report holds the throttle this long
    var BLINK = { chrome: 1, edge: 1, opera: 1, brave: 1, vivaldi: 1, yandex: 1, samsung: 1, chromium: 1 };
    var BRAND_KEYS = {
      'Google Chrome': 'chrome', 'Microsoft Edge': 'edge', 'Opera': 'opera', 'Opera GX': 'opera',
      'Brave': 'brave', 'Vivaldi': 'vivaldi', 'Yandex': 'yandex', 'YaBrowser': 'yandex',
      'Samsung Internet': 'samsung', 'Chromium': 'chromium', 'HeadlessChrome': 'chromium'
    };
    var SOURCE_TYPES = { meta: 1, url: 1, global: 1, dom: 1, cookie: 1, storage: 1, 'function': 1, webrtc: 1 };
    var DEST_TYPES = { pixel: 1, http: 1, beacon: 1, local: 1, callback: 1, console: 1 };
    var COUNTS = { pixel: 1, http: 1, beacon: 1, callback: 1 }; // local and console are not delivery
    var WARNINGS = [];
    var VERDICTS = { current: 1, outdated: 1, unsupported: 1, unverified: 1, unknown: 1 };
    // Wire order for pixel mode; DROP lists optional fields removed first when too long.
    var FIELD_ORDER = ['v', 'sv', 'pid', 'psrc', 'ts', 'rid', 'did', 'host', 'pg', 'scope', 'ip', 'ipsrc',
      'usr', 'usrsrc', 'bk', 'bn', 'bv', 'bvp', 'bvs', 'cv', 'eng', 'os', 'osv', 'osvrd', 'arch', 'bit',
      'wow64', 'model', 'mob', 'vrd', 'rsn', 'chan', 'min', 'behind', 'basis', 'spoof', 'ext', 'lip',
      'tz', 'tzo', 'lang', 'scr', 'hw', 'brands', 'ua', 'trunc'];
    var DROP = ['ua', 'brands', 'hw', 'scr', 'lang', 'tzo', 'tz', 'lip', 'ext', 'model', 'pg', 'usrsrc', 'ipsrc', 'psrc'];
    var MAXLEN = { ua: 512, brands: 200, lip: 200, ext: 300, usr: 128, pg: 200 };

    var running = false;
    var queue = [];
    var webrtcMemo = null, webrtcFromCache = false;
    var keepAlive = [];
    var inited = false;

    /* ---------------- small helpers (ES5, old-browser safe) ---------------- */
    function noop() {}
    function now() { return new Date().getTime(); }
    function isArray(x) { return Object.prototype.toString.call(x) === '[object Array]'; }
    function isObj(x) { return x !== null && typeof x === 'object' && !isArray(x); }
    function isFn(x) { return typeof x === 'function'; }
    function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
    function trim(s) { return String(s).replace(/^\s+|\s+$/g, ''); }
    function indexOf(a, v) { if (!a) { return -1; } for (var i = 0; i < a.length; i++) { if (a[i] === v) { return i; } } return -1; }
    function keys(o) { var r = []; for (var k in o) { if (has(o, k)) { r.push(k); } } return r; }
    function merge(dst, src) {
      for (var k in src) {
        if (has(src, k)) {
          if (isObj(src[k]) && isObj(dst[k])) { merge(dst[k], src[k]); } else { dst[k] = src[k]; }
        }
      }
      return dst;
    }
    function getPath(obj, path) {
      var parts = String(path).split('.'), cur = obj;
      for (var i = 0; i < parts.length; i++) {
        if (cur === null || cur === undefined) { return undefined; }
        cur = cur[parts[i]];
      }
      return cur;
    }
    function clean(v, max) {
      if (v === null || v === undefined) { return ''; }
      var s = String(v).replace(/[\u0000-\u001f\u007f]+/g, ' ');
      s = trim(s);
      return s.length > (max || 160) ? s.substring(0, max || 160) : s;
    }
    function log() {
      if (!CONFIG.debug || !root.console || !root.console.log) { return; }
      try { root.console.log.apply(root.console, ['[browser-beacon]'].concat([].slice.call(arguments))); } catch (e) {}
    }
    function warn(msg) {
      if (root.console && root.console.warn) { try { root.console.warn('[browser-beacon] ' + msg); } catch (e) {} }
    }
    function uuid() {
      var b = [], i, c = root.crypto || root.msCrypto;
      if (c && c.getRandomValues && root.Uint8Array) {
        var a = new root.Uint8Array(16); c.getRandomValues(a);
        for (i = 0; i < 16; i++) { b.push(a[i]); }
      } else {
        for (i = 0; i < 16; i++) { b.push(Math.floor(Math.random() * 256)); }
      }
      b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
      var h = '';
      for (i = 0; i < 16; i++) {
        h += (b[i] < 16 ? '0' : '') + b[i].toString(16);
        if (i === 3 || i === 5 || i === 7 || i === 9) { h += '-'; }
      }
      return h;
    }
    function hash(s) { // djb2, short throttle fingerprint
      var h = 5381; s = String(s);
      for (var i = 0; i < s.length; i++) { h = ((h << 5) + h + s.charCodeAt(i)) | 0; }
      return (h >>> 0).toString(36);
    }
    function isoNow() { try { return new Date().toISOString(); } catch (e) { return String(now()); } }

    /* ---------------- storage and cookies (all failures tolerated) ------------- */
    function store(area) { try { var s = root[area]; return s && isFn(s.getItem) ? s : null; } catch (e) { return null; } }
    function sGet(k, area) { try { var s = store(area || 'localStorage'); return s ? s.getItem(k) : null; } catch (e) { return null; } }
    function sSet(k, v, area) { try { var s = store(area || 'localStorage'); if (s) { s.setItem(k, v); } } catch (e) {} }
    function sGetJSON(k, area) { try { var v = sGet(k, area); return v ? JSON.parse(v) : null; } catch (e) { return null; } }
    function sSetJSON(k, v, area) { try { sSet(k, JSON.stringify(v), area); } catch (e) {} }
    function cookieGet(name) {
      try {
        var parts = String(doc.cookie || '').split(/;\s*/);
        for (var i = 0; i < parts.length; i++) {
          var p = parts[i], eq = p.indexOf('=');
          if (eq > 0 && p.substring(0, eq) === name) { return decodeURIComponent(p.substring(eq + 1)); }
        }
      } catch (e) {}
      return null;
    }
    function cookieSet(name, value, days) {
      try {
        doc.cookie = name + '=' + encodeURIComponent(value) + '; path=/; max-age=' + Math.floor(days * 86400) +
          '; SameSite=Lax' + (loc.protocol === 'https:' ? '; Secure' : '');
      } catch (e) {}
    }

    /* ---------------- async helpers ---------------- */
    function once(fn) { var called = false; return function (v) { if (!called) { called = true; fn(v); } }; }
    // Run fn in a later task, preferably while the browser is idle, so no single
    // task holds the main thread for long.
    function yieldThen(fn) {
      if (isFn(root.requestIdleCallback)) { root.requestIdleCallback(function () { fn(); }, { timeout: 1000 }); }
      else { setTimeout(fn, 0); }
    }
    function withTimeout(task, ms, cb) {
      var done = once(cb);
      var t = setTimeout(function () { done(null); }, ms);
      try { task(function (v) { clearTimeout(t); done(v); }); } catch (e) { clearTimeout(t); done(null); }
    }
    function parallel(tasks, ms, cb) {
      var names = keys(tasks), out = {}, left = names.length, finished = false;
      function fin() { if (!finished) { finished = true; cb(out); } }
      if (!left) { return fin(); }
      var t = setTimeout(fin, ms);
      for (var i = 0; i < names.length; i++) {
        (function (n) {
          var cbOnce = once(function (v) { out[n] = v; left--; if (!left) { clearTimeout(t); fin(); } });
          try { tasks[n](cbOnce); } catch (e) { cbOnce(null); }
        })(names[i]);
      }
    }
    // cb({ text, header(name) }) on 2xx, cb(null) otherwise. Low network priority where supported.
    function httpGet(url, ms, cb) {
      var timer, done = once(function (v) { clearTimeout(timer); cb(v); });
      try {
        if (isFn(root.fetch) && isFn(root.AbortController)) {
          var ac = new root.AbortController();
          timer = setTimeout(function () { done(null); try { ac.abort(); } catch (e) {} }, ms);
          root.fetch(url, { credentials: 'same-origin', cache: 'no-store', priority: 'low', signal: ac.signal })
            .then(function (res) {
              if (!res.ok) { return done(null); }
              return res.text().then(function (t) { done({ text: t, header: function (h) { return res.headers.get(h); } }); });
            })
            .then(null, function () { done(null); });
          return;
        }
        var xhr = new root.XMLHttpRequest();
        xhr.open('GET', url, true);
        xhr.onreadystatechange = function () {
          if (xhr.readyState !== 4) { return; }
          if (xhr.status < 200 || xhr.status >= 300) { return done(null); }
          var t = xhr.responseText;
          done({ text: t, header: function (h) { try { return xhr.getResponseHeader(h); } catch (e) { return null; } } });
        };
        timer = setTimeout(function () { done(null); try { xhr.abort(); } catch (e) {} }, ms);
        xhr.send(null);
      } catch (e) { done(null); }
    }
    function bust(url) { return url + (url.indexOf('?') < 0 ? '?' : '&') + '_bb=' + now().toString(36); }

    /* ---------------- versions ---------------- */
    function parseVer(s) {
      if (s === null || s === undefined) { return null; }
      var m = String(s).match(/^\s*v?(\d{1,6})((?:\.\d{1,9}){0,3})/);
      if (!m) { return null; }
      var parts = (m[1] + m[2]).split('.'), out = [];
      for (var i = 0; i < parts.length; i++) { out.push(parseInt(parts[i], 10)); }
      while (out.length < 4) { out.push(0); }
      return out;
    }
    function cmpVer(a, b) {
      for (var i = 0; i < 4; i++) { if (a[i] !== b[i]) { return a[i] < b[i] ? -1 : 1; } }
      return 0;
    }
    function compareVersions(a, b) {
      var x = parseVer(a), y = parseVer(b);
      return x && y ? cmpVer(x, y) : null;
    }

    // tracks: [{channel, minimum, ifPatchUnknown}], first = main channel.
    function evaluate(tracks, version, precision) {
      var v = parseVer(version);
      if (!v) { return { vrd: 'unknown', rsn: 'no-version' }; }
      if (!tracks || !tracks.length) { return { vrd: 'unknown', rsn: 'no-policy' }; }
      var main = parseVer(tracks[0].minimum);
      if (v[0] > main[0]) { return { vrd: 'current', rsn: 'newer-major', chan: tracks[0].channel, min: tracks[0].minimum }; }
      for (var i = 0; i < tracks.length; i++) {
        var t = tracks[i], tv = parseVer(t.minimum);
        if (!tv || v[0] !== tv[0]) { continue; }
        if (precision === 'major') {
          return { vrd: t.ifPatchUnknown || 'current', rsn: 'major-match-patch-unknown', chan: t.channel, min: t.minimum };
        }
        if (cmpVer(v, tv) >= 0) { return { vrd: 'current', rsn: 'meets-minimum', chan: t.channel, min: t.minimum }; }
        return { vrd: 'outdated', rsn: 'below-minimum', chan: t.channel, min: t.minimum, behind: 0 };
      }
      return { vrd: 'outdated', rsn: 'major-behind', chan: tracks[0].channel, min: tracks[0].minimum, behind: main[0] - v[0] };
    }

    /* ---------------- IP addresses and CIDR (ipaddr.js) ---------------- */
    function parseIp(s, keepMapped) {
      if (s === null || s === undefined) { return null; }
      var ip = vendorIpaddr();
      s = trim(s).replace(/^\[/, '').replace(/\](:\d+)?$/, '').replace(/%[0-9A-Za-z._~-]+$/, '');
      try {
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
          return ip.IPv4.isValidFourPartDecimal(s) ? ip.IPv4.parse(s) : null; // rejects octal-looking forms
        }
        if (s.indexOf(':') >= 0 && ip.IPv6.isValid(s)) {
          var a = ip.IPv6.parse(s);
          return (!keepMapped && a.isIPv4MappedAddress()) ? a.toIPv4Address() : a;
        }
      } catch (e) {}
      return null;
    }
    function parseCidr(str) {
      var m = String(str).match(/^\s*([^\/\s]+)(?:\/(\d{1,3}))?\s*$/);
      if (!m) { return null; }
      var addr = parseIp(m[1], true);
      if (!addr) { return null; }
      var max = addr.kind() === 'ipv4' ? 32 : 128;
      var bits = m[2] === undefined || m[2] === '' ? max : parseInt(m[2], 10);
      if (bits > max) { return null; }
      var bytes = addr.toByteArray(); // host bits must be zero: 10.1.2.3/8 is almost always a typo
      for (var i = 0; i < bytes.length; i++) {
        var keep = Math.max(0, Math.min(8, bits - i * 8));
        if ((bytes[i] & (255 >> keep)) !== 0) { return null; }
      }
      return { addr: addr, bits: bits, kind: addr.kind(), text: trim(str) };
    }
    function compileRanges(list, errors, label, forbidZero) {
      var out = [];
      for (var i = 0; i < (list || []).length; i++) {
        var r = parseCidr(list[i]);
        if (!r) { errors.push(label + ': invalid or non-canonical CIDR "' + list[i] + '"'); continue; }
        if (forbidZero && r.bits === 0) { errors.push(label + ': /0 is not allowed ("' + list[i] + '")'); continue; }
        out.push(r);
      }
      return out;
    }
    function rangeHit(ip, ranges) {
      for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        try { if (r.kind === ip.kind() && ip.match(r.addr, r.bits)) { return r.text; } } catch (e) {}
      }
      return '';
    }
    var INCLUDE = [], EXCLUDE = [];
    function scopeOf(ipStr) {
      var ip = parseIp(ipStr);
      if (!ip) { return { state: 'unknown' }; }
      if (rangeHit(ip, EXCLUDE)) { return { state: 'out', ip: ip.toString(), why: 'excluded' }; }
      var hit = rangeHit(ip, INCLUDE);
      return hit ? { state: 'in', ip: ip.toString(), range: hit } : { state: 'out', ip: ip.toString() };
    }
    function firstIp(value) {
      var parts = String(value || '').split(/[\s,;]+/);
      for (var i = 0; i < parts.length; i++) { var ip = parseIp(parts[i]); if (ip) { return ip.toString(); } }
      return '';
    }

    /* ---------------- WebRTC local addresses ---------------- */
    // mayStore: only after the scope check passed, remember "this browser hides
    // local addresses" so WebRTC is not started again for localIpsRetryDays.
    function localIps(cb, mayStore) {
      function remember(list) { if (mayStore && !list.length && !webrtcFromCache) { sSet(KEY_RTC, String(now())); } }
      if (webrtcMemo) { remember(webrtcMemo); return cb(webrtcMemo); }
      var neg = parseInt(sGet(KEY_RTC) || '0', 10);
      if (neg && now() - neg < (CONFIG.collect.localIpsRetryDays || 0) * 86400000) {
        webrtcMemo = []; webrtcFromCache = true; return cb(webrtcMemo);
      }
      var PC = root.RTCPeerConnection || root.webkitRTCPeerConnection || root.mozRTCPeerConnection;
      if (!PC) { webrtcMemo = []; return cb(webrtcMemo); }
      var found = {}, list = [], pc = null, timer;
      var finish = once(function () {
        clearTimeout(timer);
        try { if (pc) { pc.onicecandidate = null; pc.close(); } } catch (e) {}
        pc = null; webrtcMemo = list; remember(list); cb(list);
      });
      function add(cand) {
        var f = String(cand || '').replace(/^a=/, '').split(' ');
        var addr = f[4];
        if (!addr || /\.local$/i.test(addr)) { return; } // mDNS-obfuscated host candidate
        var ip = parseIp(addr);
        if (ip) { var s = ip.toString(); if (!found[s]) { found[s] = 1; list.push(s); } }
      }
      try {
        pc = new PC({ iceServers: [] });
        pc.onicecandidate = function (e) {
          if (e && e.candidate) { add(e.candidate.candidate); } else { finish(); }
        };
        pc.createDataChannel('bb');
        var offer = pc.createOffer();
        if (offer && isFn(offer.then)) {
          offer.then(function (o) { return pc.setLocalDescription(o); }).then(null, finish);
        }
      } catch (e) { return finish(); }
      timer = setTimeout(finish, Math.min(CONFIG.scope.timeoutMs || 1500, 3000));
    }

    /* ---------------- value sources (IP and username) ---------------- */
    function readSource(src, ms, cb) {
      var t = src.type;
      function out(v) {
        if (v === null || v === undefined) { return cb(''); }
        var s = String(v);
        if (src.pattern) {
          try { var m = s.match(new RegExp(src.pattern)); s = m ? (m[1] !== undefined ? m[1] : m[0]) : ''; } catch (e) { s = ''; }
        }
        cb(clean(s, 256));
      }
      try {
        if (t === 'meta') {
          var el = doc.querySelector('meta[name="' + String(src.name).replace(/"/g, '') + '"]');
          return out(el ? el.getAttribute('content') : '');
        }
        if (t === 'global') { var g = getPath(root, src.path); return out(isObj(g) || isArray(g) ? '' : g); }
        if (t === 'dom') {
          var d = doc.querySelector(src.selector);
          return out(!d ? '' : (src.attr ? d.getAttribute(src.attr) : (d.textContent || d.innerText)));
        }
        if (t === 'cookie') { return out(cookieGet(src.name)); }
        if (t === 'storage') { return out(sGet(src.key, src.area === 'session' ? 'sessionStorage' : 'localStorage')); }
        if (t === 'function') {
          // fn() returns the value, or fn(cb) calls back with it
          return withTimeout(function (done) { if (src.fn.length > 0) { src.fn(done); } else { done(src.fn()); } }, ms, out);
        }
        if (t === 'url') {
          return httpGet(src.noCache === false ? src.url : bust(src.url), ms, function (resp) {
            if (!resp) { return out(''); }
            var v = src.header ? resp.header(src.header) : resp.text;
            if (src.jsonPath) { try { v = getPath(JSON.parse(v), src.jsonPath); } catch (e) { v = ''; } }
            out(v);
          });
        }
      } catch (e) { return out(''); }
      out('');
    }
    function firstValue(sources, ms, cb) {
      var i = 0;
      (function next() {
        if (!sources || i >= sources.length) { return cb({ value: '', src: '' }); }
        var s = sources[i++];
        readSource(s, ms, function (v) { if (v) { cb({ value: v, src: s.type }); } else { next(); } });
      })();
    }

    /* ---------------- scope decision ---------------- */
    function resolveScope(cb) {
      var sc = CONFIG.scope;
      if (!sc.enabled) { return cb({ state: 'disabled' }); }
      var sig = hash(JSON.stringify([sc.include, sc.exclude])); // a config change invalidates the cache
      var cached = sGetJSON(KEY_SCOPE, 'sessionStorage');
      if (cached && cached.s === sig && cached.t && now() - cached.t < sc.cacheMinutes * 60000 && cached.d && cached.d.state) {
        return cb(cached.d);
      }
      var i = 0;
      function done(d) { sSetJSON(KEY_SCOPE, { t: now(), s: sig, d: d }, 'sessionStorage'); cb(d); }
      (function next() {
        if (i >= sc.sources.length) { return done({ state: 'unknown' }); }
        var s = sc.sources[i++];
        if (s.type === 'webrtc') {
          return localIps(function (list) {
            if (!list.length) { return next(); }
            var outD = null;
            for (var j = 0; j < list.length; j++) {
              var d = scopeOf(list[j]);
              if (d.state === 'in') { d.src = 'webrtc'; return done(d); }
              if (!outD && d.state === 'out') { outD = d; }
            }
            if (outD) { outD.src = 'webrtc'; return done(outD); }
            next();
          });
        }
        readSource(s, sc.timeoutMs, function (v) {
          var ip = firstIp(v);
          if (!ip) { return next(); }
          var d = scopeOf(ip); d.src = s.type; done(d);
        });
      })();
    }

    /* ---------------- browser identity ---------------- */
    function uaKey(name, ua) {
      switch (name) {
        case 'Chrome': case 'Mobile Chrome': return 'chrome';
        case 'Edge':
          return /\bEdge\/\d/.test(ua) && !/\bEdg(A|iOS)?\//.test(ua) ? 'edge-legacy' : 'edge';
        case 'Firefox': case 'Mobile Firefox': return 'firefox';
        case 'Safari': case 'Mobile Safari': return 'safari';
        case 'Opera': case 'Opera Touch': return 'opera';
        case 'IE': case 'IEMobile': return 'ie';
        case 'Brave': return 'brave';
        case 'Vivaldi': return 'vivaldi';
        case 'Yandex': return 'yandex';
        case 'Samsung Internet': return 'samsung';
        case 'Chromium': case 'Chrome Headless': case 'Chrome WebView': return 'chromium';
      }
      return 'other';
    }
    // Chromium with Client Hints: the hints supply browser, version, OS and CPU, so
    // only the few UA tokens needed for the spoof check are read here; the full
    // parser (and its first-run compile cost) is reserved for everything else.
    function quickParse(ua) {
      var m, chrome = /\b(?:Chrome|HeadlessChrome|CriOS)\/(\d+[\d.]*)/.exec(ua), cv = chrome ? chrome[1] : '';
      var b = { name: '', version: '' };
      if ((m = /\bEdge\/(\d+[\d.]*)/.exec(ua)) && !/\bEdg(A|iOS)?\//.test(ua)) { b = { name: 'Edge', version: m[1] }; }
      else if ((m = /\bEdg(?:A|iOS)?\/(\d+[\d.]*)/.exec(ua))) { b = { name: 'Edge', version: m[1] }; }
      else if ((m = /\bOPR\/(\d+[\d.]*)/.exec(ua))) { b = { name: 'Opera', version: m[1] }; }
      else if ((m = /\bFirefox\/(\d+[\d.]*)/.exec(ua))) { b = { name: 'Firefox', version: m[1] }; }
      else if (/Trident\/|MSIE /.test(ua)) { b = { name: 'IE', version: '' }; }
      else if (cv) { b = { name: /HeadlessChrome/.test(ua) ? 'Chrome Headless' : 'Chrome', version: cv }; }
      else if ((m = /Version\/(\d+[\d.]*).*Safari\//.exec(ua))) { b = { name: 'Safari', version: m[1] }; }
      return { browser: b, engine: cv ? { name: 'Blink', version: cv } : {}, os: {}, cpu: {}, device: {} };
    }
    function parseUA(ua, ch) {
      if (ch && ch.brands && ch.brands.length && ch.platform) { return quickParse(ua); }
      // Only the parts used. getResult() would also run the device-model table,
      // the most expensive part of the parser, which is not needed here.
      try {
        var P = vendorUAParser(), p = new P(ua);
        return { browser: p.getBrowser(), engine: p.getEngine(), os: p.getOS(), cpu: p.getCPU(), device: {} };
      } catch (e) { return { browser: {}, engine: {}, os: {}, device: {}, cpu: {} }; }
    }
    function quickMobile(ua, ch) {
      return !!((ch && ch.mobile === true) || /\b(iPhone|iPod|iPad|Android|Mobile|Tablet|Kindle|Silk|PlayBook)\b|Windows Phone/.test(ua));
    }
    // Brand/version list from Client Hints (GREASE removed): part of the throttle key.
    function brandList(ch) {
      var list = ch && ch.fullVersionList && ch.fullVersionList.length ? ch.fullVersionList : (ch ? ch.brands : null), out = [];
      for (var i = 0; list && i < list.length; i++) {
        if (list[i] && list[i].brand && !isGrease(list[i].brand)) { out.push(list[i].brand + '/' + list[i].version); }
      }
      return out.join(';');
    }
    function isGrease(brand) { return /not.?a.?brand/i.test(brand); }
    function clientHints(cb) {
      var u = nav.userAgentData;
      if (!u || !u.brands || !u.brands.length) { return cb(null); }
      var low = { brands: u.brands, mobile: u.mobile, platform: u.platform };
      if (!isFn(u.getHighEntropyValues)) { return cb(low); }
      withTimeout(function (done) {
        u.getHighEntropyValues(['architecture', 'bitness', 'model', 'platformVersion', 'fullVersionList', 'wow64'])
          .then(function (h) { done(merge(merge({}, low), h || {})); }, function () { done(low); });
      }, 1000, function (v) { cb(v || low); });
    }
    function winFromNT(ua) {
      var m = /Windows NT (\d+\.\d+)/.exec(ua);
      var map = { '5.1': 'Windows XP', '5.2': 'Windows XP', '6.0': 'Windows Vista', '6.1': 'Windows 7', '6.2': 'Windows 8', '6.3': 'Windows 8.1' };
      return m && map[m[1]] ? map[m[1]] : '';
    }
    function identify(ua, r, ch) {
      var b = r.browser || {}, e = r.engine || {}, o = r.os || {}, dv = r.device || {}, cpu = r.cpu || {};
      var id = {
        key: uaKey(b.name, ua), name: b.name || 'Unknown', version: b.version || '', vsrc: 'ua',
        precision: 'full', engine: e.name || '', chromium: '', chromiumPrecision: 'full',
        brands: '', fvl: '', spoof: false, arch: cpu.architecture || '', bitness: '', wow64: '', model: ''
      };
      if (id.key === 'firefox') { id.precision = 'major'; }
      if (BLINK[id.key] || e.name === 'Blink') {
        id.chromium = e.name === 'Blink' ? (e.version || '') : '';
        if (/^\d+\.0\.0\.0$/.test(id.version)) { id.precision = 'major'; }
        if (/^\d+\.0\.0\.0$/.test(id.chromium)) { id.chromiumPrecision = 'major'; }
      }
      // Client Hints overlay (Chromium, secure contexts only)
      var list = ch && ch.fullVersionList && ch.fullVersionList.length ? ch.fullVersionList : (ch ? ch.brands : null);
      if (list && list.length) {
        var full = !!(ch.fullVersionList && ch.fullVersionList.length), pick = null, chromiumV = '', names = [];
        for (var i = 0; i < list.length; i++) {
          var it = list[i];
          if (!it || !it.brand || isGrease(it.brand)) { continue; }
          names.push(it.brand + '/' + it.version);
          if (it.brand === 'Chromium') { chromiumV = it.version; } else if (!pick) { pick = it; }
        }
        if (!pick && chromiumV) { pick = { brand: 'Chromium', version: chromiumV }; }
        if (pick) {
          var chKey = BRAND_KEYS[pick.brand] || 'chromium';
          var spoof = false;
          if (indexOf(['firefox', 'safari', 'ie', 'edge-legacy'], id.key) >= 0) { spoof = true; }
          if ((chKey === 'edge') !== (id.key === 'edge')) { spoof = true; }
          if ((chKey === 'opera') !== (id.key === 'opera')) { spoof = true; }
          var uaMaj = parseVer(id.chromium || (BLINK[id.key] ? id.version : '')), chMaj = parseVer(chromiumV || pick.version);
          if (uaMaj && chMaj && uaMaj[0] !== chMaj[0]) { spoof = true; }
          id.spoof = spoof;
          id.key = chKey; id.name = pick.brand; id.version = pick.version; id.vsrc = 'uach';
          id.precision = full ? 'full' : 'major';
          if (chromiumV) { id.chromium = chromiumV; id.chromiumPrecision = full ? 'full' : 'major'; }
          id.engine = 'Blink';
          id.brands = names.join(';');
          id.fvl = names.join(';');
        }
      }
      // OS
      var osName = '', osVer = '';
      if (ch && ch.platform) {
        osVer = ch.platformVersion || '';
        if (ch.platform === 'Windows') {
          var pv = parseInt(osVer, 10);
          if (isNaN(pv)) { osName = winFromNT(ua) || 'Windows'; }
          else if (pv >= 13) { osName = 'Windows 11'; }
          else if (pv >= 1) { osName = 'Windows 10'; }
          else { osName = winFromNT(ua) || 'Windows 7/8/8.1'; }
        } else { osName = ch.platform; }
      }
      if (!osName) {
        osName = o.name || ''; osVer = o.version || '';
        if (osName === 'Windows') { osName = osVer === '10' ? 'Windows 10/11' : (winFromNT(ua) || (osVer ? 'Windows ' + osVer : 'Windows')); }
        if (osName === 'Mac OS') { osName = 'macOS'; if (/^10\.15(\.7)?$/.test(osVer)) { osVer = osVer + ' (frozen)'; } }
      }
      id.os = osName; id.osv = osVer;
      if (ch) {
        id.arch = ch.architecture || id.arch; id.bitness = ch.bitness || '';
        id.wow64 = ch.wow64 === true ? '1' : (ch.wow64 === false ? '0' : ''); id.model = ch.model || '';
      }
      id.mobile = !!(quickMobile(ua, ch) || dv.type === 'mobile' || dv.type === 'tablet' || dv.type === 'wearable' ||
        o.name === 'iOS' || o.name === 'Android');
      return id;
    }

    /* ---------------- policy ---------------- */
    function validTracks(t) {
      if (!isArray(t) || !t.length) { return false; }
      for (var i = 0; i < t.length; i++) {
        if (!t[i] || !parseVer(t[i].minimum)) { return false; }
        if (t[i].ifPatchUnknown && !VERDICTS[t[i].ifPatchUnknown]) { return false; }
      }
      return true;
    }
    function validPolicy(p) {
      if (!isObj(p) || typeof p.id !== 'string' || !isObj(p.browsers)) { return false; }
      for (var k in p.browsers) { if (has(p.browsers, k) && !validTracks(p.browsers[k])) { return false; } }
      return true;
    }
    function mergedPolicy(feed) {
      var base = CONFIG.policy, p = {};
      var fields = ['id', 'issued', 'maxAgeDays', 'browsers', 'unsupported', 'unknownBrowser', 'os'];
      for (var i = 0; i < fields.length; i++) {
        var f = fields[i];
        p[f] = feed && feed[f] !== undefined ? feed[f] : base[f];
      }
      return p;
    }
    function policyIdHint() {
      if (!CONFIG.policy.feedUrl) { return CONFIG.policy.id; }
      var c = sGetJSON(KEY_POLICY);
      return c && c.p && c.p.id ? c.p.id : CONFIG.policy.id;
    }
    function loadPolicy(cb) {
      var url = CONFIG.policy.feedUrl;
      if (!url) { return cb(mergedPolicy(null), 'embedded'); }
      var c = sGetJSON(KEY_POLICY);
      var fresh = c && c.t && now() - c.t < CONFIG.policy.feedTtlHours * 3600000 && validPolicy(c.p);
      if (fresh) { return cb(mergedPolicy(c.p), 'feed-cache'); }
      httpGet(bust(url), CONFIG.scope.timeoutMs || 1500, function (resp) {
        if (resp) {
          try {
            var j = JSON.parse(resp.text);
            if (validPolicy(j)) { sSetJSON(KEY_POLICY, { t: now(), p: j }); return cb(mergedPolicy(j), 'feed'); }
          } catch (e) {}
        }
        if (c && validPolicy(c.p)) { return cb(mergedPolicy(c.p), 'feed-stale-cache'); }
        cb(mergedPolicy(null), 'embedded-fallback');
      });
    }
    function policyAgeDays(p) {
      var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(p.issued || '');
      if (!m) { return 0; }
      return (now() - Date.UTC(+m[1], +m[2] - 1, +m[3])) / 86400000;
    }
    function judge(id, p) {
      if (indexOf(p.unsupported, id.key) >= 0) { return { vrd: 'unsupported', rsn: 'browser-unsupported', basis: 'browser' }; }
      var tracks = p.browsers[id.key], ver = id.version, prec = id.precision, basis = 'browser';
      if (tracks && id.key === 'chromium' && id.chromium) { // unknown brands: judge the engine, not the brand number
        ver = id.chromium; prec = id.chromiumPrecision; basis = 'engine';
      }
      if (!tracks && (BLINK[id.key] || id.engine === 'Blink') && p.browsers.chromium && id.chromium) {
        tracks = p.browsers.chromium; ver = id.chromium; prec = id.chromiumPrecision; basis = 'engine';
      }
      if (!tracks) { return { vrd: p.unknownBrowser || 'unknown', rsn: 'no-policy-for-browser', basis: basis }; }
      var r = evaluate(tracks, ver, prec);
      r.basis = basis;
      if (r.vrd === 'current' && p.maxAgeDays && policyAgeDays(p) > p.maxAgeDays) { r.vrd = 'unverified'; r.rsn = 'policy-stale'; }
      return r;
    }
    function osVerdict(name, p) {
      var bad = (p.os && p.os.unsupported) || [];
      if (!name) { return 'unknown'; }
      var m = /^Windows (\d+(?:\.\d+)?)\/(\d+(?:\.\d+)?)(?:\/(\d+(?:\.\d+)?))?$/.exec(name), cands = [name];
      if (m) { cands = []; for (var i = 1; i < m.length; i++) { if (m[i]) { cands.push('Windows ' + m[i]); } } }
      var n = 0;
      for (var j = 0; j < cands.length; j++) { if (indexOf(bad, cands[j]) >= 0) { n++; } }
      return n === 0 ? 'supported' : (n === cands.length ? 'unsupported' : 'unknown');
    }

    /* ---------------- extensions ---------------- */
    function probeExtensions(id, cb) {
      var list = CONFIG.extensions.watchList || [], tasks = {}, hits = [];
      for (var i = 0; i < list.length; i++) {
        (function (x, n) {
          tasks['x' + n] = function (done) {
            try {
              if (x.selector) { return done(doc.querySelector(x.selector) ? x.name : null); }
              if (x.global) { return done(getPath(root, x.global) !== undefined ? x.name : null); }
              if (x.id && x.resource && BLINK[id.key] && isFn(root.fetch)) {
                return root.fetch('chrome-extension://' + x.id + '/' + x.resource, { cache: 'no-store' })
                  .then(function () { done(x.name); }, function () { done(null); });
              }
            } catch (e) {}
            done(null);
          };
        })(list[i], i);
      }
      parallel(tasks, CONFIG.extensions.timeoutMs, function (res) {
        for (var k in res) { if (has(res, k) && res[k]) { hits.push(clean(res[k], 60)); } }
        cb(hits);
      });
    }

    /* ---------------- device id ---------------- */
    function deviceId(create) {
      var k = CONFIG.device.idKey, idv = sGet(k) || (CONFIG.device.cookie ? cookieGet(k) : null);
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(idv || '')) {
        if (!create) { return ''; }
        idv = uuid();
      }
      if (create) { sSet(k, idv); if (CONFIG.device.cookie) { cookieSet(k, idv, CONFIG.device.cookieDays); } }
      return idv;
    }

    /* ---------------- record ---------------- */
    function buildRecord(id, sc, r, createId) {
      var pol = r.policy ? r.policy.p : mergedPolicy(null);
      var j = judge(id, pol), c = CONFIG.collect, rec = {};
      function put(k, v, max) { var s = clean(v, max || MAXLEN[k]); if (s !== '') { rec[k] = s; } }
      put('v', SCHEMA); put('sv', VERSION); put('pid', pol.id); put('psrc', r.policy ? r.policy.src : '');
      put('ts', isoNow()); put('rid', uuid()); put('did', deviceId(createId));
      put('host', loc.hostname); put('pg', loc.pathname);
      put('scope', sc.state); put('ip', sc.ip); put('ipsrc', sc.src);
      put('lip', (r.lips || []).join(','));
      if (r.user && r.user.value) { put('usr', r.user.value); put('usrsrc', r.user.src); }
      put('bk', id.key); put('bn', id.name); put('bv', id.version); put('bvp', id.precision); put('bvs', id.vsrc);
      put('cv', id.chromium); put('eng', id.engine); put('brands', id.brands);
      put('os', id.os); put('osv', id.osv); put('osvrd', osVerdict(id.os, pol));
      put('arch', id.arch); put('bit', id.bitness); put('wow64', id.wow64); put('model', id.model);
      put('mob', id.mobile ? 1 : 0);
      put('vrd', j.vrd); put('rsn', j.rsn); put('chan', j.chan); put('min', j.min);
      if (typeof j.behind === 'number') { put('behind', j.behind); }
      put('basis', j.basis); put('spoof', id.spoof ? 1 : 0);
      put('ext', (r.ext || []).join(','));
      if (c.timezone) { put('tzo', -new Date().getTimezoneOffset()); }
      if (c.timezoneName) {
        try { put('tz', root.Intl && root.Intl.DateTimeFormat ? root.Intl.DateTimeFormat().resolvedOptions().timeZone : ''); } catch (e) {}
      }
      if (c.language) { put('lang', nav.language || nav.userLanguage); }
      if (c.screen && root.screen) { put('scr', root.screen.width + 'x' + root.screen.height + '@' + (root.devicePixelRatio || 1)); }
      if (c.hardware) { put('hw', (nav.hardwareConcurrency || '') + 'c/' + (nav.deviceMemory || '') + 'g'); }
      if (c.rawUserAgent) { put('ua', nav.userAgent); } // pixel requests drop it when 'auto'
      return rec;
    }
    function pixelUrl(rec, base) {
      var max = CONFIG.delivery.maxUrlLength, work = merge({}, rec), di = 0, url;
      if (CONFIG.collect.rawUserAgent === 'auto') { delete work.ua; }
      function build() {
        var q = [];
        for (var i = 0; i < FIELD_ORDER.length; i++) {
          var k = FIELD_ORDER[i];
          if (has(work, k)) { q.push(k + '=' + encodeURIComponent(work[k])); }
        }
        q.push('_=' + now().toString(36)); // defeat caches between browser and log
        return base + (base.indexOf('?') < 0 ? '?' : '&') + q.join('&');
      }
      url = build();
      while (url.length > max && di < DROP.length) {
        if (has(work, DROP[di])) { delete work[DROP[di]]; work.trunc = '1'; url = build(); }
        di++;
      }
      return url;
    }

    /* ---------------- delivery ---------------- */
    function sendPixel(url, ms, cb) {
      var img, timer, done = once(function (ok) {
        clearTimeout(timer);
        if (img) { img.onload = img.onerror = null; var i = indexOf(keepAlive, img); if (i >= 0) { keepAlive.splice(i, 1); } }
        cb(ok);
      });
      try {
        img = new root.Image(1, 1);
        try { img.referrerPolicy = 'no-referrer'; } catch (e) {} // page query strings stay out of logs
        try { img.fetchPriority = 'low'; } catch (e) {}
        keepAlive.push(img); // hold a reference until the request completes
        img.onload = img.onerror = function () { done(true); }; // an error (e.g. 404) is still logged
        timer = setTimeout(function () { done(false); }, ms);
        img.src = url;
      } catch (e) { done(false); }
    }
    function formEncode(rec) {
      var q = [], seen = {}, i, k;
      for (i = 0; i < FIELD_ORDER.length; i++) { k = FIELD_ORDER[i]; if (has(rec, k)) { q.push(k + '=' + encodeURIComponent(rec[k])); seen[k] = 1; } }
      for (k in rec) { if (has(rec, k) && !seen[k]) { q.push(encodeURIComponent(k) + '=' + encodeURIComponent(rec[k])); } }
      return q.join('&');
    }
    // POST to a receiving HTTP server. fetch (low priority, keepalive) where available, else XHR.
    function sendHttp(d, rec, ms, cb) {
      var fmt = d.format || 'json', body, type, timer, k;
      if (fmt === 'form') { body = formEncode(rec); type = 'application/x-www-form-urlencoded'; }
      else { body = JSON.stringify(rec); type = fmt === 'text' ? 'text/plain;charset=UTF-8' : 'application/json'; }
      var headers = merge({ 'Content-Type': type }, d.headers || {}), cred = d.credentials || 'same-origin';
      var done = once(function (ok) { clearTimeout(timer); cb(ok); });
      try {
        if (isFn(root.fetch) && isFn(root.AbortController)) {
          var ac = new root.AbortController();
          var opt = { method: 'POST', body: body, headers: headers, credentials: cred, cache: 'no-store',
            referrerPolicy: 'no-referrer', priority: 'low', keepalive: d.keepalive !== false, signal: ac.signal };
          if (d.noCors) { opt.mode = 'no-cors'; }
          timer = setTimeout(function () { done(false); try { ac.abort(); } catch (e) {} }, ms);
          root.fetch(d.url, opt).then(function (res) { done(d.noCors ? true : !!(res && res.ok)); }, function () { done(false); });
          return;
        }
        var xhr = new root.XMLHttpRequest();
        xhr.open('POST', d.url, true);
        for (k in headers) { if (has(headers, k)) { xhr.setRequestHeader(k, headers[k]); } }
        if (cred === 'include') { xhr.withCredentials = true; }
        xhr.onreadystatechange = function () { if (xhr.readyState === 4) { done(xhr.status >= 200 && xhr.status < 300); } };
        timer = setTimeout(function () { done(false); try { xhr.abort(); } catch (e) {} }, ms);
        xhr.send(body);
      } catch (e) { done(false); }
    }
    function sendTo(d, rec, cb) {
      var ms = d.timeoutMs || CONFIG.delivery.timeoutMs || 5000;
      try {
        if (d.type === 'pixel') { return sendPixel(pixelUrl(rec, d.url), ms, cb); }
        if (d.type === 'http') { return sendHttp(d, rec, ms, cb); }
        if (d.type === 'beacon') {
          // A string body goes as text/plain: no CORS preflight. true = queued by the browser.
          if (isFn(nav.sendBeacon) && nav.sendBeacon(d.url, JSON.stringify(rec))) { return cb(true); }
          return sendHttp({ url: d.url, format: 'text' }, rec, ms, cb);
        }
        if (d.type === 'callback') { d.callback(merge({}, rec)); return cb(true); }
        if (d.type === 'console') { if (root.console) { root.console.log('[browser-beacon]', rec); } return cb(true); }
      } catch (e) { return cb(false); }
      cb(false);
    }
    function destLabel(d, i) { return clean(d.name || (d.type + '#' + (i + 1)), 40); }
    // cb(delivered, { label: true|false, ... }) once every non-local destination has answered.
    function deliver(rec, cb) {
      var list = CONFIG.destinations, tasks = {}, i;
      for (i = 0; i < list.length; i++) {
        if (list[i].type !== 'local') {
          (function (d, n) { tasks['d' + n] = function (done) { sendTo(d, rec, function (ok) { done(ok === true); }); }; })(list[i], i);
        }
      }
      parallel(tasks, (CONFIG.delivery.timeoutMs || 5000) + 1000, function (res) {
        var counted = 0, good = 0, status = {};
        for (var j = 0; j < list.length; j++) {
          if (list[j].type === 'local') { continue; }
          var ok = res['d' + j] === true;
          status[destLabel(list[j], j)] = ok;
          if (COUNTS[list[j].type]) { counted++; if (ok) { good++; } }
        }
        cb(counted === 0 ? true : (CONFIG.delivery.successWhen === 'all' ? good === counted : good > 0), status);
      });
    }

    /* ---------------- local log ---------------- */
    function hasLocal() {
      for (var i = 0; i < CONFIG.destinations.length; i++) { if (CONFIG.destinations[i].type === 'local') { return true; } }
      return false;
    }
    function readLog() { var l = sGetJSON(KEY_LOG); return isArray(l) ? l : []; }
    function localAppend(rec, status, delivered) {
      var L = CONFIG.localLog, to = [], k;
      for (k in status) { if (has(status, k)) { to.push(k + ':' + (status[k] ? 'ok' : 'fail')); } }
      var log = readLog(), kept = [], cutoff = now() - (L.maxDays || 30) * 86400000, i;
      log.push(merge({ _logged: isoNow(), _delivered: delivered ? 1 : 0, _to: to.join(',') }, rec));
      for (i = 0; i < log.length; i++) { var t = Date.parse(log[i] && log[i]._logged); if (!(t < cutoff)) { kept.push(log[i]); } }
      while (kept.length > (L.maxEntries || 30)) { kept.shift(); }
      var text = JSON.stringify(kept);
      while (text.length > (L.maxKB || 64) * 1024 && kept.length > 1) { kept.shift(); text = JSON.stringify(kept); }
      try { store('localStorage').setItem(KEY_LOG, text); }
      catch (e) { // storage full: keep the newest half
        try { kept = kept.slice(Math.floor(kept.length / 2)); store('localStorage').setItem(KEY_LOG, JSON.stringify(kept)); } catch (e2) {}
      }
    }
    // Saves the local log as a .jsonl file (one record per line). Returns the entry count.
    function downloadLog(filename) {
      var log = readLog();
      if (!log.length) { return 0; }
      var lines = [];
      for (var i = 0; i < log.length; i++) { lines.push(JSON.stringify(log[i])); }
      var stamp = isoNow().replace(/[-:]/g, '').substring(0, 15);
      var name = filename || ('browser-beacon-' + String(loc.hostname || 'portal').replace(/[^A-Za-z0-9.-]/g, '_') + '-' + stamp + '.jsonl');
      try {
        var blob = new root.Blob([lines.join('\n') + '\n'], { type: 'application/x-ndjson' });
        if (isFn(nav.msSaveOrOpenBlob)) { nav.msSaveOrOpenBlob(blob, name); return log.length; } // IE 11
        var U = root.URL || root.webkitURL, href = U.createObjectURL(blob), a = doc.createElement('a');
        a.href = href; a.download = name; a.style.display = 'none';
        doc.body.appendChild(a); a.click(); doc.body.removeChild(a);
        setTimeout(function () { try { U.revokeObjectURL(href); } catch (e) {} }, 10000);
        return log.length;
      } catch (e) { return -1; }
    }

    /* ---------------- optional notice ---------------- */
    function maybeNotice(rec) {
      var n = CONFIG.notice;
      if (!n.enabled || indexOf(n.verdicts, rec.vrd) < 0 || !doc.body) { return; }
      var last = parseInt(sGet(KEY_NOTICE) || '0', 10);
      if (now() - last < n.dismissHours * 3600000) { return; }
      try {
        var bar = doc.createElement('div');
        bar.setAttribute('role', 'status');
        bar.setAttribute('data-browser-beacon', 'notice');
        bar.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:2147483647;padding:10px 44px 10px 16px;' +
          'background:#7a1f1f;color:#fff;font:14px/1.4 Segoe UI,Arial,sans-serif;box-shadow:0 -2px 6px rgba(0,0,0,.3)';
        var text = String(n.text).replace('{browser}', rec.bn || 'browser').replace('{version}', rec.bv || '')
          .replace('{minimum}', rec.min || '');
        bar.appendChild(doc.createTextNode(text + ' '));
        if (n.linkText && /^(https?:\/\/|\/)/i.test(n.linkUrl || '')) {
          var a = doc.createElement('a');
          a.href = n.linkUrl; a.style.cssText = 'color:#fff;text-decoration:underline';
          a.appendChild(doc.createTextNode(n.linkText));
          bar.appendChild(a);
        }
        var x = doc.createElement('button');
        x.setAttribute('type', 'button'); x.setAttribute('aria-label', 'Dismiss');
        x.style.cssText = 'position:absolute;right:8px;top:6px;background:none;border:0;color:#fff;font-size:20px;cursor:pointer';
        x.appendChild(doc.createTextNode('\u00d7'));
        x.onclick = function () { sSet(KEY_NOTICE, String(now())); if (bar.parentNode) { bar.parentNode.removeChild(bar); } };
        bar.appendChild(x);
        doc.body.appendChild(bar);
      } catch (e) {}
    }

    /* ---------------- configuration check (fail closed) ---------------- */
    function validate() {
      var e = [], sc = CONFIG.scope, i;
      if (sc.enabled) {
        if (!isArray(sc.include) || !sc.include.length) { e.push('scope.include is empty: add company CIDR ranges (or set scope.enabled=false to report from anywhere)'); }
        INCLUDE = compileRanges(sc.include, e, 'scope.include', true);
        EXCLUDE = compileRanges(sc.exclude, e, 'scope.exclude', false);
        if (!isArray(sc.sources) || !sc.sources.length) { e.push('scope.sources is empty'); }
        for (i = 0; i < (sc.sources || []).length; i++) {
          if (!sc.sources[i] || !SOURCE_TYPES[sc.sources[i].type]) { e.push('scope.sources[' + i + ']: unknown type'); }
        }
        if (sc.onUnknown !== 'skip' && sc.onUnknown !== 'report') { e.push('scope.onUnknown must be skip or report'); }
      }
      for (i = 0; i < (CONFIG.user.sources || []).length; i++) {
        var us = CONFIG.user.sources[i];
        if (!us || !SOURCE_TYPES[us.type] || us.type === 'webrtc') { e.push('user.sources[' + i + ']: unknown type'); }
      }
      validateDestinations(e);
      if (!validPolicy(CONFIG.policy)) { e.push('policy: every browser needs channels with a parseable minimum'); }
      if (CONFIG.report.include !== 'all' && CONFIG.report.include !== 'non-current') { e.push('report.include must be all or non-current'); }
      if (CONFIG.mobile !== 'skip' && CONFIG.mobile !== 'report') { e.push('mobile must be skip or report'); }
      var wl = CONFIG.extensions.watchList || [];
      for (i = 0; i < wl.length; i++) {
        var w = wl[i] || {};
        if (!w.name) { e.push('extensions.watchList[' + i + ']: name required'); }
        if (w.id && (!/^[a-p]{32}$/.test(w.id) || !w.resource || /(^\/)|(\.\.)/.test(w.resource))) {
          e.push('extensions.watchList[' + i + ']: id must be 32 chars a-p and resource a relative path');
        }
      }
      return e;
    }
    function validateDestinations(e) {
      var list = CONFIG.destinations, i, d, k, scheme;
      if (!isArray(list) || !list.length) { return e.push('destinations is empty'); }
      for (i = 0; i < list.length; i++) {
        d = list[i]; var at = 'destinations[' + i + ']';
        if (!isObj(d) || !DEST_TYPES[d.type]) { e.push(at + ': type must be pixel, http, beacon, local, callback or console'); continue; }
        if (d.type === 'pixel' || d.type === 'http' || d.type === 'beacon') {
          if (!d.url || typeof d.url !== 'string') { e.push(at + ': url is required'); continue; }
          scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(d.url);
          if (scheme && !/^https?$/i.test(scheme[1])) { e.push(at + ': url must be http(s) or site-relative'); }
          if (loc.protocol === 'https:' && /^http:/i.test(d.url)) { e.push(at + ': http:// url would be blocked as mixed content on this https page'); }
        }
        if (d.type === 'http') {
          if (d.format && !{ json: 1, text: 1, form: 1 }[d.format]) { e.push(at + ': format must be json, text or form'); }
          if (d.credentials && !{ 'same-origin': 1, include: 1, omit: 1 }[d.credentials]) { e.push(at + ': credentials must be same-origin, include or omit'); }
          if (d.headers !== undefined && !isObj(d.headers)) { e.push(at + ': headers must be an object'); }
          if (d.noCors && ((d.format || 'json') === 'json' || (d.headers && keys(d.headers).length))) {
            e.push(at + ': noCors needs format text or form and no custom headers');
          }
          for (k in d.headers || {}) {
            if (has(d.headers, k) && /authorization|cookie|token|secret|password|api.?key/i.test(k)) {
              WARNINGS.push(at + ': header "' + k + '" is readable by anyone who can load this script');
            }
          }
        }
        if (d.type === 'callback' && !isFn(d.callback)) { e.push(at + ': callback must be a function'); }
      }
      if (CONFIG.delivery.successWhen !== 'any' && CONFIG.delivery.successWhen !== 'all') { e.push('delivery.successWhen must be any or all'); }
      if (!isArray(CONFIG.delivery.retryMinutes) || !CONFIG.delivery.retryMinutes.length) { e.push('delivery.retryMinutes must list at least one number'); }
    }
    // Configs written for v1.0/v1.1 used a single "transport" block; map it onto destinations.
    function legacyTransport() {
      var t = CONFIG.transport, o = root.BrowserBeaconConfig;
      if (!isObj(t) || !t.mode) { return; }
      if (CONFIG.allowPageOverride && isObj(o) && isArray(o.destinations)) { return; } // explicit destinations win
      var d = { type: t.mode === 'post' ? 'http' : t.mode, url: t.endpoint };
      if (t.mode === 'post') { d.format = 'json'; d.credentials = t.withCredentials ? 'include' : 'same-origin'; }
      if (t.mode === 'callback') { d.callback = t.callback; }
      CONFIG.destinations = [d];
      if (t.maxUrlLength) { CONFIG.delivery.maxUrlLength = t.maxUrlLength; }
      if (t.timeoutMs) { CONFIG.delivery.timeoutMs = t.timeoutMs; }
    }
    function hostAllowed() {
      var list = CONFIG.allowedHostnames || [], h = String(loc.hostname || '').toLowerCase();
      if (!list.length) { return true; }
      for (var i = 0; i < list.length; i++) {
        var p = String(list[i]).toLowerCase();
        if (p === h) { return true; }
        if (p.indexOf('*.') === 0 && h.length > p.length - 1 && h.substring(h.length - (p.length - 1)) === p.substring(1)) { return true; }
      }
      return false;
    }

    /* ---------------- main flow ---------------- */
    var ERRORS = [];
    function init() { // validation is deferred until first use (after page load)
      if (inited) { return ERRORS; }
      inited = true;
      try { legacyTransport(); ERRORS = validate(); } catch (e) { ERRORS = ['configuration could not be validated: ' + e]; }
      if (ERRORS.length && CONFIG.enabled) { warn('disabled by configuration errors:\n  - ' + ERRORS.join('\n  - ')); }
      if (WARNINGS.length && CONFIG.enabled) { warn('configuration warnings:\n  - ' + WARNINGS.join('\n  - ')); }
      return ERRORS;
    }
    function throttled(fp) {
      var last = sGetJSON(KEY_LAST);
      return !!(last && last.f === fp && now() - last.t < CONFIG.report.intervalHours * 3600000);
    }
    // kind 'ok': reported now. 'lease': another tab started a report, hold LEASE_MS.
    // 'fail': delivery failed, hold delivery.retryMinutes[n] (backs off on repeated failures).
    // A hold is stored as a report made (interval - hold) ago, so throttled() needs no special case.
    function markReported(fp, kind) {
      if (kind === 'ok') { return sSetJSON(KEY_LAST, { f: fp, t: now() }); }
      var prev = sGetJSON(KEY_LAST), n = prev && prev.f === fp ? (prev.n || 0) : 0, hold = LEASE_MS;
      if (kind === 'fail') {
        var r = CONFIG.delivery.retryMinutes; n++;
        hold = (+r[Math.min(n - 1, r.length - 1)] || 2) * 60000;
      }
      sSetJSON(KEY_LAST, { f: fp, t: now() - CONFIG.report.intervalHours * 3600000 + hold, n: n });
    }
    function run(opts, cb) {
      opts = opts || {}; cb = isFn(cb) ? cb : noop;
      if (!CONFIG.enabled) { return cb(null, 'disabled'); }
      if (inited && ERRORS.length) { return cb(null, 'config-error'); }
      if (!hostAllowed()) { return cb(null, 'host-not-allowed'); }
      if (!root.JSON) { return cb(null, 'no-json'); }
      if (running) { // e.g. preview() typed while the page-load run is in flight: run it next
        if (queue.length < 5) { queue.push([opts, cb]); } else { cb(null, 'busy'); }
        return;
      }
      running = true;
      var dry = !!opts.dryRun, ua = String(nav.userAgent || '');
      function finish(rec, status) {
        running = false; log(status, rec || ''); cb(rec, status);
        if (queue.length) { var nx = queue.shift(); run(nx[0], nx[1]); }
      }
      // Every stage runs in its own task, so no single task holds the main thread long.
      function step(fn) { yieldThen(function () { try { fn(); } catch (e) { finish(null, 'error'); } }); }
      // 1. Cheap checks only: most page views end here (no parsing, no network).
      function checks(ch) {
        if (!dry && CONFIG.mobile === 'skip' && quickMobile(ua, ch)) { return finish(null, 'mobile-skip'); }
        var fp = hash(ua + '|' + brandList(ch) + '|' + policyIdHint());
        if (!opts.force && !dry && throttled(fp)) { return finish(null, 'throttled'); }
        // Validate only when there is work to do (a throttled view would send nothing anyway).
        if (init().length) { return finish(null, 'config-error'); }
        resolveScope(function (sc) { step(function () { identifyStage(ch, fp, sc); }); });
      }
      // 2. Scope decided; identify the browser (the only place the UA parser can run).
      function identifyStage(ch, fp, sc) {
        var go = sc.state === 'in' || sc.state === 'disabled' || (sc.state === 'unknown' && CONFIG.scope.onUnknown === 'report');
        if (!go && !dry) { return finish(null, 'scope-' + sc.state); }
        var id = identify(ua, parseUA(ua, ch), ch);
        if (id.mobile && CONFIG.mobile === 'skip' && !dry) { return finish(null, 'mobile-skip'); }
        if (!dry) { markReported(fp, 'lease'); }
        step(function () { collectStage(fp, sc, go, id); });
      }
      // 3. Collect username, local IPs, extension hits and policy in parallel.
      function collectStage(fp, sc, go, id) {
        parallel({
          user: function (d) { firstValue(CONFIG.user.sources, CONFIG.user.timeoutMs, d); },
          lips: function (d) { if (CONFIG.collect.localIps) { localIps(d, go && !dry); } else { d([]); } },
          ext: function (d) { if (CONFIG.extensions.enabled) { probeExtensions(id, d); } else { d([]); } },
          policy: function (d) { loadPolicy(function (p, src) { d({ p: p, src: src }); }); }
        }, CONFIG.report.deadlineMs, function (r) { step(function () { sendStage(fp, sc, go, id, r); }); });
      }
      // 4. Judge and send.
      function sendStage(fp, sc, go, id, r) {
        var rec = buildRecord(id, sc, r, go && !dry);
        if (dry) { return finish(rec, go ? 'dry-run' : 'dry-run-scope-' + sc.state); }
        if (CONFIG.report.include === 'non-current' && rec.vrd === 'current') {
          markReported(fp, 'ok');
          return finish(rec, 'current-not-reported');
        }
        deliver(rec, function (ok, status) {
          markReported(fp, ok ? 'ok' : 'fail');
          maybeNotice(rec);
          if (!hasLocal()) { return finish(rec, ok ? 'sent' : 'send-failed'); }
          step(function () { localAppend(rec, status, ok); finish(rec, ok ? 'sent' : 'send-failed'); });
        });
      }
      try { clientHints(function (ch) { step(function () { checks(ch); }); }); } catch (e) { finish(null, 'error'); }
    }

    /* ---------------- init: nothing heavier than this runs before page load ---------------- */
    if (CONFIG.allowPageOverride && isObj(root.BrowserBeaconConfig)) { merge(CONFIG, root.BrowserBeaconConfig); }

    var api = {
      version: VERSION,
      // Send now, ignoring the throttle. cb(record, status)
      run: function (cb) { run({ force: true }, cb); },
      // Build the record without sending or storing anything. cb(record, status)
      preview: function (cb) {
        run({ dryRun: true }, isFn(cb) ? cb : function (rec, status) { if (root.console) { root.console.log('[browser-beacon]', status, rec); } });
      },
      // Local log (destination type 'local'): entries, save as .jsonl, clear.
      log: function () { return readLog(); },
      downloadLog: function (filename) { return downloadLog(filename); },
      clearLog: function () { try { store('localStorage').removeItem(KEY_LOG); } catch (e) {} },
      util: {
        compareVersions: compareVersions,
        evaluate: evaluate,
        parseCidr: function (s) { var r = parseCidr(s); return r ? { kind: r.kind, bits: r.bits, text: r.text } : null; },
        scopeOf: function (ip) { init(); var d = scopeOf(ip); return { state: d.state, ip: d.ip, range: d.range, why: d.why }; },
        // full=true forces the full UA parser even when hints are present (troubleshooting)
        identify: function (ua, hints, full) { return identify(ua, parseUA(ua, full ? null : hints), hints || null); },
        judge: function (ua, hints) { return judge(identify(ua, parseUA(ua, hints), hints || null), mergedPolicy(null)); }
      }
    };
    // Validated on first read, so reading it is the same as before but costs nothing at load.
    try { Object.defineProperty(api, 'configErrors', { enumerable: true, get: function () { return init().slice(); } }); }
    catch (e) { api.configErrors = init().slice(); }
    root.BrowserBeacon = api;

    var started = false, fallbackTimer = null;
    function start() {
      if (started) { return; }
      started = true;
      clearTimeout(fallbackTimer);
      setTimeout(function () { yieldThen(function () { run({}, noop); }); }, CONFIG.report.startDelayMs);
    }
    function whenShown(fn) { // a prerendered page waits until the user actually opens it
      if (doc.prerendering && doc.addEventListener) { doc.addEventListener('prerenderingchange', function () { fn(); }, false); }
      else { fn(); }
    }
    if (CONFIG.enabled && CONFIG.autoRun) {
      if (doc.readyState === 'complete') { whenShown(start); }
      else {
        if (root.addEventListener) { root.addEventListener('load', function () { whenShown(start); }, false); }
        else if (root.attachEvent) { root.attachEvent('onload', function () { whenShown(start); }); }
        if (CONFIG.report.maxWaitForLoadMs > 0) { fallbackTimer = setTimeout(function () { whenShown(start); }, CONFIG.report.maxWaitForLoadMs); }
      }
    }
  })();

  /* =========================================================================
   * Bundled third-party code. Each block between the BEGIN/END markers is
   * byte-identical to the file named, so it can be verified by hash. Both run
   * in a private scope: they create no globals and touch nothing on the page.
   * ========================================================================= */
  function vendorUAParser() {
    if (vendorUAParser.lib) { return vendorUAParser.lib; }
    vendorUAParser.lib = (function (window) {
      var exports = {}, module = { exports: exports }, define; // eslint-disable-line no-unused-vars -- hides any page AMD loader
/* @@BEGIN ua-parser-js@1.0.41 dist/ua-parser.min.js sha256=506462f545eb810192aa0cd26fd880d7234c62d0878969cc079981481d9fa2ea */
/* UAParser.js v1.0.41
   Copyright © 2012-2025 Faisal Salman <f@faisalman.com>
   MIT License */
(function(window,undefined){"use strict";var LIBVERSION="1.0.41",EMPTY="",UNKNOWN="?",FUNC_TYPE="function",UNDEF_TYPE="undefined",OBJ_TYPE="object",STR_TYPE="string",MAJOR="major",MODEL="model",NAME="name",TYPE="type",VENDOR="vendor",VERSION="version",ARCHITECTURE="architecture",CONSOLE="console",MOBILE="mobile",TABLET="tablet",SMARTTV="smarttv",WEARABLE="wearable",EMBEDDED="embedded",UA_MAX_LENGTH=500;var AMAZON="Amazon",APPLE="Apple",ASUS="ASUS",BLACKBERRY="BlackBerry",BROWSER="Browser",CHROME="Chrome",EDGE="Edge",FIREFOX="Firefox",GOOGLE="Google",HONOR="Honor",HUAWEI="Huawei",LENOVO="Lenovo",LG="LG",MICROSOFT="Microsoft",MOTOROLA="Motorola",NVIDIA="Nvidia",ONEPLUS="OnePlus",OPERA="Opera",OPPO="OPPO",SAMSUNG="Samsung",SHARP="Sharp",SONY="Sony",XIAOMI="Xiaomi",ZEBRA="Zebra",FACEBOOK="Facebook",CHROMIUM_OS="Chromium OS",MAC_OS="Mac OS",SUFFIX_BROWSER=" Browser";var extend=function(regexes,extensions){var mergedRegexes={};for(var i in regexes){if(extensions[i]&&extensions[i].length%2===0){mergedRegexes[i]=extensions[i].concat(regexes[i])}else{mergedRegexes[i]=regexes[i]}}return mergedRegexes},enumerize=function(arr){var enums={};for(var i=0;i<arr.length;i++){enums[arr[i].toUpperCase()]=arr[i]}return enums},has=function(str1,str2){return typeof str1===STR_TYPE?lowerize(str2).indexOf(lowerize(str1))!==-1:false},lowerize=function(str){return str.toLowerCase()},majorize=function(version){return typeof version===STR_TYPE?version.replace(/[^\d\.]/g,EMPTY).split(".")[0]:undefined},trim=function(str,len){if(typeof str===STR_TYPE){str=str.replace(/^\s\s*/,EMPTY);return typeof len===UNDEF_TYPE?str:str.substring(0,UA_MAX_LENGTH)}};var rgxMapper=function(ua,arrays){var i=0,j,k,p,q,matches,match;while(i<arrays.length&&!matches){var regex=arrays[i],props=arrays[i+1];j=k=0;while(j<regex.length&&!matches){if(!regex[j]){break}matches=regex[j++].exec(ua);if(!!matches){for(p=0;p<props.length;p++){match=matches[++k];q=props[p];if(typeof q===OBJ_TYPE&&q.length>0){if(q.length===2){if(typeof q[1]==FUNC_TYPE){this[q[0]]=q[1].call(this,match)}else{this[q[0]]=q[1]}}else if(q.length===3){if(typeof q[1]===FUNC_TYPE&&!(q[1].exec&&q[1].test)){this[q[0]]=match?q[1].call(this,match,q[2]):undefined}else{this[q[0]]=match?match.replace(q[1],q[2]):undefined}}else if(q.length===4){this[q[0]]=match?q[3].call(this,match.replace(q[1],q[2])):undefined}}else{this[q]=match?match:undefined}}}}i+=2}},strMapper=function(str,map){for(var i in map){if(typeof map[i]===OBJ_TYPE&&map[i].length>0){for(var j=0;j<map[i].length;j++){if(has(map[i][j],str)){return i===UNKNOWN?undefined:i}}}else if(has(map[i],str)){return i===UNKNOWN?undefined:i}}return map.hasOwnProperty("*")?map["*"]:str};var oldSafariMap={"1.0":"/8",1.2:"/1",1.3:"/3","2.0":"/412","2.0.2":"/416","2.0.3":"/417","2.0.4":"/419","?":"/"},windowsVersionMap={ME:"4.90","NT 3.11":"NT3.51","NT 4.0":"NT4.0",2e3:"NT 5.0",XP:["NT 5.1","NT 5.2"],Vista:"NT 6.0",7:"NT 6.1",8:"NT 6.2",8.1:"NT 6.3",10:["NT 6.4","NT 10.0"],RT:"ARM"};var regexes={browser:[[/\b(?:crmo|crios)\/([\w\.]+)/i],[VERSION,[NAME,"Chrome"]],[/edg(?:e|ios|a)?\/([\w\.]+)/i],[VERSION,[NAME,"Edge"]],[/(opera mini)\/([-\w\.]+)/i,/(opera [mobiletab]{3,6})\b.+version\/([-\w\.]+)/i,/(opera)(?:.+version\/|[\/ ]+)([\w\.]+)/i],[NAME,VERSION],[/opios[\/ ]+([\w\.]+)/i],[VERSION,[NAME,OPERA+" Mini"]],[/\bop(?:rg)?x\/([\w\.]+)/i],[VERSION,[NAME,OPERA+" GX"]],[/\bopr\/([\w\.]+)/i],[VERSION,[NAME,OPERA]],[/\bb[ai]*d(?:uhd|[ub]*[aekoprswx]{5,6})[\/ ]?([\w\.]+)/i],[VERSION,[NAME,"Baidu"]],[/\b(?:mxbrowser|mxios|myie2)\/?([-\w\.]*)\b/i],[VERSION,[NAME,"Maxthon"]],[/(kindle)\/([\w\.]+)/i,/(lunascape|maxthon|netfront|jasmine|blazer|sleipnir)[\/ ]?([\w\.]*)/i,/(avant|iemobile|slim(?:browser|boat|jet))[\/ ]?([\d\.]*)/i,/(?:ms|\()(ie) ([\w\.]+)/i,/(flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs|bowser|qupzilla|falkon|rekonq|puffin|brave|whale(?!.+naver)|qqbrowserlite|duckduckgo|klar|helio|(?=comodo_)?dragon)\/([-\w\.]+)/i,/(heytap|ovi|115)browser\/([\d\.]+)/i,/(weibo)__([\d\.]+)/i],[NAME,VERSION],[/quark(?:pc)?\/([-\w\.]+)/i],[VERSION,[NAME,"Quark"]],[/\bddg\/([\w\.]+)/i],[VERSION,[NAME,"DuckDuckGo"]],[/(?:\buc? ?browser|(?:juc.+)ucweb)[\/ ]?([\w\.]+)/i],[VERSION,[NAME,"UC"+BROWSER]],[/microm.+\bqbcore\/([\w\.]+)/i,/\bqbcore\/([\w\.]+).+microm/i,/micromessenger\/([\w\.]+)/i],[VERSION,[NAME,"WeChat"]],[/konqueror\/([\w\.]+)/i],[VERSION,[NAME,"Konqueror"]],[/trident.+rv[: ]([\w\.]{1,9})\b.+like gecko/i],[VERSION,[NAME,"IE"]],[/ya(?:search)?browser\/([\w\.]+)/i],[VERSION,[NAME,"Yandex"]],[/slbrowser\/([\w\.]+)/i],[VERSION,[NAME,"Smart Lenovo "+BROWSER]],[/(avast|avg)\/([\w\.]+)/i],[[NAME,/(.+)/,"$1 Secure "+BROWSER],VERSION],[/\bfocus\/([\w\.]+)/i],[VERSION,[NAME,FIREFOX+" Focus"]],[/\bopt\/([\w\.]+)/i],[VERSION,[NAME,OPERA+" Touch"]],[/coc_coc\w+\/([\w\.]+)/i],[VERSION,[NAME,"Coc Coc"]],[/dolfin\/([\w\.]+)/i],[VERSION,[NAME,"Dolphin"]],[/coast\/([\w\.]+)/i],[VERSION,[NAME,OPERA+" Coast"]],[/miuibrowser\/([\w\.]+)/i],[VERSION,[NAME,"MIUI"+SUFFIX_BROWSER]],[/fxios\/([\w\.-]+)/i],[VERSION,[NAME,FIREFOX]],[/\bqihoobrowser\/?([\w\.]*)/i],[VERSION,[NAME,"360"]],[/\b(qq)\/([\w\.]+)/i],[[NAME,/(.+)/,"$1Browser"],VERSION],[/(oculus|sailfish|huawei|vivo|pico)browser\/([\w\.]+)/i],[[NAME,/(.+)/,"$1"+SUFFIX_BROWSER],VERSION],[/samsungbrowser\/([\w\.]+)/i],[VERSION,[NAME,SAMSUNG+" Internet"]],[/metasr[\/ ]?([\d\.]+)/i],[VERSION,[NAME,"Sogou Explorer"]],[/(sogou)mo\w+\/([\d\.]+)/i],[[NAME,"Sogou Mobile"],VERSION],[/(electron)\/([\w\.]+) safari/i,/(tesla)(?: qtcarbrowser|\/(20\d\d\.[-\w\.]+))/i,/m?(qqbrowser|2345(?=browser|chrome|explorer))\w*[\/ ]?v?([\w\.]+)/i],[NAME,VERSION],[/(lbbrowser|rekonq)/i,/\[(linkedin)app\]/i],[NAME],[/ome\/([\w\.]+) \w* ?(iron) saf/i,/ome\/([\w\.]+).+qihu (360)[es]e/i],[VERSION,NAME],[/((?:fban\/fbios|fb_iab\/fb4a)(?!.+fbav)|;fbav\/([\w\.]+);)/i],[[NAME,FACEBOOK],VERSION],[/(Klarna)\/([\w\.]+)/i,/(kakao(?:talk|story))[\/ ]([\w\.]+)/i,/(naver)\(.*?(\d+\.[\w\.]+).*\)/i,/(daum)apps[\/ ]([\w\.]+)/i,/safari (line)\/([\w\.]+)/i,/\b(line)\/([\w\.]+)\/iab/i,/(alipay)client\/([\w\.]+)/i,/(twitter)(?:and| f.+e\/([\w\.]+))/i,/(chromium|instagram|snapchat)[\/ ]([-\w\.]+)/i],[NAME,VERSION],[/\bgsa\/([\w\.]+) .*safari\//i],[VERSION,[NAME,"GSA"]],[/musical_ly(?:.+app_?version\/|_)([\w\.]+)/i],[VERSION,[NAME,"TikTok"]],[/headlesschrome(?:\/([\w\.]+)| )/i],[VERSION,[NAME,CHROME+" Headless"]],[/ wv\).+(chrome)\/([\w\.]+)/i],[[NAME,CHROME+" WebView"],VERSION],[/droid.+ version\/([\w\.]+)\b.+(?:mobile safari|safari)/i],[VERSION,[NAME,"Android "+BROWSER]],[/(chrome|omniweb|arora|[tizenoka]{5} ?browser)\/v?([\w\.]+)/i],[NAME,VERSION],[/version\/([\w\.\,]+) .*mobile\/\w+ (safari)/i],[VERSION,[NAME,"Mobile Safari"]],[/version\/([\w(\.|\,)]+) .*(mobile ?safari|safari)/i],[VERSION,NAME],[/webkit.+?(mobile ?safari|safari)(\/[\w\.]+)/i],[NAME,[VERSION,strMapper,oldSafariMap]],[/(webkit|khtml)\/([\w\.]+)/i],[NAME,VERSION],[/(navigator|netscape\d?)\/([-\w\.]+)/i],[[NAME,"Netscape"],VERSION],[/(wolvic|librewolf)\/([\w\.]+)/i],[NAME,VERSION],[/mobile vr; rv:([\w\.]+)\).+firefox/i],[VERSION,[NAME,FIREFOX+" Reality"]],[/ekiohf.+(flow)\/([\w\.]+)/i,/(swiftfox)/i,/(icedragon|iceweasel|camino|chimera|fennec|maemo browser|minimo|conkeror)[\/ ]?([\w\.\+]+)/i,/(seamonkey|k-meleon|icecat|iceape|firebird|phoenix|palemoon|basilisk|waterfox)\/([-\w\.]+)$/i,/(firefox)\/([\w\.]+)/i,/(mozilla)\/([\w\.]+) .+rv\:.+gecko\/\d+/i,/(amaya|dillo|doris|icab|ladybird|lynx|mosaic|netsurf|obigo|polaris|w3m|(?:go|ice|up)[\. ]?browser)[-\/ ]?v?([\w\.]+)/i,/\b(links) \(([\w\.]+)/i],[NAME,[VERSION,/_/g,"."]],[/(cobalt)\/([\w\.]+)/i],[NAME,[VERSION,/master.|lts./,""]]],cpu:[[/\b((amd|x|x86[-_]?|wow|win)64)\b/i],[[ARCHITECTURE,"amd64"]],[/(ia32(?=;))/i,/\b((i[346]|x)86)(pc)?\b/i],[[ARCHITECTURE,"ia32"]],[/\b(aarch64|arm(v?[89]e?l?|_?64))\b/i],[[ARCHITECTURE,"arm64"]],[/\b(arm(v[67])?ht?n?[fl]p?)\b/i],[[ARCHITECTURE,"armhf"]],[/( (ce|mobile); ppc;|\/[\w\.]+arm\b)/i],[[ARCHITECTURE,"arm"]],[/((ppc|powerpc)(64)?)( mac|;|\))/i],[[ARCHITECTURE,/ower/,EMPTY,lowerize]],[/ sun4\w[;\)]/i],[[ARCHITECTURE,"sparc"]],[/\b(avr32|ia64(?=;)|68k(?=\))|\barm(?=v([1-7]|[5-7]1)l?|;|eabi)|(irix|mips|sparc)(64)?\b|pa-risc)/i],[[ARCHITECTURE,lowerize]]],device:[[/\b(sch-i[89]0\d|shw-m380s|sm-[ptx]\w{2,4}|gt-[pn]\d{2,4}|sgh-t8[56]9|nexus 10)/i],[MODEL,[VENDOR,SAMSUNG],[TYPE,TABLET]],[/\b((?:s[cgp]h|gt|sm)-(?![lr])\w+|sc[g-]?[\d]+a?|galaxy nexus)/i,/samsung[- ]((?!sm-[lr])[-\w]+)/i,/sec-(sgh\w+)/i],[MODEL,[VENDOR,SAMSUNG],[TYPE,MOBILE]],[/(?:\/|\()(ip(?:hone|od)[\w, ]*)(?:\/|;)/i],[MODEL,[VENDOR,APPLE],[TYPE,MOBILE]],[/\((ipad);[-\w\),; ]+apple/i,/applecoremedia\/[\w\.]+ \((ipad)/i,/\b(ipad)\d\d?,\d\d?[;\]].+ios/i],[MODEL,[VENDOR,APPLE],[TYPE,TABLET]],[/(macintosh);/i],[MODEL,[VENDOR,APPLE]],[/\b(sh-?[altvz]?\d\d[a-ekm]?)/i],[MODEL,[VENDOR,SHARP],[TYPE,MOBILE]],[/\b((?:brt|eln|hey2?|gdi|jdn)-a?[lnw]09|(?:ag[rm]3?|jdn2|kob2)-a?[lw]0[09]hn)(?: bui|\)|;)/i],[MODEL,[VENDOR,HONOR],[TYPE,TABLET]],[/honor([-\w ]+)[;\)]/i],[MODEL,[VENDOR,HONOR],[TYPE,MOBILE]],[/\b((?:ag[rs][2356]?k?|bah[234]?|bg[2o]|bt[kv]|cmr|cpn|db[ry]2?|jdn2|got|kob2?k?|mon|pce|scm|sht?|[tw]gr|vrd)-[ad]?[lw][0125][09]b?|605hw|bg2-u03|(?:gem|fdr|m2|ple|t1)-[7a]0[1-4][lu]|t1-a2[13][lw]|mediapad[\w\. ]*(?= bui|\)))\b(?!.+d\/s)/i],[MODEL,[VENDOR,HUAWEI],[TYPE,TABLET]],[/(?:huawei)([-\w ]+)[;\)]/i,/\b(nexus 6p|\w{2,4}e?-[atu]?[ln][\dx][012359c][adn]?)\b(?!.+d\/s)/i],[MODEL,[VENDOR,HUAWEI],[TYPE,MOBILE]],[/oid[^\)]+; (2[\dbc]{4}(182|283|rp\w{2})[cgl]|m2105k81a?c)(?: bui|\))/i,/\b((?:red)?mi[-_ ]?pad[\w- ]*)(?: bui|\))/i],[[MODEL,/_/g," "],[VENDOR,XIAOMI],[TYPE,TABLET]],[/\b(poco[\w ]+|m2\d{3}j\d\d[a-z]{2})(?: bui|\))/i,/\b; (\w+) build\/hm\1/i,/\b(hm[-_ ]?note?[_ ]?(?:\d\w)?) bui/i,/\b(redmi[\-_ ]?(?:note|k)?[\w_ ]+)(?: bui|\))/i,/oid[^\)]+; (m?[12][0-389][01]\w{3,6}[c-y])( bui|; wv|\))/i,/\b(mi[-_ ]?(?:a\d|one|one[_ ]plus|note lte|max|cc)?[_ ]?(?:\d?\w?)[_ ]?(?:plus|se|lite|pro)?)(?: bui|\))/i,/ ([\w ]+) miui\/v?\d/i],[[MODEL,/_/g," "],[VENDOR,XIAOMI],[TYPE,MOBILE]],[/; (\w+) bui.+ oppo/i,/\b(cph[12]\d{3}|p(?:af|c[al]|d\w|e[ar])[mt]\d0|x9007|a101op)\b/i],[MODEL,[VENDOR,OPPO],[TYPE,MOBILE]],[/\b(opd2(\d{3}a?))(?: bui|\))/i],[MODEL,[VENDOR,strMapper,{OnePlus:["304","403","203"],"*":OPPO}],[TYPE,TABLET]],[/vivo (\w+)(?: bui|\))/i,/\b(v[12]\d{3}\w?[at])(?: bui|;)/i],[MODEL,[VENDOR,"Vivo"],[TYPE,MOBILE]],[/\b(rmx[1-3]\d{3})(?: bui|;|\))/i],[MODEL,[VENDOR,"Realme"],[TYPE,MOBILE]],[/\b(milestone|droid(?:[2-4x]| (?:bionic|x2|pro|razr))?:?( 4g)?)\b[\w ]+build\//i,/\bmot(?:orola)?[- ](\w*)/i,/((?:moto(?! 360)[\w\(\) ]+|xt\d{3,4}|nexus 6)(?= bui|\)))/i],[MODEL,[VENDOR,MOTOROLA],[TYPE,MOBILE]],[/\b(mz60\d|xoom[2 ]{0,2}) build\//i],[MODEL,[VENDOR,MOTOROLA],[TYPE,TABLET]],[/((?=lg)?[vl]k\-?\d{3}) bui| 3\.[-\w; ]{10}lg?-([06cv9]{3,4})/i],[MODEL,[VENDOR,LG],[TYPE,TABLET]],[/(lm(?:-?f100[nv]?|-[\w\.]+)(?= bui|\))|nexus [45])/i,/\blg[-e;\/ ]+((?!browser|netcast|android tv|watch)\w+)/i,/\blg-?([\d\w]+) bui/i],[MODEL,[VENDOR,LG],[TYPE,MOBILE]],[/(ideatab[-\w ]+|602lv|d-42a|a101lv|a2109a|a3500-hv|s[56]000|pb-6505[my]|tb-?x?\d{3,4}(?:f[cu]|xu|[av])|yt\d?-[jx]?\d+[lfmx])( bui|;|\)|\/)/i,/lenovo ?(b[68]0[08]0-?[hf]?|tab(?:[\w- ]+?)|tb[\w-]{6,7})( bui|;|\)|\/)/i],[MODEL,[VENDOR,LENOVO],[TYPE,TABLET]],[/(nokia) (t[12][01])/i],[VENDOR,MODEL,[TYPE,TABLET]],[/(?:maemo|nokia).*(n900|lumia \d+|rm-\d+)/i,/nokia[-_ ]?(([-\w\. ]*))/i],[[MODEL,/_/g," "],[TYPE,MOBILE],[VENDOR,"Nokia"]],[/(pixel (c|tablet))\b/i],[MODEL,[VENDOR,GOOGLE],[TYPE,TABLET]],[/droid.+; (pixel[\daxl ]{0,6})(?: bui|\))/i],[MODEL,[VENDOR,GOOGLE],[TYPE,MOBILE]],[/droid.+; (a?\d[0-2]{2}so|[c-g]\d{4}|so[-gl]\w+|xq-a\w[4-7][12])(?= bui|\).+chrome\/(?![1-6]{0,1}\d\.))/i],[MODEL,[VENDOR,SONY],[TYPE,MOBILE]],[/sony tablet [ps]/i,/\b(?:sony)?sgp\w+(?: bui|\))/i],[[MODEL,"Xperia Tablet"],[VENDOR,SONY],[TYPE,TABLET]],[/ (kb2005|in20[12]5|be20[12][59])\b/i,/(?:one)?(?:plus)? (a\d0\d\d)(?: b|\))/i],[MODEL,[VENDOR,ONEPLUS],[TYPE,MOBILE]],[/(alexa)webm/i,/(kf[a-z]{2}wi|aeo(?!bc)\w\w)( bui|\))/i,/(kf[a-z]+)( bui|\)).+silk\//i],[MODEL,[VENDOR,AMAZON],[TYPE,TABLET]],[/((?:sd|kf)[0349hijorstuw]+)( bui|\)).+silk\//i],[[MODEL,/(.+)/g,"Fire Phone $1"],[VENDOR,AMAZON],[TYPE,MOBILE]],[/(playbook);[-\w\),; ]+(rim)/i],[MODEL,VENDOR,[TYPE,TABLET]],[/\b((?:bb[a-f]|st[hv])100-\d)/i,/\(bb10; (\w+)/i],[MODEL,[VENDOR,BLACKBERRY],[TYPE,MOBILE]],[/(?:\b|asus_)(transfo[prime ]{4,10} \w+|eeepc|slider \w+|nexus 7|padfone|p00[cj])/i],[MODEL,[VENDOR,ASUS],[TYPE,TABLET]],[/ (z[bes]6[027][012][km][ls]|zenfone \d\w?)\b/i],[MODEL,[VENDOR,ASUS],[TYPE,MOBILE]],[/(nexus 9)/i],[MODEL,[VENDOR,"HTC"],[TYPE,TABLET]],[/(htc)[-;_ ]{1,2}([\w ]+(?=\)| bui)|\w+)/i,/(zte)[- ]([\w ]+?)(?: bui|\/|\))/i,/(alcatel|geeksphone|nexian|panasonic(?!(?:;|\.))|sony(?!-bra))[-_ ]?([-\w]*)/i],[VENDOR,[MODEL,/_/g," "],[TYPE,MOBILE]],[/droid [\w\.]+; ((?:8[14]9[16]|9(?:0(?:48|60|8[01])|1(?:3[27]|66)|2(?:6[69]|9[56])|466))[gqswx])\w*(\)| bui)/i],[MODEL,[VENDOR,"TCL"],[TYPE,TABLET]],[/(itel) ((\w+))/i],[[VENDOR,lowerize],MODEL,[TYPE,strMapper,{tablet:["p10001l","w7001"],"*":"mobile"}]],[/droid.+; ([ab][1-7]-?[0178a]\d\d?)/i],[MODEL,[VENDOR,"Acer"],[TYPE,TABLET]],[/droid.+; (m[1-5] note) bui/i,/\bmz-([-\w]{2,})/i],[MODEL,[VENDOR,"Meizu"],[TYPE,MOBILE]],[/; ((?:power )?armor(?:[\w ]{0,8}))(?: bui|\))/i],[MODEL,[VENDOR,"Ulefone"],[TYPE,MOBILE]],[/; (energy ?\w+)(?: bui|\))/i,/; energizer ([\w ]+)(?: bui|\))/i],[MODEL,[VENDOR,"Energizer"],[TYPE,MOBILE]],[/; cat (b35);/i,/; (b15q?|s22 flip|s48c|s62 pro)(?: bui|\))/i],[MODEL,[VENDOR,"Cat"],[TYPE,MOBILE]],[/((?:new )?andromax[\w- ]+)(?: bui|\))/i],[MODEL,[VENDOR,"Smartfren"],[TYPE,MOBILE]],[/droid.+; (a(?:015|06[35]|142p?))/i],[MODEL,[VENDOR,"Nothing"],[TYPE,MOBILE]],[/; (x67 5g|tikeasy \w+|ac[1789]\d\w+)( b|\))/i,/archos ?(5|gamepad2?|([\w ]*[t1789]|hello) ?\d+[\w ]*)( b|\))/i],[MODEL,[VENDOR,"Archos"],[TYPE,TABLET]],[/archos ([\w ]+)( b|\))/i,/; (ac[3-6]\d\w{2,8})( b|\))/i],[MODEL,[VENDOR,"Archos"],[TYPE,MOBILE]],[/(imo) (tab \w+)/i,/(infinix) (x1101b?)/i],[VENDOR,MODEL,[TYPE,TABLET]],[/(blackberry|benq|palm(?=\-)|sonyericsson|acer|asus(?! zenw)|dell|jolla|meizu|motorola|polytron|infinix|tecno|micromax|advan)[-_ ]?([-\w]*)/i,/; (hmd|imo) ([\w ]+?)(?: bui|\))/i,/(hp) ([\w ]+\w)/i,/(microsoft); (lumia[\w ]+)/i,/(lenovo)[-_ ]?([-\w ]+?)(?: bui|\)|\/)/i,/(oppo) ?([\w ]+) bui/i],[VENDOR,MODEL,[TYPE,MOBILE]],[/(kobo)\s(ereader|touch)/i,/(hp).+(touchpad(?!.+tablet)|tablet)/i,/(kindle)\/([\w\.]+)/i,/(nook)[\w ]+build\/(\w+)/i,/(dell) (strea[kpr\d ]*[\dko])/i,/(le[- ]+pan)[- ]+(\w{1,9}) bui/i,/(trinity)[- ]*(t\d{3}) bui/i,/(gigaset)[- ]+(q\w{1,9}) bui/i,/(vodafone) ([\w ]+)(?:\)| bui)/i],[VENDOR,MODEL,[TYPE,TABLET]],[/(surface duo)/i],[MODEL,[VENDOR,MICROSOFT],[TYPE,TABLET]],[/droid [\d\.]+; (fp\du?)(?: b|\))/i],[MODEL,[VENDOR,"Fairphone"],[TYPE,MOBILE]],[/(u304aa)/i],[MODEL,[VENDOR,"AT&T"],[TYPE,MOBILE]],[/\bsie-(\w*)/i],[MODEL,[VENDOR,"Siemens"],[TYPE,MOBILE]],[/\b(rct\w+) b/i],[MODEL,[VENDOR,"RCA"],[TYPE,TABLET]],[/\b(venue[\d ]{2,7}) b/i],[MODEL,[VENDOR,"Dell"],[TYPE,TABLET]],[/\b(q(?:mv|ta)\w+) b/i],[MODEL,[VENDOR,"Verizon"],[TYPE,TABLET]],[/\b(?:barnes[& ]+noble |bn[rt])([\w\+ ]*) b/i],[MODEL,[VENDOR,"Barnes & Noble"],[TYPE,TABLET]],[/\b(tm\d{3}\w+) b/i],[MODEL,[VENDOR,"NuVision"],[TYPE,TABLET]],[/\b(k88) b/i],[MODEL,[VENDOR,"ZTE"],[TYPE,TABLET]],[/\b(nx\d{3}j) b/i],[MODEL,[VENDOR,"ZTE"],[TYPE,MOBILE]],[/\b(gen\d{3}) b.+49h/i],[MODEL,[VENDOR,"Swiss"],[TYPE,MOBILE]],[/\b(zur\d{3}) b/i],[MODEL,[VENDOR,"Swiss"],[TYPE,TABLET]],[/\b((zeki)?tb.*\b) b/i],[MODEL,[VENDOR,"Zeki"],[TYPE,TABLET]],[/\b([yr]\d{2}) b/i,/\b(dragon[- ]+touch |dt)(\w{5}) b/i],[[VENDOR,"Dragon Touch"],MODEL,[TYPE,TABLET]],[/\b(ns-?\w{0,9}) b/i],[MODEL,[VENDOR,"Insignia"],[TYPE,TABLET]],[/\b((nxa|next)-?\w{0,9}) b/i],[MODEL,[VENDOR,"NextBook"],[TYPE,TABLET]],[/\b(xtreme\_)?(v(1[045]|2[015]|[3469]0|7[05])) b/i],[[VENDOR,"Voice"],MODEL,[TYPE,MOBILE]],[/\b(lvtel\-)?(v1[12]) b/i],[[VENDOR,"LvTel"],MODEL,[TYPE,MOBILE]],[/\b(ph-1) /i],[MODEL,[VENDOR,"Essential"],[TYPE,MOBILE]],[/\b(v(100md|700na|7011|917g).*\b) b/i],[MODEL,[VENDOR,"Envizen"],[TYPE,TABLET]],[/\b(trio[-\w\. ]+) b/i],[MODEL,[VENDOR,"MachSpeed"],[TYPE,TABLET]],[/\btu_(1491) b/i],[MODEL,[VENDOR,"Rotor"],[TYPE,TABLET]],[/((?:tegranote|shield t(?!.+d tv))[\w- ]*?)(?: b|\))/i],[MODEL,[VENDOR,NVIDIA],[TYPE,TABLET]],[/(sprint) (\w+)/i],[VENDOR,MODEL,[TYPE,MOBILE]],[/(kin\.[onetw]{3})/i],[[MODEL,/\./g," "],[VENDOR,MICROSOFT],[TYPE,MOBILE]],[/droid.+; (cc6666?|et5[16]|mc[239][23]x?|vc8[03]x?)\)/i],[MODEL,[VENDOR,ZEBRA],[TYPE,TABLET]],[/droid.+; (ec30|ps20|tc[2-8]\d[kx])\)/i],[MODEL,[VENDOR,ZEBRA],[TYPE,MOBILE]],[/smart-tv.+(samsung)/i],[VENDOR,[TYPE,SMARTTV]],[/hbbtv.+maple;(\d+)/i],[[MODEL,/^/,"SmartTV"],[VENDOR,SAMSUNG],[TYPE,SMARTTV]],[/(nux; netcast.+smarttv|lg (netcast\.tv-201\d|android tv))/i],[[VENDOR,LG],[TYPE,SMARTTV]],[/(apple) ?tv/i],[VENDOR,[MODEL,APPLE+" TV"],[TYPE,SMARTTV]],[/crkey/i],[[MODEL,CHROME+"cast"],[VENDOR,GOOGLE],[TYPE,SMARTTV]],[/droid.+aft(\w+)( bui|\))/i],[MODEL,[VENDOR,AMAZON],[TYPE,SMARTTV]],[/(shield \w+ tv)/i],[MODEL,[VENDOR,NVIDIA],[TYPE,SMARTTV]],[/\(dtv[\);].+(aquos)/i,/(aquos-tv[\w ]+)\)/i],[MODEL,[VENDOR,SHARP],[TYPE,SMARTTV]],[/(bravia[\w ]+)( bui|\))/i],[MODEL,[VENDOR,SONY],[TYPE,SMARTTV]],[/(mi(tv|box)-?\w+) bui/i],[MODEL,[VENDOR,XIAOMI],[TYPE,SMARTTV]],[/Hbbtv.*(technisat) (.*);/i],[VENDOR,MODEL,[TYPE,SMARTTV]],[/\b(roku)[\dx]*[\)\/]((?:dvp-)?[\d\.]*)/i,/hbbtv\/\d+\.\d+\.\d+ +\([\w\+ ]*; *([\w\d][^;]*);([^;]*)/i],[[VENDOR,trim],[MODEL,trim],[TYPE,SMARTTV]],[/droid.+; ([\w- ]+) (?:android tv|smart[- ]?tv)/i],[MODEL,[TYPE,SMARTTV]],[/\b(android tv|smart[- ]?tv|opera tv|tv; rv:)\b/i],[[TYPE,SMARTTV]],[/(ouya)/i,/(nintendo) ([wids3utch]+)/i],[VENDOR,MODEL,[TYPE,CONSOLE]],[/droid.+; (shield)( bui|\))/i],[MODEL,[VENDOR,NVIDIA],[TYPE,CONSOLE]],[/(playstation \w+)/i],[MODEL,[VENDOR,SONY],[TYPE,CONSOLE]],[/\b(xbox(?: one)?(?!; xbox))[\); ]/i],[MODEL,[VENDOR,MICROSOFT],[TYPE,CONSOLE]],[/\b(sm-[lr]\d\d[0156][fnuw]?s?|gear live)\b/i],[MODEL,[VENDOR,SAMSUNG],[TYPE,WEARABLE]],[/((pebble))app/i,/(asus|google|lg|oppo) ((pixel |zen)?watch[\w ]*)( bui|\))/i],[VENDOR,MODEL,[TYPE,WEARABLE]],[/(ow(?:19|20)?we?[1-3]{1,3})/i],[MODEL,[VENDOR,OPPO],[TYPE,WEARABLE]],[/(watch)(?: ?os[,\/]|\d,\d\/)[\d\.]+/i],[MODEL,[VENDOR,APPLE],[TYPE,WEARABLE]],[/(opwwe\d{3})/i],[MODEL,[VENDOR,ONEPLUS],[TYPE,WEARABLE]],[/(moto 360)/i],[MODEL,[VENDOR,MOTOROLA],[TYPE,WEARABLE]],[/(smartwatch 3)/i],[MODEL,[VENDOR,SONY],[TYPE,WEARABLE]],[/(g watch r)/i],[MODEL,[VENDOR,LG],[TYPE,WEARABLE]],[/droid.+; (wt63?0{2,3})\)/i],[MODEL,[VENDOR,ZEBRA],[TYPE,WEARABLE]],[/droid.+; (glass) \d/i],[MODEL,[VENDOR,GOOGLE],[TYPE,WEARABLE]],[/(pico) (4|neo3(?: link|pro)?)/i],[VENDOR,MODEL,[TYPE,WEARABLE]],[/; (quest( \d| pro)?)/i],[MODEL,[VENDOR,FACEBOOK],[TYPE,WEARABLE]],[/(tesla)(?: qtcarbrowser|\/[-\w\.]+)/i],[VENDOR,[TYPE,EMBEDDED]],[/(aeobc)\b/i],[MODEL,[VENDOR,AMAZON],[TYPE,EMBEDDED]],[/(homepod).+mac os/i],[MODEL,[VENDOR,APPLE],[TYPE,EMBEDDED]],[/windows iot/i],[[TYPE,EMBEDDED]],[/droid .+?; ([^;]+?)(?: bui|; wv\)|\) applew).+? mobile safari/i],[MODEL,[TYPE,MOBILE]],[/droid .+?; ([^;]+?)(?: bui|\) applew).+?(?! mobile) safari/i],[MODEL,[TYPE,TABLET]],[/\b((tablet|tab)[;\/]|focus\/\d(?!.+mobile))/i],[[TYPE,TABLET]],[/(phone|mobile(?:[;\/]| [ \w\/\.]*safari)|pda(?=.+windows ce))/i],[[TYPE,MOBILE]],[/droid .+?; ([\w\. -]+)( bui|\))/i],[MODEL,[VENDOR,"Generic"]]],engine:[[/windows.+ edge\/([\w\.]+)/i],[VERSION,[NAME,EDGE+"HTML"]],[/(arkweb)\/([\w\.]+)/i],[NAME,VERSION],[/webkit\/537\.36.+chrome\/(?!27)([\w\.]+)/i],[VERSION,[NAME,"Blink"]],[/(presto)\/([\w\.]+)/i,/(webkit|trident|netfront|netsurf|amaya|lynx|w3m|goanna|servo)\/([\w\.]+)/i,/ekioh(flow)\/([\w\.]+)/i,/(khtml|tasman|links)[\/ ]\(?([\w\.]+)/i,/(icab)[\/ ]([23]\.[\d\.]+)/i,/\b(libweb)/i],[NAME,VERSION],[/ladybird\//i],[[NAME,"LibWeb"]],[/rv\:([\w\.]{1,9})\b.+(gecko)/i],[VERSION,NAME]],os:[[/microsoft (windows) (vista|xp)/i],[NAME,VERSION],[/(windows (?:phone(?: os)?|mobile|iot))[\/ ]?([\d\.\w ]*)/i],[NAME,[VERSION,strMapper,windowsVersionMap]],[/windows nt 6\.2; (arm)/i,/windows[\/ ]([ntce\d\. ]+\w)(?!.+xbox)/i,/(?:win(?=3|9|n)|win 9x )([nt\d\.]+)/i],[[VERSION,strMapper,windowsVersionMap],[NAME,"Windows"]],[/[adehimnop]{4,7}\b(?:.*os ([\w]+) like mac|; opera)/i,/(?:ios;fbsv\/|iphone.+ios[\/ ])([\d\.]+)/i,/cfnetwork\/.+darwin/i],[[VERSION,/_/g,"."],[NAME,"iOS"]],[/(mac os x) ?([\w\. ]*)/i,/(macintosh|mac_powerpc\b)(?!.+haiku)/i],[[NAME,MAC_OS],[VERSION,/_/g,"."]],[/droid ([\w\.]+)\b.+(android[- ]x86|harmonyos)/i],[VERSION,NAME],[/(ubuntu) ([\w\.]+) like android/i],[[NAME,/(.+)/,"$1 Touch"],VERSION],[/(android|bada|blackberry|kaios|maemo|meego|openharmony|qnx|rim tablet os|sailfish|series40|symbian|tizen|webos)\w*[-\/; ]?([\d\.]*)/i],[NAME,VERSION],[/\(bb(10);/i],[VERSION,[NAME,BLACKBERRY]],[/(?:symbian ?os|symbos|s60(?=;)|series ?60)[-\/ ]?([\w\.]*)/i],[VERSION,[NAME,"Symbian"]],[/mozilla\/[\d\.]+ \((?:mobile|tablet|tv|mobile; [\w ]+); rv:.+ gecko\/([\w\.]+)/i],[VERSION,[NAME,FIREFOX+" OS"]],[/web0s;.+rt(tv)/i,/\b(?:hp)?wos(?:browser)?\/([\w\.]+)/i],[VERSION,[NAME,"webOS"]],[/watch(?: ?os[,\/]|\d,\d\/)([\d\.]+)/i],[VERSION,[NAME,"watchOS"]],[/crkey\/([\d\.]+)/i],[VERSION,[NAME,CHROME+"cast"]],[/(cros) [\w]+(?:\)| ([\w\.]+)\b)/i],[[NAME,CHROMIUM_OS],VERSION],[/panasonic;(viera)/i,/(netrange)mmh/i,/(nettv)\/(\d+\.[\w\.]+)/i,/(nintendo|playstation) ([wids345portablevuch]+)/i,/(xbox); +xbox ([^\);]+)/i,/\b(joli|palm)\b ?(?:os)?\/?([\w\.]*)/i,/(mint)[\/\(\) ]?(\w*)/i,/(mageia|vectorlinux)[; ]/i,/([kxln]?ubuntu|debian|suse|opensuse|gentoo|arch(?= linux)|slackware|fedora|mandriva|centos|pclinuxos|red ?hat|zenwalk|linpus|raspbian|plan 9|minix|risc os|contiki|deepin|manjaro|elementary os|sabayon|linspire)(?: gnu\/linux)?(?: enterprise)?(?:[- ]linux)?(?:-gnu)?[-\/ ]?(?!chrom|package)([-\w\.]*)/i,/(hurd|linux)(?: arm\w*| x86\w*| ?)([\w\.]*)/i,/(gnu) ?([\w\.]*)/i,/\b([-frentopcghs]{0,5}bsd|dragonfly)[\/ ]?(?!amd|[ix346]{1,2}86)([\w\.]*)/i,/(haiku) (\w+)/i],[NAME,VERSION],[/(sunos) ?([\w\.\d]*)/i],[[NAME,"Solaris"],VERSION],[/((?:open)?solaris)[-\/ ]?([\w\.]*)/i,/(aix) ((\d)(?=\.|\)| )[\w\.])*/i,/\b(beos|os\/2|amigaos|morphos|openvms|fuchsia|hp-ux|serenityos)/i,/(unix) ?([\w\.]*)/i],[NAME,VERSION]]};var UAParser=function(ua,extensions){if(typeof ua===OBJ_TYPE){extensions=ua;ua=undefined}if(!(this instanceof UAParser)){return new UAParser(ua,extensions).getResult()}var _navigator=typeof window!==UNDEF_TYPE&&window.navigator?window.navigator:undefined;var _ua=ua||(_navigator&&_navigator.userAgent?_navigator.userAgent:EMPTY);var _uach=_navigator&&_navigator.userAgentData?_navigator.userAgentData:undefined;var _rgxmap=extensions?extend(regexes,extensions):regexes;var _isSelfNav=_navigator&&_navigator.userAgent==_ua;this.getBrowser=function(){var _browser={};_browser[NAME]=undefined;_browser[VERSION]=undefined;rgxMapper.call(_browser,_ua,_rgxmap.browser);_browser[MAJOR]=majorize(_browser[VERSION]);if(_isSelfNav&&_navigator&&_navigator.brave&&typeof _navigator.brave.isBrave==FUNC_TYPE){_browser[NAME]="Brave"}return _browser};this.getCPU=function(){var _cpu={};_cpu[ARCHITECTURE]=undefined;rgxMapper.call(_cpu,_ua,_rgxmap.cpu);return _cpu};this.getDevice=function(){var _device={};_device[VENDOR]=undefined;_device[MODEL]=undefined;_device[TYPE]=undefined;rgxMapper.call(_device,_ua,_rgxmap.device);if(_isSelfNav&&!_device[TYPE]&&_uach&&_uach.mobile){_device[TYPE]=MOBILE}if(_isSelfNav&&_device[MODEL]=="Macintosh"&&_navigator&&typeof _navigator.standalone!==UNDEF_TYPE&&_navigator.maxTouchPoints&&_navigator.maxTouchPoints>2){_device[MODEL]="iPad";_device[TYPE]=TABLET}return _device};this.getEngine=function(){var _engine={};_engine[NAME]=undefined;_engine[VERSION]=undefined;rgxMapper.call(_engine,_ua,_rgxmap.engine);return _engine};this.getOS=function(){var _os={};_os[NAME]=undefined;_os[VERSION]=undefined;rgxMapper.call(_os,_ua,_rgxmap.os);if(_isSelfNav&&!_os[NAME]&&_uach&&_uach.platform&&_uach.platform!="Unknown"){_os[NAME]=_uach.platform.replace(/chrome os/i,CHROMIUM_OS).replace(/macos/i,MAC_OS)}return _os};this.getResult=function(){return{ua:this.getUA(),browser:this.getBrowser(),engine:this.getEngine(),os:this.getOS(),device:this.getDevice(),cpu:this.getCPU()}};this.getUA=function(){return _ua};this.setUA=function(ua){_ua=typeof ua===STR_TYPE&&ua.length>UA_MAX_LENGTH?trim(ua,UA_MAX_LENGTH):ua;return this};this.setUA(_ua);return this};UAParser.VERSION=LIBVERSION;UAParser.BROWSER=enumerize([NAME,VERSION,MAJOR]);UAParser.CPU=enumerize([ARCHITECTURE]);UAParser.DEVICE=enumerize([MODEL,VENDOR,TYPE,CONSOLE,MOBILE,SMARTTV,TABLET,WEARABLE,EMBEDDED]);UAParser.ENGINE=UAParser.OS=enumerize([NAME,VERSION]);if(typeof exports!==UNDEF_TYPE){if(typeof module!==UNDEF_TYPE&&module.exports){exports=module.exports=UAParser}exports.UAParser=UAParser}else{if(typeof define===FUNC_TYPE&&define.amd){define(function(){return UAParser})}else if(typeof window!==UNDEF_TYPE){window.UAParser=UAParser}}var $=typeof window!==UNDEF_TYPE&&(window.jQuery||window.Zepto);if($&&!$.ua){var parser=new UAParser;$.ua=parser.getResult();$.ua.get=function(){return parser.getUA()};$.ua.set=function(ua){parser.setUA(ua);var result=parser.getResult();for(var prop in result){$.ua[prop]=result[prop]}}}})(typeof window==="object"?window:this);
/* @@END ua-parser-js */
      return module.exports;
    })({}); // empty "window": parse only the UA string passed in, no page side effects
    return vendorUAParser.lib;
  }

  function vendorIpaddr() {
    if (vendorIpaddr.lib) { return vendorIpaddr.lib; }
    vendorIpaddr.lib = (function () {
      var module = { exports: {} };
/* @@BEGIN ipaddr.js@1.9.1 ipaddr.min.js sha256=ab95215c182a1bea49617080dc12e52e3e80521894c37ce0478b69326c151440 */
(function(){var r,t,n,e,i,o,a,s;t={},s=this,"undefined"!=typeof module&&null!==module&&module.exports?module.exports=t:s.ipaddr=t,a=function(r,t,n,e){var i,o;if(r.length!==t.length)throw new Error("ipaddr: cannot match CIDR for objects with different lengths");for(i=0;e>0;){if((o=n-e)<0&&(o=0),r[i]>>o!=t[i]>>o)return!1;e-=n,i+=1}return!0},t.subnetMatch=function(r,t,n){var e,i,o,a,s;null==n&&(n="unicast");for(o in t)for(!(a=t[o])[0]||a[0]instanceof Array||(a=[a]),e=0,i=a.length;e<i;e++)if(s=a[e],r.kind()===s[0].kind()&&r.match.apply(r,s))return o;return n},t.IPv4=function(){function r(r){var t,n,e;if(4!==r.length)throw new Error("ipaddr: ipv4 octet count should be 4");for(t=0,n=r.length;t<n;t++)if(!(0<=(e=r[t])&&e<=255))throw new Error("ipaddr: ipv4 octet should fit in 8 bits");this.octets=r}return r.prototype.kind=function(){return"ipv4"},r.prototype.toString=function(){return this.octets.join(".")},r.prototype.toNormalizedString=function(){return this.toString()},r.prototype.toByteArray=function(){return this.octets.slice(0)},r.prototype.match=function(r,t){var n;if(void 0===t&&(r=(n=r)[0],t=n[1]),"ipv4"!==r.kind())throw new Error("ipaddr: cannot match ipv4 address with non-ipv4 one");return a(this.octets,r.octets,8,t)},r.prototype.SpecialRanges={unspecified:[[new r([0,0,0,0]),8]],broadcast:[[new r([255,255,255,255]),32]],multicast:[[new r([224,0,0,0]),4]],linkLocal:[[new r([169,254,0,0]),16]],loopback:[[new r([127,0,0,0]),8]],carrierGradeNat:[[new r([100,64,0,0]),10]],private:[[new r([10,0,0,0]),8],[new r([172,16,0,0]),12],[new r([192,168,0,0]),16]],reserved:[[new r([192,0,0,0]),24],[new r([192,0,2,0]),24],[new r([192,88,99,0]),24],[new r([198,51,100,0]),24],[new r([203,0,113,0]),24],[new r([240,0,0,0]),4]]},r.prototype.range=function(){return t.subnetMatch(this,this.SpecialRanges)},r.prototype.toIPv4MappedAddress=function(){return t.IPv6.parse("::ffff:"+this.toString())},r.prototype.prefixLengthFromSubnetMask=function(){var r,t,n,e,i,o,a;for(a={0:8,128:7,192:6,224:5,240:4,248:3,252:2,254:1,255:0},r=0,i=!1,t=n=3;n>=0;t=n+=-1){if(!((e=this.octets[t])in a))return null;if(o=a[e],i&&0!==o)return null;8!==o&&(i=!0),r+=o}return 32-r},r}(),n="(0?\\d+|0x[a-f0-9]+)",e={fourOctet:new RegExp("^"+n+"\\."+n+"\\."+n+"\\."+n+"$","i"),longValue:new RegExp("^"+n+"$","i")},t.IPv4.parser=function(r){var t,n,i,o,a;if(n=function(r){return"0"===r[0]&&"x"!==r[1]?parseInt(r,8):parseInt(r)},t=r.match(e.fourOctet))return function(){var r,e,o,a;for(a=[],r=0,e=(o=t.slice(1,6)).length;r<e;r++)i=o[r],a.push(n(i));return a}();if(t=r.match(e.longValue)){if((a=n(t[1]))>4294967295||a<0)throw new Error("ipaddr: address outside defined range");return function(){var r,t;for(t=[],o=r=0;r<=24;o=r+=8)t.push(a>>o&255);return t}().reverse()}return null},t.IPv6=function(){function r(r,t){var n,e,i,o,a,s;if(16===r.length)for(this.parts=[],n=e=0;e<=14;n=e+=2)this.parts.push(r[n]<<8|r[n+1]);else{if(8!==r.length)throw new Error("ipaddr: ipv6 part count should be 8 or 16");this.parts=r}for(i=0,o=(s=this.parts).length;i<o;i++)if(!(0<=(a=s[i])&&a<=65535))throw new Error("ipaddr: ipv6 part should fit in 16 bits");t&&(this.zoneId=t)}return r.prototype.kind=function(){return"ipv6"},r.prototype.toString=function(){return this.toNormalizedString().replace(/((^|:)(0(:|$))+)/,"::")},r.prototype.toRFC5952String=function(){var r,t,n,e,i;for(e=/((^|:)(0(:|$)){2,})/g,i=this.toNormalizedString(),r=0,t=-1;n=e.exec(i);)n[0].length>t&&(r=n.index,t=n[0].length);return t<0?i:i.substring(0,r)+"::"+i.substring(r+t)},r.prototype.toByteArray=function(){var r,t,n,e,i;for(r=[],t=0,n=(i=this.parts).length;t<n;t++)e=i[t],r.push(e>>8),r.push(255&e);return r},r.prototype.toNormalizedString=function(){var r,t,n;return r=function(){var r,n,e,i;for(i=[],r=0,n=(e=this.parts).length;r<n;r++)t=e[r],i.push(t.toString(16));return i}.call(this).join(":"),n="",this.zoneId&&(n="%"+this.zoneId),r+n},r.prototype.toFixedLengthString=function(){var r,t,n;return r=function(){var r,n,e,i;for(i=[],r=0,n=(e=this.parts).length;r<n;r++)t=e[r],i.push(t.toString(16).padStart(4,"0"));return i}.call(this).join(":"),n="",this.zoneId&&(n="%"+this.zoneId),r+n},r.prototype.match=function(r,t){var n;if(void 0===t&&(r=(n=r)[0],t=n[1]),"ipv6"!==r.kind())throw new Error("ipaddr: cannot match ipv6 address with non-ipv6 one");return a(this.parts,r.parts,16,t)},r.prototype.SpecialRanges={unspecified:[new r([0,0,0,0,0,0,0,0]),128],linkLocal:[new r([65152,0,0,0,0,0,0,0]),10],multicast:[new r([65280,0,0,0,0,0,0,0]),8],loopback:[new r([0,0,0,0,0,0,0,1]),128],uniqueLocal:[new r([64512,0,0,0,0,0,0,0]),7],ipv4Mapped:[new r([0,0,0,0,0,65535,0,0]),96],rfc6145:[new r([0,0,0,0,65535,0,0,0]),96],rfc6052:[new r([100,65435,0,0,0,0,0,0]),96],"6to4":[new r([8194,0,0,0,0,0,0,0]),16],teredo:[new r([8193,0,0,0,0,0,0,0]),32],reserved:[[new r([8193,3512,0,0,0,0,0,0]),32]]},r.prototype.range=function(){return t.subnetMatch(this,this.SpecialRanges)},r.prototype.isIPv4MappedAddress=function(){return"ipv4Mapped"===this.range()},r.prototype.toIPv4Address=function(){var r,n,e;if(!this.isIPv4MappedAddress())throw new Error("ipaddr: trying to convert a generic ipv6 address to ipv4");return e=this.parts.slice(-2),r=e[0],n=e[1],new t.IPv4([r>>8,255&r,n>>8,255&n])},r.prototype.prefixLengthFromSubnetMask=function(){var r,t,n,e,i,o,a;for(a={0:16,32768:15,49152:14,57344:13,61440:12,63488:11,64512:10,65024:9,65280:8,65408:7,65472:6,65504:5,65520:4,65528:3,65532:2,65534:1,65535:0},r=0,i=!1,t=n=7;n>=0;t=n+=-1){if(!((e=this.parts[t])in a))return null;if(o=a[e],i&&0!==o)return null;16!==o&&(i=!0),r+=o}return 128-r},r}(),i="(?:[0-9a-f]+::?)+",o={zoneIndex:new RegExp("%[0-9a-z]{1,}","i"),native:new RegExp("^(::)?("+i+")?([0-9a-f]+)?(::)?(%[0-9a-z]{1,})?$","i"),transitional:new RegExp("^((?:"+i+")|(?:::)(?:"+i+")?)"+n+"\\."+n+"\\."+n+"\\."+n+"(%[0-9a-z]{1,})?$","i")},r=function(r,t){var n,e,i,a,s,p;if(r.indexOf("::")!==r.lastIndexOf("::"))return null;for((p=(r.match(o.zoneIndex)||[])[0])&&(p=p.substring(1),r=r.replace(/%.+$/,"")),n=0,e=-1;(e=r.indexOf(":",e+1))>=0;)n++;if("::"===r.substr(0,2)&&n--,"::"===r.substr(-2,2)&&n--,n>t)return null;for(s=t-n,a=":";s--;)a+="0:";return":"===(r=r.replace("::",a))[0]&&(r=r.slice(1)),":"===r[r.length-1]&&(r=r.slice(0,-1)),t=function(){var t,n,e,o;for(o=[],t=0,n=(e=r.split(":")).length;t<n;t++)i=e[t],o.push(parseInt(i,16));return o}(),{parts:t,zoneId:p}},t.IPv6.parser=function(t){var n,e,i,a,s,p,u;if(o.native.test(t))return r(t,8);if((a=t.match(o.transitional))&&(u=a[6]||"",(n=r(a[1].slice(0,-1)+u,6)).parts)){for(e=0,i=(p=[parseInt(a[2]),parseInt(a[3]),parseInt(a[4]),parseInt(a[5])]).length;e<i;e++)if(!(0<=(s=p[e])&&s<=255))return null;return n.parts.push(p[0]<<8|p[1]),n.parts.push(p[2]<<8|p[3]),{parts:n.parts,zoneId:n.zoneId}}return null},t.IPv4.isIPv4=t.IPv6.isIPv6=function(r){return null!==this.parser(r)},t.IPv4.isValid=function(r){try{return new this(this.parser(r)),!0}catch(r){return r,!1}},t.IPv4.isValidFourPartDecimal=function(r){return!(!t.IPv4.isValid(r)||!r.match(/^(0|[1-9]\d*)(\.(0|[1-9]\d*)){3}$/))},t.IPv6.isValid=function(r){var t;if("string"==typeof r&&-1===r.indexOf(":"))return!1;try{return t=this.parser(r),new this(t.parts,t.zoneId),!0}catch(r){return r,!1}},t.IPv4.parse=function(r){var t;if(null===(t=this.parser(r)))throw new Error("ipaddr: string is not formatted like ip address");return new this(t)},t.IPv6.parse=function(r){var t;if(null===(t=this.parser(r)).parts)throw new Error("ipaddr: string is not formatted like ip address");return new this(t.parts,t.zoneId)},t.IPv4.parseCIDR=function(r){var t,n,e;if((n=r.match(/^(.+)\/(\d+)$/))&&(t=parseInt(n[2]))>=0&&t<=32)return e=[this.parse(n[1]),t],Object.defineProperty(e,"toString",{value:function(){return this.join("/")}}),e;throw new Error("ipaddr: string is not formatted like an IPv4 CIDR range")},t.IPv4.subnetMaskFromPrefixLength=function(r){var t,n,e;if((r=parseInt(r))<0||r>32)throw new Error("ipaddr: invalid IPv4 prefix length");for(e=[0,0,0,0],n=0,t=Math.floor(r/8);n<t;)e[n]=255,n++;return t<4&&(e[t]=Math.pow(2,r%8)-1<<8-r%8),new this(e)},t.IPv4.broadcastAddressFromCIDR=function(r){var t,n,e,i,o;try{for(e=(t=this.parseCIDR(r))[0].toByteArray(),o=this.subnetMaskFromPrefixLength(t[1]).toByteArray(),i=[],n=0;n<4;)i.push(parseInt(e[n],10)|255^parseInt(o[n],10)),n++;return new this(i)}catch(r){throw r,new Error("ipaddr: the address does not have IPv4 CIDR format")}},t.IPv4.networkAddressFromCIDR=function(r){var t,n,e,i,o;try{for(e=(t=this.parseCIDR(r))[0].toByteArray(),o=this.subnetMaskFromPrefixLength(t[1]).toByteArray(),i=[],n=0;n<4;)i.push(parseInt(e[n],10)&parseInt(o[n],10)),n++;return new this(i)}catch(r){throw r,new Error("ipaddr: the address does not have IPv4 CIDR format")}},t.IPv6.parseCIDR=function(r){var t,n,e;if((n=r.match(/^(.+)\/(\d+)$/))&&(t=parseInt(n[2]))>=0&&t<=128)return e=[this.parse(n[1]),t],Object.defineProperty(e,"toString",{value:function(){return this.join("/")}}),e;throw new Error("ipaddr: string is not formatted like an IPv6 CIDR range")},t.isValid=function(r){return t.IPv6.isValid(r)||t.IPv4.isValid(r)},t.parse=function(r){if(t.IPv6.isValid(r))return t.IPv6.parse(r);if(t.IPv4.isValid(r))return t.IPv4.parse(r);throw new Error("ipaddr: the address has neither IPv6 nor IPv4 format")},t.parseCIDR=function(r){try{return t.IPv6.parseCIDR(r)}catch(n){n;try{return t.IPv4.parseCIDR(r)}catch(r){throw r,new Error("ipaddr: the address has neither IPv6 nor IPv4 CIDR format")}}},t.fromByteArray=function(r){var n;if(4===(n=r.length))return new t.IPv4(r);if(16===n)return new t.IPv6(r);throw new Error("ipaddr: the binary input is neither an IPv6 nor IPv4 address")},t.process=function(r){var t;return t=this.parse(r),"ipv6"===t.kind()&&t.isIPv4MappedAddress()?t.toIPv4Address():t}}).call(this);
/* @@END ipaddr.js */
      return module.exports;
    })();
    return vendorIpaddr.lib;
  }

  /* ---------------------------------------------------------------------------
   * THIRD-PARTY NOTICES
   *
   * UAParser.js 1.0.41 - https://github.com/faisalman/ua-parser-js
   * Copyright (c) 2012-2025 Faisal Salman <f@faisalman.com>
   *
   * ipaddr.js 1.9.1 - https://github.com/whitequark/ipaddr.js
   * Copyright (C) 2011-2017 whitequark <whitequark@whitequark.org>
   *
   * Both are distributed under the MIT License:
   *
   * Permission is hereby granted, free of charge, to any person obtaining a copy
   * of this software and associated documentation files (the "Software"), to deal
   * in the Software without restriction, including without limitation the rights
   * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   * copies of the Software, and to permit persons to whom the Software is
   * furnished to do so, subject to the following conditions:
   *
   * The above copyright notice and this permission notice shall be included in
   * all copies or substantial portions of the Software.
   *
   * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   * THE SOFTWARE.
   * ------------------------------------------------------------------------- */
})(typeof window !== 'undefined' ? window : this);

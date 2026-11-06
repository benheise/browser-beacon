# browser-beacon.js v1.2.0: destinations, local log, performance options

Updated 2026-11-01.

## New in v1.2.0
- **`destinations`** (a list) replaces the single `transport`. Each report goes to every destination in parallel:
  - `pixel`: image GET; the access log records it.
  - `http`: POST to a receiving server.
  - `beacon`: sendBeacon.
  - `local`: a rolling log in the browser.
  - `callback`.
  - `console`.
- **Old `transport` configs** are mapped onto `destinations` automatically. Destinations set explicitly in a page override take precedence.
- **`http` destination options:**
  - `format`: `json` (needs a CORS preflight when cross-origin), `text` (JSON sent as text/plain) or `form` (urlencoded). The last two need no preflight when no custom headers are set.
  - `credentials`, `headers`.
  - `noCors`: fire-and-forget to a receiver without CORS. The reply isn't checked.
  - Uses `fetch` with keepalive, low priority and no Referer, falling back to XHR on older browsers.
  - Validation blocks an `http://` URL on an `https` page (mixed content) and non-http(s) schemes.
  - Secret-looking header names (Authorization, token, key) produce a console warning, because the script is readable by anyone who can load the portal.
- **Receiver contract:** one POST per report, under 4 KB, reply with any 2xx. A cross-origin receiver needs CORS (OPTIONS 204 with Allow-Origin, Methods and Headers). The receiver should take the client IP from the connection and re-apply the scope ranges.
- **`delivery`:**
  - `successWhen` (`any` or `all`) controls when a report counts as delivered;
  - `timeoutMs` and `maxUrlLength`;
  - `retryMinutes` defaults to [2, 10, 30, 60]. Repeated failures back off, so a collector outage doesn't cause a retry on every page view.
- **Local log:** browsers don't let a web page write to disk on its own. The `local` destination keeps a capped ring buffer in the site's localStorage, limited by `localLog.maxEntries` (30), `maxKB` (64) and `maxDays` (30).
  - Each entry is the record plus `_logged`, `_delivered` and `_to`, e.g. `pixel#1:ok,http#2:fail`.
  - `BrowserBeacon.downloadLog()` saves `browser-beacon-<host>-<time>.jsonl` with one JSON record per line. IE 11 uses `msSaveOrOpenBlob`.
  - `BrowserBeacon.log()` and `BrowserBeacon.clearLog()` are also available.
  - Out-of-scope page views never write to it.

## Performance options considered
| Option | Verdict | Why |
|---|---|---|
| Web Worker (a real second thread) | Not used | Measured cost: 0.9 ms on the main thread to create, 9.6 ms to first reply on a normal CPU (6.3 / 25 ms at 6× throttle). The remaining pure-JS work is about 3–5 ms in real terms, already split into idle-time tasks. WebRTC, DOM, localStorage and image beacons are main-thread-only APIs anyway. A worker also needs a second file or a `blob:` URL, which strict CSP `worker-src` policies block. |
| async/await | Not used | Syntax only, with no runtime gain. It would break the ES5 target that lets IE 11 and stale browsers report themselves. |
| `scheduler.postTask` / `scheduler.yield()` | Not used | Chrome/Edge 129+ and Firefox 142+; Safari doesn't support them. `requestIdleCallback` already gives idle priority, with a `setTimeout` fallback where it is missing (Safari: re-enabling is still blocked upstream, WebKit bug 285049). |
| Service Worker / Background Sync | Not used | Needs its own script at the site root and would conflict with any service worker the portal has. A failed report is regenerated on a later visit, with backoff. |
| SharedArrayBuffer / Atomics | Not used | Requires cross-origin isolation (COOP/COEP headers), which would break typical portals. |
| Load the script after `onload` (as Boomerang's loader snippet does) | Documented | Keeps the script out of the page's load event entirely. Needs an inline snippet (CSP nonce). |
| Versioned file name plus long cache lifetime | Documented | Repeat views load from cache and reuse V8's compiled-code cache. |
| `fetch` keepalive, low priority, no Referer | Adopted | Lets an in-flight report finish after navigation, and doesn't compete with page requests. |
| Backoff after failed delivery | Adopted | Bounds client work during a collector outage. |

## Performance check (6× CPU throttle, v1.1 → v1.2)
| Metric | v1.1 | v1.2 |
|---|---|---|
| Long tasks after load | none | none |
| Longest task containing beacon work | 32 ms | 32 ms |
| Throttled page view | 2.1 ms | 2.0 ms |
| Script evaluate | 4.6 ms | 6.2 ms |

The evaluate increase comes from the larger file: 117 KB, about 39 KB gzipped.

## Tests
- 47 unit tests pass. New coverage: multi-destination delivery, `successWhen`, local log trimming by count, size and age, `downloadLog` (anchor and IE paths), the backoff sequence, destination validation, and http json/text/form over XHR.
- 10 real-Chromium tests pass. New coverage:
  - a cross-origin receiver with CORS: preflight, Origin, no Referer, and pixel, http and local all at once;
  - a real `.jsonl` download;
  - noCors with no preflight;
  - a receiver without CORS or offline counts as failed and backs off.

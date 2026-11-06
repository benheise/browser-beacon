# browser-beacon.js v1.1.0: performance review

Reviewed 2026-11-01. The goal was to confirm the beacon never blocks page load or degrades the client. Measurements used real Chromium 153 with 6× CPU throttling (to stand in for a slow PC), against a simulated portal page. The page had 300 table rows, a 150 KB app script and a slow image. The harness used Chrome traces and CPU profiles, attributing each event to the beacon script.

## What v1.0.0 did wrong
- **Time-zone lookup:** the first `Intl.DateTimeFormat()` call, used only for the time-zone name, blocked the main thread for 9–14 ms on a normal CPU and 61–71 ms throttled.
- **One big task:** all post-load work ran in a few tasks with no yields. The UA parser also ran its device-model regex table, which isn't needed. Together this produced long tasks of 52–140 ms after load, which would hurt responsiveness if the user clicked then.
- **Throttled views:** page views that wouldn't send anything still ran the full UA parser.
- **Pre-load work:** config validation compiled the IP library during script execution, which is in the DOMContentLoaded path when the script uses `defer`.
- **WebRTC:** it was started on every report, even on browsers that always hide local addresses (most unmanaged browsers).
- **Request priority:** the IP-echo request went out at High priority.
- **Cookie:** the device cookie rode on every portal request.
- **Missing guards:** nothing handled prerendered pages, several tabs opening at once, or a `load` event that never fires.

## Changes in v1.1.0
- **Before load:** only function definitions and one listener. Validation is deferred, and skipped entirely on throttled views.
- **Task splitting:** the work runs in five stages, each in its own idle-time task.
- **Throttled views:** a throttle check on the raw UA plus Client Hints, with no parsing and no network.
- **UA parsing:**
  - Chromium with Client Hints skips the UA parser entirely. A test asserts it gives the same identity as the full parser.
  - Other browsers skip the device-model table.
- **Time zone:** the UTC offset is collected by default. The zone name is opt-in (`collect.timezoneName`).
- **WebRTC:** skipped for 7 days after a browser shows it hides local addresses (`collect.localIpsRetryDays`). The connection is closed and its timers cleared as soon as gathering ends.
- **Requests:** same-origin GETs use `fetch` with `priority: 'low'`, falling back to XHR on browsers without it. The beacon image is low priority and released after it completes.
- **Device cookie:** now opt-in (`device.cookie: false`).
- **Guards:**
  - waits for `prerenderingchange` on prerendered pages;
  - a 2-minute cross-tab lease;
  - a `report.maxWaitForLoadMs` fallback (30 s).
- **Deploy guidance:** use `async`, not `defer`. Serve it compressed (about 35 KB) and cacheable.

## Results (6× CPU throttle; divide by roughly 6 for a typical desktop)
| Metric | v1.0.0 | v1.1.0 |
|---|---|---|
| Script evaluate, first visit | 19.2 ms | 4.6 ms |
| Script evaluate, repeat visit | 4.9 ms | 1.9 ms |
| Long tasks (>50 ms) after load, first visit | 52–140 ms | none |
| Longest task containing beacon work, first visit | 91 ms | 32 ms |
| Total beacon main-thread time after load, first visit | 166 ms | 88 ms (spread across short tasks) |
| Beacon work after load, throttled repeat visit | 5.0 ms | 2.1 ms |
| IP-echo request priority | High | Low |
| Back/forward cache | eligible | eligible (tested idle, mid-run, and before start) |
| Page errors | 0 | 0 |

DOMContentLoaded, load and first-paint timings moved by less than the run-to-run noise. The no-beacon baseline itself varied by 20–40 ms between runs.

## Tests
- 40 unit tests pass. New coverage: lease, prerender, load fallback, WebRTC negative cache, cookie opt-in, time-zone opt-in, out-of-scope views writing no localStorage, and fast-path equivalence.
- 7 real-Chromium tests pass.
- The whole file parses as ES5, ESLint is clean, and the vendored blocks are byte-identical to npm.

# browser-beacon

browser-beacon finds outdated web browsers on company workstations, including machines with no endpoint agent. Every workstation that opens your internal portal reports its browser and OS version, its IP addresses, the username and a device ID. Each browser is judged against a version policy.

There are two parts:

| Part | What it is |
|---|---|
| [`dist/browser-beacon.js`](dist/browser-beacon.js) (v1.2.0) | One standalone JavaScript file with its configuration embedded. It needs no server-side code and makes no third-party requests. It is written in ES5, so the stale browsers it exists to find can still run it. |
| [`receiver/`](receiver/) (v1.0.0) | An optional zero-dependency Node.js receiver in a Chainguard or Distroless container. It keeps only reports from your IP ranges, handles CORS and writes daily JSON Lines logs. |

## Quick start

1. **Configure.** Copy `dist/browser-beacon.js` and edit the `CONFIG` block at the top. At minimum set:
   - `scope.include`: your company CIDR ranges. The script stays off until you set them.
   - `scope.sources`: how the page learns its client IP, from a meta tag your server writes, or an echo URL. The file header has one-liners for IIS, Apache and nginx.
   - `destinations`: where reports go.
2. **Deploy.** Add it to the portal's shared layout:
   ```html
   <script src="/assets/browser-beacon.js" async></script>
   ```
3. **Check.** In any browser's developer console, run `BrowserBeacon.preview()` to see exactly what would be sent, without sending it.
4. **Collect.** Pick one or more destinations:
   - `pixel` (default): an image request any web server writes to its access log, with no server code at all.
   - `http`: POST to the [receiver](receiver/README.md):
     ```sh
     docker build -t browser-beacon-receiver receiver/
     ```
   - `local`: a capped log kept in the browser, saved with `BrowserBeacon.downloadLog()`.
   - `beacon`, `callback` and `console` are also available.

## What each report contains

- **Browser:** family and full version, from User-Agent Client Hints where available.
- **Verdict:** one of `current`, `outdated`, `unsupported`, `unverified` or `unknown`. It comes with the release channel, the minimum version and how many majors behind.
- **OS:** name and version (Windows 10 and 11 are distinguished where the browser allows), plus architecture.
- **Identity:** the IP used for the scope check, WebRTC local IPs where the browser exposes them, the username (from configurable sources) and a persistent device ID.
- **Flags:** a spoof flag when the User-Agent and Client Hints disagree, and optional extension watch-list hits.

The full field list is in the header of `dist/browser-beacon.js`.

## Keep the version policy current

The embedded minimum versions are dated **2026-11-01**. Chrome and Edge now ship a major version every two weeks, so after `policy.maxAgeDays` (21 by default) a "current" verdict becomes "unverified" rather than passing silently. Update the floors in `CONFIG`, or serve them from a JSON file named in `policy.feedUrl`.

## Limits worth knowing

- Firefox reports only its major version, and an ESR build looks the same as an un-updated Release build at that major.
- Without Client Hints (a plain-HTTP portal or an old browser), Chromium browsers report only the major version.
- A web page cannot list installed extensions. Only specific extensions you name can be detected, and only some of those.
- Everything the browser reports can be edited by the user. The scope check in the page is a privacy and noise filter. The receiver repeats it on the real source address, and its `rx_*` fields are the trustworthy ones.
- A web page cannot write files to disk by itself. The `local` log lives in browser storage until it is downloaded.

## Client impact

Before the page finishes loading, the script only registers a listener. The rest waits for page load plus idle time and runs in short tasks that yield to the page. Page views that are throttled (all but one per browser per day) cost about 2 ms on a 6× slowed CPU, with no parsing and no network. No long tasks were measured, and the back/forward cache is unaffected. See [docs/performance-v1.1.md](docs/performance-v1.1.md).

## Building and testing

- **Deploy vs. develop:** to deploy, copy `dist/browser-beacon.js` and edit its `CONFIG` block. To change the code, edit `src/core.js` and rebuild. `dist/` is generated, and `npm run check` fails if it is out of date.
- **Commands:**
  ```sh
  npm ci
  npm run build          # src/core.js + vendored libraries -> dist/browser-beacon.js
  npm run lint           # ES5 parse check + ESLint on our own code
  npm test               # 47 unit tests (jsdom)
  npm run test:receiver  # 15 receiver tests (also run inside each Docker build)
  npm run check          # all of the above, and fails if dist/ is out of date

  # Real-browser tests (Chromium via Playwright, not installed by npm ci):
  npm i --no-save playwright && npx playwright install chromium && npm run test:browser
  ```
- **Performance harness:** `perf/perf.js` measures page-load impact and main-thread time with a 6× slowed CPU.
- **Container end-to-end test:** `tests/receiver-e2e.js` drives a real browser against a running receiver container (see its header).

## Third-party code

Two libraries are bundled verbatim into `dist/browser-beacon.js`. Each block is byte-identical to its npm file, so it can be checked by hash; a unit test does this. The MIT notices are at the end of the file.

| Library | License | SHA-256 |
|---|---|---|
| [UAParser.js](https://github.com/faisalman/ua-parser-js) 1.0.41 (`dist/ua-parser.min.js`) | MIT | `506462f5…d9fa2ea` |
| [ipaddr.js](https://github.com/whitequark/ipaddr.js) 1.9.1 (`ipaddr.min.js`) | MIT | `ab95215c…c151440` |

UAParser.js 2.x is AGPL-3.0 or paid, and ipaddr.js 2.x is not ES5, so neither upgrade fits. The receiver has no npm dependencies.

## Documentation

- [docs/design-v1.0.md](docs/design-v1.0.md): original design and open-source survey
- [docs/performance-v1.1.md](docs/performance-v1.1.md): performance review and measurements
- [docs/destinations-v1.2.md](docs/destinations-v1.2.md): destinations, receiver contract, local log, performance options considered
- [receiver/README.md](receiver/README.md): receiver build, configuration, networking and operations

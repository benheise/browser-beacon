# browser-beacon.js v1.0.0 — outdated-browser telemetry for the company portal

Built 2026-11-01. A single standalone JavaScript file with its configuration embedded. It doesn't depend on any particular server and has no runtime dependencies. It is ES5, so the outdated browsers it targets can still run it.

## How it works
- The default transport is a 1x1 GIF request: `GET /browser-beacon.gif?v=1&bk=..&bv=..&vrd=..`. Any web server's access log records it, along with the client IP the server saw, the authenticated user (if the path requires auth), the time and the User-Agent. Other modes are available: `beacon` (sendBeacon JSON), `post` (XHR JSON), `callback` and `console`.
- Scope is set with `scope.include` / `scope.exclude` (IPv4/IPv6 CIDR). The script fails closed:
  - An empty include list, a malformed CIDR, a /0, or a CIDR with host bits set disables the script and logs a console warning.
  - Octal-looking IPv4 addresses are refused.
  - If no IP can be found, the default is to skip.
- Page JavaScript can't see its own address the way the server does, so the client IP has to come from one of:
  - a `<meta name="browser-beacon-client-ip">` tag the server writes into the page;
  - a same-origin echo URL (the file header has one-liners for IIS SSI, Apache mod_headers and nginx);
  - WebRTC. Browsers hide local addresses behind mDNS names unless a managed policy exposes them, so this only works on managed devices.
- The client-side scope check is a privacy and noise filter, not a security control. Re-apply the CIDR list when ingesting logs.
- Version policy has floors per channel. A newer major always passes, the same major must meet the minimum, and Extended Stable / ESR apply only to their own major. The policy can also come from a JSON feed (`policy.feedUrl`). Once the policy is older than `maxAgeDays` (21 by default), "current" becomes "unverified", so stale floors never pass silently.
- Embedded floors as of 2026-11-01:

  | Browser | Floor |
  |---|---|
  | Chrome Stable | 156.0.8078.73 |
  | Chrome Extended Stable | 152.0.7977.167 |
  | Edge Stable | 156.0.4314.58 (Edge Extended Stable not set) |
  | Firefox | 159 |
  | Firefox ESR 153 / ESR 115 | unverified (patch level isn't visible) |
  | Safari | 27.2 |
  | Other Chromium browsers | engine ≥ 155 |
  | IE, EdgeHTML | unsupported |

- Username can come from a meta tag, a JSON URL, a DOM element, a global variable, a cookie or a function. The more reliable source is the server log, by putting auth on the beacon path.
- Other features:
  - The device ID persists in localStorage and is mirrored to a first-party cookie.
  - Reports are throttled to once per 24 h per browser. A version or policy change reports on the next visit.
  - Optional notice banner, off by default.
  - Optional extension watch list (DOM markers, globals, Chromium web-accessible resources), off by default.

## Open-source components
| Project | License | Use |
|---|---|---|
| ua-parser-js 1.0.41 | MIT | Bundled verbatim. sha256 506462f5…d9fa2ea (dist/ua-parser.min.js). v2 is AGPL-3.0 or a paid PRO license. Releases 0.7.29/0.8.0/1.0.0 were hijacked in Oct 2021, so it is pinned and hash-checked, never loaded from a CDN. |
| ipaddr.js 1.9.1 | MIT | Bundled verbatim. sha256 ab95215c…c151440 (ipaddr.min.js). 2.x is not ES5. |
| browser-update.org | MIT | Reference for the user-notice concept. A lighter built-in notice is used instead. |
| Bowser 2.15 | MIT | Test oracle for UA parsing. |
| Boomerang (Akamai) | BSD-3-Clause | Considered for transport. Too heavy for one beacon. |
| browserslist-useragent-regexp 4.x | MIT | Major-version-only regex gate. Not precise enough on its own. |
| @mdn/browser-compat-data | CC0-1.0 | Candidate source of release dates for a policy-feed generator. |
| crx-scouter, z0ccc/extension-detector | none shown / unverified | Technique and data for extension probing only. Don't copy their code. |

## Verification
- The whole file parses as ES5 (acorn). ESLint is clean (no-undef, unused vars).
- The core is ASCII-only.
- The vendored blocks are byte-identical to the npm files.
- 32 jsdom unit tests pass, including:
  - 60,000 CIDR cases checked against ipaddr.js 2.5.0;
  - a 27-case UA / Client Hints corpus;
  - a Bowser cross-check;
  - scope, transport, throttle, policy feed, notice, no global leakage, and storage failures.
- 7 real-Chromium tests pass (Playwright), stable across 3 runs:
  - the Client Hints full version matched the real browser;
  - the URL echo source works;
  - out of scope sends nothing;
  - WebRTC is hidden by default and works when exposed;
  - a UA override gets flagged as spoof;
  - the notice renders.
- Real Firefox, Safari and IE weren't available. Those paths are tested from UA strings only.

## Known limits
- Firefox reports only its major version.
- Without Client Hints (plain-HTTP portal, or an old Chromium), Chromium gives only the major version.
- Extension inventory is not possible from a page. Only named watch-list items can be detected.
- Policy floors go stale within about 2 weeks at the Chrome and Edge cadence. Use `feedUrl`.

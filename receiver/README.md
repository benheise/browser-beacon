# browser-beacon receiver 1.0.0

The receiver collects reports from `browser-beacon.js` (v1.2+). It accepts the beacon's **http**, **beacon** and **pixel** destinations. It keeps a report only when the **source IP address** is inside `ALLOWED_RANGES`, and appends each kept report as one line to a **daily JSON Lines file**. CORS is handled for an allow-list of portal origins.

It uses the Node.js 26 standard library only, with no npm dependencies. It ships as a container image built on **Chainguard** (`Dockerfile`) or **Google Distroless** (`Dockerfile.distroless`).

| File | Purpose |
|---|---|
| `server.js` | The receiver (single file) |
| `Dockerfile` | Chainguard `node` image, pinned by digest |
| `Dockerfile.distroless` | Distroless `nodejs26-debian13:nonroot`, pinned by digest; no shell |
| `docker-compose.yml` | Example deployment: TLS, named log volume, read-only, no capabilities |
| `test/receiver.test.js` | Unit and process tests; run inside the image build |
| `test/smoke.js` | Post-deployment check against a running receiver |

## Build

```sh
docker build -t browser-beacon-receiver:1.0.0 .                                          # Chainguard
docker build -f Dockerfile.distroless -t browser-beacon-receiver:1.0.0-distroless .      # Distroless
```

The build runs the test suite in a first stage, using the same base image, so an image is only produced if the tests pass. Both stages use exec-form `RUN` with no shell.

**Choosing a base:**

| | Chainguard (`Dockerfile`) | Distroless (`Dockerfile.distroless`) |
|---|---|---|
| Rebuild cadence | Rebuilt daily (fastest CVE fixes) | Rebuilt as Debian and Node publish fixes |
| Versions on the free tier | `:latest` only | Pinned Node major, e.g. `nodejs26` |
| Shell in the runtime image | Currently includes busybox (`/bin/sh`) | None (verified: `exec /bin/sh` fails) |
| Node version (2026-11-01) | 26.12.1 | 26.13.0 |

If a shell-free runtime is a requirement, use Distroless.

**Refreshing the pinned digest:** both Dockerfiles pin the base image by digest so builds are repeatable. Refresh it on a schedule (or let Renovate/Dependabot do it) to pick up security fixes:

```sh
docker buildx imagetools inspect cgr.dev/chainguard/node:latest
docker buildx imagetools inspect gcr.io/distroless/nodejs26-debian13:nonroot
```

## Run

```sh
docker volume create beacon-logs
docker run -d --name beacon-receiver --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 8443:8443 \
  -e PORT=8443 \
  -e ALLOWED_RANGES="10.0.0.0/8,172.16.0.0/12" \
  -e ALLOWED_ORIGINS="https://portal.example.com" \
  -e TLS_CERT_FILE=/certs/receiver.crt -e TLS_KEY_FILE=/certs/receiver.key \
  -v /etc/beacon/certs:/certs:ro \
  -v beacon-logs:/var/log/browser-beacon \
  browser-beacon-receiver:1.0.0
```

You can use `docker compose up -d --build` with `docker-compose.yml` instead.

**Runtime properties:**
- The service runs as uid/gid 65532.
- The code is root-owned and read-only.
- Only `/var/log/browser-beacon` is writable, so a read-only root filesystem works.
- A named volume inherits the right owner. A bind-mounted log directory must be writable by uid 65532 (`chown 65532:65532 <dir>`).
- The TLS key must be readable by 65532.

### Point the beacon at it
In the `CONFIG.destinations` of `browser-beacon.js`:

```js
destinations: [
  { type: 'http',  url: 'https://beacon-rx.corp.example:8443/browser-beacon', format: 'json' },
  { type: 'pixel', url: 'https://beacon-rx.corp.example:8443/browser-beacon.gif' }   // optional second path
]
```

The portal's Content-Security-Policy must allow the receiver: `connect-src` for http, `img-src` for pixel.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `ALLOWED_RANGES` | **required** | Company ranges, IPv4/IPv6 CIDR, comma or space separated. Startup fails if empty, malformed, `/0`, or if host bits are set (`10.1.2.3/8`). |
| `EXCLUDED_RANGES` | | Ranges never accepted (guest Wi-Fi, the container network; see networking below) |
| `ALLOWED_ORIGINS` | | Portal origins allowed by CORS, e.g. `https://portal.example.com`. `*` is refused. Requests carrying any other `Origin` get 403. |
| `ALLOW_CREDENTIALS` | `false` | Send `Access-Control-Allow-Credentials: true` (needed if the beacon uses `credentials: 'include'`) |
| `ALLOWED_HEADERS` | | Extra request headers to allow in preflight (beyond `Content-Type`) |
| `REQUIRE_ORIGIN` | `false` | Reject POSTs without an `Origin` header (non-browser clients) |
| `TRUSTED_PROXIES` | | Reverse proxies whose `X-Forwarded-For` is honoured (see below) |
| `PORT` / `HOST` | `8080` / all | Listen port and address |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | | PEM files. Enables HTTPS (TLS 1.2+). Restart to load a renewed certificate. |
| `POST_PATH` / `PIXEL_PATH` | `/browser-beacon` / `/browser-beacon.gif` | Endpoints |
| `LOG_DIR` | `/var/log/browser-beacon` | Must exist and be writable |
| `LOG_PREFIX` | `browser-beacon` | File name prefix. Give each replica its own prefix if several share one volume. |
| `LOG_RETENTION_DAYS` | `0` | Delete this receiver's daily files older than N days. `0` keeps them forever: set it to match your retention policy. |
| `RATE_LIMIT_PER_MIN` | `60` | Requests per client address per minute (0 = off). Over the limit: 429. |
| `MAX_BODY_BYTES` | `8192` | Larger bodies get 413 (a beacon report is under 4 KB) |
| `STATS_INTERVAL_SECONDS` | `300` | Summary line of accepted and rejected counts on stdout (0 = off) |

Invalid configuration exits with code 2 and lists every problem. The receiver never starts with partial settings.

## What gets logged

The log path is `LOG_DIR/<prefix>-YYYY-MM-DD.jsonl` (UTC date, mode 0640). Each line is one report: the beacon's fields (see the `browser-beacon.js` header) plus fields the receiver adds itself. A client cannot set `rx_*` fields.

```json
{"v":"1","bk":"chrome","bv":"156.0.8078.80","vrd":"current","usr":"CORP\\jdoe","did":"…","rid":"…",
 "rx_time":"2026-11-01T18:00:13.902Z","rx_ip":"10.20.30.40","rx_range":"10.0.0.0/8",
 "rx_via":"http","rx_origin":"https://portal.example.com","rx_ua":"Mozilla/5.0 …"}
```

| Field | Meaning |
|---|---|
| `rx_time` | Receive time (UTC) |
| `rx_ip` | Client address used for the range check (trustworthy, unlike the beacon's own `ip`) |
| `rx_peer` | The proxy address, present only when the request came through a trusted proxy |
| `rx_range` | The `ALLOWED_RANGES` entry that matched |
| `rx_via` | `http` or `pixel` |
| `rx_origin` | Request `Origin` header |
| `rx_ua` | Request `User-Agent` header |

How requests are handled:
- Values are flattened, control characters stripped, and each value capped at 1 KB and 80 fields. Anything without a `v` field is not a report and is not logged.
- **Out-of-range sources** are answered as if accepted (204, or the GIF) and discarded. The client learns nothing and does not retry.
- The pixel endpoint always returns the same GIF.
- Rejections are counted in the periodic stats line rather than logged one by one.

## Source addresses and networking

The receiver trusts the TCP peer address. Make sure that address is the real client:

- **Published ports (`-p`) on Linux:** Docker's iptables DNAT keeps the client address for normal external traffic. Some connections are relayed by `docker-proxy` instead (hairpin or localhost traffic, some IPv6 setups). Those arrive from the container network's gateway. At startup the receiver warns if that gateway is inside `ALLOWED_RANGES`; exclude it. The compose file pins the network subnet (`BEACON_NET`, default `172.31.254.0/24`) and excludes it for this reason.
- **Host networking** (`--network host`) avoids NAT entirely. It is the simplest way to get exact client addresses on Linux.
- **Behind a reverse proxy or load balancer:** put its address in `TRUSTED_PROXIES`. The receiver then reads `X-Forwarded-For` from right to left, skipping trusted proxies; the first other address is the client. Entries it can't parse fail closed. `X-Forwarded-For` from anyone else is ignored. Configure the proxy to append to the header rather than pass a client-supplied one through unchecked.
- **Mixed content:** an `https` portal cannot send to an `http` receiver. Terminate TLS in the receiver (`TLS_*`) or in the proxy.

## Operations
- **Health:** `GET /healthz` returns 200 while the log directory is writable, otherwise 503. The image's `HEALTHCHECK` runs `node server.js --healthcheck` (no curl or shell needed).
- **Stop:** `docker stop` sends SIGTERM. The receiver stops accepting connections, finishes in-flight requests, flushes the log and exits 0, within about 0.1 s in testing.
- **Smoke test** after deploying, from a machine inside the ranges:

  ```sh
  node test/smoke.js https://beacon-rx.corp.example:8443 https://portal.example.com
  ```

  Then look for the printed report ID in today's log. Run from outside the ranges, every check still passes but nothing is logged.
- **Scaling:** run one receiver per log volume, or give each replica its own `LOG_PREFIX`.

## Testing done (2026-11-01)
- **In the image build:** 15 tests passed in each image (14 run; the TLS test is skipped there because the images have no `openssl`). The suite covers:
  - config validation;
  - CIDR matching against an independent BigInt implementation (20,000 IPv4/IPv6 cases);
  - CORS allow and deny, plus preflight;
  - JSON, text and form bodies;
  - 400/403/413/415/429 responses;
  - out-of-range and excluded sources;
  - `X-Forwarded-For` walking and spoofing;
  - the pixel endpoint;
  - UTC-midnight rollover and retention;
  - healthz, startup exit codes, `--healthcheck`, and SIGTERM flushing.
- **Locally:** all 15 tests pass, including TLS.
- **Containers (both images):** run read-only, with all capabilities dropped, no-new-privileges and TLS.
  - Both reported healthy and passed the smoke test.
  - Records landed in the named volume with mode 0640.
  - Writes to `/app` and `/tmp` failed (EROFS), and the process ran as uid 65532.
  - An out-of-range receiver logged nothing.
  - `docker stop` exited 0.
- **Real-browser end-to-end:** Chromium running `browser-beacon.js` 1.2 on a portal origin sent pixel and JSON reports cross-origin to the Distroless container over TLS. Both were logged with the same report ID and the `rx_*` fields, and the beacon's local log recorded both deliveries as successful.

# syntax=docker/dockerfile:1
#
# browser-beacon receiver on Chainguard's Node image.
#   docker build -t browser-beacon-receiver:1.0.0 .
#
# The base image is pinned by digest so builds are repeatable:
#   cgr.dev/chainguard/node:latest (Node 26.12.1), digest taken 2026-11-01.
# Chainguard rebuilds :latest daily with security fixes. Refresh the digest on a schedule:
#   docker buildx imagetools inspect cgr.dev/chainguard/node:latest
# Note: this Chainguard image currently includes busybox (/bin/sh). For a shell-free
# runtime use Dockerfile.distroless.
ARG NODE_IMAGE=cgr.dev/chainguard/node:latest@sha256:6cb70d6b2a324e491263949ea9f58938ed19031ef478e0bdb0b1810f96f8b400

# ---- 1. test: the image is only produced if the tests pass --------------------------
FROM ${NODE_IMAGE} AS test
WORKDIR /src
COPY server.js ./
COPY test/ ./test/
RUN ["/usr/bin/node", "--check", "server.js"]
RUN ["/usr/bin/node", "--test", "test/receiver.test.js"]
# Empty log directory to copy into the runtime image with the right owner.
RUN ["/usr/bin/node", "-e", "require('fs').mkdirSync('/tmp/logdir')"]

# ---- 2. runtime ----------------------------------------------------------------------
FROM ${NODE_IMAGE}
LABEL org.opencontainers.image.title="browser-beacon-receiver" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.description="Receives browser-beacon reports, keeps those from allowed IP ranges, writes daily JSON Lines logs"
# Code owned by root and read-only; only the log directory is writable by the service user.
# WORKDIR first so /app is created 0755 (COPY --chmod would also apply 0444 to a new parent).
WORKDIR /app
COPY --chown=0:0 --chmod=0444 server.js /app/server.js
COPY --from=test --chown=65532:65532 --chmod=0750 /tmp/logdir /var/log/browser-beacon
USER 65532:65532
ENV NODE_ENV=production \
    PORT=8080 \
    LOG_DIR=/var/log/browser-beacon
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/bin/node", "/app/server.js", "--healthcheck"]
# The base image's entrypoint is /usr/bin/node.
CMD ["/app/server.js"]

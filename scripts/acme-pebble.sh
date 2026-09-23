#!/usr/bin/env bash
# Local ACME e2e against pebble (Let's Encrypt's test CA).
#
# Usage: scripts/acme-pebble.sh
#
# Requires Docker. Starts pebble with validation always-valid (protocol
# flow without real DNS/ports), fetches its directory-HTTPS trust anchor,
# and runs the acme_runtime e2e (issuance → TLS serving → tunnel routing).
set -euo pipefail

PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
NAME="interflow-pebble"
TMP="$(mktemp -d)"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p 14000:14000 -p 15000:15000 \
  -e PEBBLE_VA_NOSLEEP=1 \
  -e PEBBLE_VA_ALWAYS_VALID=1 \
  -e PEBBLE_WFE_NONCEREJECT=0 \
  "$PEBBLE_IMAGE" >/dev/null

# The directory endpoint's own TLS chain anchors at the image's minica
# root; extract it from a scratch container (the runtime image is
# distroless — no shell to docker-exec).
docker rm -f "${NAME}-inspect" >/dev/null 2>&1 || true
docker create --name "${NAME}-inspect" "$PEBBLE_IMAGE" >/dev/null
docker cp "${NAME}-inspect:/test/certs/pebble.minica.pem" "$TMP/pebble.minica.pem" >/dev/null
docker rm -f "${NAME}-inspect" >/dev/null

INTERFLOW_PEBBLE=https://127.0.0.1:14000/dir \
INTERFLOW_PEBBLE_CA="$TMP/pebble.minica.pem" \
  cargo test -p interflow-expose --test acme_runtime -- --nocapture

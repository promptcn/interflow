#!/usr/bin/env bash
# Local ACME e2e against pebble (Let's Encrypt's test CA).
#
# This script is the single source of the pebble environment contract:
# image, container env, ports, and the INTERFLOW_PEBBLE / INTERFLOW_PEBBLE_CA
# variables the acme tests consume. Everything local that needs pebble
# goes through it (scripts/ci_test_stages.sh for the full test-job stages,
# the default mode below for the focused single-test run).
#
# Usage:
#   scripts/acme-pebble.sh            # up + run the acme_runtime e2e + down
#   scripts/acme-pebble.sh up         # start pebble; print eval-able export lines
#   scripts/acme-pebble.sh down       # stop pebble; drop the CA tempdir
#   scripts/acme-pebble.sh ca         # print a usable trust-anchor path (own
#                                     #   container, else extract one from any
#                                     #   running pebble — GitHub service case)
#
# Requires Docker. Pebble runs with validation always-valid (protocol flow
# without real DNS/ports).
set -euo pipefail

PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
NAME="interflow-pebble"
STATE="/tmp/interflow-pebble.state"
DIR_URL="https://127.0.0.1:14000/dir"

is_up() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$NAME"
}

cmd_up() {
  local ca_tmp
  if [ -f "$STATE" ] && is_up; then
    # shellcheck disable=SC1090
    . "$STATE" # sets CA_TMP
    print_env "$CA_TMP"
    return 0
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  ca_tmp="$(mktemp -d)"
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
  docker cp "${NAME}-inspect:/test/certs/pebble.minica.pem" "$ca_tmp/pebble.minica.pem" >/dev/null
  docker rm -f "${NAME}-inspect" >/dev/null

  printf 'CA_TMP=%q\n' "$ca_tmp" >"$STATE"

  # Readiness: the directory must answer over its own TLS chain before the
  # tests hit it (curl is present on dev hosts and CI runners; without it,
  # fall back to a fixed grace period).
  if command -v curl >/dev/null 2>&1; then
    local i
    for i in $(seq 1 30); do
      curl -fs --cacert "$ca_tmp/pebble.minica.pem" "$DIR_URL" >/dev/null 2>&1 && break
      sleep 1
    done
  else
    sleep 3
  fi

  print_env "$ca_tmp"
}

print_env() {
  printf 'export INTERFLOW_PEBBLE=%q\n' "$DIR_URL"
  printf 'export INTERFLOW_PEBBLE_CA=%q\n' "$1/pebble.minica.pem"
}

cmd_down() {
  docker rm -f "$NAME" "${NAME}-inspect" >/dev/null 2>&1 || true
  if [ -f "$STATE" ]; then
    # shellcheck disable=SC1090
    . "$STATE"
    [ -n "${CA_TMP:-}" ] && rm -rf "$CA_TMP"
    rm -f "$STATE"
  fi
}

cmd_ca() {
  if [ -f "$STATE" ]; then
    # shellcheck disable=SC1090
    . "$STATE"
    if [ -n "${CA_TMP:-}" ] && [ -f "$CA_TMP/pebble.minica.pem" ]; then
      printf '%s\n' "$CA_TMP/pebble.minica.pem"
      return 0
    fi
  fi
  # Extract from any running pebble container (the GitHub service-container
  # case — docker cp works on distroless images).
  local cid
  cid="$(docker ps -qf "name=^${NAME}$")"
  [ -n "$cid" ] || cid="$(docker ps -qf "ancestor=$PEBBLE_IMAGE")"
  [ -n "$cid" ] || { echo "FAIL: no running pebble container (run '$0 up' first)" >&2; return 1; }
  docker cp "${cid}:/test/certs/pebble.minica.pem" /tmp/interflow-pebble-ca.pem >/dev/null
  printf '%s\n' /tmp/interflow-pebble-ca.pem
}

case "${1:-run}" in
up) cmd_up ;;
down) cmd_down ;;
ca) cmd_ca ;;
run)
  # Focused run: the acme_runtime e2e (issuance → TLS serving → tunnel
  # routing) against a self-managed pebble.
  trap cmd_down EXIT
  eval "$(cmd_up)"
  cargo test -p interflow-expose --test acme_runtime -- --nocapture
  ;;
*)
  echo "usage: $0 [up|down|ca|run]" >&2
  exit 2
  ;;
esac

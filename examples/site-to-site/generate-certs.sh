#!/usr/bin/env bash
# Generate local, git-ignored mTLS material for the site-to-site example.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [ -n "${INTERFLOW_CERTS_DIR:-}" ]; then
    case "$INTERFLOW_CERTS_DIR" in
        /*) CERTS="$INTERFLOW_CERTS_DIR" ;;
        *) CERTS="$SCRIPT_DIR/$INTERFLOW_CERTS_DIR" ;;
    esac
else
    CERTS="$SCRIPT_DIR/certs"
fi
MESH_BIN="${INTERFLOW_MESH_BIN:-interflow-mesh}"
HUB_DNS="127.0.0.1"
FORCE=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --hub-dns)
            [ "$#" -ge 2 ] || { echo "--hub-dns requires a value" >&2; exit 2; }
            HUB_DNS="$2"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        *)
            echo "usage: $0 [--hub-dns <hostname-or-ip>] [--force]" >&2
            exit 2
            ;;
    esac
done

INIT_ARGS=(--tenant demo --hub-dns "$HUB_DNS" --out "$CERTS")
if [ "$FORCE" -eq 1 ]; then
    INIT_ARGS+=(--force)
fi

"$MESH_BIN" certs init "${INIT_ARGS[@]}"
for agent in lan-a lan-b; do
    AGENT_ARGS=(demo "$agent" --out "$CERTS")
    if [ "$FORCE" -eq 1 ]; then
        AGENT_ARGS+=(--force)
    fi
    "$MESH_BIN" certs agent issue "${AGENT_ARGS[@]}"
done

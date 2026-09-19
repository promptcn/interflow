#!/usr/bin/env bash
# Generate the dev-only mTLS material for the public-domain-to-lan example.

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
HUB_DNS="hub.example.com"
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
AGENT_ARGS=(demo lan-agent --out "$CERTS")
if [ "$FORCE" -eq 1 ]; then
    INIT_ARGS+=(--force)
    AGENT_ARGS+=(--force)
fi

"$MESH_BIN" certs init "${INIT_ARGS[@]}"
"$MESH_BIN" certs agent issue "${AGENT_ARGS[@]}"

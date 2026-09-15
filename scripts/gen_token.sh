#!/bin/bash
# Generate a strong random token at the recommended strength (32 bytes = 256 bits of entropy).
#
# Usage:
#   ./scripts/gen_token.sh                          # output hex
#   ./scripts/gen_token.sh base64                   # output base64
#   INTERFLOW_AGENT_TOKEN=$(./scripts/gen_token.sh) # assign directly to an env var
#
# Write the output to a file for @file: references:
#   ./scripts/gen_token.sh > /etc/interflow/agent.token && chmod 600 /etc/interflow/agent.token

set -e

format="${1:-hex}"

case "$format" in
    hex)
        openssl rand -hex 32
        ;;
    base64)
        openssl rand -base64 32
        ;;
    *)
        echo "Usage: $0 [hex|base64]" >&2
        exit 1
        ;;
esac

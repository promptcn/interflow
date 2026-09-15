#!/bin/bash
# Start interflow-expose edge (public-server side) — production-ready
#
# Purpose: run the HubServer + HTTP listener. nginx forwards port 443 traffic
# to the local 8443; the edge routes by Host header to the matching LAN
# expose agent.
#
# Read this first: the edge's internal hub defaults to 127.0.0.1:16666, but
# the LAN expose agents dial in from the public internet, so it is changed
# to 0.0.0.0:16666 here. **The expose hub supports static-token auth only —
# there is no mTLS option.** Production hardening: restrict 16666 to your
# known egress IPs with iptables / cloud security groups.

set -euo pipefail

cd "$(dirname "$0")"

: "${INTERFLOW_EDGE_TOKEN:?INTERFLOW_EDGE_TOKEN must be set (same value as the LAN expose side)}"

exec /usr/local/bin/interflow-expose edge \
    --listen 0.0.0.0:8443 \
    --hub-listen 0.0.0.0:16666 \
    --routes routes.toml \
    --token "${INTERFLOW_EDGE_TOKEN}" \
    --hub-cert certs/hub.crt \
    --hub-key certs/hub.key \
    --audit-path /var/log/interflow/edge-audit.jsonl \
    --new-conn-rate-per-ip-per-minute 30

#!/bin/bash
# Generate the full set of Interflow mTLS certificates: CA + Hub server certificate + Agent client certificates.
#
# The CN of an Agent certificate must equal the agent_id; the hub verifies during
# the handshake:
#   1. the certificate is issued by this CA (client auth)
#   2. the CN matches the x-agent-id in the request (prevents impersonation)
#
# Usage:
#   ./scripts/gen_certs.sh                                          # CA + hub + agent-1/2 into ./certs
#   ./scripts/gen_certs.sh examples/reverse-tunnel-public/certs     # into a specific directory (positional arg)
#   CERTS_DIR=... AGENTS="id1 id2" ./scripts/gen_certs.sh           # env-var overrides
#
# Generated certificates live only on this machine — they are git-ignored by
# policy (2026-09-15) and must never be committed.

set -e

CERTS_DIR="${1:-${CERTS_DIR:-certs}}"
AGENTS="${AGENTS:-agent-1 agent-2}"
DAYS="${DAYS:-365}"
CA_DAYS="${CA_DAYS:-3650}"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# -------- CA --------
if [ ! -f ca.key ] || [ ! -f ca.crt ]; then
    echo "==> Generating CA..."
    openssl genrsa -out ca.key 2048
    openssl req -x509 -new -nodes -key ca.key -sha256 -days "$CA_DAYS" \
        -out ca.crt -subj "/CN=Interflow CA"
else
    echo "==> CA already exists, skipping"
fi

# -------- Hub server certificate --------
gen_server_cert() {
    local name="$1"
    local san_dns="${2:-localhost}"
    local san_ip="${3:-127.0.0.1}"

    if [ -f "$name.key" ] && [ -f "$name.crt" ]; then
        echo "==> $name certificate already exists, skipping"
        return
    fi

    echo "==> Generating $name server certificate (SAN: $san_dns, $san_ip)..."
    openssl genrsa -out "$name.key" 2048
    # rustls requires PKCS8
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
        -in "$name.key" -out "$name.pkcs8.key"
    mv "$name.pkcs8.key" "$name.key"
    chmod 600 "$name.key"

    cat > "$name.conf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $san_dns

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $san_dns
IP.1 = $san_ip
EOF

    openssl req -new -key "$name.key" -out "$name.csr" -config "$name.conf"
    openssl x509 -req -in "$name.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "$name.crt" -days "$DAYS" -sha256 \
        -extensions v3_req -extfile "$name.conf"
    rm "$name.conf" "$name.csr"
}

# -------- Agent client certificates --------
# The CN must equal the agent_id. The hub validates this.
gen_agent_cert() {
    local agent_id="$1"

    if [ -f "agent-$agent_id.key" ] && [ -f "agent-$agent_id.crt" ]; then
        echo "==> agent-$agent_id certificate already exists, skipping"
        return
    fi

    echo "==> Generating agent-$agent_id client certificate (CN=$agent_id)..."
    openssl genrsa -out "agent-$agent_id.key" 2048
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
        -in "agent-$agent_id.key" -out "agent-$agent_id.pkcs8.key"
    mv "agent-$agent_id.pkcs8.key" "agent-$agent_id.key"
    chmod 600 "agent-$agent_id.key"

    cat > "agent-$agent_id.conf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $agent_id

[v3_req]
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

    openssl req -new -key "agent-$agent_id.key" -out "agent-$agent_id.csr" \
        -config "agent-$agent_id.conf"
    openssl x509 -req -in "agent-$agent_id.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "agent-$agent_id.crt" -days "$DAYS" -sha256 \
        -extensions v3_req -extfile "agent-$agent_id.conf"
    rm "agent-$agent_id.conf" "agent-$agent_id.csr"
}

# Generate the hub certificate
gen_server_cert hub localhost 127.0.0.1

# Generate all agent client certificates
for agent in $AGENTS; do
    gen_agent_cert "$agent"
done

echo
echo "==> Done. Contents of $CERTS_DIR:"
ls -l
echo
echo "Next steps:"
echo "  - hub.toml:        tls.cert_path = $CERTS_DIR/hub.crt, tls.key_path = $CERTS_DIR/hub.key"
echo "  - hub.toml:        auth.mtls.ca_path = $CERTS_DIR/ca.crt"
echo "  - agent-X.toml:    tls.ca_path = $CERTS_DIR/ca.crt"
echo "  - agent-X.toml:    tls.client_cert_path = $CERTS_DIR/agent-<id>.crt"
echo "  - agent-X.toml:    tls.client_key_path  = $CERTS_DIR/agent-<id>.key"

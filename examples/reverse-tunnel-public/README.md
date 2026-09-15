# Reverse Tunnel — Public Entry Point

Public users reach LAN services through a public domain. Typical use case:
exposing a home ASR/TTS service as a public API.

```
┌─────────┐     ┌─────────────────────────────────────────────┐     ┌────────────┐
│ Public  │ ──▶ │ Public server                                │ ──▶ │ LAN machine│
│ user    │     │  nginx (443) → edge (8443) → hub (16666)     │     │ expose     │
│ (HTTPS) │     │                          (0.0.0.0:16666)     │     │ → :8080    │
└─────────┘     └─────────────────────────────────────────────┘     └────────────┘
                       TLS (Let's Encrypt)        TLS (self-signed hub cert)
```

**Binary**: `interflow-expose` (subcommands `edge` / `expose` / `init`)

## Differences from scenario 1 (mesh)

| Aspect | interflow-mesh (scenario 1) | interflow-expose (scenario 2) |
|---|---|---|
| Purpose | Two LAN machines reach each other | Public users → LAN service |
| Auth | mTLS + ACL | static-token (hub has no mTLS option) |
| Public entry | hub directly exposed | nginx terminates TLS → edge → hub |
| Routing | dynamic / ACL | Host header → agent_id static route table |
| Config carrier | toml files | edge uses CLI flags; expose uses profile.toml |

⚠️ **The expose hub supports static-token auth only** — no mTLS. Production
hardening:
- Restrict port 16666 to known egress IPs with iptables / cloud security groups
- Strong random token (`openssl rand -hex 32`)
- Client authentication at the nginx layer (mTLS / Basic Auth / OAuth proxy)

## Trust model

| Role | What it can see | Can it impersonate others? |
|---|---|---|
| **Public user** | Its own requests/responses | N/A (the user is the end party) |
| **Nginx** | Plaintext between user and edge (TLS termination) | No (forward-only) |
| **Edge/hub operator** | **All plaintext** (hub also terminates TLS) | No (token + route table binding) |
| **Public attacker** | No business traffic; connecting to 16666 is rejected by token | Rejected by nginx + hub token |
| **Expose agent** | Only streams it participates in | No (agent_id binding) |

⚠️ **The entry point is exposed to the public internet** — nginx must own TLS
termination + client authentication + rate limiting. Never expose edge's 8443
directly.

## Deployment checklist

### 1. Certificates

```bash
# Public server: self-signed CA + hub certificate (for the internal edge hub).
# From the repo root — certificates are git-ignored by policy and generated
# on demand, so run this on every fresh clone:
./scripts/gen_certs.sh examples/reverse-tunnel-public/certs

# You also need real certificates for your domain (example.com here) for
# nginx — issue them with Let's Encrypt:
certbot certonly --nginx -d asr.example.com -d tts.example.com
```

> The generated `certs/` (CA + hub) is dev-only material for local testing.
> Regenerate it for production.

### 2. Nginx configuration (public entry)

See [`nginx.conf`](./nginx.conf). Key points:
- TLSv1.3 + real Let's Encrypt certificates
- `limit_req` / `limit_conn` rate limiting
- Optional client mTLS / Basic Auth
- `proxy_pass http://127.0.0.1:8443` forwarding to edge

### 3. Edge route table

See [`routes.toml`](./routes.toml). Each rule:
```toml
[[routes]]
host = "asr.example.com"          # public Host header
agent_id = "desktop"               # must match the LAN expose --agent-id
remote_addr = "127.0.0.1:8080"     # target the LAN expose agent dials
```

### 4. Start edge (public server)

See [`start-edge.sh`](./start-edge.sh). Key flags:

| Flag | Purpose |
|---|---|
| `--listen 0.0.0.0:8443` | HTTP listener; nginx forwards here |
| `--hub-listen 0.0.0.0:16666` | Internal hub; **must be 0.0.0.0** so LAN agents can dial in |
| `--routes routes.toml` | Route table |
| `--token ${INTERFLOW_EDGE_TOKEN}` | Hub auth token (same on the expose side) |
| `--hub-cert` / `--hub-key` | Hub server TLS certificate |
| `--audit-path` | Audit log JSONL |
| `--new-conn-rate-per-ip-per-minute 30` | Connect-flood defense |

```bash
export INTERFLOW_EDGE_TOKEN="$(openssl rand -hex 32)"
./start-edge.sh
sudo nginx -s reload
```

### 5. Start expose (LAN machine)

See [`profile.toml`](./profile.toml) and [`start-expose.sh`](./start-expose.sh).

```bash
export INTERFLOW_EDGE_TOKEN="<same as the public edge>"
./start-expose.sh 8080                # expose local 8080; --save writes profile.toml
# afterwards simply: interflow-expose expose 8080
```

### 6. Verify

```bash
curl https://asr.example.com/v1/status
# → nginx (443) → edge (8443) → hub (16666) → desktop expose → 127.0.0.1:8080
```

The edge audit log (`/var/log/interflow/edge-audit.jsonl`) records every
connection.

## Local testing (single machine)

Generate the dev certificates first (see §1), then:

```bash
# Terminal 1: edge (hub-listen on 127.0.0.1 for single-machine testing)
INTERFLOW_EDGE_TOKEN=dev-token interflow-expose edge \
    --listen 127.0.0.1:8443 --hub-listen 127.0.0.1:16666 \
    --routes examples/reverse-tunnel-public/routes.toml \
    --token dev-token --hub-cert examples/reverse-tunnel-public/certs/hub.crt \
    --hub-key examples/reverse-tunnel-public/certs/hub.key

# Terminal 2: a local service
python3 -m http.server 8080

# Terminal 3: expose agent
INTERFLOW_EDGE_TOKEN=dev-token interflow-expose expose 8080 \
    --hub https://127.0.0.1:16666 --token dev-token \
    --agent-id desktop --ca-path examples/reverse-tunnel-public/certs/ca.crt

# Terminal 4: verify (Host-based routing)
curl -H "Host: asr.example.com" http://127.0.0.1:8443/
```

## Security checklist

- [ ] Nginx enables TLSv1.3 + Let's Encrypt
- [ ] Nginx enables `limit_req` and `limit_conn`
- [ ] Nginx enables client mTLS or Basic Auth (depending on the service)
- [ ] Edge `--hub-listen 0.0.0.0:16666` restricted by iptables / cloud security groups
- [ ] `INTERFLOW_EDGE_TOKEN` generated with `openssl rand -hex 32`
- [ ] `--audit-path` persisted, rotated regularly
- [ ] `--new-conn-rate-per-ip-per-minute` set sensibly
- [ ] Private key permissions `chmod 600` (the loader rejects wider perms)
- [ ] Prometheus monitors edge metrics

## Common misconfigurations

| Symptom | Cause |
|---|---|
| Users get 502 | edge not running / wrong nginx port |
| Expose agent cannot reach hub | `--hub-listen` is 127.0.0.1 (should be 0.0.0.0); firewall blocks 16666 |
| Agent registers but requests 404 | routes.toml host does not match the request Host; agent_id mismatch |
| Request reaches expose but dial fails | `remote_addr` port differs from the local service's actual port |
| Both sides connected but no traffic | token mismatch (hub rejects agent registration) |
| Audit log not written | `--audit-path` parent directory missing |

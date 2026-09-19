# Public domain to LAN service

This `interflow-expose` example routes requests for `app.example.com` through
nginx and a public edge to a service listening on port `3000` in a private LAN.

```text
public user ─HTTPS─► nginx :443 ─► edge :8443 ─► hub :16666 ◄─mTLS─ lan-agent ─► 127.0.0.1:3000
```

## Files

- `generate-certs.sh` — create the local, git-ignored mTLS material
- `start-edge.sh` — run the public edge behind nginx
- `start-expose.sh` — run the LAN expose agent
- `nginx.conf` — public TLS and X-Forwarded-For topology
- `routes.toml` — Host-header route table
- `profile.toml` — optional persistent expose-agent profile

The example uses tenant `demo` and agent ID `lan-agent`. Override binaries with
`INTERFLOW_EXPOSE_BIN` or `INTERFLOW_MESH_BIN`; by default the scripts use
commands from `PATH`.

## Local smoke test

Run the commands from this directory. `start-edge.sh` is designed for the
nginx topology and therefore requires X-Forwarded-For, so the local smoke test
starts a loopback edge directly instead.

Generate a certificate whose SAN matches the local hub address:

```bash
INTERFLOW_MESH_BIN=../../target/release/interflow-mesh \
  ./generate-certs.sh --hub-dns 127.0.0.1
```

Terminal 1 — edge:

```bash
../../target/release/interflow-expose edge \
  --listen 127.0.0.1:8443 --hub-listen 127.0.0.1:16666 \
  --routes "$PWD/routes.toml" \
  --client-ca "demo=$PWD/certs/tenants/demo-ca.crt" \
  --hub-cert "$PWD/certs/hub.crt" \
  --hub-key "$PWD/certs/hub.key"
```

Terminal 2 — local service:

```bash
python3 -m http.server 3000
```

Terminal 3 — expose agent:

```bash
INTERFLOW_EXPOSE_BIN=../../target/release/interflow-expose \
  INTERFLOW_HUB_URL=https://127.0.0.1:16666 \
  ./start-expose.sh 3000
```

Terminal 4 — verify Host routing:

```bash
curl --fail -H 'Host: app.example.com' http://127.0.0.1:8443/
```

## Production deployment

1. On an operator machine, issue certificates whose hub SAN matches the address
   dialed by agents:

   ```bash
   ./generate-certs.sh --hub-dns hub.example.com
   ```

2. Copy only these files:

   | Host | Files |
   |---|---|
   | Public server | `hub.crt`, `hub.key`, `tenants/demo-ca.crt`, `routes.toml`, `nginx.conf`, `start-edge.sh` |
   | LAN machine | `agents/lan-agent.crt`, `agents/lan-agent.key`, `tenants/demo-ca.crt`, `profile.toml`, `start-expose.sh` |
   | Operator machine | keep `tenants/demo-ca.key` offline |

3. Obtain a public TLS certificate, replace the reserved `example.com`
   placeholders, install `nginx.conf`, and start `start-edge.sh`.

4. Start the LAN service and `start-expose.sh 3000` on the LAN machine.

nginx must set `X-Forwarded-For`; edge requires it so rate limits, connection
caps, metrics, and audit use the visitor IP rather than nginx's loopback address.
Authentication and tunnel authorization always use mTLS identity only.

## Security notes

- Never expose edge's HTTP listener `:8443` directly to the internet.
- Keep `tenants/demo-ca.key` offline; the public server needs only the CA cert.
- There is no certificate revocation yet. If a private key leaks, rotate the
  tenant CA and reissue every certificate it signed.

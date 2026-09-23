# Public domain to LAN service

This example routes requests for `app.example.com` through a public ingress
to a service listening on port `3000` in a private network, using the
identity-first model: you declare Ingress / Agent / Service / Route, and
`interflow plan apply` issues every Credential Pack.

```text
public user ─HTTPS─► nginx :443 ─► ingress edge :8443 ─► control :16666 ◄─mTLS─ lan-agent ─► 127.0.0.1:3000
```

## Files

- `interflow.toml` — deployment manifest (Realm / Ingress / Agent / Service / Route)
- `start-ingress.sh` — start the public ingress from its Credential Pack (local testing)
- `start-agent.sh` — start the in-network agent from its Credential Pack (local testing)
- `nginx.conf` — the reference public-TLS/XFF topology (the renderer encodes the same invariants)

`plan apply` writes `issuer/` (the secret issuer store — keep it offline) and
`dist/` — Credential Packs plus the rendered server-side material (systemd
units, nginx fragments, `install.sh`). **Production deployment** follows
the deployment guide: `install.sh` once per server (machine bootstrap —
user, dirs, binaries; it installs no units), then
`interflow node install --pack packs/<kind>-<node>` per node (pack + unit +
enable); the scripts and `nginx.conf` here are the local-testing /
pre-rendering reference.

## Local smoke test

Run from this directory. First build the CLI (`cargo build --release --bin
interflow` in the repository root), then generate a local manifest and issue
the packs:

```bash
../../target/release/interflow setup \
  --realm example \
  --control-endpoint 127.0.0.1:16666 \
  --host app.example.com \
  --agent lan-agent \
  --service web \
  --service-address 127.0.0.1:3000 \
  --out interflow.local.toml

../../target/release/interflow plan apply \
  --manifest interflow.local.toml \
  --issuer issuer \
  --out dist
```

Terminal 1 — ingress:

```bash
INTERFLOW_BIN=../../target/release/interflow \
INTERFLOW_INGRESS_PACK="$PWD/dist/packs/ingress-edge" \
  ./start-ingress.sh
```

Terminal 2 — local service:

```bash
python3 -m http.server 3000
```

Terminal 3 — agent:

```bash
INTERFLOW_BIN=../../target/release/interflow \
INTERFLOW_AGENT_PACK="$PWD/dist/packs/agent-lan-agent" \
  ./start-agent.sh
```

Terminal 4 — verify Host routing:

```bash
curl --fail -H 'Host: app.example.com' http://127.0.0.1:8443/
```

## Production deployment

1. Edit `interflow.toml`: set `realm.control_endpoint` to your public relay
   address and keep `public_tls.mode = "frontend-proxy"` for the nginx
   topology.

2. On an operator machine, issue the deployment:

   ```bash
   interflow plan apply --manifest interflow.toml --issuer issuer --out dist
   ```

3. Distribute only the packs (or seal them first with `interflow pack seal`):

   | Host | Material |
   |---|---|
   | Public server | `dist/packs/ingress-edge` + `nginx.conf` + your public TLS certificate |
   | LAN machine | `dist/packs/agent-lan-agent` |
   | Operator machine | keep `issuer/` offline — it can re-issue and revoke every identity |

4. Replace the reserved `example.com` placeholders in `nginx.conf`, install
   it, then start `start-ingress.sh` on the public server and
   `start-agent.sh` plus your service on the LAN machine.

nginx must set `X-Forwarded-For`; the ingress requires it so rate limits,
connection caps, metrics, and audit use the visitor IP rather than nginx's
loopback address. Authentication and tunnel authorization always use the
pack-issued mTLS identity only.

## Security notes

- Never expose the ingress HTTP listener `:8443` directly to the internet.
- Keep the `issuer/` store offline; servers only need their own pack.
- Rotate with `interflow rotate` and revoke with `interflow revoke` — a
  revoked credential lands in the issuer deny list and CRL.

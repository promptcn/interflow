# Site-to-site private networks

> Product-path example for the `interflow-mesh` site-to-site mode. The
> desired state lives in one manifest (`interflow.toml`); `interflow plan
> apply` renders Credential Packs, and nodes start with `interflow-mesh
> hub/agent --pack`. No certificate is ever issued or placed by hand —
> leaf credentials renew automatically (50% TTL) against the registrar,
> and `rotate` / `revoke` / `doctor` work exactly as on the expose side.
>

This example connects a client on LAN A to a service on LAN B through a
public hub. Agents authenticate to the hub with workspace-issued mTLS
credentials and establish an additional TLS 1.3 layer for TCP payloads, so
the hub routes ciphertext without terminating the agent-to-agent payload
protection.

```text
LAN A client ─► lan-a :3001 ─► hub :6666 ─► lan-b ─► 127.0.0.1:3000
                              (mTLS + routing)
```

## Product path (manifest → Credential Packs)

### 1. Render the packs (operator machine)

Build the binaries, then from this directory:

```bash
cargo build --release --bin interflow --bin interflow-mesh
./apply.sh          # interflow plan apply --manifest interflow.toml …
```

`apply.sh` renders into `./dist` (git-ignored):

- `dist/packs/hub-central/` — the hub pack: control-endpoint server
  identity (SAN = the hub dial address), the realm-scoped hub renewal
  principal, the workspace trust table, and the signed admission policy
- `dist/packs/agent-lan-a/`, `dist/packs/agent-lan-b/` — mesh-role agent
  packs: workspace identity + local rules + peer trust anchors
- `dist/systemd/` — service units per node

The offline issuer store (`./issuer`, git-ignored) stays on the operator
machine; nothing under it is ever distributed.

### 2. Local smoke test

Terminal 1 — hub:

```bash
../../../../target/release/interflow-mesh hub --pack dist/packs/hub-central
```

Terminal 2 — service and LAN B agent:

```bash
python3 -m http.server 3000
../../../../target/release/interflow-mesh agent --pack dist/packs/agent-lan-b
```

Terminal 3 — LAN A agent:

```bash
../../../../target/release/interflow-mesh agent --pack dist/packs/agent-lan-a
```

Terminal 4 — access LAN B through LAN A:

```bash
curl --fail http://127.0.0.1:3001/
```

The agents' E2E handshake succeeds before LAN B dials the target service. A
failed or missing inner TLS handshake closes the stream instead of falling
back to plaintext.

> The demo manifest points `registrar.endpoint` at a placeholder; nodes run
> fine on their bootstrap credentials (24h) but will not renew. Point it at
> a real `interflow-registrar serve` for anything longer than a smoke test.

### 3. Real deployment

1. Edit `interflow.toml`:
   - `[mesh.hub.central].endpoint` → the public dial address
     (`hub.example.com:6666`; the hub credential's SAN derives from it)
   - `[[agent.lan-a.mesh_ingress]].remote_addr` → the service address as
     reachable from LAN B
   - `[[agent.lan-b.mesh_egress]].target_addr` → the same address (the
     authorization pair must match; the manifest validator enforces it)
   - `[registrar].endpoint` → your registrar
2. `./apply.sh`, then distribute each pack to its node (`.iflowpack`
   sealed archives via `interflow pack seal` work here too).
3. Open the hub's TCP port on the firewall and start the three nodes with
   `interflow-mesh hub --pack …` / `interflow-mesh agent --pack …`
   (or install the rendered systemd units).
4. Lifecycle is the same as everywhere else:
   `interflow doctor hub --pack …`, `interflow rotate hub/central`,
   `interflow revoke --pack …`.

Cross-worksite routing: declare agents in different `[workspace.*]` and the
hub admits their streams through the signed policy's cross-workspace
entries — the manifest is the only place authorization is expressed.

## UDP forwarding (advanced)

Add `protocol = "udp"` to a mesh rule pair in the manifest (the ingress
`[[agent.<lan-a>.mesh_ingress]]` and the egress
`[[agent.<lan-b>.mesh_egress]]` must agree). UDP datagram boundaries are
preserved. The current E2E layer covers TCP only; UDP retains agent-to-hub
TLS, not agent-to-agent inner TLS.

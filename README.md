# Interflow


## Quick start

```bash
interflow setup --realm example --control-endpoint relay.example.com:16666 \
  --host app.example.com --agent desktop --service web --service-address 127.0.0.1:8080
interflow plan apply --manifest interflow.toml --issuer issuer --out dist

interflow ingress run --pack dist/packs/ingress-edge   # public entry node
interflow agent run   --pack dist/packs/agent-desktop   # in-network connector
```

You declare **Ingress / Agent / Service / Route**; identities, trust, and
signed routing policy ship inside self-describing Credential Packs — no
certificate paths anywhere. Workspaces share one ingress with per-workspace
issuers and cross-workspace deny by default. See the deployment guide for packs, rotation, revocation, `doctor`, and
the registrar; see the versioning guide for the product-version /
format-version / generation model.

A multiplexed tunnel with mTLS by default: it carries both TCP byte streams
and UDP datagrams over a single custom frame protocol (fixed 41-byte binary header, flags-carried direction/origin, opaque raw tokens, reason codes) that runs on two
transports — HTTP/2 and QUIC.

## Site-to-site (private network ↔ private network)

The same manifest model drives the mesh engine: declare a `[mesh.hub.*]`
node and per-agent mesh rules — by hand, or structurally with
`setup --face mesh` + `node add` (no TOML to write: the append is
non-destructive, and the edited manifest must pass the full validation
funnel before anything is written) — then `interflow plan apply` renders
hub and agent Credential Packs, and the nodes run on the `interflow-mesh`
binary (a node is an identity — a machine can run any number of them, each
in its own mesh):

```bash
interflow setup --face mesh --realm example --hub-name central --hub-endpoint hub.example.com:6666
interflow node add agent/lan-b --mesh-egress web:10.1.0.5:80     # serve side first
interflow node add agent/lan-a --mesh-ingress to-lan-b:127.0.0.1:3001:10.1.0.5:80@lan-b
interflow plan apply                          # all flags default: interflow.toml / issuer / dist

interflow-mesh hub   --pack dist/packs/hub-central   # public relay
interflow-mesh agent --pack dist/packs/agent-lan-a    # LAN A side
interflow-mesh agent --pack dist/packs/agent-lan-b    # LAN B side
```

Distribute a pack as an encrypted `.iflowpack` with
`interflow pack seal --pack dist/packs/<kind>-<node> --generate-passphrase`
(the output lands beside the pack; the 144-bit passphrase prints once).

Hub and agent credentials are issued offline (never enrolled), renew
automatically against the registrar, and respond to the same `rotate` /
`revoke` / `doctor` lifecycle as expose packs. The runnable scenario lives
in `crates/mesh/dev-examples/site-to-site/`.

## Engine components

The `interflow-mesh` engine is driven exclusively from Credential Packs
(the binary exposes only `hub/agent --pack`). Engine development and
isolated test topologies go through the same pack machinery
(`crates/mesh/dev-examples/site-to-site/` renders packs from a manifest);
the dev soak harness uses a testkit-only node binary with a JSON config
handoff.

## Repository layout

```
interflow/
├── crates/
│   ├── identity/   ← identity model: manifest, issuer, Credential Packs, trust bundles, policy
│   ├── cli/        ← the unified `interflow` entry point (setup / plan / ingress / agent / lifecycle)
│   ├── expose/     ← public-domain engine (lib-only, driven from packs by the CLI/GUI)
│   ├── mesh/       ← site-to-site engine + the `interflow-mesh` binary (pack-only)
│   ├── core/       ← tunnel primitives (protocol / tunnel / registry / acl / tls / pump / telemetry)
│   ├── registrar/  ← the independent enrollment / renewal service (`interflow-registrar`)
│   ├── renewal/    ← shared credential-renewal scheduler (pack lifecycle beside every engine)
│   ├── certs/      ← shared rcgen issuance behind the issuer and the test kit
│   ├── contract/   ← FORMAT_VERSION / Generation machine contracts
│   ├── util/       ← shared micro-utilities (authority parsing, atomic writes)
│   └── testkit/    ← dev-only test/bench harness
├── src/, src-tauri/ ← Tauri 2 GUI (unified node manager: expose agents, mesh agents, hubs, and ingresses side by side, each from a Credential Pack — each node is an identity, not a machine, and the GUI manages any number of them on its host)
├── examples/      ← generic, runnable scenario examples
└── Cargo.toml     ← workspace root
```

---

## Public domain → LAN service (`interflow`)

Like ngrok, it exposes a local port under a public domain — but with a fixed domain (no random assignment), and the public entry point terminates HTTPS itself: ACME by default (`[public_tls] mode = "acme"`, ports 80/443 direct), or a frontend proxy (nginx/LB) in the advanced topology.

### Topology

Default — the ingress terminates public HTTPS itself via ACME:

```
[public server]
  interflow ingress run --pack …     ← single process: control endpoint + ingress listener
     │ public HTTPS terminated here (ACME: HTTP-01 + TLS-ALPN-01, auto-renewal)
     │ HTTP/2 tunnel (mTLS from the Credential Pack)
     ▼
[local machine]
  interflow agent run --pack …       ← in-network connector; services come from the pack
     │
     ▼
  127.0.0.1:3000
```

Advanced — frontend proxy (`[public_tls] mode = "frontend-proxy"`): nginx/LB
terminates TLS on 443 and `proxy_pass`es plaintext HTTP/1 to the ingress
listener (e.g. `127.0.0.1:8443`); the tunnel leg below is unchanged.

### First run

```bash
# 1. Operator machine: declare the deployment (the single source of truth)
interflow setup \
  --realm example --control-endpoint relay.example.com:16666 \
  --registrar-endpoint https://registrar.example.com \
  --host app.example.com --agent myagent \
  --service web --service-address 127.0.0.1:3000

# 2. Run the independent short-lived credential registrar (keep `issuer/` offline)
interflow-registrar certificate --issuer issuer --realm example \
  --endpoint https://registrar.example.com
interflow-registrar serve --issuer issuer --listen 0.0.0.0:18666 \
  --tls-cert registrar.crt \
  --endpoint https://registrar.example.com \
  --tls-key registrar.key --leaf-ttl 24h \
  --control-endpoint relay.example.com:16666

# 3. Issue every identity + Credential Pack (append more agents any time:
#    interflow node add agent/<name> --service id:address, then re-apply)
interflow plan apply --manifest interflow.toml --issuer issuer --out dist

# 4. Public server: start the ingress from its pack
interflow ingress run --pack dist/packs/ingress-edge

# 5. Local machine: start the agent from its pack (transfer it encrypted:
#    interflow pack seal --pack dist/packs/agent-myagent --generate-passphrase)
interflow agent run --pack dist/packs/agent-myagent
```

No certificate paths anywhere: the packs carry identity, trust, the signed
route policy, and the node configuration. Leaf credentials default to a 24h
TTL and renew automatically at 50% remaining lifetime. `interflow rotate`
remains for policy/trust generation changes, revoke with `interflow revoke`,
and diagnose with `interflow doctor`.

### Key design

- **The ingress is a consolidated component**, not a "hub + ingress bundle": the public listener and the tunnel server cooperate directly on the same event loop — public request → peek the first 8 KB for the `Host` header → route-table lookup (from the signed policy, in memory) → open a tunnel stream to the target egress agent → pass the byte stream through
- **Public HTTPS**: ACME terminates TLS on the ingress by default (HTTP-01 + TLS-ALPN-01, auto-renewal); the fronted topology keeps nginx terminating TLS with the ingress receiving plaintext HTTP/1 from `proxy_pass`
- **L4 passthrough**: the edge does not parse the full HTTP protocol — it only peeks the Host header for routing; the remaining byte stream crosses the tunnel untouched, and the backend service (a local HTTP server / SSH / any TCP service) parses it itself
- **h2 tunnel by default, QUIC opt-in**: the agent↔ingress leg can switch to QUIC via the pack / GUI transport preference (verified e2e in `crates/expose/tests/e2e_expose_quic.rs`); the control leg stays on h2, and a QUIC listener on the ingress side is on the manifest roadmap

### Deployment notes: long silent windows and SSE

When the backend is an LLM / SSE-style service that stays silent for a long time before bursting, the three-tier idle budget must nest from largest to smallest:

```
nginx proxy_read_timeout (default 60s — must be raised)
  ≥ edge stream idle timeout (fixed 300s policy default)
  ≥ the longest silent interval of the service (e.g. the wait for the first LLM token)
```

nginx's default `proxy_read_timeout 60s` cuts the connection after 60 s of backend silence — before interflow's 300 s budget ever gets a chance to act; the default response buffering also breaks SSE token-by-token streaming. The example [`examples/public-domain-to-lan/nginx.conf`](examples/public-domain-to-lan/nginx.conf) already contains the correct settings; when configuring by hand, all three pieces are mandatory:

```nginx
location / {
    proxy_pass http://127.0.0.1:8443;
    proxy_set_header Host $host;
    proxy_http_version 1.1;    # required for keep-alive
    proxy_read_timeout 6m;     # ≥ edge stream idle timeout (300s)
    proxy_buffering off;       # don't buffer SSE token-by-token streaming
}
```

---

## Transports and UDP

**h2 is the default transport** — it connects wherever TCP egress is allowed. **QUIC is an opt-in upgrade** for the agent↔ingress leg (a transport preference in the pack / GUI): tunnel streams then run on QUIC native streams (custom frames written raw), eliminating single-TCP-connection head-of-line blocking. The choice is static per agent with no automatic fallback between the two — which is exactly why h2 stays the default. ACL / stream limits / mTLS / cert-pin keep identical semantics on both transports.

**UDP** is carried as datagrams over an encrypted agent-to-agent QUIC association: datagram boundaries are preserved (RFC 9221 DATAGRAM frames), large packets are explicitly fragmented and reassembled (never silently truncated), and bidirectional per-IP / return-path anti-amplification rate limits are on by default. The engine carries UDP today in the site-to-site engine mode; exposing UDP services in the manifest is on the roadmap.

---

## Comparison with frp / rathole

One-line positioning: **frp is the most feature-complete bundle with the largest community; rathole subtracts for embedded use (minimal build ~574 KiB); interflow builds for the scenarios that dare to attach a private network to the public internet — strong security by default and transport-design completeness.**

### Differentiators

| Dimension | frp | rathole | interflow |
|---|---|---|---|
| Transport stack | TCP / KCP / QUIC / WS (quic-go, QUIC streams instead of yamux) | TCP / TLS / Noise / WS (one connection per stream) | **One frame protocol over both long-lived h2 streams and QUIC (quinn)**, cross-transport interop (h2 agent ↔ quic agent via the same hub relay, e2e-verified) |
| UDP carriage | reliable stream (loss HOLs the whole service) | reliable stream | **inner QUIC DATAGRAM over an encrypted agent-to-agent association** (datagram semantics + explicit large-packet fragmentation) |
| Large UDP packets | 1500-byte read buffer by default, overlong packets silently truncated | hardcoded 2048, silently truncated | 65535-byte read buffer; truncation is an explicit drop with a counter |
| UDP amplification defense | none | none | per-IP pps + byte dual-bucket inbound rate limit and a return-path rate limit, on by default |
| Security defaults | random self-signed cert + client skips verification + token (CA / mTLS / OIDC configurable) | per-service token + optional Noise/TLS | **mTLS + SHA256 cert-pin + constant-time comparison + inner TLS/QUIC for TCP/UDP payloads**, same standard defaults on h2 / QUIC; identity is a signed pack, never a shared secret |
| Topology | expose family (stcp / xtcp visitor) | expose only | public-domain tunnels (L4 passthrough + Host routing) + **site-to-site engine mode** |
| TCP data plane | reliable stream | reliable stream | **structured and lossless**: per-stream channels, no frame-loss path in the data plane; end-to-end stall bounds (dispatch 5s / backend write 10s / hub dispatch 30s), failures visible in metrics by reason |
| Resource defense | server-side limits (maxPoolCount / maxPorts, …) | none | hub concurrency limits + ACL + audit; **independent agent-side defenses** (local stream caps / stream-open rate limiting / dial double timeouts, independent of hub configuration) |
| Change contract | frpc admin API (re-reads the file) | file watch (notify) | **explicit by construction**: a pack generation is immutable — route/trust changes go through `rotate` / re-`plan apply` and are verifiable (`doctor`, Trust Bundles with generation + digest); the engine-level hub additionally supports SIGHUP hot reload with a documented immediate / new-connections-only / restart-required contract |
| Binary size | ~10 MiB | minimal build 574 KiB (feature trimming + upx) | several MiB (minimization is not a goal — see the product decisions below) |
| Feature surface | plugin family / P2P hole punching / load balancing / health checks / dashboard | minimal | no plugins, no P2P (explicit trade-offs) |
| Ecosystem | the largest community and distribution ecosystem | OpenWrt / embedded niche | new project |

### Where frp and rathole are still stronger (honestly)

- **frp**: P2P hole punching (xtcp, relay-free direct connection), aggressive KCP transport, client plugins (protocol conversion / static files / socks5 egress), L7 vhost routing, proxy load balancing and health checks, OIDC, a web dashboard, and the largest community and third-party ecosystem.
- **rathole**: a ~574 KiB embedded minimal build (a dropbear-class presence on routers / OpenWrt), the minimal-configuration mindset of certificate-free Noise; its "one connection per stream" model naturally has no cross-stream head-of-line blocking on TCP.
- **interflow's known boundaries**: h2 mode has cross-stream TCP head-of-line blocking (solved by the QUIC transport; h2 remains the default — deployable wherever TCP egress works — while QUIC is an opt-in upgrade that requires UDP egress); the public-domain product path does not expose UDP yet (the engine carries it today in the site-to-site mode; manifest-level exposure is on the roadmap); community size and third-party ecosystem start from zero.

### Explicitly out of scope (product decisions, not missing capability)

- No pursuit of minimal binary size — it directly conflicts with "strong security by default (rustls mandatory) + both transports available by default"
- No plugin system — protocol conversion / static files / forward proxy are left to nginx and the backend, keeping the hub pure

> Performance methodology: single stream ~130–160 MiB/s, 4-stream aggregate ~195 MiB/s, round-trip latency 121 µs (localhost loopback criterion, h2 transport; QUIC comparison in `crates/mesh/benches/`). frp / rathole behaviors in the comparison table were verified against their sources; anchors in [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Build & development

```bash
# Build the whole workspace
cargo build --workspace

# Tests (workspace-wide unit + e2e: adversarial and resilience scenarios such
# as silent-link recovery / slow backends / Open floods / disconnect
# self-healing, plus config-invariant locks: liveness-chain derivations,
# negotiation compatibility matrix, schema validation rules)
cargo test --workspace

# Cross-platform release builds (zig for cross-compilation; artifacts land in artifacts/)
./scripts/build-linux.sh       # x86_64 musl; pass "aarch64" for the arm build
./scripts/build-macos.sh
./scripts/build-windows.sh

# GUI (Tauri 2, unified node manager): macOS DMG
./scripts/build-dmg.sh

# Docker (mesh hub/agent image by default; --build-arg BINARY=interflow also works)
docker build -t interflow:latest .
```

### Common just targets

```
just test          # all tests
just lint          # strict clippy (forbid unsafe / deny panic)
just example-public-domain-plan
just example-public-domain-ingress
just example-public-domain-agent
```

(Engine-level recipes such as the site-to-site example exist too — `just --list`.)

---

## Tech stack

- **Rust 2024** + Tokio
- **Dual transport stack**: long-lived HTTP/2 streams (hyper 1.x: `/stream/up` upstream + `/poll` downstream mirrored streaming) and QUIC (quinn 0.11: one QUIC stream per tunnel stream + RFC 9221 DATAGRAM), both sharing the same custom frame protocol (codec property-tested + cargo-fuzzed)
- **rustls** (no openssl; mTLS / cert pinning / SHA256 fingerprint verification)
- **TOML** configuration (`deny_unknown_fields` guards against typos; defaults single-sourced in code)
- **Tracing** + Prometheus metrics
- **Strict lints**: `deny(unsafe_code)`, `deny(panic)`, `warn(pedantic + nursery)`

## License

Apache-2.0 — see [LICENSE](LICENSE).

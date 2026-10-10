# Interflow

Identity-first tunnels with mTLS by default. One manifest declares the
deployment; every node — public ingress, in-network agent, mesh hub — runs
from a self-describing **Credential Pack** that carries its identity, trust,
and signed routing policy. There are no shared secrets and no certificate
paths to manage by hand: the client certificate *is* the credential, and the
tenant behind it is derived from which CA anchors the chain.

Two faces share one engine core:

- **Public domain → LAN** (`interflow-cli ingress / agent run`) — expose a
  local service under a fixed public domain, with the public entry point
  terminating HTTPS itself (ACME by default).
- **Site-to-site mesh** (`interflow-mesh hub / agent`) — private network ↔
  private network over a pure stream-relay hub.

A Tauri 2 GUI manages all node kinds side by side on its host, each from its
own pack — a node is an identity, not a machine.

## Quick start

```bash
interflow-cli setup --realm example --control-endpoint relay.example.com:16666 \
  --host app.example.com --agent desktop --service web --service-address 127.0.0.1:8080
interflow-cli plan apply --manifest interflow.toml --issuer issuer --out dist

interflow-cli ingress run --pack dist/packs/ingress-edge   # public entry node
interflow-cli agent run   --pack dist/packs/agent-desktop   # in-network connector
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
funnel before anything is written) — then `interflow-cli plan apply` renders
hub and agent Credential Packs, and the nodes run on the `interflow-mesh`
binary (a node is an identity — a machine can run any number of them, each
in its own mesh):

```bash
interflow-cli setup --face mesh --realm example --hub-name central --hub-endpoint hub.example.com:6666
interflow-cli node add agent/lan-b --mesh-egress web:10.1.0.5:80     # serve side first
interflow-cli node add agent/lan-a --mesh-ingress to-lan-b:127.0.0.1:3001:10.1.0.5:80@lan-b
interflow-cli plan apply                          # all flags default: interflow.toml / issuer / dist

interflow-mesh hub   --pack dist/packs/hub-central   # public relay
interflow-mesh agent --pack dist/packs/agent-lan-a    # LAN A side
interflow-mesh agent --pack dist/packs/agent-lan-b    # LAN B side
```

Mesh rules are TCP by default; prefix one with `udp/`
(`--mesh-egress udp/dns:10.1.0.1:53`, per-rule idle timeouts) to declare a
UDP service — datagrams then ride an encrypted agent-to-agent QUIC
association (see [Transports and UDP](#transports-and-udp)).

Distribute a pack as an encrypted `.iflowpack` with
`interflow-cli pack seal --pack dist/packs/<kind>-<node> --generate-passphrase`
(the output lands beside the pack; the 144-bit passphrase prints once).

Hub and agent credentials are issued offline (never enrolled), renew
automatically against the registrar, and respond to the same `rotate` /
`revoke` / `doctor` lifecycle as expose packs. The runnable scenario lives
in `crates/mesh/dev-examples/site-to-site/`.

## The identity model

`interflow.toml` is the single source of truth. `interflow-cli plan apply`
validates it and renders one Credential Pack per node under
`dist/packs/<kind>-<node>/`:

```
pack.toml     canonical metadata: kind / realm / workspace / node / generation /
              identity_mode / rendered_by (the provenance stamp)
node.toml     fully resolved node configuration (listeners, services,
              transport, edge settings — every scalar key always written)
identity/     leaf certificate + key per principal (an agent gets exactly
              its workspace principal; an ingress one per served workspace)
trust/        issuer CA certs + Trust Bundle metadata; offline packs embed
              the revocation snapshot here
policy/       policy.toml + policy.sig — the ed25519-signed runtime policy
SHA256SUMS    digest manifest over every pack file; state/ is outside it
state/        node-local runtime state (ACME cache, live policy, live CRLs)
              — deliberately never sealed
```

Every pack is stamped with an `identity_mode`, chosen in the manifest:

- **`registrar`** (default) — short-lived leaves (1 h–24 h, default 24 h)
  that renew unattended against the independent registrar at 50% remaining
  lifetime; renewal completion is a graceful process exit so the supervisor
  restarts onto the new material. The node pulls fresh CRLs every 60 s and
  verification fails closed after a 1 h staleness bound.
- **`offline`** — no registrar section allowed; long-lived leaves
  (7 d–365 d, default 90 d) rotated manually. The pack embeds a revocation
  snapshot at `plan apply` / `rotate` time; a missing snapshot is a render
  defect, never a runtime fallback.

The mode statically pins where a node reads its CRLs from (`state/crls`
when registrar-managed, `trust/crls` when offline) — there is no
existence-probing fallback between the two.

### Lifecycle surface

| Command | What it does |
|---|---|
| `interflow-cli doctor ingress \| agent \| hub \| route \| trust \| issuer` | diagnose identity, trust, routes, and connectivity in product terms |
| `interflow-cli identity inspect [--expert]` / `identity renew` | inspect the identity a pack carries (X.509 detail) / force one renewal cycle |
| `interflow-cli rotate --manifest … <node>` | issue the next pack generation (an identity + trust change) |
| `interflow-cli revoke --pack … [--reason key-compromise]` | deny-list + CRL entry; the RFC 5280 reason code distinguishes a leak emergency from a planned retirement |
| `interflow-cli trust --pack …` | export the realm Trust Bundle (public verification material) |
| `interflow-cli audit verify <path>` | verify an audit ledger's hash chain, gzip segments included |
| `interflow-cli issuer backup init / now / status / rekey`, `issuer verify`, `issuer restore` | encrypted backups of the issuer store — the deployment's entire signing capability |
| `interflow-cli proposals list / approve / reject` | the mesh stream-proposal queue (approve = manifest edit + mint + publish) |
| `interflow-cli node install --pack …` | idempotent server install: pack + systemd unit; re-running is an upgrade |

Rule-only changes never rotate identity: `plan apply` signs the next policy
generation and publishes it — nodes pick it up within 10 s (anti-rollback
watermark), no restart.

## Engine components

The `interflow-mesh` engine is driven exclusively from Credential Packs
(the binary exposes `hub` / `agent` under `--pack`, plus `version`).
Engine development and isolated test topologies go through the same pack
machinery (`crates/mesh/dev-examples/site-to-site/` renders packs from a
manifest); the dev soak harness uses a testkit-only node binary with a JSON
config handoff.

## Repository layout

```
interflow/
├── crates/
│   ├── identity/   ← identity model: manifest, issuer, Credential Packs, trust bundles, policy
│   ├── cli/        ← the unified `interflow-cli` entry point (setup / plan / ingress / agent / lifecycle)
│   ├── expose/     ← public-domain engine (lib-only, driven from packs by the CLI/GUI)
│   ├── mesh/       ← site-to-site engine + the `interflow-mesh` binary (pack-only)
│   ├── core/       ← tunnel primitives (protocol / tunnel / registry / acl / tls / pump / telemetry)
│   ├── registrar/  ← the independent enrollment / renewal service (`interflow-registrar`)
│   ├── renewal/    ← shared credential-renewal scheduler (pack lifecycle beside every engine)
│   ├── certs/      ← shared rcgen issuance behind the issuer and the test kit
│   ├── contract/   ← FORMAT_VERSION / Generation machine contracts
│   ├── buildinfo/  ← the one BUILD_TAG composing every binary's version body (CLI version output, GUI top bar, pack `rendered_by` stamps)
│   ├── util/       ← shared micro-utilities (topology defaults, digests, authority parsing, atomic writes, systemd units)
│   └── testkit/    ← dev-only test/bench harness
├── src/, src-tauri/ ← Tauri 2 GUI (unified node manager: expose agents, mesh agents, hubs, and ingresses side by side, each from a Credential Pack — each node is an identity, not a machine, and the GUI manages any number of them on its host)
├── examples/      ← generic, runnable scenario examples
└── Cargo.toml     ← workspace root
```

---

## Public domain → LAN service (`interflow-cli`)

Like ngrok, it exposes a local port under a public domain — but with a fixed domain (no random assignment), and the public entry point terminates HTTPS itself: ACME by default (`[public_tls] mode = "acme"`, ports 80/443 direct), or a frontend proxy (nginx/LB) in the advanced topology.

### Topology

Default — the ingress terminates public HTTPS itself via ACME:

```
[public server]
  interflow-cli ingress run --pack …     ← single process: control endpoint + ingress listener
     │ public HTTPS terminated here (ACME: HTTP-01 + TLS-ALPN-01, auto-renewal)
     │ tunnel (mTLS from the Credential Pack; h2 by default, QUIC opt-in)
     ▼
[local machine]
  interflow-cli agent run --pack …       ← in-network connector; services come from the pack
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
interflow-cli setup \
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
#    interflow-cli node add agent/<name> --service id:address, then re-apply)
interflow-cli plan apply --manifest interflow.toml --issuer issuer --out dist

# 4. Public server: start the ingress from its pack
interflow-cli ingress run --pack dist/packs/ingress-edge

# 5. Local machine: start the agent from its pack (transfer it encrypted:
#    interflow-cli pack seal --pack dist/packs/agent-myagent --generate-passphrase)
interflow-cli agent run --pack dist/packs/agent-myagent
```

No certificate paths anywhere: the packs carry identity, trust, the signed
route policy, and the node configuration. In `registrar` identity mode
leaves default to a 24h TTL and renew automatically at 50% remaining
lifetime; `offline` packs default to 90-day leaves under manual rotation.
`interflow-cli rotate` handles policy/trust generation changes, revoke with
`interflow-cli revoke`, and diagnose with `interflow-cli doctor`.

### Key design

- **The ingress is a consolidated component**, not a "hub + ingress bundle": the public listener and the tunnel server cooperate directly on the same event loop — public request → peek the first 8 KB for the `Host` header → route-table lookup (from the signed policy, in memory) → open a tunnel stream to the target egress agent → pass the byte stream through
- **Public HTTPS**: ACME terminates TLS on the ingress by default (HTTP-01 + TLS-ALPN-01, auto-renewal); the fronted topology keeps nginx terminating TLS with the ingress receiving plaintext HTTP/1 from `proxy_pass`
- **L4 passthrough**: the edge does not parse the full HTTP protocol — it only peeks the Host header for routing; the remaining byte stream crosses the tunnel untouched, and the backend service (a local HTTP server / SSH / any TCP service) parses it itself
- **h2 tunnel by default, QUIC opt-in**: an agent whose pack carries `transport = "quic"` moves its whole session with the ingress — control roundtrips included — onto QUIC, so tunnel streams run as QUIC native streams; the ingress side declares its QUIC face with a `quic_listen` on the ingress node (e2e-verified in `crates/expose/tests/e2e_expose_quic.rs`)

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

**h2 is the default transport** — it connects wherever TCP egress is allowed. **QUIC is an opt-in upgrade** (a per-agent `transport = "quic"` in the manifest / GUI): the agent's entire session — control roundtrips included — moves onto QUIC, and tunnel streams then run on QUIC native streams (custom frames written raw), eliminating single-TCP-connection head-of-line blocking. The dialed side must open its QUIC face: `quic_listen` on the ingress node or on the mesh hub (both are manifest fields; absence keeps QUIC off). The choice is static per agent with no automatic fallback between the two — which is exactly why h2 stays the default. ACL / stream limits / mTLS / cert-pin keep identical semantics on both transports.

**UDP** is carried as datagrams over an encrypted agent-to-agent QUIC association: datagram boundaries are preserved (RFC 9221 DATAGRAM frames), large packets are explicitly fragmented and reassembled (never silently truncated), and bidirectional per-IP / return-path anti-amplification rate limits are on by default. Site-to-site rules declare UDP in the manifest today (`node add` mesh rules take a `udp/` prefix, with per-rule idle timeouts); carrying UDP on the public-domain face is on the roadmap.

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
| Change contract | frpc admin API (re-reads the file) | file watch (notify) | **explicit by construction**: a pack generation is immutable — trust/identity changes go through `rotate` / re-`plan apply` and are verifiable (`doctor`, Trust Bundles with generation + digest); rule-only changes hot-apply as a newly signed policy generation (nodes pull it within 10 s, anti-rollback watermark) — no restart, no file watching |
| Binary size | ~10 MiB | minimal build 574 KiB (feature trimming + upx) | several MiB (minimization is not a goal — see the product decisions below) |
| Feature surface | plugin family / P2P hole punching / load balancing / health checks / dashboard | minimal | no plugins, no P2P (explicit trade-offs) |
| Ecosystem | the largest community and distribution ecosystem | OpenWrt / embedded niche | new project |

### Where frp and rathole are still stronger (honestly)

- **frp**: P2P hole punching (xtcp, relay-free direct connection), aggressive KCP transport, client plugins (protocol conversion / static files / socks5 egress), L7 vhost routing, proxy load balancing and health checks, OIDC, a web dashboard, and the largest community and third-party ecosystem.
- **rathole**: a ~574 KiB embedded minimal build (a dropbear-class presence on routers / OpenWrt), the minimal-configuration mindset of certificate-free Noise; its "one connection per stream" model naturally has no cross-stream head-of-line blocking on TCP.
- **interflow's known boundaries**: h2 mode has cross-stream TCP head-of-line blocking (solved by the QUIC transport; h2 remains the default — deployable wherever TCP egress works — while QUIC is an opt-in upgrade that requires UDP egress); the public-domain face does not carry UDP yet (site-to-site mesh rules declare it in the manifest today; the public-domain face is on the roadmap); community size and third-party ecosystem start from zero.

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
# negotiation compatibility matrix, schema validation rules).
# cargo-nextest runs cases each in its own process and test binaries in
# parallel — the e2e suite is wall-clock-bound on real timers, so this is
# ~4.8x faster than a sequential libtest run (doc tests stay on libtest:
# nextest does not run them). Install: brew install cargo-nextest
# (or `cargo install cargo-nextest --locked`).
# Enforced at runtime: e2e binaries assembled via interflow-testkit refuse
# plain `cargo test` and fail fast with a hint (doc tests and benches are
# exempt; INTERFLOW_LIBTEST_OK=1 overrides for libtest-specific debugging).
cargo nextest run --workspace --all-features

# Cross-platform release builds (zig for cross-compilation; artifacts land in artifacts/)
./scripts/build-linux.sh       # x86_64 musl; pass "aarch64" for the arm build
./scripts/build-macos.sh
./scripts/build-windows.sh

# GUI (Tauri 2, unified node manager): macOS DMG
./scripts/build-dmg.sh

# Docker (mesh hub/agent image by default; --build-arg BINARY=interflow-cli also works)
docker build -t interflow:latest .
```

### Common just targets

```
just test          # all tests (cargo-nextest + doc tests on libtest)
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

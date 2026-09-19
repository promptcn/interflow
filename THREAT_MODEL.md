# Threat Model

> Initial version, 2026-09-15. This is an engineering document: it describes
> the security surface **as implemented in this repository**, each mechanism
> with a code anchor so every claim can be checked against the tree. It is
> the companion of [SECURITY.md](SECURITY.md) — that file defines the
> vulnerability reporting policy; the scope rules stated there follow from
> the model described here.

Reading discipline, mirroring how the codebase is actually secured:

- **Only implemented mechanisms are described.** Anything designed but not
  shipped is listed as a gap in [§8](#8-known-blind-spots-and-residual-risks),
  never as a capability.
- **Known blind spots are named**, not smoothed over.
- Backing is in-tree: adversarial and resilience test scenarios, and a
  fails-before-fix regression test for every escaped bug. Nothing here is a
  "production-verified" claim — interflow is pre-1.0.

## 1. System shape and assets

Two binaries share one tunnel core (`interflow-core`: a single frame protocol
carried over HTTP/2 and QUIC):

- **`interflow-mesh`** (site-to-site): a public **hub** — a pure stream
  router that never terminates public TLS and never parses HTTP — plus
  symmetric **agents**: ingress listeners in LAN A, egress dialers in LAN B.
- **`interflow-expose`** (public domain → LAN service): a consolidated
  **edge** on the public server (tunnel server and L4 HTTP/1 listener in one
  process, behind a TLS-terminating fronting proxy) and a local expose
  client that dials the backend.

Assets the model protects:

- **Availability** of the hub, edge, and agent processes. Most of this
  document is resource-exhaustion resistance.
- **Reachability of LAN services behind egress agents** — the thing the
  tunnel exists to grant, and what an attacker wants to reach or flood.
- **Confidentiality and integrity of tunneled bytes** — per hop; see
  [§6](#6-attacker-position-the-relay-host-hub-or-edge-operator).
- **Key material and configuration** on every host: the tenant CA private
  keys, agent certificates, the control API token, rule files on disk.

## 2. Trust boundaries

1. **Credentials are the trust boundary.** An agent is whatever holds a
   valid mTLS client certificate — on both the h2 and QUIC planes the leaf
   certificate's CN *is* the agent identity and the anchoring tenant CA
   *is* the tenant (since the v4 mTLS-only rework there is no other
   credential; see
   [§6.5](#65-tenant-isolation-multi-tenant-hubs-since-v4)). Possession of
   an agent credential is not treated as a vulnerability (see
   [SECURITY.md](SECURITY.md#out-of-scope) — rotate it); what this model
   does is bound what the position can do ([§5](#5-attacker-position-holder-of-agent-credentials)).
2. **The relay host is inside the trust boundary.** Agent↔hub sessions are
   TLS, but the relay terminates that TLS and routes plaintext frames (see
   [§6](#6-attacker-position-the-relay-host-hub-or-edge-operator)).
3. **The LAN behind an egress agent is reachable exactly as far as the egress
   rules and the hub ACL allow.** Stream-open authorization happens at the
   hub (`[[acl.rules]]`: source agent → target agent); the egress agent then
   dials the rule's `target_addr`. The ACL is the blast-radius control on
   "which LAN services a given agent's counterparties can reach".

## 3. Attacker positions

The model enumerates four positions, ordered by how much they hold:

| # | Position | Section |
|---|---|---|
| 1 | Public unauthenticated client (internet) | [§4](#4-attacker-position-public-unauthenticated-client) |
| 2 | Holder of agent credentials (compromised credential) | [§5](#5-attacker-position-holder-of-agent-credentials) |
| 3 | The relay host operator (hub or edge) | [§6](#6-attacker-position-the-relay-host-hub-or-edge-operator) |
| 4 | Local actor on an agent host (control API) | [§7](#7-attacker-position-local-actor-on-an-agent-host--the-control-api-surface) |
| 5 | A malicious or compromised **tenant** (multi-tenant hub) | [§6.5](#65-tenant-isolation-multi-tenant-hubs-since-v4) |

## 4. Attacker position: public unauthenticated client

### 4.1 Reaching the mesh hub

Registration requires a credential before any tunnel capability exists:

- mTLS is the only authentication mode: the client certificate must chain
  to a tenant CA in the trust table (`[[auth.tenants]]`), and config
  validation rejects an empty trust table or a missing/disabled `[tls]`
  (`crates/mesh/src/config/hub.rs`, `crates/mesh/src/config/validate.rs`).
- The client certificate's leaf CN is extracted and bound as the agent
  identity, and the tenant is derived from which tenant CA anchors the
  chain — a cryptographic fact, never claimable
  (`crates/core/src/tls/server.rs`; the QUIC side reads quinn's
  `peer_identity()`).
- **Hub identity verification on the agent side**: agents authenticate the
  hub via the configured CA, or pin its leaf certificate by SHA-256
  fingerprint (`make_pinned_verifier`, `crates/core/src/tls/cert_pin.rs`);
  the expose client's self-dial to its own edge pins by default — both
  endpoints are the same process, so the trust model needs no CA chain
  (`crates/expose/src/edge/mod.rs`).
- **Pre-auth per-IP rate limiting** (default 30 auth attempts per minute,
  `AuthRateLimiter`) rejects brute-force enumeration with 429 before
  registration is processed; failures are counted and audited
  (`interflow_hub_auth_failures` metric with reason).

### 4.2 Reaching the expose edge

The edge fronts public HTTP by design — it is unauthenticated, so the
defenses are resource-shape defenses:

- **Bounded Host peek**: at most 8 KiB read and a 10 s timeout while looking
  for the `Host` header; a connection that dribbles its first bytes is
  closed (`HOST_PEEK_BYTES` / `HOST_PEEK_TIMEOUT`,
  `crates/expose/src/edge/mod.rs` and `listener.rs`). Unknown hosts are
  closed (no route).
- **Client write-stall bound**: after acceptance, a client that stops
  reading (full send buffer) is closed after 10 s
  (`CLIENT_WRITE_STALL_TIMEOUT`, `crates/expose/src/edge/listener.rs`).
- **Per-IP new-connection rate limit** (default 30/min), which defeats
  connect→peek→disconnect loops that would otherwise bypass the
  concurrency cap, plus a **global concurrent-connection cap**
  (`ConnTracker`, `crates/core/src/security/conn_limit.rs`).
- **L4 passthrough**: beyond the bounded Host peek the edge parses no HTTP —
  request content is carried untouched and is the backend's concern, not
  the edge's. This keeps the edge's own parser surface near zero.
- **Stream idle budget**: a stream silent in both directions for
  `--stream-idle-timeout-secs` (default 300, refuses 0) is closed — the
  same budget bounds how long any single public connection can pin memory.
- **QUIC plane (opt-in)**: with `--quic-listen` the embedded hub opens a
  public QUIC listener for expose clients. It is the same hardening as the
  mesh hub's QUIC face — TLS is mandatory (the listener refuses to start
  without `--hub-cert`/`--hub-key`), clients authenticate with mTLS client
  certificates at the handshake (the registration Hello frame carries
  capability bits, not a credential), and handshake failures / idle
  connections are counted and evicted — so the
  added public surface inherits §4.1 rather than introducing a new trust
  path. The nginx-fronted HTTP/1 surface above is unaffected either way.

### 4.3 Reaching a mesh ingress listener directly

Ingress listeners are intended for LAN-internal interfaces. They carry no
local per-IP connection rate limit (TCP rules have an optional
`idle_timeout_secs`; UDP rules have the rate limits of §4.4) — **directly
exposing a TCP ingress listener to the public internet is unsupported** and
is listed as a deployment requirement, not a defense ([§8](#8-known-blind-spots-and-residual-risks)).

### 4.4 UDP reflection / amplification

A public UDP socket is a reflection point: an attacker spoofs the victim's
source address, the egress-side service responds, and the response travels
back through the tunnel toward the spoofed victim. Both directions are
bounded (`crates/core/src/security/rate_limit.rs`, defaults from
`crates/mesh/src/config/agent.rs`):

- **Inbound, per source IP, dual bucket**: packet rate (default 50 pps) and
  byte rate (default 10 KiB/s). A single datagram larger than the
  per-second byte quota is deterministically dropped, never queued.
- **Return path, per session**: byte rate toward the public side (default
  256 KiB/s) — even a fully spoofed inbound side cannot turn a session into
  a large amplification relay.
- **No silent truncation**: the read buffer is 65535 bytes — deliberately
  above the 65507-byte IPv4 theoretical maximum, so ordinary traffic can
  never be clipped at the socket layer; a datagram that fills the entire
  buffer (only possible with an IPv6 jumbogram) is an explicit drop with a
  counter (`interflow_udp_datagram_truncated`,
  `crates/mesh/src/agent/ingress_udp.rs`). Silent truncation would corrupt
  DNS-style traffic and hide the event.

## 5. Attacker position: holder of agent credentials

Per [§2](#2-trust-boundaries) this is not a vulnerability — the model bounds
the position. An authenticated agent can open streams within its ACL set,
and denial of service **within that set is achievable**; the honest
statement is that the ACL bounds the blast radius, it does not guarantee
availability of the targets.

Bounds enforced at the hub:

- **ACL**: stream opens are checked against `[[acl.rules]]`
  (source → target); denials produce a `StreamDenied` audit event with
  source and reason, and a metric.
- **Concurrency limits**: `max_streams_per_agent` (default 256) and
  `max_streams_total` (default 100 000), enforced identically on the h2 and
  QUIC planes (`crates/mesh/src/hub/routing.rs`, `quic.rs`).
- **Heartbeat eviction**: agents heartbeating on the control channel are
  evicted after a 75 s silence window (15 s interval × 5); eviction tears
  down the agent's orphan streams and counters, so a dead or hostile agent
  cannot hold table space (`crates/mesh/src/hub/heartbeat.rs`).

Bounds enforced at the egress agent itself — deliberately independent of hub
configuration, so a misconfigured or wider hub does not widen the agent
(`EgressPolicy`, `crates/mesh/src/agent/egress.rs`):

- **Local stream cap**: `max_incoming_streams` (default 256, 0 = unlimited)
  — the agent keeps its own ceiling below/aside the hub's.
- **Stream-open rate limit**: `max_stream_opens_per_sec` (default 100,
  burst 256) — an open/close churn attack stays below any concurrency cap,
  but every Open costs the agent a DNS resolve plus a TCP connect against
  the real backend; the rate limit bounds how far the agent can be used as
  a connection-flooding reflection surface toward the LAN.
- **Bounded event-queue wait**: a flood that outruns the agent's
  stream-acceptance loop waits at most 2 s, then the new stream is dropped
  with rollback and a counter
  (`interflow_agent_open_dropped_total{reason=…}`,
  `crates/core/src/tunnel/transport.rs`). Before this bound existed, a
  flood converted into a whole-agent eviction cycle via the hub's dispatch
  timeout — flood no longer has session-level leverage.
- **Dial timeouts**: DNS resolve and TCP connect are each bounded
  (default 5 s), so blackhole targets cannot pin the stream table until
  OS-level timeouts (~75 s) fire.

All three rejection dimensions (event backlog / local limit / rate limit)
are individually visible as metric counters, to tell "misconfigured
thresholds hurting legitimate traffic" apart from "under flood".

## 6. Attacker position: the relay host (hub or edge operator)

The hub never terminates public TLS and never parses HTTP — but it does
terminate the agent↔hub TLS and handle the frame stream. What the relay
host can do to tunnel payloads therefore depends on the tenant's e2e
(`[e2e]`) configuration (docs/design/agent-e2e-encryption.md):

- **`[e2e] mode = "off"` (default): per-hop TLS only.** Tunneled payloads
  are readable and modifiable by whoever controls the relay host —
  confidentiality and integrity are per hop (agent ↔ relay, relay ↔
  agent). Operating a site-to-site mesh through a public relay in this
  mode means trusting that relay with plaintext; pick the hub host
  accordingly, or run the hub on infrastructure you control.
- **`[e2e] mode = "required"` (per tenant): per-hop TLS + an inner
  agent↔agent TLS 1.3 layer.** After the Open frame, the two agents run an
  mTLS handshake *inside* the tunnel stream (handshake bytes ride ordinary
  Data frames) and all payload bytes are ciphertext to the relay: it can
  neither read, modify, inject, nor impersonate (leaf CN must equal the
  stream's declared peer, chain must anchor to the tenant's configured
  anchors), and the egress dials the LAN backend only after that handshake
  verifies — a malicious relay's content-level capabilities degrade to
  availability attacks (drop/delay/reorder streams), which are outside
  this layer's promise. Stream metadata (source/target agents, target
  address, size/timing) remains visible to the relay by routing necessity.
  `opportunistic` mode exists only as a migration window and provides no
  security claim (an active downgrade is indistinguishable from an old
  peer).

UDP streams remain on per-hop TLS in every mode (phase-1 boundary of the
RFC above): a tenant with UDP rules keeps its plaintext-to-relay exposure
for those streams and shows up as an audit item.

The same model applies to scenario A's edge: the public TLS termination
belongs to the fronting proxy, the proxy→edge hop is plaintext HTTP/1 by
design and must stay on the same host or a trusted network segment, and
gateway flows carry the inner layer only when the edge runs with the
stable gateway identity (`--gateway-cert/--gateway-key`; without it the
per-restart minted principal cannot be anchored anywhere, and
`required`-mode egresses reject gateway streams by design).

### 6.5 Tenant isolation (multi-tenant hubs, since v4)

Since the v4 mTLS-only rework (docs/design/multi-tenant-mtls-only.md), a hub
may carry multiple tenants, each with its own client CA:

- **Identity** is `(tenant, agent_id)` — the tenant is derived from which
  tenant root anchors the certificate chain (a cryptographic fact, never
  claimable), the agent id from the leaf CN. A tenant CA's private key
  leaking mints identities for **that tenant only**; rotation unit = tenant.
- **Cross-tenant streams are denied by default**; same-tenant streams are
  allowed by default; `[[acl.rules]]` grant explicit cross-tenant
  exceptions. The expose edge's in-process `_edge` gateway principal is the
  only always-cross-tenant opener (it is the route origin for every public
  connection and rotates its ephemeral CA each restart).
- **Token authentication no longer exists** (agent or admin): client
  certificates are the only credential, on both the h2 and QUIC planes. A
  SIGHUP reload rebuilds the mTLS acceptor from the tenant table — a reload
  can no longer silently drop client-certificate enforcement.
- `GET /agents` is tenant-scoped observability: an identity sees its own
  tenant's list only (a cross-tenant list is reconnaissance material).
- **Real client IPs** are restored per topology and key rate limits,
  connection caps, audit and metrics **only** — never identity or ACL
  decisions (identity is exclusively mTLS). The mechanisms are mutually
  exclusive and share one `--trusted-proxy` set: **PROXY protocol v2**
  (`ppp` crate, v1 rejected; LB / nginx-stream fronts, preamble read
  pre-peek; an untrusted source sending a PROXY signature is hard-rejected)
  and **X-Forwarded-For** on the edge's standard nginx HTTP `proxy_pass`
  leg (stock nginx cannot emit PROXY there): only the right-most chain
  entry appended by a trusted proxy is used, left-side (client-forged)
  entries are ignored, and `required` rejects a trusted proxy that sends no
  parseable header. With XFF active, per-IP gating for a trusted proxy is
  deferred until the request head is buffered; the fronting nginx's own
  `limit_req`/`limit_conn` cover that leg in the meantime.
- Residual: the §6 relay-host plaintext exposure is now conditional —
  closed for TCP streams of `required` tenants by the agent↔agent inner
  TLS layer (docs/design/agent-e2e-encryption.md, implemented), still open
  for `off` tenants, `opportunistic` windows, and UDP streams (phase 2).

### Supply-chain note (the `ppp` dependency)

`ppp` 2.3.0 is the first parser-class third-party dependency on a
pre-authentication path (PROXY preamble). Rationale and the audit surface:
single transitive dependency (`thiserror`), ecosystem de-facto standard
since 2019; parsed input restricted to v2 (nginx always emits v2); the
integration boundary carries property tests plus a fuzz-style
arbitrary-bytes battery (no panic, no IP from untrusted sources), aligned
with the §8.2 fuzzing roadmap.

## 7. Attacker position: local actor on an agent host — the control API surface

Mesh agents expose a local HTTP/1 control API
(`[control]`, `crates/mesh/src/agent/control.rs`): list/add/remove ingress
and egress rules at runtime. Its attack surface and its guardrails:

- **Loopback by default** (`127.0.0.1:9000`). Binding a non-loopback address
  requires an explicit `allow_remote = true` — config validation rejects
  the combination otherwise (`crates/mesh/src/config/validate.rs`).
- **Token mandatory**: enabling `[control]` without `auth_token` is a config
  validation error. When set, every endpoint — read and write — requires the
  Bearer token, compared in constant time.
- **Bounded request bodies**: 64 KiB cap on the control port (rule objects
  are tiny); oversized bodies are rejected.
- **Acknowledgment means persisted**: a mutating command returns 200 only
  after the rule file is written to disk; on persistence failure the
  in-memory and runtime side effects are rolled back and a 500 is returned.
  Every write is a receipt, not a fire-and-forget.
- **Origin annotation and drift convergence**: rules carry an origin
  annotation distinguishing how they came to exist (config file vs control
  API), and listing endpoints surface it; on reconnect the agent resyncs
  with the hub so accumulated drift converges. The mutable configuration
  surface stays auditable without the agent offering any remote control
  capability to the tunnel side.

Residual exposure, stated plainly: with the default loopback bind the trust
statement is "any local process on the agent host" — same-host
considerations apply as for any loopback service.

## 8. Known blind spots and residual risks

Named deliberately; this section is part of the document, not a footnote:

1. **Time-dependent liveness defects as a class.** Two real bugs of this
   class have been found and fixed (a data-plane stall that needed hours of
   specific timing to manifest, and a silent hub death that left idle QUIC
   agents hanging in `Connected`). Each fix carries a regression test that
   fails on the pre-fix code, and a nightly **soak harness** runs a real
   process topology with stall / memory-drift / liveness assertions. The
   class is mitigated by construction, not eliminated — unit tests are
   structurally blind to long-run timing conditions.
2. **Per-IP limits are per-IP.** The hub auth limiter, the edge
   new-connection limiter, and the UDP inbound buckets are all keyed per
   source address; a distributed flood bypasses the per-IP dimension. Global
   caps (connection concurrency, stream totals) bound process-level cost,
   not per-source fairness. Reports of *asymmetric* resource exhaustion
   (cheap for the attacker, expensive for interflow) are explicitly in
   reporting scope per [SECURITY.md](SECURITY.md#out-of-scope).
3. **No local rate limiting on TCP ingress listeners** ([§4.3](#43-reaching-a-mesh-ingress-listener-directly)):
   keep ingress on internal interfaces; direct public exposure is
   unsupported until that changes.
4. **No built-in public TLS termination on the edge yet.** Scenario A
   expects a fronting proxy for TLS today; handshake-time resource defenses
   (handshake deadlines, global handshake-rate budgets, SNI/Host consistency
   checks) are designed but arrive together with edge TLS support — they are
   not present capabilities.
5. **The GUI (`src/` + `src-tauri/`) builds in CI and ships as release
   artifacts (DMG / AppImage / deb / NSIS / MSI), but has not had a dedicated
   security review; its surface is outside this document's reviewed scope.
6. **Pre-1.0.** The surface evolves; this document is dated and tracks the
   tree, not aspirations.

## 9. Out of scope

Mirrors [SECURITY.md](SECURITY.md#out-of-scope), with the model's rationale:

- **Volumetric DDoS** that saturates the host's network before interflow
  sees a packet — no application can defend below its own NIC queue.
- **Compromised trusted credentials** (a stolen agent certificate or tenant
  CA key). Key material is the trust boundary ([§2](#2-trust-boundaries));
  the response is rotation, and the model's job is bounding the position
  ([§5](#5-attacker-position-holder-of-agent-credentials)).
- **Dependency vulnerabilities** — report upstream; exploitable-through-
  default-configuration reports are tracked here.
- **Misconfiguration** of the host, firewall, or any reverse proxy in front
  of interflow.

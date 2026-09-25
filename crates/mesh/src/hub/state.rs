//! Hub shared state types.
//!
//! These types are shared across handler modules:
//! - [`TunnelData`] (from `interflow-core`) is the minimal data unit passed
//!   around inside the hub (one-to-one with wire protocol frames)
//! - [`AgentSession`] is the runtime state of a single registered agent
//! - [`ActiveStream`] is the metadata of one opened end-to-end TCP stream

use bytes::{Bytes, BytesMut};
use interflow_core::error::InterflowError;
use interflow_core::protocol::{CircuitToken, RouteToken, StreamProto};
use interflow_core::security::{AuditSink, AuthRateLimiter, ConnTracker};
pub use interflow_core::tunnel::TunnelData;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::HubConfig;
use http_body_util::combinators::BoxBody;
use hyper::body::Frame;
use interflow_core::protocol::frame as wire;
use interflow_core::tls::TlsPlane;

/// Hub HTTP response body type alias.
pub type HubResponseBody = BoxBody<Bytes, InterflowError>;

/// Alias for `Arc<RwLock<HubConfig>>`, supporting hot reload.
pub type SharedHubConfig = Arc<RwLock<HubConfig>>;

/// The TLS plane (mTLS acceptor + tenant derivation set), swapped atomically
/// on reload so a connection's handshake and its tenant derivation always
/// come from the same configuration generation.
///
/// `std::sync::RwLock`: the read side only clones an `Arc` (never awaits);
/// the write side is the SIGHUP reload task.
pub type SharedTlsPlane = Arc<std::sync::RwLock<Arc<TlsPlane>>>;

/// Registry type: qualified agent key `"{tenant}/{agent_id}"` ->
/// `Arc<RwLock<AgentSession>>`. The qualified key is unambiguous because
/// neither tenant names nor agent ids may contain `/`.
pub type SharedAgents = Arc<RwLock<HashMap<String, Arc<RwLock<AgentSession>>>>>;

/// The registry key form `"{tenant}/{agent}"`.
///
/// The single source of the qualified-id format: everything that builds or
/// asserts a registry key goes through this fn (never by hand), so a format
/// change surfaces as a compile-time event at one definition site, not as
/// scattered red tests.
pub fn qualified_agent_id(tenant: &str, agent: &str) -> String {
    format!("{tenant}/{agent}")
}

/// The mTLS-derived identity of one connection: tenant ownership comes from
/// the certificate chain's anchoring root (never claimable), the agent id is
/// the leaf CN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Owning tenant name.
    pub tenant: Arc<str>,
    /// Agent id (the client certificate CN).
    pub agent: String,
    /// Whether the owning tenant is a trusted gateway (may open streams
    /// across tenant boundaries).
    pub trusted_gateway: bool,
    /// The connection certificate's validity window as unix seconds
    /// `(not_before, not_after)`. The hub reads it (never judges it —
    /// webpki already rejected expired certificates at the handshake) to
    /// phase the agent's credential expiry; `None` only if the leaf
    /// failed to parse, in which case expiry phasing simply has no input.
    pub leaf_validity_unix: Option<(i64, i64)>,
}

impl PeerIdentity {
    /// The registry key form `"{tenant}/{agent}"`.
    pub fn qualified(&self) -> String {
        qualified_agent_id(&self.tenant, &self.agent)
    }

    /// The connection certificate's `notAfter` (unix seconds), when the
    /// leaf parsed.
    pub fn leaf_not_after_unix(&self) -> Option<i64> {
        self.leaf_validity_unix.map(|(_, not_after)| not_after)
    }

    /// Splits a qualified key `"{tenant}/{agent}"` back into its parts.
    /// `None` for malformed keys.
    pub(crate) fn split_qualified(key: &str) -> Option<(&str, &str)> {
        let (tenant, agent) = key.split_once('/')?;
        (!tenant.is_empty() && !agent.is_empty()).then_some((tenant, agent))
    }
}

/// Shared table of `agent_id -> active stream count`.
///
/// Used for `max_streams_per_agent` limiting. The `std::sync::Mutex` is held
/// only briefly during check-and-increment (nanosecond scale), never across
/// an await — avoiding a tokio Mutex serializing the hot path.
pub type SharedStreamCounts = Arc<std::sync::Mutex<HashMap<String, usize>>>;

/// Active stream table type.
pub type SharedActiveStreams =
    Arc<RwLock<HashMap<interflow_core::protocol::StreamId, ActiveStream>>>;

/// Route token → `(source semantic agent, qualified semantic target)`.
/// Tokens are removed when their source semantic agent registers a new
/// circuit; target reconnection intentionally leaves them valid.
pub type SharedRouteLeases = Arc<RwLock<HashMap<RouteToken, (CircuitToken, String, String)>>>;

/// Hot-reloadable runtime limits (a lock-free hot-path atomic collection,
/// one struct threaded through the whole hub).
///
/// `HubServer` assembles the initial values from configuration;
/// `HubService` / `AcceptContext` hold clones; the SIGHUP reload task
/// writes new values. Eliminates the pattern of "the same set of atomics
/// passed around one by one as separate parameters across
/// server/service/accept/reload".
#[derive(Clone)]
pub struct HubLimits {
    /// Maximum concurrent active streams per agent.
    pub max_streams_per_agent: Arc<AtomicUsize>,
    /// Maximum concurrent active streams globally.
    pub max_streams_total: Arc<AtomicUsize>,
    /// Maximum wait in seconds when writing a Data frame into an agent channel.
    pub channel_send_timeout_secs: Arc<AtomicU64>,
    /// Grace period in seconds that an entry survives after a poll disconnect.
    pub poll_grace_secs: Arc<AtomicU64>,
}

impl HubLimits {
    /// Initializes the current values of each limit from the hub
    /// configuration.
    pub fn from_config(cfg: &HubConfig) -> Self {
        Self {
            max_streams_per_agent: Arc::new(AtomicUsize::new(cfg.security.max_streams_per_agent)),
            max_streams_total: Arc::new(AtomicUsize::new(cfg.security.max_streams_total)),
            channel_send_timeout_secs: Arc::new(AtomicU64::new(
                cfg.security.channel_send_timeout_secs,
            )),
            poll_grace_secs: Arc::new(AtomicU64::new(cfg.security.poll_grace_secs)),
        }
    }
}

/// Capacity (in frames) of the per-agent hub→agent channel — the poll
/// downlink, the QUIC relay, and channel rebuilds all use it. When full,
/// senders wait in a bounded fashion, propagating backpressure upstream.
pub(crate) const HUB_CHANNEL_CAP: usize = 256;

/// Tries to acquire a stream slot for `agent`. Returns true on success;
/// returns false without incrementing when over `max`. `max = 0` means
/// unlimited. The lock is held only briefly (check-and-increment,
/// nanosecond scale), never across an await. Shared by the h2 plane
/// (`frame_open`) and the QUIC relay.
pub(crate) fn try_acquire_stream_slot(
    counts: &SharedStreamCounts,
    agent: &str,
    max: usize,
) -> bool {
    if max == 0 {
        return true;
    }
    let mut map = counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = map.entry(agent.to_string()).or_insert(0);
    if *entry >= max {
        false
    } else {
        *entry += 1;
        true
    }
}

/// Releases one stream slot for `agent` (the counterpart of
/// [`try_acquire_stream_slot`]). Removes the key when the count reaches
/// zero to prevent unbounded HashMap growth.
pub(crate) fn release_stream_slot(counts: &SharedStreamCounts, agent: &str) {
    let mut map = counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(entry) = map.get_mut(agent) {
        *entry = entry.saturating_sub(1);
        if *entry == 0 {
            map.remove(agent);
        }
    }
}

/// Reserved tenant name for the realm issuer's control principals (the
/// policy publication face).
///
/// The TLS plane anchors the realm root under this name; data-plane
/// endpoints reject it, `PUT /policy` requires it.
pub const CONTROL_TENANT: &str = "control";

/// Qualified agent -> the latest policy generation whose **serving** has
/// already been recorded in the audit ledger for that agent.
///
/// `policy_pulled` is a state-transition event (a generation reaching an
/// agent), not a heartbeat: steady-state pulls (the watcher ticks where
/// nothing changed — 304s) are authentication activity, not ledger
/// material. The table dedupes the remaining repeats the conditional
/// request cannot: a 200 re-serve of the same generation (e.g. the agent's
/// apply failed and it pulls again) is one arrival per generation, not one
/// per delivery.
///
/// In-memory by design: the authoritative "which generation does this
/// agent hold" state lives agent-side (`x-policy-seen`) — after a hub
/// restart every online agent answers 304 against its current generation,
/// so no catch-up bookkeeping is owed. Entries are bounded by the set of
/// agents that ever registered in this process (a few dozen bytes each).
pub type SharedPolicyPullLedger = Arc<std::sync::Mutex<HashMap<String, u64>>>;

/// Check-and-set for one `policy_pulled` ledger entry: returns `true`
/// (and advances the table) only when this agent has not already been
/// recorded at `generation`; `false` when the serving is a repeat. The
/// `std::sync::Mutex` is held only for the compare-and-swap (nanosecond
/// scale), never across an await.
pub(crate) fn should_record_policy_pull(
    ledger: &SharedPolicyPullLedger,
    agent: &str,
    generation: u64,
) -> bool {
    let mut map = ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if map.get(agent).is_some_and(|&g| g == generation) {
        false
    } else {
        map.insert(agent.to_owned(), generation);
        true
    }
}

/// Qualified agent -> the credential-expiry phase already recorded for
/// that agent (`credential_expiry` audit events).
///
/// The SAME state-transfer accounting discipline as
/// [`SharedPolicyPullLedger`]: an agent's leaf crossing a phase boundary
/// (healthy → warn → critical, or back to healthy after a rotation) is
/// one event per crossing; an agent sitting in a phase is not news, no
/// matter how many heartbeat ticks observe it. In-memory: after a hub
/// restart the first observation of a non-healthy agent re-fires once
/// (a fresh process attesting to what it sees — bounded, not noise).
pub type SharedExpiryLedger =
    Arc<std::sync::Mutex<HashMap<String, interflow_identity::expiry::LeafPhase>>>;

/// One observed phase crossing (the heartbeat tick's expiry check output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExpiryTransition {
    /// The qualified agent whose leaf crossed a phase boundary.
    pub agent: String,
    /// The phase before the crossing (an unobserved agent starts at
    /// `Healthy`: a first sighting already inside `warn` counts as a
    /// crossing — the hub has never attested otherwise).
    pub from: interflow_identity::expiry::LeafPhase,
    /// The leaf health at the crossing.
    pub health: interflow_identity::expiry::LeafHealth,
}

/// Check-and-advance one agent's recorded expiry phase: returns the
/// crossing when the observed phase differs from the recorded one (or the
/// agent was never recorded), `None` while it is unchanged. `None` is
/// also returned when the certificate window is unknown (leaf failed to
/// parse — no input, no attestation, ledger untouched).
pub(crate) fn expiry_transition(
    ledger: &SharedExpiryLedger,
    agent: &str,
    leaf_validity_unix: Option<(i64, i64)>,
    now_unix: i64,
) -> Option<ExpiryTransition> {
    let (not_before, not_after) = leaf_validity_unix?;
    let health =
        interflow_identity::expiry::leaf_phase_from_validity(not_before, not_after, now_unix);
    let mut map = ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let from = map
        .get(agent)
        .copied()
        .unwrap_or(interflow_identity::expiry::LeafPhase::Healthy);
    if from == health.phase {
        return None;
    }
    map.insert(agent.to_owned(), health.phase);
    Some(ExpiryTransition {
        agent: agent.to_owned(),
        from,
        health,
    })
}

/// A verified policy bundle cached for serving.
///
/// Carries the fingerprint of the channel directory it was loaded from
/// (mtime+len of both files — [`crate::pack::policy_channel_fingerprint`])
/// plus the verified bytes. An atomic publish changes the fingerprint, so
/// a stale cache can never serve: fingerprint hit ⇒ the verified bytes are
/// exactly what is on disk. Turns the steady-state pull path (one request
/// per agent per watch interval) into two `stat` calls instead of a file
/// read + ed25519 verification.
pub struct CachedPolicy {
    /// The channel directory the bytes were loaded from (`dir` or
    /// `embedded_dir`).
    pub dir: std::path::PathBuf,
    /// Fingerprint of `dir` at load time.
    pub fingerprint: Option<(std::time::SystemTime, u64, std::time::SystemTime, u64)>,
    /// The canonical policy TOML bytes.
    pub body: Bytes,
    /// The detached signature.
    pub signature: Vec<u8>,
    /// The serving generation.
    pub generation: u64,
}

/// Runtime face of the signed-policy publication channel.
///
/// What `PUT /policy` verifies against, where accepted updates persist
/// (the reload watcher polls the same files), the anti-rollback floor
/// that only ever advances, and the serve cache that keeps steady-state
/// pulls off the disk.
pub struct PolicyChannel {
    /// The trust bundle's policy verifying key (hex).
    pub verifier_key_hex: String,
    /// Persistence dir (`<pack>/state/policy`).
    pub dir: std::path::PathBuf,
    /// The pack's embedded policy snapshot dir (`<pack>/policy`) — served
    /// to pullers when no update has been published.
    pub embedded_dir: std::path::PathBuf,
    /// Highest policy generation this hub has accepted.
    pub floor: std::sync::atomic::AtomicU64,
    /// Verified bundle cache, keyed by the channel fingerprint (see
    /// [`CachedPolicy`]). `std::sync::RwLock`: both sides only clone/copy
    /// under the lock, never await.
    pub cached: std::sync::RwLock<Option<CachedPolicy>>,
}

/// Long-lived shared hub state.
///
/// One aggregate carried verbatim by the h2 plane, the QUIC plane, and the
/// background supervision tasks (heartbeat / eviction / poll-grace).
/// Previously split across four overlapping structs whose only differences
/// were which subset of this table they happened to reference.
#[derive(Clone)]
pub struct HubState {
    /// Table of registered agents.
    pub agents: SharedAgents,
    /// Control-plane route leases. Keys and values split semantic identity from
    /// the opaque data plane, but this table is memory-only and never logged.
    pub route_leases: SharedRouteLeases,
    /// Hub configuration (hot-reloadable).
    pub config: SharedHubConfig,
    /// Active stream table.
    pub active_streams: SharedActiveStreams,
    /// TLS plane (mTLS acceptor + tenant derivation).
    pub tls_plane: SharedTlsPlane,
    /// Hot-reloadable runtime limits.
    pub limits: HubLimits,
    /// Authentication rate limiter (None means disabled).
    pub rate_limiter: Option<Arc<AuthRateLimiter>>,
    /// Active stream count per source agent (for `max_streams_per_agent`).
    pub stream_counts: SharedStreamCounts,
    /// Audit log sink (no-op in disabled mode).
    pub audit: AuditSink,
    /// The signed-policy publication channel (`PUT /policy`): verifier +
    /// persistence dir + the anti-rollback floor. `None` on non-pack hubs.
    pub policy_channel: Option<Arc<PolicyChannel>>,
    /// Audit dedup table for policy servings (see
    /// [`SharedPolicyPullLedger`]).
    pub policy_pull_ledger: SharedPolicyPullLedger,
    /// Per-agent credential-expiry phase already recorded (see
    /// [`SharedExpiryLedger`]) — the symmetric-transfer accounting state
    /// for `credential_expiry` events.
    pub expiry_ledger: SharedExpiryLedger,
    /// Connection tracker (per-IP + global caps).
    pub conn_tracker: Arc<ConnTracker>,
    /// Background task group: connection-level tasks attach here so the
    /// shutdown drain waits for all of them to close out.
    pub tasks: TaskTracker,
    /// Shutdown signal: once triggered, connections enter graceful
    /// GOAWAY/CONNECTION_CLOSE close-out.
    pub shutdown: CancellationToken,
}

// The data frame type reuses `interflow_core::tunnel::TunnelData`
// (isomorphic with the agent side, eliminating a twin definition); the
// direction/origin semantics live in the frame flags (`FLAG_RESPONSE`,
// `FLAG_HUB_ORIGIN`) and are derived into `FrameOrigin` on the core
// `TunnelData`.

/// Shared state of a single agent.
///
/// The outer `HashMap` indexes into this `Arc` by `agent_id`; the inner
/// `RwLock` guards the mutable fields (`rx` take/return, channel rebuilds).
/// The hot path (Data frame forwarding) only clones an `mpsc::Sender` under
/// the inner read lock and releases it immediately; the actual
/// `tx.send().await` executes outside all locks.
pub struct AgentSession {
    /// Opaque data-plane identity for the current registration. Rotates when
    /// another TLS connection replaces this semantic agent registration.
    pub circuit: CircuitToken,
    /// Sender — hub → agent /poll write end (**data plane**: Data / Ping;
    /// when full the sender waits in a bounded fashion, propagating
    /// backpressure upstream).
    pub tx: mpsc::Sender<TunnelData>,
    /// Control-plane sender — Open / `_close_` lifecycle notifications
    /// (unbounded: delivery while online; a full data channel never drops a
    /// close notification, see [`crate::hub::control`]).
    pub ctrl_tx: mpsc::UnboundedSender<TunnelData>,
    /// Control-plane backlog count (sentinel diagnostics): +1 on the send
    /// side ([`crate::hub::control`]), -1 per frame taken by the poll pump
    /// ([`RxStream`]). Reset to zero with the new channel on session
    /// replacement.
    pub ctrl_backlog: Arc<AtomicUsize>,
    /// `Some` means idle, available for the next `/poll` to take; `None`
    /// means currently held by some poll connection.
    pub rx: Option<mpsc::Receiver<TunnelData>>,
    /// Control-plane receiver (same lifetime as `rx`: poll take/return and
    /// generation semantics are fully synchronized).
    pub ctrl_rx: Option<mpsc::UnboundedReceiver<TunnelData>>,
    /// Channel generation: +1 on every channel replacement (register
    /// rebuilding in place / poll detecting closure and rebuilding /
    /// eviction). The poll connection records the generation when taking rx;
    /// on return ([`RxStream`] Drop), a generation mismatch means the stale
    /// receiver is discarded, preventing an old connection from overwriting
    /// a stale receiver onto the new channel.
    pub generation: u64,
    /// Time of the last heartbeat Pong received (reset to now on
    /// registration / re-registration).
    pub last_pong: Instant,
    /// Wake handle of the suspended poll body.
    ///
    /// [`RxStream::poll_next`] registers its waker here before returning
    /// Pending (its mpsc waker only reacts to channel events); after
    /// advancing the generation, eviction/channel rebuilds call
    /// [`AgentSession::wake_poll`] to wake it actively so poll_next
    /// re-runs the generation self-check and ends the response — otherwise
    /// evict cannot reach the rx privately owned by RxStream, and a
    /// residual poll response would hang forever.
    ///
    /// The `Arc` wrapper lets RxStream clone it at construction so
    /// poll_next (a synchronous context) can register without going
    /// through a tokio RwLock, avoiding a "registration failed + wake
    /// lost" race with evict's write lock.
    pub poll_waker: Arc<std::sync::Mutex<Option<Waker>>>,
    /// Upload stream (`POST /stream/up`) lease: `Some` = an active upload
    /// reader task exists.
    ///
    /// Dual to poll's rx single-consumer semantics:
    /// - when an active upload exists in the same generation, a new upload
    ///   gets 409;
    /// - register preemption / [`crate::hub::heartbeat::evict_agent`]
    ///   eviction cancels the lease; the reader task exits → the 200
    ///   response body ends → the agent perceives the death signal and
    ///   rebuilds;
    /// - when the reader itself exits (disconnect / protocol error) it
    ///   returns the lease (only if it is still its own, judged via
    ///   ptr_eq).
    pub up_lease: Option<Arc<tokio_util::sync::CancellationToken>>,
    /// QUIC connection handle: `Some` means this agent registered over QUIC
    /// (traffic streams go through the relay rather than /poll). Set back
    /// to `None` when an h2 re-registration replaces the channel in place.
    pub quic: Option<Arc<QuicAgentConn>>,
    /// The registration certificate's validity window `(not_before,
    /// not_after)` in unix seconds — the hub-side input to credential
    /// expiry phasing (see [`SharedExpiryLedger`]). Refreshed at every
    /// registration (a reconnected agent presents its current leaf;
    /// `install_channels` keeps the previous value, the register sites
    /// overwrite it).
    pub leaf_validity_unix: Option<(i64, i64)>,
}

impl AgentSession {
    /// Creates a fresh session with new channels (generation 0). `quic`
    /// carries the relay connection when registration arrives over QUIC;
    /// `leaf_validity_unix` carries the registration certificate's
    /// validity window (None when the leaf did not parse — expiry phasing
    /// then simply has no input for this session).
    pub fn new(
        circuit: CircuitToken,
        quic: Option<Arc<QuicAgentConn>>,
        leaf_validity_unix: Option<(i64, i64)>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(HUB_CHANNEL_CAP);
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        Self {
            circuit,
            tx,
            ctrl_tx,
            ctrl_backlog: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rx: Some(rx),
            ctrl_rx: Some(ctrl_rx),
            generation: 0,
            last_pong: Instant::now(),
            poll_waker: Arc::new(std::sync::Mutex::new(None)),
            up_lease: None,
            quic,
            leaf_validity_unix,
        }
    }

    /// Installs fresh channels into an existing entry — the
    /// replace-in-place re-registration protocol (h2 and QUIC registration
    /// preemption alike): advances the generation, refreshes liveness,
    /// wakes the suspended poll body, invalidates the upload lease, and
    /// overwrites the QUIC handle (`None` when an h2 registration
    /// preempts a QUIC session; the old relay closes itself out via its
    /// connection-lost watcher).
    ///
    /// Replacing in place (rather than overwriting the whole Arc) is
    /// required: the old poll connection's RxStream holds the old Arc, and
    /// Drop identifies a stale rx via the generation comparison — replacing
    /// the whole Arc would make the comparison always hit the old Arc.
    pub fn install_channels(&mut self, circuit: CircuitToken, quic: Option<Arc<QuicAgentConn>>) {
        let (tx, rx) = mpsc::channel(HUB_CHANNEL_CAP);
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        self.circuit = circuit;
        self.tx = tx;
        self.ctrl_tx = ctrl_tx;
        self.rx = Some(rx);
        self.ctrl_rx = Some(ctrl_rx);
        self.ctrl_backlog = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        self.generation += 1;
        self.last_pong = Instant::now();
        self.quic = quic;
        self.wake_poll();
        if let Some(lease) = self.up_lease.take() {
            lease.cancel();
        }
    }

    /// Severs the session — eviction step one: an RxStream still hanging on
    /// some poll connection ends its response via the generation
    /// self-check; dropping rx closes the data channel so every sender
    /// blocked in `send().await` unblocks immediately; dropping ctrl_rx
    /// closes the control channel (subsequent lifecycle notifications fail
    /// immediately instead of queueing for a consumer that no longer
    /// exists); the upload lease cancellation ends the upload reader's
    /// response so the agent rebuilds.
    pub fn terminate(&mut self) {
        self.rx = None;
        self.ctrl_rx = None;
        self.generation += 1;
        self.wake_poll();
        if let Some(lease) = self.up_lease.take() {
            lease.cancel();
        }
    }

    /// Wakes the suspended poll body (urging it to self-check and end after
    /// a generation advance). Synchronous, non-blocking.
    pub fn wake_poll(&self) {
        if let Ok(mut guard) = self.poll_waker.lock()
            && let Some(waker) = guard.take()
        {
            waker.wake();
        }
    }
}

/// Dispatch plane of one end of a stream (the transport shape is encoded in
/// the type rather than implicitly expressed via `Option`).
#[derive(Debug, Clone)]
pub enum StreamFace {
    /// h2 agent: frames are dispatched via `lookup_tx` → `/poll`.
    Poll,
    /// QUIC agent: frames are written to this agent's relay stream writer
    /// task.
    Relay(mpsc::Sender<TunnelData>),
}

impl StreamFace {
    /// Relay sender (`None` for an h2 end).
    pub const fn relay_sender(&self) -> Option<&mpsc::Sender<TunnelData>> {
        match self {
            Self::Poll => None,
            Self::Relay(tx) => Some(tx),
        }
    }

    /// Whether this is a QUIC relay plane.
    pub const fn is_relay(&self) -> bool {
        matches!(self, Self::Relay(_))
    }
}

/// Metadata of one active end-to-end stream.
#[derive(Debug, Clone)]
pub struct ActiveStream {
    /// Initiating agent.
    pub source_agent: String,
    /// Target agent.
    pub target_agent: String,
    /// Initiating agent's opaque data-plane identity.
    pub source_circuit: CircuitToken,
    /// Target agent's opaque data-plane identity.
    pub target_circuit: CircuitToken,
    /// Stream-carried protocol (recorded at Open); Data frames pass the
    /// corresponding flags through so egress can identify it statelessly.
    pub proto: StreamProto,
    /// Target-end dispatch plane (h2 → /poll; QUIC → relay stream writer
    /// task).
    pub target: StreamFace,
    /// Source-end dispatch plane (return-path frames: h2 → /poll; QUIC →
    /// written back to its bidirectional stream).
    pub source: StreamFace,
    /// Whether the DATAGRAM fast path is in effect for this stream (UDP
    /// stream + QUIC capability on both ends + hub toggle).
    pub datagram_ok: bool,
}

/// QUIC agent connection handle (attached to [`AgentSession`]; `None` for
/// h2-registered agents).
///
/// - `conn`: opens relay streams to this agent (the h2 source → quic target
///   interop path).
/// - `control`: control stream write handle (tokio Mutex: Ping frames are
///   low-frequency, take exclusive write directly).
pub struct QuicAgentConn {
    /// quinn connection.
    pub conn: quinn::Connection,
    /// Control stream sender (Ping).
    pub control: tokio::sync::Mutex<quinn::SendStream>,
    /// Whether this agent negotiated DATAGRAM capability (Hello/HelloAck
    /// caps).
    pub datagram_cap: std::sync::atomic::AtomicBool,
}

/// Adapts an `mpsc::Receiver<TunnelData>` into a `futures::Stream` for a
/// hyper body.
///
/// **Zero-copy path**: each `TunnelData` is split into two `Frame::data`
/// yields:
/// 1. header (magic + ver + type + flags + sid + sa + payload_len)
/// 2. payload (the original `Bytes`, moved rather than copied)
///
/// The HTTP/2 body accumulates in order into a BytesMut at the agent end;
/// the decoder is unaware. This eliminates the per-frame payload memcpy on
/// the hub→agent path.
pub struct RxStream {
    rx: Option<mpsc::Receiver<TunnelData>>,
    ctrl_rx: Option<mpsc::UnboundedReceiver<TunnelData>>,
    /// Control-plane backlog count sharing the session's origin
    /// (decremented by one per frame taken).
    ctrl_backlog: Option<Arc<AtomicUsize>>,
    pending_payload: Option<Bytes>,
    state: Option<Arc<RwLock<AgentSession>>>,
    generation: u64,
    /// Wake slot sharing the origin of `AgentSession::poll_waker` (cloned
    /// at construction; accessed synchronously in poll_next).
    poll_waker: Option<Arc<std::sync::Mutex<Option<Waker>>>>,
    /// Shared hub state needed by the poll-grace task.
    hub: Arc<HubState>,
    /// Owning agent id (only for the grace task's logging and eviction).
    agent_id: String,
}

impl RxStream {
    /// Builds the poll response body stream: returns rx when the connection
    /// drops, and evicts the agent if nobody re-`/poll`s within the grace
    /// period (see [`crate::hub::heartbeat::evict_agent`]).
    #[allow(clippy::too_many_arguments)] // channel/state handles are passed explicitly one by one; the semantics cannot be merged
    pub const fn new(
        rx: mpsc::Receiver<TunnelData>,
        ctrl_rx: mpsc::UnboundedReceiver<TunnelData>,
        ctrl_backlog: Arc<AtomicUsize>,
        state: Arc<RwLock<AgentSession>>,
        generation: u64,
        poll_waker: Arc<std::sync::Mutex<Option<Waker>>>,
        hub: Arc<HubState>,
        agent_id: String,
    ) -> Self {
        Self {
            rx: Some(rx),
            ctrl_rx: Some(ctrl_rx),
            ctrl_backlog: Some(ctrl_backlog),
            pending_payload: None,
            state: Some(state),
            generation,
            poll_waker: Some(poll_waker),
            hub,
            agent_id,
        }
    }
}

/// Converts a usize count to the f64 of a gauge (narrowed through u32 to
/// avoid cast_precision_loss; agent/stream counts are far below u32::MAX in
/// practice).
pub(crate) fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

impl Drop for RxStream {
    /// When the poll connection drops, return rx to `AgentSession` so the
    /// same agent's next /poll reuses it immediately instead of being stuck
    /// on 409 waiting for the keepalive timeout. On a generation mismatch
    /// (the channel was replaced by register/rebuild) or when rx is already
    /// occupied, the stale receiver is discarded.
    ///
    /// After returning it, a grace timer starts: if nobody takes rx within
    /// the grace period, the agent is dead (a healthy agent's poll
    /// reconnect backoff tops out at 5s) — evict the registry entry +
    /// orphan streams so subsequent requests take the fast-fail "agent does
    /// not exist" path instead of a black hole.
    fn drop(&mut self) {
        let rx = self.rx.take();
        let ctrl_rx = self.ctrl_rx.take();
        if rx.is_none() && ctrl_rx.is_none() {
            return;
        }
        let Some(state) = self.state.take() else {
            return;
        };
        let hub = self.hub.clone();
        let agent_id = self.agent_id.clone();
        let generation = self.generation;
        // Drop may happen during runtime shutdown (tests / process exit);
        // if try_current fails, discard and degrade to the keepalive-timeout
        // fallback.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                {
                    let mut st = state.write().await;
                    if st.generation == generation && st.rx.is_none() {
                        if let Some(rx) = rx {
                            st.rx = Some(rx);
                        }
                        if let Some(ctrl_rx) = ctrl_rx {
                            st.ctrl_rx = Some(ctrl_rx);
                        }
                        tracing::debug!(
                            "poll connection dropped, rx/ctrl_rx returned (generation={generation})"
                        );
                    }
                }
                let grace = std::time::Duration::from_secs(
                    hub.limits.poll_grace_secs.load(AtomicOrdering::Relaxed),
                );
                tokio::time::sleep(grace).await;
                // Re-check: same Arc + same generation + rx still never
                // taken → confirmed dead. Any failure of these conditions
                // (re-registration / rebuild / a fresh poll) means the
                // agent is still active.
                let still_idle = {
                    let st = state.read().await;
                    st.generation == generation && st.rx.is_some()
                };
                if still_idle {
                    crate::hub::heartbeat::evict_agent(
                        &hub,
                        &agent_id,
                        &state,
                        "poll_grace_expired",
                    )
                    .await;
                }
            });
        }
    }
}

impl futures::Stream for RxStream {
    type Item = std::result::Result<Frame<Bytes>, InterflowError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Flush the payload left over from the previous frame first
        if let Some(payload) = self.pending_payload.take() {
            return Poll::Ready(Some(Ok(Frame::data(payload))));
        }

        // Generation self-check: when the channel has been rebuilt/evicted
        // (generation advanced), end this response stream proactively.
        // This lets residual poll connections after evict/re-registration
        // close out cleanly; the agent re-/polls immediately after its drain
        // returns (implicitly re-registering if necessary) instead of
        // hanging on a zombie poll. try_read is non-blocking; on lock
        // contention, skip this round and check again on the next frame.
        let stale = match self.state.as_ref() {
            Some(state) => match state.try_read() {
                Ok(st) => st.generation != self.generation,
                Err(_) => false,
            },
            None => false,
        };
        if stale {
            self.rx = None;
            self.ctrl_rx = None;
            return Poll::Ready(None);
        }

        // Control plane takes priority: lifecycle notifications (Open /
        // `_close_`) must not be delayed by data-plane backlog. The ordering
        // contract is in the `hub::control` module docs — a stream's Open
        // precedes its Close (same-channel FIFO); `_close_` may overtake
        // request-direction tail data queued in the data channel; a
        // response-direction Close already preserved FIFO through the data
        // channel on the hub side before falling back to this channel.
        if let Some(ctrl_rx) = self.ctrl_rx.as_mut() {
            match ctrl_rx.poll_recv(cx) {
                Poll::Ready(Some(df)) => {
                    if let Some(backlog) = &self.ctrl_backlog {
                        backlog.fetch_sub(1, AtomicOrdering::Relaxed);
                    }
                    return self.begin_frame(df);
                }
                // Control channel closed = the session's channel was
                // replaced/evicted (generation self-check is above); end
                // this response body, and the agent re-/polls.
                Poll::Ready(None) => {
                    self.rx = None;
                    self.ctrl_rx = None;
                    return Poll::Ready(None);
                }
                Poll::Pending => {}
            }
        }

        let Some(rx) = self.rx.as_mut() else {
            return Poll::Ready(None);
        };
        match rx.poll_recv(cx) {
            Poll::Ready(Some(df)) => self.begin_frame(df),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                // Register the waker before returning Pending: the mpsc
                // waker only reacts to channel events; eviction/generation
                // advances (which send no frame) must go through
                // wake_poll to wake actively and trigger the generation
                // self-check.
                if let Some(slot) = &self.poll_waker
                    && let Ok(mut guard) = slot.lock()
                {
                    *guard = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }
}

impl RxStream {
    /// First of the two `Frame::data` yields for one `TunnelData` (the
    /// header); the payload waits for the next poll (Bytes moved rather
    /// than copied).
    fn begin_frame(
        &mut self,
        df: TunnelData,
    ) -> Poll<Option<Result<Frame<Bytes>, InterflowError>>> {
        use interflow_core::protocol::FrameOrigin;
        // The circuit field is derived from the origin: agent frames carry
        // the opaque circuit, response/hub frames the zero marker (the
        // header has no string source field anymore).
        let circuit = match df.origin {
            FrameOrigin::Agent(c) => c,
            FrameOrigin::Response | FrameOrigin::Hub => {
                interflow_core::protocol::CircuitToken::ZERO
            }
        };
        let mut header = BytesMut::with_capacity(wire::FRAME_HEADER_LEN);
        if wire::encode_frame_header(
            df.stream_type,
            df.flags,
            df.stream_id,
            circuit,
            df.data.len(),
            &mut header,
        )
        .is_none()
        {
            tracing::error!(
                "Frame encode failed (contract violation): stream_id={}",
                df.stream_id
            );
            return Poll::Ready(Some(Ok(Frame::data(Bytes::new()))));
        }
        self.pending_payload = Some(df.data);
        Poll::Ready(Some(Ok(Frame::data(header.freeze()))))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn policy_pull_ledger_dedups_by_agent_and_generation() {
        let ledger: SharedPolicyPullLedger = Arc::new(std::sync::Mutex::new(HashMap::new()));
        // First sighting of a generation at an agent: a state transition.
        assert!(should_record_policy_pull(&ledger, "main/lan-a", 2));
        // Same agent, same generation (a re-serve after a failed apply): a
        // repeat, not a transition.
        assert!(!should_record_policy_pull(&ledger, "main/lan-a", 2));
        // A newer generation reaching the same agent: a transition again.
        assert!(should_record_policy_pull(&ledger, "main/lan-a", 3));
        // Agents are independent — lan-b reaching a generation lan-a already
        // holds is still a transition for lan-b.
        assert!(should_record_policy_pull(&ledger, "main/lan-b", 2));
        assert!(!should_record_policy_pull(&ledger, "main/lan-b", 2));
    }

    #[test]
    fn expiry_ledger_fires_once_per_phase_crossing() {
        use interflow_identity::expiry::LeafPhase;
        let ledger: SharedExpiryLedger = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let ttl = 90 * 86_400;
        let now = 80 * 86_400; // 10d left → warn (11%)
        // First sighting inside warn: a crossing from the implicit
        // healthy baseline (the hub has never attested otherwise).
        let t = expiry_transition(&ledger, "main/lan-a", Some((0, ttl)), now).unwrap();
        assert_eq!(t.from, LeafPhase::Healthy);
        assert_eq!(t.health.phase, LeafPhase::Warn);
        // Every subsequent tick in the same phase: silence.
        assert!(expiry_transition(&ledger, "main/lan-a", Some((0, ttl)), now).is_none());
        assert!(expiry_transition(&ledger, "main/lan-a", Some((0, ttl)), now + 3600).is_none());
        // Crossing into critical: exactly one event.
        let later = 82 * 86_400; // 8d left → critical
        let t = expiry_transition(&ledger, "main/lan-a", Some((0, ttl)), later).unwrap();
        assert_eq!(
            (t.from, t.health.phase),
            (LeafPhase::Warn, LeafPhase::Critical)
        );
        assert!(expiry_transition(&ledger, "main/lan-a", Some((0, ttl)), later + 60).is_none());
        // Rotation: a fresh leaf lands back in healthy — a symmetric
        // crossing (the hub-side "problem solved" attestation).
        let rotated_not_after = later + ttl;
        let t = expiry_transition(
            &ledger,
            "main/lan-a",
            Some((later, rotated_not_after)),
            later,
        )
        .unwrap();
        assert_eq!(
            (t.from, t.health.phase),
            (LeafPhase::Critical, LeafPhase::Healthy)
        );
        // And it can degrade again after recovery.
        let t = expiry_transition(
            &ledger,
            "main/lan-a",
            Some((later, rotated_not_after)),
            rotated_not_after - 5 * 86_400,
        )
        .unwrap();
        assert_eq!(t.health.phase, LeafPhase::Critical);
        // No validity window (unparseable leaf): no input, no attestation,
        // ledger untouched.
        assert!(expiry_transition(&ledger, "main/lan-x", None, now).is_none());
        // Agents are independent.
        assert!(expiry_transition(&ledger, "main/lan-b", Some((0, ttl)), now).is_some());
    }
}

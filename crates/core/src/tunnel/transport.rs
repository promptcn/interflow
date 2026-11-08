//! Tunnel transport abstraction: the agent-side tunnel operation trait (2026-09-11 backlog §6.3).
//!
//! `AgentTunnel` is the facade for consumers (mesh ingress/egress, expose edge)
//! and holds a `dyn TunnelTransport` backend. Current backends:
//! - [`crate::tunnel::h2::H2Tunnel`]: HTTP/2 + POST /stream + GET /poll (current semantics)
//! - (P2b) `QuicTunnel`: QUIC native streams carrying custom frames
//!
//! Design constraints:
//! - Direction and origin live in the frame flags (`FLAG_RESPONSE`,
//!   `FLAG_HUB_ORIGIN`) rather than in-band sentinel strings; the dispatch
//!   layer derives them into a [`FrameOrigin`];
//! - Two consumption forms on the inbound side (2026-09-12 refactor; lossy
//!   broadcast was removed):
//!   - **Response direction** (`FLAG_RESPONSE`): a dedicated channel
//!     registered via `register_stream` (ingress return path / expose
//!     edge), end-to-end backpressure;
//!   - **Request direction** (everything else, including loopback): dispatch
//!     creates a dedicated channel on Open and hands it to egress via
//!     `take_incoming_streams` (consumed by the per-stream forwarder).
//!     The channel is **created then handed off while still inside the dispatch
//!     lock** (dispatch is the sole writer of the table), so subsequent
//!     Data/Close frames always hit it — there is no registration race.
//!     Ordering is guaranteed by the transport: h2 has a total order over the
//!     single poll body; QUIC is ordered within each relay stream and Open is
//!     the first frame.
//! - When a single-stream consumer stalls, dispatch performs only a **bounded
//!   wait** ([`DISPATCH_SEND_TIMEOUT`]); on timeout it **poisons that stream**
//!   (remove the table entry → channel closes → consumer exits itself and
//!   sends a Close notification), without affecting other streams or tearing
//!   down the session;
//! - The new-stream event channel is also bounded ([`INCOMING_SEND_TIMEOUT`]):
//!   when the egress main loop is backlogged and dispatch's hand-off wait for
//!   an Open exceeds the limit, it **drops the event and rolls back the table
//!   entry** — flooding Opens no longer propagates a stall into a whole-agent
//!   eviction (already-established healthy streams are unaffected). Data/Close
//!   frames of established streams are still never silently dropped on any
//!   path.

use crate::error::{InterflowError, Result};
use crate::protocol::{CloseReason, FrameOrigin, FrameType, StreamId, StreamProto};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, trace, warn};

/// Tunnel data
#[derive(Debug, Clone)]
pub struct TunnelData {
    /// The stream id.
    pub stream_id: StreamId,
    /// The frame origin: an agent circuit, the response direction, or the hub
    /// (derived from the frame flags — replaces the former sentinel strings).
    pub origin: FrameOrigin,
    /// The payload.
    pub data: Bytes,
    /// The frame type.
    pub stream_type: FrameType,
    /// Wire flags bits (passed through). On Open frames, `FLAG_UDP` set means the stream carries UDP datagrams.
    pub flags: u8,
}

/// A new inbound stream in the request direction: the Open frame itself plus a dedicated channel for the stream's subsequent frames.
///
/// Handed to egress by [`TunnelTransport::take_incoming_streams`]; the channel
/// capacity is [`STREAM_CHANNEL_CAP`], and if the consumer (the per-stream
/// forwarder) stalls, dispatch applies a bounded wait with poisoning as the
/// fallback.
pub struct IncomingStream {
    /// The relayed Open frame (the requester circuit is the frame's circuit
    /// field; the payload is empty).
    pub open: TunnelData,
    /// The dedicated channel for this stream's subsequent Data/Close frames; closure is the poison signal.
    pub frames: mpsc::Receiver<TunnelData>,
}

/// The tunnel transport backend trait.
#[async_trait]
pub trait TunnelTransport: Send + Sync + 'static {
    /// Opens a tunnel stream (request direction).
    ///
    /// `proto` declares the protocol carried by the stream (TCP byte stream /
    /// UDP datagram).
    async fn send_open(
        &self,
        stream_id: StreamId,
        target_agent: &str,
        proto: StreamProto,
    ) -> Result<()> {
        self.send_open_with(stream_id, target_agent, proto, false)
            .await
    }

    /// [`TunnelTransport::send_open`] with the per-stream e2e (inner TLS)
    /// declaration: `true` sets [`crate::protocol::FLAG_E2E`] on the Open
    /// frame, asking the target agent for the agent↔agent TLS layer
    async fn send_open_with(
        &self,
        stream_id: StreamId,
        target_agent: &str,
        proto: StreamProto,
        e2e: bool,
    ) -> Result<()>;

    /// Sends a data frame (request direction, ingress → hub).
    async fn send_data(&self, stream_id: StreamId, data: Bytes) -> Result<()>;

    /// Sends a data frame (response direction, egress → hub).
    async fn send_data_response(&self, stream_id: StreamId, data: Bytes) -> Result<()>;

    /// Closes the stream (request direction).
    async fn send_close(&self, stream_id: StreamId) -> Result<()>;

    /// Closes the stream (response direction). `reason` travels as the u8
    /// Close payload code (the shared
    /// `interflow_contract::close_reason_code` table; [`CloseReason::CLOSE_FRAME`]
    /// = ordinary close) so the far end can distinguish backend failures from
    /// normal teardown (2026-09-16 reason-propagation hardening).
    async fn send_close_response(&self, stream_id: StreamId, reason: CloseReason) -> Result<()>;

    /// Registers the dedicated inbound channel for a response-direction stream (ingress return path / expose edge). Re-registering overwrites the old channel.
    async fn register_stream(&self, stream_id: StreamId) -> mpsc::Receiver<TunnelData>;

    /// Unregisters the dedicated channel for a response-direction stream.
    async fn unregister_stream(&self, stream_id: StreamId);

    /// Takes the receiver end for new request-direction stream events (consumed by egress). May only be taken once per tunnel;
    /// while not yet taken, request-direction Opens that arrive park waiting
    /// for takeover (bounded, see [`ATTACH_GRACE`]) — this covers the
    /// session-establishment timing window where "the hub dispatches an Open
    /// before the egress handler starts"; only after the timeout (abnormal
    /// routing to a pure ingress agent) is the Open dropped.
    async fn take_incoming_streams(&self) -> Option<mpsc::Receiver<IncomingStream>>;

    /// Unregisters the request-direction stream channel (called when a forwarder exits; idempotent).
    async fn unregister_incoming_stream(&self, stream_id: StreamId);

    /// Session-termination contract: releases all stream resources of this tunnel. Idempotent (repeat calls have no side effects).
    ///
    /// Semantics: calling this declares the end of this tunnel's session
    /// (disconnect / watchdog / user shutdown / direct-connection peer exit).
    /// Implementations must:
    /// 1. cancel internal background tasks (poll / upload / read loops);
    /// 2. clear both dispatch tables (drop all senders — leftover consumer
    ///    forwarders/pumps see `recv()` return `None` and exit naturally,
    ///    releasing backend connections and fds with them);
    /// 3. reclaim transport-backend-specific resources (e.g. QUIC closing the
    ///    connection and endpoint).
    ///
    /// This is the transport-side half of the invariant "no stream task may
    /// outlive the session lifecycle": consumers (the client teardown
    /// sequence) call it explicitly, and a background task dying on its own
    /// (e.g. the h2 poll exiting) also triggers the same table cleanup
    /// internally — two paths, so cleanup does not depend on any single call
    /// site remembering it.
    async fn shutdown(&self);

    /// Pulls the hub's current signed policy bundle over this session's
    /// control plane, as a conditional request: `seen` is the generation the
    /// caller already holds, and a hub at or below it answers "not modified"
    /// (HTTP `304` on the h2 face; the `unchanged` outcome in the QUIC
    /// frame face). Transports without a request/response control plane keep
    /// the default: an unsupported error the caller treats as "this
    /// deployment distributes policy through the node-local file channel".
    async fn pull_policy(&self, _seen: u64) -> Result<PolicyPull> {
        Err(InterflowError::protocol(
            "this transport has no policy control plane".to_string(),
        ))
    }

    /// Fetches the tenant's registered agents over this session's control
    /// plane (`GET /agents` on the h2 face; the [`PeerListRequest`
    /// frame](crate::protocol::FrameType::PeerListRequest) on the QUIC
    /// face) — presence plus leaf health per agent, the peer-observability
    /// read the GUI's Peers section renders. Transports without a
    /// request/response control plane keep the default: an unsupported
    /// error the caller renders as "peers unavailable on this session".
    async fn list_agents(&self) -> Result<Vec<PeerInfo>> {
        Err(InterflowError::protocol(
            "this transport has no agents control plane".to_string(),
        ))
    }

    /// Submits one self-service stream proposal over this session's control
    /// plane (`POST /proposals` on h2; the [`ProposalSubmitRequest`
    /// frame](crate::protocol::FrameType::ProposalSubmitRequest) on QUIC).
    /// The requester is this session's identity; the hub's funnel answers
    /// queued / duplicate / denied-with-reason.
    async fn submit_stream_proposal(
        &self,
        _request: &StreamProposalRequest,
    ) -> Result<ProposalSubmitOutcome> {
        Err(InterflowError::protocol(
            "this transport has no proposals control plane".to_string(),
        ))
    }

    /// Fetches this node's own proposals (pending and decided, until each
    /// record's TTL lapses) — the receipts face (`GET /proposals/mine` on
    /// h2; the [`ProposalMineRequest`
    /// frame](crate::protocol::FrameType::ProposalMineRequest) on QUIC).
    async fn my_proposals(&self) -> Result<Vec<ProposalReceipt>> {
        Err(InterflowError::protocol(
            "this transport has no proposals control plane".to_string(),
        ))
    }

    /// One stream-intent exchange over this session's control plane
    /// (`POST /streams/intent` on h2; the [`StreamIntentRequest`
    /// frame](crate::protocol::FrameType::StreamIntentRequest) on QUIC):
    /// reports this node's actually-paused stream names and receives the
    /// operator's pending pause/resume ops. The requester is this
    /// session's identity; the report lands under that identity only.
    async fn exchange_stream_intents(
        &self,
        _report: &StreamIntentReport,
    ) -> Result<StreamIntentOps> {
        Err(InterflowError::protocol(
            "this transport has no stream-intent control plane".to_string(),
        ))
    }

    /// One out-of-band target-recovery notice over this session's control
    /// plane (`POST /breakers/recovered` on h2; the [`TargetRecoveredRequest`
    /// frame](crate::protocol::FrameType::TargetRecoveredRequest) on QUIC):
    /// the background recovery prober's report that a backend this agent's
    /// egress breaker had tripped is answering bare-TCP dials again. The
    /// requester is this session's identity — an edge-hub on the receiving
    /// side closes the matching route-breaker entries ahead of their
    /// cooldown; every other hub acks without acting. Informational by
    /// design: a lost or unsupported notice only means the receiver keeps
    /// its cooldown-based recovery.
    async fn report_target_recovered(
        &self,
        _notice: &TargetRecoveredNotice,
    ) -> Result<TargetRecoveredAck> {
        Err(InterflowError::protocol(
            "this transport has no target-recovery control plane".to_string(),
        ))
    }

    /// One CRL-poll liveness report over this session's control plane
    /// (`POST /crls/liveness` on h2; the [`CrlLivenessRequest`
    /// frame](crate::protocol::FrameType::CrlLivenessRequest) on QUIC):
    /// this node's renewal loop publishing its current level — the
    /// confirmation instant of the last successful registrar CRL poll (a
    /// no-change poll IS a success) plus the cumulative failure count.
    /// The requester is this session's identity; the report lands under
    /// that identity only.
    ///
    /// The report is the level itself, not a heartbeat: the reporting
    /// task reads the renewal loop's shared face at send time, so a hung
    /// loop keeps producing reports whose confirmation instant stays
    /// frozen — exactly the silence the hub-side recency sweeper exists
    /// to classify.
    async fn report_crl_liveness(&self, _report: &CrlLivenessReport) -> Result<()> {
        Err(InterflowError::protocol(
            "this transport has no CRL-liveness control plane".to_string(),
        ))
    }

    /// One node-status report over this session's control plane
    /// (`POST /node/status` on h2; the [`NodeStatusRequest`
    /// frame](crate::protocol::FrameType::NodeStatusRequest) on QUIC):
    /// this node's engine-level levels (per-stream byte activity; later
    /// the connection-quality window stats) — the things only the node
    /// itself can observe, published so the hub's fleet faces can carry
    /// them. The requester is this session's identity; the report lands
    /// under that identity only.
    ///
    /// Same level-not-heartbeat doctrine as
    /// [`Self::report_crl_liveness`]: the reporter reads shared state at
    /// send time, so a wedged engine's frozen levels arrive verbatim —
    /// which is exactly the silence the consumers' recency judgments
    /// classify.
    async fn report_node_status(&self, _report: &NodeStatusReport) -> Result<()> {
        Err(InterflowError::protocol(
            "this transport has no node-status control plane".to_string(),
        ))
    }

    /// One demanding liveness roundtrip: a probe whose success means, and
    /// only means, that the hub answered within the backend's internal
    /// deadline ([`FrameType::LivenessPing`] request /
    /// [`FrameType::LivenessPong`] response on a fresh short-lived
    /// bi-stream on the QUIC face; `GET /ping` on h2) — the carriage the
    /// supervisor's out-of-tree probe rides.
    ///
    /// This is the transport-side half of the 2026-10-09 one-way-blackhole
    /// fix: quinn's idle timer resets only on *received* authenticated
    /// packets and its keep-alive is send-only, so a session whose inbound
    /// direction still delivers stays "alive" at every transport-layer
    /// sensor while its outbound path is black-holed. The only reliable
    /// proof of a bidirectional path is an answer to a question we asked —
    /// this method is that question.
    ///
    /// Deliberately a required method, not a defaulted one: a default
    /// `Err` would read as strikes to the probe (rebuild loops on any
    /// backend that merely forgot to implement it), a default `Ok` would
    /// assert liveness no one proved. Every backend must state its answer
    /// explicitly.
    async fn liveness_roundtrip(&self) -> Result<()>;

    /// Steady-state receive liveness — see [`SteadyStateLiveness`]. The
    /// default (`None`) opts a backend or form out of the supervisor's
    /// out-of-tree silence probe (no provably-fatal silence, no signal).
    fn steady_state_liveness(&self) -> Option<SteadyStateLiveness> {
        None
    }
}

/// Steady-state receive liveness of a transport backend: the
/// out-of-session-tree death signal.
///
/// Design constraint (the 2026-10-07 zero-attribution session-death case):
/// every *in-tree* death sensor (critical tasks, stall monitors, connection
/// watchers) shares fate with the session task tree it watches — when the
/// tree wedges as a whole, all sensors go blind together and the supervisor,
/// which merely awaits the session, sees nothing. The last line of defense
/// therefore must be **task-independent shared state**: `last_rx_unix_millis`
/// is an atomic maintained by the transport object on every receive path,
/// readable without any task being alive, and observed from *outside* the
/// session tree.
///
/// This ledger is the *passive* tier of the out-of-tree probe. The 2026-10-09
/// one-way-blackhole case added the *demanding* tier
/// ([`TunnelTransport::liveness_roundtrip`]): a ledger can only report what
/// arrived, and an unexplained feeder (or a wall-clock rollback) can keep it
/// looking fresh while every answer the path owes us is lost — so the probe
/// now also asks a question on its own monotonic cadence and believes only
/// its own roundtrips' outcomes.
///
/// `None` (the default) means this backend/form has no death-decidable
/// silence: a backend may only return `Some` when it can itself prove that
/// prolonged inbound silence is fatal (a guaranteed downlink cadence —
/// heartbeat pings, in-connection request/response exchanges) — otherwise it
/// would turn a legitimately quiet connection into a rebuild loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SteadyStateLiveness {
    /// Unix epoch milliseconds of the last inbound byte from the hub on any
    /// receive path of this backend (control frames, stream data, datagrams,
    /// request/response exchanges riding the connection). Initialized to the
    /// connection/registration completion instant.
    pub last_rx_unix_millis: u64,
    /// How long without any inbound data this connection must be considered
    /// dead (a rebuild, not a wait). Derived from the backend's guaranteed
    /// downlink cadence; always strictly above the in-tree stall/death lines
    /// so a living tree reacts first and this stays a pure backstop.
    pub silence_budget: Duration,
}

/// Shared time source for [`SteadyStateLiveness`] timestamps (unix epoch
/// milliseconds; 0 only if the clock is before the epoch, which no consumer
/// treats differently from "long ago").
pub fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The result of one conditional policy pull over the session's control
/// plane — the transport-uniform shape of the hub's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPull {
    /// The hub serves nothing newer than the caller's watermark. Carries
    /// the hub's **reported** serving generation — always a real value on
    /// this variant (a 304 without `x-policy-generation` is a protocol
    /// violation, not a zero here); a serving generation *below* the
    /// caller's watermark is the lineage-deadlock signature the watcher
    /// reports.
    UpToDate { hub_generation: u64 },
    /// The hub carries no policy distribution face (or no bundle behind
    /// one) — an explicit, legitimate state (e.g. an embedded edge hub),
    /// distinct from "nothing newer": there is no generation to report and
    /// nothing this session can pull. The node-local file channel remains
    /// the only distribution path.
    NoPolicyFace,
    /// A bundle newer than the caller's watermark.
    Update(PolicyFetch),
}

/// One signed policy bundle served by the hub's `GET /policy`.
///
/// The opaque canonical bytes, their detached signature, and the serving
/// generation — the caller verifies the signature against its own trust
/// anchor; the hub is a distributor, never an authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFetch {
    pub body: Bytes,
    pub signature: Vec<u8>,
    pub generation: u64,
}

/// One registered agent of the connection's tenant, as the control plane
/// reports it.
///
/// The transport-uniform shape both faces decode into (h2 `GET /agents`
/// JSON and the QUIC `PeerListResponse` payload carry the same bytes; the
/// hub-side producer type is `interflow_mesh::hub::http::AgentListEntry`,
/// whose JSON shape these serde derives mirror field-for-field).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerInfo {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// The reachability reading (`registered ≠ reachable`): a QUIC relay
    /// session in place, or an h2 poll body in place / within reconnect
    /// grace. Pong freshness is deliberately not part of it.
    pub online: bool,
    /// Credential health parsed from the registration certificate; `None`
    /// (null on the wire) when the leaf did not parse.
    pub leaf_expiry: Option<PeerLeafExpiry>,
}

/// The `leaf_expiry` object of a [`PeerInfo`] — the flat wire shape
/// `{not_after_unix, remaining_secs, phase}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerLeafExpiry {
    pub not_after_unix: i64,
    pub remaining_secs: i64,
    pub phase: PeerLeafPhase,
}

/// The leaf-health phase on the wire.
///
/// Mirrors `interflow_identity::expiry::LeafPhase` (snake_case spelling);
/// held as a core-local enum so this crate's serde stays independent of
/// the identity crate — the e2e guards parse real hub output through this
/// type and fail on any spelling drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerLeafPhase {
    /// More than the warn ratio of the TTL remains.
    Healthy,
    /// Less than the warn ratio remains — rotate soon.
    Warn,
    /// Less than the critical ratio remains (or already expired).
    Critical,
}

/// One self-service stream proposal's request face — a node asking its
/// operator for one more `mesh_ingress` stream.
///
/// kube-CSR shape: the node can only propose; minting stays with the
/// issuer. The fields ARE the manifest validator's fields, so the hub's
/// submit funnel can run the same pairing checks the apply-time validator
/// runs. The requester is NEVER taken from this struct — the mTLS identity
/// of the connection is the requester.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamProposalRequest {
    /// The listen-side rule name (unique per agent).
    pub name: String,
    /// The loopback listen address (`host:port`) on the requester.
    pub listen: String,
    /// tcp / udp.
    pub protocol: StreamProtoWire,
    /// The agent whose network dials `remote_addr` (plain agent id).
    pub target_agent: String,
    /// The address the target dials for this stream.
    pub remote_addr: String,
    /// Stream idle budget (1..=86400; `None` = protocol default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
}

/// The protocol spelling on the proposal wire (snake_case; mirrors
/// `StreamProto` without dragging the frame-layer type into JSON payloads).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamProtoWire {
    Tcp,
    Udp,
}

impl From<StreamProto> for StreamProtoWire {
    fn from(p: StreamProto) -> Self {
        match p {
            StreamProto::Tcp => Self::Tcp,
            StreamProto::Udp => Self::Udp,
        }
    }
}

impl From<StreamProtoWire> for StreamProto {
    fn from(p: StreamProtoWire) -> Self {
        match p {
            StreamProtoWire::Tcp => Self::Tcp,
            StreamProtoWire::Udp => Self::Udp,
        }
    }
}

/// The hub's answer to one proposal submission.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProposalSubmitOutcome {
    /// Queued for the operator (carries the proposal's id and expiry).
    Queued { id: String, expires_at_unix: u64 },
    /// An identical pending proposal already exists (idempotent resubmit).
    Duplicate { id: String, expires_at_unix: u64 },
    /// Refused at the door — the funnel's readable reason (the same text
    /// the apply-time validator would produce, delivered at request time).
    Denied { reason: String },
}

/// One proposal of this node, as the receipts query returns it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProposalReceipt {
    pub id: String,
    pub rule: StreamProposalRequest,
    pub submitted_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: ProposalStatusWire,
}

/// A proposal's decision state on the wire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProposalStatusWire {
    /// Awaiting the operator.
    Pending,
    /// Approved — the approval minted `generation`; the stream arrives
    /// through the ordinary policy distribution (≤1 watch interval).
    Approved { generation: u64 },
    /// Rejected — `reason` is the operator's receipt text.
    Rejected { reason: String },
}

/// The agent's stream-intent report: what this node's persisted pause
/// set actually holds right now (the names of its paused ingress
/// streams).
///
/// Sent with every intent exchange; the hub reconciles its
/// operator-issued pending ops against this face and clears each op the
/// report reflects (set membership IS the ack — no sequence numbers).
/// Planned unavailability
/// a
/// paused stream's listener is deliberately down and its port
/// deliberately free; this report is how the hub's observability faces
/// tell that state apart from an unexpected death.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamIntentReport {
    /// The paused stream names, sorted (the wire form of a `BTreeSet`).
    pub paused: Vec<String>,
}

/// The hub's answer to one intent exchange: the pending pause/resume
/// ops the operator queued for THIS agent, oldest first.
///
/// Applying them is idempotent (set add/remove), so a re-delivered op
/// after a restart is harmless; the agent's next report acks them
/// implicitly.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct StreamIntentOps {
    /// Pending ops for the reporting agent (empty = nothing queued).
    #[serde(default)]
    pub ops: Vec<StreamIntentOp>,
}

/// One operator-issued stream-intent op.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StreamIntentOp {
    /// Pause the named ingress stream (stop its listener, release the
    /// port; persists across agent restarts).
    Pause { name: String },
    /// Resume the named ingress stream (explicitly the only unpause).
    Resume { name: String },
}

/// The recovery prober's out-of-band notice: a backend this agent's egress
/// breaker had tripped is answering bare-TCP dials again
///
/// `service_ids` are the agent's own egress-rule names offering the
/// recovered dial target over TCP — the same ids an expose edge's routes
/// select by (`Route::service_id`), which is how the receiving hub maps
/// the notice onto hosts. An empty list (a dynamically-addressed target no
/// named rule offers) is skipped by the sender.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TargetRecoveredNotice {
    /// The recovered dial target, agent vocabulary (`host:port`).
    pub target_addr: String,
    /// The egress-rule (service) ids whose TCP dial target this is.
    pub service_ids: Vec<String>,
}

/// The hub's acknowledgement of one [`TargetRecoveredNotice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct TargetRecoveredAck {
    /// How many route-breaker entries the hub actually closed on the strength
    /// of this notice (0 on hubs with no edge face — acknowledged, no-op).
    pub closed_routes: u32,
}

/// One node's CRL-poll liveness level, as the control plane carries it.
///
/// The wire shape of the renewal loop's face snapshot
/// (`interflow_renewal::CrlPollSnapshot`; kept as a core-local struct so
/// this crate's serde stays independent, exactly like [`PeerInfo`]). The
/// hub stores this verbatim under the reporting identity and judges
/// recency against ITS OWN clock: the age that matters is
/// `hub_now - last_success_unix`, never the report's arrival instant —
/// a hung loop with a healthy reporter must still read silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct CrlLivenessReport {
    /// Unix seconds of the last successful CRL poll (no-change included).
    pub last_success_unix: u64,
    /// Cumulative failed polls since the reporting process started.
    pub failures_total: u64,
    /// The renewal backoff ladder's current stage (consecutive failed
    /// renewal attempts, 0 = none) — additive (2026-10-20
    /// connection-quality face; an older hub reads it as absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_backoff_failures: Option<u32>,
}

/// One stream's byte-activity level, as the node-status report carries
/// it (the fossil face's row material).
///
/// The last instant any byte crossed this stream's pump in either
/// direction, plus the rule's idle budget (the silence-judgment anchor;
/// absent when the rule sets none).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeStreamActivity {
    /// The stream rule's name (policy vocabulary).
    pub name: String,
    /// Unix seconds of the last byte (open/listen-time baseline before
    /// the first byte ever crosses).
    pub last_byte_unix: u64,
    /// The rule's `idle_timeout_secs`, when it sets one — the fossil
    /// judgment's per-row cadence anchor (a multiple of the budget), so
    /// consumers never hardcode a rhythm they do not own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_budget_secs: Option<u32>,
}

/// One node's engine-level status report, as the control plane carries
/// it (`POST /node/status` on h2; the [`NodeStatusRequest`
/// frame](crate::protocol::FrameType::NodeStatusRequest) on QUIC).
///
/// The report is a LEVEL, not a heartbeat (the CRL-liveness doctrine):
/// the reporter reads the engine's shared state at send time, so a
/// wedged engine keeps producing reports whose levels stay frozen —
/// consumers judge recency against the levels' own instants. Sections
/// are additive-optional so the shape grows without an epoch bump (the
/// connection-quality window stats ride this report later, 2026-10-20
/// backlog family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct ConnectionQualityWire {
    /// Session establishments inside the reconnect window (one hour).
    pub reconnects_last_hour: u32,
    /// Median answered demanding-roundtrip, millis (`None` = no
    /// answered sample in the window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_p50_ms: Option<u64>,
    /// 99th-percentile answered roundtrip, millis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_p99_ms: Option<u64>,
    /// Unanswered demanding roundtrips in the window — the
    /// one-way-blackhole leading signal.
    pub rtt_timeouts: u32,
    /// Total roundtrip samples in the window (the confidence
    /// denominator).
    pub rtt_samples: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct NodeStatusReport {
    /// The connection-quality window stats (the engine's supervisor
    /// domain). Absent on older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionQualityWire>,
    /// Per-stream byte activity, sorted by name (the wire form of a
    /// `BTreeMap`). Absent/empty on nodes without mesh stream rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<NodeStreamActivity>,
}

/// Capacity (in frames) of the per-stream dedicated channel. A healthy
/// consumer's steady-state backlog stays far below this; a full channel means
/// the consumer has stalled, handled by poisoning via [`DISPATCH_SEND_TIMEOUT`]
/// as the fallback — no unbounded backlog.
const STREAM_CHANNEL_CAP: usize = 256;

// Capacity of the new-stream event channel (control plane) is DERIVED from
// the agent's local concurrent stream limit (`max_incoming_streams`), not
// independently picked: the egress main loop drains instantly at steady
// state, the capacity exists to absorb stream-creation bursts, and a
// legitimate whole-table burst must not get stuck at the channel layer
// (previously the two 256s were unrelated literals that merely happened to
// match). See `config::params::transport::incoming_channel_cap`. Backlog
// beyond capacity is bounded by [`INCOMING_SEND_TIMEOUT`] as the fallback.

/// Bounded wait for dispatch delivering a single frame to a stream channel. On timeout the stream is poisoned (table entry removed, channel closed).
///
/// Must be significantly smaller than the hub-side `channel_send_timeout_secs`
/// (default 30s): a single-stream stall converges in place to that stream
/// closing before the hub evicts the agent, rather than escalating to a
/// whole-connection reconnect.
const DISPATCH_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded wait for dispatch handing an event off to the new-stream event channel. On timeout the event is dropped and the table entry rolled back
/// (that stream fails; the Close is finalized by the origin's timeout or the
/// hub's reaping, the same family as "late-frame dropping").
///
/// When an Open flood fills the event channel, the correct action is for the
/// new stream to yield rather than let dispatch hang indefinitely alongside
/// it: the bounded wait keeps progress visible to the poll body / QUIC read
/// loop, so a merely-lagging (still alive) egress main loop does not trigger
/// hub eviction. Must be significantly smaller than
/// [`DISPATCH_SEND_TIMEOUT`] and hub `channel_send_timeout_secs` (30s).
const INCOMING_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound on how long an Open parks before egress takeover.
///
/// Session establishment has an inherent timing window: the hub can dispatch
/// an Open as soon as registration/poll is established, while the agent's
/// egress handler takes over inbound streams a beat later — if an Open
/// arriving within that window were dropped, the stream would hang silently
/// until the idle timeout (reproduced in the soak guardrail on 2026-09-13).
/// The parking wait covers this window (handler startup is on the order of
/// milliseconds); the truly-unclaimed case (abnormal routing) falls into the
/// existing drop path after this bound. The test profile shortens it to keep
/// test cases at second scale.
#[cfg(not(test))]
const ATTACH_GRACE: Duration = Duration::from_secs(10);
#[cfg(test)]
const ATTACH_GRACE: Duration = Duration::from_millis(200);

// The parking-wait concurrency budget mirrors the event-channel capacity
// (same anti-flood family; see `incoming_channel_cap`): an Open flood before
// takeover must not breed parking tasks without bound; over-budget Opens
// yield immediately.

/// Egress takeover latch: set when `take_incoming_streams` runs, waking parked Open hand-offs.
#[derive(Default)]
struct AttachGate {
    attached: AtomicBool,
    notify: Notify,
}

impl AttachGate {
    fn attach(&self) {
        self.attached.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire)
    }
}

/// Inbound frame dispatcher: shared by h2 (decoded from /poll) and QUIC (stream read tasks).
///
/// Direction classification replaces the old loopback/Open special-casing:
/// `FLAG_RESPONSE` → response direction; everything else (including loopback,
/// circuit == own) → request direction. The request/response channels for the
/// same sid live in two separate tables, so one agent playing both roles
/// (loopback) does not conflict.
/// Sharded stream-channel table (2026-11-04 audit §2.2/§2.4): per-frame
/// delivery resolves ONE shard read; registration/unregistration write only
/// their own shard. Std locks — every critical section is a clone-out, never
/// held across an await.
struct StreamChannels {
    shards: [std::sync::RwLock<HashMap<StreamId, mpsc::Sender<TunnelData>>>; 16],
}

impl StreamChannels {
    fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| std::sync::RwLock::new(HashMap::new())),
        }
    }

    fn shard(
        &self,
        id: &StreamId,
    ) -> &std::sync::RwLock<HashMap<StreamId, mpsc::Sender<TunnelData>>> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        id.hash(&mut hasher);
        let idx = hasher.finish() % self.shards.len() as u64;
        &self.shards[usize::try_from(idx).unwrap_or(0)]
    }

    /// Inserts, reporting whether a previous channel existed (duplicate Open).
    fn insert(&self, id: StreamId, tx: mpsc::Sender<TunnelData>) -> bool {
        self.shard(&id)
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, tx)
            .is_some()
    }

    /// Removes the entry only while it is still the given channel (a
    /// duplicate Open's rollback must not delete its successor's channel).
    fn remove_if(&self, id: &StreamId, tx: &mpsc::Sender<TunnelData>) {
        let mut guard = self
            .shard(id)
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.get(id).is_some_and(|cur| cur.same_channel(tx)) {
            guard.remove(id);
        }
    }

    /// Removes, reporting whether an entry was there.
    fn remove(&self, id: &StreamId) -> bool {
        self.shard(id)
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id)
            .is_some()
    }

    /// Clones out one stream's sender.
    fn get(&self, id: &StreamId) -> Option<mpsc::Sender<TunnelData>> {
        self.shard(id)
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    fn contains(&self, id: &StreamId) -> bool {
        self.shard(id)
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(id)
    }

    /// Total entries across shards (tests + diagnostics).
    #[cfg(test)]
    fn total(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }

    /// Clears every shard, returning the released entry count.
    fn clear(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let mut guard = s.write().unwrap_or_else(std::sync::PoisonError::into_inner);
                let n = guard.len();
                guard.clear();
                n
            })
            .sum()
    }
}

pub struct TunnelDispatch {
    /// Response-direction stream channels (registered by ingress/edge via register_stream).
    resp_streams: Arc<StreamChannels>,
    /// Request-direction stream channels (created by dispatch on Open).
    req_streams: Arc<StreamChannels>,
    /// New-stream event sender (delivery only begins after the receiver is taken by egress; see open_request_stream).
    incoming_tx: mpsc::Sender<IncomingStream>,
    /// New-stream event receiver (take-once; still `Some` means egress has not taken over).
    incoming_rx: std::sync::Mutex<Option<mpsc::Receiver<IncomingStream>>>,
    /// Egress takeover latch (set on take; parked Opens wait on it).
    attach_gate: Arc<AttachGate>,
    /// Count of Opens parked in the wait (anti-flood budget).
    pending_attach: Arc<AtomicUsize>,
    /// Parking-wait concurrency budget (mirrors the event-channel capacity).
    pending_attach_cap: usize,
}

/// Outcome of the non-blocking delivery pass.
#[derive(Debug)]
pub enum DeliverOutcome {
    /// Handed to the stream channel (or handled inline: Open routed to
    /// the request-stream machinery, which is queue-based, never
    /// blocking on a full stream channel).
    Delivered,
    /// The stream's channel is full: per-stream ordering requires the
    /// caller to park this frame (and any further frames of the same
    /// stream this batch) and resolve it with the timed discipline
    /// ([`TunnelDispatch::deliver_parked`]).
    Parked(TunnelData),
    /// No such stream / consumer gone: dropped (already accounted).
    Gone,
}

impl TunnelDispatch {
    /// Builds with the default event-channel budget (the shared floor) —
    /// for tests and callers without a stream limit.
    pub fn new() -> Self {
        Self::with_stream_limit(0)
    }
}

impl Default for TunnelDispatch {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelDispatch {
    /// Builds with the event-channel budget derived from the agent's local
    /// concurrent-stream limit: `max_incoming_streams` legitimate Opens must
    /// pass in one go; 0 (unlimited) falls back to the floor.
    pub fn with_stream_limit(max_incoming_streams: usize) -> Self {
        let cap = crate::config::params::transport::incoming_channel_cap(max_incoming_streams);
        let (incoming_tx, incoming_rx) = mpsc::channel(cap);
        Self {
            resp_streams: Arc::new(StreamChannels::new()),
            req_streams: Arc::new(StreamChannels::new()),
            incoming_tx,
            incoming_rx: std::sync::Mutex::new(Some(incoming_rx)),
            attach_gate: Arc::new(AttachGate::default()),
            pending_attach: Arc::new(AtomicUsize::new(0)),
            pending_attach_cap: cap,
        }
    }

    /// Registers a dedicated response-direction stream channel (capacity [`STREAM_CHANNEL_CAP`]: under congestion the sender
    /// applies a bounded wait + poisoning fallback, so a single stream's
    /// backlog cannot blow up memory).
    pub fn register_stream(&self, stream_id: StreamId) -> mpsc::Receiver<TunnelData> {
        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAP);
        self.resp_streams.insert(stream_id, tx);
        rx
    }

    /// Unregisters the dedicated response-direction stream channel.
    pub fn unregister_stream(&self, stream_id: StreamId) {
        self.resp_streams.remove(&stream_id);
    }

    /// Takes the request-direction new-stream event receiver (take-once) and wakes parked Open hand-offs.
    pub(crate) fn take_incoming_streams(&self) -> Option<mpsc::Receiver<IncomingStream>> {
        let rx = self
            .incoming_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if rx.is_some() {
            self.attach_gate.attach();
        }
        rx
    }

    /// Unregisters the request-direction stream channel (called when a forwarder exits; idempotent).
    pub(crate) fn unregister_incoming_stream(&self, stream_id: StreamId) {
        self.req_streams.remove(&stream_id);
    }

    /// Session termination: clears the request-direction stream table, returning the number of entries released (idempotent; a second call returns 0).
    ///
    /// Dropping all senders → each stream's forwarder sees `recv()` return
    /// `None` and exits in place → backend connections (TCP fds / UDP
    /// sockets) are released as the tasks exit. This is the root cure for the
    /// retention cycle "forwarder holds tunnel Arc → dispatch holds sender →
    /// channel never closes": after the tunnel dies no new frames arrive, the
    /// poisoning path never triggers, so table entries must be released
    /// uniformly by the termination contract
    /// ([`TunnelTransport::shutdown`])
    pub(crate) fn close_all_request_streams(&self) -> usize {
        self.req_streams.clear()
    }

    /// Session termination: clears the response-direction stream table, returning the number of entries released (idempotent).
    ///
    /// Dropping all senders → the write half of the ingress/edge pump sees
    /// `recv()` return `None` and closes out → the client socket is closed
    /// with it (no longer relying on the idle timeout to expire on its own).
    pub(crate) fn close_all_response_streams(&self) -> usize {
        self.resp_streams.clear()
    }

    /// Dispatches a `TunnelData` frame to the corresponding stream channel based on direction.
    ///
    /// - Response direction (`FLAG_RESPONSE`): delivered on a resp-table hit,
    ///   dropped on a miss (late frame);
    /// - Close notification (a hub-authored Close, `FLAG_HUB_ORIGIN`, sent by
    ///   the hub when the peer tears down the stream): delivered to the req
    ///   table first (the egress
    ///   forwarder reclaims the slot/connection as soon as it receives it —
    ///   otherwise streams closed by the origin linger indefinitely on the
    ///   agent side); with no req-table entry it goes to the resp table
    ///   (ingress/edge stream teardown);
    /// - Request-direction Open: create the channel + hand off to egress (see
    ///   [`Self::open_request_stream`]);
    /// - Request-direction Data/Close: delivered on a req-table hit, dropped
    ///   on a miss (late frame, or a QUIC DATAGRAM arriving before the Open —
    ///   legitimate loss under UDP semantics).
    pub async fn dispatch(&self, tunnel_data: TunnelData) {
        // Open builds stream state (channel creation + hand-off) and awaits
        // its own bounded machinery — never a full stream channel.
        if !matches!(tunnel_data.origin, FrameOrigin::Response)
            && !matches!(tunnel_data.origin, FrameOrigin::Hub)
            && matches!(tunnel_data.stream_type, FrameType::Open)
        {
            self.open_request_stream(tunnel_data).await;
            return;
        }
        // Non-blocking first: only a backpressured (Full) channel falls to
        // the timed wait — the h2/QUIC read loops' common path never arms a
        // timer (§2.3/§2.4).
        if let DeliverOutcome::Parked(tunnel_data) = self.try_deliver(tunnel_data) {
            self.deliver_parked(tunnel_data).await;
        }
    }

    /// The non-blocking delivery pass (§2.4): routes exactly like
    /// [`Self::dispatch`] but never waits — `try_send` semantics. Open
    /// frames are NOT handled here (they build stream state through async
    /// machinery — the caller awaits [`Self::dispatch`] for them).
    pub fn try_deliver(&self, tunnel_data: TunnelData) -> DeliverOutcome {
        let is_response = matches!(tunnel_data.origin, FrameOrigin::Response);
        let is_close_notification = matches!(tunnel_data.origin, FrameOrigin::Hub)
            && tunnel_data.stream_type == FrameType::Close;

        if is_response {
            Self::try_deliver_into(tunnel_data, &self.resp_streams, "response")
        } else if is_close_notification {
            // Deliver to the req table first (the egress forwarder reclaims
            // the slot/connection as soon as it receives it — otherwise
            // streams closed by the origin linger indefinitely on the agent
            // side); with no req-table entry go to the resp table
            // (ingress/edge stream teardown).
            if self.req_streams.contains(&tunnel_data.stream_id) {
                Self::try_deliver_into(tunnel_data, &self.req_streams, "request")
            } else {
                Self::try_deliver_into(tunnel_data, &self.resp_streams, "response")
            }
        } else {
            Self::try_deliver_into(tunnel_data, &self.req_streams, "request")
        }
    }

    /// Non-blocking send into one table (the shared fast path).
    fn try_deliver_into(
        tunnel_data: TunnelData,
        table: &StreamChannels,
        direction: &'static str,
    ) -> DeliverOutcome {
        let stream_id = tunnel_data.stream_id;
        let Some(tx) = table.get(&stream_id) else {
            // Frames keep arriving for a stream after its channel is gone
            // until the peer learns of the close — a steady-state signal for
            // the counter, trace-only per frame.
            metrics::counter!("interflow_dispatch_frames_dropped_total", "reason" => "late_frame", "direction" => direction)
                .increment(1);
            trace!(
                "no channel for stream {} in {direction} direction (late frame), dropping",
                stream_id
            );
            return DeliverOutcome::Gone;
        };
        match tx.try_send(tunnel_data) {
            Ok(()) => DeliverOutcome::Delivered,
            Err(mpsc::error::TrySendError::Full(tunnel_data)) => {
                DeliverOutcome::Parked(tunnel_data)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                metrics::counter!("interflow_dispatch_frames_dropped_total", "reason" => "consumer_exited", "direction" => direction)
                    .increment(1);
                trace!(
                    "stream {} channel closed (consumer exited), dropping further frames",
                    stream_id
                );
                DeliverOutcome::Gone
            }
        }
    }

    /// Resolution of a parked frame (§2.4): re-derives the routing table,
    /// then the timed bounded wait + poisoning discipline. Only
    /// backpressured frames reach here — the fast path never arms a timer.
    ///
    /// Timeout = consumer stalled → poison (remove the table entry; once all
    /// senders are dropped the channel closes, and the consumer exits itself
    /// on `recv() == None` and notifies the peer). Channel already closed =
    /// consumer has exited; drop this frame.
    pub async fn deliver_parked(&self, tunnel_data: TunnelData) {
        let stream_id = tunnel_data.stream_id;
        let is_response = matches!(tunnel_data.origin, FrameOrigin::Response);
        let is_close_notification = matches!(tunnel_data.origin, FrameOrigin::Hub)
            && tunnel_data.stream_type == FrameType::Close;
        let (table, direction) = if is_response {
            (&self.resp_streams, "response")
        } else if is_close_notification && self.req_streams.contains(&stream_id) {
            (&self.req_streams, "request")
        } else if is_close_notification {
            (&self.resp_streams, "response")
        } else {
            (&self.req_streams, "request")
        };
        let Some(tx) = table.get(&stream_id) else {
            // The stream left the table between park and resolution (peer
            // closed / poison raced): drop, already accounted at park time.
            trace!(
                "parked stream {} left the table before resolution, dropping",
                stream_id
            );
            return;
        };
        match tokio::time::timeout(DISPATCH_SEND_TIMEOUT, tx.send(tunnel_data)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                metrics::counter!("interflow_dispatch_frames_dropped_total", "reason" => "consumer_exited", "direction" => direction)
                    .increment(1);
                trace!(
                    "stream {} channel closed (consumer exited), dropping further frames",
                    stream_id
                );
            }
            Err(_) => {
                metrics::counter!("interflow_dispatch_stream_poisoned_total", "direction" => direction)
                    .increment(1);
                warn!(
                    "stream {} consumer stalled for over {DISPATCH_SEND_TIMEOUT:?}, poisoning the stream (direction={direction})",
                    stream_id
                );
                table.remove(&stream_id);
            }
        }
    }

    /// Request-direction Open: creates the dedicated channel (inserted into the table inside the lock before hand-off, eliminating the registration race —
    /// subsequent Data/Close frames always hit the channel) and hands
    /// `(Open frame, Receiver)` off to egress.
    async fn open_request_stream(&self, open: TunnelData) {
        let stream_id = open.stream_id;
        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAP);
        if self.req_streams.insert(stream_id, tx.clone()) {
            warn!(
                "duplicate Open for request-direction stream {stream_id}, overwriting old channel (old forwarder will exit)"
            );
        }

        // Egress has taken over: direct bounded hand-off.
        if self.attach_gate.is_attached() {
            Self::hand_off_incoming(
                &self.incoming_tx,
                &self.req_streams,
                open,
                rx,
                stream_id,
                &tx,
            )
            .await;
            return;
        }

        // Egress has not taken over (session-establishment timing window: an
        // Open dispatched by the hub before the handler task starts, or
        // abnormal routing to a pure ingress agent): park with a bounded wait
        // for takeover instead of blocking the dispatch loop. If the budget is
        // full, yield immediately (anti-flood semantics, same family as the
        // backlog fallback).
        if self.pending_attach.fetch_add(1, Ordering::Relaxed) >= self.pending_attach_cap {
            self.pending_attach.fetch_sub(1, Ordering::Relaxed);
            metrics::counter!("interflow_agent_open_dropped_total", "reason" => "attach_backlog")
                .increment(1);
            warn!(
                "pending-attach budget full ({}), dropping Open: {stream_id}",
                self.pending_attach_cap
            );
            Self::remove_req_stream(&self.req_streams, stream_id, &tx);
            return;
        }
        let gate = Arc::clone(&self.attach_gate);
        let incoming_tx = self.incoming_tx.clone();
        let req_streams = Arc::clone(&self.req_streams);
        let pending = Arc::clone(&self.pending_attach);
        tokio::spawn(async move {
            let deadline = Instant::now() + ATTACH_GRACE;
            loop {
                if gate.is_attached() {
                    break;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                // Re-check once after registering the wake point, closing the "between set and register" missed-wakeup window
                let notified = gate.notify.notified();
                if gate.is_attached() {
                    break;
                }
                if tokio::time::timeout(remaining, notified).await.is_err() {
                    break;
                }
            }
            pending.fetch_sub(1, Ordering::Relaxed);
            if !gate.is_attached() {
                metrics::counter!("interflow_agent_open_dropped_total", "reason" => "attach_timeout")
                    .increment(1);
                warn!(
                    "egress did not attach within {ATTACH_GRACE:?} (misrouted or handler not started), dropping Open and rolling back table entry: {stream_id}"
                );
                Self::remove_req_stream(&req_streams, stream_id, &tx);
                return;
            }
            Self::hand_off_incoming(&incoming_tx, &req_streams, open, rx, stream_id, &tx).await;
        });
    }

    /// Control-plane hand-off (bounded): the egress main loop only parses + spawns at steady state, draining instantly.
    /// Exceeding the wait = egress backlogged/stalled; the new stream yields —
    /// drop the event and roll back the table entry rather than let dispatch
    /// hang indefinitely alongside it (a flood of Opens no longer propagates
    /// into a hub-side stall and whole-agent eviction loop). A dead egress
    /// task is covered by the channel-closed branch and the client-side
    /// JoinError fallback.
    async fn hand_off_incoming(
        incoming_tx: &mpsc::Sender<IncomingStream>,
        req_streams: &Arc<StreamChannels>,
        open: TunnelData,
        frames: mpsc::Receiver<TunnelData>,
        stream_id: StreamId,
        tx: &mpsc::Sender<TunnelData>,
    ) {
        match tokio::time::timeout(
            INCOMING_SEND_TIMEOUT,
            incoming_tx.send(IncomingStream { open, frames }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                debug!("new-stream event has no consumer (egress exited): {stream_id}");
                Self::remove_req_stream(req_streams, stream_id, tx);
            }
            Err(_) => {
                metrics::counter!(
                    "interflow_agent_open_dropped_total",
                    "reason" => "event_backlog"
                )
                .increment(1);
                warn!(
                    "new-stream event channel backlog exceeded {INCOMING_SEND_TIMEOUT:?}, dropping Open and rolling back table entry: {stream_id}"
                );
                Self::remove_req_stream(req_streams, stream_id, tx);
            }
        }
    }

    /// Rolls back a request-direction table entry, only if the current entry is still the channel inserted for this stream (`same_channel`).
    ///
    /// Under QUIC, the read tasks of multiple relay streams may dispatch
    /// concurrently: after a duplicate Open for the same sid overwrites the
    /// entry, the old Open's timeout rollback must not delete the new Open's
    /// channel (otherwise the new forwarder would be poisoned for no reason).
    fn remove_req_stream(
        map: &Arc<StreamChannels>,
        stream_id: StreamId,
        tx: &mpsc::Sender<TunnelData>,
    ) {
        map.remove_if(&stream_id, tx);
    }

    /// Decodes tunnel data (binary length-prefixed frames, supports fragmentation).
    ///
    /// - the payload shares the original buffer allocation zero-copy via
    ///   `Bytes::slice`
    /// - `decode_frame` automatically consumes the decoded bytes
    /// - unknown frame type → if `MUST_UNDERSTAND` is set, discard the buffer
    ///   and return None to trigger reconnect; otherwise skip this frame and
    ///   continue
    pub(crate) fn decode_tunnel_data(buffer: &mut bytes::BytesMut) -> Option<TunnelData> {
        use crate::protocol::frame as wire;
        let outcome = wire::decode_frame(buffer);
        match outcome {
            wire::DecodeOutcome::Ok(frame) => Some(TunnelData {
                // typed Copy ids — zero allocation on the dispatch path (the
                // former String ×2 + Arc<str> are gone)
                stream_id: frame.stream_id,
                origin: FrameOrigin::from_parts(frame.flags, frame.circuit),
                // payload is a Bytes slice, zero-copy
                data: frame.payload,
                stream_type: frame.frame_type,
                flags: frame.flags,
            }),
            wire::DecodeOutcome::Pending => None,
            wire::DecodeOutcome::Error => {
                tracing::error!(
                    "invalid tunnel frame format (magic/version/field mismatch), discarding and reconnecting"
                );
                buffer.clear();
                None
            }
            wire::DecodeOutcome::UnknownType {
                must_understand,
                total_len: _,
            } => {
                if must_understand {
                    tracing::error!(
                        "received unknown must-understand frame type, disconnecting and reconnecting"
                    );
                    buffer.clear();
                    None
                } else {
                    // decode_frame has already consumed this frame automatically; continue parsing the remaining buffer
                    Self::decode_tunnel_data(buffer)
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// In-process Prometheus recorder (same direct-read form as the mesh e2e tests).
    static METRICS: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();

    fn metrics_handle() -> &'static metrics_exporter_prometheus::PrometheusHandle {
        METRICS.get_or_init(|| {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            let _ = metrics::set_global_recorder(recorder);
            handle
        })
    }

    /// A deterministic nonzero test circuit (hex `12...30`, same shape as the
    /// negotiation tests).
    fn test_circuit() -> crate::protocol::CircuitToken {
        crate::protocol::CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap()
    }

    /// A nonzero StreamId encoding a small integer label.
    fn sid(label: u64) -> StreamId {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&label.to_be_bytes());
        bytes[15] = 1;
        StreamId::from_bytes(bytes)
    }

    fn open_td(label: u64) -> TunnelData {
        TunnelData {
            stream_id: sid(label),
            origin: FrameOrigin::Agent(test_circuit()),
            data: Bytes::new(),
            stream_type: FrameType::Open,
            flags: 0,
        }
    }

    fn req_stream_count(dispatch: &TunnelDispatch) -> usize {
        dispatch.req_streams.total()
    }

    /// F1 (main regression, unit form): Open hand-off is bounded when the event channel is backlogged —
    /// past `INCOMING_SEND_TIMEOUT` the event is dropped + the table entry
    /// rolled back + the counter incremented, and dispatch does not block
    /// indefinitely (does not propagate into hub eviction).
    #[tokio::test(start_paused = true)]
    async fn open_event_backlog_drop_is_bounded_and_rolls_back() {
        let _ = metrics_handle();
        let dispatch = TunnelDispatch::new();
        // Egress has taken over (receiver taken) but leaves the backlog unconsumed: fill the event channel
        let _rx = dispatch.take_incoming_streams().unwrap();
        for i in 0..crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            dispatch.dispatch(open_td(i as u64 + 1)).await;
        }
        assert_eq!(
            req_stream_count(&dispatch),
            crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR
        );

        // Over-budget Open: with a paused clock, deterministically reach the timeout branch
        let started = tokio::time::Instant::now();
        dispatch.dispatch(open_td(9_001)).await;
        assert!(started.elapsed() >= INCOMING_SEND_TIMEOUT);

        // Table entry rolled back (dropped stream leaves no channel), counter +1
        assert!(
            dispatch.req_streams.get(&sid(9_001)).is_none(),
            "the over-budget Open's table entry must be rolled back"
        );
        let dropped = metrics_handle()
            .render()
            .lines()
            .filter(|l| {
                l.starts_with("interflow_agent_open_dropped_total{reason=\"event_backlog\"}")
            })
            .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<u64>().ok()))
            .sum::<u64>();
        assert!(
            dropped >= 1,
            "event_backlog counter missing: {}",
            metrics_handle().render()
        );
    }

    /// Healthy path: with egress consuming normally, the Open is handed off immediately (bounding introduces no regression).
    #[tokio::test]
    async fn open_delivers_to_egress_consumer() {
        let dispatch = TunnelDispatch::new();
        let mut rx = dispatch.take_incoming_streams().unwrap();
        dispatch.dispatch(open_td(1)).await;
        let ev = rx
            .recv()
            .await
            .expect("Open event should be handed off immediately (channel far from full)");
        assert_eq!(ev.open.stream_id, sid(1));
        assert!(dispatch.req_streams.contains(&sid(1)));
    }

    /// Main regression (the timing race reproduced in the soak guardrail on 2026-09-13; fails before the fix):
    /// an Open arrives **before** egress takeover (the hub dispatched it before
    /// the handler task started); once takeover happens it must still be handed
    /// off — otherwise the stream hangs silently until the idle timeout.
    #[tokio::test]
    async fn open_before_egress_attach_is_delivered_after_attach() {
        let dispatch = TunnelDispatch::new();
        // Not yet taken over: the Open parks (table entry retained, not dropped)
        dispatch.dispatch(open_td(2)).await;
        assert!(
            dispatch.req_streams.contains(&sid(2)),
            "the table entry must be retained while parked (later Data frames must hit the channel)"
        );

        // Egress takes over (handler task starts) — the parked Open should be handed off immediately
        let mut rx = dispatch.take_incoming_streams().unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("the parked Open must be handed off after takeover (this recv times out before the fix)")
            .expect("channel alive");
        assert_eq!(ev.open.stream_id, sid(2));

        // A Data frame arriving during the parking window hits the same channel (zero loss)
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(2),
                origin: FrameOrigin::Agent(test_circuit()),
                data: Bytes::from_static(b"early-data"),
                stream_type: FrameType::Data,
                flags: 0,
            })
            .await;
        let mut frames = ev.frames;
        let td = tokio::time::timeout(Duration::from_secs(1), frames.recv())
            .await
            .expect("the Data frame from the parking window should hit the established channel")
            .expect("channel alive");
        assert_eq!(&td.data[..], b"early-data");
    }

    /// Egress never takes over (abnormal routing / handler not started): after
    /// [`ATTACH_GRACE`] the parked Open is dropped and the table entry rolled
    /// back, with the `attach_timeout` counter.
    #[tokio::test]
    async fn open_without_egress_attachment_drops_after_grace() {
        let _ = metrics_handle();
        let dispatch = TunnelDispatch::new();
        dispatch.dispatch(open_td(3)).await;
        assert_eq!(
            req_stream_count(&dispatch),
            1,
            "parked within the grace period"
        );

        // Must converge after the test-profile ATTACH_GRACE (200ms)
        let deadline = Instant::now() + Duration::from_secs(5);
        while req_stream_count(&dispatch) > 0 {
            assert!(
                Instant::now() < deadline,
                "the table entry must be rolled back after the grace period"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let dropped = metrics_handle()
            .render()
            .lines()
            .filter(|l| {
                l.starts_with("interflow_agent_open_dropped_total{reason=\"attach_timeout\"}")
            })
            .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<u64>().ok()))
            .sum::<u64>();
        assert!(dropped >= 1, "attach_timeout counter missing");
    }

    /// Parking budget full before takeover: over-budget Opens yield immediately (anti-flood does not break due to parking).
    #[tokio::test]
    async fn attach_pending_overflow_drops_immediately() {
        let _ = metrics_handle();
        let dispatch = TunnelDispatch::new();
        for i in 0..crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            dispatch.dispatch(open_td(i as u64 + 1)).await;
        }
        assert_eq!(
            req_stream_count(&dispatch),
            crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR
        );

        dispatch.dispatch(open_td(9_001)).await;
        assert_eq!(
            req_stream_count(&dispatch),
            crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR,
            "the over-budget Open must not park (entry count unchanged)"
        );
        let dropped = metrics_handle()
            .render()
            .lines()
            .filter(|l| {
                l.starts_with("interflow_agent_open_dropped_total{reason=\"attach_backlog\"}")
            })
            .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<u64>().ok()))
            .sum::<u64>();
        assert!(dropped >= 1, "attach_backlog counter missing");

        // After takeover, all parked events are handed off (every stream arrives at egress alive)
        let mut rx = dispatch.take_incoming_streams().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = 0usize;
        while got < crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            assert!(
                Instant::now() < deadline,
                "not all parked events were handed off ({got})"
            );
            if rx.recv().await.is_some() {
                got += 1;
            } else {
                panic!("channel closed early (handed off {got})");
            }
        }
    }

    /// Close-notification routing: with a req-table entry (egress forwarder in service) → delivered to
    /// the req channel (the forwarder reclaims the slot upon receipt); with no
    /// req-table entry → goes to the resp table (no regression on the
    /// ingress/edge stream-teardown path).
    #[tokio::test]
    async fn close_notification_routes_to_forwarder_first() {
        let dispatch = TunnelDispatch::new();
        let mut rx = dispatch.take_incoming_streams().unwrap();
        dispatch.dispatch(open_td(4)).await;
        let ev = rx.recv().await.expect("Open handed off");
        let mut frames = ev.frames;

        // Close notification → req channel (the forwarder side receives the Close frame)
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(4),
                origin: FrameOrigin::Hub,
                data: Bytes::from_static(&[3]),
                stream_type: FrameType::Close,
                flags: 0,
            })
            .await;
        let td = tokio::time::timeout(Duration::from_secs(1), frames.recv())
            .await
            .expect("the notification should be delivered immediately")
            .expect("channel alive");
        assert_eq!(td.stream_type, FrameType::Close);

        // _close_ with no req-table entry → resp table (received by the ingress registrant)
        let mut resp = dispatch.register_stream(sid(5));
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(5),
                origin: FrameOrigin::Hub,
                data: Bytes::from_static(&[0]),
                stream_type: FrameType::Close,
                flags: 0,
            })
            .await;
        let td = tokio::time::timeout(Duration::from_secs(1), resp.recv())
            .await
            .expect("the resp notification should be delivered immediately")
            .expect("channel alive");
        assert_eq!(td.stream_type, FrameType::Close);
    }

    /// Egress receiver already closed (task exited): send fails immediately and the table entry is rolled back.
    #[tokio::test]
    async fn open_fails_fast_when_egress_receiver_closed() {
        let dispatch = TunnelDispatch::new();
        let rx = dispatch.take_incoming_streams().unwrap();
        drop(rx);
        let started = tokio::time::Instant::now();
        dispatch.dispatch(open_td(6)).await;
        assert!(
            started.elapsed() < INCOMING_SEND_TIMEOUT,
            "a closed channel should fail immediately instead of waiting out the full timeout"
        );
        assert_eq!(req_stream_count(&dispatch), 0);
    }

    /// Termination contract (main regression, 2026-09-14 fd leak): `close_all_request_streams`
    /// clears the request-direction table and drops all senders — from the
    /// forwarder's perspective the channel is closed (`recv() == None` is the
    /// self-termination signal). Before the fix, senders were pinned in the
    /// table, forwarders hung forever, and the backend TCP fds were never
    /// released.
    #[tokio::test]
    async fn close_all_request_streams_releases_forwarder_channels() {
        let dispatch = TunnelDispatch::new();
        let mut rx = dispatch.take_incoming_streams().unwrap();
        dispatch.dispatch(open_td(7)).await;
        dispatch.dispatch(open_td(8)).await;
        let ev1 = rx.recv().await.expect("Open handed off");
        let ev2 = rx.recv().await.expect("Open handed off");
        assert_eq!(req_stream_count(&dispatch), 2);

        let n = dispatch.close_all_request_streams();
        assert_eq!(n, 2, "returns the number of cleared entries");
        assert_eq!(req_stream_count(&dispatch), 0);

        // From the forwarder's perspective: channel closure is visible immediately, and it is idempotent (a second call returns 0)
        for mut frames in [ev1.frames, ev2.frames] {
            let r = tokio::time::timeout(Duration::from_secs(1), frames.recv()).await;
            assert!(
                matches!(r, Ok(None)),
                "recv must return None immediately after close_all"
            );
        }
        assert_eq!(dispatch.close_all_request_streams(), 0);
    }

    /// Termination contract (response direction): `close_all_response_streams` clears the resp table —
    /// the write half of the ingress/edge pump closes out on `recv() == None`
    /// (the socket is closed with it).
    #[tokio::test]
    async fn close_all_response_streams_releases_pump_channels() {
        let dispatch = TunnelDispatch::new();
        let mut pump_rx = dispatch.register_stream(sid(9));
        assert_eq!(dispatch.close_all_response_streams(), 1);

        let r = tokio::time::timeout(Duration::from_secs(1), pump_rx.recv()).await;
        assert!(
            matches!(r, Ok(None)),
            "the pump channel must close immediately after close_all"
        );
        // Table now empty: subsequent frames are dropped as late frames, no hit
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(9),
                origin: FrameOrigin::Response,
                data: Bytes::new(),
                stream_type: FrameType::Data,
                flags: 0,
            })
            .await;
        assert_eq!(dispatch.close_all_response_streams(), 0);
    }

    /// Duplicate-Open overwrite + timeout-rollback same_channel guard: the old Open's rollback
    /// must not remove the channel installed by the newer duplicate Open
    /// (protection against mis-deletion under concurrent QUIC dispatch).
    #[tokio::test(start_paused = true)]
    async fn timeout_rollback_keeps_newer_duplicate_entry() {
        let dispatch = Arc::new(TunnelDispatch::new());
        let _rx = dispatch.take_incoming_streams().unwrap();
        for i in 0..crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            dispatch.dispatch(open_td(i as u64 + 1)).await;
        }
        // The first Open blocks on the timeout; while it is pending, Open the
        // same sid once more (simulating the insertion interleaving of
        // concurrent dispatch: the new channel goes straight into the table).
        let d = Arc::clone(&dispatch);
        let first = tokio::spawn(async move {
            d.dispatch(open_td(10)).await;
        });
        tokio::task::yield_now().await;
        {
            let (tx2, _rx2) = mpsc::channel(STREAM_CHANNEL_CAP);
            dispatch.req_streams.insert(sid(10), tx2);
        }
        first.await.unwrap();
        // The old Open's timeout rollback is stopped by the same_channel guard: the new channel stays in the table
        assert!(
            dispatch.req_streams.contains(&sid(10)),
            "the timeout rollback must not mis-delete the new channel installed by the duplicate Open"
        );
    }

    /// §2.4 non-blocking delivery: a backpressured (full) stream parks its
    /// frame while other streams in the same batch keep flowing — one
    /// stalled consumer cannot head-of-line-block the poll loop.
    #[tokio::test]
    async fn try_deliver_parks_full_stream_without_blocking_others() {
        let dispatch = TunnelDispatch::new();
        let stalled = sid(1);
        let healthy = sid(2);
        let mut stalled_rx = dispatch.register_stream(stalled);
        let mut healthy_rx = dispatch.register_stream(healthy);

        // Fill the stalled stream's channel to capacity (no consumer).
        for i in 0..STREAM_CHANNEL_CAP {
            let frame = TunnelData {
                stream_id: stalled,
                origin: FrameOrigin::Response,
                data: Bytes::from(vec![0u8; 8]),
                stream_type: FrameType::Data,
                flags: 0,
            };
            let _ = &i;
            assert!(
                matches!(dispatch.try_deliver(frame), DeliverOutcome::Delivered),
                "fill below capacity delivers without parking"
            );
        }

        // Capacity exhausted: the next frame parks instead of waiting.
        let overflow = TunnelData {
            stream_id: stalled,
            origin: FrameOrigin::Response,
            data: Bytes::from_static(b"overflow"),
            stream_type: FrameType::Data,
            flags: 0,
        };
        let parked_frame = match dispatch.try_deliver(overflow) {
            DeliverOutcome::Parked(td) => td,
            other => panic!("expected Parked, got {other:?}"),
        };

        // The healthy stream flows in the same batch (no waiting on the
        // stalled one).
        let flows = TunnelData {
            stream_id: healthy,
            origin: FrameOrigin::Response,
            data: Bytes::from_static(b"healthy"),
            stream_type: FrameType::Data,
            flags: 0,
        };
        assert!(matches!(
            dispatch.try_deliver(flows),
            DeliverOutcome::Delivered
        ));
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), healthy_rx.recv())
            .await
            .expect("healthy stream delivered immediately")
            .expect("frame");
        assert_eq!(received.data.as_ref(), b"healthy");

        // Parked resolution: after the consumer drains, the parked frame
        // lands (order preserved behind the queued backlog).
        let drained = stalled_rx.recv().await.expect("backlog frame");
        assert_eq!(drained.data.len(), 8);
        dispatch.deliver_parked(parked_frame).await;
        for _ in 0..(STREAM_CHANNEL_CAP - 1) {
            stalled_rx.recv().await.expect("backlog frame");
        }
        let last = tokio::time::timeout(std::time::Duration::from_secs(1), stalled_rx.recv())
            .await
            .expect("parked frame resolved")
            .expect("frame");
        assert_eq!(last.data.as_ref(), b"overflow");
    }

    /// A poisoned stream (consumer stalled past the deadline) is removed
    /// from the table by the parked-resolution path — the existing
    /// discipline carried over the §2.4 restructure.
    #[tokio::test(start_paused = true)]
    async fn deliver_parked_poisons_stalled_consumer() {
        let dispatch = TunnelDispatch::new();
        let stream = sid(3);
        let _never_drained = dispatch.register_stream(stream);

        for _ in 0..STREAM_CHANNEL_CAP {
            let frame = TunnelData {
                stream_id: stream,
                origin: FrameOrigin::Response,
                data: Bytes::from(vec![0u8; 4]),
                stream_type: FrameType::Data,
                flags: 0,
            };
            assert!(matches!(
                dispatch.try_deliver(frame),
                DeliverOutcome::Delivered
            ));
        }
        let overflow = TunnelData {
            stream_id: stream,
            origin: FrameOrigin::Response,
            data: Bytes::from_static(b"x"),
            stream_type: FrameType::Data,
            flags: 0,
        };
        let parked = match dispatch.try_deliver(overflow) {
            DeliverOutcome::Parked(td) => td,
            other => panic!("expected Parked, got {other:?}"),
        };

        // Advance past DISPATCH_SEND_TIMEOUT with no consumer: the
        // resolution poisons the stream (table entry removed).
        tokio::time::advance(DISPATCH_SEND_TIMEOUT + std::time::Duration::from_millis(50)).await;
        dispatch.deliver_parked(parked).await;
        assert!(
            !dispatch.resp_streams.contains(&stream),
            "a stalled consumer must be poisoned out of the table"
        );
    }
}

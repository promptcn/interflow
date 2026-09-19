//! HTTP/2 tunnel backend: `POST /stream/up` (uplink, streaming) + `GET /poll` (downlink, streaming).
//!
//! Wire semantics (2026-09-12 uplink streaming — the mirror of `/poll`):
//! - The uplink is one long-lived `POST /stream/up` whose request body is
//!   written frame by frame with the existing frame codec
//!   ([`crate::protocol::frame`]). The previous "one full HTTP exchange per
//!   frame" shape pinned single-stream throughput at 1/RTT (measured
//!   ~172µs/frame for a 64B datagram on loopback).
//! - Direction semantics live at the frame layer: response-direction frames
//!   carry `source_agent = "_response_"` (the same sentinel the hub's QUIC
//!   relay uses, [`RESPONSE_SOURCE`]); request-direction frames carry the real
//!   agent id — the `x-direction` header is retired.
//! - The Open frame carries stream-creation metadata: `FLAG_UDP` is set per
//!   protocol, and the payload is `"{target_agent}:{target_addr}"` (the same
//!   encoding as the QUIC backend).
//! - Upload response body ending = death signal: the agent immediately
//!   rebuilds the upload (implicit re-registration on the hub side heals it,
//!   fully symmetric with a `/poll` disconnect); the h2 connection itself
//!   dying → session-level reconnect (existing path).
//! - Downlink unchanged: a frame stream over the long `/poll` response; hub
//!   heartbeat Pings are intercepted and answered at the decode layer.
//!
//! Error signaling: frame-level rejection (ACL / stream quota / target not
//! registered) no longer has a per-frame HTTP status — the hub sends a
//! `"_close_"` frame over `/poll` carrying `CLOSE:{sid}:{reason}`, and the
//! pump side reuses the existing Close stream-teardown path. `send_open`
//! returning Ok only means the frame entered the uplink channel.

use crate::error::{InterflowError, Result};
use crate::protocol::{FrameType, StreamProto, frame as wire};
use crate::tunnel::agent::H2Liveness;
use crate::tunnel::chunking::ChunkHygiene;
use crate::tunnel::session_tasks::{Beat, SessionTasks, beat_interval};
use crate::tunnel::transport::{RESPONSE_SOURCE, TunnelData, TunnelDispatch, TunnelTransport};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, StatusCode};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::{Mutex, mpsc};
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// The h2 request body type.
///
/// The request body of the streaming uplink POST shares this type parameter
/// (`SendRequest<H2RequestBody>`) with empty-body requests such as `/poll`
/// and `/register`.
pub type H2RequestBody = BoxBody<Bytes, InterflowError>;

/// Capacity (in frames) of the uplink frame channel. Mirrors the `/poll`
/// downlink channel capacity; when full, `send().await` applies backpressure
/// to the pump and ultimately to the TCP/UDP source.
const UPLOAD_CHANNEL_CAP: usize = 256;

/// Builds an empty request body (shared by bodyless requests such as `/poll` and `/register`).
pub fn empty_request_body() -> H2RequestBody {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// The HTTP/2 tunnel backend.
pub(crate) struct H2Tunnel {
    agent_id: String,
    /// Session-termination token (a same-node clone passed in at construction): `shutdown()` cancels it,
    /// stopping the upload/poll background tasks.
    token: CancellationToken,
    dispatch: Arc<TunnelDispatch>,
    /// The uplink frame writer end. Replaced wholesale by the upload task each
    /// time it rebuilds the stream; during an upload death gap the channel is
    /// already closed, so `send` errors → the pump tears the stream down (TCP
    /// semantics, no silent frame drops).
    up_tx: Arc<Mutex<mpsc::Sender<Bytes>>>,
}

/// How one h2 poll round ended. Cancellation is modeled as its own outcome
/// instead of being folded into the failure shape: a user Stop observed
/// mid-drain is neither success nor failure, and feeding it into the retry
/// accounting produced an orphan "retrying connection in 200ms…" log line
/// for a backoff the very next await cancelled (the 2026-09-18 GUI
/// papercut).
enum PollOutcome {
    /// The stream was consumed to its end: the connection lived, retry
    /// pacing resets.
    Drained,
    /// The round failed before or during consumption: count it, log, back
    /// off.
    Failed,
    /// Shutdown was observed inside the drain: exit without bookkeeping.
    Cancelled,
}

impl H2Tunnel {
    /// Creates the tunnel backend from an established HTTP/2 connection.
    ///
    /// Registration is done by the caller (`AgentClient`); this method only
    /// takes over the connection and starts the two background tasks: the
    /// uplink stream and the downlink poll. When `shutdown` is cancelled the
    /// tasks exit and release the connection (otherwise the connection stays
    /// open, and after the same agent_id restarts, the old tasks would contend
    /// with the new instance for hub-side resources).
    ///
    /// `liveness` (see [`H2Liveness`]) decides the data-plane heartbeat
    /// shape: the poll receive-side watchdog, the Pong return path, and the
    /// critical-task stall timeout. `tasks` owns the session token (the
    /// cascade target of the death contract) and the task tracker.
    pub fn new(
        agent_id: String,
        hub_url: &str,
        sender: SendRequest<H2RequestBody>,
        tasks: &SessionTasks,
        liveness: H2Liveness,
    ) -> Self {
        let tasks = tasks.clone();
        let shutdown = tasks.token().clone();
        let sender = Arc::new(Mutex::new(sender));
        let dispatch = Arc::new(TunnelDispatch::new());
        // Pre-build the first-round frame channel: sends that happen before the
        // upload is established buffer there (instead of erroring) and flow out
        // as soon as the first request is up — eliminating the race in the
        // "tunnel constructed → upload ready" window.
        let (first_up_tx, first_up_rx) = mpsc::channel(UPLOAD_CHANNEL_CAP);
        let up_tx = Arc::new(Mutex::new(first_up_tx));

        // Critical under the death contract: the task exiting for ANY reason
        // (return, panic, abort) ends the session for rebuild. Before the
        // 2026-09-16 hardening these were fire-and-forget spawns — an upload
        // or poll task death went entirely unobserved.
        let upload_sender = sender.clone();
        let upload_agent_id = agent_id.clone();
        let upload_hub_url = hub_url.to_string();
        let upload_up_tx = up_tx.clone();
        let upload_shutdown = shutdown.clone();
        tasks.spawn_critical(
            "h2-upload",
            Some(liveness.task_stall_timeout),
            move |beat| {
                Self::run_upload_loop(
                    upload_sender,
                    upload_agent_id,
                    upload_hub_url,
                    upload_up_tx,
                    upload_shutdown,
                    Some(first_up_rx),
                    liveness.establish_timeout,
                    liveness.task_stall_timeout,
                    beat,
                )
            },
        );

        let dispatch_for_poll = dispatch.clone();
        let agent_id_for_poll = agent_id.clone();
        let hub_url_for_poll = hub_url.to_string();
        let up_tx_for_poll = up_tx.clone();
        let token_for_poll = shutdown.clone();
        let poll_tasks = tasks.clone();

        tasks.spawn_critical("h2-poll", Some(liveness.task_stall_timeout), move |beat| {
            async move {
                Self::run_poll_loop(
                    sender,
                    agent_id_for_poll,
                    hub_url_for_poll,
                    &dispatch_for_poll,
                    token_for_poll,
                    up_tx_for_poll,
                    liveness,
                    poll_tasks,
                    liveness.task_stall_timeout,
                    beat,
                )
                .await;
                // Internal-cause cleanup (the second half of the termination
                // contract): poll exiting = this tunnel will receive no more
                // inbound frames = every consumer in the dispatch tables is
                // already dead-waiting — clear the tables in place to release
                // them (forwarders/pumps get None from recv() and exit, backend
                // fds released), without depending on the consumer remembering to
                // call shutdown(). Coexists idempotently with explicit shutdown().
                Self::release_all_streams(&dispatch_for_poll).await;
                debug!("data receive task finished");
            }
        });

        Self {
            agent_id,
            token: shutdown,
            dispatch,
            up_tx,
        }
    }

    /// Body of the termination contract: clears both dispatch tables with counts (idempotent).
    ///
    /// Shared by [`Self::shutdown`] (external cause: the consumer's teardown
    /// sequence) and poll-loop exit (internal cause: connection death /
    /// watchdog).
    async fn release_all_streams(dispatch: &TunnelDispatch) {
        let req = dispatch.close_all_request_streams().await;
        let resp = dispatch.close_all_response_streams().await;
        if req + resp > 0 {
            metrics::counter!("interflow_agent_session_teardown_streams_killed_total")
                .increment(u64::try_from(req + resp).unwrap_or(u64::MAX));
            info!(
                "h2 tunnel teardown: released {req} request-direction / {resp} response-direction stranded streams \
                 (channel closed -> consumers exit in place)"
            );
        }
    }

    /// Writes one complete frame into the uplink channel (control-frame path: Open/Close etc., no large payload).
    async fn send_frame(
        &self,
        frame_type: FrameType,
        flags: u8,
        stream_id: &str,
        source: &str,
        payload: &[u8],
    ) -> Result<()> {
        let mut buf = BytesMut::with_capacity(64 + payload.len());
        wire::encode_frame(frame_type, flags, stream_id, source, payload, &mut buf).ok_or_else(
            || {
                InterflowError::stream(
                    "frame encoding failed (field length limit exceeded)".to_string(),
                )
            },
        )?;
        self.send_up_bytes(buf.freeze()).await
    }

    /// Data-frame path: header and payload go in as two separate body chunks, with the payload `Bytes`
    /// reaching the h2 DATA frame zero-copy (the same shape as the hub-side
    /// `RxStream` downlink). The two enqueues complete under the same
    /// `up_tx` lock, guaranteeing frame boundaries are not interleaved by
    /// concurrent senders.
    async fn send_data_frame(&self, stream_id: &str, source: &str, data: Bytes) -> Result<()> {
        let mut header = BytesMut::with_capacity(64 + stream_id.len() + source.len());
        wire::encode_frame_header(
            FrameType::Data,
            0,
            stream_id,
            source,
            data.len(),
            &mut header,
        )
        .ok_or_else(|| {
            InterflowError::stream(
                "frame encoding failed (field length limit exceeded)".to_string(),
            )
        })?;
        let tx = self.up_tx.lock().await;
        if let Err(e) = tx.send(header.freeze()).await {
            return Err(Self::up_closed(e));
        }
        tx.send(data).await.map_err(Self::up_closed)
    }

    async fn send_up_bytes(&self, bytes: Bytes) -> Result<()> {
        let tx = self.up_tx.lock().await;
        tx.send(bytes).await.map_err(Self::up_closed)
    }

    fn up_closed(_: mpsc::error::SendError<Bytes>) -> InterflowError {
        InterflowError::connection(
            "upload stream unavailable (rebuilding or disconnected)".to_string(),
        )
    }

    /// The uplink long loop (mirror of `run_poll_loop`).
    ///
    /// Each round: obtain a frame channel (the first round reuses the
    /// pre-built channel from construction, later rounds create a new one and
    /// swap it in) → send the streaming `POST /stream/up` → await 200
    /// (non-2xx backs off and retries; 409 = an active upload already exists
    /// for this identity) → hang on the response body waiting for the death
    /// signal. When the response body ends (hub removal / preemption /
    /// disconnect), rebuild immediately — the hub-side `/stream/up` implicit
    /// re-registration covers the removal case, fully symmetric with `/poll`.
    ///
    /// Runs under the session death contract: exiting for any reason (this
    /// loop's own `break`s were already session-ending events) ends the
    /// session. `beat` + `stall_timeout` implement the stall heartbeat —
    /// every long wait below beats through [`Beat::during`], so a wedged
    /// (never-progressing) loop is caught even though its channel stays
    /// open and sends keep buffering as fake successes.
    #[allow(clippy::too_many_arguments)]
    async fn run_upload_loop(
        sender: Arc<Mutex<SendRequest<H2RequestBody>>>,
        agent_id: String,
        hub_url: String,
        up_tx_slot: Arc<Mutex<mpsc::Sender<Bytes>>>,
        shutdown: CancellationToken,
        mut first_rx: Option<mpsc::Receiver<Bytes>>,
        establish_timeout: Duration,
        stall_timeout: Duration,
        beat: Beat,
    ) {
        const BASE_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_INTERVAL: Duration = Duration::from_secs(5);
        let beat_every = beat_interval(stall_timeout);
        let mut consecutive_failures = 0u32;

        loop {
            beat.beat();
            // The first round reuses the channel pre-built at construction
            // (its tx is already in the slot; sends earlier than the 200
            // buffer there); every later round creates a new channel and
            // swaps it in only after success — on the failure path the tx is
            // dropped, the channel seals, and senders fail fast instead of
            // falling into a black hole.
            let (pending_tx, rx) = if let Some(rx) = first_rx.take() {
                (None, rx)
            } else {
                let (tx, rx) = mpsc::channel(UPLOAD_CHANNEL_CAP);
                (Some(tx), rx)
            };
            let body = StreamBody::new(ChunkHygiene::new(upload_body_stream(rx))).boxed();

            let builder = Request::builder()
                .method("POST")
                .uri(format!("{hub_url}/stream/up"))
                .header("x-agent-id", &agent_id);
            let req = match builder.body(body) {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to build upload request: {e}");
                    break;
                }
            };

            // Build the request + send future within the same scope; the lock is released as soon as the future is extracted
            let resp_result = {
                let mut sender_locked = sender.lock().await;
                let ready = tokio::select! {
                    () = shutdown.cancelled() => break,
                    r = sender_locked.ready() => r,
                };
                if let Err(e) = ready {
                    error!("hub connection lost (upload): {e}");
                    break;
                }
                sender_locked.send_request(req)
            };

            // Send-establishment bound (the upload-side mirror of the poll
            // receive watchdog): the future raced only against shutdown
            // before, so a request that never resolves (hyper SendRequest
            // hang edge states after connection death included) parked this
            // loop forever. Healthy hubs answer headers immediately, so
            // exceeding the bound is a dead request path — cancel the
            // session token and let the supervisor rebuild.
            let resp = tokio::select! {
                () = shutdown.cancelled() => break,
                r = beat.during(beat_every, tokio::time::timeout(establish_timeout, resp_result)) => {
                    let Ok(resp) = r else {
                        metrics::counter!("interflow_agent_tunnel_establish_timeout_total", "stream" => "upload").increment(1);
                        warn!(
                            "upload stream request not answered within {establish_timeout:?} \
                             (no response headers), treating as connection death, rebuilding session"
                        );
                        shutdown.cancel();
                        break;
                    };
                    resp
                }
            };
            let resp = match resp {
                Ok(r) if r.status().is_success() => r,
                Ok(r) => {
                    warn!("upload stream request rejected: {}", r.status());
                    consecutive_failures += 1;
                    Self::upload_backoff(
                        &shutdown,
                        BASE_INTERVAL,
                        MAX_INTERVAL,
                        consecutive_failures,
                        &beat,
                        beat_every,
                    )
                    .await;
                    continue;
                }
                Err(e) => {
                    error!("upload stream send failed: {e}");
                    consecutive_failures += 1;
                    Self::upload_backoff(
                        &shutdown,
                        BASE_INTERVAL,
                        MAX_INTERVAL,
                        consecutive_failures,
                        &beat,
                        beat_every,
                    )
                    .await;
                    continue;
                }
            };

            // 200: swap in this round's channel; the pump's send path recovers
            if let Some(tx) = pending_tx {
                *up_tx_slot.lock().await = tx;
            }
            if consecutive_failures > 0 {
                info!("upload stream rebuilt");
            }
            consecutive_failures = 0;

            // Fault injection: panic right after a round establishes (the
            // upload-task death scenario) or wedge in place (the stall
            // scenario — the channel was just swapped in, so uplink sends
            // buffer as fake successes; only a stall heartbeat catches it).
            crate::fault::trigger(crate::fault::FaultPoint::H2UploadLoopAfterEstablish);
            if crate::fault::stall(crate::fault::FaultPoint::H2UploadLoopStall) {
                std::future::pending::<()>().await;
            }

            // Response body ending = upload death signal (under normal
            // conditions this body never yields data frames; it only carries
            // the "alive" semantics; the hub ending it declares this upload
            // terminated)
            let mut body = resp.into_body();
            loop {
                let frame_res = tokio::select! {
                    () = shutdown.cancelled() => break,
                    f = beat.during(beat_every, body.frame()) => f,
                };
                match frame_res {
                    None | Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            if shutdown.is_cancelled() {
                break;
            }
            // Seal the channel immediately: sends in the death gap fail fast
            // (the pump tears the stream down, TCP semantics); recovery comes
            // when the next round establishes a new channel
            {
                let (dead_tx, dead_rx) = mpsc::channel(1);
                drop(dead_rx);
                *up_tx_slot.lock().await = dead_tx;
            }
            info!("upload stream ended, rebuilding immediately");
        }
        debug!("upload task finished");
    }

    /// Uplink retry backoff (failure count is incremented by the caller; mirrors the poll loop's backoff discipline).
    /// Beats throughout — a backoff sleep is progress, not a stall.
    async fn upload_backoff(
        shutdown: &CancellationToken,
        base: Duration,
        max: Duration,
        consecutive_failures: u32,
        beat: &Beat,
        beat_every: Duration,
    ) {
        // Cancellation is not a retry: a Stop observed before the backoff
        // would log an orphan "retrying upload stream…" line for a sleep the
        // select then immediately abandons (the poll-loop mirror of this is
        // `PollOutcome::Cancelled`). The caller's next await observes the
        // token and exits.
        if shutdown.is_cancelled() {
            return;
        }
        let backoff_ms = compute_backoff_ms(base, consecutive_failures);
        let interval = max.min(Duration::from_millis(backoff_ms));
        warn!("retrying upload stream in {interval:?}...");
        tokio::select! {
            () = shutdown.cancelled() => {},
            () = beat.during(beat_every, tokio::time::sleep(interval)) => {}
        }
    }

    /// Starts the background polling task to receive data
    #[allow(clippy::too_many_arguments)]
    async fn run_poll_loop(
        sender: Arc<Mutex<SendRequest<H2RequestBody>>>,
        agent_id: String,
        hub_url: String,
        dispatch: &TunnelDispatch,
        shutdown: CancellationToken,
        up_tx: Arc<Mutex<mpsc::Sender<Bytes>>>,
        liveness: H2Liveness,
        tasks: SessionTasks,
        stall_timeout: Duration,
        beat: Beat,
    ) {
        const BASE_INTERVAL: Duration = Duration::from_millis(100);
        const MAX_INTERVAL: Duration = Duration::from_secs(5);
        let beat_every = beat_interval(stall_timeout);
        let mut consecutive_failures = 0;
        let mut buffer = BytesMut::with_capacity(8192);

        loop {
            beat.beat();
            // Build the request + send future within the same scope; the sender lock is released as soon as the send future is extracted.
            let resp_result = {
                let mut sender_locked = sender.lock().await;
                let ready = tokio::select! {
                    () = shutdown.cancelled() => break,
                    r = sender_locked.ready() => r,
                };
                if let Err(e) = ready {
                    error!("hub connection lost: {}", e);
                    break;
                }
                match Self::build_poll_request(&agent_id, &hub_url) {
                    Ok(req) => Ok(sender_locked.send_request(req)),
                    Err(e) => {
                        error!("failed to prepare request: {}", e);
                        Err(())
                    }
                }
            };

            let outcome = match resp_result {
                Ok(fut) => {
                    // Send-establishment bound: same rationale as the upload
                    // loop's — the receive-side watchdog only starts once
                    // headers arrive, so a poll request that never resolves
                    // is invisible to it. Exceeding the bound cancels the
                    // session token (supervisor rebuild / direct-dialer
                    // fail-fast).
                    let resp = tokio::select! {
                        () = shutdown.cancelled() => break,
                        r = beat.during(beat_every, tokio::time::timeout(liveness.establish_timeout, fut)) => {
                            let Ok(resp) = r else {
                                metrics::counter!("interflow_agent_tunnel_establish_timeout_total", "stream" => "poll").increment(1);
                                warn!(
                                    "poll stream request not answered within {:?} \
                                     (no response headers), treating as connection death, rebuilding session",
                                    liveness.establish_timeout
                                );
                                shutdown.cancel();
                                break;
                            };
                            resp
                        }
                    };
                    Self::drain_poll_response(
                        resp,
                        &agent_id,
                        &mut buffer,
                        dispatch,
                        &up_tx,
                        liveness,
                        &shutdown,
                        &tasks,
                        &beat,
                        beat_every,
                    )
                    .await
                }
                // Request construction failed: treat as one failure and continue the backoff loop
                Err(()) => PollOutcome::Failed,
            };

            match outcome {
                PollOutcome::Cancelled => break,
                PollOutcome::Drained => consecutive_failures = 0,
                PollOutcome::Failed => consecutive_failures += 1,
            }

            let backoff_ms = compute_backoff_ms(BASE_INTERVAL, consecutive_failures);
            let current_interval = MAX_INTERVAL.min(Duration::from_millis(backoff_ms));
            if consecutive_failures > 0 {
                info!("retrying connection in {:?}...", current_interval);
            }
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = beat.during(beat_every, tokio::time::sleep(current_interval)) => {}
            }
        }
    }

    /// Builds the `/poll` request (without the sender; the caller sends it).
    fn build_poll_request(agent_id: &str, hub_url: &str) -> Result<Request<H2RequestBody>> {
        let builder = Request::builder()
            .method("GET")
            .uri(format!("{hub_url}/poll"))
            .header("x-agent-id", agent_id);
        builder
            .body(empty_request_body())
            .map_err(|e| InterflowError::connection(format!("failed to build request: {e}")))
    }

    /// Handles the `/poll` response: the outcome classifies how the round
    /// ended for the caller's retry accounting (see [`PollOutcome`]).
    ///
    /// Hub heartbeat Ping frames are intercepted and answered here (in a
    /// separate task, not blocking the read loop) instead of entering business
    /// dispatch — every tunnel consumer (mesh agent, expose edge)
    /// automatically gains heartbeat-answering capability.
    ///
    /// Data-plane liveness (root-cured on 2026-09-13):
    /// - **Pong rides the uplink stream**: the answer itself
    ///   proves the agent→hub data path;
    /// - **Poll receive-side watchdog**: a successful write on the hub side ≠
    ///   receipt by the peer (kernel/proxy buffers absorb writes); a stall in
    ///   the hub→agent direction can only be detected at the receiving end —
    ///   receiving no frames at all (including Pings) for a consecutive
    ///   `liveness.poll_watchdog` cancels the session and rebuilds it.
    #[allow(clippy::too_many_arguments)]
    async fn drain_poll_response(
        resp_result: hyper::Result<hyper::Response<hyper::body::Incoming>>,
        agent_id: &str,
        buffer: &mut BytesMut,
        dispatch: &TunnelDispatch,
        up_tx: &Arc<Mutex<mpsc::Sender<Bytes>>>,
        liveness: H2Liveness,
        shutdown: &CancellationToken,
        tasks: &SessionTasks,
        beat: &Beat,
        beat_every: Duration,
    ) -> PollOutcome {
        let resp = match resp_result {
            Ok(r) => r,
            Err(e) => {
                error!("failed to send poll request: {}", e);
                return PollOutcome::Failed;
            }
        };
        if resp.status() != StatusCode::OK {
            tracing::warn!("poll request rejected: {}", resp.status());
            return PollOutcome::Failed;
        }
        info!("connected to hub streaming endpoint");
        // Fault injection: panic right after the poll stream connects (the
        // poll-task death scenario — with it dies the in-task receive
        // watchdog).
        crate::fault::trigger(crate::fault::FaultPoint::H2PollLoopAfterConnect);
        let mut body = resp.into_body();
        loop {
            // The watchdog resets only on "any frame": heartbeat Pings
            // guarantee a healthy poll stream has at least one frame per
            // interval; long total silence can only be a stall.
            let frame_res = if liveness.poll_watchdog.is_zero() {
                tokio::select! {
                    () = shutdown.cancelled() => return PollOutcome::Cancelled,
                    f = beat.during(beat_every, body.frame()) => f,
                }
            } else {
                tokio::select! {
                    () = shutdown.cancelled() => return PollOutcome::Cancelled,
                    r = beat.during(beat_every, tokio::time::timeout(liveness.poll_watchdog, body.frame())) => {
                        let Ok(f) = r else {
                            warn!(
                                "poll stream {:?} received no frames (including heartbeat Ping), \
                                 data-plane stall detected, rebuilding session",
                                liveness.poll_watchdog
                            );
                            // Same-node clone of the session token: cancelling
                            // it terminates the whole session; the supervisor
                            // follows the existing backoff reconnect path
                            shutdown.cancel();
                            return PollOutcome::Failed;
                        };
                        f
                    }
                }
            };
            let Some(frame_res) = frame_res else { break };
            match frame_res {
                Ok(frame) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    buffer.extend_from_slice(&data);
                    while let Some(tunnel_data) = TunnelDispatch::decode_tunnel_data(buffer) {
                        if tunnel_data.stream_type == FrameType::Ping {
                            Self::spawn_pong(tasks, agent_id, up_tx);
                            continue;
                        }
                        dispatch.dispatch(tunnel_data).await;
                    }
                }
                Err(e) => {
                    error!("failed to read stream data: {}", e);
                    break;
                }
            }
        }
        info!("hub stream disconnected, preparing to reconnect");
        buffer.clear();
        PollOutcome::Drained
    }

    /// Answers a hub heartbeat Ping with a Pong frame over the uplink data
    /// stream (proving the agent→hub data path). Runs as a separate task: a
    /// blocking `send` on a full uplink channel must not stall the poll read
    /// loop — a full channel is itself an uplink outage, and the hub will
    /// age the session out via `last_pong`, which is semantically correct.
    fn spawn_pong(tasks: &SessionTasks, agent_id: &str, up_tx: &Arc<Mutex<mpsc::Sender<Bytes>>>) {
        let agent_id = agent_id.to_string();
        let up_tx = up_tx.clone();
        tasks.spawn_auxiliary(async move {
            let mut buf = BytesMut::with_capacity(64 + agent_id.len());
            if wire::encode_frame(FrameType::Pong, 0, "", &agent_id, &[], &mut buf).is_none() {
                return;
            }
            let sent = {
                let tx = up_tx.lock().await;
                tx.send(buf.freeze()).await.is_ok()
            };
            if !sent {
                debug!("upstream Pong send failed (upload rebuilding)");
            }
        });
    }
}

/// `mpsc::Receiver<Bytes>` → hyper body stream adapter.
///
/// Each `Bytes` is yielded as one DATA chunk; frame boundaries are
/// guaranteed by the caller (header and payload are enqueued adjacently, see
/// [`H2Tunnel::send_data_frame`]). The caller wraps this in
/// [`ChunkHygiene`], which may coalesce adjacent chunks into one larger DATA
/// frame — harmless: the hub-side reader accumulates body bytes and decodes
/// frames incrementally, so DATA frame boundaries carry no semantics.
fn upload_body_stream(
    mut rx: mpsc::Receiver<Bytes>,
) -> impl futures::Stream<Item = std::result::Result<Frame<Bytes>, InterflowError>> {
    futures::stream::poll_fn(
        move |cx: &mut Context<'_>| -> Poll<Option<std::result::Result<Frame<Bytes>, InterflowError>>> {
            rx.poll_recv(cx)
                .map(|item| item.map(|bytes| Ok(Frame::data(bytes))))
        },
    )
}

#[async_trait]
impl TunnelTransport for H2Tunnel {
    async fn send_open_with(
        &self,
        stream_id: &str,
        target_agent: &str,
        target_addr: Option<&str>,
        proto: StreamProto,
        e2e: bool,
    ) -> Result<()> {
        // Open frame payload: "{target_agent}:{target_addr}" (same encoding
        // as the QUIC backend; the hub parses it with split_once(':'); the
        // agent id charset contains no colon).
        let payload = format!("{target_agent}:{}", target_addr.unwrap_or(""));
        let flags = proto.as_flag() | if e2e { crate::protocol::FLAG_E2E } else { 0 };
        self.send_frame(
            FrameType::Open,
            flags,
            stream_id,
            &self.agent_id,
            payload.as_bytes(),
        )
        .await
    }

    async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()> {
        self.send_data_frame(stream_id, &self.agent_id, data).await
    }

    async fn send_data_response(&self, stream_id: &str, data: Bytes) -> Result<()> {
        self.send_data_frame(stream_id, RESPONSE_SOURCE, data).await
    }

    async fn send_close(&self, stream_id: &str) -> Result<()> {
        self.send_frame(FrameType::Close, 0, stream_id, &self.agent_id, b"")
            .await
    }

    async fn send_close_response(&self, stream_id: &str, reason: &str) -> Result<()> {
        self.send_frame(
            FrameType::Close,
            0,
            stream_id,
            RESPONSE_SOURCE,
            reason.as_bytes(),
        )
        .await
    }

    async fn register_stream(&self, stream_id: String) -> tokio::sync::mpsc::Receiver<TunnelData> {
        self.dispatch.register_stream(stream_id).await
    }

    async fn unregister_stream(&self, stream_id: &str) {
        self.dispatch.unregister_stream(stream_id).await;
    }

    async fn take_incoming_streams(
        &self,
    ) -> Option<tokio::sync::mpsc::Receiver<crate::tunnel::transport::IncomingStream>> {
        self.dispatch.take_incoming_streams()
    }

    async fn unregister_incoming_stream(&self, stream_id: &str) {
        self.dispatch.unregister_incoming_stream(stream_id).await;
    }

    /// Termination contract (external-cause channel): called explicitly by the consumer's teardown sequence.
    ///
    /// Cancel the session token (stopping poll/upload) → clear both dispatch
    /// tables (leftover consumers exit in place, backend fds released) →
    /// seal the uplink channel (read tasks stuck in `send_data_response`
    /// fail fast instead of hanging). Idempotent; coexists with the
    /// internal-cause table cleanup on poll exit.
    async fn shutdown(&self) {
        self.token.cancel();
        Self::release_all_streams(&self.dispatch).await;
        // Seal the uplink channel: sends in the death gap fail fast (same
        // sealing semantics as the upload rebuild gap), preventing the
        // close-out path from hanging on a send to a full channel.
        {
            let (dead_tx, dead_rx) = mpsc::channel(1);
            drop(dead_rx);
            *self.up_tx.lock().await = dead_tx;
        }
    }
}

/// Exponential backoff: BASE * 2^failures, failures clamped at 6 (i.e. at most 64×). Returns milliseconds.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn compute_backoff_ms(base: Duration, failures: u32) -> u64 {
    base.as_millis() as u64 * 2_u64.pow(failures.min(6))
}

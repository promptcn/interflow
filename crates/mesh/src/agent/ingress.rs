use crate::agent::control::{ControlOpError, IngressCommand};
use crate::agent::ingress_addrs::IngressAddrs;
use crate::agent::ingress_listeners::IngressListeners;
use crate::agent::reconcile_report::ReconcileReport;
use crate::agent::rules::RuleStore;
use crate::config::IngressRule;
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::{CloseReason, StreamProto};
use interflow_core::tunnel::AgentTunnel;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

/// Tolerance for a stalled client-response write: a single-frame write
/// timeout (client not reading -> send buffer full) closes the connection.
/// Pairs with response-direction dispatch poisoning (channel full for 5s
/// closes it) — without this upper bound the write task would hang forever
/// in `write_all`, and the poison signal (channel closed) would never be
/// consumed.
// Single-sourced with the expose edge listener (core transport profile).
const CLIENT_WRITE_STALL_TIMEOUT: Duration =
    interflow_core::config::params::DEFAULT_CLIENT_WRITE_STALL_TIMEOUT;

/// Global concurrent-connection cap per ingress rule. Combined with
/// ulimit -n, guards against a connection flood exhausting the scheduler
/// and file descriptors.
const MAX_CONCURRENT_CONNECTIONS: usize = 4096;

/// Catch-all reconcile cadence. Store-change notifications drive normal
/// convergence; the tick is the level-triggered safety net that retries
/// failed binds and heals any state a missed trigger could have left
/// behind.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(15);

/// The rule a bound listener is serving — the actual-state cell. A
/// param-level policy change writes this in place; the accept loops read
/// it per connection/datagram, so new traffic picks up new idle budgets
/// and targets without the socket ever being touched.
pub(crate) type ServingRule = Arc<std::sync::RwLock<IngressRule>>;

fn read_serving(cell: &ServingRule) -> std::sync::RwLockReadGuard<'_, IngressRule> {
    cell.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_serving(cell: &ServingRule, rule: IngressRule) {
    *cell
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = rule;
}

/// Listener identity: the fields that define the socket itself. Everything
/// else in [`IngressRule`] is a live parameter served from the cell.
const fn identity(rule: &IngressRule) -> (SocketAddr, StreamProto) {
    (rule.listen_addr, rule.listen_protocol)
}

/// What one desired-vs-actual comparison asks the reconciler to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileAction {
    /// The bound listener serves exactly the desired rule — nothing to do.
    NoChange,
    /// Socket identity unchanged: swap the serving rule in place; the
    /// listener is never touched (no rebind, no race, no hole).
    UpdateParams,
    /// Identity changed: bind the new listener first, then stop the old.
    Replace,
}

/// The reconcile decision for one rule. The whole-struct equality first
/// arm is the fast path; the identity split below it is the 2026-10-07
/// fix — before it, a connection-level knob change (`idle_timeout_secs`)
/// was classified as a full replace, and the replace's close-then-rebind
/// order could lose the listener silently.
fn classify(current: &IngressRule, desired: &IngressRule) -> ReconcileAction {
    if current == desired {
        ReconcileAction::NoChange
    } else if identity(current) == identity(desired) {
        ReconcileAction::UpdateParams
    } else {
        ReconcileAction::Replace
    }
}

/// Abort a listener task and reap it, so its socket is deterministically
/// released before the call returns (`AbortHandle` alone cannot offer
/// this — the release timing was the rebind race).
async fn stop_and_reap(handle: tokio::task::JoinHandle<()>) {
    handle.abort();
    let _ = handle.await;
}

/// Listener teardown bookkeeping. Carries the log attribution so even the
/// Drop path (session teardown) emits node-attributed lines — the steady
/// state must never regress to bare lines (the 2026-10-09 bug shape).
struct ListenerGuard {
    node: String,
    handles: HashMap<String, tokio::task::JoinHandle<()>>,
}

impl Drop for ListenerGuard {
    fn drop(&mut self) {
        for (name, handle) in &self.handles {
            info!(node = %self.node, "Stopping ingress listener (cleanup): {}", name);
            handle.abort();
        }
    }
}

pub struct IngressHandler {
    agent_id: String,
    /// Log attribution (`AgentInfo::effective_log_name`): every line the
    /// handler and its spawned listeners/pumps emit carries it, so the GUI
    /// "This node" view filters by node.
    node: String,
    tunnel: AgentTunnel,
    /// Cross-session rule truth — the DESIRED state and the only input
    /// reconcile reads (level-triggered: never a pushed snapshot).
    store: Arc<RuleStore>,
    /// Session token: the lifecycle anchor of listeners and per-connection
    /// pumps — session end (watchdog/disconnect/shutdown) exits them all,
    /// and client sockets release with the task (no longer relying on the
    /// idle timeout to die).
    session: CancellationToken,
    /// Session-level task tracker: listeners and per-connection pumps hang
    /// off it and close out boundedly in the teardown sequence.
    tracker: TaskTracker,
    command_rx: Option<mpsc::Receiver<IngressCommand>>,
    guard: ListenerGuard,
    /// The serving-rule cell of each currently-bound listener (the
    /// ACTUAL state; keys are kept in lockstep with `guard`).
    bound: HashMap<String, ServingRule>,
    /// Agent-scoped table of actually-bound listener addresses: a `:0` port
    /// materializes here at bind and the next session rebuild re-binds the
    /// same concrete address (port pinning — see [`IngressAddrs`]).
    addrs: Arc<IngressAddrs>,
    /// Agent-scoped listener health face: bound addresses and bind errors,
    /// observable from the [`AgentHandle`](crate::agent::AgentHandle).
    listeners: Arc<IngressListeners>,
    /// Mandatory inner-TLS runtime.
    e2e: Arc<crate::agent::e2e::E2eRuntime>,
    /// Readiness signal: set once a session has bound every rule in its
    /// startup snapshot without error. This is the agent's local-serving
    /// face — the condition `node install` used to fake with TCP probes
    /// (and what a `Type=notify` unit's READY=1 now waits on).
    ingress_ready: tokio::sync::watch::Sender<bool>,
}

impl IngressHandler {
    #[allow(clippy::too_many_arguments)] // session wiring handles are passed explicitly one by one
    pub fn new_with_tunnel(
        agent_id: String,
        log_name: String,
        tunnel: AgentTunnel,
        store: Arc<RuleStore>,
        session: CancellationToken,
        tracker: TaskTracker,
        command_rx: Option<mpsc::Receiver<IngressCommand>>,
        addrs: Arc<IngressAddrs>,
        listeners: Arc<IngressListeners>,
        e2e: Arc<crate::agent::e2e::E2eRuntime>,
        ingress_ready: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self {
            agent_id,
            guard: ListenerGuard {
                node: log_name.clone(),
                handles: HashMap::new(),
            },
            node: log_name,
            tunnel,
            store,
            session,
            tracker,
            command_rx,
            bound: HashMap::new(),
            addrs,
            listeners,
            e2e,
            ingress_ready,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!(node = %self.node, "Ingress handler started, agent_id={}", self.agent_id);

        // Level-triggered from the first instant: bind whatever the store
        // says; readiness is decided by this pass.
        let failed = self.reconcile().await;
        if failed == 0 {
            // Idempotent across session rebuilds: the watch keeps the
            // latest value, and readiness only ever turns on.
            let _ = self.ingress_ready.send(true);
        }

        // Reconcile triggers, level-triggered: rule-store changes (policy
        // reload, control API), a periodic catch-all tick (retries failed
        // binds, heals anything a missed wake-up could leave behind), and
        // the command channel (Add/Remove/List + session teardown).
        let mut version = self.store.version_rx();
        let mut tick = tokio::time::interval(RECONCILE_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut commands = self.command_rx.take();
        loop {
            let next_command = async {
                match commands.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                cmd = next_command => match cmd {
                    Some(IngressCommand::Add(rule, resp_tx)) => {
                        let _ = resp_tx.send(self.handle_add(rule).await);
                    }
                    Some(IngressCommand::Remove(name, resp_tx)) => {
                        let _ = resp_tx.send(self.handle_remove(&name).await);
                    }
                    Some(IngressCommand::List(resp_tx)) => {
                        let views = self.store.ingress_views().await;
                        info!(node = %self.node, "Handled List command, returning {} rules", views.len());
                        let _ = resp_tx.send(views);
                    }
                    None => break, // senders dropped (session teardown)
                },
                changed = version.changed() => {
                    if changed.is_ok() {
                        self.reconcile().await;
                    }
                }
                _ = tick.tick() => {
                    self.reconcile().await;
                }
            }
        }

        Ok(())
    }

    /// Drive the bound listener set toward the store's rule table. Pure
    /// level-triggered control: every invocation re-derives the whole
    /// diff, so a missed trigger only delays convergence to the next tick
    /// — the store, not a message, is the desired-state truth.
    ///
    /// Ordering rules that make a reconcile never lose a healthy listener:
    /// - param-level change: the serving cell is swapped in place; the
    ///   socket is not touched at all;
    /// - identity change: the new listener is bound BEFORE the old one
    ///   stops (their addresses/protocols differ, so the binds cannot
    ///   conflict), and the old task is reaped deterministically;
    /// - a failed bind leaves the previous listener serving and is retried
    ///   on the next reconcile — there is never a hole.
    ///
    /// Returns the number of rules that want a listener but do not have
    /// one (bind failures pending retry).
    async fn reconcile(&mut self) -> usize {
        let desired = self.store.ingress_snapshot().await;
        let mut report = ReconcileReport::new();

        // Stop listeners whose rule is gone from the desired face.
        let names: Vec<String> = self.bound.keys().cloned().collect();
        for name in names {
            if desired.iter().any(|r| r.name == name) {
                continue;
            }
            if let Some(handle) = self.guard.handles.remove(&name) {
                info!(node = %self.node, "Rule gone, stopping ingress listener: {name}");
                stop_and_reap(handle).await;
            }
            self.addrs.remove(&name);
            self.bound.remove(&name);
            self.listeners.remove(&name);
            metrics::gauge!("interflow_agent_ingress_listener_bound", "rule" => name.clone())
                .set(0.0);
            report.record_removed();
        }

        // Drive every desired rule to its listener.
        for rule in desired {
            let name = rule.name.clone();
            let actual = self
                .bound
                .get(&name)
                .map(|cell| (Arc::clone(cell), classify(&read_serving(cell), &rule)));
            match actual {
                Some((_, ReconcileAction::NoChange)) => {}
                Some((cell, ReconcileAction::UpdateParams)) => {
                    // Socket identity unchanged: hot-swap the serving rule;
                    // the next accepted connection/datagram reads the new
                    // params. The listener is never touched.
                    write_serving(&cell, rule);
                    if let Some(addr) = self.addrs.get(&name) {
                        self.listeners.set_bound(&name, addr);
                    }
                    report.record_changed();
                    info!(node = %self.node, "Policy change hot-applied to ingress listener params: {name}");
                }
                _ => {
                    // New rule, or identity change: bind first, stop old
                    // only after the new listener is up.
                    let old = self.guard.handles.remove(&name);
                    match self.start_listener(rule).await {
                        Ok(()) => {
                            if let Some(handle) = old {
                                info!(node = %self.node, "Identity change, replacing ingress listener: {name}");
                                stop_and_reap(handle).await;
                                report.record_changed();
                            } else {
                                report.record_added();
                            }
                        }
                        Err(e) => {
                            // The new bind failed: the previous listener
                            // keeps serving (its guard/bound entries are
                            // restored) and the next reconcile retries. A
                            // replace must never trade a working listener
                            // for a hole.
                            error!(
                                node = %self.node,
                                "Ingress listener bind for {name} failed ({e}); \
                                 keeping the previous listener serving, retry scheduled"
                            );
                            if let Some(handle) = old {
                                self.guard.handles.insert(name.clone(), handle);
                            }
                            self.listeners.set_failed(&name, e.to_string());
                            metrics::counter!(
                                "interflow_agent_ingress_listener_bind_failures_total",
                                "rule" => name.clone(),
                            )
                            .increment(1);
                            report.record_failed();
                        }
                    }
                }
            }
        }
        // Transitions → info, steady-state sample → debug: the module
        // policy lives in ReconcileReport, machine-locked by its tests.
        report.log(&self.node, "Ingress");
        report.failed()
    }

    /// Add (or replace by name): the store is the desired truth and the
    /// reconcile applies it; Ok acknowledges the rule is in effect (the
    /// listener is bound and serving exactly this rule).
    async fn handle_add(&mut self, rule: IngressRule) -> std::result::Result<(), ControlOpError> {
        let name = rule.name.clone();
        if !rule.listen_addr.ip().is_loopback() {
            return Err(ControlOpError::Apply(format!(
                "ingress {name} rejected: listen_addr must be loopback"
            )));
        }
        self.store
            .add_ingress(rule.clone())
            .await
            .map_err(ControlOpError::from)?;
        self.reconcile().await;
        let serving = self
            .bound
            .get(&name)
            .is_some_and(|cell| *read_serving(cell) == rule);
        if serving {
            Ok(())
        } else {
            let reason = self
                .listeners
                .get(&name)
                .and_then(|status| status.last_error)
                .unwrap_or_else(|| "listener did not come up".to_string());
            Err(ControlOpError::Apply(format!(
                "failed to start listener: {reason}"
            )))
        }
    }

    /// Remove: the store decides existence (NotFound comes from the rule
    /// truth); the reconcile stops the listener.
    async fn handle_remove(&mut self, name: &str) -> std::result::Result<(), ControlOpError> {
        self.store
            .remove_ingress(name)
            .await
            .map_err(ControlOpError::from)?;
        self.reconcile().await;
        Ok(())
    }

    /// The address a rule's listener should bind: a `:0` config with a
    /// previously-bound address pins to that concrete address so the port is
    /// stable across session rebuilds; anything else binds as configured.
    fn bind_target(&self, rule: &IngressRule) -> SocketAddr {
        if rule.listen_addr.port() == 0
            && let Some(pinned) = self.addrs.get(&rule.name)
        {
            return pinned;
        }
        rule.listen_addr
    }

    async fn start_listener(&mut self, rule: IngressRule) -> Result<()> {
        if !rule.listen_addr.ip().is_loopback() {
            return Err(InterflowError::config(format!(
                "ingress {} listen_addr must be loopback",
                rule.name
            )));
        }
        let name = rule.name.clone();
        let cell: ServingRule = Arc::new(std::sync::RwLock::new(rule));
        let protocol = read_serving(&cell).listen_protocol;
        match protocol {
            StreamProto::Tcp => self.start_tcp_listener(Arc::clone(&cell)).await?,
            StreamProto::Udp => self.start_udp_listener(Arc::clone(&cell))?,
        }
        self.bound.insert(name, cell);
        Ok(())
    }

    fn start_udp_listener(&mut self, cell: ServingRule) -> Result<()> {
        let rule = read_serving(&cell).clone();
        info!(
            node = %self.node,
            "Starting ingress (UDP) listener: {} -> {}",
            rule.listen_addr, rule.target_agent
        );

        let target = self.bind_target(&rule);
        let socket = match crate::agent::ingress_udp::bind_udp_socket(target) {
            Ok(s) => s,
            // A pinned `:0` rebind can find the address taken (another
            // process grabbed it between sessions) — fall back to the
            // configured address and let the fresh bind re-record.
            Err(e) if target != rule.listen_addr => {
                warn!(
                    node = %self.node,
                    "pinned ingress addr rebind failed ({e}); falling back to {}",
                    rule.listen_addr
                );
                crate::agent::ingress_udp::bind_udp_socket(rule.listen_addr)
                    .map_err(InterflowError::Io)?
            }
            Err(e) => return Err(InterflowError::Io(e)),
        };
        let actual = socket.local_addr().map_err(InterflowError::Io)?;
        self.addrs.set(&rule.name, actual);
        self.listeners.set_bound(&rule.name, actual);
        metrics::gauge!("interflow_agent_ingress_listener_bound", "rule" => rule.name.clone())
            .set(1.0);
        info!(
            node = %self.node,
            "Ingress (UDP) listener bound: {} -> {}",
            actual, rule.target_agent
        );

        let tunnel = self.tunnel.clone();
        let session = self.session.clone();
        let e2e = Arc::clone(&self.e2e);
        let node = self.node.clone();
        let name = rule.name;
        let handle = self.tracker.spawn(async move {
            // Stop on session end (the socket closes as the task drops)
            tokio::select! {
                () = session.cancelled() => {}
                () = crate::agent::ingress_udp::run_udp_listener(
                    socket,
                    cell,
                    tunnel,
                    e2e,
                    node,
                ) => {}
            }
        });

        self.guard.handles.insert(name, handle);
        Ok(())
    }

    async fn start_tcp_listener(&mut self, cell: ServingRule) -> Result<()> {
        let rule = read_serving(&cell).clone();
        info!(
            node = %self.node,
            "Starting ingress listener: {} -> {}",
            rule.listen_addr, rule.target_agent
        );

        let target = self.bind_target(&rule);
        let listener = match TcpListener::bind(target).await {
            Ok(l) => l,
            // Same pinned-rebind fallback as the UDP path above.
            Err(e) if target != rule.listen_addr => {
                warn!(
                    node = %self.node,
                    "pinned ingress addr rebind failed ({e}); falling back to {}",
                    rule.listen_addr
                );
                TcpListener::bind(rule.listen_addr)
                    .await
                    .map_err(InterflowError::Io)?
            }
            Err(e) => return Err(InterflowError::Io(e)),
        };
        let actual = listener.local_addr().map_err(InterflowError::Io)?;
        self.addrs.set(&rule.name, actual);
        self.listeners.set_bound(&rule.name, actual);
        metrics::gauge!("interflow_agent_ingress_listener_bound", "rule" => rule.name.clone())
            .set(1.0);
        info!(
            node = %self.node,
            "Ingress listener bound: {} -> {}",
            actual, rule.target_agent
        );

        let name = rule.name.clone();
        let agent_id = self.agent_id.clone();
        let tunnel = self.tunnel.clone();
        let session = self.session.clone();
        let conn_tracker = self.tracker.clone();
        let per_conn_tracker = self.tracker.clone();
        let e2e = self.e2e.clone();
        let node = self.node.clone();

        // Global concurrency cap: guards against a connection flood
        // exhausting the scheduler and file descriptors (combined with
        // ulimit -n).
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        let handle = conn_tracker.spawn(async move {
            // Stop accepting on session end; already-accepted connections
            // exit in place via their own child tasks (also hanging off the
            // tracker + holding the token) — the pump future is
            // cancellation-safe (the socket half releases on drop), no
            // longer relying on the 300s idle timeout to die off.
            tokio::select! {
                () = session.cancelled() => {}
                () = async {
                    loop {
                        // Reserve one permit up front so concurrency is
                        // limited before accept
                        let Ok(permit) = sem.clone().acquire_owned().await else {
                            error!(node = %node, "Concurrency-limit semaphore closed");
                            break;
                        };

                        match listener.accept().await {
                            Ok((socket, addr)) => {
                                info!(node = %node, "Connection accepted: {} (rule: {})", addr, name);
                                // TCP_NODELAY: disable Nagle to cut
                                // small-packet latency
                                let _ = socket.set_nodelay(true);
                                let tunnel = tunnel.clone();
                                // The serving rule is read per connection:
                                // a param-level policy change writes the
                                // cell and the next connection serves the
                                // new params without the socket moving.
                                let rule = read_serving(&cell).clone();
                                let agent_id = agent_id.clone();
                                let session = session.clone();
                                let e2e = e2e.clone();
                                let node = node.clone();

                                per_conn_tracker.spawn(async move {
                                    // _permit releases automatically when
                                    // the task ends
                                    let _permit = permit;
                                    tokio::select! {
                                        () = session.cancelled() => {}
                                        r = Self::handle_connection(socket, tunnel, rule, agent_id, e2e, &node) => {
                                            if let Err(e) = r {
                                                error!(node = %node, "Connection handling error: {}", e);
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                error!(node = %node, "Listener accept error: {}", e);
                                drop(permit);
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                } => {}
            }
        });
        self.guard.handles.insert(rule.name, handle);
        Ok(())
    }

    async fn handle_connection(
        socket: tokio::net::TcpStream,
        tunnel: AgentTunnel,
        rule: IngressRule,
        agent_id: String,
        e2e: Arc<crate::agent::e2e::E2eRuntime>,
        node: &str,
    ) -> Result<()> {
        // Stream idle timeout: close the stream when neither direction has
        // data for this long (default tcp 300s, configurable per rule)
        let idle_timeout = rule.effective_idle_timeout();
        let stream_id = interflow_core::protocol::StreamId::random()?;

        let pump_cfg = interflow_core::tunnel::pump::PumpConfig {
            idle_timeout,
            write_stall_timeout: CLIENT_WRITE_STALL_TIMEOUT,
            idle_timeout_counter: "interflow_ingress_stream_idle_timeout",
            write_stall_counter: "interflow_ingress_client_write_stall",
            log_label: "ingress",
        };

        // Mandatory inner TLS: the inner client handshake runs between the
        // Open and the pump; handshake bytes ride ordinary Data frames (the
        // hub only sees ciphertext). A missing runtime or failed handshake
        // closes the stream — there is no plaintext fallback (RFC §3/§4).
        let rt = Arc::clone(&e2e);

        // Register a dedicated channel (avoids a broadcast storm).
        let data_rx = tunnel.register_stream(stream_id).await;
        if let Err(e) = tunnel
            .send_open_with(stream_id, &rule.target_agent, StreamProto::Tcp, true)
            .await
        {
            tunnel.unregister_stream(stream_id).await;
            return Err(e);
        }

        let expected_peer = crate::agent::e2e::bare_agent_id(&rule.target_agent);
        let connector = match rt.client_connector(expected_peer) {
            Ok(c) => c,
            Err(e) => {
                // Startup-assembled material went stale mid-session: fail closed.
                crate::agent::e2e::record_handshake_failure(
                    crate::agent::e2e::SIDE_INGRESS,
                    "protocol",
                );
                warn!(
                    node = %node,
                    "inner TLS connector build failed for {stream_id} -> {expected_peer}: {e}; closing stream"
                );
                tunnel.unregister_stream(stream_id).await;
                return Err(e);
            }
        };

        let adapter =
            interflow_core::tunnel::e2e::E2eTunnelIo::ingress(data_rx, tunnel.clone(), stream_id);
        match interflow_core::tunnel::e2e::inner_tls_connect(
            adapter,
            connector,
            rt.handshake_timeout,
        )
        .await
        {
            interflow_core::tunnel::e2e::E2eHandshakeOutcome::Established(mut tls, _reason) => {
                crate::agent::e2e::record_handshake_ok(crate::agent::e2e::SIDE_INGRESS);
                let selector = rule.remote_addr.clone().map_or(
                    interflow_core::tunnel::TargetSelector::Default,
                    interflow_core::tunnel::TargetSelector::Address,
                );
                let hello = interflow_core::tunnel::InnerStreamHello {
                    source_principal: agent_id.clone(),
                    source_fingerprint: rt.local_fingerprint(),
                    selector,
                    correlation_id: *uuid::Uuid::new_v4().as_bytes(),
                };
                if let Err(e) = hello.write(&mut tls).await {
                    crate::agent::e2e::record_handshake_failure(
                        crate::agent::e2e::SIDE_INGRESS,
                        "protocol",
                    );
                    let _ = tunnel.send_close(stream_id).await;
                    tunnel.unregister_stream(stream_id).await;
                    return Err(e.into());
                }
                let sid = stream_id;
                let t2 = tunnel.clone();
                let outcome = interflow_core::tunnel::pump::pump_duplex(
                    socket,
                    tls,
                    &pump_cfg,
                    CloseReason::CloseFrame,
                    interflow_core::tunnel::pump::DUPLEX_LOCAL_EOF_DRAIN,
                    stream_id,
                    async move {
                        // The TLS close_notify rode Data frames; the stream
                        // Close itself is this side's to send (no-op on the
                        // peer-close-ended path — the hub already reaped it).
                        let _ = t2.send_close(sid).await;
                        t2.unregister_stream(sid).await;
                    },
                )
                .await;
                // The budget cut a silent stream, not a dead peer: say so
                // with the knobs that matter, so the operator's first stop
                // is the manifest, not the journal archaeology.
                if outcome.idle_expired {
                    let budget = idle_timeout.as_secs();
                    info!(
                        node = %node,
                        "mesh ingress stream idle timeout: rule {} closed after {budget}s of \
                         total silence (stream {stream_id}) — for requests that legitimately \
                         stay silent (non-streaming LLM calls with long thinking), raise \
                         `idle_timeout_secs` on this rule in the manifest",
                        rule.name
                    );
                }
                Ok(())
            }
            interflow_core::tunnel::e2e::E2eHandshakeOutcome::Failed { error } => {
                let reason = crate::agent::e2e::failure_reason_of(&error);
                crate::agent::e2e::record_handshake_failure(
                    crate::agent::e2e::SIDE_INGRESS,
                    reason,
                );
                warn!(node = %node, "inner TLS handshake failed ({reason}: {error}), closing stream {stream_id}");
                let _ = tunnel.send_close(stream_id).await;
                tunnel.unregister_stream(stream_id).await;
                Err(InterflowError::connection(format!(
                    "inner TLS handshake failed: {error}"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, port: u16) -> IngressRule {
        IngressRule {
            name: name.into(),
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            listen_protocol: StreamProto::Tcp,
            target_agent: "remote".into(),
            remote_addr: None,
            idle_timeout_secs: None,
            udp_per_ip_pps: 0,
            udp_per_ip_bytes_per_sec: 0,
            udp_egress_bytes_per_sec: 0,
        }
    }

    /// The 2026-10-07 bug shape, machine-locked: a connection-level knob
    /// change is an in-place param update, never a listener replace.
    #[test]
    fn classify_splits_param_changes_from_identity_changes() {
        // Identical rules: nothing to do.
        assert_eq!(
            classify(&rule("svc", 1), &rule("svc", 1)),
            ReconcileAction::NoChange
        );

        // The incident: only `idle_timeout_secs` changed (mes-portal gen
        // 7→8). The old whole-struct diff called this a replace.
        let mut idle = rule("svc", 1);
        idle.idle_timeout_secs = Some(1800);
        assert_eq!(
            classify(&rule("svc", 1), &idle),
            ReconcileAction::UpdateParams
        );

        // Every other non-identity field is a live param too.
        let mut target = rule("svc", 1);
        target.target_agent = "other".into();
        let mut remote = rule("svc", 1);
        remote.remote_addr = Some("127.0.0.1:9".into());
        let mut pps = rule("svc", 1);
        pps.udp_per_ip_pps = 100;
        assert_eq!(
            classify(&rule("svc", 1), &target),
            ReconcileAction::UpdateParams
        );
        assert_eq!(
            classify(&rule("svc", 1), &remote),
            ReconcileAction::UpdateParams
        );
        assert_eq!(
            classify(&rule("svc", 1), &pps),
            ReconcileAction::UpdateParams
        );

        // Identity changes rebind: the listen address...
        assert_eq!(
            classify(&rule("svc", 1), &rule("svc", 2)),
            ReconcileAction::Replace
        );
        // ...and the protocol (same address).
        let mut udp = rule("svc", 1);
        udp.listen_protocol = StreamProto::Udp;
        assert_eq!(classify(&rule("svc", 1), &udp), ReconcileAction::Replace);

        // A `:0` config keeps its identity across param changes (pinning
        // must never turn a param change into a rebind).
        let mut zero = rule("svc", 0);
        zero.idle_timeout_secs = Some(9);
        let mut zero_changed = zero.clone();
        zero_changed.idle_timeout_secs = Some(10);
        assert_eq!(
            classify(&zero, &zero_changed),
            ReconcileAction::UpdateParams
        );
    }
}

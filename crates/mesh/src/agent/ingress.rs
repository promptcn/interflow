use crate::agent::control::{ControlOpError, IngressCommand};
use crate::agent::ingress_addrs::IngressAddrs;
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
use tokio::task::AbortHandle;
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

struct ListenerGuard(HashMap<String, AbortHandle>);

impl Drop for ListenerGuard {
    fn drop(&mut self) {
        for (name, handle) in &self.0 {
            info!("Stopping ingress listener (cleanup): {}", name);
            handle.abort();
        }
    }
}

pub struct IngressHandler {
    agent_id: String,
    tunnel: AgentTunnel,
    /// Cross-session rule truth (in-memory).
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
    /// The rule each currently-bound listener serves (the reconcile base for
    /// signed-policy reloads: a same-name rule with different fields is a
    /// replace, not a skip).
    bound: HashMap<String, IngressRule>,
    /// Agent-scoped table of actually-bound listener addresses: a `:0` port
    /// materializes here at bind and the next session rebuild re-binds the
    /// same concrete address (port pinning — see [`IngressAddrs`]).
    addrs: Arc<IngressAddrs>,
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
        tunnel: AgentTunnel,
        store: Arc<RuleStore>,
        session: CancellationToken,
        tracker: TaskTracker,
        command_rx: Option<mpsc::Receiver<IngressCommand>>,
        addrs: Arc<IngressAddrs>,
        e2e: Arc<crate::agent::e2e::E2eRuntime>,
        ingress_ready: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self {
            agent_id,
            tunnel,
            store,
            session,
            tracker,
            command_rx,
            guard: ListenerGuard(HashMap::new()),
            bound: HashMap::new(),
            addrs,
            e2e,
            ingress_ready,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Ingress handler started, agent_id={}", self.agent_id);

        // At session establishment, take the current rule tables from the
        // store (including API additions from the previous session)
        let mut all_bound = true;
        for rule in self.store.ingress_snapshot().await {
            if let Err(e) = self.start_listener(rule.clone()).await {
                error!("Failed to start ingress listener {}: {}", rule.name, e);
                all_bound = false;
            }
        }
        if all_bound {
            // Idempotent across session rebuilds: the watch keeps the
            // latest value, and readiness only ever turns on.
            let _ = self.ingress_ready.send(true);
        }

        if let Some(mut rx) = self.command_rx.take() {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    IngressCommand::Add(rule, resp_tx) => {
                        let _ = resp_tx.send(self.handle_add(rule).await);
                    }
                    IngressCommand::Remove(name, resp_tx) => {
                        let _ = resp_tx.send(self.handle_remove(&name).await);
                    }
                    IngressCommand::List(resp_tx) => {
                        let views = self.store.ingress_views().await;
                        info!("Handled List command, returning {} rules", views.len());
                        let _ = resp_tx.send(views);
                    }
                    IngressCommand::Sync(desired) => {
                        self.handle_sync(desired).await;
                    }
                }
            }
        } else {
            std::future::pending::<()>().await;
        }

        Ok(())
    }

    /// Signed-policy reload: reconcile the live listener set against the
    /// new rule face. Added or changed rules bind (same-name change stops
    /// the old listener first); removed rules stop. The store (rule truth)
    /// has already been replaced by the reloader — this only reconciles the
    /// runtime face, so a listener that fails to bind is loud but never
    /// reverts the signed truth.
    async fn handle_sync(&mut self, desired: Vec<IngressRule>) {
        let mut added = 0usize;
        let mut changed = 0usize;
        let mut removed = 0usize;
        // Stop listeners whose rule is gone.
        let names: Vec<String> = self.bound.keys().cloned().collect();
        for name in names {
            if !desired.iter().any(|r| r.name == name) {
                if let Some(handle) = self.guard.0.remove(&name) {
                    info!("Policy reload stopped ingress listener: {name}");
                    handle.abort();
                }
                self.addrs.remove(&name);
                self.bound.remove(&name);
                removed += 1;
            }
        }
        // Bind new rules and replace changed ones.
        for rule in desired {
            let name = rule.name.clone();
            let unchanged = self
                .bound
                .get(&name)
                .is_some_and(|current| *current == rule);
            if unchanged {
                continue;
            }
            let is_change = self.bound.contains_key(&name);
            if let Some(old) = self.guard.0.remove(&name) {
                info!("Policy reload replacing ingress listener: {name}");
                old.abort();
            }
            match self.start_listener(rule).await {
                Ok(()) => {
                    if is_change {
                        changed += 1;
                    } else {
                        added += 1;
                    }
                }
                Err(e) => {
                    error!("Policy reload failed to bind ingress listener {name}: {e}");
                    self.bound.remove(&name);
                }
            }
        }
        info!("Policy reload reconciled ingress listeners: +{added} ~{changed} -{removed}");
    }

    /// Add: start the listener first (the fallible runtime side effect), then
    /// record the rule in the store. An Ok acknowledgment = the rule is in
    /// effect.
    async fn handle_add(&mut self, rule: IngressRule) -> std::result::Result<(), ControlOpError> {
        let name = rule.name.clone();
        if !rule.listen_addr.ip().is_loopback() {
            return Err(ControlOpError::Apply(format!(
                "ingress {name} rejected: listen_addr must be loopback"
            )));
        }
        // Same-name replacement: stop the old listener first (the old
        // implementation overwrote the map entry directly, leaking the
        // listener task)
        if let Some(old) = self.guard.0.remove(&name) {
            info!(
                "Same-name replacement, stopping old ingress listener: {}",
                name
            );
            old.abort();
        }
        if let Err(e) = self.start_listener(rule.clone()).await {
            return Err(ControlOpError::Apply(format!(
                "failed to start listener: {e}"
            )));
        }
        self.store.add_ingress(rule).await.map_err(Into::into)
    }

    /// Remove: stop the listener, then drop the rule from the store.
    async fn handle_remove(&mut self, name: &str) -> std::result::Result<(), ControlOpError> {
        let Some(handle) = self.guard.0.remove(name) else {
            return Err(ControlOpError::NotFound(format!(
                "ingress rule not found: {name}"
            )));
        };
        info!("Stopping ingress listener: {}", name);
        handle.abort();
        self.addrs.remove(name);
        self.bound.remove(name);
        self.store.remove_ingress(name).await.map_err(Into::into)
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
        match rule.listen_protocol {
            StreamProto::Tcp => self.start_tcp_listener(rule.clone()).await,
            StreamProto::Udp => self.start_udp_listener(rule.clone()),
        }?;
        self.bound.insert(name, rule);
        Ok(())
    }

    fn start_udp_listener(&mut self, rule: IngressRule) -> Result<()> {
        info!(
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
        info!(
            "Ingress (UDP) listener bound: {} -> {}",
            actual, rule.target_agent
        );

        let tunnel = self.tunnel.clone();
        let rule_clone = rule.clone();
        let session = self.session.clone();
        let e2e = Arc::clone(&self.e2e);
        let handle = self.tracker.spawn(async move {
            // Stop on session end (the socket closes as the task drops)
            tokio::select! {
                () = session.cancelled() => {}
                () = crate::agent::ingress_udp::run_udp_listener(
                    socket,
                    rule_clone,
                    tunnel,
                    e2e,
                ) => {}
            }
        });

        self.guard.0.insert(rule.name, handle.abort_handle());
        Ok(())
    }

    async fn start_tcp_listener(&mut self, rule: IngressRule) -> Result<()> {
        info!(
            "Starting ingress listener: {} -> {}",
            rule.listen_addr, rule.target_agent
        );

        let target = self.bind_target(&rule);
        let listener = match TcpListener::bind(target).await {
            Ok(l) => l,
            // Same pinned-rebind fallback as the UDP path above.
            Err(e) if target != rule.listen_addr => {
                warn!(
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
        info!(
            "Ingress listener bound: {} -> {}",
            actual, rule.target_agent
        );

        let agent_id = self.agent_id.clone();
        let tunnel = self.tunnel.clone();
        let rule_clone = rule.clone();
        let session = self.session.clone();
        let conn_tracker = self.tracker.clone();
        let per_conn_tracker = self.tracker.clone();
        let e2e = self.e2e.clone();

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
                            error!("Concurrency-limit semaphore closed");
                            break;
                        };

                        match listener.accept().await {
                            Ok((socket, addr)) => {
                                info!("Connection accepted: {} (rule: {})", addr, rule_clone.name);
                                // TCP_NODELAY: disable Nagle to cut
                                // small-packet latency
                                let _ = socket.set_nodelay(true);
                                let tunnel = tunnel.clone();
                                let rule = rule_clone.clone();
                                let agent_id = agent_id.clone();
                                let session = session.clone();
                                let e2e = e2e.clone();

                                per_conn_tracker.spawn(async move {
                                    // _permit releases automatically when
                                    // the task ends
                                    let _permit = permit;
                                    tokio::select! {
                                        () = session.cancelled() => {}
                                        r = Self::handle_connection(socket, tunnel, rule, agent_id, e2e) => {
                                            if let Err(e) = r {
                                                error!("Connection handling error: {}", e);
                                            }
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Listener accept error: {}", e);
                                drop(permit);
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                } => {}
            }
        });
        self.guard.0.insert(rule.name, handle.abort_handle());
        Ok(())
    }

    async fn handle_connection(
        socket: tokio::net::TcpStream,
        tunnel: AgentTunnel,
        rule: IngressRule,
        agent_id: String,
        e2e: Arc<crate::agent::e2e::E2eRuntime>,
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
                    Duration::ZERO,
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
                warn!("inner TLS handshake failed ({reason}: {error}), closing stream {stream_id}");
                let _ = tunnel.send_close(stream_id).await;
                tunnel.unregister_stream(stream_id).await;
                Err(InterflowError::connection(format!(
                    "inner TLS handshake failed: {error}"
                )))
            }
        }
    }
}

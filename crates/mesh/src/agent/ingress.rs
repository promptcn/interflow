use crate::agent::control::{ControlOpError, IngressCommand};
use crate::agent::rules::RuleStore;
use crate::config::IngressRule;
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::StreamProto;
use interflow_core::tunnel::AgentTunnel;
use std::collections::HashMap;
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
const CLIENT_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Cross-session rule truth (in-memory + write-through persistence).
    store: Arc<RuleStore>,
    /// Session token: the lifecycle anchor of listeners and per-connection
    /// pumps — session end (watchdog/disconnect/shutdown) exits them all,
    /// and client sockets release with the task (no longer relying on the
    /// idle timeout to die off).
    session: CancellationToken,
    /// Session-level task tracker: listeners and per-connection pumps hang
    /// off it and close out boundedly in the teardown sequence.
    tracker: TaskTracker,
    command_rx: Option<mpsc::Receiver<IngressCommand>>,
    guard: ListenerGuard,
}

impl IngressHandler {
    pub fn new_with_tunnel(
        agent_id: String,
        tunnel: AgentTunnel,
        store: Arc<RuleStore>,
        session: CancellationToken,
        tracker: TaskTracker,
        command_rx: Option<mpsc::Receiver<IngressCommand>>,
    ) -> Self {
        Self {
            agent_id,
            tunnel,
            store,
            session,
            tracker,
            command_rx,
            guard: ListenerGuard(HashMap::new()),
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Ingress handler started, agent_id={}", self.agent_id);

        // At session establishment, take the current rule tables from the
        // store (including API additions from the previous session)
        for rule in self.store.ingress_snapshot().await {
            if let Err(e) = self.start_listener(rule.clone()).await {
                error!("Failed to start ingress listener {}: {}", rule.name, e);
            }
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
                }
            }
        } else {
            std::future::pending::<()>().await;
        }

        Ok(())
    }

    /// Add: start the listener first (the fallible runtime side effect),
    /// then persist; if persistence fails, roll back the listener just
    /// started. An Ok acknowledgment = the rule is in effect and persisted
    /// to disk.
    async fn handle_add(&mut self, rule: IngressRule) -> std::result::Result<(), ControlOpError> {
        let name = rule.name.clone();
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
        match self.store.add_ingress(rule).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Persistence failed: roll back the listener; neither memory
                // nor the file changed
                if let Some(handle) = self.guard.0.remove(&name) {
                    handle.abort();
                }
                Err(e.into())
            }
        }
    }

    /// Remove: stop the listener first, then persist; if persistence fails,
    /// compensate by restarting the listener from the rule still in the
    /// store (memory untouched, the rule keeps serving).
    async fn handle_remove(&mut self, name: &str) -> std::result::Result<(), ControlOpError> {
        let Some(handle) = self.guard.0.remove(name) else {
            return Err(ControlOpError::NotFound(format!(
                "ingress rule not found: {name}"
            )));
        };
        info!("Stopping ingress listener: {}", name);
        handle.abort();
        match self.store.remove_ingress(name).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Compensation: the store's memory was untouched (the
                // persist-first step failed); restart the listener from the
                // original rule
                match self.store.get_ingress(name).await {
                    Some(rule) => {
                        if let Err(e2) = self.start_listener(rule).await {
                            error!(
                                "Removal of {} failed to persist ({e}) and listener compensation restart failed ({e2}), \
                                 rule remains in memory but is no longer listening; next session resync will restore it",
                                name
                            );
                        }
                    }
                    None => {
                        warn!(
                            "Removal of {} failed to persist and the rule is gone from the store, skipping compensation",
                            name
                        );
                    }
                }
                Err(e.into())
            }
        }
    }

    async fn start_listener(&mut self, rule: IngressRule) -> Result<()> {
        match rule.listen_protocol {
            StreamProto::Tcp => self.start_tcp_listener(rule).await,
            StreamProto::Udp => self.start_udp_listener(rule),
        }
    }

    fn start_udp_listener(&mut self, rule: IngressRule) -> Result<()> {
        info!(
            "Starting ingress (UDP) listener: {} -> {}",
            rule.listen_addr, rule.target_agent
        );

        let socket = crate::agent::ingress_udp::bind_udp_socket(rule.listen_addr)
            .map_err(InterflowError::Io)?;

        let tunnel = self.tunnel.clone();
        let rule_clone = rule.clone();
        let session = self.session.clone();
        let handle = self.tracker.spawn(async move {
            // Stop on session end (the socket closes as the task drops)
            tokio::select! {
                () = session.cancelled() => {}
                () = crate::agent::ingress_udp::run_udp_listener(socket, rule_clone, tunnel) => {}
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

        let listener = TcpListener::bind(rule.listen_addr)
            .await
            .map_err(InterflowError::Io)?;

        let agent_id = self.agent_id.clone();
        let tunnel = self.tunnel.clone();
        let rule_clone = rule.clone();
        let session = self.session.clone();
        let conn_tracker = self.tracker.clone();
        let per_conn_tracker = self.tracker.clone();

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

                                per_conn_tracker.spawn(async move {
                                    // _permit releases automatically when
                                    // the task ends
                                    let _permit = permit;
                                    tokio::select! {
                                        () = session.cancelled() => {}
                                        r = Self::handle_connection(socket, tunnel, rule, agent_id) => {
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
        _agent_id: String,
    ) -> Result<()> {
        // Stream idle timeout: close the stream when neither direction has
        // data for this long (default tcp 300s, configurable per rule)
        let idle_timeout = rule.effective_idle_timeout();
        let stream_id = uuid::Uuid::new_v4().to_string();

        // Register a dedicated channel (avoids a broadcast storm)
        let data_rx = tunnel.register_stream(stream_id.clone()).await;

        // Send the stream-open signal
        if let Err(e) = tunnel
            .send_open(
                &stream_id,
                &rule.target_agent,
                rule.remote_addr.as_deref(),
                StreamProto::Tcp,
            )
            .await
        {
            tunnel.unregister_stream(&stream_id).await;
            return Err(e);
        }

        // Bidirectional pumps (shared implementation, inlined futures
        // without spawning): either half exiting winds down the whole
        // stream and unregisters it — when the write half exits first the
        // read half is cancelled by drop (preventing a half-open socket
        // from lingering until the idle timeout), and when the read half
        // exits first it unregisters before flushing the buffer. The
        // JoinHandle double-poll panic class is structurally excluded
        // (docs/bug/2026-09-13-select-branch-double-await-joinhandle-panic.md).
        let (rd, wr) = socket.into_split();
        interflow_core::tunnel::pump::pump_tcp_stream(
            rd,
            wr,
            data_rx,
            &tunnel,
            &stream_id,
            &interflow_core::tunnel::pump::PumpConfig {
                idle_timeout,
                write_stall_timeout: CLIENT_WRITE_STALL_TIMEOUT,
                idle_timeout_counter: "interflow_ingress_stream_idle_timeout",
                write_stall_counter: "interflow_ingress_client_write_stall",
                log_label: "ingress",
            },
            // The mesh ingress has no consumer for the peer's close reason
            // (no route-level negative caching on this plane).
            None,
        )
        .await;

        Ok(())
    }
}

//! Stack assembly: in-process hub / agent instances, graceful shutdown, readiness probes.
//!
//! The hub handle is the engine-level [`interflow_mesh::hub::HubHandle`]
//! (spawn + lifecycle watch + graceful shutdown); [`spawn_hub`] wraps it with
//! the test contract "returned only once accepting". The agent exposes
//! [`AgentHandle`] directly (which supports `shutdown_graceful`).

use interflow_mesh::agent::{AgentClient, AgentHandle, AgentState};
use interflow_mesh::config::{AgentConfig, HubConfig};
pub use interflow_mesh::hub::{HubHandle, HubLifecycle};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// A loopback address that is guaranteed-refused **by construction**: port 1
/// sits below every OS ephemeral-port range (Linux 32768+, macOS/Windows
/// 49152+), so a kernel `:0` allocation can never hand it to another test,
/// and no legitimate service listens on it in CI or dev environments.
///
/// Negative-path tests (an agent dialing a dead hub, an egress target that
/// must ECONNREFUSED) use this instead of binding-and-releasing a probe port
/// — the pick-then-release shape races parallel tests, this cannot.
pub fn refused_addr() -> SocketAddr {
    "127.0.0.1:1".parse().expect("refused addr")
}

/// A running edge started by [`spawn_edge`]: the actually-bound listener
/// addresses plus the lifecycle handles.
pub struct EdgeHandle {
    ready: interflow_expose::edge::EdgeReady,
    shutdown_token: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<interflow_core::error::Result<()>>,
}

impl EdgeHandle {
    /// The public listener's actually-bound address (`:0` materializes
    /// here).
    pub fn public_addr(&self) -> SocketAddr {
        self.ready.public
    }

    /// The control endpoint's (embedded hub) actually-bound address — TCP
    /// and QUIC dual-stack on one port.
    pub fn control_addr(&self) -> SocketAddr {
        self.ready.control
    }

    /// The ACME HTTP-01/redirect face's bound address, when enabled and
    /// bound (best-effort: `None` when the :80 bind failed non-fatally).
    pub fn acme_http_addr(&self) -> Option<SocketAddr> {
        self.ready.acme_http
    }

    /// The control endpoint's dedicated QUIC face (when configured on its
    /// own port; `None` when off or derived dual-stack).
    pub fn control_quic_addr(&self) -> Option<SocketAddr> {
        self.ready.control_quic
    }

    /// The full readiness record (public / control / control_quic /
    /// acme_http).
    pub fn ready(&self) -> interflow_expose::edge::EdgeReady {
        self.ready
    }

    /// Stop the edge and wait for its cooperative teardown (public listener
    /// stops accepting, the control endpoint drains, the ACME :80 listener
    /// releases its port). Cancellation resolves as `Ok(())`.
    pub async fn shutdown(self) -> interflow_core::error::Result<()> {
        self.shutdown_token.cancel();
        match self.task.await {
            Ok(result) => result,
            Err(e) if e.is_cancelled() => Ok(()),
            Err(e) => Err(interflow_core::error::InterflowError::JoinError(e)),
        }
    }
}

/// Start an edge and **wait until it is actually serving** before
/// returning: the readiness signal fires only after the public listener is
/// bound, the control endpoint (embedded hub) is up, and every internal
/// workspace agent has registered — strictly stronger than the TCP probes
/// tests used to run against the two ports.
///
/// Configure `:0` listen addresses and read them back from the handle
/// (kernel-assigned at bind — no pick-then-bind window under parallel
/// `cargo test`).
///
/// # Panics
/// Panics if the edge exits before readiness or never becomes ready within
/// the startup budget — the same loud contract as [`spawn_hub`].
pub async fn spawn_edge(cfg: interflow_expose::edge::EdgeConfig) -> EdgeHandle {
    const READY_TIMEOUT: Duration = Duration::from_secs(30);
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let run_token = shutdown_token.clone();
    let task = tokio::spawn(async move {
        interflow_expose::edge::run_until_signalled(cfg, run_token, ready_tx).await
    });
    let ready = match tokio::time::timeout(READY_TIMEOUT, ready_rx).await {
        Ok(Ok(ready)) => ready,
        Ok(Err(_recv_err)) => panic!("edge exited before signalling readiness"),
        Err(_) => {
            shutdown_token.cancel();
            panic!("edge not ready within {READY_TIMEOUT:?}");
        }
    };
    EdgeHandle {
        ready,
        shutdown_token,
        task,
    }
}

/// Start a hub and **wait until it is accepting connections** (TCP bound +
/// QUIC listener up) before returning.
///
/// This is the readiness contract for every in-process hub in tests: by the
/// time a `HubHandle` exists the hub can be connected to — no startup sleeps,
/// no port probing at call sites. Panics (with the server error) if the hub
/// never reaches readiness.
pub async fn spawn_hub(cfg: HubConfig) -> HubHandle {
    const READY_TIMEOUT: Duration = Duration::from_secs(10);
    let hub = HubHandle::spawn(cfg).expect("hub build");
    let mut state = hub.subscribe_state();
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        match state.borrow_and_update().clone() {
            HubLifecycle::Running => return hub,
            // Ended before readiness (e.g. listen bind failure): surface the
            // real error instead of a confusing downstream failure.
            HubLifecycle::Failed { error } => panic!("hub not ready: {error}"),
            HubLifecycle::Starting => {}
            terminal => panic!("hub left readiness wait in {terminal:?}"),
        }
        if tokio::time::timeout_at(deadline, state.changed())
            .await
            .is_err()
        {
            panic!(
                "hub not ready within {READY_TIMEOUT:?} (state: {:?})",
                hub.state()
            );
        }
    }
}

/// Start an agent and return its handle. Call `shutdown_graceful` for a clean stop;
/// simply dropping it matches the old behavior (reclaimed when the runtime ends).
///
/// # Panics
/// Panics on an invalid config (`AgentClient::new` fails) — there is no point continuing
/// past an assembly-time error.
pub fn spawn_agent(cfg: AgentConfig) -> AgentHandle {
    AgentClient::new(cfg).expect("agent build").start()
}

/// Default budget for [`spawn_agent_registered`] — generous for connect +
/// register under parallel-test load.
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Spawn an agent and wait until it is **registered at the hub**
/// (`AgentState::Connected` is only set after connect + register complete).
///
/// This is the gate every test needs before addressing the agent: an Open
/// routed to an unregistered target is torn down by the hub with `_close_`,
/// so a fire-and-forget spawn followed by an immediate Open races the
/// agent's own registration. Panics with the final agent state on timeout —
/// there is no recovery path for a test whose agent never registers.
pub async fn spawn_agent_registered(cfg: AgentConfig) -> AgentHandle {
    let handle = spawn_agent(cfg);
    if !wait_agent_connected(&handle, REGISTRATION_TIMEOUT).await {
        panic!(
            "agent did not register within {REGISTRATION_TIMEOUT:?} (state: {:?})",
            handle.state()
        );
    }
    handle
}

/// Repeatedly attempt a TCP connection to `addr` until success or timeout. Used to wait
/// for an agent to bring up its listener.
pub async fn wait_for_tcp(addr: SocketAddr, timeout: Duration) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Wait for the agent to reach Connected (registration complete). Returns false on
/// timeout (the caller decides whether that is fatal).
pub async fn wait_agent_connected(handle: &AgentHandle, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if matches!(handle.state(), AgentState::Connected { .. }) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    matches!(handle.state(), AgentState::Connected { .. })
}

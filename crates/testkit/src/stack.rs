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

/// Bind 127.0.0.1:0 to grab an ephemeral port (released immediately after binding; there is
/// a tiny race between tests but it is usually good enough).
pub fn pick_ephemeral_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
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

//! `/poll` handling: long-lived connection that streams `TunnelData` from hub → agent.

use crate::hub::service::{HubService, agent_id_of, bind_connection_identity, text_response};
use crate::hub::state::{HubResponseBody, RxStream};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use interflow_core::error::Result;
use interflow_core::tunnel::ChunkHygiene;
use tokio::sync::mpsc;
use tracing::{info, warn};

impl HubService {
    /// Handles a `/poll` long-polling request.
    ///
    /// Four cases:
    /// 1. `rx` idle → take it and start streaming dispatch.
    /// 2. Channel closed → rebuild in place and keep serving.
    /// 3. `rx` held by another poll connection → return 409 Conflict.
    /// 4. Agent unregistered → implicit re-registration (an evicted agent
    ///    recovers on its very next poll).
    pub(crate) async fn handle_poll(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        let agent_id = agent_id_of(&req)?;

        // Identity binding check (bare id vs the mTLS identity's CN)
        if let Err(resp) =
            bind_connection_identity(&self.connection_identity, agent_id, "poll").await
        {
            return Ok(*resp);
        }
        let agent_key = self.qualified_id().await;

        // Take the AgentSession Arc (outer read lock is very short-lived)
        let state_arc = {
            let agents = self.agents.read().await;
            agents.get(&agent_key).cloned()
        };

        let state_arc = if let Some(a) = state_arc {
            a
        } else {
            // Implicit re-registration: when an agent that was evicted (poll
            // grace / heartbeat / send timeout) still holds a healthy
            // connection, its next /poll restores registration right here,
            // without waiting for a disconnect to trigger reconnect and
            // re-registration (edge processes never re-register and rely on
            // this self-healing path in particular).
            // The identity binding check above already passed, so the
            // authentication level is equivalent to /register.
            self.implicit_re_register(&agent_key).await
        };

        // Decide under the inner write lock: take the existing rx /
        // rebuild the channel in place / return 409
        let (rx, ctrl_rx, ctrl_backlog, generation, waker_slot) = {
            let mut state = state_arc.write().await;
            if let Some(rx) = state.rx.take() {
                let ctrl_rx = state
                    .ctrl_rx
                    .take()
                    .expect("ctrl_rx and rx share a lifetime (poll take/return are paired)");
                let backlog = state.ctrl_backlog.clone();
                (
                    rx,
                    ctrl_rx,
                    backlog,
                    state.generation,
                    state.poll_waker.clone(),
                )
            } else if state.tx.is_closed() {
                // A deliberately narrower protocol than
                // [`AgentSession::install_channels`]: the registration
                // survives (liveness and QUIC handle untouched, the active
                // upload lease keeps running) and the fresh rx is consumed
                // by this very poll instead of being parked.
                info!("Agent {agent_key} channel closed or lost, recreating");
                let (tx, rx) = mpsc::channel(256);
                let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
                state.tx = tx;
                state.ctrl_tx = ctrl_tx;
                state.ctrl_backlog = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                state.generation += 1;
                let generation = state.generation;
                // Wake the old poll body: the generation has advanced, so it
                // should end (it may still be hanging on the old channel)
                state.wake_poll();
                let backlog = state.ctrl_backlog.clone();
                let waker_slot = state.poll_waker.clone();
                // Heartbeats are served by the global supervision loop (see
                // hub/heartbeat.rs); channel rebuilds no longer need (or have)
                // a per-agent heartbeat task taking over
                (rx, ctrl_rx, backlog, generation, waker_slot)
            } else {
                warn!(
                    "Agent {} attempted poll but no channel available (in use)",
                    agent_id
                );
                return Ok(text_response(StatusCode::CONFLICT, "Channel busy"));
            }
        };

        let stream = RxStream::new(
            rx,
            ctrl_rx,
            ctrl_backlog,
            state_arc,
            generation,
            waker_slot,
            self.handles(),
            agent_key.clone(),
        );
        // ChunkHygiene enforces the h2 body chunking invariants (no empty
        // non-final chunks, small chunks coalesced to ≥256B — see
        // interflow_core::tunnel::chunking): body chunk boundaries become h2
        // DATA frames, and h2 ≥0.4.16 GOAWAYs connections whose peer emits
        // pathological frame shapes (the 2026-09-17 heartbeat-churn bug).
        let body = BodyExt::boxed(StreamBody::new(ChunkHygiene::new(stream)));

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .expect("status+body response is infallible");

        info!("Agent {agent_key} entering streaming receive mode");
        Ok(response)
    }
}

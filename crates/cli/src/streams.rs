//! The operator's planned-unavailability verbs: `stream pause|resume`
//! (stream-level) and `maintenance on|off` (node-level) — the CLI face of
//! (internal design notes).
//!
//! Discipline (the backlog's 操作面纪律): the verbs are symmetric and
//! IDEMPOTENT — pausing an already-paused stream and resuming an unpaused
//! one are quiet no-ops, never errors — so "what state is this in?" is
//! never an anxiety. One declaration, nothing to remember: a paused
//! stream's intent lives on the node (it survives restarts and only an
//! explicit resume lifts it), a maintenance declaration lives at the hub
//! (and lifts itself when the node rejoins).
//!
//! Convergence reporting is honest about asynchrony: the op is queued at
//! the hub the moment the verb returns; the verb then waits a bounded
//! window for the hub's REPORTED face to reflect it (the node applies and
//! re-reports within one watch interval when online). A node that is
//! offline keeps its queued op — the verb says so instead of failing.

use std::path::Path;
use std::time::{Duration, Instant};

use interflow_core::tunnel::transport::StreamIntentOp;
use interflow_identity::manifest::Manifest;
use interflow_mesh::hub::stream_intents::IntentQueued;

use crate::outln;
use crate::plan::{ControlCredential, manifest_hub_endpoint};

/// How long the verb waits for the face to converge before reporting
/// "queued" (one policy-watch interval plus margin — an online node
/// converges well inside it).
const FACE_WAIT: Duration = Duration::from_secs(15);
/// Face poll cadence while waiting.
const FACE_POLL: Duration = Duration::from_millis(500);

/// Mints one control credential for the whole verb (queue + face polls —
/// one mint, not one per poll).
fn control_credential(
    manifest_path: &Path,
    issuer_dir: &Path,
) -> interflow_core::error::Result<(String, ControlCredential)> {
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let endpoint = manifest_hub_endpoint(&manifest);
    if endpoint.is_empty() {
        return Err(interflow_core::error::InterflowError::config(
            "the manifest names no hub endpoint — planned-unavailability verbs need a running hub"
                .to_string(),
        ));
    }
    let issuer = interflow_identity::issuance::IssuerStore::open(issuer_dir);
    issuer.ensure_realm().map_err(crate::runtime::pack_error)?;
    let cred = ControlCredential::mint(&issuer, &manifest.realm.id)?;
    Ok((endpoint, cred))
}

/// Resolves the operator's `--agent` (bare name or qualified
/// `tenant/agent`) against the hub's reported rows. Bare names must
/// resolve uniquely — ambiguity is an error naming the candidates, never
/// a silent pick.
fn resolve_agent(
    agent: &str,
    rows: &[interflow_mesh::hub::policy::PolicyAgentWatermark],
) -> interflow_core::error::Result<String> {
    if agent.contains('/') {
        return Ok(agent.to_string());
    }
    let matches: Vec<&str> = rows
        .iter()
        .map(|row| row.agent.as_str())
        .filter(|qualified| qualified.rsplit('/').next() == Some(agent))
        .collect();
    match matches.as_slice() {
        [one] => Ok((*one).to_string()),
        [] => Err(interflow_core::error::InterflowError::config(format!(
            "no fleet member named `{agent}` — is the node registered?"
        ))),
        many => Err(interflow_core::error::InterflowError::config(format!(
            "`{agent}` is ambiguous across tenants: {} — pass the qualified id",
            many.join(", ")
        ))),
    }
}

/// The hub's current overview rows (one credential call).
fn overview(
    cred: &ControlCredential,
    endpoint: &str,
) -> interflow_core::error::Result<interflow_mesh::hub::policy::HubOverview> {
    cred.call(endpoint, |ep, ca, cert, key| async move {
        interflow_mesh::hub::policy::query_hub_overview(&ep, &ca, &cert, &key).await
    })
}

/// `stream pause --agent A --name S` / `stream resume …`.
pub fn stream_pause_resume(
    manifest_path: &Path,
    issuer_dir: &Path,
    agent: &str,
    name: &str,
    pause: bool,
) -> interflow_core::error::Result<()> {
    let (endpoint, cred) = control_credential(manifest_path, issuer_dir)?;
    let rows = overview(&cred, &endpoint)?;
    let qualified = resolve_agent(agent, &rows.agents)?;

    let verb = if pause { "pause" } else { "resume" };
    let opposite = if pause { "resumed" } else { "paused" };
    let already = if pause { "paused" } else { "serving" };
    let op = if pause {
        StreamIntentOp::Pause {
            name: name.to_string(),
        }
    } else {
        StreamIntentOp::Resume {
            name: name.to_string(),
        }
    };
    let queue_agent = qualified.clone();
    let queued: IntentQueued = cred.call(&endpoint, |ep, ca, cert, key| async move {
        interflow_mesh::hub::stream_intents::queue_op(&ep, &ca, &cert, &key, &queue_agent, &op)
            .await
    })?;

    let face_shows = |paused: &[String]| paused.iter().any(|s| s == name);
    if let Some(paused) = &queued.paused_streams
        && face_shows(paused) == pause
    {
        outln!("{name} on {qualified} is already {already} — nothing to do");
        return Ok(());
    }

    // Bounded convergence wait on the reported face.
    let deadline = Instant::now() + FACE_WAIT;
    let mut converged = false;
    loop {
        if let Ok(rows) = overview(&cred, &endpoint)
            && let Some(row) = rows.agents.iter().find(|row| row.agent == qualified)
            && let Some(paused) = &row.paused_streams
            && face_shows(paused) == pause
        {
            converged = true;
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(FACE_POLL);
    }
    if !converged {
        outln!(
            "{verb} for {name} on {qualified} queued at the hub — the node is offline or has not exchanged since; it will apply the {verb} when it next checks in"
        );
        return Ok(());
    }
    if pause {
        outln!(
            "{name} on {qualified} paused — listener stopped, port released; resume with `interflow-cli stream resume`"
        );
        maybe_all_paused_guidance(manifest_path, &qualified, name, &cred, &endpoint)?;
    } else {
        outln!("{name} on {qualified} {opposite} and serving again");
    }
    Ok(())
}

/// The 安全边界 guidance: pausing a node's LAST unpaused stream makes it
/// an empty shell — the equivalent of taking the node down while keeping
/// its absence unreadable as planned. Point the operator at the
/// node-level verb instead of stacking pauses.
fn maybe_all_paused_guidance(
    manifest_path: &Path,
    qualified: &str,
    just_paused: &str,
    cred: &ControlCredential,
    endpoint: &str,
) -> interflow_core::error::Result<()> {
    let bare = qualified.rsplit('/').next().unwrap_or(qualified);
    let Ok(manifest) = Manifest::load(manifest_path) else {
        return Ok(());
    };
    let Some(agent) = manifest.agent.get(bare) else {
        return Ok(());
    };
    let streams: Vec<&str> = agent.mesh_ingress.iter().map(|r| r.name.as_str()).collect();
    let rows = overview(cred, endpoint)?;
    let Some(row) = rows.agents.iter().find(|row| row.agent == qualified) else {
        return Ok(());
    };
    let paused = row.paused_streams.clone().unwrap_or_default();
    let all_paused = !streams.is_empty()
        && streams
            .iter()
            .all(|name| paused.iter().any(|p| p == *name) || *name == just_paused);
    if all_paused {
        outln!(
            "note: every stream of {qualified} is now paused — the node is an empty shell. If it is going down entirely, prefer the node-level verb (`interflow-cli maintenance on --agent {bare}`) over stacked pauses: one declaration covers the whole leg and lifts itself when the node returns."
        );
    }
    Ok(())
}

/// The GUI's hub-path wrapper (no printing): queue one op, return the
/// hub's current face answer. `None` = the manifest names no hub endpoint.
pub fn queue_stream_op(
    manifest_path: &Path,
    issuer_dir: &Path,
    agent: &str,
    name: &str,
    pause: bool,
) -> interflow_core::error::Result<Option<IntentQueued>> {
    let (endpoint, cred) = control_credential(manifest_path, issuer_dir)?;
    let op = if pause {
        StreamIntentOp::Pause {
            name: name.to_string(),
        }
    } else {
        StreamIntentOp::Resume {
            name: name.to_string(),
        }
    };
    let agent = agent.to_string();
    Ok(Some(cred.call(
        &endpoint,
        move |ep, ca, cert, key| async move {
            interflow_mesh::hub::stream_intents::queue_op(&ep, &ca, &cert, &key, &agent, &op).await
        },
    )?))
}

/// The GUI's hub-path wrapper for maintenance on/off (no printing).
/// `None` = the manifest names no hub endpoint.
pub fn hub_maintenance(
    manifest_path: &Path,
    issuer_dir: &Path,
    agent: &str,
    on: bool,
) -> interflow_core::error::Result<Option<String>> {
    let (endpoint, cred) = control_credential(manifest_path, issuer_dir)?;
    let agent = agent.to_string();
    Ok(Some(cred.call(
        &endpoint,
        move |ep, ca, cert, key| async move {
            interflow_mesh::hub::maintenance::set_maintenance(&ep, &ca, &cert, &key, &agent, on)
                .await
        },
    )?))
}

/// `maintenance on|off --agent A`.
pub fn maintenance_on_off(
    manifest_path: &Path,
    issuer_dir: &Path,
    agent: &str,
    on: bool,
) -> interflow_core::error::Result<()> {
    let (endpoint, cred) = control_credential(manifest_path, issuer_dir)?;
    let rows = overview(&cred, &endpoint)?;
    let qualified = resolve_agent(agent, &rows.agents)?;
    let set_agent = qualified.clone();
    let note: String = cred.call(&endpoint, move |ep, ca, cert, key| async move {
        interflow_mesh::hub::maintenance::set_maintenance(&ep, &ca, &cert, &key, &set_agent, on)
            .await
    })?;
    if !note.is_empty() {
        outln!("{note}");
    } else if on {
        outln!("{qualified} declared under maintenance");
    } else {
        outln!("maintenance lifted for {qualified}");
    }
    Ok(())
}

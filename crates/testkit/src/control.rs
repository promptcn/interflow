//! The operator control-plane face for e2e tests: a second hub tenant
//! named `control` (the same realm-anchored principal class the CLI/GUI
//! mint from the issuer store, here issued straight from a test CA) plus
//! thin wrappers over the hub's operator clients — the planned-
//! unavailability verbs (`stream pause|resume`, `maintenance on|off`) and
//! the faces the assertions wait on (`/policy/floor` overview, snapshot).
//!
//! The data-plane tenants stay exactly as `hub_config` builds them; the
//! control tenant is ADDITIVE, so a test that never touches it behaves
//! identically to before.

use std::time::Duration;

use interflow_mesh::hub::state::CONTROL_TENANT;

use crate::certs::TestCerts;
use crate::wait::eventually_async;
use interflow_mesh::config::{AclRule, HeartbeatConfig, HubConfig, HubSecurityConfig};

/// Adds the `control` tenant (anchored at `control`'s CA) to a hub config
/// built by the ordinary testkit builders — the operator-plane e2e entry.
pub fn with_control_tenant(mut cfg: HubConfig, control: &TestCerts) -> HubConfig {
    cfg.auth.tenants.push(interflow_mesh::config::TenantConfig {
        name: CONTROL_TENANT.to_string(),
        ca_path: control.ca_path().display().to_string(),
        crl_path: Some(control.crl_path().display().to_string()),
        trusted_gateway: false,
    });
    cfg
}

/// `hub_config` + the control tenant.
pub fn hub_config_with_control(
    listen_port: u16,
    certs: &TestCerts,
    control: &TestCerts,
    acl_rules: Vec<AclRule>,
) -> HubConfig {
    with_control_tenant(crate::hub_config(listen_port, certs, acl_rules), control)
}

/// `hub_quic_config` + the control tenant.
pub fn hub_quic_config_with_control(
    listen_port: u16,
    certs: &TestCerts,
    control: &TestCerts,
    acl_rules: Vec<AclRule>,
) -> HubConfig {
    with_control_tenant(
        crate::hub_quic_config(listen_port, certs, acl_rules),
        control,
    )
}

/// `hub_config_tuned` + the control tenant (timer-compressed variants).
pub fn hub_config_tuned_with_control(
    listen_port: u16,
    certs: &TestCerts,
    control: &TestCerts,
    acl_rules: Vec<AclRule>,
    security: HubSecurityConfig,
    heartbeat: HeartbeatConfig,
) -> HubConfig {
    with_control_tenant(
        crate::hub_config_tuned(listen_port, certs, acl_rules, security, heartbeat),
        control,
    )
}

/// The hub's operator overview (presence + watermarks + the planned-
/// unavailability faces).
pub async fn overview(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
) -> interflow_core::error::Result<interflow_mesh::hub::policy::HubOverview> {
    let (cert, key) = control.client_paths();
    interflow_mesh::hub::policy::query_hub_overview(endpoint, &hub_certs.ca_path(), &cert, &key)
        .await
}

/// The hub's fleet snapshot (presence + `evicted_total` + the faces).
pub async fn snapshot(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
) -> interflow_core::error::Result<interflow_mesh::hub::snapshot::FleetSnapshotDoc> {
    let (cert, key) = control.client_paths();
    interflow_mesh::hub::snapshot::query_fleet_snapshot(endpoint, &hub_certs.ca_path(), &cert, &key)
        .await
}

/// The floor version clock's current reading (the immediate probe — no
/// `since`, no hold).
pub async fn floor_version(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
) -> interflow_core::error::Result<u64> {
    let (cert, key) = control.client_paths();
    // `since = current` can never hold a diverged answer, so probing via
    // the watch call with a zero hold exercises the same parse path the
    // GUI watcher uses.
    interflow_mesh::hub::policy::watch_floor_version(
        endpoint,
        &hub_certs.ca_path(),
        &cert,
        &key,
        0,
        0,
    )
    .await
}

/// One blocking-watch cycle of the floor version clock: holds until the
/// version diverges from `since` or `wait_secs` elapses, then answers
/// with the current version (equality with `since` = nothing moved).
pub async fn watch_floor_version(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    since: u64,
    wait_secs: u64,
) -> interflow_core::error::Result<u64> {
    let (cert, key) = control.client_paths();
    interflow_mesh::hub::policy::watch_floor_version(
        endpoint,
        &hub_certs.ca_path(),
        &cert,
        &key,
        since,
        wait_secs,
    )
    .await
}

/// Queues one pause op for `agent`'s stream `name` (the operator verb's
/// hub half; the node applies it on its next intent exchange).
pub async fn pause_stream(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    agent: &str,
    name: &str,
) -> interflow_core::error::Result<()> {
    let (cert, key) = control.client_paths();
    interflow_mesh::hub::stream_intents::queue_op(
        endpoint,
        &hub_certs.ca_path(),
        &cert,
        &key,
        agent,
        &interflow_core::tunnel::transport::StreamIntentOp::Pause {
            name: name.to_string(),
        },
    )
    .await
    .map(|_| ())
}

/// Queues one resume op.
pub async fn resume_stream(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    agent: &str,
    name: &str,
) -> interflow_core::error::Result<()> {
    let (cert, key) = control.client_paths();
    interflow_mesh::hub::stream_intents::queue_op(
        endpoint,
        &hub_certs.ca_path(),
        &cert,
        &key,
        agent,
        &interflow_core::tunnel::transport::StreamIntentOp::Resume {
            name: name.to_string(),
        },
    )
    .await
    .map(|_| ())
}

/// Declares / lifts node maintenance.
pub async fn set_maintenance(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    agent: &str,
    on: bool,
) -> interflow_core::error::Result<String> {
    let (cert, key) = control.client_paths();
    interflow_mesh::hub::maintenance::set_maintenance(
        endpoint,
        &hub_certs.ca_path(),
        &cert,
        &key,
        agent,
        on,
    )
    .await
}

/// Whether the hub's snapshot face reports `agent` with `name` paused.
/// The snapshot (not the policy-floor overview) is the face tests read:
/// it answers on every hub, including testkit hubs that carry no policy
/// channel (the overview's agents array rides `/policy/floor`).
pub async fn reports_paused(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    agent: &str,
    name: &str,
) -> bool {
    match snapshot(endpoint, hub_certs, control).await {
        Ok(doc) => doc.agents.iter().any(|row| {
            row.agent == agent
                && row
                    .paused_streams
                    .as_ref()
                    .is_some_and(|paused| paused.iter().any(|p| p == name))
        }),
        Err(_) => false,
    }
}

/// Waits (bounded) until the hub's reported face shows `agent`'s stream
/// `name` in the given pause state — the CLI verb's convergence
/// condition, at test cadence.
pub async fn wait_stream_pause_state(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    agent: &str,
    name: &str,
    paused: bool,
    what: &'static str,
) {
    eventually_async(what, Duration::from_secs(25), || async {
        let shows = reports_paused(endpoint, hub_certs, control, agent, name).await;
        (shows == paused).then_some(()).ok_or_else(|| {
            format!(
                "face does not report {name} {} yet",
                if paused { "paused" } else { "unpaused" }
            )
        })
    })
    .await;
}

/// Whether the snapshot carries the maintenance declaration for `agent`.
pub async fn reports_maintenance(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    agent: &str,
) -> Option<bool> {
    snapshot(endpoint, hub_certs, control)
        .await
        .ok()?
        .agents
        .into_iter()
        .find(|row| row.agent == agent)
        // A present row with no maintenance key IS "not declared" (the
        // field is additive-optional); `None` is reserved for "no row".
        .map(|row| row.maintenance.unwrap_or(false))
}

/// Waits (bounded) until the hub face reports `agent`'s maintenance state.
pub async fn wait_maintenance(
    endpoint: &str,
    hub_certs: &TestCerts,
    control: &TestCerts,
    agent: &str,
    on: bool,
    what: &'static str,
) {
    eventually_async(what, Duration::from_secs(15), || async {
        let shows = reports_maintenance(endpoint, hub_certs, control, agent).await;
        shows
            .is_some_and(|declared| declared == on)
            .then_some(())
            .ok_or_else(|| format!("face does not report maintenance={on} yet (got {shows:?})"))
    })
    .await;
}

/// The hub's `evicted_total` straight from the snapshot face (the
/// acceptance window's "this number did not move").
pub async fn evicted_total(endpoint: &str, hub_certs: &TestCerts, control: &TestCerts) -> u64 {
    snapshot(endpoint, hub_certs, control)
        .await
        .map(|doc| doc.hub.evicted_total)
        .unwrap_or(u64::MAX)
}

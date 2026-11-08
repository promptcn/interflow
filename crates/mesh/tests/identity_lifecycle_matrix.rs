//! Identity-plane lifecycle matrix — the registrar/renewal/CRL face
//! organized BY MIGRATION EVENT, the way `e2e_lifecycle_matrix.rs` does it
//! for the mesh data plane
//! ((internal design notes); the mesh
//! method: "the bug clusters were not feature logic errors but invariant
//! failures on migration events — feature-organized e2e existed,
//! event-organized coverage did not").
//!
//! This module doc IS the matrix (living documentation beside the code it
//! locks). Every row names its invariant and either the test(s) that
//! lock it or an explicit, reasoned exemption. Cross-crate "Locked by"
//! entries are deliberate: the identity plane has no single host crate.
//!
//! | # | Migration event | Invariant | Locked by |
//! |---|---|---|---|
//! | 1 | Registrar unreachable (connection refused) when the 50% renewal window opens, gone across several ladder rungs, back at the same address | The backoff ladder keeps retrying (never gives up, never spaces the CRL polls); nothing fails closed early (expiry and the CRL bound both ahead); the first attempt after revival converges in one pass (one rotation, one `rotation_succeeded`, CRL lane healed) | `renewal/tests/registrar_absence.rs::registrar_unreachable_across_the_window_backs_off_and_converges_on_revival` (real kill + revival on the same port/issuer via `RegistrarFixtureOptions::revive`); the up-but-503 shape: `renewal/tests/scheduler.rs::failed_renewals_back_off_then_recover`; the error class: `::unreachable_registrar_maps_to_connection_error` |
//! | 2 | Registrar absent or refusing past the 10% warning band, on to leaf expiry | The warning is observable and follows the ladder; at expiry the node STOPS SERVING (fail-closed) rather than running on an expired leaf; the hub refuses an expired leaf at every new handshake | Warning: `scheduler.rs::less_than_ten_percent_ttl_logs_the_expiry_warning` (refusing registrar), `scheduler_clock_skew.rs::slow_clock_keeps_warning_after_backoff_and_fails_closed_skew_late` (order under skew). Scheduler fail-closed: `scheduler.rs::expired_credentials_fail_closed`. Node + hub, real time: **this file** `expired_leaf_is_refused_by_the_hub_and_the_node_fails_closed` — the node exits within one poll interval (≤ `CRL_POLL`) of the real expiry through the production `run_agent` wiring; new handshakes with the expired leaf are refused by the hub's TLS plane; fresh material is accepted. Physics note: TOTAL unreachability cannot reach the band on leaves longer than ~2.5h — the CRL freshness bound (row 3, 1h) fails closed first; the band shape is therefore locked with a reachable-but-refusing registrar, which is also the deployment shape that produces it. |
//! | 3 | CRL pulls failing — short of, then beyond, the 1h freshness bound | Beyond the bound: fail-closed ("refusing unrevocable credentials"); short of it: polls keep cadence, the face counts failures and freezes its confirmation instant; on recovery the instant advances and the loop carries on (no restart); the bound reads the monotonic clock | `scheduler.rs::crl_pull_failures_beyond_one_hour_fail_closed` (real registrar, `FaultPoint::Crls`), `::crl_pull_recovers_before_the_bound_without_failing_closed`, `::crl_poll_face_counts_failures_and_freezes_recency`, `::crl_poll_face_advances_on_no_change_polls`; the axis: `scheduler_clock_skew.rs::crl_staleness_bound_follows_the_monotonic_clock_not_the_wall`; hub-side classification: `mesh/tests/crl_poll_face_level.rs` |
//! | 4 | Supervisor restart loop (renewal completes → clean exit → restart onto the new material → next cycle) | Material advances monotonically per cycle; the post-rotation restart settles onto the bumped CRL fast (no storm: bounded `ran_for` per segment shape); traffic is served on each selected generation; old material is refused at the handshake | `mesh/tests/renewal_supervisor_restart.rs::renewal_exits_onto_supervisor_restart_with_new_material` (renewal-exit → CRL-exit → renewal-exit on real 45s leaves); `mesh/tests/rotate_transition.rs::rotate_transition_window_rejects_old_pack_and_serves_new` (old pack refused, new served, same window) |
//! | 5 | Enroll race — one code, many concurrent clients | Exactly one client is issued a leaf; the rest are refused in the 400 class with the "already been used" reason; the ledger shows the code spent once; other codes are unaffected | `registrar/tests/http.rs::concurrent_enrolls_with_one_code_admit_exactly_one` (8 racers released by a barrier). **Exemption — cross-process race:** `EnrollmentCodes::consume` serializes through a process-wide mutex; its file lock is not held across the read-modify-write (`registrar/src/service.rs` `load_locked`/`save_locked`). The deployment shape is one registrar process per issuer store, where the invariant holds; two registrar processes sharing a store is not a supported topology — if it becomes one, that is a new row with its own test, not a gap in this one. |
//! | 6 | Two hub generations overlapping | — inherits **G6**, deliberately not re-ledgered here | G6 (parked until the real migration window) |
//! | 7 | Credential-material churn under soak (registrar absence, renewal failure, CRL stall as soak phases) | — inherits **G7** (same doc); adjacent, not overlapping: (internal design notes) is VISITOR-identity churn, G7 is MATERIAL churn | G7 (evaluated when the soak harness grows a registrar role) |
//!
//! Supporting locks already in place (the inventory's starting point, not
//! re-done): expiry phasing on the fleet face (`credential_expiry_face.rs`,
//! both transports), revocation taking effect without a restart
//! (`crl_hot_swap.rs`), a revoked ledger self-healing onto the bootstrap
//! identity (`revoked_ledger_selfheal.rs`), the registrar's HTTP contract
//! (`registrar/tests/http.rs`: anonymous renew refused, injected 503 then
//! recovery, enroll→renew→confirm over mTLS), and the ambient-proxy
//! refusal sweep (433bc12).
//!
//! # Clock-skew arbitration points
//!
//! Companion to (internal design notes)
//! (route 1 delivered; route 2 — a Clock seam in the engines — declined,
//! route 3 — process-level fake time — rejected). Every time-anchored
//! decision, which clock it reads, and how that is pinned:
//!
//! | Decision | Clock | Pinned by |
//! |---|---|---|
//! | Renewal 50% threshold | wall | `scheduler_clock_skew.rs::slow_clock_renews_at_half_of_its_own_view`, `::fast_clock_inside_the_half_renews_on_the_first_pass`, `::renewal_threshold_follows_the_wall_clock_not_the_monotonic` |
//! | 10% warning band | wall | `::slow_clock_keeps_warning_after_backoff_and_fails_closed_skew_late` (order and reachability under skew) |
//! | Leaf expiry fail-closed (scheduler) | wall | `::fast_clock_past_the_leaf_fails_closed_before_any_renewal` (ahead: early, conservative), `::slow_clock_keeps_warning_…` (behind: exactly |skew| late — the bounded overshoot a slow host pays; the hub's own clock refuses the leaf at the real expiry) |
//! | CRL freshness bound | monotonic | `::crl_staleness_bound_follows_the_monotonic_clock_not_the_wall` (wall steps of either direction invisible; monotonic alone trips it). **Offset skew exempt by construction**: a monotonic difference never sees the wall at all. |
//! | Renewed material's validity | the REGISTRAR's wall | `assert_fresh_leaf_is_issuer_anchored` in every skew case — skew moves WHEN the scheduler acts, never WHAT it receives |
//! | Hub heartbeat liveness / route leases | hub-local monotonic (`Instant::elapsed`) / circuit-bound | **Exempt**: single-clock by construction; no cross-host comparison exists to skew |
//! | Hub credential-expiry phasing (`heartbeat.rs`) | hub wall vs. certificate absolute time | **Exempt**: observability only (audit + log); no gate. See the observation below. |
//! | Hub CRL-liveness "silent" classification (`CRL_SILENT_AFTER_SECS`) | agent-reported wall vs. hub wall | **Exempt**: observability only; `note_success` is `fetch_max` (backward steps cannot regress it) |
//! | TLS leaf validation (hub acceptor, registrar mTLS) | each end's real clock | **Exempt by design**: the trust anchor is deliberately not injectable; it is also the backstop that bounds the slow-host overshoot above |
//! | QUIC transport timers | quinn-internal | Non-goal (no security arbitration) |
//!
//! # Observations recorded by this inventory (not changed here)
//!
//! - **The hub does not pre-empt an established session whose leaf has
//!   expired.** Its heartbeat tick classifies the phase and audits/logs
//!   ("the node will stop serving at expiry"), relying on the node's own
//!   fail-closed; new handshakes are refused by the TLS plane. The
//!   unserved-on-expired-leaf window is therefore bounded by the node's
//!   poll cadence (≤ `CRL_POLL` = 60s), which the row-2 test pins. Whether
//!   the hub should ALSO evict at expiry is a design question for its own
//!   ledger entry; this matrix records the current contract honestly.
//! - **A 1h leaf's warning band (6m) is narrower than the ladder's top rung
//!   (15m):** under a persistently refusing registrar, gate-open passes can
//!   skip the band entirely and no warning is emitted. The warning fires
//!   only on gate-open passes by implementation choice. Observability
//!   improvement candidate; the 24h-leaf tests choose their TTL for this
//!   reason.
//!
//! Budget discipline as in the mesh matrix: the real-time case here is
//! bounded by one leaf lifetime plus one poll interval (~90s on 45s
//! leaves); the fake-time rows live in `renewal/tests/` and cost seconds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::{IssuerStore, LeafTtl};
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config, run_agent};
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Leaf TTL under identity's `short-leaf-ttl` test feature (the floor is
/// 30s; 45s leaves the hub and agents time to come up before the 50%
/// line at 22.5s).
const LEAF_TTL: i64 = 45;

/// The renewal loop's poll cadence: the bound on how long after the real
/// expiry the node's own fail-closed can land (the expiry check runs at
/// the top of each pass; the pass sleeps at most this long).
const POLL_BOUND: Duration = interflow_renewal::CRL_POLL;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn earliest_expiry(pack_dir: &Path) -> OffsetDateTime {
    let pack = CredentialPack::load_runtime(pack_dir).unwrap();
    ActiveCredentialSet::load_or_bootstrap(&pack)
        .unwrap()
        .earliest_expiry()
        .unwrap()
}

/// One echo roundtrip through the live ingress→hub→egress path, retried
/// for `window`.
async fn echoed_roundtrip(listen_port: u16, window: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let attempt = tokio::time::timeout(Duration::from_secs(5), async {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
                .await
                .ok()?;
            client.write_all(b"identity-matrix").await.ok()?;
            let mut echoed = vec![0u8; b"identity-matrix".len()];
            client.read_exact(&mut echoed).await.ok()?;
            Some(echoed)
        })
        .await;
        if let Some(echoed) = attempt.ok().flatten() {
            assert_eq!(echoed, b"identity-matrix");
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A bare mTLS handshake against the hub with the pack's leaf — the
/// hub's TLS-plane verdict on that material, nothing else (no
/// registration). `Ok` = the hub accepted the client certificate and
/// kept the connection; `Err` = refused (the same probe shape as
/// `rotate_transition.rs`).
async fn mtls_handshake_dial(hub_port: u16, pack_dir: &Path) -> Result<(), String> {
    let pack_dir = pack_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let entry = active.entries.values().next().unwrap();
        let ca_pem = pack
            .trust
            .issuers
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let dir = tempfile::tempdir().unwrap();
        let (ca, crt, key) = (
            dir.path().join("ca.pem"),
            dir.path().join("c.crt"),
            dir.path().join("c.key"),
        );
        std::fs::write(&ca, &ca_pem).unwrap();
        std::fs::write(&crt, &entry.cert_pem).unwrap();
        std::fs::write(&key, &entry.key_pem).unwrap();
        let config = interflow_core::tls::client::build_client_config(
            None,
            Some(&ca.display().to_string()),
            Some(&crt.display().to_string()),
            Some(&key.display().to_string()),
            &["h2"],
        )
        .map_err(|e| e.to_string())?;
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_owned())
            .map_err(|e| e.to_string())?;
        let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
            .map_err(|e| e.to_string())?;
        let addr: std::net::SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();
        let mut sock = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
        while conn.is_handshaking() {
            if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
                return Err("handshake write failed".to_owned());
            }
            if conn.wants_read() && conn.read_tls(&mut sock).is_err() {
                return Err("handshake read failed — the peer closed on us".to_owned());
            }
            if let Err(e) = conn.process_new_packets() {
                return Err(e.to_string());
            }
        }
        // Flush the final flight (TLS 1.3: the client's Finished carries
        // its certificate), then see whether the server keeps us.
        if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
            return Err("final flight write failed".to_owned());
        }
        let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 512];
        match std::io::Read::read(&mut sock, &mut buf) {
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(format!("post-handshake read failed: {e}")),
            Ok(0) => Err("the peer closed the connection right after the handshake".to_owned()),
            Ok(n) => match conn.read_tls(&mut &buf[..n]).map_err(|e| e.to_string()) {
                Ok(_) => conn
                    .process_new_packets()
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            },
        }
    })
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Row 2: registrar absent past the band, leaf expires — the node stops
// serving within one poll interval of the real expiry (production
// run_agent wiring), the hub refuses the expired leaf at every new
// handshake, fresh material is accepted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_leaf_is_refused_by_the_hub_and_the_node_fails_closed() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let listen_port = free_port();

    // The far-end service behind lan-b.
    let echo = tokio::net::TcpListener::bind(("127.0.0.1", echo_port))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // The registrar issues 45s leaves; it will be gone when the node's
    // renewal window opens.
    let registrar = interflow_testkit::registrar::spawn_registrar(
        interflow_testkit::registrar::RegistrarFixtureOptions {
            ttl: LeafTtl::from_seconds(LEAF_TTL).unwrap(),
            ..interflow_testkit::registrar::RegistrarFixtureOptions::default()
        },
    )
    .await;
    registrar.wait_ready().await;
    let registrar_endpoint = registrar.endpoint().to_owned();
    let issuer = IssuerStore::open(registrar.issuer_dir());
    let dir = tempfile::tempdir().unwrap();

    // One declaration, two leaf lifetimes: the agents under test live on
    // 45s leaves; the hub renders from the same declaration at 1h so ITS
    // certificate stays valid for the whole case — otherwise a client
    // refusing the hub's expired server cert would be indistinguishable
    // from the hub refusing the client's expired leaf, and the row-2
    // assertion is about the latter.
    let declaration = |leaf_ttl: &str, newcomer: &str| {
        Manifest::parse(&format!(
            r#"
[realm]
id = "test"
[identity]
leaf_ttl = "{leaf_ttl}"
[registrar]
endpoint = "{registrar_endpoint}"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.main]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_port}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
{newcomer}"#
        ))
        .unwrap()
    };
    let manifest = declaration("45s", "");
    let hub_manifest = declaration("1h", "");

    // Hub: environment (manual assembly, no scheduler of its own), on the
    // long-lived leaf.
    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &hub_manifest, "central", 1, &hub_dir).unwrap();
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // lan-b: the far-end agent (manual assembly, lives for the test).
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();
    let agent_b = {
        let pack = CredentialPack::load_runtime(&pack_dir_b).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, &pack_dir_b).unwrap();
        AgentClient::new(config).unwrap().start()
    };

    // lan-a: the node under test, on the production run_agent wiring.
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();
    let expiry = earliest_expiry(&pack_dir_a);
    // Prime the CRL first-write exit so the supervised run below is a pure
    // lifecycle cycle (the same priming renewal_supervisor_restart does).
    interflow_renewal::renewal_scheduler(
        &pack_dir_a,
        std::sync::Arc::new(interflow_renewal::CrlPollFace::new()),
    )
    .await
    .unwrap();

    // The hub accepts the valid leaf at the handshake (the baseline the
    // refusal below is measured against).
    mtls_handshake_dial(hub_port, &pack_dir_a)
        .await
        .expect("a valid leaf is accepted");

    // The registrar goes away for good before the window opens: renewal
    // attempts will fail in the connection class, the ladder will back off,
    // and the leaf will expire un-renewed.
    registrar.kill();

    let node_pack = pack_dir_a.clone();
    let node = tokio::spawn(async move { run_agent(&node_pack).await });
    assert!(
        echoed_roundtrip(listen_port, Duration::from_secs(10)).await,
        "the node serves traffic on its valid leaf"
    );

    // Fail-closed: the node's run ends in the expiry error, no earlier
    // than the real expiry and no later than one poll interval past it.
    let budget = Duration::from_secs(u64::try_from(LEAF_TTL).unwrap())
        + POLL_BOUND
        + Duration::from_secs(30);
    let exit = tokio::time::timeout(budget, node)
        .await
        .expect("the node stops within one poll interval of expiry")
        .unwrap();
    let exited_at = OffsetDateTime::now_utc();
    let err = exit.expect_err("an expired leaf ends the node's run");
    assert!(
        err.to_string().contains("active credential expired"),
        "the exit names the cause: {err}"
    );
    assert!(
        exited_at >= expiry,
        "fail-closed never pre-empts a valid leaf: exited {exited_at}, expiry {expiry}"
    );
    let late_by = exited_at - expiry;
    assert!(
        late_by <= time::Duration::try_from(POLL_BOUND).unwrap() + time::Duration::seconds(15),
        "fail-closed lands within one poll interval of the real expiry: late by {late_by}"
    );

    // The hub's verdict on the expired material: refused at the handshake.
    // The hub's own certificate is valid for an hour, so this is the
    // SERVER's refusal of the client leaf, not the client's of the server.
    let refused = mtls_handshake_dial(hub_port, &pack_dir_a)
        .await
        .expect_err("the hub must refuse an expired leaf at the handshake");
    assert!(
        !refused.contains("invalid peer certificate"),
        "the refusal must be the hub's verdict on the client leaf, not the client's on the \
         hub's certificate: {refused}"
    );

    // Fresh material from the same issuer is accepted — the refusal was
    // about the leaf, not the realm. A NEW principal is the honest probe:
    // re-rendering lan-a reuses its persisted identity material (a
    // re-render does not re-sign identity; renewal/rotate do), so it would
    // present the very leaf that just expired.
    let manifest_with_newcomer = declaration(
        "45s",
        "[agent.lan-c]\nworkspace = \"main\"\n[[agent.lan-c.mesh_egress]]\nname = \"svc\"\ntarget_addr = \"127.0.0.1:1\"\n",
    );
    let pack_dir_fresh = dir.path().join("packs/agent-lan-c");
    AgentCredentialPack::render(
        &issuer,
        &manifest_with_newcomer,
        "lan-c",
        1,
        &pack_dir_fresh,
    )
    .unwrap();
    assert!(
        earliest_expiry(&pack_dir_fresh) > OffsetDateTime::now_utc(),
        "the newcomer's leaf is freshly issued"
    );
    mtls_handshake_dial(hub_port, &pack_dir_fresh)
        .await
        .expect("fresh material from the same issuer is accepted");

    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}

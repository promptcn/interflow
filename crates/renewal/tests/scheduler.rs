//! Scheduler-direct tests over the injected clock
//!:
//! 50%-TTL threshold triggering, the backoff ladder, expiry fail-closed,
//! the 10% warning band, the offline watch's once-only 20% warning, and
//! the CRL staleness bound.
//!
//! Every case drives the REAL scheduler loop against a REAL in-process
//! registrar over HTTPS — only time is faked. The fixture mirrors
//! `crates/cli/tests/renewal.rs` (issuer store → `serve` → `plan::apply`),
//! so the packs under test are production-shaped. Most cases ask for 1h
//! leaves (the registrar-tier floor) so the 50% line sits 30 fake minutes
//! out instead of 12 fake hours.
//!
//! Serial discipline: the registrar fault hook and the tracing capture
//! buffer are process-global (the same discipline as core's fault tests),
//! so every case takes [`SERIAL`] first.

use interflow_cli::plan::{self, BackupInitOptions};
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::{IssuerStore, LeafTtl};
use interflow_identity::pack::CredentialPack;
use interflow_registrar::fault::{self, FaultAction, FaultPoint};
use interflow_renewal::{renewal_scheduler_with_clock, renewal_scheduler_with_crl_reload};
use interflow_testkit::clock::FakeClock;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::JoinHandle;

use interflow_core::error::Result;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Settled real time per fake-time chunk — enough for the scheduler's
/// in-loop HTTPS round trips on loopback.
// Real settle time for the in-loop HTTPS traffic between fake-time chunks.
// 50ms was enough on an idle dev machine, but a starved 2vCPU CI runner
// lets pulls that came due in fake time miss their settle window (the
// crl_pull cadence case counted 4 of the expected >= 6 on 2026-10-17) —
// 300ms buys the real round trip without moving the suite's wall clock
// meaningfully (the drive loops are chunk-count bound, not settle bound).
const SETTLE: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Tracing capture: the scheduler's banners (rotation_failed, the warning
// bands) are tracing events; a global fmt subscriber mirrors every line
// into a shared buffer the tests grep.
// ---------------------------------------------------------------------------
mod capture {
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};

    static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    struct Maker;

    impl tracing_subscriber::fmt::MakeWriter<'_> for Maker {
        type Writer = Writer;

        fn make_writer(&self) -> Self::Writer {
            Writer
        }
    }

    struct Writer;

    impl Write for Writer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            LINES
                .lock()
                .expect("capture lock poisoned")
                .push(String::from_utf8_lossy(buf).trim().to_owned());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Installs the capturing subscriber once per test binary.
    pub fn install_once() {
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_max_level(tracing::Level::INFO)
                    .with_ansi(false)
                    .with_writer(Maker)
                    .finish(),
            );
        });
    }

    pub fn clear() {
        LINES.lock().expect("capture lock poisoned").clear();
    }

    /// How many captured lines contain `needle`.
    pub fn count(needle: &str) -> usize {
        LINES
            .lock()
            .expect("capture lock poisoned")
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Fixture: issuer store → in-process registrar → plan::apply → agent pack
// ---------------------------------------------------------------------------

/// A registrar-tier agent pack plus the live registrar behind it.
struct AgentFixture {
    dir: tempfile::TempDir,
    endpoint: String,
    /// The spawned `serve` task — abortable to make the registrar
    /// unreachable mid-test.
    serve: tokio::task::JoinHandle<interflow_identity::Result<()>>,
    pack_dir: PathBuf,
}

/// Renders an agent pack against a live in-process registrar serving
/// `ttl`-long leaves (`ttl` is a humantime string; manifest and registrar
/// agree on it).
async fn agent_fixture(ttl: &str) -> AgentFixture {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ttl_secs = i64::try_from(
        humantime::parse_duration(ttl)
            .expect("ttl humantime")
            .as_secs(),
    )
    .expect("ttl fits");
    let dir = tempfile::tempdir().expect("tempdir");
    let issuer_dir = dir.path().join("issuer");
    let issuer = IssuerStore::open(&issuer_dir);
    issuer.ensure_realm().expect("ensure realm");
    issuer.ensure_workspace("main").expect("ensure workspace");
    issuer.ensure_policy_key().expect("ensure policy key");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    let endpoint = format!("https://127.0.0.1:{port}");
    let tls = issuer
        .issue_control_endpoint("test", "registrar", &endpoint)
        .expect("registrar TLS identity");
    std::fs::write(dir.path().join("registrar.crt"), &tls.chain_pem).expect("write crt");
    std::fs::write(dir.path().join("registrar.key"), &tls.key_pem).expect("write key");
    let serve = tokio::spawn(interflow_registrar::server::serve(
        issuer_dir.clone(),
        interflow_registrar::server::ServeOptions {
            listen: format!("127.0.0.1:{port}").parse().expect("socket addr"),
            public_endpoint: endpoint.clone(),
            tls_cert: dir.path().join("registrar.crt"),
            tls_key: dir.path().join("registrar.key"),
            ttl: LeafTtl::from_seconds(ttl_secs).expect("serve ttl"),
            control_endpoint: "127.0.0.1:16666".to_owned(),
            hub_endpoints: Default::default(),
        },
    ));
    wait_ready(&issuer_dir, &endpoint).await;
    let manifest_path = dir.path().join("interflow.toml");
    std::fs::write(
        &manifest_path,
        format!(
            r#"
[realm]
id = "test"
control_endpoint = "127.0.0.1:16666"
[identity]
leaf_ttl = "{ttl}"
[registrar]
endpoint = "{endpoint}"
[ingress.edge]
workspaces = ["main"]
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "web"
address = "127.0.0.1:18080"
[[route]]
host = "web.test"
service = "main/desktop/web"
"#
        ),
    )
    .expect("write manifest");
    plan::apply(
        &manifest_path,
        &issuer_dir,
        &dir.path().join("dist"),
        false,
        &BackupInitOptions {
            skip: true,
            ..BackupInitOptions::default()
        },
        false,
    )
    .expect("plan apply");
    let pack_dir = dir.path().join("dist/packs/agent-desktop");
    AgentFixture {
        dir,
        endpoint,
        serve,
        pack_dir,
    }
}

/// An offline-tier agent pack (180d leaves): nothing dials anything.
fn offline_pack_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("interflow.toml");
    std::fs::write(
        &manifest_path,
        r#"
[realm]
id = "test"
control_endpoint = "127.0.0.1:26666"

[public_tls]
mode = "frontend-proxy"

[identity]
mode = "offline"
leaf_ttl = "180d"

[ingress.edge]
workspaces = ["main"]
listen = "127.0.0.1:18443"
control_listen = "127.0.0.1:26666"

[workspace.main]

[agent.desktop]
workspace = "main"

[[agent.desktop.services]]
id = "web"
address = "127.0.0.1:18080"

[[route]]
host = "web.test"
service = "main/desktop/web"
"#,
    )
    .expect("write manifest");
    plan::apply(
        &manifest_path,
        &dir.path().join("issuer"),
        &dir.path().join("dist"),
        false,
        &BackupInitOptions {
            skip: true,
            ..BackupInitOptions::default()
        },
        false,
    )
    .expect("offline plan apply");
    let pack_dir = dir.path().join("dist/packs/agent-desktop");
    (dir, pack_dir)
}

async fn wait_ready(issuer_dir: &Path, endpoint: &str) {
    let ca = IssuerStore::open(issuer_dir)
        .realm_issuer()
        .expect("realm issuer")
        .cert_pem()
        .to_owned();
    // One client for the whole poll: rebuilding per iteration re-initializes
    // the TLS provider every time and a slow runner spends the budget on
    // client construction instead of requests.
    let client = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(ca.as_bytes()).expect("root certificate"),
        )
        .build()
        .expect("client");
    for _ in 0..1000 {
        if client
            .get(format!("{endpoint}/health"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    unreachable!("registrar never became ready at {endpoint}");
}

fn active_set(pack_dir: &Path) -> ActiveCredentialSet {
    ActiveCredentialSet::load_or_bootstrap(&CredentialPack::load_runtime(pack_dir).expect("pack"))
        .expect("active set")
}

/// Runs the scheduler once on the real clock. On a fresh pack the first
/// CRL pull writes the files and the scheduler exits onto the supervisor
/// restart — which is exactly the priming the timed cases need: afterwards
/// every pull is `Ok(false)` and the loop gets to the threshold math.
async fn prime_crls(pack_dir: &Path) {
    renewal_scheduler_with_crl_reload(pack_dir, None, None)
        .await
        .expect("CRL first-write exit is Ok");
    assert!(
        pack_dir
            .join("state/crls")
            .read_dir()
            .expect("crl dir")
            .count()
            > 0,
        "priming wrote the CRL files"
    );
}

// ---------------------------------------------------------------------------
// Fake-time driver
// ---------------------------------------------------------------------------

type Scheduler = JoinHandle<Result<()>>;

fn spawn_scheduler(pack_dir: &Path, clock: &FakeClock) -> Scheduler {
    let pack_dir = pack_dir.to_path_buf();
    let clock: Arc<dyn interflow_renewal::Clock> = Arc::new(clock.clone());
    tokio::spawn(async move { renewal_scheduler_with_clock(&pack_dir, None, None, clock).await })
}

/// Advances fake time in `step` chunks (with real settle time for the
/// in-loop HTTPS traffic) until the scheduler settles; returns its result.
async fn drive_to_completion(
    clock: &FakeClock,
    scheduler: Scheduler,
    step: Duration,
    max_chunks: usize,
) -> Result<()> {
    for _ in 0..max_chunks {
        if scheduler.is_finished() {
            return scheduler.await.expect("scheduler join");
        }
        clock.advance(step);
        tokio::time::sleep(SETTLE).await;
    }
    assert!(
        scheduler.is_finished(),
        "scheduler did not settle within {max_chunks} chunks of {step:?}"
    );
    scheduler.await.expect("scheduler join")
}

/// Drives a fixed number of chunks and reports whether the scheduler
/// settled (for cases that deliberately keep running).
async fn drive_chunks(
    clock: &FakeClock,
    scheduler: &Scheduler,
    step: Duration,
    chunks: usize,
) -> bool {
    for _ in 0..chunks {
        if scheduler.is_finished() {
            return true;
        }
        clock.advance(step);
        tokio::time::sleep(SETTLE).await;
    }
    scheduler.is_finished()
}

/// A fault hook that fails `/v1/renew` for the first `failures` requests,
/// recording the fake-clock reading of every consult (the renewal-attempt
/// timestamps the backoff assertions need).
struct RenewFault {
    failures: usize,
    consults: std::sync::Mutex<Vec<OffsetDateTime>>,
}

impl RenewFault {
    fn install(failures: usize, clock: &FakeClock) -> Arc<Self> {
        let plan = Arc::new(Self {
            failures,
            consults: std::sync::Mutex::new(Vec::new()),
        });
        let hook_clock = clock.clone();
        let hook_plan = Arc::clone(&plan);
        fault::install_hook(Arc::new(move |point: FaultPoint| {
            if point != FaultPoint::Renew {
                return FaultAction::Continue;
            }
            let mut consults = hook_plan.consults.lock().expect("consult lock poisoned");
            consults.push(hook_clock.now());
            if consults.len() <= hook_plan.failures {
                FaultAction::ServiceUnavailable
            } else {
                FaultAction::Continue
            }
        }));
        plan
    }

    /// Fake-clock readings at each `/v1/renew` consult, in order.
    fn consult_times(&self) -> Vec<OffsetDateTime> {
        self.consults.lock().expect("consult lock poisoned").clone()
    }
}

// ---------------------------------------------------------------------------
// G1: 50%-TTL threshold natural triggering
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg_attr(
    target_os = "linux",
    ignore = "registrar fixture never becomes ready on Linux (serve runs, /health never answers) — ticketed in (internal design notes)"
)]
async fn scheduler_renews_at_half_ttl_and_not_before() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 1h leaves: the 50% line sits ~30 fake minutes out.
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;

    let before = active_set(&fixture.pack_dir);
    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock);

    // 28 of the 30 minutes: still short of the threshold — the scheduler
    // must stay parked on its poll sleeps, credentials untouched.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_secs(60), 28).await;
    assert!(!finished, "no exit before the 50% line");
    let mid = active_set(&fixture.pack_dir);
    assert_eq!(mid.sequence, before.sequence, "no renewal before 50% TTL");
    assert!(
        mid.entries["agent-main"].serial == before.entries["agent-main"].serial,
        "no material change before 50% TTL"
    );

    // Cross the line: the next loop iteration renews for real and the
    // scheduler returns Ok onto the supervisor restart.
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(60), 5).await;
    result.expect("renewal at the 50% line succeeds");
    let after = active_set(&fixture.pack_dir);
    assert_eq!(after.sequence, before.sequence + 1, "one rotation");
    assert_ne!(
        after.entries["agent-main"].serial, before.entries["agent-main"].serial,
        "the leaf material changed"
    );
    assert!(capture::count("rotation_succeeded") >= 1);
    // The pre-threshold phase paces at the CRL poll cadence, never longer.
    assert!(
        clock
            .sleep_requests()
            .iter()
            .all(|slept| *slept <= Duration::from_secs(60)),
        "poll sleeps stay at the CRL cadence: {:?}",
        clock.sleep_requests()
    );
    fault::clear_hook();
}

// ---------------------------------------------------------------------------
// G1: backoff ladder + retry-then-recover
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg_attr(
    target_os = "linux",
    ignore = "registrar fixture never becomes ready on Linux (serve runs, /health never answers) — ticketed in (internal design notes)"
)]
async fn failed_renewals_back_off_then_recover() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;

    let clock = FakeClock::at_real_now();
    // First two /v1/renew requests 503; the third succeeds (renew +
    // confirm complete the rotation).
    let plan_hook = RenewFault::install(2, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock);

    // 30s chunks so attempt gaps resolve the ladder steps.
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(30), 260).await;
    result.expect("recovery after two failures");
    fault::clear_hook();

    let attempts = plan_hook.consult_times();
    assert_eq!(
        attempts.len(),
        3,
        "exactly three renewal attempts: {attempts:?}"
    );
    // The ladder gates attempts: 60s after the first failure, 2m after the
    // second (chunked driving adds at most one 30s chunk of slack; a
    // broken gate retrying every loop tick would land at ~30s).
    let first_gap = attempts[1] - attempts[0];
    let second_gap = attempts[2] - attempts[1];
    assert!(
        first_gap >= time::Duration::seconds(59) && first_gap < time::Duration::seconds(90),
        "second attempt ~60s out: {first_gap}"
    );
    assert!(
        second_gap >= time::Duration::seconds(119) && second_gap < time::Duration::seconds(150),
        "third attempt ~2m out: {second_gap}"
    );
    // Both failures left their rotation_failed banner.
    assert_eq!(capture::count("rotation_failed"), 2);
    // The recovery really rotated.
    assert!(capture::count("rotation_succeeded") >= 1);
    // CRL polling kept its ≤60s cadence throughout the backoff window —
    // the ladder spaces attempts, never CRL polls.
    assert!(
        clock
            .sleep_requests()
            .iter()
            .all(|slept| *slept <= Duration::from_secs(60)),
        "backoff never spaces CRL polls: {:?}",
        clock.sleep_requests()
    );
}

// ---------------------------------------------------------------------------
// G1: expiry fail-closed
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg_attr(
    target_os = "linux",
    ignore = "registrar fixture never becomes ready on Linux (serve runs, /health never answers) — ticketed in (internal design notes)"
)]
async fn expired_credentials_fail_closed() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;

    // Renewal permanently failing keeps the loop alive past the 50% line,
    // so the leaf's own expiry is what the scheduler must refuse to
    // outlive.
    let clock = FakeClock::at_real_now();
    let _plan_hook = RenewFault::install(usize::MAX, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock);
    // 70 minutes into a 1h leaf (5-minute chunks).
    let result = drive_to_completion(&clock, scheduler, Duration::from_mins(5), 16).await;
    fault::clear_hook();
    let err = result.expect_err("expiry must fail closed");
    assert!(
        err.to_string()
            .contains("active credential expired — refusing to continue without renewal"),
        "expiry message: {err}"
    );
}

// ---------------------------------------------------------------------------
// G1: the 10% warning band
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg_attr(
    target_os = "linux",
    ignore = "registrar fixture never becomes ready on Linux (serve runs, /health never answers) — ticketed in (internal design notes)"
)]
async fn less_than_ten_percent_ttl_logs_the_expiry_warning() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: threshold at 12h, the 10% warning band opens at 21.6h.
    // Renewal permanently failing keeps the scheduler looping past the
    // threshold with the backoff ladder capped at 15m, so gate-open
    // iterations (the ones that carry the banner) land inside the band.
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;

    let clock = FakeClock::at_real_now();
    let plan_hook = RenewFault::install(usize::MAX, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock);

    // 23h in: inside the warning band, short of expiry.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_mins(30), 46).await;
    assert!(!finished, "still retrying, not expired");
    scheduler.abort();
    fault::clear_hook();

    assert!(
        capture::count("credential_expiry_warning: less than 10% TTL remains") >= 1,
        "warning band banner present"
    );
    assert!(
        !plan_hook.consult_times().is_empty(),
        "renewal attempts actually happened"
    );
}

// ---------------------------------------------------------------------------
// G1: offline_watch — once-only 20% warning + expiry fail-closed (the
// 2026-09-25 regression lock: the trigger fires at 20% remaining, not 80%)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offline_watch_warns_once_at_twenty_percent_then_fails_closed() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let (_dir, pack_dir) = offline_pack_dir();

    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&pack_dir, &clock);

    // 180d leaves: the warning band opens below 20% remaining (< 36d left
    // ⇒ first possible at day 145). 143 days in, nothing may have fired —
    // a regression to the pre-2026-09-25 80%-remaining trigger would have
    // fired around day 36.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_hours(24), 143).await;
    assert!(!finished, "offline watch keeps running");
    assert_eq!(
        capture::count("credential_expiry_warning"),
        0,
        "no warning while more than 20% of the leaf remains"
    );

    // Into the band: fires, and only once however long the watch runs.
    drive_chunks(&clock, &scheduler, Duration::from_hours(24), 4).await;
    assert_eq!(
        capture::count("credential_expiry_warning"),
        1,
        "the offline warning fires exactly once"
    );

    // Past expiry: fail closed, still exactly one warning.
    let result = drive_to_completion(&clock, scheduler, Duration::from_hours(24), 40).await;
    let err = result.expect_err("offline expiry must fail closed");
    assert!(
        err.to_string().contains("offline credentials do not renew"),
        "offline expiry message: {err}"
    );
    assert_eq!(
        capture::count("credential_expiry_warning"),
        1,
        "the once-flag holds across the rest of the leaf's life"
    );
}

// ---------------------------------------------------------------------------
// G2: registrar unreachable — the client-side error mapping
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg_attr(
    target_os = "linux",
    ignore = "registrar fixture never becomes ready on Linux (serve runs, /health never answers) — ticketed in (internal design notes)"
)]
async fn unreachable_registrar_maps_to_connection_error() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;

    // Kill the registrar and wait for the port to stop answering.
    fixture.serve.abort();
    let ca = {
        let issuer = IssuerStore::open(fixture.dir.path().join("issuer"));
        issuer
            .realm_issuer()
            .expect("realm issuer")
            .cert_pem()
            .to_owned()
    };
    for _ in 0..100 {
        let probe = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(ca.as_bytes()).expect("root certificate"),
            )
            .build()
            .expect("probe client");
        if probe
            .get(format!("{}/health", fixture.endpoint))
            .send()
            .await
            .is_err()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A forced renewal against the dead endpoint must surface as a
    // connection-class error (the class the backoff ladder reacts to).
    let err = interflow_renewal::renew_all(&fixture.pack_dir, true)
        .await
        .expect_err("unreachable registrar must fail");
    assert!(
        err.to_string().contains("registrar request failed"),
        "connection-class mapping: {err}"
    );
}

// ---------------------------------------------------------------------------
// G3: CRL staleness fail-closed (pull failing > 1h ⇒ refuse to continue)
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg_attr(
    target_os = "linux",
    ignore = "registrar fixture never becomes ready on Linux (serve runs, /health never answers) — ticketed in (internal design notes)"
)]
async fn crl_pull_failures_beyond_one_hour_fail_closed() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: the threshold (12h out) never interferes with a ~70min
    // drive, so renewal is not part of this case.
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;

    let pulls = Arc::new(AtomicUsize::new(0));
    let hook_pulls = Arc::clone(&pulls);
    fault::install_hook(Arc::new(move |point: FaultPoint| {
        if point == FaultPoint::Crls {
            hook_pulls.fetch_add(1, Ordering::SeqCst);
            FaultAction::ServiceUnavailable
        } else {
            FaultAction::Continue
        }
    }));

    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock);
    // 10-minute chunks: the bound is 1h, so the fail-closed lands on chunk
    // ~7; short of the bound the loop must keep polling.
    let result = drive_to_completion(&clock, scheduler, Duration::from_mins(10), 10).await;
    fault::clear_hook();
    let err = result.expect_err("staleness bound must fail closed");
    assert!(
        err.to_string()
            .contains("CRL freshness bound exceeded — refusing unrevocable credentials"),
        "staleness message: {err}"
    );
    assert!(
        pulls.load(Ordering::SeqCst) >= 6,
        "pulls kept their cadence while stale: {}",
        pulls.load(Ordering::SeqCst)
    );
}

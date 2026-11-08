//! Shared fixture for the renewal scheduler's fake-time test binaries
//! (`scheduler.rs`, `scheduler_clock_skew.rs`, `registrar_absence.rs`):
//! the issuer-store → in-process registrar → `plan::apply` pack pipeline,
//! the tracing capture buffer, the fake-clock driver and the registrar
//! fault hooks. One home, so every binary drives the REAL scheduler loop
//! against a REAL registrar over HTTPS with only time faked, and a fixture
//! change cannot leave one binary on a stale copy.
//!
//! Each integration-test binary compiles this module separately, so the
//! process-global statics here (the capture buffer, the serial mutex) are
//! per binary; under nextest every test is its own process anyway.
#![allow(dead_code, reason = "each test binary uses the subset it needs")]

use interflow_cli::plan::{self, BackupInitOptions};
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::pack::CredentialPack;
use interflow_registrar::fault::{self, FaultAction, FaultPoint};
use interflow_renewal::{
    CrlPollFace, renewal_scheduler_with_clock, renewal_scheduler_with_crl_reload,
};
use interflow_testkit::clock::FakeClock;
use interflow_testkit::registrar::{RegistrarFixture, RegistrarFixtureOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::task::JoinHandle;

use interflow_core::error::Result;

/// Serial discipline: the registrar fault hook and the tracing capture
/// buffer are process-global (the same discipline as core's fault tests),
/// so every case takes this first.
pub static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Real-time cap for one chunk's quiescence wait: a wake's processing is a
/// handful of loopback HTTPS round trips — anything approaching this is a
/// hang, not slowness, and must fail loudly instead of stalling the drive.
const SETTLE_CAP: Duration = Duration::from_secs(5);

/// Waits until the scheduler has finished whatever a wake started: either
/// the whole task completed, or every fake-clock sleep is re-parked beyond
/// the current fake time. Runner speed no longer influences which fake
/// chunk a consult lands in — the fixed real-time settles of the 2026-10
/// era let a slow container's round trips straddle a chunk boundary and
/// shifted attempt timestamps a whole chunk late (the backoff-ladder
/// assertions pay for exactly that).
pub async fn settle(clock: &FakeClock, scheduler: &Scheduler) {
    let cap = tokio::time::Instant::now() + SETTLE_CAP;
    loop {
        if scheduler.is_finished() || clock.all_parked_beyond_now() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < cap,
            "scheduler did not go quiescent within {SETTLE_CAP:?} of a chunk advance"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// Tracing capture: the scheduler's banners (rotation_failed, the warning
// bands) are tracing events; a global fmt subscriber mirrors every line
// into a shared buffer the tests grep.
// ---------------------------------------------------------------------------
pub mod capture {
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
            // Mirror to stderr: the buffer is only readable through the
            // assertions, so a fixture that never becomes ready needs the
            // stderr copy to be diagnosable under --nocapture (nextest
            // prints captured output on failure only).
            let _ = std::io::stderr().write_all(buf);
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

    /// Position of the first captured line containing `needle` — the
    /// ordering record (which banner came first).
    pub fn first_index(needle: &str) -> Option<usize> {
        LINES
            .lock()
            .expect("capture lock poisoned")
            .iter()
            .position(|line| line.contains(needle))
    }
}

// ---------------------------------------------------------------------------
// Fixture: issuer store → in-process registrar → plan::apply → agent pack
// ---------------------------------------------------------------------------

/// A registrar-tier agent pack plus the live registrar behind it.
pub struct AgentFixture {
    /// The live registrar (issuer provisioning, ready, killable).
    pub registrar: RegistrarFixture,
    /// Holds the manifest/dist tree alive for the test body.
    pub dir: tempfile::TempDir,
    pub pack_dir: PathBuf,
}

/// Renders an agent pack against a live in-process registrar serving
/// `ttl`-long leaves (`ttl` is a humantime string; manifest and registrar
/// agree on it).
pub async fn agent_fixture(ttl: &str) -> AgentFixture {
    agent_fixture_with(ttl, RegistrarFixtureOptions::default()).await
}

/// [`agent_fixture`] with explicit registrar options (`ttl` still rules;
/// the other fields — a fixed listen address, control endpoint — pass
/// through).
pub async fn agent_fixture_with(ttl: &str, options: RegistrarFixtureOptions) -> AgentFixture {
    let ttl_secs = i64::try_from(
        humantime::parse_duration(ttl)
            .expect("ttl humantime")
            .as_secs(),
    )
    .expect("ttl fits");
    let registrar = interflow_testkit::registrar::spawn_registrar(RegistrarFixtureOptions {
        ttl: interflow_identity::issuance::LeafTtl::from_seconds(ttl_secs).expect("serve ttl"),
        ..options
    })
    .await;
    registrar.wait_ready().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let endpoint = registrar.endpoint().to_owned();
    let issuer_dir = registrar.issuer_dir().to_owned();
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
        registrar,
        dir,
        pack_dir,
    }
}

/// An offline-tier agent pack (180d leaves): nothing dials anything.
pub fn offline_pack_dir() -> (tempfile::TempDir, PathBuf) {
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

pub fn active_set(pack_dir: &Path) -> ActiveCredentialSet {
    ActiveCredentialSet::load_or_bootstrap(&CredentialPack::load_runtime(pack_dir).expect("pack"))
        .expect("active set")
}

/// The real (issuer-clock) expiry of the pack's earliest-expiring leaf.
pub fn earliest_expiry(pack_dir: &Path) -> OffsetDateTime {
    active_set(pack_dir)
        .earliest_expiry()
        .expect("earliest expiry")
}

/// Runs the scheduler once on the real clock. On a fresh pack the first
/// CRL pull writes the files and the scheduler exits onto the supervisor
/// restart — which is exactly the priming the timed cases need: afterwards
/// every pull is `Ok(false)` and the loop gets to the threshold math.
pub async fn prime_crls(pack_dir: &Path) {
    renewal_scheduler_with_crl_reload(pack_dir, None, None, Arc::new(CrlPollFace::new()))
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

pub type Scheduler = JoinHandle<Result<()>>;

pub fn spawn_scheduler(pack_dir: &Path, clock: &FakeClock, face: &Arc<CrlPollFace>) -> Scheduler {
    let pack_dir = pack_dir.to_path_buf();
    let clock: Arc<dyn interflow_renewal::Clock> = Arc::new(clock.clone());
    let face = Arc::clone(face);
    tokio::spawn(async move {
        renewal_scheduler_with_clock(&pack_dir, None, None, clock, face, None).await
    })
}

/// Advances fake time in `step` chunks (with real settle time for the
/// in-loop HTTPS traffic) until the scheduler settles; returns its result.
pub async fn drive_to_completion(
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
        settle(clock, &scheduler).await;
    }
    assert!(
        scheduler.is_finished(),
        "scheduler did not settle within {max_chunks} chunks of {step:?}"
    );
    scheduler.await.expect("scheduler join")
}

/// Drives a fixed number of chunks and reports whether the scheduler
/// settled (for cases that deliberately keep running).
pub async fn drive_chunks(
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
        settle(clock, scheduler).await;
    }
    scheduler.is_finished()
}

/// A fault hook that fails `/v1/renew` for the first `failures` requests,
/// recording the fake-clock reading of every consult (the renewal-attempt
/// timestamps the backoff assertions need).
pub struct RenewFault {
    failures: usize,
    consults: std::sync::Mutex<Vec<OffsetDateTime>>,
}

impl RenewFault {
    pub fn install(failures: usize, clock: &FakeClock) -> Arc<Self> {
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
    pub fn consult_times(&self) -> Vec<OffsetDateTime> {
        self.consults.lock().expect("consult lock poisoned").clone()
    }
}

//! Deterministic fault injection for the registrar API surface.
//!
//! The renewal failure paths (client backoff, CRL staleness fail-closed,
//! retry-then-recover) need the *real* registrar to fail on demand — a
//! parallel mock server would drift from real behavior. Mirroring
//! `interflow-core`'s fault module, everything here is gated by the
//! `fault-injection` cargo feature:
//! - feature **off** (production builds): no hook can even be installed and
//!   the server-side consult compiles away — zero cost, zero surface;
//! - feature **on** (tests via dev-dependencies): each matching request
//!   consults the installed [`Hook`]; [`FaultAction::ServiceUnavailable`]
//!   turns the request into an HTTP 503.
//!
//! The hook is process-global: one test binary hosting several in-process
//! registrars must keep fault-using cases serialized (the same discipline as
//! core's fault tests).

/// One variant per faultable registrar endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// `POST /v1/renew`
    Renew,
    /// `POST /v1/renew-control`
    RenewControl,
    /// `POST /v1/confirm`
    Confirm,
    /// `POST /v1/confirm-control`
    ConfirmControl,
    /// `GET /v1/crls`
    Crls,
}

impl FaultPoint {
    /// The endpoint this point guards, as matched against the request path.
    const fn path(self) -> &'static str {
        match self {
            Self::Renew => "/v1/renew",
            Self::RenewControl => "/v1/renew-control",
            Self::Confirm => "/v1/confirm",
            Self::ConfirmControl => "/v1/confirm-control",
            Self::Crls => "/v1/crls",
        }
    }
}

/// What the installed plan wants for a request hitting the fault point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    /// Serve the request normally: the default whenever no hook is
    /// installed (and always when the feature is off).
    Continue,
    /// Answer with HTTP 503 before the handler runs.
    ServiceUnavailable,
}

/// Decision hook: consulted once per request whose path matches a
/// [`FaultPoint`].
///
/// Tests typically count consults (the closure runs on the request path,
/// so it can also snapshot clocks or state) and arm a bounded number of
/// failures.
pub type Hook = std::sync::Arc<dyn Fn(FaultPoint) -> FaultAction + Send + Sync + 'static>;

#[cfg(feature = "fault-injection")]
static HOOK: std::sync::RwLock<Option<Hook>> = std::sync::RwLock::new(None);

/// Installs (replaces) the decision hook. Replaceable rather than OnceLock
/// because one test binary hosts many serial test cases, each with its own
/// plan.
#[cfg(feature = "fault-injection")]
pub fn install_hook(hook: Hook) {
    let mut slot = HOOK.write().expect("fault hook lock poisoned");
    *slot = Some(hook);
}

/// Removes any installed hook (test teardown).
#[cfg(feature = "fault-injection")]
pub fn clear_hook() {
    let mut slot = HOOK.write().expect("fault hook lock poisoned");
    *slot = None;
}

#[cfg(feature = "fault-injection")]
fn action(point: FaultPoint) -> FaultAction {
    if let Some(hook) = HOOK.read().expect("fault hook lock poisoned").as_ref() {
        return hook(point);
    }
    FaultAction::Continue
}

/// Feature-off build: no hook can even be installed, so every request
/// continues. `const` so call sites fold away entirely at compile time.
#[cfg(not(feature = "fault-injection"))]
const fn action(_point: FaultPoint) -> FaultAction {
    FaultAction::Continue
}

/// Server-side consult: reports whether the request hitting `path` should
/// be failed with 503 before its handler runs.
pub(crate) fn should_fail(path: &str) -> bool {
    const POINTS: [FaultPoint; 5] = [
        FaultPoint::Renew,
        FaultPoint::RenewControl,
        FaultPoint::Confirm,
        FaultPoint::ConfirmControl,
        FaultPoint::Crls,
    ];
    POINTS
        .iter()
        .any(|point| point.path() == path && action(*point) == FaultAction::ServiceUnavailable)
}

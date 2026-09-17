//! Test-side fault plans: install point-targeted panics/stalls into
//! `interflow-core`'s injection call points, with a consumption log.
//!
//! Usage pattern (serial e2e tests — one plan per test case):
//!
//! ```ignore
//! let faults = fault::install(
//!     fault::FaultPlan::new().panic_at(fault::FaultPoint::H2UploadLoopAfterEstablish),
//! );
//! // ... run the stack, wait for the self-healing assertions ...
//! // Prove the injection actually fired (guards against vacuous greens):
//! assert!(faults.fired(fault::FaultPoint::H2UploadLoopAfterEstablish));
//! ```
//!
//! Every green assertion must be paired with a `fired` check: a test that
//! passes without the fault having fired is testing nothing.

use interflow_core::fault::{self, FaultAction, FaultPoint};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Which fault to inject at which point, and how many times.
#[derive(Default)]
pub struct FaultPlan {
    entries: HashMap<FaultPoint, (FaultAction, u32)>,
}

impl FaultPlan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Panic once when `point` is triggered.
    pub fn panic_at(mut self, point: FaultPoint) -> Self {
        self.entries.insert(point, (FaultAction::Panic, 1));
        self
    }

    /// Wedge (park forever) the call site the first time `point` is
    /// consulted.
    pub fn stall_at(mut self, point: FaultPoint) -> Self {
        self.entries.insert(point, (FaultAction::Stall, 1));
        self
    }
}

/// Consumption log for an installed plan: proves injections actually fired.
#[derive(Clone)]
pub struct FaultLog {
    fired: Arc<Mutex<Vec<FaultPoint>>>,
}

impl FaultLog {
    /// Whether the given point ever fired.
    pub fn fired(&self, point: FaultPoint) -> bool {
        self.fired
            .lock()
            .expect("fault log lock poisoned")
            .contains(&point)
    }
}

/// Installs (replaces) the global fault plan; returns the consumption log.
pub fn install(plan: FaultPlan) -> FaultLog {
    let fired = Arc::new(Mutex::new(Vec::new()));
    let log = FaultLog {
        fired: fired.clone(),
    };
    let entries = Arc::new(Mutex::new(plan.entries));
    fault::install_hook(Arc::new(move |point: FaultPoint| {
        let mut guard = entries.lock().expect("fault entries lock poisoned");
        let Some((action, remaining)) = guard.get_mut(&point) else {
            return FaultAction::Continue;
        };
        if *remaining == 0 {
            return FaultAction::Continue;
        }
        *remaining -= 1;
        let act = *action;
        drop(guard);
        fired.lock().expect("fault log lock poisoned").push(point);
        act
    }));
    log
}

/// Removes any installed plan (test teardown).
pub fn clear() {
    fault::clear_hook();
}

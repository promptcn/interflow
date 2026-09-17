//! Hub connection-level limiting: per-IP cap + global cap.
//!
//! Unlike [`crate::hub::rate_limit`] (per-IP request rate, against brute-force
//! token enumeration), this is connection-level: preventing a single IP from
//! overwhelming the hub and global resource exhaustion.
//!
//! Uses [`ConnGuard`]'s RAII: when a cap is exceeded,
//! [`ConnTracker::try_acquire`] returns `None` and the caller should
//! close/reject the new connection; the guard decrements the count
//! automatically on drop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Connection counter (shared, clone-friendly — no inner Arc because the
/// fields are already atomics/locks).
pub struct ConnTracker {
    inner: Mutex<HashMap<IpAddr, usize>>,
    total: AtomicUsize,
    /// Per-IP cap; 0 means unlimited.
    per_ip_limit: usize,
    /// Global cap; 0 means unlimited.
    total_limit: usize,
}

impl ConnTracker {
    /// Constructs. `per_ip_limit = 0` or `total_limit = 0` means that item is unlimited.
    pub fn new(per_ip_limit: usize, total_limit: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            total: AtomicUsize::new(0),
            per_ip_limit,
            total_limit,
        }
    }

    /// Tries to occupy one connection slot for `ip` (owned version; the guard holds an Arc and manages its own lifetime).
    ///
    /// `Some(guard)` means passed; `None` means over the cap and the caller
    /// should reject. Any partial counts already incremented are rolled back
    /// on failure.
    #[allow(clippy::significant_drop_tightening)]
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        // 1. Unconditionally increment the global count (total() is also the
        //    metrics gauge and shutdown-drain basis; it must reflect the real
        //    connection count even when no cap is configured)
        let prev = self.total.fetch_add(1, Ordering::AcqRel);
        if self.total_limit > 0 && prev >= self.total_limit {
            self.total.fetch_sub(1, Ordering::AcqRel);
            metrics::counter!("interflow_hub_conn_limit_denied", "scope" => "total").increment(1);
            return None;
        }

        // 2. Per-IP
        let ip_exceeded = if self.per_ip_limit > 0 {
            // Poison recovery by into_inner: the counters' invariants hold
            // by construction, so another thread's panic must not take the
            // limiter down with it.
            let mut map = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = map.entry(ip).or_insert(0);
            *entry += 1;
            if *entry > self.per_ip_limit {
                *entry -= 1;
                true
            } else {
                false
            }
        } else {
            false
        };

        if ip_exceeded {
            // Roll back the global count
            self.total.fetch_sub(1, Ordering::AcqRel);
            metrics::counter!("interflow_hub_conn_limit_denied", "scope" => "per_ip").increment(1);
            return None;
        }

        Some(ConnGuard {
            tracker: Arc::clone(self),
            ip,
            active: true,
        })
    }

    fn release(&self, ip: IpAddr) {
        self.total.fetch_sub(1, Ordering::AcqRel);
        if self.per_ip_limit > 0 {
            // Poison recovery by into_inner: the counters' invariants hold
            // by construction, so another thread's panic must not take the
            // limiter down with it.
            let mut map = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = map.get_mut(&ip) {
                *entry = entry.saturating_sub(1);
                if *entry == 0 {
                    map.remove(&ip);
                }
            }
        }
    }

    /// The current global connection count. Counted regardless of caps (metrics gauge / shutdown-drain basis).
    pub fn total(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }
}

/// Connection-slot RAII guard. Releases automatically on drop. Owned (holds
/// Arc<ConnTracker>), so it can cross spawn / 'static boundaries.
pub struct ConnGuard {
    tracker: Arc<ConnTracker>,
    ip: IpAddr,
    active: bool,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if self.active {
            self.tracker.release(self.ip);
            self.active = false;
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[test]
    fn total_limit_blocks_beyond_cap() {
        let t = Arc::new(ConnTracker::new(0, 2));
        let g1 = t.try_acquire("127.0.0.1".parse().unwrap());
        let g2 = t.try_acquire("127.0.0.1".parse().unwrap());
        let g3 = t.try_acquire("127.0.0.1".parse().unwrap());
        assert!(g1.is_some() && g2.is_some());
        assert!(g3.is_none(), "third should be blocked");
        drop(g1);
        let g4 = t.try_acquire("127.0.0.1".parse().unwrap());
        assert!(g4.is_some(), "after release should pass");
    }

    #[test]
    fn per_ip_limit_independent_of_total() {
        let t = Arc::new(ConnTracker::new(1, 100));
        let g1 = t.try_acquire("1.1.1.1".parse().unwrap());
        let g2 = t.try_acquire("1.1.1.1".parse().unwrap()); // the second from the same IP should be rejected
        let g3 = t.try_acquire("2.2.2.2".parse().unwrap()); // a different IP should pass
        assert!(g1.is_some());
        assert!(g2.is_none(), "second from same IP should be blocked");
        assert!(g3.is_some(), "different IP should pass");
    }

    #[test]
    fn zero_means_unlimited() {
        let t = Arc::new(ConnTracker::new(0, 0));
        for _ in 0..100 {
            assert!(t.try_acquire("127.0.0.1".parse().unwrap()).is_some());
        }
    }
}

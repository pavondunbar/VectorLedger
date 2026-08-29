//! Background license watcher — re-checks the on-disk license once per day.
//!
//! # Why this exists
//!
//! The license is loaded once at `vledger start` and held in memory.  A
//! server that is never restarted would therefore retain its original (e.g.
//! Enterprise) feature set even after the license file on disk has been
//! replaced with a downgraded or expired one.
//!
//! `spawn_license_watcher` fixes this by running a Tokio task that wakes up
//! at the next midnight boundary (UTC) and then every 24 hours thereafter,
//! re-reading and re-verifying `<data_dir>/license.json` on each tick.  If
//! the license has changed or expired the shared `Arc<RwLock<LicenseStore>>`
//! is updated in place, so subsequent `require_feature` calls see the new
//! state immediately — without any restart.
//!
//! # Timing guarantee
//!
//! The first check fires at midnight UTC on the day *after* the watcher is
//! started.  A downgrade applied on Monday takes effect on Tuesday — exactly
//! the behaviour requested.
//!
//! # Cancellation
//!
//! Pass a `tokio_util::sync::CancellationToken`; the task exits cleanly when
//! the token is cancelled (i.e. on graceful server shutdown).

use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::store::LicenseStore;

/// Shared, live license handle.  Hand the `Arc` to every subsystem that needs
/// to gate features; they call `store.read().await.require_feature(…)`.
pub type SharedLicense = Arc<RwLock<LicenseStore>>;

/// Spawn the daily license-watcher task.
///
/// Returns a `SharedLicense` that is kept up-to-date as the watcher runs.
/// The task exits when `shutdown` is cancelled.
///
/// # Arguments
///
/// * `data_dir` — path to the VectorLedger data directory; the watcher reads
///   `<data_dir>/license.json` on each daily tick.
/// * `initial`  — the `LicenseStore` loaded at startup (returned by
///   `LicenseStore::load_or_free`).
/// * `shutdown` — cancellation token wired to the server's graceful-shutdown
///   signal; the background task exits when this is cancelled.
pub fn spawn_license_watcher(
    data_dir: &Path,
    initial: LicenseStore,
    shutdown: CancellationToken,
) -> SharedLicense {
    let shared = Arc::new(RwLock::new(initial));
    let handle = Arc::clone(&shared);
    let dir = data_dir.to_path_buf();

    tokio::spawn(async move {
        loop {
            let delay = seconds_until_next_midnight();

            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(delay)) => {
                    refresh(&handle, &dir).await;
                }
                _ = shutdown.cancelled() => {
                    tracing::debug!("License watcher shutting down.");
                    break;
                }
            }
        }
    });

    shared
}

/// Reload the license from disk and update the shared store.
async fn refresh(shared: &SharedLicense, data_dir: &std::path::Path) {
    let new_license = LicenseStore::load_or_free(data_dir);

    let mut guard = shared.write().await;
    let old_tier = guard.tier.clone();
    let new_tier = new_license.tier.clone();

    *guard = new_license;
    drop(guard); // release write lock before logging

    if old_tier != new_tier {
        tracing::warn!(
            old = %old_tier,
            new = %new_tier,
            "License tier changed during daily re-check. \
             New entitlements are now in effect."
        );
    } else {
        tracing::info!(
            tier = %new_tier,
            "Daily license check passed — no change."
        );
    }
}

/// Returns the number of whole seconds until the next UTC midnight.
///
/// Minimum value is 1 second so the loop never busy-spins if called at exactly
/// midnight.
fn seconds_until_next_midnight() -> u64 {
    let now = Utc::now();
    let seconds_today = now.timestamp() % 86_400; // seconds elapsed since midnight
    let remaining = 86_400 - seconds_today; // seconds until next midnight
                                            // Clamp to at least 1 so we never sleep 0 seconds.
    remaining.max(1) as u64
}

#[cfg(test)]
mod tests {
    use super::seconds_until_next_midnight;

    #[test]
    fn never_returns_zero() {
        // Just verify the function always returns a positive value.
        let secs = seconds_until_next_midnight();
        assert!(secs >= 1, "expected >= 1, got {secs}");
        assert!(secs <= 86_400, "expected <= 86400, got {secs}");
    }
}

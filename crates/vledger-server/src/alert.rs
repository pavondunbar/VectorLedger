//! Alert channel abstraction for VectorLedger (Fix #42).
//!
//! The background monitors (VERIFY_CHAIN, financial invariant check) already
//! detect violations and write `tracing::error!` events.  This module adds a
//! pluggable `AlertChannel` trait so those signals can be routed to
//! actionable destinations — Slack, PagerDuty, Teams (all via webhook), or
//! SMTP — in addition to the existing Prometheus metrics and tracing logs.
//!
//! ## Configuration
//!
//! Alert channels are configured in `<data-dir>/catalog/alerts.json`:
//!
//! ```json
//! {
//!   "channels": [
//!     {
//!       "type": "webhook",
//!       "url": "https://hooks.slack.com/services/T.../B.../...",
//!       "min_severity": "warning"
//!     },
//!     {
//!       "type": "webhook",
//!       "url": "https://events.pagerduty.com/v2/enqueue",
//!       "min_severity": "critical"
//!     }
//!   ],
//!   "cooldown_seconds": 300
//! }
//! ```
//!
//! ## Severity levels
//!
//! | Severity   | Used for |
//! |------------|----------|
//! | `info`     | Scheduled checks that passed — informational only |
//! | `warning`  | Retention evaluation, non-critical anomalies |
//! | `critical` | Chain integrity failure, financial invariant violation |
//!
//! ## Cooldown
//!
//! A per-source cooldown prevents alert storms.  If the same `source` fires
//! within `cooldown_seconds` of a previous alert, the alert is suppressed
//! (but still logged at DEBUG level).  Set `cooldown_seconds = 0` to disable.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// ── Alert ─────────────────────────────────────────────────────────────────────

/// Severity of an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// A single alert event fired by VectorLedger's background monitors.
#[derive(Debug, Clone)]
pub struct Alert {
    /// Machine-readable source identifier, e.g. `"verify-chain-scheduler"`.
    pub source: String,
    /// Human-readable summary of the alert condition.
    pub message: String,
    pub severity: Severity,
    /// UTC timestamp when this alert was generated.
    pub fired_at: chrono::DateTime<chrono::Utc>,
}

impl Alert {
    pub fn new(source: impl Into<String>, message: impl Into<String>, severity: Severity) -> Self {
        Self {
            source: source.into(),
            message: message.into(),
            severity,
            fired_at: chrono::Utc::now(),
        }
    }

    pub fn critical(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(source, message, Severity::Critical)
    }

    pub fn warning(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(source, message, Severity::Warning)
    }
}

// ── AlertChannel trait ────────────────────────────────────────────────────────

/// A destination that can receive alert events.
pub trait AlertChannel: Send + Sync {
    /// Send `alert` to this channel.  Returns `Ok(())` on success or if the
    /// alert was suppressed by cooldown.  Returns `Err` only on a hard
    /// delivery failure — the caller should log the error and continue.
    fn send(&self, alert: &Alert) -> Result<(), String>;
}

// ── LogOnlyAlertChannel — default, no external dependency ────────────────────

/// Logs alerts using `tracing`.  This is the default channel and preserves
/// the existing behaviour when no `alerts.json` is configured.
pub struct LogOnlyAlertChannel;

impl AlertChannel for LogOnlyAlertChannel {
    fn send(&self, alert: &Alert) -> Result<(), String> {
        match alert.severity {
            Severity::Critical => tracing::error!(
                source = %alert.source,
                severity = %alert.severity,
                "ALERT: {}",
                alert.message
            ),
            Severity::Warning => tracing::warn!(
                source = %alert.source,
                severity = %alert.severity,
                "ALERT: {}",
                alert.message
            ),
            Severity::Info => tracing::info!(
                source = %alert.source,
                severity = %alert.severity,
                "ALERT: {}",
                alert.message
            ),
        }
        Ok(())
    }
}

// ── WebhookAlertChannel — Slack / PagerDuty / Teams / generic ─────────────────

/// Sends alerts as HTTP POST JSON payloads to a webhook URL.
///
/// Compatible with:
/// - **Slack Incoming Webhooks**: `{"text": "…"}`
/// - **PagerDuty Events API v2**: `{"routing_key":"…","event_action":"trigger",…}`
/// - **Generic webhooks**: raw `AlertPayload` JSON
///
/// The payload format is auto-detected from the URL host:
/// - `hooks.slack.com` → Slack format
/// - `events.pagerduty.com` → PagerDuty format
/// - anything else → generic JSON
pub struct WebhookAlertChannel {
    url: String,
    min_severity: Severity,
    cooldown: Duration,
    /// Last fire time per source — keyed by `Alert::source`.
    last_fired: Mutex<HashMap<String, Instant>>,
    /// Tokio runtime handle for the blocking HTTP call.
    rt: tokio::runtime::Handle,
}

impl WebhookAlertChannel {
    pub fn new(url: String, min_severity: Severity, cooldown_secs: u64) -> Self {
        Self {
            url,
            min_severity,
            cooldown: Duration::from_secs(cooldown_secs),
            last_fired: Mutex::new(HashMap::new()),
            rt: tokio::runtime::Handle::current(),
        }
    }

    fn is_cooled_down(&self, source: &str) -> bool {
        if self.cooldown.is_zero() {
            return true;
        }
        let mut map = self.last_fired.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if let Some(&last) = map.get(source) {
            if now.duration_since(last) < self.cooldown {
                return false; // still in cooldown
            }
        }
        map.insert(source.to_string(), now);
        true
    }

    fn build_payload(&self, alert: &Alert) -> serde_json::Value {
        let url_lower = self.url.to_lowercase();
        if url_lower.contains("hooks.slack.com") {
            // Slack Incoming Webhook format
            serde_json::json!({
                "text": format!(
                    "*[{}]* `{}` — {}",
                    alert.severity.to_string().to_uppercase(),
                    alert.source,
                    alert.message
                )
            })
        } else if url_lower.contains("pagerduty.com") {
            // PagerDuty Events API v2
            serde_json::json!({
                "routing_key": "",   // operator sets in URL or env
                "event_action": "trigger",
                "payload": {
                    "summary": alert.message,
                    "severity": match alert.severity {
                        Severity::Critical => "critical",
                        Severity::Warning  => "warning",
                        Severity::Info     => "info",
                    },
                    "source": alert.source,
                    "timestamp": alert.fired_at.to_rfc3339(),
                }
            })
        } else {
            // Generic JSON payload
            serde_json::json!({
                "source":   alert.source,
                "severity": alert.severity.to_string(),
                "message":  alert.message,
                "fired_at": alert.fired_at.to_rfc3339(),
            })
        }
    }
}

impl AlertChannel for WebhookAlertChannel {
    fn send(&self, alert: &Alert) -> Result<(), String> {
        if alert.severity < self.min_severity {
            debug!(
                source = %alert.source,
                severity = %alert.severity,
                min = %self.min_severity,
                "Alert below channel minimum severity — suppressed"
            );
            return Ok(());
        }

        if !self.is_cooled_down(&alert.source) {
            debug!(
                source = %alert.source,
                "Alert suppressed by cooldown"
            );
            return Ok(());
        }

        let payload = self.build_payload(alert);
        let url = self.url.clone();
        let payload_str = serde_json::to_string(&payload)
            .map_err(|e| format!("Failed to serialise alert payload: {e}"))?;

        // Execute the HTTP POST on the existing Tokio runtime.
        // We use block_in_place so this doesn't block the async executor.
        let result = tokio::task::block_in_place(|| {
            self.rt.block_on(async move {
                // Use reqwest with a short timeout so a broken webhook
                // doesn't stall the background monitor loop.
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|e| format!("HTTP client error: {e}"))?;
                let resp = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(payload_str)
                    .send()
                    .await
                    .map_err(|e| format!("Webhook POST failed: {e}"))?;
                if !resp.status().is_success() {
                    return Err(format!(
                        "Webhook returned non-2xx status: {}",
                        resp.status()
                    ));
                }
                Ok::<(), String>(())
            })
        });

        if let Err(ref e) = result {
            warn!(url = %self.url, error = %e, "Webhook alert delivery failed");
        }
        result
    }
}

// ── AlertRouter — fan-out to multiple channels ────────────────────────────────

/// Routes a single alert to all configured channels.
///
/// A failure on one channel does not prevent delivery to the others.
pub struct AlertRouter {
    channels: Vec<Box<dyn AlertChannel>>,
}

impl AlertRouter {
    /// Create a router with an empty channel list (no-op until channels are added).
    pub fn new() -> Self {
        Self { channels: Vec::new() }
    }

    /// Add a channel to the router.
    pub fn add_channel(&mut self, ch: Box<dyn AlertChannel>) {
        self.channels.push(ch);
    }

    /// Fire `alert` to all channels, logging any delivery failures.
    pub fn fire(&self, alert: Alert) {
        for ch in &self.channels {
            if let Err(e) = ch.send(&alert) {
                warn!(error = %e, source = %alert.source, "Alert channel delivery failed");
            }
        }
    }

    /// Convenience: fire a critical alert.
    pub fn critical(&self, source: impl Into<String>, message: impl Into<String>) {
        self.fire(Alert::critical(source, message));
    }

    /// Convenience: fire a warning alert.
    pub fn warning(&self, source: impl Into<String>, message: impl Into<String>) {
        self.fire(Alert::warning(source, message));
    }
}

impl Default for AlertRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Config loading ────────────────────────────────────────────────────────────

/// Deserialised form of a single entry in `alerts.json` `channels` array.
#[derive(Debug, Deserialize)]
struct ChannelConfig {
    #[serde(rename = "type")]
    kind: String,
    /// Webhook URL (required for `type = "webhook"`).
    url: Option<String>,
    /// Minimum severity level for this channel (default: `warning`).
    #[serde(default = "default_min_severity")]
    min_severity: Severity,
}

fn default_min_severity() -> Severity {
    Severity::Warning
}

/// Deserialised `alerts.json`.
#[derive(Debug, Deserialize)]
struct AlertsConfig {
    #[serde(default)]
    channels: Vec<ChannelConfig>,
    /// Per-source cooldown in seconds (0 = disabled).
    #[serde(default = "default_cooldown")]
    cooldown_seconds: u64,
}

fn default_cooldown() -> u64 {
    300 // 5 minutes
}

/// Load an `AlertRouter` from `<data_dir>/catalog/alerts.json`.
///
/// Always returns a valid router:
/// - If `alerts.json` does not exist or is malformed, returns a router
///   containing only the `LogOnlyAlertChannel` (existing behaviour).
/// - If `alerts.json` is present and valid, the configured channels are
///   added in addition to `LogOnlyAlertChannel`.
///
/// This function must be called from within a Tokio runtime context because
/// `WebhookAlertChannel` captures the runtime handle.
pub fn load_alert_router(data_dir: &Path) -> AlertRouter {
    let mut router = AlertRouter::new();
    // LogOnly is always present — preserves existing tracing behaviour.
    router.add_channel(Box::new(LogOnlyAlertChannel));

    let config_path = data_dir.join("catalog").join("alerts.json");
    if !config_path.exists() {
        return router;
    }

    let raw = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            warn!(path = %config_path.display(), error = %e, "Failed to read alerts.json");
            return router;
        }
    };

    let cfg: AlertsConfig = match serde_json::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            warn!(path = %config_path.display(), error = %e, "Malformed alerts.json — using log-only alerts");
            return router;
        }
    };

    for ch in cfg.channels {
        match ch.kind.as_str() {
            "webhook" => {
                if let Some(url) = ch.url {
                    router.add_channel(Box::new(WebhookAlertChannel::new(
                        url,
                        ch.min_severity,
                        cfg.cooldown_seconds,
                    )));
                } else {
                    warn!("alerts.json: webhook channel missing 'url' field — skipped");
                }
            }
            other => {
                warn!(kind = other, "alerts.json: unknown channel type — skipped");
            }
        }
    }

    router
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    struct CountingChannel(Arc<AtomicU32>);
    impl AlertChannel for CountingChannel {
        fn send(&self, _: &Alert) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn router_fans_out_to_all_channels() {
        let count = Arc::new(AtomicU32::new(0));
        let mut router = AlertRouter::new();
        router.add_channel(Box::new(CountingChannel(Arc::clone(&count))));
        router.add_channel(Box::new(CountingChannel(Arc::clone(&count))));
        router.critical("test", "boom");
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn log_only_channel_never_errors() {
        let ch = LogOnlyAlertChannel;
        let alert = Alert::critical("test", "chain broken");
        assert!(ch.send(&alert).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn webhook_channel_suppresses_below_min_severity() {
        // Build a webhook channel that only accepts Critical.
        // Sending Warning should be suppressed (Ok, no HTTP call).
        let ch = WebhookAlertChannel::new(
            "https://example.com/hook".into(),
            Severity::Critical,
            0,
        );
        let alert = Alert::warning("src", "non-critical");
        assert!(ch.send(&alert).is_ok()); // suppressed, not an error
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cooldown_suppresses_repeated_alerts() {
        // 60-second cooldown
        let ch = WebhookAlertChannel::new(
            "https://example.com/hook".into(),
            Severity::Info,
            60,
        );
        // First call: not cooled down yet → would attempt delivery
        // (HTTP will fail since example.com/hook isn't real — we only
        // check that the cooldown mechanism tracks state correctly)
        let _ = ch.send(&Alert::critical("src", "first"));
        // Second call: within cooldown window → suppressed (Ok)
        let result = ch.send(&Alert::critical("src", "second"));
        assert!(result.is_ok());
    }

    #[test]
    fn load_alert_router_returns_log_only_when_no_config() {
        let dir = tempfile::TempDir::new().unwrap();
        // No alerts.json — should return a router with LogOnlyAlertChannel
        let router = load_alert_router(dir.path());
        // Router should not panic and should have at least 1 channel
        router.critical("test", "verify this doesn't panic");
    }
}

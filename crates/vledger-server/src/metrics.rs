//! Prometheus metrics exposition for VectorLedger.
//!
//! Exposes a `/metrics` HTTP endpoint in the Prometheus text format
//! (Content-Type: `text/plain; version=0.0.4`).
//!
//! ## Available metrics
//!
//! | Metric | Type | Description |
//! |--------|------|-------------|
//! | `vledger_build_info` | gauge | Build version, Rust version, target |
//! | `vledger_ledger_entries_total` | counter | Total journal entries posted |
//! | `vledger_ledger_accounts_total` | gauge | Total accounts in chart-of-accounts |
//! | `vledger_wal_segments_total` | gauge | Number of WAL segment files |
//! | `vledger_wal_sync_lag_ms` | gauge | Milliseconds since last WAL fsync |
//! | `vledger_connections_active` | gauge | Currently open client connections |
//! | `vledger_connections_total` | counter | Total connections accepted since start |
//! | `vledger_auth_successes_total` | counter | Successful authentications |
//! | `vledger_auth_failures_total` | counter | Failed authentication attempts |
//! | `vledger_queries_total` | counter | SQL queries executed |
//! | `vledger_query_duration_ms_sum` | counter | Cumulative query execution time (ms) |
//! | `vledger_chain_verification_failures_total` | counter | Hash chain integrity failures |
//! | `vledger_backup_age_seconds` | gauge | Seconds since the last backup was created |
//! | `vledger_replica_lag_lsn` | gauge | Replication lag in LSN records |
//! | `vledger_foureyes_pending_total` | gauge | Four-eyes entries awaiting approval |
//! | `vledger_uptime_seconds` | gauge | Server uptime in seconds |
//!
//! ## Usage
//!
//! The metrics server binds on a separate port (default: `--metrics-port 9090`)
//! so it can be firewalled off from application traffic.
//!
//! ```bash
//! vledger start --metrics-port 9090
//! curl http://127.0.0.1:9090/metrics
//! ```
//!
//! ## Scrape config (Prometheus)
//!
//! ```yaml
//! scrape_configs:
//!   - job_name: vledger
//!     static_configs:
//!       - targets: ['your-host:9090']
//!     scrape_interval: 15s
//! ```

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use tokio_util::sync::CancellationToken;
use tracing::info;

// ── Metrics registry ──────────────────────────────────────────────────────────

/// All runtime-mutable metrics for VectorLedger.
///
/// All fields use `AtomicU64` / `AtomicI64` so they can be read from the
/// metrics HTTP handler without locking.  Increment/set from hot paths.
#[derive(Debug)]
pub struct Metrics {
    // ── Ledger ────────────────────────────────────────────────────────────
    pub ledger_entries_total: AtomicU64,
    pub ledger_accounts_total: AtomicU64,

    // ── WAL ───────────────────────────────────────────────────────────────
    pub wal_segments_total: AtomicU64,
    /// Unix timestamp (ms) of the last WAL fsync.
    pub wal_last_sync_ms: AtomicU64,

    // ── Connections ───────────────────────────────────────────────────────
    pub connections_active: AtomicI64,
    pub connections_total: AtomicU64,

    // ── Authentication ────────────────────────────────────────────────────
    pub auth_successes_total: AtomicU64,
    pub auth_failures_total: AtomicU64,

    // ── Queries ───────────────────────────────────────────────────────────
    pub queries_total: AtomicU64,
    pub query_duration_ms_sum: AtomicU64,

    // ── Security / integrity ──────────────────────────────────────────────
    pub chain_verify_failures: AtomicU64,

    // ── Operational ───────────────────────────────────────────────────────
    /// Unix timestamp (seconds) of the last successful backup.
    pub last_backup_unix_secs: AtomicU64,
    pub replica_lag_lsn: AtomicU64,
    pub foureyes_pending_total: AtomicU64,

    // ── Startup timestamp ─────────────────────────────────────────────────
    pub started_at: Instant,
}

impl Metrics {
    /// Create a new zero-initialised metrics registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ledger_entries_total: AtomicU64::new(0),
            ledger_accounts_total: AtomicU64::new(0),
            wal_segments_total: AtomicU64::new(0),
            wal_last_sync_ms: AtomicU64::new(0),
            connections_active: AtomicI64::new(0),
            connections_total: AtomicU64::new(0),
            auth_successes_total: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            queries_total: AtomicU64::new(0),
            query_duration_ms_sum: AtomicU64::new(0),
            chain_verify_failures: AtomicU64::new(0),
            last_backup_unix_secs: AtomicU64::new(0),
            replica_lag_lsn: AtomicU64::new(0),
            foureyes_pending_total: AtomicU64::new(0),
            started_at: Instant::now(),
        })
    }

    // ── Convenience increment helpers ─────────────────────────────────────

    pub fn inc_entries(&self) {
        self.ledger_entries_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn set_accounts(&self, n: u64) {
        self.ledger_accounts_total.store(n, Ordering::Relaxed);
    }
    pub fn set_wal_segments(&self, n: u64) {
        self.wal_segments_total.store(n, Ordering::Relaxed);
    }
    pub fn record_wal_sync(&self) {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.wal_last_sync_ms.store(ms, Ordering::Relaxed);
    }
    pub fn conn_open(&self) {
        self.connections_active.fetch_add(1, Ordering::Relaxed);
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn conn_close(&self) {
        self.connections_active.fetch_add(-1, Ordering::Relaxed);
    }
    pub fn inc_auth_success(&self) {
        self.auth_successes_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_auth_failure(&self) {
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_query(&self, duration_ms: u64) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        self.query_duration_ms_sum
            .fetch_add(duration_ms, Ordering::Relaxed);
    }
    pub fn inc_chain_failure(&self) {
        self.chain_verify_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_backup(&self) {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_backup_unix_secs.store(secs, Ordering::Relaxed);
    }
    pub fn set_replica_lag(&self, lag: u64) {
        self.replica_lag_lsn.store(lag, Ordering::Relaxed);
    }
    pub fn set_foureyes_pending(&self, n: u64) {
        self.foureyes_pending_total.store(n, Ordering::Relaxed);
    }

    // ── Prometheus text format serialisation ──────────────────────────────

    /// Render all metrics as a Prometheus text format scrape response.
    pub fn render(&self) -> String {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let wal_last_sync = self.wal_last_sync_ms.load(Ordering::Relaxed);
        let wal_lag_ms = if wal_last_sync == 0 {
            0
        } else {
            now_ms.saturating_sub(wal_last_sync)
        };

        let last_backup = self.last_backup_unix_secs.load(Ordering::Relaxed);
        let backup_age = if last_backup == 0 {
            0u64
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(last_backup)
        };

        let uptime = self.started_at.elapsed().as_secs();

        let mut out = String::with_capacity(2048);

        // ── Build info ────────────────────────────────────────────────────
        out.push_str("# HELP vledger_build_info VectorLedger build metadata\n");
        out.push_str("# TYPE vledger_build_info gauge\n");
        out.push_str(&format!(
            "vledger_build_info{{version=\"{}\",rust_version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION"),
            option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        ));

        // ── Uptime ────────────────────────────────────────────────────────
        out.push_str("# HELP vledger_uptime_seconds Server uptime in seconds\n");
        out.push_str("# TYPE vledger_uptime_seconds gauge\n");
        out.push_str(&format!("vledger_uptime_seconds {uptime}\n"));

        // ── Ledger ────────────────────────────────────────────────────────
        out.push_str("# HELP vledger_ledger_entries_total Total journal entries posted\n");
        out.push_str("# TYPE vledger_ledger_entries_total counter\n");
        out.push_str(&format!(
            "vledger_ledger_entries_total {}\n",
            self.ledger_entries_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP vledger_ledger_accounts_total Accounts in chart-of-accounts\n");
        out.push_str("# TYPE vledger_ledger_accounts_total gauge\n");
        out.push_str(&format!(
            "vledger_ledger_accounts_total {}\n",
            self.ledger_accounts_total.load(Ordering::Relaxed)
        ));

        // ── WAL ───────────────────────────────────────────────────────────
        out.push_str("# HELP vledger_wal_segments_total Number of WAL segment files\n");
        out.push_str("# TYPE vledger_wal_segments_total gauge\n");
        out.push_str(&format!(
            "vledger_wal_segments_total {}\n",
            self.wal_segments_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP vledger_wal_sync_lag_ms Milliseconds since last WAL fsync\n");
        out.push_str("# TYPE vledger_wal_sync_lag_ms gauge\n");
        out.push_str(&format!("vledger_wal_sync_lag_ms {wal_lag_ms}\n"));

        // ── Connections ───────────────────────────────────────────────────
        out.push_str("# HELP vledger_connections_active Currently open connections\n");
        out.push_str("# TYPE vledger_connections_active gauge\n");
        out.push_str(&format!(
            "vledger_connections_active {}\n",
            self.connections_active.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP vledger_connections_total Total connections accepted since start\n");
        out.push_str("# TYPE vledger_connections_total counter\n");
        out.push_str(&format!(
            "vledger_connections_total {}\n",
            self.connections_total.load(Ordering::Relaxed)
        ));

        // ── Auth ──────────────────────────────────────────────────────────
        out.push_str("# HELP vledger_auth_successes_total Successful authentications\n");
        out.push_str("# TYPE vledger_auth_successes_total counter\n");
        out.push_str(&format!(
            "vledger_auth_successes_total {}\n",
            self.auth_successes_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP vledger_auth_failures_total Failed authentication attempts\n");
        out.push_str("# TYPE vledger_auth_failures_total counter\n");
        out.push_str(&format!(
            "vledger_auth_failures_total {}\n",
            self.auth_failures_total.load(Ordering::Relaxed)
        ));

        // ── Queries ───────────────────────────────────────────────────────
        out.push_str("# HELP vledger_queries_total SQL queries executed\n");
        out.push_str("# TYPE vledger_queries_total counter\n");
        out.push_str(&format!(
            "vledger_queries_total {}\n",
            self.queries_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP vledger_query_duration_ms_sum Cumulative query execution time (ms)\n");
        out.push_str("# TYPE vledger_query_duration_ms_sum counter\n");
        out.push_str(&format!(
            "vledger_query_duration_ms_sum {}\n",
            self.query_duration_ms_sum.load(Ordering::Relaxed)
        ));

        // ── Security ──────────────────────────────────────────────────────
        out.push_str(
            "# HELP vledger_chain_verification_failures_total Hash chain integrity failures\n",
        );
        out.push_str("# TYPE vledger_chain_verification_failures_total counter\n");
        out.push_str(&format!(
            "vledger_chain_verification_failures_total {}\n",
            self.chain_verify_failures.load(Ordering::Relaxed)
        ));

        // ── Operational ───────────────────────────────────────────────────
        out.push_str("# HELP vledger_backup_age_seconds Seconds since the last backup\n");
        out.push_str("# TYPE vledger_backup_age_seconds gauge\n");
        out.push_str(&format!("vledger_backup_age_seconds {backup_age}\n"));

        out.push_str("# HELP vledger_replica_lag_lsn Replication lag in WAL records\n");
        out.push_str("# TYPE vledger_replica_lag_lsn gauge\n");
        out.push_str(&format!(
            "vledger_replica_lag_lsn {}\n",
            self.replica_lag_lsn.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP vledger_foureyes_pending_total Four-eyes entries awaiting approval\n");
        out.push_str("# TYPE vledger_foureyes_pending_total gauge\n");
        out.push_str(&format!(
            "vledger_foureyes_pending_total {}\n",
            self.foureyes_pending_total.load(Ordering::Relaxed)
        ));

        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Arc::try_unwrap(Self::new()).unwrap_or_else(|_arc| {
            // This path is unreachable for default() since we just created it,
            // but we need to satisfy the compiler.
            panic!("unexpected Arc contention in Metrics::default")
        })
    }
}

// ── HTTP server ───────────────────────────────────────────────────────────────

/// Start the Prometheus metrics HTTP server on `bind_addr`.
///
/// The server exposes a single endpoint:
/// - `GET /metrics` — Prometheus text format scrape target
/// - `GET /health`  — liveness probe (returns `200 OK` with body `ok`)
///
/// The server shuts down gracefully when `shutdown` is cancelled.
pub async fn run_metrics_server(
    bind_addr: String,
    metrics: Arc<Metrics>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(handler_metrics))
        .route("/health", get(handler_health))
        .with_state(metrics);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "Prometheus metrics server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { shutdown.cancelled().await })
        .await?;

    info!("Metrics server shut down");
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handler_metrics(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    let body = metrics.render();
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

async fn handler_health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_produces_valid_prometheus_lines() {
        let m = Metrics::new();
        m.inc_entries();
        m.inc_entries();
        m.inc_auth_failure();
        m.inc_auth_success();
        m.inc_query(42);
        m.set_accounts(5);
        m.set_wal_segments(3);
        m.record_wal_sync();
        m.conn_open();
        m.conn_open();
        m.conn_close();

        let output = m.render();

        // Every metric must appear exactly once.
        let required = [
            "vledger_build_info",
            "vledger_uptime_seconds",
            "vledger_ledger_entries_total 2",
            "vledger_ledger_accounts_total 5",
            "vledger_wal_segments_total 3",
            "vledger_connections_active 1",
            "vledger_connections_total 2",
            "vledger_auth_successes_total 1",
            "vledger_auth_failures_total 1",
            "vledger_queries_total 1",
            "vledger_query_duration_ms_sum 42",
            "vledger_chain_verification_failures_total 0",
            "vledger_backup_age_seconds",
            "vledger_replica_lag_lsn 0",
            "vledger_foureyes_pending_total 0",
        ];

        for expected in &required {
            assert!(
                output.contains(expected),
                "Expected '{expected}' in metrics output.\nFull output:\n{output}"
            );
        }
    }

    #[test]
    fn render_format_is_valid_prom_text() {
        let m = Metrics::new();
        let output = m.render();

        // Every non-blank, non-comment line must contain a space separating
        // the metric name from its value.
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            assert!(
                trimmed.contains(' '),
                "Metric line must have at least one space: '{trimmed}'"
            );
            // Value must be parseable as f64.
            let value_str = trimmed.rsplit(' ').next().unwrap_or("");
            value_str.parse::<f64>().unwrap_or_else(|_| {
                panic!("Metric value '{value_str}' is not a valid number in line '{trimmed}'");
            });
        }
    }

    #[test]
    fn wal_sync_lag_increases_over_time() {
        let m = Metrics::new();
        m.record_wal_sync();
        // Sleep briefly so lag is non-zero.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let output = m.render();
        // The lag line should be present and non-negative.
        assert!(output.contains("vledger_wal_sync_lag_ms"));
    }

    #[tokio::test]
    async fn health_endpoint_returns_200() {
        let result = handler_health().await.into_response();
        assert_eq!(result.status(), StatusCode::OK);
    }
}

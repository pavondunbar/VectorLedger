//! # vledger-server — TLS 1.3 server with authentication and authorisation.

pub mod auth;
pub mod config;
pub mod error;
pub mod handler;
pub mod metrics;
pub mod protocol;
pub mod tls;

pub use auth::{Role, UserStore, Session, check_plan_privilege};
pub use config::ServerConfig;
pub use error::ServerError;
pub use metrics::{Metrics, run_metrics_server};

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use vledger_ledger::LedgerStore;

// ── Per-IP rate-limiter ───────────────────────────────────────────────────────

#[derive(Debug)]
struct IpBucket {
    tokens:       f64,
    last_checked: Instant,
}

const RATE_BURST: f64        = 10.0;
const RATE_REFILL_PER_SEC: f64 = 2.0;
const BUCKET_TTL: Duration   = Duration::from_secs(300);

impl IpBucket {
    fn new() -> Self {
        Self { tokens: RATE_BURST, last_checked: Instant::now() }
    }

    fn try_acquire(&mut self) -> bool {
        let now     = Instant::now();
        let elapsed = now.duration_since(self.last_checked).as_secs_f64();
        self.last_checked = now;
        self.tokens = (self.tokens + elapsed * RATE_REFILL_PER_SEC).min(RATE_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// The VectorLedger server.
pub struct Server {
    config:     Arc<ServerConfig>,
    ledger:     Arc<RwLock<LedgerStore>>,
    user_store: Arc<UserStore>,
}

impl Server {
    /// Create a server.
    pub fn new(config: ServerConfig, ledger: LedgerStore) -> Self {
        let catalog_dir = config.catalog_dir.clone()
            .unwrap_or_else(|| "./vledger-data/catalog".into());
        let user_store = UserStore::open(Path::new(&catalog_dir))
            .unwrap_or_else(|_| {
                let tmp = std::env::temp_dir()
                    .join(format!("vledger-catalog-{}", std::process::id()));
                let _ = std::fs::create_dir_all(&tmp);
                UserStore::open(&tmp).expect("cannot create temp user store")
            });
        Self {
            config:     Arc::new(config),
            ledger:     Arc::new(RwLock::new(ledger)),
            user_store: Arc::new(user_store),
        }
    }

    /// Create a server with an explicit `UserStore` (useful for testing).
    pub fn with_user_store(
        config:     ServerConfig,
        ledger:     LedgerStore,
        user_store: UserStore,
    ) -> Self {
        Self {
            config:     Arc::new(config),
            ledger:     Arc::new(RwLock::new(ledger)),
            user_store: Arc::new(user_store),
        }
    }

    /// Start listening.  Runs until `shutdown` is cancelled or the process exits.
    ///
    /// ## Graceful shutdown (Fix #2)
    /// When `shutdown` is cancelled (SIGTERM / CTRL-C / test signal):
    /// 1. The accept loop stops accepting new TCP connections immediately.
    /// 2. The semaphore is closed — any task still waiting for a permit gets
    ///    a `None` and exits without spawning.
    /// 3. The server waits to re-acquire all `max_connections` permits, which
    ///    completes only once every in-flight connection task has dropped its
    ///    permit (i.e. closed its connection).
    /// 4. Each connection task receives the cancellation signal and exits its
    ///    read loop, sending a `FATAL: server shutting down` response so
    ///    clients can distinguish a planned shutdown from a crash.
    pub async fn run(self, shutdown: CancellationToken) -> Result<(), ServerError> {
        let acceptor = match (&self.config.tls_cert_path, &self.config.tls_key_path) {
            (Some(cert), Some(key)) => {
                info!("Loading TLS certificate from disk");
                tls::acceptor_from_files(
                    std::path::Path::new(cert),
                    std::path::Path::new(key),
                    self.config.mtls_ca_cert.as_deref(),
                )?
            }
            _ => {
                info!(hostname = %self.config.tls_hostname,
                      "Loading or generating self-signed TLS certificate");
                tls::self_signed_acceptor(
                    &self.config.tls_hostname,
                    self.config.catalog_dir.as_deref(),
                    self.config.mtls_ca_cert.as_deref(),
                )?
            }
        };

        let listener  = TcpListener::bind(&self.config.bind_addr).await
            .map_err(|e| ServerError::BindFailed {
                addr:   self.config.bind_addr.clone(),
                reason: e.to_string(),
            })?;

        let semaphore  = Arc::new(Semaphore::new(self.config.max_connections));
        let ip_buckets: Arc<tokio::sync::Mutex<HashMap<IpAddr, IpBucket>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        info!(
            addr            = %self.config.bind_addr,
            max_connections = self.config.max_connections,
            rate_burst      = RATE_BURST,
            rate_refill_s   = RATE_REFILL_PER_SEC,
            "VectorLedger listening"
        );

        // Background session-purge task — cancelled when the token fires.
        {
            let user_store_purge = Arc::clone(&self.user_store);
            let token = shutdown.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(auth::SESSION_PURGE_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            user_store_purge.purge_expired_sessions().await;
                        }
                        _ = token.cancelled() => break,
                    }
                }
            });
        }

        // Group-commit background flusher — only started in GroupCommit mode.
        {
            use vledger_wal::WalSyncMode;
            if self.config.wal_sync_mode == WalSyncMode::GroupCommit {
                // Extract the wal_dir from the ledger's data directory.
                // The WAL lives at <data_dir>/wal.
                let wal_dir = {
                    let guard = self.ledger.read().await;
                    guard.wal_dir().to_path_buf()
                };
                // Borrow the FlushState from the WAL writer inside the ledger.
                let flush_state = {
                    let guard = self.ledger.read().await;
                    guard.wal_flush_state()
                };
                if let Some(fs) = flush_state {
                    vledger_wal::spawn_group_commit_flusher(
                        wal_dir,
                        fs,
                        self.config.group_commit_delay_ms,
                        shutdown.clone(),
                    );
                    info!(
                        delay_ms = self.config.group_commit_delay_ms,
                        "Group-commit WAL flusher started"
                    );
                }
            }
        }

        // ── Accept loop ───────────────────────────────────────────────────
        loop {
            let (tcp_stream, peer_addr) = tokio::select! {
                // Normal accept path.
                res = listener.accept() => match res {
                    Ok(s)  => s,
                    Err(e) => { error!("Accept error: {e}"); continue; }
                },
                // Graceful shutdown: stop accepting.
                _ = shutdown.cancelled() => {
                    info!("Shutdown signal received — stopping accept loop");
                    break;
                }
            };

            let peer_ip = peer_addr.ip();

            // Per-IP rate limit.
            {
                let mut buckets = ip_buckets.lock().await;
                let now = Instant::now();
                buckets.retain(|_, b| now.duration_since(b.last_checked) < BUCKET_TTL);
                let bucket = buckets.entry(peer_ip).or_insert_with(IpBucket::new);
                if !bucket.try_acquire() {
                    warn!(peer = %peer_addr, "Rate limit exceeded — dropping connection");
                    drop(tcp_stream);
                    continue;
                }
            }

            // Connection-count semaphore.
            let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                Ok(p)  => p,
                Err(_) => {
                    warn!(peer = %peer_addr, max_connections = self.config.max_connections,
                          "Connection limit reached — queuing");
                    match Arc::clone(&semaphore).acquire_owned().await {
                        Ok(p)  => p,
                        Err(_) => { drop(tcp_stream); break; }
                    }
                }
            };

            let acceptor   = acceptor.clone();
            let ledger     = Arc::clone(&self.ledger);
            let config     = Arc::clone(&self.config);
            let user_store = Arc::clone(&self.user_store);
            let conn_token = shutdown.clone();

            tokio::spawn(async move {
                let _permit = permit;
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        handler::handle_connection(
                            tls_stream, ledger, config, user_store, peer_addr, conn_token,
                        ).await;
                    }
                    Err(e) => error!(peer = %peer_addr, "TLS handshake failed: {e}"),
                }
            });
        }

        // ── Drain in-flight connections ───────────────────────────────────
        // Re-acquire all permits: completes once every connection task has
        // dropped its permit, i.e. every active connection has closed.
        info!(
            max_connections = self.config.max_connections,
            "Waiting for in-flight connections to close…"
        );
        let _ = semaphore.acquire_many(self.config.max_connections as u32).await;
        info!("All connections closed — shutdown complete");

        Ok(())
    }
}



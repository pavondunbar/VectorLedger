//! Server configuration.

use serde::{Deserialize, Serialize};
use vledger_wal::WalSyncMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to bind, e.g. "127.0.0.1:5433".
    pub bind_addr: String,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Path to the TLS certificate (PEM).  None → use self-signed.
    pub tls_cert_path: Option<String>,
    /// Path to the TLS private key (PEM).  None → use self-signed.
    pub tls_key_path: Option<String>,
    /// Hostname used for self-signed certificate generation.
    pub tls_hostname: String,
    /// Attach Merkle proofs to every SELECT response.
    pub attach_proofs: bool,
    /// Whether to require authentication on every connection.
    pub require_auth: bool,
    /// Path to the catalog directory (for users.json and server secret).
    pub catalog_dir: Option<String>,
    /// Path to CA certificate PEM for mutual TLS client authentication.
    pub mtls_ca_cert: Option<String>,
    /// WAL sync mode — controls when fsync is called.
    ///
    /// - `per_record`   — fsync after every record (safest, slowest)
    /// - `group_commit` — background flush every `group_commit_delay_ms` ms (default, recommended)
    /// - `no_sync`      — never fsync (dev/test only, never use in production)
    pub wal_sync_mode: WalSyncMode,
    /// Flush interval for group-commit mode (milliseconds).
    /// Lower values reduce the data-loss window; higher values increase TPS.
    /// Default: 2 ms.  Only used when `wal_sync_mode = group_commit`.
    pub group_commit_delay_ms: u64,
    /// Maximum time in milliseconds a single SQL query may run before it is
    /// cancelled and the client receives a `query_timeout` error.
    ///
    /// This prevents a long-running scan or expensive aggregate from holding
    /// the write lock indefinitely and starving other connections.
    ///
    /// Default: 30 000 ms (30 s).  Set to 0 to disable (not recommended for
    /// production deployments).
    pub query_timeout_ms: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:5433".into(),
            max_connections: 128,
            tls_cert_path: None,
            tls_key_path: None,
            tls_hostname: "localhost".into(),
            attach_proofs: false,
            require_auth: true,
            catalog_dir: None,
            mtls_ca_cert: None,
            wal_sync_mode: WalSyncMode::GroupCommit,
            group_commit_delay_ms: 2,
            query_timeout_ms: 30_000,
        }
    }
}

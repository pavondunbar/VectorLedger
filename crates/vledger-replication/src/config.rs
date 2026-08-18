//! Replication configuration.

use serde::{Deserialize, Serialize};

/// Whether this node is a primary (sends WAL) or a replica (receives WAL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationRole {
    Primary,
    Replica,
}

/// TLS configuration shared by primary (server side) and replica (client side).
///
/// ## Modes
/// | tls_enabled | tls_ca_cert | client_cert | Effective mode               |
/// |-------------|-------------|-------------|------------------------------|
/// | false       | —           | —           | Plain TCP (dev only)         |
/// | true        | None        | None        | TLS, self-signed, no mTLS    |
/// | true        | Some(ca)    | None        | TLS, CA-verified, no mTLS    |
/// | true        | Some(ca)    | Some(c+k)   | Mutual TLS (mTLS)            |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationTlsConfig {
    /// Enable TLS on the replication channel.  Default: `true`.
    /// Set to `false` only for single-machine dev/test — never in production.
    pub enabled: bool,

    // ── Server (primary) side ──────────────────────────────────────────

    /// Path to the primary's TLS certificate PEM.
    /// `None` → generate a self-signed certificate at startup.
    pub server_cert: Option<String>,
    /// Path to the primary's TLS private key PEM.
    /// `None` → generate in-process alongside the self-signed cert.
    pub server_key: Option<String>,
    /// Hostname embedded in the self-signed certificate / used for SNI.
    /// Default: `"vledger-primary"`.
    pub server_hostname: String,

    // ── Client (replica) side ──────────────────────────────────────────

    /// Path to the CA certificate PEM used by the replica to verify the
    /// primary's certificate.
    /// `None` → disable server certificate verification (dev only).
    pub ca_cert: Option<String>,

    /// Path to the replica's client certificate PEM (mTLS).
    /// `None` → mTLS disabled; primary does not require a client certificate.
    pub client_cert: Option<String>,
    /// Path to the replica's client private key PEM (mTLS).
    pub client_key: Option<String>,
}

impl Default for ReplicationTlsConfig {
    fn default() -> Self {
        Self {
            enabled:         true,
            server_cert:     None,
            server_key:      None,
            server_hostname: "vledger-primary".into(),
            ca_cert:         None,
            client_cert:     None,
            client_key:      None,
        }
    }
}

/// Top-level replication configuration.
///
/// Serialised to / from `vledger-data/replication.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Role of this node.
    pub role: ReplicationRole,

    /// Primary: bind address for the WAL shipping listener.
    /// Replica: address of the primary to connect to.
    /// Format: `host:port`, default port `5434`.
    pub replication_addr: String,

    /// How long (ms) the primary waits for a replica ACK before returning
    /// `AckTimeout`.  Default: 5000 ms.
    pub ack_timeout_ms: u64,

    /// Heartbeat interval (ms).  Default: 1000 ms.
    pub heartbeat_interval_ms: u64,

    /// Maximum bytes to buffer per replica connection.  Default: 64 MiB.
    pub send_buffer_bytes: usize,

    /// Path to the shared 32-byte HMAC secret (hex-encoded, mode 0o600).
    /// Both primary and every replica must hold the same secret.
    /// `None` → defaults to `vledger-data/replication_secret.hex`.
    #[serde(default)]
    pub secret_path: Option<String>,

    /// TLS configuration for the replication channel (Tasks #1 and #2).
    /// Default: TLS enabled, self-signed cert, no mTLS.
    #[serde(default)]
    pub tls: ReplicationTlsConfig,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            role:                  ReplicationRole::Primary,
            replication_addr:      "127.0.0.1:5434".into(),
            ack_timeout_ms:        5_000,
            heartbeat_interval_ms: 1_000,
            send_buffer_bytes:     64 * 1024 * 1024,
            secret_path:           None,
            tls:                   ReplicationTlsConfig::default(),
        }
    }
}

impl ReplicationConfig {
    /// Load from `<data_dir>/replication.json`, falling back to `Default`
    /// if the file is absent.
    pub fn load(data_dir: &std::path::Path) -> Result<Self, String> {
        let path = data_dir.join("replication.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read replication.json: {e}"))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("invalid replication.json: {e}"))
    }
}

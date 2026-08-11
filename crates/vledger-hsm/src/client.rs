//! Async PyHSM client — supports Model 1 (local) and Model 2 (remote mTLS).
//!
//! ## Model 1 — same server (dev, CI, single-server production)
//!
//! ```text
//! VectorLedger
//!      │
//!      ▼  Unix domain socket (/tmp/pyhsm.sock)
//!    PyHSM
//! ```
//!
//! Create with `HsmClient::local(socket_path, caller_id)` or
//! `HsmClient::default_socket(caller_id)`.
//!
//! ## Model 2 — same-region separate server (production)
//!
//! ```text
//! VectorLedger ──── TLS 1.3 + mTLS ───► PyHSM (private subnet)
//! ```
//!
//! Create with `HsmClient::remote(config, caller_id)` where `config` is a
//! `RemotePyHsmConfig` containing the endpoint, CA cert, and optional client
//! cert/key for mutual TLS.
//!
//! ## Wire protocol
//! Both transports use the same newline-delimited JSON protocol.  The remote
//! transport adds `requestId` and `timestamp` fields to every message for
//! replay-attack prevention; PyHSM should reject duplicate request IDs and
//! stale timestamps.
//!
//! ## Usage
//! ```no_run
//! use vledger_hsm::{HsmClient, remote::RemotePyHsmConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Model 1
//!     let local = HsmClient::default_socket("vledger");
//!
//!     // Model 2
//!     let cfg = RemotePyHsmConfig {
//!         endpoint:    "https://pyhsm.internal.example.com:8443".into(),
//!         ca_cert:     "/etc/vledger/pyhsm/ca.pem".into(),
//!         client_cert: Some("/etc/vledger/pyhsm/client.pem".into()),
//!         client_key:  Some("/etc/vledger/pyhsm/client-key.pem".into()),
//!         timeout_ms:  5_000,
//!         max_retries: 3,
//!     };
//!     let remote = HsmClient::remote(cfg, "vledger");
//! }
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::error::HsmError;
use crate::protocol::{HsmRequest, HsmResponse, KeyPolicy};
use crate::remote::{HsmTransport, RemotePyHsmConfig, build_tls_connector, new_request_id, server_name, utc_timestamp};

// ── HsmClient ─────────────────────────────────────────────────────────────────

/// Async client for the PyHSM daemon.
///
/// Supports both Model 1 (local Unix socket / TCP loopback) and Model 2
/// (remote TLS 1.3 + mTLS).  All cryptographic operations have identical
/// semantics regardless of transport — the transport is an implementation
/// detail invisible to callers.
#[derive(Clone)]
pub struct HsmClient {
    transport:  HsmTransport,
    caller_id:  String,
}

impl HsmClient {
    // ── Constructors ──────────────────────────────────────────────────────

    /// **Model 1** — connect via a Unix domain socket (or TCP loopback on Windows).
    ///
    /// `socket_path` — `/tmp/pyhsm.sock` on Linux/macOS; `127.0.0.1:7777` on Windows.
    pub fn new(socket_path: impl AsRef<Path>, caller_id: impl Into<String>) -> Self {
        let path = socket_path.as_ref();
        let transport = if path.to_str().map(|s| s.contains(':')).unwrap_or(false) {
            HsmTransport::LocalTcp(path.to_string_lossy().into_owned())
        } else {
            HsmTransport::LocalSocket(path.to_path_buf())
        };
        Self { transport, caller_id: caller_id.into() }
    }

    /// **Model 1** — use the platform default address.
    ///
    /// - Unix: `/tmp/pyhsm.sock`
    /// - Windows: `127.0.0.1:7777`
    pub fn default_socket(caller_id: impl Into<String>) -> Self {
        Self::new(default_pyhsm_address(), caller_id)
    }

    /// **Model 2** — connect to a remote PyHSM over TLS 1.3 + mTLS.
    ///
    /// `config` must contain a valid `ca_cert` path.  `client_cert` and
    /// `client_key` are required for full mutual TLS.
    pub fn remote(config: RemotePyHsmConfig, caller_id: impl Into<String>) -> Self {
        Self {
            transport:  HsmTransport::remote(config),
            caller_id:  caller_id.into(),
        }
    }

    /// Construct from any `HsmTransport` value directly.
    pub fn with_transport(transport: HsmTransport, caller_id: impl Into<String>) -> Self {
        Self { transport, caller_id: caller_id.into() }
    }

    /// Returns a description of the active transport for logging.
    pub fn transport_description(&self) -> String {
        self.transport.description()
    }

    // ── Symmetric operations ──────────────────────────────────────────────

    /// Encrypt `plaintext` with the key identified by `key_id`.
    pub async fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        let req = HsmRequest::Encrypt {
            key_id:    key_id.to_string(),
            plaintext: hex::encode(plaintext),
            caller_id: self.caller_id.clone(),
        };
        let resp = self.send(&req).await?;
        let hex_ct = resp.data
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| HsmError::Remote("encrypt: missing data in response".into()))?;
        hex::decode(&hex_ct).map_err(|e| HsmError::Serialisation(e.to_string()))
    }

    /// Decrypt `ciphertext` with the key identified by `key_id`.
    pub async fn decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        let req = HsmRequest::Decrypt {
            key_id:     key_id.to_string(),
            ciphertext: hex::encode(ciphertext),
            caller_id:  self.caller_id.clone(),
        };
        let resp = self.send(&req).await?;
        let hex_pt = resp.data
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| HsmError::Remote("decrypt: missing data in response".into()))?;
        let bytes = hex::decode(&hex_pt).map_err(|e| HsmError::Serialisation(e.to_string()))?;
        Ok(Zeroizing::new(bytes))
    }

    // ── Asymmetric operations ─────────────────────────────────────────────

    /// Sign `message` with the key identified by `key_id`.
    pub async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HsmError> {
        let req = HsmRequest::Sign {
            key_id:    key_id.to_string(),
            message:   hex::encode(message),
            caller_id: self.caller_id.clone(),
        };
        let resp = self.send(&req).await?;
        let hex_sig = resp.data
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| HsmError::Remote("sign: missing data in response".into()))?;
        hex::decode(&hex_sig).map_err(|e| HsmError::Serialisation(e.to_string()))
    }

    /// Verify `signature` over `message` using the key identified by `key_id`.
    pub async fn verify(&self, key_id: &str, message: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        let req = HsmRequest::Verify {
            key_id:    key_id.to_string(),
            message:   hex::encode(message),
            signature: hex::encode(signature),
            caller_id: self.caller_id.clone(),
        };
        let resp = self.send(&req).await?;
        Ok(resp.data.and_then(|v| v.as_bool()).unwrap_or(false))
    }

    // ── Key management ────────────────────────────────────────────────────

    /// Generate a new key with the given policy.
    pub async fn generate_key(&self, key_id: &str, policy: Option<KeyPolicy>) -> Result<(), HsmError> {
        let req = HsmRequest::GenerateKey {
            key_id:    key_id.to_string(),
            policy,
            caller_id: self.caller_id.clone(),
        };
        self.send(&req).await.map(|_| ())
    }

    /// Rotate a key (old version archived for decryption, new version used for encryption).
    pub async fn rotate_key(&self, key_id: &str) -> Result<(), HsmError> {
        let req = HsmRequest::RotateKey {
            key_id:    key_id.to_string(),
            caller_id: self.caller_id.clone(),
        };
        self.send(&req).await.map(|_| ())
    }

    /// Permanently destroy a key. Irreversible.
    pub async fn destroy_key(&self, key_id: &str) -> Result<(), HsmError> {
        let req = HsmRequest::DestroyKey {
            key_id:    key_id.to_string(),
            caller_id: self.caller_id.clone(),
        };
        self.send(&req).await.map(|_| ())
    }

    // ── Health ────────────────────────────────────────────────────────────

    /// Check that the PyHSM daemon is running and responsive.
    pub async fn health(&self) -> Result<(), HsmError> {
        let req = HsmRequest::Health { caller_id: self.caller_id.clone() };
        self.send(&req).await.map(|_| ())
    }

    /// Returns `true` if the PyHSM daemon is reachable and responds to health.
    pub async fn is_available(&self) -> bool {
        // For local socket transport, cheaply check file existence first.
        if let HsmTransport::LocalSocket(ref p) = self.transport {
            if !p.exists() {
                return false;
            }
        }
        self.health().await.is_ok()
    }

    // ── Named key helpers (vledger key namespace) ─────────────────────────

    /// Canonical key ID for a table's encryption key.
    pub fn table_encrypt_key_id(table_id: u32) -> String {
        format!("vledger.table.{table_id}.encrypt")
    }

    /// Canonical key ID for the WAL signing key.
    pub fn wal_signing_key_id() -> &'static str {
        "vledger.wal.signing"
    }

    /// Canonical key ID for commit signing.
    pub fn commit_signing_key_id() -> &'static str {
        "vledger.commit.signing"
    }

    /// Ensure the core vledger keys exist, generating them if absent.
    pub async fn provision_vgdb_keys(&self) -> Result<(), HsmError> {
        let keys = [
            (Self::wal_signing_key_id(),    KeyPolicy::sign_only()),
            (Self::commit_signing_key_id(), KeyPolicy::sign_only()),
        ];
        for (kid, policy) in &keys {
            match self.generate_key(kid, Some(policy.clone())).await {
                Ok(()) => debug!(key_id = kid, "HSM key provisioned"),
                Err(e) => {
                    warn!(key_id = kid, "HSM key provision: {e} (may already exist)");
                }
            }
        }
        Ok(())
    }

    // ── Internal dispatch ─────────────────────────────────────────────────

    async fn send(&self, req: &HsmRequest) -> Result<HsmResponse, HsmError> {
        match &self.transport {
            HsmTransport::LocalSocket(path)  => self.send_unix(req, path).await,
            HsmTransport::LocalTcp(addr)     => self.send_tcp(req, addr).await,
            HsmTransport::Remote(cfg)        => self.send_remote(req, cfg).await,
        }
    }

    // ── Model 1: Unix socket ──────────────────────────────────────────────

    #[cfg(unix)]
    async fn send_unix(&self, req: &HsmRequest, path: &PathBuf) -> Result<HsmResponse, HsmError> {
        use tokio::net::UnixStream;

        const MS: u64 = 10_000;

        if !path.exists() {
            return Err(HsmError::SocketNotFound { path: path.display().to_string() });
        }

        let stream = timeout(Duration::from_millis(MS), UnixStream::connect(path))
            .await
            .map_err(|_| HsmError::Timeout { ms: MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

        let line = self.serialize_local(req)?;
        let (reader_half, mut writer) = tokio::io::split(stream);

        timeout(Duration::from_millis(MS), writer.write_all(line.as_bytes()))
            .await
            .map_err(|_| HsmError::Timeout { ms: MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

        let mut buf   = BufReader::new(reader_half);
        let mut resp  = String::new();
        timeout(Duration::from_millis(MS), buf.read_line(&mut resp))
            .await
            .map_err(|_| HsmError::Timeout { ms: MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

        parse_response(&resp)
    }

    #[cfg(not(unix))]
    async fn send_unix(&self, req: &HsmRequest, path: &PathBuf) -> Result<HsmResponse, HsmError> {
        // Unix sockets not available on this platform — fall back to TCP.
        let addr = path.to_str().unwrap_or("127.0.0.1:7777").to_string();
        self.send_tcp(req, &addr).await
    }

    // ── Model 1: TCP loopback (Windows / explicit TCP mode) ───────────────

    async fn send_tcp(&self, req: &HsmRequest, addr: &str) -> Result<HsmResponse, HsmError> {
        const MS: u64 = 10_000;

        let stream = timeout(
            Duration::from_millis(MS),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| HsmError::Timeout { ms: MS })?
        .map_err(|e| HsmError::Ipc(format!("TCP connect to PyHSM at {addr}: {e}")))?;

        let line = self.serialize_local(req)?;
        let (reader_half, mut writer) = tokio::io::split(stream);

        timeout(Duration::from_millis(MS), writer.write_all(line.as_bytes()))
            .await
            .map_err(|_| HsmError::Timeout { ms: MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

        let mut buf  = BufReader::new(reader_half);
        let mut resp = String::new();
        timeout(Duration::from_millis(MS), buf.read_line(&mut resp))
            .await
            .map_err(|_| HsmError::Timeout { ms: MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

        parse_response(&resp)
    }

    // ── Model 2: Remote TLS 1.3 + mTLS ───────────────────────────────────

    async fn send_remote(&self, req: &HsmRequest, cfg: &RemotePyHsmConfig) -> Result<HsmResponse, HsmError> {
        let ms = cfg.timeout_ms;
        let mut last_error = String::new();

        for attempt in 1..=(cfg.max_retries.max(1)) {
            match self.try_send_remote(req, cfg, ms).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    last_error = e.to_string();
                    // Only retry on connection/timeout errors, not on protocol
                    // errors (wrong key, policy violation, etc.).
                    let is_retryable = matches!(
                        &e,
                        HsmError::Connection(_) | HsmError::Timeout { .. } | HsmError::Tls(_)
                    );
                    if !is_retryable || attempt == cfg.max_retries {
                        return Err(e);
                    }
                    warn!(
                        attempt,
                        max = cfg.max_retries,
                        error = %last_error,
                        "PyHSM remote request failed — retrying"
                    );
                    // Brief back-off: 100 ms × attempt number.
                    tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt))).await;
                }
            }
        }

        Err(HsmError::RetriesExhausted {
            attempts:   cfg.max_retries,
            last_error,
        })
    }

    async fn try_send_remote(
        &self,
        req: &HsmRequest,
        cfg: &RemotePyHsmConfig,
        timeout_ms: u64,
    ) -> Result<HsmResponse, HsmError> {
        let (host, port) = cfg.host_port()?;

        // Build TLS connector (validates certs at call time so startup fails
        // fast if the PEM files are missing or corrupt).
        let connector = build_tls_connector(
            &cfg.ca_cert,
            cfg.client_cert.as_deref(),
            cfg.client_key.as_deref(),
        )?;

        // TCP connect
        let tcp = timeout(
            Duration::from_millis(timeout_ms),
            tokio::net::TcpStream::connect((&host as &str, port)),
        )
        .await
        .map_err(|_| HsmError::Timeout { ms: timeout_ms })?
        .map_err(|e| HsmError::Connection(format!("TCP connect to {host}:{port}: {e}")))?;

        // TLS handshake
        let sni = server_name(&host)?;
        let tls_stream = timeout(
            Duration::from_millis(timeout_ms),
            connector.connect(sni, tcp),
        )
        .await
        .map_err(|_| HsmError::Timeout { ms: timeout_ms })?
        .map_err(|e| HsmError::Tls(format!("TLS handshake with {host}:{port}: {e}")))?;

        // Serialize with replay-prevention fields injected.
        let line = self.serialize_remote(req)?;

        let (reader_half, mut writer) = tokio::io::split(tls_stream);

        timeout(Duration::from_millis(timeout_ms), writer.write_all(line.as_bytes()))
            .await
            .map_err(|_| HsmError::Timeout { ms: timeout_ms })?
            .map_err(|e| HsmError::Connection(e.to_string()))?;

        let mut buf  = BufReader::new(reader_half);
        let mut resp = String::new();
        timeout(Duration::from_millis(timeout_ms), buf.read_line(&mut resp))
            .await
            .map_err(|_| HsmError::Timeout { ms: timeout_ms })?
            .map_err(|e| HsmError::Connection(e.to_string()))?;

        parse_response(&resp)
    }

    // ── Serialisation helpers ─────────────────────────────────────────────

    /// Serialize for local transports — plain NDJSON, no extra fields.
    fn serialize_local(&self, req: &HsmRequest) -> Result<String, HsmError> {
        let mut line = serde_json::to_string(req)
            .map_err(|e| HsmError::Serialisation(e.to_string()))?;
        line.push('\n');
        Ok(line)
    }

    /// Serialize for remote transport — inject `requestId` and `timestamp`
    /// for replay-attack prevention.
    fn serialize_remote(&self, req: &HsmRequest) -> Result<String, HsmError> {
        let mut value = serde_json::to_value(req)
            .map_err(|e| HsmError::Serialisation(e.to_string()))?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("requestId".into(),  serde_json::Value::String(new_request_id()));
            obj.insert("timestamp".into(),  serde_json::Value::String(utc_timestamp()));
        }
        let mut line = serde_json::to_string(&value)
            .map_err(|e| HsmError::Serialisation(e.to_string()))?;
        line.push('\n');
        Ok(line)
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn parse_response(resp_line: &str) -> Result<HsmResponse, HsmError> {
    let resp: HsmResponse = serde_json::from_str(resp_line.trim())
        .map_err(|e| HsmError::Serialisation(format!("bad response JSON: {e}")))?;
    if !resp.ok {
        return Err(HsmError::Remote(
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    debug!("HSM IPC OK");
    Ok(resp)
}

/// Default PyHSM address for this platform.
///
/// - Unix: `/tmp/pyhsm.sock`
/// - Windows: `127.0.0.1:7777`
pub fn default_pyhsm_address() -> &'static str {
    #[cfg(unix)]
    { "/tmp/pyhsm.sock" }
    #[cfg(not(unix))]
    { "127.0.0.1:7777" }
}

// ── KeyProvider trait ─────────────────────────────────────────────────────────

use async_trait::async_trait;

#[async_trait]
pub trait KeyProvider: Send + Sync + 'static {
    async fn encrypt_data(&self, key_id: &str, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, HsmError>;
    async fn decrypt_data(&self, key_id: &str, ciphertext: &[u8], aad: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, HsmError>;
    async fn sign_data(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HsmError>;
}

#[async_trait]
impl KeyProvider for HsmClient {
    async fn encrypt_data(&self, key_id: &str, plaintext: &[u8], _aad: Option<&[u8]>) -> Result<Vec<u8>, HsmError> {
        self.encrypt(key_id, plaintext).await
    }
    async fn decrypt_data(&self, key_id: &str, ciphertext: &[u8], _aad: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        self.decrypt(key_id, ciphertext).await
    }
    async fn sign_data(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.sign(key_id, message).await
    }
}

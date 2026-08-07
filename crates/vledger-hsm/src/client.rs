//! Async PyHSM IPC client.
//!
//! Connects to the PyHSM daemon and exposes a typed Rust API matching the
//! TypeScript client in `PyHSM/pyhsm-ts/client.ts`.
//!
//! ## Transport
//! | Platform | Transport | Address format |
//! |---|---|---|
//! | Linux / macOS | Unix domain socket | `/tmp/pyhsm.sock` |
//! | Windows | TCP loopback | `127.0.0.1:7777` or `<host>:<port>` |
//!
//! On Windows, start the PyHSM daemon with `PYHSM_TCP_PORT=7777` and pass
//! `--pyhsm-socket 127.0.0.1:7777` (or set `PYHSM_SOCKET_PATH=127.0.0.1:7777`).
//!
//! ## Usage
//! ```no_run
//! use vledger_hsm::HsmClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     let hsm = HsmClient::new("/tmp/pyhsm.sock", "vledger");
//!     hsm.generate_key("vgdb/table/1/encrypt", None).await.unwrap();
//!     let ct = hsm.encrypt("vgdb/table/1/encrypt", b"secret data").await.unwrap();
//!     let pt = hsm.decrypt("vgdb/table/1/encrypt", &ct).await.unwrap();
//!     assert_eq!(*pt, b"secret data");
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

/// Timeout for a single IPC round-trip.
const IPC_TIMEOUT_MS: u64 = 10_000;

/// Async client for the PyHSM Unix socket daemon.
#[derive(Clone)]
pub struct HsmClient {
    socket_path: PathBuf,
    caller_id:   String,
}

impl HsmClient {
    /// Create a new client.
    ///
    /// `socket_path` — path to the PyHSM Unix domain socket (default `/tmp/pyhsm.sock`).
    /// `caller_id`   — identifies this process in PyHSM's audit log.
    pub fn new(socket_path: impl AsRef<Path>, caller_id: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            caller_id:   caller_id.into(),
        }
    }

    /// Use the default socket/address for this platform.
    ///
    /// - Unix: `/tmp/pyhsm.sock`
    /// - Windows: `127.0.0.1:7777` (PyHSM TCP mode via `PYHSM_TCP_PORT=7777`)
    pub fn default_socket(caller_id: impl Into<String>) -> Self {
        Self::new(default_pyhsm_address(), caller_id)
    }

    // ── Symmetric operations ──────────────────────────────────────────────

    /// Encrypt `plaintext` with the key identified by `key_id`.
    /// Returns raw ciphertext bytes (the PyHSM hex-encodes over the wire).
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
    /// Returns plaintext bytes, zeroized after use by the caller.
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
    /// Returns the raw signature bytes.
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
        let req = HsmRequest::RotateKey { key_id: key_id.to_string(), caller_id: self.caller_id.clone() };
        self.send(&req).await.map(|_| ())
    }

    /// Permanently destroy a key. Irreversible.
    pub async fn destroy_key(&self, key_id: &str) -> Result<(), HsmError> {
        let req = HsmRequest::DestroyKey { key_id: key_id.to_string(), caller_id: self.caller_id.clone() };
        self.send(&req).await.map(|_| ())
    }

    // ── Health ────────────────────────────────────────────────────────────

    /// Check that the PyHSM daemon is running and responsive.
    pub async fn health(&self) -> Result<(), HsmError> {
        let req = HsmRequest::Health { caller_id: self.caller_id.clone() };
        self.send(&req).await.map(|_| ())
    }

    /// Returns `true` if the PyHSM daemon socket exists and responds to health.
    pub async fn is_available(&self) -> bool {
        // On Unix we can cheaply check for socket existence before connecting.
        #[cfg(unix)]
        if !self.socket_path.exists() {
            return false;
        }
        self.health().await.is_ok()
    }

    // ── Named key helpers (vgdb key namespace) ────────────────────────────

    /// Derive the canonical key ID for a table's encryption key.
    pub fn table_encrypt_key_id(table_id: u32) -> String {
        format!("vledger.table.{table_id}.encrypt")
    }

    /// Derive the canonical key ID for the WAL signing key.
    pub fn wal_signing_key_id() -> &'static str {
        "vledger.wal.signing"
    }

    /// Derive the canonical key ID for commit signing.
    pub fn commit_signing_key_id() -> &'static str {
        "vledger.commit.signing"
    }

    /// Ensure the vgdb core keys exist, generating them if absent.
    pub async fn provision_vgdb_keys(&self) -> Result<(), HsmError> {
        let keys = [
            (Self::wal_signing_key_id(),    KeyPolicy::sign_only()),
            (Self::commit_signing_key_id(), KeyPolicy::sign_only()),
        ];
        for (kid, policy) in &keys {
            // generate_key is idempotent on PyHSM if the key already exists
            match self.generate_key(kid, Some(policy.clone())).await {
                Ok(()) => debug!(key_id = kid, "HSM key provisioned"),
                Err(e) => {
                    // Key may already exist — PyHSM returns an error for duplicates
                    warn!(key_id = kid, "HSM key provision: {e} (may already exist)");
                }
            }
        }
        Ok(())
    }

    // ── Internal IPC ──────────────────────────────────────────────────────

    async fn send(&self, req: &HsmRequest) -> Result<HsmResponse, HsmError> {
        // Serialise request once — shared by both platform branches.
        let mut line = serde_json::to_string(req)
            .map_err(|e| HsmError::Serialisation(e.to_string()))?;
        line.push('\n');

        #[cfg(unix)]
        {
            use tokio::net::UnixStream;

            if !self.socket_path.exists() {
                return Err(HsmError::SocketNotFound {
                    path: self.socket_path.display().to_string(),
                });
            }

            let stream = timeout(
                Duration::from_millis(IPC_TIMEOUT_MS),
                UnixStream::connect(&self.socket_path),
            )
            .await
            .map_err(|_| HsmError::Timeout { ms: IPC_TIMEOUT_MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

            let (reader_half, mut writer) = tokio::io::split(stream);

            timeout(Duration::from_millis(IPC_TIMEOUT_MS), writer.write_all(line.as_bytes()))
                .await
                .map_err(|_| HsmError::Timeout { ms: IPC_TIMEOUT_MS })?
                .map_err(|e| HsmError::Ipc(e.to_string()))?;

            let mut buf_reader = BufReader::new(reader_half);
            let mut resp_line  = String::new();
            timeout(
                Duration::from_millis(IPC_TIMEOUT_MS),
                buf_reader.read_line(&mut resp_line),
            )
            .await
            .map_err(|_| HsmError::Timeout { ms: IPC_TIMEOUT_MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

            return parse_response(&resp_line);
        }

        #[cfg(not(unix))]
        {
            // Windows: connect to PyHSM over TCP loopback.
            // The socket_path field holds a "host:port" string on Windows,
            // e.g. "127.0.0.1:7777".  Start PyHSM with PYHSM_TCP_PORT=7777.
            let addr = self.socket_path.to_str().unwrap_or("127.0.0.1:7777");

            let stream = timeout(
                Duration::from_millis(IPC_TIMEOUT_MS),
                tokio::net::TcpStream::connect(addr),
            )
            .await
            .map_err(|_| HsmError::Timeout { ms: IPC_TIMEOUT_MS })?
            .map_err(|e| HsmError::Ipc(format!("TCP connect to PyHSM at {addr}: {e}")))?;

            let (reader_half, mut writer) = tokio::io::split(stream);

            timeout(Duration::from_millis(IPC_TIMEOUT_MS), writer.write_all(line.as_bytes()))
                .await
                .map_err(|_| HsmError::Timeout { ms: IPC_TIMEOUT_MS })?
                .map_err(|e| HsmError::Ipc(e.to_string()))?;

            let mut buf_reader = BufReader::new(reader_half);
            let mut resp_line  = String::new();
            timeout(
                Duration::from_millis(IPC_TIMEOUT_MS),
                buf_reader.read_line(&mut resp_line),
            )
            .await
            .map_err(|_| HsmError::Timeout { ms: IPC_TIMEOUT_MS })?
            .map_err(|e| HsmError::Ipc(e.to_string()))?;

            return parse_response(&resp_line);
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Parse a raw NDJSON response line into an `HsmResponse`.
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

// ── HsmKeyProvider ────────────────────────────────────────────────────────────
//
// Wraps HsmClient to provide EncryptionKey material to PageStore without
// ever exposing the raw key bytes in vgdb's address space.
// Instead, PageStore calls hsm.encrypt/decrypt directly, bypassing the
// in-process EncryptionKey entirely.
//
// This is exposed as a trait so we can mock it in tests.

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

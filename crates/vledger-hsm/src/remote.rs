//! Model 2 — remote PyHSM configuration and mTLS connector.
//!
//! This module provides:
//! - `RemotePyHsmConfig`: all parameters needed to connect to a PyHSM daemon
//!   running on a separate server (same-region private subnet, Model 2).
//! - `HsmTransport`: enum selecting between Model 1 (local Unix socket / TCP
//!   loopback) and Model 2 (remote TLS 1.3 + mTLS).
//! - `build_tls_connector`: builds a `tokio_rustls::TlsConnector` from the
//!   supplied PEM paths, enforcing TLS 1.3 and mutual authentication.
//!
//! ## Security properties
//! - TLS 1.3 only — TLS 1.2 is explicitly disabled.
//! - Client certificate (mTLS) is required when `client_cert` and
//!   `client_key` are set.  Without them the connector is outbound-only
//!   (unauthenticated client), which is appropriate only in very controlled
//!   environments.
//! - The server certificate is verified against `ca_cert`.  There is no
//!   "accept-any-cert" path for remote HSM connections — if the CA cert is
//!   missing the build fails hard at startup, not silently at runtime.
//! - Request/response nonces (unique `request_id` UUID) are embedded in
//!   every wire message to prevent replay attacks over TLS.  PyHSM is
//!   expected to reject duplicate `request_id` values within its replay
//!   window.
//!
//! ## Wire protocol
//! Same newline-delimited JSON as the Unix socket path, extended with two
//! fields that PyHSM MUST validate:
//!
//! ```json
//! {
//!   "type": "encrypt",
//!   "keyId": "vledger.master-key",
//!   "plaintext": "<hex>",
//!   "callerId": "vledger",
//!   "requestId": "<uuid-v4>",
//!   "timestamp": "<rfc3339-utc>"
//! }
//! ```
//!
//! PyHSM should reject:
//!  - duplicate `requestId` within the replay window (recommended: 5 min)
//!  - `timestamp` more than 2 min in the past or future
//!  - requests from a `callerId` not in its allowlist

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::TlsConnector;

use crate::error::HsmError;

// ── RemotePyHsmConfig ─────────────────────────────────────────────────────────

/// All parameters required to reach a remote PyHSM daemon over mTLS.
///
/// Intended to be stored in `key_source.json` (non-secret fields only) and
/// enriched at runtime from environment variables for the secret key material.
///
/// ## Environment variable overrides
/// | Field          | Env var override          |
/// |----------------|--------------------------|
/// | `endpoint`     | `PYHSM_ENDPOINT`          |
/// | `ca_cert`      | `PYHSM_CA_CERT`           |
/// | `client_cert`  | `PYHSM_CLIENT_CERT`       |
/// | `client_key`   | `PYHSM_CLIENT_KEY`        |
/// | `timeout_ms`   | `PYHSM_TIMEOUT_MS`        |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemotePyHsmConfig {
    /// HTTPS endpoint of the remote PyHSM daemon.
    /// Format: `https://<host>:<port>`
    /// Example: `https://pyhsm.internal.example.com:8443`
    pub endpoint: String,

    /// Path to the PEM file containing the CA certificate used to verify the
    /// PyHSM server's TLS certificate.
    ///
    /// Must be set — there is no insecure fallback for remote HSM connections.
    pub ca_cert: String,

    /// Path to the PEM file containing VectorLedger's client certificate
    /// (the public half of the mTLS identity).
    ///
    /// Required for mutual TLS.  If absent, the TLS handshake is one-way
    /// (server-authenticated only) — acceptable only in very restricted
    /// network environments where mTLS is enforced at the load-balancer layer.
    #[serde(default)]
    pub client_cert: Option<String>,

    /// Path to the PEM file containing VectorLedger's client private key
    /// (the private half of the mTLS identity).
    ///
    /// Required when `client_cert` is set.
    #[serde(default)]
    pub client_key: Option<String>,

    /// Per-request timeout in milliseconds.  Default: 5000 ms.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum number of retries on transient network errors.  Default: 3.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_timeout_ms() -> u64 {
    5_000
}
fn default_max_retries() -> u32 {
    3
}

impl RemotePyHsmConfig {
    /// Apply environment variable overrides on top of the deserialized config.
    ///
    /// Call this after deserializing from `key_source.json` so that operators
    /// can override paths at deploy time (e.g. in container env-var injection)
    /// without modifying the config file.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("PYHSM_ENDPOINT") {
            self.endpoint = v;
        }
        if let Ok(v) = std::env::var("PYHSM_CA_CERT") {
            self.ca_cert = v;
        }
        if let Ok(v) = std::env::var("PYHSM_CLIENT_CERT") {
            self.client_cert = Some(v);
        }
        if let Ok(v) = std::env::var("PYHSM_CLIENT_KEY") {
            self.client_key = Some(v);
        }
        if let Ok(v) = std::env::var("PYHSM_TIMEOUT_MS") {
            if let Ok(ms) = v.parse() {
                self.timeout_ms = ms;
            }
        }
    }

    /// Parse the host and port from `self.endpoint`.
    ///
    /// Strips the `https://` scheme prefix (required) and splits on `:`.
    /// Returns `(host, port)`.
    pub fn host_port(&self) -> Result<(String, u16), HsmError> {
        let stripped = self.endpoint.strip_prefix("https://").ok_or_else(|| {
            HsmError::Config(format!(
                "PYHSM endpoint must start with 'https://' — got: {}",
                self.endpoint
            ))
        })?;
        let (host, port_str) = stripped.rsplit_once(':').unwrap_or((stripped, "8443"));
        let port: u16 = port_str
            .parse()
            .map_err(|_| HsmError::Config(format!("Invalid port in PYHSM endpoint: {port_str}")))?;
        Ok((host.to_string(), port))
    }
}

// ── HsmTransport ──────────────────────────────────────────────────────────────

/// Selects the PyHSM transport at construction time.
///
/// | Variant       | Model | Transport             | Typical use                         |
/// |---------------|-------|-----------------------|-------------------------------------|
/// | `LocalSocket` | 1     | Unix domain socket    | Dev, CI, single-server production   |
/// | `LocalTcp`    | 1     | TCP loopback          | Windows dev / same-host PyHSM       |
/// | `Remote`      | 2     | TLS 1.3 + mTLS TCP   | Same-region separate-server prod    |
#[derive(Debug, Clone)]
pub enum HsmTransport {
    /// Model 1 — Unix domain socket path (e.g. `/tmp/pyhsm.sock`).
    LocalSocket(PathBuf),
    /// Model 1 — TCP loopback address (e.g. `127.0.0.1:7777`), used on
    /// Windows or when PyHSM is configured with `PYHSM_TCP_PORT`.
    LocalTcp(String),
    /// Model 2 — remote PyHSM over TLS 1.3 with optional mTLS.
    Remote(RemotePyHsmConfig),
}

impl HsmTransport {
    /// Construct from a socket path string.
    ///
    /// Heuristic:
    /// - If it starts with `https://`  → `Remote` (Model 2).
    /// - If it contains `:`            → `LocalTcp` (Windows loopback).
    /// - Otherwise                     → `LocalSocket` (Unix socket path).
    pub fn from_address(addr: &str) -> Self {
        if addr.starts_with("https://") {
            // Minimal remote config from the endpoint alone; caller must
            // supply full RemotePyHsmConfig for mTLS.
            Self::Remote(RemotePyHsmConfig {
                endpoint: addr.to_string(),
                ca_cert: std::env::var("PYHSM_CA_CERT").unwrap_or_default(),
                client_cert: std::env::var("PYHSM_CLIENT_CERT").ok(),
                client_key: std::env::var("PYHSM_CLIENT_KEY").ok(),
                timeout_ms: default_timeout_ms(),
                max_retries: default_max_retries(),
            })
        } else if addr.contains(':') {
            Self::LocalTcp(addr.to_string())
        } else {
            Self::LocalSocket(PathBuf::from(addr))
        }
    }

    /// Construct a Model 2 `Remote` transport from a full config.
    pub fn remote(mut cfg: RemotePyHsmConfig) -> Self {
        cfg.apply_env_overrides();
        Self::Remote(cfg)
    }

    /// Returns a human-readable description for logging.
    pub fn description(&self) -> String {
        match self {
            Self::LocalSocket(p) => format!("Unix socket: {}", p.display()),
            Self::LocalTcp(addr) => format!("TCP loopback: {addr}"),
            Self::Remote(cfg) => format!("Remote mTLS: {}", cfg.endpoint),
        }
    }
}

// ── TLS connector builder ─────────────────────────────────────────────────────

/// Build a `TlsConnector` that enforces TLS 1.3 and optionally mTLS.
///
/// # Arguments
/// - `ca_cert_path` — PEM file with the CA cert to verify the PyHSM server.
/// - `client_cert_path` / `client_key_path` — optional mTLS identity.
///
/// # Errors
/// Returns `HsmError::Tls` if any PEM file is missing, malformed, or if
/// the key does not match the certificate.
pub fn build_tls_connector(
    ca_cert_path: &str,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> Result<TlsConnector, HsmError> {
    // ── Root CA ───────────────────────────────────────────────────────────
    let ca_pem = read_pem_file(ca_cert_path)?;
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        let cert = cert.map_err(|e| HsmError::Tls(format!("CA cert parse error: {e}")))?;
        root_store
            .add(cert)
            .map_err(|e| HsmError::Tls(format!("CA cert add error: {e}")))?;
    }

    // ── TLS 1.3 only ──────────────────────────────────────────────────────
    let tls_versions: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

    let config = if let (Some(cert_path), Some(key_path)) = (client_cert_path, client_key_path) {
        // ── mTLS: load client certificate + key ───────────────────────────
        let cert_pem = read_pem_file(cert_path)?;
        let key_pem = read_pem_file(key_path)?;

        let client_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| HsmError::Tls(format!("Client cert parse error: {e}")))?;

        if client_certs.is_empty() {
            return Err(HsmError::Tls(format!(
                "No certificate found in client cert file: {cert_path}"
            )));
        }

        // Try PKCS#8 first, then SEC1 (EC), then PKCS#1 (RSA).
        // All three are common outputs of `openssl genrsa` / `openssl genpkey`.
        let client_key: PrivateKeyDer<'static> = {
            // PKCS#8 — `openssl genpkey`, most modern tooling default.
            let mut key_reader = key_pem.as_slice();
            let pkcs8: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_default();

            if let Some(k) = pkcs8.into_iter().next() {
                PrivateKeyDer::Pkcs8(k)
            } else {
                // SEC1 — `openssl ecparam -genkey`, EC keys in legacy PEM format.
                let mut key_reader2 = key_pem.as_slice();
                let ec: Vec<_> = rustls_pemfile::ec_private_keys(&mut key_reader2)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap_or_default();

                if let Some(k) = ec.into_iter().next() {
                    PrivateKeyDer::Sec1(k)
                } else {
                    // PKCS#1 — `openssl genrsa`, RSA keys in legacy PEM format
                    // ("BEGIN RSA PRIVATE KEY").
                    let mut key_reader3 = key_pem.as_slice();
                    let rsa: Vec<_> = rustls_pemfile::rsa_private_keys(&mut key_reader3)
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap_or_default();

                    if let Some(k) = rsa.into_iter().next() {
                        PrivateKeyDer::Pkcs1(k)
                    } else {
                        return Err(HsmError::Tls(format!(
                            "No private key found in client key file: {key_path}\n\
                             Supported formats: PKCS#8 PEM, SEC1 EC PEM, PKCS#1 RSA PEM"
                        )));
                    }
                }
            }
        };

        rustls::ClientConfig::builder_with_protocol_versions(tls_versions)
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .map_err(|e| HsmError::Tls(format!("mTLS client config error: {e}")))?
    } else {
        // ── Server-authenticated only (no client cert) ────────────────────
        rustls::ClientConfig::builder_with_protocol_versions(tls_versions)
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Parse the server name from the host string for TLS SNI.
pub fn server_name(host: &str) -> Result<ServerName<'static>, HsmError> {
    ServerName::try_from(host.to_string())
        .map_err(|_| HsmError::Tls(format!("Invalid TLS server name: {host}")))
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn read_pem_file(path: &str) -> Result<Vec<u8>, HsmError> {
    std::fs::read(Path::new(path))
        .map_err(|e| HsmError::Tls(format!("Cannot read PEM file '{path}': {e}")))
}

/// Generate a UUID v4 request ID for replay-attack prevention.
pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Current UTC timestamp in RFC 3339 format, used in remote requests.
pub fn utc_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

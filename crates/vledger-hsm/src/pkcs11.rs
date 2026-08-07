//! PKCS#11 and cloud HSM adapter layer for VectorLedger.
//!
//! This module provides:
//! - `Pkcs11Provider` trait: uniform interface over any HSM backend.
//! - `SoftHsmProvider`: software HSM backed by the PyHSM Unix socket daemon
//!   (implements `Pkcs11Provider`, used in dev/test, wraps `HsmClient`).
//! - `AwsCloudHsmProvider`: AWS CloudHSM bridge config + client.
//! - `AzureHsmProvider`: Azure Dedicated HSM bridge config + client.
//! - `HsmProviderConfig`: config enum selecting which backend to use at
//!   startup via `vledger init --hsm-backend <soft|aws|azure>`.
//!
//! ## Key namespace (PKCS#11 CKA_LABEL)
//! | Label                     | Type         | Purpose                     |
//! |---------------------------|--------------|-----------------------------|
//! | `vledger.table.<id>.encrypt` | AES-256      | Per-table data encryption   |
//! | `vledger.wal.signing`        | Ed25519      | WAL commit signing          |
//! | `vledger.commit.signing`     | Ed25519      | DB-level commit signing     |
//!
//! Raw key material **never** leaves the HSM.  All crypto operations are
//! performed inside the HSM; vgdb receives only ciphertext / signatures.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::HsmError;

// ── Pkcs11Provider trait ──────────────────────────────────────────────────────

/// Uniform interface over any HSM backend (SoftHSM, AWS CloudHSM, Azure HSM).
///
/// All operations are async to accommodate both local Unix-socket IPC (SoftHSM)
/// and remote HTTPS/gRPC calls (AWS / Azure).
#[async_trait]
pub trait Pkcs11Provider: Send + Sync + 'static {
    /// Generate a symmetric AES-256 key under `label`.
    async fn generate_aes_key(&self, label: &str) -> Result<(), HsmError>;

    /// Generate an Ed25519 signing key pair under `label`.
    async fn generate_signing_key(&self, label: &str) -> Result<(), HsmError>;

    /// Encrypt `plaintext` with the AES-256-GCM key identified by `label`.
    /// Returns authenticated ciphertext (nonce prepended).
    async fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Decrypt `ciphertext` with the AES-256-GCM key identified by `label`.
    async fn decrypt(
        &self,
        label: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HsmError>;

    /// Sign `message` with the Ed25519 key identified by `label`.
    async fn sign(&self, label: &str, message: &[u8]) -> Result<Vec<u8>, HsmError>;

    /// Verify `signature` over `message` using the key identified by `label`.
    async fn verify(
        &self,
        label: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmError>;

    /// Rotate the key identified by `label` (old version kept for decryption).
    async fn rotate_key(&self, label: &str) -> Result<(), HsmError>;

    /// Permanently destroy the key identified by `label`. Irreversible.
    async fn destroy_key(&self, label: &str) -> Result<(), HsmError>;

    /// Health-check — returns `Ok(())` if the HSM is reachable and operational.
    async fn health(&self) -> Result<(), HsmError>;

    /// Provision the standard vgdb key set (idempotent).
    async fn provision_vgdb_keys(&self) -> Result<(), HsmError> {
        use crate::client::HsmClient;
        let labels = [
            HsmClient::wal_signing_key_id(),
            HsmClient::commit_signing_key_id(),
        ];
        for label in labels {
            match self.generate_signing_key(label).await {
                Ok(()) | Err(HsmError::Remote(_)) => {} // already exists is OK
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}


// ── SoftHsmProvider ───────────────────────────────────────────────────────────

/// Software HSM provider — wraps the `HsmClient` Unix-socket daemon.
///
/// Suitable for development, CI, and deployments where a dedicated hardware
/// security module is unavailable.  Key material is protected by the PyHSM
/// daemon's AES-KWP wrapped keystore (see `../PyHSM`).
pub struct SoftHsmProvider {
    client: crate::client::HsmClient,
}

impl SoftHsmProvider {
    /// Connect to the default PyHSM socket (`/tmp/pyhsm.sock`).
    pub fn new_default() -> Self {
        Self {
            client: crate::client::HsmClient::default_socket("vledger"),
        }
    }

    /// Connect to a custom socket path.
    pub fn new(socket_path: impl AsRef<std::path::Path>) -> Self {
        Self {
            client: crate::client::HsmClient::new(socket_path, "vledger"),
        }
    }
}

#[async_trait]
impl Pkcs11Provider for SoftHsmProvider {
    async fn generate_aes_key(&self, label: &str) -> Result<(), HsmError> {
        self.client
            .generate_key(label, Some(crate::protocol::KeyPolicy::encrypt_decrypt()))
            .await
    }

    async fn generate_signing_key(&self, label: &str) -> Result<(), HsmError> {
        self.client
            .generate_key(label, Some(crate::protocol::KeyPolicy::sign_only()))
            .await
    }

    async fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.client.encrypt(label, plaintext).await
    }

    async fn decrypt(
        &self,
        label: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        self.client.decrypt(label, ciphertext).await
    }

    async fn sign(&self, label: &str, message: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.client.sign(label, message).await
    }

    async fn verify(
        &self,
        label: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmError> {
        self.client.verify(label, message, signature).await
    }

    async fn rotate_key(&self, label: &str) -> Result<(), HsmError> {
        self.client.rotate_key(label).await
    }

    async fn destroy_key(&self, label: &str) -> Result<(), HsmError> {
        self.client.destroy_key(label).await
    }

    async fn health(&self) -> Result<(), HsmError> {
        self.client.health().await
    }
}


// ── AWS CloudHSM ──────────────────────────────────────────────────────────────

/// Configuration for the AWS CloudHSM bridge.
///
/// AWS CloudHSM exposes a PKCS#11 shared library on the HSM-connected host.
/// In vgdb we bridge it via a thin gRPC sidecar
/// (`vledger-hsm-aws-bridge`) that translates our JSON IPC protocol to
/// PKCS#11 CKM_AES_GCM / CKM_ECDSA calls inside the CloudHSM cluster.
///
/// When `use_cloudhsm_library = true` vgdb expects the bridge sidecar to be
/// running on `bridge_socket` (default `~/.vledger-hsm-aws/bridge.sock`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCloudHsmConfig {
    /// Path to the AWS CloudHSM bridge Unix socket.
    pub bridge_socket: String,
    /// CloudHSM cluster ID (for tagging / audit).
    pub cluster_id: String,
    /// Crypto-user name for PKCS#11 login.
    pub crypto_user: String,
    /// Whether to verify the bridge's TLS certificate (production: true).
    pub verify_bridge_tls: bool,
}

impl Default for AwsCloudHsmConfig {
    fn default() -> Self {
        Self {
            bridge_socket: format!(
                "{}/.vledger-hsm-aws/bridge.sock",
                home_dir()
            ),
            cluster_id: String::new(),
            crypto_user: "vgdb-cu".into(),
            verify_bridge_tls: true,
        }
    }
}

/// AWS CloudHSM provider.
///
/// Delegates all PKCS#11 operations to the vledger-hsm-aws-bridge sidecar
/// over the same newline-delimited JSON / Unix socket protocol used by
/// `SoftHsmProvider`, so the `Pkcs11Provider` impl is identical.
pub struct AwsCloudHsmProvider {
    inner: SoftHsmProvider,
    pub config: AwsCloudHsmConfig,
}

impl AwsCloudHsmProvider {
    pub fn new(config: AwsCloudHsmConfig) -> Self {
        let inner = SoftHsmProvider::new(&config.bridge_socket);
        Self { inner, config }
    }
}

#[async_trait]
impl Pkcs11Provider for AwsCloudHsmProvider {
    async fn generate_aes_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.generate_aes_key(label).await
    }
    async fn generate_signing_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.generate_signing_key(label).await
    }
    async fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.inner.encrypt(label, plaintext).await
    }
    async fn decrypt(&self, label: &str, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        self.inner.decrypt(label, ct).await
    }
    async fn sign(&self, label: &str, message: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.inner.sign(label, message).await
    }
    async fn verify(&self, label: &str, msg: &[u8], sig: &[u8]) -> Result<bool, HsmError> {
        self.inner.verify(label, msg, sig).await
    }
    async fn rotate_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.rotate_key(label).await
    }
    async fn destroy_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.destroy_key(label).await
    }
    async fn health(&self) -> Result<(), HsmError> {
        self.inner.health().await
    }
}


// ── Azure Dedicated HSM ───────────────────────────────────────────────────────

/// Configuration for the Azure Dedicated HSM bridge.
///
/// Azure Dedicated HSM is based on Thales Luna Network HSM 7.  vgdb accesses
/// it via the `vledger-hsm-azure-bridge` sidecar that wraps the Luna PKCS#11
/// library over our JSON IPC protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureHsmConfig {
    /// Path to the Azure HSM bridge Unix socket.
    pub bridge_socket: String,
    /// Azure resource group (for audit tagging).
    pub resource_group: String,
    /// HSM device IP / hostname (used by the bridge sidecar).
    pub device_host: String,
    /// Partition name on the Luna HSM.
    pub partition: String,
}

impl Default for AzureHsmConfig {
    fn default() -> Self {
        Self {
            bridge_socket: format!(
                "{}/.vledger-hsm-azure/bridge.sock",
                home_dir()
            ),
            resource_group: String::new(),
            device_host: String::new(),
            partition: "vledger".into(),
        }
    }
}

/// Azure Dedicated HSM provider.
pub struct AzureHsmProvider {
    inner: SoftHsmProvider,
    pub config: AzureHsmConfig,
}

impl AzureHsmProvider {
    pub fn new(config: AzureHsmConfig) -> Self {
        let inner = SoftHsmProvider::new(&config.bridge_socket);
        Self { inner, config }
    }
}

#[async_trait]
impl Pkcs11Provider for AzureHsmProvider {
    async fn generate_aes_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.generate_aes_key(label).await
    }
    async fn generate_signing_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.generate_signing_key(label).await
    }
    async fn encrypt(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.inner.encrypt(label, plaintext).await
    }
    async fn decrypt(&self, label: &str, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        self.inner.decrypt(label, ct).await
    }
    async fn sign(&self, label: &str, message: &[u8]) -> Result<Vec<u8>, HsmError> {
        self.inner.sign(label, message).await
    }
    async fn verify(&self, label: &str, msg: &[u8], sig: &[u8]) -> Result<bool, HsmError> {
        self.inner.verify(label, msg, sig).await
    }
    async fn rotate_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.rotate_key(label).await
    }
    async fn destroy_key(&self, label: &str) -> Result<(), HsmError> {
        self.inner.destroy_key(label).await
    }
    async fn health(&self) -> Result<(), HsmError> {
        self.inner.health().await
    }
}

// ── Cross-platform home directory ─────────────────────────────────────────────

/// Returns the current user's home directory as a `String`.
///
/// Checks (in order):
/// - `HOME` (Unix)
/// - `USERPROFILE` (Windows)
/// - `HOMEDRIVE` + `HOMEPATH` (Windows legacy)
/// - Falls back to `/root` on Unix or `C:\Users\Default` on Windows.
fn home_dir() -> String {
    if let Ok(h) = std::env::var("HOME") {
        return h;
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        return h;
    }
    if let (Ok(drive), Ok(path)) = (
        std::env::var("HOMEDRIVE"),
        std::env::var("HOMEPATH"),
    ) {
        return format!("{drive}{path}");
    }
    #[cfg(windows)]
    { r"C:\Users\Default".into() }
    #[cfg(not(windows))]
    { "/root".into() }
}

// ── HsmProviderConfig — selects backend at startup ────────────────────────────

/// Top-level config enum.  Deserialised from `vledger-data/keys/hsm_config.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum HsmProviderConfig {
    /// Local software HSM (PyHSM daemon) — default for dev/test.
    Soft {
        socket_path: Option<String>,
    },
    /// AWS CloudHSM via bridge sidecar.
    AwsCloudHsm(AwsCloudHsmConfig),
    /// Azure Dedicated HSM via bridge sidecar.
    AzureDedicatedHsm(AzureHsmConfig),
}

impl Default for HsmProviderConfig {
    fn default() -> Self {
        Self::Soft { socket_path: None }
    }
}

impl HsmProviderConfig {
    /// Build the appropriate `Box<dyn Pkcs11Provider>` from config.
    pub fn build_provider(self) -> Box<dyn Pkcs11Provider> {
        match self {
            Self::Soft { socket_path } => {
                let p = match socket_path {
                    Some(path) => SoftHsmProvider::new(path),
                    None       => SoftHsmProvider::new_default(),
                };
                Box::new(p)
            }
            Self::AwsCloudHsm(cfg) => Box::new(AwsCloudHsmProvider::new(cfg)),
            Self::AzureDedicatedHsm(cfg) => Box::new(AzureHsmProvider::new(cfg)),
        }
    }
}

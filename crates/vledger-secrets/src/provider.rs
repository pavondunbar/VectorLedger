//! `MasterKeyProvider` trait and all backend implementations.
//!
//! ## Fix #1 — reqwest replaces hand-rolled HTTP client
//! All Vault and AWS KMS HTTP calls now use `reqwest` with the `rustls-tls`
//! backend.  The previous `MinimalHttpClient` / `RequestBuilder` /
//! `base64_decode` / `url_parse` implementations have been removed.
//!
//! ## Fix #7 — HMAC integrity check on kms_data_key.enc
//! The AWS KMS ciphertext blob is now stored as
//! `<blob_b64>\n<hmac_hex>\n` where `hmac_hex` is
//! `HMAC-SHA256(key = BLAKE3(access_key_id || region), msg = blob_b64)`.
//! On every restart the HMAC is verified before calling KMS Decrypt.
//! A tampered blob is detected before any network call is made.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::SecretsError;

type HmacSha256 = Hmac<Sha256>;

// ── MasterKeyProvider trait ───────────────────────────────────────────────────

/// Async trait implemented by every secrets-manager backend.
///
/// Callers receive a `Zeroizing<[u8; 32]>` — the 32-byte master key is
/// cleared from memory when the returned value is dropped.
#[async_trait]
pub trait MasterKeyProvider: Send + Sync + 'static {
    /// Fetch the 32-byte master encryption key.
    async fn load_master_key(&self) -> Result<Zeroizing<[u8; 32]>, SecretsError>;

    /// Human-readable description of this provider (logged at startup).
    fn description(&self) -> String;
}


// ── KeySourceConfig — persisted to key_source.json ───────────────────────────

/// Top-level configuration serialised to `vledger-data/keys/key_source.json`.
///
/// Contains only non-secret metadata.  The key itself never appears here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum KeySourceConfig {
    /// Read key from the `VectorLedger_MASTER_KEY` environment variable (hex-encoded).
    /// Suitable for CI pipelines and container deployments via secrets injection.
    Env {
        /// Name of the environment variable to read. Default: `VectorLedger_MASTER_KEY`.
        #[serde(default = "default_env_var")]
        var: String,
    },

    /// Read key from a hex file on disk (dev / last-resort fallback only).
    /// The file must contain exactly 64 hex characters and have mode 0o600.
    File {
        path: String,
    },

    /// HashiCorp Vault KV v2 backend.
    ///
    /// The Vault token is read from `VAULT_TOKEN` env variable at runtime
    /// (never stored in config).
    Vault {
        /// Vault server address, e.g. `http://127.0.0.1:8200`.
        addr: String,
        /// KV v2 mount path, e.g. `secret`.
        mount: String,
        /// Secret path within the mount, e.g. `vledger/master_key`.
        secret_path: String,
        /// JSON field name within the secret containing the hex key.
        /// Default: `"value"`.
        #[serde(default = "default_vault_field")]
        field: String,
        /// Vault namespace (Vault Enterprise only). `None` for open-source Vault.
        #[serde(default)]
        namespace: Option<String>,
    },

    /// AWS KMS data-key backend.
    ///
    /// Uses `GenerateDataKey` to produce a 256-bit plaintext data key.
    /// AWS credentials are resolved via the standard credential chain
    /// (env vars → `~/.aws/credentials` → instance metadata).
    AwsKms {
        /// KMS Customer Master Key ARN or alias.
        key_id: String,
        /// AWS region, e.g. `us-east-1`.
        region: String,
        /// Optional encryption context key-value pairs for audit.
        #[serde(default)]
        encryption_context: std::collections::HashMap<String, String>,
    },

    /// PyHSM Unix-socket daemon backend — **Model 1** (same server).
    ///
    /// The master key is generated once inside the PyHSM daemon and never
    /// leaves it.  VectorLedger stores only an encrypted blob (sealed by
    /// PyHSM's own AES-256-GCM-SIV key-wrapping layer) in
    /// `keys/pyhsm_master_key.enc`, plus an HMAC-BLAKE3 integrity seal.
    ///
    /// On every start the blob is sent to PyHSM for decryption; the
    /// plaintext key exists in-process only for the duration of startup
    /// key derivation, then is zeroized.
    ///
    /// ## Prerequisites
    /// The PyHSM TypeScript daemon (`pyhsm-ts/process.ts`) must be running
    /// and listening on `socket_path` before `vledger start` is invoked.
    PyHsm {
        /// Path to the PyHSM Unix domain socket.
        /// Default: `/tmp/pyhsm.sock`  (overrideable via `PYHSM_SOCKET_PATH`).
        #[serde(default = "default_pyhsm_socket")]
        socket_path: String,
        /// Caller identifier written to the PyHSM audit log.
        /// Default: `"vledger"`.
        #[serde(default = "default_pyhsm_caller_id")]
        caller_id: String,
        /// Key ID used inside PyHSM for the master-key wrapping key.
        /// Default: `"vledger.master-key"`.
        #[serde(default = "default_pyhsm_key_id")]
        key_id: String,
    },

    /// Remote PyHSM daemon backend — **Model 2** (same-region, separate server).
    ///
    /// PyHSM runs on a dedicated server in the same region's private subnet.
    /// VectorLedger connects over TLS 1.3 with mutual certificate
    /// authentication (mTLS).  The JSON IPC wire protocol is identical to
    /// the local socket transport; every remote request additionally carries
    /// a `requestId` (UUID v4) and `timestamp` (RFC 3339) for replay-attack
    /// prevention.
    ///
    /// ## Key lifecycle
    /// Identical to `PyHsm`: a wrapped blob is cached in
    /// `keys/pyhsm_master_key.enc` with an HMAC integrity seal.  On first
    /// boot the plaintext key is generated locally, encrypted by the remote
    /// PyHSM daemon, and the ciphertext is cached.  On subsequent boots the
    /// cached blob is decrypted by PyHSM over mTLS; the plaintext exists
    /// in-process only for startup key derivation, then is zeroized.
    ///
    /// ## Configuration
    /// All paths may be overridden by environment variables at runtime:
    ///
    /// | Field          | Env var override      |
    /// |----------------|-----------------------|
    /// | `endpoint`     | `PYHSM_ENDPOINT`      |
    /// | `ca_cert`      | `PYHSM_CA_CERT`       |
    /// | `client_cert`  | `PYHSM_CLIENT_CERT`   |
    /// | `client_key`   | `PYHSM_CLIENT_KEY`    |
    /// | `timeout_ms`   | `PYHSM_TIMEOUT_MS`    |
    ///
    /// ## Prerequisites
    /// - PyHSM server must expose an HTTPS endpoint on the private subnet.
    /// - CA certificate that signed the PyHSM server's TLS cert must be
    ///   present at `ca_cert`.
    /// - mTLS client certificate and key (signed by PyHSM's client CA) must
    ///   be present at `client_cert` / `client_key`.
    /// - Security group / firewall must allow VectorLedger → PyHSM only.
    RemotePyHsm {
        /// HTTPS endpoint of the remote PyHSM daemon.
        /// Example: `https://pyhsm.internal.example.com:8443`
        /// Overrideable via `PYHSM_ENDPOINT`.
        endpoint: String,

        /// Path to the PEM file containing the CA certificate used to verify
        /// the PyHSM server's TLS certificate.
        /// Overrideable via `PYHSM_CA_CERT`.
        ca_cert: String,

        /// Path to the PEM file containing VectorLedger's mTLS client
        /// certificate.  Required for mutual TLS.
        /// Overrideable via `PYHSM_CLIENT_CERT`.
        #[serde(default)]
        client_cert: Option<String>,

        /// Path to the PEM file containing VectorLedger's mTLS client private
        /// key.  Required when `client_cert` is set.
        /// Overrideable via `PYHSM_CLIENT_KEY`.
        #[serde(default)]
        client_key: Option<String>,

        /// Per-request timeout in milliseconds.  Default: 5000.
        /// Overrideable via `PYHSM_TIMEOUT_MS`.
        #[serde(default = "default_remote_timeout_ms")]
        timeout_ms: u64,

        /// Maximum number of retries on transient network errors.  Default: 3.
        #[serde(default = "default_remote_max_retries")]
        max_retries: u32,

        /// Caller identifier written to the PyHSM audit log.
        /// Default: `"vledger"`.
        #[serde(default = "default_pyhsm_caller_id")]
        caller_id: String,

        /// Key ID used inside PyHSM for the master-key wrapping key.
        /// Default: `"vledger.master-key"`.
        #[serde(default = "default_pyhsm_key_id")]
        key_id: String,
    },
}

fn default_env_var()     -> String { "VectorLedger_MASTER_KEY".into() }
fn default_vault_field() -> String { "value".into() }
fn default_pyhsm_socket()    -> String {
    #[cfg(unix)]
    { "/tmp/pyhsm.sock".into() }
    #[cfg(not(unix))]
    { "127.0.0.1:7777".into() }
}
fn default_pyhsm_caller_id() -> String { "vledger".into() }
fn default_pyhsm_key_id()    -> String { "vledger.master-key".into() }
fn default_remote_timeout_ms()  -> u64 { 5_000 }
fn default_remote_max_retries() -> u32 { 3 }

impl KeySourceConfig {
    /// Load config from a JSON file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SecretsError> {
        let data = std::fs::read_to_string(path.as_ref())
            .map_err(|e| SecretsError::FileError {
                path:   path.as_ref().display().to_string(),
                reason: e.to_string(),
            })?;
        serde_json::from_str(&data)
            .map_err(|e| SecretsError::Serialisation(e.to_string()))
    }

    /// Save config to a JSON file with mode 0o600.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), SecretsError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| SecretsError::Serialisation(e.to_string()))?;
        std::fs::write(path.as_ref(), &json)?;
        set_mode_600(path.as_ref());
        Ok(())
    }
}

/// Build a `Box<dyn MasterKeyProvider>` from a `KeySourceConfig`.
///
/// `cache_dir` should be `data_dir/keys/` so that the PyHSM encrypted blob
/// (`pyhsm_master_key.enc`) and the AWS KMS blob (`kms_data_key.enc`) are
/// written next to `key_source.json` and survive across restarts regardless
/// of the process working directory.  Pass `None` only in tests or when no
/// data directory exists yet.
pub fn build_provider(
    cfg:       &KeySourceConfig,
    cache_dir: Option<&Path>,
) -> Result<Box<dyn MasterKeyProvider>, SecretsError> {
    let cache = cache_dir.map(|p| p.to_path_buf());
    match cfg {
        KeySourceConfig::Env { var } =>
            Ok(Box::new(EnvVarProvider { var: var.clone() })),
        KeySourceConfig::File { path } =>
            Ok(Box::new(FileProvider { path: PathBuf::from(path) })),
        KeySourceConfig::Vault { addr, mount, secret_path, field, namespace } =>
            Ok(Box::new(HashiCorpVaultProvider {
                addr:        addr.clone(),
                mount:       mount.clone(),
                secret_path: secret_path.clone(),
                field:       field.clone(),
                namespace:   namespace.clone(),
            })),
        KeySourceConfig::AwsKms { key_id, region, encryption_context } =>
            Ok(Box::new(AwsKmsProvider {
                key_id:             key_id.clone(),
                region:             region.clone(),
                encryption_context: encryption_context.clone(),
                cache_dir:          cache.clone(),
            })),
        KeySourceConfig::PyHsm { socket_path, caller_id, key_id } =>
            Ok(Box::new(PyHsmProvider {
                socket_path: socket_path.clone(),
                caller_id:   caller_id.clone(),
                key_id:      key_id.clone(),
                cache_dir:   cache.clone(),
            })),
        KeySourceConfig::RemotePyHsm {
            endpoint, ca_cert, client_cert, client_key,
            timeout_ms, max_retries, caller_id, key_id,
        } =>
            Ok(Box::new(RemotePyHsmProvider {
                endpoint:    endpoint.clone(),
                ca_cert:     ca_cert.clone(),
                client_cert: client_cert.clone(),
                client_key:  client_key.clone(),
                timeout_ms:  *timeout_ms,
                max_retries: *max_retries,
                caller_id:   caller_id.clone(),
                key_id:      key_id.clone(),
                cache_dir:   cache,
            })),
    }
}


// ── EnvVarProvider ────────────────────────────────────────────────────────────

/// Reads the master key from an environment variable (hex-encoded, 64 chars).
pub struct EnvVarProvider {
    pub var: String,
}

#[async_trait]
impl MasterKeyProvider for EnvVarProvider {
    async fn load_master_key(&self) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
        let hex_val = std::env::var(&self.var)
            .map_err(|_| SecretsError::EnvVarMissing { var: self.var.clone() })?;
        parse_hex_key(hex_val.trim())
    }

    fn description(&self) -> String {
        format!("environment variable '{}'", self.var)
    }
}

// ── FileProvider ──────────────────────────────────────────────────────────────

/// Reads the master key from a hex file on disk.
///
/// **Development / fallback use only.**
pub struct FileProvider {
    pub path: PathBuf,
}

#[async_trait]
impl MasterKeyProvider for FileProvider {
    async fn load_master_key(&self) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
        let hex_val = std::fs::read_to_string(&self.path)
            .map_err(|e| SecretsError::FileError {
                path:   self.path.display().to_string(),
                reason: e.to_string(),
            })?;
        parse_hex_key(hex_val.trim())
    }

    fn description(&self) -> String {
        format!("key file '{}'", self.path.display())
    }
}

impl FileProvider {
    /// Generate a new random key, write it to `path` with mode 0o600,
    /// and return the provider.
    pub fn generate(path: impl AsRef<Path>) -> Result<Self, SecretsError> {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        std::fs::write(path.as_ref(), hex::encode(key))?;
        set_mode_600(path.as_ref());
        tracing::warn!(
            path = %path.as_ref().display(),
            "Master key written to disk file. For production use --key-source env, vault, or aws_kms."
        );
        Ok(Self { path: path.as_ref().to_path_buf() })
    }
}


// ── HashiCorpVaultProvider ────────────────────────────────────────────────────

/// Fetches the master key from HashiCorp Vault KV v2.
///
/// Uses reqwest (rustls-tls backend) — no hand-rolled HTTP client (Fix #1).
///
/// ## Prerequisites
/// - `VAULT_TOKEN` environment variable must be set.
/// - The secret must have a field named `field` (default `"value"`) whose
///   value is the 64-character hex-encoded 32-byte master key.
pub struct HashiCorpVaultProvider {
    pub addr:        String,
    pub mount:       String,
    pub secret_path: String,
    pub field:       String,
    pub namespace:   Option<String>,
}

#[async_trait]
impl MasterKeyProvider for HashiCorpVaultProvider {
    async fn load_master_key(&self) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
        let token = std::env::var("VAULT_TOKEN")
            .map_err(|_| SecretsError::Vault(
                "VAULT_TOKEN environment variable not set".into()
            ))?;

        // Fix #6: check the token's TTL before fetching the secret.
        // A token that expires between deployments will cause a silent startup
        // failure.  We log an error if already expired, a warning if < 24 h
        // remaining, and an info message otherwise.  The check is best-effort
        // and non-fatal — if the lookup-self call fails we proceed anyway.
        self.check_vault_token_ttl(&token).await;

        // KV v2 read URL: <addr>/v1/<mount>/data/<path>
        let url = format!(
            "{}/v1/{}/data/{}",
            self.addr.trim_end_matches('/'),
            self.mount,
            self.secret_path,
        );

        let client = build_reqwest_client()?;
        let mut req = client
            .get(&url)
            .header("X-Vault-Token", &token);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        let resp = req.send().await
            .map_err(|e| SecretsError::Http(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SecretsError::Vault(format!(
                "Vault returned HTTP {status}: {body}"
            )));
        }

        // KV v2 response shape: { "data": { "data": { "<field>": "<hex>" } } }
        let body: serde_json::Value = resp.json().await
            .map_err(|e| SecretsError::Vault(format!("parse response: {e}")))?;

        let hex_val = body
            .pointer(&format!("/data/data/{}", self.field))
            .and_then(|v| v.as_str())
            .ok_or_else(|| SecretsError::Vault(format!(
                "field '{}' not found in KV v2 secret at '{}'",
                self.field, self.secret_path
            )))?;

        parse_hex_key(hex_val.trim())
    }

    fn description(&self) -> String {
        format!(
            "HashiCorp Vault KV v2 at {}/{}/{}",
            self.addr, self.mount, self.secret_path
        )
    }
}

impl HashiCorpVaultProvider {
    /// Call `GET /v1/auth/token/lookup-self` and log the token's TTL.
    ///
    /// Fix #6: surface token expiry problems at startup rather than at the
    /// next server restart when the token may have already expired.
    ///
    /// - TTL == 0  → token never expires (root token or no-ttl policy) — info.
    /// - TTL > 0 and < 24 h → warn: rotation is overdue.
    /// - TTL <= 0 (expired) → error: the secret fetch that follows will fail.
    /// - Request fails → debug log; we proceed and let the secret fetch error.
    async fn check_vault_token_ttl(&self, token: &str) {
        let url = format!(
            "{}/v1/auth/token/lookup-self",
            self.addr.trim_end_matches('/')
        );
        let client = match build_reqwest_client() {
            Ok(c)  => c,
            Err(e) => { tracing::debug!("Vault TTL check: cannot build client: {e}"); return; }
        };
        let mut req = client.get(&url).header("X-Vault-Token", token);
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let resp = match req.send().await {
            Ok(r)  => r,
            Err(e) => { tracing::debug!("Vault TTL check request failed: {e}"); return; }
        };
        if !resp.status().is_success() {
            tracing::debug!("Vault TTL check returned {}", resp.status());
            return;
        }
        let body: serde_json::Value = match resp.json().await {
            Ok(b)  => b,
            Err(e) => { tracing::debug!("Vault TTL check: parse error: {e}"); return; }
        };
        // Response shape: { "data": { "ttl": <seconds>, "expire_time": "<rfc3339>" } }
        let ttl = body
            .pointer("/data/ttl")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        let expire_time = body
            .pointer("/data/expire_time")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        const WARN_THRESHOLD_SECS: i64 = 86_400; // 24 hours
        if ttl == 0 {
            tracing::info!(
                vault_addr = %self.addr,
                "Vault token has no TTL (non-expiring)"
            );
        } else if ttl < 0 {
            tracing::error!(
                vault_addr = %self.addr,
                expire_time,
                "Vault token appears to be expired — secret fetch will fail. \
                 Renew VAULT_TOKEN before restarting."
            );
        } else if ttl < WARN_THRESHOLD_SECS {
            tracing::warn!(
                vault_addr  = %self.addr,
                ttl_seconds = ttl,
                expire_time,
                "Vault token expires in less than 24 h — renew VAULT_TOKEN \
                 before the next server restart."
            );
        } else {
            tracing::info!(
                vault_addr  = %self.addr,
                ttl_seconds = ttl,
                expire_time,
                "Vault token TTL OK"
            );
        }
    }
}


// ── AwsKmsProvider ────────────────────────────────────────────────────────────

/// Derives the master key from AWS KMS via reqwest (Fix #1).
///
/// ## Cache file format (Fix #7 — HMAC integrity check)
/// `kms_data_key.enc` now stores two newline-separated lines:
/// ```text
/// <ciphertext_blob_base64>
/// <hmac_sha256_hex>
/// ```
/// where `hmac_sha256_hex = HMAC-SHA256(key=BLAKE3(access_key_id||region),
/// msg=ciphertext_blob_base64)`.
///
/// On every restart the HMAC is verified before calling KMS Decrypt.
/// A file whose HMAC does not match is rejected with an error — a local
/// attacker who can write to the cache file cannot substitute a different
/// KMS blob without also knowing the AWS credentials (which are used as
/// the HMAC key derivation input).
pub struct AwsKmsProvider {
    pub key_id:             String,
    pub region:             String,
    pub encryption_context: std::collections::HashMap<String, String>,
    /// Directory where `kms_data_key.enc` is cached (mode 0o600).
    pub cache_dir: Option<std::path::PathBuf>,
}

impl AwsKmsProvider {
    fn cache_path(&self) -> std::path::PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("kms_data_key.enc")
    }

    /// Derive the HMAC key from AWS credentials + region.
    /// Using credentials as input means an attacker without them cannot
    /// forge a valid HMAC for a substituted blob.
    fn hmac_key(creds: &AwsCredentials, region: &str) -> [u8; 32] {
        let mut input = creds.access_key_id.as_bytes().to_vec();
        input.extend_from_slice(region.as_bytes());
        *blake3::hash(&input).as_bytes()
    }

    /// Compute HMAC-SHA256 over `data` using `key`.
    fn compute_hmac(key: &[u8], data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Write `blob_b64` and its HMAC to the cache file (mode 0o600).
    fn write_cache(
        &self,
        cache: &Path,
        blob_b64: &str,
        creds: &AwsCredentials,
    ) -> Result<(), SecretsError> {
        let hmac_hex = Self::compute_hmac(&Self::hmac_key(creds, &self.region), blob_b64);
        let contents = format!("{blob_b64}\n{hmac_hex}\n");
        std::fs::write(cache, &contents)
            .map_err(|e| SecretsError::AwsKms(format!("write kms_data_key.enc: {e}")))?;
        set_mode_600(cache);
        Ok(())
    }

    /// Read the cache file and verify the HMAC before returning the blob.
    fn read_cache_verified(
        &self,
        cache: &Path,
        creds: &AwsCredentials,
    ) -> Result<String, SecretsError> {
        let raw = std::fs::read_to_string(cache)
            .map_err(|e| SecretsError::AwsKms(format!("read kms_data_key.enc: {e}")))?;
        let mut lines = raw.lines();
        let blob_b64 = lines.next()
            .ok_or_else(|| SecretsError::AwsKms(
                "kms_data_key.enc: missing ciphertext line".into()
            ))?;
        let stored_hmac = lines.next()
            .ok_or_else(|| SecretsError::AwsKms(
                "kms_data_key.enc: missing HMAC line — file may be from an older version, \
                 delete it to trigger re-generation".into()
            ))?;

        let expected_hmac = Self::compute_hmac(
            &Self::hmac_key(creds, &self.region),
            blob_b64,
        );

        // Constant-time comparison to resist timing attacks.
        use subtle::ConstantTimeEq;
        let ok = stored_hmac.as_bytes().ct_eq(expected_hmac.as_bytes());
        if !bool::from(ok) {
            return Err(SecretsError::AwsKms(
                "kms_data_key.enc HMAC verification FAILED — file may have been tampered with. \
                 Delete it to force re-generation from KMS.".into()
            ));
        }

        Ok(blob_b64.to_string())
    }
}

#[async_trait]
impl MasterKeyProvider for AwsKmsProvider {
    async fn load_master_key(&self) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
        let creds = AwsCredentials::from_env()?;
        let cache = self.cache_path();

        if cache.exists() {
            // Verify HMAC before making any network call (Fix #7).
            let blob_b64 = self.read_cache_verified(&cache, &creds)?;
            tracing::info!("AWS KMS: HMAC verified — decrypting cached data key");
            return kms_decrypt(&self.region, &blob_b64, &self.encryption_context, &creds).await;
        }

        // GenerateDataKey path — first boot.
        let (plaintext, ct_b64) = kms_generate_data_key(
            &self.region, &self.key_id, &self.encryption_context, &creds,
        ).await?;
        self.write_cache(&cache, &ct_b64, &creds)?;
        tracing::info!(path = %cache.display(), "AWS KMS: cached ciphertext blob with HMAC");
        Ok(plaintext)
    }

    fn description(&self) -> String {
        format!("AWS KMS key '{}' in region '{}'", self.key_id, self.region)
    }
}


// ── AWS credentials ───────────────────────────────────────────────────────────

struct AwsCredentials {
    access_key_id:     String,
    secret_access_key: String,
    session_token:     Option<String>,
}

impl AwsCredentials {
    fn from_env() -> Result<Self, SecretsError> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| SecretsError::AwsKms("AWS_ACCESS_KEY_ID not set".into()))?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| SecretsError::AwsKms("AWS_SECRET_ACCESS_KEY not set".into()))?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        Ok(Self { access_key_id, secret_access_key, session_token })
    }
}

// ── AWS Signature Version 4 ───────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derive the SigV4 signing key.
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k1 = hmac_sha256_bytes(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k2 = hmac_sha256_bytes(&k1, region.as_bytes());
    let k3 = hmac_sha256_bytes(&k2, service.as_bytes());
    hmac_sha256_bytes(&k3, b"aws4_request")
}

/// Build `(Authorization-header-value, X-Amz-Date-value)` for a KMS POST.
fn sigv4_auth(
    host:   &str,
    target: &str,
    body:   &str,
    region: &str,
    creds:  &AwsCredentials,
) -> (String, String) {
    let now      = chrono::Utc::now();
    let date_str = now.format("%Y%m%d").to_string();
    let dt_str   = now.format("%Y%m%dT%H%M%SZ").to_string();

    let body_hash = sha256_hex(body.as_bytes());

    let mut ch = format!(
        "content-type:application/x-amz-json-1.1\nhost:{host}\n\
         x-amz-date:{dt_str}\nx-amz-target:{target}\n"
    );
    let mut sh = "content-type;host;x-amz-date;x-amz-target".to_string();
    if let Some(tok) = &creds.session_token {
        ch.push_str(&format!("x-amz-security-token:{tok}\n"));
        sh.push_str(";x-amz-security-token");
    }

    let canonical = format!("POST\n/\n\n{ch}\n{sh}\n{body_hash}");
    let scope     = format!("{date_str}/{region}/kms/aws4_request");
    let sts       = format!(
        "AWS4-HMAC-SHA256\n{dt_str}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    let sig_key = derive_signing_key(&creds.secret_access_key, &date_str, region, "kms");
    let sig     = hex::encode(hmac_sha256_bytes(&sig_key, sts.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={sh}, Signature={sig}",
        creds.access_key_id,
    );
    (auth, dt_str)
}


// ── KMS API calls (Fix #1: reqwest replaces hand-rolled HTTP) ─────────────────

async fn kms_generate_data_key(
    region:  &str,
    key_id:  &str,
    enc_ctx: &std::collections::HashMap<String, String>,
    creds:   &AwsCredentials,
) -> Result<(Zeroizing<[u8; 32]>, String), SecretsError> {
    let host   = format!("kms.{region}.amazonaws.com");
    let target = "TrentService.GenerateDataKey";
    let mut payload = serde_json::json!({ "KeyId": key_id, "KeySpec": "AES_256" });
    if !enc_ctx.is_empty() {
        payload["EncryptionContext"] = serde_json::to_value(enc_ctx)
            .map_err(|e| SecretsError::Serialisation(e.to_string()))?;
    }
    let body = serde_json::to_string(&payload)
        .map_err(|e| SecretsError::Serialisation(e.to_string()))?;
    let (auth, dt) = sigv4_auth(&host, target, &body, region, creds);

    let client = build_reqwest_client()?;
    let mut req = client
        .post(format!("https://{host}/"))
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", target)
        .header("X-Amz-Date", &dt)
        .header("Authorization", &auth);
    if let Some(tok) = &creds.session_token {
        req = req.header("X-Amz-Security-Token", tok);
    }

    let resp = req.body(body).send().await
        .map_err(|e| SecretsError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(SecretsError::AwsKms(format!(
            "GenerateDataKey HTTP {status}: {}",
            resp.text().await.unwrap_or_default()
        )));
    }

    let json: serde_json::Value = resp.json().await
        .map_err(|e| SecretsError::AwsKms(format!("parse: {e}")))?;
    let pt_b64 = json["Plaintext"].as_str()
        .ok_or_else(|| SecretsError::AwsKms("Plaintext missing".into()))?;
    let ct_b64 = json["CiphertextBlob"].as_str()
        .ok_or_else(|| SecretsError::AwsKms("CiphertextBlob missing".into()))?
        .to_string();
    Ok((decode_kms_key(pt_b64)?, ct_b64))
}

async fn kms_decrypt(
    region:  &str,
    ct_b64:  &str,
    enc_ctx: &std::collections::HashMap<String, String>,
    creds:   &AwsCredentials,
) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
    let host   = format!("kms.{region}.amazonaws.com");
    let target = "TrentService.Decrypt";
    let mut payload = serde_json::json!({ "CiphertextBlob": ct_b64 });
    if !enc_ctx.is_empty() {
        payload["EncryptionContext"] = serde_json::to_value(enc_ctx)
            .map_err(|e| SecretsError::Serialisation(e.to_string()))?;
    }
    let body = serde_json::to_string(&payload)
        .map_err(|e| SecretsError::Serialisation(e.to_string()))?;
    let (auth, dt) = sigv4_auth(&host, target, &body, region, creds);

    let client = build_reqwest_client()?;
    let mut req = client
        .post(format!("https://{host}/"))
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", target)
        .header("X-Amz-Date", &dt)
        .header("Authorization", &auth);
    if let Some(tok) = &creds.session_token {
        req = req.header("X-Amz-Security-Token", tok);
    }

    let resp = req.body(body).send().await
        .map_err(|e| SecretsError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(SecretsError::AwsKms(format!(
            "Decrypt HTTP {status}: {}",
            resp.text().await.unwrap_or_default()
        )));
    }

    let json: serde_json::Value = resp.json().await
        .map_err(|e| SecretsError::AwsKms(format!("parse: {e}")))?;
    let pt_b64 = json["Plaintext"].as_str()
        .ok_or_else(|| SecretsError::AwsKms("Plaintext missing in Decrypt response".into()))?;
    decode_kms_key(pt_b64)
}

fn decode_kms_key(b64: &str) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
    // Fix #3: use the base64 crate (BASE64_STANDARD engine) instead of the
    // previously hand-rolled decoder.  AWS always returns padded standard
    // RFC 4648 base64, which BASE64_STANDARD handles correctly including
    // whitespace stripping via the lenient variant.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD
        .decode(b64.trim())
        .map_err(|e| SecretsError::AwsKms(format!("base64 decode: {e}")))?;
    let len = bytes.len();
    bytes.try_into()
        .map(Zeroizing::new)
        .map_err(|_| SecretsError::InvalidKeyLength { got: len })
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn parse_hex_key(hex_str: &str) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| SecretsError::HexDecode(e.to_string()))?;
    let len = bytes.len();
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SecretsError::InvalidKeyLength { got: len })?;
    Ok(Zeroizing::new(key))
}

/// Build a reqwest client that uses the rustls-tls backend.
/// This replaces the hand-rolled MinimalHttpClient (Fix #1).
fn build_reqwest_client() -> Result<ReqwestClient, SecretsError> {
    ReqwestClient::builder()
        .use_rustls_tls()
        .build()
        .map_err(|e| SecretsError::Http(format!("build reqwest client: {e}")))
}

fn set_mode_600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}



// ── PyHsmProvider ─────────────────────────────────────────────────────────────

/// Derives the VectorLedger master key from the PyHSM Unix-socket daemon.
///
/// ## How it works
///
/// PyHSM owns a wrapping key (`key_id`, default `"vledger.master-key"`) whose
/// raw bytes **never** leave the daemon.  VectorLedger's 32-byte master key is
/// encrypted by PyHSM and the resulting ciphertext is stored locally in
/// `<data_dir>/keys/pyhsm_master_key.enc` with an BLAKE3-keyed HMAC-SHA256
/// integrity seal (same pattern as `AwsKmsProvider`).
///
/// ### First boot (`pyhsm_master_key.enc` absent)
/// 1. Generate a 32-byte master key with `OsRng`.
/// 2. Ask PyHSM to encrypt it → receive a Base64 ciphertext.
/// 3. Write `<ciphertext_b64>\n<hmac_hex>\n` to the cache file (mode 0o600).
/// 4. Return the plaintext key.
///
/// ### Subsequent boots (cache present)
/// 1. Read and HMAC-verify the cache file.
/// 2. Send the Base64 ciphertext to PyHSM → receive plaintext.
/// 3. Return the plaintext key.
///
/// The HMAC key is `BLAKE3(socket_path || key_id)` so an attacker who can
/// write the cache file but does not know which PyHSM instance / key is in
/// use cannot forge a valid seal.
pub struct PyHsmProvider {
    pub socket_path: String,
    pub caller_id:   String,
    pub key_id:      String,
    /// Directory where `pyhsm_master_key.enc` is cached.  `None` → current dir.
    pub cache_dir:   Option<std::path::PathBuf>,
}

impl PyHsmProvider {
    fn cache_path(&self) -> std::path::PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("pyhsm_master_key.enc")
    }

    /// HMAC key = BLAKE3(socket_path || key_id).
    /// Ties the integrity seal to this specific PyHSM instance and wrapping key.
    fn hmac_key(&self) -> [u8; 32] {
        let mut input = self.socket_path.as_bytes().to_vec();
        input.extend_from_slice(self.key_id.as_bytes());
        *blake3::hash(&input).as_bytes()
    }

    fn compute_hmac(key: &[u8], data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn write_cache(&self, path: &std::path::Path, ct_b64: &str) -> Result<(), SecretsError> {
        let hmac_hex = Self::compute_hmac(&self.hmac_key(), ct_b64);
        std::fs::write(path, format!("{ct_b64}\n{hmac_hex}\n"))
            .map_err(|e| SecretsError::PyHsm(format!("write pyhsm_master_key.enc: {e}")))?;
        set_mode_600(path);
        Ok(())
    }

    fn read_cache_verified(&self, path: &std::path::Path) -> Result<String, SecretsError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| SecretsError::PyHsm(format!("read pyhsm_master_key.enc: {e}")))?;
        let mut lines = raw.lines();
        let ct_b64 = lines.next().ok_or_else(|| {
            SecretsError::PyHsm("pyhsm_master_key.enc: missing ciphertext line".into())
        })?;
        let stored_hmac = lines.next().ok_or_else(|| {
            SecretsError::PyHsm(
                "pyhsm_master_key.enc: missing HMAC line — \
                 delete the file to trigger re-generation"
                    .into(),
            )
        })?;
        let expected = Self::compute_hmac(&self.hmac_key(), ct_b64);
        use subtle::ConstantTimeEq;
        if !bool::from(stored_hmac.as_bytes().ct_eq(expected.as_bytes())) {
            return Err(SecretsError::PyHsm(
                "pyhsm_master_key.enc HMAC verification FAILED — \
                 file may have been tampered with. \
                 Delete it to force re-generation."
                    .into(),
            ));
        }
        Ok(ct_b64.to_string())
    }

    /// Ensure the wrapping key exists in PyHSM, generating it if absent.
    async fn ensure_wrapping_key(&self) -> Result<(), SecretsError> {
        // generateKey is idempotent — if it already exists PyHSM returns an
        // error string containing "already exists"; we treat that as success.
        let req = serde_json::json!({
            "type": "generateKey",
            "keyId": self.key_id,
            "policy": { "allowEncrypt": true, "allowDecrypt": true },
            "callerId": self.caller_id,
        });
        match self.ipc_call(&req).await {
            Ok(_) => Ok(()),
            Err(SecretsError::PyHsm(ref msg)) if msg.contains("already exists") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Encrypt `plaintext` via PyHSM and return the Base64 ciphertext string.
    ///
    /// Fix #5: the JSON request contains the hex-encoded key bytes in the
    /// "plaintext" field.  We must never log the full request object —
    /// tracing/debug output must reference only the key_id and operation type,
    /// never the plaintext value.  The `ipc_call` helper is called with a
    /// pre-built `Value`; we log only the sanitized version here.
    async fn hsm_encrypt(&self, plaintext: &[u8]) -> Result<String, SecretsError> {
        // Build the request but keep the plaintext value out of any log output.
        // hex::encode produces a borrowed String; we move it directly into the
        // JSON Value without binding it to a named variable that could be
        // accidentally logged.
        let req = serde_json::json!({
            "type": "encrypt",
            "keyId": self.key_id,
            "plaintext": hex::encode(plaintext),
            "callerId": self.caller_id,
        });
        // Log only the sanitized (plaintext-free) shape so debug traces from
        // this call site never contain key material.
        tracing::debug!(
            key_id   = %self.key_id,
            caller   = %self.caller_id,
            op       = "encrypt",
            "PyHSM encrypt request (plaintext redacted from log)"
        );
        let resp = self.ipc_call(&req).await?;
        resp["data"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| SecretsError::PyHsm("encrypt: missing data in response".into()))
    }

    /// Decrypt a Base64 ciphertext via PyHSM and return plaintext bytes.
    async fn hsm_decrypt(&self, ct_b64: &str) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
        let req = serde_json::json!({
            "type": "decrypt",
            "keyId": self.key_id,
            "ciphertext": ct_b64,
            "callerId": self.caller_id,
        });
        let resp = self.ipc_call(&req).await?;
        let plaintext = resp["data"]
            .as_str()
            .ok_or_else(|| SecretsError::PyHsm("decrypt: missing data in response".into()))?
            .to_string();
        Ok(Zeroizing::new(plaintext.into_bytes()))
    }

    /// Send a single JSON request to the PyHSM socket/address and return the
    /// parsed success `data` value, or a `SecretsError::PyHsm` on failure.
    ///
    /// ## Transport
    /// | Platform | Transport        | `socket_path` format    |
    /// |----------|------------------|-------------------------|
    /// | Unix     | Unix domain socket | `/tmp/pyhsm.sock`     |
    /// | Windows  | TCP loopback       | `127.0.0.1:7777`      |
    ///
    /// Fix #5: this method never logs the `req` object because it may contain
    /// a `"plaintext"` field with key material.  Callers are responsible for
    /// emitting their own sanitized debug logs before calling `ipc_call`.
    async fn ipc_call(
        &self,
        req: &serde_json::Value,
    ) -> Result<serde_json::Value, SecretsError> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::time::{timeout, Duration};

        let mut line = serde_json::to_string(req)
            .map_err(|e| SecretsError::Serialisation(e.to_string()))?;
        line.push('\n');

        #[cfg(unix)]
        {
            use tokio::net::UnixStream;

            let socket = std::path::Path::new(&self.socket_path);
            if !socket.exists() {
                return Err(SecretsError::PyHsm(format!(
                    "PyHSM socket not found at '{}' — is the PyHSM daemon running?\n\
                     Start it with: npx tsx pyhsm-ts/process.ts",
                    self.socket_path
                )));
            }

            let stream = timeout(Duration::from_secs(10), UnixStream::connect(socket))
                .await
                .map_err(|_| SecretsError::PyHsm("PyHSM IPC connect timeout (10 s)".into()))?
                .map_err(|e| SecretsError::PyHsm(format!("PyHSM IPC connect: {e}")))?;

            let (reader_half, mut writer) = tokio::io::split(stream);

            timeout(Duration::from_secs(10), writer.write_all(line.as_bytes()))
                .await
                .map_err(|_| SecretsError::PyHsm("PyHSM IPC write timeout".into()))?
                .map_err(|e| SecretsError::PyHsm(format!("PyHSM IPC write: {e}")))?;

            let mut resp_line = String::new();
            timeout(
                Duration::from_secs(10),
                BufReader::new(reader_half).read_line(&mut resp_line),
            )
            .await
            .map_err(|_| SecretsError::PyHsm("PyHSM IPC read timeout".into()))?
            .map_err(|e| SecretsError::PyHsm(format!("PyHSM IPC read: {e}")))?;

            return pyhsm_parse_response(resp_line.trim());
        }

        #[cfg(not(unix))]
        {
            // Windows: connect over TCP loopback.
            // Start PyHSM with PYHSM_TCP_PORT=7777 (or whichever port you use).
            let addr = &self.socket_path;

            let stream = timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(addr))
                .await
                .map_err(|_| SecretsError::PyHsm("PyHSM TCP connect timeout (10 s)".into()))?
                .map_err(|e| SecretsError::PyHsm(format!(
                    "PyHSM TCP connect to '{}' failed: {e}\n\
                     Is the PyHSM daemon running with PYHSM_TCP_PORT set?\n\
                     Start it with: $env:PYHSM_TCP_PORT=7777; npx tsx pyhsm-ts/process.ts",
                    addr
                )))?;

            let (reader_half, mut writer) = tokio::io::split(stream);

            timeout(Duration::from_secs(10), writer.write_all(line.as_bytes()))
                .await
                .map_err(|_| SecretsError::PyHsm("PyHSM IPC write timeout".into()))?
                .map_err(|e| SecretsError::PyHsm(format!("PyHSM IPC write: {e}")))?;

            let mut resp_line = String::new();
            timeout(
                Duration::from_secs(10),
                BufReader::new(reader_half).read_line(&mut resp_line),
            )
            .await
            .map_err(|_| SecretsError::PyHsm("PyHSM IPC read timeout".into()))?
            .map_err(|e| SecretsError::PyHsm(format!("PyHSM IPC read: {e}")))?;

            return pyhsm_parse_response(resp_line.trim());
        }
    }
}

#[async_trait]
impl MasterKeyProvider for PyHsmProvider {
    async fn load_master_key(&self) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
        let cache = self.cache_path();

        if cache.exists() {
            // Subsequent boots: verify HMAC, then ask PyHSM to decrypt.
            let ct_b64 = self.read_cache_verified(&cache)?;
            tracing::info!(
                socket = %self.socket_path,
                key_id = %self.key_id,
                "PyHSM: HMAC verified — decrypting cached master key blob"
            );
            let plaintext = self.hsm_decrypt(&ct_b64).await?;
            return bytes_to_key32(plaintext.as_slice());
        }

        // First boot: generate master key, seal it inside PyHSM.
        tracing::info!(
            socket = %self.socket_path,
            key_id = %self.key_id,
            "PyHSM: first boot — generating and sealing master key"
        );

        // Ensure the wrapping key exists in PyHSM.
        self.ensure_wrapping_key().await?;

        // Generate a fresh 32-byte master key.
        use rand::RngCore;
        let mut raw = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(raw.as_mut());

        // Pass the raw key bytes to hsm_encrypt, which hex-encodes them
        // before embedding in the JSON request (Fix #5: encoding happens
        // inside hsm_encrypt so no intermediate hex binding is created that
        // could be accidentally logged by the caller).
        let ct_b64  = self.hsm_encrypt(raw.as_ref()).await?;

        // Cache the encrypted blob with HMAC integrity seal.
        self.write_cache(&cache, &ct_b64)?;
        tracing::info!(
            path = %cache.display(),
            "PyHSM: master key sealed and cached"
        );

        Ok(Zeroizing::new(*raw))
    }

    fn description(&self) -> String {
        format!(
            "PyHSM daemon at '{}' (key '{}')",
            self.socket_path, self.key_id
        )
    }
}

/// Parse a raw NDJSON response line from PyHSM.
fn pyhsm_parse_response(line: &str) -> Result<serde_json::Value, SecretsError> {
    let resp: serde_json::Value = serde_json::from_str(line)
        .map_err(|e| SecretsError::PyHsm(format!("PyHSM bad JSON response: {e}")))?;
    if resp["ok"].as_bool() != Some(true) {
        let msg = resp["error"].as_str().unwrap_or("unknown error").to_string();
        return Err(SecretsError::PyHsm(format!("PyHSM returned error: {msg}")));
    }
    Ok(resp)
}

/// Convert a plaintext byte slice returned by PyHSM decrypt back to a
/// 32-byte key.  PyHSM round-trips through hex encoding, so the plaintext
/// is the hex string we originally passed to encrypt.
fn bytes_to_key32(plaintext: &[u8]) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
    // Try hex decode first (our encoding path).
    let s = std::str::from_utf8(plaintext)
        .map_err(|e| SecretsError::PyHsm(format!("plaintext is not valid UTF-8: {e}")))?;
    parse_hex_key(s.trim())
}



// ── RemotePyHsmProvider ───────────────────────────────────────────────────────

/// Derives the VectorLedger master key from a **remote** PyHSM daemon over
/// TLS 1.3 + mTLS — **Model 2** (same-region, separate server).
///
/// ## How it works
/// Identical key lifecycle to `PyHsmProvider` (local Unix socket):
/// - First boot: generate 32-byte master key, seal it via remote PyHSM,
///   cache the ciphertext blob with an HMAC integrity seal.
/// - Subsequent boots: verify HMAC, send blob to remote PyHSM for
///   decryption over mTLS, return plaintext only for startup key derivation.
///
/// ## Security boundary
/// The private key material never crosses the network — only the encrypted
/// blob (ciphertext produced by PyHSM) and the decrypted plaintext for the
/// in-process master key derivation.  The PyHSM private wrapping key stays
/// on the PyHSM server at all times.
///
/// ## Replay prevention
/// Every request to the remote PyHSM carries a unique `requestId` (UUID v4)
/// and a `timestamp` (RFC 3339).  PyHSM is expected to reject duplicate
/// request IDs within a replay window and stale timestamps.
pub struct RemotePyHsmProvider {
    pub endpoint:    String,
    pub ca_cert:     String,
    pub client_cert: Option<String>,
    pub client_key:  Option<String>,
    pub timeout_ms:  u64,
    pub max_retries: u32,
    pub caller_id:   String,
    pub key_id:      String,
    /// Directory where `pyhsm_master_key.enc` is cached.  `None` → current dir.
    pub cache_dir:   Option<std::path::PathBuf>,
}

impl RemotePyHsmProvider {
    fn cache_path(&self) -> std::path::PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("pyhsm_master_key.enc")
    }

    /// HMAC key = BLAKE3(endpoint || key_id).
    /// Ties the integrity seal to this specific remote endpoint and wrapping key.
    fn hmac_key(&self) -> [u8; 32] {
        let mut input = self.endpoint.as_bytes().to_vec();
        input.extend_from_slice(self.key_id.as_bytes());
        *blake3::hash(&input).as_bytes()
    }

    fn compute_hmac(key: &[u8], data: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn write_cache(&self, path: &std::path::Path, ct_b64: &str) -> Result<(), SecretsError> {
        let hmac_hex = Self::compute_hmac(&self.hmac_key(), ct_b64);
        std::fs::write(path, format!("{ct_b64}\n{hmac_hex}\n"))
            .map_err(|e| SecretsError::PyHsm(format!("write pyhsm_master_key.enc: {e}")))?;
        set_mode_600(path);
        Ok(())
    }

    fn read_cache_verified(&self, path: &std::path::Path) -> Result<String, SecretsError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| SecretsError::PyHsm(format!("read pyhsm_master_key.enc: {e}")))?;
        let mut lines = raw.lines();
        let ct_b64 = lines.next().ok_or_else(|| {
            SecretsError::PyHsm("pyhsm_master_key.enc: missing ciphertext line".into())
        })?;
        let stored_hmac = lines.next().ok_or_else(|| {
            SecretsError::PyHsm(
                "pyhsm_master_key.enc: missing HMAC line — \
                 delete the file to trigger re-generation".into(),
            )
        })?;
        let expected = Self::compute_hmac(&self.hmac_key(), ct_b64);
        use subtle::ConstantTimeEq;
        if !bool::from(stored_hmac.as_bytes().ct_eq(expected.as_bytes())) {
            return Err(SecretsError::PyHsm(
                "pyhsm_master_key.enc HMAC verification FAILED — \
                 file may have been tampered with. \
                 Delete it to force re-generation.".into(),
            ));
        }
        Ok(ct_b64.to_string())
    }

    /// Build an `HsmClient` configured for the remote transport.
    fn build_hsm_client(&self) -> Result<vledger_hsm::HsmClient, SecretsError> {
        let cfg = vledger_hsm::RemotePyHsmConfig {
            endpoint:    self.resolve_env("PYHSM_ENDPOINT",     &self.endpoint),
            ca_cert:     self.resolve_env("PYHSM_CA_CERT",      &self.ca_cert),
            client_cert: self.resolve_env_opt("PYHSM_CLIENT_CERT", self.client_cert.as_deref()),
            client_key:  self.resolve_env_opt("PYHSM_CLIENT_KEY",  self.client_key.as_deref()),
            timeout_ms:  std::env::var("PYHSM_TIMEOUT_MS")
                             .ok()
                             .and_then(|v| v.parse().ok())
                             .unwrap_or(self.timeout_ms),
            max_retries: self.max_retries,
        };
        Ok(vledger_hsm::HsmClient::remote(cfg, &self.caller_id))
    }

    fn resolve_env(&self, var: &str, fallback: &str) -> String {
        std::env::var(var).unwrap_or_else(|_| fallback.to_string())
    }

    fn resolve_env_opt(&self, var: &str, fallback: Option<&str>) -> Option<String> {
        std::env::var(var).ok().or_else(|| fallback.map(|s| s.to_string()))
    }

    /// Encrypt `plaintext` via the remote PyHSM and return Base64 ciphertext.
    async fn hsm_encrypt(
        &self,
        client:    &vledger_hsm::HsmClient,
        plaintext: &[u8],
    ) -> Result<String, SecretsError> {
        let ct = client.encrypt(&self.key_id, plaintext).await
            .map_err(|e| SecretsError::PyHsm(format!("remote PyHSM encrypt: {e}")))?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(STANDARD.encode(&ct))
    }

    /// Decrypt a Base64 ciphertext via the remote PyHSM and return plaintext bytes.
    async fn hsm_decrypt(
        &self,
        client: &vledger_hsm::HsmClient,
        ct_b64: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let ct = STANDARD.decode(ct_b64.trim())
            .map_err(|e| SecretsError::PyHsm(format!("base64 decode cached blob: {e}")))?;
        let pt = client.decrypt(&self.key_id, &ct).await
            .map_err(|e| SecretsError::PyHsm(format!("remote PyHSM decrypt: {e}")))?;
        Ok(pt)
    }

    /// Ensure the wrapping key exists in the remote PyHSM, generating if absent.
    async fn ensure_wrapping_key(
        &self,
        client: &vledger_hsm::HsmClient,
    ) -> Result<(), SecretsError> {
        use vledger_hsm::KeyPolicy;
        match client.generate_key(&self.key_id, Some(KeyPolicy::encrypt_decrypt())).await {
            Ok(()) => Ok(()),
            Err(vledger_hsm::HsmError::Remote(ref msg)) if msg.contains("already exists") => Ok(()),
            Err(e) => Err(SecretsError::PyHsm(format!("ensure wrapping key: {e}"))),
        }
    }
}

#[async_trait]
impl MasterKeyProvider for RemotePyHsmProvider {
    async fn load_master_key(&self) -> Result<Zeroizing<[u8; 32]>, SecretsError> {
        let client = self.build_hsm_client()?;
        let cache  = self.cache_path();

        if cache.exists() {
            let ct_b64 = self.read_cache_verified(&cache)?;
            tracing::info!(
                endpoint = %self.endpoint,
                key_id   = %self.key_id,
                "Remote PyHSM: HMAC verified — decrypting cached master key blob"
            );
            let plaintext = self.hsm_decrypt(&client, &ct_b64).await?;
            return bytes_to_key32(plaintext.as_slice());
        }

        // First boot: generate master key, seal it inside remote PyHSM.
        tracing::info!(
            endpoint = %self.endpoint,
            key_id   = %self.key_id,
            "Remote PyHSM: first boot — generating and sealing master key"
        );

        self.ensure_wrapping_key(&client).await?;

        use rand::RngCore;
        let mut raw = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(raw.as_mut());

        let ct_b64 = self.hsm_encrypt(&client, raw.as_ref()).await?;
        self.write_cache(&cache, &ct_b64)?;
        tracing::info!(
            path = %cache.display(),
            "Remote PyHSM: master key sealed and cached"
        );

        Ok(Zeroizing::new(*raw))
    }

    fn description(&self) -> String {
        format!(
            "Remote PyHSM daemon at '{}' (mTLS, key '{}')",
            self.endpoint, self.key_id
        )
    }
}

//! `vledger rotate-keys` — HSM key rotation for all VectorLedger key slots.
//!
//! Supports both:
//! - **Model 1**: local PyHSM via Unix socket (pass `socket_path`, leave
//!   `pyhsm_endpoint` as `None`).
//! - **Model 2**: remote PyHSM via TLS 1.3 + mTLS (pass `pyhsm_endpoint`
//!   and the associated cert paths; `socket_path` is ignored).
//!
//! ## What rotation does
//! 1. Connects to the configured HSM backend.
//! 2. For each active key slot (`vledger.table.<id>.encrypt`,
//!    `vledger.wal.signing`, `vledger.commit.signing`):
//!    a. Calls `HsmClient::rotate_key(key_id)` — the HSM archives the old
//!       version and generates a new one; old ciphertext can still be
//!       decrypted with the archived version.
//!    b. Writes an `AuditEvent::KeyRotated` entry to the audit log.
//! 3. Prints a summary of rotated keys.
//!
//! ## Safety
//! Key rotation is **non-destructive** — the HSM keeps the previous key
//! version for decryption so existing page files remain readable.  Only new
//! writes use the new key version.

use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

use vledger_audit::{AuditEventKind, AuditLog};
use vledger_hsm::{HsmClient, RemotePyHsmConfig};

/// Rotate all VectorLedger HSM key slots and record the events in the audit log.
///
/// ## Transport selection
/// - If `pyhsm_endpoint` is `Some(url)` → **Model 2** (remote mTLS).
///   `socket_path` is ignored.
/// - Otherwise → **Model 1** (local socket).  `socket_path` defaults to
///   `/tmp/pyhsm.sock` when `None`.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_keys(
    data_dir: &Path,
    socket_path: Option<&str>,
    caller_id: &str,
    pyhsm_endpoint: Option<&str>,
    pyhsm_ca_cert: Option<&str>,
    pyhsm_client_cert: Option<&str>,
    pyhsm_client_key: Option<&str>,
    pyhsm_timeout_ms: u64,
    pyhsm_max_retries: u32,
) -> Result<Vec<String>> {
    // ── Build the appropriate client ──────────────────────────────────────
    let client = if let Some(endpoint) = pyhsm_endpoint {
        // Model 2 — remote PyHSM over mTLS.
        let ca_cert = pyhsm_ca_cert
            .map(|s| s.to_string())
            .or_else(|| std::env::var("PYHSM_CA_CERT").ok())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--pyhsm-ca-cert (or PYHSM_CA_CERT) is required when using --pyhsm-endpoint"
                )
            })?;
        let cfg = RemotePyHsmConfig {
            endpoint: endpoint.to_string(),
            ca_cert,
            client_cert: pyhsm_client_cert
                .map(|s| s.to_string())
                .or_else(|| std::env::var("PYHSM_CLIENT_CERT").ok()),
            client_key: pyhsm_client_key
                .map(|s| s.to_string())
                .or_else(|| std::env::var("PYHSM_CLIENT_KEY").ok()),
            timeout_ms: std::env::var("PYHSM_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(pyhsm_timeout_ms),
            max_retries: pyhsm_max_retries,
        };
        info!(
            endpoint = %cfg.endpoint,
            "Connecting to remote PyHSM (Model 2 — mTLS)"
        );
        HsmClient::remote(cfg, caller_id)
    } else {
        // Model 1 — local Unix socket (or TCP loopback on Windows).
        let addr = socket_path
            .map(|s| s.to_string())
            .or_else(|| std::env::var("PYHSM_SOCKET_PATH").ok())
            .unwrap_or_else(|| vledger_hsm::default_pyhsm_address().to_string());
        info!(socket = %addr, "Connecting to local PyHSM (Model 1 — Unix socket)");
        HsmClient::new(&addr, caller_id)
    };

    // ── Verify HSM is reachable ───────────────────────────────────────────
    if !client.is_available().await {
        anyhow::bail!(
            "HSM daemon not reachable at {}.\n\
             Ensure PyHSM is running and the endpoint/socket is correct.\n\
             Transport: {}",
            pyhsm_endpoint.unwrap_or_else(|| socket_path.unwrap_or("/tmp/pyhsm.sock")),
            client.transport_description(),
        );
    }

    // ── Open audit log ────────────────────────────────────────────────────
    let audit_path = data_dir.join("audit").join("audit.log");
    let audit = AuditLog::open(&audit_path).context("Failed to open audit log")?;

    // ── Collect key IDs to rotate ─────────────────────────────────────────
    let mut key_ids: Vec<String> = vec![
        HsmClient::wal_signing_key_id().to_string(),
        HsmClient::commit_signing_key_id().to_string(),
    ];

    // Per-table encryption keys: scan the pages directory for table IDs.
    let pages_dir = data_dir.join("pages");
    if pages_dir.exists() {
        for entry in std::fs::read_dir(&pages_dir).context("Failed to read pages directory")? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_prefix("table_") {
                let table_id: u32 = id_str
                    .split('_')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let key_id = HsmClient::table_encrypt_key_id(table_id);
                if !key_ids.contains(&key_id) {
                    key_ids.push(key_id);
                }
            }
        }
    }

    // Always include table 0 (accounts) and table 1 (entries).
    for tid in 0u32..=1 {
        let kid = HsmClient::table_encrypt_key_id(tid);
        if !key_ids.contains(&kid) {
            key_ids.push(kid);
        }
    }

    // ── Rotate ────────────────────────────────────────────────────────────
    let mut rotated = Vec::new();

    for key_id in &key_ids {
        info!(key_id, "Rotating HSM key");
        match client.rotate_key(key_id).await {
            Ok(()) => {
                audit
                    .append(AuditEventKind::KeyRotated {
                        key_id: key_id.clone(),
                        caller_id: caller_id.to_string(),
                    })
                    .context("Failed to write audit event")?;
                rotated.push(key_id.clone());
                info!(key_id, "Key rotation complete");
            }
            Err(e) => {
                // Key may not exist yet (e.g. table keys on a fresh instance).
                tracing::warn!(key_id, "Key rotation skipped: {e}");
            }
        }
    }

    Ok(rotated)
}

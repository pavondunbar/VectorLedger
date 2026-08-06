//! `vledger rotate-keys` — HSM key rotation for all VectorLedger key slots.
//!
//! ## What rotation does
//! 1. Connects to the configured HSM backend.
//! 2. For each active key slot (`vledger.table.<id>.encrypt`, `vledger.wal.signing`,
//!    `vledger.commit.signing`):
//!    a. Calls `HsmClient::rotate_key(key_id)` — the HSM archives the old
//!       version and generates a new one; old ciphertext can still be decrypted
//!       with the archived version.
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
use vledger_hsm::HsmClient;

/// Rotate all VectorLedger HSM key slots and record the events in the audit log.
///
/// `socket_path` — path to the PyHSM daemon socket (or bridge socket for
/// AWS/Azure).  `None` uses the default `/tmp/pyhsm.sock`.
pub async fn rotate_keys(
    data_dir:    &Path,
    socket_path: Option<&str>,
    caller_id:   &str,
) -> Result<Vec<String>> {
    let client = match socket_path {
        Some(p) => HsmClient::new(p, caller_id),
        None    => HsmClient::default_socket(caller_id),
    };

    // Check HSM is reachable
    if !client.is_available().await {
        anyhow::bail!(
            "HSM daemon not reachable. Ensure PyHSM (or the AWS/Azure bridge) is running."
        );
    }

    // Open audit log
    let audit_path = data_dir.join("audit").join("audit.log");
    let audit = AuditLog::open(&audit_path)
        .context("Failed to open audit log")?;

    // Collect key IDs to rotate
    // Fixed keys
    let mut key_ids: Vec<String> = vec![
        HsmClient::wal_signing_key_id().to_string(),
        HsmClient::commit_signing_key_id().to_string(),
    ];

    // Per-table encryption keys: scan the pages directory for table IDs
    let pages_dir = data_dir.join("pages");
    if pages_dir.exists() {
        for entry in std::fs::read_dir(&pages_dir)
            .context("Failed to read pages directory")?
        {
            let entry = entry?;
            let name  = entry.file_name().to_string_lossy().to_string();
            // Page files are named "table_<id>_*.bin" or similar.
            // Extract the table ID from the filename prefix "table_<id>".
            if let Some(id_str) = name.strip_prefix("table_") {
                let table_id: u32 = id_str
                    .split('_').next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let key_id = HsmClient::table_encrypt_key_id(table_id);
                if !key_ids.contains(&key_id) {
                    key_ids.push(key_id);
                }
            }
        }
    }

    // Always include table 0 (accounts) and table 1 (entries)
    for tid in 0u32..=1 {
        let kid = HsmClient::table_encrypt_key_id(tid);
        if !key_ids.contains(&kid) {
            key_ids.push(kid);
        }
    }

    let mut rotated = Vec::new();

    for key_id in &key_ids {
        info!(key_id, "Rotating HSM key");
        match client.rotate_key(key_id).await {
            Ok(()) => {
                audit.append(AuditEventKind::KeyRotated {
                    key_id:    key_id.clone(),
                    caller_id: caller_id.to_string(),
                }).context("Failed to write audit event")?;
                rotated.push(key_id.clone());
                info!(key_id, "Key rotation complete");
            }
            Err(e) => {
                // Key may not exist yet (e.g. table keys on a fresh instance)
                tracing::warn!(key_id, "Key rotation skipped: {e}");
            }
        }
    }

    Ok(rotated)
}

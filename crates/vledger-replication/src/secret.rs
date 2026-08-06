//! Shared-secret management for replication authentication (Fix #9).
//!
//! The secret is a 32-byte random value stored as a 64-char hex string in a
//! file with mode 0o600.  Both primary and replica must have the *same* file
//! (copy it to replica nodes via a secure channel such as `scp` or a secrets
//! manager).
//!
//! If the file does not exist when the primary starts, one is generated
//! automatically and written to `secret_path`.  The replica will fail to
//! authenticate until its copy is updated — this is intentional.

use std::path::Path;

use crate::error::ReplicationError;

/// Load the 32-byte replication secret from `path`.
///
/// Returns `Err(SecretError)` if the file is missing, unreadable, or not
/// valid hex of exactly 32 bytes.
pub fn load_secret(path: &Path) -> Result<[u8; 32], ReplicationError> {
    let hex = std::fs::read_to_string(path)
        .map_err(|e| ReplicationError::SecretError(
            format!("cannot read {}: {e}", path.display())
        ))?;

    let bytes = hex::decode(hex.trim())
        .map_err(|e| ReplicationError::SecretError(
            format!("invalid hex in {}: {e}", path.display())
        ))?;

    let len = bytes.len();
    bytes.try_into().map_err(|_| ReplicationError::SecretError(
        format!(
            "{} must contain exactly 32 bytes (64 hex chars), got {len} bytes",
            path.display(),
        )
    ))
}

/// Generate a fresh 32-byte secret, write it to `path` with mode 0o600,
/// and return it.
///
/// Called automatically on the primary when no secret file exists.
pub fn generate_and_save(path: &Path) -> Result<[u8; 32], ReplicationError> {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    std::fs::write(path, hex::encode(secret))
        .map_err(|e| ReplicationError::SecretError(
            format!("cannot write {}: {e}", path.display())
        ))?;

    set_mode_600(path)?;
    tracing::info!(
        path = %path.display(),
        "Generated new replication secret — copy to all replica nodes"
    );
    Ok(secret)
}

/// Load an existing secret or generate a new one if the file doesn't exist.
pub fn load_or_generate(path: &Path) -> Result<[u8; 32], ReplicationError> {
    if path.exists() {
        load_secret(path)
    } else {
        generate_and_save(path)
    }
}

/// Default secret file path relative to `data_dir`.
pub fn default_secret_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("replication_secret.hex")
}

// ── File permission helper ────────────────────────────────────────────────────

fn set_mode_600(path: &Path) -> Result<(), ReplicationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| ReplicationError::SecretError(
                format!("chmod 600 {}: {e}", path.display())
            ))?;
    }
    #[cfg(not(unix))]
    { let _ = path; }
    Ok(())
}

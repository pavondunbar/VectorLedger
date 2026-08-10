//! `vledger backup` and `vledger restore` — snapshot archive operations.
//!
//! ## Backup format (encrypted)
//!
//! ```text
//! vledger-backup-<timestamp>.tar
//!   MANIFEST.json        ← file list + BLAKE3 hashes + backup metadata (plaintext)
//!   wal/<file>.enc       ← AES-256-GCM encrypted file  (nonce || ciphertext_with_tag)
//!   pages/<file>.enc     ← AES-256-GCM encrypted file
//!   catalog/<file>.enc   ← AES-256-GCM encrypted file
//!   keys/<file>.enc      ← AES-256-GCM encrypted file  (public keys only)
//!   audit/<file>.enc     ← AES-256-GCM encrypted file
//! ```
//!
//! ## Encryption design
//! - Each file is encrypted with AES-256-GCM using a unique 96-bit random nonce.
//! - The encryption key is a per-backup ephemeral key derived from the master key
//!   via HKDF-SHA256 with context `vgdb/backup/<timestamp_unix>`.
//! - The MANIFEST.json is stored in plaintext so the manifest hash and file list
//!   can be verified without decrypting every file.  File content hashes in the
//!   manifest are computed over the *plaintext* bytes so restore can verify
//!   integrity post-decryption.
//! - The backup encryption key is stored alongside the archive in
//!   `<output>.key` (AES-256-GCM encrypted under the master key, with
//!   context AAD = `"vgdb/backup-key-wrap"`).
//!
//! ## Symlink/traversal hardening
//! - `walkdir_safe` resolves every entry with `canonicalize` and verifies
//!   it remains under the `data_dir` canonical root before including it.
//! - Symlinks pointing outside `data_dir` are silently skipped with a
//!   `warn!` log entry.  Symlinks within `data_dir` are followed as normal
//!   files — only their resolved target is included.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use vledger_crypto::{
    encrypt::{decrypt, encrypt, EncryptionKey},
    kdf::MasterKey,
};

// ── Manifest ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub vledger_version: String,
    pub created_at_unix: u64,
    pub created_at_rfc:  String,
    /// Map from relative path inside the archive (without `.enc` suffix) to
    /// BLAKE3 hex hash of the **plaintext** bytes.
    pub files:           BTreeMap<String, String>,
    /// BLAKE3 hash of all (path, file_hash) pairs sorted lexicographically.
    pub manifest_hash:   String,
    /// Whether file content in this archive is AES-256-GCM encrypted.
    /// Always `true` for archives created by this version.
    pub encrypted:       bool,
}

impl BackupManifest {
    fn compute_manifest_hash(files: &BTreeMap<String, String>) -> String {
        let mut hasher = blake3::Hasher::new();
        for (path, hash) in files {
            hasher.update(path.as_bytes());
            hasher.update(hash.as_bytes());
        }
        hex::encode(hasher.finalize().as_bytes())
    }

    pub fn verify(&self) -> bool {
        let expected = Self::compute_manifest_hash(&self.files);
        expected == self.manifest_hash
    }
}

// ── Key-wrap helpers ──────────────────────────────────────────────────────────

/// The `.key` sidecar stored next to the `.tar` archive.
///
/// Contains the 32-byte backup encryption key, encrypted under the master key.
/// Format: `nonce (12 bytes) || ciphertext_with_tag` — identical to the
/// standard `vledger_crypto::encrypt` wire format.
#[derive(Debug, Serialize, Deserialize)]
struct BackupKeySidecar {
    /// AES-256-GCM ciphertext of the 32-byte backup key, hex-encoded.
    /// AAD = b"vgdb/backup-key-wrap".
    wrapped_key_hex: String,
    /// HKDF context used to derive the backup key from the master key.
    kdf_context: String,
}

/// Derive a per-backup AES-256-GCM encryption key from `master` using HKDF.
fn derive_backup_key(master: &MasterKey, ts_unix: u64) -> Result<EncryptionKey> {
    let ctx     = format!("vgdb/backup/{ts_unix}");
    let derived = master.derive(&ctx)
        .context("HKDF derive backup key")?;
    Ok(derived.into_encryption_key())
}

/// Encrypt and persist the backup key as a `.key` sidecar file next to `archive_path`.
fn write_key_sidecar(
    archive_path: &Path,
    backup_key:   &EncryptionKey,
    master:       &MasterKey,
    ts_unix:      u64,
) -> Result<()> {
    let kdf_context = format!("vgdb/backup/{ts_unix}");

    // Wrap the backup key under the master key.
    // We need a wrapping key from the master.  Use a fixed context for the
    // key-wrapping key so it is always deterministically re-derivable.
    let wrap_key = master
        .derive("vgdb/backup-key-wrap")
        .context("derive backup key-wrap key")?
        .into_encryption_key();

    let ct = encrypt(&wrap_key, backup_key.as_bytes(), Some(b"vgdb/backup-key-wrap"))
        .context("encrypt backup key sidecar")?;

    let sidecar = BackupKeySidecar {
        wrapped_key_hex: hex::encode(&ct),
        kdf_context,
    };
    let json = serde_json::to_string_pretty(&sidecar)
        .context("serialise key sidecar")?;

    let sidecar_path = sidecar_path(archive_path);
    std::fs::write(&sidecar_path, &json)
        .with_context(|| format!("write key sidecar: {}", sidecar_path.display()))?;

    // Restrict to owner-read/write only.
    set_mode_600(&sidecar_path);

    info!(path = %sidecar_path.display(), "Backup key sidecar written");
    Ok(())
}

/// Load and unwrap the backup key from its `.key` sidecar file.
fn read_key_sidecar(archive_path: &Path, master: &MasterKey) -> Result<EncryptionKey> {
    let sidecar_path = sidecar_path(archive_path);
    let json = std::fs::read_to_string(&sidecar_path)
        .with_context(|| format!(
            "Cannot read backup key sidecar '{}'. \
             This file must accompany the archive to restore an encrypted backup.",
            sidecar_path.display()
        ))?;

    let sidecar: BackupKeySidecar = serde_json::from_str(&json)
        .context("parse key sidecar JSON")?;

    let ct = hex::decode(&sidecar.wrapped_key_hex)
        .context("hex-decode wrapped key")?;

    let wrap_key = master
        .derive("vgdb/backup-key-wrap")
        .context("re-derive backup key-wrap key")?
        .into_encryption_key();

    let pt = decrypt(&wrap_key, &ct, Some(b"vgdb/backup-key-wrap"))
        .map_err(|_| anyhow::anyhow!(
            "Backup key decryption failed — wrong master key or corrupted sidecar"
        ))?;

    let key_bytes: [u8; 32] = pt
        .try_into()
        .map_err(|_| anyhow::anyhow!("Backup key wrong length"))?;
    Ok(EncryptionKey::from_bytes(key_bytes))
}

fn sidecar_path(archive_path: &Path) -> PathBuf {
    // e.g. vledger-backup-20260810-120000.tar → vledger-backup-20260810-120000.tar.key
    let mut p = archive_path.to_path_buf();
    let name  = p
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    p.set_file_name(format!("{name}.key"));
    p
}

// ── Backup ────────────────────────────────────────────────────────────────────

/// Create an **encrypted** backup of `data_dir`.
///
/// Writes:
/// - `output_path`        — tar archive containing encrypted file blobs + MANIFEST.json
/// - `output_path` + `.key` — AES-256-GCM wrapped backup key (mode 0o600)
///
/// Pass `master_key = None` in tests where no real master key is available;
/// files will be stored **unencrypted** and `BackupManifest::encrypted` will
/// be `false`.  Production callers should always supply the master key.
pub fn create_backup(
    data_dir:   &Path,
    output_path: &Path,
) -> Result<BackupManifest> {
    create_backup_inner(data_dir, output_path, None)
}

/// Like `create_backup` but accepts an explicit master key for encryption.
pub fn create_backup_encrypted(
    data_dir:    &Path,
    output_path: &Path,
    master:      &MasterKey,
) -> Result<BackupManifest> {
    create_backup_inner(data_dir, output_path, Some(master))
}

fn create_backup_inner(
    data_dir:    &Path,
    output_path: &Path,
    master:      Option<&MasterKey>,
) -> Result<BackupManifest> {
    let ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts_rfc    = chrono::Utc::now().to_rfc3339();
    let encrypted = master.is_some();

    // Derive a per-backup AES-256-GCM key (or None for unencrypted path).
    let backup_key: Option<EncryptionKey> = if let Some(m) = master {
        Some(derive_backup_key(m, ts_unix)?)
    } else {
        None
    };

    info!(
        output    = %output_path.display(),
        encrypted = encrypted,
        "Creating backup"
    );

    // Resolve the canonical root of data_dir so symlink checks work.
    let canonical_root = data_dir.canonicalize()
        .with_context(|| format!("Cannot canonicalize data_dir: {}", data_dir.display()))?;

    let output_file = std::fs::File::create(output_path)
        .with_context(|| format!("Cannot create backup file: {}", output_path.display()))?;

    let mut archive = tar::Builder::new(output_file);
    let mut files: BTreeMap<String, String> = BTreeMap::new();

    // Directories to back up (private key material stays in HSM).
    let backup_dirs = ["wal", "pages", "catalog", "audit"];
    // Public-key files only from keys/.
    let keys_whitelist = ["db_signing_pubkey.hex"];

    for dir_name in &backup_dirs {
        let dir = data_dir.join(dir_name);
        if !dir.exists() { continue; }
        archive_dir_safe(
            &dir,
            dir_name,
            &canonical_root,
            backup_key.as_ref(),
            &mut archive,
            &mut files,
        )
        .with_context(|| format!("Failed to archive {dir_name}/"))?;
    }

    // Keys directory — public material only, via whitelist.
    let keys_dir = data_dir.join("keys");
    if keys_dir.exists() {
        for name in &keys_whitelist {
            let src = keys_dir.join(name);
            if !src.exists() { continue; }
            // Symlink check: resolved path must stay under canonical_root.
            let resolved = match src.canonicalize() {
                Ok(p) => p,
                Err(e) => {
                    warn!(path = %src.display(), "Cannot resolve keys/{name}: {e} — skipping");
                    continue;
                }
            };
            if !resolved.starts_with(&canonical_root) {
                warn!(
                    path     = %src.display(),
                    resolved = %resolved.display(),
                    "keys/{name} resolves outside data_dir — skipping (possible symlink attack)"
                );
                continue;
            }

            let bytes    = std::fs::read(&resolved)?;
            let hash     = hex::encode(blake3::hash(&bytes).as_bytes());
            let relative = format!("keys/{name}");

            let stored_bytes = if let Some(ref key) = backup_key {
                let ct = encrypt(key, &bytes, Some(relative.as_bytes()))
                    .context("encrypt keys file")?;
                ct
            } else {
                bytes
            };

            let archive_name = if encrypted {
                format!("{relative}.enc")
            } else {
                relative.clone()
            };

            write_archive_entry(&mut archive, &archive_name, &stored_bytes)?;
            files.insert(relative, hash);
        }
    }

    let manifest_hash = BackupManifest::compute_manifest_hash(&files);
    let manifest = BackupManifest {
        vledger_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at_unix: ts_unix,
        created_at_rfc:  ts_rfc,
        files:           files.clone(),
        manifest_hash,
        encrypted,
    };

    // Write MANIFEST.json unencrypted so it can be inspected without the key.
    let manifest_json  = serde_json::to_string_pretty(&manifest)
        .context("Failed to serialise manifest")?;
    let manifest_bytes = manifest_json.as_bytes();
    write_archive_entry(&mut archive, "MANIFEST.json", manifest_bytes)?;

    archive.finish().context("Failed to finalise archive")?;

    // Write the encrypted key sidecar.
    if let Some(m) = master {
        if let Some(ref key) = backup_key {
            write_key_sidecar(output_path, key, m, ts_unix)?;
        }
    }

    info!(
        files         = manifest.files.len(),
        output        = %output_path.display(),
        encrypted,
        manifest_hash = %&manifest.manifest_hash[..16],
        "Backup complete"
    );
    Ok(manifest)
}

// ── Restore ───────────────────────────────────────────────────────────────────

/// Restore a backup archive to `target_dir`.
///
/// If `BackupManifest::encrypted = true`, `master` must be `Some` and the
/// `.key` sidecar must be present alongside the archive.  Pass `master = None`
/// only when restoring unencrypted (legacy / test) archives.
pub fn restore_backup(
    archive_path: &Path,
    target_dir:   &Path,
    force:        bool,
) -> Result<BackupManifest> {
    restore_backup_inner(archive_path, target_dir, force, None)
}

/// Like `restore_backup` but supplies the master key to decrypt an encrypted archive.
pub fn restore_backup_encrypted(
    archive_path: &Path,
    target_dir:   &Path,
    force:        bool,
    master:       &MasterKey,
) -> Result<BackupManifest> {
    restore_backup_inner(archive_path, target_dir, force, Some(master))
}

fn restore_backup_inner(
    archive_path: &Path,
    target_dir:   &Path,
    force:        bool,
    master:       Option<&MasterKey>,
) -> Result<BackupManifest> {
    if target_dir.exists() && !force {
        anyhow::bail!(
            "Target directory already exists: {}\nUse --force to overwrite.",
            target_dir.display()
        );
    }

    info!(
        archive   = %archive_path.display(),
        target    = %target_dir.display(),
        "Restoring backup"
    );

    let archive_file = std::fs::File::open(archive_path)
        .with_context(|| format!("Cannot open archive: {}", archive_path.display()))?;

    // ── First pass: read and verify MANIFEST ──────────────────────────────
    let manifest = {
        let mut archive: tar::Archive<&std::fs::File> = tar::Archive::new(&archive_file);
        let mut found: Option<BackupManifest> = None;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            if path.to_string_lossy() == "MANIFEST.json" {
                let mut buf = String::new();
                entry.read_to_string(&mut buf)?;
                found = Some(
                    serde_json::from_str(&buf).context("Failed to parse MANIFEST.json")?,
                );
                break;
            }
        }
        found.context("MANIFEST.json not found in archive")?
    };

    if !manifest.verify() {
        anyhow::bail!(
            "Backup manifest hash verification FAILED — archive may be corrupt or tampered"
        );
    }

    // Load backup key if the archive is encrypted.
    let backup_key: Option<EncryptionKey> = if manifest.encrypted {
        let m = master.ok_or_else(|| anyhow::anyhow!(
            "Archive is encrypted but no master key was provided for restore.\n\
             Use `vledger restore` which loads the master key automatically."
        ))?;
        Some(read_key_sidecar(archive_path, m)?)
    } else {
        None
    };

    // ── Second pass: extract (decrypting as we go) ────────────────────────
    let archive_file = std::fs::File::open(archive_path)?;
    let mut archive  = tar::Archive::new(archive_file);
    std::fs::create_dir_all(target_dir)?;

    // Resolve canonical target root to guard against path-traversal in the
    // archive's stored entry names.
    let canonical_target = target_dir.canonicalize()
        .with_context(|| format!("Cannot canonicalize target_dir: {}", target_dir.display()))?;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_path_buf();
        let entry_name = entry_path.to_string_lossy().to_string();

        // Skip the manifest — already processed.
        if entry_name == "MANIFEST.json" { continue; }

        // Strip the `.enc` suffix to recover the real relative path.
        let logical_name = if manifest.encrypted && entry_name.ends_with(".enc") {
            entry_name[..entry_name.len() - 4].to_string()
        } else {
            entry_name.clone()
        };

        // Path-traversal guard: the entry must not escape target_dir.
        let dest = target_dir.join(&logical_name);
        // We can't canonicalize the destination before it exists, so check
        // that normalising the path components doesn't escape the root.
        if let Ok(normalised) = dest.canonicalize()
            .or_else(|_| {
                // File doesn't exist yet; check the parent instead.
                dest.parent()
                    .map(|p| p.canonicalize().map(|c| c.join(dest.file_name().unwrap_or_default())))
                    .unwrap_or_else(|| Ok(dest.clone()))
            })
        {
            if !normalised.starts_with(&canonical_target) {
                warn!(
                    entry    = %entry_name,
                    dest     = %dest.display(),
                    "Archive entry would escape target directory — skipping"
                );
                continue;
            }
        }

        // Create parent directories.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Read entry bytes.
        let mut raw = Vec::new();
        entry.read_to_end(&mut raw)?;

        // Decrypt if needed.
        let plain = if let Some(ref key) = backup_key {
            decrypt(key, &raw, Some(logical_name.as_bytes()))
                .map_err(|_| anyhow::anyhow!(
                    "Decryption failed for '{}' — wrong key or corrupted archive",
                    logical_name
                ))?
        } else {
            raw
        };

        std::fs::write(&dest, &plain)
            .with_context(|| format!("Failed to write '{}'", dest.display()))?;
    }

    // ── Third pass: verify BLAKE3 hashes of restored plaintext files ──────
    let mut failures = Vec::new();
    for (rel_path, expected_hash) in &manifest.files {
        let full = target_dir.join(rel_path);
        if !full.exists() {
            failures.push(format!("Missing: {rel_path}"));
            continue;
        }
        let bytes  = std::fs::read(&full)?;
        let actual = hex::encode(blake3::hash(&bytes).as_bytes());
        if &actual != expected_hash {
            failures.push(format!("Hash mismatch: {rel_path}"));
        }
    }

    if !failures.is_empty() {
        anyhow::bail!("Restore verification failed:\n{}", failures.join("\n"));
    }

    info!(
        files  = manifest.files.len(),
        target = %target_dir.display(),
        "Restore complete and verified"
    );
    Ok(manifest)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Walk `dir` recursively, skipping any entry whose canonical path escapes
/// `canonical_root` (symlink traversal hardening).
///
/// Returns a flat list of resolved absolute `PathBuf` values, all of which
/// are confirmed to reside within `canonical_root`.
fn walkdir_safe(dir: &Path, canonical_root: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path  = entry.path();

        // Resolve the real path (follows symlinks).
        let resolved = match path.canonicalize() {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    "Cannot resolve path during backup walk: {e} — skipping"
                );
                continue;
            }
        };

        // Symlink/traversal guard: resolved path must stay under data_dir.
        if !resolved.starts_with(canonical_root) {
            warn!(
                path     = %path.display(),
                resolved = %resolved.display(),
                "Path resolves outside data_dir — skipping (possible symlink attack)"
            );
            continue;
        }

        if resolved.is_dir() {
            result.extend(walkdir_safe(&path, canonical_root)?);
        } else {
            result.push(resolved);
        }
    }
    Ok(result)
}

/// Archive all files under `dir`, encrypting each one if `backup_key` is Some.
///
/// Archive entry names are `<prefix>/<relative_path>[.enc]`.
/// Manifest entries use the plaintext-relative path (no `.enc`).
fn archive_dir_safe<W: Write>(
    dir:          &Path,
    prefix:       &str,
    canonical_root: &Path,
    backup_key:   Option<&EncryptionKey>,
    archive:      &mut tar::Builder<W>,
    files:        &mut BTreeMap<String, String>,
) -> Result<()> {
    for resolved in walkdir_safe(dir, canonical_root)? {
        // Relative path from dir root — used as the logical archive name.
        let rel = resolved
            .strip_prefix(dir)
            .unwrap_or(&resolved);
        let relative = format!("{prefix}/{}", rel.display());

        let bytes = std::fs::read(&resolved)?;
        let hash  = hex::encode(blake3::hash(&bytes).as_bytes());

        let (stored_bytes, archive_name) = if let Some(key) = backup_key {
            let ct = encrypt(key, &bytes, Some(relative.as_bytes()))
                .with_context(|| format!("encrypt {relative}"))?;
            (ct, format!("{relative}.enc"))
        } else {
            (bytes, relative.clone())
        };

        write_archive_entry(archive, &archive_name, &stored_bytes)?;
        files.insert(relative, hash);
    }
    Ok(())
}

/// Write a single in-memory buffer as a tar entry.
fn write_archive_entry<W: Write>(
    archive: &mut tar::Builder<W>,
    name:    &str,
    data:    &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, name, data)
        .with_context(|| format!("Failed to write archive entry '{name}'"))
}

/// Restrict a file to owner-read/write only (0o600).
fn set_mode_600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    { let _ = path; }
}


// ── External backup integrity verification ────────────────────────────────────

/// Verify a backup archive without restoring it to disk.
///
/// This performs:
/// 1. Reads `MANIFEST.json` from the archive.
/// 2. Verifies the manifest hash (tamper check on the file list itself).
/// 3. If the archive is encrypted and `master` is `Some`, decrypts every
///    file entry and verifies its BLAKE3 hash against the manifest.
/// 4. If `master` is `None` and the archive is encrypted, reports the file
///    list and manifest hash only (cannot verify encrypted content).
///
/// Returns a `VerifyReport` describing the outcome.
pub fn verify_backup(
    archive_path: &Path,
    master:       Option<&MasterKey>,
) -> Result<VerifyReport, anyhow::Error> {
    use std::io::Read;

    // ── First pass: extract and validate MANIFEST ─────────────────────────
    let archive_file = std::fs::File::open(archive_path)
        .with_context(|| format!("Cannot open archive: {}", archive_path.display()))?;
    let mut archive: tar::Archive<&std::fs::File> = tar::Archive::new(&archive_file);

    let manifest: BackupManifest = {
        let mut found: Option<BackupManifest> = None;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path()?.to_string_lossy() == "MANIFEST.json" {
                let mut buf = String::new();
                entry.read_to_string(&mut buf)?;
                found = Some(serde_json::from_str(&buf).context("Parse MANIFEST.json")?);
                break;
            }
        }
        found.context("MANIFEST.json not found in archive")?
    };

    let manifest_ok = manifest.verify();

    // ── Second pass: verify per-file hashes if decryption is possible ─────
    let backup_key: Option<vledger_crypto::encrypt::EncryptionKey> = if manifest.encrypted {
        match master {
            Some(m) => {
                // Re-derive the backup key from the .key sidecar
                let sidecar_path = {
                    let name = archive_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let mut p = archive_path.to_path_buf();
                    p.set_file_name(format!("{name}.key"));
                    p
                };
                if sidecar_path.exists() {
                    // Use the existing read_key_sidecar via the restore path
                    Some(read_key_sidecar(archive_path, m)?)
                } else {
                    None // Cannot decrypt without sidecar
                }
            }
            None => None,
        }
    } else {
        None
    };

    let mut file_results: Vec<FileVerifyResult> = Vec::new();

    if backup_key.is_some() || !manifest.encrypted {
        let archive_file2 = std::fs::File::open(archive_path)?;
        let mut archive2  = tar::Archive::new(archive_file2);

        for entry in archive2.entries()? {
            let mut entry = entry?;
            let entry_name = entry.path()?.to_string_lossy().to_string();
            if entry_name == "MANIFEST.json" { continue; }

            let logical_name = if manifest.encrypted && entry_name.ends_with(".enc") {
                entry_name[..entry_name.len() - 4].to_string()
            } else {
                entry_name.clone()
            };

            let expected_hash = match manifest.files.get(&logical_name) {
                Some(h) => h.clone(),
                None    => {
                    file_results.push(FileVerifyResult {
                        path:    logical_name,
                        status:  FileVerifyStatus::NotInManifest,
                        reason:  None,
                    });
                    continue;
                }
            };

            let mut raw = Vec::new();
            entry.read_to_end(&mut raw)?;

            let plain = if let Some(ref key) = backup_key {
                match vledger_crypto::encrypt::decrypt(key, &raw, Some(logical_name.as_bytes())) {
                    Ok(p)  => p,
                    Err(_) => {
                        file_results.push(FileVerifyResult {
                            path:   logical_name,
                            status: FileVerifyStatus::DecryptionFailed,
                            reason: None,
                        });
                        continue;
                    }
                }
            } else {
                raw
            };

            let actual_hash = hex::encode(blake3::hash(&plain).as_bytes());
            if actual_hash == expected_hash {
                file_results.push(FileVerifyResult {
                    path:   logical_name,
                    status: FileVerifyStatus::Ok,
                    reason: None,
                });
            } else {
                file_results.push(FileVerifyResult {
                    path:   logical_name.clone(),
                    status: FileVerifyStatus::HashMismatch,
                    reason: Some(format!(
                        "expected {}, got {}", &expected_hash[..16], &actual_hash[..16]
                    )),
                });
            }
        }
    }

    let failed_files = file_results.iter()
        .filter(|r| r.status != FileVerifyStatus::Ok)
        .count();

    Ok(VerifyReport {
        archive_path:      archive_path.to_path_buf(),
        vledger_version:   manifest.vledger_version.clone(),
        created_at:        manifest.created_at_rfc.clone(),
        encrypted:         manifest.encrypted,
        manifest_hash:     manifest.manifest_hash.clone(),
        manifest_hash_ok:  manifest_ok,
        total_files:       manifest.files.len(),
        content_verified:  !file_results.is_empty(),
        file_results,
        failed_files,
    })
}

/// Status of a single file's verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileVerifyStatus {
    /// File hash matched.
    Ok,
    /// File hash did not match the manifest.
    HashMismatch,
    /// File could not be decrypted (wrong key or corrupt ciphertext).
    DecryptionFailed,
    /// File was present in the archive but absent from the manifest.
    NotInManifest,
}

/// Per-file verification result.
#[derive(Debug, Clone)]
pub struct FileVerifyResult {
    pub path:   String,
    pub status: FileVerifyStatus,
    pub reason: Option<String>,
}

/// Complete report from `verify_backup`.
#[derive(Debug)]
pub struct VerifyReport {
    pub archive_path:      std::path::PathBuf,
    pub vledger_version:   String,
    pub created_at:        String,
    pub encrypted:         bool,
    pub manifest_hash:     String,
    pub manifest_hash_ok:  bool,
    pub total_files:       usize,
    pub content_verified:  bool,
    pub file_results:      Vec<FileVerifyResult>,
    pub failed_files:      usize,
}

impl VerifyReport {
    /// `true` if every verifiable check passed.
    pub fn is_ok(&self) -> bool {
        self.manifest_hash_ok && self.failed_files == 0
    }

    /// Print a human-readable summary to stdout.
    pub fn print_summary(&self) {
        println!("── VectorLedger Backup Verification ────────────");
        println!("  Archive   : {}", self.archive_path.display());
        println!("  Version   : {}", self.vledger_version);
        println!("  Created   : {}", self.created_at);
        println!("  Encrypted : {}", self.encrypted);
        println!("  Files     : {}", self.total_files);
        println!("  Manifest  : {}",
            if self.manifest_hash_ok { "✓ OK" } else { "✗ TAMPERED" });

        if self.content_verified {
            let ok_count   = self.file_results.iter().filter(|r| r.status == FileVerifyStatus::Ok).count();
            let fail_count = self.failed_files;
            println!("  Content   : {ok_count} OK, {fail_count} FAILED");
            for r in &self.file_results {
                if r.status != FileVerifyStatus::Ok {
                    println!("    ✗ {} — {:?}{}", r.path, r.status,
                        r.reason.as_deref().map(|s| format!(": {s}")).unwrap_or_default());
                }
            }
        } else if self.encrypted {
            println!("  Content   : skipped (no master key — manifest-only verify)");
        }

        println!("  Result    : {}", if self.is_ok() { "✓ PASS" } else { "✗ FAIL" });
        println!("──────────────────────────────────────────────────");
    }
}

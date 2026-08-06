//! `vledger backup` and `vledger restore` — snapshot archive operations.
//!
//! ## Backup format
//! A backup is a `.tar` archive with a BLAKE3 manifest:
//!
//! ```text
//! vledger-backup-<timestamp>/
//!   MANIFEST.json        ← file list + BLAKE3 hashes + backup metadata
//!   wal/                 ← all WAL segment files
//!   pages/               ← all encrypted page files
//!   catalog/             ← VERSION + signing pubkey
//!   keys/                ← public keys only (private key material stays in HSM)
//!   audit/               ← full audit log
//! ```
//!
//! The archive is streamed to `--output <path>` (defaults to
//! `./vledger-backup-<timestamp>.tar`).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

// ── Manifest ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifest {
    pub vledger_version:    String,
    pub created_at_unix: u64,
    pub created_at_rfc:  String,
    /// Map from relative path inside the archive to BLAKE3 hex hash.
    pub files:           BTreeMap<String, String>,
    /// BLAKE3 hash of all (path, file_hash) pairs sorted lexicographically.
    pub manifest_hash:   String,
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

// ── Backup ────────────────────────────────────────────────────────────────────

/// Create a backup of `data_dir` and write a `.tar` archive to `output_path`.
pub fn create_backup(data_dir: &Path, output_path: &Path) -> Result<BackupManifest> {
    let ts_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts_rfc = chrono::Utc::now().to_rfc3339();

    info!(output = %output_path.display(), "Creating backup");

    let output_file = std::fs::File::create(output_path)
        .with_context(|| format!("Cannot create backup file: {}", output_path.display()))?;

    let mut archive = tar::Builder::new(output_file);
    let mut files: BTreeMap<String, String> = BTreeMap::new();

    // Directories to back up (skip keys/ private material — HSM holds that)
    let backup_dirs = ["wal", "pages", "catalog", "audit"];
    // Also include top-level public key files only
    let keys_whitelist = ["db_signing_pubkey.hex"];

    for dir_name in &backup_dirs {
        let dir = data_dir.join(dir_name);
        if !dir.exists() { continue; }
        archive_dir(&dir, dir_name, &mut archive, &mut files)
            .with_context(|| format!("Failed to archive {dir_name}/"))?;
    }

    // Keys — public material only
    let keys_dir = data_dir.join("keys");
    if keys_dir.exists() {
        for name in &keys_whitelist {
            let src = keys_dir.join(name);
            if src.exists() {
                let relative = format!("keys/{name}");
                let bytes = std::fs::read(&src)?;
                let hash  = hex::encode(blake3::hash(&bytes).as_bytes());
                archive.append_path_with_name(&src, &relative)
                    .with_context(|| format!("Failed to add {relative} to archive"))?;
                files.insert(relative, hash);
            }
        }
    }

    let manifest_hash = BackupManifest::compute_manifest_hash(&files);
    let manifest = BackupManifest {
        vledger_version:    env!("CARGO_PKG_VERSION").to_string(),
        created_at_unix: ts_unix,
        created_at_rfc:  ts_rfc,
        files:           files.clone(),
        manifest_hash,
    };

    // Write manifest into the archive
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .context("Failed to serialise manifest")?;
    let manifest_bytes = manifest_json.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, "MANIFEST.json", manifest_bytes)
        .context("Failed to write MANIFEST.json")?;

    archive.finish().context("Failed to finalise archive")?;

    info!(
        files    = manifest.files.len(),
        output   = %output_path.display(),
        manifest_hash = %&manifest.manifest_hash[..16],
        "Backup complete"
    );
    Ok(manifest)
}

fn archive_dir<W: Write>(
    dir:     &Path,
    prefix:  &str,
    archive: &mut tar::Builder<W>,
    files:   &mut BTreeMap<String, String>,
) -> Result<()> {
    for entry in walkdir(dir)? {
        let path = entry?;
        if path.is_file() {
            let relative = format!("{prefix}/{}", path.strip_prefix(dir)
                .unwrap_or(&path).display());
            let bytes = std::fs::read(&path)?;
            let hash  = hex::encode(blake3::hash(&bytes).as_bytes());
            files.insert(relative.clone(), hash);
            archive.append_path_with_name(&path, &relative)
                .with_context(|| format!("Failed to add {relative}"))?;
        }
    }
    Ok(())
}

/// Simple recursive directory walk (no external dep required).
fn walkdir(dir: &Path) -> Result<Vec<anyhow::Result<PathBuf>>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path  = entry.path();
        if path.is_dir() {
            result.extend(walkdir(&path)?);
        } else {
            result.push(Ok(path));
        }
    }
    Ok(result)
}

// ── Restore ───────────────────────────────────────────────────────────────────

/// Restore a backup archive to `target_dir`.
///
/// Verifies the manifest hash before extracting.  Refuses to overwrite an
/// existing data directory unless `force = true`.
pub fn restore_backup(archive_path: &Path, target_dir: &Path, force: bool) -> Result<BackupManifest> {
    if target_dir.exists() && !force {
        anyhow::bail!(
            "Target directory already exists: {}\nUse --force to overwrite.",
            target_dir.display()
        );
    }

    info!(archive = %archive_path.display(), target = %target_dir.display(), "Restoring backup");

    let archive_file = std::fs::File::open(archive_path)
        .with_context(|| format!("Cannot open archive: {}", archive_path.display()))?;

    // First pass: read and verify manifest
    let manifest = {
        let mut archive = tar::Archive::new(&archive_file);
        let mut manifest: Option<BackupManifest> = None;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            if path.to_string_lossy() == "MANIFEST.json" {
                let mut buf = String::new();
                entry.read_to_string(&mut buf)?;
                manifest = Some(serde_json::from_str(&buf)
                    .context("Failed to parse MANIFEST.json")?);
                break;
            }
        }
        manifest.context("MANIFEST.json not found in archive")?
    };

    if !manifest.verify() {
        anyhow::bail!("Backup manifest hash verification FAILED — archive may be corrupt or tampered");
    }

    // Second pass: extract
    let archive_file = std::fs::File::open(archive_path)?;
    let mut archive  = tar::Archive::new(archive_file);
    std::fs::create_dir_all(target_dir)?;
    archive.unpack(target_dir)
        .context("Failed to extract archive")?;

    // Third pass: verify each file's BLAKE3 hash against the manifest
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
        anyhow::bail!(
            "Restore verification failed:\n{}",
            failures.join("\n")
        );
    }

    info!(
        files  = manifest.files.len(),
        target = %target_dir.display(),
        "Restore complete and verified"
    );
    Ok(manifest)
}

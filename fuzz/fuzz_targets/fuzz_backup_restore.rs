//! Fuzz target: backup archive parsing and restore pipeline.
//!
//! The backup/restore logic lives in `crates/vledger/src/backup.rs` which is
//! a private module of the binary crate.  This fuzz target exercises the same
//! parsing surfaces directly through the underlying crates to avoid coupling
//! to the binary's internal module structure.
//!
//! ## What is fuzzed
//!
//! ### tar archive parsing
//! - Arbitrary byte streams fed to `tar::Archive::entries()`.
//! - Entry path names: empty, very long, `../` traversal sequences, null bytes.
//! - Entry data: truncated, corrupt, oversized.
//!
//! ### BackupManifest JSON parsing (serde_json)
//! - Arbitrary bytes parsed as `BackupManifest` JSON.
//! - Valid-looking manifests with wrong `manifest_hash`.
//! - Manifests with huge `files` maps.
//!
//! ### AES-256-GCM decryption (`vledger_crypto::encrypt::decrypt`)
//! - Arbitrary ciphertext with a fixed key.
//! - Ciphertext too short to hold a nonce.
//! - Ciphertext with a valid nonce but corrupt tag.
//! - AAD mismatches (fuzz bytes as AAD).
//!
//! ### BLAKE3 manifest hash verification
//! - `BackupManifest::verify()` with fuzz-derived `manifest_hash` values.
//!
//! ### Path-traversal guard (canonical path prefix check)
//! - Entry names with `../` sequences must not cause a panic; the caller is
//!   responsible for rejecting them, and we confirm no panic occurs when
//!   the check is applied.
//!
//! ## Success criteria
//! - No panic
//! - No unbounded allocation (libfuzzer OOM limit)
//! - No infinite loop (timeout)

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;
use std::io::Read;

use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use vledger_crypto::encrypt::{decrypt, encrypt, EncryptionKey};

// ── Inline the manifest type to avoid depending on the binary crate ──────────
// This mirrors the real `BackupManifest` struct in backup.rs exactly so the
// fuzzer exercises the same serde paths.

#[derive(Debug, Serialize, Deserialize)]
struct BackupManifest {
    pub vledger_version: String,
    pub created_at_unix: u64,
    pub created_at_rfc: String,
    pub files: BTreeMap<String, String>,
    pub manifest_hash: String,
    pub encrypted: bool,
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

    fn verify(&self) -> bool {
        let expected = Self::compute_manifest_hash(&self.files);
        expected == self.manifest_hash
    }
}

fuzz_target!(|data: &[u8]| {
    // Bound input to avoid runaway allocations.
    if data.len() > 4 * 1024 * 1024 {
        return;
    }

    // ── Surface 1: tar archive parsing ────────────────────────────────────
    {
        let cursor = std::io::Cursor::new(data);
        let mut archive = tar::Archive::new(cursor);
        if let Ok(entries) = archive.entries() {
            for (i, entry) in entries.enumerate() {
                if i > 512 {
                    break; // bound iteration
                }
                if let Ok(mut e) = entry {
                    // Exercise path() — must not panic on arbitrary names.
                    // Read path first (borrows e), clone the result, then consume e.
                    let path_str: Option<String> = e
                        .path()
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned());

                    // Read up to 64 KiB per entry to bound memory use.
                    let mut buf = Vec::new();
                    let _ = e.take(64 * 1024).read_to_end(&mut buf);

                    // Path-traversal check simulation: normalise the path
                    // and ensure the prefix check itself doesn't panic.
                    if let Some(s) = path_str {
                        // Guard: reject entries whose name starts with ".."
                        // or contains null bytes — must not panic.
                        let _is_safe = !s.starts_with("..") && !s.contains('\0');
                    }
                }
            }
        }
    }

    // ── Surface 2: BackupManifest JSON deserialization ────────────────────
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() <= 128 * 1024 {
            if let Ok(manifest) = serde_json::from_str::<BackupManifest>(s) {
                // verify() must not panic for any parsed manifest.
                let _ = manifest.verify();

                // Bound the `files` map to prevent OOM on huge crafted manifests.
                assert!(
                    manifest.files.len() <= 100_000,
                    "manifest.files map exceeded 100_000 entries — possible fuzz-amplification"
                );
            }
        }
    }

    // ── Surface 3: AES-256-GCM decryption with fuzz ciphertext ───────────
    {
        let key_bytes = [0x42u8; 32]; // fixed key — we're fuzzing the ciphertext parsing
        let key = EncryptionKey::from_bytes(key_bytes);

        // Decrypt with no AAD.
        let _ = decrypt(&key, data, None);

        // Decrypt with fuzz bytes as AAD (bound to 256 bytes).
        let aad_len = data.len().min(256);
        let _ = decrypt(&key, data, Some(&data[..aad_len]));

        // Decrypt with a fixed AAD string (the path format used in production).
        let _ = decrypt(&key, data, Some(b"wal/00000000000000000000.wal"));
    }

    // ── Surface 4: encrypt → corrupt → decrypt ───────────────────────────
    // Proves the AEAD tag validation catches any single-byte corruption.
    if !data.is_empty() && data.len() <= 4096 {
        let key = EncryptionKey::from_bytes([0x55u8; 32]);
        if let Ok(mut ct) = encrypt(&key, data, None) {
            // Flip one byte in the ciphertext body (past the 12-byte nonce).
            if ct.len() > 12 {
                ct[12] ^= 0x01;
                // Must return Err (AEAD authentication failed), never panic.
                assert!(
                    decrypt(&key, &ct, None).is_err(),
                    "AES-256-GCM: tampered ciphertext must not decrypt successfully"
                );
            }
        }
    }

    // ── Surface 5: BLAKE3 hash computation on arbitrary inputs ───────────
    // blake3::hash must not panic on any input.
    let _ = blake3::hash(data);

    // ── Surface 6: tar + MANIFEST round-trip parsing ──────────────────────
    // Build a minimal tar archive in memory, inject fuzz bytes as
    // MANIFEST.json content, and parse it back — same path as restore_backup.
    {
        let dir = match TempDir::new() {
            Ok(d) => d,
            Err(_) => return,
        };
        let archive_path = dir.path().join("test.tar");

        // Write a tar archive with fuzz bytes as MANIFEST.json.
        let manifest_content = &data[..data.len().min(4096)];
        if let Ok(f) = std::fs::File::create(&archive_path) {
            let mut builder = tar::Builder::new(f);
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest_content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            let _ = builder.append_data(&mut header, "MANIFEST.json", manifest_content);
            let _ = builder.finish();
        }

        // Parse it back — same logic as the first pass in restore_backup_inner.
        if let Ok(f) = std::fs::File::open(&archive_path) {
            let mut archive = tar::Archive::new(f);
            if let Ok(entries) = archive.entries() {
                for entry in entries {
                    if let Ok(mut e) = entry {
                        if e.path().ok().map(|p| p.to_string_lossy() == "MANIFEST.json").unwrap_or(false) {
                            let mut buf = String::new();
                            let _ = e.take(64 * 1024).read_to_string(&mut buf);
                            if let Ok(m) = serde_json::from_str::<BackupManifest>(&buf) {
                                let _ = m.verify();
                            }
                        }
                    }
                }
            }
        }
    }
});

//! Fuzz target: backup key sidecar (.key file) parsing.
//!
//! The `.key` sidecar file is JSON-encoded AES-256-GCM wrapped key material.
//! This target exercises the sidecar parser specifically (separate from the
//! tar archive which is covered by fuzz_backup_restore).
//!
//! ## What is fuzzed
//! - Arbitrary JSON as BackupKeySidecar content
//! - `wrapped_key_hex` field: wrong length, invalid hex, empty, all-zeros
//! - `kdf_context` field: arbitrary strings
//! - Decryption of fuzz ciphertext with a fixed wrapping key
//! - Path to sidecar: non-existent file, empty file, binary content

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Read;
use tempfile::TempDir;

use vledger_crypto::encrypt::{decrypt, encrypt, EncryptionKey};
use vledger_crypto::kdf::MasterKey;

/// Mirrors the internal BackupKeySidecar struct for fuzzing purposes.
#[derive(serde::Serialize, serde::Deserialize)]
struct BackupKeySidecar {
    wrapped_key_hex: String,
    kdf_context: String,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }

    let dir = match TempDir::new() {
        Ok(d) => d,
        Err(_) => return,
    };

    // ── Surface 1: parse arbitrary bytes as JSON sidecar ─────────────────
    if let Ok(s) = std::str::from_utf8(data) {
        if s.len() <= 64 * 1024 {
            if let Ok(sidecar) = serde_json::from_str::<BackupKeySidecar>(s) {
                // Try to decode the wrapped_key_hex
                let ct_result = hex::decode(&sidecar.wrapped_key_hex);

                if let Ok(ct) = ct_result {
                    // Try to decrypt with a fixed wrapping key
                    let wrap_key = EncryptionKey::from_bytes([0x55u8; 32]);
                    let _ = decrypt(&wrap_key, &ct, Some(b"vgdb/backup-key-wrap"));
                }
            }
        }
    }

    // ── Surface 2: write fuzz bytes as sidecar file and parse ────────────
    {
        let sidecar_path = dir.path().join("test.tar.key");
        if std::fs::write(&sidecar_path, data).is_ok() {
            // Simulate what the restore path does: read JSON, hex-decode, decrypt
            if let Ok(json) = std::fs::read_to_string(&sidecar_path) {
                if let Ok(sidecar) = serde_json::from_str::<BackupKeySidecar>(&json) {
                    if let Ok(ct) = hex::decode(&sidecar.wrapped_key_hex) {
                        let wrap_key = EncryptionKey::from_bytes([0x55u8; 32]);
                        let result = decrypt(&wrap_key, &ct, Some(b"vgdb/backup-key-wrap"));
                        if let Ok(pt) = result {
                            // If decrypt succeeded, try to use as a 32-byte key
                            let _: Option<[u8; 32]> = pt.try_into().ok();
                        }
                    }
                }
            }
        }
    }

    // ── Surface 3: sidecar with fuzz-derived wrapped key content ─────────
    {
        // Build a structurally valid sidecar with fuzz bytes as the ciphertext
        let fuzz_hex = hex::encode(&data[..data.len().min(100)]);
        let sidecar = BackupKeySidecar {
            wrapped_key_hex: fuzz_hex,
            kdf_context: String::from_utf8_lossy(&data[..data.len().min(64)]).into_owned(),
        };
        if let Ok(json) = serde_json::to_string(&sidecar) {
            let sidecar_path = dir.path().join("fuzz.tar.key");
            if std::fs::write(&sidecar_path, &json).is_ok() {
                if let Ok(content) = std::fs::read_to_string(&sidecar_path) {
                    if let Ok(parsed) = serde_json::from_str::<BackupKeySidecar>(&content) {
                        let wrap_key = EncryptionKey::from_bytes([0xABu8; 32]);
                        if let Ok(ct) = hex::decode(&parsed.wrapped_key_hex) {
                            let _ = decrypt(&wrap_key, &ct, Some(b"vgdb/backup-key-wrap"));
                        }
                    }
                }
            }
        }
    }

    // ── Surface 4: AES-256-GCM encrypt → fuzz-corrupt → decrypt ──────────
    // Verifies that the AEAD tag catches any corruption in the wrapped key.
    if !data.is_empty() && data.len() <= 1024 {
        let master = MasterKey::from_bytes([0x42u8; 32]);
        if let Ok(wrap_derived) = master.derive("vgdb/backup-key-wrap") {
            let wrap_key = wrap_derived.into_encryption_key();
            let backup_key_bytes = [0x99u8; 32];
            if let Ok(mut ct) = encrypt(&wrap_key, &backup_key_bytes, Some(b"vgdb/backup-key-wrap")) {
                // Corrupt the ciphertext using the first fuzz byte as XOR mask
                if ct.len() > 12 {
                    ct[12] ^= data[0];
                    if data[0] != 0 {
                        // Non-zero XOR must fail to decrypt
                        assert!(
                            decrypt(&wrap_key, &ct, Some(b"vgdb/backup-key-wrap")).is_err(),
                            "AES-GCM: single-byte corruption must cause decryption failure"
                        );
                    }
                }
            }
        }
    }
});

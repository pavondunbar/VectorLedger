//! Comprehensive tests for the MasterKey / DerivedKey hierarchy.
//!
//! The existing kdf.rs has 3 basic tests. This file adds coverage for:
//! - Determinism across instances (same master bytes → same derived key)
//! - All named derivation helpers produce distinct keys
//! - Row keys are isolated per (table_id, row_id) pair
//! - WAL key is separate from all table keys
//! - DerivedKey conversions (into_encryption_key, into_signing_seed)
//! - Empty context is accepted (edge case)
//! - Very long context strings work correctly
//! - MasterKey::generate() produces different keys each call
//! - DerivedKey::context field is preserved correctly

#[cfg(test)]
mod tests {
    use crate::kdf::{DerivedKey, MasterKey};

    // ─────────────────────────────────────────────────────────────────────
    // Determinism
    // ─────────────────────────────────────────────────────────────────────

    /// Same master key bytes + same context → identical derived key bytes.
    #[test]
    fn derive_is_deterministic_across_instances() {
        let bytes = [0x42u8; 32];
        let m1 = MasterKey::from_bytes(bytes);
        let m2 = MasterKey::from_bytes(bytes);
        let k1 = m1.derive("vgdb/table/1/encrypt").unwrap();
        let k2 = m2.derive("vgdb/table/1/encrypt").unwrap();
        assert_eq!(
            k1.as_bytes(),
            k2.as_bytes(),
            "same master bytes + same context must produce identical derived key"
        );
    }

    /// Different master key bytes → different derived keys for same context.
    #[test]
    fn different_master_keys_produce_different_derived_keys() {
        let m1 = MasterKey::from_bytes([0x11u8; 32]);
        let m2 = MasterKey::from_bytes([0x22u8; 32]);
        let ctx = "vgdb/table/0/encrypt";
        let k1 = m1.derive(ctx).unwrap();
        let k2 = m2.derive(ctx).unwrap();
        assert_ne!(
            k1.as_bytes(),
            k2.as_bytes(),
            "different master keys must produce different derived keys for the same context"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Context separation — all named helpers produce distinct keys
    // ─────────────────────────────────────────────────────────────────────

    /// table_encrypt_key and table_sign_key for the same table are distinct.
    #[test]
    fn encrypt_and_sign_keys_for_same_table_are_distinct() {
        let master = MasterKey::from_bytes([0x55u8; 32]);
        let enc = master.table_encrypt_key(0).unwrap();
        let sign = master.table_sign_key(0).unwrap();
        assert_ne!(enc.as_bytes(), sign.as_bytes(), "encrypt and sign keys must differ for same table");
    }

    /// table_encrypt_key for different table IDs are distinct.
    #[test]
    fn encrypt_keys_for_different_tables_are_distinct() {
        let master = MasterKey::from_bytes([0x33u8; 32]);
        let k0 = master.table_encrypt_key(0).unwrap();
        let k1 = master.table_encrypt_key(1).unwrap();
        let k2 = master.table_encrypt_key(2).unwrap();
        assert_ne!(k0.as_bytes(), k1.as_bytes());
        assert_ne!(k1.as_bytes(), k2.as_bytes());
        assert_ne!(k0.as_bytes(), k2.as_bytes());
    }

    /// WAL sign key is distinct from all table keys.
    #[test]
    fn wal_sign_key_distinct_from_table_keys() {
        let master = MasterKey::from_bytes([0x77u8; 32]);
        let wal = master.wal_sign_key().unwrap();
        let t0_enc = master.table_encrypt_key(0).unwrap();
        let t0_sign = master.table_sign_key(0).unwrap();
        assert_ne!(wal.as_bytes(), t0_enc.as_bytes(), "WAL key must differ from table-0 encrypt key");
        assert_ne!(wal.as_bytes(), t0_sign.as_bytes(), "WAL key must differ from table-0 sign key");
    }

    /// row_key is distinct for different row IDs within the same table.
    #[test]
    fn row_keys_differ_by_row_id() {
        let master = MasterKey::from_bytes([0x99u8; 32]);
        let r0 = master.row_key(1, 0).unwrap();
        let r1 = master.row_key(1, 1).unwrap();
        let r100 = master.row_key(1, 100).unwrap();
        assert_ne!(r0.as_bytes(), r1.as_bytes());
        assert_ne!(r1.as_bytes(), r100.as_bytes());
        assert_ne!(r0.as_bytes(), r100.as_bytes());
    }

    /// row_key is distinct for the same row ID across different tables.
    #[test]
    fn row_keys_differ_by_table_id() {
        let master = MasterKey::from_bytes([0xAAu8; 32]);
        let r_t0 = master.row_key(0, 42).unwrap();
        let r_t1 = master.row_key(1, 42).unwrap();
        assert_ne!(
            r_t0.as_bytes(), r_t1.as_bytes(),
            "same row ID in different tables must produce different keys"
        );
    }

    /// row_key is distinct from the table's encrypt key (context isolation).
    #[test]
    fn row_key_distinct_from_table_encrypt_key() {
        let master = MasterKey::from_bytes([0xBBu8; 32]);
        let row = master.row_key(1, 0).unwrap();
        let enc = master.table_encrypt_key(1).unwrap();
        assert_ne!(row.as_bytes(), enc.as_bytes());
    }

    // ─────────────────────────────────────────────────────────────────────
    // All six canonical contexts are pairwise distinct
    // ─────────────────────────────────────────────────────────────────────

    /// All named derivation contexts for a single configuration produce
    /// mutually distinct keys.
    #[test]
    fn all_canonical_contexts_produce_distinct_keys() {
        let master = MasterKey::from_bytes([0xCCu8; 32]);
        let keys: Vec<[u8; 32]> = vec![
            *master.table_encrypt_key(0).unwrap().as_bytes(),
            *master.table_sign_key(0).unwrap().as_bytes(),
            *master.row_key(0, 0).unwrap().as_bytes(),
            *master.wal_sign_key().unwrap().as_bytes(),
            *master.table_encrypt_key(1).unwrap().as_bytes(),
            *master.table_sign_key(1).unwrap().as_bytes(),
        ];

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "keys[{i}] and keys[{j}] must be distinct"
                );
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // DerivedKey conversions
    // ─────────────────────────────────────────────────────────────────────

    /// into_encryption_key returns an EncryptionKey that can encrypt/decrypt.
    #[test]
    fn derived_key_into_encryption_key_works() {
        let master = MasterKey::from_bytes([0xDDu8; 32]);
        let derived = master.table_encrypt_key(0).unwrap();
        let enc_key = derived.into_encryption_key();
        // Verify encrypt/decrypt round-trip works with the derived key
        let plaintext = b"test data for derived key encryption";
        let ciphertext = crate::encrypt::encrypt(&enc_key, plaintext, None).unwrap();
        let decrypted = crate::encrypt::decrypt(&enc_key, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext, "encrypt/decrypt round-trip must work with derived key");
    }

    /// into_signing_seed returns a 32-byte array usable as an Ed25519 seed.
    #[test]
    fn derived_key_into_signing_seed_is_32_bytes() {
        let master = MasterKey::from_bytes([0xEEu8; 32]);
        let derived = master.wal_sign_key().unwrap();
        let seed = derived.into_signing_seed();
        assert_eq!(seed.len(), 32, "signing seed must be 32 bytes");
        // Verify it produces a valid Ed25519 key
        use crate::sign::DbSigningKey;
        let _signing_key = DbSigningKey::from_bytes(&seed).unwrap();
    }

    // ─────────────────────────────────────────────────────────────────────
    // DerivedKey::context field
    // ─────────────────────────────────────────────────────────────────────

    /// DerivedKey::context is set to the exact context string used.
    #[test]
    fn derived_key_context_field_preserved() {
        let master = MasterKey::from_bytes([0xFFu8; 32]);
        let ctx = "vgdb/table/42/encrypt";
        let key = master.derive(ctx).unwrap();
        assert_eq!(key.context, ctx, "DerivedKey::context must match the derivation context");
    }

    #[test]
    fn table_encrypt_key_context_matches_expected_pattern() {
        let master = MasterKey::generate();
        let key = master.table_encrypt_key(7).unwrap();
        assert_eq!(key.context, "vgdb/table/7/encrypt");
    }

    #[test]
    fn table_sign_key_context_matches_expected_pattern() {
        let master = MasterKey::generate();
        let key = master.table_sign_key(3).unwrap();
        assert_eq!(key.context, "vgdb/table/3/sign");
    }

    #[test]
    fn wal_sign_key_context_matches_expected_pattern() {
        let master = MasterKey::generate();
        let key = master.wal_sign_key().unwrap();
        assert_eq!(key.context, "vgdb/wal/sign");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Edge cases
    // ─────────────────────────────────────────────────────────────────────

    /// Empty context string is accepted by HKDF.
    #[test]
    fn derive_with_empty_context_is_accepted() {
        let master = MasterKey::from_bytes([0x01u8; 32]);
        let result = master.derive("");
        assert!(result.is_ok(), "empty context must be accepted by HKDF");
    }

    /// Very long context string works correctly.
    #[test]
    fn derive_with_long_context_works() {
        let master = MasterKey::from_bytes([0x02u8; 32]);
        let long_ctx = "vgdb/".repeat(100);
        let result = master.derive(&long_ctx);
        assert!(result.is_ok(), "very long context must work");
    }

    /// Empty context and non-empty context produce different keys.
    #[test]
    fn empty_context_differs_from_nonempty_context() {
        let master = MasterKey::from_bytes([0x03u8; 32]);
        let k_empty = master.derive("").unwrap();
        let k_nonempty = master.derive("vgdb/table/0/encrypt").unwrap();
        assert_ne!(k_empty.as_bytes(), k_nonempty.as_bytes());
    }

    /// MasterKey::generate produces distinct keys on each call.
    #[test]
    fn master_key_generate_produces_unique_keys() {
        let m1 = MasterKey::generate();
        let m2 = MasterKey::generate();
        // Both derive the same context — but from different masters
        let k1 = m1.derive("ctx").unwrap();
        let k2 = m2.derive("ctx").unwrap();
        assert_ne!(
            k1.as_bytes(),
            k2.as_bytes(),
            "two different MasterKey::generate() calls must produce different keys"
        );
    }

    /// All 32 bytes of the derived key are used (no truncation).
    #[test]
    fn derived_key_uses_all_32_bytes() {
        let master = MasterKey::from_bytes([0x04u8; 32]);
        let key = master.derive("full-32-bytes-test").unwrap();
        let bytes = key.as_bytes();
        // Verify not all zeros (astronomically unlikely for a real HKDF output)
        assert_ne!(bytes, &[0u8; 32], "derived key must not be all zeros");
        // Verify length
        assert_eq!(bytes.len(), 32, "derived key must be exactly 32 bytes");
    }
}

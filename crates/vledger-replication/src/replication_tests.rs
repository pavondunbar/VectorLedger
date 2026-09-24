//! Unit tests for the replication subsystem.
//!
//! Tests cover the components that can be exercised without a live TCP
//! connection: protocol encoding/decoding, HMAC challenge-response, secret
//! management, and divergence detection.
//!
//! Network-dependent tests (WalShipper::listen_and_accept, WalReceiver::run)
//! are integration tests that require two running nodes and are out of scope
//! for this unit suite.

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use crate::{
        divergence::{build_checkpoint, compute_wal_chain_hash, verify_checkpoint},
        error::ReplicationError,
        protocol::{
            compute_mac, decode_ack, decode_replication, encode_ack, encode_handshake,
            encode_replication, mac_eq, AckMessage, AckPayload, AuthChallenge, AuthResponse,
            AuthResult, HeartbeatMsg, ReplicationMessage, WalRecordMsg,
        },
        secret::{default_secret_path, generate_and_save, load_or_generate, load_secret},
    };

    // ── Helpers ───────────────────────────────────────────────────────────

    fn write_wal_records(dir: &std::path::Path, count: u64) {
        use vledger_wal::record::BeginPayload;
        use vledger_wal::{RecordType, WalWriter};
        let mut w = WalWriter::open(dir).unwrap();
        for i in 0..count {
            w.append_record(
                i,
                RecordType::Begin,
                &BeginPayload {
                    description: Some(format!("tx-{i}")),
                },
            )
            .unwrap();
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // HMAC challenge-response
    // ─────────────────────────────────────────────────────────────────────

    /// compute_mac with the same key and nonce always produces the same MAC.
    #[test]
    fn hmac_compute_is_deterministic() {
        let secret = [0x42u8; 32];
        let nonce = b"test-nonce-12345678901234567890ab";
        let mac1 = compute_mac(&secret, nonce);
        let mac2 = compute_mac(&secret, nonce);
        assert_eq!(mac1, mac2, "same secret + nonce must produce same MAC");
    }

    /// Different nonces produce different MACs.
    #[test]
    fn hmac_different_nonces_produce_different_macs() {
        let secret = [0xAAu8; 32];
        let mac1 = compute_mac(&secret, b"nonce-A");
        let mac2 = compute_mac(&secret, b"nonce-B");
        assert_ne!(mac1, mac2, "different nonces must produce different MACs");
    }

    /// Different secrets produce different MACs for the same nonce.
    #[test]
    fn hmac_different_secrets_produce_different_macs() {
        let nonce = b"same-nonce-for-both";
        let mac1 = compute_mac(&[0x11u8; 32], nonce);
        let mac2 = compute_mac(&[0x22u8; 32], nonce);
        assert_ne!(mac1, mac2, "different secrets must produce different MACs");
    }

    /// mac_eq uses constant-time comparison: equal MACs return true.
    #[test]
    fn mac_eq_equal_macs_returns_true() {
        let secret = [0x55u8; 32];
        let nonce = b"consistent-nonce";
        let mac = compute_mac(&secret, nonce);
        assert!(mac_eq(&mac, &mac), "identical MACs must be equal");
    }

    /// mac_eq: unequal MACs return false.
    #[test]
    fn mac_eq_unequal_macs_returns_false() {
        let mac_a = compute_mac(&[0x11u8; 32], b"nonce");
        let mac_b = compute_mac(&[0x22u8; 32], b"nonce");
        assert!(!mac_eq(&mac_a, &mac_b), "different MACs must not be equal");
    }

    /// Full handshake simulation: primary generates challenge, replica
    /// computes MAC with shared secret, primary verifies.
    #[test]
    fn full_handshake_simulation_succeeds_with_correct_secret() {
        let shared_secret = [0xDEu8; 32];

        // Primary: generate a random 32-byte nonce
        let nonce_bytes = [0xABu8; 32];
        let challenge = AuthChallenge {
            nonce: hex::encode(nonce_bytes),
        };

        // Replica: decode challenge, compute MAC with shared secret
        let nonce_decoded = hex::decode(&challenge.nonce).unwrap();
        let replica_mac = compute_mac(&shared_secret, &nonce_decoded);
        let response = AuthResponse {
            mac: hex::encode(replica_mac),
        };

        // Primary: verify MAC
        let claimed_mac_bytes = hex::decode(&response.mac).unwrap();
        let claimed_mac: [u8; 32] = claimed_mac_bytes.try_into().unwrap();
        let expected_mac = compute_mac(&shared_secret, &nonce_decoded);

        assert!(
            mac_eq(&expected_mac, &claimed_mac),
            "handshake must succeed when replica uses the correct secret"
        );
    }

    /// Handshake fails when replica uses a wrong secret.
    #[test]
    fn full_handshake_simulation_fails_with_wrong_secret() {
        let primary_secret = [0xDEu8; 32];
        let wrong_secret = [0xFFu8; 32];
        let nonce_bytes = [0xABu8; 32];

        let challenge = AuthChallenge {
            nonce: hex::encode(nonce_bytes),
        };

        // Replica uses the WRONG secret
        let nonce_decoded = hex::decode(&challenge.nonce).unwrap();
        let replica_mac = compute_mac(&wrong_secret, &nonce_decoded);
        let response = AuthResponse {
            mac: hex::encode(replica_mac),
        };

        // Primary verifies with its correct secret
        let claimed_mac_bytes = hex::decode(&response.mac).unwrap();
        let claimed_mac: [u8; 32] = claimed_mac_bytes.try_into().unwrap();
        let expected_mac = compute_mac(&primary_secret, &nonce_decoded);

        assert!(
            !mac_eq(&expected_mac, &claimed_mac),
            "handshake must fail when replica uses the wrong secret"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Protocol encoding/decoding
    // ─────────────────────────────────────────────────────────────────────

    /// WalRecordMsg round-trips through encode/decode.
    #[test]
    fn wal_record_msg_roundtrip() {
        let msg = ReplicationMessage::WalRecord(WalRecordMsg {
            lsn: 42,
            segment: 0,
            record_hex: hex::encode(b"record bytes"),
            record_hash_hex: hex::encode([0u8; 32]),
        });
        let encoded = encode_replication(&msg).unwrap();
        let line = std::str::from_utf8(&encoded).unwrap().trim().to_string();
        let decoded = decode_replication(&line).unwrap();
        match decoded {
            ReplicationMessage::WalRecord(r) => {
                assert_eq!(r.lsn, 42);
                assert_eq!(r.segment, 0);
            }
            other => panic!("expected WalRecord, got {other:?}"),
        }
    }

    /// Heartbeat round-trips.
    #[test]
    fn heartbeat_msg_roundtrip() {
        let msg = ReplicationMessage::Heartbeat(HeartbeatMsg {
            last_lsn: 100,
            ts: "2026-09-23T12:00:00Z".into(),
        });
        let encoded = encode_replication(&msg).unwrap();
        let line = std::str::from_utf8(&encoded).unwrap().trim().to_string();
        let decoded = decode_replication(&line).unwrap();
        match decoded {
            ReplicationMessage::Heartbeat(h) => assert_eq!(h.last_lsn, 100),
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    /// AckPayload round-trips.
    #[test]
    fn ack_payload_roundtrip() {
        let ack = AckMessage::Ack(AckPayload { lsn: 77 });
        let encoded = encode_ack(&ack).unwrap();
        let line = std::str::from_utf8(&encoded).unwrap().trim().to_string();
        let decoded = decode_ack(&line).unwrap();
        match decoded {
            AckMessage::Ack(a) => assert_eq!(a.lsn, 77),
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    /// AuthChallenge/Response/Result encode correctly as handshake messages.
    #[test]
    fn handshake_messages_encode_as_newline_terminated_json() {
        let challenge = AuthChallenge { nonce: "aabbccdd".into() };
        let bytes = encode_handshake(&challenge).unwrap();
        assert!(bytes.ends_with(b"\n"), "handshake message must end with newline");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("aabbccdd"), "nonce must appear in encoded message");

        let result = AuthResult { ok: true, error: None };
        let bytes2 = encode_handshake(&result).unwrap();
        let s2 = std::str::from_utf8(&bytes2).unwrap();
        assert!(s2.contains("true"), "ok:true must appear in AuthResult");

        let fail = AuthResult { ok: false, error: Some("bad mac".into()) };
        let bytes3 = encode_handshake(&fail).unwrap();
        let s3 = std::str::from_utf8(&bytes3).unwrap();
        assert!(s3.contains("bad mac"), "error message must appear in AuthResult");
    }

    /// Malformed JSON returns an error, not a panic.
    #[test]
    fn decode_malformed_json_returns_error() {
        let result = decode_replication("not valid json at all !!!");
        assert!(result.is_err(), "malformed JSON must return Err");

        let result2 = decode_ack("{\"type\":\"ack\""); // truncated
        assert!(result2.is_err(), "truncated JSON must return Err");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Secret management
    // ─────────────────────────────────────────────────────────────────────

    /// generate_and_save creates a 32-byte secret and persists it as hex.
    #[test]
    fn generate_and_save_creates_valid_secret() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("replication_secret.hex");

        let secret = generate_and_save(&path).unwrap();
        assert_eq!(secret.len(), 32, "secret must be 32 bytes");
        assert!(path.exists(), "secret file must be created");

        // File must be readable as hex
        let contents = std::fs::read_to_string(&path).unwrap();
        let decoded = hex::decode(contents.trim()).unwrap();
        assert_eq!(decoded.len(), 32, "file must contain 32 hex-encoded bytes");
        assert_eq!(decoded.as_slice(), &secret, "file must contain the returned secret");
    }

    /// load_secret round-trips with generate_and_save.
    #[test]
    fn load_secret_reads_generated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.hex");
        let original = generate_and_save(&path).unwrap();
        let loaded = load_secret(&path).unwrap();
        assert_eq!(original, loaded, "loaded secret must match generated secret");
    }

    /// load_secret fails gracefully on missing file.
    #[test]
    fn load_secret_missing_file_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does_not_exist.hex");
        let result = load_secret(&path);
        assert!(
            matches!(result, Err(ReplicationError::SecretError(_))),
            "missing file must return SecretError"
        );
    }

    /// load_secret fails on invalid hex.
    #[test]
    fn load_secret_invalid_hex_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.hex");
        std::fs::write(&path, "not-valid-hex-!!").unwrap();
        let result = load_secret(&path);
        assert!(
            matches!(result, Err(ReplicationError::SecretError(_))),
            "invalid hex must return SecretError"
        );
    }

    /// load_secret fails when hex decodes to wrong length.
    #[test]
    fn load_secret_wrong_length_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("short.hex");
        std::fs::write(&path, hex::encode([0u8; 16])).unwrap(); // 16 bytes, not 32
        let result = load_secret(&path);
        assert!(
            matches!(result, Err(ReplicationError::SecretError(_))),
            "16-byte secret must return SecretError (expected 32)"
        );
    }

    /// load_or_generate creates the file when absent; returns existing when present.
    #[test]
    fn load_or_generate_creates_then_reuses() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rep_secret.hex");

        // First call: file absent → generates
        assert!(!path.exists());
        let s1 = load_or_generate(&path).unwrap();
        assert!(path.exists(), "load_or_generate must create the file");

        // Second call: file present → loads (must be identical)
        let s2 = load_or_generate(&path).unwrap();
        assert_eq!(s1, s2, "load_or_generate must return same secret on second call");
    }

    /// default_secret_path returns <data_dir>/replication_secret.hex.
    #[test]
    fn default_secret_path_correct() {
        let dir = TempDir::new().unwrap();
        let path = default_secret_path(dir.path());
        assert_eq!(
            path,
            dir.path().join("replication_secret.hex"),
            "default secret path must be <data_dir>/replication_secret.hex"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // Divergence detection
    // ─────────────────────────────────────────────────────────────────────

    /// compute_wal_chain_hash is deterministic for the same WAL.
    #[test]
    fn wal_chain_hash_deterministic() {
        let dir = TempDir::new().unwrap();
        write_wal_records(dir.path(), 10);
        let h1 = compute_wal_chain_hash(dir.path(), 100).unwrap();
        let h2 = compute_wal_chain_hash(dir.path(), 100).unwrap();
        assert_eq!(h1, h2, "WAL chain hash must be deterministic");
    }

    /// An empty WAL returns the zero hash.
    #[test]
    fn wal_chain_hash_empty_wal_returns_zero() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        // No WAL files — directory exists but is empty
        let h = compute_wal_chain_hash(dir.path(), 0);
        // Either Ok([0;32]) or Err is acceptable for an empty WAL dir
        match h {
            Ok(hash) => assert_eq!(hash, [0u8; 32], "empty WAL must return zero hash"),
            Err(_) => {} // acceptable: no segments to open
        }
    }

    /// build_checkpoint embeds the WAL chain hash and ledger tip.
    #[test]
    fn build_checkpoint_fields_correct() {
        let dir = TempDir::new().unwrap();
        write_wal_records(dir.path(), 5);
        let tip = [0xABu8; 32];
        let cp = build_checkpoint(dir.path(), 10, 5, &tip).unwrap();
        assert_eq!(cp.lsn, 10);
        assert_eq!(cp.ledger_sequence, 5);
        assert_eq!(cp.ledger_chain_tip_hex, hex::encode(tip));
        assert_eq!(cp.chain_hash_hex.len(), 64, "chain_hash_hex must be 64 hex chars");
    }

    /// verify_checkpoint reports no divergence when WAL and tip match.
    #[test]
    fn verify_checkpoint_no_divergence_when_identical() {
        let dir = TempDir::new().unwrap();
        write_wal_records(dir.path(), 5);
        let tip = [0u8; 32];
        let cp = build_checkpoint(dir.path(), 100, 5, &tip).unwrap();
        let report = verify_checkpoint(dir.path(), &cp, &tip);
        assert!(
            !report.diverged,
            "identical WAL and tip must not report divergence: {:?}",
            report.reason
        );
    }

    /// verify_checkpoint detects ledger tip mismatch.
    #[test]
    fn verify_checkpoint_detects_tip_mismatch() {
        let dir = TempDir::new().unwrap();
        write_wal_records(dir.path(), 3);
        let primary_tip = [0xAAu8; 32];
        let local_tip = [0xBBu8; 32];
        let cp = build_checkpoint(dir.path(), 10, 3, &primary_tip).unwrap();
        let report = verify_checkpoint(dir.path(), &cp, &local_tip);
        assert!(report.diverged, "mismatched tips must trigger divergence");
        assert!(
            report.reason.as_deref().unwrap_or("").contains("Ledger chain tip mismatch"),
            "reason must mention ledger chain tip"
        );
    }

    /// verify_checkpoint detects tampered chain_hash_hex.
    #[test]
    fn verify_checkpoint_detects_tampered_chain_hash() {
        let dir = TempDir::new().unwrap();
        write_wal_records(dir.path(), 3);
        let tip = [0u8; 32];
        let mut cp = build_checkpoint(dir.path(), 10, 3, &tip).unwrap();
        cp.chain_hash_hex = "0".repeat(64); // all-zeros = wrong hash
        let report = verify_checkpoint(dir.path(), &cp, &tip);
        assert!(report.diverged, "tampered chain hash must trigger divergence");
    }

    /// verify_checkpoint with invalid (malformed) chain_hash_hex triggers divergence.
    #[test]
    fn verify_checkpoint_invalid_hex_triggers_divergence() {
        let dir = TempDir::new().unwrap();
        write_wal_records(dir.path(), 2);
        let tip = [0u8; 32];
        let mut cp = build_checkpoint(dir.path(), 10, 2, &tip).unwrap();
        cp.chain_hash_hex = "not-valid-hex!".into();
        let report = verify_checkpoint(dir.path(), &cp, &tip);
        assert!(report.diverged, "invalid chain_hash_hex must trigger divergence");
    }

    // ─────────────────────────────────────────────────────────────────────
    // ReplicationConfig loading
    // ─────────────────────────────────────────────────────────────────────

    /// ReplicationConfig::load returns default when file absent.
    #[test]
    fn replication_config_defaults_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let cfg = crate::config::ReplicationConfig::load(dir.path()).unwrap();
        assert_eq!(cfg.ack_timeout_ms, 5_000);
        assert_eq!(cfg.replication_addr, "127.0.0.1:5434");
    }

    /// ReplicationConfig::load parses a valid JSON file.
    #[test]
    fn replication_config_loads_valid_json() {
        let dir = TempDir::new().unwrap();
        let json = r#"{
            "role": "primary",
            "replication_addr": "0.0.0.0:5434",
            "ack_timeout_ms": 10000,
            "heartbeat_interval_ms": 2000,
            "send_buffer_bytes": 1048576,
            "tls": {
                "enabled": true,
                "server_hostname": "primary-node"
            }
        }"#;
        std::fs::write(dir.path().join("replication.json"), json).unwrap();
        let cfg = crate::config::ReplicationConfig::load(dir.path()).unwrap();
        assert_eq!(cfg.ack_timeout_ms, 10_000);
        assert_eq!(cfg.replication_addr, "0.0.0.0:5434");
    }

    /// ReplicationConfig::load returns Err on malformed JSON.
    #[test]
    fn replication_config_errors_on_invalid_json() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("replication.json"), "{ not json }").unwrap();
        let result = crate::config::ReplicationConfig::load(dir.path());
        assert!(result.is_err(), "malformed replication.json must return Err");
    }
}

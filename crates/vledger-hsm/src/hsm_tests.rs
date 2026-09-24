//! Unit tests for the HSM client interface.
//!
//! These tests cover the offline-testable surface of vledger-hsm:
//! - HsmTransport construction and description
//! - HsmClient static helpers (key ID generation)
//! - KeyPolicy constructors
//! - RemotePyHsmConfig parsing and validation
//! - HsmError display (important for operator-facing messages)
//! - SoftHsmProvider construction (does not require a live socket)
//! - HsmClient::is_available() — must return false with no live socket
//! - HsmProviderConfig::build_provider selects the correct backend
//!
//! Tests that require a live PyHSM socket are integration tests out of scope
//! for this unit suite.

#[cfg(test)]
mod tests {
    use crate::{
        client::{default_pyhsm_address, HsmClient},
        error::HsmError,
        pkcs11::{
            AwsCloudHsmConfig, AwsCloudHsmProvider, AzureHsmConfig, AzureHsmProvider,
            HsmProviderConfig, SoftHsmProvider,
        },
        protocol::KeyPolicy,
        remote::{HsmTransport, RemotePyHsmConfig},
    };

    // ─────────────────────────────────────────────────────────────────────
    // HsmTransport
    // ─────────────────────────────────────────────────────────────────────

    /// HsmTransport::from_address identifies socket paths vs TCP addresses.
    #[test]
    fn transport_from_address_unix_socket() {
        let t = HsmTransport::from_address("/tmp/pyhsm.sock");
        let desc = t.description();
        assert!(
            desc.contains("pyhsm.sock") || desc.contains("socket") || desc.contains("/tmp"),
            "socket transport description must reference the path: {desc}"
        );
    }

    #[test]
    fn transport_from_address_tcp() {
        let t = HsmTransport::from_address("127.0.0.1:7777");
        let desc = t.description();
        assert!(
            desc.contains("127.0.0.1") || desc.contains("7777") || desc.contains("tcp"),
            "TCP transport description must reference the address: {desc}"
        );
    }

    /// HsmTransport::description returns a non-empty string for all variants.
    #[test]
    fn transport_description_non_empty_for_all_variants() {
        let local = HsmTransport::from_address("/tmp/pyhsm.sock");
        assert!(!local.description().is_empty());

        let tcp = HsmTransport::from_address("127.0.0.1:7777");
        assert!(!tcp.description().is_empty());

        let remote = HsmTransport::remote(RemotePyHsmConfig {
            endpoint: "https://hsm.example.com:443".into(),
            ca_cert: "/etc/ssl/ca.crt".into(),
            client_cert: None,
            client_key: None,
            timeout_ms: 5000,
            max_retries: 3,
        });
        assert!(!remote.description().is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────
    // HsmClient static helpers
    // ─────────────────────────────────────────────────────────────────────

    /// table_encrypt_key_id returns a stable, non-empty string.
    #[test]
    fn table_encrypt_key_id_format() {
        let id0 = HsmClient::table_encrypt_key_id(0);
        let id1 = HsmClient::table_encrypt_key_id(1);
        let id42 = HsmClient::table_encrypt_key_id(42);

        assert!(!id0.is_empty(), "key ID must not be empty");
        assert_ne!(id0, id1, "different table IDs must produce different key IDs");
        assert!(
            id42.contains("42"),
            "key ID must embed the table ID: {id42}"
        );
    }

    /// wal_signing_key_id and commit_signing_key_id return distinct strings.
    #[test]
    fn signing_key_ids_are_distinct() {
        let wal_id = HsmClient::wal_signing_key_id();
        let commit_id = HsmClient::commit_signing_key_id();
        assert!(!wal_id.is_empty());
        assert!(!commit_id.is_empty());
        assert_ne!(wal_id, commit_id, "WAL and commit signing key IDs must differ");
    }

    /// default_pyhsm_address is not empty.
    #[test]
    fn default_pyhsm_address_non_empty() {
        let addr = default_pyhsm_address();
        assert!(!addr.is_empty(), "default pyhsm address must not be empty");
    }

    /// HsmClient::transport_description reflects the configured transport.
    #[test]
    fn hsm_client_transport_description_reflects_address() {
        let client = HsmClient::new("/tmp/pyhsm.sock", "test-caller");
        let desc = client.transport_description();
        assert!(!desc.is_empty(), "transport description must not be empty");
    }

    // ─────────────────────────────────────────────────────────────────────
    // HsmClient::is_available (no live socket — must return false)
    // ─────────────────────────────────────────────────────────────────────

    /// is_available returns false when no PyHSM daemon is listening.
    #[tokio::test]
    async fn is_available_false_without_live_socket() {
        let client = HsmClient::new("/tmp/__no_such_pyhsm_socket_vledger_test__.sock", "test");
        assert!(
            !client.is_available().await,
            "is_available must return false when no socket exists"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // KeyPolicy
    // ─────────────────────────────────────────────────────────────────────

    /// KeyPolicy::encrypt_decrypt enables both operations.
    #[test]
    fn key_policy_encrypt_decrypt_enables_both() {
        let policy = KeyPolicy::encrypt_decrypt();
        assert!(policy.allow_encrypt, "encrypt_decrypt policy must allow encryption");
        assert!(policy.allow_decrypt, "encrypt_decrypt policy must allow decryption");
    }

    /// KeyPolicy::sign_only disables encrypt/decrypt.
    #[test]
    fn key_policy_sign_only_disables_encrypt_decrypt() {
        let policy = KeyPolicy::sign_only();
        assert!(
            !policy.allow_encrypt,
            "sign_only policy must not allow encryption"
        );
        assert!(
            !policy.allow_decrypt,
            "sign_only policy must not allow decryption"
        );
        assert_eq!(
            policy.allow_sign,
            Some(true),
            "sign_only policy must allow signing"
        );
    }

    /// KeyPolicy serialises and deserialises correctly.
    #[test]
    fn key_policy_roundtrip_serde() {
        let policy = KeyPolicy {
            allow_encrypt: true,
            allow_decrypt: false,
            allow_sign: Some(true),
            max_operations: Some(1_000),
            expires_at: Some("2027-12-31".into()),
            allowed_callers: Some(vec!["vledger".into()]),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: KeyPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.allow_encrypt, true);
        assert_eq!(decoded.allow_decrypt, false);
        assert_eq!(decoded.max_operations, Some(1_000));
        assert_eq!(decoded.expires_at.as_deref(), Some("2027-12-31"));
    }

    // ─────────────────────────────────────────────────────────────────────
    // RemotePyHsmConfig
    // ─────────────────────────────────────────────────────────────────────

    /// RemotePyHsmConfig::host_port parses valid endpoint.
    #[test]
    fn remote_config_host_port_valid() {
        let cfg = RemotePyHsmConfig {
            endpoint: "https://hsm.internal:8443".into(),
            ca_cert: "/certs/ca.crt".into(),
            client_cert: None,
            client_key: None,
            timeout_ms: 5000,
            max_retries: 3,
        };
        let (host, port) = cfg.host_port().unwrap();
        assert_eq!(host, "hsm.internal");
        assert_eq!(port, 8443);
    }

    /// RemotePyHsmConfig::host_port returns error on malformed endpoint.
    #[test]
    fn remote_config_host_port_malformed() {
        let cfg = RemotePyHsmConfig {
            endpoint: "not-a-url".into(),
            ca_cert: "/certs/ca.crt".into(),
            client_cert: None,
            client_key: None,
            timeout_ms: 5000,
            max_retries: 3,
        };
        assert!(cfg.host_port().is_err(), "malformed endpoint must return error");
    }

    // ─────────────────────────────────────────────────────────────────────
    // HsmError display
    // ─────────────────────────────────────────────────────────────────────

    /// HsmError variants display non-empty operator-friendly messages.
    #[test]
    fn hsm_errors_display_non_empty_messages() {
        let errors = vec![
            HsmError::Ipc("ipc error".into()),
            HsmError::Remote("remote error".into()),
            HsmError::SocketNotFound { path: "/tmp/pyhsm.sock".into() },
            HsmError::Timeout { ms: 5000 },
            HsmError::KeyNotFound("my-key".into()),
            HsmError::PolicyViolation("encrypt not allowed".into()),
            HsmError::CryptoFailed("bad signature".into()),
            HsmError::Config("bad config".into()),
        ];
        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "HsmError display must not be empty: {err:?}");
        }
    }

    /// SocketNotFound error message includes the path.
    #[test]
    fn socket_not_found_message_includes_path() {
        let err = HsmError::SocketNotFound { path: "/var/run/pyhsm.sock".into() };
        assert!(
            err.to_string().contains("/var/run/pyhsm.sock"),
            "SocketNotFound message must include the socket path"
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    // HsmProviderConfig
    // ─────────────────────────────────────────────────────────────────────

    /// HsmProviderConfig::build_provider returns a usable provider object.
    #[test]
    fn hsm_provider_config_soft_builds_provider() {
        let cfg = HsmProviderConfig::Soft { socket_path: None };
        let _provider = cfg.build_provider();
        // If this compiles and doesn't panic, the factory works.
    }

    #[test]
    fn hsm_provider_config_aws_builds_provider() {
        let cfg = HsmProviderConfig::AwsCloudHsm(AwsCloudHsmConfig {
            bridge_socket: "/tmp/aws_bridge.sock".into(),
            cluster_id: "cluster-001".into(),
            crypto_user: "vledger-user".into(),
            verify_bridge_tls: false,
        });
        let _provider = cfg.build_provider();
    }

    #[test]
    fn hsm_provider_config_azure_builds_provider() {
        let cfg = HsmProviderConfig::AzureDedicatedHsm(AzureHsmConfig {
            bridge_socket: "/tmp/azure_bridge.sock".into(),
            resource_group: "vledger-rg".into(),
            device_host: "hsm.azure.example.com".into(),
            partition: "partition-1".into(),
        });
        let _provider = cfg.build_provider();
    }

    /// HsmProviderConfig serialises and deserialises correctly.
    #[test]
    fn hsm_provider_config_serde_roundtrip() {
        let cfg = HsmProviderConfig::Soft { socket_path: Some("/tmp/pyhsm.sock".into()) };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: HsmProviderConfig = serde_json::from_str(&json).unwrap();
        match back {
            HsmProviderConfig::Soft { socket_path } => {
                assert_eq!(socket_path.as_deref(), Some("/tmp/pyhsm.sock"));
            }
            other => panic!("expected Soft variant, got {other:?}"),
        }
    }
}

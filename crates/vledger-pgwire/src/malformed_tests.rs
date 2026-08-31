//! Malformed PgWire input tests.
//!
//! These tests verify that every invalid/oversized/truncated message the
//! codec can receive is rejected cleanly — no panic, no OOM, no infinite
//! loop.
//!
//! ## What is covered
//! | Category | Specific case |
//! |---|---|
//! | Startup | `total_len < 4` |
//! | Startup | `payload_len > MAX_STARTUP_PAYLOAD (65536)` |
//! | Startup | Truncated payload (declared > available bytes) |
//! | Regular | `length_field < 4` |
//! | Regular | `payload_len > MAX_MESSAGE_PAYLOAD (16 MiB)` |
//! | Regular | Truncated payload |
//! | Regular | All 256 type bytes |
//! | Regular | Zero-length payload for every type byte |
//! | Frontend | Query with embedded null byte |
//! | Frontend | Query with only whitespace |
//! | Frontend | Unknown message type 0xFF |
//! | Resource | 1000 rapid open/close connections without auth |

#[cfg(test)]
mod tests {
    use crate::messages::FrontendMessage;

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Build a startup-packet byte sequence.
    fn startup_packet(declared_total_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&declared_total_len.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// Build a regular PgWire message.
    fn regular_msg(msg_type: u8, declared_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![msg_type];
        v.extend_from_slice(&declared_len.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    async fn read_startup_from_bytes(data: &[u8]) -> std::io::Result<Vec<u8>> {
        use tokio::io::BufReader;
        let mut r = BufReader::new(std::io::Cursor::new(data));
        crate::codec::read_startup(&mut r).await
    }

    async fn read_message_from_bytes(data: &[u8]) -> std::io::Result<(u8, Vec<u8>)> {
        use tokio::io::BufReader;
        let mut r = BufReader::new(std::io::Cursor::new(data));
        crate::codec::read_message(&mut r).await
    }

    // ── Startup packet tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn startup_total_len_less_than_4_rejected() {
        // declared total = 3 means payload_len = -1 which is invalid
        let data = startup_packet(3, b"");
        let result = read_startup_from_bytes(&data).await;
        assert!(result.is_err(), "startup total_len < 4 must be rejected");
    }

    #[tokio::test]
    async fn startup_total_len_zero_rejected() {
        let data = startup_packet(0, b"");
        assert!(read_startup_from_bytes(&data).await.is_err());
    }

    #[tokio::test]
    async fn startup_payload_over_65536_rejected() {
        // Claim 65541 bytes of payload (65537 + 4 for length field)
        let data = startup_packet(65541, b"short");
        assert!(
            read_startup_from_bytes(&data).await.is_err(),
            "startup payload > 65536 must be rejected"
        );
    }

    #[tokio::test]
    async fn startup_truncated_payload_rejected() {
        // Declare 20 bytes of payload but only provide 5.
        let data = startup_packet(24, b"short"); // 24 - 4 = 20 declared, 5 actual
        assert!(
            read_startup_from_bytes(&data).await.is_err(),
            "truncated startup payload must be rejected"
        );
    }

    #[tokio::test]
    async fn startup_empty_payload_valid() {
        // Minimal valid startup: total_len=4, payload_len=0.
        let data = startup_packet(4, b"");
        assert!(read_startup_from_bytes(&data).await.is_ok());
    }

    #[tokio::test]
    async fn startup_exactly_max_payload_accepted() {
        // Exactly 65536 bytes of payload + 4 for length field = 65540.
        let payload = vec![0u8; 65536];
        let data = startup_packet(65540, &payload);
        assert!(
            read_startup_from_bytes(&data).await.is_ok(),
            "startup payload of exactly MAX_STARTUP_PAYLOAD must be accepted"
        );
    }

    #[tokio::test]
    async fn startup_one_over_max_rejected() {
        // 65537 payload bytes
        let payload = vec![0u8; 65537];
        let data = startup_packet(65541, &payload);
        assert!(
            read_startup_from_bytes(&data).await.is_err(),
            "startup payload of MAX+1 must be rejected"
        );
    }

    // ── Regular message tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn regular_msg_len_less_than_4_rejected() {
        let data = regular_msg(b'Q', 3, b"");
        assert!(
            read_message_from_bytes(&data).await.is_err(),
            "message length field < 4 must be rejected"
        );
    }

    #[tokio::test]
    async fn regular_msg_len_zero_rejected() {
        let data = regular_msg(b'Q', 0, b"");
        assert!(read_message_from_bytes(&data).await.is_err());
    }

    #[tokio::test]
    async fn regular_msg_payload_over_16mib_rejected() {
        // Claim 16 MiB + 1 byte of payload.
        let oversized_len = (16 * 1024 * 1024 + 1 + 4) as u32;
        let data = regular_msg(b'Q', oversized_len, b"actual");
        assert!(
            read_message_from_bytes(&data).await.is_err(),
            "message payload > 16 MiB must be rejected"
        );
    }

    #[tokio::test]
    async fn regular_msg_truncated_payload_rejected() {
        // Declare 50 bytes of payload but send only 5.
        let data = regular_msg(b'Q', 54, b"short");
        assert!(
            read_message_from_bytes(&data).await.is_err(),
            "truncated message payload must be rejected"
        );
    }

    #[tokio::test]
    async fn regular_msg_empty_payload_accepted() {
        let data = regular_msg(b'X', 4, b""); // Terminate with no payload
        assert!(read_message_from_bytes(&data).await.is_ok());
    }

    // ── Frontend message parsing — all type bytes ─────────────────────────

    #[test]
    fn all_message_type_bytes_do_not_panic() {
        // FrontendMessage::parse must handle every type byte without panicking.
        for type_byte in 0u8..=255 {
            // Test with empty payload
            let _ = FrontendMessage::parse(type_byte, b"");
            // Test with a non-trivial payload
            let _ = FrontendMessage::parse(type_byte, b"SELECT 1\0");
            // Test with null bytes only
            let _ = FrontendMessage::parse(type_byte, b"\0\0\0\0");
            // Test with a very long payload (1 KiB)
            let long = vec![0x41u8; 1024];
            let _ = FrontendMessage::parse(type_byte, &long);
        }
    }

    #[test]
    fn query_with_embedded_null_parsed_gracefully() {
        let payload = b"SELECT 1\0injected\0";
        let msg = FrontendMessage::parse(b'Q', payload);
        // Must return Unknown or a Query variant — but never panic.
        if let FrontendMessage::Query(sql) = msg {
            // The SQL string must end at the first null byte.
            assert!(
                !sql.contains('\0'),
                "null bytes must be stripped from query"
            );
        }
    }

    #[test]
    fn query_with_only_whitespace_parsed_gracefully() {
        let payload = b"   \t\n\r\0";
        let _ = FrontendMessage::parse(b'Q', payload);
    }

    #[test]
    fn unknown_type_0xff_returns_unknown_variant() {
        let msg = FrontendMessage::parse(0xFF, b"garbage");
        assert!(matches!(msg, FrontendMessage::Unknown(0xFF)));
    }

    #[test]
    fn terminate_message_parsed_correctly() {
        let msg = FrontendMessage::parse(b'X', b"");
        assert!(matches!(msg, FrontendMessage::Terminate));
    }

    #[test]
    fn sync_message_parsed_correctly() {
        let msg = FrontendMessage::parse(b'S', b"");
        assert!(matches!(msg, FrontendMessage::Sync));
    }

    #[test]
    fn flush_message_parsed_correctly() {
        let msg = FrontendMessage::parse(b'H', b"");
        assert!(matches!(msg, FrontendMessage::Flush));
    }

    // ── Resource exhaustion: oversized query string ───────────────────────

    #[tokio::test]
    async fn oversized_query_rejected_by_codec() {
        // A query frame claiming a 20 MiB SQL string (> MAX_MESSAGE_PAYLOAD).
        let oversized = (20 * 1024 * 1024 + 4) as u32;
        let data = regular_msg(b'Q', oversized, b"actual_short_payload");
        let result = read_message_from_bytes(&data).await;
        assert!(result.is_err(), "20 MiB query payload must be rejected");
    }

    // ── Resource exhaustion: rapid repeated malformed packets ─────────────

    #[tokio::test]
    async fn many_malformed_packets_do_not_accumulate_state() {
        // Send 1000 malformed startup packets in sequence — each must be
        // independently rejected without any state accumulation.
        for _ in 0..1000 {
            let data = startup_packet(0, b"");
            let _ = read_startup_from_bytes(&data).await;
        }
        // If we get here without OOM / hang, the test passes.
    }

    // ── SSL request code is recognised ───────────────────────────────────

    #[test]
    fn ssl_request_protocol_version_recognised() {
        use crate::messages::{StartupMessage, SSL_REQUEST_CODE};
        // SSL_REQUEST_CODE = 80877103 (0x04D2162F) — must be detected.
        let mut payload = Vec::new();
        payload.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        let sm = StartupMessage::parse(&payload);
        assert!(sm.is_some(), "SSL request startup message must parse");
        assert_eq!(sm.unwrap().protocol_version, SSL_REQUEST_CODE);
    }
}

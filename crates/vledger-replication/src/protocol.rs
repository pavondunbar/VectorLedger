//! Replication wire protocol — newline-delimited JSON messages.
//!
//! All messages are framed as a single JSON object followed by `\n`.
//!
//! ## Authentication handshake (Fix #9)
//!
//! Before any WAL records are exchanged the primary and replica perform a
//! challenge-response handshake using a shared 32-byte secret.  The secret
//! is stored on disk at the path configured in `ReplicationConfig::secret_path`
//! (default `vledger-data/replication_secret.hex`, mode 0o600).
//!
//! ```text
//! Primary → Replica : AuthChallenge { nonce: "<32-byte hex>" }
//! Replica → Primary : AuthResponse  { mac:   "<32-byte hex>" }
//! Primary → Replica : AuthResult    { ok: true }          (or closes conn)
//! ```
//!
//! `mac = BLAKE3-keyed(key=secret, data=nonce_bytes)`.
//!
//! The MAC is computed with `blake3::Hasher::new_keyed` so the secret is
//! the BLAKE3 key material — never transmitted.

use serde::{Deserialize, Serialize};

// ── LSN type ──────────────────────────────────────────────────────────────────

/// Log Sequence Number — monotonically increasing identifier for a WAL record.
pub type Lsn = u64;

// ── Handshake messages (Fix #9) ───────────────────────────────────────────────

/// Sent by the primary immediately after TCP accept.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthChallenge {
    /// 32 random bytes, hex-encoded.
    pub nonce: String,
}

/// Sent by the replica in response to `AuthChallenge`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    /// `BLAKE3-keyed(key=secret, data=nonce_bytes)`, hex-encoded (32 bytes).
    pub mac: String,
}

/// Sent by the primary after verifying the MAC.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResult {
    pub ok: bool,
    /// Human-readable reason on failure.
    pub error: Option<String>,
}

// ── Compute and verify MACs ───────────────────────────────────────────────────

/// Compute `BLAKE3-keyed(key=secret, data=nonce)`.
pub fn compute_mac(secret: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// Constant-time comparison of two 32-byte arrays to resist timing attacks.
pub fn mac_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // XOR all bytes and OR the results — constant time regardless of where
    // the first difference occurs.
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Replication messages ──────────────────────────────────────────────────────

/// Messages sent from primary → replica after authentication.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReplicationMessage {
    WalRecord(WalRecordMsg),
    Heartbeat(HeartbeatMsg),
}

/// WAL record payload shipped from primary → replica.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecordMsg {
    pub lsn: Lsn,
    pub segment: u64,
    pub record_hex: String,
    pub record_hash_hex: String,
}

/// Heartbeat from primary to replica.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMsg {
    pub last_lsn: Lsn,
    pub ts: String,
}

// ── Acknowledgement (replica → primary) ──────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AckMessage {
    Ack(AckPayload),
    HeartbeatAck(HeartbeatAckPayload),
    Error(ReplicaError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckPayload {
    pub lsn: Lsn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatAckPayload {
    pub last_lsn: Lsn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaError {
    pub lsn: Option<Lsn>,
    pub message: String,
}

// ── Wire encoding helpers ─────────────────────────────────────────────────────

pub fn encode_replication(msg: &ReplicationMessage) -> Result<Vec<u8>, serde_json::Error> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s.into_bytes())
}

pub fn encode_ack(msg: &AckMessage) -> Result<Vec<u8>, serde_json::Error> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s.into_bytes())
}

pub fn decode_replication(line: &str) -> Result<ReplicationMessage, serde_json::Error> {
    serde_json::from_str(line.trim())
}

pub fn decode_ack(line: &str) -> Result<AckMessage, serde_json::Error> {
    serde_json::from_str(line.trim())
}

/// Encode a handshake message to a newline-terminated JSON line.
pub fn encode_handshake<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s.into_bytes())
}

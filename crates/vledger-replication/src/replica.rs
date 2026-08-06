//! Replica-side WAL receiver with TLS encryption and HMAC handshake.
//!
//! ## Security (Tasks #1, #2, Fix #9)
//! 1. Connects to the primary over TLS 1.3 (Task #1).
//! 2. Optionally presents a client certificate for mTLS (Task #2).
//! 3. Performs BLAKE3-keyed HMAC challenge-response inside TLS (Fix #9).

use std::path::PathBuf;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::{debug, error, info};

use crate::config::ReplicationConfig;
use crate::error::ReplicationError;
use crate::protocol::{
    self, AckMessage, AckPayload, AuthChallenge, AuthResponse, AuthResult,
    HeartbeatAckPayload, ReplicationMessage, Lsn, compute_mac, encode_handshake,
};
use crate::secret;
use crate::tls as repl_tls;

// ── WalReceiver ───────────────────────────────────────────────────────────────

pub struct WalReceiver {
    config:  ReplicationConfig,
    secret:  [u8; 32],
    wal_dir: PathBuf,
}

impl WalReceiver {
    /// Create a new `WalReceiver`.  The replication secret must already exist
    /// on the replica (`secret::load_secret` — not generated here).
    pub fn new(
        config:   ReplicationConfig,
        wal_dir:  PathBuf,
        data_dir: &std::path::Path,
    ) -> Result<Self, ReplicationError> {
        let secret_path = config.secret_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| secret::default_secret_path(data_dir));

        let secret = secret::load_secret(&secret_path)?;
        Ok(Self { config, secret, wal_dir })
    }

    /// Connect to the primary and stream WAL records.
    /// Reconnects with exponential back-off on any error.
    pub async fn run(&self) -> Result<(), ReplicationError> {
        let mut backoff_ms = 500u64;
        loop {
            match self.connect_and_stream().await {
                Ok(()) => {
                    info!("Replication stream ended cleanly, reconnecting...");
                    backoff_ms = 500;
                }
                Err(ReplicationError::AuthFailed(ref e)) => {
                    error!("Replication auth failed: {e}. Backing off {backoff_ms}ms...");
                    backoff_ms = (backoff_ms * 4).min(60_000);
                }
                Err(e) => {
                    error!("Replication error: {e}. Reconnecting in {backoff_ms}ms...");
                    backoff_ms = (backoff_ms * 2).min(30_000);
                }
            }
            sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    async fn connect_and_stream(&self) -> Result<(), ReplicationError> {
        info!(primary = %self.config.replication_addr, "Connecting to primary");

        let tcp = TcpStream::connect(&self.config.replication_addr)
            .await
            .map_err(|e| ReplicationError::ConnectionRefused(e.to_string()))?;

        // ── Task #1: wrap in TLS ──────────────────────────────────────────
        let connector = repl_tls::build_connector(&self.config.tls)?;

        // SNI name — use the server_hostname from config (matches the cert CN).
        let server_name = ServerName::try_from(self.config.tls.server_hostname.clone())
            .map_err(|e| ReplicationError::Tls(format!("invalid server hostname: {e}")))?;

        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| ReplicationError::Tls(format!("TLS connect failed: {e}")))?;

        info!(primary = %self.config.replication_addr, "TLS handshake complete");

        let (r, mut w) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(r);

        // ── Fix #9: HMAC challenge-response inside TLS ────────────────────
        self.perform_handshake(&mut reader, &mut w).await?;
        info!(primary = %self.config.replication_addr, "Replication authenticated");

        // ── WAL receive loop ──────────────────────────────────────────────
        let applier = ReplicaApplier::new(self.wal_dir.clone());
        let mut last_lsn: Lsn = 0;

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Err(e) => return Err(e.into()),
                Ok(0)  => return Err(ReplicationError::StreamEnded),
                Ok(_)  => {}
            }

            let msg = protocol::decode_replication(&line)
                .map_err(|e| ReplicationError::Serialisation(e.to_string()))?;

            match msg {
                ReplicationMessage::WalRecord(rec) => {
                    debug!(lsn = rec.lsn, "Replica received WAL record");

                    let record_bytes = hex::decode(&rec.record_hex)
                        .map_err(|e| ReplicationError::InvalidRecord(e.to_string()))?;

                    let expected_hash = hex::encode(blake3::hash(&record_bytes).as_bytes());
                    if expected_hash != rec.record_hash_hex {
                        let ack = AckMessage::Error(crate::protocol::ReplicaError {
                            lsn:     Some(rec.lsn),
                            message: "hash mismatch on received WAL record".into(),
                        });
                        if let Ok(wire) = protocol::encode_ack(&ack) {
                            let _ = w.write_all(&wire).await;
                        }
                        return Err(ReplicationError::InvalidRecord(
                            format!("hash mismatch at lsn {}", rec.lsn)
                        ));
                    }

                    applier.apply(&record_bytes, rec.segment).await?;
                    last_lsn = rec.lsn;

                    let ack  = AckMessage::Ack(AckPayload { lsn: rec.lsn });
                    let wire = protocol::encode_ack(&ack)
                        .map_err(|e| ReplicationError::Serialisation(e.to_string()))?;
                    w.write_all(&wire).await?;
                    w.flush().await?;
                    debug!(lsn = rec.lsn, "Replica sent ACK");
                }

                ReplicationMessage::Heartbeat(hb) => {
                    debug!(last_lsn = hb.last_lsn, "Replica received heartbeat");
                    let ack  = AckMessage::HeartbeatAck(HeartbeatAckPayload { last_lsn });
                    let wire = protocol::encode_ack(&ack)
                        .map_err(|e| ReplicationError::Serialisation(e.to_string()))?;
                    let _ = w.write_all(&wire).await;
                    let _ = w.flush().await;
                }
            }
        }
    }

    async fn perform_handshake<R, W>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut W,
    ) -> Result<(), ReplicationError>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        // Read challenge.
        let mut line = String::new();
        let n = reader.read_line(&mut line).await
            .map_err(|e| ReplicationError::AuthFailed(format!("read challenge: {e}")))?;
        if n == 0 {
            return Err(ReplicationError::AuthFailed("primary closed during handshake".into()));
        }

        let challenge: AuthChallenge = serde_json::from_str(line.trim())
            .map_err(|e| ReplicationError::AuthFailed(format!("parse challenge: {e}")))?;

        let nonce = hex::decode(&challenge.nonce)
            .map_err(|e| ReplicationError::AuthFailed(format!("invalid nonce hex: {e}")))?;

        let mac = compute_mac(&self.secret, &nonce);
        let response = AuthResponse { mac: hex::encode(mac) };
        let wire = encode_handshake(&response)
            .map_err(|e| ReplicationError::Serialisation(e.to_string()))?;
        writer.write_all(&wire).await
            .map_err(|e| ReplicationError::AuthFailed(format!("write response: {e}")))?;
        let _ = writer.flush().await;

        // Read result.
        let mut line = String::new();
        let n = reader.read_line(&mut line).await
            .map_err(|e| ReplicationError::AuthFailed(format!("read auth result: {e}")))?;
        if n == 0 {
            return Err(ReplicationError::AuthFailed("primary closed after MAC".into()));
        }

        let result: AuthResult = serde_json::from_str(line.trim())
            .map_err(|e| ReplicationError::AuthFailed(format!("parse auth result: {e}")))?;

        if !result.ok {
            return Err(ReplicationError::AuthFailed(
                result.error.unwrap_or_else(|| "rejected by primary".into())
            ));
        }

        Ok(())
    }
}

// ── ReplicaApplier ────────────────────────────────────────────────────────────

pub struct ReplicaApplier {
    wal_dir: PathBuf,
}

impl ReplicaApplier {
    pub fn new(wal_dir: PathBuf) -> Self { Self { wal_dir } }

    pub async fn apply(&self, record_bytes: &[u8], segment: u64) -> Result<(), ReplicationError> {
        let seg_path = self.wal_dir.join(format!("{segment:020}.wal"));
        tokio::fs::create_dir_all(&self.wal_dir).await?;

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true).append(true).open(&seg_path)?;
        file.write_all(record_bytes)?;
        file.flush()?;
        file.sync_all()?;

        debug!(segment, "Replica applied WAL record");
        Ok(())
    }

    pub fn replay_wal(&self) -> Result<vledger_wal::recovery::RecoveryResult, ReplicationError> {
        vledger_wal::recovery::recover(&self.wal_dir)
            .map_err(|e| ReplicationError::Ledger(e.to_string()))
    }
}

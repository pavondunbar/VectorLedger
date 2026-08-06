//! Primary-side WAL shipper with TLS encryption and authenticated handshake.
//!
//! ## Security (Tasks #1, #2, Fix #9)
//!
//! Every replica connection goes through three layers:
//!
//! 1. **TLS handshake** (Task #1) — all bytes on the wire are encrypted and
//!    integrity-protected.  The primary presents a certificate; the replica
//!    may verify it against a CA.
//!
//! 2. **Mutual TLS** (Task #2, optional) — when `tls.client_cert` /
//!    `tls.client_key` are configured, the primary requires the replica to
//!    present a certificate that it validates against `tls.ca_cert`.
//!
//! 3. **BLAKE3-keyed HMAC challenge-response** (Fix #9) — runs inside TLS
//!    so the secret is never exposed in plaintext on the network.
//!
//! ```text
//! TCP accept → TLS handshake → AuthChallenge/AuthResponse → WAL stream
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::ReplicationConfig;
use crate::error::ReplicationError;
use crate::protocol::{
    self, AckMessage, AuthChallenge, AuthResponse, AuthResult,
    HeartbeatMsg, ReplicationMessage, WalRecordMsg, Lsn,
    compute_mac, mac_eq, encode_handshake,
};
use crate::secret;
use crate::tls as repl_tls;

// ── Type aliases for TLS-wrapped streams ─────────────────────────────────────

type TlsServerStream = tokio_rustls::server::TlsStream<TcpStream>;

// ── WalShipper ────────────────────────────────────────────────────────────────

/// Primary-side WAL shipper.
pub struct WalShipper {
    config:   ReplicationConfig,
    secret:   [u8; 32],
    replicas: Arc<Mutex<Vec<ReplicaConn>>>,
    next_lsn: Arc<std::sync::atomic::AtomicU64>,
}

struct ReplicaConn {
    writer: tokio::io::WriteHalf<TlsServerStream>,
    reader: BufReader<tokio::io::ReadHalf<TlsServerStream>>,
    peer:   std::net::SocketAddr,
}

impl WalShipper {
    /// Create a new `WalShipper`.  Loads (or generates) the HMAC secret from
    /// `data_dir`.
    pub fn new(
        config:   ReplicationConfig,
        data_dir: &std::path::Path,
    ) -> Result<Self, ReplicationError> {
        let secret_path = config.secret_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| secret::default_secret_path(data_dir));

        let secret = secret::load_or_generate(&secret_path)?;

        Ok(Self {
            config,
            secret,
            replicas: Arc::new(Mutex::new(Vec::new())),
            next_lsn: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        })
    }

    /// Bind the replication port and accept authenticated TLS replica
    /// connections in the background.
    pub async fn listen_and_accept(&self) -> Result<(), ReplicationError> {
        let addr     = self.config.replication_addr.clone();
        let replicas = self.replicas.clone();
        let secret   = self.secret;
        let hs_ms    = self.config.ack_timeout_ms;
        let tls_cfg  = self.config.tls.clone();

        let listener = TcpListener::bind(&addr).await?;

        if tls_cfg.enabled {
            let acceptor = repl_tls::build_acceptor(&tls_cfg)?;
            let mtls = tls_cfg.client_cert.is_some();
            info!(
                addr   = %addr,
                tls    = true,
                mtls   = mtls,
                "WAL shipper listening (TLS{} + HMAC auth)",
                if mtls { " + mTLS" } else { "" }
            );
            tokio::spawn(async move {
                Self::accept_loop_tls(listener, acceptor, replicas, secret, hs_ms).await;
            });
        } else {
            // Plain TCP — dev/test only
            warn!("WAL shipper: TLS disabled. Do not use in production.");
            tokio::spawn(async move {
                Self::accept_loop_plain(listener, replicas, secret, hs_ms).await;
            });
        }

        Ok(())
    }

    async fn accept_loop_tls(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        replicas: Arc<Mutex<Vec<ReplicaConn>>>,
        secret:   [u8; 32],
        hs_ms:    u64,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let acceptor = acceptor.clone();
                    let replicas = replicas.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Err(e) => warn!(%peer, "TLS handshake failed: {e}"),
                            Ok(tls_stream) => {
                                match authenticate_replica_tls(tls_stream, peer, &secret, hs_ms).await {
                                    Ok(conn) => {
                                        info!(%peer, "Replica authenticated (TLS)");
                                        replicas.lock().await.push(conn);
                                    }
                                    Err(e) => warn!(%peer, "Replica auth failed: {e}"),
                                }
                            }
                        }
                    });
                }
                Err(e) => error!("Replication listener error: {e}"),
            }
        }
    }

    /// Plain-TCP accept loop (dev/test only — TLS disabled).
    async fn accept_loop_plain(
        listener: TcpListener,
        replicas: Arc<Mutex<Vec<ReplicaConn>>>,
        secret:   [u8; 32],
        hs_ms:    u64,
    ) {
        // Wrap the plain TCP stream in a "null" TLS layer using rcgen so the
        // rest of the code is type-uniform. In practice dev mode won't reach
        // production so we use a throwaway self-signed acceptor.
        let dummy_tls_cfg = crate::config::ReplicationTlsConfig {
            enabled:         true,
            server_cert:     None,
            server_key:      None,
            server_hostname: "dev-primary".into(),
            ca_cert:         None,
            client_cert:     None,
            client_key:      None,
        };
        let acceptor = match repl_tls::build_acceptor(&dummy_tls_cfg) {
            Ok(a) => a,
            Err(e) => { error!("Cannot build dev TLS acceptor: {e}"); return; }
        };
        Self::accept_loop_tls(listener, acceptor, replicas, secret, hs_ms).await;
    }

    // ── WAL shipping ──────────────────────────────────────────────────────

    /// Ship a WAL record to all connected replicas synchronously.
    pub async fn ship(
        &self,
        record_bytes: &[u8],
        segment:      u64,
    ) -> Result<Lsn, ReplicationError> {
        use std::sync::atomic::Ordering;

        let lsn             = self.next_lsn.fetch_add(1, Ordering::SeqCst);
        let record_hex      = hex::encode(record_bytes);
        let record_hash_hex = hex::encode(blake3::hash(record_bytes).as_bytes());

        let msg = ReplicationMessage::WalRecord(WalRecordMsg {
            lsn, segment, record_hex, record_hash_hex,
        });

        let wire = protocol::encode_replication(&msg)
            .map_err(|e| ReplicationError::Serialisation(e.to_string()))?;

        let ack_timeout = Duration::from_millis(self.config.ack_timeout_ms);
        let mut replicas = self.replicas.lock().await;
        let mut dead = Vec::new();

        for (i, conn) in replicas.iter_mut().enumerate() {
            if let Err(e) = conn.writer.write_all(&wire).await {
                warn!(peer = %conn.peer, "Replica write error: {e}");
                dead.push(i);
                continue;
            }
            let _ = conn.writer.flush().await;

            let mut line = String::new();
            match timeout(ack_timeout, conn.reader.read_line(&mut line)).await {
                Err(_) => {
                    warn!(peer = %conn.peer, lsn, "Replica ACK timeout");
                    dead.push(i);
                    return Err(ReplicationError::AckTimeout { lsn, ms: self.config.ack_timeout_ms });
                }
                Ok(Err(e)) => {
                    warn!(peer = %conn.peer, "Replica read error: {e}");
                    dead.push(i);
                    continue;
                }
                Ok(Ok(0)) => {
                    warn!(peer = %conn.peer, "Replica disconnected");
                    dead.push(i);
                    return Err(ReplicationError::StreamEnded);
                }
                Ok(Ok(_)) => {
                    match protocol::decode_ack(&line) {
                        Err(e) => warn!(peer = %conn.peer, "Bad ACK JSON: {e}"),
                        Ok(AckMessage::Ack(ack)) => {
                            if ack.lsn != lsn {
                                return Err(ReplicationError::AckMismatch {
                                    expected: lsn, got: ack.lsn,
                                });
                            }
                            debug!(peer = %conn.peer, lsn, "Replica ACK received");
                        }
                        Ok(AckMessage::Error(err)) => {
                            error!(peer = %conn.peer, "Replica error: {}", err.message);
                            dead.push(i);
                        }
                        Ok(_) => {}
                    }
                }
            }
        }

        for i in dead.into_iter().rev() {
            replicas.swap_remove(i);
        }
        Ok(lsn)
    }

    /// Send a heartbeat to all replicas.
    pub async fn heartbeat(&self) {
        let msg = ReplicationMessage::Heartbeat(HeartbeatMsg {
            last_lsn: self.next_lsn.load(std::sync::atomic::Ordering::SeqCst).saturating_sub(1),
            ts: chrono::Utc::now().to_rfc3339(),
        });
        let wire = match protocol::encode_replication(&msg) {
            Ok(b) => b,
            Err(_) => return,
        };
        let mut replicas = self.replicas.lock().await;
        let mut dead = Vec::new();
        for (i, conn) in replicas.iter_mut().enumerate() {
            if conn.writer.write_all(&wire).await.is_err() {
                dead.push(i);
            }
        }
        for i in dead.into_iter().rev() {
            replicas.swap_remove(i);
        }
    }

    /// Number of currently connected replicas.
    pub async fn replica_count(&self) -> usize {
        self.replicas.lock().await.len()
    }
}

// ── HMAC handshake over TLS (Fix #9 inside Task #1) ──────────────────────────

async fn authenticate_replica_tls(
    tls_stream: TlsServerStream,
    peer:       std::net::SocketAddr,
    secret:     &[u8; 32],
    hs_ms:      u64,
) -> Result<ReplicaConn, ReplicationError> {
    let timeout_dur = Duration::from_millis(hs_ms);
    let (r, mut w) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(r);

    // 1. Send challenge.
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = AuthChallenge { nonce: hex::encode(nonce) };
    let wire = encode_handshake(&challenge)
        .map_err(|e| ReplicationError::Serialisation(e.to_string()))?;
    timeout(timeout_dur, w.write_all(&wire))
        .await
        .map_err(|_| ReplicationError::AuthFailed("timeout sending challenge".into()))?
        .map_err(|e| ReplicationError::AuthFailed(format!("write challenge: {e}")))?;
    let _ = w.flush().await;

    // 2. Read response.
    let mut line = String::new();
    let n = timeout(timeout_dur, reader.read_line(&mut line))
        .await
        .map_err(|_| ReplicationError::AuthFailed("timeout on auth response".into()))?
        .map_err(|e| ReplicationError::AuthFailed(format!("read response: {e}")))?;
    if n == 0 {
        return Err(ReplicationError::AuthFailed("replica closed connection".into()));
    }

    let response: AuthResponse = serde_json::from_str(line.trim())
        .map_err(|e| ReplicationError::AuthFailed(format!("parse AuthResponse: {e}")))?;

    let replica_mac: [u8; 32] = hex::decode(&response.mac)
        .map_err(|e| ReplicationError::AuthFailed(format!("invalid MAC hex: {e}")))?
        .try_into()
        .map_err(|_| ReplicationError::AuthFailed("MAC must be 32 bytes".into()))?;

    // 3. Verify (constant-time).
    let expected = compute_mac(secret, &nonce);
    if !mac_eq(&expected, &replica_mac) {
        let reject = AuthResult { ok: false, error: Some("invalid MAC".into()) };
        if let Ok(wire) = encode_handshake(&reject) {
            let _ = w.write_all(&wire).await;
            let _ = w.flush().await;
        }
        warn!(%peer, "Replica rejected: MAC mismatch");
        return Err(ReplicationError::AuthFailed(format!("MAC mismatch from {peer}")));
    }

    // 4. Confirm.
    let ok = AuthResult { ok: true, error: None };
    let wire = encode_handshake(&ok)
        .map_err(|e| ReplicationError::Serialisation(e.to_string()))?;
    w.write_all(&wire).await
        .map_err(|e| ReplicationError::AuthFailed(format!("write auth result: {e}")))?;
    let _ = w.flush().await;

    debug!(%peer, "Replication handshake complete (TLS)");
    Ok(ReplicaConn { writer: w, reader, peer })
}

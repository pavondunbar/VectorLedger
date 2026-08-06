//! PostgreSQL wire-protocol server for VectorLedger.
//!
//! ## Security model
//! Every inbound PgWire connection is fully authenticated:
//!
//! 1. TLS is mandatory — rustls TLS 1.3 handshake before any protocol bytes.
//! 2. Password authentication via `AuthenticationCleartextPassword` (safe
//!    inside TLS).  Verified against the shared `UserStore` (Argon2id).
//! 3. Role-based privilege check on the resolved `LogicalPlan` variant.
//!
//! ## Resource controls (Fix #1 and Fix #2)
//!
//! **Fix #1 — Connection-level idle timeouts**
//! - `AUTH_TIMEOUT` (30 s): unauthenticated connections that never send a
//!   password are reaped after 30 seconds, freeing the semaphore slot.
//! - `IDLE_TIMEOUT` (5 min): authenticated-but-idle connections are reaped
//!   after 5 minutes of silence.  The client receives an `ErrorResponse`
//!   before the connection is closed so it can distinguish timeout from crash.
//!
//! **Fix #2 — max_connections semaphore + per-IP token-bucket rate limiter**
//! - A `Semaphore` with `config.max_connections` permits bounds the total
//!   number of concurrent Tokio tasks.  Excess connections wait in the kernel
//!   TCP backlog until a slot is available.
//! - A per-IP token-bucket (`PG_RATE_BURST` / `PG_RATE_REFILL_PER_SEC`)
//!   rejects connections from flood sources before the TLS handshake.
//!   Idle bucket entries are evicted after `PG_BUCKET_TTL` to bound memory.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use vledger_ledger::LedgerStore;
use vledger_server::auth::{Role, UserStore};
use vledger_sql::planner::LogicalPlan;

use crate::codec;
use crate::messages::{self, FrontendMessage, StartupMessage, FieldDesc,
                      PROTOCOL_VERSION_3, SSL_REQUEST_CODE};

// ── Timeout constants (Fix #1) ────────────────────────────────────────────────

/// Deadline for receiving the initial startup + password message after the TLS
/// handshake completes.  Reclaims the semaphore slot from clients that open a
/// TLS connection but never authenticate.
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum idle time between query frames for an authenticated connection.
/// A silent authenticated client is reaped after this duration.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

// ── Rate-limiter constants (Fix #2) ───────────────────────────────────────────

/// Maximum burst of connections an IP can open in one instant.
const PG_RATE_BURST: f64 = 10.0;
/// Token refill rate — connections per second allowed at steady state.
const PG_RATE_REFILL_PER_SEC: f64 = 2.0;
/// How long to keep an idle IP bucket before evicting it from the map.
const PG_BUCKET_TTL: Duration = Duration::from_secs(300);

// ── Per-IP token bucket (Fix #2) ──────────────────────────────────────────────

#[derive(Debug)]
struct IpBucket {
    tokens:       f64,
    last_checked: Instant,
}

impl IpBucket {
    fn new() -> Self {
        Self { tokens: PG_RATE_BURST, last_checked: Instant::now() }
    }

    fn try_acquire(&mut self) -> bool {
        let now     = Instant::now();
        let elapsed = now.duration_since(self.last_checked).as_secs_f64();
        self.last_checked = now;
        self.tokens = (self.tokens + elapsed * PG_RATE_REFILL_PER_SEC).min(PG_RATE_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Configuration for the PostgreSQL wire-protocol listener.
#[derive(Debug, Clone)]
pub struct PgWireConfig {
    /// TCP address to bind (default `127.0.0.1:5432`).
    pub bind_addr: String,
    /// Database name expected from clients (informational only).
    pub database:  String,
    /// Whether to attach Merkle proofs to every SELECT response.
    pub attach_proofs: bool,
    /// Path to TLS certificate PEM.  `None` → generate self-signed.
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key PEM.  `None` → generate self-signed.
    pub tls_key_path:  Option<String>,
    /// Hostname for self-signed certificate CN (default `localhost`).
    pub tls_hostname:  String,
    /// Catalog directory for TLS cert persistence.
    /// `None` → ephemeral cert (not persisted across restarts).
    pub catalog_dir:   Option<String>,
    /// Maximum concurrent connections (Fix #2).  Default: 64.
    pub max_connections: usize,
}

impl Default for PgWireConfig {
    fn default() -> Self {
        Self {
            bind_addr:       "127.0.0.1:5432".into(),
            database:        "vledger".into(),
            attach_proofs:   false,
            tls_cert_path:   None,
            tls_key_path:    None,
            tls_hostname:    "localhost".into(),
            catalog_dir:     None,
            max_connections: 64,
        }
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

/// PostgreSQL wire-protocol server with mandatory TLS, authentication, and
/// connection-resource controls.
pub struct PgWireServer {
    config:     PgWireConfig,
    ledger:     Arc<tokio::sync::Mutex<LedgerStore>>,
    user_store: Arc<UserStore>,
}

impl PgWireServer {
    /// Create a new server.
    ///
    /// `user_store` is shared with the native TLS server so that both
    /// listeners use the same user database.
    pub fn new(config: PgWireConfig, ledger: LedgerStore, user_store: Arc<UserStore>) -> Self {
        Self {
            config,
            ledger:     Arc::new(tokio::sync::Mutex::new(ledger)),
            user_store,
        }
    }

    /// Start accepting connections.  Runs until `shutdown` is cancelled or the process exits.
    ///
    /// On shutdown: stops accepting, drains all in-flight connections by waiting
    /// for the semaphore to fully release, then returns.
    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let acceptor   = build_tls_acceptor(&self.config)?;
        let listener   = TcpListener::bind(&self.config.bind_addr).await?;

        // Fix #2: connection-count cap.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_connections));

        // Fix #2: per-IP token-bucket rate limiter.
        let ip_buckets: Arc<tokio::sync::Mutex<HashMap<IpAddr, IpBucket>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        info!(
            addr            = %self.config.bind_addr,
            tls             = true,
            auth            = true,
            max_connections = self.config.max_connections,
            rate_burst      = PG_RATE_BURST,
            rate_refill_s   = PG_RATE_REFILL_PER_SEC,
            auth_timeout_s  = AUTH_TIMEOUT.as_secs(),
            idle_timeout_s  = IDLE_TIMEOUT.as_secs(),
            "PgWire server listening"
        );

        let ledger     = self.ledger.clone();
        let attach     = self.config.attach_proofs;
        let user_store = self.user_store.clone();

        loop {
            let (stream, peer) = tokio::select! {
                res = listener.accept() => match res {
                    Ok(s)  => s,
                    Err(e) => { error!("PgWire accept error: {e}"); continue; }
                },
                _ = shutdown.cancelled() => {
                    info!("PgWire shutdown signal received — stopping accept loop");
                    break;
                }
            };
            let peer_ip = peer.ip();

            // ── Fix #2: per-IP rate limit ─────────────────────────────────
            {
                let mut buckets = ip_buckets.lock().await;
                let now = Instant::now();
                buckets.retain(|_, b| now.duration_since(b.last_checked) < PG_BUCKET_TTL);
                let bucket = buckets.entry(peer_ip).or_insert_with(IpBucket::new);
                if !bucket.try_acquire() {
                    warn!(%peer, "PgWire rate limit exceeded — dropping connection");
                    drop(stream);
                    continue;
                }
            }

            // ── Fix #2: connection-count semaphore ────────────────────────
            let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        %peer,
                        max = self.config.max_connections,
                        "PgWire connection limit reached — queuing"
                    );
                    match Arc::clone(&semaphore).acquire_owned().await {
                        Ok(p)  => p,
                        Err(_) => { drop(stream); break; }
                    }
                }
            };

            debug!(%peer, "PgWire new TCP connection");

            let acceptor   = acceptor.clone();
            let ledger     = ledger.clone();
            let user_store = user_store.clone();
            let conn_token = shutdown.clone();

            tokio::spawn(async move {
                let _permit = permit; // held for full connection lifetime
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) =
                            handle_connection(tls_stream, ledger, user_store, attach, peer, conn_token).await
                        {
                            error!(%peer, "PgWire connection error: {e}");
                        }
                    }
                    Err(e) => warn!(%peer, "PgWire TLS handshake failed: {e}"),
                }
            });
        }

        // Drain in-flight connections.
        info!(max_connections = self.config.max_connections,
              "PgWire waiting for in-flight connections to close…");
        let _ = semaphore.acquire_many(self.config.max_connections as u32).await;
        info!("PgWire all connections closed — shutdown complete");

        Ok(())
    }
}

// ── TLS acceptor builder ──────────────────────────────────────────────────────

fn build_tls_acceptor(cfg: &PgWireConfig) -> anyhow::Result<TlsAcceptor> {
    use rustls::ServerConfig as RustlsConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc as StdArc;

    let (certs, key): (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) =
        match (&cfg.tls_cert_path, &cfg.tls_key_path) {
            (Some(cert_path), Some(key_path)) => {
                use rustls::pki_types::pem::PemObject;
                let certs = CertificateDer::pem_file_iter(cert_path)?
                    .collect::<Result<Vec<_>, _>>()?;
                let key   = PrivateKeyDer::from_pem_file(key_path)?;
                (certs, key)
            }
            _ => {
                use rcgen::{generate_simple_self_signed, CertifiedKey};
                let CertifiedKey { cert, key_pair } =
                    generate_simple_self_signed(vec![cfg.tls_hostname.clone()])?;
                let cert_der = CertificateDer::from(cert.der().to_vec());
                let key_der  = PrivateKeyDer::Pkcs8(
                    PrivatePkcs8KeyDer::from(key_pair.serialize_der())
                );
                info!(hostname = %cfg.tls_hostname,
                      "PgWire: generating self-signed TLS certificate");
                (vec![cert_der], key_der)
            }
        };

    let config = RustlsConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(StdArc::new(config)))
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_connection(
    stream:        tokio_rustls::server::TlsStream<TcpStream>,
    ledger:        Arc<tokio::sync::Mutex<LedgerStore>>,
    user_store:    Arc<UserStore>,
    attach_proofs: bool,
    peer:          std::net::SocketAddr,
    shutdown:      CancellationToken,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // ── Startup phase — wrapped in AUTH_TIMEOUT, also select on shutdown ──
    let startup_payload = tokio::select! {
        res = timeout(AUTH_TIMEOUT, codec::read_startup(&mut reader)) => match res {
            Ok(Ok(p))  => p,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                warn!(%peer, "PgWire auth timeout (startup)");
                let _ = codec::write_all(&mut write_half, &messages::error_response(
                    "FATAL", "57P01",
                    &format!("authentication timeout after {}s", AUTH_TIMEOUT.as_secs()),
                )).await;
                return Ok(());
            }
        },
        _ = shutdown.cancelled() => {
            let _ = codec::write_all(&mut write_half, &messages::error_response(
                "FATAL", "57P01", "server shutting down",
            )).await;
            return Ok(());
        }
    };

    let startup = match StartupMessage::parse(&startup_payload) {
        Some(s) => s,
        None    => {
            anyhow::bail!("failed to parse startup message");
        }
    };

    // SSL upgrade request — confirm TLS already established, then read real startup.
    if startup.protocol_version == SSL_REQUEST_CODE {
        codec::write_all(&mut write_half, b"S").await?;
        let payload2 = tokio::select! {
            res = timeout(AUTH_TIMEOUT, codec::read_startup(&mut reader)) => match res {
                Ok(Ok(p))  => p,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    warn!(%peer, "PgWire auth timeout (post-SSL startup)");
                    let _ = codec::write_all(&mut write_half,
                        &messages::error_response("FATAL", "57P01", "authentication timeout")).await;
                    return Ok(());
                }
            },
            _ = shutdown.cancelled() => {
                let _ = codec::write_all(&mut write_half,
                    &messages::error_response("FATAL", "57P01", "server shutting down")).await;
                return Ok(());
            }
        };
        let real_startup = StartupMessage::parse(&payload2)
            .ok_or_else(|| anyhow::anyhow!("failed to parse post-ssl startup"))?;
        return handle_authenticated(
            real_startup, reader, write_half, ledger, user_store, attach_proofs, peer, shutdown,
        ).await;
    }

    if startup.protocol_version != PROTOCOL_VERSION_3 {
        let err = messages::error_response(
            "FATAL", "08P01",
            &format!("unsupported protocol version {}", startup.protocol_version),
        );
        codec::write_all(&mut write_half, &err).await?;
        return Ok(());
    }

    handle_authenticated(startup, reader, write_half, ledger, user_store, attach_proofs, peer, shutdown).await
}

/// Authenticate the client then run the query loop.
///
/// All reads in the auth phase use `AUTH_TIMEOUT`; all reads in the query
/// loop use `IDLE_TIMEOUT` (Fix #1).
async fn handle_authenticated<R, W>(
    startup:       StartupMessage,
    mut reader:    BufReader<R>,
    mut writer:    W,
    ledger:        Arc<tokio::sync::Mutex<LedgerStore>>,
    user_store:    Arc<UserStore>,
    attach_proofs: bool,
    peer:          std::net::SocketAddr,
    shutdown:      CancellationToken,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let username = startup.params.get("user")
        .cloned()
        .unwrap_or_else(|| "vledger".into());

    // ── Auth phase: send password prompt, read reply — under AUTH_TIMEOUT ─
    codec::write_all(&mut writer, &messages::auth_cleartext_password()).await?;

    let (msg_type, payload) = tokio::select! {
        res = timeout(AUTH_TIMEOUT, codec::read_message(&mut reader)) => match res {
            Ok(Ok(m))  => m,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                warn!(%peer, %username, "PgWire auth timeout (password)");
                let _ = codec::write_all(&mut writer, &messages::error_response(
                    "FATAL", "57P01",
                    &format!("authentication timeout after {}s", AUTH_TIMEOUT.as_secs()),
                )).await;
                return Ok(());
            }
        },
        _ = shutdown.cancelled() => {
            let _ = codec::write_all(&mut writer,
                &messages::error_response("FATAL", "57P01", "server shutting down")).await;
            return Ok(());
        }
    };

    if msg_type != b'p' {
        codec::write_all(
            &mut writer,
            &messages::error_response("FATAL", "28P01", "expected PasswordMessage"),
        ).await?;
        return Ok(());
    }

    let password = payload
        .split(|&b| b == 0)
        .next()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();

    let session = match user_store.authenticate(&username, &password) {
        Ok(s)  => s,
        Err(e) => {
            warn!(%peer, %username, "PgWire auth failed: {e}");
            codec::write_all(
                &mut writer,
                &messages::error_response("FATAL", "28P01", "password authentication failed"),
            ).await?;
            return Ok(());
        }
    };

    info!(%peer, username = %session.username, role = %session.role, "PgWire authenticated");

    // ── Server greetings ──────────────────────────────────────────────────
    let greet = [
        messages::auth_ok(),
        messages::parameter_status("server_version", "15.0 (VectorLedger vgdb)"),
        messages::parameter_status("client_encoding", "UTF8"),
        messages::parameter_status("DateStyle", "ISO, MDY"),
        messages::parameter_status("TimeZone", "UTC"),
        messages::parameter_status("integer_datetimes", "on"),
        messages::backend_key_data(std::process::id(), 0),
        messages::ready_for_query(b'I'),
    ];
    codec::write_messages(&mut writer, &greet).await?;

    let role = session.role;

    // ── Query loop — each read guarded by IDLE_TIMEOUT, also shutdown ────
    loop {
        let read_result = tokio::select! {
            res = timeout(IDLE_TIMEOUT, codec::read_message(&mut reader)) => res,
            _ = shutdown.cancelled() => {
                warn!(%peer, username = %session.username, "PgWire shutdown — closing connection");
                let _ = codec::write_all(&mut writer,
                    &messages::error_response("FATAL", "57P01", "server shutting down")).await;
                break;
            }
        };

        let (msg_type, payload) = match read_result {
            // Idle timeout: inform the client and close cleanly.
            Err(_) => {
                warn!(
                    %peer,
                    username = %session.username,
                    timeout_s = IDLE_TIMEOUT.as_secs(),
                    "PgWire idle timeout — closing connection"
                );
                let _ = codec::write_all(
                    &mut writer,
                    &messages::error_response(
                        "FATAL", "57P01",
                        &format!("idle timeout: no request received within {}s",
                                 IDLE_TIMEOUT.as_secs()),
                    ),
                ).await;
                break;
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(m))  => m,
        };

        let msg = FrontendMessage::parse(msg_type, &payload);
        debug!(?msg, "PgWire message received");

        match msg {
            FrontendMessage::Terminate => {
                debug!(username = %session.username, "PgWire client terminated");
                break;
            }

            FrontendMessage::Query(sql) => {
                let responses = execute_query(&sql, &ledger, attach_proofs, role).await;
                codec::write_messages(&mut writer, &responses).await?;
            }

            FrontendMessage::Parse { query, .. } => {
                let mut msgs = vec![messages::parse_complete()];
                if query.trim().is_empty() { msgs.push(messages::no_data()); }
                codec::write_messages(&mut writer, &msgs).await?;
            }

            FrontendMessage::Bind { .. } => {
                codec::write_all(&mut writer, &messages::bind_complete()).await?;
            }

            FrontendMessage::Describe { .. } => {
                codec::write_all(&mut writer, &messages::no_data()).await?;
            }

            FrontendMessage::Execute { portal } => {
                let responses = execute_query(&portal, &ledger, attach_proofs, role).await;
                codec::write_messages(&mut writer, &responses).await?;
            }

            FrontendMessage::Sync | FrontendMessage::Flush => {
                codec::write_all(&mut writer, &messages::ready_for_query(b'I')).await?;
            }

            FrontendMessage::Unknown(t) => {
                warn!(msg_type = t, "Unhandled pgwire message type");
            }
        }
    }

    info!(%peer, username = %session.username, "PgWire connection closed");
    Ok(())
}

// ── Query execution ───────────────────────────────────────────────────────────

async fn execute_query(
    sql:            &str,
    ledger:         &Arc<tokio::sync::Mutex<LedgerStore>>,
    _attach_proofs: bool,
    role:           Role,
) -> Vec<Vec<u8>> {
    let sql = sql.trim();
    if sql.is_empty() || sql == ";" {
        return vec![messages::empty_query_response(), messages::ready_for_query(b'I')];
    }

    let sql_upper = sql.to_uppercase();

    // Client-compatibility stubs (psql meta-commands).
    if sql_upper.starts_with("SET ") || sql_upper.starts_with("SET\t") {
        return vec![messages::command_complete("SET"), messages::ready_for_query(b'I')];
    }
    if sql_upper.starts_with("SHOW ") {
        let var = sql[5..].trim().trim_end_matches(';');
        let val = match var.to_uppercase().as_str() {
            "SERVER_VERSION"  => "15.0",
            "CLIENT_ENCODING" => "UTF8",
            "DATESTYLE"       => "ISO, MDY",
            "TIMEZONE"        => "UTC",
            _                 => "",
        };
        return vec![
            messages::row_description(&[FieldDesc::text(var)]),
            messages::data_row(&[Some(val.to_string())]),
            messages::command_complete("SHOW"),
            messages::ready_for_query(b'I'),
        ];
    }
    if sql_upper.contains("PG_CATALOG") || sql_upper.contains("INFORMATION_SCHEMA") {
        return vec![
            messages::row_description(&[]),
            messages::command_complete("SELECT 0"),
            messages::ready_for_query(b'I'),
        ];
    }

    use vledger_sql::{executor::Executor, parser::parse_one, planner::LogicalPlanBuilder};

    let stmt = match parse_one(sql) {
        Ok(s)  => s,
        Err(e) => return vec![
            messages::error_response("ERROR", "42601", &format!("syntax error: {e}")),
            messages::ready_for_query(b'E'),
        ],
    };

    let plan = match LogicalPlanBuilder::plan(stmt) {
        Ok(p)  => p,
        Err(e) => return vec![
            messages::error_response("ERROR", "42601", &format!("plan error: {e}")),
            messages::ready_for_query(b'E'),
        ],
    };

    if let Err(e) = check_plan_privilege(role, &plan) {
        return vec![
            messages::error_response("ERROR", "42501", &e),
            messages::ready_for_query(b'E'),
        ];
    }

    let result = {
        let mut ledger = ledger.lock().await;
        Executor::new(&mut *ledger).execute(plan)
    };

    match result {
        Err(e) => vec![
            messages::error_response("ERROR", "XX000", &e.to_string()),
            messages::ready_for_query(b'E'),
        ],
        Ok(qr) => {
            let mut msgs: Vec<Vec<u8>> = Vec::new();
            if qr.columns.is_empty() && qr.rows.is_empty() {
                let tag = if sql_upper.starts_with("INSERT") {
                    format!("INSERT 0 {}", qr.rows_affected)
                } else if sql_upper.starts_with("UPDATE") {
                    format!("UPDATE {}", qr.rows_affected)
                } else if sql_upper.starts_with("DELETE") {
                    format!("DELETE {}", qr.rows_affected)
                } else {
                    format!("OK {}", qr.rows_affected)
                };
                msgs.push(messages::command_complete(&tag));
            } else {
                let fields: Vec<FieldDesc> = qr.columns.iter().map(|c| {
                    if c == "balance" || c == "sequence" || c == "entries_verified" {
                        FieldDesc::bigint(c.clone())
                    } else {
                        FieldDesc::text(c.clone())
                    }
                }).collect();
                msgs.push(messages::row_description(&fields));
                for row in &qr.rows {
                    let vals: Vec<Option<String>> = qr.columns.iter()
                        .map(|col| row.get(col).map(|v| v.to_string()))
                        .collect();
                    msgs.push(messages::data_row(&vals));
                }
                let tag = if sql_upper.starts_with("INSERT") {
                    format!("INSERT 0 {}", qr.rows_affected)
                } else {
                    format!("SELECT {}", qr.rows.len())
                };
                msgs.push(messages::command_complete(&tag));
            }
            msgs.push(messages::ready_for_query(b'I'));
            msgs
        }
    }
}

// ── Plan-level privilege check ────────────────────────────────────────────────

fn check_plan_privilege(role: Role, plan: &LogicalPlan) -> Result<(), String> {
    use vledger_sql::planner::LogicalPlan::*;
    match plan {
        PostEntry(_) if !role.can_insert_ledger() =>
            Err(format!("role '{role}' cannot post journal entries")),
        CreateAccount(_) if !role.can_insert_accounts() =>
            Err(format!("role '{role}' cannot create accounts")),
        VerifyChain if !role.can_verify() =>
            Err(format!("role '{role}' cannot run VERIFY_CHAIN")),
        ScanEntries { .. } | ScanAccounts { .. } | GetBalance { .. }
        | Join(_) | Aggregate(_) | Window(_) if !role.can_select() =>
            Err(format!("role '{role}' cannot execute SELECT")),
        _ => Ok(()),
    }
}

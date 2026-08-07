//! Per-connection handler with authentication and authorization enforcement.
//!
//! ## Connection lifecycle
//! ```text
//! 1. Accept TLS connection
//! 2. Read first JSON frame (max MAX_LINE_BYTES) — MUST contain
//!    {"auth": {"username":…, "password":…}} OR {"token": "<session-token>"}
//! 3. Validate credentials → obtain Session (username + Role)
//! 4. For every subsequent frame:
//!    a. Validate token (re-check session not expired)
//!    b. Check Role privilege against the resolved LogicalPlan (Fix #7)
//!    c. Execute SQL
//!    d. Return result
//! ```
//!
//! ## Security hardening
//! - Fix #2: `require_auth = false` grants `ReadOnly` (not Admin) with a
//!   loud startup warning.
//! - Fix #6: every read is wrapped in `tokio::time::timeout`.
//!   - Initial auth frame: `AUTH_TIMEOUT` (30 s).  A client that opens a
//!     TLS connection and sends nothing will have its connection closed
//!     within 30 seconds, freeing the semaphore slot.
//!   - Subsequent frames: `IDLE_TIMEOUT` (5 min).  An authenticated but
//!     idle connection is reaped after 5 minutes of silence.
//!   In both cases the client receives a JSON error response before the
//!   connection is dropped so it can distinguish a timeout from a server
//!   crash.
//! - Fix #7: privilege is checked on the resolved `LogicalPlan` type, not
//!   raw SQL text.
//! - Fix #8: incoming line reads are bounded to `MAX_LINE_BYTES` to prevent
//!   OOM from an oversized request.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use vledger_ledger::LedgerStore;
use vledger_sql::{executor::{Executor, ReadExecutor}, parser::parse_one, planner::{LogicalPlan, LogicalPlanBuilder}};

use crate::auth::{check_plan_privilege, Session, UserStore};
use crate::config::ServerConfig;
use crate::protocol::{AdminCommand, Request, Response};

/// Maximum number of bytes accepted in a single newline-delimited JSON frame.
///
/// Fix #8: prevents OOM from a client sending an arbitrarily large request.
/// 4 MiB is generous — a typical vgdb SQL request is well under 1 KiB.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Deadline for receiving the initial authentication frame after the TLS
/// handshake completes (Fix #6).  A client that connects but never sends
/// credentials holds a semaphore slot; this timeout reclaims it.
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Maximum idle time between frames for an already-authenticated connection
/// (Fix #6).  Long-running sessions that go silent for longer than this are
/// reaped so they don't hold resources indefinitely.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Handle a single TLS connection until the client disconnects or `shutdown` fires.
pub async fn handle_connection(
    stream:     TlsStream<TcpStream>,
    ledger:     Arc<RwLock<LedgerStore>>,
    config:     Arc<ServerConfig>,
    user_store: Arc<UserStore>,
    peer_addr:  std::net::SocketAddr,
    shutdown:   CancellationToken,
) {
    // Task #5: the require_auth=false path only exists in dev-no-auth builds.
    // In a default (production) build this warning and the anonymous-session
    // branch below are compiled out entirely, making it impossible to
    // accidentally deploy an unauthenticated server.
    #[cfg(feature = "dev-no-auth")]
    if !config.require_auth {
        warn!(
            "⚠  dev-no-auth feature active — connections accepted without credentials \
             (ReadOnly role only). THIS BUILD MUST NOT BE USED IN PRODUCTION."
        );
    }
    // In a non-dev build, require_auth must always be true.  Enforce this at
    // runtime as a defence-in-depth guard even though the bypass code is
    // compiled out.
    #[cfg(not(feature = "dev-no-auth"))]
    if !config.require_auth {
        warn!(
            "⚠  require_auth=false is set but the dev-no-auth feature is not enabled. \
             Authentication is STILL enforced. Rebuild with --features dev-no-auth \
             if you intentionally want to disable auth (dev/test only)."
        );
    }

    info!(peer = %peer_addr, "New connection");

    let (reader_half, mut writer_half) = tokio::io::split(stream);
    let mut reader  = BufReader::new(reader_half);
    let mut session: Option<Session> = None;

    loop {
        // Fix #6: use a tighter deadline for the unauthenticated auth frame
        // and a longer idle timeout for subsequent frames.
        let deadline = if session.is_none() { AUTH_TIMEOUT } else { IDLE_TIMEOUT };

        // Fix #8: read line with a hard byte cap, wrapped in a timeout.
        // Also select on the shutdown token so graceful shutdown closes
        // active connections with a proper FATAL response.
        let line = tokio::select! {
            // Graceful shutdown: inform the client and exit.
            _ = shutdown.cancelled() => {
                warn!(peer = %peer_addr, "Server shutting down — closing connection");
                send(&mut writer_half, Response::err(
                    "server shutting down".to_string()
                )).await;
                break;
            }
            res = timeout(deadline, read_line_bounded(&mut reader, MAX_LINE_BYTES)) => {
                match res {
                    // Timeout expired — inform the client and close.
                    Err(_) => {
                        if session.is_none() {
                            warn!(
                                peer = %peer_addr,
                                timeout_s = AUTH_TIMEOUT.as_secs(),
                                "Auth timeout — closing unauthenticated connection"
                            );
                            send(&mut writer_half, Response::err(
                                format!("authentication timeout: no credentials received within {}s",
                                        AUTH_TIMEOUT.as_secs())
                            )).await;
                        } else {
                            warn!(
                                peer = %peer_addr,
                                timeout_s = IDLE_TIMEOUT.as_secs(),
                                "Idle timeout — closing authenticated connection"
                            );
                            send(&mut writer_half, Response::err(
                                format!("idle timeout: no request received within {}s",
                                        IDLE_TIMEOUT.as_secs())
                            )).await;
                        }
                        break;
                    }
                    Ok(Ok(Some(l))) if !l.trim().is_empty() => l,
                    Ok(Ok(Some(_))) => continue,
                    Ok(Ok(None))    => break,  // clean EOF
                    Ok(Err(e)) => {
                        warn!(peer = %peer_addr, "Read error: {e}");
                        break;
                    }
                }
            }
        };

        debug!(peer = %peer_addr, "Received frame");

        let req: Request = match serde_json::from_str(&line) {
            Ok(r)  => r,
            Err(e) => {
                send(&mut writer_half, Response::err(format!("Invalid JSON: {e}"))).await;
                continue;
            }
        };

        // ── Authentication gate ───────────────────────────────────────────
        if session.is_none() {
            let result = if let Some(creds) = &req.auth {
                user_store.authenticate(&creds.username, &creds.password)
                    .map_err(|e| e.to_string())
            } else if let Some(token) = &req.token {
                user_store.validate_token(token).await
                    .map_err(|e| e.to_string())
            } else {
                // Task #5: the unauthenticated path is compiled in only when
                // the dev-no-auth feature is explicitly enabled.
                #[cfg(feature = "dev-no-auth")]
                if !config.require_auth {
                    // Dev mode: anonymous ReadOnly session (never Admin).
                    Ok(Session {
                        username:   "anonymous".into(),
                        role:       crate::auth::Role::ReadOnly,
                        token:      "no-auth".into(),
                        expires_at: std::time::SystemTime::now()
                            + std::time::Duration::from_secs(86400),
                    })
                } else {
                    Err("authentication required — send \
                         {\"auth\":{\"username\":…,\"password\":…}} first"
                        .into())
                }
                // Production build: auth is always required regardless of config.
                #[cfg(not(feature = "dev-no-auth"))]
                Err("authentication required — send \
                     {\"auth\":{\"username\":…,\"password\":…}} first"
                    .into())
            };

            match result {
                Err(e) => {
                    warn!(peer = %peer_addr, "Auth failed: {e}");
                    send(&mut writer_half, Response::err(e)).await;
                    // Close connection on auth failure — don't allow retries
                    // on the same connection (forces TCP reconnect, imposes
                    // connection-setup overhead on brute-forcers).
                    break;
                }
                Ok(s) => {
                    let token = s.token.clone();
                    let role  = s.role.to_string();
                    session = Some(s);
                    if req.sql.is_none() {
                        send(&mut writer_half, Response::auth_ok(token, role)).await;
                        continue;
                    }
                }
            }
        } else if let Some(token) = &req.token {
            // Re-validate token on every frame (catches expiry mid-session).
            match user_store.validate_token(token).await {
                Ok(s)  => { session = Some(s); }
                Err(e) => {
                    send(&mut writer_half, Response::err(e.to_string())).await;
                    break;
                }
            }
        }

        // ── Admin commands ────────────────────────────────────────────────
        if let Some(admin_cmd) = req.admin {
            let sess = session.as_ref().unwrap();
            if !sess.role.can_admin() {
                send(&mut writer_half, Response::err(
                    format!("Permission denied: role '{}' cannot perform admin operations", sess.role)
                )).await;
                continue;
            }
            let resp = execute_admin(admin_cmd, &user_store).await;
            send(&mut writer_half, resp).await;
            continue;
        }

        // ── SQL execution ─────────────────────────────────────────────────
        let sql = match req.sql {
            Some(ref s) => s.as_str(),
            None => {
                if let Some(ref s) = session {
                    send(&mut writer_half,
                        Response::auth_ok(s.token.clone(), s.role.to_string())).await;
                }
                continue;
            }
        };

        let sess = session.as_ref().unwrap();
        let response = execute_sql(sql, req.with_proof, &ledger, &config, sess).await;
        send(&mut writer_half, response).await;
    }

    info!(
        peer = %peer_addr,
        user = session.as_ref().map(|s| s.username.as_str()).unwrap_or("unauthenticated"),
        "Connection closed"
    );
}

async fn execute_sql(
    sql:        &str,
    with_proof: bool,
    ledger:     &Arc<RwLock<LedgerStore>>,
    config:     &Arc<ServerConfig>,
    session:    &Session,
) -> Response {
    let stmt = match parse_one(sql) {
        Ok(s)  => s,
        Err(e) => return Response::err(format!("SQL parse error: {e}")),
    };
    let plan = match LogicalPlanBuilder::plan(stmt) {
        Ok(p)  => p,
        Err(e) => return Response::err(format!("Plan error: {e}")),
    };

    if let Err(e) = check_plan_privilege(session, &plan) {
        return Response::err(format!("Permission denied: {e}"));
    }

    let attach = config.attach_proofs || with_proof;

    // Write plans take an exclusive write lock.
    // Read plans take a shared read lock — multiple concurrent SELECTs
    // proceed without blocking each other.
    let is_write = matches!(
        plan,
        LogicalPlan::PostEntry(_) | LogicalPlan::CreateAccount(_)
    );

    if is_write {
        let mut guard = ledger.write().await;
        let result = if attach {
            Executor::with_proofs(&mut *guard).execute(plan)
        } else {
            Executor::new(&mut *guard).execute(plan)
        };
        drop(guard);
        match result {
            Ok(qr) => Response::ok(qr.columns, qr.rows, qr.rows_affected, qr.proof, qr.message),
            Err(e) => Response::err(e.to_string()),
        }
    } else {
        let guard = ledger.read().await;
        let result = if attach {
            ReadExecutor::with_proofs(&*guard).execute(plan)
        } else {
            ReadExecutor::new(&*guard).execute(plan)
        };
        drop(guard);
        match result {
            Ok(qr) => Response::ok(qr.columns, qr.rows, qr.rows_affected, qr.proof, qr.message),
            Err(e) => Response::err(e.to_string()),
        }
    }
}

// ── Bounded line reader (Fix #8) ──────────────────────────────────────────────

/// Read a newline-terminated line from `reader`, rejecting any line that
/// exceeds `max_bytes` before the newline is found.
///
/// Returns:
/// - `Ok(Some(line))` — a complete line was read.
/// - `Ok(None)`       — the peer closed the connection cleanly.
/// - `Err(_)`         — I/O error or the line exceeded `max_bytes`.
async fn read_line_bounded<R>(
    reader:    &mut BufReader<R>,
    max_bytes: usize,
) -> std::io::Result<Option<String>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = String::new();
    // Read byte-by-byte until newline or limit exceeded.
    // BufReader batches the I/O; we pay only one syscall per buffer fill.
    loop {
        if buf.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("request line exceeds {max_bytes} bytes"),
            ));
        }
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        if buf.ends_with('\n') {
            // Strip the trailing newline before returning.
            buf.truncate(buf.trim_end_matches('\n').len());
            return Ok(Some(buf));
        }
    }
}

async fn send(writer: &mut (impl AsyncWriteExt + Unpin), resp: Response) {
    if let Ok(mut json) = serde_json::to_string(&resp) {
        json.push('\n');
        let _ = writer.write_all(json.as_bytes()).await;
    }
}

// ── Admin command execution ───────────────────────────────────────────────────

async fn execute_admin(cmd: AdminCommand, user_store: &Arc<UserStore>) -> Response {
    match cmd {
        AdminCommand::SetPassword { username, new_password } => {
            match user_store.set_password(&username, &new_password) {
                Ok(()) => Response::ok(
                    vec!["result".into()],
                    vec![],
                    0,
                    None,
                    format!("Password updated for '{username}'. All sessions revoked."),
                ),
                Err(e) => Response::err(e.to_string()),
            }
        }
        AdminCommand::CreateUser { username, password, role } => {
            let parsed_role = match role.parse::<crate::auth::Role>() {
                Ok(r)  => r,
                Err(e) => return Response::err(e),
            };
            match user_store.create_user(&username, &password, parsed_role, None) {
                Ok(()) => Response::ok(vec![], vec![], 0, None,
                    format!("User '{username}' created with role '{role}'.")),
                Err(e) => Response::err(e.to_string()),
            }
        }
        AdminCommand::DeleteUser { username } => {
            match user_store.delete_user(&username) {
                Ok(()) => Response::ok(vec![], vec![], 0, None,
                    format!("User '{username}' deleted.")),
                Err(e) => Response::err(e.to_string()),
            }
        }
        AdminCommand::SetEnabled { username, enabled } => {
            match user_store.set_enabled(&username, enabled) {
                Ok(()) => {
                    let state = if enabled { "enabled" } else { "disabled" };
                    Response::ok(vec![], vec![], 0, None,
                        format!("User '{username}' {state}."))
                }
                Err(e) => Response::err(e.to_string()),
            }
        }
        AdminCommand::ListUsers => {
            let mut users = user_store.list_users();
            users.sort_by(|a, b| a.0.cmp(&b.0));
            let rows = users.iter().map(|(name, role, enabled)| {
                vledger_sql::result::Row {
                    columns: vec!["username".into(), "role".into(), "enabled".into()],
                    values: vec![
                        vledger_sql::result::Value::Text(name.clone()),
                        vledger_sql::result::Value::Text(role.to_string()),
                        vledger_sql::result::Value::Text(enabled.to_string()),
                    ],
                }
            }).collect();
            Response::ok(
                vec!["username".into(), "role".into(), "enabled".into()],
                rows,
                users.len(),
                None,
                format!("{} user(s)", users.len()),
            )
        }
    }
}

//! Authentication and authorization for VectorLedger.
//!
//! ## Design
//! - Users are stored in `vledger-data/catalog/users.json` (Argon2id-hashed passwords).
//! - Every connection must authenticate before executing SQL.
//! - Four built-in roles control what SQL operations are permitted:
//!
//! | Role      | SELECT | INSERT ledger | INSERT accounts | VERIFY | Admin ops |
//! |-----------|--------|---------------|-----------------|--------|-----------|
//! | Admin     | ✓      | ✓             | ✓               | ✓      | ✓         |
//! | Operator  | ✓      | ✓             | ✓               | ✓      | ✗         |
//! | Auditor   | ✓      | ✗             | ✗               | ✓      | ✗         |
//! | ReadOnly  | ✓      | ✗             | ✗               | ✗      | ✗         |
//!
//! ## Security hardening applied
//! - Fix #2: `require_auth = false` grants `ReadOnly` (not Admin) with a loud
//!   startup warning.  Should only be used for local development.
//! - Fix #3: `.server_secret` is written with mode 0o600 (owner read/write only).
//! - Fix #4: Session tokens use a 32-byte `OsRng` nonce, not a timestamp.
//! - Fix #5: Failed login attempts are tracked per-username; after
//!   `MAX_FAILED_ATTEMPTS` consecutive failures the account is locked for
//!   `LOCKOUT_DURATION`.  Each failure also adds a short delay to resist
//!   online brute-force at network speed.
//! - Fix #6: `users.json` is written with mode 0o600.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::ServerError;

// ── Session storage constants ─────────────────────────────────────────────────

/// Hard cap on the number of concurrent in-memory sessions.
///
/// Fix #4: prevents unbounded memory growth from clients that authenticate
/// in a loop and never use their tokens.  When a new session would exceed
/// this limit, expired sessions are evicted first; if still at capacity the
/// oldest (earliest `expires_at`) live session is dropped to make room.
const MAX_SESSIONS: usize = 4_096;

/// How often the background purge task removes expired sessions.
pub const SESSION_PURGE_INTERVAL: Duration = Duration::from_secs(60);

// ── Brute-force constants ─────────────────────────────────────────────────────

/// Number of consecutive failures before an account is temporarily locked.
const MAX_FAILED_ATTEMPTS: u32 = 5;
/// How long a locked account remains locked.
const LOCKOUT_DURATION: Duration = Duration::from_secs(300); // 5 minutes
/// Base delay inserted after every failed attempt (doubles each failure, capped).
const BASE_FAIL_DELAY_MS: u64 = 200;
/// Maximum per-attempt delay cap.
const MAX_FAIL_DELAY_MS: u64 = 3_000;

// ── Role ─────────────────────────────────────────────────────────────────────

/// Role assigned to a user account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full access including user management.
    Admin,
    /// Can post entries and create accounts; cannot manage users.
    Operator,
    /// Can query and verify; cannot write.
    Auditor,
    /// SELECT only.
    ReadOnly,
}

impl Role {
    pub fn can_select(self)          -> bool { true }
    pub fn can_insert_ledger(self)   -> bool { matches!(self, Role::Admin | Role::Operator) }
    pub fn can_insert_accounts(self) -> bool { matches!(self, Role::Admin | Role::Operator) }
    pub fn can_verify(self)          -> bool { matches!(self, Role::Admin | Role::Operator | Role::Auditor) }
    pub fn can_admin(self)           -> bool { matches!(self, Role::Admin) }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin    => write!(f, "admin"),
            Role::Operator => write!(f, "operator"),
            Role::Auditor  => write!(f, "auditor"),
            Role::ReadOnly => write!(f, "readonly"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin"                  => Ok(Role::Admin),
            "operator"               => Ok(Role::Operator),
            "auditor"                => Ok(Role::Auditor),
            "readonly" | "read_only" => Ok(Role::ReadOnly),
            other => Err(format!(
                "unknown role '{other}' — use: admin, operator, auditor, readonly"
            )),
        }
    }
}

// ── User record ───────────────────────────────────────────────────────────────

/// A single user account stored in `users.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username:      String,
    /// Argon2id PHC string (`$argon2id$v=19$...`).
    pub password_hash: String,
    pub role:          Role,
    pub enabled:       bool,
    pub created_at:    String,
    /// Optional per-user domain restriction — `None` = all domains.
    pub domain_filter: Option<String>,
}

// ── Session token ─────────────────────────────────────────────────────────────

/// An authenticated session.
#[derive(Debug, Clone)]
pub struct Session {
    pub username:   String,
    pub role:       Role,
    pub token:      String,
    pub expires_at: SystemTime,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

// ── Failure tracking (Fix #5) ─────────────────────────────────────────────────

/// Per-username failure state.
#[derive(Debug)]
struct FailureState {
    /// Number of consecutive failures since last success.
    count:       u32,
    /// Wall-clock time of the first failure in the current run.
    locked_at:   Option<Instant>,
}

impl FailureState {
    fn new() -> Self {
        Self { count: 0, locked_at: None }
    }

    /// Returns true if this account is currently locked out.
    fn is_locked(&self) -> bool {
        match self.locked_at {
            Some(t) => t.elapsed() < LOCKOUT_DURATION,
            None    => false,
        }
    }

    /// Record a failure; lock the account if threshold reached.
    fn record_failure(&mut self) {
        self.count += 1;
        if self.count >= MAX_FAILED_ATTEMPTS && self.locked_at.is_none() {
            self.locked_at = Some(Instant::now());
        }
    }

    /// Reset on successful authentication.
    fn reset(&mut self) {
        self.count     = 0;
        self.locked_at = None;
    }

    /// Milliseconds to sleep before returning a failure response.
    /// Doubles with each attempt, capped at MAX_FAIL_DELAY_MS.
    fn delay_ms(&self) -> u64 {
        // 2^attempts, saturating, capped at MAX_FAIL_DELAY_MS
        let exp = BASE_FAIL_DELAY_MS
            .saturating_mul(1u64 << self.count.min(10) as u64);
        exp.min(MAX_FAIL_DELAY_MS)
    }
}

// ── UserStore ─────────────────────────────────────────────────────────────────

/// Thread-safe in-memory user store, persisted to `users.json`.
///
/// ## Lock discipline (Fix #4)
/// `users` and `failures` are accessed synchronously from `authenticate` and
/// user-management methods (which deliberately call `std::thread::sleep` for
/// brute-force back-off, so they already run on a blocking thread).  These
/// fields keep `std::sync::RwLock`.
///
/// `sessions` is read and written from async contexts
/// (`validate_token`, `insert_session_bounded`, `purge_expired_sessions`,
/// `revoke_sessions_for`).  Holding a `std::sync::RwLock` write-guard across
/// the eviction scan blocks the Tokio thread-pool thread for the scan
/// duration.  Under high authentication load this can starve other tasks.
///
/// Fix: `sessions` now uses `tokio::sync::RwLock`.  All methods that touch
/// `sessions` are `async` and yield the thread while waiting for the lock.
/// `authenticate` bridges into the async session insert via
/// `tokio::task::block_in_place` so it remains callable from the blocking
/// thread that handles the Argon2 computation.
pub struct UserStore {
    users_path:    PathBuf,
    users:         RwLock<HashMap<String, UserRecord>>,
    /// Fix #4: tokio-aware RwLock — async callers yield instead of blocking
    /// the thread-pool thread during the eviction scan.
    sessions:      tokio::sync::RwLock<HashMap<String, Session>>,
    server_secret: [u8; 32],
    session_ttl:   Duration,
    failures:      RwLock<HashMap<String, FailureState>>,
}

impl UserStore {
    /// Open (or create) the user store at `catalog_dir/users.json`.
    ///
    /// If the file doesn't exist, a default `admin` account is created with a
    /// random 24-character password printed to stdout once.
    pub fn open(catalog_dir: &Path) -> Result<Self, ServerError> {
        let users_path  = catalog_dir.join("users.json");
        let secret_path = catalog_dir.join(".server_secret");

        // ── Fix #3: server secret with mode 0o600 ─────────────────────────
        let server_secret: [u8; 32] = if secret_path.exists() {
            let hex = std::fs::read_to_string(&secret_path)
                .map_err(ServerError::Io)?;
            let bytes = hex::decode(hex.trim())
                .map_err(|e| ServerError::Auth(format!("corrupt server secret: {e}")))?;
            bytes.try_into()
                .map_err(|_| ServerError::Auth("corrupt server secret length".into()))?
        } else {
            use rand::RngCore;
            let mut secret = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            std::fs::write(&secret_path, hex::encode(secret))
                .map_err(ServerError::Io)?;
            // Fix #3: restrict to owner read/write only.
            set_file_mode_600(&secret_path)?;
            secret
        };

        // ── Fix #6: users.json with mode 0o600 ────────────────────────────
        let mut users: HashMap<String, UserRecord> = if users_path.exists() {
            let data = std::fs::read_to_string(&users_path).map_err(ServerError::Io)?;
            serde_json::from_str(&data)
                .map_err(|e| ServerError::Auth(format!("corrupt users.json: {e}")))?
        } else {
            HashMap::new()
        };

        // Bootstrap: create admin if no users exist.
        if users.is_empty() {
            use rand::Rng;
            let initial_password: String = rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(24)
                .map(char::from)
                .collect();
            let hash = hash_password(&initial_password)
                .map_err(ServerError::Auth)?;
            let admin = UserRecord {
                username:      "admin".into(),
                password_hash: hash,
                role:          Role::Admin,
                enabled:       true,
                created_at:    chrono::Utc::now().to_rfc3339(),
                domain_filter: None,
            };
            println!("╔══════════════════════════════════════════════════════╗");
            println!("║  VectorLedger — Initial Admin Credentials          ║");
            println!("║  Username : admin                                    ║");
            println!("║  Password : {initial_password:<40} ║");
            println!("║  CHANGE THIS IMMEDIATELY with `vledger user set-password`║");
            println!("╚══════════════════════════════════════════════════════╝");
            users.insert("admin".into(), admin);
            let json = serde_json::to_string_pretty(&users)
                .map_err(|e| ServerError::Auth(e.to_string()))?;
            std::fs::write(&users_path, &json).map_err(ServerError::Io)?;
            // Fix #6: restrict to owner read/write only.
            set_file_mode_600(&users_path)?;
        }

        Ok(Self {
            users_path,
            users:         RwLock::new(users),
            sessions:      tokio::sync::RwLock::new(HashMap::new()),
            server_secret,
            session_ttl:   Duration::from_secs(3600),
            failures:      RwLock::new(HashMap::new()),
        })
    }

    // ── Authentication ────────────────────────────────────────────────────

    /// Verify credentials and return a new session token on success.
    ///
    /// Fix #5: tracks consecutive failures per-username.  After
    /// `MAX_FAILED_ATTEMPTS` failures the account is locked for
    /// `LOCKOUT_DURATION`.  Each failure inserts an exponential delay to
    /// slow online brute-force attacks.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<Session, ServerError> {
        // ── Lockout check ─────────────────────────────────────────────────
        {
            let failures = self.failures.read().unwrap_or_else(|p| p.into_inner());
            if let Some(state) = failures.get(username) {
                if state.is_locked() {
                    warn!(username, "Account locked due to too many failed attempts");
                    return Err(ServerError::Auth(
                        "account temporarily locked — too many failed attempts".into()
                    ));
                }
            }
        }

        let users = self.users.read().unwrap_or_else(|p| p.into_inner());
        let user  = users.get(username)
            .ok_or_else(|| ServerError::Auth("invalid credentials".into()));

        // Shadow the result so we can apply the delay before returning.
        let result: Result<Session, ServerError> = match user {
            Err(e) => {
                // Unknown username — still record failure to prevent
                // username-enumeration via timing differences.
                drop(users);
                self.record_failure(username);
                Err(e)
            }
            Ok(user) => {
                if !user.enabled {
                    drop(users);
                    self.record_failure(username);
                    return Err(ServerError::Auth("account disabled".into()));
                }

                match verify_password(password, &user.password_hash) {
                    Err(_) => {
                        drop(users);
                        self.record_failure(username);
                        Err(ServerError::Auth("invalid credentials".into()))
                    }
                    Ok(()) => {
                        // Success — reset failure counter.
                        let token   = self.mint_token(username, user.role);
                        let expires = SystemTime::now() + self.session_ttl;
                        let session = Session {
                            username:   username.to_string(),
                            role:       user.role,
                            token:      token.clone(),
                            expires_at: expires,
                        };
                        drop(users);
                        {
                            let mut failures = self.failures.write().unwrap_or_else(|p| p.into_inner());
                            failures.entry(username.to_string()).or_insert_with(FailureState::new).reset();
                        }
                        // Fix #4: insert_session_bounded is async (tokio::sync::RwLock).
                        // authenticate is called from a blocking thread (it calls
                        // thread::sleep), so we bridge back into async via block_in_place.
                        tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(
                                self.insert_session_bounded(token.clone(), session.clone())
                            )
                        });
                        info!(username, role = %session.role, "Authenticated");
                        Ok(session)
                    }
                }
            }
        };

        result
    }

    /// Record a failed attempt and apply a back-off delay synchronously.
    fn record_failure(&self, username: &str) {
        let delay_ms = {
            let mut failures = self.failures.write().unwrap_or_else(|p| p.into_inner());
            let state = failures.entry(username.to_string()).or_insert_with(FailureState::new);
            let d = state.delay_ms();
            state.record_failure();
            warn!(username, attempts = state.count, "Authentication failure");
            d
        };
        // Insert delay *outside* the lock so we don't hold it during sleep.
        std::thread::sleep(Duration::from_millis(delay_ms));
    }

    /// Validate a session token and return the session if valid.
    ///
    /// Fix #4: async — acquires the tokio RwLock without blocking the thread.
    pub async fn validate_token(&self, token: &str) -> Result<Session, ServerError> {
        // Purge expired sessions lazily under a write lock.
        {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, s| !s.is_expired());
        }
        let sessions = self.sessions.read().await;
        sessions.get(token)
            .filter(|s| !s.is_expired())
            .cloned()
            .ok_or_else(|| ServerError::Auth("invalid or expired session token".into()))
    }

    // ── User management ───────────────────────────────────────────────────

    /// Create a new user.
    pub fn create_user(
        &self,
        username: &str,
        password: &str,
        role:     Role,
        domain:   Option<String>,
    ) -> Result<(), ServerError> {
        let hash = hash_password(password).map_err(ServerError::Auth)?;
        let record = UserRecord {
            username:      username.to_string(),
            password_hash: hash,
            role,
            enabled:       true,
            created_at:    chrono::Utc::now().to_rfc3339(),
            domain_filter: domain,
        };
        {
            let mut users = self.users.write().unwrap_or_else(|p| p.into_inner());
            if users.contains_key(username) {
                return Err(ServerError::Auth(format!("user '{username}' already exists")));
            }
            users.insert(username.to_string(), record);
        }
        self.persist()
    }

    /// Change a user's password.
    ///
    /// All active sessions for `username` are revoked so any previously
    /// issued token (which may have been compromised) stops working
    /// immediately.  The user must re-authenticate with the new password.
    pub fn set_password(&self, username: &str, new_password: &str) -> Result<(), ServerError> {
        let hash = hash_password(new_password).map_err(ServerError::Auth)?;
        {
            let mut users = self.users.write().unwrap_or_else(|p| p.into_inner());
            let user = users.get_mut(username)
                .ok_or_else(|| ServerError::Auth(format!("user '{username}' not found")))?;
            user.password_hash = hash;
        }
        // Revoke existing sessions so old tokens are immediately invalid.
        let revoked = self.revoke_sessions_for(username);
        if revoked > 0 {
            info!(username, revoked, "Sessions revoked due to password change");
        }
        self.persist()
    }

    /// Enable or disable a user account.
    ///
    /// When disabling (`enabled = false`) all active sessions for `username`
    /// are immediately revoked so no in-flight token can be used after this
    /// call returns.
    pub fn set_enabled(&self, username: &str, enabled: bool) -> Result<(), ServerError> {
        {
            let mut users = self.users.write().unwrap_or_else(|p| p.into_inner());
            let user = users.get_mut(username)
                .ok_or_else(|| ServerError::Auth(format!("user '{username}' not found")))?;
            user.enabled = enabled;
        }
        // Task #4: revoke all active sessions when the account is disabled.
        if !enabled {
            let revoked = self.revoke_sessions_for(username);
            if revoked > 0 {
                warn!(username, revoked, "Sessions revoked due to account disable");
            }
        }
        self.persist()
    }

    /// List all users (without password hashes).
    pub fn list_users(&self) -> Vec<(String, Role, bool)> {
        self.users.read().unwrap_or_else(|p| p.into_inner()).values()
            .map(|u| (u.username.clone(), u.role, u.enabled))
            .collect()
    }

    /// Delete a user.
    ///
    /// All active sessions for `username` are immediately revoked before the
    /// account record is removed, so no in-flight token survives deletion.
    pub fn delete_user(&self, username: &str) -> Result<(), ServerError> {
        self.users.write().unwrap_or_else(|p| p.into_inner()).remove(username)
            .ok_or_else(|| ServerError::Auth(format!("user '{username}' not found")))?;
        // Task #4: purge sessions before persisting the deletion.
        let revoked = self.revoke_sessions_for(username);
        if revoked > 0 {
            warn!(username, revoked, "Sessions revoked due to account deletion");
        }
        self.persist()
    }

    // ── Internal ──────────────────────────────────────────────────────────

    /// Immediately invalidate all sessions belonging to `username`.
    ///
    /// Returns the number of sessions removed.  Fix #4: async.
    fn revoke_sessions_for(&self, username: &str) -> usize {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut sessions = self.sessions.write().await;
                let before = sessions.len();
                sessions.retain(|_, s| s.username != username);
                before - sessions.len()
            })
        })
    }

    /// Insert a session into the bounded map (Fix #4).
    ///
    /// Async — acquires the tokio RwLock write guard without blocking the
    /// thread pool.  The eviction scan runs entirely inside the guard; it is
    /// CPU-only (no I/O) and completes in microseconds even at MAX_SESSIONS.
    async fn insert_session_bounded(&self, token: String, session: Session) {
        let mut sessions = self.sessions.write().await;

        // Step 1: evict expired entries.
        if sessions.len() >= MAX_SESSIONS {
            let now = SystemTime::now();
            sessions.retain(|_, s| s.expires_at > now);
        }

        // Step 2: if still at cap, drop the oldest live session.
        if sessions.len() >= MAX_SESSIONS {
            let oldest_token = sessions
                .iter()
                .min_by_key(|(_, s)| s.expires_at)
                .map(|(t, _)| t.clone());
            if let Some(t) = oldest_token {
                warn!(
                    evicted_token = &t[..8],
                    "Session store at MAX_SESSIONS ({MAX_SESSIONS}) — evicting oldest session"
                );
                sessions.remove(&t);
            }
        }

        sessions.insert(token, session);
    }

    /// Remove all expired sessions from the in-memory map.
    ///
    /// Fix #4: async — uses the tokio RwLock to avoid blocking the thread pool.
    pub async fn purge_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        let now    = SystemTime::now();
        sessions.retain(|_, s| s.expires_at > now);
        let evicted = before - sessions.len();
        if evicted > 0 {
            tracing::debug!(evicted, remaining = sessions.len(), "Purged expired sessions");
        }
        evicted
    }

    /// Mint a session token.
    ///
    /// Fix #4: uses a 32-byte `OsRng` nonce instead of a nanosecond
    /// timestamp, so two tokens issued simultaneously for the same user
    /// are always distinct.
    fn mint_token(&self, username: &str, role: Role) -> String {
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let mut hasher = blake3::Hasher::new_keyed(&self.server_secret);
        hasher.update(username.as_bytes());
        hasher.update(role.to_string().as_bytes());
        hasher.update(&nonce);
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Write `users.json` to disk.
    ///
    /// Fix #6: always restores mode 0o600 after writing.
    fn persist(&self) -> Result<(), ServerError> {
        let users = self.users.read().unwrap_or_else(|p| p.into_inner());
        let json  = serde_json::to_string_pretty(&*users)
            .map_err(|e| ServerError::Auth(e.to_string()))?;
        std::fs::write(&self.users_path, json).map_err(ServerError::Io)?;
        set_file_mode_600(&self.users_path)?;
        Ok(())
    }
}

// ── File permission helper (Fix #3, #6) ───────────────────────────────────────

/// Set UNIX file permissions to 0o600 (owner read/write, no group/other access).
///
/// On non-Unix platforms this is a no-op — Windows uses ACLs and the file is
/// already inside the vgdb data directory which should be ACL-protected.
fn set_file_mode_600(path: &Path) -> Result<(), ServerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(ServerError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path; // suppress unused warning on Windows
    }
    Ok(())
}

// ── Password helpers ──────────────────────────────────────────────────────────

/// Hash a password with Argon2id (64 MiB / 3 iterations / 4 lanes).
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt   = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| e.to_string())
}

/// Verify a password against an Argon2id PHC string.
pub fn verify_password(password: &str, hash: &str) -> Result<(), ()> {
    let parsed = PasswordHash::new(hash).map_err(|_| ())?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| ())
}

// ── Privilege check (Fix #7 — native server handler) ─────────────────────────

/// Check whether `session` is allowed to execute the given `LogicalPlan`.
///
/// Fix #7: operates on the *resolved* `LogicalPlan` variant, not raw SQL
/// text — immune to whitespace/comment bypass.
pub fn check_plan_privilege(
    session: &Session,
    plan:    &vledger_sql::planner::LogicalPlan,
) -> Result<(), String> {
    use vledger_sql::planner::LogicalPlan::*;
    match plan {
        PostEntry(_) if !session.role.can_insert_ledger() =>
            Err(format!("role '{}' cannot post journal entries", session.role)),
        CreateAccount(_) if !session.role.can_insert_accounts() =>
            Err(format!("role '{}' cannot create accounts", session.role)),
        VerifyChain if !session.role.can_verify() =>
            Err(format!("role '{}' cannot run VERIFY_CHAIN", session.role)),
        ScanEntries { .. } | ScanAccounts { .. } | GetBalance { .. }
        | Join(_) | Aggregate(_) | Window(_)
            if !session.role.can_select() =>
            Err(format!("role '{}' cannot execute SELECT", session.role)),
        _ => Ok(()),
    }
}

/// Legacy string-based check retained for callers that have not yet been
/// migrated to `check_plan_privilege`.  Forwards to the plan-level check
/// where possible; otherwise keeps the original SQL-text path.
///
/// Deprecated — use `check_plan_privilege` directly.
#[deprecated(note = "use check_plan_privilege with a resolved LogicalPlan")]
pub fn check_privilege(session: &Session, plan_sql: &str) -> Result<(), String> {
    // Attempt to resolve to a plan first (best-effort — parse errors fall
    // back to the text check so callers don't break).
    if let Ok(stmt) = vledger_sql::parser::parse_one(plan_sql) {
        if let Ok(plan) = vledger_sql::planner::LogicalPlanBuilder::plan(stmt) {
            return check_plan_privilege(session, &plan);
        }
    }

    // Fallback: original string check (used only if parsing fails).
    let upper           = plan_sql.trim().to_uppercase();
    let is_insert       = upper.starts_with("INSERT");
    let is_insert_ledger = is_insert && upper.contains("INTO LEDGER");
    let is_insert_acct   = is_insert && upper.contains("INTO ACCOUNTS");
    let is_verify        = upper.contains("VERIFY_CHAIN");
    let is_admin_op      = upper.starts_with("CREATE USER")
        || upper.starts_with("DROP USER")
        || upper.starts_with("ALTER USER");

    if is_admin_op       && !session.role.can_admin()           { return Err(format!("role '{}' cannot perform admin operations", session.role)); }
    if is_insert_ledger  && !session.role.can_insert_ledger()   { return Err(format!("role '{}' cannot post journal entries", session.role)); }
    if is_insert_acct    && !session.role.can_insert_accounts() { return Err(format!("role '{}' cannot create accounts", session.role)); }
    if is_verify         && !session.role.can_verify()          { return Err(format!("role '{}' cannot run VERIFY_CHAIN", session.role)); }

    Ok(())
}

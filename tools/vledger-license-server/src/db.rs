//! SQLite database layer.
//!
//! ## Schema
//!
//! ### `licenses`
//! One row per issued license.  A customer may have multiple rows if they
//! have renewed — the most recent row for a given `stripe_customer_id` is
//! always the active one.
//!
//! ### `download_tokens`
//! One-time signed tokens that let a customer download their `license.json`
//! without authentication.  Tokens are single-use and expire after 72 hours.
//!
//! ## Thread safety
//! `rusqlite::Connection` is `!Send`.  We open one connection per call using
//! a path stored in `Db` and protect it with a `Mutex` so the single
//! connection can be shared across Tokio tasks via `Arc<Db>`.

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::error::ServerError;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single issued license record.
#[derive(Debug, Clone)]
pub struct LicenseRecord {
    pub id:                  String,   // UUID v4
    pub stripe_customer_id:  String,
    pub stripe_subscription_id: String,
    pub licensee:            String,
    pub email:               String,
    pub tier:                String,   // "starter" | "growth" | "enterprise"
    pub issued_at:           String,   // YYYY-MM-DD
    pub expires_at:          String,   // YYYY-MM-DD  (billing end + 7-day grace)
    pub features:            String,   // comma-separated feature list
    pub license_json:        String,   // the complete signed license.json payload
    pub created_at:          DateTime<Utc>,
}

/// A one-time download token.
#[derive(Debug, Clone)]
pub struct DownloadToken {
    pub token:       String,           // 32-byte URL-safe base64
    pub license_id:  String,           // FK → licenses.id
    pub email:       String,           // who can use it (informational)
    pub expires_at:  DateTime<Utc>,    // tokens expire after 72 hours
    pub used:        bool,
}

// ── Db handle ─────────────────────────────────────────────────────────────────

/// Shared database handle.  Wrap in `Arc<Db>` and pass to handlers.
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Open (or create) the SQLite database at `path` and run migrations.
    pub fn open(path: &Path) -> Result<Self, ServerError> {
        let conn = Connection::open(path)
            .map_err(|e| ServerError::Database(e.to_string()))?;

        // Enable WAL mode for better concurrent read performance.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| ServerError::Database(e.to_string()))?;

        let db = Self { conn: Mutex::new(conn) };
        db.migrate()?;
        Ok(db)
    }

    // ── Migrations ────────────────────────────────────────────────────────

    fn migrate(&self) -> Result<(), ServerError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS licenses (
                id                      TEXT PRIMARY KEY,
                stripe_customer_id      TEXT NOT NULL,
                stripe_subscription_id  TEXT NOT NULL,
                licensee                TEXT NOT NULL,
                email                   TEXT NOT NULL,
                tier                    TEXT NOT NULL,
                issued_at               TEXT NOT NULL,
                expires_at              TEXT NOT NULL,
                features                TEXT NOT NULL,
                license_json            TEXT NOT NULL,
                created_at              TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_licenses_customer
                ON licenses(stripe_customer_id);

            CREATE INDEX IF NOT EXISTS idx_licenses_subscription
                ON licenses(stripe_subscription_id);

            CREATE INDEX IF NOT EXISTS idx_licenses_email
                ON licenses(email);

            CREATE TABLE IF NOT EXISTS download_tokens (
                token        TEXT PRIMARY KEY,
                license_id   TEXT NOT NULL REFERENCES licenses(id),
                email        TEXT NOT NULL,
                expires_at   TEXT NOT NULL,
                used         INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_tokens_license
                ON download_tokens(license_id);
        "#).map_err(|e| ServerError::Database(e.to_string()))
    }

    // ── License operations ────────────────────────────────────────────────

    /// Insert a newly issued license record.
    pub fn insert_license(&self, rec: &LicenseRecord) -> Result<(), ServerError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO licenses
               (id, stripe_customer_id, stripe_subscription_id,
                licensee, email, tier, issued_at, expires_at,
                features, license_json, created_at)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
            params![
                rec.id,
                rec.stripe_customer_id,
                rec.stripe_subscription_id,
                rec.licensee,
                rec.email,
                rec.tier,
                rec.issued_at,
                rec.expires_at,
                rec.features,
                rec.license_json,
                rec.created_at.to_rfc3339(),
            ],
        ).map_err(|e| ServerError::Database(e.to_string()))?;
        Ok(())
    }

    /// Fetch the most recently issued license for a Stripe subscription.
    pub fn latest_license_for_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<LicenseRecord>, ServerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, stripe_customer_id, stripe_subscription_id,
                      licensee, email, tier, issued_at, expires_at,
                      features, license_json, created_at
               FROM   licenses
               WHERE  stripe_subscription_id = ?1
               ORDER  BY created_at DESC
               LIMIT  1"#,
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        let mut rows = stmt.query(params![subscription_id])
            .map_err(|e| ServerError::Database(e.to_string()))?;

        if let Some(row) = rows.next()
            .map_err(|e| ServerError::Database(e.to_string()))?
        {
            Ok(Some(row_to_license(row)?))
        } else {
            Ok(None)
        }
    }

    /// Fetch a license by its primary key.
    pub fn get_license(&self, id: &str) -> Result<Option<LicenseRecord>, ServerError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, stripe_customer_id, stripe_subscription_id,
                      licensee, email, tier, issued_at, expires_at,
                      features, license_json, created_at
               FROM   licenses
               WHERE  id = ?1"#,
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        let mut rows = stmt.query(params![id])
            .map_err(|e| ServerError::Database(e.to_string()))?;

        if let Some(row) = rows.next()
            .map_err(|e| ServerError::Database(e.to_string()))?
        {
            Ok(Some(row_to_license(row)?))
        } else {
            Ok(None)
        }
    }

    // ── Download token operations ─────────────────────────────────────────

    /// Create and store a new one-time download token for `license_id`.
    /// Returns the token string (URL-safe base64, 32 bytes of entropy).
    pub fn create_download_token(
        &self,
        license_id: &str,
        email:      &str,
    ) -> Result<String, ServerError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use rand::RngCore;

        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let token     = URL_SAFE_NO_PAD.encode(raw);
        let expires_at = Utc::now() + chrono::Duration::hours(72);

        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO download_tokens (token, license_id, email, expires_at, used)
               VALUES (?1, ?2, ?3, ?4, 0)"#,
            params![token, license_id, email, expires_at.to_rfc3339()],
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        Ok(token)
    }

    /// Look up a download token.  Returns `None` if not found, expired,
    /// or already used.
    pub fn consume_download_token(
        &self,
        token: &str,
    ) -> Result<Option<DownloadToken>, ServerError> {
        let conn = self.conn.lock().unwrap();

        // Fetch the token row.
        let mut stmt = conn.prepare(
            r#"SELECT token, license_id, email, expires_at, used
               FROM   download_tokens
               WHERE  token = ?1"#,
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        let mut rows = stmt.query(params![token])
            .map_err(|e| ServerError::Database(e.to_string()))?;

        let dt = if let Some(row) = rows.next()
            .map_err(|e| ServerError::Database(e.to_string()))?
        {
            let expires_str: String = row.get(3)
                .map_err(|e| ServerError::Database(e.to_string()))?;
            let used: i64 = row.get(4)
                .map_err(|e| ServerError::Database(e.to_string()))?;
            let expires_at = DateTime::parse_from_rfc3339(&expires_str)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| ServerError::Database(e.to_string()))?;

            if used != 0 || Utc::now() > expires_at {
                return Ok(None);
            }

            DownloadToken {
                token:      row.get(0).map_err(|e| ServerError::Database(e.to_string()))?,
                license_id: row.get(1).map_err(|e| ServerError::Database(e.to_string()))?,
                email:      row.get(2).map_err(|e| ServerError::Database(e.to_string()))?,
                expires_at,
                used: false,
            }
        } else {
            return Ok(None);
        };

        // Mark as used atomically.
        drop(rows);
        drop(stmt);
        conn.execute(
            "UPDATE download_tokens SET used = 1 WHERE token = ?1",
            params![token],
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        Ok(Some(dt))
    }

    /// Store a long-lived API key token (never expires, not single-use).
    /// Used for the `GET /license/current?token=<api-key>` pull endpoint.
    pub fn create_api_token(
        &self,
        license_id: &str,
        email:      &str,
    ) -> Result<String, ServerError> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use rand::RngCore;

        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        // Prefix with "vgl_" so tokens are unambiguous in logs/support.
        let token     = format!("vgl_{}", URL_SAFE_NO_PAD.encode(raw));
        // expires_at far future — effectively never expires.
        let expires_at = Utc::now() + chrono::Duration::days(36500);

        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO download_tokens (token, license_id, email, expires_at, used)
               VALUES (?1, ?2, ?3, ?4, 0)"#,
            params![token, license_id, email, expires_at.to_rfc3339()],
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        Ok(token)
    }

    /// Look up an API token and return the current license for it without
    /// consuming (marking used) the token — for the pull endpoint.
    pub fn get_license_for_api_token(
        &self,
        token: &str,
    ) -> Result<Option<LicenseRecord>, ServerError> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            r#"SELECT l.id, l.stripe_customer_id, l.stripe_subscription_id,
                      l.licensee, l.email, l.tier, l.issued_at, l.expires_at,
                      l.features, l.license_json, l.created_at
               FROM   download_tokens dt
               JOIN   licenses l ON l.id = dt.license_id
               WHERE  dt.token    = ?1
                 AND  dt.used     = 0
                 AND  dt.expires_at > ?2
               ORDER  BY l.created_at DESC
               LIMIT  1"#,
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        let now = Utc::now().to_rfc3339();
        let mut rows = stmt.query(params![token, now])
            .map_err(|e| ServerError::Database(e.to_string()))?;

        if let Some(row) = rows.next()
            .map_err(|e| ServerError::Database(e.to_string()))?
        {
            Ok(Some(row_to_license(row)?))
        } else {
            Ok(None)
        }
    }

    /// Update the `license_id` pointer of an API token to point at the
    /// newest renewal for a subscription.  Called after every renewal so
    /// the pull endpoint always returns the current license.
    pub fn repoint_api_tokens_for_subscription(
        &self,
        subscription_id: &str,
        new_license_id:  &str,
    ) -> Result<(), ServerError> {
        let conn = self.conn.lock().unwrap();

        // Find all API tokens (non-consumed, far-future expiry) linked to
        // any previous license for this subscription.
        conn.execute(
            r#"UPDATE download_tokens
               SET    license_id = ?1
               WHERE  license_id IN (
                   SELECT id FROM licenses
                   WHERE  stripe_subscription_id = ?2
               )
               AND    used = 0
               AND    expires_at > ?3"#,
            params![
                new_license_id,
                subscription_id,
                Utc::now().to_rfc3339(),
            ],
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        Ok(())
    }

    /// Return the token string of the current long-lived API token for a
    /// subscription, if one exists.  Used during renewals to include the
    /// same token in the renewal email rather than generating a new one.
    pub fn get_api_token_for_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<String>, ServerError> {
        let conn = self.conn.lock().unwrap();

        // API tokens are identified by having a far-future expiry (> 1 year
        // from now) and not being consumed.  One-time download tokens expire
        // within 72 hours so this distinguishes the two.
        let threshold = (Utc::now() + chrono::Duration::days(365))
            .to_rfc3339();

        let mut stmt = conn.prepare(
            r#"SELECT dt.token
               FROM   download_tokens dt
               JOIN   licenses l ON l.id = dt.license_id
               WHERE  l.stripe_subscription_id = ?1
                 AND  dt.used      = 0
                 AND  dt.expires_at > ?2
               ORDER  BY l.created_at DESC
               LIMIT  1"#,
        ).map_err(|e| ServerError::Database(e.to_string()))?;

        let mut rows = stmt.query(params![subscription_id, threshold])
            .map_err(|e| ServerError::Database(e.to_string()))?;

        if let Some(row) = rows.next()
            .map_err(|e| ServerError::Database(e.to_string()))?
        {
            let token: String = row.get(0)
                .map_err(|e| ServerError::Database(e.to_string()))?;
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }
}  // impl Db

// ── Row helpers ───────────────────────────────────────────────────────────────

fn row_to_license(row: &rusqlite::Row<'_>) -> Result<LicenseRecord, ServerError> {
    let created_str: String = row.get(10)
        .map_err(|e| ServerError::Database(e.to_string()))?;
    let created_at = DateTime::parse_from_rfc3339(&created_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| ServerError::Database(e.to_string()))?;

    Ok(LicenseRecord {
        id:                     row.get(0).map_err(|e| ServerError::Database(e.to_string()))?,
        stripe_customer_id:     row.get(1).map_err(|e| ServerError::Database(e.to_string()))?,
        stripe_subscription_id: row.get(2).map_err(|e| ServerError::Database(e.to_string()))?,
        licensee:               row.get(3).map_err(|e| ServerError::Database(e.to_string()))?,
        email:                  row.get(4).map_err(|e| ServerError::Database(e.to_string()))?,
        tier:                   row.get(5).map_err(|e| ServerError::Database(e.to_string()))?,
        issued_at:              row.get(6).map_err(|e| ServerError::Database(e.to_string()))?,
        expires_at:             row.get(7).map_err(|e| ServerError::Database(e.to_string()))?,
        features:               row.get(8).map_err(|e| ServerError::Database(e.to_string()))?,
        license_json:           row.get(9).map_err(|e| ServerError::Database(e.to_string()))?,
        created_at,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a new UUID v4 as a lowercase hyphenated string.
pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}

//! # vledger-license-server
//!
//! **VectorGuard Labs internal service — not distributed to customers.**
//!
//! Receives Stripe webhooks, issues signed `license.json` files, stores them
//! in SQLite, and delivers them to customers via email and a pull endpoint.
//!
//! ## Configuration (environment variables)
//!
//! All configuration is read from environment variables at startup.  No
//! config file is required.  In production, inject these from your secrets
//! manager (AWS Secrets Manager, Vault, etc.).
//!
//! | Variable | Required | Description |
//! |---|---|---|
//! | `VLEDGER_LICENSE_SIGNING_KEY` | ✓ | Hex-encoded 32-byte Ed25519 private key |
//! | `STRIPE_WEBHOOK_SECRET` | ✓ | Stripe endpoint signing secret (`whsec_...`) |
//! | `RESEND_API_KEY` | ✓ | Resend API key (`re_...`) |
//! | `EMAIL_FROM` | ✓ | Sender address, e.g. `licenses@vectorguardlabs.com` |
//! | `BASE_URL` | ✓ | Public base URL of this server, e.g. `https://licenses.vectorguardlabs.com` |
//! | `DATABASE_PATH` | | Path to SQLite file (default: `./licenses.db`) |
//! | `BIND_ADDR` | | Bind address (default: `0.0.0.0:8080`) |
//!
//! ## Endpoints
//!
//! ```
//! POST /webhook                         Stripe webhook receiver
//! GET  /license/:token                  One-time 72-hour download link
//! GET  /license/current?token=<api_key> Long-lived pull endpoint (for cron)
//! GET  /health                          Uptime / readiness check
//! ```
//!
//! ## Startup sequence
//!
//! 1. Load and validate all required env vars — fail fast if any are missing.
//! 2. Open (or create) the SQLite database and run migrations.
//! 3. Validate the signing key by doing a test sign and verify.
//! 4. Start the Axum HTTP server.

mod db;
mod email;
mod error;
mod routes;
mod signing;
mod stripe;

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use reqwest::Client;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;

use db::Db;

// ── AppState ──────────────────────────────────────────────────────────────────

/// Shared application state passed to every handler via `Arc<AppState>`.
pub struct AppState {
    pub db:     Db,
    pub http:   Client,
    pub config: Config,
}

// ── Config ────────────────────────────────────────────────────────────────────

/// Server configuration loaded from environment variables at startup.
pub struct Config {
    /// Hex-encoded Ed25519 private signing key.
    pub license_signing_key:    String,
    /// Stripe webhook endpoint signing secret.
    pub stripe_webhook_secret:  String,
    /// Resend API key.
    pub resend_api_key:         String,
    /// Email sender address.
    pub email_from:             String,
    /// Public base URL of this server (used to build download links).
    pub base_url:               String,
}

impl Config {
    /// Load configuration from environment variables.
    /// Returns an error listing every missing variable so operators see all
    /// problems at once rather than one per startup attempt.
    fn from_env() -> Result<Self, String> {
        let mut missing: Vec<&str> = Vec::new();

        macro_rules! require {
            ($var:expr) => {
                std::env::var($var).unwrap_or_else(|_| {
                    missing.push($var);
                    String::new()
                })
            };
        }

        let license_signing_key   = require!("VLEDGER_LICENSE_SIGNING_KEY");
        let stripe_webhook_secret = require!("STRIPE_WEBHOOK_SECRET");
        let resend_api_key        = require!("RESEND_API_KEY");
        let email_from            = require!("EMAIL_FROM");
        let base_url              = require!("BASE_URL");

        if !missing.is_empty() {
            return Err(format!(
                "Missing required environment variables: {}",
                missing.join(", ")
            ));
        }

        Ok(Self {
            license_signing_key,
            stripe_webhook_secret,
            resend_api_key,
            email_from,
            base_url,
        })
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // ── Logging ───────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,vledger_license_server=debug")),
        )
        .with_target(true)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "vledger-license-server starting"
    );

    // ── Config ────────────────────────────────────────────────────────────
    let config = Config::from_env().unwrap_or_else(|e| {
        eprintln!("Configuration error: {e}");
        std::process::exit(1);
    });

    // ── Database ──────────────────────────────────────────────────────────
    let db_path = std::env::var("DATABASE_PATH")
        .unwrap_or_else(|_| "./licenses.db".to_string());

    let db = Db::open(std::path::Path::new(&db_path)).unwrap_or_else(|e| {
        eprintln!("Database error: {e}");
        std::process::exit(1);
    });

    info!(path = %db_path, "SQLite database opened");

    // ── Validate signing key ──────────────────────────────────────────────
    // Do a test sign at startup so a bad key fails loudly before the first
    // real webhook arrives.
    validate_signing_key(&config.license_signing_key).unwrap_or_else(|e| {
        eprintln!("Invalid VLEDGER_LICENSE_SIGNING_KEY: {e}");
        std::process::exit(1);
    });

    info!("License signing key validated");

    // ── HTTP client ───────────────────────────────────────────────────────
    let http = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to build HTTP client: {e}");
            std::process::exit(1);
        });

    // ── Shared state ──────────────────────────────────────────────────────
    let state = Arc::new(AppState { db, http, config });

    // ── Router ────────────────────────────────────────────────────────────
    let app = Router::new()
        .route("/health",           get(routes::health))
        .route("/webhook",          post(routes::stripe_webhook))
        // One-time 72-hour download link — :token must come before /current
        // to avoid Axum matching "current" as a token value.
        .route("/license/current",  get(routes::pull_license))
        .route("/license/:token",   get(routes::download_license))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // ── Bind ──────────────────────────────────────────────────────────────
    let bind_addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind to {bind_addr}: {e}");
            std::process::exit(1);
        });

    info!(addr = %bind_addr, "Listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            eprintln!("Server error: {e}");
            std::process::exit(1);
        });

    info!("Server shut down gracefully");
}

// ── Startup validation ────────────────────────────────────────────────────────

/// Verify the signing key is a valid 32-byte Ed25519 private key by doing
/// a test sign/verify round-trip.
fn validate_signing_key(hex_key: &str) -> Result<(), String> {
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| format!("not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes.try_into()
        .map_err(|_| "must be exactly 32 bytes (64 hex chars)".to_string())?;

    let signing_key  = SigningKey::from_bytes(&arr);
    let verifying_key = signing_key.verifying_key();
    let msg          = b"vledger-license-server startup self-test";
    let sig          = signing_key.sign(msg);

    verifying_key.verify(msg, &sig)
        .map_err(|e| format!("sign/verify round-trip failed: {e}"))?;

    Ok(())
}

// ── Graceful shutdown ─────────────────────────────────────────────────────────

/// Wait for SIGTERM or CTRL-C, then return so Axum can drain in-flight
/// requests before the process exits.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install CTRL-C handler");
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c  => { info!("Received CTRL-C — shutting down") },
        _ = sigterm => { info!("Received SIGTERM — shutting down") },
    }
}

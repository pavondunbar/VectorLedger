//! Standalone `vledger-mcp` binary.
//!
//! Starts a Model Context Protocol server backed by a VectorLedger data
//! directory.  Designed to run alongside `vledger start` — it opens the
//! data directory in read-only-compatible mode or connects via the direct
//! LedgerStore API when the main process is not running.
//!
//! ## Usage
//! ```text
//! vledger-mcp [OPTIONS]
//!
//! Options:
//!   --data-dir  <PATH>      VectorLedger data directory [default: ./vledger-data]
//!   --bind      <ADDR>      Listen address [default: 127.0.0.1:3000]
//!   --username  <USER>      Auth username [env: VLEDGER_CLI_USER]
//!   --password  <PASS>      Auth password [env: VLEDGER_CLI_PASSWORD]
//!   --log-level <LEVEL>     Tracing filter [default: info]
//! ```
//!
//! ## Environment variables
//! - `VLEDGER_CLI_USER`     — username (overridden by --username)
//! - `VLEDGER_CLI_PASSWORD` — password (overridden by --password)

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::info;

use vledger_mcp::{McpConfig, McpServer};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(clap::Parser, Debug)]
#[command(
    name        = "vledger-mcp",
    version     = env!("CARGO_PKG_VERSION"),
    about       = "Model Context Protocol server for VectorLedger",
    long_about  = None,
)]
struct Cli {
    /// VectorLedger data directory.
    #[arg(long, default_value = "./vledger-data")]
    data_dir: PathBuf,

    /// Address the MCP server will bind to.
    #[arg(long, default_value = "127.0.0.1:3000")]
    bind: String,

    /// Username for authenticating against the ledger's user store.
    /// Falls back to the VLEDGER_CLI_USER environment variable.
    #[arg(long)]
    username: Option<String>,

    /// Password for authentication.
    /// Falls back to the VLEDGER_CLI_PASSWORD environment variable.
    /// Prompted interactively if both are absent.
    #[arg(long)]
    password: Option<String>,

    /// Tracing log level filter (e.g. "info", "debug", "vledger_mcp=debug").
    #[arg(long, default_value = "info")]
    log_level: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    use clap::Parser;
    let cli = Cli::parse();

    // Initialise tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.parse().unwrap_or_default()),
        )
        .init();

    // Resolve credentials.
    let username = cli
        .username
        .or_else(|| std::env::var("VLEDGER_CLI_USER").ok())
        .unwrap_or_else(|| "admin".to_string());

    let password = cli
        .password
        .or_else(|| std::env::var("VLEDGER_CLI_PASSWORD").ok())
        .unwrap_or_default();

    // Open the data directory.
    if !cli.data_dir.exists() {
        anyhow::bail!(
            "Data directory {:?} does not exist.\n\
             Initialise first with `vledger init`.",
            cli.data_dir
        );
    }

    let catalog_dir = cli.data_dir.join("catalog");
    let user_store = Arc::new(
        vledger_server::UserStore::open(&catalog_dir)
            .context("Failed to open user store")?,
    );

    let ledger = Arc::new(RwLock::new(
        vledger_ledger::LedgerStore::open(&cli.data_dir)
            .context("Failed to open ledger")?,
    ));

    info!(
        data_dir = %cli.data_dir.display(),
        bind      = %cli.bind,
        username  = %username,
        "Starting vledger-mcp"
    );

    let config = McpConfig {
        bind: cli.bind,
        username,
        password,
        monthly_limit: vledger_mcp::LIMIT_UNLIMITED,
        data_dir: cli.data_dir.clone(),
        session_timeout_secs: 30 * 60, // 30 minutes
    };

    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    // Graceful shutdown on Ctrl-C.
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl-C");
        info!("Shutdown signal received");
        shutdown_clone.cancel();
    });

    McpServer::new(config, ledger, user_store)
        .run(shutdown)
        .await
}

//! # vledger — VectorLedger
//!
//! Cryptographically verifiable financial database engine.
//! Built by VectorGuard Labs.

mod backup;
mod key_rotation;
mod self_test;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "vledger",
    version = env!("CARGO_PKG_VERSION"),
    about = "VectorLedger — cryptographically verifiable financial database engine",
)]
struct Cli {
    #[arg(short, long, default_value = "./vledger-data", global = true)]
    data_dir: PathBuf,

    #[arg(short, long, default_value = "info", global = true)]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialise a new database at the data directory.
    Init {
        #[arg(long)]
        force: bool,
        /// Master key source backend.
        /// Choices: env, file, vault, aws_kms, pyhsm  (default: pyhsm)
        /// - pyhsm    : PyHSM Unix-socket daemon — default; requires running daemon
        /// - env      : read from VectorLedger_MASTER_KEY environment variable
        /// - file     : generate and store in vledger-data/keys/master_key.hex (dev only)
        /// - vault    : HashiCorp Vault KV v2 (set VAULT_TOKEN, --vault-addr, --vault-path)
        /// - aws_kms  : AWS KMS GenerateDataKey (set AWS credentials, --kms-key-id)
        #[arg(long, default_value = "pyhsm")]
        key_source: String,
        /// Vault server address (used with --key-source=vault).
        #[arg(long, default_value = "http://127.0.0.1:8200")]
        vault_addr: String,
        /// Vault KV v2 mount (used with --key-source=vault).
        #[arg(long, default_value = "secret")]
        vault_mount: String,
        /// Vault secret path (used with --key-source=vault).
        #[arg(long, default_value = "vledger/master_key")]
        vault_path: String,
        /// AWS KMS key ARN or alias (used with --key-source=aws_kms).
        #[arg(long)]
        kms_key_id: Option<String>,
        /// AWS region (used with --key-source=aws_kms).
        #[arg(long, default_value = "us-east-1")]
        kms_region: String,
        /// PyHSM Unix socket path (used with --key-source=pyhsm).
        /// Overrides the PYHSM_SOCKET_PATH environment variable.
        /// Default: /tmp/pyhsm.sock
        #[arg(long)]
        pyhsm_socket: Option<String>,
        /// Caller ID written to the PyHSM audit log (used with --key-source=pyhsm or remote-pyhsm).
        /// Default: vledger
        #[arg(long, default_value = "vledger")]
        pyhsm_caller_id: String,

        // ── Model 2: remote PyHSM over mTLS ───────────────────────────────
        /// Remote PyHSM HTTPS endpoint (selects --key-source=remote-pyhsm automatically).
        /// Example: https://pyhsm.internal.example.com:8443
        /// Overrides the PYHSM_ENDPOINT environment variable.
        #[arg(long)]
        pyhsm_endpoint: Option<String>,
        /// Path to the PEM file containing the CA certificate used to verify
        /// the remote PyHSM server's TLS certificate.
        /// Required when --pyhsm-endpoint is set.
        /// Overrides the PYHSM_CA_CERT environment variable.
        #[arg(long)]
        pyhsm_ca_cert: Option<String>,
        /// Path to VectorLedger's mTLS client certificate PEM file.
        /// Required for mutual TLS with the remote PyHSM daemon.
        /// Overrides the PYHSM_CLIENT_CERT environment variable.
        #[arg(long)]
        pyhsm_client_cert: Option<String>,
        /// Path to VectorLedger's mTLS client private key PEM file.
        /// Required when --pyhsm-client-cert is set.
        /// Overrides the PYHSM_CLIENT_KEY environment variable.
        #[arg(long)]
        pyhsm_client_key: Option<String>,
        /// Per-request timeout in milliseconds for remote PyHSM calls.
        /// Default: 5000
        /// Overrides the PYHSM_TIMEOUT_MS environment variable.
        #[arg(long, default_value_t = 5000)]
        pyhsm_timeout_ms: u64,
        /// Maximum number of retries on transient remote PyHSM errors.
        /// Default: 3
        #[arg(long, default_value_t = 3)]
        pyhsm_max_retries: u32,
    },
    /// Start the TLS 1.3 server and accept SQL connections.
    Start {
        #[arg(long, default_value = "127.0.0.1:5433")]
        bind: String,
        /// Also start the PostgreSQL wire-protocol listener on port 5432.
        #[arg(long)]
        pgwire: bool,
        /// Attach Merkle proofs to every SELECT response.
        #[arg(long)]
        with_proofs: bool,
        /// WAL sync mode: per_record | group_commit | no_sync (default: group_commit)
        #[arg(long, default_value = "group_commit")]
        wal_sync_mode: String,
        /// Group-commit flush interval in milliseconds (default: 2).
        #[arg(long, default_value_t = 2)]
        group_commit_delay_ms: u64,
        /// Maximum time in milliseconds a single SQL query may run before it
        /// is cancelled and the client receives a query_timeout error.
        #[arg(long, default_value_t = 30_000)]
        query_timeout_ms: u64,
        /// Bind address for the Prometheus metrics HTTP server.
        /// Set to empty string to disable.
        #[arg(long, default_value = "127.0.0.1:9090")]
        metrics_addr: String,
        /// Maximum number of concurrent client connections accepted by the
        /// server.  Applies to both the native TLS listener and the pgwire
        /// listener.  Increase this for high-concurrency / enterprise
        /// deployments.  Default: 128.
        #[arg(long, default_value_t = 128)]
        max_connections: usize,
    },
    /// Show database status.
    Status,
    /// Verify WAL and ledger chain integrity.
    ///
    /// With --self-test, runs a full integrity self-test against a fresh
    /// isolated database that never touches your production data.
    Verify {
        /// Run the full integrity self-test suite in an isolated database.
        #[arg(long)]
        self_test: bool,

        /// Number of entries to generate for the self-test.
        /// Presets: 10,000 (dev) | 100,000 (default) | 1,000,000 (enterprise).
        #[arg(long, default_value_t = 100_000)]
        entries: u64,

        /// Keep the self-test database after completion (for manual inspection).
        /// The test directory path is printed at the end.
        #[arg(long)]
        keep_data: bool,
    },
    /// Run SQL against the database (interactive REPL or single statement).
    ///
    /// When a server is running (default: 127.0.0.1:5433) the CLI connects
    /// over TLS — this is the correct mode when `vledger start` is active,
    /// because the server holds an exclusive file lock on the data directory.
    ///
    /// Requires valid credentials.  If neither --password nor
    /// VLEDGER_CLI_PASSWORD is supplied the CLI prompts interactively
    /// (recommended — avoids exposing credentials in process listings and
    /// shell history).
    ///
    /// ⚠  SECURITY: --password and VLEDGER_CLI_PASSWORD are provided for
    /// automation pipelines only.  --password exposes the credential in
    /// `ps` output and shell history.  VLEDGER_CLI_PASSWORD exposes it in
    /// /proc/<pid>/environ on Linux.  Prefer interactive prompts or a
    /// secrets-manager integration for production use.
    #[command(name = "sql")]
    Sql {
        /// SQL statement to run (omit for interactive REPL).
        #[arg(short, long)]
        query: Option<String>,
        /// Username to authenticate with.
        /// Falls back to VLEDGER_CLI_USER environment variable.
        #[arg(short, long)]
        username: Option<String>,
        /// Password for authentication (prompted interactively if omitted —
        /// the interactive prompt is the safest option).
        ///
        /// ⚠  SECURITY WARNING: supplying a password via this flag exposes it
        /// in `ps` output and your shell history.  For automation, prefer
        /// VLEDGER_CLI_PASSWORD (env var) or, better still, a secrets manager
        /// that injects credentials without touching the command line.
        /// Falls back to VLEDGER_CLI_PASSWORD environment variable.
        #[arg(short, long)]
        password: Option<String>,
        /// Connect to a running server instead of opening the data directory
        /// directly.  Use this whenever `vledger start` is active.
        /// Format: host:port  (default: 127.0.0.1:5433)
        #[arg(long)]
        server: Option<String>,
        /// Path to a PEM file containing the CA certificate used to verify the
        /// server's TLS certificate.
        ///
        /// Required when connecting to a server at a non-loopback address.
        /// For loopback connections (127.0.0.1 / ::1 / localhost) the self-
        /// signed certificate is accepted automatically.
        ///
        /// Example: --ca-cert /etc/vledger/ca.crt
        #[arg(long)]
        ca_cert: Option<String>,
    },
    /// Run the full Phase 2 self-test suite.
    #[command(name = "self-test")]
    SelfTest,
    /// Run the Phase 3 production-hardening self-test suite.
    #[command(name = "self-test-phase3")]
    SelfTestPhase3,

    // ── Phase 3 CLI ───────────────────────────────────────────────────────

    /// Create a point-in-time backup snapshot (tar archive + BLAKE3 manifest).
    Backup {
        /// Output path for the .tar archive.
        /// Defaults to ./vledger-backup-<timestamp>.tar
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Restore a backup snapshot to a target directory.
    Restore {
        /// Path to the .tar archive created by `vledger backup`.
        #[arg(short = 'f', long)]
        from: PathBuf,
        /// Target data directory to restore into.
        #[arg(short, long)]
        target: Option<PathBuf>,
        /// Overwrite existing data directory.
        #[arg(long)]
        force: bool,
    },
    /// Rotate all HSM key slots and record audit events.
    #[command(name = "rotate-keys")]
    RotateKeys {
        /// Path to the HSM daemon socket (default: /tmp/pyhsm.sock).
        /// For remote PyHSM, use --pyhsm-endpoint instead.
        #[arg(long)]
        hsm_socket: Option<String>,
        /// Caller identifier written to the audit log.
        #[arg(long, default_value = "vledger-admin")]
        caller_id: String,

        // ── Model 2: remote PyHSM ─────────────────────────────────────────
        /// Remote PyHSM HTTPS endpoint (Model 2).
        /// Example: https://pyhsm.internal.example.com:8443
        /// Overrides the PYHSM_ENDPOINT environment variable.
        #[arg(long)]
        pyhsm_endpoint: Option<String>,
        /// Path to the CA certificate PEM for verifying the remote PyHSM server.
        /// Required when --pyhsm-endpoint is set.
        #[arg(long)]
        pyhsm_ca_cert: Option<String>,
        /// Path to VectorLedger's mTLS client certificate PEM.
        #[arg(long)]
        pyhsm_client_cert: Option<String>,
        /// Path to VectorLedger's mTLS client private key PEM.
        #[arg(long)]
        pyhsm_client_key: Option<String>,
        /// Per-request timeout in milliseconds for remote PyHSM calls.
        /// Default: 5000
        #[arg(long, default_value_t = 5000)]
        pyhsm_timeout_ms: u64,
        /// Maximum number of retries on transient remote PyHSM errors.
        /// Default: 3
        #[arg(long, default_value_t = 3)]
        pyhsm_max_retries: u32,
    },
    /// Export the audit log to JSON or CSV.
    #[command(name = "audit-export")]
    AuditExport {
        /// Output format: json or csv (default: json).
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Start of date range (RFC 3339, default: beginning of log).
        #[arg(long)]
        from: Option<String>,
        /// End of date range (RFC 3339, default: now).
        #[arg(long)]
        to: Option<String>,
    },
    /// Generate a compliance report (soc2 or pci-dss).
    #[command(name = "compliance-report")]
    ComplianceReport {
        /// Standard to evaluate: soc2 or pci-dss.
        #[arg(long, default_value = "soc2")]
        standard: String,
        /// Output format: json or markdown (default: markdown).
        #[arg(long, default_value = "markdown")]
        format: String,
        /// Output file path (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Manage user accounts (admin only).
    #[command(name = "user", subcommand_required = true)]
    User {
        #[command(subcommand)]
        action: UserAction,
        /// Path to a PEM file containing the CA certificate used to verify the
        /// server's TLS certificate when connecting to a running server.
        ///
        /// Required when the server is at a non-loopback address.
        #[arg(long, global = true)]
        ca_cert: Option<String>,
    },
    /// Verify a backup archive without restoring it (manifest + hash check).
    #[command(name = "backup-verify")]
    BackupVerify {
        /// Path to the .tar archive to verify.
        #[arg(short = 'f', long)]
        from: PathBuf,
        /// Verify encrypted file contents (requires master key from key_source.json).
        #[arg(long, default_value = "true")]
        decrypt: bool,
    },
    /// Show the active license tier, features, and expiry.
    #[command(name = "license")]
    License,
}

/// Sub-actions for `vledger user`.
#[derive(Subcommand)]
enum UserAction {
    /// Change a user's password.
    #[command(name = "set-password")]
    SetPassword {
        /// Username whose password will be changed.
        #[arg(short, long)]
        username: Option<String>,
        /// New password (prompted interactively if omitted).
        #[arg(long)]
        new_password: Option<String>,
    },
    /// Create a new user account (admin only).
    #[command(name = "create")]
    Create {
        /// Username for the new account.
        #[arg(short, long)]
        username: String,
        /// Role: admin, operator, auditor, readonly.
        #[arg(short, long, default_value = "readonly")]
        role: String,
        /// Password (prompted interactively if omitted).
        #[arg(long)]
        password: Option<String>,
    },
    /// List all user accounts.
    #[command(name = "list")]
    List,
    /// Enable or disable a user account.
    #[command(name = "set-enabled")]
    SetEnabled {
        #[arg(short, long)]
        username: String,
        /// true to enable, false to disable.
        #[arg(long)]
        enabled: bool,
    },
    /// Delete a user account.
    #[command(name = "delete")]
    Delete {
        #[arg(short, long)]
        username: String,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Install the aws-lc-rs crypto provider as the process-level default for
    // rustls. This must happen before any TLS acceptor or connector is built.
    // Without this, rustls 0.23+ panics when it cannot auto-detect a unique
    // provider (e.g. when both aws-lc-rs and ring are compiled in transitively).
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok(); // ok() — ignore the error if a provider was already installed

    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_target(true)
        .compact()
        .init();

    match cli.command {
        Commands::Init { force, key_source, vault_addr, vault_mount, vault_path, kms_key_id, kms_region, pyhsm_socket, pyhsm_caller_id, pyhsm_endpoint, pyhsm_ca_cert, pyhsm_client_cert, pyhsm_client_key, pyhsm_timeout_ms, pyhsm_max_retries }
            => cmd_init(&cli.data_dir, force, &key_source, &vault_addr, &vault_mount, &vault_path, kms_key_id.as_deref(), &kms_region, pyhsm_socket.as_deref(), &pyhsm_caller_id, pyhsm_endpoint.as_deref(), pyhsm_ca_cert.as_deref(), pyhsm_client_cert.as_deref(), pyhsm_client_key.as_deref(), pyhsm_timeout_ms, pyhsm_max_retries).await,
        Commands::Start { bind, pgwire, with_proofs, wal_sync_mode, group_commit_delay_ms, query_timeout_ms, metrics_addr, max_connections }
            => cmd_start(&cli.data_dir, &bind, pgwire, with_proofs, &wal_sync_mode, group_commit_delay_ms, query_timeout_ms, &metrics_addr, max_connections).await,
        Commands::Status                             => cmd_status(&cli.data_dir).await,
        Commands::Verify { self_test, entries, keep_data }  => {
            if self_test {
                crate::self_test::run(entries, keep_data).await
            } else {
                cmd_verify(&cli.data_dir).await
            }
        }
        Commands::Sql { query, username, password, server, ca_cert } => cmd_sql(&cli.data_dir, query.as_deref(), username.as_deref(), password.as_deref(), server.as_deref(), ca_cert.as_deref()).await,
        Commands::SelfTest                           => cmd_self_test().await,
        Commands::SelfTestPhase3                     => cmd_self_test_phase3().await,
        // Phase 3
        Commands::Backup { output }                  => cmd_backup(&cli.data_dir, output.as_deref()).await,
        Commands::Restore { from, target, force }    => cmd_restore(&from, target.as_deref(), &cli.data_dir, force).await,
        Commands::RotateKeys { hsm_socket, caller_id, pyhsm_endpoint, pyhsm_ca_cert, pyhsm_client_cert, pyhsm_client_key, pyhsm_timeout_ms, pyhsm_max_retries } => cmd_rotate_keys(&cli.data_dir, hsm_socket.as_deref(), &caller_id, pyhsm_endpoint.as_deref(), pyhsm_ca_cert.as_deref(), pyhsm_client_cert.as_deref(), pyhsm_client_key.as_deref(), pyhsm_timeout_ms, pyhsm_max_retries).await,
        Commands::AuditExport { format, output, from, to } => cmd_audit_export(&cli.data_dir, &format, output.as_deref(), from.as_deref(), to.as_deref()).await,
        Commands::ComplianceReport { standard, format, output } => cmd_compliance_report(&cli.data_dir, &standard, &format, output.as_deref()).await,
        Commands::User { action, ca_cert } => cmd_user(&cli.data_dir, action, ca_cert.as_deref()).await,
        Commands::License          => cmd_license(&cli.data_dir),
        Commands::BackupVerify { from, decrypt } => cmd_backup_verify(&cli.data_dir, &from, decrypt).await,
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

async fn cmd_init(
    data_dir:          &PathBuf,
    force:             bool,
    key_source:        &str,
    vault_addr:        &str,
    vault_mount:       &str,
    vault_path:        &str,
    kms_key_id:        Option<&str>,
    kms_region:        &str,
    pyhsm_socket:      Option<&str>,
    pyhsm_caller_id:   &str,
    pyhsm_endpoint:    Option<&str>,
    pyhsm_ca_cert:     Option<&str>,
    pyhsm_client_cert: Option<&str>,
    pyhsm_client_key:  Option<&str>,
    pyhsm_timeout_ms:  u64,
    pyhsm_max_retries: u32,
) -> Result<()> {
    if data_dir.exists() && !force {
        anyhow::bail!(
            "Data directory already exists: {}\nUse --force to reinitialise",
            data_dir.display()
        );
    }

    info!(data_dir = %data_dir.display(), "Initialising VectorLedger");

    let dirs = ["wal", "pages", "indexes", "catalog", "snapshots", "keys", "audit"];
    for d in &dirs {
        std::fs::create_dir_all(data_dir.join(d))
            .with_context(|| format!("Failed to create {d}"))?;
    }

    let signing_key   = vledger_crypto::sign::DbSigningKey::generate();
    let pubkey_hex    = hex::encode(signing_key.public_key().to_bytes());
    let privkey_hex   = hex::encode(signing_key.to_bytes());
    std::fs::write(data_dir.join("keys").join("db_signing_pubkey.hex"), &pubkey_hex)?;
    // Private key persisted with mode 0o600 — required for WAL commit signing.
    let privkey_path  = data_dir.join("keys").join("db_signing_key.hex");
    std::fs::write(&privkey_path, &privkey_hex)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&privkey_path, std::fs::Permissions::from_mode(0o600));
    }

    let _master_key = vledger_crypto::kdf::MasterKey::generate();
    std::fs::write(
        data_dir.join("keys").join("MASTER_KEY_PLACEHOLDER.txt"),
        "In production, store the master key in an HSM. Delete this file before deployment.\n",
    )?;

    // ── Task #3: configure and persist key source ──────────────────────
    {
        use vledger_secrets::{KeySourceConfig, FileProvider};

        let key_source_cfg = match key_source {
            "file" => {
                let key_path = data_dir.join("keys").join("master_key.hex");
                FileProvider::generate(&key_path)
                    .context("Failed to generate master key file")?;
                KeySourceConfig::File { path: key_path.display().to_string() }
            }
            "vault" => {
                KeySourceConfig::Vault {
                    addr:        vault_addr.to_string(),
                    mount:       vault_mount.to_string(),
                    secret_path: vault_path.to_string(),
                    field:       "value".to_string(),
                    namespace:   None,
                }
            }
            "aws_kms" => {
                let key_id = kms_key_id
                    .ok_or_else(|| anyhow::anyhow!("--kms-key-id is required for aws_kms key source"))?;
                KeySourceConfig::AwsKms {
                    key_id:             key_id.to_string(),
                    region:             kms_region.to_string(),
                    encryption_context: std::collections::HashMap::new(),
                }
            }
            "pyhsm" => {
                // Resolve socket path: CLI flag → env var → platform default.
                let socket = pyhsm_socket
                    .map(|s| s.to_string())
                    .or_else(|| std::env::var("PYHSM_SOCKET_PATH").ok())
                    .unwrap_or_else(|| vledger_hsm::default_pyhsm_address().to_string());
                KeySourceConfig::PyHsm {
                    socket_path: socket,
                    caller_id:   pyhsm_caller_id.to_string(),
                    key_id:      "vledger.master-key".to_string(),
                }
            }
            // Model 2: explicitly requested, or auto-detected when --pyhsm-endpoint is supplied.
            "remote-pyhsm" | "pyhsm-remote" => {
                let endpoint = pyhsm_endpoint
                    .map(|s| s.to_string())
                    .or_else(|| std::env::var("PYHSM_ENDPOINT").ok())
                    .ok_or_else(|| anyhow::anyhow!(
                        "--pyhsm-endpoint (or PYHSM_ENDPOINT) is required for remote-pyhsm key source"
                    ))?;
                let ca_cert = pyhsm_ca_cert
                    .map(|s| s.to_string())
                    .or_else(|| std::env::var("PYHSM_CA_CERT").ok())
                    .ok_or_else(|| anyhow::anyhow!(
                        "--pyhsm-ca-cert (or PYHSM_CA_CERT) is required for remote-pyhsm key source"
                    ))?;
                KeySourceConfig::RemotePyHsm {
                    endpoint,
                    ca_cert,
                    client_cert: pyhsm_client_cert
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("PYHSM_CLIENT_CERT").ok()),
                    client_key:  pyhsm_client_key
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("PYHSM_CLIENT_KEY").ok()),
                    timeout_ms:  std::env::var("PYHSM_TIMEOUT_MS")
                        .ok().and_then(|v| v.parse().ok())
                        .unwrap_or(pyhsm_timeout_ms),
                    max_retries: pyhsm_max_retries,
                    caller_id:   pyhsm_caller_id.to_string(),
                    key_id:      "vledger.master-key".to_string(),
                }
            }
            _ => {
                // Explicit --key-source env, or unrecognised value: fall back to env var.
                KeySourceConfig::Env { var: "VectorLedger_MASTER_KEY".to_string() }
            }
        };

        let key_source_path = data_dir.join("keys").join("key_source.json");
        key_source_cfg.save_to_file(&key_source_path)
            .context("Failed to write key_source.json")?;

        println!("  Key source : {key_source}");
        match &key_source_cfg {
            KeySourceConfig::Env { var } =>
                println!("  ⚠  Set ${var} before starting the server."),
            KeySourceConfig::File { path } =>
                println!("  ⚠  Master key written to {path} — move to a secrets manager before production."),
            KeySourceConfig::Vault { addr, secret_path, .. } =>
                println!("  Vault: {addr} → {secret_path}"),
            KeySourceConfig::AwsKms { key_id, region, .. } =>
                println!("  AWS KMS: {key_id} in {region}"),
            KeySourceConfig::PyHsm { socket_path, key_id, .. } =>
                println!("  PyHSM (local): socket={socket_path}  wrapping-key={key_id}"),
            KeySourceConfig::RemotePyHsm { endpoint, key_id, client_cert, .. } => {
                println!("  PyHSM (remote mTLS): endpoint={endpoint}  wrapping-key={key_id}");
                if client_cert.is_some() {
                    println!("  mTLS client cert : configured");
                } else {
                    println!("  mTLS client cert : ⚠  not set — server-auth only");
                }
            }
        }
    }

    std::fs::write(
        data_dir.join("catalog").join("VERSION"),
        format!("vledger_version={}\ncreated_at={}\npubkey={}\n",
            env!("CARGO_PKG_VERSION"), chrono::Utc::now().to_rfc3339(), pubkey_hex),
    )?;

    println!("✓ VectorLedger initialised at: {}", data_dir.display());
    println!("  Signing key (first 16 hex): {}", &pubkey_hex[..16]);
    for d in &dirs { println!("    {d}"); }
    println!("\n  Master key source stored in: keys/key_source.json");
    Ok(())
}

// ── start ─────────────────────────────────────────────────────────────────────

async fn cmd_start(data_dir: &PathBuf, bind: &str, pgwire: bool, with_proofs: bool, wal_sync_mode: &str, group_commit_delay_ms: u64, query_timeout_ms: u64, metrics_addr: &str, max_connections: usize) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Data directory not found — run `vledger init` first.");
    }

    // ── Fix #7: no_sync production guard ──────────────────────────────────
    // NoSync mode never calls fsync — any crash between a COMMIT and the next
    // OS writeback loses committed transactions permanently.  Refuse to start
    // against a data directory that already contains committed WAL segments
    // unless the operator explicitly acknowledges the risk.  In all cases emit
    // a loud error so the setting cannot be silently deployed to production.
    if wal_sync_mode == "no_sync" {
        let wal_dir = data_dir.join("wal");
        let has_existing_data = wal_dir.exists()
            && std::fs::read_dir(&wal_dir)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);

        if has_existing_data {
            anyhow::bail!(
                "⛔  REFUSED: --wal-sync-mode=no_sync is set but the WAL directory \
                 already contains committed data at '{}'.\n\
                 Starting with no_sync against existing data risks silent, permanent \
                 data loss on the next crash.\n\
                 Use --wal-sync-mode=group_commit (recommended) or \
                 --wal-sync-mode=per_record instead.\n\
                 If you genuinely need no_sync for a dev/test database with \
                 pre-existing data, delete the WAL directory first.",
                wal_dir.display()
            );
        }

        // Even for a fresh database, make the danger impossible to miss.
        tracing::error!(
            "⚠  WAL sync mode is NO_SYNC — fsync is NEVER called. \
             Committed transactions will be lost on a crash or power failure. \
             THIS SETTING MUST NOT BE USED IN PRODUCTION."
        );
    }

    // ── License check ─────────────────────────────────────────────────────
    let license = vledger_license::LicenseStore::load_or_free(data_dir);

    if pgwire {
        license.require_feature(vledger_license::Feature::PgWire)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    info!("Opening ledger at {}", data_dir.display());
    let ledger = std::sync::Arc::new(tokio::sync::RwLock::new(
        vledger_ledger::LedgerStore::open(data_dir)
            .context("Failed to open ledger")?
    ));

    // Write a ServerStarted audit event so audit/audit.log is created on
    // first start. This satisfies CC6.2 (audit trail present) and ensures
    // the compliance check passes even before any SQL has been executed.
    {
        let audit_path = data_dir.join("audit").join("audit.log");
        match vledger_audit::AuditLog::open(&audit_path) {
            Ok(log) => {
                let _ = log.append(vledger_audit::AuditEventKind::ServerStarted {
                    bind_addr: bind.to_string(),
                    version:   env!("CARGO_PKG_VERSION").to_string(),
                });
            }
            Err(e) => {
                tracing::warn!("Failed to open audit log at startup: {e}");
            }
        }
    }

    let config = vledger_server::ServerConfig {
        bind_addr: bind.to_string(),
        attach_proofs: with_proofs,
        wal_sync_mode: wal_sync_mode.parse()
            .unwrap_or_else(|e| {
                eprintln!("⚠  Invalid --wal-sync-mode '{wal_sync_mode}': {e}. Defaulting to group_commit.");
                vledger_wal::WalSyncMode::GroupCommit
            }),
        group_commit_delay_ms,
        query_timeout_ms,
        max_connections,
        ..Default::default()
    };

    println!("── VectorLedger ────────────────────────────────");
    println!("  Listening  : {bind}  (TLS 1.3)");
    println!("  Data dir   : {}", data_dir.display());
    println!("  Proofs     : {with_proofs}");
    println!("  Protocol   : newline-delimited JSON");
    println!("  WAL sync   : {wal_sync_mode}{}",
        if wal_sync_mode == "group_commit" {
            format!("  (flush every {group_commit_delay_ms} ms)")
        } else {
            String::new()
        }
    );
    println!("  Query limit: {}",
        if query_timeout_ms == 0 {
            "none (⚠  disabled — not recommended for production)".to_string()
        } else {
            format!("{query_timeout_ms} ms")
        }
    );
    if !metrics_addr.is_empty() {
        println!("  Metrics    : http://{metrics_addr}/metrics  (Prometheus)");
    }
    license.print_banner();
    if pgwire {
        println!("  PgWire     : 127.0.0.1:5432  (PostgreSQL wire protocol)");
    }
    println!("──────────────────────────────────────────────────");

    // ── Graceful shutdown: wire SIGTERM and CTRL-C to a CancellationToken ──
    let shutdown = tokio_util::sync::CancellationToken::new();
    {
        let token = shutdown.clone();
        tokio::spawn(async move {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            let mut sigterm = {
                use tokio::signal::unix::{signal, SignalKind};
                signal(SignalKind::terminate()).expect("failed to install SIGTERM handler")
            };
            #[cfg(unix)]
            tokio::select! {
                _ = ctrl_c                  => tracing::info!("CTRL-C received — shutting down"),
                _ = sigterm.recv()          => tracing::info!("SIGTERM received — shutting down"),
            }
            #[cfg(not(unix))]
            { ctrl_c.await.ok(); tracing::info!("CTRL-C received — shutting down"); }
            token.cancel();
        });
    }

    let catalog_dir_str = data_dir.join("catalog")
        .to_string_lossy().to_string();
    let mut config_with_catalog = config.clone();
    config_with_catalog.catalog_dir = Some(catalog_dir_str);

    let user_store = std::sync::Arc::new(
        vledger_server::UserStore::open(&data_dir.join("catalog"))
            .context("Failed to open user store")?
    );

    if pgwire {
        let pg_config = vledger_pgwire::PgWireConfig {
            bind_addr:       "127.0.0.1:5432".into(),
            database:        "vledger".into(),
            attach_proofs:   with_proofs,
            tls_cert_path:   None,
            tls_key_path:    None,
            tls_hostname:    "localhost".into(),
            catalog_dir:     None,
            max_connections,
        };
        let pg_server = vledger_pgwire::PgWireServer::new_shared(
            pg_config,
            std::sync::Arc::clone(&ledger),
            std::sync::Arc::clone(&user_store),
        );
        let pg_token = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = pg_server.run(pg_token).await {
                tracing::error!("PgWire server error: {e}");
            }
        });
    }

    // ── Prometheus metrics server ─────────────────────────────────────────
    if !metrics_addr.is_empty() {
        let metrics     = vledger_server::Metrics::new();
        let metrics_tok = shutdown.clone();
        let addr        = metrics_addr.to_string();
        tokio::spawn(async move {
            if let Err(e) = vledger_server::run_metrics_server(addr, metrics, metrics_tok).await {
                tracing::warn!("Metrics server error: {e}");
            }
        });
    }

    vledger_server::Server::new_shared(config_with_catalog, ledger, user_store)
        .run(shutdown)
        .await
        .context("Server error")
}

// ── status ────────────────────────────────────────────────────────────────────

async fn cmd_status(data_dir: &PathBuf) -> Result<()> {
    if !data_dir.exists() {
        println!("Not initialised at: {}", data_dir.display());
        return Ok(());
    }
    if let Ok(v) = std::fs::read_to_string(data_dir.join("catalog").join("VERSION")) {
        println!("── VectorLedger Status ─────────────────────────");
        println!("{}", v.trim());
    }
    let wal_dir = data_dir.join("wal");
    if wal_dir.exists() {
        let segs = vledger_wal::segment::list_segments(&wal_dir)?;
        println!("  WAL segments : {}", segs.len());
        if let Some(last) = segs.last() {
            println!("  Active seg   : {:020}", last);
        }
    }
    Ok(())
}

// ── verify ────────────────────────────────────────────────────────────────────

async fn cmd_verify(data_dir: &PathBuf) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }
    println!("── VectorLedger Integrity Verification ─────────");

    // WAL
    let wal_dir = data_dir.join("wal");
    print!("  WAL integrity            ... ");
    if wal_dir.exists() {
        let r = vledger_wal::recovery::recover(&wal_dir)?;
        if r.torn_write_detected {
            println!("⚠  TORN WRITE");
        } else {
            println!("✓ ({} committed txns)", r.committed.len());
        }
    } else {
        println!("N/A (no WAL yet)");
    }

    // Ledger hash chain
    print!("  Ledger hash chain        ... ");
    match vledger_ledger::LedgerStore::open(data_dir) {
        Ok(ledger) => {
            match ledger.verify_chain_integrity() {
                Ok(()) => println!("✓ ({} entries, tip={})",
                    ledger.entry_count(),
                    hex::encode(&ledger.chain_tip()[..8])),
                Err(e) => println!("✗ BROKEN: {e}"),
            }
        }
        Err(e) => println!("N/A ({e})"),
    }

    println!("\n✓ Verification complete");
    Ok(())
}

// ── sql ───────────────────────────────────────────────────────────────────────

async fn cmd_sql(
    data_dir: &PathBuf,
    query:    Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    server:   Option<&str>,
    ca_cert:  Option<&str>,
) -> Result<()> {
    // Resolve credentials first (needed for both network and direct modes).
    let resolved_username = resolve_username(username);
    let resolved_password = resolve_password(password);

    // ── Network mode: connect to a running server over TLS ────────────────
    // Use this when `vledger start` is running (it holds the data-dir lock).
    // Explicitly requested via --server, OR auto-detected by probing the
    // default address.
    let server_addr = server
        .map(|s| s.to_string())
        .or_else(|| {
            // Auto-detect: if the default port is reachable, prefer network mode.
            let addr = "127.0.0.1:5433";
            if std::net::TcpStream::connect_timeout(
                &addr.parse().unwrap(),
                std::time::Duration::from_millis(200),
            ).is_ok() {
                Some(addr.to_string())
            } else {
                None
            }
        });

    if let Some(addr) = server_addr {
        return cmd_sql_network(&addr, query, &resolved_username, &resolved_password, ca_cert).await;
    }

    // ── Direct mode: open the data directory (only safe when server is NOT running) ──
    if !data_dir.exists() {
        anyhow::bail!(
            "Not initialised and no running server found.\n\
             Run `vledger init` then `vledger start`, or pass --server <host:port>."
        );
    }

    let catalog_dir = data_dir.join("catalog");
    let user_store = vledger_server::UserStore::open(&catalog_dir)
        .context("Failed to open user store — run `vledger start` to initialise auth")?;

    let session = user_store.authenticate(&resolved_username, &resolved_password)
        .map_err(|_| anyhow::anyhow!("Authentication failed"))?;

    info!(
        username = %session.username,
        role     = %session.role,
        "CLI authenticated"
    );

    let mut ledger = vledger_ledger::LedgerStore::open(data_dir)
        .context("Failed to open ledger")?;

    if let Some(sql) = query {
        run_sql_authenticated(&mut ledger, sql, &session)?;
    } else {
        println!("VectorLedger SQL REPL — authenticated as {} ({})", session.username, session.role);
        println!("  Data dir: {} | Type 'exit' or Ctrl-D to quit", data_dir.display());
        println!();
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            print!("vledger> ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            line.clear();
            if stdin.read_line(&mut line).unwrap_or(0) == 0 { break; }
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            if trimmed == "exit" || trimmed == "\\q" { break; }
            if let Err(e) = run_sql_authenticated(&mut ledger, trimmed, &session) {
                eprintln!("Error: {e}");
            }
        }
    }
    Ok(())
}

/// Connect to a running vledger server over TLS and run SQL.
async fn cmd_sql_network(
    addr:     &str,
    query:    Option<&str>,
    username: &str,
    password: &str,
    ca_cert:  Option<&str>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    let host_part = addr.split(':').next().unwrap_or("127.0.0.1");
    let port: u16 = addr.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(5433);

    // Fix #1: only accept self-signed / unverified certificates when the
    // target is a loopback address.  For any non-loopback address the caller
    // MUST supply --ca-cert; failing to do so produces a hard error so the
    // danger cannot be silently ignored.
    let is_loopback = host_part == "127.0.0.1"
        || host_part == "::1"
        || host_part.eq_ignore_ascii_case("localhost");

    let tls_config: ClientConfig = if let Some(ca_path) = ca_cert {
        // CA-verified mode: load the supplied PEM and verify normally.
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("Cannot read CA certificate: {ca_path}"))?;
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            root_store.add(cert.context("Invalid CA certificate DER")?)
                .context("Failed to add CA certificate to root store")?;
        }
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else if is_loopback {
        // Loopback-only: self-signed cert accepted, with a visible warning.
        tracing::warn!(
            "TLS certificate verification is DISABLED for loopback connection to {addr}. \
             Use --ca-cert <path> to enable verification."
        );
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
            .with_no_client_auth()
    } else {
        // Non-loopback without --ca-cert: refuse with an actionable error.
        anyhow::bail!(
            "TLS certificate verification is required for non-loopback connections.\n\
             Provide the server's CA certificate with --ca-cert <path>.\n\
             Example: vledger sql --server {addr} --ca-cert /etc/vledger/ca.crt\n\n\
             If this is a development server with a self-signed certificate,\
             connect via loopback (127.0.0.1) or copy the server's\
             catalog/tls_cert.pem and pass it as --ca-cert."
        );
    };

    let connector  = TlsConnector::from(std::sync::Arc::new(tls_config));

    let tcp = tokio::net::TcpStream::connect((host_part, port)).await
        .with_context(|| format!("Cannot connect to server at {addr}"))?;

    let server_name = ServerName::try_from(host_part.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid server hostname: {host_part}"))?;
    let tls = connector.connect(server_name, tcp).await
        .context("TLS handshake failed")?;

    // Split into read/write halves with concrete types so the compiler can
    // infer `R` in `BufReader<R>` without ambiguity.
    let (read_half, mut write_half) =
        tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();

    // ── Authenticate ──────────────────────────────────────────────────────
    let auth_req = serde_json::json!({
        "auth": { "username": username, "password": password }
    });
    write_half.write_all(format!("{}\n", auth_req).as_bytes()).await?;
    write_half.flush().await?;

    let auth_line = lines.next_line().await?
        .ok_or_else(|| anyhow::anyhow!("Server closed connection during auth"))?;
    let auth_resp: serde_json::Value = serde_json::from_str(&auth_line)
        .context("Invalid auth response from server")?;

    if !auth_resp["ok"].as_bool().unwrap_or(false) {
        anyhow::bail!(
            "Authentication failed: {}",
            auth_resp["error"].as_str().unwrap_or("unknown error")
        );
    }

    let token = auth_resp["token"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Server did not return a session token"))?
        .to_string();
    let role = auth_resp["role"].as_str().unwrap_or("unknown");

    // ── Helper: send one SQL and print the response ───────────────────────
    macro_rules! send_sql {
        ($sql:expr) => {{
            let req = serde_json::json!({ "sql": $sql, "token": token });
            write_half.write_all(format!("{}\n", req).as_bytes()).await?;
            write_half.flush().await?;
            let resp_line = lines.next_line().await?
                .ok_or_else(|| anyhow::anyhow!("Server closed connection"))?;
            serde_json::from_str::<serde_json::Value>(&resp_line)
                .context("Invalid response from server")?
        }};
    }

    let print_response = |resp: &serde_json::Value, expanded: bool| {
        if !resp["ok"].as_bool().unwrap_or(false) {
            eprintln!("Error: {}", resp["error"].as_str().unwrap_or("unknown"));
            return;
        }
        let cols: Vec<&str> = resp["columns"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let rows = resp["rows"].as_array();

        if expanded && !cols.is_empty() {
            // ── Expanded (vertical) display — like psql \x ────────────────
            let col_width = cols.iter().map(|c| c.len()).max().unwrap_or(0);
            if let Some(rows) = rows {
                for (i, row) in rows.iter().enumerate() {
                    println!("─────────────────────── [ row {} ]", i + 1);
                    if let Some(vals) = row.as_array() {
                        for (col, val) in cols.iter().zip(vals.iter()) {
                            let v = val.as_str()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| val.to_string());
                            println!("{:>width$} │ {}", col, v, width = col_width);
                        }
                    }
                }
                if rows.is_empty() {
                    println!("(0 rows)");
                }
            }
        } else if !cols.is_empty() {
            // ── Normal (horizontal) display ───────────────────────────────
            // Calculate column widths: max of header width and widest value.
            let all_vals: Vec<Vec<String>> = rows.map(|rs| {
                rs.iter().map(|row| {
                    row.as_array().map(|vals| {
                        vals.iter().map(|v| {
                            v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string())
                        }).collect::<Vec<_>>()
                    }).unwrap_or_default()
                }).collect()
            }).unwrap_or_default();

            let widths: Vec<usize> = cols.iter().enumerate().map(|(i, c)| {
                let val_max = all_vals.iter()
                    .filter_map(|r| r.get(i))
                    .map(|v| v.len())
                    .max()
                    .unwrap_or(0);
                c.len().max(val_max)
            }).collect();

            // Header row.
            let header: Vec<String> = cols.iter().zip(widths.iter())
                .map(|(c, w)| format!("{:<width$}", c, width = w))
                .collect();
            println!("{}", header.join(" │ "));

            // Separator.
            let sep: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
            println!("{}", sep.join("─┼─"));

            // Data rows.
            for row_vals in &all_vals {
                let cells: Vec<String> = widths.iter().enumerate().map(|(i, w)| {
                    let v = row_vals.get(i).map(|s| s.as_str()).unwrap_or("");
                    format!("{:<width$}", v, width = w)
                }).collect();
                println!("{}", cells.join(" │ "));
            }
        }

        println!("── {}", resp["message"].as_str().unwrap_or(""));
        println!();
    };

    if let Some(sql) = query {
        // Single-shot mode — always normal display.
        let resp = send_sql!(sql);
        print_response(&resp, false);
    } else {
        // Interactive REPL.
        let mut expanded = false;
        println!("VectorLedger SQL REPL — connected to {addr} as {username} ({role})");
        println!("  Type 'exit' or Ctrl-D to quit. Use \\x to toggle expanded display.");
        println!();
        let stdin = std::io::stdin();
        let mut line = String::new();
        loop {
            let prompt = if expanded { "vledger (expanded)> " } else { "vledger> " };
            print!("{prompt}");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            line.clear();
            if stdin.read_line(&mut line).unwrap_or(0) == 0 { break; }
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() { continue; }
            if trimmed == "exit" || trimmed == "\\q" { break; }

            // Handle REPL meta-commands (no server round-trip needed).
            if trimmed == "\\x" {
                expanded = !expanded;
                println!("Expanded display is {}.", if expanded { "on" } else { "off" });
                println!();
                continue;
            }
            if trimmed == "\\?" || trimmed == "\\help" {
                println!("  \\x        Toggle expanded (vertical) display");
                println!("  \\q        Quit");
                println!("  exit      Quit");
                println!("  \\?        Show this help");
                println!();
                continue;
            }

            let req = serde_json::json!({ "sql": trimmed, "token": token });
            if let Err(e) = write_half.write_all(format!("{}\n", req).as_bytes()).await
                .and(write_half.flush().await) {
                eprintln!("Connection error: {e}");
                break;
            }
            match lines.next_line().await {
                Ok(Some(resp_line)) => {
                    match serde_json::from_str::<serde_json::Value>(&resp_line) {
                        Ok(resp) => print_response(&resp, expanded),
                        Err(e)   => eprintln!("Bad response: {e}"),
                    }
                }
                Ok(None) => { eprintln!("Server closed connection."); break; }
                Err(e)   => { eprintln!("Read error: {e}"); break; }
            }
        }
    }

    Ok(())
}

/// A TLS certificate verifier that accepts any certificate.
///
/// Fix #1: this verifier is ONLY used when the target address resolves to a
/// loopback interface (127.0.0.1 / ::1 / localhost) and no --ca-cert was
/// supplied.  For any non-loopback address the CLI requires --ca-cert and
/// builds a verified `ClientConfig` instead, so this struct is never reached
/// for remote connections.
#[derive(Debug)]
struct AcceptAnyCert;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Credential helpers ────────────────────────────────────────────────────────

fn resolve_username(username: Option<&str>) -> String {
    username
        .map(|s| s.to_string())
        .or_else(|| std::env::var("VLEDGER_CLI_USER").ok())
        .unwrap_or_else(|| {
            use std::io::Write;
            print!("Username: ");
            let _ = std::io::stdout().flush();
            let mut u = String::new();
            let _ = std::io::stdin().read_line(&mut u);
            u.trim().to_string()
        })
}

fn resolve_password(password: Option<&str>) -> String {
    if let Some(pw) = password {
        // Credential was passed on the command line — emit a visible security
        // warning.  The flag is intentionally not hidden so operators notice
        // it appearing in shell history and process listings.
        eprintln!(
            "⚠  SECURITY: password supplied via --password flag. \
             This value is visible in `ps` output and your shell history. \
             Omit --password to be prompted interactively instead."
        );
        return pw.to_string();
    }
    if let Ok(pw) = std::env::var("VLEDGER_CLI_PASSWORD") {
        eprintln!(
            "⚠  SECURITY: password read from VLEDGER_CLI_PASSWORD environment variable. \
             On Linux this value is visible in /proc/<pid>/environ to other processes \
             running as the same user. \
             Prefer an interactive prompt or a secrets manager for production use."
        );
        return pw;
    }
    read_password_from_tty()
}

// ── backup-verify ─────────────────────────────────────────────────────────────

async fn cmd_backup_verify(
    data_dir: &PathBuf,
    from:     &std::path::Path,
    decrypt:  bool,
) -> Result<()> {
    if !from.exists() {
        anyhow::bail!("Archive not found: {}", from.display());
    }

    // Optionally load master key for decrypting encrypted file content.
    let master_key_opt: Option<vledger_crypto::kdf::MasterKey> = if decrypt {
        let key_source_path = data_dir.join("keys").join("key_source.json");
        let keys_dir = data_dir.join("keys");
        if key_source_path.exists() {
            match vledger_secrets::KeySourceConfig::from_file(&key_source_path) {
                Ok(cfg) => match vledger_secrets::build_provider(&cfg, Some(&keys_dir)) {
                    Ok(provider) => match provider.load_master_key().await {
                        Ok(raw_key) => Some(vledger_crypto::kdf::MasterKey::from_bytes(*raw_key)),
                        Err(e) => {
                            eprintln!("⚠  Could not load master key ({e}) — verifying manifest only.");
                            None
                        }
                    },
                    Err(e) => {
                        eprintln!("⚠  Could not build key provider ({e}) — verifying manifest only.");
                        None
                    }
                },
                Err(e) => {
                    eprintln!("⚠  Could not read key_source.json ({e}) — verifying manifest only.");
                    None
                }
            }
        } else {
            eprintln!("⚠  key_source.json not found — verifying manifest only.");
            None
        }
    } else {
        None
    };

    let report = backup::verify_backup(from, master_key_opt.as_ref())
        .context("Backup verification failed")?;

    report.print_summary();

    if !report.is_ok() {
        anyhow::bail!("Backup verification FAILED");
    }
    Ok(())
}

// ── license ───────────────────────────────────────────────────────────────────

fn cmd_license(data_dir: &PathBuf) -> Result<()> {
    let license = vledger_license::LicenseStore::load_or_free(data_dir);

    println!("── VectorLedger License ────────────────────────");
    println!("  Tier       : {}", license.tier);
    if license.is_signed {
        println!("  Licensee   : {}", license.licensee);
        println!("  Email      : {}", license.email);
        println!("  Issued     : {}", license.issued_at);
        println!("  Expires    : {}", license.expires_at);
        if let Some(days) = license.days_remaining() {
            if days < 0 {
                println!("  Status     : ⚠  EXPIRED ({} days ago)", -days);
            } else if days < 30 {
                println!("  Status     : ⚠  Expiring soon ({days} days remaining)");
            } else {
                println!("  Status     : Active ({days} days remaining)");
            }
        }
    } else {
        println!("  Status     : No license file found — running on Free tier");
        println!("  Upgrade    : https://vectorguardlabs.com/pricing");
    }
    println!("──────────────────────────────────────────────────");

    let all_features = [
        vledger_license::Feature::PgWire,
        vledger_license::Feature::Replication,
        vledger_license::Feature::Hsm,
        vledger_license::Feature::ComplianceReport,
        vledger_license::Feature::AuditExportUnlimited,
        vledger_license::Feature::MultiNode,
    ];

    println!("  Features:");
    for feature in &all_features {
        let enabled = license.has_feature(feature);
        let mark = if enabled { "✓" } else { "✗" };
        println!("    {mark} {feature}");
    }
    println!();

    if !license.is_signed {
        println!(
            "  Place a signed license.json in your data directory to unlock\n  \
             paid features. Contact sales@vectorguardlabs.com or visit\n  \
             https://vectorguardlabs.com/pricing"
        );
    }

    Ok(())
}

// ── user ──────────────────────────────────────────────────────────────────────

async fn cmd_user(data_dir: &PathBuf, action: UserAction, ca_cert: Option<&str>) -> Result<()> {
    // If the server is running, route through it so the in-memory UserStore
    // is updated. Direct disk writes behind the server's back would be lost
    // on the next authenticate call (server holds state in memory).
    let server_addr = {
        let addr = "127.0.0.1:5433";
        if std::net::TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            std::time::Duration::from_millis(200),
        ).is_ok() {
            Some(addr.to_string())
        } else {
            None
        }
    };

    if let Some(addr) = server_addr {
        return cmd_user_network(&addr, action, ca_cert).await;
    }

    // ── Direct mode: server is not running, safe to edit disk directly ───
    let catalog_dir = data_dir.join("catalog");
    if !catalog_dir.exists() {
        anyhow::bail!(
            "Data directory not initialised at: {}\nRun `vledger init` first.",
            data_dir.display()
        );
    }
    let store = vledger_server::UserStore::open(&catalog_dir)
        .context("Failed to open user store")?;

    match action {
        UserAction::SetPassword { username, new_password } => {
            let target = username.unwrap_or_else(|| resolve_username(None));
            let new_pw = new_password.unwrap_or_else(|| {
                let pw1 = prompt_new_password("New password: ");
                let pw2 = prompt_new_password("Confirm password: ");
                if pw1 != pw2 { eprintln!("Passwords do not match."); std::process::exit(1); }
                pw1
            });
            store.set_password(&target, &new_pw)
                .with_context(|| format!("Failed to set password for '{target}'"))?;
            println!("✓ Password updated for '{target}'.");
        }
        UserAction::Create { username, role, password } => {
            let role_parsed: vledger_server::auth::Role = role.parse()
                .map_err(|e: String| anyhow::anyhow!(e))?;
            let pw = password.unwrap_or_else(|| {
                let pw1 = prompt_new_password("Password: ");
                let pw2 = prompt_new_password("Confirm password: ");
                if pw1 != pw2 { eprintln!("Passwords do not match."); std::process::exit(1); }
                pw1
            });
            store.create_user(&username, &pw, role_parsed, None)
                .with_context(|| format!("Failed to create user '{username}'"))?;
            println!("✓ User '{username}' created with role '{role}'.");
        }
        UserAction::List => {
            let mut users = store.list_users();
            users.sort_by(|a, b| a.0.cmp(&b.0));
            println!("{:<20} {:<12} {}", "USERNAME", "ROLE", "ENABLED");
            println!("{}", "-".repeat(40));
            for (name, role, enabled) in users {
                println!("{:<20} {:<12} {}", name, role, enabled);
            }
        }
        UserAction::SetEnabled { username, enabled } => {
            store.set_enabled(&username, enabled)
                .with_context(|| format!("Failed to update '{username}'"))?;
            let state = if enabled { "enabled" } else { "disabled" };
            println!("✓ User '{username}' {state}.");
        }
        UserAction::Delete { username } => {
            store.delete_user(&username)
                .with_context(|| format!("Failed to delete '{username}'"))?;
            println!("✓ User '{username}' deleted.");
        }
    }
    Ok(())
}

/// Send a user management command to a running server over TLS.
async fn cmd_user_network(addr: &str, action: UserAction, ca_cert: Option<&str>) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    // Fix #1: same CA-cert / loopback logic as cmd_sql_network.
    let host_part = addr.split(':').next().unwrap_or("127.0.0.1");
    let port: u16 = addr.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(5433);

    let is_loopback = host_part == "127.0.0.1"
        || host_part == "::1"
        || host_part.eq_ignore_ascii_case("localhost");

    let tls_config: ClientConfig = if let Some(ca_path) = ca_cert {
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("Cannot read CA certificate: {ca_path}"))?;
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            root_store.add(cert.context("Invalid CA certificate DER")?)
                .context("Failed to add CA certificate to root store")?;
        }
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else if is_loopback {
        tracing::warn!(
            "TLS certificate verification is DISABLED for loopback connection to {addr}. \
             Use --ca-cert <path> to enable verification."
        );
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
            .with_no_client_auth()
    } else {
        anyhow::bail!(
            "TLS certificate verification is required for non-loopback connections.\n\
             Provide the server's CA certificate with --ca-cert <path>.\n\
             Example: vledger user --ca-cert /etc/vledger/ca.crt --server {addr} list"
        );
    };

    // Gather credentials for the admin user who is authorised to make changes.
    println!("Connecting to server at {addr} — admin credentials required.");
    let username = resolve_username(None);
    let password = resolve_password(None);

    // Collect the new password / other interactive prompts BEFORE opening
    // the TLS connection so the terminal is clean.
    let admin_cmd = match action {
        UserAction::SetPassword { username: target, new_password } => {
            let target = target.unwrap_or_else(|| {
                use std::io::Write;
                print!("Username to change: ");
                let _ = std::io::stdout().flush();
                let mut u = String::new();
                let _ = std::io::stdin().read_line(&mut u);
                u.trim().to_string()
            });
            let new_pw = new_password.unwrap_or_else(|| {
                let pw1 = prompt_new_password("New password: ");
                let pw2 = prompt_new_password("Confirm password: ");
                if pw1 != pw2 { eprintln!("Passwords do not match."); std::process::exit(1); }
                pw1
            });
            serde_json::json!({ "op": "set_password", "username": target, "new_password": new_pw })
        }
        UserAction::Create { username: target, role, password } => {
            let pw = password.unwrap_or_else(|| {
                let pw1 = prompt_new_password("Password: ");
                let pw2 = prompt_new_password("Confirm password: ");
                if pw1 != pw2 { eprintln!("Passwords do not match."); std::process::exit(1); }
                pw1
            });
            serde_json::json!({ "op": "create_user", "username": target, "password": pw, "role": role })
        }
        UserAction::List =>
            serde_json::json!({ "op": "list_users" }),
        UserAction::SetEnabled { username: target, enabled } =>
            serde_json::json!({ "op": "set_enabled", "username": target, "enabled": enabled }),
        UserAction::Delete { username: target } =>
            serde_json::json!({ "op": "delete_user", "username": target }),
    };

    // Connect.
    let connector = TlsConnector::from(std::sync::Arc::new(tls_config));
    let tcp = tokio::net::TcpStream::connect((host_part, port)).await
        .with_context(|| format!("Cannot connect to server at {addr}"))?;
    let server_name = ServerName::try_from(host_part.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid hostname: {host_part}"))?;
    let tls = connector.connect(server_name, tcp).await
        .context("TLS handshake failed")?;

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();

    // Authenticate first.
    let auth_req = serde_json::json!({ "auth": { "username": username, "password": password } });
    write_half.write_all(format!("{}\n", auth_req).as_bytes()).await?;
    write_half.flush().await?;

    let auth_line = lines.next_line().await?
        .ok_or_else(|| anyhow::anyhow!("Server closed connection during auth"))?;
    let auth_resp: serde_json::Value = serde_json::from_str(&auth_line)?;
    if !auth_resp["ok"].as_bool().unwrap_or(false) {
        anyhow::bail!("Authentication failed: {}",
            auth_resp["error"].as_str().unwrap_or("unknown"));
    }
    let token = auth_resp["token"].as_str()
        .ok_or_else(|| anyhow::anyhow!("No token in auth response"))?
        .to_string();

    // Send the admin command.
    let req = serde_json::json!({ "token": token, "admin": admin_cmd });
    write_half.write_all(format!("{}\n", req).as_bytes()).await?;
    write_half.flush().await?;

    let resp_line = lines.next_line().await?
        .ok_or_else(|| anyhow::anyhow!("Server closed connection"))?;
    let resp: serde_json::Value = serde_json::from_str(&resp_line)?;

    if !resp["ok"].as_bool().unwrap_or(false) {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }

    // Print list output if present.
    if let Some(rows) = resp["rows"].as_array() {
        if !rows.is_empty() {
            let cols: Vec<&str> = resp["columns"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            if !cols.is_empty() {
                println!("{:<20} {:<12} {}", cols[0], cols.get(1).unwrap_or(&""), cols.get(2).unwrap_or(&""));
                println!("{}", "-".repeat(40));
            }
            for row in rows {
                if let Some(vals) = row.as_array() {
                    let v: Vec<String> = vals.iter()
                        .map(|v| v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string()))
                        .collect();
                    println!("{:<20} {:<12} {}", v.get(0).map(|s| s.as_str()).unwrap_or(""),
                             v.get(1).map(|s| s.as_str()).unwrap_or(""),
                             v.get(2).map(|s| s.as_str()).unwrap_or(""));
                }
            }
        }
    }

    println!("✓ {}", resp["message"].as_str().unwrap_or("Done."));
    Ok(())
}

// ── Windows console echo suppression ─────────────────────────────────────────

/// Temporarily disable `ENABLE_ECHO_INPUT` on the Windows console stdin
/// handle while `f` runs, then restore the original mode.
///
/// Uses `windows-sys` `GetConsoleMode` / `SetConsoleMode` which are always
/// available on Windows console hosts (cmd.exe, PowerShell, Windows Terminal).
/// Falls back to a plain call if the handle is not a console (e.g. redirected).
#[cfg(windows)]
fn suppress_echo_windows<F: FnOnce() -> String>(f: F) -> String {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, SetConsoleMode, ENABLE_ECHO_INPUT,
    };

    let handle = std::io::stdin().as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut orig_mode: u32 = 0;
    let has_console = unsafe { GetConsoleMode(handle, &mut orig_mode) } != 0;

    if has_console {
        unsafe { SetConsoleMode(handle, orig_mode & !ENABLE_ECHO_INPUT) };
    }

    let result = f();

    if has_console {
        unsafe { SetConsoleMode(handle, orig_mode) };
    }

    result
}

fn prompt_new_password(prompt: &str) -> String {
    use std::io::Write;
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    // Reuse the same tty-echo-off logic.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        let orig = if unsafe { libc::tcgetattr(fd, &mut termios) } == 0 {
            let orig = termios;
            termios.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
            Some(orig)
        } else { None };
        let mut pw = String::new();
        let _ = std::io::stdin().read_line(&mut pw);
        println!();
        if let Some(orig) = orig {
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
        }
        pw.trim().to_string()
    }
    #[cfg(windows)]
    {
        suppress_echo_windows(|| {
            let mut pw = String::new();
            let _ = std::io::stdin().read_line(&mut pw);
            println!();
            pw.trim().to_string()
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut pw = String::new();
        let _ = std::io::stdin().read_line(&mut pw);
        pw.trim().to_string()
    }
}

/// Execute one SQL statement with full privilege enforcement.
fn run_sql_authenticated(
    ledger:  &mut vledger_ledger::LedgerStore,
    sql:     &str,
    session: &vledger_server::auth::Session,
) -> Result<()> {
    use vledger_sql::{executor::Executor, parser::parse_one, planner::LogicalPlanBuilder};
    use vledger_server::auth::check_plan_privilege;

    let stmt = parse_one(sql).map_err(|e| anyhow::anyhow!("Parse error: {e}"))?;
    let plan = LogicalPlanBuilder::plan(stmt).map_err(|e| anyhow::anyhow!("Plan error: {e}"))?;

    // Enforce RBAC on the resolved LogicalPlan — identical to the network path.
    check_plan_privilege(session, &plan)
        .map_err(|e| anyhow::anyhow!("Permission denied: {e}"))?;

    match Executor::with_proofs(ledger).execute(plan) {
        Err(e) => eprintln!("Error: {e}"),
        Ok(result) => {
            println!("{}", result.columns.join(" | "));
            println!("{}", "-".repeat(result.columns.iter().map(|c| c.len() + 3).sum::<usize>().max(40)));
            for row in &result.rows {
                let vals: Vec<String> = row.values.iter().map(|v| v.to_string()).collect();
                println!("{}", vals.join(" | "));
            }
            println!(
                "── {} | {}",
                result.message,
                if result.proof.is_some() { "proof attached ✓" } else { "no proof" }
            );
            if let Some(ref proof) = result.proof {
                println!("   Merkle root : {}", &hex::encode(proof.root)[..16]);
            }
            println!();
        }
    }
    Ok(())
}

/// Read a password from the terminal without echoing.
/// Uses `stty -echo` on Unix; falls back to a plain read if unavailable.
fn read_password_from_tty() -> String {
    use std::io::Write;
    print!("Password: ");
    let _ = std::io::stdout().flush();

    #[cfg(unix)]
    {
        // Disable echo, read, re-enable echo.
        use std::os::unix::io::AsRawFd;
        let fd = std::io::stdin().as_raw_fd();
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        let orig = if unsafe { libc::tcgetattr(fd, &mut termios) } == 0 {
            let orig = termios;
            termios.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
            Some(orig)
        } else {
            None
        };

        let mut pw = String::new();
        let _ = std::io::stdin().read_line(&mut pw);
        println!(); // newline after hidden input

        if let Some(orig) = orig {
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &orig) };
        }
        pw.trim().to_string()
    }

    #[cfg(windows)]
    {
        suppress_echo_windows(|| {
            let mut pw = String::new();
            let _ = std::io::stdin().read_line(&mut pw);
            println!();
            pw.trim().to_string()
        })
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Other platforms: plain read (no echo suppression)
        let mut pw = String::new();
        let _ = std::io::stdin().read_line(&mut pw);
        pw.trim().to_string()
    }
}

// ── self-test ─────────────────────────────────────────────────────────────────

async fn cmd_self_test() -> Result<()> {
    println!("── VectorLedger Phase 2 Self-Test ───────────────");

    // ── 1. Crypto primitives ────────────────────────────────────────────────
    print!("  [1/7] Hash chain             ... ");
    {
        use vledger_crypto::{hash::{ChainEntry, verify_chain}, ZERO_HASH};
        let e1 = ChainEntry::new(1, &ZERO_HASH, b"entry one");
        let e2 = ChainEntry::new(2, &e1.chain_hash, b"entry two");
        verify_chain(&[e1, e2]).unwrap();
    }
    println!("✓");

    print!("  [2/7] AES-256-GCM encryption ... ");
    {
        use vledger_crypto::encrypt::{EncryptionKey, encrypt, decrypt};
        let k = EncryptionKey::generate();
        let ct = encrypt(&k, b"secret financial row", Some(b"table=1")).unwrap();
        let pt = decrypt(&k, &ct, Some(b"table=1")).unwrap();
        assert_eq!(pt, b"secret financial row");
    }
    println!("✓");

    print!("  [3/7] Merkle proofs          ... ");
    {
        use vledger_crypto::merkle::merkle_proof;
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];
        for i in 0..items.len() {
            merkle_proof(&items, i).unwrap().verify().unwrap();
        }
    }
    println!("✓");

    // ── 2. WAL-backed ledger ────────────────────────────────────────────────
    print!("  [4/7] WAL-backed ledger      ... ");
    {
        use tempfile::TempDir;
        use vledger_ledger::{Account, AccountType, Amount, LedgerStore, entry::JournalEntryBuilder};
        let dir = TempDir::new().unwrap();
        let data = dir.path();
        std::fs::create_dir_all(data.join("wal")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();

        let (cash_id, rev_id) = {
            let mut store = LedgerStore::open(data).unwrap();
            let cash = store.create_account(Account::new("CASH","Cash",AccountType::Asset,"USD","test")).unwrap();
            let rev  = store.create_account(Account::new("REV","Revenue",AccountType::Income,"USD","test")).unwrap();
            let amt  = Amount::new(50_000).unwrap();
            let e = JournalEntryBuilder::new("Sale","test").debit(cash,amt,"USD").credit(rev,amt,"USD").build();
            store.post_entry(e).unwrap();
            (cash, rev)
        };

        // Reopen — WAL replay
        let store2 = LedgerStore::open(data).unwrap();
        assert_eq!(store2.balance(&cash_id), 50_000);
        assert_eq!(store2.balance(&rev_id),  50_000);
        store2.verify_chain_integrity().unwrap();
    }
    println!("✓");

    // ── 3. Page encryption ──────────────────────────────────────────────────
    print!("  [5/7] Page encryption        ... ");
    {
        use tempfile::TempDir;
        use vledger_crypto::encrypt::EncryptionKey;
        use vledger_pages::{Page, PageStore};
        let dir = TempDir::new().unwrap();
        let mut store = PageStore::open(dir.path()).unwrap();
        store.register_table_key(1, EncryptionKey::generate());
        let mut page = Page::new(0, 1);
        page.write_slot(b"encrypted ledger row").unwrap();
        page.seal();
        store.write_page(&page).unwrap();
        let loaded = store.read_page(1, 0).unwrap();
        assert_eq!(loaded.read_slot(0).unwrap(), b"encrypted ledger row");
    }
    println!("✓");

    // ── 4. SQL engine ───────────────────────────────────────────────────────
    print!("  [6/7] SQL engine             ... ");
    {
        use tempfile::TempDir;
        use vledger_ledger::LedgerStore;
        use vledger_sql::{executor::Executor, parser::parse_one, planner::LogicalPlanBuilder, result::Value};

        let dir = TempDir::new().unwrap();
        let data = dir.path();
        std::fs::create_dir_all(data.join("wal")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();
        let mut ledger = LedgerStore::open(data).unwrap();

        let run = |ledger: &mut LedgerStore, sql: &str| {
            let stmt = parse_one(sql).unwrap();
            let plan = LogicalPlanBuilder::plan(stmt).unwrap();
            Executor::new(ledger).execute(plan).unwrap()
        };

        run(&mut ledger, "INSERT INTO accounts (code,name,account_type,currency,domain) VALUES ('CASH','Cash','asset','USD','test')");
        run(&mut ledger, "INSERT INTO accounts (code,name,account_type,currency,domain) VALUES ('REV','Revenue','income','USD','test')");
        run(&mut ledger, "INSERT INTO ledger (description,debit_account,credit_account,amount,currency,domain) VALUES ('Sale','CASH','REV',99000,'USD','test')");

        let bal = run(&mut ledger, "SELECT BALANCE('CASH')");
        assert_eq!(bal.rows[0].get("balance"), Some(&Value::BigInt(99_000)));

        let chain = run(&mut ledger, "SELECT VERIFY_CHAIN()");
        assert_eq!(chain.rows[0].get("status"), Some(&Value::Text("OK".into())));
    }
    println!("✓");

    // ── 5. Verifiable query (Merkle proof) ──────────────────────────────────
    print!("  [7/7] Verifiable query proof  ... ");
    {
        use tempfile::TempDir;
        use vledger_ledger::LedgerStore;
        use vledger_sql::{executor::Executor, parser::parse_one, planner::LogicalPlanBuilder};

        let dir = TempDir::new().unwrap();
        let data = dir.path();
        std::fs::create_dir_all(data.join("wal")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();
        let mut ledger = LedgerStore::open(data).unwrap();

        let run = |ledger: &mut LedgerStore, sql: &str| {
            let stmt = parse_one(sql).unwrap();
            let plan = LogicalPlanBuilder::plan(stmt).unwrap();
            Executor::new(ledger).execute(plan).unwrap()
        };

        run(&mut ledger, "INSERT INTO accounts (code,name,account_type,currency,domain) VALUES ('A','Account A','asset','USD','test')");
        run(&mut ledger, "INSERT INTO accounts (code,name,account_type,currency,domain) VALUES ('B','Account B','income','USD','test')");
        for i in 1..=4u64 {
            run(&mut ledger, &format!("INSERT INTO ledger (description,debit_account,credit_account,amount,currency,domain) VALUES ('Tx{i}','A','B',{},  'USD','test')", i*1000));
        }

        // Execute with proofs
        let stmt = parse_one("SELECT * FROM ledger").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::with_proofs(&mut ledger).execute(plan).unwrap();

        assert_eq!(result.rows.len(), 4);
        let proof = result.proof.expect("proof must be attached");
        assert_eq!(proof.leaf_proofs.len(), 4);

        // Verify each leaf proof independently
        for leaf in &proof.leaf_proofs {
            let mut cur = leaf.leaf_hash;
            for step in &leaf.path {
                cur = if step.sibling_is_left {
                    vledger_crypto::hash::hash_node(&step.sibling, &cur)
                } else {
                    vledger_crypto::hash::hash_node(&cur, &step.sibling)
                };
            }
            assert_eq!(cur, proof.root, "Merkle proof verification failed");
        }
    }
    println!("✓");

    println!("\n✓ All Phase 2 self-tests passed.");
    println!("  Engine  : VectorLedger v{}", env!("CARGO_PKG_VERSION"));
    println!("  Builder : VectorGuard Labs");
    println!();
    println!("Phase 2 features active:");
    println!("  ✓ WAL-backed durable ledger with crash recovery");
    println!("  ✓ SQL interface (SELECT / INSERT / BALANCE / VERIFY_CHAIN)");
    println!("  ✓ Per-table AES-256-GCM encryption");
    println!("  ✓ Merkle proofs on every SELECT response");
    println!("  ✓ TLS 1.3 server (start with: vledger start)");
    Ok(())
}


// ── backup ────────────────────────────────────────────────────────────────────

async fn cmd_backup(data_dir: &PathBuf, output: Option<&std::path::Path>) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }
    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let default_name = format!("vledger-backup-{ts}.tar");
    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(&default_name));

    println!("── VectorLedger Backup ─────────────────────────");

    // Load the master key so backup files are AES-256-GCM encrypted.
    // Fall back to unencrypted if the key source is unavailable (e.g. HSM
    // not running in a recovery scenario), but warn loudly.
    let key_source_path = data_dir.join("keys").join("key_source.json");
    let keys_dir = data_dir.join("keys");
    let manifest = if key_source_path.exists() {
        match vledger_secrets::KeySourceConfig::from_file(&key_source_path) {
            Ok(cfg) => match vledger_secrets::build_provider(&cfg, Some(&keys_dir)) {
                Ok(provider) => match provider.load_master_key().await {
                    Ok(raw_key) => {
                        let master = vledger_crypto::kdf::MasterKey::from_bytes(*raw_key);
                        println!("  Encryption : AES-256-GCM (master key loaded)");
                        backup::create_backup_encrypted(data_dir, &out_path, &master)?
                    }
                    Err(e) => {
                        eprintln!("⚠  Could not load master key ({e}). Backup will be UNENCRYPTED.");
                        backup::create_backup(data_dir, &out_path)?
                    }
                },
                Err(e) => {
                    eprintln!("⚠  Could not build key provider ({e}). Backup will be UNENCRYPTED.");
                    backup::create_backup(data_dir, &out_path)?
                }
            },
            Err(e) => {
                eprintln!("⚠  Could not read key_source.json ({e}). Backup will be UNENCRYPTED.");
                backup::create_backup(data_dir, &out_path)?
            }
        }
    } else {
        eprintln!("⚠  key_source.json not found. Backup will be UNENCRYPTED.");
        backup::create_backup(data_dir, &out_path)?
    };

    println!("  Archive   : {}", out_path.display());
    if manifest.encrypted {
        println!("  Key sidecar: {}.key  (keep alongside archive for restore)", out_path.display());
    }
    println!("  Files     : {}", manifest.files.len());
    println!("  Created   : {}", manifest.created_at_rfc);
    println!("  Hash      : {}", &manifest.manifest_hash[..32]);
    println!("✓ Backup complete");
    Ok(())
}

// ── restore ───────────────────────────────────────────────────────────────────

async fn cmd_restore(
    from:     &std::path::Path,
    target:   Option<&std::path::Path>,
    data_dir: &PathBuf,
    force:    bool,
) -> Result<()> {
    let target = target
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.clone());

    println!("── VectorLedger Restore ────────────────────────");

    // Peek at the manifest inside the archive to decide whether to decrypt.
    // We attempt to load the master key from the *destination* data_dir's
    // key_source.json (the one that was present when the backup was made).
    // If unavailable, fall back to the unencrypted restore path with a warning.
    let key_source_path = data_dir.join("keys").join("key_source.json");
    let keys_dir = data_dir.join("keys");
    let manifest = if key_source_path.exists() {
        match vledger_secrets::KeySourceConfig::from_file(&key_source_path) {
            Ok(cfg) => match vledger_secrets::build_provider(&cfg, Some(&keys_dir)) {
                Ok(provider) => match provider.load_master_key().await {
                    Ok(raw_key) => {
                        let master = vledger_crypto::kdf::MasterKey::from_bytes(*raw_key);
                        // Try encrypted restore; if the archive is not
                        // encrypted the inner code will still work because
                        // restore_backup_encrypted falls through to plaintext
                        // when manifest.encrypted = false.
                        backup::restore_backup_encrypted(from, &target, force, &master)?
                    }
                    Err(e) => {
                        eprintln!("⚠  Could not load master key ({e}). Attempting unencrypted restore.");
                        backup::restore_backup(from, &target, force)?
                    }
                },
                Err(e) => {
                    eprintln!("⚠  Could not build key provider ({e}). Attempting unencrypted restore.");
                    backup::restore_backup(from, &target, force)?
                }
            },
            Err(e) => {
                eprintln!("⚠  Could not read key_source.json ({e}). Attempting unencrypted restore.");
                backup::restore_backup(from, &target, force)?
            }
        }
    } else {
        backup::restore_backup(from, &target, force)?
    };

    println!("  Archive   : {}", from.display());
    println!("  Target    : {}", target.display());
    println!("  Files     : {}", manifest.files.len());
    println!("  Backup ts : {}", manifest.created_at_rfc);
    println!("✓ Restore complete — run `vledger verify` to confirm integrity");
    Ok(())
}

// ── rotate-keys ───────────────────────────────────────────────────────────────

async fn cmd_rotate_keys(
    data_dir:          &PathBuf,
    hsm_socket:        Option<&str>,
    caller_id:         &str,
    pyhsm_endpoint:    Option<&str>,
    pyhsm_ca_cert:     Option<&str>,
    pyhsm_client_cert: Option<&str>,
    pyhsm_client_key:  Option<&str>,
    pyhsm_timeout_ms:  u64,
    pyhsm_max_retries: u32,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }
    println!("── VectorLedger Key Rotation ───────────────────");
    let rotated = key_rotation::rotate_keys(
        data_dir,
        hsm_socket,
        caller_id,
        pyhsm_endpoint,
        pyhsm_ca_cert,
        pyhsm_client_cert,
        pyhsm_client_key,
        pyhsm_timeout_ms,
        pyhsm_max_retries,
    ).await?;
    if rotated.is_empty() {
        println!("  No keys rotated (HSM may not be running or no keys found)");
    } else {
        for key_id in &rotated {
            println!("  ✓ {key_id}");
        }
        println!("  {} key(s) rotated", rotated.len());
    }
    println!("✓ Key rotation complete — audit events written");
    Ok(())
}

// ── audit-export ──────────────────────────────────────────────────────────────

async fn cmd_audit_export(
    data_dir: &PathBuf,
    format:   &str,
    output:   Option<&std::path::Path>,
    from:     Option<&str>,
    to:       Option<&str>,
) -> Result<()> {
    use vledger_audit::export::{export_csv, export_json, TimeRange};

    let log_path = data_dir.join("audit").join("audit.log");
    if !log_path.exists() {
        anyhow::bail!("Audit log not found at {}", log_path.display());
    }

    // Parse date range
    let range = {
        let from_dt = from.map(|s| chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&chrono::Utc))
            .context("Invalid --from date (use RFC 3339)"))
            .transpose()?;
        let to_dt = to.map(|s| chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&chrono::Utc))
            .context("Invalid --to date (use RFC 3339)"))
            .transpose()?;
        match (from_dt, to_dt) {
            (Some(f), Some(t)) => TimeRange::new(f, t),
            _ => TimeRange::all(),
        }
    };

    let count = if let Some(out_path) = output {
        let mut file = std::fs::File::create(out_path)
            .with_context(|| format!("Cannot create output file: {}", out_path.display()))?;
        match format {
            "csv"  => export_csv(&log_path, &range, &mut file)?,
            _      => export_json(&log_path, &range, &mut file)?,
        }
    } else {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        match format {
            "csv"  => export_csv(&log_path, &range, &mut out)?,
            _      => export_json(&log_path, &range, &mut out)?,
        }
    };

    eprintln!("Exported {count} audit events");
    Ok(())
}

// ── compliance-report ─────────────────────────────────────────────────────────

async fn cmd_compliance_report(
    data_dir:  &PathBuf,
    standard:  &str,
    format:    &str,
    output:    Option<&std::path::Path>,
) -> Result<()> {
    use vledger_compliance::{ComplianceEngine, ComplianceStandard, ReportDateRange};

    // ── License check ─────────────────────────────────────────────────────
    let license = vledger_license::LicenseStore::load_or_free(data_dir);
    license.require_feature(vledger_license::Feature::ComplianceReport)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let std_enum = match standard.to_lowercase().as_str() {
        "soc2" | "soc-2" => ComplianceStandard::Soc2,
        "pci"  | "pci-dss" | "pcidss" => ComplianceStandard::PciDss,
        other => anyhow::bail!("Unknown standard '{other}' — use: soc2 or pci-dss"),
    };

    let engine = ComplianceEngine::new(data_dir.clone());
    let report = engine.generate_report(std_enum, ReportDateRange::last_90_days())
        .context("Failed to generate compliance report")?;

    let content = match format.to_lowercase().as_str() {
        "json" => report.to_json().context("Failed to serialise report")?,
        _      => report.to_markdown(),
    };

    if let Some(out_path) = output {
        std::fs::write(out_path, &content)
            .with_context(|| format!("Cannot write report to {}", out_path.display()))?;
        eprintln!("Report written to {}", out_path.display());
    } else {
        println!("{content}");
    }
    eprintln!("{}", report.summary());
    Ok(())
}


// ── self-test-phase3 ──────────────────────────────────────────────────────────

async fn cmd_self_test_phase3() -> Result<()> {
    println!("── VectorLedger Phase 3 Self-Test ───────────────");

    // ── 1. Audit log (WORM append + chain verify + export) ─────────────
    print!("  [1/7] Audit log (WORM + chain)     ... ");
    {
        use tempfile::TempDir;
        use vledger_audit::{AuditEventKind, AuditLog};
        use vledger_audit::export::{export_json, export_csv, TimeRange};

        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        let log = AuditLog::open(&log_path).unwrap();

        log.append(AuditEventKind::AuthEvent {
            caller_id: "alice".into(), success: true, peer_addr: "127.0.0.1".into(),
        }).unwrap();
        log.append(AuditEventKind::EntryPosted {
            entry_id: vledger_ledger::entry::JournalEntryBuilder::new("x","x").build().id,
            entry_sequence: 1, domain: "test".into(),
            amount_sum: 50_000, caller_id: "alice".into(),
        }).unwrap();
        log.append(AuditEventKind::KeyRotated {
            key_id: "vledger.wal.signing".into(), caller_id: "admin".into(),
        }).unwrap();

        let count = log.verify_chain().unwrap();
        assert_eq!(count, 3);

        // JSON export
        let mut json_buf = Vec::new();
        let exported = export_json(&log_path, &TimeRange::all(), &mut json_buf).unwrap();
        assert_eq!(exported, 3);

        // CSV export
        let mut csv_buf = Vec::new();
        let exported = export_csv(&log_path, &TimeRange::all(), &mut csv_buf).unwrap();
        assert_eq!(exported, 3);
        let csv_str = String::from_utf8(csv_buf).unwrap();
        assert!(csv_str.contains("sequence,ts,kind"));
    }
    println!("✓");

    // ── 2. Four-eyes workflow ───────────────────────────────────────────
    print!("  [2/7] Four-eyes workflow           ... ");
    {
        use tempfile::TempDir;
        use vledger_foureyes::FourEyesQueue;

        let dir  = TempDir::new().unwrap();
        let queue = FourEyesQueue::open(dir.path()).unwrap();

        let fake_entry = b"fake-journal-entry-payload";
        let rec = queue.submit(fake_entry, "Sale", "test", "alice").unwrap();
        assert_eq!(queue.list_pending().len(), 1);

        // Self-approval must fail
        assert!(queue.approve(rec.id, "alice", |_| Ok(())).is_err());

        // Bob approves
        let approved = queue.approve(rec.id, "bob", |bytes| {
            assert_eq!(bytes, fake_entry);
            Ok(())
        }).unwrap();
        assert_eq!(approved.approver_id.as_deref(), Some("bob"));
        assert_eq!(queue.list_pending().len(), 0);

        // Test rejection path
        let rec2 = queue.submit(fake_entry, "Transfer", "test", "carol").unwrap();
        let rejected = queue.reject(rec2.id, "dave", "Insufficient documentation").unwrap();
        assert_eq!(rejected.reject_reason.as_deref(), Some("Insufficient documentation"));
        assert_eq!(queue.list_pending().len(), 0);
    }
    println!("✓");

    // ── 3. Compliance report (SOC 2) ────────────────────────────────────
    print!("  [3/7] Compliance report (SOC 2)    ... ");
    {
        use tempfile::TempDir;
        use vledger_compliance::{ComplianceEngine, ComplianceStandard, ReportDateRange};

        let dir = TempDir::new().unwrap();
        // Create minimal directory structure
        let data = dir.path();
        std::fs::create_dir_all(data.join("catalog")).unwrap();
        std::fs::create_dir_all(data.join("wal")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();
        std::fs::write(data.join("catalog").join("VERSION"), "vledger_version=0.1.0\n").unwrap();

        let engine = ComplianceEngine::new(data.to_path_buf());
        let report = engine.generate_report(
            ComplianceStandard::Soc2,
            ReportDateRange::last_90_days(),
        ).unwrap();

        assert!(!report.evidence.is_empty(), "SOC 2 report must contain evidence");
        let md = report.to_markdown();
        assert!(md.contains("Soc2"), "Markdown must contain standard name");
        let _json = report.to_json().unwrap();
    }
    println!("✓");

    // ── 4. Compliance report (PCI-DSS) ──────────────────────────────────
    print!("  [4/7] Compliance report (PCI-DSS)  ... ");
    {
        use tempfile::TempDir;
        use vledger_compliance::{ComplianceEngine, ComplianceStandard, ReportDateRange};

        let dir = TempDir::new().unwrap();
        let data = dir.path();
        std::fs::create_dir_all(data.join("catalog")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();
        std::fs::write(data.join("catalog").join("VERSION"), "vledger_version=0.1.0\n").unwrap();

        let engine = ComplianceEngine::new(data.to_path_buf());
        let report = engine.generate_report(
            ComplianceStandard::PciDss,
            ReportDateRange::last_year(),
        ).unwrap();
        assert!(!report.evidence.is_empty());
    }
    println!("✓");

    // ── 5. Backup & restore round-trip ──────────────────────────────────
    print!("  [5/7] Backup & restore round-trip  ... ");
    {
        use tempfile::TempDir;

        let src_dir = TempDir::new().unwrap();
        let data = src_dir.path();
        // Minimal data layout
        std::fs::create_dir_all(data.join("wal")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();
        std::fs::create_dir_all(data.join("catalog")).unwrap();
        std::fs::create_dir_all(data.join("audit")).unwrap();
        std::fs::create_dir_all(data.join("keys")).unwrap();
        std::fs::write(data.join("catalog").join("VERSION"), "vledger_version=0.1.0\n").unwrap();
        std::fs::write(data.join("wal").join("00000000000000000001.wal"), b"fake-wal-data").unwrap();
        std::fs::write(data.join("keys").join("db_signing_pubkey.hex"), b"deadbeef").unwrap();

        let archive_dir = TempDir::new().unwrap();
        let archive_path = archive_dir.path().join("test.tar");

        let manifest = backup::create_backup(data, &archive_path).unwrap();
        assert!(manifest.files.len() >= 2);
        assert!(manifest.verify());

        let restore_dir = TempDir::new().unwrap();
        let restored = backup::restore_backup(&archive_path, restore_dir.path(), true).unwrap();
        assert_eq!(restored.manifest_hash, manifest.manifest_hash);
        assert!(restore_dir.path().join("catalog").join("VERSION").exists());
    }
    println!("✓");

    // ── 6. PgWire message encoding ──────────────────────────────────────
    print!("  [6/7] PgWire message encoding      ... ");
    {
        use vledger_pgwire::*;
        // Verify all backend message builders produce valid framing
        let auth    = messages::auth_ok();
        assert_eq!(auth[0], b'R');
        let rd      = messages::row_description(&[messages::FieldDesc::text("balance")]);
        assert_eq!(rd[0], b'T');
        let dr      = messages::data_row(&[Some("99000".into())]);
        assert_eq!(dr[0], b'D');
        let cc      = messages::command_complete("SELECT 1");
        assert_eq!(cc[0], b'C');
        let rfq     = messages::ready_for_query(b'I');
        assert_eq!(rfq[0], b'Z');
        let err     = messages::error_response("ERROR", "42601", "syntax error");
        assert_eq!(err[0], b'E');
        // Verify length fields are consistent (len field at bytes 1-4 = payload+4)
        let cc_len  = u32::from_be_bytes([cc[1], cc[2], cc[3], cc[4]]) as usize;
        assert_eq!(cc_len, cc.len() - 1);
    }
    println!("✓");

    // ── 7. SQL optimizer (aggregate + window) ───────────────────────────
    print!("  [7/7] SQL optimizer (agg + window) ... ");
    {
        use tempfile::TempDir;
        use vledger_ledger::LedgerStore;
        use vledger_sql::{executor::Executor, parser::parse_one, planner::LogicalPlanBuilder};

        let dir  = TempDir::new().unwrap();
        let data = dir.path();
        std::fs::create_dir_all(data.join("wal")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();
        let mut ledger = LedgerStore::open(data).unwrap();

        let run = |ledger: &mut LedgerStore, sql: &str| {
            let stmt = parse_one(sql).unwrap();
            let plan = LogicalPlanBuilder::plan(stmt).unwrap();
            Executor::new(ledger).execute(plan).unwrap()
        };

        run(&mut ledger, "INSERT INTO accounts (code,name,account_type,currency,domain) VALUES ('A','Account A','asset','USD','test')");
        run(&mut ledger, "INSERT INTO accounts (code,name,account_type,currency,domain) VALUES ('B','Account B','income','USD','test')");
        for i in 1..=3u64 {
            run(&mut ledger, &format!(
                "INSERT INTO ledger (description,debit_account,credit_account,amount,currency,domain) \
                 VALUES ('Tx{i}','A','B',{},'USD','test')", i * 1000));
        }

        // Aggregate: COUNT
        let agg_sql = "SELECT COUNT(sequence) FROM ledger";
        let stmt = parse_one(agg_sql).unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::new(&mut ledger).execute(plan).unwrap();
        assert_eq!(result.rows.len(), 1, "Aggregate should produce 1 row");

        // Window: ROW_NUMBER() OVER ()
        let win_sql = "SELECT ROW_NUMBER() OVER () AS rn FROM ledger";
        let stmt = parse_one(win_sql).unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::new(&mut ledger).execute(plan).unwrap();
        assert_eq!(result.rows.len(), 3, "Window function should return all rows");
    }
    println!("✓");

    println!("\n✓ All Phase 3 self-tests passed.");
    println!("  Engine  : VectorLedger v{}", env!("CARGO_PKG_VERSION"));
    println!("  Builder : VectorGuard Labs");
    println!();
    println!("Phase 3 features active:");
    println!("  ✓ HSM PKCS#11 adapter (SoftHSM / AWS CloudHSM / Azure Dedicated HSM)");
    println!("  ✓ PostgreSQL wire protocol v3 (psql, pgAdmin, Metabase compatible)");
    println!("  ✓ Synchronous hot-standby WAL replication (primary + replica)");
    println!("  ✓ Query optimizer (joins, aggregates, window functions)");
    println!("  ✓ Client SDKs (Python, TypeScript, Go)");
    println!("  ✓ WORM audit log with BLAKE3 chain + JSON/CSV export");
    println!("  ✓ Compliance reporting (SOC 2 + PCI-DSS evidence generation)");
    println!("  ✓ Four-eyes workflow enforcement at the server layer");
    println!("  ✓ CLI: backup, restore, rotate-keys, audit-export, compliance-report");
    Ok(())
}

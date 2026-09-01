//! # vledger — VectorLedger
//!
//! Cryptographically verifiable financial database engine.
//! Built by VectorGuard Labs.

// Use jemalloc as the global allocator on Linux/macOS.
// jemalloc aggressively returns freed memory to the OS (unlike ptmalloc),
// preventing the ~7 GB RSS accumulation that occurs during WAL recovery
// when 25M+ records are processed and freed one at a time.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod audit_package;
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
    /// Start a WAL replication primary (Growth+ feature).
    /// Reads config from <data_dir>/replication.json.
    #[command(name = "start-primary")]
    StartPrimary {
        /// Bind address for the WAL shipper (overrides replication.json).
        #[arg(long)]
        bind: Option<String>,
    },
    /// Start a WAL replication replica (Growth+ feature).
    /// Reads config from <data_dir>/replication.json.
    #[command(name = "start-replica")]
    StartReplica {
        /// Primary address to connect to (overrides replication.json).
        #[arg(long)]
        primary: Option<String>,
    },
    /// Show the active license tier, features, and expiry.
    #[command(name = "license")]
    License,

    /// One-time migration: populate the SQLite entry index from the WAL.
    ///
    /// Run this if the SQLite index (vledger.db) is empty after a large import.
    /// Reads the WAL in batches and writes entries to SQLite incrementally.
    /// Progress is printed every 100,000 entries so you can see it working.
    /// Safe to interrupt and re-run — already-indexed entries are skipped.
    /// Writes wal-checkpoint.json when complete so future startups are fast.
    #[command(name = "migrate-to-sqlite")]
    MigrateToSqlite,
    /// Generate a portable, self-contained audit evidence package (JSON).
    ///
    /// Default (commitment-only): computes the Merkle root over all entries,
    /// signs it with the database signing key, and writes a compact JSON
    /// commitment. Fast at any scale — seconds regardless of ledger size.
    ///
    /// Use --include-entries to also embed all entries and per-entry Merkle
    /// proofs (only practical for ledgers with fewer than ~10,000 entries).
    ///
    /// Use `vledger audit-proof` to generate an on-demand inclusion proof
    /// for a specific entry against this commitment.
    #[command(name = "audit-package")]
    AuditPackage {
        /// Output path for the JSON file.
        /// Default: ./vledger-audit-package-<timestamp>.json
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Embed all entries and per-entry Merkle proofs in the package.
        /// Only practical for small ledgers (< ~10,000 entries).
        #[arg(long)]
        include_entries: bool,
        /// Organisation name to embed in the package metadata.
        /// Example: --tenant "Acme Financial"
        #[arg(long)]
        tenant: Option<String>,
        /// Human-readable description of this audit package.
        /// Example: --description "Q3 2026 ledger audit"
        #[arg(long)]
        description: Option<String>,
        /// Start of the reporting period (YYYY-MM-DD or RFC 3339).
        /// Example: --period-start 2026-07-01
        #[arg(long)]
        period_start: Option<String>,
        /// End of the reporting period (YYYY-MM-DD or RFC 3339).
        /// Example: --period-end 2026-09-30
        #[arg(long)]
        period_end: Option<String>,
    },
    /// Generate a single-entry inclusion proof against a commitment package.
    ///
    /// Produces a self-contained JSON file proving that the entry at
    /// --sequence belongs to the Merkle root in the commitment package.
    /// The auditor can verify it with `vledger verify-audit-package`
    /// without any database access.
    #[command(name = "audit-proof")]
    AuditProof {
        /// Path to the commitment package JSON (generated by audit-package).
        #[arg(long)]
        commitment: PathBuf,
        /// Sequence number of the entry to prove.
        #[arg(long)]
        sequence: u64,
        /// Output path for the proof JSON file.
        /// Default: ./vledger-entry-proof-<sequence>.json
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a portable audit evidence package produced by `vledger audit-package`.
    ///
    /// Checks all layers independently: root signature, content hashes
    /// (if entries present), hash-chain linkage, and Merkle inclusion proofs.
    /// Requires no database access, no server, and no key files.
    #[command(name = "verify-audit-package")]
    VerifyAuditPackage {
        /// Path to the audit package or entry proof JSON file to verify.
        #[arg(short = 'f', long)]
        file: PathBuf,
    },

    /// Seed the database with randomly generated journal entries for testing.
    /// Generates realistic double-entry transactions with random amounts,
    /// accounts, currencies, and descriptions. Does not require a running server.
    #[command(name = "seed")]
    Seed {
        /// Number of journal entries to generate.
        #[arg(long, default_value_t = 10_000)]
        entries: u64,
        /// Number of accounts to create (entries are distributed across them).
        #[arg(long, default_value_t = 20)]
        accounts: u64,
        /// Random seed for reproducible datasets (default: random).
        #[arg(long)]
        seed: Option<u64>,
        /// Print progress every N entries (0 = silent).
        #[arg(long, default_value_t = 100_000)]
        progress: u64,
    },

    /// Import journal entries from a CSV or JSON file into VectorLedger.
    ///
    /// Every row goes through the full post_entry() integrity path:
    /// debit/credit validation, account existence, currency check,
    /// balance constraints, idempotency, hash chain, WAL persistence.
    ///
    /// Recommended workflow:
    ///   1. vledger import --file export.csv --dry-run   (validate first)
    ///   2. vledger import --file export.csv             (execute)
    ///   3. Receive cryptographic import manifest
    ///
    /// The server must NOT be running — import opens the data directory directly.
    #[command(name = "import")]
    Import {
        /// Path to the import file (CSV or JSON).
        #[arg(short = 'f', long)]
        file: PathBuf,
        /// File format: csv or json (detected from extension if omitted).
        #[arg(long)]
        format: Option<String>,
        /// Validate only — do not write any data. Reports all errors found.
        #[arg(long)]
        dry_run: bool,
        /// Column mapping: --map SOURCE_COL=TARGET_FIELD (repeat as needed).
        /// Target fields: description, debit_account, credit_account, amount,
        ///   currency, domain, external_ref, idempotency_key, effective_date
        /// Example: --map memo=description --map from_acct=debit_account
        #[arg(long = "map", value_name = "SRC=TARGET")]
        mappings: Vec<String>,
        /// Path to a JSON mapping file (alternative to --map flags).
        /// Format: {"source_col": "target_field", ...}
        #[arg(long)]
        mapping_file: Option<PathBuf>,
        /// Default domain for imported entries.
        #[arg(long, default_value = "main")]
        domain: String,
        /// Default currency when not present in the source file.
        #[arg(long, default_value = "USD")]
        default_currency: String,
        /// Source column to use as the idempotency key for duplicate detection.
        /// If omitted, a BLAKE3 hash of the full row is used automatically.
        #[arg(long)]
        id_column: Option<String>,
        /// Behaviour on row error: abort (default), skip, or collect.
        #[arg(long, default_value = "abort")]
        on_error: String,
        /// Rows per checkpoint (progress saved after each batch for --resume).
        #[arg(long, default_value_t = 1_000)]
        batch_size: u64,
        /// Checkpoint state file path (used by --resume).
        #[arg(long, default_value = "import-state.json")]
        state_file: PathBuf,
        /// Resume a previously interrupted import from the last checkpoint.
        #[arg(long)]
        resume: bool,
        /// Print progress every N rows (0 = silent).
        #[arg(long, default_value_t = 10_000)]
        progress: u64,
        /// Path to write the cryptographic import manifest.
        #[arg(long, default_value = "import-manifest.json")]
        manifest: PathBuf,
        /// Automatically create accounts referenced in the file but not in the ledger.
        #[arg(long)]
        create_accounts: bool,
        /// Comma-separated list of source columns to pack into the metadata JSON field.
        /// Example: --metadata-columns sender_name,receiver_name,channel,status
        /// These columns are stored as a JSON object on every imported entry,
        /// hash-protected and queryable via SELECT * FROM ledger.
        #[arg(long)]
        metadata_columns: Option<String>,
        /// WAL sync mode for the import: group_commit (default), per_record, or no_sync.
        /// Use no_sync for maximum import speed on bulk migrations — run
        /// `vledger verify` after import completes to confirm integrity.
        #[arg(long, default_value = "group_commit")]
        wal_sync_mode: String,
    },

    /// Exits non-zero if any discrepancy is found.
    #[command(name = "reconcile")]
    Reconcile {
        /// Output format: text (default) or json.
        #[arg(long, default_value = "text")]
        format: String,
        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Transition a journal entry through the settlement lifecycle.
    /// Status transitions: Posted → Pending → Settled | Failed
    #[command(name = "settle")]
    Settle {
        /// Entry ID (UUID) to transition.
        #[arg(long)]
        entry_id: String,
        /// New status: pending, settled, or failed.
        #[arg(long)]
        status: String,
        /// Optional notes (e.g. settlement reference, failure reason).
        #[arg(long)]
        notes: Option<String>,
    },

    /// Manage data retention policies.
    /// Policies are stored in <data-dir>/catalog/retention_policy.json.
    #[command(name = "retention", subcommand_required = true)]
    Retention {
        #[command(subcommand)]
        action: RetentionAction,
    },

    /// Manage legal holds on accounts.
    /// A legal hold prevents any new entries, reversals, or settlement
    /// transitions involving the held account.
    #[command(name = "hold", subcommand_required = true)]
    Hold {
        #[command(subcommand)]
        action: HoldAction,
    },

    /// Manage accounting rule versions.
    /// Rule versions are stored in <data-dir>/catalog/accounting_rules.json.
    #[command(name = "rules", subcommand_required = true)]
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
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

/// Sub-actions for `vledger retention`.
#[derive(Subcommand)]
enum RetentionAction {
    /// Show the current retention policy.
    #[command(name = "show")]
    Show,
    /// Set the default retention period in days (0 = keep forever).
    #[command(name = "set")]
    Set {
        /// Default retention in days (0 = keep forever).
        #[arg(long)]
        days: u64,
        /// Apply this retention to a specific domain only (optional).
        #[arg(long)]
        domain: Option<String>,
    },
    /// Clear retention policy (revert to keep-forever).
    #[command(name = "clear")]
    Clear,
}

/// Sub-actions for `vledger hold`.
#[derive(Subcommand)]
enum HoldAction {
    /// Place a legal hold on an account.
    #[command(name = "place")]
    Place {
        /// Account code or UUID to place the hold on.
        #[arg(long)]
        account: String,
    },
    /// Lift the legal hold on an account.
    #[command(name = "lift")]
    Lift {
        /// Account code or UUID to lift the hold from.
        #[arg(long)]
        account: String,
    },
    /// List all accounts currently under a legal hold.
    #[command(name = "list")]
    List,
}

/// Sub-actions for `vledger rules`.
#[derive(Subcommand)]
enum RulesAction {
    /// Show the current accounting rules version.
    #[command(name = "show")]
    Show,
    /// Record a new accounting rules version with a description.
    #[command(name = "set")]
    Set {
        /// Version string, e.g. "2026-Q3" or "v2".
        #[arg(long)]
        version: String,
        /// Human-readable description of what changed.
        #[arg(long)]
        description: String,
        /// Effective date (YYYY-MM-DD). Defaults to today.
        #[arg(long)]
        effective_date: Option<String>,
    },
    /// List all recorded rule versions.
    #[command(name = "history")]
    History,
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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_target(true)
        .compact()
        .init();

    match cli.command {
        Commands::Init {
            force,
            key_source,
            vault_addr,
            vault_mount,
            vault_path,
            kms_key_id,
            kms_region,
            pyhsm_socket,
            pyhsm_caller_id,
            pyhsm_endpoint,
            pyhsm_ca_cert,
            pyhsm_client_cert,
            pyhsm_client_key,
            pyhsm_timeout_ms,
            pyhsm_max_retries,
        } => {
            cmd_init(
                &cli.data_dir,
                force,
                &key_source,
                &vault_addr,
                &vault_mount,
                &vault_path,
                kms_key_id.as_deref(),
                &kms_region,
                pyhsm_socket.as_deref(),
                &pyhsm_caller_id,
                pyhsm_endpoint.as_deref(),
                pyhsm_ca_cert.as_deref(),
                pyhsm_client_cert.as_deref(),
                pyhsm_client_key.as_deref(),
                pyhsm_timeout_ms,
                pyhsm_max_retries,
            )
            .await
        }
        Commands::Start {
            bind,
            pgwire,
            with_proofs,
            wal_sync_mode,
            group_commit_delay_ms,
            query_timeout_ms,
            metrics_addr,
            max_connections,
        } => {
            cmd_start(
                &cli.data_dir,
                &bind,
                pgwire,
                with_proofs,
                &wal_sync_mode,
                group_commit_delay_ms,
                query_timeout_ms,
                &metrics_addr,
                max_connections,
            )
            .await
        }
        Commands::Status => cmd_status(&cli.data_dir).await,
        Commands::Verify {
            self_test,
            entries,
            keep_data,
        } => {
            if self_test {
                crate::self_test::run(entries, keep_data).await
            } else {
                cmd_verify(&cli.data_dir).await
            }
        }
        Commands::Sql {
            query,
            username,
            password,
            server,
            ca_cert,
        } => {
            cmd_sql(
                &cli.data_dir,
                query.as_deref(),
                username.as_deref(),
                password.as_deref(),
                server.as_deref(),
                ca_cert.as_deref(),
            )
            .await
        }
        Commands::SelfTest => cmd_self_test().await,
        Commands::SelfTestPhase3 => cmd_self_test_phase3().await,
        // Phase 3
        Commands::Backup { output } => cmd_backup(&cli.data_dir, output.as_deref()).await,
        Commands::Restore {
            from,
            target,
            force,
        } => cmd_restore(&from, target.as_deref(), &cli.data_dir, force).await,
        Commands::RotateKeys {
            hsm_socket,
            caller_id,
            pyhsm_endpoint,
            pyhsm_ca_cert,
            pyhsm_client_cert,
            pyhsm_client_key,
            pyhsm_timeout_ms,
            pyhsm_max_retries,
        } => {
            cmd_rotate_keys(
                &cli.data_dir,
                hsm_socket.as_deref(),
                &caller_id,
                pyhsm_endpoint.as_deref(),
                pyhsm_ca_cert.as_deref(),
                pyhsm_client_cert.as_deref(),
                pyhsm_client_key.as_deref(),
                pyhsm_timeout_ms,
                pyhsm_max_retries,
            )
            .await
        }
        Commands::AuditExport {
            format,
            output,
            from,
            to,
        } => {
            cmd_audit_export(
                &cli.data_dir,
                &format,
                output.as_deref(),
                from.as_deref(),
                to.as_deref(),
            )
            .await
        }
        Commands::ComplianceReport {
            standard,
            format,
            output,
        } => cmd_compliance_report(&cli.data_dir, &standard, &format, output.as_deref()).await,
        Commands::User { action, ca_cert } => {
            cmd_user(&cli.data_dir, action, ca_cert.as_deref()).await
        }
        Commands::License => cmd_license(&cli.data_dir),
        Commands::MigrateToSqlite => cmd_migrate_to_sqlite(&cli.data_dir).await,
        Commands::BackupVerify { from, decrypt } => {
            cmd_backup_verify(&cli.data_dir, &from, decrypt).await
        }
        Commands::StartPrimary { bind } => cmd_start_primary(&cli.data_dir, bind.as_deref()).await,
        Commands::StartReplica { primary } => {
            cmd_start_replica(&cli.data_dir, primary.as_deref()).await
        }
        Commands::AuditPackage {
            output,
            include_entries,
            tenant,
            description,
            period_start,
            period_end,
        } => {
            cmd_audit_package(
                &cli.data_dir,
                output.as_deref(),
                include_entries,
                tenant,
                description,
                period_start,
                period_end,
            )
            .await
        }
        Commands::AuditProof {
            commitment,
            sequence,
            output,
        } => cmd_audit_proof(&cli.data_dir, &commitment, sequence, output.as_deref()).await,
        Commands::VerifyAuditPackage { file } => cmd_verify_audit_package(&file).await,
        Commands::Seed {
            entries,
            accounts,
            seed,
            progress,
        } => cmd_seed(&cli.data_dir, entries, accounts, seed, progress).await,
        Commands::Import {
            file,
            format,
            dry_run,
            mappings,
            mapping_file,
            domain,
            default_currency,
            id_column,
            on_error,
            batch_size,
            state_file,
            resume,
            progress,
            manifest,
            create_accounts,
            metadata_columns,
            wal_sync_mode,
        } => {
            cmd_import(
                &cli.data_dir,
                &file,
                format.as_deref(),
                dry_run,
                &mappings,
                mapping_file.as_deref(),
                &domain,
                &default_currency,
                id_column.as_deref(),
                &on_error,
                batch_size,
                &state_file,
                resume,
                progress,
                &manifest,
                create_accounts,
                metadata_columns.as_deref(),
                &wal_sync_mode,
            )
            .await
        }
        Commands::Reconcile { format, output } => {
            cmd_reconcile(&cli.data_dir, &format, output.as_deref()).await
        }
        Commands::Settle {
            entry_id,
            status,
            notes,
        } => cmd_settle(&cli.data_dir, &entry_id, &status, notes).await,
        Commands::Retention { action } => cmd_retention(&cli.data_dir, action).await,
        Commands::Hold { action } => cmd_hold(&cli.data_dir, action).await,
        Commands::Rules { action } => cmd_rules(&cli.data_dir, action).await,
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

async fn cmd_init(
    data_dir: &PathBuf,
    force: bool,
    key_source: &str,
    vault_addr: &str,
    vault_mount: &str,
    vault_path: &str,
    kms_key_id: Option<&str>,
    kms_region: &str,
    pyhsm_socket: Option<&str>,
    pyhsm_caller_id: &str,
    pyhsm_endpoint: Option<&str>,
    pyhsm_ca_cert: Option<&str>,
    pyhsm_client_cert: Option<&str>,
    pyhsm_client_key: Option<&str>,
    pyhsm_timeout_ms: u64,
    pyhsm_max_retries: u32,
) -> Result<()> {
    if data_dir.exists() && !force {
        anyhow::bail!(
            "Data directory already exists: {}\nUse --force to reinitialise",
            data_dir.display()
        );
    }

    info!(data_dir = %data_dir.display(), "Initialising VectorLedger");

    let dirs = [
        "wal",
        "pages",
        "indexes",
        "catalog",
        "snapshots",
        "keys",
        "audit",
    ];
    for d in &dirs {
        std::fs::create_dir_all(data_dir.join(d))
            .with_context(|| format!("Failed to create {d}"))?;
    }

    let signing_key = vledger_crypto::sign::DbSigningKey::generate();
    let pubkey_hex = hex::encode(signing_key.public_key().to_bytes());
    let privkey_hex = hex::encode(signing_key.to_bytes());
    std::fs::write(
        data_dir.join("keys").join("db_signing_pubkey.hex"),
        &pubkey_hex,
    )?;
    // Private key persisted with mode 0o600 — required for WAL commit signing.
    let privkey_path = data_dir.join("keys").join("db_signing_key.hex");
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
        use vledger_secrets::{FileProvider, KeySourceConfig};

        // ── HSM license check ─────────────────────────────────────────────
        // PyHSM key sources (pyhsm, remote-pyhsm) are Enterprise-only.
        // Check before doing any work so a non-Enterprise user gets a clear
        // error immediately rather than a partial initialisation.
        if matches!(key_source, "pyhsm" | "remote-pyhsm" | "pyhsm-remote") {
            let license = vledger_license::LicenseStore::load_or_free(data_dir);
            license
                .require_feature(vledger_license::Feature::Hsm)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }

        let key_source_cfg = match key_source {
            "file" => {
                let key_path = data_dir.join("keys").join("master_key.hex");
                FileProvider::generate(&key_path).context("Failed to generate master key file")?;
                KeySourceConfig::File {
                    path: key_path.display().to_string(),
                }
            }
            "vault" => KeySourceConfig::Vault {
                addr: vault_addr.to_string(),
                mount: vault_mount.to_string(),
                secret_path: vault_path.to_string(),
                field: "value".to_string(),
                namespace: None,
            },
            "aws_kms" => {
                let key_id = kms_key_id.ok_or_else(|| {
                    anyhow::anyhow!("--kms-key-id is required for aws_kms key source")
                })?;
                KeySourceConfig::AwsKms {
                    key_id: key_id.to_string(),
                    region: kms_region.to_string(),
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
                    caller_id: pyhsm_caller_id.to_string(),
                    key_id: "vledger.master-key".to_string(),
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
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                        "--pyhsm-ca-cert (or PYHSM_CA_CERT) is required for remote-pyhsm key source"
                    )
                    })?;
                KeySourceConfig::RemotePyHsm {
                    endpoint,
                    ca_cert,
                    client_cert: pyhsm_client_cert
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("PYHSM_CLIENT_CERT").ok()),
                    client_key: pyhsm_client_key
                        .map(|s| s.to_string())
                        .or_else(|| std::env::var("PYHSM_CLIENT_KEY").ok()),
                    timeout_ms: std::env::var("PYHSM_TIMEOUT_MS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(pyhsm_timeout_ms),
                    max_retries: pyhsm_max_retries,
                    caller_id: pyhsm_caller_id.to_string(),
                    key_id: "vledger.master-key".to_string(),
                }
            }
            _ => {
                // Explicit --key-source env, or unrecognised value: fall back to env var.
                KeySourceConfig::Env {
                    var: "VectorLedger_MASTER_KEY".to_string(),
                }
            }
        };

        let key_source_path = data_dir.join("keys").join("key_source.json");
        key_source_cfg
            .save_to_file(&key_source_path)
            .context("Failed to write key_source.json")?;

        println!("  Key source : {key_source}");
        match &key_source_cfg {
            KeySourceConfig::Env { var } => println!("  ⚠  Set ${var} before starting the server."),
            KeySourceConfig::File { path } => println!(
                "  ⚠  Master key written to {path} — move to a secrets manager before production."
            ),
            KeySourceConfig::Vault {
                addr, secret_path, ..
            } => println!("  Vault: {addr} → {secret_path}"),
            KeySourceConfig::AwsKms { key_id, region, .. } => {
                println!("  AWS KMS: {key_id} in {region}")
            }
            KeySourceConfig::PyHsm {
                socket_path,
                key_id,
                ..
            } => println!("  PyHSM (local): socket={socket_path}  wrapping-key={key_id}"),
            KeySourceConfig::RemotePyHsm {
                endpoint,
                key_id,
                client_cert,
                ..
            } => {
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
        format!(
            "vledger_version={}\ncreated_at={}\npubkey={}\n",
            env!("CARGO_PKG_VERSION"),
            chrono::Utc::now().to_rfc3339(),
            pubkey_hex
        ),
    )?;

    println!("✓ VectorLedger initialised at: {}", data_dir.display());
    println!("  Signing key (first 16 hex): {}", &pubkey_hex[..16]);
    for d in &dirs {
        println!("    {d}");
    }
    println!("\n  Master key source stored in: keys/key_source.json");
    Ok(())
}

// ── start ─────────────────────────────────────────────────────────────────────

async fn cmd_start(
    data_dir: &PathBuf,
    bind: &str,
    pgwire: bool,
    with_proofs: bool,
    wal_sync_mode: &str,
    group_commit_delay_ms: u64,
    query_timeout_ms: u64,
    metrics_addr: &str,
    max_connections: usize,
) -> Result<()> {
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
    // Load the license synchronously at startup so we can gate features and
    // print the banner before anything else starts.  After the shutdown token
    // is wired up (below) we hand this off to the daily background watcher
    // which refreshes it at each UTC midnight — ensuring a downgrade applied
    // on Monday is in effect by Tuesday without requiring a restart.
    let initial_license = vledger_license::LicenseStore::load_or_free(data_dir);

    if pgwire {
        initial_license
            .require_feature(vledger_license::Feature::PgWire)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // ── Replication license check ─────────────────────────────────────────
    // WAL replication is a Growth+ feature. Gate it now if a replication
    // config file is present so the server refuses to start rather than
    // silently running without replication when a user is on a lower tier.
    if data_dir.join("replication.json").exists() {
        initial_license
            .require_feature(vledger_license::Feature::Replication)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    info!("Opening ledger at {}", data_dir.display());
    let ledger = std::sync::Arc::new(tokio::sync::RwLock::new(
        vledger_ledger::LedgerStore::open(data_dir).context("Failed to open ledger")?,
    ));

    // Write a ServerStarted audit event so audit/audit.log is created on
    // first start. This satisfies CC6.2 (audit trail present) and ensures
    // the compliance check passes even before any SQL has been executed.
    // The Arc<AuditLog> is kept alive and threaded into every connection
    // handler so all audit events share a single monotonic sequence.
    let audit_log: std::sync::Arc<vledger_audit::AuditLog> = {
        let audit_path = data_dir.join("audit").join("audit.log");
        match vledger_audit::AuditLog::open(&audit_path) {
            Ok(log) => {
                let log = std::sync::Arc::new(log);
                let _ = log.append(vledger_audit::AuditEventKind::ServerStarted {
                    bind_addr: bind.to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                });
                log
            }
            Err(e) => {
                tracing::warn!("Failed to open audit log at startup: {e}");
                let tmp = std::env::temp_dir().join("vledger-audit-fallback.log");
                match vledger_audit::AuditLog::open(&tmp) {
                    Ok(fallback) => {
                        tracing::warn!(
                            path = %tmp.display(),
                            "Using fallback audit log — events will be lost on restart. \
                             Fix the primary audit log path before production use."
                        );
                        std::sync::Arc::new(fallback)
                    }
                    Err(e2) => {
                        anyhow::bail!(
                            "Cannot open audit log ({e}) and fallback at {} also failed ({e2}). \
                             Ensure the audit directory exists and is writable.",
                            tmp.display()
                        );
                    }
                }
            }
        }
    };

    let config = vledger_server::ServerConfig {
        bind_addr: bind.to_string(),
        attach_proofs: with_proofs,
        wal_sync_mode: wal_sync_mode.parse().unwrap_or_else(|e| {
            eprintln!(
                "⚠  Invalid --wal-sync-mode '{wal_sync_mode}': {e}. Defaulting to group_commit."
            );
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
    println!(
        "  WAL sync   : {wal_sync_mode}{}",
        if wal_sync_mode == "group_commit" {
            format!("  (flush every {group_commit_delay_ms} ms)")
        } else {
            String::new()
        }
    );
    println!(
        "  Query limit: {}",
        if query_timeout_ms == 0 {
            "none (⚠  disabled — not recommended for production)".to_string()
        } else {
            format!("{query_timeout_ms} ms")
        }
    );
    if !metrics_addr.is_empty() {
        println!("  Metrics    : http://{metrics_addr}/metrics  (Prometheus)");
    }
    initial_license.print_banner();
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
            {
                use tokio::signal::unix::{signal, SignalKind};
                match signal(SignalKind::terminate()) {
                    Ok(mut sigterm) => {
                        tokio::select! {
                            _ = ctrl_c         => tracing::info!("CTRL-C received — shutting down"),
                            _ = sigterm.recv() => tracing::info!("SIGTERM received — shutting down"),
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to install SIGTERM handler: {e}. \
                             SIGTERM will be ignored — only CTRL-C will trigger graceful shutdown."
                        );
                        ctrl_c.await.ok();
                        tracing::info!("CTRL-C received — shutting down");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                ctrl_c.await.ok();
                tracing::info!("CTRL-C received — shutting down");
            }
            token.cancel();
        });
    }

    // ── Daily license watcher ─────────────────────────────────────────────
    // Wrap the initial license in a shared RwLock and spawn a background task
    // that re-reads license.json at each UTC midnight.  Any downgrade or
    // expiry applied during the day takes effect at the next midnight tick
    // without requiring a server restart.
    let _license =
        vledger_license::spawn_license_watcher(data_dir, initial_license, shutdown.clone());

    let catalog_dir_str = data_dir.join("catalog").to_string_lossy().to_string();
    let mut config_with_catalog = config.clone();
    config_with_catalog.catalog_dir = Some(catalog_dir_str);

    let user_store = std::sync::Arc::new(
        vledger_server::UserStore::open(&data_dir.join("catalog"))
            .context("Failed to open user store")?,
    );

    if pgwire {
        let pg_config = vledger_pgwire::PgWireConfig {
            bind_addr: "127.0.0.1:5432".into(),
            database: "vledger".into(),
            attach_proofs: with_proofs,
            tls_cert_path: None,
            tls_key_path: None,
            tls_hostname: "localhost".into(),
            catalog_dir: None,
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
        let metrics = vledger_server::Metrics::new();
        let metrics_tok = shutdown.clone();
        let addr = metrics_addr.to_string();
        tokio::spawn(async move {
            if let Err(e) = vledger_server::run_metrics_server(addr, metrics, metrics_tok).await {
                tracing::warn!("Metrics server error: {e}");
            }
        });
    }

    // ── Background: scheduled VERIFY_CHAIN (Feature #35) ─────────────────
    // Runs verify_chain_integrity() every hour in the background.
    // Any failure is logged as an error and written to the audit log.
    {
        let ledger_bg = std::sync::Arc::clone(&ledger);
        let audit_bg = Some(std::sync::Arc::clone(&audit_log));
        let tok = shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let guard = ledger_bg.read().await;
                        match guard.verify_chain_integrity() {
                            Ok(()) => {
                                let n = guard.entry_count();
                                tracing::info!(entries = n, "Scheduled VERIFY_CHAIN: OK");
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "SCHEDULED VERIFY_CHAIN FAILED — INTEGRITY VIOLATION");
                                if let Some(ref log) = audit_bg {
                                    let _ = log.append(
                                        vledger_audit::AuditEventKind::QueryExecuted {
                                            sql: format!("INTEGRITY_ALERT: {e}"),
                                            caller_id: "verify-chain-scheduler".into(),
                                            rows_affected: 0,
                                            duration_ms: 0,
                                        },
                                    );
                                }
                            }
                        }
                    }
                    _ = tok.cancelled() => break,
                }
            }
        });
    }

    // ── Background: financial invariant monitor (Feature #36) ─────────────
    // Checks assets==liabilities+equity every 15 minutes.
    // Logs an error and writes to audit log if the invariant is violated.
    {
        let ledger_inv = std::sync::Arc::clone(&ledger);
        let audit_inv = Some(std::sync::Arc::clone(&audit_log));
        let tok = shutdown.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let guard = ledger_inv.read().await;
                        if let Err(msg) = guard.check_financial_invariants() {
                            tracing::error!(
                                "FINANCIAL INVARIANT VIOLATION: {msg}"
                            );
                            if let Some(ref log) = audit_inv {
                                let _ = log.append(
                                    vledger_audit::AuditEventKind::QueryExecuted {
                                        sql: format!("INVARIANT_ALERT: {msg}"),
                                        caller_id: "invariant-monitor".into(),
                                        rows_affected: 0,
                                        duration_ms: 0,
                                    },
                                );
                            }
                        }
                    }
                    _ = tok.cancelled() => break,
                }
            }
        });
    }

    vledger_server::Server::new_shared_with_shipper(
        config_with_catalog,
        ledger.clone(),
        user_store,
        // Wire the WAL shipper when replication.json is present.
        if data_dir.join("replication.json").exists() {
            match vledger_replication::ReplicationConfig::load(data_dir) {
                Ok(cfg) if matches!(cfg.role, vledger_replication::ReplicationRole::Primary) => {
                    match vledger_replication::WalShipper::new(cfg, data_dir) {
                        Ok(s) => {
                            let s = std::sync::Arc::new(s);
                            if let Err(e) = s.listen_and_accept().await {
                                tracing::warn!("WAL shipper failed to bind: {e}");
                                None
                            } else {
                                tracing::info!("WAL replication shipper started");
                                Some(s)
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Could not initialise WAL shipper: {e}");
                            None
                        }
                    }
                }
                _ => None,
            }
        } else {
            None
        },
        Some(audit_log),
    )
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

    let wal_dir = data_dir.join("wal");
    if !wal_dir.exists() {
        println!("  WAL integrity            ... N/A (no WAL yet)");
        println!("  Ledger hash chain        ... N/A (no WAL yet)");
        println!("\n✓ Verification complete");
        return Ok(());
    }

    // ── Streaming WAL + hash chain verification ───────────────────────────
    // Uses WalReader directly (record-at-a-time iterator) instead of recover()
    // which collects all committed transactions into a Vec.
    //
    // Memory: O(1 transaction) — we hold at most one transaction's data
    // records in memory at a time (typically 1 record per tx for imports).
    // For 10M entries this stays flat at a few MB regardless of dataset size.
    print!("  WAL + hash chain         ... ");
    {
        use vledger_crypto::ZERO_HASH;
        use vledger_wal::reader::WalReader;
        use vledger_wal::record::RecordType;
        use vledger_wal::recovery::decode_data_payload;

        let reader = WalReader::open_with_key(&wal_dir, None)
            .map_err(|e| anyhow::anyhow!("Cannot open WAL: {e}"))?;

        // Per-transaction state — cleared on each Commit/Rollback.
        let mut pending_data: Vec<vledger_wal::record::WalRecord> = Vec::new();
        let mut committed_txns: u64 = 0;
        let mut torn_write = false;

        // Chain state — updated as we verify each committed entry.
        let mut prev_chain_hash = ZERO_HASH;
        let mut entry_count: u64 = 0;
        let mut chain_tip = ZERO_HASH;
        let mut chain_broken = false;
        let mut chain_break_msg = String::new();

        'scan: for result in reader {
            match result {
                Err(
                    vledger_wal::error::WalError::ChecksumMismatch { .. }
                    | vledger_wal::error::WalError::TruncatedRecord { .. }
                    | vledger_wal::error::WalError::BadMagic
                    | vledger_wal::error::WalError::Decryption,
                ) => {
                    torn_write = true;
                    break 'scan;
                }
                Err(e) => return Err(anyhow::anyhow!("WAL read error: {e}")),
                Ok(record) => {
                    let record_type = match vledger_wal::record::RecordType::try_from(
                        record.header.record_type,
                    ) {
                        Ok(rt) => rt,
                        Err(_) => continue,
                    };

                    match record_type {
                        RecordType::Begin => {
                            pending_data.clear();
                        }
                        RecordType::Data => {
                            pending_data.push(record);
                        }
                        RecordType::Commit => {
                            committed_txns += 1;
                            // Process this transaction's data records immediately
                            // then clear them — never accumulate across transactions.
                            for data_record in &pending_data {
                                let payload = match decode_data_payload(data_record) {
                                    Ok(p) => p,
                                    Err(_) => continue,
                                };
                                // Only journal entry records (table_id=1, Insert/Update).
                                if payload.table_id != 1 {
                                    continue;
                                }
                                if !matches!(
                                    payload.mutation,
                                    vledger_wal::record::MutationKind::Insert
                                        | vledger_wal::record::MutationKind::Update
                                ) {
                                    continue;
                                }
                                let entry: vledger_ledger::JournalEntry =
                                    match bincode::serde::decode_from_slice(
                                        &payload.row_data,
                                        bincode::config::standard(),
                                    ) {
                                        Ok((e, _)) => e,
                                        Err(e) => {
                                            chain_broken = true;
                                            chain_break_msg = format!("decode error: {e}");
                                            break 'scan;
                                        }
                                    };
                                if !entry.verify_hashes() {
                                    chain_broken = true;
                                    chain_break_msg =
                                        format!("hash mismatch at sequence {}", entry.sequence);
                                    break 'scan;
                                }
                                if entry.prev_hash != prev_chain_hash {
                                    chain_broken = true;
                                    chain_break_msg = format!(
                                        "chain linkage broken at sequence {}",
                                        entry.sequence
                                    );
                                    break 'scan;
                                }
                                prev_chain_hash = entry.chain_hash;
                                chain_tip = entry.chain_hash;
                                entry_count += 1;
                            }
                            pending_data.clear();
                        }
                        RecordType::Rollback => {
                            pending_data.clear();
                        }
                        _ => {}
                    }
                }
            }
        }

        if chain_broken {
            println!("✗ BROKEN: {chain_break_msg}");
        } else if torn_write && entry_count == 0 {
            println!("⚠  TORN WRITE (no committed entries found)");
        } else {
            let torn_note = if torn_write {
                " ⚠ torn write detected"
            } else {
                ""
            };
            println!(
                "✓ ({committed_txns} txns, {entry_count} entries, tip={}){torn_note}",
                hex::encode(&chain_tip[..8])
            );
        }
    }

    println!("\n✓ Verification complete");
    Ok(())
}

// ── sql ───────────────────────────────────────────────────────────────────────

async fn cmd_sql(
    data_dir: &PathBuf,
    query: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
    server: Option<&str>,
    ca_cert: Option<&str>,
) -> Result<()> {
    // Resolve credentials first (needed for both network and direct modes).
    let resolved_username = resolve_username(username);
    let resolved_password = resolve_password(password);

    // ── Network mode: connect to a running server over TLS ────────────────
    // Use this when `vledger start` is running (it holds the data-dir lock).
    // Explicitly requested via --server, OR auto-detected by probing the
    // default address.
    let server_addr = server.map(|s| s.to_string()).or_else(|| {
        // Auto-detect: if the default port is reachable, prefer network mode.
        let addr = "127.0.0.1:5433";
        if std::net::TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
        {
            Some(addr.to_string())
        } else {
            None
        }
    });

    if let Some(addr) = server_addr {
        return cmd_sql_network(
            &addr,
            query,
            &resolved_username,
            &resolved_password,
            ca_cert,
        )
        .await;
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

    let session = user_store
        .authenticate(&resolved_username, &resolved_password)
        .map_err(|_| anyhow::anyhow!("Authentication failed"))?;

    info!(
        username = %session.username,
        role     = %session.role,
        "CLI authenticated"
    );

    let mut ledger =
        vledger_ledger::LedgerStore::open(data_dir).context("Failed to open ledger")?;

    if let Some(sql) = query {
        run_sql_authenticated(&mut ledger, sql, &session)?;
    } else {
        println!(
            "VectorLedger SQL REPL — authenticated as {} ({})",
            session.username, session.role
        );
        println!(
            "  Data dir: {} | Type 'exit' or Ctrl-D to quit",
            data_dir.display()
        );
        println!();

        let mut rl = rustyline::DefaultEditor::new().context("Failed to initialize line editor")?;
        loop {
            let prompt = "vledger> ";
            match rl.readline(prompt) {
                Ok(line) => {
                    let trimmed = line.trim().to_string();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let _ = rl.add_history_entry(&trimmed);
                    if trimmed == "exit" || trimmed == "\\q" {
                        break;
                    }
                    if let Err(e) = run_sql_authenticated(&mut ledger, &trimmed, &session) {
                        eprintln!("Error: {e}");
                    }
                }
                Err(rustyline::error::ReadlineError::Eof)
                | Err(rustyline::error::ReadlineError::Interrupted) => break,
                Err(e) => {
                    eprintln!("Input error: {e}");
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Connect to a running vledger server over TLS and run SQL.
async fn cmd_sql_network(
    addr: &str,
    query: Option<&str>,
    username: &str,
    password: &str,
    ca_cert: Option<&str>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::TlsConnector;

    let host_part = addr.split(':').next().unwrap_or("127.0.0.1");
    let port: u16 = addr
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(5433);

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
            root_store
                .add(cert.context("Invalid CA certificate DER")?)
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

    let connector = TlsConnector::from(std::sync::Arc::new(tls_config));

    let tcp = tokio::net::TcpStream::connect((host_part, port))
        .await
        .with_context(|| format!("Cannot connect to server at {addr}"))?;

    let server_name = ServerName::try_from(host_part.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid server hostname: {host_part}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;

    // Split into read/write halves with concrete types so the compiler can
    // infer `R` in `BufReader<R>` without ambiguity.
    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();

    // ── Authenticate ──────────────────────────────────────────────────────
    let auth_req = serde_json::json!({
        "auth": { "username": username, "password": password }
    });
    write_half
        .write_all(format!("{}\n", auth_req).as_bytes())
        .await?;
    write_half.flush().await?;

    let auth_line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("Server closed connection during auth"))?;
    let auth_resp: serde_json::Value =
        serde_json::from_str(&auth_line).context("Invalid auth response from server")?;

    if !auth_resp["ok"].as_bool().unwrap_or(false) {
        anyhow::bail!(
            "Authentication failed: {}",
            auth_resp["error"].as_str().unwrap_or("unknown error")
        );
    }

    let token = auth_resp["token"]
        .as_str()
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
        let cols: Vec<&str> = resp["columns"]
            .as_array()
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
                            let v = val
                                .as_str()
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
            let all_vals: Vec<Vec<String>> = rows
                .map(|rs| {
                    rs.iter()
                        .map(|row| {
                            row.as_array()
                                .map(|vals| {
                                    vals.iter()
                                        .map(|v| {
                                            v.as_str()
                                                .map(|s| s.to_string())
                                                .unwrap_or_else(|| v.to_string())
                                        })
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default()
                        })
                        .collect()
                })
                .unwrap_or_default();

            let widths: Vec<usize> = cols
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let val_max = all_vals
                        .iter()
                        .filter_map(|r| r.get(i))
                        .map(|v| v.len())
                        .max()
                        .unwrap_or(0);
                    c.len().max(val_max)
                })
                .collect();

            // Header row.
            let header: Vec<String> = cols
                .iter()
                .zip(widths.iter())
                .map(|(c, w)| format!("{:<width$}", c, width = w))
                .collect();
            println!("{}", header.join(" │ "));

            // Separator.
            let sep: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
            println!("{}", sep.join("─┼─"));

            // Data rows.
            for row_vals in &all_vals {
                let cells: Vec<String> = widths
                    .iter()
                    .enumerate()
                    .map(|(i, w)| {
                        let v = row_vals.get(i).map(|s| s.as_str()).unwrap_or("");
                        format!("{:<width$}", v, width = w)
                    })
                    .collect();
                println!("{}", cells.join(" │ "));
            }
        }

        println!("── {}", resp["message"].as_str().unwrap_or(""));

        // ── Merkle proof display ──────────────────────────────────────────
        if let Some(proof) = resp.get("proof").filter(|p| !p.is_null()) {
            let root_hex = proof["root_hex"].as_str().unwrap_or("");
            let leaf_count = proof["leaf_count"].as_u64().unwrap_or(0);
            let verified = proof["verified"].as_bool().unwrap_or(false);
            let verified_str = if verified {
                "✓ verified"
            } else {
                "✗ FAILED"
            };
            println!("   Merkle proof : {} ({} leaves)", verified_str, leaf_count);
            if !root_hex.is_empty() {
                println!("   Merkle root  : {}", &root_hex[..root_hex.len().min(32)]);
            }
        }

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

        let mut rl = rustyline::DefaultEditor::new().context("Failed to initialize line editor")?;
        loop {
            let prompt = if expanded {
                "vledger (expanded)> "
            } else {
                "vledger> "
            };
            match rl.readline(prompt) {
                Ok(line) => {
                    let trimmed = line.trim().to_string();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let _ = rl.add_history_entry(&trimmed);
                    if trimmed == "exit" || trimmed == "\\q" {
                        break;
                    }

                    // Handle REPL meta-commands (no server round-trip needed).
                    if trimmed == "\\x" {
                        expanded = !expanded;
                        println!(
                            "Expanded display is {}.",
                            if expanded { "on" } else { "off" }
                        );
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
                    if let Err(e) = write_half
                        .write_all(format!("{}\n", req).as_bytes())
                        .await
                        .and(write_half.flush().await)
                    {
                        eprintln!("Connection error: {e}");
                        break;
                    }
                    match lines.next_line().await {
                        Ok(Some(resp_line)) => {
                            match serde_json::from_str::<serde_json::Value>(&resp_line) {
                                Ok(resp) => print_response(&resp, expanded),
                                Err(e) => eprintln!("Bad response: {e}"),
                            }
                        }
                        Ok(None) => {
                            eprintln!("Server closed connection.");
                            break;
                        }
                        Err(e) => {
                            eprintln!("Read error: {e}");
                            break;
                        }
                    }
                }
                Err(rustyline::error::ReadlineError::Eof)
                | Err(rustyline::error::ReadlineError::Interrupted) => break,
                Err(e) => {
                    eprintln!("Input error: {e}");
                    break;
                }
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
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
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
    from: &std::path::Path,
    decrypt: bool,
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
                            eprintln!(
                                "⚠  Could not load master key ({e}) — verifying manifest only."
                            );
                            None
                        }
                    },
                    Err(e) => {
                        eprintln!(
                            "⚠  Could not build key provider ({e}) — verifying manifest only."
                        );
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
        println!("  Upgrade    : https://vledger.vectorguardlabs.com");
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
             paid features. Contact pavon@vectorguardlabs.com or visit\n  \
             https://vledger.vectorguardlabs.com"
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
        )
        .is_ok()
        {
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
    let store =
        vledger_server::UserStore::open(&catalog_dir).context("Failed to open user store")?;

    match action {
        UserAction::SetPassword {
            username,
            new_password,
        } => {
            let target = username.unwrap_or_else(|| resolve_username(None));
            let new_pw = new_password.unwrap_or_else(|| {
                let pw1 = prompt_new_password("New password: ");
                let pw2 = prompt_new_password("Confirm password: ");
                if pw1 != pw2 {
                    eprintln!("Passwords do not match.");
                    std::process::exit(1);
                }
                pw1
            });
            store
                .set_password(&target, &new_pw)
                .with_context(|| format!("Failed to set password for '{target}'"))?;
            println!("✓ Password updated for '{target}'.");
        }
        UserAction::Create {
            username,
            role,
            password,
        } => {
            let role_parsed: vledger_server::auth::Role =
                role.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let pw = password.unwrap_or_else(|| {
                let pw1 = prompt_new_password("Password: ");
                let pw2 = prompt_new_password("Confirm password: ");
                if pw1 != pw2 {
                    eprintln!("Passwords do not match.");
                    std::process::exit(1);
                }
                pw1
            });
            store
                .create_user(&username, &pw, role_parsed, None)
                .with_context(|| format!("Failed to create user '{username}'"))?;
            println!("✓ User '{username}' created with role '{role}'.");
        }
        UserAction::List => {
            let mut users = store.list_users();
            users.sort_by(|a, b| a.0.cmp(&b.0));
            println!("{:<20} {:<12} ENABLED", "USERNAME", "ROLE");
            println!("{}", "-".repeat(40));
            for (name, role, enabled) in users {
                println!("{:<20} {:<12} {}", name, role, enabled);
            }
        }
        UserAction::SetEnabled { username, enabled } => {
            store
                .set_enabled(&username, enabled)
                .with_context(|| format!("Failed to update '{username}'"))?;
            let state = if enabled { "enabled" } else { "disabled" };
            println!("✓ User '{username}' {state}.");
        }
        UserAction::Delete { username } => {
            store
                .delete_user(&username)
                .with_context(|| format!("Failed to delete '{username}'"))?;
            println!("✓ User '{username}' deleted.");
        }
    }
    Ok(())
}

/// Send a user management command to a running server over TLS.
async fn cmd_user_network(addr: &str, action: UserAction, ca_cert: Option<&str>) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::TlsConnector;

    // Fix #1: same CA-cert / loopback logic as cmd_sql_network.
    let host_part = addr.split(':').next().unwrap_or("127.0.0.1");
    let port: u16 = addr
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(5433);

    let is_loopback = host_part == "127.0.0.1"
        || host_part == "::1"
        || host_part.eq_ignore_ascii_case("localhost");

    let tls_config: ClientConfig = if let Some(ca_path) = ca_cert {
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("Cannot read CA certificate: {ca_path}"))?;
        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            root_store
                .add(cert.context("Invalid CA certificate DER")?)
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
        UserAction::SetPassword {
            username: target,
            new_password,
        } => {
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
                if pw1 != pw2 {
                    eprintln!("Passwords do not match.");
                    std::process::exit(1);
                }
                pw1
            });
            serde_json::json!({ "op": "set_password", "username": target, "new_password": new_pw })
        }
        UserAction::Create {
            username: target,
            role,
            password,
        } => {
            let pw = password.unwrap_or_else(|| {
                let pw1 = prompt_new_password("Password: ");
                let pw2 = prompt_new_password("Confirm password: ");
                if pw1 != pw2 {
                    eprintln!("Passwords do not match.");
                    std::process::exit(1);
                }
                pw1
            });
            serde_json::json!({ "op": "create_user", "username": target, "password": pw, "role": role })
        }
        UserAction::List => serde_json::json!({ "op": "list_users" }),
        UserAction::SetEnabled {
            username: target,
            enabled,
        } => serde_json::json!({ "op": "set_enabled", "username": target, "enabled": enabled }),
        UserAction::Delete { username: target } => {
            serde_json::json!({ "op": "delete_user", "username": target })
        }
    };

    // Connect.
    let connector = TlsConnector::from(std::sync::Arc::new(tls_config));
    let tcp = tokio::net::TcpStream::connect((host_part, port))
        .await
        .with_context(|| format!("Cannot connect to server at {addr}"))?;
    let server_name = ServerName::try_from(host_part.to_string())
        .map_err(|_| anyhow::anyhow!("Invalid hostname: {host_part}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();

    // Authenticate first.
    let auth_req = serde_json::json!({ "auth": { "username": username, "password": password } });
    write_half
        .write_all(format!("{}\n", auth_req).as_bytes())
        .await?;
    write_half.flush().await?;

    let auth_line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("Server closed connection during auth"))?;
    let auth_resp: serde_json::Value = serde_json::from_str(&auth_line)?;
    if !auth_resp["ok"].as_bool().unwrap_or(false) {
        anyhow::bail!(
            "Authentication failed: {}",
            auth_resp["error"].as_str().unwrap_or("unknown")
        );
    }
    let token = auth_resp["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No token in auth response"))?
        .to_string();

    // Send the admin command.
    let req = serde_json::json!({ "token": token, "admin": admin_cmd });
    write_half
        .write_all(format!("{}\n", req).as_bytes())
        .await?;
    write_half.flush().await?;

    let resp_line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("Server closed connection"))?;
    let resp: serde_json::Value = serde_json::from_str(&resp_line)?;

    if !resp["ok"].as_bool().unwrap_or(false) {
        anyhow::bail!("{}", resp["error"].as_str().unwrap_or("unknown error"));
    }

    // Print list output if present.
    if let Some(rows) = resp["rows"].as_array() {
        if !rows.is_empty() {
            let cols: Vec<&str> = resp["columns"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            if !cols.is_empty() {
                println!(
                    "{:<20} {:<12} {}",
                    cols[0],
                    cols.get(1).unwrap_or(&""),
                    cols.get(2).unwrap_or(&"")
                );
                println!("{}", "-".repeat(40));
            }
            for row in rows {
                if let Some(vals) = row.as_array() {
                    let v: Vec<String> = vals
                        .iter()
                        .map(|v| {
                            v.as_str()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| v.to_string())
                        })
                        .collect();
                    println!(
                        "{:<20} {:<12} {}",
                        v.first().map(|s| s.as_str()).unwrap_or(""),
                        v.get(1).map(|s| s.as_str()).unwrap_or(""),
                        v.get(2).map(|s| s.as_str()).unwrap_or("")
                    );
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
    use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleMode, ENABLE_ECHO_INPUT};

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
        } else {
            None
        };
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
    ledger: &mut vledger_ledger::LedgerStore,
    sql: &str,
    session: &vledger_server::auth::Session,
) -> Result<()> {
    use vledger_server::auth::check_plan_privilege;
    use vledger_sql::{executor::Executor, parser::parse_one, planner::LogicalPlanBuilder};

    let stmt = parse_one(sql).map_err(|e| anyhow::anyhow!("Parse error: {e}"))?;
    let plan = LogicalPlanBuilder::plan(stmt).map_err(|e| anyhow::anyhow!("Plan error: {e}"))?;

    // Enforce RBAC on the resolved LogicalPlan — identical to the network path.
    check_plan_privilege(session, &plan).map_err(|e| anyhow::anyhow!("Permission denied: {e}"))?;

    match Executor::with_proofs(ledger).execute(plan) {
        Err(e) => eprintln!("Error: {e}"),
        Ok(result) => {
            println!("{}", result.columns.join(" | "));
            println!(
                "{}",
                "-".repeat(
                    result
                        .columns
                        .iter()
                        .map(|c| c.len() + 3)
                        .sum::<usize>()
                        .max(40)
                )
            );
            for row in &result.rows {
                let vals: Vec<String> = row.values.iter().map(|v| v.to_string()).collect();
                println!("{}", vals.join(" | "));
            }
            println!(
                "── {} | {}",
                result.message,
                if result.proof.is_some() {
                    "proof attached ✓"
                } else {
                    "no proof"
                }
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
        use vledger_crypto::{
            hash::{verify_chain, ChainEntry},
            ZERO_HASH,
        };
        let e1 = ChainEntry::new(1, &ZERO_HASH, b"entry one");
        let e2 = ChainEntry::new(2, &e1.chain_hash, b"entry two");
        verify_chain(&[e1, e2]).unwrap();
    }
    println!("✓");

    print!("  [2/7] AES-256-GCM encryption ... ");
    {
        use vledger_crypto::encrypt::{decrypt, encrypt, EncryptionKey};
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
        use vledger_ledger::{
            entry::JournalEntryBuilder, Account, AccountType, Amount, LedgerStore,
        };
        let dir = TempDir::new().unwrap();
        let data = dir.path();
        std::fs::create_dir_all(data.join("wal")).unwrap();
        std::fs::create_dir_all(data.join("pages")).unwrap();

        let (cash_id, rev_id) = {
            let mut store = LedgerStore::open(data).unwrap();
            let cash = store
                .create_account(Account::new(
                    "CASH",
                    "Cash",
                    AccountType::Asset,
                    "USD",
                    "test",
                ))
                .unwrap();
            let rev = store
                .create_account(Account::new(
                    "REV",
                    "Revenue",
                    AccountType::Income,
                    "USD",
                    "test",
                ))
                .unwrap();
            let amt = Amount::new(50_000).unwrap();
            let e = JournalEntryBuilder::new("Sale", "test")
                .debit(cash, amt, "USD")
                .credit(rev, amt, "USD")
                .build();
            store.post_entry(e).unwrap();
            (cash, rev)
        };

        // Reopen — WAL replay
        let store2 = LedgerStore::open(data).unwrap();
        assert_eq!(store2.balance(&cash_id), 50_000);
        assert_eq!(store2.balance(&rev_id), 50_000);
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
        use vledger_sql::{
            executor::Executor, parser::parse_one, planner::LogicalPlanBuilder, result::Value,
        };

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

    // Open the audit log so the BackupCreated event is recorded.
    let audit_path = data_dir.join("audit").join("audit.log");
    let audit_log = vledger_audit::AuditLog::open(&audit_path).ok();

    let manifest = if key_source_path.exists() {
        match vledger_secrets::KeySourceConfig::from_file(&key_source_path) {
            Ok(cfg) => match vledger_secrets::build_provider(&cfg, Some(&keys_dir)) {
                Ok(provider) => match provider.load_master_key().await {
                    Ok(raw_key) => {
                        let master = vledger_crypto::kdf::MasterKey::from_bytes(*raw_key);
                        println!("  Encryption : AES-256-GCM (master key loaded)");
                        match &audit_log {
                            Some(log) => backup::create_backup_encrypted_audited(
                                data_dir, &out_path, &master, log,
                            )?,
                            None => backup::create_backup_encrypted(data_dir, &out_path, &master)?,
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "⚠  Could not load master key ({e}). Backup will be UNENCRYPTED."
                        );
                        match &audit_log {
                            Some(log) => backup::create_backup_audited(data_dir, &out_path, log)?,
                            None => backup::create_backup(data_dir, &out_path)?,
                        }
                    }
                },
                Err(e) => {
                    eprintln!("⚠  Could not build key provider ({e}). Backup will be UNENCRYPTED.");
                    match &audit_log {
                        Some(log) => backup::create_backup_audited(data_dir, &out_path, log)?,
                        None => backup::create_backup(data_dir, &out_path)?,
                    }
                }
            },
            Err(e) => {
                eprintln!("⚠  Could not read key_source.json ({e}). Backup will be UNENCRYPTED.");
                match &audit_log {
                    Some(log) => backup::create_backup_audited(data_dir, &out_path, log)?,
                    None => backup::create_backup(data_dir, &out_path)?,
                }
            }
        }
    } else {
        eprintln!("⚠  key_source.json not found. Backup will be UNENCRYPTED.");
        match &audit_log {
            Some(log) => backup::create_backup_audited(data_dir, &out_path, log)?,
            None => backup::create_backup(data_dir, &out_path)?,
        }
    };

    println!("  Archive   : {}", out_path.display());
    if manifest.encrypted {
        println!(
            "  Key sidecar: {}.key  (keep alongside archive for restore)",
            out_path.display()
        );
    }
    println!("  Files     : {}", manifest.files.len());
    println!("  Created   : {}", manifest.created_at_rfc);
    println!("  Hash      : {}", &manifest.manifest_hash[..32]);
    println!("✓ Backup complete");
    Ok(())
}

// ── restore ───────────────────────────────────────────────────────────────────

async fn cmd_restore(
    from: &std::path::Path,
    target: Option<&std::path::Path>,
    data_dir: &PathBuf,
    force: bool,
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
            Ok(cfg) => {
                match vledger_secrets::build_provider(&cfg, Some(&keys_dir)) {
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
                }
            }
            Err(e) => {
                eprintln!(
                    "⚠  Could not read key_source.json ({e}). Attempting unencrypted restore."
                );
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
    data_dir: &PathBuf,
    hsm_socket: Option<&str>,
    caller_id: &str,
    pyhsm_endpoint: Option<&str>,
    pyhsm_ca_cert: Option<&str>,
    pyhsm_client_cert: Option<&str>,
    pyhsm_client_key: Option<&str>,
    pyhsm_timeout_ms: u64,
    pyhsm_max_retries: u32,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }
    // ── License check ─────────────────────────────────────────────────────
    // Key rotation requires HSM access — Enterprise-only feature.
    {
        let license = vledger_license::LicenseStore::load_or_free(data_dir);
        license
            .require_feature(vledger_license::Feature::Hsm)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
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
    )
    .await?;
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
    format: &str,
    output: Option<&std::path::Path>,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<()> {
    use vledger_audit::export::{export_csv, export_json, TimeRange};

    // ── License check ─────────────────────────────────────────────────────
    // Audit export date range is gated by tier:
    //   Free     — last 30 days only
    //   Starter  — last 90 days only
    //   Growth / Enterprise — unlimited (requires AuditExportUnlimited feature)
    //
    // The window is enforced by clamping the effective `from` date regardless
    // of what the caller requests. A caller cannot bypass this by omitting
    // --from; the cap is applied to TimeRange::all() as well.
    let license = vledger_license::LicenseStore::load_or_free(data_dir);
    let unlimited = license.has_feature(&vledger_license::Feature::AuditExportUnlimited);

    // Days the caller is allowed to look back from now.
    let max_days: Option<i64> = if unlimited {
        None // no cap
    } else {
        match license.tier {
            vledger_license::LicenseTier::Starter => Some(90),
            // Free tier (and any unknown/downgraded tier) — 30 days.
            _ => Some(30),
        }
    };

    let log_path = data_dir.join("audit").join("audit.log");
    if !log_path.exists() {
        anyhow::bail!("Audit log not found at {}", log_path.display());
    }

    // Parse date range
    let range = {
        let from_dt = from
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .context("Invalid --from date (use RFC 3339)")
            })
            .transpose()?;
        let to_dt = to
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .context("Invalid --to date (use RFC 3339)")
            })
            .transpose()?;

        // Apply tier cap: compute the earliest `from` this tier is allowed.
        let effective_from = if let Some(days) = max_days {
            let earliest = chrono::Utc::now() - chrono::Duration::days(days);
            match from_dt {
                // Caller requested a range — clamp it forward if it exceeds the cap.
                Some(requested) if requested < earliest => {
                    eprintln!(
                        "⚠  Your {} license limits audit export to the last {} days. \
                         Clamping --from to {}.\n   \
                         Upgrade at https://vledger.vectorguardlabs.com",
                        license.tier,
                        days,
                        earliest.format("%Y-%m-%dT%H:%M:%SZ"),
                    );
                    Some(earliest)
                }
                // Caller's range is within the allowed window — use as-is.
                Some(requested) => Some(requested),
                // No --from supplied — default to the tier cap.
                None => Some(earliest),
            }
        } else {
            // Unlimited tier — honour the caller's --from (or no cap if omitted).
            from_dt
        };

        match (effective_from, to_dt) {
            (Some(f), Some(t)) => TimeRange::new(f, t),
            (Some(f), None) => TimeRange::new(f, chrono::Utc::now()),
            _ => TimeRange::all(),
        }
    };

    let count = if let Some(out_path) = output {
        let mut file = std::fs::File::create(out_path)
            .with_context(|| format!("Cannot create output file: {}", out_path.display()))?;
        match format {
            "csv" => export_csv(&log_path, &range, &mut file)?,
            _ => export_json(&log_path, &range, &mut file)?,
        }
    } else {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        match format {
            "csv" => export_csv(&log_path, &range, &mut out)?,
            _ => export_json(&log_path, &range, &mut out)?,
        }
    };

    eprintln!("Exported {count} audit events");
    Ok(())
}

// ── compliance-report ─────────────────────────────────────────────────────────

async fn cmd_compliance_report(
    data_dir: &PathBuf,
    standard: &str,
    format: &str,
    output: Option<&std::path::Path>,
) -> Result<()> {
    use vledger_compliance::{ComplianceEngine, ComplianceStandard, ReportDateRange};

    // ── License check ─────────────────────────────────────────────────────
    let license = vledger_license::LicenseStore::load_or_free(data_dir);
    license
        .require_feature(vledger_license::Feature::ComplianceReport)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let std_enum = match standard.to_lowercase().as_str() {
        "soc2" | "soc-2" => ComplianceStandard::Soc2,
        "pci" | "pci-dss" | "pcidss" => ComplianceStandard::PciDss,
        other => anyhow::bail!("Unknown standard '{other}' — use: soc2 or pci-dss"),
    };

    let engine = ComplianceEngine::new(data_dir.clone());
    let report = engine
        .generate_report(std_enum, ReportDateRange::last_90_days())
        .context("Failed to generate compliance report")?;

    let content = match format.to_lowercase().as_str() {
        "json" => report.to_json().context("Failed to serialise report")?,
        _ => report.to_markdown(),
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
        use vledger_audit::export::{export_csv, export_json, TimeRange};
        use vledger_audit::{AuditEventKind, AuditLog};

        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        let log = AuditLog::open(&log_path).unwrap();

        log.append(AuditEventKind::AuthEvent {
            caller_id: "alice".into(),
            success: true,
            peer_addr: "127.0.0.1".into(),
        })
        .unwrap();
        log.append(AuditEventKind::EntryPosted {
            entry_id: vledger_ledger::entry::JournalEntryBuilder::new("x", "x")
                .build()
                .id,
            entry_sequence: 1,
            domain: "test".into(),
            amount_sum: 50_000,
            caller_id: "alice".into(),
        })
        .unwrap();
        log.append(AuditEventKind::KeyRotated {
            key_id: "vledger.wal.signing".into(),
            caller_id: "admin".into(),
        })
        .unwrap();

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

        let dir = TempDir::new().unwrap();
        let queue = FourEyesQueue::open(dir.path()).unwrap();

        let fake_entry = b"fake-journal-entry-payload";
        let rec = queue.submit(fake_entry, "Sale", "test", "alice").unwrap();
        assert_eq!(queue.list_pending().len(), 1);

        // Self-approval must fail
        assert!(queue.approve(rec.id, "alice", |_| Ok(())).is_err());

        // Bob approves
        let approved = queue
            .approve(rec.id, "bob", |bytes| {
                assert_eq!(bytes, fake_entry);
                Ok(())
            })
            .unwrap();
        assert_eq!(approved.approver_id.as_deref(), Some("bob"));
        assert_eq!(queue.list_pending().len(), 0);

        // Test rejection path
        let rec2 = queue
            .submit(fake_entry, "Transfer", "test", "carol")
            .unwrap();
        let rejected = queue
            .reject(rec2.id, "dave", "Insufficient documentation")
            .unwrap();
        assert_eq!(
            rejected.reject_reason.as_deref(),
            Some("Insufficient documentation")
        );
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
        std::fs::write(
            data.join("catalog").join("VERSION"),
            "vledger_version=0.1.0\n",
        )
        .unwrap();

        let engine = ComplianceEngine::new(data.to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::Soc2, ReportDateRange::last_90_days())
            .unwrap();

        assert!(
            !report.evidence.is_empty(),
            "SOC 2 report must contain evidence"
        );
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
        std::fs::write(
            data.join("catalog").join("VERSION"),
            "vledger_version=0.1.0\n",
        )
        .unwrap();

        let engine = ComplianceEngine::new(data.to_path_buf());
        let report = engine
            .generate_report(ComplianceStandard::PciDss, ReportDateRange::last_year())
            .unwrap();
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
        std::fs::write(
            data.join("catalog").join("VERSION"),
            "vledger_version=0.1.0\n",
        )
        .unwrap();
        std::fs::write(
            data.join("wal").join("00000000000000000001.wal"),
            b"fake-wal-data",
        )
        .unwrap();
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
        let auth = messages::auth_ok();
        assert_eq!(auth[0], b'R');
        let rd = messages::row_description(&[messages::FieldDesc::text("balance")]);
        assert_eq!(rd[0], b'T');
        let dr = messages::data_row(&[Some("99000".into())]);
        assert_eq!(dr[0], b'D');
        let cc = messages::command_complete("SELECT 1");
        assert_eq!(cc[0], b'C');
        let rfq = messages::ready_for_query(b'I');
        assert_eq!(rfq[0], b'Z');
        let err = messages::error_response("ERROR", "42601", "syntax error");
        assert_eq!(err[0], b'E');
        // Verify length fields are consistent (len field at bytes 1-4 = payload+4)
        let cc_len = u32::from_be_bytes([cc[1], cc[2], cc[3], cc[4]]) as usize;
        assert_eq!(cc_len, cc.len() - 1);
    }
    println!("✓");

    // ── 7. SQL optimizer (aggregate + window) ───────────────────────────
    print!("  [7/7] SQL optimizer (agg + window) ... ");
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
        assert_eq!(
            result.rows.len(),
            3,
            "Window function should return all rows"
        );
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

// ── start-primary ─────────────────────────────────────────────────────────────

async fn cmd_start_primary(data_dir: &PathBuf, bind: Option<&str>) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!(
            "Not initialised at: {} — run `vledger init` first.",
            data_dir.display()
        );
    }

    // ── License check ─────────────────────────────────────────────────────
    let license = vledger_license::LicenseStore::load_or_free(data_dir);
    license
        .require_feature(vledger_license::Feature::Replication)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // ── Load or default config ─────────────────────────────────────────────
    let cfg_path = data_dir.join("replication.json");
    let mut cfg: vledger_replication::ReplicationConfig = if cfg_path.exists() {
        let raw = std::fs::read_to_string(&cfg_path).context("Failed to read replication.json")?;
        serde_json::from_str(&raw).context("Invalid replication.json — check the format")?
    } else {
        // No file — write a sensible default so the operator has something
        // to customise, then proceed with that default.
        let default = vledger_replication::ReplicationConfig::default();
        let json = serde_json::to_string_pretty(&default)
            .context("Failed to serialise default replication config")?;
        std::fs::write(&cfg_path, &json).context("Failed to write default replication.json")?;
        eprintln!(
            "⚠  No replication.json found — wrote default config to {}.\n   \
             Review and adjust before deploying to production.",
            cfg_path.display()
        );
        default
    };

    // CLI flag overrides file.
    if let Some(addr) = bind {
        cfg.replication_addr = addr.to_string();
    }

    // ── Start WAL shipper ─────────────────────────────────────────────────
    let shipper = vledger_replication::WalShipper::new(cfg.clone(), data_dir)
        .context("Failed to initialise WAL shipper")?;

    shipper
        .listen_and_accept()
        .await
        .context("Failed to bind replication listener")?;

    println!("── VectorLedger Primary (WAL Shipper) ──────────────");
    println!(
        "  Replication : {} (TLS {})",
        cfg.replication_addr,
        if cfg.tls.enabled {
            "enabled"
        } else {
            "disabled — dev only"
        },
    );
    println!("  Hostname    : {}", cfg.tls.server_hostname);
    println!(
        "  Secret      : {}",
        cfg.secret_path
            .as_deref()
            .unwrap_or("replication_secret.hex (auto-generated in data dir)"),
    );
    println!(
        "\n  Share the secret with each replica:\n    \
         scp {}/replication_secret.hex replica:/path/to/vledger-data/\n",
        data_dir.display()
    );
    println!("──────────────────────────────────────────────────────");

    // ── Graceful shutdown + heartbeat loop ────────────────────────────────
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
                _ = ctrl_c         => {},
                _ = sigterm.recv() => {},
            }
            #[cfg(not(unix))]
            {
                ctrl_c.await.ok();
            }
            token.cancel();
        });
    }

    let heartbeat_interval = tokio::time::Duration::from_millis(cfg.heartbeat_interval_ms);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("Shutdown signal received — WAL shipper stopping.");
                break;
            }
            _ = tokio::time::sleep(heartbeat_interval) => {
                shipper.heartbeat().await;
                let n = shipper.replica_count().await;
                tracing::debug!(replicas = n, "Heartbeat sent");
            }
        }
    }

    println!("✓ Primary shutdown complete.");
    Ok(())
}

// ── start-replica ─────────────────────────────────────────────────────────────

async fn cmd_start_replica(data_dir: &PathBuf, primary: Option<&str>) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!(
            "Not initialised at: {} — run `vledger init` first.",
            data_dir.display()
        );
    }

    // ── License check ─────────────────────────────────────────────────────
    let license = vledger_license::LicenseStore::load_or_free(data_dir);
    license
        .require_feature(vledger_license::Feature::Replication)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // ── Load config ────────────────────────────────────────────────────────
    let cfg_path = data_dir.join("replication.json");
    let mut cfg: vledger_replication::ReplicationConfig = if cfg_path.exists() {
        let raw = std::fs::read_to_string(&cfg_path).context("Failed to read replication.json")?;
        serde_json::from_str(&raw).context("Invalid replication.json — check the format")?
    } else {
        anyhow::bail!(
            "replication.json not found at {}.\n\
             Create it with your primary's address, e.g.:\n\
             {{\n  \
               \"role\": \"replica\",\n  \
               \"replication_addr\": \"<primary-host>:5434\",\n  \
               \"tls\": {{ \"enabled\": true, \"server_hostname\": \"vledger-primary\",\n            \
                         \"ca_cert\": \"/path/to/replication-ca.pem\" }}\n\
             }}",
            cfg_path.display()
        );
    };

    // CLI flag overrides file.
    if let Some(addr) = primary {
        cfg.replication_addr = addr.to_string();
    }

    // ── Ensure WAL directory exists ────────────────────────────────────────
    let wal_dir = data_dir.join("wal");
    std::fs::create_dir_all(&wal_dir).context("Failed to create local WAL directory")?;

    // ── Construct receiver ─────────────────────────────────────────────────
    // The HMAC secret must already exist — it is not generated on the replica.
    // Copy it from the primary: scp primary:/path/to/vledger-data/replication_secret.hex .
    let receiver = vledger_replication::WalReceiver::new(cfg.clone(), wal_dir.clone(), data_dir)
        .with_context(|| {
            format!(
                "Failed to initialise WAL receiver.\n\
                 Ensure replication_secret.hex is present at {}/replication_secret.hex\n\
                 (copy it from the primary node).",
                data_dir.display()
            )
        })?;

    println!("── VectorLedger Replica (WAL Receiver) ─────────────");
    println!("  Primary     : {}", cfg.replication_addr);
    println!(
        "  TLS         : {} (SNI: {})",
        if cfg.tls.enabled {
            "enabled"
        } else {
            "disabled — dev only"
        },
        cfg.tls.server_hostname,
    );
    println!("  Local WAL   : {}", wal_dir.display());
    println!("──────────────────────────────────────────────────────");

    // ── Graceful shutdown ─────────────────────────────────────────────────
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
                _ = ctrl_c         => {},
                _ = sigterm.recv() => {},
            }
            #[cfg(not(unix))]
            {
                ctrl_c.await.ok();
            }
            token.cancel();
        });
    }

    // ── Run receiver — loops forever, reconnecting on transient errors ─────
    let recv_handle = {
        let token = shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                result = receiver.run() => {
                    // run() normally never returns — only on unrecoverable error.
                    if let Err(e) = result {
                        tracing::error!("WAL receiver exited unexpectedly: {e}");
                    }
                }
                _ = token.cancelled() => {
                    tracing::info!("Shutdown signal received — WAL receiver stopping.");
                }
            }
        })
    };

    recv_handle.await.ok();
    println!("✓ Replica shutdown complete.");
    Ok(())
}

// ── audit-package ─────────────────────────────────────────────────────────────

async fn cmd_audit_package(
    data_dir: &PathBuf,
    output: Option<&std::path::Path>,
    include_entries: bool,
    tenant: Option<String>,
    description: Option<String>,
    period_start: Option<String>,
    period_end: Option<String>,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!(
            "Not initialised at: {} — run `vledger init` first.",
            data_dir.display()
        );
    }

    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let default_name = format!("vledger-audit-package-{ts}.json");
    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(&default_name));

    println!("── VectorLedger Audit Package ──────────────────");
    println!("  Data dir : {}", data_dir.display());
    println!(
        "  Mode     : {}",
        if include_entries {
            "full (entries + proofs)"
        } else {
            "commitment-only (fast)"
        }
    );
    if let Some(ref t) = tenant {
        println!("  Tenant   : {t}");
    }
    if let Some(ref d) = description {
        println!("  Desc     : {d}");
    }
    if let Some(ref s) = period_start {
        println!(
            "  Period   : {} → {}",
            s,
            period_end.as_deref().unwrap_or("?")
        );
    }

    if include_entries {
        println!("  ⚠  --include-entries is slow for large ledgers. Use the default");
        println!("     commitment-only mode and `vledger audit-proof` for individual entries.");
    }

    let opts = audit_package::GenerateOptions {
        include_entries,
        tenant,
        description,
        period_start,
        period_end,
    };
    let report = audit_package::generate(data_dir, &out_path, opts)
        .context("Failed to generate audit package")?;

    println!("  Entries  : {}", report.entry_count);
    println!(
        "  Root     : {}",
        &report.root_hex[..report.root_hex.len().min(32)]
    );
    println!(
        "  Chain tip: {}",
        &report.chain_tip_hex[..report.chain_tip_hex.len().min(32)]
    );
    println!(
        "  Signed   : {}",
        if report.signed {
            "yes (Ed25519)"
        } else {
            "no (no signing key)"
        }
    );
    println!("  Type     : {}", report.package_type);
    println!("  Output   : {}", report.output_path.display());
    println!("✓ Audit package generated");
    println!();
    if !include_entries {
        println!("  To prove a specific entry to an auditor:");
        println!("  vledger audit-proof \\");
        println!("    --commitment {} \\", report.output_path.display());
        println!("    --sequence <N>");
    }
    println!("  To verify:");
    println!(
        "  vledger verify-audit-package --file {}",
        report.output_path.display()
    );
    Ok(())
}

// ── audit-proof ───────────────────────────────────────────────────────────────

async fn cmd_audit_proof(
    data_dir: &PathBuf,
    commitment_file: &std::path::Path,
    sequence: u64,
    output: Option<&std::path::Path>,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!(
            "Not initialised at: {} — run `vledger init` first.",
            data_dir.display()
        );
    }
    if !commitment_file.exists() {
        anyhow::bail!("Commitment file not found: {}", commitment_file.display());
    }

    let default_name = format!("vledger-entry-proof-{sequence}.json");
    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(&default_name));

    println!("── VectorLedger Entry Proof ────────────────────");
    println!("  Sequence   : {sequence}");
    println!("  Commitment : {}", commitment_file.display());

    let report = audit_package::prove_entry(data_dir, commitment_file, sequence, &out_path)
        .context("Failed to generate entry proof")?;

    println!("  Entry ID   : {}", report.entry_id);
    println!(
        "  Root       : {}",
        &report.root_hex[..report.root_hex.len().min(32)]
    );
    println!("  Output     : {}", report.output_path.display());
    println!("✓ Entry proof generated");
    println!();
    println!("  Send this file to the auditor. They can verify it with:");
    println!(
        "  vledger verify-audit-package --file {}",
        report.output_path.display()
    );
    Ok(())
}

// ── verify-audit-package ──────────────────────────────────────────────────────

async fn cmd_verify_audit_package(file: &std::path::Path) -> Result<()> {
    if !file.exists() {
        anyhow::bail!("File not found: {}", file.display());
    }

    println!("── VectorLedger Audit Verifier ─────────────────");
    println!("  File     : {}", file.display());

    let report = audit_package::verify(file)
        .context("Audit package verification encountered an unexpected error")?;

    println!("  Type     : {}", report.package_type);
    println!("  Format   : v{}", report.format_version);
    println!("  Generated: {}", report.generated_at);
    println!("  Version  : VectorLedger {}", report.vledger_version);
    println!("  Entries  : {}", report.entry_count);
    println!();

    let mark = |ok: bool| if ok { "✓" } else { "✗" };

    // Show checks relevant to the package type.
    match report.package_type.as_str() {
        "commitment" => {
            println!(
                "  [1/1] Root signature   {}",
                match report.sig_status {
                    audit_package::SigStatus::Valid => "✓ verified",
                    audit_package::SigStatus::Invalid => "✗ FAILED",
                    audit_package::SigStatus::Absent => "⚠  absent",
                }
            );
        }
        "entry_proof" => {
            println!("  [1/3] Content hash     {}", mark(report.content_ok));
            println!("  [2/3] Chain hash       {}", mark(report.chain_ok));
            println!("  [3/3] Merkle proof     {}", mark(report.merkle_ok));
        }
        _ => {
            // full
            println!("  [1/4] Content hashes   {}", mark(report.content_ok));
            println!("  [2/4] Chain linkage    {}", mark(report.chain_ok));
            println!("  [3/4] Merkle proofs    {}", mark(report.merkle_ok));
            println!(
                "  [4/4] Root signature   {}",
                match report.sig_status {
                    audit_package::SigStatus::Valid => "✓ verified",
                    audit_package::SigStatus::Invalid => "✗ FAILED",
                    audit_package::SigStatus::Absent => "⚠  absent",
                }
            );
        }
    }

    println!();

    if report.passed {
        println!(
            "✓ INTEGRITY VERIFIED — {} entries, all checks passed.",
            report.entry_count
        );
        if !report.root_hex.is_empty() {
            println!(
                "  Merkle root : {}",
                &report.root_hex[..report.root_hex.len().min(32)]
            );
        }
        match report.sig_status {
            audit_package::SigStatus::Valid => {
                println!();
                println!("✓ AUTHENTICITY VERIFIED");
                println!("  Tenant      : {}", report.tenant);
                println!(
                    "  Period      : {} → {}",
                    report.period_start, report.period_end
                );
                println!(
                    "  Entries     : {} (seq {} → {})",
                    report.entry_count, report.first_sequence, report.last_sequence
                );
                println!(
                    "  Signing key : {}",
                    &report.signing_pubkey[..report.signing_pubkey.len().min(32)]
                );
                println!("  All metadata fields are cryptographically bound to the signature.");
            }
            audit_package::SigStatus::Absent => {
                println!();
                println!("⚠  AUTHENTICITY NOT VERIFIED");
                println!("   Root signature is absent — the commitment was generated without a");
                println!("   database signing key.  Integrity of the data is confirmed, but the");
                println!("   origin of the commitment cannot be cryptographically authenticated.");
                println!("   In production, run `vledger init` to generate a signing key.");
            }
            audit_package::SigStatus::Invalid => {
                // Already added to errors above, handled in the failed branch.
            }
        }
    } else {
        println!("✗ VERIFICATION FAILED — {} error(s):", report.errors.len());
        for e in &report.errors {
            println!("    • {e}");
        }
        anyhow::bail!("Audit package verification failed");
    }

    Ok(())
}

// ── reconcile ─────────────────────────────────────────────────────────────────

async fn cmd_reconcile(
    data_dir: &PathBuf,
    format: &str,
    output: Option<&std::path::Path>,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }

    let ledger = vledger_ledger::LedgerStore::open(data_dir).context("Failed to open ledger")?;

    let discrepancies = ledger.reconcile();

    let text_out: String = if discrepancies.is_empty() {
        "── VectorLedger Reconciliation ─────────────────\n  ✓  All accounts reconcile.  Balance cache matches journal entries.\n──────────────────────────────────────────────────\n".to_string()
    } else {
        let mut s = format!(
            "── VectorLedger Reconciliation ─────────────────\n  ✗  {} discrepanc{} found:\n\n",
            discrepancies.len(),
            if discrepancies.len() == 1 { "y" } else { "ies" }
        );
        for d in &discrepancies {
            s.push_str(&format!(
                "  Account  : {} ({})\n  Cached   : {}\n  Computed : {}\n  Delta    : {}\n\n",
                d.account_code, d.account_id, d.cached_balance, d.recomputed_balance, d.delta
            ));
        }
        s.push_str("──────────────────────────────────────────────────\n");
        s
    };

    let json_out = serde_json::json!({
        "reconciled": discrepancies.is_empty(),
        "discrepancy_count": discrepancies.len(),
        "discrepancies": discrepancies.iter().map(|d| serde_json::json!({
            "account_id": d.account_id.to_string(),
            "account_code": d.account_code,
            "cached_balance": d.cached_balance,
            "recomputed_balance": d.recomputed_balance,
            "delta": d.delta,
        })).collect::<Vec<_>>(),
    });

    let content = if format == "json" {
        serde_json::to_string_pretty(&json_out)? + "\n"
    } else {
        text_out
    };

    match output {
        Some(p) => std::fs::write(p, &content)
            .with_context(|| format!("Cannot write to {}", p.display()))?,
        None => print!("{content}"),
    }

    if !discrepancies.is_empty() {
        anyhow::bail!(
            "{} reconciliation discrepanc{} found",
            discrepancies.len(),
            if discrepancies.len() == 1 { "y" } else { "ies" }
        );
    }
    Ok(())
}

// ── settle ────────────────────────────────────────────────────────────────────

async fn cmd_settle(
    data_dir: &PathBuf,
    entry_id_str: &str,
    status_str: &str,
    notes: Option<String>,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }

    let entry_id = uuid::Uuid::parse_str(entry_id_str)
        .with_context(|| format!("Invalid entry UUID: {entry_id_str}"))?;

    let mut ledger =
        vledger_ledger::LedgerStore::open(data_dir).context("Failed to open ledger")?;

    match status_str.to_lowercase().as_str() {
        "pending" => ledger
            .mark_pending(entry_id, notes)
            .context("Failed to mark entry as pending")?,
        "settled" => ledger
            .mark_settled(entry_id, notes)
            .context("Failed to mark entry as settled")?,
        "failed" => ledger
            .mark_failed(entry_id, notes)
            .context("Failed to mark entry as failed")?,
        other => anyhow::bail!("Unknown status '{other}'. Valid values: pending, settled, failed"),
    }

    let effective = ledger.effective_status(&entry_id);
    println!("── Settlement Lifecycle ─────────────────────────");
    println!("  Entry ID : {entry_id}");
    println!("  Status   : {effective:?}");
    println!("──────────────────────────────────────────────────");
    Ok(())
}

// ── retention ─────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RetentionPolicy {
    /// Default retention in days (0 = keep forever).
    pub default_days: u64,
    /// Per-domain overrides: domain → days (0 = keep forever).
    pub domain_overrides: std::collections::HashMap<String, u64>,
    /// UTC timestamp when this policy was last updated.
    pub updated_at: String,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            default_days: 0,
            domain_overrides: std::collections::HashMap::new(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl RetentionPolicy {
    fn path(data_dir: &std::path::Path) -> std::path::PathBuf {
        data_dir.join("catalog").join("retention_policy.json")
    }

    fn load(data_dir: &std::path::Path) -> anyhow::Result<Self> {
        let p = Self::path(data_dir);
        if !p.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&p)?;
        Ok(serde_json::from_str(&raw)?)
    }

    fn save(&self, data_dir: &std::path::Path) -> anyhow::Result<()> {
        let p = Self::path(data_dir);
        std::fs::write(&p, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

async fn cmd_retention(data_dir: &PathBuf, action: RetentionAction) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }
    match action {
        RetentionAction::Show => {
            let policy = RetentionPolicy::load(data_dir)?;
            println!("── Retention Policy ─────────────────────────────");
            if policy.default_days == 0 {
                println!("  Default    : keep forever");
            } else {
                println!("  Default    : {} days", policy.default_days);
            }
            if policy.domain_overrides.is_empty() {
                println!("  Overrides  : none");
            } else {
                println!("  Overrides  :");
                let mut overrides: Vec<_> = policy.domain_overrides.iter().collect();
                overrides.sort_by_key(|(k, _)| k.as_str());
                for (domain, days) in overrides {
                    if *days == 0 {
                        println!("    {domain} → keep forever");
                    } else {
                        println!("    {domain} → {days} days");
                    }
                }
            }
            println!("  Updated    : {}", policy.updated_at);
            println!("──────────────────────────────────────────────────");
        }
        RetentionAction::Set { days, domain } => {
            let mut policy = RetentionPolicy::load(data_dir)?;
            policy.updated_at = chrono::Utc::now().to_rfc3339();
            match domain {
                Some(d) => {
                    policy.domain_overrides.insert(d.clone(), days);
                    let desc = if days == 0 {
                        "keep forever".to_string()
                    } else {
                        format!("{days} days")
                    };
                    println!("  Set retention for domain '{d}': {desc}");
                }
                None => {
                    policy.default_days = days;
                    let desc = if days == 0 {
                        "keep forever".to_string()
                    } else {
                        format!("{days} days")
                    };
                    println!("  Set default retention: {desc}");
                }
            }
            policy.save(data_dir)?;
            println!("  Saved to: {}", RetentionPolicy::path(data_dir).display());
        }
        RetentionAction::Clear => {
            let policy = RetentionPolicy::default();
            policy.save(data_dir)?;
            println!("  Retention policy cleared (keep forever).");
        }
    }
    Ok(())
}

// ── hold ──────────────────────────────────────────────────────────────────────

async fn cmd_hold(data_dir: &PathBuf, action: HoldAction) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }

    let mut ledger =
        vledger_ledger::LedgerStore::open(data_dir).context("Failed to open ledger")?;

    match action {
        HoldAction::Place { account } => {
            let id = resolve_account_id(&ledger, &account)?;
            ledger
                .place_legal_hold(&id)
                .context("Failed to place legal hold")?;
            println!("── Legal Hold Placed ────────────────────────────");
            println!("  Account : {account} ({id})");
            println!("  Status  : HOLD ACTIVE — no entries permitted");
            println!("──────────────────────────────────────────────────");
        }
        HoldAction::Lift { account } => {
            let id = resolve_account_id(&ledger, &account)?;
            ledger
                .lift_legal_hold(&id)
                .context("Failed to lift legal hold")?;
            println!("── Legal Hold Lifted ────────────────────────────");
            println!("  Account : {account} ({id})");
            println!("  Status  : hold removed — entries permitted");
            println!("──────────────────────────────────────────────────");
        }
        HoldAction::List => {
            println!("── Accounts Under Legal Hold ────────────────────");
            let mut found = 0usize;
            for acct in ledger.all_accounts() {
                if ledger.is_under_legal_hold(&acct.id) {
                    println!("  {} ({}) — domain: {}", acct.code, acct.id, acct.domain);
                    found += 1;
                }
            }
            if found == 0 {
                println!("  No accounts are currently under a legal hold.");
            }
            println!("──────────────────────────────────────────────────");
        }
    }
    Ok(())
}

/// Resolve an account code or UUID string to an AccountId.
fn resolve_account_id(
    ledger: &vledger_ledger::LedgerStore,
    account_ref: &str,
) -> Result<vledger_ledger::AccountId> {
    if let Ok(id) = uuid::Uuid::parse_str(account_ref) {
        if ledger.get_account(&id).is_some() {
            return Ok(id);
        }
    }
    ledger
        .all_accounts()
        .find(|a| a.code == account_ref)
        .map(|a| a.id)
        .ok_or_else(|| anyhow::anyhow!("Account '{}' not found", account_ref))
}

// ── rules ─────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct AccountingRuleVersion {
    pub version: String,
    pub description: String,
    pub effective_date: String,
    pub recorded_at: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct AccountingRules {
    pub current_version: Option<String>,
    pub history: Vec<AccountingRuleVersion>,
}

impl AccountingRules {
    fn path(data_dir: &std::path::Path) -> std::path::PathBuf {
        data_dir.join("catalog").join("accounting_rules.json")
    }

    fn load(data_dir: &std::path::Path) -> anyhow::Result<Self> {
        let p = Self::path(data_dir);
        if !p.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&p)?;
        Ok(serde_json::from_str(&raw)?)
    }

    fn save(&self, data_dir: &std::path::Path) -> anyhow::Result<()> {
        let p = Self::path(data_dir);
        std::fs::write(&p, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

async fn cmd_rules(data_dir: &PathBuf, action: RulesAction) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Not initialised at: {}", data_dir.display());
    }
    match action {
        RulesAction::Show => {
            let rules = AccountingRules::load(data_dir)?;
            println!("── Accounting Rules ─────────────────────────────");
            match &rules.current_version {
                Some(v) => {
                    println!("  Current version : {v}");
                    if let Some(entry) = rules.history.iter().rev().find(|e| &e.version == v) {
                        println!("  Description     : {}", entry.description);
                        println!("  Effective date  : {}", entry.effective_date);
                        println!("  Recorded at     : {}", entry.recorded_at);
                    }
                }
                None => println!("  No accounting rules version recorded."),
            }
            println!("──────────────────────────────────────────────────");
        }
        RulesAction::Set {
            version,
            description,
            effective_date,
        } => {
            let mut rules = AccountingRules::load(data_dir)?;
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            let entry = AccountingRuleVersion {
                version: version.clone(),
                description,
                effective_date: effective_date.unwrap_or_else(|| today.clone()),
                recorded_at: chrono::Utc::now().to_rfc3339(),
            };
            rules.current_version = Some(version.clone());
            rules.history.push(entry);
            rules.save(data_dir)?;
            println!("── Accounting Rules Updated ─────────────────────");
            println!("  Version : {version}");
            println!("  Saved to: {}", AccountingRules::path(data_dir).display());
            println!("──────────────────────────────────────────────────");
        }
        RulesAction::History => {
            let rules = AccountingRules::load(data_dir)?;
            println!("── Accounting Rules History ─────────────────────");
            if rules.history.is_empty() {
                println!("  No rule versions recorded.");
            } else {
                for (i, entry) in rules.history.iter().enumerate().rev() {
                    let marker = if rules.current_version.as_deref() == Some(&entry.version) {
                        " ← current"
                    } else {
                        ""
                    };
                    println!(
                        "  [{}] {} — {}{}",
                        i + 1,
                        entry.version,
                        entry.effective_date,
                        marker
                    );
                    println!("       {}", entry.description);
                    println!("       recorded: {}", entry.recorded_at);
                }
            }
            println!("──────────────────────────────────────────────────");
        }
    }
    Ok(())
}

// ── seed ──────────────────────────────────────────────────────────────────────

async fn cmd_seed(
    data_dir: &PathBuf,
    entry_count: u64,
    account_count: u64,
    seed: Option<u64>,
    progress_interval: u64,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Data directory not found — run `vledger init` first.");
    }

    // ── Simple deterministic PRNG (xorshift64) ────────────────────────────
    struct Rng {
        x: u64,
    }
    impl Rng {
        fn new(seed: u64) -> Self {
            Self {
                x: if seed == 0 { 0xdeadbeef_cafebabe } else { seed },
            }
        }
        fn next(&mut self) -> u64 {
            self.x ^= self.x << 13;
            self.x ^= self.x >> 7;
            self.x ^= self.x << 17;
            self.x
        }
        fn range(&mut self, lo: u64, hi: u64) -> u64 {
            lo + self.next() % (hi - lo)
        }
    }

    let rng_seed = seed.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    });

    let mut rng = Rng::new(rng_seed);

    println!("── VectorLedger Seed ────────────────────────────");
    println!("  Entries  : {entry_count}");
    println!("  Accounts : {account_count}");
    println!("  RNG seed : {rng_seed}");
    println!("  Data dir : {}", data_dir.display());
    println!("─────────────────────────────────────────────────");

    let mut ledger =
        vledger_ledger::LedgerStore::open(data_dir).context("Failed to open ledger")?;

    // ── Account types, currencies, and description templates ─────────────
    let account_types = [
        (vledger_ledger::AccountType::Asset, "ASSET"),
        (vledger_ledger::AccountType::Liability, "LIAB"),
        (vledger_ledger::AccountType::Income, "INC"),
        (vledger_ledger::AccountType::Expense, "EXP"),
        (vledger_ledger::AccountType::Equity, "EQ"),
    ];
    let currencies = ["USD", "EUR", "GBP", "USD", "USD"]; // weighted toward USD
    let domains = ["main", "main", "main", "fx", "ops"];
    let descriptions = [
        "Customer payment",
        "Vendor invoice",
        "Payroll disbursement",
        "Wire transfer",
        "FX conversion",
        "Interest income",
        "Service fee",
        "Loan repayment",
        "Dividend payment",
        "Tax provision",
        "Refund issued",
        "Capital contribution",
        "Asset purchase",
        "Depreciation",
        "Operating expense",
    ];

    // ── Create accounts ───────────────────────────────────────────────────
    // Check how many already exist — only create what's missing.
    let existing: Vec<_> = ledger.all_accounts().map(|a| a.id).collect();
    let need = account_count as usize;

    let mut account_ids: Vec<uuid::Uuid> = existing.clone();

    if account_ids.len() < need {
        let to_create = need - account_ids.len();
        eprint!("  Creating {} accounts...", to_create);
        for i in 0..to_create {
            let type_idx = rng.range(0, account_types.len() as u64) as usize;
            let curr_idx = rng.range(0, currencies.len() as u64) as usize;
            let dom_idx = rng.range(0, domains.len() as u64) as usize;
            let (atype, prefix) = &account_types[type_idx];
            let code = format!("{prefix}-{:04}", account_ids.len() + i + 1);
            let name = format!("{} Account #{}", prefix, account_ids.len() + i + 1);
            let acct = vledger_ledger::Account::new(
                &code,
                &name,
                *atype,
                currencies[curr_idx],
                domains[dom_idx],
            );
            match ledger.create_account(acct) {
                Ok(id) => account_ids.push(id),
                Err(e) => eprintln!("\n  Warning: could not create account: {e}"),
            }
        }
        eprintln!(" done.");
    }

    if account_ids.len() < 2 {
        anyhow::bail!("Need at least 2 accounts to post entries. Increase --accounts.");
    }

    // ── Build per-currency account index ─────────────────────────────────
    // Group account indices by currency so we always pick matching pairs,
    // eliminating currency-mismatch skips entirely.
    let mut by_currency: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (idx, id) in account_ids.iter().enumerate() {
        if let Some(acct) = ledger.get_account(id) {
            by_currency
                .entry(acct.currency_code.clone())
                .or_default()
                .push(idx);
        }
    }
    // Only keep currencies with at least 2 accounts.
    let viable: Vec<(String, Vec<usize>)> = by_currency
        .into_iter()
        .filter(|(_, ids)| ids.len() >= 2)
        .collect();

    if viable.is_empty() {
        anyhow::bail!(
            "No currency has 2 or more accounts. \
             Increase --accounts so at least one currency has 2 accounts."
        );
    }

    // ── Post entries ──────────────────────────────────────────────────────
    let start = std::time::Instant::now();
    let mut posted = 0u64;
    let mut errors = 0u64;

    for i in 0..entry_count {
        // Pick a currency group that has ≥ 2 accounts, then pick two
        // distinct accounts from it — guarantees currency always matches.
        let (currency, pool) = &viable[rng.range(0, viable.len() as u64) as usize];
        let a = rng.range(0, pool.len() as u64) as usize;
        let mut b = rng.range(0, (pool.len() - 1) as u64) as usize;
        if b >= a {
            b += 1;
        }
        let debit_id = account_ids[pool[a]];
        let credit_id = account_ids[pool[b]];

        // Random amount: $1.00 – $99,999.99 in cents (100 – 9_999_999)
        let amount_minor = rng.range(100, 9_999_999);
        let amount = match vledger_ledger::Amount::new(amount_minor as i64) {
            Some(a) => a,
            None => continue,
        };

        let desc_idx = rng.range(0, descriptions.len() as u64) as usize;
        let dom_idx = rng.range(0, domains.len() as u64) as usize;
        let description = format!("{} #{}", descriptions[desc_idx], i + 1);

        let entry = vledger_ledger::JournalEntryBuilder::new(&description, domains[dom_idx])
            .debit(debit_id, amount, currency.as_str())
            .credit(credit_id, amount, currency.as_str())
            .build();

        match ledger.post_entry(entry) {
            Ok(_) => posted += 1,
            Err(_) => {
                errors += 1;
                // Currency mismatch or non-negative balance violation —
                // skip silently and continue seeding.
            }
        }

        if progress_interval > 0 && (i + 1) % progress_interval == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let tps = posted as f64 / elapsed;
            println!(
                "  {}/{} entries posted  ({:.0} TPS)",
                posted, entry_count, tps
            );
        }
    }

    let elapsed = start.elapsed();
    let tps = posted as f64 / elapsed.as_secs_f64();

    println!();
    println!("── Seed Complete ─────────────────────────────────");
    println!("  Posted   : {posted}");
    if errors > 0 {
        println!("  Skipped  : {errors}  (currency mismatch / balance constraint)");
    }
    println!("  Accounts : {}", account_ids.len());
    println!("  Elapsed  : {:.2}s", elapsed.as_secs_f64());
    println!("  TPS      : {tps:.0}");
    println!("──────────────────────────────────────────────────");
    println!();
    println!("  Next steps:");
    println!("  vledger verify --data-dir {}", data_dir.display());
    println!(
        "  vledger audit-package --data-dir {} --output audit.json",
        data_dir.display()
    );

    Ok(())
}

// ── import ────────────────────────────────────────────────────────────────────

/// A single row from the import file after column mapping is applied.
#[derive(Debug)]
struct ImportRow {
    description: String,
    debit_account: String,
    credit_account: String,
    amount: i64,
    currency: String,
    domain: String,
    external_ref: Option<String>,
    idempotency_key: Option<String>,
    effective_date: Option<String>,
    /// Raw row bytes used for auto-idempotency-key generation.
    raw: String,
    /// All original source columns (pre-mapping) for metadata extraction.
    raw_fields: std::collections::HashMap<String, String>,
}

/// Column mapping: source column name → target ImportRow field name.
type ColMap = std::collections::HashMap<String, String>;

/// Checkpoint state persisted between batches for --resume.
#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct ImportState {
    pub file: String,
    pub rows_processed: u64,
    pub rows_imported: u64,
    pub rows_skipped: u64,
    pub rows_already_existed: u64,
    pub last_row_index: u64,
    pub started_at: String,
}

impl ImportState {
    fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }
    fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// Import manifest written at completion.
#[derive(Debug, serde::Serialize)]
struct ImportManifest {
    pub import_id: String,
    pub source_file: String,
    pub source_sha256: String,
    pub started_at: String,
    pub completed_at: String,
    pub dry_run: bool,
    pub rows_processed: u64,
    pub rows_imported: u64,
    pub rows_already_existed: u64,
    pub rows_skipped: u64,
    pub rows_failed: u64,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub chain_tip: String,
    pub entry_count: usize,
    pub format: String,
    pub domain: String,
    pub on_error: String,
}

#[allow(clippy::too_many_arguments)]
async fn cmd_import(
    data_dir: &PathBuf,
    file: &PathBuf,
    format: Option<&str>,
    dry_run: bool,
    mappings: &[String],
    mapping_file: Option<&std::path::Path>,
    domain: &str,
    default_currency: &str,
    id_column: Option<&str>,
    on_error: &str,
    batch_size: u64,
    state_file: &std::path::Path,
    resume: bool,
    progress_interval: u64,
    manifest_path: &std::path::Path,
    create_accounts: bool,
    metadata_columns: Option<&str>,
    wal_sync_mode: &str,
) -> Result<()> {
    if !data_dir.exists() {
        anyhow::bail!("Data directory not found — run `vledger init` first.");
    }
    if !file.exists() {
        anyhow::bail!("Import file not found: {}", file.display());
    }

    let started_at = chrono::Utc::now().to_rfc3339();

    // ── Detect format ─────────────────────────────────────────────────────
    let fmt = format.map(|s| s.to_lowercase()).unwrap_or_else(|| {
        file.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("csv")
            .to_lowercase()
    });
    if fmt != "csv" && fmt != "json" {
        anyhow::bail!("Unsupported format '{}'. Use csv or json.", fmt);
    }

    // ── Validate on_error mode ────────────────────────────────────────────
    if !["abort", "skip", "collect"].contains(&on_error) {
        anyhow::bail!("--on-error must be one of: abort, skip, collect");
    }

    // ── Build column mapping ──────────────────────────────────────────────
    let mut col_map: ColMap = ColMap::new();

    // Load from mapping file first, then --map flags override.
    if let Some(mf) = mapping_file {
        if mf.exists() {
            let raw = std::fs::read_to_string(mf)
                .with_context(|| format!("Cannot read mapping file: {}", mf.display()))?;
            let parsed: std::collections::HashMap<String, String> = serde_json::from_str(&raw)
                .with_context(|| "Mapping file must be a JSON object: {\"src\": \"target\"}")?;
            col_map.extend(parsed);
        }
    }
    for m in mappings {
        let parts: Vec<&str> = m.splitn(2, '=').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid --map value '{}'. Use: SOURCE_COL=TARGET_FIELD", m);
        }
        col_map.insert(parts[0].to_string(), parts[1].to_string());
    }

    // ── Compute source file hash (streaming — constant memory) ───────────
    // Read the file in 64 KiB chunks so a 50 GB CSV doesn't require 50 GB RAM.
    let source_sha256 = {
        use std::io::Read;
        let mut hasher = blake3::Hasher::new();
        let f = std::fs::File::open(file)
            .with_context(|| format!("Cannot read import file: {}", file.display()))?;
        let mut reader = std::io::BufReader::with_capacity(65_536, f);
        let mut buf = [0u8; 65_536];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        hex::encode(hasher.finalize().as_bytes())
    };

    // ── Count rows for the header (streaming pass — no heap allocation) ──
    // We need total_rows for progress reporting. Walk the CSV once with a
    // lightweight counter before the main import pass.
    let total_rows: u64 = {
        let f = std::fs::File::open(file)
            .with_context(|| format!("Cannot read import file: {}", file.display()))?;
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .trim(csv::Trim::All)
            .from_reader(std::io::BufReader::with_capacity(65_536, f));
        let mut count = 0u64;
        for result in reader.records() {
            result.context("Failed to read CSV record during row count")?;
            count += 1;
        }
        count
    };

    // ── Parse metadata column list ────────────────────────────────────────
    let meta_cols: Vec<&str> = metadata_columns
        .map(|s| s.split(',').map(|c| c.trim()).collect())
        .unwrap_or_default();

    println!("── VectorLedger Import ───────────────────────────");
    println!("  File       : {}", file.display());
    println!("  Format     : {}", fmt.to_uppercase());
    println!("  Rows       : {total_rows}");
    println!(
        "  Dry run    : {}",
        if dry_run {
            "YES — no data will be written"
        } else {
            "no"
        }
    );
    if !col_map.is_empty() {
        println!("  Mappings   : {}", col_map.len());
    }
    println!("  On error   : {on_error}");
    println!(
        "  Source SHA : {}...{}",
        &source_sha256[..8],
        &source_sha256[56..]
    );
    println!("──────────────────────────────────────────────────");

    // ── Load checkpoint state for resume ─────────────────────────────────
    let mut state = if resume {
        let s = ImportState::load(state_file)?;
        if s.rows_processed > 0 {
            println!("  Resuming from row {} / {total_rows}", s.rows_processed);
        }
        s
    } else {
        // Fresh run — delete any stale state file.
        if state_file.exists() {
            let _ = std::fs::remove_file(state_file);
        }
        ImportState {
            file: file.display().to_string(),
            started_at: started_at.clone(),
            ..Default::default()
        }
    };

    let skip_rows = state.last_row_index;

    // ── Open ledger in import mode (constant memory) ─────────────────────
    let sync_mode: vledger_wal::WalSyncMode = wal_sync_mode.parse().unwrap_or_else(|_| {
        eprintln!(
            "  ⚠  Unknown --wal-sync-mode '{}', defaulting to group_commit",
            wal_sync_mode
        );
        vledger_wal::WalSyncMode::GroupCommit
    });
    if sync_mode == vledger_wal::WalSyncMode::NoSync {
        eprintln!("  ⚠  --wal-sync-mode=no_sync: fsync disabled for this import.");
        eprintln!(
            "     Run `vledger verify --data-dir {}` after completion.",
            data_dir.display()
        );
    }
    // open_for_import replays WAL without loading entries into RAM.
    // Memory stays flat at O(accounts) regardless of entry count.
    let mut ledger = vledger_ledger::LedgerStore::open_for_import(data_dir, sync_mode)
        .context("Failed to open ledger. Is vledger start running? Stop it first.")?;

    // Build account lookup: code → AccountId
    let mut account_lookup: std::collections::HashMap<String, vledger_ledger::AccountId> = ledger
        .all_accounts()
        .map(|a| (a.code.clone(), a.id))
        .collect();

    // ── Helper: open a streaming CSV reader ───────────────────────────────
    // Returns (headers, reader) — each call opens a fresh file handle so
    // the same file can be streamed twice (once for dry-run, once for import)
    // without holding both in memory simultaneously.
    let open_csv =
        || -> anyhow::Result<(Vec<String>, csv::Reader<std::io::BufReader<std::fs::File>>)> {
            let f = std::fs::File::open(file)
                .with_context(|| format!("Cannot open import file: {}", file.display()))?;
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(true)
                .flexible(true)
                .trim(csv::Trim::All)
                .from_reader(std::io::BufReader::with_capacity(65_536, f));
            let headers: Vec<String> = reader
                .headers()
                .context("Failed to read CSV headers")?
                .iter()
                .map(|h| h.to_string())
                .collect();
            Ok((headers, reader))
        };

    // ── Validation / dry-run pass (streaming) ─────────────────────────────
    if dry_run || on_error == "collect" {
        println!();
        println!("  Validating rows...");

        let (headers, mut reader) = open_csv()?;
        let resolved: std::collections::HashMap<String, String> = headers
            .iter()
            .map(|h| {
                (
                    h.clone(),
                    col_map.get(h).cloned().unwrap_or_else(|| h.clone()),
                )
            })
            .collect();

        let mut validation_errors: Vec<(u64, String)> = Vec::new();
        let mut currencies_seen: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut accounts_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut row_num = 0u64;

        for result in reader.records() {
            row_num += 1;
            let record = result.context("Failed to read CSV record")?;
            let raw = record.iter().collect::<Vec<_>>().join(",");
            let mut raw_fields = std::collections::HashMap::new();
            let mut map = std::collections::HashMap::new();
            for (i, h) in headers.iter().enumerate() {
                let val = record.get(i).unwrap_or("").to_string();
                raw_fields.insert(h.clone(), val.clone());
                let target = resolved.get(h).cloned().unwrap_or_else(|| h.clone());
                map.insert(target, val);
            }
            match row_from_map(map, &raw, raw_fields, domain, default_currency) {
                Ok(row) => {
                    currencies_seen.insert(row.currency.clone());
                    accounts_seen.insert(row.debit_account.clone());
                    accounts_seen.insert(row.credit_account.clone());
                    if let Err(e) = validate_import_row(&row, &account_lookup) {
                        validation_errors.push((row_num, e.to_string()));
                    }
                }
                Err(e) => {
                    validation_errors.push((row_num, e.to_string()));
                }
            }
        }

        let valid = row_num.saturating_sub(validation_errors.len() as u64);
        let accounts_missing: Vec<_> = accounts_seen
            .iter()
            .filter(|c| !account_lookup.contains_key(*c))
            .collect();

        println!();
        println!("── Import Validation Report ─────────────────────");
        println!("  Rows detected     : {row_num}");
        println!("  Valid             : {valid}");
        println!("  Invalid           : {}", validation_errors.len());
        println!("  Accounts detected : {}", accounts_seen.len());
        println!("  Accounts missing  : {}", accounts_missing.len());
        println!(
            "  Currencies        : {}",
            currencies_seen
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );

        if !validation_errors.is_empty() {
            println!();
            println!("  Errors (first 20):");
            for (r, err) in validation_errors.iter().take(20) {
                println!("    Row {r:>8}: {err}");
            }
            if validation_errors.len() > 20 {
                println!("    ... and {} more", validation_errors.len() - 20);
            }
        }
        if !accounts_missing.is_empty() && !create_accounts {
            println!();
            println!("  Missing accounts (use --create-accounts to create them):");
            for a in accounts_missing.iter().take(10) {
                println!("    {a}");
            }
        }
        println!("──────────────────────────────────────────────────");

        if dry_run {
            if validation_errors.is_empty() {
                println!("\n  ✓  Dry run complete — no errors found.");
                println!("     Run without --dry-run to import.");
            } else {
                println!(
                    "\n  ✗  Dry run found {} error(s). Fix them before importing.",
                    validation_errors.len()
                );
            }
            println!();
            return Ok(());
        }

        if on_error == "collect" && !validation_errors.is_empty() {
            anyhow::bail!(
                "{} validation error(s) found. Fix them or use --on-error skip.",
                validation_errors.len()
            );
        }
    }

    // ── Import loop (streaming — constant memory) ─────────────────────────
    println!();
    println!("  Importing...");
    let import_start = std::time::Instant::now();
    let mut rows_failed: u64 = 0;
    let mut first_sequence: Option<u64> = None;
    let mut last_sequence: Option<u64> = None;
    let mut batch_count: u64 = 0;
    let mut row_num = 0u64;

    let (headers, mut reader) = open_csv()?;
    let resolved: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|h| {
            (
                h.clone(),
                col_map.get(h).cloned().unwrap_or_else(|| h.clone()),
            )
        })
        .collect();

    for result in reader.records() {
        row_num += 1;
        let row_num_local = row_num;

        // Skip already-processed rows on resume.
        if row_num_local <= skip_rows {
            continue;
        }

        let record = match result {
            Ok(r) => r,
            Err(e) => {
                if on_error == "abort" {
                    anyhow::bail!("Row {row_num_local}: CSV read error: {e}");
                }
                eprintln!("  ⚠  Row {row_num_local} skipped: CSV read error: {e}");
                rows_failed += 1;
                continue;
            }
        };
        let raw = record.iter().collect::<Vec<_>>().join(",");
        let mut raw_fields = std::collections::HashMap::new();
        let mut map = std::collections::HashMap::new();
        for (i, h) in headers.iter().enumerate() {
            let val = record.get(i).unwrap_or("").to_string();
            raw_fields.insert(h.clone(), val.clone());
            let target = resolved.get(h).cloned().unwrap_or_else(|| h.clone());
            map.insert(target, val);
        }

        let row = match row_from_map(map, &raw, raw_fields, domain, default_currency) {
            Ok(r) => r,
            Err(e) => {
                if on_error == "abort" {
                    anyhow::bail!("Row {row_num_local}: {e}");
                }
                eprintln!("  ⚠  Row {row_num_local} skipped: {e}");
                rows_failed += 1;
                continue;
            }
        };

        // The row_num here acts as the loop variable for the rest of the body.
        let row_num = row_num_local;

        // Build idempotency key.
        let idem_key = if let Some(ref id_col) = id_column {
            // Use the row's id_column value if present — stored in external_ref as fallback.
            row.idempotency_key
                .clone()
                .or_else(|| row.external_ref.clone())
                .unwrap_or_else(|| {
                    let raw = format!("{}:row:{}", id_col, row_num);
                    hex::encode(blake3::hash(raw.as_bytes()).as_bytes())
                })
        } else {
            // Auto: BLAKE3 of full raw row content.
            let key = format!(
                "import:{}:{}",
                &source_sha256[..16],
                hex::encode(blake3::hash(row.raw.as_bytes()).as_bytes())
            );
            key
        };

        // Resolve or create accounts.
        let debit_id = match resolve_or_create_account(
            &mut ledger,
            &mut account_lookup,
            &row.debit_account,
            &row.currency,
            &row.domain,
            create_accounts,
        ) {
            Ok(id) => id,
            Err(e) => {
                let msg = format!("debit account '{}': {}", row.debit_account, e);
                if on_error == "abort" {
                    anyhow::bail!("Row {row_num}: {msg}");
                }
                eprintln!("  ⚠  Row {row_num} skipped: {msg}");
                state.rows_skipped += 1;
                rows_failed += 1;
                continue;
            }
        };

        let credit_id = match resolve_or_create_account(
            &mut ledger,
            &mut account_lookup,
            &row.credit_account,
            &row.currency,
            &row.domain,
            create_accounts,
        ) {
            Ok(id) => id,
            Err(e) => {
                let msg = format!("credit account '{}': {}", row.credit_account, e);
                if on_error == "abort" {
                    anyhow::bail!("Row {row_num}: {msg}");
                }
                eprintln!("  ⚠  Row {row_num} skipped: {msg}");
                state.rows_skipped += 1;
                rows_failed += 1;
                continue;
            }
        };

        let amount = match vledger_ledger::Amount::new(row.amount) {
            Some(a) => a,
            None => {
                let msg = format!("amount must be non-zero (got {})", row.amount);
                if on_error == "abort" {
                    anyhow::bail!("Row {row_num}: {msg}");
                }
                eprintln!("  ⚠  Row {row_num} skipped: {msg}");
                state.rows_skipped += 1;
                rows_failed += 1;
                continue;
            }
        };

        // Parse effective_date if provided.
        let effective_at = if let Some(ref date_str) = row.effective_date {
            match chrono::DateTime::parse_from_rfc3339(date_str) {
                Ok(dt) => dt.with_timezone(&chrono::Utc),
                Err(_) => {
                    // Try YYYY-MM-DD
                    match chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                        Ok(d) => d
                            .and_hms_opt(0, 0, 0)
                            .map(|dt| {
                                chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                                    dt,
                                    chrono::Utc,
                                )
                            })
                            .unwrap_or_else(chrono::Utc::now),
                        Err(_) => chrono::Utc::now(),
                    }
                }
            }
        } else {
            chrono::Utc::now()
        };

        let mut builder = vledger_ledger::JournalEntryBuilder::new(&row.description, &row.domain)
            .debit(debit_id, amount, &row.currency)
            .credit(credit_id, amount, &row.currency)
            .effective_at(effective_at)
            .idempotency_key(&idem_key);

        if let Some(ref ext) = row.external_ref {
            if !ext.is_empty() {
                builder = builder.external_ref(ext);
            }
        }

        // Build metadata JSON from the designated extra columns.
        if !meta_cols.is_empty() {
            let mut obj = serde_json::Map::new();
            // raw is a comma-separated value string for CSV; for JSON it's
            // the serialized object. We re-parse the raw field map from the
            // row's raw string to extract the requested columns.
            // Simpler: store raw_fields on ImportRow directly.
            for col in &meta_cols {
                if let Some(val) = row.raw_fields.get(*col) {
                    obj.insert(col.to_string(), serde_json::Value::String(val.clone()));
                }
            }
            if !obj.is_empty() {
                builder = builder.metadata(serde_json::Value::Object(obj).to_string());
            }
        }

        let entry = builder.build();

        match ledger.import_entry_direct(entry) {
            Ok(0) => {
                // Idempotency key already exists — entry was previously imported.
                state.rows_already_existed += 1;
            }
            Ok(seq) => {
                if first_sequence.is_none() {
                    first_sequence = Some(seq);
                }
                last_sequence = Some(seq);
                state.rows_imported += 1;
            }
            Err(vledger_ledger::LedgerError::IdempotencyConflict(_)) => {
                state.rows_already_existed += 1;
            }
            Err(e) => {
                if on_error == "abort" {
                    anyhow::bail!("Row {row_num}: {e}");
                }
                eprintln!("  ⚠  Row {row_num} skipped: {e}");
                state.rows_skipped += 1;
                rows_failed += 1;
                continue;
            }
        }

        state.rows_processed += 1;
        state.last_row_index = row_num;
        batch_count += 1;

        // Progress reporting.
        if progress_interval > 0 && state.rows_processed % progress_interval == 0 {
            let elapsed = import_start.elapsed().as_secs_f64();
            let tps = state.rows_imported as f64 / elapsed;
            println!(
                "  {}/{} rows  |  imported: {}  existed: {}  skipped: {}  ({:.0} TPS)",
                row_num,
                total_rows,
                state.rows_imported,
                state.rows_already_existed,
                state.rows_skipped,
                tps
            );
        }

        // Checkpoint after each batch.
        if batch_count >= batch_size {
            state.save(state_file)?;
            batch_count = 0;
        }
    }

    // Final checkpoint save.
    state.save(state_file)?;

    let elapsed = import_start.elapsed();
    let tps = if elapsed.as_secs_f64() > 0.0 {
        state.rows_imported as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    let chain_tip = hex::encode(ledger.chain_tip());
    let entry_count = ledger.entry_count();
    let completed_at = chrono::Utc::now().to_rfc3339();

    // ── Import manifest ───────────────────────────────────────────────────
    let import_id = format!("imp_{}", &source_sha256[..16]);
    let manifest = ImportManifest {
        import_id: import_id.clone(),
        source_file: file.display().to_string(),
        source_sha256: source_sha256.clone(),
        started_at: started_at.clone(),
        completed_at: completed_at.clone(),
        dry_run,
        rows_processed: state.rows_processed,
        rows_imported: state.rows_imported,
        rows_already_existed: state.rows_already_existed,
        rows_skipped: state.rows_skipped,
        rows_failed,
        first_sequence,
        last_sequence,
        chain_tip: chain_tip.clone(),
        entry_count,
        format: fmt.clone(),
        domain: domain.to_string(),
        on_error: on_error.to_string(),
    };
    std::fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;

    // Clean up state file on successful completion.
    if rows_failed == 0 && state_file.exists() {
        let _ = std::fs::remove_file(state_file);
    }

    println!();
    println!("── Import Complete ───────────────────────────────");
    println!("  Source file       : {}", file.display());
    println!(
        "  Source SHA-256    : {}...{}",
        &source_sha256[..8],
        &source_sha256[56..]
    );
    println!("  Import ID         : {import_id}");
    println!();
    println!("  Rows processed    : {}", state.rows_processed);
    println!("  Rows imported     : {}", state.rows_imported);
    println!("  Already existed   : {}", state.rows_already_existed);
    println!("  Rows skipped      : {}", state.rows_skipped);
    if rows_failed > 0 {
        println!("  Rows failed       : {rows_failed}");
    }
    println!();
    if let (Some(first), Some(last)) = (first_sequence, last_sequence) {
        println!("  First sequence    : {first}");
        println!("  Last sequence     : {last}");
    }
    println!(
        "  Chain tip         : {}...{}",
        &chain_tip[..16],
        &chain_tip[48..]
    );
    println!("  Total entries     : {entry_count}");
    println!();
    println!(
        "  Elapsed           : {:.2}s  ({:.0} TPS)",
        elapsed.as_secs_f64(),
        tps
    );
    println!("  Manifest          : {}", manifest_path.display());
    println!("──────────────────────────────────────────────────");

    if rows_failed > 0 {
        anyhow::bail!("{rows_failed} row(s) failed to import.");
    }

    Ok(())
}

/// Validate a single import row without writing anything.
fn validate_import_row(
    row: &ImportRow,
    account_lookup: &std::collections::HashMap<String, vledger_ledger::AccountId>,
) -> anyhow::Result<()> {
    if row.description.is_empty() {
        anyhow::bail!("description is empty");
    }
    if row.debit_account.is_empty() {
        anyhow::bail!("debit_account is empty");
    }
    if row.credit_account.is_empty() {
        anyhow::bail!("credit_account is empty");
    }
    if row.debit_account == row.credit_account {
        anyhow::bail!("debit_account and credit_account are the same");
    }
    if row.amount <= 0 {
        anyhow::bail!("amount must be a positive integer, got {}", row.amount);
    }
    if row.currency.is_empty() {
        anyhow::bail!("currency is empty");
    }
    if !account_lookup.contains_key(&row.debit_account) {
        anyhow::bail!("debit account '{}' not found in ledger", row.debit_account);
    }
    if !account_lookup.contains_key(&row.credit_account) {
        anyhow::bail!(
            "credit account '{}' not found in ledger",
            row.credit_account
        );
    }
    Ok(())
}

/// Resolve an account code to its ID, optionally creating it if missing.
fn resolve_or_create_account(
    ledger: &mut vledger_ledger::LedgerStore,
    lookup: &mut std::collections::HashMap<String, vledger_ledger::AccountId>,
    code: &str,
    currency: &str,
    domain: &str,
    create: bool,
) -> anyhow::Result<vledger_ledger::AccountId> {
    if let Some(&id) = lookup.get(code) {
        return Ok(id);
    }
    if !create {
        anyhow::bail!(
            "account '{}' not found. Use --create-accounts to create it.",
            code
        );
    }
    // Auto-create as Suspense type with no balance constraints.
    // Suspense accounts have no normal-balance direction and do not enforce
    // non-negative balance, making them safe for migration from external
    // datasets where account types are unknown and balances may go negative
    // during the import sequence before offsetting credits arrive.
    let mut acct = vledger_ledger::Account::new(
        code,
        code, // name = code until updated
        vledger_ledger::AccountType::Suspense,
        currency,
        domain,
    );
    acct.require_non_negative_balance = false;
    let id = ledger
        .create_account(acct)
        .with_context(|| format!("Failed to create account '{code}'"))?;
    lookup.insert(code.to_string(), id);
    Ok(id)
}

/// Parse CSV bytes into `ImportRow` values using the column mapping.
fn parse_csv_rows(
    data: &[u8],
    col_map: &ColMap,
    default_domain: &str,
    default_currency: &str,
) -> anyhow::Result<Vec<ImportRow>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(data);

    let headers: Vec<String> = reader
        .headers()
        .context("Failed to read CSV headers")?
        .iter()
        .map(|h| h.to_string())
        .collect();

    // Build a resolved header name → field name map.
    let resolved: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|h| {
            let target = col_map.get(h).cloned().unwrap_or_else(|| h.clone());
            (h.clone(), target)
        })
        .collect();

    let mut rows = Vec::new();
    for result in reader.records() {
        let record = result.context("Failed to read CSV record")?;
        let raw = record.iter().collect::<Vec<_>>().join(",");
        // raw_fields: original source column names → values (before mapping)
        let mut raw_fields: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for (i, h) in headers.iter().enumerate() {
            let val = record.get(i).unwrap_or("").to_string();
            raw_fields.insert(h.clone(), val.clone());
            let target = resolved.get(h).cloned().unwrap_or_else(|| h.clone());
            map.insert(target, val);
        }
        rows.push(row_from_map(
            map,
            &raw,
            raw_fields,
            default_domain,
            default_currency,
        )?);
    }
    Ok(rows)
}

/// Parse JSON bytes (array of objects) into `ImportRow` values.
fn parse_json_rows(
    data: &[u8],
    col_map: &ColMap,
    default_domain: &str,
    default_currency: &str,
) -> anyhow::Result<Vec<ImportRow>> {
    let json_str = std::str::from_utf8(data).context("JSON file is not valid UTF-8")?;
    let records: Vec<std::collections::HashMap<String, serde_json::Value>> =
        serde_json::from_str(json_str).context("JSON file must be an array of objects")?;

    let mut rows = Vec::new();
    for record in records {
        let raw = serde_json::to_string(&record).unwrap_or_default();
        let mut raw_fields: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for (k, v) in record {
            let val = match &v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            raw_fields.insert(k.clone(), val.clone());
            let target = col_map.get(&k).cloned().unwrap_or(k);
            map.insert(target, val);
        }
        rows.push(row_from_map(
            map,
            &raw,
            raw_fields,
            default_domain,
            default_currency,
        )?);
    }
    Ok(rows)
}

/// Build an `ImportRow` from a resolved field map.
fn row_from_map(
    map: std::collections::HashMap<String, String>,
    raw: &str,
    raw_fields: std::collections::HashMap<String, String>,
    default_domain: &str,
    default_currency: &str,
) -> anyhow::Result<ImportRow> {
    let get = |key: &str| map.get(key).cloned().unwrap_or_default();

    let amount_str = get("amount");
    let amount: i64 = amount_str
        .trim()
        .parse::<i64>()
        .or_else(|_| {
            // Parse as decimal and convert to minor units (multiply by 100).
            // $915.87 → 91587 cents. This preserves cents-level precision
            // rather than rounding to the nearest whole dollar.
            amount_str
                .trim()
                .parse::<f64>()
                .map(|f| (f * 100.0).round() as i64)
        })
        .with_context(|| format!("Cannot parse amount '{}' as integer or decimal", amount_str))?;

    Ok(ImportRow {
        description: get("description"),
        debit_account: get("debit_account"),
        credit_account: get("credit_account"),
        amount,
        currency: {
            let c = get("currency");
            if c.is_empty() {
                default_currency.to_string()
            } else {
                c.to_uppercase()
            }
        },
        domain: {
            let d = get("domain");
            if d.is_empty() {
                default_domain.to_string()
            } else {
                d
            }
        },
        external_ref: {
            let v = get("external_ref");
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        },
        idempotency_key: {
            let v = get("idempotency_key");
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        },
        effective_date: {
            let v = get("effective_date");
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        },
        raw: raw.to_string(),
        raw_fields,
    })
}



// ── migrate-to-sqlite ─────────────────────────────────────────────────────────

/// One-time migration: read WAL records and populate the SQLite entry index.
///
/// Optimizations:
/// - SQLite in migration mode: journal=OFF, sync=OFF, 256MB cache, EXCLUSIVE lock
/// - 100,000-entry batches per transaction
/// - Pre-compiled INSERT statement reused per batch
/// - account_entries rebuilt in a separate pass after entries are indexed
/// - Progress printed every 1M entries
///
/// Expected throughput: 50,000-150,000 entries/sec (vs ~2,400 before).
async fn cmd_migrate_to_sqlite(data_dir: &std::path::Path) -> anyhow::Result<()> {
    use vledger_ledger::entry_db::EntryDb;
    use vledger_ledger::wal_checkpoint::WalCheckpoint;
    use vledger_wal::recovery::recover_streaming;
    use vledger_wal::record::MutationKind;

    println!("── VectorLedger SQLite Migration ──────────────────────");
    println!("  Populating SQLite index from WAL records.");
    println!("  This is a one-time operation. Safe to interrupt.");
    println!();

    let wal_dir = data_dir.join("wal");
    let db_path = data_dir.join("vledger.db");

    // Open SQLite in migration mode: aggressive PRAGMAs for bulk insert speed.
    let entry_db = EntryDb::open_for_migration(&db_path)
        .map_err(|e| anyhow::anyhow!("Cannot open SQLite index: {e}"))?;
    entry_db
        .ensure_account_entries_table()
        .map_err(|e| anyhow::anyhow!("Cannot create tables: {e}"))?;

    let already_indexed = entry_db.count().unwrap_or(0);
    let start_seq = entry_db.max_sequence().unwrap_or(0);

    println!("  Already indexed : {} entries", already_indexed);
    println!("  Resuming from   : sequence {}", start_seq + 1);
    println!();

    let segments = vledger_wal::segment::list_segments(&wal_dir)
        .map_err(|e| anyhow::anyhow!("Cannot list WAL segments: {e}"))?;
    let total_segments = segments.len();
    let est_total = total_segments as u64 * 80_000u64;
    println!("  WAL segments    : {}", total_segments);
    println!("  Est. entries    : ~{}", est_total);
    println!("  Batch size      : 100,000 entries per transaction");
    println!("  Mode            : bulk (journal=OFF, sync=OFF)");
    println!();
    println!("  Reading WAL and indexing entries...");
    println!();

    const BATCH_SIZE: usize = 100_000;
    let mut batch: Vec<vledger_ledger::entry::JournalEntry> = Vec::with_capacity(BATCH_SIZE);
    let mut indexed: u64 = 0;
    let mut skipped: u64 = 0;
    let start = std::time::Instant::now();

    let result = recover_streaming::<anyhow::Error, _>(
        &wal_dir,
        None,
        false,
        None,
        0,
        |tx| {
            for payload in tx.data_payloads {
                if !matches!(payload.mutation, MutationKind::Insert | MutationKind::Update) {
                    continue;
                }
                if payload.table_id != 1 || payload.row_data.is_empty() {
                    continue;
                }

                let entry: vledger_ledger::entry::JournalEntry =
                    bincode::serde::decode_from_slice(
                        &payload.row_data,
                        bincode::config::standard(),
                    )
                    .map(|(e, _)| e)
                    .map_err(|e| anyhow::anyhow!("decode entry: {e}"))?;

                if entry.sequence <= start_seq {
                    skipped += 1;
                    continue;
                }

                batch.push(entry);

                if batch.len() >= BATCH_SIZE {
                    let n = entry_db
                        .bulk_insert_migration(&batch)
                        .map_err(|e| anyhow::anyhow!("bulk_insert: {e}"))?;
                    indexed += n;
                    batch.clear();

                    let elapsed = start.elapsed().as_secs_f64().max(0.001);
                    let tps = indexed as f64 / elapsed;
                    let pct = if est_total > 0 {
                        (indexed + already_indexed) * 100 / est_total
                    } else {
                        0
                    };
                    eprint!(
                        "\r  Entries: {:>12}  ~{}%  ({:.0}/sec)    ",
                        indexed, pct, tps
                    );
                }
            }
            Ok(())
        },
    );

    // Flush final partial batch.
    if !batch.is_empty() {
        let n = entry_db
            .bulk_insert_migration(&batch)
            .map_err(|e| anyhow::anyhow!("final batch: {e}"))?;
        indexed += n;
    }

    result?;

    let elapsed = start.elapsed().as_secs_f64().max(0.001);
    let tps = indexed as f64 / elapsed;
    let total = already_indexed + indexed;

    eprintln!();
    println!("  ✓ Entries indexed       : {} ({:.0}/sec)", indexed, tps);
    println!("  Previously indexed      : {}", already_indexed);
    println!("  Total in SQLite         : {}", total);
    println!("  Elapsed                 : {:.1}s", elapsed);
    println!();

    // Rebuild account_entries cross-reference index.
    println!("  Rebuilding account index (pass 2 of 2)...");
    let ae_start = std::time::Instant::now();
    let mut ae_count: u64 = 0;
    let mut ae_batch: u64 = 0;

    entry_db
        .begin_bulk()
        .map_err(|e| anyhow::anyhow!("begin_bulk ae: {e}"))?;

    entry_db
        .stream_all(|entry| {
            for line in &entry.lines {
                entry_db
                    .insert_account_entry(&line.account_id, entry.sequence)
                    .map_err(|e| {
                        vledger_ledger::error::LedgerError::Serialization(format!(
                            "insert_account_entry: {e}"
                        ))
                    })?;
                ae_count += 1;
                ae_batch += 1;
            }
            if ae_batch >= 500_000 {
                let _ = entry_db.commit_bulk();
                let _ = entry_db.begin_bulk();
                ae_batch = 0;
                eprint!("\r  Account index: {:>12} lines    ", ae_count);
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("stream_all: {e}"))?;

    let _ = entry_db.commit_bulk();
    eprintln!();

    let ae_elapsed = ae_start.elapsed().as_secs_f64().max(0.001);
    println!(
        "  ✓ Account index rebuilt : {} lines in {:.1}s",
        ae_count, ae_elapsed
    );
    println!();

    // Write WAL startup checkpoint.
    let segs = vledger_wal::segment::list_segments(&wal_dir).unwrap_or_default();
    let last_seg = segs.last().copied().unwrap_or(0);
    let final_max = entry_db.max_sequence().unwrap_or(0);
    let cp = WalCheckpoint {
        sqlite_max_sequence: final_max,
        first_needed_segment: last_seg,
    };
    WalCheckpoint::write(data_dir, &cp)
        .map_err(|e| anyhow::anyhow!("Failed to write checkpoint: {e}"))?;

    println!("── Migration Complete ──────────────────────────────────");
    println!(
        "  WAL checkpoint written  : segment {} on next startup",
        last_seg
    );
    println!("──────────────────────────────────────────────────────");
    println!();
    println!("✓ Done. You can now start the server:");
    println!(
        "  nohup vledger start --data-dir {} --with-proofs &",
        data_dir.display()
    );

    Ok(())
}

//! vledger-bench — TPS benchmark for VectorLedger
//!
//! Connects to a running vledger server, authenticates, then runs a
//! configurable mixed INSERT/SELECT workload with N concurrent clients
//! and reports TPS, latency percentiles, and a structured JSON report
//! suitable for publishing as server-class benchmark numbers.
//!
//! ## Usage
//!
//! ```bash
//! # Start the server first:
//! #   vledger start --data-dir ./vledger-data --pgwire
//!
//! # Run with defaults (10 clients, 1000 txns each, mixed workload):
//! cargo run --release --package vledger-bench -- \
//!     --username admin --password <pw>
//!
//! # Full benchmark with JSON report:
//! cargo run --release --package vledger-bench -- \
//!     --clients 50 \
//!     --transactions 5000 \
//!     --workload mixed \
//!     --server 127.0.0.1:5433 \
//!     --username admin \
//!     --password secret \
//!     --instance-type "AWS c7g.xlarge" \
//!     --storage-type "EBS gp3" \
//!     --wal-sync-mode group_commit \
//!     --report ./benchmark-results.json
//! ```

use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Barrier;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(name = "vledger-bench", about = "TPS benchmark tool for VectorLedger")]
struct Cli {
    /// Server address to benchmark against.
    #[arg(long, default_value = "127.0.0.1:5433")]
    server: String,

    /// Username to authenticate with.
    #[arg(short, long, default_value = "admin")]
    username: String,

    /// Password for authentication.
    #[arg(short, long, default_value = "admin")]
    password: String,

    /// Number of concurrent client connections.
    #[arg(short, long, default_value_t = 10)]
    clients: usize,

    /// Number of transactions each client sends.
    #[arg(short, long, default_value_t = 1000)]
    transactions: usize,

    /// Workload type: insert | select | mixed (70% INSERT / 30% SELECT)
    #[arg(short, long, default_value = "mixed")]
    workload: String,

    /// Warm-up transactions per client (not counted in results).
    #[arg(long, default_value_t = 50)]
    warmup: usize,

    /// Instance type label for the report (e.g. "AWS c7g.xlarge").
    #[arg(long, default_value = "unknown")]
    instance_type: String,

    /// Storage type label for the report (e.g. "EBS gp3", "local NVMe").
    #[arg(long, default_value = "unknown")]
    storage_type: String,

    /// WAL sync mode used by the server (for report metadata).
    #[arg(long, default_value = "group_commit")]
    wal_sync_mode: String,

    /// Write a structured JSON report to this file.
    #[arg(long)]
    report: Option<std::path::PathBuf>,

    /// Print every individual latency sample (noisy at scale).
    #[arg(long)]
    verbose: bool,
}

// ── TLS helper — accepts self-signed certs (loopback dev default) ─────────────

#[derive(Debug)]
struct AcceptAnyCert;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8],
        _: &tokio_rustls::rustls::pki_types::CertificateDer,
        _: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8],
        _: &tokio_rustls::rustls::pki_types::CertificateDer,
        _: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        vec![
            tokio_rustls::rustls::SignatureScheme::ED25519,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA512,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA384,
            tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

// ── Per-client result ─────────────────────────────────────────────────────────

struct ClientResult {
    latencies_us: Vec<u64>,
    errors:       usize,
}

// ── Single-client worker ──────────────────────────────────────────────────────

async fn run_client(
    cli:       Arc<Cli>,
    tls_cfg:   Arc<ClientConfig>,
    barrier:   Arc<Barrier>,
    client_id: usize,
) -> ClientResult {
    let mut latencies = Vec::with_capacity(cli.transactions);
    let mut errors    = 0usize;

    let addr      = &cli.server;
    let host_part = addr.split(':').next().unwrap_or("127.0.0.1");
    let port: u16 = addr.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(5433);

    let tcp = match tokio::net::TcpStream::connect((host_part, port)).await {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("[client {client_id}] TCP connect failed: {e}");
            return ClientResult { latencies_us: vec![], errors: cli.transactions };
        }
    };

    let connector   = TlsConnector::from(tls_cfg);
    let server_name = match ServerName::try_from(host_part.to_string()) {
        Ok(n)  => n,
        Err(e) => {
            eprintln!("[client {client_id}] Invalid server name: {e}");
            return ClientResult { latencies_us: vec![], errors: cli.transactions };
        }
    };
    let tls = match connector.connect(server_name, tcp).await {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("[client {client_id}] TLS handshake failed: {e}");
            return ClientResult { latencies_us: vec![], errors: cli.transactions };
        }
    };

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();

    // Authenticate
    let auth = serde_json::json!({
        "auth": { "username": cli.username, "password": cli.password }
    });
    if write_half.write_all(format!("{auth}\n").as_bytes()).await.is_err() {
        return ClientResult { latencies_us: vec![], errors: cli.transactions };
    }
    let auth_line = match lines.next_line().await {
        Ok(Some(l)) => l,
        _ => return ClientResult { latencies_us: vec![], errors: cli.transactions },
    };
    let auth_resp: serde_json::Value = serde_json::from_str(&auth_line).unwrap_or_default();
    if !auth_resp["ok"].as_bool().unwrap_or(false) {
        eprintln!("[client {client_id}] Auth failed: {}",
            auth_resp["error"].as_str().unwrap_or("unknown"));
        return ClientResult { latencies_us: vec![], errors: cli.transactions };
    }
    let token = auth_resp["token"].as_str().unwrap_or("").to_string();

    // Ensure benchmark accounts exist for this client
    for (code, acct_type) in [
        (format!("bench-debit-{client_id}"),  "asset"),
        (format!("bench-credit-{client_id}"), "income"),
    ] {
        let sql = format!(
            "INSERT INTO accounts (code, name, account_type, currency, domain) \
             VALUES ('{code}', '{code}', '{acct_type}', 'USD', 'benchmark')"
        );
        let req = serde_json::json!({ "sql": sql, "token": token });
        let _ = write_half.write_all(format!("{req}\n").as_bytes()).await;
        let _ = lines.next_line().await; // ignore duplicate-key errors
    }

    // Warm-up (not counted in results)
    for i in 0..cli.warmup {
        let sql = make_sql(&cli.workload, client_id, i);
        let req = serde_json::json!({ "sql": sql, "token": token });
        let _ = write_half.write_all(format!("{req}\n").as_bytes()).await;
        let _ = lines.next_line().await;
    }

    // Synchronise — all clients start their measured window simultaneously
    barrier.wait().await;

    // Measured transactions
    for i in 0..cli.transactions {
        let sql = make_sql(&cli.workload, client_id, cli.warmup + i);
        let req = serde_json::json!({ "sql": sql, "token": token });

        let t0 = Instant::now();
        if write_half.write_all(format!("{req}\n").as_bytes()).await.is_err() {
            errors += 1;
            continue;
        }
        let resp_line = match lines.next_line().await {
            Ok(Some(l)) => l,
            _ => { errors += 1; continue; }
        };
        let elapsed_us = t0.elapsed().as_micros() as u64;

        let resp: serde_json::Value = serde_json::from_str(&resp_line).unwrap_or_default();
        if !resp["ok"].as_bool().unwrap_or(false) {
            errors += 1;
            if cli.verbose {
                eprintln!("[client {client_id}] txn {i} error: {}",
                    resp["error"].as_str().unwrap_or("?"));
            }
        } else {
            latencies.push(elapsed_us);
            if cli.verbose {
                println!("[client {client_id}] txn {i} — {elapsed_us} µs");
            }
        }
    }

    ClientResult { latencies_us: latencies, errors }
}

// ── SQL workload generator ────────────────────────────────────────────────────

fn make_sql(workload: &str, client_id: usize, seq: usize) -> String {
    let unique_id = client_id * 10_000_000 + seq;
    match workload {
        "select" => "SELECT * FROM ledger LIMIT 10".to_string(),
        "mixed" => {
            if seq % 10 < 7 {
                format!(
                    "INSERT INTO ledger \
                     (description, debit_account, credit_account, amount, currency, domain) \
                     VALUES ('bench-{unique_id}', 'bench-debit-{client_id}', \
                             'bench-credit-{client_id}', 1000, 'USD', 'benchmark')"
                )
            } else {
                "SELECT * FROM ledger LIMIT 10".to_string()
            }
        }
        _ => format!(
            "INSERT INTO ledger \
             (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('bench-{unique_id}', 'bench-debit-{client_id}', \
                     'bench-credit-{client_id}', 1000, 'USD', 'benchmark')"
        ),
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() { return 0; }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn print_histogram(sorted: &[u64]) {
    if sorted.is_empty() { return; }
    let min     = *sorted.first().unwrap();
    let max     = *sorted.last().unwrap();
    let range   = (max - min).max(1);
    let buckets = 10usize;
    let width   = range / buckets as u64 + 1;

    println!("\n  Latency histogram (µs):");
    for b in 0..buckets {
        let lo    = min + b as u64 * width;
        let hi    = lo + width;
        let count = sorted.iter().filter(|&&v| v >= lo && v < hi).count();
        let bar   = "#".repeat(
            (count * 40 / sorted.len().max(1)).max(if count > 0 { 1 } else { 0 })
        );
        println!("  {:>7}–{:<7} | {:<40} {}", lo, hi, bar, count);
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let cli = Arc::new(Cli::parse());

    println!("── VectorLedger TPS Benchmark ───────────────────");
    println!("  Server        : {}", cli.server);
    println!("  Clients       : {}", cli.clients);
    println!("  Txns/client   : {}", cli.transactions);
    println!("  Total txns    : {}", cli.clients * cli.transactions);
    println!("  Workload      : {}", cli.workload);
    println!("  Warm-up       : {} txns/client", cli.warmup);
    println!("  Instance type : {}", cli.instance_type);
    println!("  Storage       : {}", cli.storage_type);
    println!("  WAL sync mode : {}", cli.wal_sync_mode);
    println!("──────────────────────────────────────────────────");

    let total_txns = cli.clients * cli.transactions;

    let tls_cfg = Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth()
    );

    let barrier = Arc::new(Barrier::new(cli.clients));

    print!("  Connecting and warming up {} clients... ", cli.clients);
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    let wall_start = Instant::now();
    let mut handles = Vec::with_capacity(cli.clients);
    for id in 0..cli.clients {
        handles.push(tokio::spawn(run_client(
            Arc::clone(&cli),
            Arc::clone(&tls_cfg),
            Arc::clone(&barrier),
            id,
        )));
    }

    let mut all_latencies: Vec<u64> = Vec::with_capacity(total_txns);
    let mut total_errors = 0usize;
    for handle in handles {
        match handle.await {
            Ok(r)  => { all_latencies.extend_from_slice(&r.latencies_us); total_errors += r.errors; }
            Err(e) => eprintln!("Client task panicked: {e}"),
        }
    }

    let wall_elapsed = wall_start.elapsed();
    let successful   = all_latencies.len();
    all_latencies.sort_unstable();

    let tps     = successful as f64 / wall_elapsed.as_secs_f64();
    let avg_us  = if successful > 0 { all_latencies.iter().sum::<u64>() / successful as u64 } else { 0 };
    let min_us  = all_latencies.first().copied().unwrap_or(0);
    let max_us  = all_latencies.last().copied().unwrap_or(0);
    let p50_us  = percentile(&all_latencies, 50.0);
    let p90_us  = percentile(&all_latencies, 90.0);
    let p95_us  = percentile(&all_latencies, 95.0);
    let p99_us  = percentile(&all_latencies, 99.0);
    let p999_us = percentile(&all_latencies, 99.9);

    println!("done.\n");
    println!("── Results ──────────────────────────────────────");
    println!("  Wall time     : {:.3} s", wall_elapsed.as_secs_f64());
    println!("  Successful    : {successful} / {total_txns}");
    println!("  Errors        : {total_errors}");
    println!("  TPS           : {tps:.1}");
    println!();
    println!("  Latency       µs          ms");
    println!("    min  : {:>10}   {:>8.3}", min_us,  min_us  as f64 / 1000.0);
    println!("    avg  : {:>10}   {:>8.3}", avg_us,  avg_us  as f64 / 1000.0);
    println!("    p50  : {:>10}   {:>8.3}", p50_us,  p50_us  as f64 / 1000.0);
    println!("    p90  : {:>10}   {:>8.3}", p90_us,  p90_us  as f64 / 1000.0);
    println!("    p95  : {:>10}   {:>8.3}", p95_us,  p95_us  as f64 / 1000.0);
    println!("    p99  : {:>10}   {:>8.3}", p99_us,  p99_us  as f64 / 1000.0);
    println!("    p99.9: {:>10}   {:>8.3}", p999_us, p999_us as f64 / 1000.0);
    println!("    max  : {:>10}   {:>8.3}", max_us,  max_us  as f64 / 1000.0);

    print_histogram(&all_latencies);

    // ── Structured JSON report ────────────────────────────────────────────
    if let Some(ref report_path) = cli.report {
        let report = serde_json::json!({
            "benchmark": {
                "run_at":                   chrono::Utc::now().to_rfc3339(),
                "server":                   cli.server,
                "clients":                  cli.clients,
                "transactions_per_client":  cli.transactions,
                "total_transactions":       total_txns,
                "workload":                 cli.workload,
                "warmup_per_client":        cli.warmup,
            },
            "environment": {
                "instance_type":  cli.instance_type,
                "storage_type":   cli.storage_type,
                "wal_sync_mode":  cli.wal_sync_mode,
                "os":             std::env::consts::OS,
                "arch":           std::env::consts::ARCH,
            },
            "results": {
                "wall_time_s": wall_elapsed.as_secs_f64(),
                "tps":         tps,
                "successful":  successful,
                "errors":      total_errors,
                "latency_us":  {
                    "min":   min_us,
                    "avg":   avg_us,
                    "p50":   p50_us,
                    "p90":   p90_us,
                    "p95":   p95_us,
                    "p99":   p99_us,
                    "p99_9": p999_us,
                    "max":   max_us,
                },
                "latency_ms": {
                    "min":   min_us  as f64 / 1000.0,
                    "avg":   avg_us  as f64 / 1000.0,
                    "p50":   p50_us  as f64 / 1000.0,
                    "p90":   p90_us  as f64 / 1000.0,
                    "p95":   p95_us  as f64 / 1000.0,
                    "p99":   p99_us  as f64 / 1000.0,
                    "p99_9": p999_us as f64 / 1000.0,
                    "max":   max_us  as f64 / 1000.0,
                },
            },
        });

        let json_str = serde_json::to_string_pretty(&report)?;
        std::fs::write(report_path, &json_str)?;
        println!("\n  Report written : {}", report_path.display());
    }

    println!("\n──────────────────────────────────────────────────");
    if total_errors > 0 {
        eprintln!("  ⚠  {total_errors} error(s) — check server logs");
        std::process::exit(1);
    }
    Ok(())
}

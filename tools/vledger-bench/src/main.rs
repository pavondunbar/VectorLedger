//! vledger-bench — TPS benchmark for VectorLedger
//!
//! Connects to a running vledger server, authenticates, then hammers it with
//! SQL transactions from N concurrent clients and reports throughput and
//! latency percentiles.
//!
//! ## Usage
//!
//! ```bash
//! # Start the server first:
//! #   export VectorLedger_MASTER_KEY=$(openssl rand -hex 32)
//! #   vledger init --key-source env
//! #   vledger start
//!
//! # Run with defaults (10 clients, 1000 txns each, INSERT workload):
//! cargo run --release --package vledger-bench
//!
//! # Run with custom options:
//! cargo run --release --package vledger-bench -- \
//!     --clients 50 \
//!     --transactions 5000 \
//!     --workload mixed \
//!     --server 127.0.0.1:5433 \
//!     --username admin \
//!     --password secret
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
#[command(
    name = "vledger-bench",
    about = "TPS benchmark tool for VectorLedger",
    long_about = None,
)]
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

    /// Workload type.
    ///
    /// insert — INSERT only (write-heavy)
    /// select — SELECT only (read-heavy)
    /// mixed  — 70% INSERT, 30% SELECT
    #[arg(short, long, default_value = "insert")]
    workload: String,

    /// Warm-up transactions per client (not counted in results).
    #[arg(long, default_value_t = 50)]
    warmup: usize,

    /// Print every individual latency sample (useful for debugging; noisy at scale).
    #[arg(long)]
    verbose: bool,
}

// ── TLS helper — accepts self-signed certs (dev default) ─────────────────────

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
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
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
    latencies_us: Vec<u64>,   // per-txn latency in microseconds
    errors:       usize,
}

// ── Single-client worker ──────────────────────────────────────────────────────

async fn run_client(
    cli:      Arc<Cli>,
    tls_cfg:  Arc<ClientConfig>,
    barrier:  Arc<Barrier>,
    client_id: usize,
) -> ClientResult {
    let mut latencies = Vec::with_capacity(cli.transactions);
    let mut errors    = 0usize;

    // ── Connect ───────────────────────────────────────────────────────────
    let addr       = &cli.server;
    let host_part  = addr.split(':').next().unwrap_or("127.0.0.1");
    let port: u16  = addr.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(5433);

    let tcp = match tokio::net::TcpStream::connect((host_part, port)).await {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("[client {client_id}] TCP connect failed: {e}");
            return ClientResult { latencies_us: vec![], errors: cli.transactions };
        }
    };

    let connector   = TlsConnector::from(tls_cfg);
    let server_name = ServerName::try_from(host_part.to_string())
        .expect("invalid server hostname");
    let tls = match connector.connect(server_name, tcp).await {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("[client {client_id}] TLS handshake failed: {e}");
            return ClientResult { latencies_us: vec![], errors: cli.transactions };
        }
    };

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut lines = BufReader::new(read_half).lines();

    // ── Authenticate ──────────────────────────────────────────────────────
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
    let auth_resp: serde_json::Value = match serde_json::from_str(&auth_line) {
        Ok(v) => v,
        Err(_) => return ClientResult { latencies_us: vec![], errors: cli.transactions },
    };
    if !auth_resp["ok"].as_bool().unwrap_or(false) {
        eprintln!(
            "[client {client_id}] Auth failed: {}",
            auth_resp["error"].as_str().unwrap_or("unknown")
        );
        return ClientResult { latencies_us: vec![], errors: cli.transactions };
    }
    let token = auth_resp["token"].as_str().unwrap_or("").to_string();

    // ── Warm-up ───────────────────────────────────────────────────────────
    // First, ensure the debit and credit accounts exist for this client.
    for (acct_id, acct_type) in [
        (format!("acct-debit-{client_id}"),  "asset"),
        (format!("acct-credit-{client_id}"), "income"),
    ] {
        let sql = format!(
            "INSERT INTO accounts (code, name, account_type, currency, domain) \
             VALUES ('{acct_id}', '{acct_id}', '{acct_type}', 'USD', 'benchmark')"
        );
        let req = serde_json::json!({ "sql": sql, "token": token });
        let _ = write_half.write_all(format!("{req}\n").as_bytes()).await;
        let _ = lines.next_line().await; // ignore duplicate-key errors
    }

    for i in 0..cli.warmup {
        let sql = make_sql(&cli.workload, client_id, i);
        let req = serde_json::json!({ "sql": sql, "token": token });
        let _ = write_half.write_all(format!("{req}\n").as_bytes()).await;
        let _ = lines.next_line().await;
    }

    // ── Wait for all clients to finish warm-up before starting the clock ──
    barrier.wait().await;

    // ── Measured transactions ─────────────────────────────────────────────
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

        let resp: serde_json::Value = match serde_json::from_str(&resp_line) {
            Ok(v) => v,
            Err(_) => { errors += 1; continue; }
        };

        if !resp["ok"].as_bool().unwrap_or(false) {
            errors += 1;
            if cli.verbose {
                eprintln!(
                    "[client {client_id}] txn {i} error: {}",
                    resp["error"].as_str().unwrap_or("?")
                );
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
    // Use a simple counter as the unique key.
    let unique_id = client_id * 1_000_000 + seq;

    match workload {
        "select" => {
            "SELECT * FROM ledger LIMIT 10".to_string()
        }
        "mixed" => {
            if seq % 10 < 7 {
                format!(
                    "INSERT INTO ledger (description, debit_account, credit_account, amount, currency) \
                     VALUES ('bench-{unique_id}', 'acct-debit-{client_id}', 'acct-credit-{client_id}', 100, 'USD')"
                )
            } else {
                "SELECT * FROM ledger LIMIT 10".to_string()
            }
        }
        // "insert" and default
        _ => {
            format!(
                "INSERT INTO ledger (description, debit_account, credit_account, amount, currency) \
                 VALUES ('bench-{unique_id}', 'acct-debit-{client_id}', 'acct-credit-{client_id}', 100, 'USD')"
            )
        }
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
    let min   = *sorted.first().unwrap();
    let max   = *sorted.last().unwrap();
    let range = (max - min).max(1);
    let buckets = 10usize;
    let width   = range / buckets as u64 + 1;

    println!("\n  Latency histogram (µs):");
    for b in 0..buckets {
        let lo    = min + b as u64 * width;
        let hi    = lo + width;
        let count = sorted.iter().filter(|&&v| v >= lo && v < hi).count();
        let bar   = "#".repeat((count * 40 / sorted.len().max(1)).max(if count > 0 { 1 } else { 0 }));
        println!("  {:>7}–{:<7} | {:<40} {}", lo, hi, bar, count);
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let cli = Arc::new(Cli::parse());

    println!("── VectorLedger TPS Benchmark ───────────────────");
    println!("  Server      : {}", cli.server);
    println!("  Clients     : {}", cli.clients);
    println!("  Txns/client : {}", cli.transactions);
    println!("  Workload    : {}", cli.workload);
    println!("  Warm-up     : {} txns/client", cli.warmup);
    println!("──────────────────────────────────────────────────");

    let total_txns = cli.clients * cli.transactions;

    // Build TLS config (accept self-signed for dev)
    let tls_cfg = Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth()
    );

    // Barrier ensures all clients start their measured window simultaneously
    let barrier = Arc::new(Barrier::new(cli.clients));

    // Spawn all client tasks
    let wall_start = Instant::now();
    let mut handles = Vec::with_capacity(cli.clients);
    for id in 0..cli.clients {
        let cli_c     = Arc::clone(&cli);
        let tls_c     = Arc::clone(&tls_cfg);
        let barrier_c = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            run_client(cli_c, tls_c, barrier_c, id).await
        }));
    }

    // Collect results
    let mut all_latencies: Vec<u64> = Vec::with_capacity(total_txns);
    let mut total_errors = 0usize;
    for handle in handles {
        match handle.await {
            Ok(r) => {
                all_latencies.extend_from_slice(&r.latencies_us);
                total_errors += r.errors;
            }
            Err(e) => eprintln!("Client task panicked: {e}"),
        }
    }

    let wall_elapsed = wall_start.elapsed();
    let successful   = all_latencies.len();

    // Sort for percentiles
    all_latencies.sort_unstable();

    // Compute stats
    let tps = successful as f64 / wall_elapsed.as_secs_f64();
    let avg = if successful > 0 {
        all_latencies.iter().sum::<u64>() / successful as u64
    } else { 0 };

    println!("\n── Results ──────────────────────────────────────");
    println!("  Wall time   : {:.3} s", wall_elapsed.as_secs_f64());
    println!("  Successful  : {successful} / {total_txns}");
    println!("  Errors      : {total_errors}");
    println!("  TPS         : {tps:.1}  transactions/second");
    println!();
    println!("  Latency (µs):");
    println!("    min  : {}", all_latencies.first().copied().unwrap_or(0));
    println!("    avg  : {avg}");
    println!("    p50  : {}", percentile(&all_latencies, 50.0));
    println!("    p90  : {}", percentile(&all_latencies, 90.0));
    println!("    p95  : {}", percentile(&all_latencies, 95.0));
    println!("    p99  : {}", percentile(&all_latencies, 99.0));
    println!("    max  : {}", all_latencies.last().copied().unwrap_or(0));

    print_histogram(&all_latencies);

    println!("\n── Interpretation ───────────────────────────────");
    println!("  TPS < 1,000        — expected for a single dev node on a laptop");
    println!("  TPS 1,000–10,000   — good for a production single node");
    println!("  TPS > 10,000       — excellent; likely bottlenecked by client");
    println!("  p99 latency        — the number your SLA should be written against");
    println!("  errors > 0         — check server logs; likely auth or schema mismatch");
    println!("──────────────────────────────────────────────────\n");

    if total_errors > 0 {
        std::process::exit(1);
    }
    Ok(())
}

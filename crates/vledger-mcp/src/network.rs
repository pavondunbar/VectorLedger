//! Network-mode tool executor for the VectorLedger MCP server.
//!
//! When `vledger mcp --server host:port` is used, the MCP server does NOT
//! open the data directory directly (which would conflict with a running
//! `vledger start` process). Instead, every tool call is translated to a
//! SQL statement and sent to the running server over its native TLS JSON
//! protocol (the same protocol used by `vledger sql --server`).
//!
//! This module owns the connection lifecycle: it authenticates once at
//! startup and keeps the TLS stream open for the lifetime of the MCP server.
//! Individual tool calls acquire a mutex, send one JSON frame, and read one
//! response frame.

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tracing::debug;

use std::sync::Arc;

// ── Connection handle ─────────────────────────────────────────────────────────

/// A persistent, authenticated connection to a running `vledger start` server.
///
/// Thread-safe: each call acquires the inner mutex for its request/response
/// round-trip, then releases it.  The connection is kept open between calls.
pub struct NetworkConnection {
    inner: Arc<Mutex<ConnectionInner>>,
}

struct ConnectionInner {
    write_half: tokio::io::WriteHalf<TlsStream<TcpStream>>,
    lines: tokio::io::Lines<BufReader<tokio::io::ReadHalf<TlsStream<TcpStream>>>>,
    token: String,
}

impl NetworkConnection {
    /// Connect to a running vledger server, authenticate, and return a handle.
    ///
    /// `ca_cert_path` — path to PEM CA certificate.  Pass `None` for loopback
    /// connections (self-signed certificate accepted with a warning).
    pub async fn connect(
        addr: &str,
        username: &str,
        password: &str,
        ca_cert_path: Option<&str>,
    ) -> Result<Self> {
        use tokio_rustls::rustls::pki_types::ServerName;

        let host_part = addr.split(':').next().unwrap_or("127.0.0.1");
        let port: u16 = addr
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(5433);

        let is_loopback = host_part == "127.0.0.1"
            || host_part == "::1"
            || host_part.eq_ignore_ascii_case("localhost");

        let tls_config: ClientConfig = if let Some(ca_path) = ca_cert_path {
            let ca_pem = std::fs::read(ca_path)
                .with_context(|| format!("Cannot read CA certificate: {ca_path}"))?;
            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
                root_store
                    .add(cert.context("Invalid CA certificate DER")?)
                    .context("Failed to add CA cert to root store")?;
            }
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else if is_loopback {
            tracing::warn!(
                "TLS certificate verification DISABLED for loopback MCP→server connection to {addr}."
            );
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
                .with_no_client_auth()
        } else {
            anyhow::bail!(
                "TLS certificate verification is required for non-loopback connections.\n\
                 Provide the server's CA certificate with --ca-cert <path>."
            );
        };

        let connector = TlsConnector::from(Arc::new(tls_config));
        let tcp = TcpStream::connect((host_part, port))
            .await
            .with_context(|| format!("Cannot connect to vledger server at {addr}"))?;

        let server_name = ServerName::try_from(host_part.to_string())
            .map_err(|_| anyhow::anyhow!("Invalid server hostname: {host_part}"))?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("TLS handshake with vledger server failed")?;

        let (read_half, mut write_half) = tokio::io::split(tls);
        let mut lines = BufReader::new(read_half).lines();

        // Authenticate
        let auth_req = serde_json::json!({
            "auth": { "username": username, "password": password }
        });
        write_half
            .write_all(format!("{}\n", auth_req).as_bytes())
            .await
            .context("Failed to send auth frame")?;
        write_half.flush().await?;

        let auth_line = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Server closed connection during auth"))?;
        let auth_resp: Value =
            serde_json::from_str(&auth_line).context("Invalid auth response from server")?;

        if !auth_resp["ok"].as_bool().unwrap_or(false) {
            anyhow::bail!(
                "MCP→server authentication failed: {}",
                auth_resp["error"].as_str().unwrap_or("unknown error")
            );
        }

        let token = auth_resp["token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Server did not return a session token"))?
            .to_string();

        tracing::info!(addr, "MCP server authenticated against vledger server");

        Ok(Self {
            inner: Arc::new(Mutex::new(ConnectionInner {
                write_half,
                lines,
                token,
            })),
        })
    }

    /// Execute a SQL statement against the remote server and return the
    /// raw JSON response value.
    pub async fn execute_sql(&self, sql: &str) -> Result<Value> {
        let mut guard = self.inner.lock().await;
        let ConnectionInner { write_half, lines, token } = &mut *guard;

        let req = serde_json::json!({ "sql": sql, "token": token });
        write_half
            .write_all(format!("{}\n", req).as_bytes())
            .await
            .context("Failed to send SQL frame to server")?;
        write_half.flush().await?;

        let resp_line = lines
            .next_line()
            .await?
            .ok_or_else(|| anyhow::anyhow!("Server closed connection during SQL execution"))?;

        debug!(sql, "SQL response received");

        serde_json::from_str::<Value>(&resp_line).context("Invalid SQL response from server")
    }
}

// ── AcceptAnyCert (loopback only) ─────────────────────────────────────────────

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
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::ServerCertVerified,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dh_params: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dh_params: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
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

// ── Network-mode tool dispatcher ──────────────────────────────────────────────

/// Convert a server JSON response into a human-readable MCP content string.
fn response_to_text(resp: &Value) -> String {
    if !resp["ok"].as_bool().unwrap_or(false) {
        return format!(
            "Error: {}",
            resp["error"].as_str().unwrap_or("unknown error")
        );
    }

    let cols: Vec<&str> = resp["columns"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    if cols.is_empty() {
        return resp["message"].as_str().unwrap_or("").to_string();
    }

    let mut out = String::new();
    out.push_str(&cols.join(" | "));
    out.push('\n');
    out.push_str(
        &cols.iter().map(|c| "-".repeat(c.len())).collect::<Vec<_>>().join("-+-"),
    );
    out.push('\n');

    if let Some(rows) = resp["rows"].as_array() {
        for row in rows {
            if let Some(vals) = row.as_array() {
                let cells: Vec<String> = vals
                    .iter()
                    .map(|v| v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string()))
                    .collect();
                out.push_str(&cells.join(" | "));
                out.push('\n');
            }
        }
    }

    out.push_str(&format!("\n{}\n", resp["message"].as_str().unwrap_or("")));

    if let Some(proof) = resp.get("proof").filter(|p| !p.is_null()) {
        let root = proof["root_hex"].as_str().unwrap_or("");
        let leaves = proof["leaf_count"].as_u64().unwrap_or(0);
        let verified = proof["verified"].as_bool().unwrap_or(false);
        if !root.is_empty() {
            out.push_str(&format!(
                "\nMerkle proof: {} leaves — root {} ({})\n",
                leaves,
                root,
                if verified { "verified" } else { "unverified" }
            ));
        }
    }

    out
}

fn ok_text(text: impl Into<String>) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": false
    })
}

fn err_text(text: impl Into<String>) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": true
    })
}

fn escape(s: &str) -> String {
    s.replace('\'', "''")
}

fn format_amount(minor_units: i64, currency: &str) -> String {
    let zero_decimal = matches!(currency, "JPY" | "KRW" | "VND" | "CLP" | "IDR");
    if zero_decimal {
        format!("{currency} {minor_units}")
    } else {
        let dollars = minor_units / 100;
        let cents = (minor_units % 100).abs();
        format!("{currency} {dollars}.{cents:02}")
    }
}

/// Dispatch a tool call in network mode (proxy to running vledger server).
pub async fn dispatch_tool_network(
    name: &str,
    args: &Value,
    conn: &NetworkConnection,
) -> Result<Value> {
    match name {
        "query_ledger" => {
            let sql = args["sql"].as_str()
                .ok_or_else(|| anyhow::anyhow!("'sql' is required"))?;
            match conn.execute_sql(sql).await {
                Ok(resp) => Ok(ok_text(response_to_text(&resp))),
                Err(e) => Ok(err_text(format!("Query failed: {e}"))),
            }
        }

        "post_entry" => {
            let description    = args["description"].as_str().ok_or_else(|| anyhow::anyhow!("'description' required"))?;
            let debit_account  = args["debit_account"].as_str().ok_or_else(|| anyhow::anyhow!("'debit_account' required"))?;
            let credit_account = args["credit_account"].as_str().ok_or_else(|| anyhow::anyhow!("'credit_account' required"))?;
            let amount         = args["amount"].as_i64().ok_or_else(|| anyhow::anyhow!("'amount' required"))?;
            let currency       = args["currency"].as_str().ok_or_else(|| anyhow::anyhow!("'currency' required"))?;
            let domain         = args["domain"].as_str().unwrap_or("main");
            let external_ref   = args["external_ref"].as_str().unwrap_or("");
            let metadata       = args["metadata"].as_str().unwrap_or("");

            if amount <= 0 {
                return Ok(err_text("'amount' must be positive integer in minor units"));
            }

            let sql = if !metadata.is_empty() {
                format!("INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref, metadata) VALUES ('{}','{}','{}',{},'{}','{}','{}','{}')",
                    escape(description), escape(debit_account), escape(credit_account),
                    amount, escape(currency), escape(domain), escape(external_ref), escape(metadata))
            } else if !external_ref.is_empty() {
                format!("INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref) VALUES ('{}','{}','{}',{},'{}','{}','{}')",
                    escape(description), escape(debit_account), escape(credit_account),
                    amount, escape(currency), escape(domain), escape(external_ref))
            } else {
                format!("INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) VALUES ('{}','{}','{}',{},'{}','{}')",
                    escape(description), escape(debit_account), escape(credit_account),
                    amount, escape(currency), escape(domain))
            };

            match conn.execute_sql(&sql).await {
                Ok(resp) => Ok(ok_text(response_to_text(&resp))),
                Err(e) => Ok(err_text(format!("Failed to post entry: {e}"))),
            }
        }

        "get_balance" => {
            let account = args["account"].as_str().ok_or_else(|| anyhow::anyhow!("'account' required"))?;
            let sql = format!("SELECT BALANCE('{}')", escape(account));
            match conn.execute_sql(&sql).await {
                Ok(resp) => Ok(ok_text(response_to_text(&resp))),
                Err(e) => Ok(err_text(format!("Balance query failed: {e}"))),
            }
        }

        "list_accounts" => {
            let mut conditions = Vec::new();
            if let Some(d) = args["domain"].as_str() { conditions.push(format!("domain = '{}'", escape(d))); }
            if let Some(c) = args["currency"].as_str() { conditions.push(format!("currency = '{}'", escape(c))); }
            let sql = if conditions.is_empty() {
                "SELECT id, code, name, account_type, currency, domain, balance FROM accounts".to_string()
            } else {
                format!("SELECT id, code, name, account_type, currency, domain, balance FROM accounts WHERE {}", conditions.join(" AND "))
            };
            match conn.execute_sql(&sql).await {
                Ok(resp) => Ok(ok_text(response_to_text(&resp))),
                Err(e) => Ok(err_text(format!("List accounts failed: {e}"))),
            }
        }

        "query_ledger_lines" => {
            let limit = args["limit"].as_u64().unwrap_or(100);
            let mut conditions = Vec::new();
            if let Some(d) = args["domain"].as_str() { conditions.push(format!("domain = '{}'", escape(d))); }
            if let Some(dc) = args["dr_cr"].as_str() {
                if dc != "Debit" && dc != "Credit" { return Ok(err_text("'dr_cr' must be 'Debit' or 'Credit'")); }
                conditions.push(format!("dr_cr = '{dc}'"));
            }
            let sql = if conditions.is_empty() {
                format!("SELECT date, sequence, entry_id, description, dr_cr, amount, currency, domain FROM ledger_lines LIMIT {limit}")
            } else {
                format!("SELECT date, sequence, entry_id, description, dr_cr, amount, currency, domain FROM ledger_lines WHERE {} LIMIT {limit}", conditions.join(" AND "))
            };
            match conn.execute_sql(&sql).await {
                Ok(resp) => Ok(ok_text(response_to_text(&resp))),
                Err(e) => Ok(err_text(format!("Ledger lines query failed: {e}"))),
            }
        }

        "verify_chain" => {
            let sql = match (args["from_seq"].as_u64(), args["to_seq"].as_u64()) {
                (Some(from), Some(to)) => format!("SELECT VERIFY_CHAIN({from}, {to})"),
                _ => "SELECT VERIFY_CHAIN()".to_string(),
            };
            match conn.execute_sql(&sql).await {
                Ok(resp) => Ok(ok_text(response_to_text(&resp))),
                Err(e) => Ok(err_text(format!("Chain verification failed: {e}"))),
            }
        }

        "merkle_root" => {
            let from_seq = args["from_seq"].as_u64().ok_or_else(|| anyhow::anyhow!("'from_seq' required"))?;
            let to_seq   = args["to_seq"].as_u64().ok_or_else(|| anyhow::anyhow!("'to_seq' required"))?;
            let sql = format!("SELECT MERKLE_ROOT({from_seq}, {to_seq})");
            match conn.execute_sql(&sql).await {
                Ok(resp) => Ok(ok_text(response_to_text(&resp))),
                Err(e) => Ok(err_text(format!("Merkle root failed: {e}"))),
            }
        }

        // High-order tools: translate to SQL chains and proxy each
        "explain_balance" => {
            let account = args["account"].as_str().ok_or_else(|| anyhow::anyhow!("'account' required"))?;
            let limit = args["limit"].as_u64().unwrap_or(20);
            let esc = escape(account);

            // Resolve account
            let acct_resp = conn.execute_sql(
                &format!("SELECT id, code, name, account_type, currency, balance FROM accounts WHERE code = '{esc}'")
            ).await.unwrap_or(serde_json::json!({"ok":false}));

            let rows = acct_resp["rows"].as_array();
            let (acct_id, acct_code, acct_name, acct_type, currency, bal_raw) =
                if let Some(r) = rows.and_then(|r| r.first()).and_then(|r| r.as_array()) {
                    (
                        r.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r.get(1).and_then(|v| v.as_str()).unwrap_or(account).to_string(),
                        r.get(2).and_then(|v| v.as_str()).unwrap_or(account).to_string(),
                        r.get(3).and_then(|v| v.as_str()).unwrap_or("Asset").to_string(),
                        r.get(4).and_then(|v| v.as_str()).unwrap_or("USD").to_string(),
                        r.get(5).and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                    )
                } else {
                    return Ok(err_text(format!("Account '{account}' not found")));
                };

            let debit_resp = conn.execute_sql(
                &format!("SELECT date, sequence, description, amount, currency FROM ledger_lines WHERE account_id = '{acct_id}' AND dr_cr = 'Debit' LIMIT {limit}")
            ).await.unwrap_or_default_json();

            let credit_resp = conn.execute_sql(
                &format!("SELECT date, sequence, description, amount, currency FROM ledger_lines WHERE account_id = '{acct_id}' AND dr_cr = 'Credit' LIMIT {limit}")
            ).await.unwrap_or_default_json();

            let normal_dir = if acct_type == "Asset" || acct_type == "Expense" { "Debit" } else { "Credit" };

            let mut out = format!("## Balance Explanation — {acct_name} ({acct_code})\n\n");
            out.push_str(&format!("**Account type:** {acct_type}  \n"));
            out.push_str(&format!("**Normal balance direction:** {normal_dir}  \n"));
            out.push_str(&format!("**Current balance:** {}\n\n", format_amount(bal_raw, &currency)));
            out.push_str("### Recent debits\n\n");
            out.push_str(&response_to_text(&debit_resp));
            out.push_str("\n### Recent credits\n\n");
            out.push_str(&response_to_text(&credit_resp));

            Ok(ok_text(out))
        }

        "reconcile_account" => {
            let account = args["account"].as_str().ok_or_else(|| anyhow::anyhow!("'account' required"))?;
            let esc = escape(account);

            let acct_resp = conn.execute_sql(
                &format!("SELECT id, code, name, account_type, currency, balance FROM accounts WHERE code = '{esc}'")
            ).await.unwrap_or_default_json();

            let rows = acct_resp["rows"].as_array();
            let (acct_id, acct_code, acct_name, acct_type, currency, stored_bal) =
                if let Some(r) = rows.and_then(|r| r.first()).and_then(|r| r.as_array()) {
                    (
                        r.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r.get(1).and_then(|v| v.as_str()).unwrap_or(account).to_string(),
                        r.get(2).and_then(|v| v.as_str()).unwrap_or(account).to_string(),
                        r.get(3).and_then(|v| v.as_str()).unwrap_or("Asset").to_string(),
                        r.get(4).and_then(|v| v.as_str()).unwrap_or("USD").to_string(),
                        r.get(5).and_then(|v| v.as_str()).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                    )
                } else {
                    return Ok(err_text(format!("Account '{account}' not found")));
                };

            let dr_resp = conn.execute_sql(
                &format!("SELECT SUM(amount) FROM ledger_lines WHERE account_id = '{acct_id}' AND dr_cr = 'Debit'")
            ).await.unwrap_or_default_json();
            let cr_resp = conn.execute_sql(
                &format!("SELECT SUM(amount) FROM ledger_lines WHERE account_id = '{acct_id}' AND dr_cr = 'Credit'")
            ).await.unwrap_or_default_json();

            let total_debits: i64 = dr_resp["rows"].as_array()
                .and_then(|r| r.first()).and_then(|r| r.as_array())
                .and_then(|r| r.first()).and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok()).unwrap_or(0);
            let total_credits: i64 = cr_resp["rows"].as_array()
                .and_then(|r| r.first()).and_then(|r| r.as_array())
                .and_then(|r| r.first()).and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok()).unwrap_or(0);

            let computed = if acct_type == "Asset" || acct_type == "Expense" {
                total_debits - total_credits
            } else {
                total_credits - total_debits
            };
            let discrepancy = stored_bal - computed;
            let is_ok = discrepancy == 0;

            let mut out = format!("## Reconciliation — {acct_name} ({acct_code})\n\n");
            out.push_str(&format!("| Field | Value |\n|---|---|\n"));
            out.push_str(&format!("| Account type | {acct_type} |\n"));
            out.push_str(&format!("| Total debits | {} |\n", format_amount(total_debits, &currency)));
            out.push_str(&format!("| Total credits | {} |\n", format_amount(total_credits, &currency)));
            out.push_str(&format!("| Computed balance | {} |\n", format_amount(computed, &currency)));
            out.push_str(&format!("| Stored balance | {} |\n", format_amount(stored_bal, &currency)));
            out.push_str(&format!("| Discrepancy | {} |\n", format_amount(discrepancy, &currency)));
            out.push_str(&format!("| **Result** | **{}** |\n\n",
                if is_ok { "✓ BALANCED" } else { "✗ DISCREPANCY DETECTED" }));

            if !is_ok {
                out.push_str(&format!(
                    "Discrepancy of {}. Run `VERIFY_CHAIN()` and `vledger reconcile` to investigate.\n",
                    format_amount(discrepancy.abs(), &currency)
                ));
            }

            Ok(ok_text(out))
        }

        "find_policy_violations" => {
            let threshold = args["large_amount_threshold_minor_units"].as_i64().unwrap_or(5_000_000);
            let mut out = String::from("## Policy Violation Report\n\n");
            let mut violations = 0usize;

            if args["check_large_amounts"].as_bool().unwrap_or(true) {
                let sql = format!("SELECT sequence, entry_id, description, amount, currency, dr_cr, date FROM ledger_lines WHERE amount > {threshold} LIMIT 50");
                let resp = conn.execute_sql(&sql).await.unwrap_or_default_json();
                let count = resp["rows"].as_array().map(|r| r.len()).unwrap_or(0);
                violations += count;
                if count > 0 {
                    out.push_str(&format!("### ⚠ Large Transactions (> {threshold} minor units)\n\n"));
                    out.push_str(&response_to_text(&resp));
                    out.push('\n');
                } else {
                    out.push_str(&format!("### ✓ Large Transactions — none above {threshold}\n\n"));
                }
            }

            if args["check_pending_too_long"].as_bool().unwrap_or(true) {
                let sql = "SELECT sequence, id, description, domain, effective_at FROM ledger WHERE status = 'Pending' LIMIT 50";
                let resp = conn.execute_sql(sql).await.unwrap_or_default_json();
                let count = resp["rows"].as_array().map(|r| r.len()).unwrap_or(0);
                violations += count;
                if count > 0 {
                    out.push_str("### ⚠ Pending Entries (unsettled)\n\n");
                    out.push_str(&response_to_text(&resp));
                    out.push('\n');
                } else {
                    out.push_str("### ✓ Pending Entries — none found\n\n");
                }
            }

            if args["check_missing_external_ref"].as_bool().unwrap_or(true) {
                let sql = "SELECT sequence, id, description, domain FROM ledger WHERE status = 'Posted' AND external_ref = '' LIMIT 50";
                let resp = conn.execute_sql(sql).await.unwrap_or_default_json();
                let count = resp["rows"].as_array().map(|r| r.len()).unwrap_or(0);
                violations += count;
                if count > 0 {
                    out.push_str("### ⚠ Posted Entries Missing External Reference\n\n");
                    out.push_str(&response_to_text(&resp));
                    out.push('\n');
                } else {
                    out.push_str("### ✓ External References — all posted entries have one\n\n");
                }
            }

            if args["check_failed_entries"].as_bool().unwrap_or(true) {
                let sql = "SELECT sequence, id, description, domain, effective_at FROM ledger WHERE status = 'Failed' LIMIT 50";
                let resp = conn.execute_sql(sql).await.unwrap_or_default_json();
                let count = resp["rows"].as_array().map(|r| r.len()).unwrap_or(0);
                violations += count;
                if count > 0 {
                    out.push_str("### ⚠ Failed Entries\n\n");
                    out.push_str(&response_to_text(&resp));
                    out.push('\n');
                } else {
                    out.push_str("### ✓ Failed Entries — none found\n\n");
                }
            }

            out.push_str(&format!("---\n\n**Total violations: {}**\n", violations));
            Ok(ok_text(out))
        }

        "summarize_period" => {
            let from = args["from"].as_str().ok_or_else(|| anyhow::anyhow!("'from' required"))?;
            let to   = args["to"].as_str().ok_or_else(|| anyhow::anyhow!("'to' required"))?;
            let domain = args["domain"].as_str().unwrap_or("main");
            let from_ts = if from.contains('T') { from.to_string() } else { format!("{from}T00:00:00Z") };
            let to_ts   = if to.contains('T')   { to.to_string()   } else { format!("{to}T23:59:59Z") };
            let bf = format!("effective_at >= '{from_ts}' AND effective_at <= '{to_ts}' AND domain = '{}'", escape(domain));

            let posted = conn.execute_sql(&format!("SELECT COUNT(sequence) FROM ledger WHERE {bf} AND status = 'Posted'")).await.unwrap_or_default_json();
            let failed = conn.execute_sql(&format!("SELECT COUNT(sequence) FROM ledger WHERE {bf} AND status = 'Failed'")).await.unwrap_or_default_json();
            let pending = conn.execute_sql(&format!("SELECT COUNT(sequence) FROM ledger WHERE {bf} AND status = 'Pending'")).await.unwrap_or_default_json();
            let chain = conn.execute_sql("SELECT VERIFY_CHAIN()").await.unwrap_or_default_json();

            let get_count = |r: &Value| -> i64 {
                r["rows"].as_array()
                    .and_then(|a| a.first()).and_then(|r| r.as_array())
                    .and_then(|r| r.first()).and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok()).unwrap_or(0)
            };

            let n_posted  = get_count(&posted);
            let n_failed  = get_count(&failed);
            let n_pending = get_count(&pending);
            let chain_ok  = response_to_text(&chain).to_uppercase().contains("OK");
            let success_rate = if n_posted + n_failed > 0 {
                (n_posted as f64 / (n_posted + n_failed) as f64 * 100.0) as u64
            } else { 100 };

            let mut out = format!("## Period Summary — {domain}\n**Period:** {from} to {to}\n\n");
            out.push_str("| Status | Count |\n|---|---|\n");
            out.push_str(&format!("| Posted | {n_posted} |\n| Pending | {n_pending} |\n| Failed | {n_failed} |\n| Success rate | {success_rate}% |\n\n"));
            out.push_str(&format!("**Chain integrity:** {}\n", if chain_ok { "✓ VERIFIED" } else { "✗ BROKEN" }));

            Ok(ok_text(out))
        }

        "audit_report" => {
            let from   = args["from"].as_str().ok_or_else(|| anyhow::anyhow!("'from' required"))?;
            let to     = args["to"].as_str().ok_or_else(|| anyhow::anyhow!("'to' required"))?;
            let tenant = args["tenant"].as_str().unwrap_or("VectorLedger Customer");
            let domain = args["domain"].as_str().unwrap_or("main");
            let from_ts = if from.contains('T') { from.to_string() } else { format!("{from}T00:00:00Z") };
            let to_ts   = if to.contains('T')   { to.to_string()   } else { format!("{to}T23:59:59Z") };
            let bf = format!("effective_at >= '{from_ts}' AND effective_at <= '{to_ts}' AND domain = '{}'", escape(domain));

            let count_resp = conn.execute_sql(&format!("SELECT COUNT(sequence) FROM ledger WHERE {bf}")).await.unwrap_or_default_json();
            let seq_resp   = conn.execute_sql(&format!("SELECT MIN(sequence), MAX(sequence) FROM ledger WHERE {bf}")).await.unwrap_or_default_json();
            let chain_resp = conn.execute_sql("SELECT VERIFY_CHAIN()").await.unwrap_or_default_json();
            let sample_resp = conn.execute_sql(&format!("SELECT sequence, id, status, description, effective_at, content_hash FROM ledger WHERE {bf} LIMIT 5")).await.unwrap_or_default_json();

            let entry_count: i64 = count_resp["rows"].as_array()
                .and_then(|a| a.first()).and_then(|r| r.as_array())
                .and_then(|r| r.first()).and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok()).unwrap_or(0);

            let (min_seq, max_seq) = seq_resp["rows"].as_array()
                .and_then(|a| a.first()).and_then(|r| r.as_array())
                .map(|r| (
                    r.get(0).and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                    r.get(1).and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0),
                ))
                .unwrap_or((0, 0));

            let chain_ok = response_to_text(&chain_resp).to_uppercase().contains("OK");

            let merkle_root = if min_seq > 0 && max_seq >= min_seq {
                conn.execute_sql(&format!("SELECT MERKLE_ROOT({min_seq}, {max_seq})")).await
                    .ok()
                    .and_then(|r| r["rows"].as_array()?.first()?.as_array()?.get(3)?.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unavailable".to_string())
            } else {
                "no entries".to_string()
            };

            let mut out = format!("# Cryptographic Audit Report\n\n**Tenant:** {tenant}  \n**Period:** {from} to {to}  \n**Domain:** {domain}\n\n");
            out.push_str("---\n\n## 1. Ledger Summary\n\n");
            out.push_str(&format!("| Field | Value |\n|---|---|\n| Total entries | {entry_count} |\n| First sequence | {min_seq} |\n| Last sequence | {max_seq} |\n| Chain integrity | {} |\n\n",
                if chain_ok { "✓ VERIFIED" } else { "✗ BROKEN" }));
            out.push_str("## 2. Merkle Commitment\n\n");
            out.push_str(&format!("```\nMerkle root: {merkle_root}\nSequences:   {min_seq} – {max_seq}\nEntries:     {entry_count}\n```\n\n"));
            out.push_str("## 3. Sample Entries\n\n");
            out.push_str(&response_to_text(&sample_resp));
            out.push_str("\n## 4. Verification\n\n```bash\nvledger verify-audit-package --file audit.json\n```\n");

            Ok(ok_text(out))
        }

        other => anyhow::bail!("Unknown tool: {other}"),
    }
}

// ── Helper trait for default JSON ─────────────────────────────────────────────

trait UnwrapOrDefaultJson {
    fn unwrap_or_default_json(self) -> Value;
}

impl UnwrapOrDefaultJson for Result<Value> {
    fn unwrap_or_default_json(self) -> Value {
        self.unwrap_or_else(|_| serde_json::json!({"ok": false, "rows": [], "columns": [], "message": ""}))
    }
}

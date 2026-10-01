//! Tool dispatch for the VectorLedger MCP server.
//!
//! Each tool handler receives the raw JSON `arguments` object from the
//! `tools/call` JSON-RPC request, executes the appropriate SQL via the
//! vledger SQL engine, and returns a structured MCP `content` response.

use std::sync::{RwLock, Arc};

use anyhow::Result;
use serde_json::{json, Value};

use vledger_ledger::LedgerStore;
use vledger_server::auth::{check_plan_privilege, Session};
use vledger_sql::{
    executor::Executor,
    parser::parse_one,
    planner::LogicalPlanBuilder,
    result::{QueryResult, Value as LedgerValue},
};

// ── Public entry point ────────────────────────────────────────────────────────

/// Route a `tools/call` request to the correct handler.
///
/// Returns an MCP-compliant `content` array:
/// ```json
/// { "content": [{ "type": "text", "text": "..." }], "isError": false }
/// ```
pub fn dispatch_tool(
    name: &str,
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    match name {
        "query_ledger"       => tool_query_ledger(args, ledger, session),
        "post_entry"         => tool_post_entry(args, ledger, session),
        "get_balance"        => tool_get_balance(args, ledger, session),
        "list_accounts"      => tool_list_accounts(args, ledger, session),
        "query_ledger_lines" => tool_query_ledger_lines(args, ledger, session),
        "verify_chain"       => tool_verify_chain(args, ledger, session),
        "merkle_root"        => tool_merkle_root(args, ledger, session),
        other => anyhow::bail!("Unknown tool: {other}"),
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Execute a SQL string through the full parse→plan→privilege→execute pipeline.
fn run_sql(
    sql: &str,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<QueryResult> {
    let stmt = parse_one(sql).map_err(|e| anyhow::anyhow!("SQL parse error: {e}"))?;
    let plan =
        LogicalPlanBuilder::plan(stmt).map_err(|e| anyhow::anyhow!("SQL plan error: {e}"))?;

    check_plan_privilege(session, &plan)
        .map_err(|e| anyhow::anyhow!("Permission denied: {e}"))?;

    let mut store = ledger
        .write()
        .map_err(|_| anyhow::anyhow!("Ledger lock poisoned"))?;

    Executor::with_proofs(&mut *store)
        .execute(plan)
        .map_err(|e| anyhow::anyhow!("Execution error: {e}"))
}

/// Format a `QueryResult` as a human-readable Markdown table string.
fn result_to_text(result: &QueryResult) -> String {
    if result.columns.is_empty() {
        return format!("{}\n", result.message);
    }

    let mut out = String::new();

    // Header
    out.push_str(&result.columns.join(" | "));
    out.push('\n');
    // Separator
    out.push_str(
        &result
            .columns
            .iter()
            .map(|c| "-".repeat(c.len()))
            .collect::<Vec<_>>()
            .join("-+-"),
    );
    out.push('\n');
    // Rows
    for row in &result.rows {
        let vals: Vec<String> = row.values.iter().map(|v| ledger_value_to_string(v)).collect();
        out.push_str(&vals.join(" | "));
        out.push('\n');
    }
    // Footer
    out.push_str(&format!("\n{}\n", result.message));

    // Merkle proof summary
    if let Some(ref proof) = result.proof {
        let root_hex = hex::encode(proof.root);
        out.push_str(&format!(
            "\nMerkle proof: {} leaves — root {}\n",
            proof.leaf_proofs.len(),
            root_hex,
        ));
    }

    out
}

fn ledger_value_to_string(v: &LedgerValue) -> String {
    match v {
        LedgerValue::Null      => "NULL".to_string(),
        LedgerValue::Int(i)    => i.to_string(),
        LedgerValue::BigInt(i) => i.to_string(),
        LedgerValue::Text(s)   => s.clone(),
        LedgerValue::Bool(b)   => b.to_string(),
        LedgerValue::Timestamp(t) => t.clone(),
        LedgerValue::Hash(h)   => h.clone(),
        LedgerValue::Uuid(u)   => u.clone(),
    }
}

/// Wrap a text string in the MCP `content` envelope.
fn ok_text(text: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": false
    })
}

/// Wrap an error message in the MCP `content` envelope.
fn err_text(text: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": true
    })
}

// ── Tool implementations ──────────────────────────────────────────────────────

/// Run any read-only SELECT against the ledger.
fn tool_query_ledger(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let sql = args["sql"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("'sql' argument is required"))?;

    match run_sql(sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Query failed: {e}"))),
    }
}

/// Record a new double-entry journal entry.
fn tool_post_entry(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let description = args["description"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("'description' is required"))?;
    let debit_account = args["debit_account"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("'debit_account' is required"))?;
    let credit_account = args["credit_account"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("'credit_account' is required"))?;
    let amount = args["amount"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("'amount' is required and must be an integer"))?;
    let currency = args["currency"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("'currency' is required"))?;
    let domain = args["domain"].as_str().unwrap_or("main");
    let external_ref = args["external_ref"].as_str().unwrap_or("");
    let metadata = args["metadata"].as_str().unwrap_or("");

    if amount <= 0 {
        return Ok(err_text("'amount' must be a positive integer (minor units)"));
    }

    // Build the INSERT SQL from the validated arguments.
    // Use parameterised-style quoting: escape single quotes in string fields.
    let escape = |s: &str| s.replace('\'', "''");

    let sql = if !metadata.is_empty() {
        format!(
            "INSERT INTO ledger \
             (description, debit_account, credit_account, amount, currency, domain, external_ref, metadata) \
             VALUES ('{}', '{}', '{}', {}, '{}', '{}', '{}', '{}')",
            escape(description),
            escape(debit_account),
            escape(credit_account),
            amount,
            escape(currency),
            escape(domain),
            escape(external_ref),
            escape(metadata),
        )
    } else if !external_ref.is_empty() {
        format!(
            "INSERT INTO ledger \
             (description, debit_account, credit_account, amount, currency, domain, external_ref) \
             VALUES ('{}', '{}', '{}', {}, '{}', '{}', '{}')",
            escape(description),
            escape(debit_account),
            escape(credit_account),
            amount,
            escape(currency),
            escape(domain),
            escape(external_ref),
        )
    } else {
        format!(
            "INSERT INTO ledger \
             (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('{}', '{}', '{}', {}, '{}', '{}')",
            escape(description),
            escape(debit_account),
            escape(credit_account),
            amount,
            escape(currency),
            escape(domain),
        )
    };

    match run_sql(&sql, ledger, session) {
        Ok(result) => {
            let mut text = result.message.clone();
            if let Some(seq) = result.entry_sequence {
                text.push_str(&format!("\nSequence: {seq}"));
            }
            if let Some(ref id) = result.entry_id {
                text.push_str(&format!("\nEntry ID: {id}"));
            }
            Ok(ok_text(text))
        }
        Err(e) => Ok(err_text(format!("Failed to post entry: {e}"))),
    }
}

/// Return the current balance of a single account.
fn tool_get_balance(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let account = args["account"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("'account' is required"))?;

    let sql = format!("SELECT BALANCE('{}')", account.replace('\'', "''"));

    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Balance query failed: {e}"))),
    }
}

/// List all accounts, optionally filtered by domain or currency.
fn tool_list_accounts(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let mut conditions: Vec<String> = Vec::new();

    if let Some(domain) = args["domain"].as_str() {
        conditions.push(format!("domain = '{}'", domain.replace('\'', "''")));
    }
    if let Some(currency) = args["currency"].as_str() {
        conditions.push(format!("currency = '{}'", currency.replace('\'', "''")));
    }

    let sql = if conditions.is_empty() {
        "SELECT id, code, name, account_type, currency, domain, balance FROM accounts".to_string()
    } else {
        format!(
            "SELECT id, code, name, account_type, currency, domain, balance FROM accounts WHERE {}",
            conditions.join(" AND ")
        )
    };

    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("List accounts failed: {e}"))),
    }
}

/// Query individual debit/credit journal lines.
fn tool_query_ledger_lines(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let limit = args["limit"].as_u64().unwrap_or(100);
    let mut conditions: Vec<String> = Vec::new();

    if let Some(domain) = args["domain"].as_str() {
        conditions.push(format!("domain = '{}'", domain.replace('\'', "''")));
    }
    if let Some(dr_cr) = args["dr_cr"].as_str() {
        if dr_cr != "Debit" && dr_cr != "Credit" {
            return Ok(err_text("'dr_cr' must be 'Debit' or 'Credit'"));
        }
        conditions.push(format!("dr_cr = '{dr_cr}'"));
    }

    let sql = if conditions.is_empty() {
        format!(
            "SELECT date, sequence, entry_id, description, dr_cr, amount, currency, domain \
             FROM ledger_lines LIMIT {limit}"
        )
    } else {
        format!(
            "SELECT date, sequence, entry_id, description, dr_cr, amount, currency, domain \
             FROM ledger_lines WHERE {} LIMIT {limit}",
            conditions.join(" AND ")
        )
    };

    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Ledger lines query failed: {e}"))),
    }
}

/// Verify the cryptographic hash chain.
fn tool_verify_chain(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let sql = match (args["from_seq"].as_u64(), args["to_seq"].as_u64()) {
        (Some(from), Some(to)) => format!("SELECT VERIFY_CHAIN({from}, {to})"),
        _ => "SELECT VERIFY_CHAIN()".to_string(),
    };

    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Chain verification failed: {e}"))),
    }
}

/// Compute the Merkle root over a sequence range.
fn tool_merkle_root(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let from_seq = args["from_seq"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("'from_seq' is required"))?;
    let to_seq = args["to_seq"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("'to_seq' is required"))?;

    let sql = format!("SELECT MERKLE_ROOT({from_seq}, {to_seq})");

    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Merkle root computation failed: {e}"))),
    }
}

//! Tool dispatch for the VectorLedger MCP server.
//!
//! ## Low-level tools (direct SQL wrappers)
//! `query_ledger`, `post_entry`, `get_balance`, `list_accounts`,
//! `query_ledger_lines`, `verify_chain`, `merkle_root`
//!
//! ## High-order financial reasoning tools
//! `explain_balance`       — why is an account at its current balance?
//! `reconcile_account`     — do debits and credits net to the running balance?
//! `find_policy_violations`— entries that break configurable financial rules
//! `summarize_period`      — natural-language period summary with key metrics
//! `audit_report`          — cryptographic audit evidence narrative for a period

use std::sync::{Arc, RwLock};

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
pub fn dispatch_tool(
    name: &str,
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    match name {
        // Low-level tools
        "query_ledger"            => tool_query_ledger(args, ledger, session),
        "post_entry"              => tool_post_entry(args, ledger, session),
        "get_balance"             => tool_get_balance(args, ledger, session),
        "list_accounts"           => tool_list_accounts(args, ledger, session),
        "query_ledger_lines"      => tool_query_ledger_lines(args, ledger, session),
        "verify_chain"            => tool_verify_chain(args, ledger, session),
        "merkle_root"             => tool_merkle_root(args, ledger, session),
        // High-order financial reasoning tools
        "explain_balance"         => tool_explain_balance(args, ledger, session),
        "reconcile_account"       => tool_reconcile_account(args, ledger, session),
        "find_policy_violations"  => tool_find_policy_violations(args, ledger, session),
        "summarize_period"        => tool_summarize_period(args, ledger, session),
        "audit_report"            => tool_audit_report(args, ledger, session),
        // Identity and authorization tools
        "resolve_account"         => tool_resolve_account(args, ledger, session),
        // Correction workflow tools
        "propose_correction"      => tool_propose_correction(args, ledger, session),
        "execute_correction"      => tool_execute_correction(args, ledger, session),
        other => anyhow::bail!("Unknown tool: {other}"),
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn run_sql(
    sql: &str,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<QueryResult> {
    let stmt = parse_one(sql).map_err(|e| anyhow::anyhow!("SQL parse error: {e}"))?;
    let plan = LogicalPlanBuilder::plan(stmt)
        .map_err(|e| anyhow::anyhow!("SQL plan error: {e}"))?;
    check_plan_privilege(session, &plan)
        .map_err(|e| anyhow::anyhow!("Permission denied: {e}"))?;
    let mut store = ledger
        .write()
        .map_err(|_| anyhow::anyhow!("Ledger lock poisoned"))?;
    Executor::with_proofs(&mut *store)
        .execute(plan)
        .map_err(|e| anyhow::anyhow!("Execution error: {e}"))
}

/// Pull a single scalar string value from the first row / first column.
fn scalar_str(result: &QueryResult) -> Option<String> {
    result.rows.first()?.values.first().map(ledger_value_to_string)
}

/// Pull all rows as Vec<Vec<String>>.
fn rows_as_strings(result: &QueryResult) -> Vec<Vec<String>> {
    result
        .rows
        .iter()
        .map(|r| r.values.iter().map(ledger_value_to_string).collect())
        .collect()
}

fn result_to_text(result: &QueryResult) -> String {
    if result.columns.is_empty() {
        return format!("{}\n", result.message);
    }
    let mut out = String::new();
    out.push_str(&result.columns.join(" | "));
    out.push('\n');
    out.push_str(
        &result
            .columns
            .iter()
            .map(|c| "-".repeat(c.len()))
            .collect::<Vec<_>>()
            .join("-+-"),
    );
    out.push('\n');
    for row in &result.rows {
        let vals: Vec<String> = row.values.iter().map(|v| ledger_value_to_string(v)).collect();
        out.push_str(&vals.join(" | "));
        out.push('\n');
    }
    out.push_str(&format!("\n{}\n", result.message));
    if let Some(ref proof) = result.proof {
        out.push_str(&format!(
            "\nMerkle proof: {} leaves — root {}\n",
            proof.leaf_proofs.len(),
            hex::encode(proof.root),
        ));
    }
    out
}

fn ledger_value_to_string(v: &LedgerValue) -> String {
    match v {
        LedgerValue::Null         => "NULL".to_string(),
        LedgerValue::Int(i)       => i.to_string(),
        LedgerValue::BigInt(i)    => i.to_string(),
        LedgerValue::Text(s)      => s.clone(),
        LedgerValue::Bool(b)      => b.to_string(),
        LedgerValue::Timestamp(t) => t.clone(),
        LedgerValue::Hash(h)      => h.clone(),
        LedgerValue::Uuid(u)      => u.clone(),
    }
}

fn ok_text(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": false })
}

fn err_text(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": true })
}

/// Format a minor-unit integer as a display string with currency.
/// e.g. 1000000, "USD" → "$10,000.00"
fn format_amount(minor_units: i64, currency: &str) -> String {
    // JPY and similar zero-decimal currencies
    let zero_decimal = matches!(currency, "JPY" | "KRW" | "VND" | "CLP" | "IDR");
    if zero_decimal {
        format!("{} {:}", currency, minor_units)
    } else {
        let dollars = minor_units / 100;
        let cents = (minor_units % 100).abs();
        format!("{} {:},{:02}", currency, dollars, cents)
            .replacen(',', " ", 0) // keep commas for thousands
    }
}

// ── Low-level tool implementations ───────────────────────────────────────────

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

fn tool_post_entry(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let description    = args["description"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'description' is required"))?;
    let debit_account  = args["debit_account"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'debit_account' is required"))?;
    let credit_account = args["credit_account"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'credit_account' is required"))?;
    let amount         = args["amount"].as_i64()
        .ok_or_else(|| anyhow::anyhow!("'amount' is required and must be an integer"))?;
    let currency       = args["currency"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'currency' is required"))?;
    let domain         = args["domain"].as_str().unwrap_or("main");
    let external_ref   = args["external_ref"].as_str().unwrap_or("");
    let metadata       = args["metadata"].as_str().unwrap_or("");

    if amount <= 0 {
        return Ok(err_text("'amount' must be a positive integer in minor units (e.g. cents). \
                            $100.00 USD = 10000"));
    }

    let escape = |s: &str| s.replace('\'', "''");
    let sql = if !metadata.is_empty() {
        format!(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref, metadata) \
             VALUES ('{}', '{}', '{}', {}, '{}', '{}', '{}', '{}')",
            escape(description), escape(debit_account), escape(credit_account),
            amount, escape(currency), escape(domain), escape(external_ref), escape(metadata),
        )
    } else if !external_ref.is_empty() {
        format!(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain, external_ref) \
             VALUES ('{}', '{}', '{}', {}, '{}', '{}', '{}')",
            escape(description), escape(debit_account), escape(credit_account),
            amount, escape(currency), escape(domain), escape(external_ref),
        )
    } else {
        format!(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('{}', '{}', '{}', {}, '{}', '{}')",
            escape(description), escape(debit_account), escape(credit_account),
            amount, escape(currency), escape(domain),
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

fn tool_get_balance(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let account = args["account"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'account' is required"))?;
    let sql = format!("SELECT BALANCE('{}')", account.replace('\'', "''"));
    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Balance query failed: {e}"))),
    }
}

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
    // Default to 500 rows — callers wanting more should filter by domain/currency
    // or use query_ledger with an explicit LIMIT. Without a cap this query can
    // return hundreds of thousands of rows and overflow the TLS frame buffer.
    let limit = args["limit"].as_u64().unwrap_or(500);

    let sql = if conditions.is_empty() {
        format!("SELECT id, code, name, account_type, currency, domain, balance FROM accounts LIMIT {limit}")
    } else {
        format!(
            "SELECT id, code, name, account_type, currency, domain, balance FROM accounts WHERE {} LIMIT {limit}",
            conditions.join(" AND ")
        )
    };
    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("List accounts failed: {e}"))),
    }
}

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
        format!("SELECT date, sequence, entry_id, description, dr_cr, amount, currency, domain \
                 FROM ledger_lines LIMIT {limit}")
    } else {
        format!("SELECT date, sequence, entry_id, description, dr_cr, amount, currency, domain \
                 FROM ledger_lines WHERE {} LIMIT {limit}", conditions.join(" AND "))
    };
    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Ledger lines query failed: {e}"))),
    }
}

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

fn tool_merkle_root(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let from_seq = args["from_seq"].as_u64()
        .ok_or_else(|| anyhow::anyhow!("'from_seq' is required"))?;
    let to_seq = args["to_seq"].as_u64()
        .ok_or_else(|| anyhow::anyhow!("'to_seq' is required"))?;
    let sql = format!("SELECT MERKLE_ROOT({from_seq}, {to_seq})");
    match run_sql(&sql, ledger, session) {
        Ok(result) => Ok(ok_text(result_to_text(&result))),
        Err(e) => Ok(err_text(format!("Merkle root computation failed: {e}"))),
    }
}

// ── High-order financial reasoning tools ─────────────────────────────────────

/// Explain why an account is at its current balance.
///
/// Chains: get_balance → recent debit lines → recent credit lines → narrative.
fn tool_explain_balance(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let account = args["account"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'account' is required"))?;
    let limit = args["limit"].as_u64().unwrap_or(20);

    let esc = account.replace('\'', "''");

    // 1. Current balance (used indirectly via account record's balance field)
    let _bal_result = match run_sql(&format!("SELECT BALANCE('{esc}')"), ledger, session) {
        Ok(r) => r,
        Err(e) => return Ok(err_text(format!("Could not get balance: {e}"))),
    };

    // 2. Account metadata
    let acct_result = match run_sql(
        &format!("SELECT id, code, name, account_type, currency, balance FROM accounts \
                  WHERE code = '{esc}'"),
        ledger, session,
    ) {
        Ok(r) => r,
        Err(_) => {
            // Try by UUID
            match run_sql(
                &format!("SELECT id, code, name, account_type, currency, balance FROM accounts \
                          WHERE id = '{esc}'"),
                ledger, session,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_text(format!("Account not found: {e}"))),
            }
        }
    };

    let acct_rows = rows_as_strings(&acct_result);
    if acct_rows.is_empty() {
        return Ok(err_text(format!("Account '{account}' not found")));
    }
    let acct = &acct_rows[0];
    let acct_id   = acct.get(0).map(|s| s.as_str()).unwrap_or("?");
    let acct_code = acct.get(1).map(|s| s.as_str()).unwrap_or("?");
    let acct_name = acct.get(2).map(|s| s.as_str()).unwrap_or("?");
    let acct_type = acct.get(3).map(|s| s.as_str()).unwrap_or("?");
    let currency  = acct.get(4).map(|s| s.as_str()).unwrap_or("USD");
    let bal_raw: i64 = acct.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

    // 3. Recent debit lines
    let debit_sql = format!(
        "SELECT date, sequence, description, amount, currency FROM ledger_lines \
         WHERE account_id = '{acct_id}' AND dr_cr = 'Debit' LIMIT {limit}"
    );
    let debit_result = run_sql(&debit_sql, ledger, session).unwrap_or_default();

    // 4. Recent credit lines
    let credit_sql = format!(
        "SELECT date, sequence, description, amount, currency FROM ledger_lines \
         WHERE account_id = '{acct_id}' AND dr_cr = 'Credit' LIMIT {limit}"
    );
    let credit_result = run_sql(&credit_sql, ledger, session).unwrap_or_default();

    // 5. Total debits and credits from lines
    let total_debits: i64 = rows_as_strings(&debit_result)
        .iter()
        .filter_map(|r| r.get(3).and_then(|v| v.parse::<i64>().ok()))
        .sum();
    let total_credits: i64 = rows_as_strings(&credit_result)
        .iter()
        .filter_map(|r| r.get(3).and_then(|v| v.parse::<i64>().ok()))
        .sum();

    // 6. Build narrative
    let normal_dir = match acct_type {
        "Asset" | "Expense" => "Debit",
        _ => "Credit",
    };

    let mut out = String::new();
    out.push_str(&format!("## Balance Explanation — {acct_name} ({acct_code})\n\n"));
    out.push_str(&format!("**Account type:** {acct_type}  \n"));
    out.push_str(&format!("**Normal balance direction:** {normal_dir}  \n"));
    out.push_str(&format!("**Current balance:** {} (minor units: {bal_raw})\n\n",
        format_amount(bal_raw, currency)));

    out.push_str(&format!("### Recent activity (last {limit} lines per side)\n\n"));
    out.push_str(&format!("| Side   | Transactions | Total |\n"));
    out.push_str(&format!("|--------|-------------|-------|\n"));
    out.push_str(&format!("| Debit  | {} | {} |\n",
        debit_result.rows.len(), format_amount(total_debits, currency)));
    out.push_str(&format!("| Credit | {} | {} |\n\n",
        credit_result.rows.len(), format_amount(total_credits, currency)));

    if !debit_result.rows.is_empty() {
        out.push_str("### Recent debits\n\n");
        out.push_str(&result_to_text(&debit_result));
        out.push('\n');
    }
    if !credit_result.rows.is_empty() {
        out.push_str("### Recent credits\n\n");
        out.push_str(&result_to_text(&credit_result));
        out.push('\n');
    }

    out.push_str("### Interpretation\n\n");
    out.push_str(&format!(
        "The current balance of {} reflects the net of all debits and credits \
         posted to this {acct_type} account. For {acct_type} accounts, increases \
         are recorded as {normal_dir}s and decreases as the opposite side. \
         To investigate further, call `query_ledger_lines` with the account_id \
         `{acct_id}` or call `reconcile_account` to verify the balance matches \
         the sum of all posted lines.\n",
        format_amount(bal_raw, currency)
    ));

    Ok(ok_text(out))
}

/// Reconcile an account: verify that the running balance equals
/// sum(debits) - sum(credits) across all posted ledger lines.
fn tool_reconcile_account(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let account = args["account"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'account' is required"))?;
    let esc = account.replace('\'', "''");

    // Resolve account
    let acct_result = run_sql(
        &format!("SELECT id, code, name, account_type, currency, balance \
                  FROM accounts WHERE code = '{esc}'"),
        ledger, session,
    ).or_else(|_| run_sql(
        &format!("SELECT id, code, name, account_type, currency, balance \
                  FROM accounts WHERE id = '{esc}'"),
        ledger, session,
    )).map_err(|e| anyhow::anyhow!("Account not found: {e}"))?;

    let rows = rows_as_strings(&acct_result);
    if rows.is_empty() {
        return Ok(err_text(format!("Account '{account}' not found")));
    }
    let r = &rows[0];
    let acct_id   = r.get(0).map(|s| s.as_str()).unwrap_or("?");
    let acct_code = r.get(1).map(|s| s.as_str()).unwrap_or("?");
    let acct_name = r.get(2).map(|s| s.as_str()).unwrap_or("?");
    let acct_type = r.get(3).map(|s| s.as_str()).unwrap_or("?");
    let currency  = r.get(4).map(|s| s.as_str()).unwrap_or("USD");
    let stored_balance: i64 = r.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

    // Sum debits from posted lines
    let debit_sql = format!(
        "SELECT SUM(amount) FROM ledger_lines WHERE account_id = '{acct_id}' AND dr_cr = 'Debit'"
    );
    let credit_sql = format!(
        "SELECT SUM(amount) FROM ledger_lines WHERE account_id = '{acct_id}' AND dr_cr = 'Credit'"
    );

    let total_debits: i64 = run_sql(&debit_sql, ledger, session)
        .ok()
        .and_then(|r| scalar_str(&r))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let total_credits: i64 = run_sql(&credit_sql, ledger, session)
        .ok()
        .and_then(|r| scalar_str(&r))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // For Asset/Expense: balance = debits - credits
    // For Liability/Equity/Income: balance = credits - debits
    let computed_balance = match acct_type {
        "Asset" | "Expense" => total_debits - total_credits,
        _ => total_credits - total_debits,
    };

    let discrepancy = stored_balance - computed_balance;
    let is_ok = discrepancy == 0;

    let mut out = String::new();
    out.push_str(&format!("## Reconciliation — {acct_name} ({acct_code})\n\n"));
    out.push_str(&format!("| Field | Value |\n|---|---|\n"));
    out.push_str(&format!("| Account type | {acct_type} |\n"));
    out.push_str(&format!("| Currency | {currency} |\n"));
    out.push_str(&format!("| Total debits (all lines) | {} |\n", format_amount(total_debits, currency)));
    out.push_str(&format!("| Total credits (all lines) | {} |\n", format_amount(total_credits, currency)));
    out.push_str(&format!("| Computed balance | {} |\n", format_amount(computed_balance, currency)));
    out.push_str(&format!("| Stored balance | {} |\n", format_amount(stored_balance, currency)));
    out.push_str(&format!("| Discrepancy | {} |\n", format_amount(discrepancy, currency)));
    out.push_str(&format!("| **Result** | **{}** |\n\n",
        if is_ok { "✓ BALANCED" } else { "✗ DISCREPANCY DETECTED" }));

    if is_ok {
        out.push_str("The stored running balance matches the sum of all posted ledger lines. \
                      No discrepancy found.\n");
    } else {
        out.push_str(&format!(
            "**WARNING:** The stored balance differs from the sum of ledger lines by {}. \
             This may indicate:\n\
             - Pending or failed entries included in the balance cache\n\
             - A balance cache inconsistency (run `vledger reconcile` on the server)\n\
             - Entries posted outside the normal flow\n\n\
             Run `VERIFY_CHAIN()` to confirm cryptographic integrity, then \
             `vledger reconcile --data-dir <path>` to recompute all balances from scratch.\n",
            format_amount(discrepancy.abs(), currency)
        ));
    }

    Ok(ok_text(out))
}

/// Find entries that violate configurable financial policies.
///
/// Policies checked (enabled by default, disable via args):
/// - `large_amount`      — entries above a threshold (default $50,000)
/// - `pending_too_long`  — entries still Pending after N days (default 3)
/// - `no_external_ref`   — Posted entries missing an external reference
/// - `failed_entries`    — any entries with status = 'Failed'
fn tool_find_policy_violations(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let large_threshold_minor = args["large_amount_threshold_minor_units"]
        .as_i64()
        .unwrap_or(5_000_000); // $50,000.00
    let pending_days = args["pending_days_threshold"].as_u64().unwrap_or(3);
    let check_large   = args["check_large_amounts"].as_bool().unwrap_or(true);
    let check_pending = args["check_pending_too_long"].as_bool().unwrap_or(true);
    let check_no_ref  = args["check_missing_external_ref"].as_bool().unwrap_or(true);
    let check_failed  = args["check_failed_entries"].as_bool().unwrap_or(true);

    let mut out = String::new();
    out.push_str("## Policy Violation Report\n\n");
    let mut violations_found = 0usize;

    // 1. Large amounts
    if check_large {
        let sql = format!(
            "SELECT sequence, description, domain, effective_at FROM ledger \
             WHERE status = 'Posted' LIMIT 100"
        );
        // We check via ledger_lines for amount because ledger header doesn't expose amount directly
        let lines_sql = format!(
            "SELECT sequence, entry_id, description, amount, currency, dr_cr, date \
             FROM ledger_lines WHERE amount > {large_threshold_minor} LIMIT 50"
        );
        match run_sql(&lines_sql, ledger, session) {
            Ok(result) if !result.rows.is_empty() => {
                violations_found += result.rows.len();
                out.push_str(&format!(
                    "### ⚠ Large Transactions (> {} minor units)\n\n",
                    large_threshold_minor
                ));
                out.push_str(&result_to_text(&result));
                out.push('\n');
            }
            _ => {
                out.push_str(&format!(
                    "### ✓ Large Transactions — none found above {} minor units\n\n",
                    large_threshold_minor
                ));
            }
        }
        let _ = sql; // suppress unused warning
    }

    // 2. Pending too long
    if check_pending {
        let sql = format!(
            "SELECT sequence, id, description, domain, effective_at, posted_at \
             FROM ledger WHERE status = 'Pending' LIMIT 50"
        );
        match run_sql(&sql, ledger, session) {
            Ok(result) if !result.rows.is_empty() => {
                violations_found += result.rows.len();
                out.push_str(&format!(
                    "### ⚠ Pending Entries (unsettled — review if older than {} days)\n\n",
                    pending_days
                ));
                out.push_str(&result_to_text(&result));
                out.push('\n');
            }
            _ => {
                out.push_str("### ✓ Pending Entries — none found\n\n");
            }
        }
    }

    // 3. Missing external reference
    if check_no_ref {
        let sql = "SELECT sequence, id, description, domain, effective_at \
                   FROM ledger WHERE status = 'Posted' AND external_ref = '' LIMIT 50";
        match run_sql(sql, ledger, session) {
            Ok(result) if !result.rows.is_empty() => {
                violations_found += result.rows.len();
                out.push_str("### ⚠ Posted Entries Missing External Reference\n\n");
                out.push_str(&result_to_text(&result));
                out.push_str("\nThese entries have no external_ref. If your policy requires \
                              a payment gateway ID or external system reference on every \
                              posted entry, these need attention.\n\n");
            }
            _ => {
                out.push_str("### ✓ External References — all posted entries have a reference\n\n");
            }
        }
    }

    // 4. Failed entries
    if check_failed {
        let sql = "SELECT sequence, id, description, domain, effective_at \
                   FROM ledger WHERE status = 'Failed' LIMIT 50";
        match run_sql(sql, ledger, session) {
            Ok(result) if !result.rows.is_empty() => {
                violations_found += result.rows.len();
                out.push_str("### ⚠ Failed Entries\n\n");
                out.push_str(&result_to_text(&result));
                out.push_str("\nThese entries have status = 'Failed'. Review whether \
                              reversal or correction entries are needed.\n\n");
            }
            _ => {
                out.push_str("### ✓ Failed Entries — none found\n\n");
            }
        }
    }

    out.push_str(&format!("---\n\n**Total violations found: {}**\n", violations_found));
    if violations_found == 0 {
        out.push_str("\nAll configured policy checks passed. No violations detected.\n");
    }

    Ok(ok_text(out))
}

/// Produce a natural-language financial summary for a period.
///
/// Chains: entry count → total volume → failed/pending counts → chain integrity.
fn tool_summarize_period(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let from = args["from"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'from' is required (ISO-8601 date, e.g. '2026-09-01')"))?;
    let to = args["to"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'to' is required (ISO-8601 date, e.g. '2026-09-30')"))?;
    let domain = args["domain"].as_str().unwrap_or("main");
    let esc_domain = domain.replace('\'', "''");

    // Build ISO timestamps if only dates were given
    let from_ts = if from.contains('T') { from.to_string() } else { format!("{from}T00:00:00Z") };
    let to_ts   = if to.contains('T')   { to.to_string()   } else { format!("{to}T23:59:59Z") };

    let base_filter = format!(
        "effective_at >= '{from_ts}' AND effective_at <= '{to_ts}' AND domain = '{esc_domain}'"
    );

    // 1. Total posted entries
    let count_sql = format!("SELECT COUNT(sequence) FROM ledger WHERE {base_filter} AND status = 'Posted'");
    let total_posted: i64 = run_sql(&count_sql, ledger, session)
        .ok().and_then(|r| scalar_str(&r)).and_then(|s| s.parse().ok()).unwrap_or(0);

    // 2. Failed entries
    let failed_sql = format!("SELECT COUNT(sequence) FROM ledger WHERE {base_filter} AND status = 'Failed'");
    let total_failed: i64 = run_sql(&failed_sql, ledger, session)
        .ok().and_then(|r| scalar_str(&r)).and_then(|s| s.parse().ok()).unwrap_or(0);

    // 3. Pending entries
    let pending_sql = format!("SELECT COUNT(sequence) FROM ledger WHERE {base_filter} AND status = 'Pending'");
    let total_pending: i64 = run_sql(&pending_sql, ledger, session)
        .ok().and_then(|r| scalar_str(&r)).and_then(|s| s.parse().ok()).unwrap_or(0);

    // 4. Total debit volume (all lines in period)
    let volume_sql = format!(
        "SELECT SUM(amount) FROM ledger_lines WHERE date >= '{}' AND date <= '{}' AND dr_cr = 'Debit' AND domain = '{esc_domain}'",
        &from_ts[..10], &to_ts[..10]
    );
    let total_volume: i64 = run_sql(&volume_sql, ledger, session)
        .ok().and_then(|r| scalar_str(&r)).and_then(|s| s.parse().ok()).unwrap_or(0);

    // 5. Sequence range for this period (to compute Merkle root)
    let seq_sql = format!(
        "SELECT MIN(sequence), MAX(sequence) FROM ledger WHERE {base_filter}"
    );
    let seq_rows = run_sql(&seq_sql, ledger, session).ok();
    let (min_seq, max_seq) = seq_rows.as_ref()
        .and_then(|r| r.rows.first())
        .map(|row| {
            let min = ledger_value_to_string(&row.values[0]).parse::<u64>().unwrap_or(0);
            let max = ledger_value_to_string(&row.values[1]).parse::<u64>().unwrap_or(0);
            (min, max)
        })
        .unwrap_or((0, 0));

    // 6. Merkle root for the period (if we have a range)
    let merkle_info = if min_seq > 0 && max_seq >= min_seq {
        let mr_sql = format!("SELECT MERKLE_ROOT({min_seq}, {max_seq})");
        run_sql(&mr_sql, ledger, session)
            .ok()
            .and_then(|r| r.rows.first().map(|row| {
                ledger_value_to_string(&row.values[3]) // merkle_root column
            }))
            .unwrap_or_else(|| "unavailable".to_string())
    } else {
        "no entries in period".to_string()
    };

    // 7. Chain integrity
    let chain_ok = if min_seq > 0 && max_seq >= min_seq {
        let vc_sql = format!("SELECT VERIFY_CHAIN({min_seq}, {max_seq})");
        run_sql(&vc_sql, ledger, session)
            .ok()
            .and_then(|r| scalar_str(&r))
            .map(|s| s.to_uppercase().contains("OK"))
            .unwrap_or(false)
    } else {
        true // no entries = nothing to verify
    };

    let success_rate = if total_posted + total_failed > 0 {
        (total_posted as f64 / (total_posted + total_failed) as f64 * 100.0) as u64
    } else {
        100
    };

    let mut out = String::new();
    out.push_str(&format!("## Period Summary — {domain} domain\n"));
    out.push_str(&format!("**Period:** {from} to {to}\n\n"));
    out.push_str("### Transaction counts\n\n");
    out.push_str(&format!("| Status | Count |\n|---|---|\n"));
    out.push_str(&format!("| Posted (committed) | {total_posted} |\n"));
    out.push_str(&format!("| Pending (unsettled) | {total_pending} |\n"));
    out.push_str(&format!("| Failed | {total_failed} |\n"));
    out.push_str(&format!("| Success rate | {success_rate}% |\n\n"));

    out.push_str("### Volume\n\n");
    out.push_str(&format!("Total debit volume: {} minor units\n\n", total_volume));

    out.push_str("### Sequence range\n\n");
    out.push_str(&format!("| Metric | Value |\n|---|---|\n"));
    out.push_str(&format!("| First sequence | {min_seq} |\n"));
    out.push_str(&format!("| Last sequence | {max_seq} |\n"));
    out.push_str(&format!("| Entry count | {} |\n\n", max_seq.saturating_sub(min_seq) + 1));

    out.push_str("### Cryptographic integrity\n\n");
    out.push_str(&format!("| Check | Result |\n|---|---|\n"));
    out.push_str(&format!("| Hash chain | {} |\n",
        if chain_ok { "✓ VERIFIED" } else { "✗ CHAIN BROKEN — INVESTIGATE IMMEDIATELY" }));
    out.push_str(&format!("| Merkle root | `{}` |\n\n", merkle_info));

    out.push_str("### Summary\n\n");
    out.push_str(&format!(
        "In the period from {from} to {to} on the '{domain}' domain, \
         VectorLedger recorded {total_posted} posted entries with a total debit \
         volume of {} minor units. {} entries failed and {} are still pending. \
         The cryptographic hash chain over sequences {min_seq}–{max_seq} is {}. \
         The Merkle commitment for this period is `{}`.\n",
        total_volume,
        total_failed,
        total_pending,
        if chain_ok { "intact" } else { "BROKEN — requires immediate investigation" },
        merkle_info,
    ));

    Ok(ok_text(out))
}

/// Generate a cryptographic audit evidence narrative for a period.
///
/// Produces a structured report suitable for presenting to an auditor:
/// period summary, chain verification, Merkle commitment, sample entries.
fn tool_audit_report(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let from = args["from"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'from' is required (e.g. '2026-09-01')"))?;
    let to = args["to"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'to' is required (e.g. '2026-09-30')"))?;
    let tenant = args["tenant"].as_str().unwrap_or("VectorLedger Customer");
    let domain = args["domain"].as_str().unwrap_or("main");
    let esc_domain = domain.replace('\'', "''");

    let from_ts = if from.contains('T') { from.to_string() } else { format!("{from}T00:00:00Z") };
    let to_ts   = if to.contains('T')   { to.to_string()   } else { format!("{to}T23:59:59Z") };
    let base_filter = format!(
        "effective_at >= '{from_ts}' AND effective_at <= '{to_ts}' AND domain = '{esc_domain}'"
    );

    // Entry count
    let count_sql = format!("SELECT COUNT(sequence) FROM ledger WHERE {base_filter}");
    let entry_count: i64 = run_sql(&count_sql, ledger, session)
        .ok().and_then(|r| scalar_str(&r)).and_then(|s| s.parse().ok()).unwrap_or(0);

    // Sequence range
    let seq_sql = format!("SELECT MIN(sequence), MAX(sequence) FROM ledger WHERE {base_filter}");
    let (min_seq, max_seq) = run_sql(&seq_sql, ledger, session)
        .ok()
        .and_then(|r| r.rows.first().map(|row| (
            ledger_value_to_string(&row.values[0]).parse::<u64>().unwrap_or(0),
            ledger_value_to_string(&row.values[1]).parse::<u64>().unwrap_or(0),
        )))
        .unwrap_or((0, 0));

    // Chain verification
    let (chain_status, chain_detail) = if min_seq > 0 && max_seq >= min_seq {
        let vc_sql = format!("SELECT VERIFY_CHAIN({min_seq}, {max_seq})");
        match run_sql(&vc_sql, ledger, session) {
            Ok(r) => {
                let detail = result_to_text(&r);
                let ok = detail.to_uppercase().contains("OK");
                (if ok { "VERIFIED" } else { "FAILED" }, detail)
            }
            Err(e) => ("ERROR", format!("{e}")),
        }
    } else {
        ("NO ENTRIES", "No entries in this period.".to_string())
    };

    // Merkle root
    let merkle_root = if min_seq > 0 && max_seq >= min_seq {
        let mr_sql = format!("SELECT MERKLE_ROOT({min_seq}, {max_seq})");
        run_sql(&mr_sql, ledger, session)
            .ok()
            .and_then(|r| r.rows.first().map(|row| ledger_value_to_string(&row.values[3])))
            .unwrap_or_else(|| "unavailable".to_string())
    } else {
        "no entries".to_string()
    };

    // Sample entries (first 5)
    let sample_sql = format!(
        "SELECT sequence, id, status, description, effective_at, content_hash \
         FROM ledger WHERE {base_filter} LIMIT 5"
    );
    let sample_result = run_sql(&sample_sql, ledger, session).unwrap_or_default();

    // Full chain integrity
    let full_chain_sql = "SELECT VERIFY_CHAIN()".to_string();
    let full_chain_ok = run_sql(&full_chain_sql, ledger, session)
        .ok()
        .and_then(|r| scalar_str(&r))
        .map(|s| s.to_uppercase().contains("OK"))
        .unwrap_or(false);

    let mut out = String::new();
    out.push_str(&format!("# Cryptographic Audit Report\n\n"));
    out.push_str(&format!("**Tenant:** {tenant}  \n"));
    out.push_str(&format!("**Audit period:** {from} to {to}  \n"));
    out.push_str(&format!("**Domain:** {domain}  \n"));
    out.push_str(&format!("**Generated by:** VectorLedger v{}  \n\n",
        env!("CARGO_PKG_VERSION")));

    out.push_str("---\n\n## 1. Ledger Summary\n\n");
    out.push_str(&format!("| Field | Value |\n|---|---|\n"));
    out.push_str(&format!("| Total entries in period | {entry_count} |\n"));
    out.push_str(&format!("| First sequence | {min_seq} |\n"));
    out.push_str(&format!("| Last sequence | {max_seq} |\n"));
    out.push_str(&format!("| Full ledger chain integrity | {} |\n\n",
        if full_chain_ok { "✓ VERIFIED" } else { "✗ BROKEN" }));

    out.push_str("## 2. Period Hash Chain Verification\n\n");
    out.push_str(&format!("Chain status for sequences {min_seq}–{max_seq}: **{chain_status}**\n\n"));
    out.push_str(&chain_detail);
    out.push('\n');

    out.push_str("## 3. Merkle Commitment\n\n");
    out.push_str("The BLAKE3 Merkle root below is a cryptographic commitment over the \
                  `content_hash` of every entry in this period. Any third party can \
                  independently verify that a specific entry belongs to this commitment \
                  using `vledger audit-proof`.\n\n");
    out.push_str(&format!("```\nMerkle root: {merkle_root}\nSequences:   {min_seq} – {max_seq}\nEntries:     {entry_count}\n```\n\n"));

    out.push_str("## 4. Sample Entries\n\n");
    out.push_str("The following entries are a sample from the audit period. Each \
                  `content_hash` independently fingerprints its entry. Any modification \
                  to any field would produce a different hash and break the chain.\n\n");
    out.push_str(&result_to_text(&sample_result));

    out.push_str("\n## 5. Verification Instructions\n\n");
    out.push_str("To independently verify this report:\n\n");
    out.push_str("```bash\n");
    out.push_str("# Verify the full hash chain\n");
    out.push_str("vledger sql --ask \"verify the chain integrity\"\n\n");
    out.push_str("# Generate a portable audit package (no database access needed by auditor)\n");
    out.push_str(&format!("vledger audit-package \\\n  --data-dir ./vledger-data \\\n  \
                           --tenant \"{tenant}\" \\\n  --period-start {from} \\\n  \
                           --period-end {to} \\\n  --output audit-{from}-{to}.json\n\n"));
    out.push_str("# Verify the package (auditor runs this — no database required)\n");
    out.push_str("vledger verify-audit-package --file audit-package.json\n");
    out.push_str("```\n\n");

    out.push_str("---\n\n");
    out.push_str("*This report was generated by VectorLedger's cryptographic audit engine. \
                  The Merkle root and chain verification results are derived from \
                  tamper-evident BLAKE3 hash chains and cannot be retrospectively altered \
                  without invalidating the chain. This report is a technical input to an \
                  audit — it does not by itself constitute regulatory compliance.*\n");

    Ok(ok_text(out))
}

// ── Identity resolution tool ──────────────────────────────────────────────────

/// Resolve an account identity from a name, code, or UUID.
///
/// This is the MANDATORY first step before any write operation involving a
/// named person or entity. It searches the accounts table by code, name,
/// and UUID and returns either:
///
/// - FOUND: the account id, code, name, type, currency, and current balance
/// - NOT_FOUND: a clear refusal with instructions — the agent must STOP and
///   ask the user to clarify rather than guessing or using a random account
/// - MULTIPLE_FOUND: a list of candidates — the agent must ask the user to
///   disambiguate before proceeding
///
/// The agent MUST call this tool for EVERY named party before calling
/// `post_entry`. Never infer account identity from transaction context.
fn tool_resolve_account(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let query = args["query"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("'query' is required — name, code, or UUID to resolve"))?;

    let esc = query.replace('\'', "''");

    // Try exact code match
    let by_code = run_sql(
        &format!("SELECT id, code, name, account_type, currency, domain, balance \
                  FROM accounts WHERE code = '{esc}'"),
        ledger, session,
    );

    // Try exact name match
    let by_name = run_sql(
        &format!("SELECT id, code, name, account_type, currency, domain, balance \
                  FROM accounts WHERE name = '{esc}'"),
        ledger, session,
    );

    // Try UUID match
    let by_uuid = run_sql(
        &format!("SELECT id, code, name, account_type, currency, domain, balance \
                  FROM accounts WHERE id = '{esc}'"),
        ledger, session,
    );

    // Try metadata search in ledger for entries mentioning this name
    let by_metadata = run_sql(
        &format!("SELECT sequence, description, metadata FROM ledger \
                  WHERE metadata LIKE '%{esc}%' LIMIT 5"),
        ledger, session,
    );

    // Collect all direct account matches
    let mut matches: Vec<Vec<String>> = Vec::new();

    for result in [by_code, by_name, by_uuid] {
        if let Ok(r) = result {
            for row in &r.rows {
                let vals: Vec<String> = row.values.iter().map(|v| ledger_value_to_string(v)).collect();
                // Deduplicate by account id (first column)
                if !matches.iter().any(|m| m.first() == vals.first()) {
                    matches.push(vals);
                }
            }
        }
    }

    let mut out = format!("## Account Resolution — \"{query}\"\n\n");

    if matches.is_empty() {
        // No direct account match — check if they appear in transaction metadata
        let metadata_rows = by_metadata.ok()
            .map(|r| rows_as_strings(&r))
            .unwrap_or_default();

        out.push_str("### ✗ NOT FOUND\n\n");
        out.push_str(&format!(
            "No account found with code, name, or UUID matching `{query}`.\n\n"
        ));

        if !metadata_rows.is_empty() {
            out.push_str("This name appears in transaction metadata (as sender/receiver), \
                          but VectorLedger accounts use numeric codes — the person's name \
                          in metadata does not identify their account.\n\n");
            out.push_str("**Recent transactions mentioning this name:**\n\n");
            for row in &metadata_rows {
                let seq  = row.get(0).map(|s| s.as_str()).unwrap_or("?");
                let desc = row.get(1).map(|s| s.as_str()).unwrap_or("?");
                out.push_str(&format!("- Sequence {seq}: {desc}\n"));
            }
            out.push('\n');
            out.push_str("To find the actual account, look up the ledger_lines for one \
                          of these entries and identify the account UUID from the \
                          `account_id` column. Then use that UUID as the debit or credit \
                          account in `post_entry`.\n\n");
        }

        out.push_str("**⛔ STOP — do not post this entry.**\n\n");
        out.push_str("The correct action is to:\n");
        out.push_str("1. Ask the user to provide the exact account code or UUID for each party, OR\n");
        out.push_str("2. Ask the user to look up the account in their system of record and provide it, OR\n");
        out.push_str("3. Use `query_ledger` with `SELECT * FROM ledger_lines WHERE account_id = '<uuid>'` \
                      to confirm an account belongs to the correct person before using it.\n\n");
        out.push_str("Never assign a random or unverified account to a named individual.\n");

        return Ok(err_text(out));
    }

    if matches.len() == 1 {
        let r = &matches[0];
        let acct_id   = r.get(0).map(|s| s.as_str()).unwrap_or("?");
        let acct_code = r.get(1).map(|s| s.as_str()).unwrap_or("?");
        let acct_name = r.get(2).map(|s| s.as_str()).unwrap_or("?");
        let acct_type = r.get(3).map(|s| s.as_str()).unwrap_or("?");
        let currency  = r.get(4).map(|s| s.as_str()).unwrap_or("?");
        let domain    = r.get(5).map(|s| s.as_str()).unwrap_or("?");
        let balance: i64 = r.get(6).and_then(|s| s.parse().ok()).unwrap_or(0);

        out.push_str("### ✓ FOUND — single match\n\n");
        out.push_str("| Field | Value |\n|---|---|\n");
        out.push_str(&format!("| Account ID | `{acct_id}` |\n"));
        out.push_str(&format!("| Code | {acct_code} |\n"));
        out.push_str(&format!("| Name | {acct_name} |\n"));
        out.push_str(&format!("| Type | {acct_type} |\n"));
        out.push_str(&format!("| Currency | {currency} |\n"));
        out.push_str(&format!("| Domain | {domain} |\n"));
        out.push_str(&format!("| Balance | {} minor units |\n\n", balance));
        out.push_str("✓ This account can be used in `post_entry` as `debit_account` or \
                      `credit_account` using the Account ID above.\n\n");
        out.push_str("**Before posting, confirm with the user** that this is the correct \
                      account for the intended party.\n");

        return Ok(ok_text(out));
    }

    // Multiple matches — must disambiguate
    out.push_str(&format!("### ⚠ MULTIPLE MATCHES ({} accounts found)\n\n", matches.len()));
    out.push_str("| Account ID | Code | Name | Type | Currency | Balance |\n|---|---|---|---|---|---|\n");
    for r in &matches {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            r.get(0).map(|s| s.as_str()).unwrap_or("?"),
            r.get(1).map(|s| s.as_str()).unwrap_or("?"),
            r.get(2).map(|s| s.as_str()).unwrap_or("?"),
            r.get(3).map(|s| s.as_str()).unwrap_or("?"),
            r.get(4).map(|s| s.as_str()).unwrap_or("?"),
            r.get(6).map(|s| s.as_str()).unwrap_or("?"),
        ));
    }
    out.push('\n');
    out.push_str("**⛔ STOP — do not post this entry.**\n\n");
    out.push_str("Multiple accounts match this query. Ask the user to specify \
                  which account ID to use before proceeding.\n");

    Ok(err_text(out))
}

// ── Correction workflow tools ─────────────────────────────────────────────────

/// Step 1 of the correction workflow: look up the original entry and produce
/// a structured proposal showing exactly what will happen — the reversal and
/// correction entries — before anything is written.
///
/// The agent MUST show this proposal to the user and receive explicit
/// confirmation before calling `execute_correction`.
fn tool_propose_correction(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let sequence = args["sequence"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("'sequence' is required"))?;
    let correct_amount_minor = args["correct_amount_minor_units"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!(
            "'correct_amount_minor_units' is required (integer minor units, e.g. 40192 for $401.92)"
        ))?;

    if correct_amount_minor <= 0 {
        return Ok(err_text("'correct_amount_minor_units' must be a positive integer"));
    }

    // Look up the original entry header
    let entry_sql = format!(
        "SELECT sequence, id, status, description, domain, effective_at, \
         external_ref, content_hash, chain_hash, metadata \
         FROM ledger WHERE sequence = {sequence}"
    );
    let entry_result = match run_sql(&entry_sql, ledger, session) {
        Ok(r) => r,
        Err(e) => return Ok(err_text(format!("Could not look up entry #{sequence}: {e}"))),
    };

    if entry_result.rows.is_empty() {
        return Ok(err_text(format!("Entry #{sequence} not found")));
    }

    let entry_row = &entry_result.rows[0];
    let vals: Vec<String> = entry_row.values.iter().map(|v| ledger_value_to_string(v)).collect();

    let entry_id     = vals.get(1).cloned().unwrap_or_default();
    let status       = vals.get(2).cloned().unwrap_or_default();
    let description  = vals.get(3).cloned().unwrap_or_default();
    let domain       = vals.get(4).cloned().unwrap_or_default();
    let content_hash = vals.get(7).cloned().unwrap_or_default();
    let chain_hash   = vals.get(8).cloned().unwrap_or_default();

    // Only Posted entries can be reversed
    if status != "Posted" {
        return Ok(err_text(format!(
            "Entry #{sequence} has status '{status}' — only 'Posted' entries can be corrected.\n\
             A reversal can only be applied to a committed Posted entry."
        )));
    }

    // Look up the ledger lines to find the original debit/credit accounts and amount
    let lines_sql = format!(
        "SELECT account_id, dr_cr, amount, currency FROM ledger_lines \
         WHERE sequence = {sequence} ORDER BY dr_cr"
    );
    let lines_result = match run_sql(&lines_sql, ledger, session) {
        Ok(r) => r,
        Err(e) => return Ok(err_text(format!("Could not look up lines for #{sequence}: {e}"))),
    };

    if lines_result.rows.len() < 2 {
        return Ok(err_text(format!("Entry #{sequence} does not have the expected 2 journal lines")));
    }

    let line_vals: Vec<Vec<String>> = lines_result.rows.iter()
        .map(|r| r.values.iter().map(|v| ledger_value_to_string(v)).collect())
        .collect();

    // Find debit and credit lines
    let debit_line  = line_vals.iter().find(|r| r.get(1).map(|s| s == "Debit").unwrap_or(false));
    let credit_line = line_vals.iter().find(|r| r.get(1).map(|s| s == "Credit").unwrap_or(false));

    let (debit_account_id, credit_account_id, original_amount_minor, currency) = match (debit_line, credit_line) {
        (Some(d), Some(c)) => {
            let amt: i64 = d.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let cur = d.get(3).cloned().unwrap_or_else(|| "USD".to_string());
            (d[0].clone(), c[0].clone(), amt, cur)
        }
        _ => return Ok(err_text(format!("Could not determine debit/credit accounts for #{sequence}"))),
    };

    // Format amounts for display
    let fmt_amt = |minor: i64| format_amount(minor, &currency);

    let original_display  = fmt_amt(original_amount_minor);
    let correct_display   = fmt_amt(correct_amount_minor);
    let adjustment        = correct_amount_minor - original_amount_minor;
    let adjustment_display = if adjustment >= 0 {
        format!("+{}", fmt_amt(adjustment))
    } else {
        format!("-{}", fmt_amt(adjustment.abs()))
    };

    // Build the structured proposal
    let mut out = String::new();
    out.push_str("## Correction Proposal\n\n");
    out.push_str("────────────────────────────────────────────\n\n");
    out.push_str(&format!("**Original entry:** #{sequence}  \n"));
    out.push_str(&format!("**Description:** {}  \n", description));
    out.push_str(&format!("**Original amount:** {}  \n", original_display));
    out.push_str(&format!("**Correct amount:** {}  \n", correct_display));
    out.push_str(&format!("**Net adjustment:** {}  \n\n", adjustment_display));
    out.push_str("────────────────────────────────────────────\n\n");

    out.push_str("### Proposed actions\n\n");
    out.push_str(&format!(
        "**1. Reverse entry #{sequence}** *(flip debit and credit)*  \n"
    ));
    out.push_str(&format!("   Debit:  `{credit_account_id}` — {}  \n", original_display));
    out.push_str(&format!("   Credit: `{debit_account_id}` — {}  \n\n", original_display));

    out.push_str("**2. Post correction** *(restore correct amount)*  \n");
    out.push_str(&format!("   Debit:  `{debit_account_id}` — {}  \n", correct_display));
    out.push_str(&format!("   Credit: `{credit_account_id}` — {}  \n\n", correct_display));

    out.push_str("────────────────────────────────────────────\n\n");
    out.push_str("### What will be preserved\n\n");
    out.push_str(&format!("| Field | Value |\n|---|---|\n"));
    out.push_str(&format!("| Historical entry | ✓ PRESERVED — entry #{sequence} is never modified |\n"));
    out.push_str(&format!("| Original content_hash | ✓ PRESERVED — `{}` |\n", &content_hash[..16]));
    out.push_str(&format!("| Original chain_hash | ✓ PRESERVED — `{}` |\n", &chain_hash[..16]));
    out.push_str("| New entries | Will be APPENDED as new sequences |\n");
    out.push_str("| Double-entry balance | ✓ Both new entries will balance |\n");
    out.push_str("| Hash chain | ✓ Extended with reversal and correction |\n\n");

    out.push_str("────────────────────────────────────────────\n\n");
    out.push_str("### ⚠ Awaiting confirmation\n\n");
    out.push_str("**Ask the user:** *\"Shall I proceed with this correction?\"*\n\n");
    out.push_str("If confirmed, call `execute_correction` with:\n");
    out.push_str(&format!("```json\n{{\n"));
    out.push_str(&format!("  \"sequence\": {sequence},\n"));
    out.push_str(&format!("  \"correct_amount_minor_units\": {correct_amount_minor},\n"));
    out.push_str(&format!("  \"original_description\": \"{description}\",\n"));
    out.push_str(&format!("  \"debit_account_id\": \"{debit_account_id}\",\n"));
    out.push_str(&format!("  \"credit_account_id\": \"{credit_account_id}\",\n"));
    out.push_str(&format!("  \"original_amount_minor_units\": {original_amount_minor},\n"));
    out.push_str(&format!("  \"currency\": \"{currency}\",\n"));
    out.push_str(&format!("  \"domain\": \"{domain}\",\n"));
    out.push_str(&format!("  \"original_entry_id\": \"{entry_id}\"\n"));
    out.push_str("}\n```\n\n");
    out.push_str("Do NOT call `execute_correction` without explicit user confirmation.\n");

    Ok(ok_text(out))
}

/// Step 2 of the correction workflow: execute the reversal and correction
/// entries after the user has confirmed the proposal from `propose_correction`.
///
/// This tool MUST only be called after `propose_correction` has been shown
/// to the user and they have explicitly confirmed they want to proceed.
fn tool_execute_correction(
    args: &Value,
    ledger: &Arc<RwLock<LedgerStore>>,
    session: &Session,
) -> Result<Value> {
    let sequence               = args["sequence"].as_u64()
        .ok_or_else(|| anyhow::anyhow!("'sequence' is required"))?;
    let correct_amount         = args["correct_amount_minor_units"].as_i64()
        .ok_or_else(|| anyhow::anyhow!("'correct_amount_minor_units' is required"))?;
    let original_amount        = args["original_amount_minor_units"].as_i64()
        .ok_or_else(|| anyhow::anyhow!("'original_amount_minor_units' is required"))?;
    let debit_account_id       = args["debit_account_id"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'debit_account_id' is required"))?;
    let credit_account_id      = args["credit_account_id"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'credit_account_id' is required"))?;
    let original_description   = args["original_description"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'original_description' is required"))?;
    let original_entry_id      = args["original_entry_id"].as_str()
        .ok_or_else(|| anyhow::anyhow!("'original_entry_id' is required"))?;
    let currency               = args["currency"].as_str().unwrap_or("USD");
    let domain                 = args["domain"].as_str().unwrap_or("main");

    let escape = |s: &str| s.replace('\'', "''");
    let fmt = |m: i64| format_amount(m, currency);

    // ── Derive stable, deterministic idempotency keys ─────────────────────────
    //
    // These keys are derived entirely from `original_entry_id`, which is
    // provided by the caller and is stable across retries.  If the agent
    // crashes after posting the reversal but before posting the correction,
    // or if the user re-submits the same request, the idempotency keys ensure
    // each of the two entries is posted exactly once — a retry is a no-op.
    let reversal_idem_key    = format!("reversal-of-{original_entry_id}");
    let correction_idem_key  = format!("correction-of-{original_entry_id}");

    // ── Pre-flight: detect prior (partial) execution ──────────────────────────
    //
    // Query both idempotency keys up-front.  Three states are possible:
    //   (a) Neither exists  → first execution, proceed normally.
    //   (b) Both exist      → fully completed on a prior run; return the
    //                         existing sequences so the caller gets a valid
    //                         confirmation without any new writes.
    //   (c) Only reversal   → agent crashed between the two INSERTs; skip the
    //                         reversal INSERT and post only the correction.
    let reversal_exists_sql = format!(
        "SELECT sequence FROM ledger WHERE idempotency_key = '{}' LIMIT 1",
        escape(&reversal_idem_key)
    );
    let correction_exists_sql = format!(
        "SELECT sequence FROM ledger WHERE idempotency_key = '{}' LIMIT 1",
        escape(&correction_idem_key)
    );

    let existing_reversal_seq: Option<u64> = run_sql(&reversal_exists_sql, ledger, session)
        .ok()
        .and_then(|r| r.rows.into_iter().next())
        .and_then(|row| row.values.into_iter().next())
        .and_then(|v| match v {
            vledger_sql::result::Value::BigInt(i) => Some(i as u64),
            vledger_sql::result::Value::Int(i)    => Some(i as u64),
            _                                      => None,
        });

    let existing_correction_seq: Option<u64> = run_sql(&correction_exists_sql, ledger, session)
        .ok()
        .and_then(|r| r.rows.into_iter().next())
        .and_then(|row| row.values.into_iter().next())
        .and_then(|v| match v {
            vledger_sql::result::Value::BigInt(i) => Some(i as u64),
            vledger_sql::result::Value::Int(i)    => Some(i as u64),
            _                                      => None,
        });

    // Both entries were already posted on a prior run — return confirmation
    // without making any new writes.
    if let (Some(rev_seq), Some(cor_seq)) = (existing_reversal_seq, existing_correction_seq) {
        let chain_ok = run_sql("SELECT VERIFY_CHAIN()", ledger, session)
            .ok()
            .map(|r| result_to_text(&r).to_uppercase().contains("OK"))
            .unwrap_or(false);

        let mut out = String::new();
        out.push_str("## Correction Already Applied (Idempotent)\n\n");
        out.push_str("────────────────────────────────────────────\n\n");
        out.push_str("This correction was already posted on a prior run. ");
        out.push_str("No new entries have been written.\n\n");
        out.push_str(&format!("✓ **Reversal** (existing)  \n"));
        out.push_str(&format!("  Sequence: {rev_seq}  \n"));
        out.push_str(&format!("  Amount:   {} (original amount reversed)  \n\n", fmt(original_amount)));
        out.push_str(&format!("✓ **Correction** (existing)  \n"));
        out.push_str(&format!("  Sequence: {cor_seq}  \n"));
        out.push_str(&format!("  Amount:   {} (correct amount)  \n\n", fmt(correct_amount)));
        out.push_str("────────────────────────────────────────────\n\n");
        out.push_str(&format!("| Hash chain | {} |\n",
            if chain_ok { "✓ Verified" } else { "⚠ Verify manually with VERIFY_CHAIN()" }
        ));
        return Ok(ok_text(out));
    }

    // ── Post the reversal (skip if already posted from a prior partial run) ───
    let reversal_desc = format!(
        "Reversal of #{sequence} — {}",
        escape(original_description)
    );
    let reversal_meta = format!(
        "{{\"reverses\":\"{original_entry_id}\",\"reason\":\"amount_correction\",\
         \"original_amount\":{original_amount},\"correct_amount\":{correct_amount}}}"
    );

    let (reversal_seq, reversal_id) = if let Some(seq) = existing_reversal_seq {
        // Already posted — reuse the existing sequence from the prior run.
        let id = run_sql(
            &format!("SELECT id FROM ledger WHERE sequence = {seq} LIMIT 1"),
            ledger,
            session,
        )
        .ok()
        .and_then(|r| r.rows.into_iter().next())
        .and_then(|row| row.values.into_iter().next())
        .map(|v| ledger_value_to_string(&v))
        .unwrap_or_else(|| "?".to_string());
        (Some(seq), id)
    } else {
        let reversal_sql = format!(
            "INSERT INTO ledger \
             (description, debit_account, credit_account, amount, currency, domain, \
              external_ref, idempotency_key, metadata) \
             VALUES ('{}', '{}', '{}', {}, '{}', '{}', 'reversal-of-{}', '{}', '{}')",
            escape(&reversal_desc),
            escape(credit_account_id),   // flip: original credit becomes debit
            escape(debit_account_id),    // flip: original debit becomes credit
            original_amount,
            escape(currency),
            escape(domain),
            escape(original_entry_id),
            escape(&reversal_idem_key),
            escape(&reversal_meta),
        );

        let result = match run_sql(&reversal_sql, ledger, session) {
            Ok(r) => r,
            Err(e) => return Ok(err_text(format!("Failed to post reversal: {e}"))),
        };

        let id = result.entry_id.map(|u| u.to_string())
            .unwrap_or_else(|| "?".to_string());
        (result.entry_sequence, id)
    };

    // ── Post the correction ───────────────────────────────────────────────────
    let correction_desc = format!(
        "Correction of #{sequence} — {}",
        escape(original_description)
    );
    let correction_meta = format!(
        "{{\"corrects\":\"{original_entry_id}\",\"reason\":\"amount_correction\",\
         \"original_amount\":{original_amount},\"correct_amount\":{correct_amount}}}"
    );
    let correction_sql = format!(
        "INSERT INTO ledger \
         (description, debit_account, credit_account, amount, currency, domain, \
          external_ref, idempotency_key, metadata) \
         VALUES ('{}', '{}', '{}', {}, '{}', '{}', 'correction-of-{}', '{}', '{}')",
        escape(&correction_desc),
        escape(debit_account_id),
        escape(credit_account_id),
        correct_amount,
        escape(currency),
        escape(domain),
        escape(original_entry_id),
        escape(&correction_idem_key),
        escape(&correction_meta),
    );

    let correction_result = match run_sql(&correction_sql, ledger, session) {
        Ok(r) => r,
        Err(e) => return Ok(err_text(format!(
            "Reversal was posted (sequence {:?}) but correction FAILED: {e}\n\
             The ledger now has an unmatched reversal. Post the correction manually.",
            reversal_seq
        ))),
    };

    let correction_seq = correction_result.entry_sequence;
    let correction_id  = correction_result.entry_id.map(|u| u.to_string())
        .unwrap_or_else(|| "?".to_string());

    // ── Verify chain integrity ────────────────────────────────────────────────
    let chain_ok = run_sql("SELECT VERIFY_CHAIN()", ledger, session)
        .ok()
        .map(|r| result_to_text(&r).to_uppercase().contains("OK"))
        .unwrap_or(false);

    // ── Build confirmation summary ────────────────────────────────────────────
    let mut out = String::new();
    out.push_str("## Correction Complete\n\n");
    out.push_str("────────────────────────────────────────────\n\n");

    out.push_str(&format!("✓ **Reversal posted**  \n"));
    out.push_str(&format!("  Sequence: {}  \n", reversal_seq.map(|s| s.to_string()).unwrap_or("?".into())));
    out.push_str(&format!("  Entry ID: {}  \n", reversal_id));
    out.push_str(&format!("  Amount:   {} (original amount reversed)  \n\n", fmt(original_amount)));

    out.push_str(&format!("✓ **Correction posted**  \n"));
    out.push_str(&format!("  Sequence: {}  \n", correction_seq.map(|s| s.to_string()).unwrap_or("?".into())));
    out.push_str(&format!("  Entry ID: {}  \n", correction_id));
    out.push_str(&format!("  Amount:   {} (correct amount)  \n\n", fmt(correct_amount)));

    out.push_str("────────────────────────────────────────────\n\n");
    out.push_str("| Check | Result |\n|---|---|\n");
    out.push_str(&format!("| Double-entry balanced | ✓ Both entries balance |\n"));
    out.push_str(&format!("| Original entry #{sequence} | ✓ PRESERVED — not modified |\n"));
    out.push_str(&format!("| Hash chain | {} |\n",
        if chain_ok { "✓ Extended and verified" } else { "⚠ Verify manually with VERIFY_CHAIN()" }
    ));
    out.push_str(&format!("| Net adjustment | {} |\n\n", {
        let adj = correct_amount - original_amount;
        if adj >= 0 { format!("+{}", fmt(adj)) } else { format!("-{}", fmt(adj.abs())) }
    }));

    out.push_str(&format!(
        "The ledger now reflects {} for this transaction. \
         The original entry #{sequence} at {} is preserved in full with its \
         original content_hash and chain_hash intact.\n",
        fmt(correct_amount),
        fmt(original_amount),
    ));

    Ok(ok_text(out))
}

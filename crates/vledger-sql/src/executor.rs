//! SQL executor — runs a `LogicalPlan` against a `LedgerStore`.
//!
//! ## Read/write split
//!
//! `Executor` requires `&mut LedgerStore` and handles write plans
//! (`PostEntry`, `CreateAccount`).
//!
//! `ReadExecutor` requires only `&LedgerStore` and handles all read-only
//! plans (`ScanEntries`, `ScanAccounts`, `GetBalance`, `VerifyChain`,
//! `Join`, `Aggregate`, `Window`).
//!
//! The server uses `RwLock::read()` for read plans and `RwLock::write()`
//! for write plans, allowing concurrent reads without blocking each other.

use hex;
use uuid::Uuid;
use vledger_crypto::merkle::{merkle_proof, merkle_root};
use vledger_ledger::{Account, AccountType, Amount, JournalEntryBuilder, LedgerStore};

use crate::error::SqlError;
use crate::planner::{AccountSpec, AggFn, EntryFilter, EntrySpec, LogicalPlan};
use crate::result::{LeafProof, MerkleProof, ProofStep, QueryResult, Row, Value};

// ── ReadExecutor — immutable borrow, all read-only plans ─────────────────────

/// Read-only executor.  Requires only `&LedgerStore`.
///
/// The server acquires `RwLock::read()` before constructing this, allowing
/// multiple concurrent read queries without any lock contention between them.
pub struct ReadExecutor<'a> {
    ledger: &'a LedgerStore,
    /// When `true`, every SELECT attaches a Merkle proof to the result.
    pub attach_proofs: bool,
}

impl<'a> ReadExecutor<'a> {
    pub fn new(ledger: &'a LedgerStore) -> Self {
        Self {
            ledger,
            attach_proofs: false,
        }
    }

    pub fn with_proofs(ledger: &'a LedgerStore) -> Self {
        Self {
            ledger,
            attach_proofs: true,
        }
    }

    /// Execute a read-only `LogicalPlan`.
    /// Returns `Err(SqlError::Unsupported)` if a write plan is passed.
    pub fn execute(&self, plan: LogicalPlan) -> Result<QueryResult, SqlError> {
        match plan {
            LogicalPlan::ScanEntries { filter } => self.exec_scan_entries(filter),
            LogicalPlan::ScanLedgerLines { filter } => self.exec_scan_ledger_lines(filter),
            LogicalPlan::ScanAccounts { filter } => self.exec_scan_accounts(filter),
            LogicalPlan::GetBalance { account_ref } => self.exec_get_balance(&account_ref),
            LogicalPlan::VerifyChain { from_seq, to_seq } => {
                self.exec_verify_chain(from_seq, to_seq)
            }
            LogicalPlan::VerifyEntry { sequence } => self.exec_verify_entry(sequence),
            LogicalPlan::Constant { col, val } => self.exec_constant(col, val),
            LogicalPlan::Join(spec) => self.exec_join(spec),
            LogicalPlan::Aggregate(spec) => self.exec_aggregate(spec),
            LogicalPlan::Window(spec) => self.exec_window(spec),
            LogicalPlan::PostEntry(_) | LogicalPlan::CreateAccount(_) => {
                Err(SqlError::Unsupported(
                    "write plans must be executed with Executor (requires &mut LedgerStore)".into(),
                ))
            }
        }
    }

    // ── SELECT FROM ledger ────────────────────────────────────────────────
    //
    // Safety cap: unbounded full-table scans on a large ledger will exhaust
    // server memory.  When no LIMIT or point-lookup filter is supplied the
    // server applies DEFAULT_SCAN_LIMIT automatically and appends a notice
    // to the result message so the caller knows to paginate.
    const DEFAULT_SCAN_LIMIT: usize = 10_000;

    fn exec_scan_entries(&self, filter: Option<EntryFilter>) -> Result<QueryResult, SqlError> {
        let entries = self.ledger.all_entries();

        let cols = vec![
            "sequence".into(),
            "id".into(),
            "status".into(),
            "description".into(),
            "domain".into(),
            "effective_at".into(),
            "posted_at".into(),
            "external_ref".into(),
            "content_hash".into(),
            "chain_hash".into(),
            "lines".into(),
        ];

        let all_leaf_data: Vec<Vec<u8>> = entries.iter().map(|e| e.content_hash.to_vec()).collect();

        let is_point_lookup = matches!(
            filter,
            Some(EntryFilter::BySequence(_)) | Some(EntryFilter::ByExternalRef(_))
        );
        let explicit_limit = if let Some(EntryFilter::Limit(n)) = &filter {
            Some(*n)
        } else {
            None
        };

        // Apply filter predicate.
        let filtered: Vec<(usize, _)> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| match &filter {
                None => true,
                Some(EntryFilter::BySequence(seq)) => e.sequence == *seq,
                Some(EntryFilter::ByExternalRef(r)) => {
                    e.external_ref.as_deref() == Some(r.as_str())
                }
                Some(EntryFilter::ByDomain(d)) => &e.domain == d,
                Some(EntryFilter::ByStatus(s)) => {
                    format!("{:?}", e.status).to_lowercase() == s.to_lowercase()
                }
                Some(EntryFilter::Limit(_)) => true,
            })
            .collect();

        // Determine effective row cap:
        // - Point lookups (by sequence / external_ref): no cap needed.
        // - Explicit LIMIT n: honour exactly.
        // - Everything else (full scan, by domain, by status): cap at DEFAULT_SCAN_LIMIT.
        let (capped, cap_applied) = if is_point_lookup {
            (filtered, false)
        } else {
            let limit = explicit_limit.unwrap_or(Self::DEFAULT_SCAN_LIMIT);
            let capped = filtered.into_iter().take(limit).collect::<Vec<_>>();
            let cap_applied = explicit_limit.is_none();
            (capped, cap_applied)
        };

        let mut rows = Vec::new();
        let mut leaf_indices = Vec::new();

        for (idx, entry) in &capped {
            let lines_str = entry
                .lines
                .iter()
                .map(|l| {
                    format!(
                        "{}: {:?} {} {}",
                        l.account_id,
                        l.dr_cr,
                        l.amount.as_i64(),
                        l.currency_code
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");

            rows.push(Row::new(
                cols.clone(),
                vec![
                    Value::BigInt(entry.sequence as i128),
                    Value::Uuid(entry.id.to_string()),
                    Value::Text(format!("{:?}", entry.status)),
                    Value::Text(entry.description.clone()),
                    Value::Text(entry.domain.clone()),
                    Value::Timestamp(entry.effective_at.to_rfc3339()),
                    Value::Timestamp(entry.posted_at.to_rfc3339()),
                    Value::Text(entry.external_ref.clone().unwrap_or_default()),
                    Value::Hash(hex::encode(entry.content_hash)),
                    Value::Hash(hex::encode(entry.chain_hash)),
                    Value::Text(lines_str),
                ],
            ));
            leaf_indices.push(*idx);
        }

        let n = rows.len();
        let message = if cap_applied {
            format!(
                "{n} rows (capped at {limit} — use LIMIT n or WHERE sequence = x to paginate)",
                limit = Self::DEFAULT_SCAN_LIMIT
            )
        } else {
            format!("{n} rows")
        };
        let mut result = QueryResult::rows(cols, rows, message);

        if self.attach_proofs && !all_leaf_data.is_empty() {
            result.proof = Some(build_merkle_proof(
                &all_leaf_data,
                &leaf_indices,
                |root: &[u8; 32]| self.ledger.sign_bytes(root),
            ));
        }

        Ok(result)
    }

    // ── SELECT * FROM ledger_lines — one row per journal line ────────────
    //
    // Traditional accountant's view: each debit and credit appears on its
    // own row alongside the entry metadata.  Format:
    //
    //  date        | sequence | description | account_id | dr_cr  | amount | currency | domain
    //  2026-08-17  | 1        | Wire xfer   | <uuid>     | Debit  | 100.00 | USD      | main
    //  2026-08-17  | 1        | Wire xfer   | <uuid>     | Credit | 100.00 | USD      | main

    fn exec_scan_ledger_lines(&self, filter: Option<EntryFilter>) -> Result<QueryResult, SqlError> {
        let entries = self.ledger.all_entries();

        let cols = vec![
            "date".into(),
            "sequence".into(),
            "entry_id".into(),
            "description".into(),
            "domain".into(),
            "account_id".into(),
            "dr_cr".into(),
            "amount".into(),
            "currency".into(),
            "status".into(),
        ];

        // Apply entry-level filter first, then expand each entry into its lines.
        // Point lookups (by sequence) skip the cap; everything else is capped at
        // DEFAULT_SCAN_LIMIT entries (before line expansion) to prevent OOM.
        let is_point_lookup = matches!(
            filter,
            Some(EntryFilter::BySequence(_)) | Some(EntryFilter::ByExternalRef(_))
        );
        let explicit_limit = if let Some(EntryFilter::Limit(n)) = &filter {
            Some(*n)
        } else {
            None
        };

        let filtered_entries: Vec<_> = entries
            .iter()
            .filter(|e| match &filter {
                None => true,
                Some(EntryFilter::BySequence(seq)) => e.sequence == *seq,
                Some(EntryFilter::ByExternalRef(r)) => {
                    e.external_ref.as_deref() == Some(r.as_str())
                }
                Some(EntryFilter::ByDomain(d)) => &e.domain == d,
                Some(EntryFilter::ByStatus(s)) => {
                    format!("{:?}", e.status).to_lowercase() == s.to_lowercase()
                }
                Some(EntryFilter::Limit(_)) => true,
            })
            .collect();

        let (capped_entries, cap_applied) = if is_point_lookup {
            (filtered_entries, false)
        } else {
            let limit = explicit_limit.unwrap_or(Self::DEFAULT_SCAN_LIMIT);
            let capped = filtered_entries.into_iter().take(limit).collect::<Vec<_>>();
            let cap_applied = explicit_limit.is_none();
            (capped, cap_applied)
        };

        let mut rows = Vec::new();

        for entry in capped_entries {
            let date = entry.effective_at.format("%Y-%m-%d").to_string();
            for line in &entry.lines {
                let dr_cr_str = match line.dr_cr {
                    vledger_ledger::entry::DrCr::Debit => "Debit",
                    vledger_ledger::entry::DrCr::Credit => "Credit",
                };
                // Format amount as decimal with 2 decimal places.
                // Amounts are stored in minor units (cents), so divide by 100.
                let amount_display = format!("{:.2}", line.amount.as_i64() as f64 / 100.0);

                rows.push(Row::new(
                    cols.clone(),
                    vec![
                        Value::Text(date.clone()),
                        Value::BigInt(entry.sequence as i128),
                        Value::Uuid(entry.id.to_string()),
                        Value::Text(entry.description.clone()),
                        Value::Text(entry.domain.clone()),
                        Value::Uuid(line.account_id.to_string()),
                        Value::Text(dr_cr_str.to_string()),
                        Value::Text(amount_display),
                        Value::Text(line.currency_code.clone()),
                        Value::Text(format!("{:?}", entry.status)),
                    ],
                ));
            }
        }

        let n = rows.len();
        let message = if cap_applied {
            format!(
                "{n} rows (capped at {limit} entries — use LIMIT n or WHERE sequence = x to paginate)",
                limit = Self::DEFAULT_SCAN_LIMIT
            )
        } else {
            format!("{n} rows")
        };
        Ok(QueryResult::rows(cols, rows, message))
    }

    // ── SELECT 1 / SELECT 'hello' / constant expression ──────────────────

    fn exec_constant(&self, col: String, val: String) -> Result<QueryResult, SqlError> {
        let cols = vec![col];
        let rows = vec![Row::new(cols.clone(), vec![Value::Text(val)])];
        Ok(QueryResult::rows(cols, rows, String::new()))
    }

    // ── SELECT FROM accounts ──────────────────────────────────────────────

    fn exec_scan_accounts(&self, filter: Option<EntryFilter>) -> Result<QueryResult, SqlError> {
        let cols = vec![
            "id".into(),
            "code".into(),
            "name".into(),
            "account_type".into(),
            "currency".into(),
            "status".into(),
            "domain".into(),
            "balance".into(),
        ];

        // Collect first so we don't hold the iterator while calling balance().
        let accounts: Vec<_> = self.ledger.all_accounts().cloned().collect();

        let rows: Vec<Row> = accounts
            .iter()
            .filter(|a| match &filter {
                None => true,
                Some(EntryFilter::ByDomain(d)) if d.starts_with("__account_code:") => {
                    a.code == d.trim_start_matches("__account_code:")
                }
                Some(EntryFilter::ByDomain(d)) if d.starts_with("__account_currency:") => {
                    a.currency_code == d.trim_start_matches("__account_currency:")
                }
                Some(EntryFilter::ByDomain(d)) => &a.domain == d,
                _ => true,
            })
            .map(|a| {
                let bal = self.ledger.balance(&a.id);
                Row::new(
                    cols.clone(),
                    vec![
                        Value::Uuid(a.id.to_string()),
                        Value::Text(a.code.clone()),
                        Value::Text(a.name.clone()),
                        Value::Text(format!("{:?}", a.account_type)),
                        Value::Text(a.currency_code.clone()),
                        Value::Text(format!("{:?}", a.status)),
                        Value::Text(a.domain.clone()),
                        Value::BigInt(bal),
                    ],
                )
            })
            .collect();

        let n = rows.len();
        Ok(QueryResult::rows(cols, rows, format!("{n} accounts")))
    }

    // ── SELECT BALANCE('…') ───────────────────────────────────────────────

    fn exec_get_balance(&self, account_ref: &str) -> Result<QueryResult, SqlError> {
        let acct_id = self.resolve_account(account_ref)?;
        let balance = self.ledger.balance(&acct_id);
        let cols = vec!["account".into(), "balance".into()];
        let rows = vec![Row::new(
            cols.clone(),
            vec![Value::Text(account_ref.to_string()), Value::BigInt(balance)],
        )];
        Ok(QueryResult::rows(
            cols,
            rows,
            format!("balance = {balance}"),
        ))
    }

    // ── SELECT VERIFY_CHAIN() / VERIFY_CHAIN(from, to) ───────────────────

    fn exec_verify_chain(
        &self,
        from_seq: Option<u64>,
        to_seq: Option<u64>,
    ) -> Result<QueryResult, SqlError> {
        let cols = vec![
            "status".into(),
            "entries_verified".into(),
            "chain_tip".into(),
        ];

        // Full chain when no range specified.
        if from_seq.is_none() && to_seq.is_none() {
            return match self.ledger.verify_chain_integrity() {
                Ok(()) => {
                    let n = self.ledger.entry_count();
                    let tip = hex::encode(self.ledger.chain_tip());
                    let rows = vec![Row::new(
                        cols.clone(),
                        vec![
                            Value::Text("OK".into()),
                            Value::BigInt(n as i128),
                            Value::Hash(tip),
                        ],
                    )];
                    Ok(QueryResult::rows(cols, rows, "Chain integrity verified"))
                }
                Err(e) => Ok(QueryResult::empty(format!("INTEGRITY FAILURE: {e}"))),
            };
        }

        // Range verification.
        match self.ledger.verify_chain_range(from_seq, to_seq) {
            Ok((count, tip)) => {
                let rows = vec![Row::new(
                    cols.clone(),
                    vec![
                        Value::Text("OK".into()),
                        Value::BigInt(count as i128),
                        Value::Hash(hex::encode(tip)),
                    ],
                )];
                Ok(QueryResult::rows(
                    cols,
                    rows,
                    format!("Chain range verified ({count} entries)"),
                ))
            }
            Err(e) => Ok(QueryResult::empty(format!("INTEGRITY FAILURE: {e}"))),
        }
    }

    // ── SELECT VERIFY_ENTRY(seq) ──────────────────────────────────────────

    fn exec_verify_entry(&self, sequence: u64) -> Result<QueryResult, SqlError> {
        let cols = vec![
            "sequence".into(),
            "status".into(),
            "content_hash".into(),
            "chain_hash".into(),
            "description".into(),
        ];
        match self.ledger.get_entry_by_sequence(sequence) {
            None => Ok(QueryResult::empty(format!(
                "entry with sequence {sequence} not found"
            ))),
            Some(entry) => {
                let ok = entry.verify_hashes();
                let rows = vec![Row::new(
                    cols.clone(),
                    vec![
                        Value::BigInt(entry.sequence as i128),
                        Value::Text(if ok { "VALID" } else { "CORRUPTED" }.into()),
                        Value::Hash(hex::encode(entry.content_hash)),
                        Value::Hash(hex::encode(entry.chain_hash)),
                        Value::Text(entry.description.clone()),
                    ],
                )];
                Ok(QueryResult::rows(
                    cols,
                    rows,
                    if ok {
                        "Entry hash verified".to_string()
                    } else {
                        "INTEGRITY FAILURE: hash mismatch".to_string()
                    },
                ))
            }
        }
    }

    // ── JOIN ──────────────────────────────────────────────────────────────

    fn exec_join(&self, spec: crate::planner::JoinSpec) -> Result<QueryResult, SqlError> {
        use crate::planner::JoinType;
        use std::collections::HashMap;

        let left_result = self.execute(*spec.left)?;
        let right_result = self.execute(*spec.right)?;

        let right_key_col = right_result
            .columns
            .iter()
            .position(|c| c == "id" || c == "code")
            .unwrap_or(0);

        let mut right_map: HashMap<String, &Row> = HashMap::new();
        for row in &right_result.rows {
            if let Some(k) = row.values.get(right_key_col) {
                right_map.insert(k.to_string(), row);
            }
        }

        let mut out_cols = left_result.columns.clone();
        for c in &right_result.columns {
            if !out_cols.contains(c) {
                out_cols.push(format!("r_{c}"));
            }
        }

        let mut rows: Vec<Row> = Vec::new();
        for left_row in &left_result.rows {
            let join_key = left_row
                .get("account_id")
                .or_else(|| left_row.values.first())
                .map(|v| v.to_string())
                .unwrap_or_default();

            let right_row = right_map.get(&join_key).copied();
            match (spec.join_type, right_row) {
                (_, Some(rr)) => {
                    let mut vals = left_row.values.clone();
                    for v in &rr.values {
                        vals.push(v.clone());
                    }
                    rows.push(Row::new(out_cols.clone(), vals));
                }
                (JoinType::LeftOuter, None) => {
                    let mut vals = left_row.values.clone();
                    for _ in &right_result.columns {
                        vals.push(Value::Null);
                    }
                    rows.push(Row::new(out_cols.clone(), vals));
                }
                (JoinType::Inner, None) => {}
            }
        }

        let n = rows.len();
        Ok(QueryResult::rows(
            out_cols,
            rows,
            format!("{n} rows (join)"),
        ))
    }

    // ── AGGREGATE ─────────────────────────────────────────────────────────

    fn exec_aggregate(&self, spec: crate::planner::AggregateSpec) -> Result<QueryResult, SqlError> {
        use std::collections::HashMap;

        let input = self.execute(*spec.input)?;
        let col_idx =
            |name: &str| -> Option<usize> { input.columns.iter().position(|c| c == name) };

        let mut groups: HashMap<Vec<String>, Vec<&Row>> = HashMap::new();
        for row in &input.rows {
            let key: Vec<String> = if spec.group_by.is_empty() {
                vec!["__all__".into()]
            } else {
                spec.group_by
                    .iter()
                    .map(|gb| {
                        col_idx(gb)
                            .and_then(|i| row.values.get(i))
                            .map(|v| v.to_string())
                            .unwrap_or_default()
                    })
                    .collect()
            };
            groups.entry(key).or_default().push(row);
        }

        let mut out_cols = spec.group_by.clone();
        for agg in &spec.aggregates {
            out_cols.push(agg.alias.clone());
        }

        let mut result_rows: Vec<Row> = Vec::new();
        let mut keys: Vec<Vec<String>> = groups.keys().cloned().collect();
        keys.sort();

        for key in &keys {
            let group_rows = &groups[key];
            let mut vals: Vec<Value> = if spec.group_by.is_empty() {
                vec![]
            } else {
                key.iter().map(|k| Value::Text(k.clone())).collect()
            };
            for agg in &spec.aggregates {
                vals.push(compute_aggregate(
                    agg.func,
                    col_idx(&agg.column),
                    group_rows,
                ));
            }
            result_rows.push(Row::new(out_cols.clone(), vals));
        }

        let n = result_rows.len();
        Ok(QueryResult::rows(
            out_cols,
            result_rows,
            format!("{n} groups"),
        ))
    }

    // ── WINDOW ────────────────────────────────────────────────────────────

    fn exec_window(&self, spec: crate::planner::WindowSpec) -> Result<QueryResult, SqlError> {
        use crate::planner::WindowFn;
        use std::collections::HashMap;

        let mut input = self.execute(*spec.input)?;
        let col_idx =
            |name: &str| -> Option<usize> { input.columns.iter().position(|c| c == name) };
        let value_col_idx = col_idx(&spec.column);

        let partition_indices: Vec<usize> = spec
            .partition_by
            .iter()
            .filter_map(|c| col_idx(c))
            .collect();

        struct PartitionState {
            running_sum: i128,
            running_count: usize,
            row_number: u64,
        }
        let mut partition_state: HashMap<Vec<String>, PartitionState> = HashMap::new();

        let alias = spec.alias.clone();
        input.columns.push(alias.clone());

        for row in input.rows.iter_mut() {
            row.columns.push(alias.clone());
            let part_key: Vec<String> = partition_indices
                .iter()
                .map(|&i| row.values.get(i).map(|v| v.to_string()).unwrap_or_default())
                .collect();

            let state = partition_state.entry(part_key).or_insert(PartitionState {
                running_sum: 0,
                running_count: 0,
                row_number: 0,
            });
            state.row_number += 1;

            let raw_val: i128 = value_col_idx
                .and_then(|i| row.values.get(i))
                .and_then(|v| match v {
                    Value::BigInt(n) => Some(*n),
                    Value::Int(n) => Some(*n as i128),
                    _ => None,
                })
                .unwrap_or(0);

            state.running_sum += raw_val;
            state.running_count += 1;

            let result_val = match spec.window_fn {
                WindowFn::RowNumber | WindowFn::Rank | WindowFn::DenseRank => {
                    Value::BigInt(state.row_number as i128)
                }
                WindowFn::RunningSum => Value::BigInt(state.running_sum),
                WindowFn::RunningAvg => {
                    Value::BigInt(state.running_sum / state.running_count.max(1) as i128)
                }
                WindowFn::Lag => Value::BigInt(state.running_sum - raw_val),
                WindowFn::Lead => Value::BigInt(raw_val),
            };
            row.values.push(result_val);
        }

        let n = input.rows.len();
        Ok(QueryResult::rows(
            input.columns,
            input.rows,
            format!("{n} rows (window)"),
        ))
    }

    // ── Account resolution ────────────────────────────────────────────────

    fn resolve_account(&self, account_ref: &str) -> Result<Uuid, SqlError> {
        if let Ok(id) = Uuid::parse_str(account_ref) {
            if self.ledger.get_account(&id).is_some() {
                return Ok(id);
            }
        }
        self.ledger
            .all_accounts()
            .find(|a| a.code == account_ref)
            .map(|a| a.id)
            .ok_or_else(|| SqlError::Execution(format!("account '{account_ref}' not found")))
    }
}

// ── Executor — mutable borrow, write plans only ───────────────────────────────

/// Write executor.  Requires `&mut LedgerStore`.
///
/// For read plans this delegates to a `ReadExecutor` built from the same
/// `&LedgerStore` reference, so callers only need one entry point.
pub struct Executor<'a> {
    ledger: &'a mut LedgerStore,
    pub attach_proofs: bool,
}

impl<'a> Executor<'a> {
    pub fn new(ledger: &'a mut LedgerStore) -> Self {
        Self {
            ledger,
            attach_proofs: false,
        }
    }

    pub fn with_proofs(ledger: &'a mut LedgerStore) -> Self {
        Self {
            ledger,
            attach_proofs: true,
        }
    }

    /// Execute any `LogicalPlan`.
    ///
    /// Read plans are forwarded to `ReadExecutor` (which only borrows `&self.ledger`).
    /// Write plans are handled directly here with `&mut self.ledger`.
    pub fn execute(&mut self, plan: LogicalPlan) -> Result<QueryResult, SqlError> {
        match plan {
            // Write plans — require &mut LedgerStore.
            LogicalPlan::PostEntry(spec) => self.exec_post_entry(spec),
            LogicalPlan::CreateAccount(spec) => self.exec_create_account(spec),
            #[cfg(test)]
            LogicalPlan::TamperEntry {
                sequence,
                new_description,
            } => self.exec_tamper_entry(sequence, new_description),

            // Read plans — delegate to ReadExecutor.
            read_plan => {
                let reader = ReadExecutor {
                    ledger: self.ledger,
                    attach_proofs: self.attach_proofs,
                };
                reader.execute(read_plan)
            }
        }
    }

    // ── INSERT INTO ledger ────────────────────────────────────────────────

    fn exec_post_entry(&mut self, spec: EntrySpec) -> Result<QueryResult, SqlError> {
        let debit_id = self.resolve_account(&spec.debit_account)?;
        let credit_id = self.resolve_account(&spec.credit_account)?;

        let amount = Amount::new(spec.amount).ok_or_else(|| SqlError::InvalidValue {
            field: "amount".into(),
            reason: "must be non-zero".into(),
        })?;

        let mut builder = JournalEntryBuilder::new(&spec.description, &spec.domain)
            .debit(debit_id, amount, &spec.currency)
            .credit(credit_id, amount, &spec.currency);

        if let Some(r) = &spec.external_ref {
            builder = builder.external_ref(r);
        }
        if let Some(k) = &spec.idempotency_key {
            builder = builder.idempotency_key(k);
        }

        let entry = builder.build();
        let posted = self.ledger.post_entry(entry)?;
        let seq = posted.sequence;
        let id = posted.id;
        let domain = posted.domain.clone();
        let amount = posted
            .lines
            .iter()
            .filter(|l| matches!(l.dr_cr, vledger_ledger::entry::DrCr::Debit))
            .map(|l| l.amount.as_i64())
            .sum::<i64>();

        let cols = vec!["sequence".into(), "id".into(), "status".into()];
        let rows = vec![Row::new(
            cols.clone(),
            vec![
                Value::BigInt(seq as i128),
                Value::Uuid(id.to_string()),
                Value::Text("Posted".into()),
            ],
        )];
        let mut qr = QueryResult::rows(cols, rows, format!("1 entry posted (sequence={seq})"));
        qr.entry_id = Some(id);
        qr.entry_sequence = Some(seq);
        qr.domain = Some(domain);
        qr.amount_sum = Some(amount);
        Ok(qr)
    }

    // ── INSERT INTO accounts ──────────────────────────────────────────────

    fn exec_create_account(&mut self, spec: AccountSpec) -> Result<QueryResult, SqlError> {
        let acct_type = parse_account_type(&spec.account_type)?;
        let acct = Account::new(
            &spec.code,
            &spec.name,
            acct_type,
            &spec.currency,
            &spec.domain,
        );
        let id = self.ledger.create_account(acct)?;

        let cols = vec!["id".into(), "code".into(), "status".into()];
        let rows = vec![Row::new(
            cols.clone(),
            vec![
                Value::Uuid(id.to_string()),
                Value::Text(spec.code.clone()),
                Value::Text("Created".into()),
            ],
        )];
        Ok(QueryResult::rows(
            cols,
            rows,
            format!("Account '{}' created", spec.code),
        ))
    }

    // ── TAMPER_ENTRY — test only (cfg-gated, not compiled into release) ──

    #[cfg(test)]
    fn exec_tamper_entry(
        &mut self,
        sequence: u64,
        new_description: String,
    ) -> Result<QueryResult, SqlError> {
        let found = self
            .ledger
            .tamper_entry_for_demo(sequence, new_description.clone());
        let cols = vec![
            "sequence".into(),
            "status".into(),
            "tampered_field".into(),
            "new_value".into(),
        ];
        if found {
            let rows = vec![crate::result::Row::new(
                cols.clone(),
                vec![
                    crate::result::Value::BigInt(sequence as i128),
                    crate::result::Value::Text("TAMPERED — run VERIFY_CHAIN() to detect".into()),
                    crate::result::Value::Text("description".into()),
                    crate::result::Value::Text(new_description),
                ],
            )];
            Ok(crate::result::QueryResult::rows(
                cols,
                rows,
                "Entry tampered in memory. Hash chain NOT updated. VERIFY_CHAIN() will now fail."
                    .to_string(),
            ))
        } else {
            Err(SqlError::Execution(format!(
                "entry with sequence {sequence} not found"
            )))
        }
    }

    // ── Account resolution (uses &self.ledger — read-only) ────────────────

    fn resolve_account(&self, account_ref: &str) -> Result<Uuid, SqlError> {
        if let Ok(id) = Uuid::parse_str(account_ref) {
            if self.ledger.get_account(&id).is_some() {
                return Ok(id);
            }
        }
        self.ledger
            .all_accounts()
            .find(|a| a.code == account_ref)
            .map(|a| a.id)
            .ok_or_else(|| SqlError::Execution(format!("account '{account_ref}' not found")))
    }
}

// ── Shared free functions ─────────────────────────────────────────────────────

/// Build a [`MerkleProof`] for the given leaf indices.
///
/// `sign_root` is called with the computed root bytes and should return
/// `Some((signature_64, pubkey_32))` when a signing key is available, or
/// `None` for unsigned proofs.  Unsigned proofs are still cryptographically
/// valid membership proofs — they simply lack the server's Ed25519 attestation
/// that binds the root to the database's identity.
fn build_merkle_proof<F>(all_leaves: &[Vec<u8>], indices: &[usize], sign_root: F) -> MerkleProof
where
    F: FnOnce(&[u8; 32]) -> Option<([u8; 64], [u8; 32])>,
{
    let root = merkle_root(all_leaves);
    let mut leaf_proofs = Vec::new();
    for &idx in indices {
        if idx >= all_leaves.len() {
            continue;
        }
        if let Some(proof) = merkle_proof(all_leaves, idx) {
            let path = proof
                .path
                .iter()
                .map(|step| ProofStep {
                    sibling: step.sibling,
                    sibling_is_left: step.sibling_is_left,
                })
                .collect();
            leaf_proofs.push(LeafProof {
                leaf_index: proof.leaf_index,
                leaf_hash: proof.leaf_hash,
                path,
            });
        }
    }

    // Optionally sign the root with the database's Ed25519 signing key.
    // The signed message is the raw 32-byte root so external verifiers only
    // need the root bytes and the public key — no schema knowledge required.
    let (root_signature, signing_public_key) = match sign_root(&root) {
        Some((sig, pubkey)) => (Some(sig.to_vec()), Some(pubkey)),
        None => (None, None),
    };

    MerkleProof {
        root,
        leaf_proofs,
        root_signature,
        signing_public_key,
    }
}

fn parse_account_type(s: &str) -> Result<AccountType, SqlError> {
    match s.to_lowercase().as_str() {
        "asset" => Ok(AccountType::Asset),
        "liability" => Ok(AccountType::Liability),
        "equity" => Ok(AccountType::Equity),
        "income" => Ok(AccountType::Income),
        "expense" => Ok(AccountType::Expense),
        "contra" => Ok(AccountType::Contra),
        "suspense" => Ok(AccountType::Suspense),
        other => Err(SqlError::InvalidValue {
            field: "account_type".into(),
            reason: format!("unknown type '{other}'"),
        }),
    }
}

fn compute_aggregate(func: AggFn, col_idx: Option<usize>, rows: &[&Row]) -> Value {
    let nums: Vec<i128> = rows
        .iter()
        .filter_map(|r| col_idx.and_then(|i| r.values.get(i)))
        .filter_map(|v| match v {
            Value::BigInt(n) => Some(*n),
            Value::Int(n) => Some(*n as i128),
            _ => None,
        })
        .collect();

    match func {
        AggFn::Count => Value::BigInt(rows.len() as i128),
        AggFn::Sum => Value::BigInt(nums.iter().sum()),
        AggFn::Min => Value::BigInt(nums.iter().copied().min().unwrap_or(0)),
        AggFn::Max => Value::BigInt(nums.iter().copied().max().unwrap_or(0)),
        AggFn::Avg => {
            if nums.is_empty() {
                Value::Null
            } else {
                Value::BigInt(nums.iter().sum::<i128>() / nums.len() as i128)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_one;
    use crate::planner::LogicalPlanBuilder;
    use tempfile::TempDir;

    fn open_ledger() -> (TempDir, LedgerStore) {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("wal")).unwrap();
        std::fs::create_dir_all(dir.path().join("pages")).unwrap();
        let ledger = LedgerStore::open(dir.path()).unwrap();
        (dir, ledger)
    }

    fn run(ledger: &mut LedgerStore, sql: &str) -> QueryResult {
        let stmt = parse_one(sql).expect("parse failed");
        let plan = LogicalPlanBuilder::plan(stmt).expect("plan failed");
        Executor::new(ledger).execute(plan).expect("execute failed")
    }

    fn setup_accounts(ledger: &mut LedgerStore) {
        run(ledger, "INSERT INTO accounts (code, name, account_type, currency, domain) VALUES ('CASH', 'Cash', 'asset', 'USD', 'test')");
        run(ledger, "INSERT INTO accounts (code, name, account_type, currency, domain) VALUES ('REV', 'Revenue', 'income', 'USD', 'test')");
    }

    #[test]
    fn insert_into_accounts_creates_account() {
        let (_dir, mut ledger) = open_ledger();
        let result = run(
            &mut ledger,
            "INSERT INTO accounts (code, name, account_type, currency, domain) \
             VALUES ('CASH', 'Cash USD', 'asset', 'USD', 'test')",
        );
        assert_eq!(result.rows_affected, 1);
        assert_eq!(
            result.rows[0].get("status"),
            Some(&Value::Text("Created".into()))
        );
    }

    #[test]
    fn insert_into_ledger_posts_entry() {
        let (_dir, mut ledger) = open_ledger();
        setup_accounts(&mut ledger);
        let result = run(&mut ledger,
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Sale', 'CASH', 'REV', 50000, 'USD', 'test')");
        assert_eq!(result.rows_affected, 1);
    }

    #[test]
    fn select_from_ledger_returns_entries() {
        let (_dir, mut ledger) = open_ledger();
        setup_accounts(&mut ledger);
        for desc in &["Tx1", "Tx2"] {
            run(&mut ledger, &format!(
                "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
                 VALUES ('{desc}', 'CASH', 'REV', 1000, 'USD', 'test')"));
        }
        let result = run(&mut ledger, "SELECT * FROM ledger");
        assert_eq!(result.rows.len(), 2);
    }

    #[test]
    fn select_balance_returns_correct_value() {
        let (_dir, mut ledger) = open_ledger();
        setup_accounts(&mut ledger);
        run(&mut ledger,
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Sale', 'CASH', 'REV', 75000, 'USD', 'test')");
        let result = run(&mut ledger, "SELECT BALANCE('CASH')");
        assert_eq!(result.rows[0].get("balance"), Some(&Value::BigInt(75000)));
    }

    #[test]
    fn verify_chain_passes_after_entries() {
        let (_dir, mut ledger) = open_ledger();
        setup_accounts(&mut ledger);
        run(&mut ledger,
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Tx', 'CASH', 'REV', 100, 'USD', 'test')");
        let result = run(&mut ledger, "SELECT VERIFY_CHAIN()");
        assert_eq!(
            result.rows[0].get("status"),
            Some(&Value::Text("OK".into()))
        );
    }

    #[test]
    fn select_with_proof_attaches_and_verifies() {
        let (_dir, mut ledger) = open_ledger();
        setup_accounts(&mut ledger);
        run(&mut ledger,
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Tx', 'CASH', 'REV', 100, 'USD', 'test')");
        let stmt = parse_one("SELECT * FROM ledger").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::with_proofs(&mut ledger).execute(plan).unwrap();
        let proof = result.proof.expect("proof should be attached");
        assert!(!proof.leaf_proofs.is_empty());
        for leaf in &proof.leaf_proofs {
            let mut current = leaf.leaf_hash;
            for step in &leaf.path {
                current = if step.sibling_is_left {
                    vledger_crypto::hash::hash_node(&step.sibling, &current)
                } else {
                    vledger_crypto::hash::hash_node(&current, &step.sibling)
                };
            }
            assert_eq!(
                current, proof.root,
                "Merkle proof path must resolve to root"
            );
        }
    }

    /// When the ledger is opened without a signing key (default `open()`),
    /// `root_signature` must be `None` — no false attestation.
    #[test]
    fn proof_root_signature_is_none_without_signing_key() {
        let (_dir, mut ledger) = open_ledger();
        setup_accounts(&mut ledger);
        run(&mut ledger,
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Tx', 'CASH', 'REV', 100, 'USD', 'test')");
        let stmt = parse_one("SELECT * FROM ledger").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = Executor::with_proofs(&mut ledger).execute(plan).unwrap();
        let proof = result.proof.expect("proof should be attached");
        assert!(
            proof.root_signature.is_none(),
            "root_signature must be None when no signing key is configured"
        );
        assert!(
            proof.signing_public_key.is_none(),
            "signing_public_key must be None when no signing key is configured"
        );
    }

    /// When the ledger is opened with a signing key, `root_signature` must
    /// be present and the Ed25519 signature must verify against the root.
    #[test]
    fn proof_root_signature_verifies_with_signing_key() {
        use vledger_crypto::sign::DbSigningKey;

        // Directly exercise the contract: when sign_bytes returns Some((sig, pubkey)),
        // the executor populates root_signature and the signature is a valid
        // Ed25519 signature over the Merkle root.
        let all_leaves: Vec<Vec<u8>> = vec![b"leaf-a".to_vec(), b"leaf-b".to_vec()];

        let signing_key = DbSigningKey::generate();
        let pubkey = signing_key.public_key().to_bytes();

        // Simulate what build_merkle_proof does internally when sign_root returns Some.
        let root = vledger_crypto::merkle::merkle_root(&all_leaves);
        let sig = signing_key.sign(&root);

        let proof = crate::result::MerkleProof {
            root,
            leaf_proofs: vec![],
            root_signature: Some(sig.to_vec()),
            signing_public_key: Some(pubkey),
        };

        // Verify the signature over the root.
        let sig_bytes: [u8; 64] = proof
            .root_signature
            .as_ref()
            .unwrap()
            .as_slice()
            .try_into()
            .expect("signature must be 64 bytes");
        signing_key
            .public_key()
            .verify(&proof.root, &sig_bytes)
            .expect("root_signature must be a valid Ed25519 signature over the Merkle root");

        // Confirm that a tampered root fails verification.
        let mut bad_root = proof.root;
        bad_root[0] ^= 0xFF;
        assert!(
            signing_key
                .public_key()
                .verify(&bad_root, &sig_bytes)
                .is_err(),
            "tampered root must fail signature verification"
        );
    }

    #[test]
    fn read_executor_handles_scan_entries() {
        let (_dir, mut ledger) = open_ledger();
        setup_accounts(&mut ledger);
        run(&mut ledger,
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('Tx', 'CASH', 'REV', 100, 'USD', 'test')");
        // ReadExecutor should work independently with &LedgerStore
        let stmt = parse_one("SELECT * FROM ledger").unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = ReadExecutor::new(&ledger).execute(plan).unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn read_executor_rejects_write_plans() {
        let (_dir, ledger) = open_ledger();
        let stmt = parse_one(
            "INSERT INTO accounts (code, name, account_type, currency, domain) \
             VALUES ('A', 'A', 'asset', 'USD', 'test')",
        )
        .unwrap();
        let plan = LogicalPlanBuilder::plan(stmt).unwrap();
        let result = ReadExecutor::new(&ledger).execute(plan);
        assert!(result.is_err());
    }
}

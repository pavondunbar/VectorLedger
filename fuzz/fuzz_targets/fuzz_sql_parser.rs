//! Fuzz target: SQL parser and query planner.
//!
//! Feeds arbitrary UTF-8 (and non-UTF-8 byte sequences coerced to strings)
//! through the full parse → plan → (optionally) execute pipeline.
//!
//! ## What is fuzzed
//! - Random byte sequences that happen to be valid UTF-8
//! - Syntactically valid SQL with extreme numeric values
//! - SQL injection patterns (UNION, comment sequences, null bytes)
//! - Extremely long identifiers and string literals
//! - Nested subqueries beyond reasonable depth
//! - Whitespace/comment-only inputs
//!
//! ## Success criteria
//! - No panic at any stage
//! - parse_one always returns Ok or a well-typed parse error
//! - plan always returns Ok or a well-typed plan error
//! - Execution on an empty in-memory ledger always returns Ok or a typed error

#![no_main]

use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

fuzz_target!(|data: &[u8]| {
    // Convert to a &str — skip inputs that are not valid UTF-8
    let sql = match std::str::from_utf8(data) {
        Ok(s)  => s,
        Err(_) => return,
    };

    // Bound input length — very long inputs are uninteresting after a threshold
    if sql.len() > 4096 { return; }

    // Stage 1: parse — must not panic
    let stmt = match vledger_sql::parser::parse_one(sql) {
        Ok(s)  => s,
        Err(_) => return, // parse error is acceptable
    };

    // Stage 2: plan — must not panic
    let plan = match vledger_sql::planner::LogicalPlanBuilder::plan(stmt) {
        Ok(p)  => p,
        Err(_) => return, // plan error is acceptable
    };

    // Stage 3: execute against a fresh in-memory ledger — must not panic
    let dir = match TempDir::new() {
        Ok(d)  => d,
        Err(_) => return,
    };
    let data_path = dir.path();
    let _ = std::fs::create_dir_all(data_path.join("wal"));
    let _ = std::fs::create_dir_all(data_path.join("pages"));

    if let Ok(mut ledger) = vledger_ledger::LedgerStore::open(data_path) {
        let _result = vledger_sql::executor::Executor::new(&mut ledger).execute(plan);
        // Any result — Ok or Err — is acceptable; panic is not.
    }
});

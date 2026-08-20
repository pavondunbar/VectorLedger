//! SQL parser — wraps `sqlparser` and normalises statements for the planner.
//!
//! ## Denial-of-Service hardening
//!
//! `sqlparser-rs` uses a recursive-descent parser.  Every opening parenthesis
//! in the SQL text causes at least one additional stack frame.  On the default
//! system stack (~8 MiB on Linux/macOS) this overflows at roughly 45–55 levels
//! of nesting, aborting the entire process with SIGABRT — a critical DoS.
//!
//! Two guards are applied **before** the SQL text reaches the parser:
//!
//! 1. **Length limit** (`MAX_SQL_BYTES`): rejects any query whose byte length
//!    exceeds 64 KiB.  This bounds the worst-case input space and eliminates
//!    the possibility of constructing a deeply-nested payload that also stays
//!    short.  64 KiB is orders of magnitude more than any legitimate
//!    VectorLedger query requires.
//!
//! 2. **Nesting-depth counter** (`MAX_NESTING_DEPTH`): scans the raw SQL
//!    bytes in a single O(n) pass, tracking the current parenthesis depth.
//!    If the depth ever exceeds the limit the query is rejected before the
//!    parser is called.  String literals and line/block comments are skipped
//!    so that `'('` or `/* ( */` inside them do not count toward the depth.
//!
//! Both checks return a typed `SqlError` variant so callers (including the
//! server's `execute_sql` function) can log and surface them cleanly without
//! any risk of a process abort.

use sqlparser::ast::Statement;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser as SqlParser;

use crate::error::SqlError;

// ── Guard constants ───────────────────────────────────────────────────────────

/// Maximum SQL query size in bytes.  Queries longer than this are rejected
/// before the parser is invoked.
///
/// 64 KiB is already extremely generous for VectorLedger's supported statement
/// set (INSERT, SELECT, BALANCE, VERIFY_CHAIN).  Raise only if you add support
/// for very large batch inputs and have independently validated the parser's
/// stack usage at the new limit.
pub const MAX_SQL_BYTES: usize = 64 * 1024; // 64 KiB

/// Maximum parenthesis nesting depth accepted in a SQL query.
///
/// `sqlparser-rs` uses recursive descent and recurses at least once per `(`.
/// On a typical 8 MiB system stack, overflow occurs at ~50 levels.  We cap at
/// 20 to leave a large safety margin while still allowing any realistic query.
/// The deepest legitimate query seen in VectorLedger's test suite is 2 levels.
pub const MAX_NESTING_DEPTH: usize = 20;

// ── Pre-parse guards ──────────────────────────────────────────────────────────

/// Scan `sql` in a single O(n) pass and return `Err` if:
/// - The byte length exceeds `MAX_SQL_BYTES`, OR
/// - The parenthesis nesting depth exceeds `MAX_NESTING_DEPTH`.
///
/// The scanner skips characters inside:
/// - Single-quoted string literals  `'…'`  (with `''` escape handling)
/// - Double-quoted identifiers       `"…"`  (with `""` escape handling)
/// - Line comments                   `--…\n`
/// - Block comments                  `/*…*/`  (non-nested, per SQL standard)
///
/// This ensures that `'('` or `/* SELECT ( */` inside literals/comments does
/// not contribute to the depth counter.
fn check_query_limits(sql: &str) -> Result<(), SqlError> {
    let bytes = sql.as_bytes();
    let len = bytes.len();

    if len > MAX_SQL_BYTES {
        return Err(SqlError::QueryTooLong {
            len,
            limit: MAX_SQL_BYTES,
        });
    }

    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut i = 0usize;

    while i < len {
        match bytes[i] {
            // ── Single-quoted string literal ──────────────────────────────
            b'\'' => {
                i += 1;
                while i < len {
                    if bytes[i] == b'\'' {
                        // Peek ahead: '' is an escaped quote, not end of string.
                        if i + 1 < len && bytes[i + 1] == b'\'' {
                            i += 2; // skip escaped quote
                        } else {
                            i += 1; // consume closing quote
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }

            // ── Double-quoted identifier ──────────────────────────────────
            b'"' => {
                i += 1;
                while i < len {
                    if bytes[i] == b'"' {
                        if i + 1 < len && bytes[i + 1] == b'"' {
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }

            // ── Line comment  -- … \n ─────────────────────────────────────
            b'-' if i + 1 < len && bytes[i + 1] == b'-' => {
                i += 2;
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                // consume the newline itself if present
                if i < len {
                    i += 1;
                }
            }

            // ── Block comment  /* … */ ────────────────────────────────────
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < len {
                    if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                // If the block comment is unterminated we just reached EOF;
                // the parser will report a proper parse error.
            }

            // ── Opening parenthesis ───────────────────────────────────────
            b'(' => {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
                if max_depth > MAX_NESTING_DEPTH {
                    return Err(SqlError::NestingTooDeep {
                        depth: max_depth,
                        limit: MAX_NESTING_DEPTH,
                    });
                }
                i += 1;
            }

            // ── Closing parenthesis ───────────────────────────────────────
            b')' => {
                // Underflow (unbalanced parens) is fine to pass through —
                // the parser will reject it with a proper syntax error.
                depth = depth.saturating_sub(1);
                i += 1;
            }

            _ => {
                i += 1;
            }
        }
    }

    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse one or more SQL statements from `sql`.
///
/// Returns a `Vec<Statement>` so that multi-statement batches work (e.g.
/// `BEGIN; INSERT …; COMMIT;`).
///
/// **Pre-parse guards** are applied before `sqlparser` is called — see the
/// module-level documentation for details.
pub fn parse(sql: &str) -> Result<Vec<Statement>, SqlError> {
    check_query_limits(sql)?;
    SqlParser::parse_sql(&GenericDialect {}, sql).map_err(|e| SqlError::Parse(e.to_string()))
}

/// Parse exactly one SQL statement.  Returns an error if there are zero or
/// more than one statements.
///
/// **Pre-parse guards** are applied before `sqlparser` is called — see the
/// module-level documentation for details.
pub fn parse_one(sql: &str) -> Result<Statement, SqlError> {
    // Strip a single trailing semicolon (and surrounding whitespace) so
    // users can type SQL in the conventional `SELECT …;` style without
    // triggering the "got 2 statements" error that the underlying parser
    // produces when it sees an empty statement after the semicolon.
    let sql = sql.trim().trim_end_matches(';').trim();
    check_query_limits(sql)?;
    let mut stmts = SqlParser::parse_sql(&GenericDialect {}, sql)
        .map_err(|e| SqlError::Parse(e.to_string()))?;
    match stmts.len() {
        0 => Err(SqlError::Parse("empty SQL input".into())),
        1 => Ok(stmts.remove(0)),
        n => Err(SqlError::Parse(format!(
            "expected exactly 1 statement, got {n}; use execute_batch for multi-statement input"
        ))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing behavioural tests ────────────────────────────────────────

    #[test]
    fn parse_select() {
        let stmt = parse_one("SELECT * FROM ledger").unwrap();
        assert!(matches!(stmt, Statement::Query(_)));
    }

    #[test]
    fn parse_insert() {
        parse_one(
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency) \
             VALUES ('Sale', 'cash', 'revenue', 10000, 'USD')",
        )
        .unwrap();
    }

    #[test]
    fn parse_create_table() {
        parse_one(
            "CREATE TABLE accounts \
             (code VARCHAR, name VARCHAR, account_type VARCHAR, currency VARCHAR, domain VARCHAR)",
        )
        .unwrap();
    }

    #[test]
    fn empty_sql_errors() {
        assert!(parse_one("").is_err());
    }

    // ── Guard: length limit ───────────────────────────────────────────────

    #[test]
    fn query_exactly_at_limit_is_accepted() {
        // A query that is exactly MAX_SQL_BYTES bytes long (all spaces + a
        // valid keyword so the parser has something to parse) must pass the
        // length guard.  We use a comment so the extra bytes don't confuse
        // the parser.
        let padding = " ".repeat(MAX_SQL_BYTES - "SELECT * FROM ledger".len());
        let sql = format!("SELECT * FROM ledger{padding}");
        assert_eq!(sql.len(), MAX_SQL_BYTES);
        // Length guard passes; parser may succeed or return a parse error —
        // either way it must NOT return QueryTooLong.
        match parse_one(&sql) {
            Err(SqlError::QueryTooLong { .. }) => {
                panic!("query exactly at limit must not be rejected by length guard");
            }
            _ => {} // ok — parser error or success are both fine here
        }
    }

    #[test]
    fn query_one_byte_over_limit_is_rejected() {
        let sql = "x".repeat(MAX_SQL_BYTES + 1);
        match parse_one(&sql) {
            Err(SqlError::QueryTooLong { len, limit }) => {
                assert_eq!(len, MAX_SQL_BYTES + 1);
                assert_eq!(limit, MAX_SQL_BYTES);
            }
            other => panic!("expected QueryTooLong, got {other:?}"),
        }
    }

    #[test]
    fn query_far_over_limit_is_rejected() {
        let sql = "x".repeat(MAX_SQL_BYTES * 10);
        assert!(matches!(
            parse_one(&sql),
            Err(SqlError::QueryTooLong { .. })
        ));
    }

    // ── Guard: nesting depth ──────────────────────────────────────────────

    #[test]
    fn nesting_at_limit_is_accepted() {
        // MAX_NESTING_DEPTH open parens, immediately closed — valid but deep.
        let parens = format!(
            "{}{}",
            "(".repeat(MAX_NESTING_DEPTH),
            ")".repeat(MAX_NESTING_DEPTH)
        );
        // check_query_limits must pass (parser may error — that's fine).
        let result = check_query_limits(&parens);
        assert!(
            result.is_ok(),
            "nesting exactly at limit must pass the guard: {result:?}"
        );
    }

    #[test]
    fn nesting_one_over_limit_is_rejected() {
        let depth = MAX_NESTING_DEPTH + 1;
        let sql = format!("{}{}", "(".repeat(depth), ")".repeat(depth));
        match check_query_limits(&sql) {
            Err(SqlError::NestingTooDeep { depth: d, limit }) => {
                assert_eq!(d, depth);
                assert_eq!(limit, MAX_NESTING_DEPTH);
            }
            other => panic!("expected NestingTooDeep, got {other:?}"),
        }
    }

    #[test]
    fn nesting_50_levels_is_rejected_not_stack_overflow() {
        // This is the former DoS vector. It must now return NestingTooDeep
        // cleanly instead of aborting the process.
        let mut sql = "SELECT * FROM ledger".to_string();
        for _ in 0..50 {
            sql = format!("SELECT * FROM ({sql}) AS sub");
        }
        match parse_one(&sql) {
            Err(SqlError::NestingTooDeep { .. }) => {} // correct
            Err(SqlError::QueryTooLong { .. }) => {}   // also fine — depth guard or length guard
            Err(e) => panic!("unexpected error variant: {e}"),
            Ok(_) => panic!("50-level nesting must be rejected"),
        }
    }

    #[test]
    fn parens_inside_string_literals_not_counted() {
        // Parentheses inside single-quoted string literals must not count.
        // Build a query where every ( appears inside a string value.
        // Each VALUES clause contributes one string containing '(', but
        // the real nesting depth of the query is 1 (the VALUES parens).
        let n = MAX_NESTING_DEPTH + 5;
        // One real paren pair for VALUES(...), then n string literals each
        // containing a ( — none of which should count toward depth.
        let values: String = (0..n)
            .map(|_| "'('".to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("SELECT {values} FROM ledger WHERE domain = '((((('");
        // Real structural depth is 0 (no parens outside strings). Must pass.
        let result = check_query_limits(&sql);
        assert!(
            !matches!(result, Err(SqlError::NestingTooDeep { .. })),
            "parens inside string literals must not count toward depth: {result:?}"
        );
    }

    #[test]
    fn parens_inside_line_comments_not_counted() {
        let mut sql = String::from("SELECT * FROM ledger");
        for _ in 0..=MAX_NESTING_DEPTH {
            sql.push_str(" -- this is a comment with ( parens )\n");
        }
        let result = check_query_limits(&sql);
        assert!(
            !matches!(result, Err(SqlError::NestingTooDeep { .. })),
            "parens in line comments must not count: {result:?}"
        );
    }

    #[test]
    fn parens_inside_block_comments_not_counted() {
        let comment_parens = "/* ".to_string() + &"( ".repeat(MAX_NESTING_DEPTH + 5) + "*/";
        let sql = format!("SELECT * FROM ledger {comment_parens}");
        let result = check_query_limits(&sql);
        assert!(
            !matches!(result, Err(SqlError::NestingTooDeep { .. })),
            "parens in block comments must not count: {result:?}"
        );
    }

    #[test]
    fn unbalanced_close_parens_do_not_panic() {
        // Saturating subtraction means extra `)` never panic.
        let sql = ")))))))))))))))))))))";
        let result = check_query_limits(sql);
        assert!(
            result.is_ok(),
            "unbalanced close parens must not panic: {result:?}"
        );
    }

    #[test]
    fn legitimate_queries_pass_guards() {
        let queries = [
            "SELECT * FROM ledger",
            "SELECT * FROM accounts",
            "SELECT BALANCE('CASH')",
            "SELECT VERIFY_CHAIN()",
            "INSERT INTO ledger (description, debit_account, credit_account, amount, currency, domain) \
             VALUES ('sale', 'CASH', 'REV', 1000, 'USD', 'main')",
            "SELECT * FROM ledger WHERE domain = 'main'",
            "SELECT * FROM ledger LIMIT 10",
            "SELECT SUM(amount) FROM ledger GROUP BY domain",
        ];
        for q in &queries {
            assert!(
                check_query_limits(q).is_ok(),
                "legitimate query must pass guards: {q}"
            );
        }
    }
}

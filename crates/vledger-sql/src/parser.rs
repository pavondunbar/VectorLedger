//! SQL parser — wraps `sqlparser` and normalises statements for the planner.
//!
//! We use the `GenericDialect` so that both standard SQL and our
//! VectorGuard-specific extensions parse without error.

use sqlparser::ast::Statement;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser as SqlParser;

use crate::error::SqlError;

/// Parse one or more SQL statements from `sql`.
///
/// Returns a `Vec<Statement>` so that multi-statement batches work (e.g.
/// `BEGIN; INSERT …; COMMIT;`).
pub fn parse(sql: &str) -> Result<Vec<Statement>, SqlError> {
    SqlParser::parse_sql(&GenericDialect {}, sql)
        .map_err(|e| SqlError::Parse(e.to_string()))
}

/// Parse exactly one SQL statement. Returns an error if there are zero or
/// more than one statements.
pub fn parse_one(sql: &str) -> Result<Statement, SqlError> {
    // Strip a single trailing semicolon (and surrounding whitespace) so
    // users can type SQL in the conventional `SELECT …;` style without
    // triggering the "got 2 statements" error that the underlying parser
    // produces when it sees an empty statement after the semicolon.
    let sql = sql.trim().trim_end_matches(';').trim();
    let mut stmts = parse(sql)?;
    match stmts.len() {
        0 => Err(SqlError::Parse("empty SQL input".into())),
        1 => Ok(stmts.remove(0)),
        n => Err(SqlError::Parse(format!(
            "expected exactly 1 statement, got {n}; use execute_batch for multi-statement input"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

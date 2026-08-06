//! # vledger-sql
//!
//! SQL interface for VectorLedger.
//!
//! ## Supported statements (Phase 2)
//!
//! | Statement                  | Behaviour                                      |
//! |----------------------------|------------------------------------------------|
//! | `CREATE ACCOUNT …`         | VectorGuard-specific DDL (non-standard SQL)    |
//! | `CREATE TABLE accounts`    | Alias: creates account in chart of accounts    |
//! | `INSERT INTO ledger …`     | Post a journal entry                           |
//! | `SELECT … FROM ledger`     | Query journal entries with optional WHERE      |
//! | `SELECT … FROM accounts`   | Query accounts                                 |
//! | `SELECT BALANCE(account)`  | Return current balance                         |
//! | `SELECT VERIFY_CHAIN()`    | Verify hash chain integrity                    |
//!
//! ## Pipeline
//!
//! ```text
//! SQL text
//!   │
//!   ▼  parser::parse()
//! sqlparser::Statement
//!   │
//!   ▼  planner::plan()
//! LogicalPlan
//!   │
//!   ▼  executor::execute()
//! QueryResult  (rows + optional MerkleProof)
//! ```

pub mod error;
pub mod executor;
pub mod optimizer;
pub mod parser;
pub mod planner;
pub mod result;

pub use error::SqlError;
pub use executor::Executor;
pub use optimizer::explain as explain_plan;
pub use planner::{AggFn, AggregateSpec, JoinSpec, JoinType, LogicalPlan, LogicalPlanBuilder,
                  WindowFn, WindowSpec};
pub use result::{QueryResult, Row, Value};

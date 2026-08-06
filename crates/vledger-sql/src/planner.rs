//! Logical planner — converts `sqlparser::ast::Statement` into a `LogicalPlan`
//! that the executor can act on without knowing SQL syntax.
//!
//! Phase 3 additions:
//! - `LogicalPlan::Join`       — ledger ⨝ accounts (hash join)
//! - `LogicalPlan::Aggregate`  — GROUP BY + SUM/COUNT/AVG/MIN/MAX
//! - `LogicalPlan::Window`     — OVER (PARTITION BY … ORDER BY …)

use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr,
    FunctionArguments, GroupByExpr, Query, SelectItem,
    SetExpr, Statement, TableFactor, Value as SqlValue, Values,
    WindowSpec as AstWindowSpec,
};

use crate::error::SqlError;

// ── Target table names ────────────────────────────────────────────────────────

const TABLE_LEDGER: &str = "ledger";
const TABLE_ACCOUNTS: &str = "accounts";

// ── Logical Plan ─────────────────────────────────────────────────────────────

/// The logical representation of a SQL statement after planning.
/// The executor pattern-matches on this to perform the operation.
#[derive(Debug, Clone)]
pub enum LogicalPlan {
    /// SELECT * FROM ledger [WHERE …]
    ScanEntries { filter: Option<EntryFilter> },

    /// SELECT * FROM accounts [WHERE …]
    ScanAccounts { filter: Option<EntryFilter> },

    /// SELECT BALANCE('<account_code_or_id>')
    GetBalance { account_ref: String },

    /// SELECT VERIFY_CHAIN()
    VerifyChain,

    /// INSERT INTO ledger (…) VALUES (…)
    PostEntry(EntrySpec),

    /// CREATE TABLE accounts (…) VALUES (…)  — also used as CREATE ACCOUNT
    CreateAccount(AccountSpec),

    // ── Phase 3 ───────────────────────────────────────────────────────────

    /// SELECT … FROM ledger JOIN accounts ON …
    Join(JoinSpec),

    /// SELECT aggregate_fn(col) FROM … GROUP BY …
    Aggregate(AggregateSpec),

    /// SELECT window_fn() OVER (PARTITION BY … ORDER BY …) FROM …
    Window(WindowSpec),
}

// ── Join ──────────────────────────────────────────────────────────────────────

/// How to combine left and right scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinType {
    Inner,
    LeftOuter,
}

/// Specification for a join plan.
#[derive(Debug, Clone)]
pub struct JoinSpec {
    pub left:         Box<LogicalPlan>,
    pub right:        Box<LogicalPlan>,
    pub join_type:    JoinType,
    /// `"ledger.account_id = accounts.id"` style condition (string form for now).
    pub on_condition: String,
    /// Columns to project from the joined output.
    pub projections:  Vec<String>,
}

// ── Aggregate ─────────────────────────────────────────────────────────────────

/// Aggregate function type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggFn {
    Sum,
    Count,
    Avg,
    Min,
    Max,
}

impl std::fmt::Display for AggFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AggFn::Sum   => write!(f, "SUM"),
            AggFn::Count => write!(f, "COUNT"),
            AggFn::Avg   => write!(f, "AVG"),
            AggFn::Min   => write!(f, "MIN"),
            AggFn::Max   => write!(f, "MAX"),
        }
    }
}

/// A single aggregation expression (`SUM(amount) AS total`).
#[derive(Debug, Clone)]
pub struct AggExpr {
    pub func:    AggFn,
    /// Column name to aggregate over (`*` for COUNT(*)).
    pub column:  String,
    /// Output alias.
    pub alias:   String,
}

/// Specification for an aggregate plan.
#[derive(Debug, Clone)]
pub struct AggregateSpec {
    pub input:      Box<LogicalPlan>,
    pub group_by:   Vec<String>,
    pub aggregates: Vec<AggExpr>,
}

// ── Window function ───────────────────────────────────────────────────────────

/// Window function type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowFn {
    RowNumber,
    Rank,
    DenseRank,
    RunningSum,
    RunningAvg,
    Lag,
    Lead,
}

impl std::fmt::Display for WindowFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            WindowFn::RowNumber   => "ROW_NUMBER",
            WindowFn::Rank        => "RANK",
            WindowFn::DenseRank   => "DENSE_RANK",
            WindowFn::RunningSum  => "SUM",
            WindowFn::RunningAvg  => "AVG",
            WindowFn::Lag         => "LAG",
            WindowFn::Lead        => "LEAD",
        };
        write!(f, "{s}")
    }
}

/// Specification for a window function plan.
#[derive(Debug, Clone)]
pub struct WindowSpec {
    pub input:        Box<LogicalPlan>,
    pub window_fn:    WindowFn,
    /// Column to apply the function over (e.g. `amount` for running SUM).
    pub column:       String,
    pub alias:        String,
    pub partition_by: Vec<String>,
    pub order_by:     Vec<String>,
}

/// Specification for creating a new account.
#[derive(Debug, Clone)]
pub struct AccountSpec {
    pub code: String,
    pub name: String,
    pub account_type: String,
    pub currency: String,
    pub domain: String,
}

/// Specification for posting a journal entry.
#[derive(Debug, Clone)]
pub struct EntrySpec {
    pub description: String,
    pub debit_account: String,
    pub credit_account: String,
    /// Amount in minor units (integer).
    pub amount: i64,
    pub currency: String,
    pub external_ref: Option<String>,
    pub idempotency_key: Option<String>,
    pub domain: String,
}

/// Filter predicates for entry scans (used for both ledger and accounts).
#[derive(Debug, Clone)]
pub enum EntryFilter {
    BySequence(u64),
    ByExternalRef(String),
    ByDomain(String),
    ByStatus(String),
    Limit(usize),
}

// ── Planner ───────────────────────────────────────────────────────────────────

pub struct LogicalPlanBuilder;

impl LogicalPlanBuilder {
    /// Convert a parsed `Statement` into a `LogicalPlan`, then optimise it.
    pub fn plan(stmt: Statement) -> Result<LogicalPlan, SqlError> {
        let raw = match stmt {
            Statement::Query(q)        => Self::plan_query(*q),
            Statement::Insert(ins)     => Self::plan_insert(ins),
            Statement::CreateTable(ct) => Self::plan_create_table(ct),
            other => Err(SqlError::Unsupported(format!("{other}"))),
        }?;
        Ok(crate::optimizer::optimize(raw))
    }

    // ── SELECT ────────────────────────────────────────────────────────────

    fn plan_query(q: Query) -> Result<LogicalPlan, SqlError> {
        let body = match *q.body {
            SetExpr::Select(s) => s,
            other => return Err(SqlError::Unsupported(format!("query body: {other}"))),
        };

        // ── Special function calls: BALANCE(…) and VERIFY_CHAIN() ─────────
        if body.from.is_empty() {
            if let Some(item) = body.projection.first() {
                if let SelectItem::UnnamedExpr(Expr::Function(f)) = item {
                    let fname = f.name.to_string().to_uppercase();
                    match fname.as_str() {
                        "BALANCE" => {
                            let arg = extract_function_string_arg(&f.args, "BALANCE")?;
                            return Ok(LogicalPlan::GetBalance { account_ref: arg });
                        }
                        "VERIFY_CHAIN" => return Ok(LogicalPlan::VerifyChain),
                        _ => {}
                    }
                }
            }
        }

        // ── Table scan(s) — detect JOIN ───────────────────────────────────
        if body.from.is_empty() {
            return Err(SqlError::Unsupported("SELECT with no FROM".into()));
        }

        // Detect JOIN: sqlparser puts joined tables in `from[0].joins`
        let primary_table = extract_table_name(&body.from[0].relation)?;
        let has_join = !body.from[0].joins.is_empty();

        // ── Detect window functions in projection ─────────────────────────
        for item in &body.projection {
            if let SelectItem::UnnamedExpr(Expr::Function(f))
             | SelectItem::ExprWithAlias { expr: Expr::Function(f), .. } = item {
                if let Some(ws) = extract_window_spec(f) {
                    let (wfn, col) = parse_window_fn(f)?;
                    let alias = match item {
                        SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                        _ => format!("{wfn}"),
                    };
                    let scan = base_scan(&primary_table, &body.selection, &q.limit)?;
                    return Ok(LogicalPlan::Window(WindowSpec {
                        input:        Box::new(scan),
                        window_fn:    wfn,
                        column:       col,
                        alias,
                        partition_by: ws.partition_by.iter()
                            .map(|e| expr_to_col_name(e))
                            .collect(),
                        order_by:     ws.order_by.iter()
                            .map(|o| expr_to_col_name(&o.expr))
                            .collect(),
                    }));
                }
            }
        }

        // ── Detect aggregate functions in projection ───────────────────────
        let agg_exprs = collect_aggregate_exprs(&body.projection);
        if !agg_exprs.is_empty() {
            let group_by = match &body.group_by {
                GroupByExpr::Expressions(exprs, _) => {
                    exprs.iter().map(|e| expr_to_col_name(e)).collect()
                }
                _ => vec![],
            };
            let scan = base_scan(&primary_table, &body.selection, &q.limit)?;
            return Ok(LogicalPlan::Aggregate(AggregateSpec {
                input: Box::new(scan),
                group_by,
                aggregates: agg_exprs,
            }));
        }

        // ── JOIN ──────────────────────────────────────────────────────────
        if has_join {
            let join_clause = &body.from[0].joins[0];
            let right_table = extract_table_name(&join_clause.relation)?;
            let on_cond = format!("{:?}", join_clause.join_operator);

            let left  = base_scan(&primary_table, &body.selection, &q.limit)?;
            let right = base_scan(&right_table,   &None,           &None)?;

            let join_type = match &join_clause.join_operator {
                sqlparser::ast::JoinOperator::LeftOuter(_) => JoinType::LeftOuter,
                _ => JoinType::Inner,
            };

            let projections: Vec<String> = body.projection.iter().map(|p| {
                match p {
                    SelectItem::Wildcard(_) => "*".into(),
                    SelectItem::UnnamedExpr(e) => expr_to_col_name(e),
                    SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                    _ => "*".into(),
                }
            }).collect();

            return Ok(LogicalPlan::Join(JoinSpec {
                left:         Box::new(left),
                right:        Box::new(right),
                join_type,
                on_condition: on_cond,
                projections,
            }));
        }

        // ── Simple scan ───────────────────────────────────────────────────
        let filter = if let Some(selection) = body.selection {
            Some(parse_where_to_entry_filter(&primary_table, selection)?)
        } else if let Some(limit_expr) = q.limit {
            if let Expr::Value(SqlValue::Number(n, _)) = limit_expr {
                let n: usize = n.parse().map_err(|_| SqlError::TypeError("LIMIT must be integer".into()))?;
                return match primary_table.as_str() {
                    TABLE_LEDGER   => Ok(LogicalPlan::ScanEntries { filter: Some(EntryFilter::Limit(n)) }),
                    TABLE_ACCOUNTS => Ok(LogicalPlan::ScanAccounts { filter: None }),
                    t => Err(SqlError::UnknownTable(t.into())),
                };
            }
            None
        } else {
            None
        };

        match primary_table.as_str() {
            TABLE_LEDGER   => Ok(LogicalPlan::ScanEntries { filter }),
            TABLE_ACCOUNTS => Ok(LogicalPlan::ScanAccounts { filter }),
            t => Err(SqlError::UnknownTable(t.into())),
        }
    }

    // ── INSERT INTO ledger ────────────────────────────────────────────────

    fn plan_insert(ins: sqlparser::ast::Insert) -> Result<LogicalPlan, SqlError> {
        let table = ins.table_name.to_string().to_lowercase();
        match table.as_str() {
            TABLE_LEDGER => {
                let cols: Vec<String> = ins.columns.iter().map(|c| c.value.to_lowercase()).collect();
                let rows = match *ins.source.ok_or_else(|| SqlError::MissingField("VALUES".into()))?.body {
                    SetExpr::Values(Values { rows, .. }) => rows,
                    _ => return Err(SqlError::Unsupported("INSERT with non-VALUES source".into())),
                };
                let vals = rows.into_iter().next()
                    .ok_or_else(|| SqlError::MissingField("at least one VALUES row".into()))?;

                let get = |name: &str| -> Result<String, SqlError> {
                    let idx = cols.iter().position(|c| c == name)
                        .ok_or_else(|| SqlError::MissingField(name.to_string()))?;
                    expr_to_string(&vals[idx])
                };

                let amount_str = get("amount")?;
                let amount: i64 = amount_str.parse().map_err(|_| SqlError::InvalidValue {
                    field: "amount".into(),
                    reason: "must be an integer (minor units)".into(),
                })?;

                Ok(LogicalPlan::PostEntry(EntrySpec {
                    description:     get("description")?,
                    debit_account:   get("debit_account")?,
                    credit_account:  get("credit_account")?,
                    amount,
                    currency:        get("currency")?,
                    external_ref:    get("external_ref").ok(),
                    idempotency_key: get("idempotency_key").ok(),
                    domain:          get("domain").unwrap_or_else(|_| "default".into()),
                }))
            }
            TABLE_ACCOUNTS => {
                let cols: Vec<String> = ins.columns.iter().map(|c| c.value.to_lowercase()).collect();
                let rows = match *ins.source.ok_or_else(|| SqlError::MissingField("VALUES".into()))?.body {
                    SetExpr::Values(Values { rows, .. }) => rows,
                    _ => return Err(SqlError::Unsupported("INSERT with non-VALUES source".into())),
                };
                let vals = rows.into_iter().next()
                    .ok_or_else(|| SqlError::MissingField("at least one VALUES row".into()))?;

                let get = |name: &str| -> Result<String, SqlError> {
                    let idx = cols.iter().position(|c| c == name)
                        .ok_or_else(|| SqlError::MissingField(name.to_string()))?;
                    expr_to_string(&vals[idx])
                };

                Ok(LogicalPlan::CreateAccount(AccountSpec {
                    code:         get("code")?,
                    name:         get("name")?,
                    account_type: get("account_type")?,
                    currency:     get("currency")?,
                    domain:       get("domain").unwrap_or_else(|_| "default".into()),
                }))
            }
            t => Err(SqlError::UnknownTable(t.into())),
        }
    }

    // ── CREATE TABLE accounts ─────────────────────────────────────────────

    fn plan_create_table(ct: sqlparser::ast::CreateTable) -> Result<LogicalPlan, SqlError> {
        let table = ct.name.to_string().to_lowercase();
        if table != TABLE_ACCOUNTS {
            return Err(SqlError::Unsupported(
                format!("CREATE TABLE is only supported for 'accounts', got '{table}'")));
        }
        // Values are passed as query options in Phase 2.
        // We look for a VALUES clause encoded via sqlparser options.
        // For simplicity, CREATE ACCOUNT is driven through a companion
        // "INSERT INTO accounts" statement which is the standard approach.
        Err(SqlError::Unsupported(
            "Use INSERT INTO accounts (code, name, account_type, currency, domain) VALUES (…) to create accounts".into()
        ))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_table_name(tf: &TableFactor) -> Result<String, SqlError> {
    match tf {
        TableFactor::Table { name, .. } => Ok(name.to_string().to_lowercase()),
        other => Err(SqlError::Unsupported(format!("table factor: {other}"))),
    }
}

fn expr_to_string(expr: &Expr) -> Result<String, SqlError> {
    match expr {
        Expr::Value(SqlValue::SingleQuotedString(s)) => Ok(s.clone()),
        Expr::Value(SqlValue::Number(n, _))          => Ok(n.clone()),
        Expr::Value(SqlValue::Boolean(b))            => Ok(b.to_string()),
        Expr::Value(SqlValue::Null)                  => Ok(String::new()),
        Expr::Identifier(i)                          => Ok(i.value.clone()),
        other => Err(SqlError::TypeError(format!("unsupported expression: {other}"))),
    }
}

fn extract_function_string_arg(
    args: &sqlparser::ast::FunctionArguments,
    fname: &str,
) -> Result<String, SqlError> {
    use sqlparser::ast::{FunctionArg, FunctionArgExpr, FunctionArguments};
    match args {
        FunctionArguments::List(list) => {
            list.args.first()
                .and_then(|a| match a {
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => Some(e),
                    _ => None,
                })
                .and_then(|e| expr_to_string(e).ok())
                .ok_or_else(|| SqlError::MissingField(format!("{fname}() requires a string argument")))
        }
        _ => Err(SqlError::MissingField(format!("{fname}() requires arguments"))),
    }
}

fn parse_where_to_entry_filter(table: &str, expr: Expr) -> Result<EntryFilter, SqlError> {
    if let Expr::BinaryOp { left, op: BinaryOperator::Eq, right } = expr {
        let col = match *left {
            Expr::Identifier(i) => i.value.to_lowercase(),
            Expr::CompoundIdentifier(parts) => parts.last().map(|i| i.value.to_lowercase()).unwrap_or_default(),
            _ => return Err(SqlError::Unsupported("complex WHERE clauses not yet supported".into())),
        };
        let val = expr_to_string(&right)?;
        match (table, col.as_str()) {
            (TABLE_LEDGER,   "sequence")     => Ok(EntryFilter::BySequence(val.parse().map_err(|_| SqlError::TypeError("sequence must be integer".into()))?)),
            (TABLE_LEDGER,   "external_ref") => Ok(EntryFilter::ByExternalRef(val)),
            (TABLE_LEDGER,   "domain")       => Ok(EntryFilter::ByDomain(val)),
            (TABLE_LEDGER,   "status")       => Ok(EntryFilter::ByStatus(val)),
            (TABLE_ACCOUNTS, "code")         => Ok(EntryFilter::ByDomain(format!("__account_code:{val}"))),
            (TABLE_ACCOUNTS, "domain")       => Ok(EntryFilter::ByDomain(val)),
            (TABLE_ACCOUNTS, "currency")     => Ok(EntryFilter::ByDomain(format!("__account_currency:{val}"))),
            _ => Err(SqlError::ColumnNotFound(col)),
        }
    } else {
        Err(SqlError::Unsupported("only simple column = 'value' WHERE clauses are supported".into()))
    }
}

// ── Phase 3 helpers ───────────────────────────────────────────────────────────

/// Build a base scan plan for `table_name` with an optional WHERE and LIMIT.
fn base_scan(
    table: &str,
    selection: &Option<Expr>,
    limit: &Option<Expr>,
) -> Result<LogicalPlan, SqlError> {
    let filter = if let Some(sel) = selection {
        Some(parse_where_to_entry_filter(table, sel.clone())?)
    } else if let Some(Expr::Value(SqlValue::Number(n, _))) = limit {
        let n: usize = n.parse().map_err(|_| SqlError::TypeError("LIMIT must be integer".into()))?;
        Some(EntryFilter::Limit(n))
    } else {
        None
    };
    match table {
        TABLE_LEDGER   => Ok(LogicalPlan::ScanEntries { filter }),
        TABLE_ACCOUNTS => Ok(LogicalPlan::ScanAccounts { filter }),
        t => Err(SqlError::UnknownTable(t.into())),
    }
}

/// Extract aggregate function expressions from a SELECT projection list.
fn collect_aggregate_exprs(items: &[SelectItem]) -> Vec<AggExpr> {
    let mut result = Vec::new();
    for item in items {
        let (expr, alias_override) = match item {
            SelectItem::UnnamedExpr(e) => (e, None),
            SelectItem::ExprWithAlias { expr, alias } => (expr, Some(alias.value.clone())),
            _ => continue,
        };
        if let Expr::Function(f) = expr {
            let fname = f.name.to_string().to_uppercase();
            let agg = match fname.as_str() {
                "SUM"   => AggFn::Sum,
                "COUNT" => AggFn::Count,
                "AVG"   => AggFn::Avg,
                "MIN"   => AggFn::Min,
                "MAX"   => AggFn::Max,
                _       => continue,
            };
            // Skip functions that have a OVER clause — those are windows.
            if matches!(f.over, Some(_)) {
                continue;
            }
            let col = match &f.args {
                FunctionArguments::List(list) => {
                    list.args.first()
                        .and_then(|a| match a {
                            FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => {
                                Some(expr_to_col_name(e))
                            }
                            FunctionArg::Unnamed(FunctionArgExpr::Wildcard) => {
                                Some("*".into())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| "*".into())
                }
                _ => "*".into(),
            };
            let alias = alias_override
                .unwrap_or_else(|| format!("{agg}({col})").to_lowercase());
            result.push(AggExpr { func: agg, column: col, alias });
        }
    }
    result
}

/// Extract the `OVER (…)` window spec from a function if present.
fn extract_window_spec(f: &Function) -> Option<AstWindowSpec> {
    match &f.over {
        Some(sqlparser::ast::WindowType::WindowSpec(ws)) => Some(ws.clone()),
        _ => None,
    }
}

/// Parse the window function name from a `Function` node.
fn parse_window_fn(f: &Function) -> Result<(WindowFn, String), SqlError> {
    let fname = f.name.to_string().to_uppercase();
    let wfn = match fname.as_str() {
        "ROW_NUMBER" => WindowFn::RowNumber,
        "RANK"       => WindowFn::Rank,
        "DENSE_RANK" => WindowFn::DenseRank,
        "SUM"        => WindowFn::RunningSum,
        "AVG"        => WindowFn::RunningAvg,
        "LAG"        => WindowFn::Lag,
        "LEAD"       => WindowFn::Lead,
        other => return Err(SqlError::Unsupported(format!("window function '{other}'"))),
    };
    let col = match &f.args {
        FunctionArguments::List(list) => {
            list.args.first()
                .and_then(|a| match a {
                    FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => Some(expr_to_col_name(e)),
                    _ => None,
                })
                .unwrap_or_else(|| "amount".into())
        }
        _ => "amount".into(),
    };
    Ok((wfn, col))
}

/// Convert an expression node to a bare column name string.
fn expr_to_col_name(expr: &Expr) -> String {
    match expr {
        Expr::Identifier(i)           => i.value.clone(),
        Expr::CompoundIdentifier(pts) => pts.last().map(|i| i.value.clone()).unwrap_or_default(),
        other                         => format!("{other}"),
    }
}

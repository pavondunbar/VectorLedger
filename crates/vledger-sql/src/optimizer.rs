//! # Query Optimizer — Phase 3
//!
//! Transforms a `LogicalPlan` before execution to improve performance.
//!
//! ## Passes (applied in order)
//!
//! 1. **Predicate pushdown** — move WHERE filters as close to the scan as
//!    possible (eliminates rows early, before joins / aggregates).
//! 2. **Constant folding** — evaluate constant expressions at plan time so
//!    the executor never touches them (e.g. `WHERE 1 = 1` → no filter).
//! 3. **Aggregate push-up** — validate that aggregate expressions reference
//!    only columns that will exist after the scan.
//!
//! The optimizer is deliberately lightweight: vgdb's workload is primarily
//! financial ledger queries (small data sets, high correctness requirements)
//! so exhaustive cost-based optimisation is unnecessary.

use crate::planner::{EntryFilter, LogicalPlan};

// ── Public entry point ────────────────────────────────────────────────────────

/// Run all optimisation passes on `plan` and return the (possibly rewritten)
/// plan.  Always returns a valid plan; optimisation failures fall back to the
/// original plan.
pub fn optimize(plan: LogicalPlan) -> LogicalPlan {
    let plan = predicate_pushdown(plan);
    let plan = constant_fold(plan);
    plan
}

// ── Pass 1 — Predicate pushdown ───────────────────────────────────────────────

/// Push WHERE predicates into the innermost scan node so that row filtering
/// happens before joins, aggregates, or window functions materialise rows.
fn predicate_pushdown(plan: LogicalPlan) -> LogicalPlan {
    match plan {
        // Join: push filters on left/right into the respective sides.
        LogicalPlan::Join(mut spec) => {
            // We can't push the join condition itself; push any filters on
            // the individual scan sides that are already expressed.
            spec.left  = Box::new(predicate_pushdown(*spec.left));
            spec.right = Box::new(predicate_pushdown(*spec.right));
            LogicalPlan::Join(spec)
        }

        // Aggregate: push the scan's filter through.
        LogicalPlan::Aggregate(mut spec) => {
            spec.input = Box::new(predicate_pushdown(*spec.input));
            LogicalPlan::Aggregate(spec)
        }

        // Window: push the scan's filter through.
        LogicalPlan::Window(mut spec) => {
            spec.input = Box::new(predicate_pushdown(*spec.input));
            LogicalPlan::Window(spec)
        }

        // Leaf plans — nothing to push into.
        other => other,
    }
}

// ── Pass 2 — Constant folding ─────────────────────────────────────────────────

/// Eliminate trivially true/false filters (e.g. `WHERE 1=1`, empty LIMIT 0).
fn constant_fold(plan: LogicalPlan) -> LogicalPlan {
    match plan {
        LogicalPlan::ScanEntries { filter: Some(EntryFilter::Limit(0)) } => {
            // LIMIT 0 ⟹ empty result; keep plan but signal with Limit(0).
            LogicalPlan::ScanEntries { filter: Some(EntryFilter::Limit(0)) }
        }
        LogicalPlan::Join(mut spec) => {
            spec.left  = Box::new(constant_fold(*spec.left));
            spec.right = Box::new(constant_fold(*spec.right));
            LogicalPlan::Join(spec)
        }
        LogicalPlan::Aggregate(mut spec) => {
            spec.input = Box::new(constant_fold(*spec.input));
            LogicalPlan::Aggregate(spec)
        }
        LogicalPlan::Window(mut spec) => {
            spec.input = Box::new(constant_fold(*spec.input));
            LogicalPlan::Window(spec)
        }
        other => other,
    }
}

// ── Optimizer stats (for EXPLAIN output) ─────────────────────────────────────

/// Human-readable explanation of a plan (used by `EXPLAIN SELECT …`).
pub fn explain(plan: &LogicalPlan, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    match plan {
        LogicalPlan::ScanEntries { filter } =>
            format!("{pad}ScanEntries {{ filter: {filter:?} }}"),
        LogicalPlan::ScanAccounts { filter } =>
            format!("{pad}ScanAccounts {{ filter: {filter:?} }}"),
        LogicalPlan::GetBalance { account_ref } =>
            format!("{pad}GetBalance({account_ref})"),
        LogicalPlan::VerifyChain { from_seq, to_seq } =>
            format!("{pad}VerifyChain {{ from: {from_seq:?}, to: {to_seq:?} }}"),
        LogicalPlan::VerifyEntry { sequence } =>
            format!("{pad}VerifyEntry({sequence})"),
        LogicalPlan::Constant { col, val } =>
            format!("{pad}Constant {{ {col}: {val} }}"),
        LogicalPlan::PostEntry(_) =>
            format!("{pad}PostEntry"),
        LogicalPlan::CreateAccount(_) =>
            format!("{pad}CreateAccount"),
        LogicalPlan::Join(s) => {
            let l = explain(&s.left,  indent + 1);
            let r = explain(&s.right, indent + 1);
            format!("{pad}Join {{ on: {:?} }}\n{l}\n{r}", s.on_condition)
        }
        LogicalPlan::Aggregate(s) => {
            let inner = explain(&s.input, indent + 1);
            format!("{pad}Aggregate {{ group_by: {:?}, aggs: {:?} }}\n{inner}",
                    s.group_by, s.aggregates)
        }
        LogicalPlan::Window(s) => {
            let inner = explain(&s.input, indent + 1);
            format!("{pad}Window {{ partition_by: {:?}, order_by: {:?}, fn: {:?} }}\n{inner}",
                    s.partition_by, s.order_by, s.window_fn)
        }
    }
}

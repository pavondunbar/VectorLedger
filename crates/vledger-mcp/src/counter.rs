//! Monthly Agent Query counter.
//!
//! Persists the current month's Agent Query count to
//! `<data_dir>/mcp_queries.json`. Automatically resets at the start of a new
//! calendar month (UTC).
//!
//! ## What counts as one Agent Query
//!
//! One Agent Query = one `initialize` JSON-RPC request from an MCP client.
//! Every MCP-capable client (Kiro, Claude Desktop, Cursor, etc.) sends exactly
//! one `initialize` per conversation. This correctly maps to the customer's
//! mental model: "I typed one question → that was one query."
//!
//! Multiple internal `tools/call` requests triggered by the agent to answer
//! that one question do NOT each count — the entire reasoning chain is one
//! Agent Query.
//!
//! ## What does NOT count
//! - Failed technical executions (server error before result delivered)
//! - `tools/list` requests (capability discovery only)
//! - `notifications/initialized` (MCP protocol handshake)
//!
//! Thread-safe: callers hold an `Arc<tokio::sync::Mutex<AgentQueryCounter>>`.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ── Limit constants ───────────────────────────────────────────────────────────

/// Monthly Agent Query limit for the Starter tier.
pub const LIMIT_STARTER: u64 = 10;

/// Monthly Agent Query limit for the Growth tier.
pub const LIMIT_GROWTH: u64 = 100;

/// Sentinel value meaning "no limit" (Enterprise tier).
pub const LIMIT_UNLIMITED: u64 = 0;

// ── On-disk state ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct CounterState {
    /// Calendar month this counter covers, formatted as `"YYYY-MM"`.
    month: String,
    /// Number of Agent Queries consumed this month.
    count: u64,
}

// ── AgentQueryCounter ─────────────────────────────────────────────────────────

/// Persistent monthly Agent Query counter.
///
/// Incremented once per `initialize` request — the MCP protocol boundary that
/// corresponds to one human natural-language question, regardless of how many
/// internal tool calls the agent makes to answer it.
pub struct AgentQueryCounter {
    path: PathBuf,
    state: CounterState,
    /// Monthly limit. 0 = unlimited (Enterprise).
    limit: u64,
}

// Type alias keeps existing code that references RunCounter compiling.
pub type RunCounter = AgentQueryCounter;

impl AgentQueryCounter {
    /// Open (or create) the counter file at `data_dir/mcp_queries.json`.
    ///
    /// `limit` — monthly cap. Pass [`LIMIT_UNLIMITED`] (0) for Enterprise.
    pub fn open(data_dir: &Path, limit: u64) -> Result<Self> {
        let path = data_dir.join("mcp_queries.json");
        let current_month = current_month_str();

        let state = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(text) => match serde_json::from_str::<CounterState>(&text) {
                    Ok(s) if s.month == current_month => {
                        info!(
                            count = s.count,
                            month = %s.month,
                            limit = if limit == 0 { "unlimited".to_string() }
                                    else { limit.to_string() },
                            "Agent Query counter loaded"
                        );
                        s
                    }
                    _ => {
                        info!(month = %current_month, "Agent Query counter reset for new month");
                        CounterState { month: current_month, count: 0 }
                    }
                },
                Err(_) => CounterState { month: current_month, count: 0 },
            }
        } else {
            CounterState { month: current_month, count: 0 }
        };

        Ok(Self { path, state, limit })
    }

    /// Current Agent Query count for this month.
    pub fn count(&self) -> u64 {
        self.state.count
    }

    /// Monthly limit (0 = unlimited).
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns `true` if the monthly limit has been reached.
    pub fn is_over_limit(&self) -> bool {
        self.limit != LIMIT_UNLIMITED && self.state.count >= self.limit
    }

    /// Remaining Agent Queries this month. Returns `None` for unlimited.
    pub fn remaining(&self) -> Option<u64> {
        if self.limit == LIMIT_UNLIMITED {
            None
        } else {
            Some(self.limit.saturating_sub(self.state.count))
        }
    }

    /// Attempt to consume one Agent Query (called on `initialize`).
    ///
    /// Returns `Ok(())` if allowed, `Err(QueryLimitError)` if the monthly
    /// limit has been reached. Always persists the updated count on success.
    /// Failed executions should NOT call this method.
    pub fn consume(&mut self) -> Result<(), QueryLimitError> {
        // Roll over if a new month started since last call.
        let current_month = current_month_str();
        if self.state.month != current_month {
            info!(month = %current_month, "Agent Query counter reset for new month");
            self.state = CounterState { month: current_month, count: 0 };
        }

        if self.limit != LIMIT_UNLIMITED && self.state.count >= self.limit {
            warn!(
                count = self.state.count,
                limit = self.limit,
                month = %self.state.month,
                "Agent Query monthly limit reached"
            );
            return Err(QueryLimitError {
                limit: self.limit,
                used: self.state.count,
                month: self.state.month.clone(),
            });
        }

        self.state.count += 1;
        let _ = self.persist(); // best-effort — never fail a query due to I/O

        info!(
            count = self.state.count,
            limit = if self.limit == 0 { "unlimited".to_string() }
                    else { self.limit.to_string() },
            remaining = self.remaining()
                .map(|r| r.to_string())
                .unwrap_or_else(|| "unlimited".to_string()),
            month = %self.state.month,
            "Agent Query consumed"
        );

        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let text = serde_json::to_string_pretty(&self.state)?;
        std::fs::write(&self.path, text)?;
        Ok(())
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Returned when the monthly Agent Query limit has been reached.
#[derive(Debug)]
pub struct QueryLimitError {
    pub limit: u64,
    pub used: u64,
    pub month: String,
}

impl std::fmt::Display for QueryLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Monthly Agent Query limit reached: {}/{} queries used in {}.\n\n\
             Upgrade your VectorLedger license to continue:\n\
               Starter:     10 Agent Queries/month  — $499/mo\n\
               Growth:     100 Agent Queries/month  — $2,499/mo\n\
               Enterprise: Unlimited Agent Queries  — from $4,999/mo\n\n\
             Contact: pavon@vectorguardlabs.com",
            self.used, self.limit, self.month
        )
    }
}

impl std::error::Error for QueryLimitError {}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn current_month_str() -> String {
    chrono::Utc::now().format("%Y-%m").to_string()
}

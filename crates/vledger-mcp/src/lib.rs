//! # vledger-mcp
//!
//! A [Model Context Protocol](https://spec.modelcontextprotocol.io) server that
//! exposes VectorLedger's SQL surface as AI-callable tools.
//!
//! ## Transport
//! HTTP with Server-Sent Events (SSE), as specified by MCP.
//! - `GET  /sse`      — client opens an SSE stream; server sends its endpoint URL
//! - `POST /message`  — client posts JSON-RPC 2.0 requests here
//!
//! ## Tools exposed
//! | Tool name            | Description |
//! |----------------------|-------------|
//! | `query_ledger`       | Run any read-only SELECT against the ledger |
//! | `post_entry`         | Record a new double-entry journal entry |
//! | `get_balance`        | Return current balance for an account |
//! | `list_accounts`      | List all accounts (optional domain/currency filter) |
//! | `query_ledger_lines` | Query individual debit/credit lines |
//! | `verify_chain`       | Verify cryptographic chain integrity |
//! | `merkle_root`        | Compute Merkle root over a sequence range |
//!
//! ## Usage
//! ```no_run
//! use std::sync::{Arc, RwLock};
//! use vledger_mcp::{McpServer, McpConfig};
//!
//! // The LedgerStore must already be opened and initialised.
//! // McpServer::run() binds and serves until the shutdown token fires.
//! ```

pub mod tools;

use std::sync::{Arc, RwLock};

use anyhow::Result;
use axum::extract::State;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::info;

use vledger_ledger::LedgerStore;
use vledger_server::auth::{Session, UserStore};

// ── Public configuration ──────────────────────────────────────────────────────

/// Configuration for the MCP server.
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Address to bind, e.g. `"127.0.0.1:3000"`.
    pub bind: String,
    /// Username the MCP server authenticates with against the UserStore.
    pub username: String,
    /// Password for the above user.
    pub password: String,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:3000".to_string(),
            username: "admin".to_string(),
            password: String::new(),
        }
    }
}

// ── JSON-RPC 2.0 wire types ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0".to_string(), id, result: Some(result), error: None }
    }

    pub fn err(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
        }
    }
}

// ── Shared server state ───────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct AppState {
    pub ledger: Arc<RwLock<LedgerStore>>,
    pub session: Arc<Session>,
    /// Broadcast channel used to push SSE events to connected clients.
    pub sse_tx: broadcast::Sender<String>,
}

// ── MCP tool registry ─────────────────────────────────────────────────────────

/// Financially-aware system prompt for AI agents connected via MCP.
///
/// Paste this into the `instructions` / `system` field of any agent that
/// will call VectorLedger tools so the model understands financial domain
/// semantics rather than treating the ledger as a generic database.
///
/// Works with: Kiro, Claude Desktop, LangChain, OpenAI Agents SDK, LlamaIndex.
pub const AGENT_SYSTEM_PROMPT: &str = r#"
You are a financial operations assistant with direct access to VectorLedger —
a cryptographically verifiable, append-only double-entry financial ledger.

## Your capabilities

You can call the following tools:

### Query tools
- query_ledger        — Run any SELECT, BALANCE(), VERIFY_CHAIN(), MERKLE_ROOT()
- get_balance         — Get the current balance of any account
- list_accounts       — List all accounts with balances
- query_ledger_lines  — Query individual debit/credit journal lines

### Write tools (operator/admin role required)
- post_entry          — Record a new double-entry journal entry

### Integrity tools
- verify_chain        — Verify cryptographic hash chain integrity
- merkle_root         — Compute a BLAKE3 Merkle commitment over a sequence range

### Financial reasoning tools (use these for complex questions)
- explain_balance      — Why is an account at its current balance?
- reconcile_account    — Does the balance match the sum of posted lines?
- find_policy_violations — Transactions that break financial rules
- summarize_period     — Natural-language summary of a date range
- audit_report         — Cryptographic audit evidence report for a period

## Financial domain knowledge you MUST apply

### Amounts are ALWAYS in minor units (integer cents)
- $10,000.00 USD = 1000000
- $82,400.00 USD = 8240000
- When displaying to users: divide by 100 for USD/EUR/GBP; JPY has no subunit
- When a user says "$50K" you mean 5000000 in tool calls

### Double-entry accounting
- Every transaction has EXACTLY one Debit line and one Credit line
- Debits and credits always balance (debit amount == credit amount)
- The ledger is APPEND-ONLY — you cannot edit or delete entries
- Corrections require a reversal entry (flip debit/credit) then a correction entry

### Account types and normal balance direction
- Asset / Expense → increased by Debits, normal balance is positive (Debit)
- Liability / Equity / Income → increased by Credits, normal balance may appear negative
- Suspense → temporary account; balance should be zero after reconciliation

### Entry status meanings
- 'Posted'    → committed, immutable, hash-chained
- 'Pending'   → awaiting settlement — does NOT affect final balance yet
- 'Settled'   → settlement confirmed
- 'Failed'    → settlement failed — may need reversal
- 'Reversal'  → reversal of a prior Posted entry

### Cryptographic fields
- content_hash → fingerprint of this entry's fields; tampering changes this
- chain_hash   → links this entry to all prior entries; breaking any prior entry breaks this
- merkle_root  → proves membership in a committed set; use for audit evidence

## How to answer financial questions

"Why is X account lower than expected?"
→ Call explain_balance('X'), then reconcile_account('X')

"Summarize last month / Q3 / this week"
→ Call summarize_period with appropriate from/to dates

"Are there any compliance issues / suspicious transactions?"
→ Call find_policy_violations

"Generate an audit report for September"
→ Call audit_report with from='2026-09-01', to='2026-09-30'

"Is the ledger intact / has it been tampered with?"
→ Call verify_chain() — if result contains 'OK' the chain is intact

"What is the Merkle root / cryptographic commitment for entries X to Y?"
→ Call merkle_root(from_seq=X, to_seq=Y)

## Behaviour rules

1. Never make up balances, amounts, or entry data — always call a tool to get real data.
2. Always show amounts in human-readable form (divide minor units by 100 for USD).
3. After posting an entry, always confirm the sequence number and entry ID returned.
4. If verify_chain returns anything other than OK, escalate immediately — this means
   potential data tampering.
5. For sensitive operations (posting entries, reconciliation), confirm with the user
   before proceeding.
6. When a question is ambiguous (which account? which period?), ask for clarification
   rather than guessing.
"#;

/// Returns the static MCP `tools/list` response payload describing every
/// available tool and its JSON Schema input shape.
pub fn tool_list() -> Value {
    json!({
        "tools": [
            // ── Low-level tools ──────────────────────────────────────────
            {
                "name": "query_ledger",
                "description": "Run a read-only SELECT against the ledger, ledger_lines, or accounts \
                                table. Also accepts special functions: BALANCE('CODE'), VERIFY_CHAIN(), \
                                VERIFY_ENTRY(seq), MERKLE_ROOT(from, to). Use for any question about \
                                entries, balances, or history.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description": "A VectorLedger SQL SELECT statement. Amounts are in integer \
                                            minor units (cents). Multiply dollar amounts by 100."
                        }
                    },
                    "required": ["sql"]
                }
            },
            {
                "name": "post_entry",
                "description": "Record a new double-entry journal entry. Both debit and credit sides \
                                are written atomically and hash-chained. amount MUST be in minor units \
                                (e.g. $100.00 USD = 10000). The ledger is append-only — corrections \
                                require a separate reversal entry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "description":    { "type": "string",  "description": "Human-readable transaction description." },
                        "debit_account":  { "type": "string",  "description": "Account code (e.g. 'CASH') or UUID to debit." },
                        "credit_account": { "type": "string",  "description": "Account code or UUID to credit." },
                        "amount":         { "type": "integer", "description": "Amount in minor units (cents). Must be positive. $100.00 = 10000." },
                        "currency":       { "type": "string",  "description": "ISO 4217 currency code, e.g. 'USD'." },
                        "domain":         { "type": "string",  "description": "Ledger domain (default: 'main')." },
                        "external_ref":   { "type": "string",  "description": "External system reference ID (optional)." },
                        "metadata":       { "type": "string",  "description": "JSON metadata string (optional)." }
                    },
                    "required": ["description", "debit_account", "credit_account", "amount", "currency"]
                }
            },
            {
                "name": "get_balance",
                "description": "Return the current running balance of a single account in minor units. \
                                For Asset/Expense accounts a positive balance is normal. For \
                                Liability/Equity/Income a negative (credit) balance is normal.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account": { "type": "string", "description": "Account code (e.g. 'CASH') or UUID." }
                    },
                    "required": ["account"]
                }
            },
            {
                "name": "list_accounts",
                "description": "List all accounts with current balances. Optionally filter by domain or currency.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain":   { "type": "string", "description": "Filter by domain (optional)." },
                        "currency": { "type": "string", "description": "Filter by currency code (optional)." }
                    }
                }
            },
            {
                "name": "query_ledger_lines",
                "description": "Query individual debit/credit journal lines. Each ledger entry has \
                                exactly 2 lines — one Debit and one Credit. Useful for account-level \
                                transaction history.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain":  { "type": "string",  "description": "Filter by domain (optional)." },
                        "dr_cr":   { "type": "string",  "description": "'Debit' or 'Credit' (optional)." },
                        "limit":   { "type": "integer", "description": "Max rows (default 100)." }
                    }
                }
            },
            {
                "name": "verify_chain",
                "description": "Verify the BLAKE3 cryptographic hash chain. Returns OK or BROKEN. \
                                A broken chain means tampering has occurred. Call this after any \
                                investigation or before producing an audit report.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from_seq": { "type": "integer", "description": "Start of range (optional, defaults to full ledger)." },
                        "to_seq":   { "type": "integer", "description": "End of range (optional)." }
                    }
                }
            },
            {
                "name": "merkle_root",
                "description": "Compute the 64-character BLAKE3 Merkle root over a range of entries. \
                                This is a cryptographic commitment — record it alongside the sequence \
                                range to prove the ledger has not changed.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from_seq": { "type": "integer", "description": "First entry sequence (inclusive)." },
                        "to_seq":   { "type": "integer", "description": "Last entry sequence (inclusive)." }
                    },
                    "required": ["from_seq", "to_seq"]
                }
            },
            // ── High-order financial reasoning tools ─────────────────────
            {
                "name": "explain_balance",
                "description": "Explain why an account is at its current balance by showing recent \
                                debits and credits, the account type, normal balance direction, and a \
                                narrative interpretation. Use this when a user asks 'why is X account \
                                at Y?' or 'where did the money in X go?'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account": { "type": "string",  "description": "Account code or UUID to explain." },
                        "limit":   { "type": "integer", "description": "Number of recent lines to show per side (default 20)." }
                    },
                    "required": ["account"]
                }
            },
            {
                "name": "reconcile_account",
                "description": "Verify that an account's running balance matches the mathematical sum \
                                of all its posted debit and credit lines. Returns BALANCED or flags a \
                                discrepancy with the exact difference. Use when investigating unexpected \
                                balances or preparing for an audit.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account": { "type": "string", "description": "Account code or UUID to reconcile." }
                    },
                    "required": ["account"]
                }
            },
            {
                "name": "find_policy_violations",
                "description": "Scan the ledger for entries that violate configurable financial policies: \
                                transactions above a large-amount threshold, entries still Pending too long, \
                                Posted entries missing an external reference, and Failed entries. Returns a \
                                categorised violation report. Use for compliance checks, fraud screening, \
                                or answering questions like 'show me transactions that need review'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "large_amount_threshold_minor_units": {
                            "type": "integer",
                            "description": "Flag entries with a line amount above this threshold in minor units (default 5000000 = $50,000)."
                        },
                        "pending_days_threshold": {
                            "type": "integer",
                            "description": "Flag Pending entries older than this many days (default 3)."
                        },
                        "check_large_amounts":       { "type": "boolean", "description": "Enable large-amount check (default true)." },
                        "check_pending_too_long":    { "type": "boolean", "description": "Enable pending-too-long check (default true)." },
                        "check_missing_external_ref":{ "type": "boolean", "description": "Enable missing-external-ref check (default true)." },
                        "check_failed_entries":      { "type": "boolean", "description": "Enable failed-entries check (default true)." }
                    }
                }
            },
            {
                "name": "summarize_period",
                "description": "Produce a natural-language financial summary for a date range: entry counts \
                                by status, total debit volume, success rate, sequence range, Merkle commitment, \
                                and chain integrity. Use when a user asks 'summarize last month' or \
                                'what happened in September?'",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from":   { "type": "string", "description": "Start date or timestamp, e.g. '2026-09-01'." },
                        "to":     { "type": "string", "description": "End date or timestamp, e.g. '2026-09-30'." },
                        "domain": { "type": "string", "description": "Domain to summarize (default 'main')." }
                    },
                    "required": ["from", "to"]
                }
            },
            {
                "name": "audit_report",
                "description": "Generate a structured cryptographic audit evidence report for a period. \
                                Includes ledger summary, hash chain verification, Merkle commitment, sample \
                                entries with content hashes, and instructions for independent verification. \
                                Suitable for presenting to an auditor or regulator.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from":   { "type": "string", "description": "Period start date, e.g. '2026-09-01'." },
                        "to":     { "type": "string", "description": "Period end date, e.g. '2026-09-30'." },
                        "tenant": { "type": "string", "description": "Organization name for the report header." },
                        "domain": { "type": "string", "description": "Domain to report on (default 'main')." }
                    },
                    "required": ["from", "to"]
                }
            }
        ]
    })
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

/// `GET /sse` — open an SSE stream and advertise the `/message` endpoint.
async fn handle_sse(State(state): State<AppState>) -> impl IntoResponse {
    let mut rx = state.sse_tx.subscribe();

    let stream = async_stream::stream! {
        // Send the MCP endpoint event immediately so the client knows where
        // to POST its JSON-RPC requests.
        yield Ok::<Event, std::convert::Infallible>(
            Event::default()
                .event("endpoint")
                .data("/message")
        );

        // Forward any broadcast messages (server-initiated notifications).
        loop {
            match rx.recv().await {
                Ok(msg) => yield Ok(Event::default().data(msg)),
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    };

    Sse::new(stream)
}

/// `POST /message` — receive a JSON-RPC 2.0 request and return the response.
async fn handle_message(
    State(state): State<AppState>,
    Json(req): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    let id = req.id.clone();
    let resp = dispatch(state, req).await;
    Json(match resp {
        Ok(result) => JsonRpcResponse::ok(id, result),
        Err(e) => JsonRpcResponse::err(id, -32000, e.to_string()),
    })
}

/// `GET /health` — simple liveness check.
async fn handle_health() -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "service": "vledger-mcp",
        "version": env!("CARGO_PKG_VERSION"),
        "tools": 12
    }))
}

// ── JSON-RPC dispatcher ───────────────────────────────────────────────────────

async fn dispatch(state: AppState, req: JsonRpcRequest) -> Result<Value> {
    match req.method.as_str() {
        // ── MCP lifecycle ─────────────────────────────────────────────────
        "initialize" => {
            Ok(json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "vledger-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": AGENT_SYSTEM_PROMPT
            }))
        }

        "notifications/initialized" => {
            // Client acknowledgement — nothing to return.
            Ok(json!(null))
        }

        // ── Tool discovery ────────────────────────────────────────────────
        "tools/list" => Ok(tool_list()),

        // ── Tool invocation ───────────────────────────────────────────────
        "tools/call" => {
            let tool_name = req.params["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing 'name' in tools/call params"))?;
            let args = &req.params["arguments"];

            tools::dispatch_tool(tool_name, args, &state.ledger, &state.session)
        }

        // ── Unknown method ────────────────────────────────────────────────
        other => anyhow::bail!("Unknown method: {other}"),
    }
}

// ── McpServer ─────────────────────────────────────────────────────────────────

/// The MCP HTTP server.
pub struct McpServer {
    config: McpConfig,
    ledger: Arc<RwLock<LedgerStore>>,
    user_store: Arc<UserStore>,
}

impl McpServer {
    /// Create a new MCP server.
    ///
    /// `ledger` should be an already-opened `LedgerStore` wrapped in an
    /// `Arc<RwLock<…>>` so it can be shared with the main vledger process.
    pub fn new(
        config: McpConfig,
        ledger: Arc<RwLock<LedgerStore>>,
        user_store: Arc<UserStore>,
    ) -> Self {
        Self { config, ledger, user_store }
    }

    /// Bind the HTTP listener and serve until `shutdown` fires.
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let session = Arc::new(
            self.user_store
                .authenticate(&self.config.username, &self.config.password)
                .map_err(|e| anyhow::anyhow!("MCP server auth failed: {e}"))?,
        );

        let (sse_tx, _) = broadcast::channel::<String>(64);

        let state = AppState {
            ledger: self.ledger,
            session,
            sse_tx,
        };

        let app = Router::new()
            .route("/sse", get(handle_sse))
            .route("/message", post(handle_message))
            .route("/health", get(handle_health))
            .with_state(state)
            .layer(
                tower_http::cors::CorsLayer::new()
                    .allow_origin(tower_http::cors::Any)
                    .allow_methods([
                        axum::http::Method::GET,
                        axum::http::Method::POST,
                        axum::http::Method::OPTIONS,
                    ])
                    .allow_headers(tower_http::cors::Any),
            );

        let listener = tokio::net::TcpListener::bind(&self.config.bind)
            .await
            .map_err(|e| anyhow::anyhow!("Cannot bind MCP server to {}: {e}", self.config.bind))?;

        info!(addr = %self.config.bind, "MCP server listening");

        axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;

        info!("MCP server shut down");
        Ok(())
    }
}

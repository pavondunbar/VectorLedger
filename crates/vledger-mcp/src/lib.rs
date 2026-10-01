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

/// Returns the static MCP `tools/list` response payload describing every
/// available tool and its JSON Schema input shape.
pub fn tool_list() -> Value {
    json!({
        "tools": [
            {
                "name": "query_ledger",
                "description": "Run a read-only SELECT statement against the VectorLedger ledger table. \
                                Returns columns, rows, row count, and a Merkle proof when applicable. \
                                Use this for any question about past entries, balances, or history.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description": "A SELECT statement targeting the `ledger`, `ledger_lines`, or `accounts` table. \
                                            Special functions: BALANCE('CODE'), VERIFY_CHAIN(), VERIFY_ENTRY(seq), MERKLE_ROOT(from,to)."
                        }
                    },
                    "required": ["sql"]
                }
            },
            {
                "name": "post_entry",
                "description": "Record a new double-entry journal entry in the ledger. \
                                Both debit and credit sides are written atomically. \
                                amount is in minor units (cents).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "description":    { "type": "string", "description": "Human-readable description of the transaction." },
                        "debit_account":  { "type": "string", "description": "Account code or UUID to debit." },
                        "credit_account": { "type": "string", "description": "Account code or UUID to credit." },
                        "amount":         { "type": "integer", "description": "Amount in minor units (e.g. cents). Must be positive." },
                        "currency":       { "type": "string", "description": "ISO 4217 currency code, e.g. USD." },
                        "domain":         { "type": "string", "description": "Ledger domain, e.g. 'main'.", "default": "main" },
                        "external_ref":   { "type": "string", "description": "Optional external reference identifier." },
                        "metadata":       { "type": "string", "description": "Optional JSON metadata string." }
                    },
                    "required": ["description", "debit_account", "credit_account", "amount", "currency"]
                }
            },
            {
                "name": "get_balance",
                "description": "Return the current running balance of a single account in minor units.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "account": {
                            "type": "string",
                            "description": "Account code (e.g. 'CASH') or UUID."
                        }
                    },
                    "required": ["account"]
                }
            },
            {
                "name": "list_accounts",
                "description": "List all accounts in the ledger with their current balances. \
                                Optionally filter by domain or currency.",
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
                "description": "Query individual debit/credit journal lines. \
                                Useful for account-level transaction history.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain":  { "type": "string",  "description": "Filter by domain (optional)." },
                        "dr_cr":   { "type": "string",  "description": "Filter by 'Debit' or 'Credit' (optional)." },
                        "limit":   { "type": "integer", "description": "Maximum rows to return (default 100)." }
                    }
                }
            },
            {
                "name": "verify_chain",
                "description": "Verify the cryptographic hash chain integrity of the ledger. \
                                Returns status, number of entries verified, and the chain tip hash.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from_seq": { "type": "integer", "description": "Start of range to verify (optional, defaults to full ledger)." },
                        "to_seq":   { "type": "integer", "description": "End of range to verify (optional)." }
                    }
                }
            },
            {
                "name": "merkle_root",
                "description": "Compute the BLAKE3 Merkle root over a range of ledger entries. \
                                Useful for producing cryptographic commitments over a time period.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "from_seq": { "type": "integer", "description": "Sequence number of the first entry (inclusive)." },
                        "to_seq":   { "type": "integer", "description": "Sequence number of the last entry (inclusive)." }
                    },
                    "required": ["from_seq", "to_seq"]
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
    Json(json!({ "ok": true, "service": "vledger-mcp" }))
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
                }
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

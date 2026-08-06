//! # vledger-pgwire
//!
//! PostgreSQL wire protocol v3 compatibility layer for VectorLedger.
//!
//! ## Security (Fix #1)
//! All connections are now protected by:
//! - Mandatory TLS 1.3 (rustls) — plain-text connections are rejected.
//! - Cleartext-password authentication inside TLS — verified against the
//!   vgdb `UserStore` using Argon2id.
//! - Plan-level RBAC — privilege is checked on the resolved `LogicalPlan`
//!   variant, not raw SQL text (Fix #7).
//!
//! ## Supported message flow
//! - SSL negotiation → TLS upgrade
//! - Startup → AuthenticationCleartextPassword → PasswordMessage → AuthOk
//! - Simple Query protocol (Q / RowDescription / DataRow / CommandComplete /
//!   EmptyQueryResponse / ErrorResponse / ReadyForQuery)
//! - Extended-query (Parse / Bind / Execute) mapped to simple-query path
//! - Terminate (X)

pub mod codec;
pub mod messages;
pub mod server;

pub use server::{PgWireConfig, PgWireServer};

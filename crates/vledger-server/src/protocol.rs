//! Wire protocol for VectorLedger.
//!
//! Simple newline-delimited JSON over a TLS stream:
//!
//! Authentication (must happen first):
//!   Client → {"auth": {"username": "alice", "password": "s3cr3t"}}
//!   Server → {"ok": true, "role": "operator", "token": "<hex-token>"}
//!          | {"ok": false, "error": "invalid credentials"}
//!
//! Subsequent requests (use token):
//!   Client → {"sql": "SELECT * FROM ledger", "token": "<hex-token>"}
//!   Server → {"ok": true, "rows": [...], "proof": {...}, "message": "..."}
//!          | {"ok": false, "error": "..."}

use serde::{Deserialize, Serialize};
use vledger_sql::result::{MerkleProof, Row};

/// An authentication sub-object in the first request frame.
#[derive(Debug, Deserialize)]
pub struct AuthCredentials {
    pub username: String,
    pub password: String,
}

/// A request frame sent by the client.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// SQL statement (absent on an auth-only request).
    pub sql: Option<String>,
    /// Credentials — present on the first request to establish a session.
    pub auth: Option<AuthCredentials>,
    /// Session token from a prior auth response.
    pub token: Option<String>,
    /// When true, attach a Merkle proof to the response.
    #[serde(default)]
    pub with_proof: bool,
    /// Admin command (e.g. set_password). Requires admin role.
    pub admin: Option<AdminCommand>,
}

/// An admin command sent by the client.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AdminCommand {
    /// Change a user's password.
    SetPassword {
        username: String,
        new_password: String,
    },
    /// Create a new user.
    CreateUser {
        username: String,
        password: String,
        role: String,
    },
    /// Delete a user.
    DeleteUser { username: String },
    /// Enable or disable a user.
    SetEnabled { username: String, enabled: bool },
    /// List all users.
    ListUsers,
}

/// A response frame sent to the client.
#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<Vec<serde_json::Value>>,
    pub rows_affected: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<ProofJson>,
    pub message: String,
    /// Session token returned after successful authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Role of the authenticated user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// JSON-serialisable proof summary.
#[derive(Debug, Serialize)]
pub struct ProofJson {
    pub root_hex: String,
    pub leaf_count: usize,
    pub verified: bool,
}

impl Response {
    pub fn ok(
        columns: Vec<String>,
        rows: Vec<Row>,
        rows_affected: usize,
        proof: Option<MerkleProof>,
        message: String,
    ) -> Self {
        let json_rows: Vec<Vec<serde_json::Value>> = rows
            .iter()
            .map(|r| {
                r.values
                    .iter()
                    .map(|v| serde_json::Value::String(v.to_string()))
                    .collect()
            })
            .collect();

        let proof_json = proof.map(|p| {
            let verified = p.leaf_proofs.iter().all(|lp| {
                let mut cur = lp.leaf_hash;
                for step in &lp.path {
                    cur = if step.sibling_is_left {
                        vledger_crypto::hash::hash_node(&step.sibling, &cur)
                    } else {
                        vledger_crypto::hash::hash_node(&cur, &step.sibling)
                    };
                }
                cur == p.root
            });
            ProofJson {
                root_hex: hex::encode(p.root),
                leaf_count: p.leaf_proofs.len(),
                verified,
            }
        });

        Self {
            ok: true,
            error: None,
            columns,
            rows: json_rows,
            rows_affected,
            proof: proof_json,
            message,
            token: None,
            role: None,
        }
    }

    pub fn auth_ok(token: String, role: String) -> Self {
        Self {
            ok: true,
            error: None,
            columns: vec![],
            rows: vec![],
            rows_affected: 0,
            proof: None,
            message: "authenticated".into(),
            token: Some(token),
            role: Some(role),
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            columns: vec![],
            rows: vec![],
            rows_affected: 0,
            proof: None,
            message: String::new(),
            token: None,
            role: None,
        }
    }
}

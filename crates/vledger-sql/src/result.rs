//! Query result types.
//!
//! Every query returns a `QueryResult` which optionally carries a Merkle
//! proof alongside the row data — this is the "verifiable query" feature.

use serde::{Deserialize, Serialize};
use vledger_crypto::Hash;

/// A single column value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Int(i64),
    BigInt(i128),
    Text(String),
    Bool(bool),
    /// UTC timestamp as an ISO-8601 string.
    Timestamp(String),
    /// A 32-byte hash rendered as lowercase hex.
    Hash(String),
    /// A UUID rendered as a hyphenated string.
    Uuid(String),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null          => write!(f, "NULL"),
            Value::Int(n)        => write!(f, "{n}"),
            Value::BigInt(n)     => write!(f, "{n}"),
            Value::Text(s)       => write!(f, "{s}"),
            Value::Bool(b)       => write!(f, "{b}"),
            Value::Timestamp(s)  => write!(f, "{s}"),
            Value::Hash(s)       => write!(f, "{s}"),
            Value::Uuid(s)       => write!(f, "{s}"),
        }
    }
}

/// A single result row: ordered column names + matching values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub columns: Vec<String>,
    pub values: Vec<Value>,
}

impl Row {
    pub fn new(columns: Vec<String>, values: Vec<Value>) -> Self {
        assert_eq!(columns.len(), values.len(), "columns/values length mismatch");
        Self { columns, values }
    }

    pub fn get(&self, col: &str) -> Option<&Value> {
        self.columns.iter().position(|c| c == col)
            .map(|i| &self.values[i])
    }
}

/// A cryptographic Merkle proof attached to a query result.
///
/// The client can independently verify that the returned rows were part of
/// the committed database state without trusting the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The database's current Merkle root (covers all entry pages).
    pub root: Hash,
    /// For each returned row: the proof path from leaf to root.
    pub leaf_proofs: Vec<LeafProof>,
    /// Ed25519 signature over `root` bytes by the database signing key.
    pub root_signature: Option<Vec<u8>>,
    /// Database signing public key.
    pub signing_public_key: Option<[u8; 32]>,
}

/// Proof that a single row belongs to the Merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafProof {
    /// Index of the leaf in the Merkle tree.
    pub leaf_index: usize,
    /// BLAKE3 hash of the leaf data.
    pub leaf_hash: Hash,
    /// Proof path (sibling hashes from leaf to root).
    pub path: Vec<ProofStep>,
}

/// A single step in a Merkle proof path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling: Hash,
    pub sibling_is_left: bool,
}

/// The complete result of a SQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Column names in result order.
    pub columns: Vec<String>,
    /// Data rows.
    pub rows: Vec<Row>,
    /// Number of rows affected (for INSERT/UPDATE).
    pub rows_affected: usize,
    /// Optional cryptographic proof that the rows belong to the committed state.
    pub proof: Option<MerkleProof>,
    /// Human-readable status message.
    pub message: String,
}

impl QueryResult {
    pub fn empty(message: impl Into<String>) -> Self {
        Self {
            columns: vec![],
            rows: vec![],
            rows_affected: 0,
            proof: None,
            message: message.into(),
        }
    }

    pub fn rows(columns: Vec<String>, rows: Vec<Row>, message: impl Into<String>) -> Self {
        let n = rows.len();
        Self { columns, rows, rows_affected: n, proof: None, message: message.into() }
    }

    pub fn with_proof(mut self, proof: MerkleProof) -> Self {
        self.proof = Some(proof);
        self
    }

    pub fn affected(n: usize, message: impl Into<String>) -> Self {
        Self {
            columns: vec![],
            rows: vec![],
            rows_affected: n,
            proof: None,
            message: message.into(),
        }
    }
}

//! PyHSM IPC wire protocol types.
//!
//! The PyHSM daemon speaks newline-delimited JSON over a Unix domain socket:
//!   Client → {"type": "encrypt", "keyId": "...", "plaintext": "<hex>", "callerId": "..."}
//!   Server → {"ok": true, "data": "<hex>"}  |  {"ok": false, "error": "..."}
//!
//! This matches the TypeScript client in PyHSM/pyhsm-ts/client.ts exactly.

use serde::{Deserialize, Serialize};

/// All request types the PyHSM daemon accepts.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum HsmRequest {
    Encrypt     { #[serde(rename = "keyId")] key_id: String, plaintext:  String, #[serde(rename = "callerId")] caller_id: String },
    Decrypt     { #[serde(rename = "keyId")] key_id: String, ciphertext: String, #[serde(rename = "callerId")] caller_id: String },
    Sign        { #[serde(rename = "keyId")] key_id: String, message:    String, #[serde(rename = "callerId")] caller_id: String },
    Verify      { #[serde(rename = "keyId")] key_id: String, message:    String, signature: String, #[serde(rename = "callerId")] caller_id: String },
    GenerateKey { #[serde(rename = "keyId")] key_id: String, policy: Option<KeyPolicy>, #[serde(rename = "callerId")] caller_id: String },
    RotateKey   { #[serde(rename = "keyId")] key_id: String, #[serde(rename = "callerId")] caller_id: String },
    DestroyKey  { #[serde(rename = "keyId")] key_id: String, #[serde(rename = "callerId")] caller_id: String },
    Health      { #[serde(rename = "callerId")] caller_id: String },
    Backup      { #[serde(rename = "callerId")] caller_id: String },
}

/// Policy applied to a key at generation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPolicy {
    pub allow_encrypt: bool,
    pub allow_decrypt: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_sign:    Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_operations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at:    Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_callers: Option<Vec<String>>,
}

impl KeyPolicy {
    pub fn encrypt_decrypt() -> Self {
        Self { allow_encrypt: true, allow_decrypt: true, allow_sign: None,
               max_operations: None, expires_at: None, allowed_callers: None }
    }
    pub fn sign_only() -> Self {
        Self { allow_encrypt: false, allow_decrypt: false, allow_sign: Some(true),
               max_operations: None, expires_at: None, allowed_callers: None }
    }
}

/// Generic response envelope from the PyHSM daemon.
#[derive(Debug, Deserialize)]
pub struct HsmResponse {
    pub ok:    bool,
    pub data:  Option<serde_json::Value>,
    pub error: Option<String>,
}

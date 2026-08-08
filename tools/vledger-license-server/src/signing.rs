//! License signing logic.
//!
//! Mirrors the canonical payload construction in `vledger-license-gen` exactly
//! so signatures produced here are accepted by every VectorLedger binary.
//!
//! ## Canonical payload
//! A compact JSON object with keys in ASCII sort order:
//! `email`, `expires_at`, `features`, `issued_at`, `licensee`, `tier`.
//! No whitespace.  The `signature` field is never included in what is signed.
//!
//! ## Grace period
//! `expiry_for_period_end(billing_end)` adds the 7-day grace period so
//! a missed payment doesn't cut off a customer the moment their billing
//! period ends.

use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::error::ServerError;

// ── Feature sets ──────────────────────────────────────────────────────────────

/// Returns the default feature list for a tier.
/// Must stay in sync with `vledger-license-gen` and `tier.rs`.
pub fn features_for_tier(tier: &str) -> Vec<&'static str> {
    match tier {
        "starter"    => vec!["pgwire"],
        "growth"     => vec!["pgwire", "replication",
                             "compliance_report", "audit_export_unlimited"],
        "enterprise" => vec!["pgwire", "replication", "hsm",
                             "compliance_report", "audit_export_unlimited",
                             "multi_node"],
        _            => vec![],  // free
    }
}

// ── Expiry helpers ────────────────────────────────────────────────────────────

/// Given the end of a Stripe billing period (as a Unix timestamp), return
/// the `expires_at` string we embed in the license: period end + 7 days grace.
///
/// The 7-day grace period ensures a customer whose card fails on renewal
/// day doesn't lose access instantly — Stripe will retry for several days
/// before cancelling the subscription, and the grace period covers that window.
pub fn expiry_for_period_end(period_end_unix: i64) -> String {
    let period_end = chrono::DateTime::from_timestamp(period_end_unix, 0)
        .unwrap_or_else(Utc::now)
        .date_naive();

    (period_end + Duration::days(7))
        .format("%Y-%m-%d")
        .to_string()
}

/// Convenience: expiry for a monthly subscription starting now.
/// Used when Stripe doesn't provide `current_period_end` (e.g. on
/// `checkout.session.completed` before the first invoice fires).
pub fn expiry_monthly_from_now() -> String {
    (Utc::now().date_naive() + Duration::days(30 + 7))
        .format("%Y-%m-%d")
        .to_string()
}

// ── Signing ───────────────────────────────────────────────────────────────────

/// Issue a signed `license.json` payload string.
///
/// `signing_key_hex` — hex-encoded 32-byte Ed25519 private key loaded from
/// the `VLEDGER_LICENSE_SIGNING_KEY` environment variable at startup.
pub fn issue_license(
    signing_key_hex:  &str,
    licensee:         &str,
    email:            &str,
    tier:             &str,
    expires_at:       &str,       // YYYY-MM-DD
    features_override: Option<Vec<String>>,
) -> Result<(String, String), ServerError> {
    // Resolve feature list.
    let features: Vec<String> = features_override.unwrap_or_else(|| {
        features_for_tier(tier)
            .iter()
            .map(|s| s.to_string())
            .collect()
    });

    let issued_at = Utc::now().format("%Y-%m-%d").to_string();

    // ── Build canonical payload (identical to vledger-license-gen) ────────
    let features_val: Vec<Value> = features.iter()
        .map(|f| Value::String(f.clone()))
        .collect();

    let mut map = BTreeMap::new();
    map.insert("email",      Value::String(email.to_string()));
    map.insert("expires_at", Value::String(expires_at.to_string()));
    map.insert("features",   Value::Array(features_val.clone()));
    map.insert("issued_at",  Value::String(issued_at.clone()));
    map.insert("licensee",   Value::String(licensee.to_string()));
    map.insert("tier",       Value::String(tier.to_string()));

    let payload = serde_json::to_vec(&map)
        .map_err(|e| ServerError::Signing(e.to_string()))?;

    // ── Sign ──────────────────────────────────────────────────────────────
    let privkey_bytes = hex::decode(signing_key_hex.trim())
        .map_err(|e| ServerError::Signing(format!("invalid signing key hex: {e}")))?;
    let privkey_arr: [u8; 32] = privkey_bytes.try_into()
        .map_err(|_| ServerError::Signing("signing key must be 32 bytes".into()))?;
    let signing_key = SigningKey::from_bytes(&privkey_arr);
    let signature   = signing_key.sign(&payload);
    let sig_hex     = hex::encode(signature.to_bytes());

    // ── Assemble final license.json ───────────────────────────────────────
    let license = json!({
        "licensee":   licensee,
        "email":      email,
        "tier":       tier,
        "issued_at":  issued_at,
        "expires_at": expires_at,
        "features":   features,
        "signature":  sig_hex,
    });

    let license_json = serde_json::to_string_pretty(&license)
        .map_err(|e| ServerError::Signing(e.to_string()))?;

    // Also return the comma-separated features string for the DB record.
    let features_csv = features.join(",");

    Ok((license_json, features_csv))
}

//! LicenseStore — loads, verifies, and caches the active license.

use std::path::Path;

use chrono::{NaiveDate, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::LicenseError;
use crate::tier::{Feature, LicenseTier};

// ── VectorGuard Labs license-signing public key ───────────────────────────────
//
// This public key is used to verify all VectorLedger license files.
// The corresponding private key is kept offline at VectorGuard Labs and
// is NEVER embedded in this binary.
//
// To rotate: generate a new keypair with `vledger-license-gen keygen`,
// update this constant, and re-release the binary.
//
// Generated with: vledger-license-gen keygen
// Key ID: vgl-license-v1
const VECTORGUARD_LICENSE_PUBKEY_HEX: &str =
    "9cf73a416943d55255a4943d2c839560454869ff8ea2fa74c33e787d70e09b14";

// ── License file structure (as stored in license.json) ───────────────────────

/// The on-disk representation of a license file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    /// Name of the licensee organisation.
    pub licensee:   String,
    /// Contact email for the license.
    pub email:      String,
    /// License tier: free, growth, enterprise.
    pub tier:       String,
    /// ISO 8601 date when the license was issued (YYYY-MM-DD).
    pub issued_at:  String,
    /// ISO 8601 date when the license expires (YYYY-MM-DD).
    pub expires_at: String,
    /// List of feature strings enabled by this license.
    pub features:   Vec<String>,
    /// Hex-encoded Ed25519 signature over `canonical_payload()`.
    pub signature:  String,
}

impl LicenseFile {
    /// The canonical bytes that are signed.  Deterministic — sorted keys,
    /// no whitespace variation.  Covers every field except `signature`.
    pub fn canonical_payload(&self) -> Vec<u8> {
        // Build a deterministic JSON object with sorted keys.
        let features_json: Vec<serde_json::Value> = self.features
            .iter()
            .map(|f| serde_json::Value::String(f.clone()))
            .collect();

        let payload = serde_json::json!({
            "email":      self.email,
            "expires_at": self.expires_at,
            "features":   features_json,
            "issued_at":  self.issued_at,
            "licensee":   self.licensee,
            "tier":       self.tier,
        });

        // Compact (no whitespace) JSON — field order is alphabetical via
        // serde_json's BTreeMap ordering when using json! macro with
        // object literals (keys are inserted in source order, not sorted).
        // Use explicit BTreeMap for guaranteed sort order.
        let mut map = std::collections::BTreeMap::new();
        map.insert("email",      serde_json::Value::String(self.email.clone()));
        map.insert("expires_at", serde_json::Value::String(self.expires_at.clone()));
        map.insert("features",   serde_json::Value::Array(features_json));
        map.insert("issued_at",  serde_json::Value::String(self.issued_at.clone()));
        map.insert("licensee",   serde_json::Value::String(self.licensee.clone()));
        map.insert("tier",       serde_json::Value::String(self.tier.clone()));

        let _ = payload; // suppress unused warning
        serde_json::to_vec(&map).unwrap_or_default()
    }
}

// ── Active in-memory license ──────────────────────────────────────────────────

/// The active license loaded at startup.
#[derive(Debug, Clone)]
pub struct LicenseStore {
    pub licensee:   String,
    pub email:      String,
    pub tier:       LicenseTier,
    pub issued_at:  NaiveDate,
    pub expires_at: NaiveDate,
    pub features:   Vec<Feature>,
    /// true = loaded from a signed license.json; false = implicit free tier.
    pub is_signed:  bool,
}

impl LicenseStore {
    /// Load the license from `<data_dir>/license.json`, verify its signature,
    /// and return the active `LicenseStore`.
    ///
    /// If `license.json` does not exist, returns an in-memory Free tier
    /// license (no file required for free tier use).
    pub fn load_or_free(data_dir: &Path) -> Self {
        let license_path = data_dir.join("license.json");

        if !license_path.exists() {
            return Self::free();
        }

        match Self::load_from_file(&license_path) {
            Ok(store) => store,
            Err(e) => {
                // Log the error but fall back to Free so the server can still
                // start — just without paid features.
                eprintln!(
                    "⚠  License error: {e}\n   \
                     Falling back to Free tier. \
                     Fix license.json or contact support@vectorguardlabs.com"
                );
                Self::free()
            }
        }
    }

    /// Load and verify a license from an explicit path.  Returns an error
    /// if the file is missing, malformed, expired, or has an invalid signature.
    pub fn load_from_file(path: &Path) -> Result<Self, LicenseError> {
        let json = std::fs::read_to_string(path)?;
        let file: LicenseFile = serde_json::from_str(&json)?;

        // ── Signature verification ────────────────────────────────────────
        let pubkey_bytes = hex::decode(VECTORGUARD_LICENSE_PUBKEY_HEX)
            .map_err(|_| LicenseError::InvalidSignature)?;
        let pubkey_arr: [u8; 32] = pubkey_bytes.try_into()
            .map_err(|_| LicenseError::InvalidSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|_| LicenseError::InvalidSignature)?;

        let sig_bytes = hex::decode(&file.signature)
            .map_err(|_| LicenseError::InvalidSignature)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| LicenseError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_arr);

        let payload = file.canonical_payload();
        verifying_key.verify(&payload, &signature)
            .map_err(|_| LicenseError::InvalidSignature)?;

        // ── Expiry check ──────────────────────────────────────────────────
        let expires = NaiveDate::parse_from_str(&file.expires_at, "%Y-%m-%d")
            .map_err(|_| LicenseError::MalformedField { field: "expires_at".into() })?;
        let today = Utc::now().date_naive();
        if today > expires {
            return Err(LicenseError::Expired { expired_at: file.expires_at.clone() });
        }

        let issued = NaiveDate::parse_from_str(&file.issued_at, "%Y-%m-%d")
            .map_err(|_| LicenseError::MalformedField { field: "issued_at".into() })?;

        let tier: LicenseTier = file.tier.parse()
            .map_err(|_| LicenseError::MalformedField { field: "tier".into() })?;

        let features: Vec<Feature> = file.features.iter()
            .filter_map(|f| f.parse().ok())
            .collect();

        Ok(Self {
            licensee:   file.licensee,
            email:      file.email,
            tier,
            issued_at:  issued,
            expires_at: expires,
            features,
            is_signed:  true,
        })
    }

    /// Construct an implicit Free tier license (no file, no signature).
    pub fn free() -> Self {
        let today = Utc::now().date_naive();
        Self {
            licensee:   "unlicensed".into(),
            email:      String::new(),
            tier:       LicenseTier::Free,
            issued_at:  today,
            expires_at: NaiveDate::from_ymd_opt(9999, 12, 31).unwrap(),
            features:   vec![],
            is_signed:  false,
        }
    }

    /// Check whether `feature` is enabled on this license.
    /// Returns `Ok(())` if entitled, or a descriptive error if not.
    pub fn require_feature(&self, feature: Feature) -> Result<(), LicenseError> {
        if self.features.contains(&feature) {
            return Ok(());
        }
        Err(LicenseError::FeatureNotEntitled {
            feature,
            tier: self.tier.display_name().to_string(),
        })
    }

    /// Returns true if the feature is available (non-error version).
    pub fn has_feature(&self, feature: &Feature) -> bool {
        self.features.contains(feature)
    }

    /// Days remaining until expiry.  Returns `None` for the free (no-expiry) tier.
    pub fn days_remaining(&self) -> Option<i64> {
        if !self.is_signed {
            return None;
        }
        let today = Utc::now().date_naive();
        Some((self.expires_at - today).num_days())
    }

    /// Print a startup banner line summarising the active license.
    pub fn print_banner(&self) {
        if !self.is_signed {
            println!(
                "  License    : Free tier — \
                 upgrade at https://vectorguardlabs.com/pricing"
            );
        } else {
            let days = self.days_remaining().unwrap_or(0);
            println!(
                "  License    : {} — {} ({} days remaining, expires {})",
                self.tier,
                self.licensee,
                days,
                self.expires_at,
            );
            if days < 30 {
                println!(
                    "  ⚠  License expires in {days} days — \
                     renew at https://vectorguardlabs.com/renew"
                );
            }
        }
    }
}

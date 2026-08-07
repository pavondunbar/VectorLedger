//! License error types.

use thiserror::Error;

use crate::tier::Feature;

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("License file not found at {path}")]
    NotFound { path: String },

    #[error("License file is invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("License signature is invalid — file may have been tampered with")]
    InvalidSignature,

    #[error("License has expired (expired: {expired_at})")]
    Expired { expired_at: String },

    #[error(
        "Feature '{feature}' is not available on your {tier} license.\n\
         Upgrade at https://vectorguardlabs.com/pricing"
    )]
    FeatureNotEntitled { feature: Feature, tier: String },

    #[error("License field '{field}' is missing or malformed")]
    MalformedField { field: String },

    #[error("I/O error reading license: {0}")]
    Io(#[from] std::io::Error),
}

//! # vledger-license
//!
//! License tier enforcement for VectorLedger.
//!
//! ## How it works
//!
//! At startup, `vledger start` calls `LicenseStore::load_or_free(data_dir)`.
//! This reads `<data_dir>/license.json` if present and verifies the Ed25519
//! signature against the VectorGuard Labs public key baked into this binary.
//! If no license file exists, a `Free` tier license is returned in-memory
//! (no file required for free tier).
//!
//! Before enabling a gated feature (pgwire, replication, HSM) the binary
//! calls `license.require_feature(Feature::PgWire)?` — this returns `Ok(())`
//! or a descriptive `LicenseError::FeatureNotEntitled` with an upgrade URL.
//!
//! ## License file format (`license.json`)
//!
//! ```json
//! {
//!   "licensee":   "acme-corp",
//!   "email":      "ops@acme.com",
//!   "tier":       "growth",
//!   "issued_at":  "2026-08-06",
//!   "expires_at": "2027-08-06",
//!   "features":   ["pgwire", "replication", "hsm", "compliance_report",
//!                  "audit_export_unlimited", "multi_node"],
//!   "signature":  "<hex-encoded Ed25519 signature over canonical payload>"
//! }
//! ```
//!
//! The signature covers `canonical_payload()` — a deterministic JSON encoding
//! of all fields except `signature` itself.

pub mod error;
pub mod store;
pub mod tier;

pub use error::LicenseError;
pub use store::LicenseStore;
pub use tier::{Feature, LicenseTier};

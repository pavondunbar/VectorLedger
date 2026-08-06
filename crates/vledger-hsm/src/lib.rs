//! # vledger-hsm
//!
//! HSM integration for VectorLedger — Phase 3 Production Hardening.
//!
//! Provides:
//! - `pkcs11` module: `Pkcs11Provider` trait + `SoftHsmProvider`,
//!   `AwsCloudHsmProvider`, `AzureHsmProvider`, `HsmProviderConfig`.
//! - `client` module: raw PyHSM Unix-socket IPC client (`HsmClient`).
//! - `protocol` module: IPC wire types.
//! - `error` module: `HsmError`.

pub mod client;
pub mod error;
pub mod pkcs11;
pub mod protocol;

pub use client::{HsmClient, KeyProvider};
pub use error::HsmError;
pub use pkcs11::{
    AwsCloudHsmConfig, AwsCloudHsmProvider,
    AzureHsmConfig, AzureHsmProvider,
    HsmProviderConfig, Pkcs11Provider, SoftHsmProvider,
};
pub use protocol::KeyPolicy;

// Re-export async_trait so callers don't need it as a direct dep
pub use async_trait::async_trait;

//! # vledger-hsm
//!
//! HSM integration for VectorLedger — supports two deployment models:
//!
//! ## Model 1 — Local PyHSM (same server)
//! PyHSM and VectorLedger run on the same host.  Communication uses a Unix
//! domain socket (`/tmp/pyhsm.sock`) or TCP loopback on Windows.
//! Best for development, CI, and single-server deployments.
//!
//! ## Model 2 — Remote PyHSM (same-region, separate server)
//! PyHSM runs on a dedicated server in the same region's private subnet.
//! VectorLedger connects over TLS 1.3 with mutual certificate authentication
//! (mTLS).  Recommended for production.
//!
//! ## Modules
//! - `client`   — `HsmClient` (dispatches to local or remote transport).
//! - `remote`   — `RemotePyHsmConfig`, `HsmTransport`, TLS connector builder.
//! - `pkcs11`   — `Pkcs11Provider` trait + `SoftHsmProvider`, cloud adapters.
//! - `protocol` — IPC wire types (`HsmRequest`, `HsmResponse`, `KeyPolicy`).
//! - `error`    — `HsmError`.

pub mod client;
pub mod error;
pub mod pkcs11;
pub mod protocol;
pub mod remote;

pub use client::{default_pyhsm_address, HsmClient, KeyProvider};
pub use error::HsmError;
pub use pkcs11::{
    AwsCloudHsmConfig, AwsCloudHsmProvider, AzureHsmConfig, AzureHsmProvider, HsmProviderConfig,
    Pkcs11Provider, SoftHsmProvider,
};
pub use protocol::KeyPolicy;
pub use remote::{HsmTransport, RemotePyHsmConfig};

// Re-export async_trait so callers don't need it as a direct dep.
pub use async_trait::async_trait;

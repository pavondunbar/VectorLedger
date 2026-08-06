//! # vledger-secrets
//!
//! Secrets manager integration for VectorLedger.
//!
//! Provides a `MasterKeyProvider` async trait with four backends:
//!
//! | Backend          | Config tag       | Source                              |
//! |------------------|------------------|-------------------------------------|
//! | `EnvVar`         | `"env"`          | `VectorLedger_MASTER_KEY` env variable      |
//! | `File`           | `"file"`         | Hex file on disk (dev/fallback only)|
//! | `HashiCorpVault` | `"vault"`        | Vault KV v2 via HTTP API            |
//! | `AwsKms`         | `"aws_kms"`      | AWS KMS GenerateDataKey             |
//!
//! ## Usage
//! ```no_run
//! use vledger_secrets::{KeySourceConfig, build_provider};
//!
//! #[tokio::main]
//! async fn main() {
//!     let cfg = KeySourceConfig::from_file("vledger-data/keys/key_source.json").unwrap();
//!     let provider = build_provider(&cfg).unwrap();
//!     let key = provider.load_master_key().await.unwrap();
//!     // key is a zeroized 32-byte array
//! }
//! ```
//!
//! ## Security notes
//! - `EnvVar` and `File` backends are suitable for development and CI.
//!   In production use `HashiCorpVault` or `AwsKms`.
//! - The 32-byte key is wrapped in `zeroize::Zeroizing` so it is cleared
//!   from memory when dropped.
//! - The `key_source.json` file contains only metadata (backend type,
//!   non-secret config). It never contains the key itself.

pub mod error;
pub mod provider;

pub use error::SecretsError;
pub use provider::{
    AwsKmsProvider, EnvVarProvider, FileProvider, HashiCorpVaultProvider,
    KeySourceConfig, MasterKeyProvider, build_provider,
};

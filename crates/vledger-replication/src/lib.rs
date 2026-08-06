//! # vledger-replication
//!
//! Synchronous hot-standby replication for VectorLedger.
//!
//! ## Security (Fix #9)
//! Every replica connection now requires a challenge-response handshake
//! before any WAL data is exchanged.  A 32-byte shared secret is stored at
//! `vledger-data/replication_secret.hex` (mode 0o600) on both nodes.
//!
//! ```text
//! Primary → Replica : AuthChallenge { nonce: "<64 hex>" }
//! Replica → Primary : AuthResponse  { mac:   "<64 hex>" }
//!    where mac = BLAKE3-keyed(key=secret, data=nonce_bytes)
//! Primary → Replica : AuthResult    { ok: true | false }
//! ```
//!
//! ## Architecture
//! ```text
//! Primary node                         Replica node
//! ──────────────────────────────────   ──────────────────────────────────
//! LedgerStore::post_entry()            WalReceiver
//!   │                                     │  TCP auth + WAL stream
//!   ├─ WAL commit record written         ├─ receives WAL records
//!   ├─ WalShipper::ship(record)          ├─ writes to local WAL dir
//!   │   │ waits for replica ACK ◄────────└─ sends ACK(lsn)
//!   │   └─ returns Ok(lsn)
//!   └─ post_entry returns Ok() to caller
//! ```

pub mod config;
pub mod error;
pub mod primary;
pub mod protocol;
pub mod replica;
pub mod secret;
pub mod tls;

pub use config::{ReplicationConfig, ReplicationRole};
pub use error::ReplicationError;
pub use primary::WalShipper;
pub use replica::{ReplicaApplier, WalReceiver};

//! # vledger-transaction
//!
//! ACID transaction manager for VectorLedger.
//!
//! ## ACID guarantees
//!
//! | Property    | Mechanism                                                  |
//! |-------------|------------------------------------------------------------|
//! | Atomicity   | All mutations buffered; committed atomically via WAL       |
//! | Consistency | Constraint checks run before commit; rollback on violation |
//! | Isolation   | MVCC snapshot isolation; serializable via conflict detect  |
//! | Durability  | WAL fsync before Commit record; page store written after  |
//!
//! ## MVCC Model
//! Every row version carries `(tx_id_created, tx_id_deleted)`.
//! - A row is **visible** to transaction T if:
//!   - `tx_id_created < T.snapshot_tx_id` (committed before T started), AND
//!   - `tx_id_deleted == 0` OR `tx_id_deleted >= T.snapshot_tx_id` (not yet
//!     deleted from T's perspective).

pub mod error;
pub mod mvcc;
pub mod tx;
pub mod manager;

pub use error::TxError;
pub use mvcc::{RowVersion, Visibility};
pub use tx::{Transaction, TxState};
pub use manager::TransactionManager;

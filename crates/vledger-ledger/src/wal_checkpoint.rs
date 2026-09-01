//! WAL startup checkpoint — records which WAL segments are already fully
//! captured in the SQLite entry index so startup can skip them.
//!
//! ## File format
//!
//! `<data_dir>/wal-checkpoint.json`:
//! ```json
//! {
//!   "sqlite_max_sequence": 25000000,
//!   "first_needed_segment": 322
//! }
//! ```
//!
//! ## Semantics
//!
//! - `sqlite_max_sequence`: the highest entry sequence number confirmed
//!   present in the SQLite index at the time the checkpoint was written.
//! - `first_needed_segment`: the index of the first WAL segment that may
//!   contain entries with sequence > sqlite_max_sequence. All segments
//!   before this index can be skipped on the next startup.
//!
//! The checkpoint is written after every successful `LedgerStore::open()`
//! and after every successful `LedgerStore::open_for_import()`. It is
//! read at the start of `replay_from_wal_mode()`.

use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalCheckpoint {
    /// Highest entry sequence number present in the SQLite index.
    pub sqlite_max_sequence: u64,
    /// Index of the first WAL segment that may have entries not yet in SQLite.
    /// All segments with index < this value can be skipped on startup.
    pub first_needed_segment: u64,
}

impl WalCheckpoint {
    pub fn path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join("wal-checkpoint.json")
    }

    /// Read the checkpoint from disk, returning `None` if it doesn't exist
    /// or cannot be parsed (safe — missing checkpoint just means full replay).
    pub fn read(data_dir: &Path) -> Option<Self> {
        let p = Self::path(data_dir);
        let bytes = std::fs::read(&p).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Write the checkpoint atomically to disk.
    pub fn write(data_dir: &Path, cp: &WalCheckpoint) -> Result<(), std::io::Error> {
        let p = Self::path(data_dir);
        let tmp = p.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(cp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }
}

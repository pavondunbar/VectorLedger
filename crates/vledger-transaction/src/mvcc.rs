//! MVCC (Multi-Version Concurrency Control) visibility logic.
//!
//! VectorLedger never overwrites rows.  Every mutation appends a new version
//! and marks the old version with a `tx_id_deleted`.  Readers use their
//! snapshot's `tx_id` to determine which version is visible to them.

use serde::{Deserialize, Serialize};

/// A single version of a row in the MVCC chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowVersion {
    /// Transaction ID that created this version.
    pub tx_id_created: u64,
    /// Transaction ID that deleted this version (0 = still live).
    pub tx_id_deleted: u64,
    /// Monotonic sequence within the creating transaction.
    pub row_sequence: u32,
    /// Serialized row data.
    pub data: Vec<u8>,
    /// BLAKE3 hash of `data` for integrity.
    pub data_hash: vledger_crypto::Hash,
    /// Hash of the previous version in this row's chain (ZERO_HASH if first).
    pub prev_hash: vledger_crypto::Hash,
}

/// Visibility result for a row version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// This version is visible to the querying transaction.
    Visible,
    /// This version was created after the snapshot — not visible.
    TooNew,
    /// This version has been deleted before the snapshot — not visible.
    Deleted,
}

/// Determine whether `version` is visible to a transaction with `snapshot_tx_id`.
///
/// Snapshot isolation rules:
/// - Version is visible if it was created by a committed tx strictly before the
///   snapshot, and has not been deleted by a committed tx before the snapshot.
///
/// In a full implementation the committed-tx set would be consulted.
/// Here we use the simplified model: tx_id < snapshot_tx_id means committed.
pub fn is_visible(version: &RowVersion, snapshot_tx_id: u64) -> Visibility {
    if version.tx_id_created >= snapshot_tx_id {
        return Visibility::TooNew;
    }
    if version.tx_id_deleted != 0 && version.tx_id_deleted < snapshot_tx_id {
        return Visibility::Deleted;
    }
    Visibility::Visible
}

/// Given a list of versions in ascending `tx_id_created` order, return the
/// latest version visible to `snapshot_tx_id`.
pub fn latest_visible<'a>(
    versions: &'a [RowVersion],
    snapshot_tx_id: u64,
) -> Option<&'a RowVersion> {
    versions
        .iter()
        .rev()
        .find(|v| is_visible(v, snapshot_tx_id) == Visibility::Visible)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_version(created: u64, deleted: u64) -> RowVersion {
        RowVersion {
            tx_id_created: created,
            tx_id_deleted: deleted,
            row_sequence: 0,
            data: vec![],
            data_hash: vledger_crypto::ZERO_HASH,
            prev_hash: vledger_crypto::ZERO_HASH,
        }
    }

    #[test]
    fn visible_when_created_before_snapshot() {
        let v = make_version(5, 0);
        assert_eq!(is_visible(&v, 10), Visibility::Visible);
    }

    #[test]
    fn too_new_when_created_at_snapshot() {
        let v = make_version(10, 0);
        assert_eq!(is_visible(&v, 10), Visibility::TooNew);
    }

    #[test]
    fn deleted_before_snapshot_not_visible() {
        let v = make_version(5, 7);
        assert_eq!(is_visible(&v, 10), Visibility::Deleted);
    }

    #[test]
    fn deleted_after_snapshot_still_visible() {
        let v = make_version(5, 12);
        assert_eq!(is_visible(&v, 10), Visibility::Visible);
    }

    #[test]
    fn latest_visible_picks_newest_eligible() {
        let versions = vec![
            make_version(1, 0),
            make_version(3, 0),
            make_version(8, 0),  // too new for snapshot=7
        ];
        let v = latest_visible(&versions, 7).unwrap();
        assert_eq!(v.tx_id_created, 3);
    }
}

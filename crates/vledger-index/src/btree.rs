//! In-memory B-tree primary key index.
//!
//! Maps `key: Vec<u8>` → `(page_id: u64, slot_id: u16)`.
//! Backed by `std::collections::BTreeMap` in Phase 1.

use std::collections::BTreeMap;

use crate::error::IndexError;

/// Location of a row within the page store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowLocation {
    pub page_id: u64,
    pub slot_id: u16,
}

/// A sorted, in-memory key → RowLocation index.
pub struct BTreeIndex {
    map: BTreeMap<Vec<u8>, RowLocation>,
    unique: bool,
}

impl BTreeIndex {
    /// Create a new unique index.
    pub fn new_unique() -> Self {
        Self { map: BTreeMap::new(), unique: true }
    }

    /// Create a new non-unique index.
    pub fn new() -> Self {
        Self { map: BTreeMap::new(), unique: false }
    }

    /// Insert a key → location mapping.
    pub fn insert(&mut self, key: Vec<u8>, location: RowLocation) -> Result<(), IndexError> {
        if self.unique && self.map.contains_key(&key) {
            return Err(IndexError::DuplicateKey(hex::encode(&key)));
        }
        self.map.insert(key, location);
        Ok(())
    }

    /// Look up a key.
    pub fn get(&self, key: &[u8]) -> Option<RowLocation> {
        self.map.get(key).copied()
    }

    /// Remove a key (used for MVCC delete markers).
    pub fn remove(&mut self, key: &[u8]) -> Option<RowLocation> {
        self.map.remove(key)
    }

    /// Range scan: returns all (key, location) pairs in [start, end).
    pub fn range<'a>(
        &'a self,
        start: &[u8],
        end: &[u8],
    ) -> impl Iterator<Item = (&'a Vec<u8>, &'a RowLocation)> {
        self.map.range(start.to_vec()..end.to_vec())
    }

    /// Number of entries in the index.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for BTreeIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_lookup() {
        let mut idx = BTreeIndex::new_unique();
        idx.insert(b"key1".to_vec(), RowLocation { page_id: 1, slot_id: 0 }).unwrap();
        assert_eq!(idx.get(b"key1"), Some(RowLocation { page_id: 1, slot_id: 0 }));
    }

    #[test]
    fn duplicate_key_unique_index_fails() {
        let mut idx = BTreeIndex::new_unique();
        idx.insert(b"k".to_vec(), RowLocation { page_id: 1, slot_id: 0 }).unwrap();
        assert!(idx.insert(b"k".to_vec(), RowLocation { page_id: 2, slot_id: 0 }).is_err());
    }
}

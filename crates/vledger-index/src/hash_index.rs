//! In-memory hash index for O(1) point lookups.

use std::collections::HashMap;
use crate::btree::RowLocation;

pub struct HashIndex {
    map: HashMap<Vec<u8>, Vec<RowLocation>>,
}

impl HashIndex {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }

    pub fn insert(&mut self, key: Vec<u8>, location: RowLocation) {
        self.map.entry(key).or_default().push(location);
    }

    pub fn get(&self, key: &[u8]) -> Option<&Vec<RowLocation>> {
        self.map.get(key)
    }

    pub fn remove_all(&mut self, key: &[u8]) -> Option<Vec<RowLocation>> {
        self.map.remove(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Default for HashIndex {
    fn default() -> Self {
        Self::new()
    }
}

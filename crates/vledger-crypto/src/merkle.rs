//! Binary Merkle tree over page hashes.
//!
//! Used to produce a single root hash that commits to the entire database
//! state.  Clients can verify that a specific page (or row) is part of the
//! committed state using a compact Merkle proof without downloading the whole
//! database.
//!
//! ## Algorithm
//! Standard binary Merkle tree:
//! - Leaves are `hash_leaf(data)`.
//! - Internal nodes are `hash_node(left, right)`.
//! - If the number of leaves is odd, the last leaf is duplicated.
//! - Domain separation (0x00 for leaves, 0x01 for nodes) prevents
//!   second-preimage attacks.

use crate::hash::{hash_leaf, hash_node};
use crate::{CryptoError, Hash};

/// Build a Merkle tree from a list of raw data items and return the root hash.
///
/// Returns `ZERO_HASH` for an empty input.
pub fn merkle_root(items: &[impl AsRef<[u8]>]) -> Hash {
    if items.is_empty() {
        return crate::ZERO_HASH;
    }

    let mut layer: Vec<Hash> = items.iter().map(|item| hash_leaf(item.as_ref())).collect();

    while layer.len() > 1 {
        layer = next_layer(&layer);
    }

    layer[0]
}

/// Compute one level up in the Merkle tree.
fn next_layer(layer: &[Hash]) -> Vec<Hash> {
    let mut next = Vec::with_capacity((layer.len() + 1) / 2);
    let mut i = 0;
    while i < layer.len() {
        let left = &layer[i];
        // Duplicate last node if the layer has an odd count
        let right = if i + 1 < layer.len() {
            &layer[i + 1]
        } else {
            &layer[i]
        };
        next.push(hash_node(left, right));
        i += 2;
    }
    next
}

/// A single step in a Merkle proof.
#[derive(Debug, Clone)]
pub struct ProofStep {
    /// The sibling hash at this level.
    pub sibling: Hash,
    /// Whether the sibling is on the left (`true`) or right (`false`).
    pub sibling_is_left: bool,
}

/// A Merkle membership proof.  The client can independently verify that
/// `leaf_data` is part of the tree with the given `root`.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Index of the leaf being proven.
    pub leaf_index: usize,
    /// Hash of the leaf value.
    pub leaf_hash: Hash,
    /// Proof path from leaf to root.
    pub path: Vec<ProofStep>,
    /// The expected root hash.
    pub root: Hash,
}

impl MerkleProof {
    /// Verify this proof.  Returns `Ok(())` if the proof is valid.
    pub fn verify(&self) -> Result<(), CryptoError> {
        let mut current = self.leaf_hash;
        for step in &self.path {
            current = if step.sibling_is_left {
                hash_node(&step.sibling, &current)
            } else {
                hash_node(&current, &step.sibling)
            };
        }
        if current == self.root {
            Ok(())
        } else {
            Err(CryptoError::MerkleProofInvalid)
        }
    }
}

/// Build a Merkle proof for the item at `leaf_index`.
///
/// Returns `None` if `leaf_index` is out of bounds.
pub fn merkle_proof(items: &[impl AsRef<[u8]>], leaf_index: usize) -> Option<MerkleProof> {
    if items.is_empty() || leaf_index >= items.len() {
        return None;
    }

    let mut layer: Vec<Hash> = items.iter().map(|item| hash_leaf(item.as_ref())).collect();
    let leaf_hash = layer[leaf_index];
    let root = merkle_root(items);

    let mut path = Vec::new();
    let mut index = leaf_index;

    while layer.len() > 1 {
        let sibling_index = if index % 2 == 0 {
            // Current is left child; sibling is to the right (or duplicate)
            (index + 1).min(layer.len() - 1)
        } else {
            // Current is right child; sibling is to the left
            index - 1
        };

        let sibling_is_left = sibling_index < index;
        path.push(ProofStep {
            sibling: layer[sibling_index],
            sibling_is_left,
        });

        layer = next_layer(&layer);
        index /= 2;
    }

    Some(MerkleProof {
        leaf_index,
        leaf_hash,
        path,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_deterministic() {
        let items: Vec<&[u8]> = vec![b"page1", b"page2", b"page3", b"page4"];
        let r1 = merkle_root(&items);
        let r2 = merkle_root(&items);
        assert_eq!(r1, r2);
    }

    #[test]
    fn single_item_root() {
        let items: Vec<&[u8]> = vec![b"only_page"];
        let root = merkle_root(&items);
        assert_ne!(root, crate::ZERO_HASH);
    }

    #[test]
    fn empty_root_is_zero() {
        let items: Vec<&[u8]> = vec![];
        assert_eq!(merkle_root(&items), crate::ZERO_HASH);
    }

    #[test]
    fn proof_verifies_for_each_leaf() {
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d", b"e"];
        for i in 0..items.len() {
            let proof = merkle_proof(&items, i).unwrap();
            proof
                .verify()
                .expect(&format!("proof failed for index {i}"));
        }
    }

    #[test]
    fn tampered_leaf_invalidates_proof() {
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let mut proof = merkle_proof(&items, 1).unwrap();
        // Replace the leaf hash with a different value
        proof.leaf_hash[0] ^= 0xFF;
        assert!(proof.verify().is_err());
    }

    #[test]
    fn different_data_different_root() {
        let items1: Vec<&[u8]> = vec![b"a", b"b"];
        let items2: Vec<&[u8]> = vec![b"a", b"c"];
        assert_ne!(merkle_root(&items1), merkle_root(&items2));
    }
}

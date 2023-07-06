#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};
use error::TrieError;
use hasher::Hasher;
use trie::PatriciaTrie;

mod error;
mod nibble;
mod node;
mod trie;

pub fn verify_proof<H: Hasher>(
    root_hash: &[u8],
    key: &[u8],
    proof: Vec<Vec<u8>>,
    hasher: H,
) -> Result<Option<Vec<u8>>, TrieError> {
    let mut memdb = MemoyDB::new();
    for node_encoded in proof.into_iter() {
        let hash = hasher.digest(&node_encoded);

        if root_hash.eq(&hash) || node_encoded.len() >= H::LENGTH {
            memdb.insert(hash, node_encoded);
        }
    }

    PatriciaTrie::from(memdb, hasher, root_hash)
        .or(Err(TrieError::InvalidProof))?
        .get(key)
        .or(Err(TrieError::InvalidProof))
}

#[derive(Debug)]
pub(crate) struct MemoyDB {
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemoyDB {
    fn new() -> Self {
        Self {
            storage: BTreeMap::new(),
        }
    }

    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.storage.insert(key, value);
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(key).cloned()
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use cita_trie::MemoryDB;
    use cita_trie::{PatriciaTrie, Trie};
    use hasher::HasherKeccak;
    use std::sync::Arc;

    use super::verify_proof;

    #[test]
    fn test_verify() {
        let memdb = Arc::new(MemoryDB::new(true));
        let hasher = Arc::new(HasherKeccak::new());

        let key = "test-key".as_bytes();
        let value = "test-value".as_bytes();

        let (root, proof) = {
            let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
            trie.insert(key.to_vec(), value.to_vec()).unwrap();

            let v = trie.get(key).unwrap();
            assert_eq!(Some(value.to_vec()), v);
            (trie.root().unwrap(), trie.get_proof(key).unwrap())
        };

        let a = verify_proof(&root, key, proof, HasherKeccak::new())
            .unwrap()
            .unwrap();
        assert_eq!(a, value)
    }
}

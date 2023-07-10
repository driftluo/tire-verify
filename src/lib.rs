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
    use rand::Rng;
    use std::{format, sync::Arc, vec, vec::Vec};

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

    // proof test ref:
    // - https://github.com/ethereum/go-ethereum/blob/master/trie/proof_test.go
    // - https://github.com/ethereum/py-trie/blob/master/tests/test_proof.py
    #[test]
    fn test_proof_basic() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::new(HasherKeccak::new()));
        trie.insert(b"doe".to_vec(), b"reindeer".to_vec()).unwrap();
        trie.insert(b"dog".to_vec(), b"puppy".to_vec()).unwrap();
        trie.insert(b"dogglesworth".to_vec(), b"cat".to_vec())
            .unwrap();
        let root = trie.root().unwrap();
        let r = format!("0x{}", hex::encode(trie.root().unwrap()));
        assert_eq!(
            r.as_str(),
            "0x8aad789dff2f538bca5d8ea56e8abe10f4c7ba3a5dea95fea4cd6e7c3a1168d3"
        );

        // proof of key exists
        let proof = trie.get_proof(b"doe").unwrap();
        let expected = vec![
            "e5831646f6a0db6ae1fda66890f6693f36560d36b4dca68b4d838f17016b151efe1d4c95c453",
            "f83b8080808080ca20887265696e6465657280a037efd11993cb04a54048c25320e9f29c50a432d28afdf01598b2978ce1ca3068808080808080808080",
        ];
        assert_eq!(
            proof
                .clone()
                .into_iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            expected
        );
        let value = trie.verify_proof(&root, b"doe", proof.clone()).unwrap();
        assert_eq!(value, Some(b"reindeer".to_vec()));
        assert_eq!(
            verify_proof(&root, b"doe", proof, HasherKeccak::new()).unwrap(),
            Some(b"reindeer".to_vec())
        );

        // proof of key not exist
        let proof = trie.get_proof(b"dogg").unwrap();
        let expected = vec![
            "e5831646f6a0db6ae1fda66890f6693f36560d36b4dca68b4d838f17016b151efe1d4c95c453",
            "f83b8080808080ca20887265696e6465657280a037efd11993cb04a54048c25320e9f29c50a432d28afdf01598b2978ce1ca3068808080808080808080",
            "e4808080808080ce89376c6573776f72746883636174808080808080808080857075707079",
        ];
        assert_eq!(
            proof
                .clone()
                .into_iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            expected
        );
        let value = trie.verify_proof(&root, b"dogg", proof.clone()).unwrap();
        assert_eq!(value, None);
        assert_eq!(
            verify_proof(&root, b"dogg", proof, HasherKeccak::new()).unwrap(),
            None
        );

        // empty proof
        let proof = vec![];
        let value = trie.verify_proof(&root, b"doe", proof.clone());
        assert!(verify_proof(&root, b"doe", proof, HasherKeccak::new()).is_err());
        assert!(value.is_err());

        // bad proof
        let proof = vec![b"aaa".to_vec(), b"ccc".to_vec()];
        let value = trie.verify_proof(&root, b"doe", proof.clone());
        assert!(value.is_err());
        assert!(verify_proof(&root, b"doe", proof, HasherKeccak::new()).is_err());
    }

    #[test]
    fn test_proof_random() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::new(HasherKeccak::new()));
        let mut rng = rand::thread_rng();
        let mut keys = vec![];
        for _ in 0..100 {
            let random_bytes: Vec<u8> = (0..rng.gen_range(2..30))
                .map(|_| rand::random::<u8>())
                .collect();
            trie.insert(random_bytes.to_vec(), random_bytes.clone())
                .unwrap();
            keys.push(random_bytes.clone());
        }
        for k in keys.clone().into_iter() {
            trie.insert(k.clone(), k.clone()).unwrap();
        }
        let root = trie.root().unwrap();
        for k in keys.into_iter() {
            let proof = trie.get_proof(&k).unwrap();
            let value = trie
                .verify_proof(&root, &k, proof.clone())
                .unwrap()
                .unwrap();
            assert_eq!(value, k);
            assert_eq!(
                verify_proof(&root, &k, proof, HasherKeccak::new())
                    .unwrap()
                    .unwrap(),
                k
            );
        }
    }

    #[test]
    fn test_proof_one_element() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::new(HasherKeccak::new()));
        trie.insert(b"k".to_vec(), b"v".to_vec()).unwrap();
        let root = trie.root().unwrap();
        let proof = trie.get_proof(b"k").unwrap();
        assert_eq!(proof.len(), 1);
        let value = trie.verify_proof(&root, b"k", proof.clone()).unwrap();
        assert_eq!(value, Some(b"v".to_vec()));

        // remove key does not affect the verify process
        trie.remove(b"k").unwrap();
        let _root = trie.root().unwrap();
        let value = trie.verify_proof(&root, b"k", proof.clone()).unwrap();
        assert_eq!(value, Some(b"v".to_vec()));
        assert_eq!(
            verify_proof(&root, b"k", proof, HasherKeccak::new()).unwrap(),
            Some(b"v".to_vec())
        );
    }
}

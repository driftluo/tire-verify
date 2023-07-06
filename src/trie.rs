use crate::{
    error::TrieError,
    nibble::Nibbles,
    node::{empty_children, Node},
    MemoyDB,
};
use alloc::vec::Vec;

use hasher::Hasher;
use rlp::{Prototype, Rlp};

#[derive(Debug)]
pub(crate) struct PatriciaTrie<H> {
    root: Node,
    db: MemoyDB,
    _hasher: H,
}

impl<H> PatriciaTrie<H>
where
    H: Hasher,
{
    pub fn from(db: MemoyDB, hasher: H, root: &[u8]) -> Result<Self, TrieError> {
        match db.get(root) {
            Some(data) => {
                let mut trie = Self {
                    root: Node::Empty,

                    db,
                    _hasher: hasher,
                };

                trie.root = trie.decode_node(&data)?;
                Ok(trie)
            }
            None => Err(TrieError::InvalidStateRoot),
        }
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        self.get_at(self.root.clone(), &Nibbles::from_raw(key.to_vec(), true))
    }

    fn decode_node(&self, data: &[u8]) -> Result<Node, TrieError> {
        let r = Rlp::new(data);

        match r.prototype()? {
            Prototype::Data(0) => Ok(Node::Empty),
            Prototype::List(2) => {
                let key = r.at(0)?.data()?;
                let key = Nibbles::from_compact(key.to_vec());

                if key.is_leaf() {
                    Ok(Node::from_leaf(key, r.at(1)?.data()?.to_vec()))
                } else {
                    let n = self.decode_node(r.at(1)?.as_raw())?;

                    Ok(Node::from_extension(key, n))
                }
            }
            Prototype::List(17) => {
                let mut nodes = empty_children();
                #[allow(clippy::needless_range_loop)]
                for i in 0..nodes.len() {
                    let rlp_data = r.at(i)?;
                    let n = self.decode_node(rlp_data.as_raw())?;
                    nodes[i] = n;
                }

                // The last element is a value node.
                let value_rlp = r.at(16)?;
                let value = if value_rlp.is_empty() {
                    None
                } else {
                    Some(value_rlp.data()?.to_vec())
                };

                Ok(Node::from_branch(nodes, value))
            }
            _ => {
                if r.is_data() && r.size() == H::LENGTH {
                    Ok(Node::from_hash(r.data()?.to_vec()))
                } else {
                    Err(TrieError::InvalidData)
                }
            }
        }
    }

    fn get_at(&self, n: Node, partial: &Nibbles) -> Result<Option<Vec<u8>>, TrieError> {
        match n {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                let borrow_leaf = leaf;

                if &borrow_leaf.key == partial {
                    Ok(Some(borrow_leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(branch) => {
                let borrow_branch = branch;

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(borrow_branch.value.clone())
                } else {
                    let index = partial.at(0);
                    self.get_at(borrow_branch.children[index].clone(), &partial.offset(1))
                }
            }
            Node::Extension(extension) => {
                let extension = extension;

                let prefix = &extension.prefix;
                let match_len = partial.common_prefix(prefix);
                if match_len == prefix.len() {
                    self.get_at(extension.node.clone(), &partial.offset(match_len))
                } else {
                    Ok(None)
                }
            }
            Node::Hash(hash_node) => {
                let borrow_hash_node = hash_node;
                let n = self.recover_from_db(&borrow_hash_node.hash)?;
                self.get_at(n, partial)
            }
        }
    }

    fn recover_from_db(&self, key: &[u8]) -> Result<Node, TrieError> {
        match self.db.get(key) {
            Some(value) => Ok(self.decode_node(&value)?),
            None => Ok(Node::Empty),
        }
    }
}

use crate::nibble::Nibbles;
use alloc::{rc::Rc, vec::Vec};

#[derive(Debug, Clone)]
pub enum Node {
    Empty,
    Leaf(Rc<LeafNode>),
    Extension(Rc<ExtensionNode>),
    Branch(Rc<BranchNode>),
    Hash(Rc<HashNode>),
}

impl Node {
    pub fn from_leaf(key: Nibbles, value: Vec<u8>) -> Self {
        let leaf = Rc::new(LeafNode { key, value });
        Node::Leaf(leaf)
    }

    pub fn from_branch(children: [Node; 16], value: Option<Vec<u8>>) -> Self {
        let branch = Rc::new(BranchNode { children, value });
        Node::Branch(branch)
    }

    pub fn from_extension(prefix: Nibbles, node: Node) -> Self {
        let ext = Rc::new(ExtensionNode { prefix, node });
        Node::Extension(ext)
    }

    pub fn from_hash(hash: Vec<u8>) -> Self {
        let hash_node = Rc::new(HashNode { hash });
        Node::Hash(hash_node)
    }
}

#[derive(Debug)]
pub struct LeafNode {
    pub key: Nibbles,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct BranchNode {
    pub children: [Node; 16],
    pub value: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct ExtensionNode {
    pub prefix: Nibbles,
    pub node: Node,
}

#[derive(Debug)]
pub struct HashNode {
    pub hash: Vec<u8>,
}

pub fn empty_children() -> [Node; 16] {
    [
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
    ]
}

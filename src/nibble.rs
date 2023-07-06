use alloc::{vec, vec::Vec};
use core::cmp::min;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Nibbles {
    hex_data: Vec<u8>,
}

impl Nibbles {
    pub fn from_hex(hex: Vec<u8>) -> Self {
        Nibbles { hex_data: hex }
    }

    pub fn from_raw(raw: Vec<u8>, is_leaf: bool) -> Self {
        let mut hex_data = vec![];
        for item in raw.into_iter() {
            hex_data.push(item / 16);
            hex_data.push(item % 16);
        }
        if is_leaf {
            hex_data.push(16);
        }
        Nibbles { hex_data }
    }

    pub fn from_compact(compact: Vec<u8>) -> Self {
        let mut hex = vec![];
        let flag = compact[0];

        let mut is_leaf = false;
        match flag >> 4 {
            0x0 => {}
            0x1 => hex.push(flag % 16),
            0x2 => is_leaf = true,
            0x3 => {
                is_leaf = true;
                hex.push(flag % 16);
            }
            _ => panic!("invalid data"),
        }

        for item in &compact[1..] {
            hex.push(item / 16);
            hex.push(item % 16);
        }
        if is_leaf {
            hex.push(16);
        }

        Nibbles { hex_data: hex }
    }

    pub fn is_leaf(&self) -> bool {
        self.hex_data[self.hex_data.len() - 1] == 16
    }

    pub fn len(&self) -> usize {
        self.hex_data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn at(&self, i: usize) -> usize {
        self.hex_data[i] as usize
    }

    pub fn common_prefix(&self, other_partial: &Nibbles) -> usize {
        let s = min(self.len(), other_partial.len());
        let mut i = 0usize;
        while i < s {
            if self.at(i) != other_partial.at(i) {
                break;
            }
            i += 1;
        }
        i
    }

    pub fn offset(&self, index: usize) -> Nibbles {
        self.slice(index, self.hex_data.len())
    }

    pub fn slice(&self, start: usize, end: usize) -> Nibbles {
        Nibbles::from_hex(self.hex_data[start..end].to_vec())
    }
}

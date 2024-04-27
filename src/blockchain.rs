use crate::block::Block;
use crate::crypto::hash::H256;
use std::collections::HashMap;

pub struct Blockchain {
    hash_to_block: HashMap<H256, Block>,
    hash_to_height: HashMap<H256, u64>,
    tip: H256,
}

impl Blockchain {
    /// Create a new blockchain, only containing the genesis block
    pub fn new(genesis_block: Block) -> Self {
        let genesis_hash = genesis_block.clone().into();
        let mut blockchain = Blockchain {
            hash_to_block: HashMap::new(),
            hash_to_height: HashMap::new(),
            tip: genesis_hash,
        };
        blockchain.hash_to_block.insert(genesis_hash, genesis_block);
        blockchain.hash_to_height.insert(genesis_hash, 0);  // Genesis block at height 0
        blockchain
    }

    /// Insert a block into blockchain
    pub fn insert(&mut self, block: Block) {
        let block_hash = block.clone().into();
        if let Some(parent_hash) = block.parent_hash() {
            if self.hash_to_block.contains_key(&parent_hash) {
                let parent_height = *self.hash_to_height.get(&parent_hash).unwrap();
                self.hash_to_block.insert(block_hash, block);
                self.hash_to_height.insert(block_hash, parent_height + 1);

                // Update the tip if the new block's height is greater than the current tip's height
                let current_tip_height = *self.hash_to_height.get(&self.tip).unwrap();
                if parent_height + 1 > current_tip_height {
                    self.tip = block_hash;
                }
            }
        }
    }

    /// Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.tip
    }

    /// Get all blocks' hashes of the longest chain (for testing purposes)
    #[cfg(any(test, test_utilities))]
    pub fn all_blocks_in_longest_chain(&self) -> Vec<H256> {
        let mut current_hash = self.tip;
        let mut chain = vec![];

        while let Some(block) = self.hash_to_block.get(&current_hash) {
            chain.push(current_hash);
            if let Some(parent_hash) = block.parent_hash() {
                current_hash = *parent_hash;
            } else {
                break;
            }
        }

        chain.reverse();
        chain
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::block::test::generate_random_block;
    use crate::crypto::hash::Hashable;

    #[test]
    fn insert_one() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block = generate_random_block(&genesis_hash);
        blockchain.insert(&block);
        assert_eq!(blockchain.tip(), block.hash());

    }
}

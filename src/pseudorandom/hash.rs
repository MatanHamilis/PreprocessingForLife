use std::mem::{size_of, transmute};

use aes::{
    cipher::{BlockEncrypt, BlockEncryptMut, KeyInit},
    Aes128, Block,
};
use once_cell::sync::Lazy;

use crate::fields::GF128;
const HASH_BLOCK_SIZE: usize = size_of::<aes::Block>();
const HASH_KEY: [u8; HASH_BLOCK_SIZE] = [
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
];
static AES: Lazy<Aes128> = Lazy::new(|| Aes128::new_from_slice(&HASH_KEY).unwrap());
pub fn correlation_robust_hash_block(block: &mut Block) {
    AES.encrypt_block(block);
}

pub fn correlation_robust_hash_block_field(block: GF128) -> GF128 {
    AES.encrypt_block(&mut block.into());
    block
}
pub fn correlation_robust_hash_block_field_slice(block: &mut [GF128]) {
    let block =
        unsafe { std::slice::from_raw_parts_mut(block.as_mut_ptr() as *mut Block, block.len()) };
    AES.encrypt_blocks(block);
}

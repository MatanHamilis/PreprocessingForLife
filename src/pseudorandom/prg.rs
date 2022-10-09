use std::ops::{Deref, DerefMut};

use crate::xor_arrays;
#[cfg(feature = "aesni")]
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128, Block,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
pub const PRG_KEY_SIZE: usize = 16;

#[cfg(not(feature = "aesni"))]
pub fn double_prg(input: &PrgValue) -> (PrgValue, PrgValue) {
    let mut seed: [u8; 32] = [0; 32];
    input
        .iter()
        .take(32)
        .zip(seed.iter_mut())
        .for_each(|(input_item, seed_item)| *seed_item = *input_item);
    let mut chacha_rng = ChaCha8Rng::from_seed(seed);
    let mut output: [PrgValue; 2] = [PrgValue; 2];
    output.iter_mut().for_each(|arr| chacha_rng.fill_bytes(arr));
    (output[0], output[1])
}

#[cfg(feature = "aesni")]
const PRG_KEY: PrgValue = PrgValue([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
#[cfg(feature = "aesni")]
static AES: Lazy<Aes128> = Lazy::new(|| Aes128::new_from_slice(&PRG_KEY[..]).unwrap());

#[repr(align(16))]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Default, Clone, Copy)]
pub struct PrgValue([u8; PRG_KEY_SIZE]);
impl From<[u8; PRG_KEY_SIZE]> for PrgValue {
    fn from(value: [u8; PRG_KEY_SIZE]) -> Self {
        Self(value)
    }
}
impl From<PrgValue> for [u8; PRG_KEY_SIZE] {
    fn from(value: PrgValue) -> Self {
        value.0
    }
}
impl From<Block> for PrgValue {
    fn from(value: Block) -> Self {
        Self(value.into())
    }
}
impl From<PrgValue> for Block {
    fn from(value: PrgValue) -> Self {
        Block::from(*value)
    }
}
impl AsRef<[u8; PRG_KEY_SIZE]> for PrgValue {
    fn as_ref(&self) -> &[u8; PRG_KEY_SIZE] {
        &self.0
    }
}
impl AsMut<[u8; PRG_KEY_SIZE]> for PrgValue {
    fn as_mut(&mut self) -> &mut [u8; PRG_KEY_SIZE] {
        &mut self.0
    }
}
impl Deref for PrgValue {
    type Target = [u8; PRG_KEY_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for PrgValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "aesni")]
pub fn double_prg(input: &PrgValue) -> (PrgValue, PrgValue) {
    let mut blocks = [Block::from(*input); 2];
    blocks[1][0] = !blocks[1][0];
    AES.encrypt_blocks(&mut blocks);
    xor_arrays(&mut blocks[0].into(), input);
    xor_arrays(&mut blocks[1].into(), input);
    blocks[1][0] = !blocks[1][0];
    (blocks[0].into(), blocks[1].into())
}

pub fn double_prg_many(input: &[Block], output: &mut [Block]) {
    const BLOCK_SIZE: usize = 1 << 4;
    const SINGLE_THREAD_THRESH: usize = 1 << 10;
    let length = std::cmp::min(BLOCK_SIZE, input.len());
    output
        .chunks_mut(2 * SINGLE_THREAD_THRESH)
        .zip(input.chunks(SINGLE_THREAD_THRESH))
        .for_each(|(output_chunk, input_chunk)| {
            output_chunk
                .chunks_mut(2 * BLOCK_SIZE)
                .zip(input_chunk.chunks(BLOCK_SIZE))
                .for_each(|(output_chunk, input_chunk)| {
                    for i in 0..length {
                        output_chunk[2 * i] = input_chunk[i];
                        output_chunk[2 * i + 1] = input_chunk[i];
                        output_chunk[2 * i + 1][0] = !output_chunk[2 * i + 1][0];
                    }
                    AES.encrypt_blocks(output_chunk);
                    for i in 0..length {
                        xor_arrays(&mut output_chunk[2 * i].into(), &input_chunk[i].into());
                        xor_arrays(&mut output_chunk[2 * i + 1].into(), &input_chunk[i].into());
                        output_chunk[2 * i + 1][0] = !output_chunk[2 * i + 1][0];
                    }
                })
        });
}

pub fn double_prg_many_inplace(in_out: &mut [Block]) {
    const BLOCK_SIZE: usize = 1 << 3;
    if in_out.len() < 2 * BLOCK_SIZE {
        double_prg_many_inplace_parametrized::<1>(in_out);
    } else {
        double_prg_many_inplace_parametrized::<BLOCK_SIZE>(in_out);
    }
}
fn double_prg_many_inplace_parametrized<const BLOCK_SIZE: usize>(in_out: &mut [Block]) {
    let input_length = in_out.len() >> 1;
    for chunk_idx in (0..(input_length / BLOCK_SIZE)).rev() {
        let input: [_; BLOCK_SIZE] = core::array::from_fn(|i| in_out[BLOCK_SIZE * chunk_idx + i]);
        let output = &mut in_out[2 * (chunk_idx * BLOCK_SIZE)..2 * (chunk_idx + 1) * BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            output[2 * i] = input[i];
            output[2 * i + 1] = input[i];
            output[2 * i + 1][0] = !input[i][0];
        }
        AES.encrypt_blocks(output);
        for i in 0..BLOCK_SIZE {
            xor_arrays(&mut output[2 * i].into(), &input[i].into());
            xor_arrays(&mut output[2 * i + 1].into(), &input[i].into());
            output[2 * i + 1][0] = !output[2 * i + 1][0];
        }
    }
}

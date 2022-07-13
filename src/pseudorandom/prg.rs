use crate::xor_arrays;
#[cfg(feature = "aesni")]
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128, Block,
};
use once_cell::sync::Lazy;
pub const PRG_KEY_SIZE: usize = 16;

#[cfg(not(feature = "aesni"))]
pub fn double_prg(input: &[u8; PRG_KEY_SIZE]) -> ([u8; PRG_KEY_SIZE], [u8; PRG_KEY_SIZE]) {
    let mut seed: [u8; 32] = [0; 32];
    input
        .iter()
        .take(32)
        .zip(seed.iter_mut())
        .for_each(|(input_item, seed_item)| *seed_item = *input_item);
    let mut chacha_rng = ChaCha8Rng::from_seed(seed);
    let mut output: [[u8; PRG_KEY_SIZE]; 2] = [[0; PRG_KEY_SIZE]; 2];
    output.iter_mut().for_each(|arr| chacha_rng.fill_bytes(arr));
    (output[0], output[1])
}

#[cfg(feature = "aesni")]
const PRG_KEY: [u8; PRG_KEY_SIZE] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
#[cfg(feature = "aesni")]
static AES: Lazy<Aes128> = Lazy::new(|| Aes128::new_from_slice(&PRG_KEY).unwrap());

#[cfg(feature = "aesni")]
pub fn double_prg(input: &[u8; PRG_KEY_SIZE]) -> ([u8; PRG_KEY_SIZE], [u8; PRG_KEY_SIZE]) {
    let mut blocks = [Block::from(*input); 2];
    blocks[1][0] = !blocks[1][0];
    AES.encrypt_blocks(&mut blocks);
    xor_arrays(&mut blocks[0].into(), input);
    xor_arrays(&mut blocks[1].into(), input);
    blocks[1][0] = !blocks[1][0];
    unsafe {
        (
            std::mem::transmute(blocks[0]),
            std::mem::transmute(blocks[1]),
        )
    }
}

pub fn double_prg_many(input: &[Block], output: &mut [Block]) {
    const SINGLE_THREAD_THRESH: usize = 1 << 3;
    let length = std::cmp::min(SINGLE_THREAD_THRESH, input.len());
    output
        .chunks_mut(2 * SINGLE_THREAD_THRESH)
        .zip(input.chunks(SINGLE_THREAD_THRESH))
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
        });
}

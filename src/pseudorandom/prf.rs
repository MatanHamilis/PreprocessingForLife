use crate::pprf::bits_to_usize;
use crate::pprf::usize_to_bits;

use super::double_prg;
use super::double_prg_many;
use super::KEY_SIZE;
#[cfg(feature = "aesni")]
use aes::Block;
use serde::Deserialize;
use serde::Serialize;
use serde_big_array::BigArray;

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct PrfInput<const INPUT_LEN: usize>(#[serde(with = "BigArray")] [bool; INPUT_LEN]);
impl<const INPUT_LEN: usize> From<[bool; INPUT_LEN]> for PrfInput<INPUT_LEN> {
    fn from(v: [bool; INPUT_LEN]) -> Self {
        Self(v)
    }
}

impl<const INPUT_BITLEN: usize> From<PrfInput<INPUT_BITLEN>> for [bool; INPUT_BITLEN] {
    fn from(value: PrfInput<INPUT_BITLEN>) -> Self {
        value.0
    }
}

impl<const INPUT_BITLEN: usize> AsRef<[bool; INPUT_BITLEN]> for PrfInput<INPUT_BITLEN> {
    fn as_ref(&self) -> &[bool; INPUT_BITLEN] {
        &self.0
    }
}

impl<const INPUT_BITLEN: usize> From<usize> for PrfInput<INPUT_BITLEN> {
    fn from(v: usize) -> Self {
        Self(usize_to_bits(v))
    }
}

impl<const INPUT_BITLEN: usize> From<&PrfInput<INPUT_BITLEN>> for usize {
    fn from(v: &PrfInput<INPUT_BITLEN>) -> Self {
        bits_to_usize(v.as_ref())
    }
}

pub fn prf_eval(key: [u8; KEY_SIZE], input: &[bool]) -> [u8; KEY_SIZE] {
    input.iter().fold(key, |prf_out, &input_bit| {
        let prg_out = double_prg(&prf_out);
        if input_bit {
            prg_out.1
        } else {
            prg_out.0
        }
    })
}

#[inline(always)]
fn block_vec(size: usize) -> Vec<Block> {
    const BLOCK_SIZE: usize = std::mem::size_of::<Block>();
    let mut v = vec![0u8; size * BLOCK_SIZE];
    let (ptr, len, cap) = (v.as_mut_ptr(), v.len(), v.capacity());
    std::mem::forget(v);
    unsafe { Vec::from_raw_parts(ptr.cast(), len / BLOCK_SIZE, cap / BLOCK_SIZE) }
}

// pub fn prf_eval_all_into_slice(key: &[u8; KEY_SIZE], depth: usize, output: &mut [[u8; KEY_SIZE]]) {
//     const SINGLE_THREAD_THRESH: usize = 10;
//     assert!(output.len() == (1 << depth));
//     let mut helper = block_vec(output.len());
//     let mut helper_two = block_vec(output.len());
//     helper[0] = Block::from(*key);
//     let mut cur_from = &mut helper;
//     let mut cur_to = &mut helper_two;

//     for i in 0..std::cmp::min(depth, SINGLE_THREAD_THRESH) {
//         double_prg_many(&cur_from[0..1 << i], &mut cur_to[..1 << (i + 1)]);
//         (cur_from, cur_to) = (cur_to, cur_from);
//     }
//     if depth > SINGLE_THREAD_THRESH {
//         for i in (0..1 << SINGLE_THREAD_THRESH).rev() {
//             cur_from[i << (depth - SINGLE_THREAD_THRESH)] = cur_from[i];
//         }
//         cur_from
//             .par_chunks_mut(1 << (depth - SINGLE_THREAD_THRESH))
//             .zip(cur_to.par_chunks_mut(1 << (depth - SINGLE_THREAD_THRESH)))
//             .for_each(|(mut cur_from, mut cur_to)| {
//                 for i in 0..(depth - SINGLE_THREAD_THRESH) {
//                     double_prg_many(&cur_from[0..1 << i], &mut cur_to[..1 << (i + 1)]);
//                     (cur_from, cur_to) = (cur_to, cur_from);
//                 }
//             })
//     }
//     let chunk_size = 1 << SINGLE_THREAD_THRESH;
//     output
//         .chunks_mut(chunk_size)
//         .zip(cur_from.chunks(chunk_size))
//         .for_each(|(output_chunk, helper_chunk)| {
//             for i in 0..output_chunk.len() {
//                 output_chunk[i] = *helper_chunk[i].as_ref();
//             }
//         });
// }

pub fn prf_eval_all_into_slice(key: &[u8; KEY_SIZE], depth: usize, output: &mut [[u8; KEY_SIZE]]) {
    let cache_depth = CACHE_LEVEL_DEPTH;
    assert!(output.len() == (1 << depth));
    let mut helper = block_vec(output.len());
    output[0] = *key;
    let output_blocks: &mut [Block] =
        unsafe { std::slice::from_raw_parts_mut(output.as_mut_ptr().cast(), output.len()) };

    for input_depth in (0..depth).step_by(cache_depth) {
        let level_depth = std::cmp::min(cache_depth, depth - input_depth);
        // Spread output for next evaluation.
        (0..(1 << input_depth)).rev().for_each(|block_idx| {
            output_blocks[block_idx << level_depth] = output_blocks[block_idx]
        });

        output_blocks
            .chunks_mut(1 << level_depth)
            .zip(helper.chunks_mut(1 << level_depth))
            .for_each(|(output_chunk, helper)| {
                prf_eval_block_inside_cache(level_depth, output_chunk[0], output_chunk, helper)
            });
    }
}

// Returns the sum of the leafs.
pub fn prf_eval_block_inside_cache(
    depth: usize,
    key: Block,
    output: &mut [Block],
    aux: &mut [Block],
) {
    assert!(output.len() == (1 << depth));
    assert!(aux.len() == (1 << depth));
    let (mut from, mut to) = if depth % 2 == 0 {
        (output, aux)
    } else {
        (aux, output)
    };
    from[0] = key;

    for i in 0..depth {
        double_prg_many(&from[0..1 << i], &mut to[0..1 << (i + 1)]);
        (from, to) = (to, from);
    }
}
pub const CACHE_LEVEL_DEPTH: usize = 10;
pub fn prf_eval_all(key: &[u8; KEY_SIZE], depth: usize) -> Vec<[u8; KEY_SIZE]> {
    let mut output: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; 1 << depth];
    prf_eval_all_into_slice(key, depth, &mut output);
    output
}

use super::double_prg_many;
use super::prg::double_prg_field;
use super::prg::PrgValue;
use crate::fields::GF128;
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

pub fn prf_eval(key: &GF128, bits: usize, input: usize) -> GF128 {
    (0..bits)
        .rev()
        .map(|i| ((input >> i) & 1) == 1)
        .fold(*key, |prf_out, input_bit| {
            let prg_out = double_prg_field(&prf_out);
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

pub fn prf_eval_all_into_slice(key: &PrgValue, depth: usize, output: &mut [PrgValue]) {
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
pub fn prf_eval_all(key: &PrgValue, depth: usize) -> Vec<PrgValue> {
    let mut output: Vec<PrgValue> = vec![PrgValue::default(); 1 << depth];
    prf_eval_all_into_slice(key, depth, &mut output);
    output
}

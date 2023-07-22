use std::{
    alloc::Layout,
    ops::{Deref, DerefMut},
};

use crate::{fields::GF128, xor_arrays};
#[cfg(feature = "aesni")]
use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes128, Block,
};
use once_cell::sync::Lazy;
use rayon::{
    prelude::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    slice::ParallelSliceMut,
};
use serde::{Deserialize, Serialize};
pub const PRG_KEY_SIZE: usize = 16;
pub const ALIGN: usize = 256;
pub fn alloc_aligned_vec(length: usize) -> Vec<GF128> {
    let layout = Layout::array::<GF128>(length)
        .unwrap()
        .align_to(ALIGN)
        .unwrap();
    let buf1 = unsafe { std::alloc::alloc(layout) as *mut GF128 };
    unsafe { Vec::from_raw_parts(buf1, length, length) }
}
pub fn fill_prg(seed: &GF128, output: &mut [GF128]) {
    let depth = output.len().ilog2();
    assert_eq!(1 << depth, output.len());
    output[0] = *seed;
    for i in 1..=depth {
        double_prg_many_inplace(&mut output[..1 << i]);
    }
}
pub fn fill_prg_cache_friendly<const EXPANSION_FACTOR: usize>(
    seed: &GF128,
    output: &mut [GF128],
    buf: &mut [GF128],
) {
    // Ensure output is aligned with cache line size.
    assert_eq!(output.as_ptr() as usize & (ALIGN - 1), 0);
    assert_eq!(buf.as_ptr() as usize & (ALIGN - 1), 0);
    let depth = output.len().ilog2() as usize;
    assert_eq!(1 << depth, output.len());
    assert_eq!(1 << depth, buf.len());
    let non_first_iteration_count = depth / EXPANSION_FACTOR;
    let first = depth - EXPANSION_FACTOR * non_first_iteration_count;
    let (mut cur, mut next) = if non_first_iteration_count & 1 == 0 {
        (output, buf)
    } else {
        (buf, output)
    };
    cur[0] = *seed;
    for i in 0..first {
        double_prg_many_inplace(&mut cur[..1 << (i + 1)]);
    }
    for i in 0..non_first_iteration_count {
        (cur, next) = (next, cur);
        let start_depth = first + i * EXPANSION_FACTOR;
        next[..1 << start_depth]
            .par_iter()
            .zip(cur.par_chunks_exact_mut(1 << EXPANSION_FACTOR))
            .for_each(|(seed, buf)| {
                buf[0] = *seed;
                for j in 1..=EXPANSION_FACTOR {
                    double_prg_many_inplace(&mut buf[..1 << j]);
                }
            });
    }
}
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

pub fn double_prg_field(input: &GF128) -> (GF128, GF128) {
    let v = unsafe {
        (input.0.as_array().as_ptr() as *const PrgValue)
            .as_ref()
            .unwrap()
    };
    let (v0, v1) = double_prg(v);
    let p0 = GF128::from(v0.0);
    let p1 = GF128::from(v1.0);
    (p0, p1)
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

pub fn double_prg_many_inplace(in_out: &mut [GF128]) {
    let in_out =
        unsafe { std::slice::from_raw_parts_mut(in_out.as_mut_ptr() as *mut Block, in_out.len()) };
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

#[cfg(test)]
mod tests {
    use std::alloc::Layout;

    use crate::fields::FieldElement;
    use crate::fields::GF128;
    use crate::pseudorandom::prg::ALIGN;
    use rand::thread_rng;

    use super::double_prg_field;
    use super::double_prg_many_inplace;
    use super::fill_prg;
    use super::fill_prg_cache_friendly;

    #[test]
    pub fn test() {
        let v = GF128::random(thread_rng());
        let (v_0, v_1) = double_prg_field(&v);
        let mut vect = vec![v, GF128::zero()];
        double_prg_many_inplace(&mut vect);
        assert_eq!(v_0, vect[0]);
        assert_eq!(v_1, vect[1]);
    }

    #[test]
    pub fn test_cache_friendly() {
        let v = GF128::random(thread_rng());
        const LEN: usize = 1 << 10;
        let layout = Layout::array::<GF128>(LEN)
            .unwrap()
            .align_to(ALIGN)
            .unwrap();
        let buf1 = unsafe { std::alloc::alloc(layout) as *mut GF128 };
        let buf2 = unsafe { std::alloc::alloc(layout) as *mut GF128 };
        let buf3 = unsafe { std::alloc::alloc(layout) as *mut GF128 };
        let mut v1 = unsafe { Vec::from_raw_parts(buf1, LEN, LEN) };
        let mut v2 = unsafe { Vec::from_raw_parts(buf2, LEN, LEN) };
        let mut v3 = unsafe { Vec::from_raw_parts(buf3, LEN, LEN) };
        fill_prg(&v, &mut v1);
        fill_prg_cache_friendly::<3>(&v, &mut v2, &mut v3);
        assert_eq!(v1, v2);
    }
}

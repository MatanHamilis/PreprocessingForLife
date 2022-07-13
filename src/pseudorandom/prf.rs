use super::double_prg;
use super::double_prg_many;
use super::KEY_SIZE;
#[cfg(feature = "aesni")]
use aes::Block;
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

pub fn prf_eval_all_into_slice(key: &[u8; KEY_SIZE], depth: usize, output: &mut [[u8; KEY_SIZE]]) {
    const SINGLE_THREAD_THRESH: usize = 1024;
    let chunk_size = std::cmp::min(SINGLE_THREAD_THRESH, output.len());
    assert!(output.len() == (1 << depth));
    let mut helper = block_vec(output.len());
    let mut helper_two = block_vec(output.len());
    helper[0] = Block::from(*key);
    let mut cur_from = &mut helper;
    let mut cur_to = &mut helper_two;

    for i in 0..depth {
        double_prg_many(&cur_from[..(1 << i)], &mut cur_to[..(1 << (i + 1))]);
        (cur_from, cur_to) = (cur_to, cur_from);
    }
    output
        .chunks_mut(chunk_size)
        .zip(cur_from.chunks(chunk_size))
        .for_each(|(output_chunk, helper_chunk)| {
            for i in 0..output_chunk.len() {
                output_chunk[i] = *helper_chunk[i].as_ref();
            }
        });
}
pub fn prf_eval_all(key: &[u8; KEY_SIZE], depth: usize) -> Vec<[u8; KEY_SIZE]> {
    let mut output: Vec<[u8; KEY_SIZE]> = vec![[0u8; KEY_SIZE]; 1 << depth];
    prf_eval_all_into_slice(key, depth, &mut output);
    output
}

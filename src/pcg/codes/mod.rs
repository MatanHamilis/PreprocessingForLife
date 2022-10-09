use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Block};

use crate::pseudorandom::prg::PrgValue;
use crate::xor_arrays;

pub fn accumulate(vec: &mut Vec<PrgValue>) {
    let vec_len = vec.len();
    let mut vec_iter = vec.iter_mut();
    let cur = vec_iter.next();
    if cur.is_none() {
        return;
    }
    let mut cur = cur.unwrap();

    for _ in 1..vec_len {
        let prev = cur;
        cur = vec_iter.next().unwrap();
        xor_arrays(cur, prev)
    }
}
#[derive(Debug)]
pub struct EACode<const WEIGHT: usize> {
    width: usize,
    // height: usize,
    cur_height: usize,
    rng_index: usize,
    aes: Aes128,
    preprocessed_vec: Option<Vec<[u32; WEIGHT]>>,
}

impl<const WEIGHT: usize> EACode<WEIGHT> {
    pub fn new(width: usize, seed: [u8; 16]) -> Self {
        EACode {
            width,
            // height,
            cur_height: 0,
            rng_index: 0,
            aes: Aes128::new_from_slice(&seed[..]).unwrap(),
            preprocessed_vec: None,
        }
    }
    pub fn preprocess(&mut self, count: usize) {
        self.cur_height = 0;
        self.preprocessed_vec = Some((0..count).map(|_| self.next().unwrap()).collect());
    }
}

impl<const WEIGHT: usize> Iterator for EACode<WEIGHT> {
    type Item = [u32; WEIGHT];
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        // if self.height == self.cur_height {
        //     return None;
        // }
        self.cur_height += 1;
        if self.preprocessed_vec.is_some() {
            if self.preprocessed_vec.get_or_insert_default().len() <= self.cur_height {
                self.cur_height = 0;
            }
            return Some(self.preprocessed_vec.get_or_insert_default()[self.cur_height - 1]);
        }

        //AES
        let mut output: [Block; WEIGHT] =
            std::array::from_fn(|i| Block::from(((self.rng_index + i) as u128).to_le_bytes()));
        self.rng_index += WEIGHT;
        self.aes.encrypt_blocks(&mut output);
        let mut output: [u32; WEIGHT] = unsafe { *output.as_ptr().cast() };
        for output_item in output.iter_mut() {
            *output_item &= (self.width - 1) as u32;
        }
        // for i in (0..WEIGHT - 3).step_by(STEP_SIZE) {
        //     let mut b = Block::from((self.cur_height as u128).to_be_bytes());
        //     self.aes.encrypt_block(&mut b);
        //     let b: [u32; 4] = unsafe { transmute(b) };
        //     for j in 0..STEP_SIZE {
        //         output[i + j] = (b[j] as usize) & (self.width - 1);
        //     }
        // }
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::EACode;
    #[test]
    pub fn test_sanity() {
        let code = EACode::<8>::new(12, [1; 16]);
        let mut i = 0;
        for v in code.take(100) {
            i += 1;
            assert_eq!(v.len(), 8);
        }
        assert_eq!(i, 100);
    }
}

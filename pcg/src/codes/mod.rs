use std::mem::size_of;

use aes::cipher::{BlockEncrypt, BlockSizeUser, KeyInit};
use aes::{Aes128, Block};
use core::mem::transmute;
// use rand::seq::index::sample;
// use rand::RngCore;
// use rand::SeedableRng;
// use rand_chacha::ChaCha8Rng;

pub struct EACode<const WEIGHT: usize> {
    width: usize,
    height: usize,
    cur_height: usize,
    // csprng: ChaCha8Rng,
    aes: Aes128,
    preprocessed_vec: Option<Vec<[usize; WEIGHT]>>,
}

impl<const WEIGHT: usize> EACode<WEIGHT> {
    pub fn new(width: usize, height: usize, seed: [u8; 32]) -> Self {
        EACode {
            width,
            height,
            cur_height: 0,
            // csprng: ChaCha8Rng::from_seed(seed),
            aes: Aes128::new_from_slice(&seed[0..16]).unwrap(),
            preprocessed_vec: None,
        }
    }
    pub fn preprocess(&mut self, count: usize) {
        self.preprocessed_vec = Some((0..count).map(|_| self.next().unwrap()).collect());
    }
}

impl<const WEIGHT: usize> Iterator for EACode<WEIGHT> {
    type Item = [usize; WEIGHT];
    fn next(&mut self) -> Option<Self::Item> {
        if self.height == self.cur_height {
            return None;
        }
        self.cur_height += 1;
        if self.preprocessed_vec.is_some()
            && self.preprocessed_vec.get_or_insert_default().len() > self.cur_height
        {
            return Some(self.preprocessed_vec.get_or_insert_default()[self.cur_height - 1]);
        }
        // let sampled = sample(&mut self.csprng, self.width, WEIGHT);
        // let mut output = [0usize; WEIGHT];
        // for (idx, output_num) in sampled.iter().enumerate() {
        //     output[idx] = output_num;
        // }
        // Some(output)
        // Some(array::from_fn(|_| {
        //     (self.csprng.next_u32() as usize) % self.width
        // }))

        //AES
        let mut output = [0; WEIGHT];
        let step_size = aes::Aes128::block_size() / size_of::<u32>();
        for i in (0..WEIGHT - 3).step_by(step_size) {
            let mut b = Block::from((self.cur_height as u128).to_be_bytes());
            self.aes.encrypt_block(&mut b);
            let b: [u32; 4] = unsafe { transmute(b) };
            for j in 0..step_size {
                if i + j >= WEIGHT {
                    break;
                }
                output[i + j] = (b[j] as usize) % self.width
            }
        }
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::codes::EACode;
    #[test]
    pub fn test_sanity() {
        let code = EACode::<5>::new(12, 100, [1; 32]);
        let mut i = 0;
        for v in code {
            i += 1;
            assert_eq!(v.len(), 5);
        }
        assert_eq!(i, 100);
    }
}

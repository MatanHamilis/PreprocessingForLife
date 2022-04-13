//! # Punctured PseudoRandom Functions (PPRF) Implementation
//!

mod distributed_generation;

use std::convert::{From, Into};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
#[derive(PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}
impl From<bool> for Direction {
    fn from(a: bool) -> Self {
        if a {
            Self::Right
        } else {
            Self::Left
        }
    }
}

pub fn double_prg<const SEED_SIZE: usize>(input: [u8; SEED_SIZE]) -> [[u8; SEED_SIZE]; 2] {
    let mut seed: [u8; 32] = [0; 32];
    input
        .iter()
        .take(32)
        .zip(seed.iter_mut())
        .for_each(|(input_item, seed_item)| *seed_item = *input_item);
    let mut chacha_rng = ChaCha8Rng::from_seed(seed);
    let mut output: [[u8; SEED_SIZE]; 2] = [[0; SEED_SIZE]; 2];
    output.iter_mut().for_each(|arr| chacha_rng.fill_bytes(arr));
    output
}

pub fn prf_eval<const SEED_SIZE: usize>(key: [u8; SEED_SIZE], input: &[bool]) -> [u8; SEED_SIZE] {
    input.iter().fold(key, |prf_out, &input_bit| {
        double_prg(prf_out)[input_bit as usize]
    })
}
pub struct PuncturedKey<const SEED_SIZE: usize, const INPUT_BITLEN: usize> {
    keys: [([u8; SEED_SIZE], Direction); INPUT_BITLEN],
}

impl<const KEY_SIZE: usize, const INPUT_BITLEN: usize> PuncturedKey<KEY_SIZE, INPUT_BITLEN> {
    pub fn puncture(prf_key: [u8; KEY_SIZE], puncture_point: [bool; INPUT_BITLEN]) -> Self {
        let mut current_key = prf_key;
        let punctured_key = puncture_point.map(|puncture_bit| {
            let [left, right] = double_prg(current_key);
            match puncture_bit.into() {
                Direction::Left => {
                    current_key = left;
                    (right, Direction::Right)
                }
                Direction::Right => {
                    current_key = right;
                    (left, Direction::Left)
                }
            }
        });
        PuncturedKey {
            keys: punctured_key,
        }
    }
    pub fn try_eval(&self, input: [bool; INPUT_BITLEN]) -> Option<[u8; KEY_SIZE]> {
        for ((i, &b), (k, direction)) in input.iter().enumerate().zip(self.keys.iter()) {
            if *direction == b.into() {
                return Some(prf_eval(*k, &input[i + 1..]));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{prf_eval, PuncturedKey};

    fn int_to_bool_array<const BITS: usize>(mut num: u32) -> [bool; BITS] {
        let mut output = [false; BITS];
        for i in 0..BITS {
            if num & 1 == 1 {
                output[i] = true;
            }
            num >>= 1;
        }
        output
    }
    #[test]
    fn one_bit_output() {
        let prf_key = [0u8];
        let puncture_point = [true];
        let punctured_key = PuncturedKey::puncture(prf_key, puncture_point);
        assert!(punctured_key.try_eval(puncture_point).is_none());
        assert_eq!(
            punctured_key.try_eval([false]).unwrap(),
            prf_eval(prf_key, &[false])
        );
    }

    #[test]
    fn check_large_domain() {
        let prf_key = [11u8; 32];
        let puncture_num = 0b010101010101;
        let puncture_point = int_to_bool_array::<20>(puncture_num);
        let punctured_key = PuncturedKey::puncture(prf_key, puncture_point);
        for i in 0..1 << puncture_point.len() {
            let prf_input = int_to_bool_array::<20>(i);
            if i != puncture_num {
                assert_eq!(
                    punctured_key.try_eval(prf_input).unwrap(),
                    prf_eval(prf_key, &prf_input)
                );
            } else {
                assert!(punctured_key.try_eval(prf_input).is_none());
            }
        }
    }
}

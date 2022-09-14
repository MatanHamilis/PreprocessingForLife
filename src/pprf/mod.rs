//! # Punctured PseudoRandom Functions (PPRF) Implementation
//!
pub mod distributed_generation;

use crate::pseudorandom::prf::{prf_eval, prf_eval_all_into_slice};
use crate::pseudorandom::{double_prg, KEY_SIZE};
use crate::xor_arrays;
use std::convert::{From, Into};

#[cfg(not(feature = "aesni"))]
use rand::{RngCore, SeedableRng};
#[cfg(not(feature = "aesni"))]
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
#[derive(PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub struct PuncturedKey<const INPUT_BITLEN: usize> {
    #[serde(with = "BigArray")]
    keys: [([u8; KEY_SIZE], Direction); INPUT_BITLEN],
}

impl<const INPUT_BITLEN: usize> PuncturedKey<INPUT_BITLEN> {
    pub fn puncture(prf_key: [u8; KEY_SIZE], puncture_point: [bool; INPUT_BITLEN]) -> Self {
        let mut current_key = prf_key;
        let punctured_key = puncture_point.map(|puncture_bit| {
            let (left, right) = double_prg(&current_key);
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

    pub fn full_eval_with_punctured_point_into_slice(
        &self,
        leaf_sum_plus_punctured_point_val: &[u8; KEY_SIZE],
        output: &mut [[u8; KEY_SIZE]],
    ) {
        assert_eq!(output.len(), 1 << INPUT_BITLEN);
        let mut top = 1 << INPUT_BITLEN;
        let mut bottom = 0;
        let mut mid = 1 << (INPUT_BITLEN - 1);
        for i in 0..INPUT_BITLEN {
            let depth = INPUT_BITLEN - 1 - i;
            let output_slice = match self.keys[i].1 {
                Direction::Left => &mut output[bottom..mid],
                _ => &mut output[mid..top],
            };
            prf_eval_all_into_slice(&self.keys[i].0, depth, output_slice);
            if self.keys[i].1 == Direction::Left {
                bottom = mid;
            } else {
                top = mid;
            }
            mid = (bottom + top) >> 1;
        }
        let mut punctured_point_val: [u8; KEY_SIZE] = *leaf_sum_plus_punctured_point_val;
        for v in output.iter() {
            xor_arrays(&mut punctured_point_val, v)
        }

        output[mid] = punctured_point_val;
    }

    pub fn full_eval_with_punctured_point(
        &self,
        leaf_sum_plus_punctured_point_val: &[u8; KEY_SIZE],
    ) -> Vec<[u8; KEY_SIZE]> {
        let mut output = vec![[0u8; KEY_SIZE]; 1 << INPUT_BITLEN];
        self.full_eval_with_punctured_point_into_slice(
            leaf_sum_plus_punctured_point_val,
            &mut output,
        );
        output
    }
}

pub fn bits_to_usize<const BITS: usize>(bits: &[bool; BITS]) -> usize {
    bits.iter()
        .rev()
        .enumerate()
        .fold(0, |acc, (id, cur)| if *cur { acc + (1 << id) } else { acc })
}

pub fn usize_to_bits<const BITS: usize>(mut n: usize) -> [bool; BITS] {
    let mut output = [false; BITS];
    for i in (0..BITS).rev() {
        if n & 1 == 1 {
            output[i] = true;
        }
        n >>= 1;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{bits_to_usize, usize_to_bits, PuncturedKey};
    use crate::pseudorandom::prf::{prf_eval, prf_eval_all};
    use crate::pseudorandom::KEY_SIZE;
    use crate::xor_arrays;

    #[test]
    fn one_bit_output() {
        let prf_key = [0u8; KEY_SIZE];
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
        let prf_key = [11u8; KEY_SIZE];
        let puncture_num = 0b0101010101;
        let puncture_point = usize_to_bits::<10>(puncture_num);
        let punctured_key = PuncturedKey::puncture(prf_key, puncture_point);
        for i in 0..1 << puncture_point.len() {
            let prf_input = usize_to_bits::<10>(i);
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

    #[test]
    fn test_full_eval_prf() {
        let prf_key = [11u8; KEY_SIZE];
        let point_num = 0b1;
        let point_arr = usize_to_bits::<1>(point_num);
        let full_eval = prf_eval_all(&prf_key, 1);
        let prf_evaluated = prf_eval(prf_key, &point_arr);
        assert_eq!(prf_evaluated, full_eval[point_num as usize]);
    }

    #[test]
    fn test_full_eval_punctured() {
        let prf_key = [11u8; KEY_SIZE];
        let puncture_point = 0b111;
        let puncture_point_arr = usize_to_bits::<3>(puncture_point);
        let punctured_key = PuncturedKey::puncture(prf_key, puncture_point_arr);
        let full_eval_regular = prf_eval_all(&prf_key, 3);
        let leaf_sum = full_eval_regular
            .iter()
            .fold([0u8; KEY_SIZE], |mut acc, cur| {
                xor_arrays(&mut acc, &cur);
                acc
            });
        let full_eval_punctured = punctured_key.full_eval_with_punctured_point(&leaf_sum);
        assert_eq!(full_eval_regular, full_eval_punctured);
    }

    #[test]
    fn punctured_point_conversion() {
        let puncture_point: usize = 0b01010101;
        let puncture_point_arr = usize_to_bits::<12>(puncture_point);
        let point = bits_to_usize(&puncture_point_arr);
        assert_eq!(puncture_point, point);
    }
}

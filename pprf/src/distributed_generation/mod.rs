//! # Distributed Generation of PPRF
//! This module intends to enable the functionality of the distributed generation of the PPRF.
//! The PPRF is generate jointly by two parties.
//! One party knows the puncturing point, while the other knows the value at the puncturing point.
//! This is the most common setting to establish the "sparse VOLE" correlation.
//! In the Sparse-VOLE correlation one party ($P_1$) will be holding a value $x$.
//! The other party ($P_2$) is holding a point $i \in \[N\]$.

use crate::double_prg;
use crate::Direction;
use crate::PuncturedKey;
use ot::receiver::FirstMessage as ReceiverFirstMessage;
use ot::receiver::OTReceiver;
use ot::sender::FirstMessage as SenderFirstMessage;
use ot::sender::OTSender;
use ot::sender::SecondMessage as SenderSecondMessage;

fn xor_arrays<const LENGTH: usize>(a: &mut [u8; LENGTH], b: [u8; LENGTH]) {
    for i in 0..LENGTH {
        a[i] ^= b[i];
    }
}

#[derive(PartialEq, Eq)]
enum PuncturerState {
    Initialized,
    FirstMessageSent,
    Finished,
}
struct Puncturer<const KEY_WIDTH: usize, const DEPTH: usize> {
    ots: [OTSender<KEY_WIDTH>; DEPTH],
    state: PuncturerState,
    messages: [([u8; KEY_WIDTH], [u8; KEY_WIDTH]); DEPTH],
}

impl<const KEY_WIDTH: usize, const DEPTH: usize> Puncturer<KEY_WIDTH, DEPTH> {
    fn new(prf_key: [u8; KEY_WIDTH]) -> Self {
        let mut puncturer = Puncturer {
            ots: [OTSender::<KEY_WIDTH>::new(); DEPTH],
            state: PuncturerState::Initialized,
            messages: [([0; KEY_WIDTH], [0; KEY_WIDTH]); DEPTH],
        };
        let mut keys = vec![prf_key];
        for i in 0..DEPTH {
            let mut new_keys = Vec::new();
            let mut left_sum = [0u8; KEY_WIDTH];
            let mut right_sum = [0u8; KEY_WIDTH];
            keys.iter().for_each(|k| {
                let [left, right] = double_prg(*k);
                xor_arrays(&mut left_sum, left);
                xor_arrays(&mut right_sum, right);
                new_keys.push(left);
                new_keys.push(right);
            });
            keys = new_keys;
            puncturer.messages[i] = (left_sum, right_sum);
        }
        puncturer
    }
    fn make_first_msg(&mut self) -> [SenderFirstMessage; DEPTH] {
        assert!(self.state == PuncturerState::Initialized);
        self.state = PuncturerState::FirstMessageSent;
        let mut output = [SenderFirstMessage::default(); DEPTH];
        // map doesn't modify the original OT object :(
        self.ots
            .iter_mut()
            .enumerate()
            .for_each(|(i, ot)| output[i] = ot.gen_first_message());
        output
    }

    fn make_second_msg(
        &mut self,
        receiver_msg: [ReceiverFirstMessage; DEPTH],
    ) -> [SenderSecondMessage<KEY_WIDTH>; DEPTH] {
        assert!(self.state == PuncturerState::FirstMessageSent);
        self.state = PuncturerState::Finished;
        let mut output = [([0; KEY_WIDTH], [0; KEY_WIDTH]); DEPTH];
        (0..DEPTH).for_each(|i| {
            output[i] = self.ots[i]
                .handle_receiver_message::<KEY_WIDTH>(receiver_msg[i], &self.messages[i]);
        });
        output
    }
}

#[derive(PartialEq, Eq)]
enum PunctureeState {
    Initialized,
    FirstMessageSent,
    Finished,
}
struct Puncturee<const KEY_WIDTH: usize, const DEPTH: usize> {
    ots: [OTReceiver<KEY_WIDTH>; DEPTH],
    state: PunctureeState,
    punctured_point: Option<[bool; DEPTH]>,
}

impl<const KEY_WIDTH: usize, const DEPTH: usize> Puncturee<KEY_WIDTH, DEPTH> {
    fn new() -> Self {
        Self {
            ots: [OTReceiver::<KEY_WIDTH>::new(); DEPTH],
            state: PunctureeState::Initialized,
            punctured_point: None,
        }
    }
    fn make_first_msg(
        &mut self,
        sender_msg: [SenderFirstMessage; DEPTH],
        punctured_point: [bool; DEPTH],
    ) -> [ReceiverFirstMessage; DEPTH] {
        assert!(self.state == PunctureeState::Initialized);
        self.state = PunctureeState::FirstMessageSent;
        self.punctured_point = Some(punctured_point);
        let mut output = [ReceiverFirstMessage::default(); DEPTH];
        for i in 0..DEPTH {
            output[i] = self.ots[i].handle_first_sender_message(sender_msg[i], !punctured_point[i])
        }
        output
    }
    fn obtain_pprf(
        &mut self,
        sender_msg: [SenderSecondMessage<KEY_WIDTH>; DEPTH],
    ) -> Option<PuncturedKey<KEY_WIDTH, DEPTH>> {
        assert!(self.state == PunctureeState::FirstMessageSent);
        self.state = PunctureeState::Finished;
        let mut ot_results = [[0; KEY_WIDTH]; DEPTH];
        for i in 0..DEPTH {
            ot_results[i] =
                match self.ots[i].handle_final_sender_message::<KEY_WIDTH>(sender_msg[i]) {
                    None => return None,
                    Some(x) => x,
                }
        }
        let ot_results = ot_results;
        let mut keys = vec![];
        let mut left_new_keys = vec![];
        let mut right_new_keys = vec![];
        let mut i = 0;
        let punctured_key = ot_results.map(|result| {
            keys.iter().for_each(|k| {
                let [left, right] = double_prg(*k);
                left_new_keys.push(left);
                right_new_keys.push(right);
            });
            let (keys_to_xor, direction) = match self.punctured_point.unwrap()[i].into() {
                // If the puncturing point goes to the right, we learn the left subtree.
                Direction::Right => (&left_new_keys, Direction::Left),
                // Otherwise learn the right subtree.
                Direction::Left => (&right_new_keys, Direction::Right),
            };
            let xored_keys = keys_to_xor.iter().fold(result, |mut acc, v| {
                xor_arrays(&mut acc, *v);
                acc
            });
            keys.clear();
            keys.append(&mut left_new_keys);
            keys.append(&mut right_new_keys);
            keys.push(xored_keys);
            i += 1;
            (xored_keys, direction)
        });
        Some(PuncturedKey {
            keys: punctured_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{prf_eval, PuncturedKey};

    use super::{Puncturee, Puncturer};

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

    fn simulate_protocol<const KEY_SIZE: usize, const DEPTH: usize>(
        prf_key: [u8; KEY_SIZE],
        punctured_point: [bool; DEPTH],
    ) -> Option<PuncturedKey<KEY_SIZE, DEPTH>> {
        let mut puncturer = Puncturer::<KEY_SIZE, DEPTH>::new(prf_key);
        let mut puncturee = Puncturee::<KEY_SIZE, DEPTH>::new();
        let puncturer_first_msg = puncturer.make_first_msg();
        let puncturee_first_msg = puncturee.make_first_msg(puncturer_first_msg, punctured_point);
        let puncturer_final_msg = puncturer.make_second_msg(puncturee_first_msg);
        puncturee.obtain_pprf(puncturer_final_msg)
    }

    #[test]
    fn one_bit_output() {
        let prf_key = [0u8];
        let puncture_point = [true];
        let punctured_key = simulate_protocol(prf_key, puncture_point).unwrap();
        assert!(punctured_key.try_eval(puncture_point).is_none());
        assert_eq!(
            punctured_key.try_eval([false]).unwrap(),
            prf_eval(prf_key, &[false])
        );
    }

    #[test]
    fn check_large_domain() {
        let prf_key = [11u8; 32];
        let puncture_num = 0b1010101;
        let puncture_point = int_to_bool_array::<10>(puncture_num);
        let punctured_key = simulate_protocol(prf_key, puncture_point).unwrap();
        for i in 0..1 << puncture_point.len() {
            let prf_input = int_to_bool_array::<10>(i);
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

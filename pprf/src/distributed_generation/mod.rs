//! # Distributed Generation of PPRF
//! This module intends to enable the functionality of the distributed generation of the PPRF.
//! The PPRF is generate jointly by two parties.
//! One party knows the puncturing point, while the other knows the value at the puncturing point.
//! This is the most common setting to establish the "sparse VOLE" correlation.
//! In the Sparse-VOLE correlation one party ($P_1$) will be holding a value $x$.
//! The other party ($P_2$) is holding a point $i \in [N]$.

use crate::double_prg;
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
    fn get_first_message(&mut self) -> [SenderFirstMessage; DEPTH] {
        assert!(self.state == PuncturerState::Initialized);
        let mut output = [SenderFirstMessage::default(); DEPTH];
        for i in 0..DEPTH {
            output[i] = self.ots[i].gen_first_message();
        }
        output
    }

    fn handle_receiver_msg(
        &mut self,
        receiver_msg: [ReceiverFirstMessage; DEPTH],
    ) -> [SenderSecondMessage<KEY_WIDTH>; DEPTH] {
        assert!(self.state == PuncturerState::FirstMessageSent);
        let mut output = [([0; KEY_WIDTH], [0; KEY_WIDTH]); DEPTH];
        for i in 0..DEPTH {
            output[i] =
                self.ots[i].handle_receiver_message::<KEY_WIDTH>(receiver_msg[i], &self.messages[i])
        }
        output
    }
}

#[derive(PartialEq, Eq)]
enum PunctureeState {
    Initialized,
    FirstMessageSent,
    Finished,
    Aborted,
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
    fn handle_first_sender_message(
        &mut self,
        sender_msg: [SenderFirstMessage; DEPTH],
        punctured_point: [bool; DEPTH],
    ) -> Option<[ReceiverFirstMessage; DEPTH]> {
        assert!(self.state != PunctureeState::Initialized);
        self.punctured_point = Some(punctured_point);
        let mut output = [ReceiverFirstMessage::default(); DEPTH];
        for i in 0..DEPTH {
            output[i] = self.ots[i].handle_first_sender_message(sender_msg[i], punctured_point[i]);
        }
        Some(output)
    }
}

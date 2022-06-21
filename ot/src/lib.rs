//! # Oblivious Transfer Implementation
//!
//! This crate implements an Oblivious Transfer protocol.
//! Namely, it implements the "Simplest OT" by [Chou and Orlandi](https://eprint.iacr.org/2015/267.pdf)

//TODO: Revise the protocol.
pub mod receiver;
pub mod sender;
use blake3::Hasher;

const KEY_EXPANDING_DOMAIN: &str = "SIMPLE_OT_KEY_EXPANDING [12/4/22] v1";

pub(crate) fn expand_key<const KEY_SIZE: usize>(key_material: &[u8]) -> [u8; KEY_SIZE] {
    let mut hasher = Hasher::new_derive_key(KEY_EXPANDING_DOMAIN);
    let mut output: [u8; KEY_SIZE] = [0; KEY_SIZE];
    hasher.update(key_material);
    hasher.finalize_xof().fill(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use crate::{receiver::OTReceiver, sender::OTSender};

    #[test]
    fn full_ot() {
        const KEY_SIZE: usize = 64;
        let messages = ([1, 1, 1, 1], [2, 2, 2, 2]);
        let mut ot_sender = OTSender::default();
        let mut ot_receiver = OTReceiver::<KEY_SIZE>::default();

        let first_msg = ot_sender.gen_first_message();
        let second_msg = ot_receiver.handle_first_sender_message(first_msg, true);
        let third_msg = ot_sender.handle_receiver_message(second_msg, &messages);
        let received_msg = ot_receiver.handle_final_sender_message(third_msg).unwrap();

        assert_eq!(received_msg, messages.1)
    }
}

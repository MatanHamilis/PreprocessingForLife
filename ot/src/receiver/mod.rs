use crate::expand_key;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use non_committing_encryption::{COSchemeKey, NonCommittingKey};
use rand_core::OsRng;

#[derive(PartialEq, Eq, Clone, Copy)]
enum State {
    Initialized,
    FirstMessageSent,
    Finished,
}
#[derive(Clone, Copy)]
pub struct OTReceiver<const KEY_SIZE: usize> {
    selection: Option<bool>,
    random_scalar: Scalar,
    state: State,
    encryption_key: Option<COSchemeKey<KEY_SIZE>>,
}

pub type FirstMessage = RistrettoPoint;

impl<const KEY_SIZE: usize> OTReceiver<KEY_SIZE> {
    pub fn new() -> Self {
        let mut csprng = OsRng;
        OTReceiver {
            selection: None,
            random_scalar: Scalar::random(&mut csprng),
            state: State::Initialized,
            encryption_key: None,
        }
    }

    pub fn handle_first_sender_message(
        &mut self,
        sender_message: RistrettoPoint,
        selection: bool,
    ) -> FirstMessage {
        assert!(self.state == State::Initialized);
        self.selection = Some(selection);
        // B= b*G.
        let point = &self.random_scalar * &RISTRETTO_BASEPOINT_TABLE;
        // Compute non-committing-encryption key.
        self.encryption_key = Some(expand_key::<KEY_SIZE>(
            (self.random_scalar * sender_message).compress().as_bytes(),
        ));
        self.state = State::FirstMessageSent;
        // Send either B + A or B depending `selection` bit.
        if selection {
            // B + A
            point + sender_message
        } else {
            // B
            point
        }
    }

    pub fn handle_final_sender_message<const MSG_SIZE: usize>(
        &mut self,
        sender_message: ([u8; KEY_SIZE], [u8; KEY_SIZE]),
    ) -> Option<[u8; MSG_SIZE]> {
        assert!(self.state == State::FirstMessageSent);

        let msg_to_decrypt = if self.selection.unwrap() {
            sender_message.1
        } else {
            sender_message.0
        };

        let key = self.encryption_key.take();
        self.state = State::Finished;
        Some(key.unwrap().decrypt(msg_to_decrypt)?)
    }
}

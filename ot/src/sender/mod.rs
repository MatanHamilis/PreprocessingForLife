use crate::expand_key;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use non_committing_encryption::{COSchemeKey, NonCommittingKey};
use rand_core::OsRng;

#[derive(PartialEq, Eq)]
enum State {
    Initialized,
    FirstMessageSent,
    FinalMessageSent,
}

pub struct OTSender<const MSG_SIZE: usize> {
    messages: ([u8; MSG_SIZE], [u8; MSG_SIZE]),
    random_scalar: Scalar,
    random_point: RistrettoPoint,
    state: State,
}

impl<const MSG_SIZE: usize> OTSender<MSG_SIZE> {
    pub(crate) fn new(messages: ([u8; MSG_SIZE], [u8; MSG_SIZE])) -> Self {
        let mut csprng = OsRng;
        let random_scalar = Scalar::random(&mut csprng);
        OTSender {
            messages,
            random_scalar,
            random_point: &RISTRETTO_BASEPOINT_TABLE * &random_scalar,
            state: State::Initialized,
        }
    }

    pub(crate) fn gen_first_message(&mut self) -> Option<RistrettoPoint> {
        if (self.state != State::Initialized) {
            return None;
        }
        self.state = State::FirstMessageSent;
        Some(self.random_point)
    }

    pub(crate) fn handle_receiver_message<const KEY_SIZE: usize>(
        &mut self,
        receiver_point: RistrettoPoint,
    ) -> Option<([u8; KEY_SIZE], [u8; KEY_SIZE])> {
        if self.state != State::FirstMessageSent {
            return None;
        }
        // K_0 = H(B*a)
        let key_0: COSchemeKey<KEY_SIZE> =
            expand_key::<KEY_SIZE>((receiver_point * self.random_scalar).compress().as_bytes());

        // K_1 = H((B-A)*a)
        let key_1: COSchemeKey<KEY_SIZE> = expand_key::<KEY_SIZE>(
            ((receiver_point - self.random_point) * self.random_scalar)
                .compress()
                .as_bytes(),
        );
        self.state = State::FinalMessageSent;
        Some((
            // E_K_0(M_0)
            key_0.encrypt(self.messages.0),
            // E_K_1(M_1)
            key_1.encrypt(self.messages.1),
        ))
    }
}

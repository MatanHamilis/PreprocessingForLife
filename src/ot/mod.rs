use crate::engine::{MultiPartyEngine, PartyId};
use crate::uc_tags::UCTag;
use blake3::Hasher;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha8,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng, RngCore};

const CURVE25519_GEN: MontgomeryPoint = MontgomeryPoint([
    0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

const TWIST_CURVE25519_GEN: MontgomeryPoint = MontgomeryPoint([
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

pub const OT_MSG_LEN: usize = 32;
pub type Msg = [u8; OT_MSG_LEN];
pub struct OTSender(Msg, Msg);
pub struct OTReceiver(Msg, bool);
pub async fn batch_endemic_ot_sender<T: MultiPartyEngine>(
    mut engine: T,
    batch_size: usize,
) -> Option<Vec<OTSender>> {
    let (a, points) = moller_msg_sender(T::rng());
    engine.broadcast(&points);
    let (msgs, _): (Vec<[u8; 32]>, PartyId) = engine.recv().await?;
    if msgs.len() != batch_size {
        return None;
    }
    let ots_sender: Vec<_> = msgs
        .into_iter()
        .enumerate()
        .map(|(idx, msg)| {
            let popf_tag = engine.uc_tag().derive(&"POPF").derive(&idx);
            let false_choice = MontgomeryPoint(popf_eval(&popf_tag, msg, false));
            let true_choice = MontgomeryPoint(popf_eval(&popf_tag, msg, true));
            let moller_tag_false = engine.uc_tag().derive(&"MOLLER KEY").derive(&(idx, false));
            let moller_tag_true = engine.uc_tag().derive(&"MOLLER KEY").derive(&(idx, true));
            OTSender(
                moller_key(&moller_tag_false, a, false_choice),
                moller_key(&moller_tag_true, a, true_choice),
            )
        })
        .collect();
    Some(ots_sender)
}

pub async fn batch_endemic_ot_receiver<T: MultiPartyEngine>(
    mut engine: T,
    choice_bits: Vec<bool>,
) -> Option<Vec<OTReceiver>> {
    let batch_size = choice_bits.len();
    let (scalars, msgs): (Vec<(Scalar, bool)>, Vec<[u8; 32]>) = (0..batch_size)
        .map(|i| {
            let (scalar, point) = moller_msg_receiver(T::rng());
            let msg = popf_program(
                &engine.uc_tag().derive(&"POPF").derive(&i),
                choice_bits[i],
                point.0,
            );
            (scalar, msg)
        })
        .unzip();
    engine.broadcast(&msgs);
    let (sender_msg, _): ((MontgomeryPoint, MontgomeryPoint), PartyId) = engine.recv().await?;
    Some(
        scalars
            .into_iter()
            .zip(choice_bits.iter().copied())
            .enumerate()
            .map(|(idx, ((scalar, is_on_curve), choice_bit))| {
                let point = if is_on_curve {
                    sender_msg.0
                } else {
                    sender_msg.1
                };
                let moller_tag = engine
                    .uc_tag()
                    .derive(&"MOLLER KEY")
                    .derive(&(idx, choice_bit));
                let key = moller_key(&moller_tag, scalar, point);
                OTReceiver(key, choice_bit)
            })
            .collect(),
    )
}

fn popf_get_key(tag: &UCTag, choice_bit: bool) -> ChaCha8 {
    let mut h = Hasher::new_keyed(&[choice_bit as u8; 32])
        .update(tag.as_ref())
        .finalize_xof();
    let mut output = [0u8; 32];
    h.fill(&mut output);
    let nonce = [0u8; 12];
    ChaCha8::new(&output.into(), &nonce.into())
}

fn popf_program(tag: &UCTag, choice_bit: bool, msg: [u8; OT_MSG_LEN]) -> [u8; OT_MSG_LEN] {
    let mut key = popf_get_key(tag, choice_bit);
    let mut output = [0u8; 32];
    key.apply_keystream_b2b(&msg, &mut output).unwrap();
    output
}

fn popf_eval(tag: &UCTag, func: [u8; OT_MSG_LEN], choice_bit: bool) -> [u8; OT_MSG_LEN] {
    let mut key = popf_get_key(tag, choice_bit);
    let mut output = [0u8; 32];
    key.apply_keystream_b2b(&func, &mut output).unwrap();
    output
}

fn moller_msg_sender(
    mut rng: impl CryptoRng + RngCore,
) -> (Scalar, (MontgomeryPoint, MontgomeryPoint)) {
    let a = Scalar::from_bits(rng.gen());
    (a, (a * CURVE25519_GEN, a * TWIST_CURVE25519_GEN))
}

fn moller_msg_receiver(mut rng: impl CryptoRng + RngCore) -> ((Scalar, bool), MontgomeryPoint) {
    let b = Scalar::from_bits(rng.gen());
    let beta: bool = rng.gen();
    let point = if beta {
        b * CURVE25519_GEN
    } else {
        b * TWIST_CURVE25519_GEN
    };
    ((b, beta), point)
}

fn moller_key(tag: &UCTag, scalar: Scalar, point: MontgomeryPoint) -> [u8; OT_MSG_LEN] {
    *Hasher::new_keyed(tag.as_ref())
        .update((scalar * point).as_bytes())
        .finalize()
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::{thread_rng, Rng};
    use tokio::join;

    use super::{batch_endemic_ot_receiver, batch_endemic_ot_sender};
    use crate::engine::LocalRouter;

    #[tokio::test]
    async fn test() {
        const BATCH_SIZE: usize = 1;
        let party_ids = [1, 2];
        let party_ids_set = HashSet::from(party_ids);
        let (router, mut engines) = LocalRouter::new("root tag".into(), &party_ids_set);
        let router_handle = tokio::spawn(router.launch());
        let mut rng = thread_rng();
        let choice_bits: [bool; BATCH_SIZE] = core::array::from_fn(|_| rng.gen());

        let ots_sender =
            batch_endemic_ot_sender(engines.remove(&party_ids[0]).unwrap(), BATCH_SIZE);
        let ots_receiver =
            batch_endemic_ot_receiver(engines.remove(&party_ids[1]).unwrap(), choice_bits.to_vec());
        let (sender_output, receiver_output) = join!(ots_sender, ots_receiver);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());
        router_handle.await.unwrap().unwrap();

        assert_eq!(BATCH_SIZE, sender_output.len());
        assert_eq!(BATCH_SIZE, receiver_output.len());
        sender_output
            .into_iter()
            .zip(receiver_output.into_iter())
            .zip(choice_bits.into_iter())
            .for_each(|((ot_sender, ot_receiver), choice_bit)| {
                assert_eq!(choice_bit, ot_receiver.1);
                if choice_bit {
                    assert_eq!(ot_sender.1, ot_receiver.0);
                } else {
                    assert_eq!(ot_sender.0, ot_receiver.0);
                }
            })
    }
}

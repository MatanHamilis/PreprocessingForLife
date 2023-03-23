use crate::engine::{MultiPartyEngine, PartyId};
use crate::fields::GF128;
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
pub struct OTSender<T>(T, T);
pub struct OTReceiver<T>(pub T, pub bool);
async fn batch_endemic_ot_sender<T: MultiPartyEngine>(
    engine: &mut T,
    batch_size: usize,
) -> Result<Vec<OTSender<Msg>>, ()> {
    let (a, points) = moller_msg_sender(T::rng());
    engine.broadcast(&points);
    let (msgs, _): (Vec<[u8; 32]>, PartyId) = engine.recv().await.ok_or(())?;
    if msgs.len() != batch_size {
        return Err(());
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
    Ok(ots_sender)
}

async fn batch_endemic_ot_receiver<T: MultiPartyEngine>(
    engine: &mut T,
    choice_bits: Vec<bool>,
) -> Result<Vec<OTReceiver<Msg>>, ()> {
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
    let (sender_msg, _): ((MontgomeryPoint, MontgomeryPoint), PartyId) =
        engine.recv().await.ok_or(())?;
    Ok(scalars
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
        .collect())
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

pub struct ChosenMessageOTSender<E: MultiPartyEngine> {
    rots: Vec<OTSender<Msg>>,
    engine: E,
}
impl<E: MultiPartyEngine> ChosenMessageOTSender<E> {
    pub async fn init(mut engine: E, batch_size: usize) -> Result<Self, ()> {
        Ok(Self {
            rots: batch_endemic_ot_sender(&mut engine, batch_size).await?,
            engine,
        })
    }
    pub async fn choose(mut self, msgs: &[(GF128, GF128)]) {
        assert_eq!(msgs.len(), self.rots.len());
        let to_send: Vec<_> = msgs
            .iter()
            .zip(self.rots.into_iter())
            .map(|(msgs, rots)| {
                let key0: [u8; 16] = core::array::from_fn(|i| rots.0[i]);
                let key1: [u8; 16] = core::array::from_fn(|i| rots.1[i]);
                let msg0 = GF128::from(key0) + msgs.0;
                let msg1 = GF128::from(key1) + msgs.1;
                (msg0, msg1)
            })
            .collect();
        self.engine.broadcast(&to_send);
    }
}
pub struct ChosenMessageOTReceiver<E: MultiPartyEngine> {
    rots: Vec<OTReceiver<Msg>>,
    engine: E,
}
impl<E: MultiPartyEngine> ChosenMessageOTReceiver<E> {
    pub async fn init(mut engine: E, batch_size: usize) -> Result<Self, ()> {
        let choice_bits: Vec<bool> = (0..batch_size).map(|_| E::rng().gen()).collect();
        let rots = batch_endemic_ot_receiver(&mut engine, choice_bits).await?;
        Ok(Self { rots, engine })
    }
    pub async fn handle_choice(mut self) -> Result<Vec<OTReceiver<GF128>>, ()> {
        let (msgs, _): (Vec<(GF128, GF128)>, PartyId) = self.engine.recv().await.ok_or(())?;
        if msgs.len() != self.rots.len() {
            return Err(());
        }
        Ok(msgs
            .into_iter()
            .zip(self.rots.iter())
            .map(|((msg0, msg1), rot)| {
                let msg = if rot.1 { msg1 } else { msg0 };
                let key0: [u8; 16] = core::array::from_fn(|i| rot.0[i]);
                let msg0 = GF128::from(key0) + msg;
                OTReceiver(msg0, rot.1)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::thread_rng;
    use tokio::join;

    use super::{ChosenMessageOTReceiver, ChosenMessageOTSender};
    use crate::{
        engine::LocalRouter,
        fields::{FieldElement, GF128},
        uc_tags::UCTag,
    };

    #[tokio::test]
    async fn test_chosen_message() {
        const BATCH_SIZE: usize = 1;
        let party_ids = [1, 2];
        let party_ids_set = HashSet::from(party_ids);
        let (router, mut engines) = LocalRouter::new(UCTag::new(&"root tag"), &party_ids_set);
        let router_handle = tokio::spawn(router.launch());
        let mut rng = thread_rng();

        let ots_sender =
            ChosenMessageOTSender::init(engines.remove(&party_ids[0]).unwrap(), BATCH_SIZE);
        let ots_receiver =
            ChosenMessageOTReceiver::init(engines.remove(&party_ids[1]).unwrap(), BATCH_SIZE);
        let (sender_output, receiver_output) = join!(ots_sender, ots_receiver);
        let (sender_output, receiver_output) = (sender_output.unwrap(), receiver_output.unwrap());

        let sender_msgs: Vec<_> = (0..BATCH_SIZE)
            .map(|_| (GF128::random(&mut rng), GF128::random(&mut rng)))
            .collect();
        let chosen_ot_sender = sender_output.choose(&sender_msgs);
        let chosen_ot_receiver = receiver_output.handle_choice();

        let (_, receiver_output) = join!(chosen_ot_sender, chosen_ot_receiver);
        let receiver_output = receiver_output.unwrap();
        router_handle.await.unwrap().unwrap();

        assert_eq!(BATCH_SIZE, sender_msgs.len());
        assert_eq!(BATCH_SIZE, receiver_output.len());
        sender_msgs
            .into_iter()
            .zip(receiver_output.into_iter())
            .for_each(|(ot_sender, ot_receiver)| {
                if ot_receiver.1 {
                    assert_eq!(ot_sender.1, ot_receiver.0);
                } else {
                    assert_eq!(ot_sender.0, ot_receiver.0);
                }
            })
    }
}

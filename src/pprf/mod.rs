use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF128},
    ot::{ChosenMessageOTReceiver, ChosenMessageOTSender},
    pseudorandom::prg::{double_prg_many_inplace, fill_prg},
};

#[derive(Serialize, Deserialize)]
pub struct OfflinePprfSender {
    pub seed: GF128,
    pub depth: usize,
}

impl OfflinePprfSender {
    pub fn new(depth: usize, seed: GF128) -> Self {
        Self { seed, depth }
    }
}

pub struct PprfSender {
    pub evals: Vec<GF128>,
    pub left_right_sums: Vec<(GF128, GF128)>,
}
impl From<OfflinePprfSender> for PprfSender {
    fn from(value: OfflinePprfSender) -> Self {
        (&value).into()
    }
}

impl From<&OfflinePprfSender> for PprfSender {
    fn from(value: &OfflinePprfSender) -> Self {
        let mut evals = vec![GF128::zero(); 1 << value.depth];
        let mut left_right_sums = Vec::<(GF128, GF128)>::with_capacity(value.depth);
        evals[0] = value.seed;
        for i in 0..value.depth {
            double_prg_many_inplace(&mut evals[0..1 << (i + 1)]);
            left_right_sums.push(
                evals[0..1 << (i + 1)]
                    .chunks_exact(2)
                    .fold((GF128::zero(), GF128::zero()), |a, b| {
                        (a.0 + b[0], a.1 + b[1])
                    }),
            );
        }
        Self {
            evals,
            left_right_sums,
        }
    }
}
pub async fn pprf_sender<T: MultiPartyEngine>(
    mut engine: T,
    left_right_sums: &[(GF128, GF128)],
    delta: GF128,
) -> Result<(), ()> {
    let ot_sender =
        ChosenMessageOTSender::init(engine.sub_protocol(&"PPRF TO OT"), left_right_sums.len())
            .await?;
    ot_sender.choose(left_right_sums).await;
    let last_msg = left_right_sums.last().unwrap();
    engine.broadcast(last_msg.0 + last_msg.1 + delta);
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct PackedPprfReceiver {
    pub punctured_index: usize,
    pub subtree_seeds: Vec<GF128>,
    pub val_at_index: GF128,
}

impl From<&PackedPprfReceiver> for PprfReceiver {
    fn from(value: &PackedPprfReceiver) -> Self {
        let depth = value.subtree_seeds.len();
        let n = 1 << depth;
        let mut evals = Vec::with_capacity(n);
        assert!(value.punctured_index < n);
        let mut current_index = value.val_at_index;
        let mut top = n;
        let mut bottom = 0;
        for seed in value.subtree_seeds.iter() {
            let mid = (top + bottom) / 2;
            if value.punctured_index >= mid {
                fill_prg(seed, &mut evals[bottom..mid]);
                bottom = mid;
            } else {
                fill_prg(seed, &mut evals[mid..top]);
                top = mid;
            }
        }
        debug_assert_eq!(bottom, value.punctured_index);
        evals[value.punctured_index] = value.val_at_index;
        Self {
            punctured_index: value.punctured_index,
            evals,
        }
    }
}

pub struct PprfReceiver {
    pub punctured_index: usize,
    pub evals: Vec<GF128>,
}
pub async fn pprf_receiver<T: MultiPartyEngine>(
    mut engine: T,
    depth: usize,
) -> Result<PprfReceiver, ()> {
    let ot_receiver =
        ChosenMessageOTReceiver::init(engine.sub_protocol(&"PPRF TO OT"), depth).await?;
    let receiver_ots = ot_receiver.handle_choice().await?;
    let mut evals = vec![GF128::zero(); 1 << depth];
    let mut punctured_index = 0;
    receiver_ots.into_iter().enumerate().for_each(|(idx, ot)| {
        let round_slice = &mut evals[0..2 << idx];
        double_prg_many_inplace(round_slice);
        let mut node_val = ot.0;
        let point_to_restore = 2 * punctured_index + (ot.1 as usize);
        punctured_index = 2 * punctured_index + (!ot.1 as usize);
        let start_idx = point_to_restore & 1;
        for p in round_slice.iter().skip(start_idx).step_by(2) {
            node_val += p;
        }
        node_val -= evals[point_to_restore];
        evals[point_to_restore] = node_val;
    });
    let xor_all = evals.iter().fold(GF128::zero(), |acc, cur| acc + *cur);
    let (xor_all_with_delta, _): (GF128, PartyId) = engine.recv().await.ok_or(())?;
    evals[punctured_index] += xor_all - xor_all_with_delta;
    Ok(PprfReceiver {
        punctured_index,
        evals,
    })
}

#[cfg(test)]
mod tests {
    use super::{pprf_receiver, pprf_sender};
    use super::{OfflinePprfSender, PprfSender};
    use crate::{
        engine::LocalRouter,
        fields::{FieldElement, GF128},
        uc_tags::UCTag,
    };
    use rand::thread_rng;
    use std::collections::HashSet;
    use tokio::join;

    #[tokio::test]
    async fn test_pprf() {
        const PPRF_DEPTH: usize = 20;
        let party_ids = [1, 2];
        let party_ids_set = HashSet::from(party_ids);
        let (router, mut engines) = LocalRouter::new(UCTag::new(&"root tag"), &party_ids_set);
        let router_handle = tokio::spawn(router.launch());
        let pprf_sender_engine = engines.remove(&party_ids[0]).unwrap();
        let pprf_receiver_engine = engines.remove(&party_ids[1]).unwrap();
        let mut rng = thread_rng();
        let delta = GF128::random(&mut rng);
        let pprf_sender_val: PprfSender =
            OfflinePprfSender::new(PPRF_DEPTH, GF128::random(&mut rng)).into();
        let pprf_sender_handle =
            pprf_sender(pprf_sender_engine, &pprf_sender_val.left_right_sums, delta);
        let pprf_receiver_handle = tokio::spawn(pprf_receiver(pprf_receiver_engine, PPRF_DEPTH));

        let (pprf_sender_future, pprf_receiver_res) =
            join!(pprf_sender_handle, pprf_receiver_handle);
        let (_, pprf_receiver_res) = (
            pprf_sender_future.unwrap(),
            pprf_receiver_res.unwrap().unwrap(),
        );

        assert_eq!(pprf_receiver_res.evals.len(), pprf_sender_val.evals.len());
        let rec_evals = pprf_receiver_res.evals;
        let snd_evals = pprf_sender_val.evals;
        let punctured_index = pprf_receiver_res.punctured_index;
        rec_evals
            .into_iter()
            .zip(snd_evals.iter().copied())
            .enumerate()
            .for_each(|(idx, (snd, rcv))| {
                if idx != punctured_index {
                    assert_eq!(snd, rcv);
                } else {
                    assert_eq!(snd + rcv, delta);
                }
            });
        router_handle.await.unwrap().unwrap();
    }
}

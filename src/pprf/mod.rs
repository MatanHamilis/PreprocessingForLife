use std::mem::MaybeUninit;

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF128},
    ot::{ChosenMessageOTReceiver, ChosenMessageOTSender},
    pseudorandom::prg::{double_prg_field, double_prg_many_inplace, fill_prg},
};

#[derive(Serialize, Deserialize)]
pub struct PackedPprfSender {
    pub seed: GF128,
    pub depth: usize,
}

impl PackedPprfSender {
    pub fn new(depth: usize, seed: GF128) -> Self {
        Self { seed, depth }
    }
}

pub struct PprfSender {
    pub evals: Vec<GF128>,
    pub left_right_sums: Vec<(GF128, GF128)>,
}
// impl From<PackedPprfSender> for PprfSender {
//     fn from(value: PackedPprfSender) -> Self {
//         (&value).into()
//     }
// }

impl PackedPprfSender {
    fn inflate_internal(&self, is_deal: bool) -> (Vec<GF128>, Option<Vec<(GF128, GF128)>>) {
        let mut evals = Vec::with_capacity(1 << self.depth);
        unsafe { evals.set_len(1 << self.depth) };
        let mut left_right_sums = if is_deal {
            None
        } else {
            Some(Vec::<(GF128, GF128)>::with_capacity(self.depth))
        };
        evals[0] = self.seed;
        for i in 0..self.depth {
            double_prg_many_inplace(&mut evals[0..1 << (i + 1)]);
            if !is_deal {
                let sums = left_right_sums.as_mut().unwrap();
                sums.push(
                    evals[0..1 << (i + 1)]
                        .chunks_exact(2)
                        .fold((GF128::zero(), GF128::zero()), |a, b| {
                            (a.0 + b[0], a.1 + b[1])
                        }),
                );
            }
        }
        (evals, left_right_sums)
    }
    pub fn inflate_distributed(&self) -> PprfSender {
        let (evals, left_right_sums) = self.inflate_internal(false);
        PprfSender {
            evals,
            left_right_sums: left_right_sums.unwrap(),
        }
    }
    pub fn inflate_with_deal(&self) -> Vec<GF128> {
        self.inflate_internal(true).0
    }
    pub fn puncture(&self, punctured_index: usize) -> PackedPprfReceiver {
        let mut seed = self.seed;
        let mut subtree_seeds = Vec::with_capacity(self.depth);
        for i in (0..self.depth).rev() {
            let (s_0, s_1) = double_prg_field(&seed);
            let bit = (punctured_index >> i) & 1 == 1;
            if bit {
                subtree_seeds.push(s_0);
                seed = s_1;
            } else {
                subtree_seeds.push(s_1);
                seed = s_0;
            }
        }
        PackedPprfReceiver {
            punctured_index,
            subtree_seeds,
        }
    }
}

// impl From<&PackedPprfSender> for PprfSender {
//     fn from(value: &PackedPprfSender) -> Self {
//         // let mut evals = vec![GF128::zero(); 1 << value.depth];
//         let mut evals = Vec::with_capacity(1 << value.depth);
//         unsafe { evals.set_len(1 << value.depth) };
//         let mut left_right_sums = Vec::<(GF128, GF128)>::with_capacity(value.depth);
//         evals[0] = value.seed;
//         for i in 0..value.depth {
//             double_prg_many_inplace(&mut evals[0..1 << (i + 1)]);
//             left_right_sums.push(
//                 evals[0..1 << (i + 1)]
//                     .chunks_exact(2)
//                     .fold((GF128::zero(), GF128::zero()), |a, b| {
//                         (a.0 + b[0], a.1 + b[1])
//                     }),
//             );
//         }
//         Self {
//             evals,
//             left_right_sums: Vec::new(),
//         }
//     }
// }
pub async fn distributed_pprf_sender(
    engine: impl MultiPartyEngine,
    left_right_sums: &[(GF128, GF128)],
) -> Result<(), ()> {
    let ot_sender =
        ChosenMessageOTSender::init(engine.sub_protocol(&"PPRF TO OT"), left_right_sums.len())
            .await?;
    ot_sender.choose(left_right_sums).await;
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct PackedPprfReceiver {
    pub punctured_index: usize,
    pub subtree_seeds: Vec<GF128>,
}

impl From<&PackedPprfReceiver> for PprfReceiver {
    fn from(value: &PackedPprfReceiver) -> Self {
        let depth = value.subtree_seeds.len();
        let n = 1 << depth;
        let mut evals = Vec::with_capacity(n);
        unsafe { evals.set_len(n) };
        assert!(value.punctured_index < n);
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
        evals[value.punctured_index] = GF128::zero();
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
pub async fn distributed_pprf_receiver<T: MultiPartyEngine>(
    mut engine: T,
    depth: usize,
) -> Result<PprfReceiver, ()> {
    let ot_receiver =
        ChosenMessageOTReceiver::init(engine.sub_protocol(&"PPRF TO OT"), depth).await?;
    let receiver_ots = ot_receiver.handle_choice().await?;
    let mut evals = Vec::with_capacity(1 << depth);
    unsafe { evals.set_len(1 << depth) };
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
    evals[punctured_index] = GF128::zero();
    Ok(PprfReceiver {
        punctured_index,
        evals,
    })
}

pub fn deal_pprf(
    depth: usize,
    mut rng: impl CryptoRng + RngCore,
) -> (PackedPprfSender, PackedPprfReceiver) {
    let sender = PackedPprfSender::new(depth, GF128::random(&mut rng));
    let punctured_index = (rng.next_u64() % (1 << depth)) as usize;
    let receiver = sender.puncture(punctured_index);
    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::{deal_pprf, distributed_pprf_receiver, distributed_pprf_sender};
    use super::{PackedPprfSender, PprfSender};
    use crate::pprf::PprfReceiver;
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
        let pprf_sender_val: PprfSender =
            PackedPprfSender::new(PPRF_DEPTH, GF128::random(&mut rng)).inflate_distributed();
        let pprf_sender_handle =
            distributed_pprf_sender(pprf_sender_engine, &pprf_sender_val.left_right_sums);
        let pprf_receiver_handle =
            tokio::spawn(distributed_pprf_receiver(pprf_receiver_engine, PPRF_DEPTH));

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
            .for_each(|(idx, (rcv, snd))| {
                if idx != punctured_index {
                    assert_eq!(snd, rcv);
                } else {
                    assert!(rcv.is_zero());
                }
            });
        router_handle.await.unwrap().unwrap();
    }
    #[test]
    fn test_puncture() {
        const DEPTH: usize = 1;
        let (sender, receiver) = deal_pprf(DEPTH, thread_rng());
        let sender = sender.inflate_with_deal();
        let receiver = PprfReceiver::from(&receiver);
        for i in 0..1 << DEPTH {
            if i != receiver.punctured_index {
                assert_eq!(sender[i], receiver.evals[i])
            }
        }
    }
}

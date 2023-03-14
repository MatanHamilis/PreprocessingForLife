use tokio::join;

use crate::{
    engine::{MultiPartyEngine, PartyId},
    fields::{FieldElement, GF128},
    ot::{ChosenMessageOTReceiver, ChosenMessageOTSender},
    pseudorandom::prg::double_prg_many_inplace,
};
pub struct PprfSender {
    seed: GF128,
    evals: Vec<GF128>,
}
pub async fn pprf_sender<T: MultiPartyEngine>(
    mut engine: T,
    depth: usize,
    delta: GF128,
) -> Result<PprfSender, ()> {
    let ot_sender_handle = ChosenMessageOTSender::init(engine.sub_protocol(&"PPRF TO OT"), depth);
    let pprf_processing_handle = tokio::spawn(async move {
        let mut ot_msgs = Vec::<(GF128, GF128)>::with_capacity(depth);
        let mut output = vec![GF128::zero(); 1 << depth];
        let seed = GF128::random(&mut T::rng());
        output[0] = seed;
        for i in 0..depth {
            double_prg_many_inplace(&mut output[0..1 << (i + 1)]);
            ot_msgs.push(
                output[0..1 << (i + 1)]
                    .chunks_exact(2)
                    .fold((GF128::zero(), GF128::zero()), |a, b| {
                        (a.0 + b[0], a.1 + b[1])
                    }),
            );
        }
        (
            ot_msgs,
            PprfSender {
                seed,
                evals: output,
            },
        )
    });
    let (pprf_gen_result, ot_init_result) = join!(pprf_processing_handle, ot_sender_handle);
    let (ot_msgs, pprf_senders) = pprf_gen_result.or(Err(()))?;
    let last_msg = ot_msgs.last().ok_or(())?;
    let msg = last_msg.0 + last_msg.1 + delta;
    engine.broadcast(&msg);
    let ot_sender = ot_init_result?;
    ot_sender.choose(&ot_msgs).await;
    Ok(pprf_senders)
}

pub struct PprfReceiver {
    punctured_index: usize,
    evals: Vec<GF128>,
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
    use crate::{engine::LocalRouter, fields::GF128};
    use rand::thread_rng;
    use std::collections::HashSet;
    use tokio::join;

    #[tokio::test]
    async fn test_pprf() {
        const PPRF_DEPTH: usize = 20;
        let party_ids = [1, 2];
        let party_ids_set = HashSet::from(party_ids);
        let (router, mut engines) = LocalRouter::new("root tag".into(), &party_ids_set);
        let router_handle = tokio::spawn(router.launch());
        let pprf_sender_engine = engines.remove(&party_ids[0]).unwrap();
        let pprf_receiver_engine = engines.remove(&party_ids[1]).unwrap();
        let mut rng = thread_rng();
        let delta = GF128::random(&mut rng);
        let pprf_sender_handle = tokio::spawn(pprf_sender(pprf_sender_engine, PPRF_DEPTH, delta));
        let pprf_receiver_handle = tokio::spawn(pprf_receiver(pprf_receiver_engine, PPRF_DEPTH));

        let (pprf_sender_res, pprf_receiver_res) = join!(pprf_sender_handle, pprf_receiver_handle);
        let (pprf_sender_res, pprf_receiver_res) = (
            pprf_sender_res.unwrap().unwrap(),
            pprf_receiver_res.unwrap().unwrap(),
        );

        assert_eq!(pprf_receiver_res.evals.len(), pprf_sender_res.evals.len());
        let rec_evals = pprf_receiver_res.evals;
        let snd_evals = pprf_sender_res.evals;
        let punctured_index = pprf_receiver_res.punctured_index;
        rec_evals
            .into_iter()
            .zip(snd_evals.into_iter())
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

use std::collections::HashMap;

use aes_prng::AesRng;
use blake3::{hash, Hash, OUT_LEN};
use rand::SeedableRng;
use rand_core::RngCore;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{engine::MultiPartyEngine, fields::FieldElement, PartyId};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CommmitShare {
    Seed([u8; 16], usize),
    Value(Box<[u8]>),
}

impl CommmitShare {
    fn len(&self) -> usize {
        match self {
            Self::Seed(_, length) => *length,
            Self::Value(v) => v.len(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OfflineCommitment {
    pub(crate) commit_share: CommmitShare,
    pub(crate) commitment: [u8; OUT_LEN],
}

pub fn commit_value<T: Serialize>(v: &T) -> [u8; OUT_LEN] {
    let mut encoded_value: Box<[u8]> = bincode::serialize(v).unwrap().into();
    *blake3::hash(&encoded_value).as_bytes()
}
impl OfflineCommitment {
    pub fn commit<T: Serialize + DeserializeOwned>(
        value: &T,
        party_count: usize,
    ) -> (Vec<CommmitShare>, [u8; OUT_LEN]) {
        let mut encoded_value: Box<[u8]> = bincode::serialize(value).unwrap().into();
        let value_hash = blake3::hash(&encoded_value);
        let mut rng = AesRng::from_random_seed();
        let seeds: Vec<[u8; 16]> = (0..party_count - 1)
            .map(|_| {
                let mut seed = [0u8; 16];
                rng.fill_bytes(&mut seed);
                seed
            })
            .collect();
        let mut xor_share: Vec<u8> = Vec::with_capacity(encoded_value.len());
        unsafe { xor_share.set_len(encoded_value.len()) };
        for s in seeds.iter().copied() {
            let mut rng = AesRng::from_seed(s);
            rng.fill_bytes(&mut xor_share);
            encoded_value
                .iter_mut()
                .zip(xor_share.iter())
                .for_each(|(d, s)| *d ^= *s);
        }
        let encoded_value_len = encoded_value.len();
        let v: Vec<_> = seeds
            .iter()
            .map(|&s| CommmitShare::Seed(s, encoded_value_len))
            .chain(std::iter::once(CommmitShare::Value(encoded_value)))
            .collect();
        (v, *value_hash.as_bytes())
    }
    pub async fn offline_commit<E: MultiPartyEngine, T: Serialize + DeserializeOwned>(
        engine: &mut E,
        value: &T,
    ) {
        let my_id = engine.my_party_id();
        let peers: Box<[PartyId]> = engine
            .party_ids()
            .iter()
            .copied()
            .filter(|v| v != &my_id)
            .collect();
        let (vs, hash) = Self::commit(value, peers.len());
        vs.iter().zip(peers.iter()).for_each(|(v, &pid)| {
            engine.send((v, hash), pid);
        });
    }

    pub async fn offline_obtain_commit(
        engine: &mut impl MultiPartyEngine,
        committer: PartyId,
    ) -> OfflineCommitment {
        let (commit_share, commitment): (CommmitShare, [u8; blake3::OUT_LEN]) =
            engine.recv_from(committer).await.unwrap();
        OfflineCommitment {
            commit_share,
            commitment,
        }
    }

    pub async fn online_decommit<T: Serialize + DeserializeOwned, E: MultiPartyEngine>(
        &self,
        engine: &mut E,
    ) -> T {
        let my_id = engine.my_party_id();
        let peers: Box<[PartyId]> = engine
            .party_ids()
            .iter()
            .copied()
            .filter(|v| v != &my_id)
            .collect();
        let mut seeds = HashMap::with_capacity(peers.len());
        let mut v = Option::<(Box<[u8]>, PartyId)>::None;
        let self_len = self.commit_share.len();
        engine.broadcast(&self.commit_share);
        let ser_len = match &self.commit_share {
            CommmitShare::Seed(s, length) => {
                seeds.insert(my_id, *s);
                *length
            }
            CommmitShare::Value(vec) => {
                let len = vec.len();
                v = Some((vec.clone(), my_id));
                len
            }
        };
        for _ in 0..peers.len() {
            let (commit_share, from): (CommmitShare, PartyId) = engine.recv().await.unwrap();
            assert_eq!(commit_share.len(), self_len);
            match commit_share {
                CommmitShare::Seed(seed, len) => {
                    assert_eq!(ser_len, len);
                    assert!(seeds.insert(from, seed).is_none());
                }
                CommmitShare::Value(vec) => {
                    assert!(v.is_none());
                    assert_eq!(ser_len, vec.len());
                    v = Some((vec, from));
                }
            }
        }
        assert!(v.is_some());
        let (mut v, v_party) = v.unwrap();
        let mut aux_vec = Vec::with_capacity(self_len);
        unsafe { aux_vec.set_len(self_len) };
        assert!(!seeds.contains_key(&v_party));
        for (_, seed) in seeds.into_iter() {
            let mut rng = AesRng::from_seed(seed);
            rng.fill_bytes(&mut aux_vec);
            v.iter_mut().zip(aux_vec.iter()).for_each(|(d, s)| *d ^= *s);
        }
        let h = hash(&v);
        assert_eq!(h, self.commitment);
        bincode::deserialize(&v).unwrap()
    }
}

pub struct StandardCommitReveal<E: MultiPartyEngine, V: Serialize + DeserializeOwned> {
    engine: E,
    commitments: HashMap<PartyId, [u8; OUT_LEN]>,
    my_value: V,
}
impl<E: MultiPartyEngine, V: Serialize + DeserializeOwned> StandardCommitReveal<E, V> {
    pub async fn commit(mut engine: E, value: V) -> Self {
        let comm = *blake3::hash(&bincode::serialize(&value).unwrap()).as_bytes();
        engine.broadcast(comm);
        let my_id = engine.my_party_id();
        let mut comms = HashMap::with_capacity(engine.party_ids().len() - 1);
        let peers: Vec<_> = engine
            .party_ids()
            .iter()
            .copied()
            .filter(|id| *id != my_id)
            .collect();
        for p in peers {
            let peer_comm = engine.recv_from(p).await.unwrap();
            comms.insert(p, peer_comm);
        }
        Self {
            engine,
            my_value: value,
            commitments: comms,
        }
    }
    pub async fn reveal(mut self) -> HashMap<PartyId, V> {
        self.engine.broadcast(self.my_value);
        let mut output_values = HashMap::with_capacity(self.engine.party_ids().len() - 1);
        for (p, comm) in self.commitments {
            let peer_value: V = self.engine.recv_from(p).await.unwrap();
            let computed_comm = *blake3::hash(&bincode::serialize(&peer_value).unwrap()).as_bytes();
            assert_eq!(computed_comm, comm);
            output_values.insert(p, peer_value);
        }
        output_values
    }
}

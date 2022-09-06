use super::scalar_party::{
    OfflineSparseVoleKey as ScalarPartyOfflineKey, PcgItem as ScalarPcgItem,
};
use super::vector_party::{
    OfflineSparseVoleKey as VectorPartyOfflineKey, PcgItem as VectorPcgItem,
};
use crate::fields::{FieldElement, GF128, GF2};

pub struct SparseVoleScalarPartyPackedOfflineKey<const PACK: usize> {
    accumulated_vector: Vec<[GF128; PACK]>,
    pub scalars: [GF128; PACK],
}

impl<const PACK: usize> SparseVoleScalarPartyPackedOfflineKey<PACK> {
    pub fn len(&self) -> usize {
        self.accumulated_vector.len()
    }

    pub fn new(offline_keys: [ScalarPartyOfflineKey; PACK]) -> Self {
        let accumulated_vector_len = offline_keys[0].accumulated_vector.len();
        let scalars = core::array::from_fn(|i| offline_keys[i].scalar);
        for i in 1..PACK {
            assert_eq!(
                accumulated_vector_len,
                offline_keys[i].accumulated_vector.len()
            );
        }

        let accumulated_vector: Vec<[GF128; PACK]> = (0..accumulated_vector_len)
            .into_iter()
            .map(|idx| {
                core::array::from_fn(|key_idx| offline_keys[key_idx].accumulated_vector[idx])
            })
            .collect();

        Self {
            accumulated_vector,
            scalars,
        }
    }
}

pub struct SparseVoleScalarPartyPackedOnlineKey<
    const PACK: usize,
    const CODE_WEIGHT: usize,
    S: Iterator<Item = [u32; CODE_WEIGHT]>,
> {
    accumulated_vector: Vec<[GF128; PACK]>,
    scalars: [GF128; PACK],
    code: S,
    cache: [ScalarPcgItem; PACK],
    cache_index: usize,
}

impl<const PACK: usize, const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>>
    SparseVoleScalarPartyPackedOnlineKey<PACK, CODE_WEIGHT, S>
{
    pub fn new(code: S, offline_key: SparseVoleScalarPartyPackedOfflineKey<PACK>) -> Self {
        Self {
            accumulated_vector: offline_key.accumulated_vector,
            scalars: offline_key.scalars,
            code,
            cache: [ScalarPcgItem::default(); PACK],
            cache_index: 0usize,
        }
    }
}

impl<const PACK: usize, const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>> Iterator
    for SparseVoleScalarPartyPackedOnlineKey<PACK, CODE_WEIGHT, S>
{
    type Item = ScalarPcgItem;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cache_index == 0 {
            let code_idxs: [u32; CODE_WEIGHT] = match self.code.next() {
                None => {
                    return None;
                }
                Some(v) => v,
            };
            let sums = code_idxs
                .into_iter()
                .map(|idx| self.accumulated_vector[idx as usize])
                .fold([GF128::default(); PACK], |acc, cur| {
                    core::array::from_fn(|idx| acc[idx] + cur[idx])
                });
            self.cache = core::array::from_fn(|idx| (sums[idx], self.scalars[idx]));
        }
        let cache_index = self.cache_index;
        self.cache_index = (cache_index + 1) % PACK;
        return Some(self.cache[cache_index]);
    }
}

pub struct SparseVoleVectorPartyPackedOfflineKey<const PACK: usize> {
    accumulated_vector: Vec<[(GF2, GF128); PACK]>,
}

impl<const PACK: usize> SparseVoleVectorPartyPackedOfflineKey<PACK> {
    pub fn len(&self) -> usize {
        self.accumulated_vector.len()
    }

    pub fn new(offline_keys: [VectorPartyOfflineKey; PACK]) -> Self {
        let accumulated_vector_len = offline_keys[0].accumulated_scalar_vector.len();
        for i in 1..PACK {
            assert_eq!(
                accumulated_vector_len,
                offline_keys[i].accumulated_scalar_vector.len()
            );
        }

        let accumulated_vector: Vec<[(GF2, GF128); PACK]> = (0..accumulated_vector_len)
            .into_iter()
            .map(|idx| {
                core::array::from_fn(|key_idx| offline_keys[key_idx].accumulated_scalar_vector[idx])
            })
            .collect();

        Self { accumulated_vector }
    }
}

pub struct SparseVoleVectorPartyPackedOnlineKey<
    const PACK: usize,
    const CODE_WEIGHT: usize,
    S: Iterator<Item = [u32; CODE_WEIGHT]>,
> {
    accumulated_vector: Vec<[(GF2, GF128); PACK]>,
    code: S,
    cache: [VectorPcgItem; PACK],
    cache_index: usize,
}

impl<const PACK: usize, const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>>
    SparseVoleVectorPartyPackedOnlineKey<PACK, CODE_WEIGHT, S>
{
    pub fn new(code: S, offline_key: SparseVoleVectorPartyPackedOfflineKey<PACK>) -> Self {
        Self {
            accumulated_vector: offline_key.accumulated_vector,
            code,
            cache: [VectorPcgItem::default(); PACK],
            cache_index: 0usize,
        }
    }
}

impl<const PACK: usize, const CODE_WEIGHT: usize, S: Iterator<Item = [u32; CODE_WEIGHT]>> Iterator
    for SparseVoleVectorPartyPackedOnlineKey<PACK, CODE_WEIGHT, S>
{
    type Item = VectorPcgItem;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cache_index == 0 {
            let code_idxs: [u32; CODE_WEIGHT] = match self.code.next() {
                None => {
                    return None;
                }
                Some(v) => v,
            };
            self.cache = code_idxs
                .into_iter()
                .map(|idx| self.accumulated_vector[idx as usize])
                .fold([(GF2::zero(), GF128::zero()); PACK], |acc, cur| {
                    core::array::from_fn(|arr_idx| {
                        (
                            acc[arr_idx].0 + cur[arr_idx].0,
                            acc[arr_idx].1 + cur[arr_idx].1,
                        )
                    })
                });
        }
        let cache_index = self.cache_index;
        self.cache_index = (cache_index + 1) % PACK;
        return Some(self.cache[cache_index]);
    }
}

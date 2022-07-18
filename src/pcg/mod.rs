pub mod bit_beaver_triples;
pub mod codes;
pub mod pprf_aggregator;
pub mod random_bit_ot;
pub mod random_ot;
pub mod sparse_vole;

pub(crate) const KEY_SIZE: usize = 16;

pub(crate) fn xor_arrays<const LENGTH: usize>(a: &mut [u8; LENGTH], b: &[u8; LENGTH]) {
    for i in 0..LENGTH {
        a[i] ^= b[i];
    }
}

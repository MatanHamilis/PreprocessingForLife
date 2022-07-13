use crate::sparse_vole::scalar_party::OnlineSparseVoleKey as ScalarSparseVoleOnlineKey;
use std::iter::Iterator;
struct RandomOTSenderOnlinePCGKey {
    vole_online_key: ScalarSparseVoleOnlineKey,
}
impl Iterator for RandomOTSenderOnlinePCGKey {
    type Item = (GF128, GF128);
    fn next(&mut self) -> Option<Self::Item> {
        match self.vole_online_key.next() {
            None => None,
            Some(v) => Some((v, v + self.vole_online_key.scalar)),
        }
    }
}

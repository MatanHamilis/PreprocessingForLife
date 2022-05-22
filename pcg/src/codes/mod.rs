use rand::seq::IteratorRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub struct EACode<const WEIGHT: usize> {
    width: usize,
    height: usize,
    cur_height: usize,
    csprng: ChaCha8Rng,
}

impl<const WEIGHT: usize> EACode<WEIGHT> {
    pub fn new(width: usize, height: usize, seed: [u8; 32]) -> Self {
        EACode {
            width,
            height,
            cur_height: 0,
            csprng: ChaCha8Rng::from_seed(seed),
        }
    }
}

impl<const WEIGHT: usize> Iterator for EACode<WEIGHT> {
    type Item = [usize; WEIGHT];
    fn next(&mut self) -> Option<Self::Item> {
        if self.height == self.cur_height {
            return None;
        }
        self.cur_height += 1;
        let mut output = [0usize; WEIGHT];
        (0..self.width).choose_multiple_fill(&mut self.csprng, &mut output);
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::codes::EACode;
    #[test]
    pub fn test_sanity() {
        let code = EACode::<5>::new(12, 100, [1; 32]);
        let mut i = 0;
        for v in code {
            i += 1;
            assert_eq!(v.len(), 12);
        }
        assert_eq!(i, 100);
    }
}

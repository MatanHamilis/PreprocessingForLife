use fields::GF128;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub struct EACode {
    weight: usize,
    width: usize,
    height: usize,
    cur_height: usize,
    csprng: ChaCha8Rng,
}

impl EACode {
    pub fn new(weight: usize, width: usize, height: usize, seed: [u8; 32]) -> Self {
        EACode {
            weight,
            width,
            height,
            cur_height: 0,
            csprng: ChaCha8Rng::from_seed(seed),
        }
    }
}

impl Iterator for EACode {
    type Item = Vec<GF128>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.height == self.cur_height {
            return None;
        }
        self.cur_height += 1;
        let mut output = vec![GF128::zero(); self.width];
        for i in (0..self.width).choose_multiple(&mut self.csprng, self.weight) {
            output[i] = GF128::one();
        }
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use crate::codes::EACode;
    #[test]
    pub fn test_sanity() {
        let code = EACode::new(5, 12, 100, [1; 32]);
        let mut i = 0;
        for v in code {
            i += 1;
            assert_eq!(v.len(), 12);
        }
        assert_eq!(i, 100);
    }
}

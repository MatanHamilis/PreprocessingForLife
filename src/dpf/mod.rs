use crate::{pseudorandom::double_prg, xor_arrays};

pub mod dpf_pir;
pub const DPF_KEY_SIZE: usize = 16;

#[derive(Default, Clone, Copy)]
pub struct CorrectionWord {
    pub string: [u8; DPF_KEY_SIZE],
    pub bit_0: bool,
    pub bit_1: bool,
}
pub struct DpfKey<const DEPTH: usize> {
    pub first_word: [u8; DPF_KEY_SIZE],
    pub first_toggle_bit: bool,
    pub corrections: [CorrectionWord; DEPTH],
    pub last_correction: [u8; DPF_KEY_SIZE],
}

fn expand_seed(seed: &[u8; DPF_KEY_SIZE]) -> ([u8; DPF_KEY_SIZE], bool, [u8; DPF_KEY_SIZE], bool) {
    let (scw_0, seed_2) = double_prg(&seed);
    let (scw_1, toggle_bits) = double_prg(&seed_2);
    (
        scw_0,
        toggle_bits[0] & 1 == 0,
        scw_1,
        toggle_bits[0] & 2 == 0,
    )
}

impl<const DEPTH: usize> DpfKey<DEPTH> {
    pub fn gen(
        hiding_point: &[bool; DEPTH],
        point_val: &[u8; DPF_KEY_SIZE],
        dpf_root_0: [u8; DPF_KEY_SIZE],
        dpf_root_1: [u8; DPF_KEY_SIZE],
    ) -> (DpfKey<DEPTH>, DpfKey<DEPTH>) {
        let mut correction = [CorrectionWord::default(); DEPTH];
        let mut toggle_0 = false;
        let mut toggle_1 = true;
        let mut cw_0 = dpf_root_0;
        let mut cw_1 = dpf_root_1;
        for i in 0..DEPTH {
            let (mut s_0_l, t_0_l, mut s_0_r, t_0_r) = expand_seed(&cw_0);
            let (s_1_l, t_1_l, s_1_r, t_1_r) = expand_seed(&cw_1);
            let (mut s_0_lose, s_1_lose, mut s_0_keep, mut s_1_keep, t_0_keep, t_1_keep) =
                if hiding_point[i] {
                    (s_0_l, s_1_l, s_0_r, s_1_r, t_0_r, t_1_r)
                } else {
                    (s_0_r, s_1_r, s_0_l, s_1_l, t_0_l, t_1_l)
                };
            xor_arrays(&mut s_0_lose, &s_1_lose);
            let s_cw = s_0_lose;
            let (t_cw_l, t_cw_r) = (
                !(t_0_l ^ t_1_l ^ hiding_point[i]),
                t_0_r ^ t_1_r ^ hiding_point[i],
            );
            let t_cw_keep = !(t_0_keep ^ t_1_keep);
            correction[i] = CorrectionWord {
                string: s_cw,
                bit_0: t_cw_l,
                bit_1: t_cw_r,
            };
            (cw_0, cw_1, toggle_0, toggle_1) = if toggle_0 {
                xor_arrays(&mut s_0_keep, &s_cw);
                (s_0_keep, s_1_keep, t_0_keep ^ t_cw_keep, t_1_keep)
            } else {
                xor_arrays(&mut s_1_keep, &s_cw);
                (s_0_keep, s_1_keep, t_0_keep, t_1_keep ^ t_cw_keep)
            }
        }
        let mut last_correction = *point_val;
        xor_arrays(&mut last_correction, &cw_0);
        xor_arrays(&mut last_correction, &cw_1);
        (
            DpfKey {
                first_word: dpf_root_0,
                first_toggle_bit: false,
                corrections: correction,
                last_correction: last_correction,
            },
            DpfKey {
                first_word: dpf_root_1,
                first_toggle_bit: true,
                corrections: correction,
                last_correction: last_correction,
            },
        )
    }
    pub fn eval(&self, point: [bool; DEPTH]) -> [u8; DPF_KEY_SIZE] {
        let mut s = self.first_word;
        let mut t = self.first_toggle_bit;
        for i in 0..DEPTH {
            let expanded = expand_seed(&s);
            let mut t_next = false;
            (s, t_next) = if point[i] {
                (expanded.2, expanded.3)
            } else {
                (expanded.0, expanded.1)
            };
            if t {
                xor_arrays(&mut s, &self.corrections[i].string);
                t_next ^= if point[i] {
                    self.corrections[i].bit_1
                } else {
                    self.corrections[i].bit_0
                }
            };
            t = t_next;
        }
        if t {
            xor_arrays(&mut s, &self.last_correction);
        }
        s
    }
    pub fn eval_all_into(&self, output: &mut [[u8; DPF_KEY_SIZE]], aux: &mut [bool]) {
        assert_eq!(output.len(), 1 << DEPTH);
        assert_eq!(aux.len(), 1 << DEPTH);
        output[0] = self.first_word;
        aux[0] = self.first_toggle_bit;
        for i in 0..DEPTH {
            for j in (0..1 << i).rev() {
                let (mut s_l, mut t_l, mut s_r, mut t_r) = expand_seed(&output[j]);
                if aux[j] {
                    xor_arrays(&mut s_l, &self.corrections[i].string);
                    xor_arrays(&mut s_r, &self.corrections[i].string);
                    t_l ^= self.corrections[i].bit_0;
                    t_r ^= self.corrections[i].bit_1;
                };
                output[2 * j] = s_l;
                aux[2 * j] = t_l;
                output[2 * j + 1] = s_r;
                aux[2 * j + 1] = t_r;
            }
        }
        for i in 0..1 << DEPTH {
            if aux[i] {
                xor_arrays(&mut output[i], &self.last_correction);
            }
        }
    }
    pub fn eval_all(&self) -> Vec<[u8; DPF_KEY_SIZE]> {
        let mut output = vec![[0u8; DPF_KEY_SIZE]; 1 << DEPTH];
        let mut aux = vec![false; 1 << DEPTH];
        self.eval_all_into(&mut output, &mut aux);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::DpfKey;
    use super::DPF_KEY_SIZE;
    use crate::pprf::usize_to_bits;
    use crate::xor_arrays;
    #[test]
    fn test_dpf_single_point() {
        const DEPTH: usize = 10;
        let hiding_point: [bool; DEPTH] = usize_to_bits(0b100110);
        let mut point_val = [2u8; DPF_KEY_SIZE];
        let dpf_root_0 = [0u8; DPF_KEY_SIZE];
        let dpf_root_1 = [1u8; DPF_KEY_SIZE];
        point_val[0] = 1;
        let (k_0, k_1) = DpfKey::gen(&hiding_point, &point_val, dpf_root_0, dpf_root_1);
        for i in 0..1 << DEPTH {
            let point = usize_to_bits(i);
            let mut k_0_eval = k_0.eval(point);
            let k_1_eval = k_1.eval(point);
            xor_arrays(&mut k_0_eval, &k_1_eval);
            if (point != hiding_point) {
                assert_eq!(k_0_eval, [0u8; DPF_KEY_SIZE]);
            } else {
                assert_eq!(k_0_eval, point_val);
            }
        }
    }
    #[test]
    fn test_dpf_eval_all() {
        const DEPTH: usize = 20;
        const HIDING_POINT: usize = 0b100110;
        let hiding_point: [bool; DEPTH] = usize_to_bits(HIDING_POINT);
        let mut point_val = [2u8; DPF_KEY_SIZE];
        let dpf_root_0 = [0u8; DPF_KEY_SIZE];
        let dpf_root_1 = [1u8; DPF_KEY_SIZE];
        point_val[0] = 1;
        let (k_0, k_1) = DpfKey::gen(&hiding_point, &point_val, dpf_root_0, dpf_root_1);
        let eval_all_0 = k_0.eval_all();
        let eval_all_1 = k_1.eval_all();
        for i in 0..1 << DEPTH {
            let mut k_0_eval = eval_all_0[i];
            let k_1_eval = eval_all_1[i];
            xor_arrays(&mut k_0_eval, &k_1_eval);
            if (i != HIDING_POINT) {
                assert_eq!(k_0_eval, [0u8; DPF_KEY_SIZE]);
            } else {
                assert_eq!(k_0_eval, point_val);
            }
        }
    }
}

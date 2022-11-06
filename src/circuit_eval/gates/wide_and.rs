use crate::{fields::FieldElement, pcg::bit_beaver_triples::WideBeaverTripletShare};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_big_array::BigArray;

pub const IS_LINEAR: bool = false;
pub const INPUT_COUNT: usize = 129;
pub const OUTPUT_COUNT: usize = 128;

pub struct WideAndGate<S: FieldElement> {
    common_input: usize,
    wide_input: [usize; INPUT_COUNT - 1],
    wide_output: [usize; OUTPUT_COUNT],
    correlation: Option<WideBeaverTripletShare<S>>,
}

impl<S: FieldElement + Serialize + DeserializeOwned> WideAndGate<S> {
    pub fn new(
        common_input: usize,
        wide_input: [usize; INPUT_COUNT - 1],
        wide_output: [usize; OUTPUT_COUNT],
    ) -> Self {
        Self {
            common_input,
            wide_input,
            wide_output,
            correlation: None,
        }
    }

    pub fn input_count() -> usize {
        INPUT_COUNT
    }
    pub fn output_count() -> usize {
        OUTPUT_COUNT
    }
    pub fn is_linear() -> bool {
        IS_LINEAR
    }

    pub fn eval(&self, wires: &mut [S]) {
        let common_input = wires[self.common_input];
        self.wide_output
            .iter()
            .zip(self.wide_input.iter())
            .for_each(|(ow, iw)| wires[*ow] = wires[*iw] * common_input);
    }

    pub fn generate_correlation(&mut self, item: WideBeaverTripletShare<S>) {
        self.correlation = Some(item);
    }

    pub fn generate_msg(&self, wires: &[S]) -> Option<WideAndMsg<S>> {
        let corr = self.correlation.as_ref()?;
        Some(WideAndMsg {
            x_open: wires[self.common_input] + corr.a_share,
            ys_open: std::array::from_fn(|i| wires[self.wide_input[i]] + corr.b_shares[i]),
        })
    }

    pub fn handle_msg(&self, wires: &[S], msg: &WideAndMsg<S>) {}
}

#[derive(Serialize, Deserialize)]
pub struct WideAndMsg<S: FieldElement> {
    #[serde(bound(deserialize = "S: FieldElement"))]
    x_open: S,
    #[serde(with = "BigArray")]
    ys_open: [S; 128],
}

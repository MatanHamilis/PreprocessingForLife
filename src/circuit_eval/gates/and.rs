use serde::{Deserialize, Serialize};

use crate::{fields::FieldElement, pcg::bit_beaver_triples::BeaverTripletShare};

pub const IS_LINEAR: bool = false;
pub const INPUT_COUNT: usize = 2;
pub const OUTPUT_COUNT: usize = 1;

#[derive(Debug)]
pub struct AndGate<S: FieldElement> {
    input_wires: [usize; INPUT_COUNT],
    output_wire: usize,
    correlation: Option<BeaverTripletShare<S>>,
}

impl<'a, S: FieldElement> AndGate<S> {
    pub fn new(input_wires: [usize; INPUT_COUNT], output_wire: usize) -> Self {
        Self {
            input_wires,
            output_wire,
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
        wires[self.output_wire] = wires[self.input_wires[0]] * wires[self.input_wires[1]];
    }
    pub fn generate_correlation(&mut self, item: BeaverTripletShare<S>) {
        self.correlation = Some(item);
    }

    pub fn generate_msg(&self, wires: &[S]) -> Option<AndMsg<S>> {
        let corr = self.correlation.as_ref()?;
        Some(AndMsg(
            wires[self.input_wires[0]] + corr.a_share,
            wires[self.input_wires[1]] + corr.b_share,
        ))
    }

    // u = Open(x + a);
    // v = Open(y + b);
    // [xy] = ((x+a)-a)((y+b)-b)=[u]v-[a]v-[b]u+[ab]=
    //          [x]v-[b]u+[ab]
    pub fn handle_msg(&mut self, wires: &mut [S], msg: &AndMsg<S>) {
        let x_share = wires[self.input_wires[0]];
        let y_share = wires[self.input_wires[1]];
        let beaver_triple = self
            .correlation
            .take()
            .expect("Corrupt circuit! This gate doesn't hold any correlation");
        let u = msg.0 + x_share + beaver_triple.a_share;
        let v = msg.1 + y_share + beaver_triple.b_share;
        wires[self.output_wire] = x_share * v - beaver_triple.b_share * u + beaver_triple.ab_share;
    }
}

#[derive(Serialize, Deserialize)]
pub struct AndMsg<S: FieldElement>(
    #[serde(bound(deserialize = "S: FieldElement"))] S,
    #[serde(bound(deserialize = "S: FieldElement"))] S,
);

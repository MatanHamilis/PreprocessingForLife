use super::Gate;
use crate::{fields::FieldElement, pcg::bit_beaver_triples::BeaverTripletShare};
use std::cell::Cell;

pub const IS_LINEAR: bool = false;
pub const INPUT_COUNT: usize = 2;
pub const OUTPUT_COUNT: usize = 1;

#[derive(Debug)]
pub struct AndGate<'a, S: FieldElement> {
    input_wires: [&'a Cell<S>; INPUT_COUNT],
    output_wire: &'a Cell<S>,
    correlation: Option<BeaverTripletShare<S>>,
}

impl<'a, S: FieldElement> AndGate<'a, S> {
    pub fn new(input_wires: [&'a Cell<S>; INPUT_COUNT], output_wire: &'a Cell<S>) -> Self {
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
    pub fn eval(&self) {
        self.output_wire
            .set(self.input_wires[0].get() * self.input_wires[1].get())
    }
    pub fn generate_correlation(
        &mut self,
        iter: &mut impl Iterator<Item = BeaverTripletShare<S>>,
    ) -> Result<(), ()> {
        self.correlation = Some(iter.next().ok_or(())?);
        Ok(())
    }
}

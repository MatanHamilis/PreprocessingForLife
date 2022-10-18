use super::Gate;
use crate::fields::FieldElement;
use std::cell::Cell;

pub const IS_LINEAR: bool = true;
pub const INPUT_COUNT: usize = 2;
pub const OUTPUT_COUNT: usize = 1;
#[derive(Debug)]
pub struct XorGate<'a, S: FieldElement> {
    input_wires: [&'a Cell<S>; INPUT_COUNT],
    output_wire: &'a Cell<S>,
}

impl<'a, S: FieldElement> XorGate<'a, S> {
    pub fn new(input_wires: [&'a Cell<S>; INPUT_COUNT], output_wire: &'a Cell<S>) -> Self {
        XorGate {
            input_wires,
            output_wire,
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
            .set(self.input_wires[0].get() + self.input_wires[1].get())
    }
}

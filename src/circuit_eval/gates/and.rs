use super::Gate;
use crate::fields::FieldElement;
use std::cell::Cell;

pub const IS_LINEAR: bool = false;
pub const INPUT_COUNT: usize = 2;
pub const OUTPUT_COUNT: usize = 1;

#[derive(Debug)]
pub struct AndGate<'a, S: FieldElement> {
    input_wires: [&'a Cell<S>; INPUT_COUNT],
    output_wire: &'a Cell<S>,
}

impl<'a, S: FieldElement> AndGate<'a, S> {
    pub fn new(input_wires: [&'a Cell<S>; INPUT_COUNT], output_wire: &'a Cell<S>) -> Self {
        Self {
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
}
impl<'a, S: FieldElement> Gate<S> for AndGate<'a, S> {
    fn is_linear(&self) -> bool {
        AndGate::is_linear()
    }
}

use super::Gate;
use crate::fields::FieldElement;
use std::cell::Cell;
use std::fmt::Debug;

pub const IS_LINEAR: bool = true;
pub const INPUT_COUNT: usize = 1;
pub const OUTPUT_COUNT: usize = 1;

#[derive(Debug)]
pub struct NotGate<'a, S: FieldElement> {
    input_wire: &'a Cell<S>,
    output_wire: &'a Cell<S>,
}

impl<'a, S: FieldElement> NotGate<'a, S> {
    pub fn new(input_wire: &Cell<S>, output_wire: &Cell<S>) -> Self {
        NotGate {
            input_wire,
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

impl<'a, S: FieldElement> Gate<S> for NotGate<'a, S> {
    fn is_linear(&self) -> bool {
        NotGate::<'a, S>::is_linear()
    }
}

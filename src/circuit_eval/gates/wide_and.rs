use super::Gate;
use crate::fields::FieldElement;
use std::cell::Cell;

pub const IS_LINEAR: bool = false;
pub const INPUT_COUNT: usize = 129;
pub const OUTPUT_COUNT: usize = 128;

#[derive(Debug)]
pub struct WideAndGate<'a, S: FieldElement> {
    input: [&'a Cell<S>; INPUT_COUNT],
    output: [&'a Cell<S>; OUTPUT_COUNT],
}

impl<'a, S: FieldElement> WideAndGate<'a, S> {
    pub fn new(
        wide_input: [&'a Cell<S>; INPUT_COUNT],
        wide_output: [&'a Cell<S>; OUTPUT_COUNT],
    ) -> Self {
        Self {
            input: wide_input,
            output: wide_output,
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

impl<'a, S: FieldElement> Gate<S> for WideAndGate<'a, S> {
    fn is_linear(&self) -> bool {
        Self::is_linear()
    }
}

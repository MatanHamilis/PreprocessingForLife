use super::Gate;
use crate::fields::FieldElement;
use std::cell::Cell;

pub const IS_LINEAR: bool = false;
pub const INPUT_COUNT: usize = 129;
pub const OUTPUT_COUNT: usize = 128;

#[derive(Debug)]
pub struct WideAndGate<'a, S: FieldElement> {
    common_input: &'a Cell<S>,
    wide_input: [&'a Cell<S>; INPUT_COUNT - 1],
    wide_output: [&'a Cell<S>; OUTPUT_COUNT],
}

impl<'a, S: FieldElement> WideAndGate<'a, S> {
    pub fn new(
        common_input: &'a Cell<S>,
        wide_input: [&'a Cell<S>; INPUT_COUNT - 1],
        wide_output: [&'a Cell<S>; OUTPUT_COUNT],
    ) -> Self {
        Self {
            common_input,
            wide_input,
            wide_output,
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
        let common_input = self.common_input.get();
        self.wide_output
            .iter()
            .zip(self.wide_input.iter())
            .for_each(|(ow, iw)| *ow.set(iw.get() * common_input));
    }
}

use crate::fields::FieldElement;
use std::cell::Cell;

pub const IS_LINEAR: bool = true;
pub const INPUT_COUNT: usize = 1;
pub const OUTPUT_COUNT: usize = 1;

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

    fn eval(&self) {
        self.output_wire.set(self.input_wire.get().neg())
    }
}

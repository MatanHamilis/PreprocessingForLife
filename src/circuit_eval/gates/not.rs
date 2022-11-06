use crate::fields::FieldElement;

pub const IS_LINEAR: bool = true;
pub const INPUT_COUNT: usize = 1;
pub const OUTPUT_COUNT: usize = 1;

pub struct NotGate {
    input_wire: usize,
    output_wire: usize,
}

impl NotGate {
    pub fn new(input_wire: usize, output_wire: usize) -> Self {
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

    pub fn eval<S: FieldElement>(&self, wires: &mut [S]) {
        wires[self.output_wire] = wires[self.input_wire].neg();
    }
}

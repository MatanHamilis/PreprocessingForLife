use crate::fields::FieldElement;

pub const IS_LINEAR: bool = true;
pub const INPUT_COUNT: usize = 2;
pub const OUTPUT_COUNT: usize = 1;
#[derive(Debug)]
pub struct XorGate {
    input_wires: [usize; INPUT_COUNT],
    output_wire: usize,
}

impl XorGate {
    pub fn new(input_wires: [usize; INPUT_COUNT], output_wire: usize) -> Self {
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
    pub fn eval<S: FieldElement>(&self, wires: &mut [S]) {
        wires[self.output_wire] = wires[self.input_wires[0]] + wires[self.input_wires[1]]
    }
}

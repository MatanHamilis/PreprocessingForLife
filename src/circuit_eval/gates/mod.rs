//! The MPC circuit evaluation protocol goes as follows:
//! 1. First, generate correlation required for computing the first layer of the circuit.
//! 2. Each party additively shares its inputs.
//! 3. For each layer of the circuit:
//!     1. For each gate in the layer - mask all the inputs and send them to the other party.
//!     2. Prepare the correlation for the next layer while waiting for the other party to send its queries.

use std::fmt::Debug;

/// This represents the trait of a boolean gate.
/// A boolean gate may possess multiple inputs and multiple outputs.
pub trait Gate: Debug {
    fn input_slice(&self) -> &[usize];
    fn input_count(&self) -> usize;

    fn output_slice(&self) -> &[usize];
    fn output_count(&self) -> usize;

    fn is_linear(&self) -> bool;
}

#[derive(Debug)]
pub struct NotGate {
    input_wire: [usize; 1],
    output_wire: [usize; 1],
}

impl NotGate {
    pub fn new(input_wire: usize, output_wire: usize) -> Self {
        NotGate {
            input_wire: [input_wire],
            output_wire: [output_wire],
        }
    }
    pub fn input_count() -> usize {
        1
    }
    pub fn output_count() -> usize {
        1
    }
}

impl Gate for NotGate {
    fn input_count(&self) -> usize {
        Self::input_count()
    }
    fn input_slice(&self) -> &[usize] {
        &self.input_wire[..]
    }
    fn output_count(&self) -> usize {
        Self::output_count()
    }
    fn output_slice(&self) -> &[usize] {
        &self.output_wire[..]
    }
    fn is_linear(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct XorGate {
    input_wires: [usize; 2],
    output_wire: [usize; 1],
}

impl XorGate {
    pub fn new(input_wires: [usize; 2], output_wire: usize) -> Self {
        XorGate {
            input_wires,
            output_wire: [output_wire],
        }
    }
    pub fn input_count() -> usize {
        2
    }
    pub fn output_count() -> usize {
        1
    }
}

impl Gate for XorGate {
    fn input_count(&self) -> usize {
        Self::input_count()
    }
    fn input_slice(&self) -> &[usize] {
        &self.input_wires[..]
    }

    fn output_count(&self) -> usize {
        Self::output_count()
    }

    fn output_slice(&self) -> &[usize] {
        &self.output_wire[..]
    }

    fn is_linear(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct AndGate {
    input_wires: [usize; 2],
    output_wire: [usize; 1],
}

impl AndGate {
    pub fn new(input_wires: [usize; 2], output_wire: usize) -> Self {
        Self {
            input_wires,
            output_wire: [output_wire],
        }
    }
    pub fn input_count() -> usize {
        2
    }
    pub fn output_count() -> usize {
        1
    }
}
impl Gate for AndGate {
    fn input_count(&self) -> usize {
        Self::input_count()
    }
    fn input_slice(&self) -> &[usize] {
        &self.input_wires[..]
    }

    fn output_count(&self) -> usize {
        Self::output_count()
    }

    fn output_slice(&self) -> &[usize] {
        &self.output_wire[..]
    }
    fn is_linear(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct WideAnd {
    input: [usize; 129],
    output: [usize; 128],
}

impl WideAnd {
    pub fn new(common_input: usize, wide_input: [usize; 128], wide_output: [usize; 128]) -> Self {
        let input: [usize; 129] = core::array::from_fn(|i| {
            if i == 0 {
                common_input
            } else {
                wide_input[i - 1]
            }
        });

        Self {
            input,
            output: wide_output,
        }
    }

    pub fn input_count() -> usize {
        129
    }
    pub fn output_count() -> usize {
        128
    }
}

impl Gate for WideAnd {
    fn input_count(&self) -> usize {
        Self::input_count()
    }
    fn output_count(&self) -> usize {
        Self::output_count()
    }
    fn input_slice(&self) -> &[usize] {
        &self.input[..]
    }
    fn output_slice(&self) -> &[usize] {
        &self.output[..]
    }
    fn is_linear(&self) -> bool {
        false
    }
}

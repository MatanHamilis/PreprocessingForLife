//! # Bristol Fashion Circuits Parser
//! Based on [Bristol Fashion documentation](https://homes.esat.kuleuven.be/~nsmart/MPC/).

use super::gates::{and, not, wide_and, xor};
use log::error;

use std::{
    collections::{HashMap, HashSet},
    mem::MaybeUninit,
};

#[derive(Clone, Copy)]
pub enum ParsedGate {
    AndGate {
        input: [usize; 2],
        output: usize,
    },
    XorGate {
        input: [usize; 2],
        output: usize,
    },
    NotGate {
        input: usize,
        output: usize,
    },
    WideAndGate {
        input: [usize; 129],
        output: [usize; 128],
    },
}

impl ParsedGate {
    pub fn input_wires(&self) -> &[usize] {
        match self {
            ParsedGate::AndGate { input, output: _ } => input,
            ParsedGate::NotGate { input, output: _ } => std::slice::from_ref(input),
            ParsedGate::XorGate { input, output: _ } => input,
            ParsedGate::WideAndGate { input, output: _ } => input,
        }
    }
    pub fn output_wires(&self) -> &[usize] {
        match self {
            ParsedGate::AndGate { input: _, output } => std::slice::from_ref(output),
            ParsedGate::NotGate { input: _, output } => std::slice::from_ref(output),
            ParsedGate::XorGate { input: _, output } => std::slice::from_ref(output),
            ParsedGate::WideAndGate { input: _, output } => output,
        }
    }
    pub fn is_linear(&self) -> bool {
        match self {
            ParsedGate::AndGate {
                input: _,
                output: _,
            } => and::IS_LINEAR,
            ParsedGate::NotGate {
                input: _,
                output: _,
            } => not::IS_LINEAR,
            ParsedGate::XorGate {
                input: _,
                output: _,
            } => xor::IS_LINEAR,
            ParsedGate::WideAndGate {
                input: _,
                output: _,
            } => wide_and::IS_LINEAR,
        }
    }
}

#[derive(PartialEq, Eq)]
enum GateOp {
    And,
    Xor,
    Inv,
    WideAnd,
}

#[derive(Clone)]
pub struct ParsedCircuit {
    pub input_wire_count: usize,
    pub output_wire_count: usize,
    pub internal_wire_count: usize,
    pub gates: Vec<Vec<ParsedGate>>,
}

impl TryFrom<&str> for GateOp {
    type Error = ();
    fn try_from(op_str: &str) -> Result<Self, Self::Error> {
        Ok(match op_str {
            "AND" => GateOp::And,
            "XOR" => GateOp::Xor,
            "INV" => GateOp::Inv,
            "wAND" => GateOp::WideAnd,
            _ => return Err(()),
        })
    }
}

#[derive(Clone)]
struct ParserIterator<'a, T: Iterator<Item = &'a str>> {
    iter: T,
}

impl<'a, T: Iterator<Item = &'a str>> ParserIterator<'a, T> {
    pub fn new(iter: T) -> Self {
        ParserIterator { iter }
    }
    pub fn next_usize(&mut self) -> Option<usize> {
        self.iter.next()?.parse().ok()
    }

    pub fn next_gateop(&mut self) -> Option<GateOp> {
        let op_str = self.iter.next()?;
        op_str.try_into().ok()
    }

    pub fn next_str(&mut self) -> Option<&'a str> {
        self.iter.next()
    }
}

fn parse_first_line(line: &str) -> Option<(usize, usize)> {
    let mut line_iter = ParserIterator::new(line.split(' '));
    let gates_num: usize = line_iter.next_usize()?;
    let wires_num: usize = line_iter.next_usize()?;
    assert!(line_iter.next_str().is_none());
    Some((gates_num, wires_num))
}

fn parse_io_lines(line: &str) -> Option<(usize, Vec<usize>)> {
    let mut line_parts: Vec<usize> = line.split(' ').map_while(|s| s.parse().ok()).collect();

    if line_parts.is_empty() {
        return None;
    }

    let io_count = line_parts.remove(0);
    if line_parts.len() != io_count {
        return None;
    }
    Some((io_count, line_parts))
}

fn parse_regular_gate_line(line: &str) -> Option<ParsedGate> {
    let mut line_iter = ParserIterator::new(line.split(' '));
    let total_input = line_iter.next_usize()?;
    let total_output = line_iter.next_usize()?;
    let op = GateOp::try_from(line.split(' ').last()?).ok()?;

    Some(match op {
        GateOp::And => {
            assert_eq!(and::INPUT_COUNT, total_input);
            assert_eq!(and::OUTPUT_COUNT, total_output);
            let input = [line_iter.next_usize()?, line_iter.next_usize()?];
            ParsedGate::AndGate {
                input,
                output: line_iter.next_usize()?,
            }
        }
        GateOp::Xor => {
            assert_eq!(xor::INPUT_COUNT, total_input);
            assert_eq!(xor::OUTPUT_COUNT, total_output);
            let input = [line_iter.next_usize()?, line_iter.next_usize()?];
            ParsedGate::XorGate {
                input,
                output: line_iter.next_usize()?,
            }
        }
        GateOp::Inv => {
            assert_eq!(not::INPUT_COUNT, total_input);
            assert_eq!(not::OUTPUT_COUNT, total_output);
            ParsedGate::NotGate {
                input: line_iter.next_usize()?,
                output: line_iter.next_usize()?,
            }
        }
        GateOp::WideAnd => {
            assert_eq!(wide_and::INPUT_COUNT, total_input);
            assert_eq!(wide_and::OUTPUT_COUNT, total_output);
            let common_input = line_iter.next_usize()?;
            let mut wide_input: [MaybeUninit<usize>; 129] = MaybeUninit::uninit_array();
            let mut wide_output: [MaybeUninit<usize>; 128] = MaybeUninit::uninit_array();
            for i in 0..128 {
                wide_input[i].write(line_iter.next_usize()?);
            }
            wide_input[128].write(common_input);
            for i in 0..128 {
                wide_output[i].write(line_iter.next_usize()?);
            }
            let input = unsafe { std::mem::transmute(wide_input) };
            let output = unsafe { std::mem::transmute(wide_output) };

            ParsedGate::WideAndGate { input, output }
        }
    })
}

pub fn parse_bristol<T: Iterator<Item = String>>(mut lines: T) -> Option<ParsedCircuit> {
    let (gates_num, total_wire_count) = parse_first_line(lines.next()?.as_str())?;
    let (_, inputs_lengths) = parse_io_lines(lines.next()?.as_str())?;
    let input_wire_count: usize = inputs_lengths.iter().sum();
    let (_, outputs_lengths) = parse_io_lines(lines.next()?.as_str())?;
    let output_wire_count: usize = outputs_lengths.iter().sum();
    if input_wire_count + output_wire_count > total_wire_count {
        return None;
    }
    lines.next();

    let mut gates: Vec<Vec<ParsedGate>> = Vec::<Vec<ParsedGate>>::new();
    let mut wire_toplogical_idx = HashMap::<usize, usize>::new();
    let mut used_wires = HashSet::<usize>::new();
    for gate_line in lines.take(gates_num) {
        let gate = parse_regular_gate_line(gate_line.as_str())?;
        let input_wires = gate.input_wires();
        let mut max_topological_index = usize::MIN;
        for &input in input_wires {
            let topological_idx = if input < input_wire_count {
                0usize
            } else {
                *wire_toplogical_idx.get(&input)?
            };
            if input >= total_wire_count - output_wire_count {
                error!("Output wire can not be used as an input wire");
                return None;
            }
            used_wires.insert(input);
            max_topological_index = std::cmp::max(max_topological_index, topological_idx);
        }
        let gate_ref = match gates.get_mut(max_topological_index) {
            None => {
                gates.push(vec![gate]);
                gates.last()?.last()?
            }
            Some(v) => {
                v.push(gate);
                v.last()?
            }
        };
        if !gate_ref.is_linear() {
            max_topological_index += 1;
        }
        for &output_wire in gate_ref.output_wires() {
            if used_wires.contains(&output_wire) {
                return None;
            }
            if output_wire < input_wire_count || output_wire >= total_wire_count {
                return None;
            }
            if wire_toplogical_idx.contains_key(&output_wire) {
                return None;
            }
            wire_toplogical_idx.insert(output_wire, max_topological_index);
        }
    }
    let total_gates_parsed: usize = gates.iter().map(|v| v.len()).sum();
    if total_gates_parsed != gates_num {
        return None;
    }
    let circuit = ParsedCircuit {
        input_wire_count,
        output_wire_count,
        internal_wire_count: total_wire_count - input_wire_count - output_wire_count,
        gates,
    };
    Some(circuit)
}

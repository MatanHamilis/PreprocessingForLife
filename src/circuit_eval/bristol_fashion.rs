//! # Bristol Fashion Circuits Parser
//! Based on [Bristol Fashion documentation](https://homes.esat.kuleuven.be/~nsmart/MPC/).

use log::error;

use crate::circuit_eval::{GateOneInputOp, GateTwoInputOp};

use super::{Circuit, Gate, GateType};
use std::collections::{HashMap, HashSet};

enum GateOp {
    AND,
    XOR,
    INV,
}

struct ParserIterator<'a, T: Iterator<Item = &'a str>> {
    iter: T,
}

impl<'a, T: Iterator<Item = &'a str>> ParserIterator<'a, T> {
    pub fn new(iter: T) -> Self {
        ParserIterator { iter }
    }
    pub fn next_usize(&mut self) -> Option<usize> {
        Some(self.iter.next()?.parse().ok()?)
    }

    pub fn next_gateop(&mut self) -> Option<GateOp> {
        let op_str = self.iter.next()?;
        Some(match op_str {
            "AND" => GateOp::AND,
            "XOR" => GateOp::XOR,
            "INV" => GateOp::INV,
            _ => return None,
        })
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

    if line_parts.len() == 0 {
        return None;
    }

    let io_count = line_parts.remove(0);
    if line_parts.len() != io_count {
        return None;
    }
    Some((io_count, line_parts))
}

fn parse_regular_gate_line(line: &str) -> Option<(GateType, usize)> {
    let mut line_iter = ParserIterator::new(line.split(" "));
    let total_input = line_iter.next_usize()?;
    if total_input > 2 || total_input < 1 {
        return None;
    }
    if line_iter.next_usize()? != 1 {
        return None;
    }
    let input_wires = if total_input == 1 {
        (line_iter.next_usize()?, None)
    } else {
        (line_iter.next_usize()?, Some(line_iter.next_usize()?))
    };

    let output_wire = line_iter.next_usize()?;
    let gate_op = line_iter.next_gateop()?;
    let gate_type = match gate_op {
        GateOp::AND => GateType::TwoInput {
            input: [input_wires.0, input_wires.1?],
            op: GateTwoInputOp::And,
        },
        GateOp::XOR => GateType::TwoInput {
            input: [input_wires.0, input_wires.1?],
            op: GateTwoInputOp::Xor,
        },
        GateOp::INV => GateType::OneInput {
            input: [input_wires.0],
            op: GateOneInputOp::Not,
        },
    };
    Some((gate_type, output_wire))
}

pub fn parse_bristol<'a, T: Iterator<Item = &'a str>>(mut lines: T) -> Option<Circuit> {
    let (gates_num, total_wire_count) = parse_first_line(lines.next()?)?;
    let (_, inputs_lengths) = parse_io_lines(lines.next()?)?;
    let input_wire_count: usize = inputs_lengths.iter().sum();
    let (_, outputs_lengths) = parse_io_lines(lines.next()?)?;
    let output_wire_count: usize = outputs_lengths.iter().sum();
    if input_wire_count + output_wire_count > total_wire_count {
        return None;
    }
    lines.next();
    let mut gates: Vec<Vec<Gate>> = Vec::<Vec<Gate>>::new();
    let mut wire_toplogical_idx = HashMap::<usize, usize>::new();
    let mut used_wires = HashSet::<usize>::new();
    for gate_line in lines.take(gates_num + 1) {
        let (gate_type, output_wire) = parse_regular_gate_line(gate_line)?;
        let input_wires = match &gate_type {
            GateType::TwoInput { input, op: _ } => &input[..],
            GateType::OneInput { input, op: _ } => &input[..],
        };
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
        let gate = Gate {
            gate_type,
            output_wire,
        };
        match gates.get_mut(max_topological_index) {
            None => gates.push(vec![gate]),
            Some(v) => v.push(gate),
        }
        if let GateType::TwoInput {
            input: _,
            op: GateTwoInputOp::And,
        } = gate_type
        {
            // In case of an AND gate, the output wire is on the next layer.
            max_topological_index += 1;
        }
        if used_wires.contains(&output_wire) {
            return None;
        }
        if output_wire < input_wire_count || output_wire >= total_wire_count {
            return None;
        }
        wire_toplogical_idx.insert(output_wire, max_topological_index);
    }
    let total_gates_parsed: usize = gates.iter().map(|v| v.len()).sum();
    if total_gates_parsed != gates_num {
        return None;
    }
    let circuit = Circuit {
        gates,
        input_wire_count,
        output_wire_count,
        total_wire_count,
    };
    Some(circuit)
}

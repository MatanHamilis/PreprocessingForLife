//! The MPC circuit evaluation protocol goes as follows:
//! 1. First, generate correlation required for computing the first layer of the circuit.
//! 2. Each party additively shares its inputs.
//! 3. For each layer of the circuit:
//!     1. For each gate in the layer - mask all the inputs and send them to the other party.
//!     2. Prepare the correlation for the next layer while waiting for the other party to send its queries.

use crate::fields::FieldElement;
use crate::pcg::bit_beaver_triples::{BeaverTripletShare, WideBeaverTripletShare};
use crate::pcg::full_key::CorrelationGenerator;
pub use and::AndGate;
pub use not::NotGate;
use serde::{Deserialize, Serialize};
pub use wide_and::WideAndGate;
pub use xor::XorGate;

use self::and::AndMsg;
use self::wide_and::WideAndMsg;

use super::bristol_fashion::ParsedGate;

pub mod and;
pub mod not;
pub mod wide_and;
pub mod xor;

#[derive(Debug)]
pub enum Gate<S: FieldElement> {
    And(and::AndGate<S>),
    Xor(xor::XorGate),
    Not(not::NotGate),
    WideAnd(WideAndGate<S>),
}

/// This represents the trait of a boolean gate.
/// A boolean gate may possess multiple inputs and multiple outputs.
impl<S: FieldElement> Gate<S> {
    /// Local Computation
    pub fn eval(&self, wires: &mut [S]) {
        match self {
            Self::Not(g) => g.eval(wires),
            Self::And(g) => g.eval(wires),
            Self::Xor(g) => g.eval(wires),
            Self::WideAnd(g) => g.eval(wires),
        }
    }

    // MPC Functions

    /// The gate may fetch some correlated randomness (Beaver Triplets)
    pub fn generate_correlation<T: CorrelationGenerator>(
        &mut self,
        correlation_generator: &mut T,
    ) -> Result<(), ()> {
        if let Self::And(g) = self {
            g.generate_correlation(correlation_generator.next_beaver_triple().ok_or(())?);
        }
        if let Self::WideAnd(g) = self {
            g.generate_correlation(correlation_generator.next_wide_beaver_triple().ok_or(())?);
        }
        Ok(())
    }

    /// If the gate requires communication the be evaluated in MPC, this function returns the message to be sent to the other party.
    /// Otherwise, simply evaluates the gate.
    pub fn eval_and_generate_msg(&self, wires: &mut [S], id: bool) -> Result<Option<Msg<S>>, ()> {
        Ok(match self {
            Gate::And(and_gate) => Some(Msg::And(and_gate.generate_msg(wires).ok_or(())?)),
            Gate::WideAnd(wand_gate) => {
                Some(Msg::WideAnd(wand_gate.generate_msg(wires).ok_or(())?))
            }
            Gate::Not(not_gate) => {
                not_gate.eval_mpc(wires, id);
                None
            }
            Gate::Xor(xor_gate) => {
                xor_gate.eval(wires);
                None
            }
        })
    }

    /// If the gate sent some message, the function handles the peer's message and evaluates the gate accordingly.
    pub fn handle_peer_msg(&mut self, wires: &mut [S], msg: &Msg<S>) {
        match (self, msg) {
            (Gate::And(and_gate), Msg::And(msg)) => and_gate.handle_msg(wires, msg),
            (Gate::WideAnd(wand_gate), Msg::WideAnd(msg)) => wand_gate.handle_msg(wires, msg),
            _ => panic!("Malformed message handling!"),
        }
    }

    fn is_linear(&self) -> bool {
        match self {
            Gate::And(_) => and::IS_LINEAR,
            Gate::Not(_) => not::IS_LINEAR,
            Gate::Xor(_) => xor::IS_LINEAR,
            Gate::WideAnd(_) => wide_and::IS_LINEAR,
        }
    }
}

impl<S: FieldElement> From<ParsedGate> for Gate<S> {
    fn from(value: ParsedGate) -> Self {
        match value {
            ParsedGate::AndGate { input, output } => Gate::And(AndGate::new(input, output)),
            ParsedGate::NotGate { input, output } => Gate::Not(NotGate::new(input, output)),
            ParsedGate::XorGate { input, output } => Gate::Xor(XorGate::new(input, output)),
            ParsedGate::WideAndGate { input, output } => {
                let [wide_input @ .., common_input] = input;
                Gate::WideAnd(WideAndGate::new(input[128], wide_input, output))
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum Msg<S: FieldElement> {
    #[serde(bound(deserialize = "S: FieldElement"))]
    And(AndMsg<S>),
    #[serde(bound(deserialize = "S: FieldElement"))]
    WideAnd(WideAndMsg<S>),
}

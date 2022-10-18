//! The MPC circuit evaluation protocol goes as follows:
//! 1. First, generate correlation required for computing the first layer of the circuit.
//! 2. Each party additively shares its inputs.
//! 3. For each layer of the circuit:
//!     1. For each gate in the layer - mask all the inputs and send them to the other party.
//!     2. Prepare the correlation for the next layer while waiting for the other party to send its queries.

use crate::fields::FieldElement;
use crate::pcg::bit_beaver_triples::BeaverTripletShare;
pub use and::AndGate;
pub use not::NotGate;
use std::cell::Cell;
pub use wide_and::WideAndGate;
pub use xor::XorGate;
pub mod and;
pub mod not;
pub mod wide_and;
pub mod xor;

/// This represents the trait of a boolean gate.
/// A boolean gate may possess multiple inputs and multiple outputs.
pub enum Gate<'a, S: FieldElement> {
    Not(NotGate<'a, S>),
    And(AndGate<'a, S>),
    Xor(XorGate<'a, S>),
    WideAnd(WideAndGate<'a, S>),
}

impl<'a, S: FieldElement> Gate<'a, S> {
    /// Local Computation
    fn eval(&self) {
        match self {
            Self::Not(g) => g.eval(),
            Self::And(g) => g.eval(),
            Self::Xor(g) => g.eval(),
            Self::WideAnd(g) => g.eval(),
        }
    }

    // MPC Functions

    /// The gate may fetch some correlated randomness (Beaver Triplets)
    fn generate_correlation(
        &mut self,
        correlation_generator: &mut impl Iterator<Item = BeaverTripletShare<S>>,
    ) -> Result<(), ()> {
        match self {
            Self::And(g) => g.generate_correlation(correlation_generator),
            _ => Ok(()),
        }
    }

    /// If the gate requires communication the be evaluated in MPC, this function returns the message to be sent to the other party.
    fn generate_msg(&self) -> Option<Vec<S>>;

    /// If the gate sent some message, the function handles the peer's message and evaluates the gate accordingly.
    fn handle_peer_msg(&mut self, msg: &[S]);

    fn is_linear(&self) -> bool;
}

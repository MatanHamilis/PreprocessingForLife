//! The MPC circuit evaluation protocol goes as follows:
//! 1. First, generate correlation required for computing the first layer of the circuit.
//! 2. Each party additively shares its inputs.
//! 3. For each layer of the circuit:
//!     1. For each gate in the layer - mask all the inputs and send them to the other party.
//!     2. Prepare the correlation for the next layer while waiting for the other party to send its queries.

use std::cell::Cell;
use std::fmt::Debug;

use crate::fields::FieldElement;
use crate::pcg::bit_beaver_triples::BeaverTripletShare;
pub mod and;
pub mod not;
pub mod wide_and;
pub mod xor;

pub use and::AndGate;
pub use not::NotGate;
pub use wide_and::WideAndGate;
pub use xor::XorGate;

/// This represents the trait of a boolean gate.
/// A boolean gate may possess multiple inputs and multiple outputs.
pub trait Gate<S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>> {
    fn set_input_wire(&self, index: usize, wire: &Cell<S>);
    fn set_output_wire(&self, index: usize, wire: &Cell<S>);

    fn get_input_wire(&self, index: usize) -> Option<&Cell<S>>;
    fn get_output_wire(&self, index: usize) -> Option<&Cell<S>>;

    /// Local Computation
    fn eval(&self);

    // MPC Functions

    /// The gate may fetch some correlated randomness (Beaver Triplets)
    fn generate_correlation(&mut self, correlation_generator: &mut T) -> Result<(), ()>;

    /// If the gate requires communication the be evaluated in MPC, this function returns the message to be sent to the other party.
    fn generate_msg(&self) -> Option<&Vec<S>>;

    /// If the gate sent some message, the function handles the peer's message and evaluates the gate accordingly.
    fn handle_peer_msg(&mut self, msg: &[S]);

    fn is_linear(&self) -> bool;
}

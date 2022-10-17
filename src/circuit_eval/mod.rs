pub mod bristol_fashion;
mod gates;
use gates::{AndGate, Gate, NotGate, WideAndGate, XorGate};
use std::cell::Cell;

use std::fmt::Debug;
use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};

use crate::{
    communicator::Communicator,
    fields::{FieldElement, GF2},
    pcg::bit_beaver_triples::BeaverTripletShare,
};

use self::bristol_fashion::{ParsedCircuit, ParsedGate};

mod and_gate {
    use crate::fields::FieldElement;
    use crate::pcg::bit_beaver_triples::BeaverTripletShare;
    pub fn eval<S: FieldElement>(x: S, y: S) -> S {
        x * y
    }
    // u = Open(x + a);
    // v = Open(y + b);
    // [xy] = ((x+a)-a)((y+b)-b)=[u]v-[a]v-[b]u+[ab]=
    //          [x]v-[b]u+[ab]
    pub fn mpc_make_msgs<S: FieldElement>(
        x_share: S,
        y_share: S,
        beaver_triplet_shares: &BeaverTripletShare<S>,
    ) -> (S, S) {
        let u_share = beaver_triplet_shares.a_share + x_share;
        let v_share = beaver_triplet_shares.b_share + y_share;
        (u_share, v_share)
    }
    pub fn mpc_handle_msgs<S: FieldElement>(
        x_share: S,
        y_share: S,
        x_response: S,
        y_response: S,
        beaver_triplet_shares: &BeaverTripletShare<S>,
    ) -> S {
        let u = beaver_triplet_shares.a_share + x_share + x_response;
        let v = beaver_triplet_shares.b_share + y_share + y_response;
        x_share * v - beaver_triplet_shares.b_share * u + beaver_triplet_shares.ab_share
    }
}

mod xor_gate {
    use crate::fields::FieldElement;
    pub fn eval<S: FieldElement>(x: S, y: S) -> S {
        x + y
    }
    pub fn eval_mpc<S: FieldElement>(x_share: S, y_share: S) -> S {
        x_share + y_share
    }
}

mod not_gate {
    use crate::fields::FieldElement;
    pub fn eval<S: FieldElement>(x: S) -> S {
        S::one() - x
    }

    pub fn eval_mpc<S: FieldElement>(mut x_share: S, should_flip: bool) -> S {
        if should_flip {
            x_share = S::one() - x_share
        }
        x_share
    }
}
mod wide_and {
    use crate::fields::FieldElement;

    pub fn eval<S: FieldElement, const N: usize>(x: S, mut ys: [S; N]) -> [S; N] {
        ys.iter_mut().for_each(|y| *y *= x);
        ys
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GateTwoInputOp {
    And,
    Xor,
}

impl GateTwoInputOp {
    fn eval(&self, x: GF2, y: GF2) -> GF2 {
        match self {
            Self::Xor => xor_gate::eval(x, y),
            Self::And => and_gate::eval(x, y),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GateOneInputOp {
    Not,
}

impl GateOneInputOp {
    fn eval(&self, x: GF2) -> GF2 {
        match self {
            Self::Not => not_gate::eval(x),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GateWideOp {
    WideAnd,
}

impl GateWideOp {
    fn eval(&self, x: GF2, ys: [GF2; 128]) -> [GF2; 128] {
        match self {
            Self::WideAnd => wide_and::eval(x, ys),
        }
    }
}

pub struct Circuit<S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>> {
    gates: Vec<Vec<Box<dyn Gate<S, T>>>>,
    input_wires: Vec<Cell<S>>,
    internal_wires: Vec<Cell<S>>,
    output_wires: Vec<Cell<S>>,
}

impl<S: FieldElement + Debug, T: Iterator<Item = BeaverTripletShare<S>>> Circuit<S, T> {
    fn parsed_wire_number_to_cell<'a>(
        input_wires: &'a Vec<Cell<S>>,
        output_wires: &'a Vec<Cell<S>>,
        internal_wires: &'a Vec<Cell<S>>,
        mut wire_number: usize,
    ) -> &'a Cell<S> {
        if wire_number < input_wires.len() {
            input_wires.get(wire_number).unwrap()
        } else {
            wire_number -= input_wires.len();
            if wire_number < internal_wires.len() {
                internal_wires.get(wire_number).unwrap()
            } else {
                wire_number -= internal_wires.len();
                output_wires
                    .get(wire_number)
                    .expect("Malformed wire number is parsed!")
            }
        }
    }
    fn new(parsed_circuit: &ParsedCircuit) -> Self {
        let input_wires = vec![Cell::<S>::default(); parsed_circuit.input_wire_count];
        let output_wires = vec![Cell::<S>::default(); parsed_circuit.output_wire_count];
        let internal_wires = vec![Cell::<S>::default(); parsed_circuit.internal_wire_count];
        let gates = parsed_circuit
            .gates
            .iter()
            .map(|parsed_layer| {
                parsed_layer
                    .iter()
                    .map(|parsed_gate| match parsed_gate {
                        &ParsedGate::NotGate { input, output } => {
                            let input_wire = Self::parsed_wire_number_to_cell(
                                &input_wires,
                                &output_wires,
                                &internal_wires,
                                input,
                            );
                            let output_wire = Self::parsed_wire_number_to_cell(
                                &input_wires,
                                &output_wires,
                                &internal_wires,
                                output,
                            );
                            Box::new(NotGate::new(input_wire, output_wire)) as Box<dyn Gate<S, T>>
                        }
                        &ParsedGate::AndGate { input, output } => {
                            let input_wire = std::array::from_fn(|i| {
                                Self::parsed_wire_number_to_cell(
                                    &input_wires,
                                    &output_wires,
                                    &internal_wires,
                                    input[i],
                                )
                            });
                            let output_wire = Self::parsed_wire_number_to_cell(
                                &input_wires,
                                &output_wires,
                                &internal_wires,
                                output,
                            );
                            Box::new(AndGate::new(input_wire, output_wire)) as Box<dyn Gate<S, T>>
                        }
                        &ParsedGate::XorGate { input, output } => {
                            let input_wire = std::array::from_fn(|i| {
                                Self::parsed_wire_number_to_cell(
                                    &input_wires,
                                    &output_wires,
                                    &internal_wires,
                                    input[i],
                                )
                            });
                            let output_wire = Self::parsed_wire_number_to_cell(
                                &input_wires,
                                &output_wires,
                                &internal_wires,
                                output,
                            );
                            Box::new(XorGate::new(input_wire, output_wire)) as Box<dyn Gate<S, T>>
                        }
                        &ParsedGate::WideAndGate { input, output } => {
                            let input_wire = std::array::from_fn(|i| {
                                Self::parsed_wire_number_to_cell(
                                    &input_wires,
                                    &output_wires,
                                    &internal_wires,
                                    input[i],
                                )
                            });
                            let output_wire = Self::parsed_wire_number_to_cell(
                                &input_wires,
                                &output_wires,
                                &internal_wires,
                                output,
                            );
                            Box::new(WideAndGate::new(input_wire, output_wire))
                                as Box<dyn Gate<S, T>>
                        }
                    })
                    .collect()
            })
            .collect();

        Self {
            input_wires,
            output_wires,
            internal_wires,
            gates,
        }
    }
}

impl<S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>> Circuit<S, T> {
    pub fn eval_circuit(&mut self, input_wires: &[S]) -> Option<Vec<S>> {
        assert_eq!(input_wires.len(), self.input_wires.len());
        input_wires
            .iter()
            .zip(self.input_wires.iter())
            .for_each(|(input, wire)| wire.set(*input));
        for gate in self.gates.iter().flatten() {
            gate.eval();
        }
        Some(self.output_wires.iter().map(|w| w.get()).collect())
    }

    pub fn input_wire_count(&self) -> usize {
        self.input_wires.len()
    }
    pub fn get_layer_count(&self) -> usize {
        self.gates.len()
    }
    pub fn output_wire_count(&self) -> usize {
        self.output_wires.len()
    }
}

#[derive(Debug)]
pub enum CircuitEvalSessionState<'a, S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>> {
    WaitingToSend(CircuitEvalSessionWaitingToSend<'a, S, T>),
    WaitingToGenCorrelation(CircuitEvalSessionWaitingToGenCorrelation<'a, S, T>),
    WaitingToReceive(CircuitEvalSessionWaitingToReceive<'a, S, T>),
    Finished(Vec<S>),
}
#[derive(Debug)]
struct CircuitEvalSession<'a, S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>> {
    circuit: &'a Circuit<S, T>,
    layer_to_process: usize,
    beaver_triple_gen: T,
    gates_in_layer_waiting_for_response: Option<Vec<&'a Box<dyn Gate<S, T>>>>,
    party_id: bool,
}

// We use three different structs to enforce certain actions to be done only in certain states by the typing system.

#[derive(Debug)]
pub struct CircuitEvalSessionWaitingToSend<
    'a,
    S: FieldElement,
    T: Iterator<Item = BeaverTripletShare<S>>,
> {
    session: CircuitEvalSession<'a, S, T>,
}
#[derive(Debug)]
pub struct CircuitEvalSessionWaitingToGenCorrelation<
    'a,
    S: FieldElement,
    T: Iterator<Item = BeaverTripletShare<S>>,
> {
    session: CircuitEvalSession<'a, S, T>,
}
#[derive(Debug)]
pub struct CircuitEvalSessionWaitingToReceive<
    'a,
    S: FieldElement,
    T: Iterator<Item = BeaverTripletShare<S>>,
> {
    session: CircuitEvalSession<'a, S, T>,
}

impl<'a, S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>> CircuitEvalSession<'a, S, T> {
    fn generate_beaver_triples_for_layer(&mut self, layer: usize) -> Result<(), ()> {
        let layer = self.circuit.gates.get(layer).ok_or(())?;
        layer
            .iter_mut()
            .try_for_each(|g| g.generate_correlation(&mut self.beaver_triple_gen))
    }
}

impl<'a, S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>>
    CircuitEvalSessionState<'a, S, T>
{
    pub fn new(
        circuit: &'a Circuit<S, T>,
        input_shares: &[S],
        beaver_triple_gen: T,
        party_id: bool,
    ) -> Self {
        assert_eq!(circuit.input_wire_count(), input_shares.len());
        circuit
            .input_wires
            .iter()
            .zip(input_shares.iter())
            .for_each(|(input_wire, input_share)| input_wire.set(*input_share));
        let mut session = CircuitEvalSession {
            circuit,
            beaver_triple_gen,
            layer_to_process: 0,
            gates_in_layer_waiting_for_response: None,
            party_id,
        };
        session
            .generate_beaver_triples_for_layer(0)
            .expect("Error generating beaver triples for first layer");
        CircuitEvalSessionState::WaitingToSend(CircuitEvalSessionWaitingToSend { session })
    }
}

impl<'a, S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>>
    CircuitEvalSessionWaitingToSend<'a, S, T>
{
    pub fn fetch_layer_messages(self) -> (CircuitEvalSessionState<'a, S, T>, Vec<&'a Vec<S>>) {
        // Prepare beaver triples for this layer.
        let mut session = self.session;
        let layer_id = session.layer_to_process;
        let current_layer = session
            .circuit
            .gates
            .get(layer_id)
            .expect("Missing layer, corrupt state!");

        // Generate the messages.
        let (msgs, ids) = current_layer
            .iter()
            .enumerate()
            .filter_map(|(id, gate)| gate.generate_msg().map(|v| (v, gate)))
            .unzip();
        session.gates_in_layer_waiting_for_response = Some(ids);

        let new_state = CircuitEvalSessionState::WaitingToGenCorrelation(
            CircuitEvalSessionWaitingToGenCorrelation { session },
        );
        (new_state, msgs)
    }
}

impl<'a, S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>>
    CircuitEvalSessionWaitingToGenCorrelation<'a, S, T>
{
    pub fn gen_correlation_for_next_layer(mut self) -> CircuitEvalSessionState<'a, S, T> {
        if self.session.circuit.gates.len() < self.session.layer_to_process + 1 {
            self.session
                .generate_beaver_triples_for_layer(self.session.layer_to_process + 1)
                .expect("Failed to generate beaver triples for next layer!");
        }
        CircuitEvalSessionState::WaitingToReceive(CircuitEvalSessionWaitingToReceive {
            session: self.session,
        })
    }
}
impl<'a, S: FieldElement, T: Iterator<Item = BeaverTripletShare<S>>>
    CircuitEvalSessionWaitingToReceive<'a, S, T>
{
    pub fn handle_layer_responses(
        self,
        responses: Vec<Vec<S>>,
    ) -> CircuitEvalSessionState<'a, S, T> {
        let mut session = self.session;
        let layer_id = session.layer_to_process;
        let current_layer = session
            .circuit
            .gates
            .get(layer_id)
            .expect("Current layer id missing, corrupt struct");
        let gates_expecting_response = session
            .gates_in_layer_waiting_for_response
            .take()
            .expect("Expecting gates vector isn't initalized, this has to be a bug!");
        assert_eq!(responses.len(), gates_expecting_response.len());
        for (response, gate_id_in_layer) in responses.into_iter().zip(
            session
                .gates_in_layer_waiting_for_response
                .take()
                .expect("Expected Gates aren't initialized, this has to be a bug!")
                .into_iter(),
        ) {
            gate_id_in_layer.handle_peer_msg(&response[..]);
        }
        session.layer_to_process = layer_id + 1;
        if session
            .circuit
            .gates
            .get(session.layer_to_process)
            .is_none()
        {
            CircuitEvalSessionState::Finished(
                session
                    .circuit
                    .output_wires
                    .into_iter()
                    .map(|v| v.get())
                    .collect(),
            )
        } else {
            CircuitEvalSessionState::WaitingToSend(CircuitEvalSessionWaitingToSend { session })
        }
    }
}

#[derive(Debug)]
pub enum CircuitEvalError {
    CommunicatorError,
}
pub fn eval_circuit<
    C: Read + Write,
    S: FieldElement + Serialize + DeserializeOwned,
    T: Iterator<Item = BeaverTripletShare<S>>,
>(
    circuit: &Circuit<S, T>,
    (mut my_input, peer_input): (Vec<S>, Vec<S>),
    correlations: T,
    communicator: &mut Communicator<C>,
    is_first: bool,
) -> Result<Vec<S>, CircuitEvalError> {
    assert_eq!(my_input.len(), peer_input.len());
    let mut received_input = communicator
        .exchange(peer_input)
        .ok_or(CircuitEvalError::CommunicatorError)?;
    if is_first {
        my_input.append(&mut received_input);
    } else {
        received_input.append(&mut my_input);
        my_input = received_input;
    }
    let mut session = CircuitEvalSessionState::new(circuit, &my_input[..], correlations, is_first);
    let party_output = loop {
        let (session_temp, queries_to_send) = match session {
            CircuitEvalSessionState::WaitingToSend(session) => session.fetch_layer_messages(),
            _ => panic!(),
        };
        session = session_temp;
        communicator
            .send(queries_to_send)
            .ok_or(CircuitEvalError::CommunicatorError)?;
        session = match session {
            CircuitEvalSessionState::WaitingToGenCorrelation(session) => {
                session.gen_correlation_for_next_layer()
            }
            _ => panic!(),
        };
        let queries_received: Vec<_> = communicator
            .receive()
            .ok_or(CircuitEvalError::CommunicatorError)?;
        session = match session {
            CircuitEvalSessionState::WaitingToReceive(session) => {
                session.handle_layer_responses(queries_received)
            }
            _ => panic!(),
        };
        if let CircuitEvalSessionState::Finished(party_output) = session {
            break party_output;
        }
    };
    Ok(party_output)
}

#[cfg(test)]
mod tests {
    use super::bristol_fashion::parse_bristol;
    use super::Circuit;
    use crate::circuit_eval::CircuitEvalSessionState;
    use crate::fields::{FieldElement, GF128, GF2};
    use crate::pcg::bit_beaver_triples::{
        BeaverTripletBitPartyOnlinePCGKey, BeaverTripletScalarPartyOnlinePCGKey,
    };
    use crate::pcg::codes::EACode;
    use crate::pcg::random_bit_ot::{ReceiverRandomBitOtPcgItem, SenderRandomBitOtPcgItem};
    use crate::pcg::sparse_vole::scalar_party::OnlineSparseVoleKey as ScalarOnlineSparseVoleKey;
    use crate::pcg::sparse_vole::vector_party::OnlineSparseVoleKey as VectorOnlineSparseVoleKey;
    use crate::pprf::usize_to_bits;
    use crate::pseudorandom::prf::PrfInput;
    use crate::pseudorandom::prg::PrgValue;
    use crate::pseudorandom::KEY_SIZE;

    fn get_prf_keys(amount: u8) -> Vec<PrgValue> {
        let mut base_prf_key = [0u8; KEY_SIZE];
        (0..amount)
            .map(|i| {
                base_prf_key[KEY_SIZE - 1] = i;
                base_prf_key.into()
            })
            .collect()
    }

    fn get_puncturing_points<const INPUT_BITLEN: usize>(amount: u8) -> Vec<PrfInput<INPUT_BITLEN>> {
        (0..amount)
            .map(|i| usize_to_bits(100 * usize::from(i) + 1).into())
            .collect()
    }

    fn eval_mpc_circuit<
        S: Iterator<Item = SenderRandomBitOtPcgItem>,
        T: Iterator<Item = ReceiverRandomBitOtPcgItem>,
    >(
        circuit: &Circuit,
        input_a: &[GF2],
        input_b: &[GF2],
        beaver_triple_scalar_key: &mut BeaverTripletScalarPartyOnlinePCGKey<GF2, S>,
        beaver_triple_vector_key: &mut BeaverTripletBitPartyOnlinePCGKey<GF2, T>,
    ) -> (Vec<GF2>, Vec<GF2>) {
        let mut first_party_session =
            CircuitEvalSessionState::new(circuit, input_a, beaver_triple_scalar_key, false);
        let mut second_party_session =
            CircuitEvalSessionState::new(circuit, input_b, beaver_triple_vector_key, true);
        let (first_party_output, second_party_output) = loop {
            let (first_party_session_temp, first_party_queries) = match first_party_session {
                CircuitEvalSessionState::WaitingToSend(session) => session.fetch_layer_messages(),
                _ => panic!(),
            };
            first_party_session = first_party_session_temp;
            let (second_party_session_temp, second_party_queries) = match second_party_session {
                CircuitEvalSessionState::WaitingToSend(session) => session.fetch_layer_messages(),
                _ => panic!(),
            };
            second_party_session = second_party_session_temp;
            first_party_session = match first_party_session {
                CircuitEvalSessionState::WaitingToGenCorrelation(session) => {
                    session.gen_correlation_for_next_layer()
                }
                _ => panic!(),
            };
            first_party_session = match first_party_session {
                CircuitEvalSessionState::WaitingToReceive(session) => {
                    session.handle_layer_responses(second_party_queries)
                }
                _ => panic!(),
            };
            second_party_session = match second_party_session {
                CircuitEvalSessionState::WaitingToGenCorrelation(session) => {
                    session.gen_correlation_for_next_layer()
                }
                _ => panic!(),
            };
            second_party_session = match second_party_session {
                CircuitEvalSessionState::WaitingToReceive(session) => {
                    session.handle_layer_responses(first_party_queries)
                }
                _ => panic!(),
            };
            if let CircuitEvalSessionState::Finished(first_party_output) = first_party_session {
                if let CircuitEvalSessionState::Finished(second_party_output) = second_party_session
                {
                    break (first_party_output, second_party_output);
                }
                panic!();
            }
        };
        (first_party_output, second_party_output)
    }

    fn gen_sparse_vole_online_keys<
        const WEIGHT: u8,
        const INPUT_BITLEN: usize,
        const CODE_WEIGHT: usize,
    >() -> (
        ScalarOnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>>,
        VectorOnlineSparseVoleKey<CODE_WEIGHT, EACode<CODE_WEIGHT>>,
    ) {
        let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let prf_keys = get_prf_keys(WEIGHT);
        let puncturing_points: Vec<PrfInput<INPUT_BITLEN>> = get_puncturing_points(WEIGHT);
        crate::pcg::sparse_vole::trusted_deal::<INPUT_BITLEN, CODE_WEIGHT>(
            &scalar,
            puncturing_points,
            prf_keys,
        )
    }

    fn test_circuit(circuit: &Circuit, input: &[GF2], random_share: &[GF2]) -> Vec<GF2> {
        const WEIGHT: u8 = 128;
        const CODE_WEIGHT: usize = 8;
        const INPUT_BITLEN: usize = 12;
        assert_eq!(input.len(), random_share.len());
        assert_eq!(input.len(), circuit.input_wire_count());
        let local_computation_output = circuit.eval_circuit(input).unwrap();

        let (scalar_online_key, vector_online_key) =
            gen_sparse_vole_online_keys::<WEIGHT, INPUT_BITLEN, CODE_WEIGHT>();

        let mut beaver_triple_scalar_key: BeaverTripletScalarPartyOnlinePCGKey<GF2, _> =
            scalar_online_key.into();
        let mut beaver_triple_vector_key: BeaverTripletBitPartyOnlinePCGKey<GF2, _> =
            vector_online_key.into();

        let input_a = random_share.to_vec();
        let input_b: Vec<_> = input
            .iter()
            .zip(random_share.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        let (output_a, output_b) = eval_mpc_circuit(
            circuit,
            &input_a,
            &input_b,
            &mut beaver_triple_scalar_key,
            &mut beaver_triple_vector_key,
        );
        assert_eq!(output_a.len(), output_b.len());
        assert_eq!(output_a.len(), circuit.output_wire_count);
        for i in 0..circuit.output_wire_count {
            assert_eq!(output_a[i] + output_b[i], local_computation_output[i]);
        }
        local_computation_output
    }

    #[test]
    fn test_small_circuit() {
        let logical_or_circuit = [
            "4 6",
            "2 1 1",
            "1 1",
            "",
            "1 1 0 2 INV",
            "1 1 1 3 INV",
            "2 1 2 3 4 AND",
            "1 1 4 5 INV",
        ];
        let circuit = parse_bristol(logical_or_circuit.into_iter().map(|s| s.to_string()))
            .expect("Failed to parse");

        // Test classical eval.
        assert_eq!(
            circuit.eval_circuit(&[GF2::one(), GF2::one()]),
            Some(vec![GF2::one()])
        );
        assert_eq!(
            circuit.eval_circuit(&[GF2::zero(), GF2::one()]),
            Some(vec![GF2::one()])
        );
        assert_eq!(
            circuit.eval_circuit(&[GF2::one(), GF2::zero()]),
            Some(vec![GF2::one()])
        );
        assert_eq!(
            circuit.eval_circuit(&[GF2::zero(), GF2::zero()]),
            Some(vec![GF2::zero()])
        );

        let input = vec![GF2::one(), GF2::zero()];
        let rand = vec![GF2::zero(), GF2::zero()];
        let output = test_circuit(&circuit, &input, &rand);

        assert_eq!(output[0], GF2::one());
    }
}

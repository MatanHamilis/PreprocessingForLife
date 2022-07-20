pub mod bristol_fashion;

use crate::{
    fields::{FieldElement, GF2},
    pcg::bit_beaver_triples::BeaverTripletShare,
};

mod and_gate {
    use crate::fields::GF2;
    use crate::pcg::bit_beaver_triples::BeaverTripletShare;
    pub fn eval(x: GF2, y: GF2) -> GF2 {
        x * y
    }
    // u = Open(x + a);
    // v = Open(y + b);
    // [xy] = ((x+a)-a)((y+b)-b)=uv-[a]v-[b]u+[ab]=
    //          [x]v-[b]u+[ab]
    pub fn mpc_make_msgs(
        x_share: GF2,
        y_share: GF2,
        beaver_triplet_shares: &BeaverTripletShare<GF2>,
    ) -> (GF2, GF2) {
        let u = beaver_triplet_shares.a_share + x_share;
        let v = beaver_triplet_shares.b_share + y_share;
        (u, v)
    }
    pub fn mpc_handle_msgs(
        x_share: GF2,
        y_share: GF2,
        x_response: GF2,
        y_response: GF2,
        beaver_triplet_shares: &BeaverTripletShare<GF2>,
    ) -> GF2 {
        let u = beaver_triplet_shares.a_share + x_share + x_response;
        let v = beaver_triplet_shares.b_share + y_share + y_response;
        x_share * v - beaver_triplet_shares.b_share * u + beaver_triplet_shares.ab_share
    }
}

mod xor_gate {
    use crate::fields::GF2;
    pub fn eval(x: GF2, y: GF2) -> GF2 {
        x + y
    }
    pub fn eval_mpc(x_share: GF2, y_share: GF2) -> GF2 {
        x_share + y_share
    }
}

mod not_gate {
    use crate::fields::GF2;
    pub fn eval(mut x: GF2) -> GF2 {
        x.flip();
        x
    }

    pub fn eval_mpc(mut x_share: GF2, should_flip: bool) -> GF2 {
        if should_flip {
            x_share.flip();
        }
        x_share
    }
}

#[derive(Clone, Copy, Debug)]
pub enum GateType {
    TwoInput {
        input: [usize; 2],
        op: GateTwoInputOp,
    },
    OneInput {
        input: [usize; 1],
        op: GateOneInputOp,
    },
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

#[derive(Debug)]
pub struct Gate {
    gate_type: GateType,
    output_wire: usize,
}

#[derive(Debug)]
pub struct Circuit {
    input_wire_count: usize,
    output_wire_count: usize,
    total_wire_count: usize,
    gates: Vec<Vec<Gate>>,
}

impl Circuit {
    pub fn eval_circuit(&self, input_wires: &[GF2]) -> Option<Vec<GF2>> {
        assert_eq!(input_wires.len(), self.input_wire_count);
        let mut wires = vec![GF2::zero(); self.total_wire_count];
        wires[0..self.input_wire_count].copy_from_slice(input_wires);
        for gate in self.gates.iter().flatten() {
            wires[gate.output_wire] = match gate.gate_type {
                GateType::OneInput { input, op } => op.eval(wires[input[0]]),
                GateType::TwoInput { input, op } => op.eval(wires[input[0]], wires[input[1]]),
            };
        }
        wires.drain(0..(self.total_wire_count - self.output_wire_count));
        Some(wires)
    }
}

#[derive(Debug)]
pub enum CircuitEvalSessionState<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> {
    WaitingToSend(CircuitEvalSessionWaitingToSend<'a, T>),
    WaitingToReceive(CircuitEvalSessionWaitingToReceive<'a, T>),
    Finished(Vec<GF2>),
}
#[derive(Debug)]
struct CircuitEvalSession<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> {
    circuit: &'a Circuit,
    wires: Vec<GF2>,
    layer_to_process: usize,
    beaver_triple_gen: T,
    beaver_triples_current_layer: Vec<BeaverTripletShare<GF2>>,
    party_id: bool,
}

// We use three different structs to enforce certain actions to be done only in certain states by the typing system.

#[derive(Debug)]
pub struct CircuitEvalSessionWaitingToSend<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> {
    session: CircuitEvalSession<'a, T>,
}
#[derive(Debug)]
pub struct CircuitEvalSessionWaitingToReceive<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> {
    session: CircuitEvalSession<'a, T>,
}

impl<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> CircuitEvalSession<'a, T> {}

impl<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> CircuitEvalSessionState<'a, T> {
    pub fn new(
        circuit: &'a Circuit,
        input_shares: &[GF2],
        beaver_triple_gen: T,
        party_id: bool,
    ) -> Self {
        assert_eq!(circuit.input_wire_count, input_shares.len());
        let wires: Vec<GF2> = input_shares
            .into_iter()
            .chain(
                [GF2::zero()]
                    .iter()
                    .cycle()
                    .take(circuit.total_wire_count - circuit.input_wire_count),
            )
            .map(|v| *v)
            .collect();
        let session = CircuitEvalSession {
            circuit,
            wires,
            beaver_triple_gen,
            beaver_triples_current_layer: vec![],
            layer_to_process: 0,
            party_id,
        };
        CircuitEvalSessionState::WaitingToSend(CircuitEvalSessionWaitingToSend { session })
    }
}

impl<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> CircuitEvalSessionWaitingToSend<'a, T> {
    pub fn fetch_layer_messages(self) -> (CircuitEvalSessionState<'a, T>, Vec<(GF2, GF2)>) {
        // Prepare beaver triples for this layer.
        let mut session = self.session;
        let layer_id = session.layer_to_process;
        let current_layer = session
            .circuit
            .gates
            .get(layer_id)
            .expect("Missing layer, corrupt state!");
        session.beaver_triples_current_layer.clear();
        session
            .beaver_triples_current_layer
            .reserve_exact(current_layer.len());

        // Generate the messages.
        let msgs = current_layer
            .iter()
            .filter_map(|g| {
                session.wires[g.output_wire] = match g.gate_type {
                    GateType::TwoInput { input, op } => {
                        let x_share = session.wires[input[0]];
                        let y_share = session.wires[input[1]];
                        match op {
                            GateTwoInputOp::Xor => xor_gate::eval_mpc(x_share, y_share),
                            GateTwoInputOp::And => {
                                let triple = session
                                    .beaver_triple_gen
                                    .next()
                                    .expect("Beaver triples generator is exhausted.");
                                let msg = Some(and_gate::mpc_make_msgs(
                                    session.wires[input[0]],
                                    session.wires[input[1]],
                                    &triple,
                                ));
                                session.beaver_triples_current_layer.push(triple);
                                return msg;
                            }
                        }
                    }
                    GateType::OneInput { input, op } => match op {
                        GateOneInputOp::Not => {
                            not_gate::eval_mpc(session.wires[input[0]], session.party_id)
                        }
                    },
                };
                None
            })
            .collect();
        let new_state =
            CircuitEvalSessionState::WaitingToReceive(CircuitEvalSessionWaitingToReceive {
                session,
            });
        (new_state, msgs)
    }
}

impl<'a, T: Iterator<Item = BeaverTripletShare<GF2>>> CircuitEvalSessionWaitingToReceive<'a, T> {
    pub fn handle_layer_responses(
        self,
        responses: Vec<(GF2, GF2)>,
    ) -> CircuitEvalSessionState<'a, T> {
        let mut session = self.session;
        let layer_id = session.layer_to_process;
        let current_layer = session
            .circuit
            .gates
            .get(layer_id)
            .expect("Current layer id missing, corrupt struct");
        let mut responses_iter = responses.into_iter();
        let mut beaver_triples_iter = session.beaver_triples_current_layer.iter();
        for g in current_layer {
            if let GateType::TwoInput {
                input,
                op: GateTwoInputOp::And,
            } = g.gate_type
            {
                let x_share = session.wires[input[0]];
                let y_share = session.wires[input[1]];
                let (x_response, y_response) = responses_iter
                    .next()
                    .expect("Malformed response from peer! Insufficient data");
                session.wires[g.output_wire] = and_gate::mpc_handle_msgs(
                    x_share,
                    y_share,
                    x_response,
                    y_response,
                    beaver_triples_iter
                        .next()
                        .expect("Insufficient preprocessed triples, this shouldn't have happened!"),
                )
            }
        }
        if responses_iter.next().is_some() {
            panic!("Malformed response from peer! Data too long");
        }
        session.layer_to_process = layer_id + 1;
        session.beaver_triples_current_layer.clear();
        if session
            .circuit
            .gates
            .get(session.layer_to_process)
            .is_none()
        {
            CircuitEvalSessionState::Finished(
                session
                    .wires
                    .into_iter()
                    .skip(session.circuit.total_wire_count - session.circuit.output_wire_count)
                    .collect(),
            )
        } else {
            CircuitEvalSessionState::WaitingToSend(CircuitEvalSessionWaitingToSend { session })
        }
    }
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
    use crate::pprf::usize_to_bits;
    use crate::pseudorandom::KEY_SIZE;

    fn get_prf_keys(amount: u8) -> Vec<[u8; KEY_SIZE]> {
        let mut base_prf_key = [0u8; KEY_SIZE];
        (0..amount)
            .map(|i| {
                base_prf_key[KEY_SIZE - 1] = i;
                base_prf_key
            })
            .collect()
    }

    fn get_puncturing_points<const INPUT_BITLEN: usize>(amount: u8) -> Vec<[bool; INPUT_BITLEN]> {
        (0..amount)
            .map(|i| usize_to_bits(100 * usize::from(i)))
            .collect()
    }

    fn share_inputs(input: &[GF2]) -> (Vec<GF2>, Vec<GF2>) {
        input
            .iter()
            .enumerate()
            .map(|(idx, val)| {
                let random_element = GF2::from(idx % 2 == 1);
                (random_element, *val - random_element)
            })
            .unzip()
    }

    fn eval_mpc_circuit<const CODE_WEIGHT: usize>(
        circuit: &Circuit,
        input_a: &[GF2],
        input_b: &[GF2],
        beaver_triple_scalar_key: &mut BeaverTripletScalarPartyOnlinePCGKey<CODE_WEIGHT>,
        beaver_triple_vector_key: &mut BeaverTripletBitPartyOnlinePCGKey<CODE_WEIGHT>,
    ) -> (Vec<GF2>, Vec<GF2>) {
        let mut first_party_session =
            CircuitEvalSessionState::new(&circuit, &input_a, beaver_triple_scalar_key, false);
        let mut second_party_session =
            CircuitEvalSessionState::new(&circuit, &input_b, beaver_triple_vector_key, true);
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
                CircuitEvalSessionState::WaitingToReceive(session) => {
                    session.handle_layer_responses(second_party_queries)
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
        let circuit = parse_bristol(logical_or_circuit.into_iter()).expect("Failed to parse");

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

        // Test MPC eval.
        const WEIGHT: u8 = 10;
        const INPUT_BITLEN: usize = 3;
        const CODE_WEIGHT: usize = 7;
        let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
        let prf_keys = get_prf_keys(WEIGHT);
        let puncturing_points: Vec<[bool; INPUT_BITLEN]> = get_puncturing_points(WEIGHT);
        let (scalar_online_key, vector_online_key) = crate::pcg::sparse_vole::trusted_deal::<
            INPUT_BITLEN,
            CODE_WEIGHT,
        >(&scalar, puncturing_points, prf_keys);

        let mut beaver_triple_scalar_key: BeaverTripletScalarPartyOnlinePCGKey<CODE_WEIGHT> =
            scalar_online_key.into();
        let mut beaver_triple_vector_key: BeaverTripletBitPartyOnlinePCGKey<CODE_WEIGHT> =
            vector_online_key.into();

        let (input_a, input_b) = share_inputs(&vec![GF2::zero(), GF2::zero()]);
        let (output_a, output_b) = eval_mpc_circuit(
            &circuit,
            &input_a,
            &input_b,
            &mut beaver_triple_scalar_key,
            &mut beaver_triple_vector_key,
        );
        assert_eq!(output_a.len(), output_b.len());
        assert_eq!(output_a.len(), 1);
        assert_eq!(output_a[0] + output_b[0], GF2::zero());
    }
}

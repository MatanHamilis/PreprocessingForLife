#![feature(generic_const_exprs)]
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Parser, Subcommand};
use silent_party::{
    circuit_eval::{
        circuit_from_file, MaliciousSecurityOffline, ParsedCircuit,
        PcgBasedPairwiseBooleanCorrelation,
    },
    engine::{MultiPartyEngine, NetworkRouter},
    fields::{FieldElement, PackedGF2, GF2, GF64},
    pcg::{PackedOfflineReceiverPcgKey, StandardDealer},
    PartyId, UCTag,
};
use tokio::join;

fn build_searching_circuit() -> ParsedCircuit {
    let path = Path::new("circuits/aes_128.txt");
    let aes_circuit = circuit_from_file(path).unwrap();
    let path = Path::new("circuits/xor_reverse.txt");
    let xor_circuit = circuit_from_file(path).unwrap();
    let path = Path::new("circuits/zero_equal.txt");
    let zero_eq_circuit = circuit_from_file(path).unwrap();
    let output = aes_circuit
        .try_compose(xor_circuit)
        .unwrap()
        .try_compose(zero_eq_circuit)
        .unwrap();
    println!(
        "Got circuit! Depth: {}. total gates: {}, total ANDs: {}",
        output.gates.len(),
        output.iter().count(),
        output.total_non_linear_gates(),
    );
    output
}

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = "Searchable Encryption with Palindrome checking - dealing"
)]
struct Cli {
    #[arg(default_value_t = 1<<10)]
    db_size_in_batches: usize,
    #[command(subcommand)]
    role: Role,
}

#[derive(Clone, Subcommand)]
enum Role {
    /// Role of the dealer.
    Dealer {
        #[arg(default_value_t = 45678)]
        listen_port: u16,
    },
    /// Role of the first participating party
    Alice {
        /// The path to store the generated correlation.
        correlation_storage_path: PathBuf,
        /// The ip and port of the dealer.
        #[arg(default_value_t = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 45678))]
        dealer: SocketAddrV4,
        /// The port on which to accept Bobs connection.
        #[arg(default_value_t = 45679)]
        listen_bob_port: u16,
    },
    /// Role of the second participating party
    Bob {
        /// The path to store the generated correlation.
        correlation_storage_path: PathBuf,
        /// The ip and port of the dealer.
        #[arg(default_value_t = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 45678))]
        dealer: SocketAddrV4,
        /// The ip and port of Alice.
        #[arg(default_value_t = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 45679))]
        alice: SocketAddrV4,
    },
}

fn role_to_party_id(role: &Role) -> PartyId {
    match role {
        Role::Dealer { listen_port: _ } => DEALER_ID,
        Role::Alice {
            dealer: _,
            listen_bob_port: _,
            correlation_storage_path: _,
        } => ALICE_ID,
        Role::Bob {
            dealer: _,
            alice: _,
            correlation_storage_path: _,
        } => BOB_ID,
    }
}
const BOB_ID: PartyId = 1;
const ALICE_ID: PartyId = 2;
const DEALER_ID: PartyId = 3;
fn role_to_listen_port(role: &Role) -> u16 {
    match role {
        Role::Dealer { listen_port } => *listen_port,
        Role::Alice {
            dealer,
            listen_bob_port,
            correlation_storage_path: _,
        } => *listen_bob_port,
        Role::Bob {
            dealer,
            alice,
            correlation_storage_path: _,
        } => 0,
    }
}
fn role_to_storage_file(role: &Role) -> File {
    let path = match role {
        Role::Dealer { listen_port: _ } => panic!(),
        Role::Alice {
            dealer: _,
            listen_bob_port: _,
            correlation_storage_path,
        } => correlation_storage_path,
        Role::Bob {
            dealer: _,
            alice: _,
            correlation_storage_path,
        } => correlation_storage_path,
    };
    File::create(path).unwrap()
}
fn role_to_peers(role: &Role) -> HashMap<PartyId, SocketAddrV4> {
    match role {
        Role::Dealer { listen_port: _ } => HashMap::new(),
        Role::Alice {
            correlation_storage_path: _,
            dealer,
            listen_bob_port: _,
        } => HashMap::from([(DEALER_ID, *dealer)]),
        Role::Bob {
            correlation_storage_path: _,
            dealer,
            alice,
        } => HashMap::from([(ALICE_ID, *alice), (DEALER_ID, *dealer)]),
    }
}
async fn setup_networking(role: &Role) -> (NetworkRouter, impl MultiPartyEngine) {
    let root_tag = UCTag::new(&"root_tag");
    let local_party_id = role_to_party_id(role);
    let listen_port = role_to_listen_port(role);
    let peers = role_to_peers(role);
    NetworkRouter::new(local_party_id, &peers, root_tag, 3, listen_port)
        .await
        .unwrap()
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    let circuit = build_searching_circuit();
    let (router, engine) = setup_networking(&cli.role).await;
    let router_handle = tokio::spawn(router.launch());
    let db_size = cli.db_size_in_batches;
    let role_future = execute_role(db_size, &cli.role, engine, circuit);
    join!(router_handle, role_future).0.unwrap();
}

async fn execute_role(
    db_size: usize,
    role: &Role,
    engine: impl MultiPartyEngine,
    circuit: ParsedCircuit,
) {
    let mut two = GF64::zero();
    two.set_bit(true, 1);
    let three = two + GF64::one();
    let four = two * two;
    let circuit = Arc::new(circuit);
    let party_input_length = HashMap::from([(ALICE_ID, (0, 128)), (BOB_ID, (128, 128))]);

    match role {
        Role::Dealer { listen_port: _ } => {
            let dealer = StandardDealer::new(50, 20);
            for i in 0..db_size {
                MaliciousSecurityOffline::<
                    { PackedGF2::BITS },
                    PackedGF2,
                    GF2,
                    GF64,
                    PcgBasedPairwiseBooleanCorrelation<
                        { PackedGF2::BITS },
                        PackedGF2,
                        PackedOfflineReceiverPcgKey<1>,
                        StandardDealer,
                    >,
                >::malicious_security_offline_dealer(
                    &mut engine.sub_protocol(format!("{}", i)),
                    two,
                    three,
                    four,
                    circuit.clone(),
                    &party_input_length,
                    &dealer,
                )
                .await;
            }
        }
        _ => {
            let mut file = role_to_storage_file(role);
            for i in 0..db_size {
                let s = MaliciousSecurityOffline::<
                    { PackedGF2::BITS },
                    PackedGF2,
                    GF2,
                    GF64,
                    PcgBasedPairwiseBooleanCorrelation<
                        { PackedGF2::BITS },
                        PackedGF2,
                        PackedOfflineReceiverPcgKey<1>,
                        StandardDealer,
                    >,
                >::malicious_security_offline_party(
                    &mut engine.sub_protocol(format!("{}", i)),
                    DEALER_ID,
                    circuit.clone(),
                )
                .await;
                bincode::serialize_into(&mut file, &s).unwrap();
            }
        }
    }
}

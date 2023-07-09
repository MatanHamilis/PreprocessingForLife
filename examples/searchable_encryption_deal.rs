#![feature(generic_const_exprs)]
use core::num;
use std::{
    collections::HashMap,
    fs::File,
    net::SocketAddrV4,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::{Args, Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{info, trace};
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
    let path = Path::new("circuits/prexor_256.txt");
    let prexor_circuit = circuit_from_file(path).unwrap();
    let path = Path::new("circuits/aes_128.txt");
    let aes_circuit = circuit_from_file(path).unwrap();
    let path = Path::new("circuits/xor_reverse.txt");
    let xor_circuit = circuit_from_file(path).unwrap();
    let path = Path::new("circuits/zero_equal.txt");
    let zero_eq_circuit = circuit_from_file(path).unwrap();
    let output = prexor_circuit
        .try_compose(aes_circuit)
        .unwrap()
        .try_compose(xor_circuit)
        .unwrap()
        .try_compose(zero_eq_circuit)
        .unwrap();
    info!(
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
    long_about = "Searchable Encryption"
)]
struct Cli {
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
    #[arg(default_value_t = 100)]
    db_size_in_batches: usize,
    #[command(subcommand)]
    role: Role,
}

#[derive(Clone, Subcommand)]
enum Role {
    /// Role of the dealer.
    Dealer {
        #[arg(default_value = "./client_correlation.bin")]
        client_correlation: String,
        #[arg(default_value = "./server_correlation.bin")]
        server_correlation: String,
    },
    /// Role of a non-dealer party
    Party {
        /// The path to store the generated correlation.
        correlation_storage_path: PathBuf,
        /// Info on connecting to the other party.
        #[command(subcommand)]
        party: Party,
    },
}

#[derive(Clone, Args)]
struct PartyArgs {
    /// The path of the DB to compute, if computing.
    #[arg(long, requires = "key_share_path")]
    db_path: Option<PathBuf>,
    #[arg(long, requires = "db_path")]
    key_share_path: Option<PathBuf>,
    /// The ip and port of the dealer, if dealing.
    #[arg(
        long,
        required_unless_present("db_path"),
        required_unless_present("key_share_path")
    )]
    dealer_info: Option<SocketAddrV4>,
}

#[derive(Clone, Subcommand)]
enum Party {
    /// Role of the first participating party
    Server {
        /// The port on which to accept Bobs connection.
        #[arg(default_value_t = 45679)]
        listen_port: u16,
    },
    /// Role of the second participating party
    Client {
        /// The ip and port of Alice.
        server_address: SocketAddrV4,
    },
}

const BOB_ID: PartyId = 1;
const ALICE_ID: PartyId = 2;
const DEALER_ID: PartyId = 3;

fn role_to_party_id(role: &Role) -> PartyId {
    match role {
        Role::Party {
            correlation_storage_path,
            party,
            party_args,
        } => match party {
            Party::Server { listen_port: _ } => ALICE_ID,
            _ => BOB_ID,
        },
        _ => DEALER_ID,
    }
}

fn role_to_listen_port(role: &Role) -> u16 {
    match role {
        Role::Dealer { listen_port } => *listen_port,
        Role::Party {
            correlation_storage_path: _,
            party,
            party_args,
        } => match party {
            Party::Server { listen_port: listen_bob_port } => *listen_bob_port,
            _ => 0,
        },
    }
}
fn is_deal(role: &Role) -> bool {
    match role {
        Role::Party {
            correlation_storage_path,
            party,
            party_args,
        } => !party_args.dealer_info.is_none(),
        _ => true,
    }
}

fn prepare_file(path: &PathBuf, is_deal: bool) -> File {
    if is_deal {
        File::create(path).unwrap()
    } else {
        File::open(path).unwrap()
    }
}

fn role_to_peers(role: &Role) -> HashMap<PartyId, SocketAddrV4> {
    match role {
        Role::Party {
            correlation_storage_path: _,
            party,
            party_args,
        } => {
            let mut peer_info = Vec::new();
            if !party_args.dealer_info.is_none() {
                let dealer_info = party_args.dealer_info.clone().unwrap();
                peer_info.push((DEALER_ID, dealer_info));
            }
            if let Party::Client { server_address: alice } = party {
                peer_info.push((ALICE_ID, *alice));
            }
            HashMap::from_iter(peer_info.into_iter())
        }
        _ => HashMap::new(),
    }
}
async fn setup_networking(role: &Role) -> (NetworkRouter, impl MultiPartyEngine) {
    let root_tag = UCTag::new(&"root_tag");
    let local_party_id = role_to_party_id(role);
    let listen_port = role_to_listen_port(role);
    let peers = role_to_peers(role);
    let num_parties = if is_deal(role) { 3 } else { 2 };
    NetworkRouter::new(local_party_id, &peers, root_tag, num_parties, listen_port)
        .await
        .unwrap()
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    pretty_env_logger::formatted_builder()
        .filter_level(cli.verbose.log_level_filter())
        .init();
    let circuit = build_searching_circuit();
    trace!(
        "Circuit input wires: {} internal wires: {} output wires: {}",
        circuit.input_wire_count,
        circuit.internal_wire_count,
        circuit.output_wire_count
    );
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
    let party_input_length = HashMap::from([(ALICE_ID, (0, 256)), (BOB_ID, (256, 256))]);

    let mb = MultiProgress::new();
    let pb = mb.add(ProgressBar::new(db_size as u64));
    let spinner_style = ProgressStyle::with_template(
        "{spinner} {prefix:.bold.dim} [{elapsed}] [{wide_bar}] {human_pos}/{human_len} ({eta})",
    )
    .unwrap()
    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
    pb.set_style(spinner_style.clone());
    pb.set_prefix("Generating Correlation:");
    match role {
        // If I'm a dealer.
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
                pb.inc(1);
            }
            pb.finish_with_message("Done sharing correlation!");
        }
        Role::Party {
            correlation_storage_path,
            party,
            party_args,
        } => {
            let deal = is_deal(role);
            let mut file = prepare_file(correlation_storage_path, deal);
            if deal {
                let ser_bar = mb.add(ProgressBar::new(db_size as u64));
                ser_bar.set_style(spinner_style);
                ser_bar.set_prefix("Writing Correlating to Disk:");
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
                    pb.inc(1);
                    bincode::serialize_into(&mut file, &s).unwrap();
                    ser_bar.inc(1);
                }
                pb.finish_with_message("Done sharing correlation!");
                ser_bar.finish_with_message("Done writing correlation to disk!");
            } else {
                // This is computation.
                let = party_args.db_path.unwrap()
            }
        }
    }
}

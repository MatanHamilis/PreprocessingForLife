use pretty_env_logger::env_logger;
use rayon::vec;
use std::{
    fs::File,
    io::BufRead,
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::exit,
    str::FromStr,
};

use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
use log::{debug, error, info, trace, warn};
use silent_party::{
    circuit_eval::{bristol_fashion::parse_bristol, eval_circuit, Circuit},
    communicator::Communicator,
    fields::GF128,
    pcg::{
        bit_beaver_triples::{
            BeaverTripletBitPartyOnlinePCGKey, BeaverTripletScalarPartyOnlinePCGKey,
        },
        codes::EACode,
        sparse_vole::scalar_party::distributed_generation as scalar_distributed_generation,
    },
    pprf::usize_to_bits,
    pseudorandom::{prf::PrfInput, KEY_SIZE},
};
use silent_party::{
    fields::GF2,
    pcg::sparse_vole::vector_party::distributed_generation as vector_distributed_generation,
};

/// Two Party PCG-based Semi-Honest MPC for boolean circuits.
#[derive(Parser, Debug)]
#[clap(name = "MPC Runner")]
#[clap(about = "An example runner for semi-honest 2PC computation based on PCGs")]
#[clap(version, author,long_about = None)]
struct CliArgs {
    #[clap(subcommand)]
    command: Commands,
    circuit_path: PathBuf,
    #[clap(flatten)]
    verbose: Verbosity,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Client { peer_address: SocketAddrV4 },
    Server { local_port: u16 },
}
pub fn main() {
    let args = CliArgs::parse();
    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    info!("Circuit file path: {:?}", args.circuit_path);
    let circuit = match circuit_from_file(&args.circuit_path) {
        Some(c) => c,
        None => {
            error!("Failed to parse circuit!");
            return;
        }
    };
    trace!("Parsed circuit file successfully!");

    let socket = match args.command {
        Commands::Server { local_port } => handle_server(&circuit, local_port),
        Commands::Client { peer_address } => handle_client(&circuit, peer_address),
    };
}

fn circuit_from_file(path: &Path) -> Option<Circuit> {
    let circuit_file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open circuit file! Error: {}", e);
            return None;
        }
    };
    let lines = std::io::BufReader::new(circuit_file)
        .lines()
        .map_while(|line| match line {
            Ok(str) => Some(str),
            Err(e) => {
                error!("File reading error! Error: {}", e);
                None
            }
        });
    match parse_bristol(lines) {
        n @ Some(_) => n,
        None => {
            error!("Failed to parse circuit!");
            return None;
        }
    }
}

fn handle_server(circuit: &Circuit, local_port: u16) {
    const WEIGHT: u8 = 128;
    const INPUT_BITLEN: usize = 13;
    info!("I am SERVER");
    info!("Listening to port: {}", local_port);
    let listener = match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), local_port))
    {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to listen on port. Error: {}", e);
            return;
        }
    };
    let stream = match listener.accept() {
        Ok(s) => {
            info!("Accepted peer! Peer address: {}", s.1);
            s.0
        }
        Err(e) => {
            error!("Failed to accept peer! Error: {}", e);
            return;
        }
    };
    stream.set_nodelay(true).expect("Failed to set nodelay");
    let mut communicator = Communicator::from(stream);
    info!("Starting PCG Generation...");
    let prf_keys = get_prf_keys(WEIGHT);
    let puncturing_points: Vec<PrfInput<INPUT_BITLEN>> = get_puncturing_points(WEIGHT);
    let pcg_offline_key =
        vector_distributed_generation(puncturing_points, prf_keys, &mut communicator).unwrap();
    let ea_code = EACode::<8>::new(pcg_offline_key.vector_length(), [0u8; 16]);
    let pcg_online_key = pcg_offline_key.provide_online_key(ea_code);
    info!("PCG offline key generated successfully!");
    info!("Preparing input...");
    let my_input = vec![GF2::default(); circuit.input_wire_count() / 2];
    let peer_input_share = vec![GF2::default(); circuit.input_wire_count() / 2];
    info!("Generating online keys...");
    let beaver_triplet_pcg_online_key: BeaverTripletBitPartyOnlinePCGKey<GF2, _> =
        pcg_online_key.into();
    let eval_start = Instant::now();
    info!("Starting circuit evaluation NOW!");
    let output = eval_circuit(
        circuit,
        (my_input, peer_input_share),
        beaver_triplet_pcg_online_key,
        &mut communicator,
        true,
    )
    .unwrap();
    let time = eval_start.elapsed();
    info!("Finished computation Successfully! Here are some statistics:");
    info!("Circuit Evaluation Took: {} millisecond", time.as_millis());
    info!("Total bytes sent: {}", communicator.total_byte_write());
    info!("Total bytes received: {}", communicator.total_bytes_read());
    info!("Output:");
    for (idx, val) in output.iter().enumerate() {
        trace!("output[{}]={:?}", idx, val);
    }
}

fn handle_client(circuit: &Circuit, peer_address: SocketAddrV4) {
    info!("I am CLIENT");
    info!("Connecting to address: {}", peer_address);
    let stream = match TcpStream::connect(peer_address) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to peer! Error: {}", e);
            return;
        }
    };
    stream.set_nodelay(true).expect("Failed to set nodelay");
    trace!("Connected to peer succesfully");
    let mut communicator = Communicator::from(stream);
    let scalar = GF128::from([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    info!("Starting PCG Generation...");
    let pcg_offline_key =
        scalar_distributed_generation::<13, _>(&scalar, &mut communicator).unwrap();
    let ea_code = EACode::<8>::new(pcg_offline_key.vector_length(), [0u8; 16]);
    let pcg_online_key = pcg_offline_key.provide_online_key(ea_code);
    info!("PCG offline key generated successfully!");
    info!("Preparing input...");
    let my_input = vec![GF2::default(); circuit.input_wire_count() / 2];
    let peer_input_share = vec![GF2::default(); circuit.input_wire_count() / 2];
    info!("Generating online keys...");
    let beaver_triplet_pcg_online_key: BeaverTripletScalarPartyOnlinePCGKey<GF2, _> =
        pcg_online_key.into();
    info!("Starting circuit evaluation NOW!");
    let eval_start = Instant::now();
    let output = eval_circuit(
        circuit,
        (my_input, peer_input_share),
        beaver_triplet_pcg_online_key,
        &mut communicator,
        false,
    )
    .unwrap();
    let time = eval_start.elapsed();
    info!("Finished computation Successfully! Here are some statistics:");
    info!("Circuit Evaluation Took: {} millisecond", time.as_millis());
    info!("Total bytes sent: {}", communicator.total_byte_write());
    info!("Total bytes received: {}", communicator.total_bytes_read());
    info!("Output:");
    for (idx, val) in output.iter().enumerate() {
        trace!("output[{}]={:?}", idx, val);
    }
}

fn get_prf_keys(amount: u8) -> Vec<[u8; KEY_SIZE]> {
    let mut base_prf_key = [0u8; KEY_SIZE];
    (0..amount)
        .map(|i| {
            base_prf_key[KEY_SIZE - 1] = i;
            base_prf_key
        })
        .collect()
}

fn get_puncturing_points<const INPUT_BITLEN: usize>(amount: u8) -> Vec<PrfInput<INPUT_BITLEN>> {
    (0..amount)
        .map(|i| usize_to_bits(100 * usize::from(i)).into())
        .collect()
}

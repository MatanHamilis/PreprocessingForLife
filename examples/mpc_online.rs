use pretty_env_logger::env_logger;
use std::{
    fs::File,
    io::BufRead,
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::Instant,
};

use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
use log::{error, info, trace};
use silent_party::{circuit_eval::bristol_fashion::ParsedCircuit, fields::GF2};
use silent_party::{
    circuit_eval::{bristol_fashion::parse_bristol, eval_circuit, Circuit},
    communicator::Communicator,
    fields::{FieldElement, PackedGF2Array, GF128},
    pprf::usize_to_bits,
    pseudorandom::{prf::PrfInput, KEY_SIZE},
};

const INPUT_WIDTH: usize = 2;
const WEIGHT: usize = 128;
const INPUT_BITLEN: usize = 13;
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
    let parsed_circuit = match circuit_from_file(&args.circuit_path) {
        Some(c) => c,
        None => {
            error!("Failed to parse circuit!");
            return;
        }
    };
    trace!("Parsed circuit file successfully!");
    info!("Circuit layer count: {}", parsed_circuit.gates.len());

    match args.command {
        Commands::Server { local_port } => handle_server(&parsed_circuit, local_port),
        Commands::Client { peer_address } => handle_client(&parsed_circuit, peer_address),
    };
}

fn circuit_from_file(path: &Path) -> Option<ParsedCircuit> {
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
            None
        }
    }
}

fn handle_server(parsed_circuit: &ParsedCircuit, local_port: u16) {
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
    let scalar = GF128::from([10, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0]);
    let prf_keys = insecure_get_prf_keys::<WEIGHT>([2; KEY_SIZE]);
    let puncturing_points = insecure_get_puncturing_points::<INPUT_BITLEN, WEIGHT>(2);
    let code_seed_first = [100; KEY_SIZE];
    let code_seed_second = [101; KEY_SIZE];

    info!("Generating PCG Keys...");
    let mut correlation_generator = silent_party::pcg_key_gen::<TcpStream, WEIGHT, INPUT_BITLEN, 8>(
        prf_keys,
        puncturing_points,
        scalar,
        code_seed_first,
        code_seed_second,
        silent_party::pcg::full_key::Role::Receiver,
        &mut communicator,
    );
    info!("PCG offline key generated successfully!");
    let circuit = Circuit::from(parsed_circuit.clone());
    info!("Preparing input...");
    let my_input = vec![GF2::zero(); circuit.input_wire_count() / 2];
    let peer_input_share = vec![GF2::zero(); circuit.input_wire_count() / 2];
    info!("Starting circuit evaluation NOW!");
    let eval_start = Instant::now();
    let output = eval_circuit(
        circuit,
        (my_input, peer_input_share),
        &mut correlation_generator,
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

fn handle_client(circuit: &ParsedCircuit, peer_address: SocketAddrV4) {
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
    let prf_keys = insecure_get_prf_keys::<WEIGHT>([1; KEY_SIZE]);
    let puncturing_points = insecure_get_puncturing_points::<INPUT_BITLEN, WEIGHT>(1);
    let code_seed_first = [100; KEY_SIZE];
    let code_seed_second = [101; KEY_SIZE];

    info!("Generating PCG Keys...");
    let mut correlation_generator = silent_party::pcg_key_gen::<TcpStream, WEIGHT, INPUT_BITLEN, 8>(
        prf_keys,
        puncturing_points,
        scalar,
        code_seed_first,
        code_seed_second,
        silent_party::pcg::full_key::Role::Sender,
        &mut communicator,
    );
    info!("PCG key generated successfully!");
    let circuit = Circuit::from(circuit.clone());
    info!("Preparing input...");
    let my_input = vec![GF2::zero(); circuit.input_wire_count() / 2];
    let peer_input_share = vec![GF2::zero(); circuit.input_wire_count() / 2];

    info!("Starting circuit evaluation NOW!");
    let eval_start = Instant::now();
    let output = eval_circuit(
        circuit,
        (my_input, peer_input_share),
        &mut correlation_generator,
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

fn insecure_get_prf_keys<const WEIGHT: usize>(
    mut base_prf_key: [u8; KEY_SIZE],
) -> [[u8; KEY_SIZE]; WEIGHT] {
    std::array::from_fn(|i| {
        base_prf_key[KEY_SIZE - 1] = u8::try_from(i).unwrap();
        base_prf_key
    })
}

fn insecure_get_puncturing_points<const INPUT_BITLEN: usize, const WEIGHT: usize>(
    base_val: usize,
) -> [PrfInput<INPUT_BITLEN>; WEIGHT] {
    std::array::from_fn(|i| usize_to_bits(base_val + 100 * usize::from(i)).into())
}

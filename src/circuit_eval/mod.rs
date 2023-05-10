use std::{fs::File, io::BufRead, path::Path};

pub use self::bristol_fashion::{parse_bristol, ParsedCircuit};
pub use self::malicious::{MaliciousSecurityOffline, PreOnlineMaterial};
pub use self::semi_honest::{
    multi_party_semi_honest_eval_circuit, FieldContainer, GF2Container,
    OfflineSemiHonestCorrelation, PackedGF2Container, PcgBasedPairwiseBooleanCorrelation,
    RegularMask, WideMask,
};

mod bristol_fashion;
mod malicious;
mod semi_honest;
mod verify;

pub fn circuit_from_file(path: &Path) -> Option<ParsedCircuit> {
    let circuit_file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return None;
        }
    };
    let lines = std::io::BufReader::new(circuit_file)
        .lines()
        .map_while(|line| match line {
            Ok(str) => Some(str),
            Err(_) => None,
        });
    match parse_bristol(lines) {
        n @ Some(_) => n,
        None => None,
    }
}

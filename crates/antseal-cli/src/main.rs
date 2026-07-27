//! `antseal` command-line interface — stub only. clap + tokio (and every
//! other CLI dependency) arrive with U1; until then the binary stays
//! dependency-free by design (P5).

// Intentional dependency edge: the CLI is a thin shell over antseal-core.
use antseal_core as _;

fn main() {
    println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
}

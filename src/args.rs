//! Command like argument parsing library
//! Only remote ID is required, other are predefined

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Remote P2P node ID (hex)
    #[arg(short, long)]
    pub remote_id: String,

    /// Remote P2P node address
    #[arg(short, long, default_value = "127.0.0.1")]
    pub address: String,

    /// Remote P2P node port
    #[arg(short, long, default_value_t = 30303)]
    pub port: u16,
}

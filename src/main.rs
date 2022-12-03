#![feature(slice_pattern)]

use clap::Parser;
use fehler::throws;
use lazy_static::lazy_static;

mod args;
mod protocols;

pub mod consts;
pub mod error;
pub mod ffi;
pub mod mac;
pub mod rlpx;
pub mod utils;

pub use error::Error;

use crate::protocols::Prot;

lazy_static! {
    pub static ref ARGS: args::Args = args::Args::parse();
}

#[throws(anyhow::Error)]
#[tokio::main]
async fn main() {
    env_logger::try_init()?;

    let prot = Prot::new(&ARGS.address, ARGS.port);

    prot.ping().await?;

    println!("------------------");
    prot.auth().await?;
}

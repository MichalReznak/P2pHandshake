//! Helper methods

use core::slice::SlicePattern;

use bytes::{Bytes, BytesMut};
use fehler::throws;
use rand::{thread_rng, RngCore};
use tokio::process::Command;

use crate::Error;

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x1, &x2)| x1 ^ x2).collect::<Vec<_>>()
}

#[throws]
pub fn pub_key(private_key: &[u8]) -> [u8; 64] {
    let secp = secp256k1::Secp256k1::new();
    let sc = secp256k1::SecretKey::from_slice(private_key.as_slice())?;
    let a = secp256k1::PublicKey::from_secret_key(&secp, &sc);

    // cut 04
    a.serialize_uncompressed()[1..].try_into()?
}

pub fn id2pk(id: &[u8]) -> Bytes {
    BytesMut::from_iter([4].iter().chain(id.iter())).freeze()
}

pub fn nonce() -> Bytes {
    let mut nonce = [0; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut nonce);
    Bytes::copy_from_slice(nonce.as_slice()) // TODO
}

// TODO
pub fn align_16(a: usize) -> usize {
    ((a as f64 / 16.0).ceil() * 16.0) as usize
}

#[throws]
pub async fn node(args: String) -> String {
    let output = Command::new("node")
        .arg("./ffi.js")
        .arg(args)
        .current_dir("./auth")
        .output()
        .await?;

    String::from_utf8(output.stdout[..output.stdout.len() - 1].to_vec())?
}

//! PING protocol implementation
//! This is not required when check for existence of a target node is required

use core::slice::SlicePattern;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{BufMut, BytesMut};
use fehler::throws;
use k256::ecdsa::recoverable::Signature;
use k256::ecdsa::signature::{Signature as _, Signer};
use k256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use web3_hash_utils::keccak256;

use crate::rlpx::types::{Endpoint, Ping};
use crate::Error;

/// Ping Packet (0x01)
/// packet-data = [version, from, to, expiration, enr-seq ...]
/// version = 4
/// from = [sender-ip, sender-udp-port, sender-tcp-port]
/// to = [recipient-ip, recipient-udp-port, 0]
/// The expiration field is an absolute UNIX time stamp.
/// Packets containing a time stamp that lies in the past are expired may not be
/// processed.
///
/// The enr-seq field is the current ENR sequence number of the sender.
/// This field is optional.
#[throws]
pub async fn ping(addr: &str, port: u16) {
    let sock = UdpSocket::bind("127.0.0.1:8081").await?; // TODO variable?
    let full_addr = format!("{}:{}", addr, port);
    sock.connect(full_addr).await?;

    let ping = Ping::builder()
        .version(4)
        .from(
            Endpoint::builder()
                .address("127.0.0.1".to_string())
                .udp_port(8081)
                .tcp_port(8081)
                .build(),
        )
        .to(Endpoint::builder()
            .address(addr.to_string())
            .udp_port(port)
            .tcp_port(port)
            .build())
        .timestamp(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 420)
        .build();

    let mut typedata = BytesMut::from(0x01_u8.to_be_bytes().as_slice());
    typedata.put(rlp::encode(&ping).as_slice());

    let sigkey = SigningKey::random(&mut OsRng);
    let sighash = keccak256(&typedata);
    let signature: Signature = sigkey.sign(&sighash);

    let mut hashdata = BytesMut::new();
    hashdata.put(signature.as_bytes());
    hashdata.put(typedata);
    hashdata.put(rlp::encode(&ping).as_slice());
    let hash = keccak256(&hashdata);

    let mut res = BytesMut::new();
    res.put(&hash[..]);
    res.put(&mut hashdata);

    println!("Sending the PING message...");
    sock.send(&res).await?;

    let mut buf = [0; 1024];
    println!("Waiting for PONG back...");
    sock.recv(&mut buf).await?;

    if buf[97] == 2 {
        println!("Got PONG back: Target node is reachable!");
    }
    else {
        println!("Did NOT got the PONG back: Target node is NOT reachable!");
    }
}

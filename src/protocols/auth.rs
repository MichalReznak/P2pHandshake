//! P2P Handshake protocol implementation

use std::time::Duration;

use fehler::throws;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::consts::PRIVATE_KEY_HEX;
use crate::{rlpx, Error, ARGS};

/// An RLPx connection is established by creating a TCP connection and agreeing
/// on ephemeral key material for further encrypted and authenticated
/// communication. The process of creating those session keys is the 'handshake'
/// and is carried out between the 'initiator' (the node which opened the TCP
/// connection) and the 'recipient' (the node which accepted it).
///
/// 1. *initiator* connects to recipient and sends its auth message
/// 2. *recipient* accepts, decrypts and verifies auth (checks that recovery of
///     signature == keccak256(ephemeral-pubk))
/// 3. *recipient* generates auth-ack message from
///     remote-ephemeral-pubk and nonce
/// 4. *recipient* derives secrets and sends the first encrypted frame
///     containing the Hello message
/// 5. *initiator* receives auth-ack and derives secrets
/// 6. *initiator* sends its first encrypted frame containing initiator
///     Hello message
/// 7. *recipient* receives and authenticates first encrypted frame
/// 8. *initiator* receives and authenticates first encrypted frame
/// 9. cryptographic handshake is complete if MAC of first encrypted frame
///     is valid on both sides
#[throws]
pub async fn auth(addr: &str, port: u16) {
    let full_addr = format!("{}:{}", addr, port);

    // TODO SSL?
    let mut stream = TcpStream::connect(full_addr).await?;
    let addr = stream.local_addr()?;
    println!("Connecting to: {:#?}", addr);

    let mut rlpx = rlpx::Rlpx::with_private_key(
        &hex::decode(PRIVATE_KEY_HEX)?,
        &hex::decode(&ARGS.remote_id)?,
    )?;

    println!("Sending Auth message");
    let auth_msg = rlpx.get_auth().await?;
    stream.write_all(&auth_msg).await?;

    let mut buf = [0; 1024];
    let msg = {
        let l = stream.read(&mut buf).await?;
        let l2 = stream.read(&mut buf[l..]).await?;
        &buf[..l + l2]
    };
    println!("Received Ack message");

    let size = u16::from_be_bytes(msg[..2].try_into()?);
    rlpx.parse_ack(&msg[..(size + 2) as usize]).await?;

    println!("Sending Hello message");
    let msg = rlpx.get_hello(addr.port()).await?;
    stream.write_all(&msg).await?;

    let mut buf = [0; 1024];
    let _l = stream.read(&mut buf).await?;

    println!("Connected!");
    println!("Keeping the connection open for 5 sec...");

    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("Closed.");
}

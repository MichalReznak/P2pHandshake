//! RLPx messages used in the protocol
//! This protocol is position based, which means that the order of member DOES
//! mather

use bytes::Bytes;
use rlp_derive::{RlpDecodable, RlpDecodableWrapper, RlpEncodable, RlpEncodableWrapper};
use typed_builder::TypedBuilder;

// (currently unused in spec)
#[derive(RlpEncodable, RlpDecodable, TypedBuilder)]
pub struct CapHeader {
    cap_id: u16,
    context_id: u16,
}

#[derive(RlpEncodable, RlpDecodable, TypedBuilder)]
pub struct AuthMsg {
    sig: Bytes,
    pub_key: Bytes,
    nonce: Bytes,
    version: u16,
}

#[derive(RlpEncodable, RlpDecodable, TypedBuilder)]
pub struct Protocol {
    name: String,
    t: u32,
}

#[derive(RlpEncodable, RlpDecodable, TypedBuilder)]
pub struct HelloMsg {
    version: u32,
    name: String,
    protocols: Vec<Protocol>,
    port: u16,
    pub_key: Bytes,
}

#[derive(RlpEncodable, RlpDecodable, TypedBuilder)]
pub struct Endpoint {
    address: String,
    udp_port: u16,
    tcp_port: u16,
}

#[derive(RlpEncodable, RlpDecodable, TypedBuilder)]
pub struct Ping {
    version: u16,
    from: Endpoint,
    to: Endpoint,
    timestamp: u64,
}

// Wrappers
#[derive(RlpEncodableWrapper, RlpDecodableWrapper, TypedBuilder)]
pub struct HelloPrefixMsg {
    zero: u32,
}

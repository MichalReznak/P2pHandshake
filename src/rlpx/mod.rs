//! Main file for the P2P Handshake protocol
//! It follows the EIP8 ethereum format

use core::slice::SlicePattern;

use aes::cipher::{KeyIvInit, StreamCipher};
use bytes::{BufMut, Bytes, BytesMut};
use fehler::throws;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use web3_hash_utils::keccak256;

use crate::ffi::EncFfi;
use crate::mac::Mac;
use crate::utils::{align_16, id2pk, nonce, pub_key, xor};
use crate::Error;

pub mod types;
use types::*;

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

pub struct Rlpx {
    client_id: Bytes,
    private_key: Bytes,
    pub_key: [u8; 64],
    eph_private_key: [u8; 32],
    nonce: Bytes,

    // Collected over time
    // TODO use generic type to remove opts
    init_msg: Option<Bytes>,
    aes: Option<Aes256Ctr>,
    mac: Option<Mac>,
}

impl Rlpx {
    #[throws]
    pub fn with_private_key(private_key: &[u8], client_id: &[u8]) -> Self {
        Self {
            pub_key: pub_key(private_key)?,
            private_key: Bytes::copy_from_slice(private_key),
            client_id: Bytes::copy_from_slice(client_id),
            eph_private_key: secp256k1::SecretKey::new(&mut OsRng).secret_bytes(),
            nonce: nonce(),

            // TODO remove options
            // Use generic type with extended functionality to remove options
            init_msg: None,
            aes: None,
            mac: None,
        }
    }

    /// **Authorization message format:**
    /// auth = auth-size || enc-auth-body
    /// auth-size = size of enc-auth-body, encoded as a big-endian 16-bit
    /// integer auth-vsn = 4
    /// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
    /// enc-auth-body = ecies.encrypt(recipient-pubk, auth-body || auth-padding,
    /// auth-size) auth-padding = arbitrary data
    #[throws]
    pub async fn get_auth(&mut self) -> Bytes {
        let ecdhx = {
            let e = EncFfi::ecdhx(&self.private_key, &id2pk(&self.client_id)).await?;
            xor(&e, &self.nonce)
        };

        let sig = EncFfi::ecdsa_sign(&self.eph_private_key, &ecdhx).await?;

        let msg = {
            let auth_msg = AuthMsg::builder()
                .sig(sig)
                .pub_key(Bytes::copy_from_slice(self.pub_key.as_slice()))
                .nonce(self.nonce.clone())
                .version(4)
                .build();
            let mut msg = rlp::encode(&auth_msg);
            msg.resize(msg.len() + thread_rng().gen_range(100..=250), 0);
            msg.freeze()
        };

        // TODO twice
        let ecies_overhead = 113;
        let mac_data = ((msg.len() + ecies_overhead) as u16).to_be_bytes();

        let enc = EncFfi::tagged_kdf(&msg, &id2pk(&self.client_id), &mac_data).await?;

        let msg = BytesMut::from_iter(mac_data.iter().chain(enc.iter())).freeze();
        self.init_msg = Some(msg.clone());
        msg
    }

    /// **Acknowledge message format:**
    /// ack = ack-size || enc-ack-body
    /// ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
    /// ack-vsn = 4
    /// ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
    /// enc-ack-body = ecies.encrypt(initiator-pubk, ack-body || ack-padding,
    /// ack-size) ack-padding = arbitrary data
    #[throws]
    pub async fn parse_ack(&mut self, msg: &[u8]) {
        let (aes_secret, mac_secret, rem_nonce) = {
            let (rem_nonce, eph_shared_secret) = {
                let output = EncFfi::concat_kdf(msg, &self.private_key).await?;

                // decrypt data
                let output = {
                    let mut msg = msg[65 + 2..].to_vec(); // public key + len
                    let iv: [u8; 16] = msg[..16].try_into()?;
                    let msg2 = &mut msg[16..];
                    let key: [u8; 16] = output.as_slice()[..16].try_into()?;
                    let mut aes = Aes128Ctr::new(&key.into(), &iv.into());
                    aes.apply_keystream(msg2);
                    Bytes::copy_from_slice(msg2)
                };

                // TODO once in a while fails
                // Ideally the method should return decode error so we could try with different
                // data
                let a: Vec<Bytes> = rlp::decode_list(&output);
                let rem_eph_pub_key = id2pk(&a[0]);
                let rem_nonce = Bytes::copy_from_slice(&a[1]);

                let eph_shared_secret =
                    EncFfi::ecdhx(self.eph_private_key.as_slice(), &rem_eph_pub_key).await?;
                (rem_nonce, eph_shared_secret)
            };

            let h_nonce =
                keccak256(BytesMut::from_iter(rem_nonce.iter().chain(self.nonce.iter())).freeze());

            let shared_secret = keccak256(
                BytesMut::from_iter(eph_shared_secret.iter().chain(h_nonce.iter())).freeze(),
            );

            let aes_secret = keccak256(
                BytesMut::from_iter(eph_shared_secret.iter().chain(shared_secret.iter())).freeze(),
            );

            let mac_secret = keccak256(
                BytesMut::from_iter(eph_shared_secret.iter().chain(aes_secret.iter())).freeze(),
            );

            (aes_secret, mac_secret, rem_nonce)
        };

        // Shared secrets
        // static-shared-secret = ecdh.agree(privkey, remote-pubk)
        // ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        // shared-secret = keccak256(ephemeral-key
        //     || keccak256(nonce || initiator-nonce))
        // aes-secret = keccak256(ephemeral-key || shared-secret)
        // mac-secret = keccak256(ephemeral-key || aes-secret)

        let iv = [0x0; 16];
        self.aes = Some(Aes256Ctr::new(&aes_secret.into(), &iv.into()));

        let mac_update = {
            let mut a = BytesMut::new();
            a.put(xor(&mac_secret, &rem_nonce).as_slice());

            if let Some(msg) = &self.init_msg {
                a.put(msg.as_slice());
            }
            else {
                panic!("NO INIT MSG!"); // TODO error
            }
            a.freeze()
        };

        self.mac = Some({
            let mut mac = Mac::with_secret(&mac_secret)?;
            mac.update(&mac_update);
            mac
        });
    }

    /// **Hello message format**
    /// Frame data
    /// frame-data = msg-id || msg-data
    /// frame-size = length of frame-data, encoded as a 24bit big-endian integer
    ///
    /// Hello (0x00)
    ///
    /// [protocolVersion: P, clientId: B, capabilities, listenPort: P, nodeKey: B_64, ...]
    ///
    /// First packet sent over the connection, and sent once by both sides.
    /// No other messages may be sent until a Hello is received.
    /// Implementations must ignore any additional list elements in Hello
    /// because they may be used by a future version.
    ///
    /// **protocolVersion** the version of the "p2p" capability, 5.
    /// **clientId** Specifies the client software identity,
    ///     as a human-readable string (e.g. "Ethereum(++)/1.0.0").
    /// **capabilities** is the list of supported capabilities
    ///     and their versions: [[cap1, capVersion1], [cap2, capVersion2], ...].
    /// **listenPort** specifies the port that the client is listening on
    ///     (on the interface that the present connection traverses).
    ///     If 0 it indicates the client is not listening.
    /// **nodeId** is the secp256k1 public key corresponding to the node's private key.
    #[throws]
    pub async fn get_hello(&mut self, port: u16) -> Bytes {
        let mut mac_data = {
            let prot = Protocol::builder().name("eth".to_string()).t(66).build();

            let hello = HelloMsg::builder()
                .version(5)
                .name("Michal Režňák".to_string())
                .protocols(vec![prot])
                .port(port)
                .pub_key(Bytes::copy_from_slice(self.pub_key.as_slice()))
                .build();

            let hello = rlp::encode(&hello);
            let hello_prefix = rlp::encode(&HelloPrefixMsg::builder().zero(0).build());

            let mut res = BytesMut::new();
            res.put(hello_prefix);
            res.put(hello);

            // Align to multiple of 16
            res.resize(align_16(res.len()), 0);
            res
        };

        let mut header_data = {
            // TODO not nice, will not fit if message is bigger
            // Use BytesMut with resize
            let size = [0, 0, mac_data.len() as u8];
            let cap = CapHeader::builder().cap_id(0).context_id(0).build();

            let mut res = BytesMut::new();
            res.put(size.as_slice());
            res.put(rlp::encode(&cap));
            res.resize(16, 0);
            res
        };

        if let Some(aes) = self.aes.as_mut() {
            aes.apply_keystream(&mut header_data);
            aes.apply_keystream(&mut mac_data);
        }
        else {
            panic!("Needs to be defined");
        }

        let (header_tag, mac_tag) = if let Some(mac) = self.mac.as_mut() {
            (mac.header_tag(&header_data), mac.data_tag(&mac_data))
        }
        else {
            panic!("Needs to be defined");
        };

        BytesMut::from_iter(
            header_data
                .iter()
                .chain(header_tag.iter())
                .chain(mac_data.iter())
                .chain(mac_tag.iter()),
        )
        .freeze()
    }
}

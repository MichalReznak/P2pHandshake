//! NodeJS FFI binding for parts implemented in different language
//! Once the dependencies are switched to rust versions than this is no longer
//! required

use bytes::Bytes;
use fehler::throws;

use crate::utils::node;
use crate::Error;

mod types;
use types::*;

pub struct EncFfi;

impl EncFfi {
    #[throws]
    pub async fn ecdsa_sign(eph_private_key: &[u8], ecdhx: &[u8]) -> Bytes {
        let args = EcdsaSign::builder()
            .ephemeral_private_key(hex::encode(eph_private_key))
            .msg(hex::encode(ecdhx))
            .build();

        let res = hex::decode(node(serde_json::to_string(&args)?).await?)?;
        Bytes::copy_from_slice(res.as_slice())
    }

    #[throws]
    pub async fn ecdhx(private_key: &[u8], public_key: &[u8]) -> Bytes {
        let args = Ecdhx::builder()
            .private_key(hex::encode(private_key))
            .public_key(hex::encode(public_key))
            .build();

        let res = hex::decode(node(serde_json::to_string(&args)?).await?)?;
        Bytes::copy_from_slice(res.as_slice())
    }

    #[throws]
    pub async fn tagged_kdf(msg: &[u8], client_pk: &[u8], mac_data: &[u8]) -> Bytes {
        let input = TaggedKdf::builder()
            .msg(hex::encode(msg))
            .remote_public_key(hex::encode(client_pk))
            .mac_data(hex::encode(mac_data))
            .build();

        let enc = hex::decode(node(serde_json::to_string(&input)?).await?)?;
        Bytes::copy_from_slice(enc.as_slice())
    }

    #[throws]
    pub async fn concat_kdf(msg: &[u8], private_key: &[u8]) -> Bytes {
        let input = ConcatKdf::builder()
            .private_key(hex::encode(private_key))
            .msg(hex::encode(msg))
            .build();

        let enc = hex::decode(node(serde_json::to_string(&input)?).await?)?;
        Bytes::copy_from_slice(enc.as_slice())
    }
}

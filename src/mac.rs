//! Message Authentication Code (MAC) algorithm
//! Needs to be synchronized with each message
//! The encryption uses Aes256 Encoder

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256Enc;
use bytes::Bytes;
use fehler::throws;
use sha3::{Digest, Keccak256};
use typed_builder::TypedBuilder;

use crate::utils::xor;
use crate::Error;

#[derive(TypedBuilder, Debug)]
pub struct Mac {
    aes: Aes256Enc,
    hash: Keccak256,
}

// TODO comments
/// Generate tags for RLPx message
impl Mac {
    #[throws]
    pub fn with_secret(secret: &[u8]) -> Self {
        Self {
            aes: Aes256Enc::new_from_slice(secret)?,
            hash: Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    pub fn header_tag(&mut self, data: &[u8]) -> Bytes {
        let mut encrypted = GenericArray::clone_from_slice(&self.digest());

        self.aes.encrypt_block(&mut encrypted);
        self.hash.update(&xor(&encrypted, data));
        self.digest()
    }

    pub fn data_tag(&mut self, data: &[u8]) -> Bytes {
        // TODO requires header_tag to be called first

        self.hash.update(data);
        let prev = self.digest();

        let mut encrypted = GenericArray::clone_from_slice(&prev);
        self.aes.encrypt_block(&mut encrypted);
        self.hash.update(&xor(&encrypted, &prev));
        self.digest()
    }

    fn digest(&mut self) -> Bytes {
        // TODO wrap around not being able to get digest without move
        let tmp_hash = self.hash.clone();
        Bytes::copy_from_slice(&tmp_hash.finalize()[..16])
    }
}

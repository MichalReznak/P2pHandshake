//! Global Error struct
//! Can be defined either per module of function
//! For simplicity only a single root Error is defined,
//! but for greater project there should not be only a single one

use std::array::TryFromSliceError;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;

use aes::cipher::InvalidLength;
use ecies::SecpError;
use hex::FromHexError;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Anyhow error: {source}"), context(false))]
    Any { source: anyhow::Error },

    #[snafu(display("Io error: {source}"), context(false))]
    Io { source: std::io::Error },

    #[snafu(display("SystemTimeError error: {source}"), context(false))]
    SystemTimeError { source: SystemTimeError },

    #[snafu(display("FromUtf8Error error: {source}"), context(false))]
    FromUtf8Error { source: FromUtf8Error },

    #[snafu(display("SerdeJson error: {source}"), context(false))]
    SerdeJson { source: serde_json::Error },

    #[snafu(display("FromHexError error: {source}"), context(false))]
    FromHex { source: FromHexError },

    #[snafu(display("SecpError error: {source}"), context(false))]
    Secp { source: SecpError },

    #[snafu(display("InvalidLength error: {source}"), context(false))]
    InvalidLength { source: InvalidLength },

    #[snafu(display("TryFromSliceError error: {source}"), context(false))]
    TryFromSliceError { source: TryFromSliceError },

    #[snafu(display("Secp256k1 error: {source}"), context(false))]
    Secp256k1 { source: secp256k1::Error },
}

/// Either use this type or the fehler library
pub type Result<T> = core::result::Result<T, Error>;

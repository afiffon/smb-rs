#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![allow(unused_parens)]

pub mod cancel;
pub mod compressed;
pub mod create;
pub mod dfsc;
pub mod echo;
pub mod encrypted;
pub mod error;
pub mod file;
pub mod header;
pub mod info;
pub mod ioctl;
pub mod lock;
pub mod message;
pub mod negotiate;
pub mod notify;
pub mod oplock;
pub mod plain;
pub mod query_dir;
pub mod session_setup;
pub mod smb1;
pub mod tree_connect;

pub use cancel::*;
pub use compressed::*;
pub use create::*;
pub use dfsc::*;
pub use echo::*;
pub use encrypted::*;
pub use error::*;
pub use file::*;
pub use header::*;
pub use info::*;
pub use ioctl::*;
pub use lock::*;
pub use message::*;
pub use negotiate::*;
pub use notify::*;
pub use oplock::*;
pub use plain::*;
pub use query_dir::*;
pub use session_setup::*;
pub use tree_connect::*;

#[cfg(test)]
mod test;
#[cfg(test)]
use test::*;

use thiserror::Error;
/// SMB Message related errors
#[derive(Error, Debug)]
pub enum SmbMsgError {
    #[error("Error code definition not found for NT Status code: {0:#x}")]
    MissingErrorCodeDefinition(u32),

    #[error("FSCTL definition not found for FSCTL code: {0:#x}")]
    MissingFsctlDefinition(u32),

    /// This error is returned when trying to get inner value of certain enum variant,
    /// but the actual variant is different.
    #[error("Unexpected content: {0} - expected {1}", actual, expected)]
    UnexpectedContent {
        actual: &'static str,
        expected: &'static str,
    },

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Invalid negotiate dialect cast to dialect: {0:?}")]
    InvalidDialect(NegotiateDialect),

    #[error("Binary read/write error: {0}")]
    BinRWError(#[from] binrw::Error),
}

type Result<T> = std::result::Result<T, SmbMsgError>;

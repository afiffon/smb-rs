//! MS-RPCE (DCE/RPC) types for RPC over SMB.
//!
//! In an optimal world, this file would have been generated
//! from IDLs.

pub mod interface;
pub mod ndr64;
pub mod pdu;
pub mod idl;

#[derive(thiserror::Error, Debug)]
pub enum SmbRpcError {
    #[error("Send/Receive provider error: {0}")]
    SendReceiveError(String),

    #[error("Invalid response data: {0}")]
    InvalidResponseData(&'static str),

    #[error("Failed to parse response data: {0}")]
    FailedToParseRpcResponse(binrw::Error),
}

type Result<T> = std::result::Result<T, SmbRpcError>;

//! Error response message

use binrw::prelude::*;

#[cfg(feature = "client")]
use binrw::io::TakeSeekExt;
use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::*;

/// The SMB2 ERROR Response packet is sent by the server to respond to a request
/// that has failed or encountered an error.
///
/// Reference: MS-SMB2 2.2.2
#[smb_response(size = 9)]
pub struct ErrorResponse {
    /// For SMB dialects other than 3.1.1, this must be set to 0.
    /// For SMB dialect 3.1.1, if nonzero, the ErrorData field is formatted as
    /// a variable-length array of SMB2 ERROR Context structures.
    #[bw(try_calc = error_data.len().try_into())]
    #[br(temp)]
    _error_context_count: u8,

    reserved: u8,

    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _byte_count: PosMarker<u32>,

    /// Variable-length data field that contains extended error information.
    /// For SMB 3.1.1 with nonzero ErrorContextCount, formatted as SMB2 ERROR Context structures.
    #[br(count = _error_context_count, map_stream = |s| s.take_seek(_byte_count.value.into()))]
    #[bw(write_with = PosMarker::write_size, args(&_byte_count))]
    pub error_data: Vec<ErrorResponseContext>,
}

/// For SMB dialect 3.1.1, error data is formatted as an array of SMB2 ERROR Context structures.
/// Each error context contains an identifier for the error context followed by the error data.
/// Each context must start at an 8-byte aligned boundary relative to the start of the SMB2 ERROR Response.
///
/// Reference: MS-SMB2 2.2.2.1
#[smb_response_binrw]
pub struct ErrorResponseContext {
    // each context item should be aligned to 8 bytes,
    // relative to the start of the error context.
    // luckily, it appears after the header, which is, itself, aligned to 8 bytes.
    #[brw(align_before = 8)]
    /// The length, in bytes, of the ErrorContextData field
    #[bw(try_calc = error_data.len().try_into())]
    _error_data_length: u32,
    /// An identifier for the error context
    pub error_id: ErrorId,
    /// Variable-length error data formatted according to the ErrorId
    #[br(count = _error_data_length)]
    pub error_data: Vec<u8>,
}

impl ErrorResponse {
    /// Locates a context by its ID,
    /// returning a reference to it if found.
    pub fn find_context(&self, id: ErrorId) -> Option<&ErrorResponseContext> {
        self.error_data.iter().find(|c| c.error_id == id)
    }
}

impl ErrorResponseContext {
    /// Interprets the error data as a u32, if possible.
    /// Returns an error if the data length is not 4 bytes.
    pub fn as_u32(&self) -> crate::Result<u32> {
        if self.error_data.len() == std::mem::size_of::<u32>() {
            Ok(u32::from_le_bytes(
                self.error_data.as_slice().try_into().unwrap(),
            ))
        } else {
            Err(crate::SmbMsgError::InvalidData(
                "Invalid error data length for u32".into(),
            ))
        }
    }

    /// Interprets the error data as a u64, if possible.
    /// Returns an error if the data length is not 8 bytes.
    pub fn as_u64(&self) -> crate::Result<u64> {
        if self.error_data.len() == std::mem::size_of::<u64>() {
            Ok(u64::from_le_bytes(
                self.error_data.as_slice().try_into().unwrap(),
            ))
        } else {
            Err(crate::SmbMsgError::InvalidData(
                "Invalid error data length for u64".into(),
            ))
        }
    }
}

/// An identifier for the error context in SMB2 ERROR Context structures.
///
/// Reference: MS-SMB2 2.2.2.1
#[smb_response_binrw]
#[brw(repr(u32))]
pub enum ErrorId {
    /// Unless otherwise specified, all errors defined in the MS-SMB2 protocol use this error ID
    Default = 0,
    /// The ErrorContextData field contains a share redirect message
    ShareRedirect = 0x72645253,
}

#[cfg(test)]
mod tests {
    use crate::*;

    test_response! {
        error_simple, Command::Cancel => Error { error_data: vec![], } => "0900000000000000"
    }

    // TODO(TEST): Add a test with added context items.
}

//! Error response message

use binrw::prelude::*;

use smb_dtyp::binrw_util::prelude::*;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,

    #[bw(try_calc = error_data.len().try_into())]
    _error_context_count: u8,

    #[bw(calc = 0)]
    _reserved: u8,

    #[bw(calc = PosMarker::default())]
    _byte_count: PosMarker<u32>,

    #[br(count = _error_context_count)]
    pub error_data: Vec<ErrorResponseContext>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ErrorResponseContext {
    // each context item should be aligned to 8 bytes,
    // relative to the start of the error context.
    // luckily, it appears after the header, which is, itself, aligned to 8 bytes.
    #[brw(align_before = 8)]
    #[bw(try_calc = error_data.len().try_into())]
    _error_data_length: u32,
    pub error_id: ErrorId,
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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum ErrorId {
    Default = 0,
    ShareRedirect = 0x72645253,
}

#[cfg(test)]
mod tests {
    use crate::*;

    test_response! {
        error_simple, Command::Cancel => Error { error_data: vec![], } => "0900000000000000"
    }
}

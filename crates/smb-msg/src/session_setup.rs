use binrw::prelude::*;
use modular_bitfield::prelude::*;

use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::{smb_request, smb_response};

#[smb_request(size = 25)]
pub struct SessionSetupRequest {
    pub flags: SetupRequestFlags,
    pub security_mode: SessionSecurityMode,
    pub capabilities: NegotiateCapabilities,
    #[bw(calc = 0)]
    _channel: u32, // reserved
    #[bw(calc = PosMarker::default())]
    __security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    security_buffer_length: u16,
    pub previous_session_id: u64,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&__security_buffer_offset))]
    pub buffer: Vec<u8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SessionSecurityMode {
    pub signing_enabled: bool,
    pub signing_required: bool,
    #[skip]
    __: B6,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SetupRequestFlags {
    pub binding: bool,
    #[skip]
    __: B7,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NegotiateCapabilities {
    pub dfs: bool,
    #[skip]
    __: B31,
}

impl SessionSetupRequest {
    pub fn new(
        buffer: Vec<u8>,
        security_mode: SessionSecurityMode,
        flags: SetupRequestFlags,
        capabilities: NegotiateCapabilities,
    ) -> SessionSetupRequest {
        SessionSetupRequest {
            flags,
            security_mode,
            capabilities,
            previous_session_id: 0,
            buffer,
        }
    }
}

#[smb_response(size = 9)]
pub struct SessionSetupResponse {
    pub session_flags: SessionFlags,
    #[bw(calc = PosMarker::default())]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    security_buffer_length: u16,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SessionFlags {
    pub is_guest: bool,
    pub is_null_session: bool,
    pub encrypt_data: bool,
    #[skip]
    __: B13,
}

impl SessionFlags {
    pub fn is_guest_or_null_session(&self) -> bool {
        self.is_guest() || self.is_null_session()
    }
}

#[smb_request(size = 4)]
#[derive(Default)]
pub struct LogoffRequest {
    #[bw(calc = 0)]
    _reserved: u16,
}

#[smb_response(size = 4)]
#[derive(Default)]
pub struct LogoffResponse {
    #[bw(calc = 0)]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use crate::*;

    use super::*;

    const SETUP_REQUEST_DATA: &'static str = "605706062b0601050502a04d304ba00e300c060a2b06010401823702020aa23904374e544c4d535350000100000097b208e2090009002e00000006000600280000000a005d580000000f41564956564d574f524b47524f5550";
    test_request! {
        SessionSetup {
            flags: SetupRequestFlags::new(),
            security_mode: SessionSecurityMode::new().with_signing_enabled(true),
            buffer: hex_to_u8_array! {SETUP_REQUEST_DATA},
            previous_session_id: 0,
            capabilities: NegotiateCapabilities::new().with_dfs(true),
        } => const_format::concatcp!("190000010100000000000000580059000000000000000000", SETUP_REQUEST_DATA)
    }

    const SETUP_RESPONSE_DATA: &'static str = "a181b03081ada0030a0101a10c060a2b06010401823702020aa281970481944e544c4d53535000020000000c000c003800000015c28ae2abf194bdb756daa9140001000000000050005000440000000a005d580000000f410056004900560056004d0002000c00410056004900560056004d0001000c00410056004900560056004d0004000c00410076006900760056006d0003000c00410076006900760056006d0007000800a876d878c569db0100000000";
    test_response! {
        SessionSetup {
            session_flags: SessionFlags::new(),
            buffer: hex_to_u8_array! {SETUP_RESPONSE_DATA}
        } => const_format::concatcp!("090000004800b300", SETUP_RESPONSE_DATA)
    }
}

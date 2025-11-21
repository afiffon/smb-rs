//! Session setup messages

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::*;

/// SMB2 SESSION_SETUP Request packet sent by the client to request a new
/// authenticated session within a new or existing SMB 2 Protocol transport connection.
///
/// MS-SMB2 2.2.5
#[smb_request(size = 25)]
pub struct SessionSetupRequest {
    /// Combination of flags for SMB 3.x dialect family
    pub flags: SetupRequestFlags,
    /// Security mode field specifying whether SMB signing is enabled or required
    pub security_mode: SessionSecurityMode,
    /// Protocol capabilities for the client
    pub capabilities: NegotiateCapabilities,
    /// Channel (reserved)
    reserved: u32,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    __security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    #[br(temp)]
    security_buffer_length: u16,
    /// Previously established session identifier for reconnection after network error
    pub previous_session_id: u64,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&__security_buffer_offset))]
    /// Security buffer containing authentication token
    pub buffer: Vec<u8>,
}

/// Security mode field specifying whether SMB signing is enabled or required at the client.
///
/// MS-SMB2 2.2.5
#[smb_dtyp::mbitfield]
pub struct SessionSecurityMode {
    /// Security signatures are enabled on the client (ignored by server)
    pub signing_enabled: bool,
    /// Security signatures are required by the client
    pub signing_required: bool,
    #[skip]
    __: B6,
}

/// Flags field for SESSION_SETUP request (SMB 3.x dialect family only).
///
/// MS-SMB2 2.2.5
#[smb_dtyp::mbitfield]
pub struct SetupRequestFlags {
    /// Request is to bind an existing session to a new connection
    pub binding: bool,
    #[skip]
    __: B7,
}

/// Protocol capabilities for the client.
///
/// MS-SMB2 2.2.5
#[smb_dtyp::mbitfield]
pub struct NegotiateCapabilities {
    /// Client supports the Distributed File System (DFS)
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

/// SMB2 SESSION_SETUP Response packet sent by the server in response to a SESSION_SETUP Request.
///
/// MS-SMB2 2.2.6
#[smb_response(size = 9)]
pub struct SessionSetupResponse {
    /// Flags indicating additional information about the session
    pub session_flags: SessionFlags,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(calc = u16::try_from(buffer.len()).unwrap())]
    #[br(temp)]
    security_buffer_length: u16,
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    /// Security buffer containing authentication token
    pub buffer: Vec<u8>,
}

/// Flags indicating additional information about the session.
///
/// MS-SMB2 2.2.6
#[smb_dtyp::mbitfield]
pub struct SessionFlags {
    /// Client has been authenticated as a guest user
    pub is_guest: bool,
    /// Client has been authenticated as an anonymous user
    pub is_null_session: bool,
    /// Server requires encryption of messages on this session (SMB 3.x only)
    pub encrypt_data: bool,
    #[skip]
    __: B13,
}

impl SessionFlags {
    pub fn is_guest_or_null_session(&self) -> bool {
        self.is_guest() || self.is_null_session()
    }
}

/// SMB2 LOGOFF Request packet sent by the client to request termination of a particular session.
///
/// MS-SMB2 2.2.7
#[smb_request(size = 4)]
#[derive(Default)]
pub struct LogoffRequest {
    reserved: u16,
}

/// SMB2 LOGOFF Response packet sent by the server in response to a LOGOFF Request.
///
/// MS-SMB2 2.2.8
#[smb_response(size = 4)]
#[derive(Default)]
pub struct LogoffResponse {
    reserved: u16,
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

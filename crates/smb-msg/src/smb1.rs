//! SMBv1 negotiation packet support.
//!
//! For multi-protocol negotiation only.

#[cfg(feature = "server")]
use binrw::io::TakeSeekExt;
use binrw::prelude::*;

use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::smb_request_binrw;

/// A (very) minimal SMB1 negotiation message,
///
/// See [`SMB1NegotiateMessage::default`] for a default message that
/// announces support for SMB2/3, as a part of multi-protocol negotiation.
#[smb_request_binrw]
#[brw(little)]
#[brw(magic(b"\xffSMB"))]
pub struct SMB1NegotiateMessage {
    #[bw(calc = 0x72)]
    #[br(assert(_command == 0x72))]
    #[br(temp)]
    _command: u8,
    status: u32,
    flags: u8,
    flags2: u16,
    #[bw(calc = 0)]
    #[br(assert(_pid_high == 0))]
    #[br(temp)]
    _pid_high: u16,
    security_features: [u8; 8],
    reserved: u16,
    #[bw(calc = 0xffff)]
    #[br(temp)]
    _tid: u16,
    #[bw(calc = 1)]
    #[br(assert(_pid_low == 1))]
    #[br(temp)]
    _pid_low: u16,
    /// uid
    reserved: u16,
    /// mid
    reserved: u16,
    // word count is always 0x0 according to MS-CIFS.
    #[bw(calc = 0)]
    #[br(assert(_word_count == 0))]
    #[br(temp)]
    _word_count: u8,
    byte_count: PosMarker<u16>,
    #[br(map_stream = |s| s.take_seek(byte_count.value.into()), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_size, args(byte_count))]
    dialects: Vec<Smb1Dialect>,
}

impl SMB1NegotiateMessage {
    /// Check if SMB2 is supported in the dialects list.
    pub fn is_smb2_supported(&self) -> bool {
        self.dialects
            .iter()
            .any(|d| d.name.to_string() == "SMB 2.002")
    }
}

impl Default for SMB1NegotiateMessage {
    fn default() -> Self {
        Self {
            status: 0,
            flags: 0x18,
            flags2: 0xc853,
            security_features: [0; 8],
            byte_count: PosMarker::default(),
            dialects: vec![
                Smb1Dialect {
                    name: binrw::NullString::from("NT LM 0.12"),
                },
                Smb1Dialect {
                    name: binrw::NullString::from("SMB 2.002"),
                },
                Smb1Dialect {
                    name: binrw::NullString::from("SMB 2.???"),
                },
            ],
        }
    }
}

/// SMB1 Dialect String
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone)]
#[brw(magic(b"\x02"))]
pub struct Smb1Dialect {
    name: binrw::NullString,
}

#[cfg(feature = "client")]
impl TryInto<Vec<u8>> for SMB1NegotiateMessage {
    type Error = binrw::Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = std::io::Cursor::new(Vec::new());
        self.write(&mut buf)?;
        Ok(buf.into_inner())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "client")]
    use super::*;
    #[cfg(feature = "client")]
    smb_tests::test_binrw_write! {
        SMB1NegotiateMessage: SMB1NegotiateMessage::default() =>
            "ff534d4272000000001853c8000000000000000000000000ffff010000000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00"
    }
}

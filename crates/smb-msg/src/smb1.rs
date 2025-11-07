//! SMBv1 negotiation packet support.
//!
//! For multi-protocol negotiation only.

use binrw::io::TakeSeekExt;
use binrw::prelude::*;

use smb_dtyp::binrw_util::prelude::*;

/// A (very) minimal SMB1 negotiation message,
///
/// See [`SMB1NegotiateMessage::default`] for a default message that
/// announces support for SMB2/3, as a part of multi-protocol negotiation.
#[binrw::binrw]
#[derive(Debug)]
#[brw(little)]
#[brw(magic(b"\xffSMB"))]
pub struct SMB1NegotiateMessage {
    #[bw(calc = 0x72)]
    #[br(assert(_command == 0x72))]
    _command: u8,
    status: u32,
    flags: u8,
    flags2: u16,
    #[bw(calc = 0)]
    #[br(assert(_pid_high == 0))]
    _pid_high: u16,
    security_features: [u8; 8],
    #[bw(calc = 0)]
    _reserved: u16,
    #[bw(calc = 0xffff)]
    _tid: u16,
    #[bw(calc = 1)]
    #[br(assert(_pid_low == 1))]
    _pid_low: u16,
    #[bw(calc = 0)]
    _uid: u16,
    #[bw(calc = 0)]
    _mid: u16,
    // word count is always 0x0 according to MS-CIFS.
    #[bw(calc = 0)]
    #[br(assert(_word_count == 0))]
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

#[derive(BinRead, BinWrite, Debug)]
#[brw(magic(b"\x02"))]
pub struct Smb1Dialect {
    name: binrw::NullString,
}

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
    use super::*;

    smb_tests::test_binrw_write! {
        SMB1NegotiateMessage: SMB1NegotiateMessage::default() =>
            "ff534d4272000000001853c8000000000000000000000000ffff010000000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00"
    }
}

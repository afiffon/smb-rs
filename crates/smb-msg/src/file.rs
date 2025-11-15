//! File-related messages: Flush, Read, Write.
#[cfg(feature = "client")]
use std::io::SeekFrom;

use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_msg_derive::*;

use super::FileId;
#[cfg(feature = "client")]
use super::header::Header;
use smb_dtyp::binrw_util::prelude::*;

#[smb_request(size = 24)]
pub struct FlushRequest {
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved1: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u32,
    pub file_id: FileId,
}

#[smb_response(size = 4)]
#[derive(Default)]
pub struct FlushResponse {
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,
}

#[smb_request(size = 49)]
pub struct ReadRequest {
    #[bw(calc = 0)]
    _padding: u8,
    pub flags: ReadFlags,
    pub length: u32,
    pub offset: u64,
    pub file_id: FileId,
    pub minimum_count: u32,
    // Currently, we do not have support for RDMA.
    // Therefore, all the related fields are set to zero.
    #[bw(calc = CommunicationChannel::None)]
    #[br(assert(channel == CommunicationChannel::None))]
    channel: CommunicationChannel,
    #[bw(calc = 0)]
    #[br(assert(_remaining_bytes == 0))]
    _remaining_bytes: u32,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_offset == 0))]
    _read_channel_info_offset: u16,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_length == 0))]
    _read_channel_info_length: u16,

    // Well, that's a little awkward, but since we never provide a blob, and yet,
    // Msft decided it makes sense to make the structure size 0x31, we need to add this padding.
    #[bw(calc = 0)]
    _pad_blob_placeholder: u8,
}

#[smb_response(size = 17)]
pub struct ReadResponse {
    // Sanity check: The offset is from the SMB header beginning.
    // it should be greater than the sum of the header and the response.
    // the STRUCT_SIZE includes the first byte of the buffer, so the offset is validated against a byte before that.
    #[br(assert(_data_offset.value as usize >= Header::STRUCT_SIZE + Self::STRUCT_SIZE - 1))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _data_offset: PosMarker<u8>,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u8,
    #[bw(try_calc = buffer.len().try_into())]
    #[br(assert(_data_length > 0))] // sanity
    _data_length: u32,
    #[bw(calc = 0)]
    #[br(assert(_data_remaining == 0))]
    _data_remaining: u32,

    // No RDMA support -- always zero, for both reserved and flags case:
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u32,

    #[br(seek_before = SeekFrom::Start(_data_offset.value as u64))]
    #[br(count = _data_length)]
    #[bw(assert(!buffer.is_empty()))] // sanity _data_length > 0 on write.
    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    pub buffer: Vec<u8>,
}

impl ReadResponse {
    pub const STRUCT_SIZE: usize = 17;
}

#[smb_dtyp::mbitfield]
pub struct ReadFlags {
    pub read_unbuffered: bool,
    pub read_compressed: bool,
    #[skip]
    __: B6,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum CommunicationChannel {
    None = 0,
    RdmaV1 = 1,
    RdmaV1Invalidate = 2,
}

/// Zero-copy write request.
///
///
/// i.e. the data is not included in the message, but is sent separately.
///
/// **note:** it is currently assumed that the data is sent immediately after the message.
#[smb_request(size = 49)]
#[allow(clippy::manual_non_exhaustive)]
pub struct WriteRequest {
    /// internal buffer offset in packet, relative to header.
    #[bw(calc = PosMarker::new(0))]
    #[br(temp)]
    _data_offset: PosMarker<u16>,

    /// Length of data to write.
    pub length: u32,
    /// Offset in file to write to.
    pub offset: u64,
    pub file_id: FileId,
    // Again, RDMA off, all 0.
    #[bw(calc = CommunicationChannel::None)]
    #[br(temp)]
    #[br(assert(channel == CommunicationChannel::None))]
    pub channel: CommunicationChannel,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(_remaining_bytes == 0))]
    _remaining_bytes: u32,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(_write_channel_info_offset == 0))]
    _write_channel_info_offset: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(_write_channel_info_length == 0))]
    _write_channel_info_length: u16,
    pub flags: WriteFlags,

    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    _write_offset: (),
}

impl WriteRequest {
    pub fn new(offset: u64, file_id: FileId, flags: WriteFlags, length: u32) -> Self {
        Self {
            length,
            offset,
            file_id,
            flags,
            _write_offset: (),
        }
    }
}

#[smb_response(size = 17)]
pub struct WriteResponse {
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,
    pub count: u32,
    #[bw(calc = 0)] // reserved
    #[br(assert(_remaining_bytes == 0))]
    _remaining_bytes: u32,
    #[bw(calc = 0)] // reserved
    #[br(assert(_write_channel_info_offset == 0))]
    _write_channel_info_offset: u16,
    #[bw(calc = 0)] // reserved
    #[br(assert(_write_channel_info_length == 0))]
    _write_channel_info_length: u16,
}

#[smb_dtyp::mbitfield]
pub struct WriteFlags {
    pub write_unbuffered: bool,
    pub write_through: bool,
    #[skip]
    __: B30,
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;
    use smb_tests::*;

    test_binrw! {
        struct FlushRequest {
            file_id: [
                0x14, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x51, 0x00, 0x10, 0x00, 0x0c, 0x00,
                0x00, 0x00,
            ]
            .into(),
        } => "1800000000000000140400000c000000510010000c000000"
    }

    test_binrw! {
        struct FlushResponse {  } => "04 00 00 00"
    }

    test_request! {
        Read {
            flags: ReadFlags::new(),
            length: 0x10203040,
            offset: 0x5060708090a0b0c,
            file_id: [
                0x03, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x00, 0x0c, 0x00,
                0x00, 0x00,
            ]
            .into(),
            minimum_count: 1,
        } => "31000000403020100c0b0a0908070605030300000c000000c50000000c0000000100000000000000000000000000000000"
    }

    test_response! {
        Read {
            buffer: b"bbbbbb".to_vec(),
        } => "11005000060000000000000000000000626262626262"
    }

    test_request! {
        Write {
            offset: 0x1234abcd,
            file_id: [
                0x14, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x51, 0x00, 0x10, 0x00, 0x0c, 0x00,
                0x00, 0x00,
            ]
            .into(),
            flags: WriteFlags::new(),
            length: "MeFriend!THIS IS FINE!".as_bytes().to_vec().len() as u32,
            _write_offset: (),
        } => "3100700016000000cdab341200000000140400000c000000510010000c00000000000000000000000000000000000000"
    }

    test_binrw! {
        struct WriteResponse { count: 0xbeefbaaf, } => "11000000afbaefbe0000000000000000"
    }
}

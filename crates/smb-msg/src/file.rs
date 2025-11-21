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

/// SMB2 FLUSH Request.
///
/// Used to flush cached file data to persistent storage.
///
/// Reference: MS-SMB2 2.2.17
#[smb_request(size = 24)]
pub struct FlushRequest {
    reserved: u16,
    reserved: u32,
    /// File identifier for the file to flush.
    pub file_id: FileId,
}

/// SMB2 FLUSH Response.
///
/// Sent by the server to confirm that data has been flushed.
///
/// Reference: MS-SMB2 2.2.18
#[smb_response(size = 4)]
#[derive(Default)]
pub struct FlushResponse {
    reserved: u16,
}

/// SMB2 READ Request.
///
/// Used to read data from a file or named pipe.
///
/// Reference: MS-SMB2 2.2.19
#[smb_request(size = 49)]
pub struct ReadRequest {
    #[bw(calc = 0)]
    #[br(temp)]
    _padding: u8,
    /// Read operation flags.
    pub flags: ReadFlags,
    /// Number of bytes to read.
    pub length: u32,
    /// Offset in the file to read from.
    pub offset: u64,
    /// File identifier for the file to read.
    pub file_id: FileId,
    /// Minimum number of bytes to read for the request to succeed.
    pub minimum_count: u32,
    #[bw(calc = CommunicationChannel::None)]
    #[br(assert(channel == CommunicationChannel::None))]
    #[br(temp)]
    channel: CommunicationChannel,
    #[bw(calc = 0)]
    #[br(assert(_remaining_bytes == 0))]
    #[br(temp)]
    _remaining_bytes: u32,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_offset == 0))]
    #[br(temp)]
    _read_channel_info_offset: u16,
    #[bw(calc = 0)]
    #[br(assert(_read_channel_info_length == 0))]
    #[br(temp)]
    _read_channel_info_length: u16,

    // Well, that's a little awkward, but since we never provide a blob, and yet,
    // Msft decided it makes sense to make the structure size 0x31, we need to add this padding.
    #[bw(calc = 0)]
    #[br(temp)]
    _pad_blob_placeholder: u8,
}

/// SMB2 READ Response.
///
/// Sent by the server with the data read from the file.
///
/// Reference: MS-SMB2 2.2.20
#[smb_response(size = 17)]
pub struct ReadResponse {
    #[br(assert(_data_offset.value as usize >= Header::STRUCT_SIZE + Self::STRUCT_SIZE - 1))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _data_offset: PosMarker<u8>,
    reserved: u8,
    #[bw(try_calc = buffer.len().try_into())]
    #[br(assert(_data_length > 0))]
    #[br(temp)]
    _data_length: u32,
    #[bw(calc = 0)]
    #[br(assert(_data_remaining == 0))]
    #[br(temp)]
    _data_remaining: u32,

    reserved: u32,

    /// Data read from the file.
    #[br(seek_before = SeekFrom::Start(_data_offset.value as u64))]
    #[br(count = _data_length)]
    #[bw(assert(!buffer.is_empty()))]
    #[bw(write_with = PosMarker::write_aoff, args(&_data_offset))]
    pub buffer: Vec<u8>,
}

impl ReadResponse {
    pub const STRUCT_SIZE: usize = 17;
}

/// Flags for read operations.
///
/// Reference: MS-SMB2 2.2.19
#[smb_dtyp::mbitfield]
pub struct ReadFlags {
    /// Bypass cache and read directly from disk.
    pub read_unbuffered: bool,
    /// Request compressed data.
    pub read_compressed: bool,
    #[skip]
    __: B6,
}

/// Communication channel types for SMB Direct.
///
/// Reference: MS-SMB2 2.2.19
#[smb_request_binrw]
#[brw(repr(u32))]
pub enum CommunicationChannel {
    /// No RDMA channel.
    None = 0,
    /// SMB Direct v1.
    RdmaV1 = 1,
    /// SMB Direct v1 with invalidate.
    RdmaV1Invalidate = 2,
}

/// SMB2 WRITE Request.
///
/// Used to write data to a file or named pipe.
///
/// Note: This is a zero-copy write where data is sent separately after the message.
///
/// Reference: MS-SMB2 2.2.21
#[smb_request(size = 49)]
#[allow(clippy::manual_non_exhaustive)]
pub struct WriteRequest {
    #[bw(calc = PosMarker::new(0))]
    #[br(temp)]
    _data_offset: PosMarker<u16>,

    /// Number of bytes to write.
    pub length: u32,
    /// Offset in the file to write to.
    pub offset: u64,
    /// File identifier for the file to write.
    pub file_id: FileId,
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
    /// Write operation flags.
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

/// SMB2 WRITE Response.
///
/// Sent by the server to confirm that data has been written.
///
/// Reference: MS-SMB2 2.2.22
#[smb_response(size = 17)]
pub struct WriteResponse {
    reserved: u16,

    /// Number of bytes written.
    pub count: u32,

    /// remaining_bytes
    reserved: u32,
    /// write_channel_info_offset
    reserved: u16,
    /// write_channel_info_length
    reserved: u16,
}

/// Flags for write operations.
///
/// Reference: MS-SMB2 2.2.21
#[smb_dtyp::mbitfield]
pub struct WriteFlags {
    /// Bypass cache and write directly to disk.
    pub write_unbuffered: bool,
    /// Ensure data is written to persistent storage before response.
    pub write_through: bool,
    #[skip]
    __: B30,
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    test_binrw_request! {
        struct FlushRequest {
            file_id: [
                0x14, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x51, 0x00, 0x10, 0x00, 0x0c, 0x00,
                0x00, 0x00,
            ]
            .into(),
        } => "1800000000000000140400000c000000510010000c000000"
    }

    test_binrw_response! {
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

    test_binrw_response! {
        struct WriteResponse { count: 0xbeefbaaf, } => "11000000afbaefbe0000000000000000"
    }
}

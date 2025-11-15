#![allow(unused_parens)]
#![allow(dead_code)] // not all structures' features are implemented yet.

//! SMB-Direct (SMBD) packets & structures
//!
//! [MS-SMBD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smbd/b25587c4-2507-47a4-aa89-e5d3f04f7197)

use binrw::prelude::*;
use modular_bitfield::prelude::*;
use std::mem::size_of;

use smb_msg::Status;

const SMBD_VERSION: u16 = 0x100; // SMBD v1.0

/// MS-SMBD 2.2.1
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SmbdNegotiateRequest {
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(min_version == SMBD_VERSION))]
    min_version: u16,
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(max_version == SMBD_VERSION))]
    max_version: u16,

    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,

    pub credits_requested: u16,
    pub preferred_send_size: u32,
    pub max_receive_size: u32,
    pub max_fragmented_size: u32,
}

impl SmbdNegotiateRequest {
    pub const ENCODED_SIZE: usize = size_of::<u16>() * 4 + size_of::<u32>() * 3;
}

/// MS-SMBD 2.2.2
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[brw(little)]
pub struct SmbdNegotiateResponse {
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(min_version == SMBD_VERSION))]
    min_version: u16,
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(max_version == SMBD_VERSION))]
    max_version: u16,
    #[bw(calc = SMBD_VERSION)]
    #[br(assert(negotiated_version == SMBD_VERSION))]
    negotiated_version: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,

    pub credits_requested: u16,
    pub credits_granted: u16,

    pub status: Status,

    pub max_read_write_size: u32,
    pub preferred_send_size: u32,
    pub max_receive_size: u32,
    pub max_fragmented_size: u32,
}

impl SmbdNegotiateResponse {
    pub const ENCODED_SIZE: usize = size_of::<u16>() * 6 + size_of::<u32>() * 5;
}

/// MS-SMBD 2.2.3
///
/// _Note:_ This is just the header of the data transfer.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct SmbdDataTransferHeader {
    pub credits_requested: u16,
    pub credits_granted: u16,
    pub flags: SmbdDataTransferFlags,

    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,

    pub remaining_data_length: u32,
    #[brw(assert(data_offset % Self::DATA_ALIGNMENT == 0))]
    pub data_offset: u32,
    pub data_length: u32,
}

impl SmbdDataTransferHeader {
    /// The required alignment of the data offset, in bytes.
    pub const DATA_ALIGNMENT: u32 = 8;
}

#[smb_dtyp::mbitfield]
pub struct SmbdDataTransferFlags {
    /// The peer is requested to promptly send a message in response. This value is used for keep alives.
    pub response_requested: bool,
    #[skip]
    __: B15,
}

/// MS-SMBD 2.2.3.1
///
/// Represents a registered RDMA buffer and is
/// used to Advertise the source and destination of RDMA Read and RDMA Write operations,
/// respectively. The upper layer optionally embeds one or more of these structures in its payload when
/// requesting RDMA direct placement of peer data via the protocol.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(little)]
pub struct BufferDescriptorV1 {
    /// The RDMA provider-specific offset, in bytes, identifying the first byte of data to be
    /// transferred to or from the registered buffer
    pub offset: u64,
    /// An RDMA provider-assigned Steering Tag for accessing the registered buffer.
    pub token: u32,
    /// The size, in bytes, of the data to be transferred to or from the registered buffer.
    pub length: u32,
}

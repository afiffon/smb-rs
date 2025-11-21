//! FSCTL codes and structs.
#[cfg(feature = "client")]
use binrw::io::TakeSeekExt;
use binrw::{NullWideString, prelude::*};
use modular_bitfield::prelude::*;
use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::{smb_message_binrw, smb_request_binrw, smb_response_binrw};

use crate::{Dialect, NegotiateSecurityMode};

use crate::dfsc::{ReqGetDfsReferral, ReqGetDfsReferralEx, RespGetDfsReferral};
use smb_dtyp::*;
use smb_fscc::*;

use super::common::IoctlRequestContent;
use crate::IoctlBuffer;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsctlCodes {
    DfsGetReferrals = 0x00060194,
    OffloadRead = 0x00094264,
    PipePeek = 0x0011400C,
    PipeWait = 0x00110018,
    PipeTransceive = 0x0011C017,
    SrvCopychunk = 0x001440F2,
    SrvEnumerateSnapshots = 0x00144064,
    SrvRequestResumeKey = 0x00140078,
    SrvReadHash = 0x001441bb,
    SrvCopychunkWrite = 0x001480F2,
    LmrRequestResiliency = 0x001401D4,
    QueryNetworkInterfaceInfo = 0x001401FC,
    SetReparsePoint = 0x000900A4,
    DfsGetReferralsEx = 0x000601B0,
    FileLevelTrim = 0x00098208,
    ValidateNegotiateInfo = 0x00140204,
    QueryAllocatedRanges = 0x000940CF,
}

/// Request packet for initiating a server-side copy of data.
/// Sent in an SMB2 IOCTL Request using FSCTL_SRV_COPYCHUNK or FSCTL_SRV_COPYCHUNK_WRITE.
///
/// Reference: MS-SMB2 2.2.31.1
#[smb_message_binrw]
pub struct SrvCopychunkCopy {
    /// A key representing the source file for the copy operation.
    /// Obtained from the server in a SRV_REQUEST_RESUME_KEY Response.
    pub source_key: [u8; SrvCopychunkCopy::SRV_KEY_LENGTH],
    /// The number of chunks of data that are to be copied.
    #[bw(try_calc = chunks.len().try_into())]
    chunk_count: u32,
    reserved: u32,
    /// An array of SRV_COPYCHUNK packets describing the ranges to be copied.
    /// The array length must equal chunk_count * size of SRV_COPYCHUNK.
    #[br(count = chunk_count)]
    pub chunks: Vec<SrvCopychunkItem>,
}

impl SrvCopychunkCopy {
    pub const SRV_KEY_LENGTH: usize = 24;
    pub const SIZE: usize = Self::SRV_KEY_LENGTH + 4 + 4;
}

/// Individual data range descriptor for server-side copy operations.
/// Sent in the chunks array of a SRV_COPYCHUNK_COPY packet to describe an individual data range to copy.
///
/// Reference: MS-SMB2 2.2.31.1.1
#[smb_message_binrw]
pub struct SrvCopychunkItem {
    /// The offset, in bytes, from the beginning of the source file to the location
    /// from which the data will be copied.
    pub source_offset: u64,
    /// The offset, in bytes, from the beginning of the destination file to where
    /// the data will be copied.
    pub target_offset: u64,
    /// The number of bytes of data to copy.
    pub length: u32,
    reserved: u32,
}

impl SrvCopychunkItem {
    pub const SIZE: usize = size_of::<u64>() * 2 + size_of::<u32>() * 2;
}

impl IoctlRequestContent for SrvCopychunkCopy {
    fn get_bin_size(&self) -> u32 {
        (Self::SIZE + self.chunks.len() * SrvCopychunkItem::SIZE) as u32
    }
}

/// Request packet for retrieving data from the Content Information File associated with a specified file.
/// Sent in an SMB2 IOCTL Request using FSCTL_SRV_READ_HASH.
/// The request is not valid for the SMB 2.0.2 dialect.
///
/// Reference: MS-SMB2 2.2.31.2
#[smb_request_binrw]
pub struct SrvReadHashReq {
    /// The hash type of the request indicating what the hash is used for.
    /// Must be set to SRV_HASH_TYPE_PEER_DIST for branch caching.
    #[bw(calc = 1)]
    #[br(assert(hash_type == 1))]
    pub hash_type: u32,
    /// The version number of the algorithm used to create the Content Information.
    /// Must be set to version 1 (branch cache version 1) or version 2 (branch cache version 2).
    /// Version 2 is only applicable for the SMB 3.x dialect family.
    #[br(assert((1..=2).contains(&hash_version)))]
    #[bw(assert((1..=2).contains(hash_version)))]
    pub hash_version: u32,
    /// Indicates the nature of the offset field and how it should be interpreted.
    pub hash_retrieval_type: SrvHashRetrievalType,
}

impl IoctlRequestContent for SrvReadHashReq {
    fn get_bin_size(&self) -> u32 {
        size_of::<u32>() as u32 * 3
    }
}

/// Enum specifying the nature of the offset field in SRV_READ_HASH requests.
/// Determines how the offset field should be interpreted for hash retrieval.
///
/// Reference: MS-SMB2 2.2.31.2
#[smb_request_binrw]
#[brw(repr(u32))]
pub enum SrvHashRetrievalType {
    /// The offset field in the SRV_READ_HASH request is relative to the beginning
    /// of the Content Information File.
    HashBased = 1,
    /// The offset field in the SRV_READ_HASH request is relative to the beginning
    /// of the file indicated by the FileId field in the IOCTL request.
    /// This value is only applicable for the SMB 3.x dialect family.
    FileBased = 2,
}

/// Request packet for requesting resiliency for a specified open file.
/// Sent in an SMB2 IOCTL Request using FSCTL_LMR_REQUEST_RESILIENCY.
/// This request is not valid for the SMB 2.0.2 dialect.
///
/// Reference: MS-SMB2 2.2.31.3
#[smb_request_binrw]
pub struct NetworkResiliencyRequest {
    /// The requested time the server holds the file open after a disconnect before releasing it.
    /// This time is in milliseconds.
    pub timeout: u32,
    reserved: u32,
}

impl IoctlRequestContent for NetworkResiliencyRequest {
    fn get_bin_size(&self) -> u32 {
        size_of::<u32>() as u32 * 2
    }
}

/// Request packet for validating a previous SMB 2 NEGOTIATE.
/// Used in FSCTL_VALIDATE_NEGOTIATE_INFO to ensure the negotiation was not tampered with.
/// Valid for clients and servers implementing SMB 3.0 and SMB 3.0.2 dialects.
///
/// Reference: MS-SMB2 2.2.31.4
#[smb_request_binrw]
pub struct ValidateNegotiateInfoRequest {
    /// The capabilities of the client.
    pub capabilities: u32,
    /// The ClientGuid of the client.
    pub guid: Guid,
    /// The security mode of the client.
    pub security_mode: NegotiateSecurityMode,
    /// The number of entries in the dialects field.
    #[bw(try_calc = dialects.len().try_into())]
    dialect_count: u16,
    /// The list of SMB2 dialects supported by the client.
    /// These entries should contain only the dialect values defined in the negotiate request.
    #[br(count = dialect_count)]
    pub dialects: Vec<Dialect>,
}

impl IoctlRequestContent for ValidateNegotiateInfoRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>()
            + Guid::GUID_SIZE
            + 2
            + size_of::<u16>()
            + self.dialects.len() * size_of::<u16>()) as u32
    }
}

/// Response packet containing snapshots associated with a share.
/// Returned by the server in an SMB2 IOCTL Response for FSCTL_SRV_ENUMERATE_SNAPSHOTS request.
/// Contains all revision timestamps associated with the Tree Connect share.
///
/// Reference: MS-SMB2 2.2.32.2
#[smb_response_binrw]
pub struct SrvSnapshotArray {
    /// The number of previous versions associated with the volume that backs this file.
    pub number_of_snap_shots: u32,
    /// The number of previous version timestamps returned in the snapshots array.
    /// If the output buffer could not accommodate the entire array, this will be zero.
    pub number_of_snap_shots_returned: u32,
    /// Position marker for the size of the snapshots array in bytes.
    /// If the output buffer is too small, this will be the amount of space the array would have occupied.
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    pub snap_shot_array_size: PosMarker<u32>,
    /// An array of timestamps in GMT format (@GMT token), separated by UNICODE null characters
    /// and terminated by two UNICODE null characters. Empty if the output buffer could not
    /// accommodate the entire array.
    #[br(parse_with = binrw::helpers::until_eof, map_stream = |s| s.take_seek(snap_shot_array_size.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&snap_shot_array_size))]
    pub snap_shots: Vec<NullWideString>,
}

#[cfg(all(feature = "client", not(feature = "server")))]
/// A trait that helps parsing FSCTL responses by matching the FSCTL code.
pub trait FsctlResponseContent: for<'a> BinRead<Args<'a> = ()> + std::fmt::Debug {
    const FSCTL_CODES: &'static [FsctlCodes];
}

#[cfg(all(feature = "server", not(feature = "client")))]
/// A trait that helps parsing FSCTL responses by matching the FSCTL code.
pub trait FsctlResponseContent: for<'a> BinWrite<Args<'a> = ()> + std::fmt::Debug {
    const FSCTL_CODES: &'static [FsctlCodes];
}

#[cfg(all(feature = "client", feature = "server"))]
/// A trait that helps parsing FSCTL responses by matching the FSCTL code.
pub trait FsctlResponseContent:
    for<'a> BinRead<Args<'a> = ()> + for<'b> BinWrite<Args<'b> = ()> + std::fmt::Debug
{
    const FSCTL_CODES: &'static [FsctlCodes];
}

macro_rules! impl_fsctl_response {
    ($code:ident, $type:ty) => {
        impl FsctlResponseContent for $type {
            const FSCTL_CODES: &'static [FsctlCodes] = &[FsctlCodes::$code];
        }
    };
}

/// Response packet containing a resume key for server-side copy operations.
/// Returned by the server in an SMB2 IOCTL Response for FSCTL_SRV_REQUEST_RESUME_KEY request.
/// The resume key can be used to uniquely identify the source file in subsequent copy operations.
///
/// Reference: MS-SMB2 2.2.32.3
#[smb_response_binrw]
pub struct SrvRequestResumeKey {
    /// A 24-byte resume key generated by the server that can be used by the client
    /// to uniquely identify the source file in FSCTL_SRV_COPYCHUNK or FSCTL_SRV_COPYCHUNK_WRITE requests.
    /// The resume key must be treated as an opaque structure.
    pub resume_key: [u8; SrvCopychunkCopy::SRV_KEY_LENGTH],
    /// The length, in bytes, of the context information. This field is unused.
    /// The server must set this field to zero, and the client must ignore it on receipt.
    /// TODO: What?!
    #[bw(calc = 0)]
    #[br(temp)]
    context_length: u32,
    /// The context extended information. This should always be set to empty according to the specification.
    #[br(count = context_length)]
    #[bw(assert(context.len() == context_length as usize))]
    pub context: Vec<u8>,
}

impl_fsctl_response!(SrvRequestResumeKey, SrvRequestResumeKey);

/// Response packet for server-side copy operations.
/// Returned by the server in an SMB2 IOCTL Response for FSCTL_SRV_COPYCHUNK or
/// FSCTL_SRV_COPYCHUNK_WRITE requests to provide the results of the copy operation.
///
/// Reference: MS-SMB2 2.2.32.1
#[smb_response_binrw]
pub struct SrvCopychunkResponse {
    /// For successful operations: the number of chunks that were successfully written.
    /// For STATUS_INVALID_PARAMETER: the maximum number of chunks the server will accept.
    pub chunks_written: u32,
    /// For successful operations: the number of bytes written in the last chunk that
    /// did not successfully process (if a partial write occurred).
    /// For STATUS_INVALID_PARAMETER: the maximum number of bytes the server will allow
    /// to be written in a single chunk.
    pub chunk_bytes_written: u32,
    /// For successful operations: the total number of bytes written in the server-side copy operation.
    /// For STATUS_INVALID_PARAMETER: the maximum number of bytes the server will accept
    /// to copy in a single request.
    pub total_bytes_written: u32,
}

impl_fsctl_response!(SrvCopychunk, SrvCopychunkResponse);

/// Response packet for SRV_READ_HASH requests.
/// Returned by the server in an SMB2 IOCTL Response for FSCTL_SRV_READ_HASH request.
/// The response is not valid for the SMB 2.0.2 dialect.
///
/// Reference: MS-SMB2 2.2.32.4
#[smb_response_binrw]
pub struct SrvReadHashRes {
    /// The hash type of the response. Must be set to SRV_HASH_TYPE_PEER_DIST for branch caching.
    #[bw(calc = 1)]
    #[br(assert(hash_type == 1))]
    hash_type: u32,
    /// The version number of the algorithm used to create the Content Information.
    /// Must be version 1 (branch cache version 1) or version 2 (branch cache version 2).
    #[br(assert((1..=2).contains(&hash_version)))]
    #[bw(assert((1..=2).contains(hash_version)))]
    hash_version: u32,
    /// The last change time of the source file.
    source_file_change_time: FileTime,
    /// The size of the source file in bytes.
    source_file_size: u64,
    /// Position marker for the length of the hash blob.
    hash_blob_length: PosMarker<u32>,
    /// Position marker for the offset of the hash blob.
    hash_blob_offset: PosMarker<u32>,
    /// Indicates whether the file has been modified since the Content Information was generated.
    dirty: u16,
    /// The length of the source file name in bytes.
    #[bw(try_calc = source_file_name.len().try_into())]
    source_file_name_length: u16,
    /// The name of the source file.
    #[br(count = source_file_name_length)]
    source_file_name: Vec<u8>,
}

impl_fsctl_response!(SrvReadHash, SrvReadHashRes);

/// Hash-based response format for SRV_READ_HASH when HashRetrievalType is SRV_HASH_RETRIEVE_HASH_BASED.
/// Contains a portion of the Content Information File retrieved from a specified offset.
///
/// Reference: MS-SMB2 2.2.32.4.2
#[smb_response_binrw]
pub struct SrvHashRetrieveHashBased {
    /// The offset, in bytes, from the beginning of the Content Information File
    /// to the portion retrieved. This equals the offset field in the SRV_READ_HASH request.
    pub offset: u64,
    /// The length, in bytes, of the retrieved portion of the Content Information File.
    #[bw(try_calc = blob.len().try_into())]
    buffer_length: u32,
    reserved: u32,
    /// A variable-length buffer that contains the retrieved portion of the Content Information File.
    /// TODO: Parse as Content Information File as specified in MS-PCCRC section 2.3.
    #[br(count = buffer_length)]
    blob: Vec<u8>,
}

impl_fsctl_response!(SrvReadHash, SrvHashRetrieveHashBased);

/// File-based response format for SRV_READ_HASH when HashRetrievalType is SRV_HASH_RETRIEVE_FILE_BASED.
/// Valid for servers implementing the SMB 3.x dialect family.
/// Contains hash information for a specified range of file data.
///
/// Reference: MS-SMB2 2.2.32.4.3
#[smb_response_binrw]
pub struct SrvHashRetrieveFileBased {
    /// File data offset corresponding to the start of the hash data returned.
    pub file_data_offset: u64,
    /// The length, in bytes, starting from the file_data_offset that is covered
    /// by the hash data returned.
    pub file_data_length: u64,
    /// The length, in bytes, of the retrieved portion of the Content Information File.
    #[bw(try_calc = buffer.len().try_into())]
    buffer_length: u32,
    reserved: u32,
    /// A variable-length buffer that contains the retrieved portion of the Content Information File.
    /// TODO: Parse as Content Information File as specified in MS-PCCRC section 2.4.
    #[br(count = buffer_length)]
    pub buffer: Vec<u8>,
}

pub type NetworkInterfacesInfo = ChainedItemList<NetworkInterfaceInfo>;

impl_fsctl_response!(QueryNetworkInterfaceInfo, NetworkInterfacesInfo);

/// Network interface information structure returned by FSCTL_QUERY_NETWORK_INTERFACE_INFO.
/// Contains details about a specific network interface on the server.
///
/// Reference: MS-SMB2 2.2.32.5
#[smb_response_binrw]
pub struct NetworkInterfaceInfo {
    /// The network interface index that specifies the network interface.
    pub if_index: u32,
    /// The capabilities of the network interface, including RSS and RDMA capability flags.
    pub capability: NetworkInterfaceCapability,
    reserved: u32,
    /// The speed of the network interface in bits per second.
    pub link_speed: u64,
    /// Socket address information describing the network interface address.
    /// Inlined sockaddr_storage for convenience and performance.
    pub sockaddr: SocketAddrStorage,
}

/// Capability flags for network interfaces indicating supported features.
/// Used in the NetworkInterfaceInfo structure to specify interface capabilities.
///
/// Reference: MS-SMB2 2.2.32.5
#[smb_dtyp::mbitfield]
pub struct NetworkInterfaceCapability {
    /// When set, specifies that the interface is RSS (Receive Side Scaling) capable.
    pub rss: bool,
    /// When set, specifies that the interface is RDMA (Remote Direct Memory Access) capable.
    pub rdma: bool,
    #[skip]
    __: B30,
}

#[smb_response_binrw]
pub enum SocketAddrStorage {
    V4(SocketAddrStorageV4),
    V6(SocketAddrStorageV6),
}

impl SocketAddrStorage {
    pub fn socket_addr(&self) -> SocketAddr {
        match self {
            SocketAddrStorage::V4(v4) => SocketAddr::V4(v4.to_addr()),
            SocketAddrStorage::V6(v6) => SocketAddr::V6(v6.to_addr()),
        }
    }
}

#[smb_response_binrw]
#[brw(magic(b"\x02\x00"))] // InterNetwork
pub struct SocketAddrStorageV4 {
    pub port: u16,
    pub address: u32,
    reserved: [u8; 128 - (2 + 2 + 4)],
}

impl SocketAddrStorageV4 {
    fn to_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(self.address.to_be()), self.port)
    }
}

#[smb_response_binrw]
#[brw(magic(b"\x17\x00"))] // InterNetworkV6
pub struct SocketAddrStorageV6 {
    pub port: u16,
    pub flow_info: u32,
    pub address: u128,
    pub scope_id: u32,
    reserved: [u8; 128 - (2 + 2 + 4 + 16 + 4)],
}

impl SocketAddrStorageV6 {
    fn to_addr(&self) -> SocketAddrV6 {
        SocketAddrV6::new(
            Ipv6Addr::from(self.address.to_be()),
            self.port,
            self.flow_info,
            self.scope_id,
        )
    }
}

/// Response for validating a previous SMB 2 NEGOTIATE.
/// Returned in an SMB2 IOCTL response for FSCTL_VALIDATE_NEGOTIATE_INFO request.
/// Valid for servers implementing the SMB 3.x dialect family, optional for others.
///
/// Reference: MS-SMB2 2.2.32.6
#[smb_response_binrw]
pub struct ValidateNegotiateInfoResponse {
    /// The capabilities of the server.
    pub capabilities: u32,
    /// The ServerGuid of the server.
    pub guid: Guid,
    /// The security mode of the server.
    pub security_mode: NegotiateSecurityMode,
    /// The SMB2 dialect in use by the server on the connection.
    pub dialect: Dialect,
}

impl_fsctl_response!(ValidateNegotiateInfo, ValidateNegotiateInfoResponse);

// DFS get referrals FSCTLs.
impl FsctlResponseContent for RespGetDfsReferral {
    const FSCTL_CODES: &'static [FsctlCodes] =
        &[FsctlCodes::DfsGetReferrals, FsctlCodes::DfsGetReferralsEx];
}

impl IoctlRequestContent for ReqGetDfsReferral {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u16>() + (self.request_file_name.len() + 1) * size_of::<u16>()) as u32
    }
}

impl IoctlRequestContent for ReqGetDfsReferralEx {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u16>() * 2 + size_of::<u32>() + self.request_data.get_bin_size()) as u32
    }
}

#[smb_message_binrw] // used as request, but also used in the response
#[derive(Default)]
pub struct QueryAllocRangesItem {
    pub offset: u64,
    pub len: u64,
}

impl IoctlRequestContent for QueryAllocRangesItem {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u64>() * 2) as u32
    }
}

#[smb_response_binrw]
#[derive(Default)]
pub struct QueryAllocRangesResult {
    #[br(parse_with = binrw::helpers::until_eof)]
    values: Vec<QueryAllocRangesItem>,
}

impl Deref for QueryAllocRangesResult {
    type Target = Vec<QueryAllocRangesItem>;
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl From<Vec<QueryAllocRangesItem>> for QueryAllocRangesResult {
    fn from(value: Vec<QueryAllocRangesItem>) -> Self {
        Self { values: value }
    }
}

impl_fsctl_response!(QueryAllocatedRanges, QueryAllocRangesResult);

/// The FSCTL_PIPE_WAIT Request requests that the server wait until either a time-out interval elapses,
/// or an instance of the specified named pipe is available for connection.
///
/// [MS-FSCC 2.3.49](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/f030a3b9-539c-4c7b-a893-86b795b9b711)
#[smb_request_binrw]
pub struct PipeWaitRequest {
    /// specifies the maximum amount of time, in units of 100 milliseconds,
    /// that the function can wait for an instance of the named pipe to be available.
    pub timeout: u64,
    #[bw(calc = name.size() as u32)]
    #[br(temp)]
    name_length: u32,
    /// Whether the Timeout parameter will be ignored.
    /// FALSE Indicates that the server MUST wait forever. Any value in `timeout` must be ignored.
    pub timeout_specified: Boolean,
    /// Reserved (padding)
    reserved: u8,
    /// A Unicode string that contains the name of the named pipe. Name MUST not include the "\pipe\",
    /// so if the operation was on \\server\pipe\pipename, the name would be "pipename".
    #[br(args {size: SizedStringSize::bytes(name_length)})]
    pub name: SizedWideString,
}

impl IoctlRequestContent for PipeWaitRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u64>()
            + size_of::<u32>()
            + size_of::<Boolean>()
            + size_of::<u8>()
            + self.name.size() as usize) as u32
    }
}

/// Stores data for a reparse point.
///
/// [MS-FSCC 2.3.81](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4dc2b168-f177-4eec-a14b-25a51cbba2cf)
#[smb_request_binrw]
pub struct SetReparsePointRequest {
    /// Contains the reparse point tag that uniquely identifies the owner of the reparse point.
    #[bw(assert((reparse_tag & 0x80000000 == 0) == reparse_guid.is_some()))]
    pub reparse_tag: u32,
    #[bw(calc = reparse_data.len() as u32)]
    reparse_data_length: u32,
    /// Applicable only for reparse points that have a GUID.
    /// See [MS-FSCC 2.1.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/a4d08374-0e92-43e2-8f88-88b94112f070)
    // Internal note: (HighBit(arseTag) == 0)Has
    #[br(if(reparse_tag & 0x80000000 == 0))]
    pub reparse_guid: Option<Guid>,
    /// Reparse-specific data for the reparse point
    #[br(count = reparse_data_length)]
    pub reparse_data: Vec<u8>,
}

impl IoctlRequestContent for SetReparsePointRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>()
            + size_of::<u32>()
            + self.reparse_guid.as_ref().map_or(0, |_| size_of::<Guid>())
            + self.reparse_data.len()) as u32
    }
}

#[smb_request_binrw]
pub struct FileLevelTrimRequest {
    /// Key - reserved
    reserved: u32,
    #[bw(calc = ranges.len() as u32)]
    num_ranges: u32,
    /// Array of ranges that describe the portions of the file that are to be trimmed.
    #[br(count = num_ranges)]
    pub ranges: Vec<FileLevelTrimRange>,
}

/// [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-file_level_trim_range)
///
/// Supports [`std::mem::size_of`].
#[smb_request_binrw]
pub struct FileLevelTrimRange {
    /// Offset, in bytes, from the start of the file for the range to be trimmed.
    pub offset: u64,
    /// Length, in bytes, for the range to be trimmed.
    pub length: u64,
}

impl IoctlRequestContent for FileLevelTrimRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>() + size_of::<u32>() + self.ranges.len() * size_of::<FileLevelTrimRange>())
            as u32
    }
}

/// [MS-FSCC 2.3.46](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6b6c8b8b-c5ac-4fa5-9182-619459fce7c7)
#[smb_response_binrw]
pub struct PipePeekResponse {
    /// The current state of the pipe
    pub named_pipe_state: NamedPipeState,
    #[bw(calc = data.len() as u32)]
    /// The size, in bytes, of the data available to read from the pipe.
    read_data_available: u32,
    /// Specifies the number of messages available in the pipe if the pipe has been created as a message-type pipe. Otherwise, this field is 0
    pub number_of_messages: u32,
    /// Specifies the length of the first message available in the pipe if the pipe has been created as a message-type pipe. Otherwise, this field is 0.
    pub message_length: u32,
    /// The data from the pipe.
    #[br(count = read_data_available as u64)]
    pub data: Vec<u8>,
}

impl_fsctl_response!(PipePeek, PipePeekResponse);

/// [MS-SMB 2.2.7.2.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/5a43eb29-50c8-46b6-8319-e793a11f6226)
#[smb_response_binrw]
pub struct SrvEnumerateSnapshotsResponse {
    /// The number of snapshots that the underlying object store contains of this file.
    pub number_of_snap_shots: u32,
    /// This value MUST be the number of snapshots that are returned in this response.
    /// If this value is less than NumberofSnapshots,
    /// then there are more snapshots than were able to fit in this response.
    pub number_of_snap_shots_returned: u32,
    /// The length, in bytes, of the SnapShotMultiSZ field.
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    snap_shot_array_size: PosMarker<u32>,
    /// A list of snapshots, described as strings, that take on the following form: @GMT-YYYY.MM.DD-HH.MM.SS
    #[br(map_stream = |s| s.take_seek(snap_shot_array_size.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&snap_shot_array_size))]
    pub snap_shots: MultiWSz,
}

impl_fsctl_response!(SrvEnumerateSnapshots, SrvEnumerateSnapshotsResponse);

/// [MS-FSCC 2.3.14](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b949a580-d8db-439b-a791-17ddc7565c4b)
#[smb_response_binrw]
pub struct FileLevelTrimResponse {
    /// The number of input ranges that were processed.
    pub num_ranges_processed: u32,
}

impl_fsctl_response!(FileLevelTrim, FileLevelTrimResponse);

/// [MS-FSCC 2.3.41](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5d41cf62-9ebc-4f62-b7d7-0d085552b6dd)
#[smb_request_binrw]
pub struct OffloadReadRequest {
    #[bw(calc = 0x20)]
    #[br(assert(_size == 0x20))]
    #[br(temp)]
    _size: u32,
    /// The flags to be set for this operation. Currently, no flags are defined.
    pub flags: u32,
    /// Time to Live (TTL) value in milliseconds for the generated Token. A value of 0 indicates a default TTL interval.
    pub token_time_to_live: u32,
    reserved: u32,
    /// the file offset, in bytes, of the start of a range of bytes in a file from which to generate the Token.
    /// MUST be aligned to a logical sector boundary on the volume.
    pub file_offset: u64,
    /// the requested range of the file from which to generate the Token.
    /// MUST be aligned to a logical sector boundary on the volume
    pub copy_length: u64,
}

impl IoctlRequestContent for OffloadReadRequest {
    fn get_bin_size(&self) -> u32 {
        (size_of::<u32>() * 4 + size_of::<u64>() * 2) as u32
    }
}

/// [MS-FSCC 2.3.42](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b98a8325-e6ec-464a-bc1b-8216b74f5828)
#[smb_response_binrw]
pub struct OffloadReadResponse {
    #[bw(calc = 528)]
    #[br(assert(_size == 528))]
    _size: u32,

    // Note: this is a reduction of the flags field.
    /// The data beyond the current range is logically equivalent to zero.
    pub all_zero_beyond_current_range: Boolean,
    _padding: u8,
    _padding2: u16,

    /// contains the amount, in bytes, of data that the Token logically represents.
    /// This value indicates a contiguous region of the file from the beginning of the requested offset in the input.
    /// This value can be smaller than the CopyLength field specified in the request data element,
    /// which indicates that less data was logically represented (logically read) with the Token than was requested.
    pub transfer_length: u64,

    /// The generated Token to be used as a representation of the data contained within the portion of the file specified in the input request.
    /// The contents of this field MUST NOT be modified during subsequent operations.
    pub token: [u8; 512], // TODO: Parse as STORAGE_OFFLOAD_TOKEN
}

impl_fsctl_response!(OffloadRead, OffloadReadResponse);

/// This macro wraps an existing type into a newtype that implements the `IoctlRequestContent` trait.
/// It also provides a constructor and implements `From` and `Deref` traits for the new type.
///
/// It's made so we can easily create new types for ioctl requests without repeating boilerplate code,
/// and prevents collisions with existing types in the `IoctlReqData` enum.
macro_rules! make_newtype {
    ($attr_type:ident $vis:vis $name:ident($inner:ty)) => {
        #[$attr_type]
        pub struct $name(pub $inner);

        impl $name {
            pub fn new(inner: $inner) -> Self {
                Self(inner)
            }
        }

        impl From<$inner> for $name {
            fn from(inner: $inner) -> Self {
                Self(inner)
            }
        }

        impl Deref for $name {
            type Target = $inner;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

macro_rules! make_req_newtype {
    ($vis:vis $name:ident($inner:ty)) => {
        make_newtype!(smb_request_binrw $vis $name($inner));
        impl IoctlRequestContent for $name {
            fn get_bin_size(&self) -> u32 {
                self.0.get_bin_size()
            }
        }
    }
}

macro_rules! make_res_newtype {
    ($fsctl:ident: $vis:vis $name:ident($inner:ty)) => {
        make_newtype!(smb_response_binrw $vis $name($inner));
        impl FsctlResponseContent for $name {
            const FSCTL_CODES: &'static [FsctlCodes] = &[FsctlCodes::$fsctl];
        }
    }
}

make_req_newtype!(pub PipePeekRequest(()));
make_req_newtype!(pub SrvEnumerateSnapshotsRequest(()));
make_req_newtype!(pub SrvRequestResumeKeyRequest(()));
make_req_newtype!(pub QueryNetworkInterfaceInfoRequest(()));
make_req_newtype!(pub PipeTransceiveRequest(IoctlBuffer));
make_req_newtype!(pub SrvCopyChunkCopyWrite(SrvCopychunkCopy));

make_res_newtype!(
    PipeWait: pub PipeWaitResponse(())
);
make_res_newtype!(
    PipeTransceive: pub PipeTransceiveResponse(IoctlBuffer)
);
make_res_newtype!(
    SetReparsePoint: pub SetReparsePointResponse(())
);

make_res_newtype!(
    LmrRequestResiliency: pub LmrRequestResiliencyResponse(())
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    test_binrw_request! {
        struct OffloadReadRequest {
            flags: 0,
            token_time_to_live: 0,
            file_offset: 0,
            copy_length: 10485760,
        } => "2000000000000000000000000000000000000000000000000000a00000000000"
    }

    test_binrw_response! {
        struct SrvRequestResumeKey {
            resume_key: [
                0x2d, 0x3, 0x0, 0x0, 0x1c, 0x0, 0x0, 0x0, 0x27, 0x11, 0x6a, 0x26, 0x30, 0xd2,
                0xdb, 0x1, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
            ],
            context: vec![],
        } => "2d0300001c00000027116a2630d2db01fffe00000000000000000000"
    }

    const CHUNK_SIZE: u32 = 1 << 20; // 1 MiB
    const TOTAL_SIZE: u32 = 10417096;
    const BLOCK_NUM: u32 = (TOTAL_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE;

    test_binrw_request! {
        struct SrvCopychunkCopy {
            source_key: [
                0x2d, 0x3, 0x0, 0x0, 0x1c, 0x0, 0x0, 0x0, 0x27, 0x11, 0x6a, 0x26, 0x30, 0xd2, 0xdb,
                0x1, 0xff, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ],
            chunks: (0..BLOCK_NUM).map(|i| SrvCopychunkItem {
                source_offset: (i * CHUNK_SIZE) as u64,
                target_offset: (i * CHUNK_SIZE) as u64,
                length: if i == BLOCK_NUM - 1 {
                    TOTAL_SIZE % CHUNK_SIZE
                } else {
                    CHUNK_SIZE
                },
            }).collect(),
        } => "2d0300001c00000027116a2630d2db01fffe0000000000000a000000000000000
        00000000000000000000000000000000000100000000000000010000000000000001000
        00000000000010000000000000002000000000000000200000000000000010000000000
        00000300000000000000030000000000000001000000000000000400000000000000040
        00000000000000100000000000000050000000000000005000000000000000100000000
        00000006000000000000000600000000000000010000000000000007000000000000000
        70000000000000001000000000000000800000000000000080000000000000001000000
        0000000009000000000000000900000000000c8f30e0000000000"
    }

    test_binrw_response! {
        struct SrvCopychunkResponse {
            chunks_written: 10,
            chunk_bytes_written: 0,
            total_bytes_written: 10417096,
        } => "0a00000000000000c8f39e00"
    }

    test_binrw_response! {
        struct QueryAllocRangesResult {
            values: vec![
                QueryAllocRangesItem {
                    offset: 0,
                    len: 4096,
                },
                QueryAllocRangesItem {
                    offset: 8192,
                    len: 46801,
                },
            ],
        } => "000000000000000000100000000000000020000000000000d1b6000000000000"
    }

    test_binrw_response! {
        NetworkInterfacesInfo: NetworkInterfacesInfo::from(vec![
                NetworkInterfaceInfo {
                    if_index: 2,
                    capability: NetworkInterfaceCapability::new().with_rdma(true),
                    link_speed: 1000000000,
                    sockaddr: SocketAddrStorage::V4(SocketAddrStorageV4 {
                        port: 0,
                        address: 0xac10cc84u32.to_be(),
                    })
                },
                NetworkInterfaceInfo {
                    if_index: 2,
                    capability: NetworkInterfaceCapability::new().with_rdma(true),
                    link_speed: 1000000000,
                    sockaddr: SocketAddrStorage::V6(SocketAddrStorageV6 {
                        port: 0,
                        flow_info: 0,
                        address: 0xfe80000000000000020c29fffe9f8bf3u128.to_be(),
                        scope_id: 0,
                    })
                },
            ]) => "9800000002000000020000000000000000ca9a3b0000000002000000ac10cc8400000000000000
            0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000020000000200000000000
            00000ca9a3b000000001700000000000000fe80000000000000020c29fffe9f8bf3000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000000000000000000000000
            00000000000000000000"
    }

    // TODO(TEST): Add missing tests. Consider testing size calc as well.
}

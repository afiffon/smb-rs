//! Tree (share) connect & disconnect messages

use binrw::prelude::*;
use binrw::{NullWideString, io::TakeSeekExt};
use modular_bitfield::prelude::*;
use smb_dtyp::{
    binrw_util::prelude::*,
    security::{ACL, ClaimSecurityAttributeRelativeV1, SID},
};

/// Flags for SMB2 TREE_CONNECT Request
///
/// Reference: MS-SMB2 2.2.9
#[smb_dtyp::mbitfield]
pub struct TreeConnectRequestFlags {
    /// Client has previously connected to the specified cluster share using the SMB dialect of the connection
    pub cluster_reconnect: bool,
    /// Client can handle synchronous share redirects via a Share Redirect error context response
    pub redirect_to_owner: bool,
    /// Tree connect request extension is present, starting at the Buffer field
    pub extension_present: bool,
    #[skip]
    __: B13,
}

/// SMB2 TREE_CONNECT Request
///
/// Sent by a client to request access to a particular share on the server.
/// Supports both the base and extension variants.
/// - On read, uses extension iff `flags.extension_present()` - parses just like the server intends.
/// - On write, uses extension iff `tree_connect_contexts` is non-empty.
///
/// Reference: MS-SMB2 2.2.9
#[smb_request(size = 9)]
pub struct TreeConnectRequest {
    /// Flags indicating how to process the operation
    pub flags: TreeConnectRequestFlags,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _path_offset: PosMarker<u16>,
    #[bw(try_calc = buffer.size().try_into())]
    #[br(temp)]
    path_length: u16,

    // -- Extension --
    #[br(if(flags.extension_present()))]
    #[br(temp)]
    #[bw(calc = if tree_connect_contexts.is_empty() { None } else { Some(PosMarker::default()) })]
    tree_connect_context_offset: Option<PosMarker<u32>>,

    #[br(if(flags.extension_present()))]
    #[bw(if(!tree_connect_contexts.is_empty()))]
    #[bw(calc = if tree_connect_contexts.is_empty() { None } else { Some(tree_connect_contexts.len().try_into().unwrap()) })]
    #[br(temp)]
    tree_connect_context_count: Option<u16>,

    #[br(if(flags.extension_present()))]
    #[bw(if(!tree_connect_contexts.is_empty()))]
    #[bw(calc = Some([0u8; 10]))]
    #[br(temp)]
    _reserved: Option<[u8; 10]>,
    // -- Extension End --
    // ------------------------------------------------
    // -- Base --
    #[brw(little)]
    #[br(args { size: SizedStringSize::bytes16(path_length) })]
    #[bw(write_with = PosMarker::write_aoff, args(&_path_offset))]
    /// Full share path name in Unicode format "\\server\share"
    pub buffer: SizedWideString,

    // -- Extension --
    #[br(if(flags.extension_present()))]
    #[br(seek_before = tree_connect_context_offset.unwrap().seek_relative(true))]
    #[br(count = tree_connect_context_count.unwrap_or(0))]
    #[bw(if(!tree_connect_contexts.is_empty()))]
    #[bw(write_with = PosMarker::write_aoff_m, args(tree_connect_context_offset.as_ref()))]
    tree_connect_contexts: Vec<TreeConnectContext>,
}

/// SMB2 TREE_CONNECT_CONTEXT Request structure
///
/// Used to encode additional properties in SMB2 TREE_CONNECT requests and responses.
///
/// Reference: MS-SMB2 2.2.9.2
#[smb_request_binrw]
pub struct TreeConnectContext {
    /// Type of context in the Data field
    #[bw(calc = 1)]
    #[br(assert(context_type == 1))]
    context_type: u16,
    /// Length in bytes of the Data field
    data_length: u16,
    reserved: u32,
    data: RemotedIdentityTreeConnect,
}

macro_rules! make_remoted_identity_connect{
    (
        $($field:ident: $value:ty),*
    ) => {
        pastey::paste! {

#[binwrite]
#[derive(Debug, BinRead, PartialEq, Eq)]
/// SMB2_REMOTED_IDENTITY_TREE_CONNECT Context
///
/// Contains remoted identity tree connect context data with user information,
/// groups, privileges, and other security attributes.
///
/// Reference: MS-SMB2 2.2.9.2.1
pub struct RemotedIdentityTreeConnect {
    #[bw(calc = PosMarker::new(1))]
    #[br(assert(_ticket_type.value == 1))]
    _ticket_type: PosMarker<u16>,
    /// Total size of this structure
    ticket_size: u16,

    // Offsets
    $(
        #[bw(calc = PosMarker::default())]
        #[br(temp)]
        [<_$field _offset>]: PosMarker<u16>,
    )*

    // Values
    $(
        #[br(seek_before = _ticket_type.seek_from([<_$field _offset>].value as u64))]
        #[bw(write_with = PosMarker::write_roff_b, args(&[<_$field _offset>], &_ticket_type))]
        $field: $value,
    )*
}
        }
    }
}

make_remoted_identity_connect! {
    user: SidAttrData,
    user_name: NullWideString,
    domain: NullWideString,
    groups: SidArrayData,
    restricted_groups: SidArrayData,
    privileges: PrivilegeArrayData,
    primary_group: SidArrayData,
    owner: BlobData<SID>,
    default_dacl: BlobData<ACL>,
    device_groups: SidArrayData,
    user_claims: BlobData<ClaimSecurityAttributeRelativeV1>,
    device_claims: BlobData<ClaimSecurityAttributeRelativeV1>
}

/// BLOB_DATA structure containing variable-length binary data
///
/// Reference: MS-SMB2 2.2.9.2.1.1
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct BlobData<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    /// Size of the blob data
    blob_size: PosMarker<u16>,
    #[br(map_stream = |s| s.take_seek(blob_size.value as u64))]
    pub blob_data: T,
}

/// Array data structure for variable-length arrays
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ArrayData<T>
where
    T: BinRead + BinWrite + 'static,
    for<'a> <T as BinRead>::Args<'a>: Default + Clone,
    for<'b> <T as BinWrite>::Args<'b>: Default + Clone,
{
    #[bw(try_calc = list.len().try_into())]
    lcount: u16,
    #[br(count = lcount)]
    pub list: Vec<T>,
}

/// SID_ATTR_DATA structure containing SID and attributes
///
/// Reference: MS-SMB2 2.2.9.2.1.2
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SidAttrData {
    /// Security identifier
    pub sid_data: SID,
    /// Attributes associated with the SID
    pub attr: SidAttrSeGroup,
}

type SidArrayData = ArrayData<SidAttrData>;

/// SE_GROUP attributes for SID
///
/// Reference: MS-SMB2 2.2.9.2.1.2
#[smb_dtyp::mbitfield]
pub struct SidAttrSeGroup {
    /// This SID is mandatory
    pub mandatory: bool,
    /// This SID is enabled by default
    pub enabled_by_default: bool,
    /// This SID is enabled for access checks
    pub group_enabled: bool,
    /// This SID is the owner SID for objects created by this user
    pub group_owner: bool,
    /// This SID cannot be disabled
    pub group_use_for_deny_only: bool,
    /// This SID identifies an integrity level
    pub group_integrity: bool,
    /// This SID is integrity-enabled
    pub group_integrity_enabled: bool,
    #[skip]
    __: B21,
    /// Identifies the logon session
    pub group_logon_id: B4,
}

/// LUID_ATTR_DATA structure containing LUID and attributes
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct LuidAttrData {
    /// Locally unique identifier
    pub luid: u64,
    /// Attributes for the LUID
    pub attr: LsaprLuidAttributes,
}

mod lsapr_luid_attributes {
    use super::*;
    /// LSAPR_LUID_ATTRIBUTES structure
    ///
    /// Reference: MS-LSAD 2.2.5.4
    #[smb_dtyp::mbitfield]
    pub struct LsaprLuidAttributes {
        /// Default privilege that is enabled by default
        pub is_default: bool,
        /// Privilege is enabled
        pub is_enabled: bool,
        #[skip]
        __: B30,
    }
}

use lsapr_luid_attributes::LsaprLuidAttributes;
use smb_msg_derive::*;

type PrivilegeData = BlobData<LuidAttrData>;

type PrivilegeArrayData = ArrayData<PrivilegeData>;

impl TreeConnectRequest {
    pub fn new(name: &str) -> TreeConnectRequest {
        TreeConnectRequest {
            flags: TreeConnectRequestFlags::new(),
            buffer: name.into(),
            tree_connect_contexts: vec![],
        }
    }
}

/// SMB2 TREE_CONNECT Response
///
/// Sent by the server when an SMB2 TREE_CONNECT request is processed successfully.
///
/// Reference: MS-SMB2 2.2.10
#[smb_response(size = 16)]
pub struct TreeConnectResponse {
    /// Type of share being accessed
    pub share_type: ShareType,
    reserved: u8,
    /// Properties for this share
    pub share_flags: ShareFlags,
    /// Capabilities for this share
    pub capabilities: TreeCapabilities,
    /// Maximal access for the user that establishes the tree connect on the share
    pub maximal_access: u32,
}

/// Share caching mode for offline file access
#[derive(BitfieldSpecifier, Debug, Clone, Copy)]
#[bits = 4]
pub enum ShareCacheMode {
    /// Manual caching - client can cache files explicitly selected by user
    Manual,
    /// Automatic caching - client can automatically cache files used by user
    Auto,
    /// VDO caching - client can use cached files even when share is available
    Vdo,
    /// No caching - offline caching must not occur
    NoCache,
    All = 0xf,
}

/// Share flags indicating various share properties
///
/// Reference: MS-SMB2 2.2.10
#[smb_dtyp::mbitfield]
pub struct ShareFlags {
    /// Share is present in a Distributed File System tree structure
    pub dfs: bool,
    /// Share is present in a DFS Root tree structure
    pub dfs_root: bool,
    #[skip]
    __: B2,
    /// Offline caching behavior for this share
    pub caching_mode: ShareCacheMode,

    /// Share disallows exclusive file opens that deny reads to an open file
    pub restrict_exclusive_opens: bool,
    /// Share disallows clients from opening files in exclusive mode that prevents deletion
    pub force_shared_delete: bool,
    /// Namespace caching is allowed (client must ignore this flag)
    pub allow_namespace_caching: bool,
    /// Server will filter directory entries based on client access permissions
    pub access_based_directory_enum: bool,
    /// Server will not issue exclusive caching rights on this share
    pub force_levelii_oplock: bool,
    /// Share supports hash generation for branch cache retrieval of data
    pub enable_hash_v1: bool,
    /// Share supports v2 hash generation for branch cache retrieval of data
    pub enable_hash_v2: bool,
    /// Server requires encryption of remote file access messages on this share
    pub encrypt_data: bool,

    #[skip]
    __: B2,
    /// Share supports identity remoting via SMB2_REMOTED_IDENTITY_TREE_CONNECT context
    pub identity_remoting: bool,
    #[skip]
    __: B1,
    /// Server supports compression of read/write messages on this share
    pub compress_data: bool,
    /// Server indicates preference to isolate communication on separate connections
    pub isolated_transport: bool,
    #[skip]
    __: B10,
}

/// Tree capabilities indicating various share capabilities
///
/// Reference: MS-SMB2 2.2.10
#[smb_dtyp::mbitfield]
pub struct TreeCapabilities {
    #[skip]
    __: B3,
    /// Share is present in a DFS tree structure
    pub dfs: bool,
    /// Share is continuously available
    pub continuous_availability: bool,
    /// Share facilitates faster recovery of durable handles
    pub scaleout: bool,
    /// Share provides monitoring through the Witness service
    pub cluster: bool,
    /// Share allows dynamic changes in ownership
    pub asymmetric: bool,

    /// Share supports synchronous share level redirection
    pub redirect_to_owner: bool,
    #[skip]
    __: B23,
}

/// Type of share being accessed
///
/// Reference: MS-SMB2 2.2.10
#[smb_response_binrw]
#[derive(Clone, Copy)]
#[brw(repr(u8))]
pub enum ShareType {
    /// Physical disk share
    Disk = 0x1,
    /// Named pipe share
    Pipe = 0x2,
    /// Printer share
    Print = 0x3,
}

/// SMB2 TREE_DISCONNECT Request
///
/// Sent by a client to request that the tree connect that is specified in the TreeId within
/// the SMB2 header be disconnected.
///
/// Reference: MS-SMB2 2.2.11
#[smb_request(size = 4)]
#[derive(Default)]
pub struct TreeDisconnectRequest {
    reserved: u16,
}

/// SMB2 TREE_DISCONNECT Response
///
/// Sent by the server when an SMB2 TREE_DISCONNECT Request is processed successfully.
///
/// Reference: MS-SMB2 2.2.12
#[smb_response(size = 4)]
#[derive(Default)]
pub struct TreeDisconnectResponse {
    reserved: u16,
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    // TODO(test): Add tests with tree connect contexts.
    test_request! {
        TreeConnect {
            flags: TreeConnectRequestFlags::new(),
            buffer: r"\\adc.aviv.local\IPC$".into(),
            tree_connect_contexts: vec![],
        } => "0900000048002a005c005c006100640063002e0061007600690076002e006c006f00630061006c005c004900500043002400"
    }

    test_binrw_response! {
        struct TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::new().with_access_based_directory_enum(true),
            capabilities: TreeCapabilities::new(),
            maximal_access: 0x001f01ff,
        } => "100001000008000000000000ff011f00"
    }
}

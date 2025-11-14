use binrw::prelude::*;
use binrw::{NullWideString, io::TakeSeekExt};
use modular_bitfield::prelude::*;
use smb_dtyp::{
    binrw_util::prelude::*,
    security::{ACL, ClaimSecurityAttributeRelativeV1, SID},
};

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct TreeConnectRequestFlags {
    pub cluster_reconnect: bool,
    pub redirect_to_owner: bool,
    pub extension_present: bool,
    #[skip]
    __: B13,
}

/// Tree Connect Request
///
/// Supports both the base and extension variants.
/// - On read, uses extension iff `flags.extension_present()` - parses just like the server intends.
/// - On write, uses extension iff `tree_connect_contexts` is non-empty.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct TreeConnectRequest {
    #[bw(calc = 9)]
    #[br(assert(_structure_size == 9))]
    _structure_size: u16,
    pub flags: TreeConnectRequestFlags,
    #[bw(calc = PosMarker::default())]
    _path_offset: PosMarker<u16>,
    #[bw(try_calc = buffer.size().try_into())]
    path_length: u16,

    // -- Extension --
    #[br(if(flags.extension_present()))]
    #[bw(calc = if tree_connect_contexts.is_empty() { None } else { Some(PosMarker::default()) })]
    tree_connect_context_offset: Option<PosMarker<u32>>,

    #[br(if(flags.extension_present()))]
    #[bw(if(!tree_connect_contexts.is_empty()))]
    #[bw(calc = if tree_connect_contexts.is_empty() { None } else { Some(tree_connect_contexts.len().try_into().unwrap()) })]
    tree_connect_context_count: Option<u16>,

    #[br(if(flags.extension_present()))]
    #[bw(if(!tree_connect_contexts.is_empty()))]
    #[bw(calc = Some([0u8; 10]))]
    _reserved: Option<[u8; 10]>,
    // -- Extension End --
    // ------------------------------------------------
    // -- Base --
    #[brw(little)]
    #[br(args { size: SizedStringSize::bytes16(path_length) })]
    #[bw(write_with = PosMarker::write_aoff, args(&_path_offset))]
    pub buffer: SizedWideString,

    // -- Extension --
    #[br(if(flags.extension_present()))]
    #[br(seek_before = tree_connect_context_offset.unwrap().seek_relative(true))]
    #[br(count = tree_connect_context_count.unwrap_or(0))]
    #[bw(if(!tree_connect_contexts.is_empty()))]
    #[bw(write_with = PosMarker::write_aoff_m, args(tree_connect_context_offset.as_ref()))]
    tree_connect_contexts: Vec<TreeConnectContext>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct TreeConnectContext {
    /// MS-SMB2 2.2.9.2: Must be set to SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID = 1.
    #[bw(calc = 1)]
    #[br(assert(context_type == 1))]
    context_type: u16,
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
pub struct RemotedIdentityTreeConnect {
    // MS-SMB2 2.2.9.2.1: Must be set to 0x1.
    #[bw(calc = PosMarker::new(1))]
    #[br(assert(_ticket_type.value == 1))]
    _ticket_type: PosMarker<u16>,
    ticket_size: u16,

    // Offsets
    $(
        #[bw(calc = PosMarker::default())]
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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct BlobData<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    blob_size: PosMarker<u16>,
    #[br(map_stream = |s| s.take_seek(blob_size.value as u64))]
    pub blob_data: T,
}

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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SidAttrData {
    pub sid_data: SID,
    pub attr: SidAttrSeGroup,
}

type SidArrayData = ArrayData<SidAttrData>;

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct SidAttrSeGroup {
    pub mandatory: bool,
    pub enabled_by_default: bool,
    pub group_enabled: bool,
    pub group_owner: bool,
    pub group_use_for_deny_only: bool,
    pub group_integrity: bool,
    pub group_integrity_enabled: bool,
    #[skip]
    __: B21,
    pub group_logon_id: B4,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct LuidAttrData {
    pub luid: u64,
    pub attr: LsaprLuidAttributes,
}

#[allow(clippy::identity_op)]
mod lsapr_luid_attributes {
    use super::*;
    /// [MS-LSAD 2.2.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/03c834c0-f310-4e0c-832e-b6e7688364d1)
    #[bitfield]
    #[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
    #[br(map = Self::from_bytes)]
    pub struct LsaprLuidAttributes {
        pub is_default: bool,
        pub is_enabled: bool,
        #[skip]
        __: B30,
    }
}

use lsapr_luid_attributes::LsaprLuidAttributes;

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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct TreeConnectResponse {
    #[bw(calc = 16)]
    #[br(assert(_structure_size == 16))]
    _structure_size: u16,
    pub share_type: ShareType,
    #[bw(calc = 0)]
    _reserved: u8,
    pub share_flags: ShareFlags,
    pub capabilities: TreeCapabilities,
    pub maximal_access: u32,
}

#[derive(BitfieldSpecifier, Debug, Clone, Copy)]
#[bits = 4]
pub enum ShareCacheMode {
    Manual,
    Auto,
    Vdo,
    NoCache,
    All = 0xf,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ShareFlags {
    pub dfs: bool,
    pub dfs_root: bool,
    #[skip]
    __: B2,
    pub caching_mode: ShareCacheMode,

    pub restrict_exclusive_opens: bool,
    pub force_shared_delete: bool,
    pub allow_namespace_caching: bool,
    pub access_based_directory_enum: bool,
    pub force_levelii_oplock: bool,
    pub enable_hash_v1: bool,
    pub enable_hash_v2: bool,
    pub encrypt_data: bool,

    #[skip]
    __: B2,
    pub identity_remoting: bool,
    #[skip]
    __: B1,
    pub compress_data: bool,
    pub isolated_transport: bool,
    #[skip]
    __: B10,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct TreeCapabilities {
    #[skip]
    __: B3,
    pub dfs: bool,
    pub continuous_availability: bool,
    pub scaleout: bool,
    pub cluster: bool,
    pub asymmetric: bool,

    pub redirect_to_owner: bool,
    #[skip]
    __: B23,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u8))]
pub enum ShareType {
    Disk = 0x1,
    Pipe = 0x2,
    Print = 0x3,
}

#[binrw::binrw]
#[derive(Debug, Default)]
pub struct TreeDisconnectRequest {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct TreeDisconnectResponse {
    #[bw(calc = 4)]
    #[br(assert(_structure_size == 4))]
    _structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use smb_tests::*;

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

    test_binrw! {
        struct TreeConnectResponse {
            share_type: ShareType::Disk,
            share_flags: ShareFlags::new().with_access_based_directory_enum(true),
            capabilities: TreeCapabilities::new(),
            maximal_access: 0x001f01ff,
        } => "100001000008000000000000ff011f00"
    }
}

//! Create & Close (files) requests and responses.

use std::fmt::{Debug, Display};
use std::io::{Cursor, SeekFrom};

use super::header::Status;
use super::*;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::SecurityDescriptor;
use smb_dtyp::{Guid, binrw_util::prelude::*};
use smb_fscc::*;

/// 2.2.14.1: SMB2_FILEID
#[binrw::binrw]
#[derive(PartialEq, Eq, Clone, Copy, Default)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl FileId {
    pub const EMPTY: FileId = FileId {
        persistent: 0,
        volatile: 0,
    };
    /// A file ID that is used to indicate that the file ID is not valid,
    /// with setting all bits to 1 - {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}.
    pub const FULL: FileId = FileId {
        persistent: u64::MAX,
        volatile: u64::MAX,
    };
}

impl From<[u8; 16]> for FileId {
    fn from(data: [u8; 16]) -> Self {
        let mut cursor = Cursor::new(data);
        Self::read_le(&mut cursor).unwrap()
    }
}

impl From<Guid> for FileId {
    fn from(guid: Guid) -> Self {
        let mut cursor = Cursor::new(Vec::new());
        guid.write_le(&mut cursor).unwrap();
        <Self as From<[u8; 16]>>::from(cursor.into_inner().try_into().unwrap())
    }
}

impl Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{{:x}|{:x}}}", self.persistent, self.volatile)
    }
}

impl Debug for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileId({})", self)
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct CreateRequest {
    #[bw(calc = 57)]
    #[br(assert(_structure_size == 57))]
    _structure_size: u16,
    #[bw(calc = 0)] // reserved
    #[br(assert(_security_flags == 0))]
    _security_flags: u8,
    pub requested_oplock_level: OplockLevel,
    pub impersonation_level: ImpersonationLevel,
    #[bw(calc = 0)]
    #[br(assert(_smb_create_flags == 0))]
    _smb_create_flags: u64,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u64,
    pub desired_access: FileAccessMask,
    pub file_attributes: FileAttributes,
    pub share_access: ShareAccessFlags,
    pub create_disposition: CreateDisposition,
    pub create_options: CreateOptions,
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>,
    #[bw(try_calc = name.size().try_into())]
    name_length: u16, // bytes
    #[bw(calc = PosMarker::default())]
    _create_contexts_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _create_contexts_length: PosMarker<u32>,

    #[brw(align_before = 8)]
    #[bw(write_with = PosMarker::write_aoff, args(&_name_offset))]
    #[br(args { size: SizedStringSize::bytes16(name_length) })]
    pub name: SizedWideString,

    /// Use the [`CreateContextRequestData`]`::first_...` function family to get the first context of a specific type.
    #[brw(align_before = 8)]
    #[br(map_stream = |s| s.take_seek(_create_contexts_length.value.into()))]
    #[bw(write_with = PosMarker::write_roff_size, args(&_create_contexts_offset, &_create_contexts_length))]
    pub contexts: ChainedItemList<RequestCreateContext, 8>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u32))]
pub enum ImpersonationLevel {
    Anonymous = 0x0,
    Identification = 0x1,
    Impersonation = 0x2,
    Delegate = 0x3,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
#[brw(repr(u32))]
pub enum CreateDisposition {
    Superseded = 0x0,
    #[default]
    Open = 0x1,
    Create = 0x2,
    OpenIf = 0x3,
    Overwrite = 0x4,
    OverwriteIf = 0x5,
}

#[bitfield]
#[derive(BinWrite, BinRead, Default, Debug, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CreateOptions {
    pub directory_file: bool,
    pub write_through: bool,
    pub sequential_only: bool,
    pub no_intermediate_buffering: bool,

    pub synchronous_io_alert: bool,
    pub synchronous_io_nonalert: bool,
    pub non_directory_file: bool,
    #[skip]
    __: bool,

    pub complete_if_oplocked: bool,
    pub no_ea_knowledge: bool,
    pub open_remote_instance: bool,
    pub random_access: bool,

    pub delete_on_close: bool,
    pub open_by_file_id: bool,
    pub open_for_backup_intent: bool,
    pub no_compression: bool,

    pub open_requiring_oplock: bool,
    pub disallow_exclusive: bool,
    #[skip]
    __: B2,

    pub reserve_opfilter: bool,
    pub open_reparse_point: bool,
    pub open_no_recall: bool,
    pub open_for_free_space_query: bool,

    #[skip]
    __: B8,
}

// share_access 4 byte flags:
#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct ShareAccessFlags {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    #[skip]
    __: B29,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct CreateResponse {
    #[bw(calc = 89)]
    #[br(assert(_structure_size == 89))]
    _structure_size: u16,
    pub oplock_level: OplockLevel,
    pub flags: CreateResponseFlags,
    pub create_action: CreateAction,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub endof_file: u64,
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    _reserved2: u32,
    pub file_id: FileId,
    // assert it's 8-aligned
    #[br(assert(create_contexts_offset.value & 0x7 == 0))]
    #[bw(calc = PosMarker::default())]
    create_contexts_offset: PosMarker<u32>, // from smb header start
    #[bw(calc = PosMarker::default())]
    create_contexts_length: PosMarker<u32>, // bytes

    /// Use the [`CreateContextResponseData`]`::first_...` function family to get the first context of a specific type.
    #[br(seek_before = SeekFrom::Start(create_contexts_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(create_contexts_length.value.into()))]
    #[bw(write_with = PosMarker::write_roff_size, args(&create_contexts_offset, &create_contexts_length))]
    pub create_contexts: ChainedItemList<ResponseCreateContext, 8>,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CreateResponseFlags {
    pub reparsepoint: bool,
    #[skip]
    __: B7,
}

// CreateAction
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum CreateAction {
    Superseded = 0x0,
    Opened = 0x1,
    Created = 0x2,
    Overwritten = 0x3,
}

/// The common definition that wrap around all create contexts, for both request and response.
///
/// This is meant to be used within a [`ChainedItemList<T>`][smb_fscc::ChainedItemList<T>]!
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[bw(import(is_last: bool))]
#[allow(clippy::manual_non_exhaustive)]
pub struct CreateContext<T>
where
    for<'a> T: BinRead<Args<'a> = (&'a Vec<u8>,)> + BinWrite<Args<'static> = ()>,
{
    #[bw(calc = PosMarker::default())]
    _name_offset: PosMarker<u16>, // relative to ChainedItem (any access must consider +CHAINED_ITEM_PREFIX_SIZE from start of item)
    #[bw(calc = u16::try_from(name.len()).unwrap())]
    name_length: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    #[bw(calc = PosMarker::default())]
    _data_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    _data_length: PosMarker<u32>,

    #[brw(align_before = 8)]
    #[br(count = name_length)]
    #[br(seek_before = _name_offset.seek_from(_name_offset.value as u64 - CHAINED_ITEM_PREFIX_SIZE as u64))]
    #[bw(write_with = PosMarker::write_roff_plus, args(&_name_offset, CHAINED_ITEM_PREFIX_SIZE as u64))]
    pub name: Vec<u8>,

    #[bw(align_before = 8)]
    #[br(assert(_data_offset.value % 8 == 0))]
    #[bw(write_with = PosMarker::write_roff_size_b_plus, args(&_data_offset, &_data_length, &_name_offset, CHAINED_ITEM_PREFIX_SIZE as u64))]
    #[br(seek_before = _name_offset.seek_from_if(_data_offset.value as u64 - CHAINED_ITEM_PREFIX_SIZE as u64, _data_length.value > 0))]
    #[br(map_stream = |s| s.take_seek(_data_length.value.into()), args(&name))]
    pub data: T,
}

macro_rules! create_context_half {
    (
        $struct_name:ident {
            $(
                $context_type:ident : $req_type:ty,
            )+
        }
    ) => {
    pastey::paste! {

/// This trait is automatically implemented for all
#[doc = concat!("[`Create", stringify!($struct_name), "`]")]
/// create context values.
pub trait [<CreateContextData $struct_name Value>] : Into<CreateContext<[<CreateContext $struct_name Data>]>> {
    const CONTEXT_NAME: &'static [u8];
}

#[doc = concat!("The [`Create", stringify!($struct_name), "`] Context data enum. ")]
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(name: &Vec<u8>))]
pub enum [<CreateContext $struct_name Data>] {
    $(
        #[br(pre_assert(name.as_slice() == CreateContextType::[<$context_type:upper>].name()))]
        [<$context_type:camel $struct_name>]($req_type),
    )+
}

impl [<CreateContext $struct_name Data>] {
    pub fn name(&self) -> &'static [u8] {
        match self {
            $(
                Self::[<$context_type:camel $struct_name>](_) => CreateContextType::[<$context_type:upper _NAME>],
            )+
        }
    }

    $(
        pub fn [<as_ $context_type:snake>](&self) -> Option<&$req_type> {
            match self {
                Self::[<$context_type:camel $struct_name>](a) => Some(a),
                _ => None,
            }
        }

        pub fn [<first_ $context_type:snake>](val: &Vec<CreateContext<Self>>) -> Option<&$req_type> {
            for ctx in val {
                if let Self::[<$context_type:camel $struct_name>](a) = &ctx.data {
                    return Some(a);
                }
            }
            None
        }
    )+
}

$(
    impl [<CreateContextData $struct_name Value>] for $req_type {
        const CONTEXT_NAME: &'static [u8] = CreateContextType::[<$context_type:upper _NAME>];
    }

    impl From<$req_type> for CreateContext<[<CreateContext $struct_name Data>]> {
        fn from(req: $req_type) -> Self {
            CreateContext::<[<CreateContext $struct_name Data>]> {
                name: <$req_type as [<CreateContextData $struct_name Value>]>::CONTEXT_NAME.to_vec(),
                data: [<CreateContext $struct_name Data>]::[<$context_type:camel $struct_name>](req),
            }
        }
    }

    impl TryInto<$req_type> for CreateContext<[<CreateContext $struct_name Data>]> {
        type Error = crate::SmbMsgError;
        fn try_into(self) -> crate::Result<$req_type> {
            match self.data {
                [<CreateContext $struct_name Data>]::[<$context_type:camel $struct_name>](a) => Ok(a),
                _ => Err(crate::SmbMsgError::UnexpectedContent {
                    expected: stringify!($req_type),
                    actual: "", // self.data.name(), TODO: Fix this by making name() a string.
                }),
            }
        }
    }
)+

pub type [<$struct_name CreateContext>] = CreateContext<[<CreateContext $struct_name Data>]>;
        }
    }
}

/// Internal macro to generate request/response context enums for create.
macro_rules! make_create_context {
    (
        $(
            $(#[doc = $docstring:literal])*
            $context_type:ident : $class_name:literal, $req_type:ty $(, $res_type:ty)?;
        )+
    ) => {
        pastey::paste!{

/// This enum contains all the types of create contexts.
pub enum CreateContextType {
    $(
        $(#[doc = $docstring])*
        [<$context_type:upper>],
    )+
}

impl CreateContextType {
    $(
        #[doc = concat!("The name for the `", stringify!($context_type), "` create context.")]
        pub const [<$context_type:upper _NAME>]: &[u8] = $class_name;
    )+

    pub fn from_name(name: &[u8]) -> Option<CreateContextType> {
        match name {
            $(
                Self::[<$context_type:upper _NAME>] => Some(Self::[<$context_type:upper>]),
            )+
            _ => None,
        }
    }

    pub fn name(&self) -> &[u8] {
        match self {
            $(
                Self::[<$context_type:upper>] => Self::[<$context_type:upper _NAME>],
            )+
        }
    }
}
        }

        create_context_half! {
            Request {
                $($context_type: $req_type,)+
            }
        }

        create_context_half! {
            Response {
                $($($context_type: $res_type,)?)+
            }
        }
    }
}

make_create_context!(
    /// The data contains the extended attributes that MUST be stored on the created file.
    exta: b"ExtA", ChainedItemList<FileFullEaInformation>;
    /// The data contains a security descriptor that MUST be stored on the created file.
    secd: b"SecD", SecurityDescriptor;
    /// The client is requesting the open to be durable
    dhnq: b"DHnQ", DurableHandleRequest, DurableHandleResponse;
    /// The client is requesting to reconnect to a durable open after being disconnected
    dhnc: b"DHNc", DurableHandleReconnect;
    /// The data contains the required allocation size of the newly created file.
    alsi: b"AlSi", AllocationSize;
    /// The client is requesting that the server return maximal access information.
    mxac: b"MxAc", QueryMaximalAccessRequest, QueryMaximalAccessResponse;
    /// The client is requesting that the server open an earlier version of the file identified by the provided time stamp.
    twrp: b"TWrp", TimewarpToken;
    /// The client is requesting that the server return a 32-byte opaque BLOB that uniquely identifies the file being opened on disk.
    qfid: b"QFid", QueryOnDiskIdReq, QueryOnDiskIdResp;
    /// The client is requesting that the server return a lease. This value is only supported for the SMB 2.1 and 3.x dialect family.
    rqls: b"RqLs", RequestLease, RequestLease; // v1+2, request & response are the same
    /// The client is requesting the open to be durable. This value is only supported for the SMB 3.x dialect family.
    dh2q: b"DH2Q", DurableHandleRequestV2, DH2QResp;
    /// The client is requesting to reconnect to a durable open after being disconnected. This value is only supported for the SMB 3.x dialect family.
    dh2c: b"DH2C", DurableHandleReconnectV2;
    /// The client is supplying an identifier provided by an application instance while opening a file. This value is only supported for the SMB 3.x dialect family.
    appinstid: b"\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A\x90\x08\xFA\x46\x2E\x14\x4D\x74", AppInstanceId, AppInstanceId;
    /// The client is supplying a version to correspond to the application instance identifier.  This value is only supported for SMB 3.1.1 dialect.
    appinstver: b"\xB9\x82\xD0\xB7\x3B\x56\x07\x4F\xA0\x7B\x52\x4A\x81\x16\xA0\x10", AppInstanceVersion, AppInstanceVersion;
    /// Provided by an application while opening a shared virtual disk file.
    /// This Create Context value is not valid for the SMB 2.002, SMB 2.1, and SMB 3.0 dialects
    svhdxopendev: b"\x9C\xCB\xCF\x9E\x04\xC1\xE6\x43\x98\x0E\x15\x8D\xA1\xF6\xEC\x83", SvhdxOpenDeviceContext, SvhdxOpenDeviceContext;
);

macro_rules! empty_req {
    ($name:ident) => {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        pub struct $name;
    };
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DurableHandleRequest {
    #[bw(calc = 0)]
    #[br(assert(durable_request == 0))]
    durable_request: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct DurableHandleResponse {
    #[bw(calc = 0)]
    _reserved: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DurableHandleReconnect {
    pub durable_request: FileId,
}
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct QueryMaximalAccessRequest {
    #[br(parse_with = binread_if_has_data)]
    pub timestamp: Option<FileTime>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AllocationSize {
    pub allocation_size: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct TimewarpToken {
    pub timestamp: FileTime,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum RequestLease {
    RqLsReqv1(RequestLeaseV1),
    RqLsReqv2(RequestLeaseV2),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct RequestLeaseV1 {
    pub lease_key: u128,
    pub lease_state: LeaseState,
    #[bw(calc = 0)]
    #[br(assert(lease_flags == 0))]
    lease_flags: u32,
    #[bw(calc = 0)]
    #[br(assert(lease_duration == 0))]
    lease_duration: u64,
}
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct RequestLeaseV2 {
    pub lease_key: u128,
    pub lease_state: LeaseState,
    pub lease_flags: LeaseFlags,
    #[bw(calc = 0)]
    #[br(assert(lease_duration == 0))]
    lease_duration: u64,
    pub parent_lease_key: u128,
    pub epoch: u16,
    #[bw(calc = 0)]
    #[br(assert(reserved == 0))]
    reserved: u16,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct LeaseFlags {
    #[skip]
    __: B2,
    pub parent_lease_key_set: bool,
    #[skip]
    __: B29,
}

empty_req!(QueryOnDiskIdReq);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DurableHandleRequestV2 {
    pub timeout: u32,
    pub flags: DurableHandleV2Flags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u64,
    pub create_guid: Guid,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct DurableHandleV2Flags {
    #[skip]
    __: bool,
    pub persistent: bool, // 0x2
    #[skip]
    __: B30,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DurableHandleReconnectV2 {
    file_id: FileId,
    create_guid: Guid,
    flags: DurableHandleV2Flags,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AppInstanceId {
    #[bw(calc = 20)]
    #[br(assert(structure_size == 20))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    pub app_instance_id: Guid,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct AppInstanceVersion {
    #[bw(calc = 24)]
    #[br(assert(structure_size == 24))]
    structure_size: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u16,
    #[bw(calc = 0)]
    #[br(assert(_reserved2 == 0))]
    _reserved2: u32,
    pub app_instance_version_high: u64,
    pub app_instance_version_low: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum SvhdxOpenDeviceContext {
    V1(SvhdxOpenDeviceContextV1),
    V2(SvhdxOpenDeviceContextV2),
}

/// [MS-RSVD sections 2.2.4.12 and 2.2.4.32.](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rsvd/6ec20c83-a6a7-49d5-ae60-72070f91d5e0)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SvhdxOpenDeviceContextV1 {
    pub version: u32,
    pub has_initiator_id: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved1 == 0))]
    reserved1: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    pub initiator_id: Guid,
    pub flags: u32,
    pub originator_flags: u32,
    pub open_request_id: u64,
    pub initiator_host_name_length: u16,
    pub initiator_host_name: [u16; 126 / 2],
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct SvhdxOpenDeviceContextV2 {
    pub version: u32,
    pub has_initiator_id: Boolean,
    #[bw(calc = 0)]
    #[br(assert(reserved1 == 0))]
    reserved1: u8,
    #[bw(calc = 0)]
    #[br(assert(reserved2 == 0))]
    reserved2: u16,
    pub initiator_id: Guid,
    pub flags: u32,
    pub originator_flags: u32,
    pub open_request_id: u64,
    pub initiator_host_name_length: u16,
    pub initiator_host_name: [u16; 126 / 2],
    pub virtual_disk_properties_initialized: u32,
    pub server_service_version: u32,
    pub virtual_sector_size: u32,
    pub physical_sector_size: u32,
    pub virtual_size: u64,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryMaximalAccessResponse {
    // MS-SMB2, 2.2.14.2.5: "MaximalAccess field is valid only if QueryStatus is STATUS_SUCCESS.
    // he status code MUST be one of those defined in [MS-ERREF] section 2.3"
    /// Use [`is_success()`][QueryMaximalAccessResponse::is_success] to check if the query was successful.
    pub query_status: Status,

    /// The maximal access mask for the opened file.
    ///
    /// Use [`access_mask()`][QueryMaximalAccessResponse::access_mask] to get the access mask if the query was successful.
    pub maximal_access: FileAccessMask,
}

impl QueryMaximalAccessResponse {
    /// Returns true if the query was successful.
    pub fn is_success(&self) -> bool {
        self.query_status == Status::Success
    }

    /// Returns the maximal access mask if the query was successful.
    pub fn maximal_access(&self) -> Option<FileAccessMask> {
        if self.is_success() {
            Some(self.maximal_access)
        } else {
            None
        }
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct QueryOnDiskIdResp {
    pub file_id: u64,
    pub volume_id: u64,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u128,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct DH2QResp {
    pub timeout: u32,
    pub flags: DurableHandleV2Flags,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct CloseRequest {
    #[bw(calc = 24)]
    #[br(assert(_structure_size == 24))]
    _structure_size: u16,
    #[bw(calc = CloseFlags::new().with_postquery_attrib(true))]
    #[br(assert(_flags == CloseFlags::new().with_postquery_attrib(true)))]
    _flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
    pub file_id: FileId,
}

#[binrw::binrw]
#[derive(Debug)]
pub struct CloseResponse {
    #[bw(calc = 60)]
    #[br(assert(_structure_size == 60))]
    _structure_size: u16,
    pub flags: CloseFlags,
    #[bw(calc = 0)]
    #[br(assert(_reserved == 0))]
    _reserved: u32,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub allocation_size: u64,
    pub endof_file: u64,
    pub file_attributes: FileAttributes,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct CloseFlags {
    pub postquery_attrib: bool,
    #[skip]
    __: B15,
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    test_request! {
        Create {
            requested_oplock_level: OplockLevel::None,
            impersonation_level: ImpersonationLevel::Impersonation,
            desired_access: FileAccessMask::from_bytes(0x00100081u32.to_le_bytes()),
            file_attributes: FileAttributes::new(),
            share_access: ShareAccessFlags::new()
                .with_read(true)
                .with_write(true)
                .with_delete(true),
            create_disposition: CreateDisposition::Open,
            create_options: CreateOptions::new()
                .with_synchronous_io_nonalert(true)
                .with_disallow_exclusive(true),
            name: "hello".into(),
            contexts: vec![
                DurableHandleRequestV2 {
                    timeout: 0,
                    flags: DurableHandleV2Flags::new(),
                    create_guid: 0x821680290c007b8b11efc0a0c679a320u128.to_le_bytes().into(),
                }
                .into(),
                QueryMaximalAccessRequest::default().into(),
                QueryOnDiskIdReq.into(),
            ]
            .into(),
        } => "390000000200000000000000000000000000000000000000810010000000000007000000010000002000020078000a008800000068
        000000680065006c006c006f0000000000000038000000100004000000180020000000444832510000000000000000000000000000000000
        00000020a379c6a0c0ef118b7b000c29801682180000001000040000001800000000004d7841630000000000000000100004000000180000
        0000005146696400000000"
    }

    test_response! {
        Create {
                oplock_level: OplockLevel::None,
                flags: CreateResponseFlags::new(),
                create_action: CreateAction::Opened,
                creation_time: 133783827154208828.into(),
                last_access_time: 133797832406291912.into(),
                last_write_time: 133783939554544738.into(),
                change_time: 133783939554544738.into(),
                allocation_size: 0,
                endof_file: 0,
                file_attributes: FileAttributes::new().with_directory(true),
                file_id: 950737950337192747837452976457u128.to_le_bytes().into(),
                create_contexts: vec![
                    QueryMaximalAccessResponse {
                        query_status: Status::Success,
                        maximal_access: FileAccessMask::from_bytes(0x001f01ffu32.to_le_bytes()),
                    }
                    .into(),
                    QueryOnDiskIdResp {
                        file_id: 0x400000001e72a,
                        volume_id: 0xb017cfd9,
                    }
                    .into(),
                ]
                .into()
            } => "59000000010000003c083896ae4bdb01c8554b706b58db01620ccdc1c84bdb01620ccdc1c84bdb0100000000000000000000
            0000000000001000000000000000490100000c000000090000000c0000009800000058000000200000001000040000001800080000
            004d7841630000000000000000ff011f000000000010000400000018002000000051466964000000002ae7010000000400d9cf17b0
            0000000000000000000000000000000000000000"
    }

    use smb_dtyp::make_guid;

    test_response_read! {
        server2016: Create {
            oplock_level: OplockLevel::None,
            flags: CreateResponseFlags::new(),
            create_action: CreateAction::Opened,
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: FileTime::ZERO,
            change_time: FileTime::ZERO,
            allocation_size: 4096,
            endof_file: 0,
            file_attributes: FileAttributes::new().with_normal(true),
            file_id: make_guid!("00000001-0001-0000-0100-000001000000").into(),
            create_contexts: vec![
                QueryMaximalAccessResponse {
                    query_status: Status::NotMapped, // Server 2016 IPC$ bug
                    maximal_access: FileAccessMask::default(),
                }
                .into(),
                QueryOnDiskIdResp {
                    file_id: 0xffff870415d75290,
                    volume_id: 0xffffe682cb589c90,
                }
                .into(),
            ].into(),
        } => "59000000010000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000
        000000008000000076007300010000000100000001000000010000009800000058000000200000001000040000001800080000004d7841
        6300000000730000c0000000000000000010000400000018002000000051466964000000009052d7150487ffff909c58cb82e6ffff0000
        0000000000000000000000000000"
    }

    /*
    Tests to add for contexts:
    dhnc: b"DHNc", DurableHandleReconnect, DurableHandleReconnect,
    dh2c: b"DH2C", DurableHandleReconnectV2, DurableHandleReconnectV2,
    appinstid: b"\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A\x90\x08\xFA\x46\x2E\x14\x4D\x74", AppInstanceId, AppInstanceId,
    appinstver: b"\xB9\x82\xD0\xB7\x3B\x56\x07\x4F\xA0\x7B\x52\x4A\x81\x16\xA0\x10", AppInstanceVersion, AppInstanceVersion,
    svhdxopendev: b"\x9C\xCB\xCF\x9E\x04\xC1\xE6\x43\x98\x0E\x15\x8D\xA1\xF6\xEC\x83", SvhdxOpenDeviceContext, SvhdxOpenDeviceContext,
     */

    use smb_dtyp::guid;
    use smb_tests::*;
    use time::macros::datetime;

    // Tests for the following contexts are not implemented here:
    // - ExtA - already tested in smb-fscc & query info/ea tests
    // - SecD - already tested in smb-dtyp tests

    test_binrw! {
        struct DurableHandleRequest {} => "00000000000000000000000000000000"
    }

    test_binrw! {
        struct DurableHandleResponse {} => "0000000000000000"
    }

    test_binrw! {
        struct QueryMaximalAccessRequest {
            timestamp: None,
        } => ""
    }

    test_binrw! {
        struct QueryMaximalAccessResponse {
            query_status: Status::Success,
            maximal_access: FileAccessMask::from_bytes(0x001f01ffu32.to_le_bytes()),
        } => "00000000ff011f00"
    }

    test_binrw! {
        struct QueryOnDiskIdReq {} => ""
    }

    test_binrw! {
        struct QueryOnDiskIdResp {
            file_id: 0x2ae7010000000400,
            volume_id: 0xd9cf17b000000000,
        } => "000400000001e72a 00000000b017cfd9 00000000000000000000000000000000"
    }

    // TODO(TEST): RqLsV1
    test_binrw! {
        RequestLease => rqlsv2: RequestLease::RqLsReqv2(RequestLeaseV2 {
            lease_key: guid!("b69d8fd8-184b-7c4d-a359-40c8a53cd2b7").as_u128(),
            lease_state: LeaseState::new().with_read_caching(true).with_handle_caching(true),
            lease_flags: LeaseFlags::new().with_parent_lease_key_set(true),
            parent_lease_key: guid!("2d158ea3-55db-f749-9cd1-095496a06627").as_u128(),
            epoch: 0
        }) => "d88f9db64b184d7ca35940c8a53cd2b703000000040000000000000000000000a38e152ddb5549f79cd1095496a0662700000000"
    }

    test_binrw! {
        struct AllocationSize {
            allocation_size: 0xebfef0d4c000,
        } => "00c0d4f0feeb0000"
    }

    test_binrw! {
        struct DurableHandleRequestV2 {
            create_guid: guid!("5a08e844-45c3-234d-87c6-596d2bc8bca5"),
            flags: DurableHandleV2Flags::new(),
            timeout: 0,
        } => "0000000000000000000000000000000044e8085ac3454d2387c6596d2bc8bca5"
    }

    test_binrw! {
        struct DH2QResp {
            timeout: 180000,
            flags: DurableHandleV2Flags::new(),
        } => "20bf020000000000"
    }

    test_binrw! {
        struct TimewarpToken {
            timestamp: datetime!(2025-01-20 15:36:20.277632400).into(),
        } => "048fa10d516bdb01"
    }

    test_binrw! {
        struct DurableHandleReconnectV2 {
            file_id: guid!("000000b3-0008-0000-dd00-000008000000").into(),
            create_guid: guid!("a23e428c-1bac-7e43-8451-91f9f2277a95"),
            flags: DurableHandleV2Flags::new(),
        } => "b300000008000000dd000000080000008c423ea2ac1b437e845191f9f2277a9500000000"
    }
}

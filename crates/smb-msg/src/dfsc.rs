//! Distributed File System Referral Protocol (MS-DFSC) messages.
//!
//! [MS-DFSC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/)

#[cfg(feature = "server")]
use binrw::io::TakeSeekExt;
use binrw::{NullWideString, prelude::*};
use modular_bitfield::prelude::*;
use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::smb_request_binrw;

/// [MS-DFSC 2.2.2](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/663c9b38-41b8-4faa-b6f6-a4576b4cea62>):
/// DFS referral requests are sent in the form of an REQ_GET_DFS_REFERRAL message, by using an appropriate transport as specified in section 2.1.
#[smb_request_binrw]
pub struct ReqGetDfsReferral {
    /// An integer that indicates the highest DFS referral version understood by the client. The DFS referral versions specified by this document are 1 through 4 inclusive. A DFS client MUST support DFS referral version 1 through the version number set in this field. The referral response messages are referral version dependent and are specified in sections 2.2.5.1 through 2.2.5.4.
    pub max_referral_level: ReferralLevel,
    /// A null-terminated Unicode string specifying the path to be resolved. The specified path MUST NOT be case-sensitive. Its format depends on the type of referral request, as specified in section 3.1.4.2.
    pub request_file_name: NullWideString,
}

/// The DFS referral version supported by the client.
/// See [`ReqGetDfsReferral::max_referral_level`].
#[smb_request_binrw]
#[brw(repr(u16))]
pub enum ReferralLevel {
    /// DFS referral version 1
    V1 = 1,
    /// DFS referral version 2
    V2 = 2,
    /// DFS referral version 3
    V3 = 3,
    /// DFS referral version 4
    V4 = 4,
}

#[smb_request_binrw]
pub struct ReqGetDfsReferralEx {
    /// An integer that indicates the highest DFS referral version understood by the client. The DFS referral versions specified by this document are 1 through 4 inclusive. A DFS client MUST support DFS referral version 1 through the version number set in this field. The referral response messages are referral version dependent and are specified in sections 2.2.5.1 through 2.2.5.4.
    pub max_referral_level: u16,
    pub request_flags: DfsRequestFlags,
    request_data_length: PosMarker<u32>,
    #[bw(write_with = PosMarker::write_size, args(request_data_length))]
    #[br(map_stream = |s| s.take_seek(request_data_length.value as u64))]
    pub request_data: DfsRequestData,
}

#[smb_dtyp::mbitfield]
pub struct DfsRequestFlags {
    /// SiteName present: The SiteName bit MUST be set to 1 if the packet contains the site name of the client.
    pub site_name: bool,
    #[skip]
    __: B15,
}

/// RequestData is part of the REQ_GET_DFS_REFERRAL_EX message (section 2.2.3).
#[smb_request_binrw]
pub struct DfsRequestData {
    #[bw(try_calc = request_file_name.size().try_into())]
    request_file_name_length: u16,
    /// A Unicode string specifying the path to be resolved. The specified path MUST be interpreted in a case-insensitive manner. Its format depends on the type of referral request, as specified in section 3.1.4.2.
    #[br(args { size: SizedStringSize::bytes16(request_file_name_length) })]
    request_file_name: SizedWideString,
    #[bw(try_calc = site_name.size().try_into())]
    site_name_length: u16,
    /// A Unicode string specifying the name of the site to which the DFS client computer belongs. The length of this string is determined by the value of the SiteNameLength field.
    #[br(args { size: SizedStringSize::bytes16(site_name_length) })]
    site_name: SizedWideString,
}

impl DfsRequestData {
    pub fn get_bin_size(&self) -> usize {
        size_of::<u16>() * 2 // lengths
            + self.request_file_name.len() * size_of::<u16>() // + request_file_name (wstring)
            + self.site_name.len() * size_of::<u16>() // + site_name (wstring)
    }
}

/// NOTE: This struct currently implements [`BinWrite`] only as a placeholder (calling it will panic).
/// [`BinRead`] is implemented and can be used to read DFS referral responses.
#[binrw::binread]
#[derive(Debug, PartialEq, Eq)]
pub struct RespGetDfsReferral {
    pub path_consumed: u16,
    #[bw(try_calc = referral_entries.len().try_into())]
    #[br(temp)]
    number_of_referrals: u16,
    pub referral_header_flags: ReferralHeaderFlags,
    #[br(count = number_of_referrals)]
    pub referral_entries: Vec<ReferralEntry>,
    // string_buffer is here, but it's use is to provide a buffer for the strings in the referral entries.
}

impl BinWrite for RespGetDfsReferral {
    type Args<'a> = ();

    fn write_options<W: binrw::io::Write + binrw::io::Seek>(
        &self,
        _writer: &mut W,
        _endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        unimplemented!(
            "Placeholder trait implementation for RespGetDfsReferral - writing is currently not supported"
        );
    }
}

#[smb_dtyp::mbitfield]
pub struct ReferralHeaderFlags {
    /// Whether all of the targets in the referral entries returned are DFS root targets capable of handling DFS referral requests.
    pub referral_servers: bool,
    /// Whether all of the targets in the referral response can be accessed without requiring further referral requests.
    pub storage_servers: bool,
    /// Whether DFS client target failback is enabled for all targets in this referral response. This value used only in version 4.
    pub target_failbacl: bool,
    #[skip]
    __: B29,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ReferralEntry {
    /* All entry types share the same fields in their beginnings, so we split it */
    #[bw(calc = value.get_version())]
    pub version: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _size: PosMarker<u16>,

    #[br(args(version))]
    // map_stream is not used here because we seek manually in the inner structs.
    #[bw(write_with = PosMarker::write_size_plus, args(&_size, Self::COMMON_PART_SIZE as u64))]
    pub value: ReferralEntryValue,
}

impl ReferralEntry {
    /// The size of the common part of the referral entry - version + size.
    pub const COMMON_PART_SIZE: usize = std::mem::size_of::<u16>() * 2;
}

macro_rules! gen_ref_entry_val {
    (
        $($ver:literal,)+
    ) => {
        pastey::paste! {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        #[br(import(version: u16))]
        pub enum ReferralEntryValue {
            $(
                #[doc = concat!("A DFS referral version", stringify!($ver), "Entry")]
                #[br(pre_assert(version == $ver))]
                [<V $ver>]([<ReferralEntryValueV $ver>]),
            )+
        }

        impl ReferralEntryValue {
            fn get_version(&self) -> u16 {
                match self {
                    $(
                        Self::[<V $ver>](_) => $ver,
                    )+
                }
            }
        }
                }
    };
}

gen_ref_entry_val!(1, 2, 3, 4,);

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ReferralEntryValueV1 {
    /// Type of server hosting the target
    pub server_type: DfsServerType,
    #[bw(calc = 0)]
    _referral_entry_flags: u16,
    /// The DFS target.
    pub share_name: NullWideString,
}

/// Type of server hosting the target
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum DfsServerType {
    /// Non-root targets returned.
    NonRoot = 0x0,
    /// Root targets returned.
    Root = 0x1,
}

/// DO NOT use this struct directly when bin read/writing.
/// Use an instance of [`ReferralEntry`] instead.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ReferralEntryValueV2 {
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _start: PosMarker<()>,
    /// Type of server hosting the target
    pub server_type: DfsServerType,
    #[bw(calc = 0)]
    _referral_entry_flags: u16,
    #[bw(calc = 0)]
    _proximity: u32,

    /// The time-out value, in seconds, of the DFS root or DFS link.
    pub time_to_live: u32,
    #[br(assert(dfs_path_offset.value >= ReferralEntry::COMMON_PART_SIZE as u16))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    dfs_path_offset: PosMarker<u16>,
    #[br(assert(dfs_alternate_path_offset.value >= ReferralEntry::COMMON_PART_SIZE as u16))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    dfs_alternate_path_offset: PosMarker<u16>,
    #[br(assert(network_address_offset.value >= ReferralEntry::COMMON_PART_SIZE as u16))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    network_address_offset: PosMarker<u16>,

    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _restore_position: PosMarker<()>,

    /// The DFS path that corresponds to the DFS root or the DFS link for which target information is returned.
    #[br(seek_before = _start.seek_from((dfs_path_offset.value as usize - ReferralEntry::COMMON_PART_SIZE).try_into().unwrap()))]
    #[bw(write_with = PosMarker::write_roff_b_plus, args(&dfs_path_offset, &_start, ReferralEntry::COMMON_PART_SIZE as u64))]
    pub dfs_path: NullWideString,
    /// The DFS path that corresponds to the DFS root or the DFS link for which target information is returned.
    #[br(seek_before = _start.seek_from((dfs_alternate_path_offset.value as usize - ReferralEntry::COMMON_PART_SIZE).try_into().unwrap()))]
    #[bw(write_with = PosMarker::write_roff_b_plus, args(&dfs_alternate_path_offset, &_start, ReferralEntry::COMMON_PART_SIZE as u64))]
    pub dfs_alternate_path: NullWideString,
    /// The DFS target that corresponds to this entry.
    #[br(seek_before = _start.seek_from((network_address_offset.value as usize - ReferralEntry::COMMON_PART_SIZE).try_into().unwrap()))]
    #[bw(write_with = PosMarker::write_roff_b_plus, args(&network_address_offset, &_start, ReferralEntry::COMMON_PART_SIZE as u64))]
    pub network_address: NullWideString,

    #[br(seek_before = _restore_position.seek_from(0))]
    #[bw(calc = ())]
    __: (),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ReferralEntryValueV3 {
    /// Type of server hosting the target
    pub server_type: DfsServerType,
    pub referral_entry_flags: ReferralEntryFlags,
    /// The time-out value, in seconds, of the DFS root or DFS link.
    pub time_to_live: u32,
    #[br(args(referral_entry_flags))]
    pub value: EntryV3Value,
}

impl ReferralEntryValueV3 {
    /// The size of the common part of the referral entry - version + size.
    pub const COMMON_PART_SIZE: usize = std::mem::size_of::<u16>() * 2 + std::mem::size_of::<u32>();
}

#[smb_dtyp::mbitfield]
pub struct ReferralEntryFlags {
    #[skip]
    __: bool,
    pub name_list_referral: bool,
    #[skip]
    __: B14,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(flags: ReferralEntryFlags))]
pub enum EntryV3Value {
    /// The DFS path that corresponds to the DFS root or the DFS link for which target information is returned.
    #[br(pre_assert(flags.name_list_referral()))]
    DfsPath(EntryV3V4DfsPaths),
    /// The DFS target that corresponds to this entry.
    #[br(pre_assert(!flags.name_list_referral()))]
    NetworkAddress(EntryV3DCRefs),
}

impl EntryV3Value {
    /// (Internal)
    ///
    /// The offset of EntryV3Value from the beginning of the [`ReferralEntry`] structure.
    /// This is used to calculate the offsets of the fields in the structure.
    const OFFSET_FROM_ENTRY_START: u16 =
        (ReferralEntry::COMMON_PART_SIZE + ReferralEntryValueV3::COMMON_PART_SIZE) as u16;
}

/// 2.2.5.3.1 NameListReferral Flag Set to 0
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct EntryV3V4DfsPaths {
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _start: PosMarker<()>,
    #[br(assert(dfs_path_offset.value >= EntryV3Value::OFFSET_FROM_ENTRY_START))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    dfs_path_offset: PosMarker<u16>,
    #[br(assert(dfs_alternate_path_offset.value >= EntryV3Value::OFFSET_FROM_ENTRY_START))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    dfs_alternate_path_offset: PosMarker<u16>,
    #[br(assert(network_address_offset.value >= EntryV3Value::OFFSET_FROM_ENTRY_START))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    network_address_offset: PosMarker<u16>,
    #[bw(calc = 0)]
    _service_site_guid: u128,

    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _restore_position: PosMarker<()>,

    /// The DFS path that corresponds to the DFS root or the DFS link for which target information is returned.
    #[br(seek_before = _start.seek_from((dfs_path_offset.value - EntryV3Value::OFFSET_FROM_ENTRY_START).into()))]
    #[bw(write_with = PosMarker::write_roff_b_plus, args(&dfs_path_offset, &_start, ReferralEntry::COMMON_PART_SIZE as u64))]
    pub dfs_path: NullWideString,
    /// The DFS path that corresponds to the DFS root or the DFS link for which target information is returned.
    #[br(seek_before = _start.seek_from((dfs_alternate_path_offset.value - EntryV3Value::OFFSET_FROM_ENTRY_START).into()))]
    #[bw(write_with = PosMarker::write_roff_b_plus, args(&dfs_alternate_path_offset, &_start, ReferralEntry::COMMON_PART_SIZE as u64))]
    pub dfs_alternate_path: NullWideString,
    /// The DFS target that corresponds to this entry.
    #[br(seek_before = _start.seek_from((network_address_offset.value - EntryV3Value::OFFSET_FROM_ENTRY_START).into()))]
    #[bw(write_with = PosMarker::write_roff_b_plus, args(&network_address_offset, &_start, ReferralEntry::COMMON_PART_SIZE as u64))]
    pub network_address: NullWideString,

    #[br(seek_before = _restore_position.seek_from(0))]
    #[bw(calc = ())]
    __: (),
}

/// 2.2.5.3.2 NameListReferral Flag Set to 1
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct EntryV3DCRefs {
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _start: PosMarker<()>,
    #[br(assert(special_name_offset.value >= EntryV3Value::OFFSET_FROM_ENTRY_START))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    special_name_offset: PosMarker<u16>,
    number_of_expanded_names: u16,
    #[br(assert(expanded_name_offset.value >= EntryV3Value::OFFSET_FROM_ENTRY_START))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    expanded_name_offset: PosMarker<u16>,

    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _restore_position: PosMarker<()>,

    #[br(seek_before = _start.seek_from((special_name_offset.value - EntryV3Value::OFFSET_FROM_ENTRY_START).into()))]
    pub special_name: NullWideString,
    #[br(seek_before = _start.seek_from((expanded_name_offset.value - EntryV3Value::OFFSET_FROM_ENTRY_START).into()))]
    #[br(count = number_of_expanded_names)]
    pub expanded_names: Vec<NullWideString>,

    #[br(seek_before = _restore_position.seek_from(0))]
    #[bw(calc = ())]
    __: (),
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ReferralEntryValueV4 {
    /// Type of server hosting the target
    pub server_type: DfsServerType,
    // The ONLY valid flag is TargetSetBoundary.
    #[br(assert((referral_entry_flags & !u16::from_le_bytes(ReferralEntryFlagsV4::new().with_target_set_boundary(true).into_bytes())) == 0))]
    pub referral_entry_flags: u16,
    /// The time-out value, in seconds, of the DFS root or DFS link.
    pub time_to_live: u32,
    // name_list_referral: bool is ALWAYS 0, so we know the type of the value.
    pub refs: EntryV3V4DfsPaths,
}

/// Internal.
#[smb_dtyp::mbitfield]
struct ReferralEntryFlagsV4 {
    #[skip]
    __: B2,
    #[skip(getters)]
    target_set_boundary: bool,
    #[skip]
    __: B13,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    test_binrw_request! {
        struct ReqGetDfsReferral {
            max_referral_level: ReferralLevel::V4,
            request_file_name: r"\ADC.aviv.local\dfs\Docs".into(),
        } => "04005c004100440043002e0061007600690076002e006c006f00630061006c005c006400660073005c0044006f00630073000000"
    }

    #[cfg(feature = "client")]
    smb_tests::test_binrw_read! {
        struct RespGetDfsReferral {
            path_consumed: 48,
            referral_header_flags: ReferralHeaderFlags::new().with_storage_servers(true),
            referral_entries: vec![
                ReferralEntry {
                    value: ReferralEntryValue::V4(ReferralEntryValueV4 {
                        server_type: DfsServerType::NonRoot,
                        referral_entry_flags: u16::from_le_bytes(
                            ReferralEntryFlagsV4::new()
                                .with_target_set_boundary(true)
                                .into_bytes()
                        ),
                        time_to_live: 1800,
                        refs: EntryV3V4DfsPaths {
                            dfs_path: r"\ADC.aviv.local\dfs\Docs".into(),
                            dfs_alternate_path: r"\ADC.aviv.local\dfs\Docs".into(),
                            network_address: r"\ADC\Shares\Docs".into()
                        }
                    })
                },
                ReferralEntry {
                    value: ReferralEntryValue::V4(ReferralEntryValueV4 {
                        server_type: DfsServerType::NonRoot,
                        referral_entry_flags: 0,
                        time_to_live: 1800,
                        refs: EntryV3V4DfsPaths {
                            dfs_path: r"\ADC.aviv.local\dfs\Docs".into(),
                            dfs_alternate_path: r"\ADC.aviv.local\dfs\Docs".into(),
                            network_address: r"\FSRV\Shares\MyShare".into()
                        }
                    })
                }
            ],
        } => "300002000200000004002200000004000807000044007600a8000000000000000000000000000000000004002200000000000807000022005400a
        800000000000000000000000000000000005c004100440043002e0061007600690076002e006c006f00630061006c005c006400660073005c0044006f00
        6300730000005c004100440043002e0061007600690076002e006c006f00630061006c005c006400660073005c0044006f006300730000005c004100440
        043005c005300680061007200650073005c0044006f006300730000005c0046005300520056005c005300680061007200650073005c004d007900530068
        006100720065000000"
    }
}

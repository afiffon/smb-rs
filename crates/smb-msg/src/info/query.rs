//! Get/Set Info Request/Response

use crate::FileId;
use binrw::{io::TakeSeekExt, prelude::*};
use modular_bitfield::prelude::*;
use smb_dtyp::{SID, SecurityDescriptor, binrw_util::prelude::*};
use smb_msg_derive::*;
use std::io::{Cursor, SeekFrom};

use super::common::*;
use smb_fscc::*;

/// Request to query information on a file, named pipe, or underlying volume.
///
/// MS-SMB2 2.2.37
#[smb_request(size = 41)]
pub struct QueryInfoRequest {
    /// The type of information queried (file, filesystem, security, or quota).
    pub info_type: InfoType,
    /// For file/filesystem queries, specifies the information class to retrieve.
    #[brw(args(info_type))]
    pub info_class: QueryInfoClass,

    /// Maximum number of bytes the server can send in the response.
    pub output_buffer_length: u32,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _input_buffer_offset: PosMarker<u16>,
    reserved: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    input_buffer_length: PosMarker<u32>,
    /// Provides additional information for security or EA queries.
    /// For security queries, contains flags indicating which security attributes to return.
    /// For EA queries without an EA list, contains index to start enumeration.
    pub additional_info: AdditionalInfo,
    /// Flags for EA enumeration control (restart scan, return single entry, index specified).
    pub flags: QueryInfoFlags,
    /// Identifier of the file or named pipe on which to perform the query.
    pub file_id: FileId,
    /// Input data for quota or EA queries. Empty for other information types.
    #[br(map_stream = |s| s.take_seek(input_buffer_length.value as u64))]
    #[br(args(&info_class, info_type))]
    #[bw(write_with = PosMarker::write_aoff_size_a, args(&_input_buffer_offset, &input_buffer_length, (info_class, *info_type)))]
    pub data: GetInfoRequestData,
}

/// Helper enum to specify the information class for query info requests,
/// when it is applicable.
#[smb_request_binrw]
#[br(import(info_type: InfoType))]
#[bw(import(info_type: &InfoType))]
pub enum QueryInfoClass {
    #[br(pre_assert(matches!(info_type, InfoType::File)))]
    #[bw(assert(matches!(info_type, InfoType::File)))]
    File(QueryFileInfoClass),

    #[br(pre_assert(matches!(info_type, InfoType::FileSystem)))]
    #[bw(assert(matches!(info_type, InfoType::FileSystem)))]
    FileSystem(QueryFileSystemInfoClass),

    Empty(NullByte),
}

impl Default for QueryInfoClass {
    fn default() -> Self {
        QueryInfoClass::Empty(NullByte {})
    }
}

/// Single null (0) byte.
///
/// - When reading, asserts that the byte is 0.
/// - When writing, always writes a 0 byte.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Default)]
pub struct NullByte {
    #[bw(calc = 0)]
    #[br(assert(_null == 0))]
    _null: u8,
}

impl AdditionalInfo {
    pub fn is_security(&self) -> bool {
        self.owner_security_information()
            || self.group_security_information()
            || self.dacl_security_information()
            || self.sacl_security_information()
            || self.label_security_information()
            || self.attribute_security_information()
            || self.scope_security_information()
            || self.backup_security_information()
    }
}

#[smb_dtyp::mbitfield]
pub struct QueryInfoFlags {
    /// Restart the scan for EAs from the beginning.
    pub restart_scan: bool,
    /// Return a single EA entry in the response buffer.
    pub return_single_entry: bool,
    /// The caller has specified an EA index.
    pub index_specified: bool,
    #[skip]
    __: B29,
}

/// Input data for query information requests that require additional parameters.
///
/// This payload is used for quota and extended attribute queries.
/// Other information types have no input data.
///
/// MS-SMB2 2.2.37
#[smb_request_binrw]
#[brw(import(file_info_class: &QueryInfoClass, query_info_type: InfoType))]
pub enum GetInfoRequestData {
    /// The query quota to perform.
    #[br(pre_assert(query_info_type == InfoType::Quota))]
    #[bw(assert(query_info_type == InfoType::Quota))]
    Quota(QueryQuotaInfo),

    /// Extended attributes information to query.
    #[br(pre_assert(matches!(file_info_class, QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)) && query_info_type == InfoType::File))]
    #[bw(assert(matches!(file_info_class, QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)) && query_info_type == InfoType::File))]
    EaInfo(GetEaInfoList),

    // Other cases have no data.
    #[br(pre_assert(query_info_type != InfoType::Quota && !(query_info_type == InfoType::File && matches!(file_info_class , QueryInfoClass::File(QueryFileInfoClass::FullEaInformation)))))]
    None(()),
}

/// Specifies the quota information to query.
///
/// MS-SMB2 2.2.37.1
#[smb_message_binrw]
pub struct QueryQuotaInfo {
    /// If true, server returns a single quota entry. Otherwise, returns maximum entries that fit.
    pub return_single: Boolean,
    /// If true, quota information is read from the beginning. Otherwise, continues from previous enumeration.
    pub restart_scan: Boolean,
    reserved: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    sid_list_length: PosMarker<u32>, // type 1: list of FileGetQuotaInformation structs.
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    start_sid_length: PosMarker<u32>, // type 2: SIDs list
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    start_sid_offset: PosMarker<u32>,

    /// Option 1: List of FileGetQuotaInformation structs to query specific quota entries.
    #[br(if(sid_list_length.value > 0))]
    #[br(map_stream = |s| s.take_seek(sid_list_length.value as u64))]
    #[bw(if(get_quota_info_content.as_ref().is_some_and(|v| !v.is_empty())))]
    #[bw(write_with = PosMarker::write_size, args(&sid_list_length))]
    pub get_quota_info_content: Option<ChainedItemList<FileGetQuotaInformation>>,

    /// Option 2: Single SID to query quota for a specific user.
    #[br(if(start_sid_length.value > 0))]
    #[bw(if(sid.is_some()))]
    #[br(seek_before = SeekFrom::Current(start_sid_offset.value as i64))]
    #[bw(write_with = PosMarker::write_size, args(&start_sid_length))]
    #[brw(assert(get_quota_info_content.is_none() != sid.is_none()))]
    // offset is 0, the default anyway.
    pub sid: Option<SID>,
}

impl QueryQuotaInfo {
    /// Builds a new [`QueryQuotaInfo`] with a list of [`FileGetQuotaInformation`] structs.
    ///
    /// MS-SMB2 2.2.37.1 Option 1
    pub fn new(
        return_single: bool,
        restart_scan: bool,
        content: Vec<FileGetQuotaInformation>,
    ) -> Self {
        Self {
            return_single: return_single.into(),
            restart_scan: restart_scan.into(),
            get_quota_info_content: Some(content.into()),
            sid: None,
        }
    }

    /// Builds a new [`QueryQuotaInfo`] with a single SID.
    ///
    /// MS-SMB2 2.2.37.1 Option 2
    pub fn new_sid(return_single: bool, restart_scan: bool, sid: SID) -> Self {
        Self {
            return_single: return_single.into(),
            restart_scan: restart_scan.into(),
            get_quota_info_content: None,
            sid: Some(sid),
        }
    }
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
pub struct GetEaInfoList {
    pub values: ChainedItemList<FileGetEaInformation>,
}

/// Response to a query information request, containing the requested data.
///
/// MS-SMB2 2.2.38
#[smb_response(size = 9)]
pub struct QueryInfoResponse {
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_buffer_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_buffer_length: PosMarker<u32>,
    /// The information being returned. Format depends on the info type and additional information from the request.
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length.value.into()))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&output_buffer_offset, &output_buffer_length))]
    data: QueryInfoResponseData,
}

impl QueryInfoResponse {
    /// Call this method first when parsing an incoming query info response.
    /// It will parse the raw data into a [QueryInfoResponseData] struct, which has
    /// a variation for each information type: File, FileSystem, Security, Quota.
    /// This is done by calling the [QueryInfoResponseData::parse] method.
    pub fn parse(&self, info_type: InfoType) -> Result<QueryInfoData, binrw::Error> {
        self.data.parse(info_type)
    }
}

/// A helper structure containing raw response data that can be parsed into specific information types.
///
/// Call [`QueryInfoResponseData::parse`] to convert to the appropriate data format
/// based on the info type from the request.
#[smb_response_binrw]
pub struct QueryInfoResponseData {
    #[br(parse_with = binrw::helpers::until_eof)]
    data: Vec<u8>,
}

impl QueryInfoResponseData {
    pub fn parse(&self, info_type: InfoType) -> Result<QueryInfoData, binrw::Error> {
        let mut cursor = Cursor::new(&self.data);
        QueryInfoData::read_args(&mut cursor, (info_type,))
    }
}

impl From<Vec<u8>> for QueryInfoResponseData {
    fn from(data: Vec<u8>) -> Self {
        QueryInfoResponseData { data }
    }
}

query_info_data! {
    QueryInfoData
    File: RawQueryInfoData<QueryFileInfo>,
    FileSystem: RawQueryInfoData<QueryFileSystemInfo>,
    Security: SecurityDescriptor,
    Quota: ChainedItemList<FileQuotaInformation>,
}

#[cfg(test)]
mod tests {

    use time::macros::datetime;

    use crate::*;
    use smb_dtyp::*;

    use super::*;

    const QUERY_INFO_HEADER_DATA: &'static str = "";

    test_request! {
        query_info_basic: QueryInfo {
            info_type: InfoType::File,
            info_class: QueryInfoClass::File(QueryFileInfoClass::NetworkOpenInformation),
            output_buffer_length: 56,
            additional_info: AdditionalInfo::new(),
            flags: QueryInfoFlags::new(),
            file_id: [
                0x77, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xc5, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0,
                0x0,
            ]
            .into(),
            data: GetInfoRequestData::None(()),
        } => const_format::concatcp!(QUERY_INFO_HEADER_DATA, "290001223800000068000000000000000000000000000000770500000c000000c50010000c000000")
    }

    test_request! {
        query_info_get_ea: QueryInfo {
            info_type: InfoType::File,
            info_class: QueryInfoClass::File(QueryFileInfoClass::FullEaInformation),
            additional_info: AdditionalInfo::new(),
            flags: QueryInfoFlags::new()
                .with_restart_scan(true)
                .with_return_single_entry(true),
            file_id: [
                0x7a, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0xd1, 0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0,
            ]
            .into(),
            data: GetInfoRequestData::EaInfo(GetEaInfoList {
                values: vec![FileGetEaInformation::new("$MpEa_D262AC624451295")].into(),
            }),
            output_buffer_length: 554,
        } => const_format::concatcp!(QUERY_INFO_HEADER_DATA, "2900010f2a020000680000001b00000000000000030000007a0500000c000000d10010000c0000000000000015244d7045615f44323632414336323434353132393500")
    }

    test_request! {
        query_security: QueryInfo {
            info_type: InfoType::Security,
            info_class: Default::default(),
            output_buffer_length: 0,
            additional_info: AdditionalInfo::new()
                .with_owner_security_information(true)
                .with_group_security_information(true)
                .with_dacl_security_information(true)
                .with_sacl_security_information(true),
            flags: QueryInfoFlags::new(),
            file_id: make_guid!("0000002b-000d-0000-3100-00000d000000").into(),
            data: GetInfoRequestData::None(()),
        } => const_format::concatcp!(QUERY_INFO_HEADER_DATA, "290003000000000068000000000000000f000000000000002b0000000d000000310000000d000000")
    }

    test_response! {
        QueryInfo {
            data: [
                0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51,
                0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1,
                0xd, 0x51, 0x6b, 0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ]
            .to_vec()
            .into()
        } => "09004800280000005b6c44ce6a58db01048fa10d516bdb01048fa10d516bdb01048fa10d516bdb012000000000000000"
    }

    #[test]
    pub fn test_query_info_resp_parse_file() {
        let raw_data: QueryInfoResponseData = [
            0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb,
            0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b, 0xdb, 0x1, 0x4, 0x8f, 0xa1, 0xd, 0x51, 0x6b,
            0xdb, 0x1, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ]
        .to_vec()
        .into();
        assert_eq!(
            raw_data
                .parse(InfoType::File)
                .unwrap()
                .as_file()
                .unwrap()
                .parse(QueryFileInfoClass::BasicInformation)
                .unwrap(),
            QueryFileInfo::BasicInformation(FileBasicInformation {
                creation_time: datetime!(2024-12-27 14:22:48.792994700).into(),
                last_access_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                last_write_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                change_time: datetime!(2025-01-20 15:36:20.277632400).into(),
                file_attributes: FileAttributes::new().with_archive(true)
            })
        )
    }

    #[test]
    fn test_query_info_resp_parse_stream_info() {
        let raw_data: QueryInfoResponseData = [
            0x48, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x93, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x5a, 0x00,
            0x6f, 0x00, 0x6e, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x49, 0x00, 0x64, 0x00, 0x65, 0x00,
            0x6e, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69, 0x00, 0x65, 0x00, 0x72, 0x00,
            0x3a, 0x00, 0x24, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0xd1, 0xd6, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00,
            0x3a, 0x00, 0x24, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00,
        ]
        .to_vec()
        .into();

        assert_eq!(
            raw_data
                .parse(InfoType::File)
                .unwrap()
                .as_file()
                .unwrap()
                .parse(QueryFileInfoClass::StreamInformation)
                .unwrap(),
            QueryFileInfo::StreamInformation(
                vec![
                    FileStreamInformationInner {
                        stream_size: 0x93,
                        stream_allocation_size: 0x1000,
                        stream_name: SizedWideString::from(":Zone.Identifier:$DATA"),
                    },
                    FileStreamInformationInner {
                        stream_size: 0xd6d1,
                        stream_allocation_size: 0xd000,
                        stream_name: SizedWideString::from("::$DATA"),
                    },
                ]
                .into()
            )
        )
    }
}

//! Directory-related messages.

#[cfg(feature = "client")]
use binrw::io::TakeSeekExt;
use smb_msg_derive::*;
use std::io::SeekFrom;

use binrw::prelude::*;
use modular_bitfield::prelude::*;

use smb_dtyp::binrw_util::prelude::*;
use smb_fscc::*;

use super::FileId;

/// SMB2 QUERY_DIRECTORY Request packet for obtaining directory enumeration.
///
/// This request is sent by the client to obtain a directory enumeration on a
/// directory open. The client specifies the type of information desired and
/// can optionally provide a search pattern to filter the results.
///
/// Reference: MS-SMB2 section 2.2.33, page 10906442-294c-46d3-8515-c277efe1f752
#[smb_request(size = 33)]
pub struct QueryDirectoryRequest {
    /// The file information class describing the format that data must be returned in.
    /// Specifies which type of directory information structure should be used for each entry.
    pub file_information_class: QueryDirectoryInfoClass,
    /// Flags indicating how the query directory operation must be processed.
    /// Controls behavior such as restarting enumeration or returning single entries.
    pub flags: QueryDirectoryFlags,
    /// The byte offset within the directory to resume enumeration from.
    /// Must be supplied when INDEX_SPECIFIED flag is set, otherwise must be zero.
    // If SMB2_INDEX_SPECIFIED is set in Flags, this value MUST be supplied.
    // Otherwise, it MUST be set to zero and the server MUST ignore it.
    #[bw(assert(flags.index_specified() || *file_index == 0))]
    pub file_index: u32,
    /// Identifier of the directory on which to perform the enumeration.
    /// This is returned from an SMB2 Create Request to open a directory.
    pub file_id: FileId,
    /// Offset from the beginning of the SMB2 header to the search pattern.
    /// Set to zero if no search pattern is provided.
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    pub file_name_offset: PosMarker<u16>,
    /// Length in bytes of the search pattern.
    /// Set to zero if no search pattern is provided.
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u16, // in bytes.
    /// The maximum number of bytes the server is allowed to return in the response.
    pub output_buffer_length: u32,
    /// Unicode search pattern for the request with wildcards and other conventions.
    /// Format is specified in MS-CIFS section 2.2.1.1.3.
    #[br(seek_before = SeekFrom::Start(file_name_offset.value as u64))]
    // map stream take until eof:
    #[br(args {size: SizedStringSize::bytes16(file_name_length)})]
    #[bw(write_with = PosMarker::write_aoff, args(&file_name_offset))]
    pub file_name: SizedWideString,
}

/// Flags indicating how the query directory operation must be processed.
///
/// These flags control the behavior of directory enumeration, such as whether
/// to restart the scan from the beginning or return only a single entry.
///
/// Reference: MS-SMB2 section 2.2.33
#[smb_dtyp::mbitfield]
pub struct QueryDirectoryFlags {
    /// The server is requested to restart the enumeration from the beginning.
    pub restart_scans: bool,
    /// The server is requested to only return the first entry of the search results.
    pub return_single_entry: bool,
    /// The server is requested to return entries beginning at the byte number specified by FileIndex.
    pub index_specified: bool,
    /// The server is requested to restart the enumeration from the beginning, and the search pattern is to be changed.
    pub reopen: bool,
    #[skip]
    __: B4,
}

/// SMB2 QUERY_DIRECTORY Response packet containing directory enumeration results.
///
/// This response is sent by a server in response to an SMB2 QUERY_DIRECTORY Request.
/// It contains the directory enumeration data in the format specified by the
/// FileInformationClass in the request.
///
/// Reference: MS-SMB2 section 2.2.34
#[smb_response(size = 9)]
pub struct QueryDirectoryResponse {
    /// Offset in bytes from the beginning of the SMB2 header to the directory enumeration data.
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_buffer_offset: PosMarker<u16>,
    /// Length in bytes of the directory enumeration being returned.
    #[bw(try_calc = output_buffer.len().try_into())]
    #[br(temp)]
    output_buffer_length: u32,
    /// Directory enumeration data in the format specified by the FileInformationClass.
    /// Format is as specified in MS-FSCC section 2.4 for the specific file information class.
    #[br(seek_before = SeekFrom::Start(output_buffer_offset.value as u64))]
    #[br(map_stream = |s| s.take_seek(output_buffer_length as u64), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_aoff, args(&output_buffer_offset))]
    pub output_buffer: Vec<u8>,
}

impl QueryDirectoryResponse {
    /// Reads and parses the output buffer as a vector of directory information entries.
    ///
    /// See viable types for conversions in the `smb-dtyp` crate - [`QueryDirectoryInfoValue`] implementations.
    ///
    /// This method parses the raw output buffer into strongly-typed directory information
    /// structures based on the type parameter T, which should match the FileInformationClass
    /// used in the original request.
    pub fn read_output<T>(&self) -> BinResult<Vec<T>>
    where
        T: QueryDirectoryInfoValue + BinRead + BinWrite,
        for<'a> <T as BinRead>::Args<'a>: Default,
        for<'b> <T as BinWrite>::Args<'b>: Default,
    {
        let mut cursor = std::io::Cursor::new(&self.output_buffer);
        Ok(
            ChainedItemList::<T, { QueryDirectoryInfo::CHAINED_ALIGNMENT }>::read_le(&mut cursor)?
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;
    #[test]
    pub fn test_both_directory_information_attribute_parse() {
        let data = [
            0x70, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x39, 0x75, 0x91, 0xbf, 0xc8, 0x4b, 0xdb, 0x1,
            0xe7, 0xb8, 0x48, 0xcd, 0xc8, 0x5d, 0xdb, 0x1, 0xe7, 0x1b, 0xed, 0xd4, 0x6a, 0x58,
            0xdb, 0x1, 0xe7, 0x1b, 0xed, 0xd4, 0x6a, 0x58, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7b,
            0x80, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x2e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x70, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3c, 0x8, 0x38, 0x96, 0xae, 0x4b, 0xdb, 0x1, 0x10, 0x6a,
            0x87, 0x4b, 0x49, 0x5d, 0xdb, 0x1, 0x62, 0xc, 0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x1, 0x62,
            0xc, 0xcd, 0xc1, 0xc8, 0x4b, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2a, 0xe7, 0x1, 0x0,
            0x0, 0x0, 0x4, 0x0, 0x2e, 0x0, 0x2e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x5b, 0x6c, 0x44, 0xce,
            0x6a, 0x58, 0xdb, 0x1, 0x5b, 0x6c, 0x44, 0xce, 0x6a, 0x58, 0xdb, 0x1, 0x5f, 0xd9, 0xd5,
            0xce, 0x6a, 0x58, 0xdb, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf0, 0xa4, 0x0, 0x0, 0x0, 0x0,
            0xa, 0x0, 0x61, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xd8, 0xce, 0xec, 0xcf, 0x6a, 0x58,
            0xdb, 0x1, 0x7e, 0xc, 0x17, 0xd9, 0x6a, 0x58, 0xdb, 0x1, 0x7e, 0xc, 0x17, 0xd9, 0x6a,
            0x58, 0xdb, 0x1, 0x7e, 0xc, 0x17, 0xd9, 0x6a, 0x58, 0xdb, 0x1, 0x6, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xb9, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x62, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0,
            0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x78, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x57,
            0x8e, 0x2f, 0xd0, 0x6a, 0x58, 0xdb, 0x1, 0xe2, 0xa8, 0xc1, 0xdd, 0x6a, 0x58, 0xdb, 0x1,
            0xe2, 0xa8, 0xc1, 0xdd, 0x6a, 0x58, 0xdb, 0x1, 0xe2, 0xa8, 0xc1, 0xdd, 0x6a, 0x58,
            0xdb, 0x1, 0xe6, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xe8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xbb, 0xf8, 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, 0x63, 0x0,
            0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x32, 0x66, 0x47, 0xd0, 0x6a, 0x58, 0xdb, 0x1, 0x3, 0xc,
            0x39, 0x53, 0x49, 0x5d, 0xdb, 0x1, 0x3, 0xc, 0x39, 0x53, 0x49, 0x5d, 0xdb, 0x1, 0x3,
            0xc, 0x39, 0x53, 0x49, 0x5d, 0xdb, 0x1, 0x26, 0x3e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xbc, 0xf8, 0x0, 0x0,
            0x0, 0x0, 0x4, 0x0, 0x64, 0x0, 0x2e, 0x0, 0x74, 0x0, 0x78, 0x0, 0x74, 0x0,
        ];

        let res = QueryDirectoryResponse {
            output_buffer: data.to_vec(),
        }
        .read_output::<FileIdBothDirectoryInformation>()
        .unwrap();

        assert_eq!(
            vec![
                FileIdBothDirectoryInformation {
                    file_index: 0,
                    creation_time: FileTime::from(datetime!(2024-12-11 12:32:31.7084985)),
                    last_access_time: FileTime::from(datetime!(2025-01-03 10:18:15.6499175)),
                    last_write_time: FileTime::from(datetime!(2024-12-27 14:22:59.9648231)),
                    change_time: FileTime::from(datetime!(2024-12-27 14:22:59.9648231)),
                    end_of_file: 0,
                    allocation_size: 0,
                    file_attributes: FileAttributes::new().with_directory(true),
                    ea_size: Some(0),
                    reparse_tag: None,
                    short_name_length: 0,
                    short_name: Default::default(),
                    file_id: 562949953454203,
                    file_name: ".".into(),
                },
                FileIdBothDirectoryInformation {
                    file_index: 0,
                    creation_time: FileTime::from(datetime!(2024-12-11 9:25:15.4208828)),
                    last_access_time: FileTime::from(datetime!(2025-01-02 19:05:31.8723088)),
                    last_write_time: FileTime::from(datetime!(2024-12-11 12:32:35.4544738)),
                    change_time: FileTime::from(datetime!(2024-12-11 12:32:35.4544738)),
                    end_of_file: 0,
                    allocation_size: 0,
                    file_attributes: FileAttributes::new().with_directory(true),
                    ea_size: Some(0),
                    reparse_tag: None,
                    short_name_length: 0,
                    short_name: Default::default(),
                    file_id: 1125899906967338,
                    file_name: "..".into(),
                },
                FileIdBothDirectoryInformation {
                    file_index: 0,
                    creation_time: FileTime::from(datetime!(2024-12-27 14:22:48.7929947)),
                    last_access_time: FileTime::from(datetime!(2024-12-27 14:22:48.7929947)),
                    last_write_time: FileTime::from(datetime!(2024-12-27 14:22:48.7929947)),
                    change_time: FileTime::from(datetime!(2024-12-27 14:22:49.7460575)),
                    end_of_file: 0,
                    allocation_size: 0,
                    file_attributes: FileAttributes::new().with_archive(true),
                    ea_size: Some(0),
                    reparse_tag: None,
                    short_name_length: 0,
                    short_name: Default::default(),
                    file_id: 2814749767148784,
                    file_name: "a.txt".into(),
                },
                FileIdBothDirectoryInformation {
                    file_index: 0,
                    creation_time: FileTime::from(datetime!(2024-12-27 14:22:51.5742424)),
                    last_access_time: FileTime::from(datetime!(2024-12-27 14:23:06.9505662)),
                    last_write_time: FileTime::from(datetime!(2024-12-27 14:23:06.9505662)),
                    change_time: FileTime::from(datetime!(2024-12-27 14:23:06.9505662)),
                    end_of_file: 6,
                    allocation_size: 8,
                    file_attributes: FileAttributes::new().with_archive(true),
                    ea_size: Some(0),
                    reparse_tag: None,
                    short_name_length: 0,
                    short_name: Default::default(),
                    file_id: 1125899906906297,
                    file_name: "b.txt".into(),
                },
                FileIdBothDirectoryInformation {
                    file_index: 0,
                    creation_time: FileTime::from(datetime!(2024-12-27 14:22:52.0116823)),
                    last_access_time: FileTime::from(datetime!(2024-12-27 14:23:14.7795682)),
                    last_write_time: FileTime::from(datetime!(2024-12-27 14:23:14.7795682)),
                    change_time: FileTime::from(datetime!(2024-12-27 14:23:14.7795682)),
                    end_of_file: 486,
                    allocation_size: 488,
                    file_attributes: FileAttributes::new().with_archive(true),
                    ea_size: Some(0),
                    reparse_tag: None,
                    short_name_length: 0,
                    short_name: Default::default(),
                    file_id: 1125899906906299,
                    file_name: "c.txt".into(),
                },
                FileIdBothDirectoryInformation {
                    file_index: 0,
                    creation_time: FileTime::from(datetime!(2024-12-27 14:22:52.167941),),
                    last_access_time: FileTime::from(datetime!(2025-01-02 19:05:44.7804931),),
                    last_write_time: FileTime::from(datetime!(2025-01-02 19:05:44.7804931),),
                    change_time: FileTime::from(datetime!(2025-01-02 19:05:44.7804931),),
                    end_of_file: 15910,
                    allocation_size: 16384,
                    file_attributes: FileAttributes::new().with_archive(true),
                    ea_size: Some(0),
                    reparse_tag: None,
                    short_name_length: 0,
                    short_name: Default::default(),
                    file_id: 1125899906906300,
                    file_name: "d.txt".into(),
                },
            ],
            res
        );
    }
}

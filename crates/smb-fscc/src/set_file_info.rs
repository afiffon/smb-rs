//! File Information Classes for setting file information.
//!
//! This module exports [`SetFileInfo`] enum and all structs that can be used to set file information.
//!
//! [MS-FSCC 2.4](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1>)

use std::ops::Deref;

use crate::file_info_classes;

use smb_dtyp::binrw_util::prelude::*;

use super::{
    FileBasicInformation, FileFullEaInformation, FileModeInformation, FileNameInformation,
    FilePipeInformation, FilePositionInformation,
};

file_info_classes! {
    /// Set file information classes.
    pub SetFileInfo {
        pub Allocation = 19,
        pub Basic = 4,
        pub Disposition = 13,
        pub EndOfFile = 20,
        pub FullEa = 15,
        pub Link = 11,
        pub Mode = 16,
        pub Pipe = 23,
        pub Position = 14,
        pub Rename = 10,
        pub ShortName = 40,
        pub ValidDataLength = 39,
    }
}

/// Set end-of-file information for a file.
///
/// [MS-FSCC 2.4.14](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/75241cca-3167-472f-8058-a52d77c6bb17>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileEndOfFileInformation {
    /// The absolute new end of file position as a byte offset from the start of the file.
    /// Specifies the offset from the beginning of the file of the byte following the last byte in the file.
    /// That is, it is the offset from the beginning of the file at which new bytes appended to the file will be written.
    /// The value of this field MUST be greater than or equal to 0.
    pub end_of_file: u64,
}

/// Mark a file for deletion.
///
/// [MS-FSCC 2.4.11](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/12c3dd1c-14f6-4229-9d29-75fb2cb392f6>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileDispositionInformation {
    /// Set to TRUE to indicate that a file should be deleted when it is closed; set to FALSE otherwise.
    /// **Note:** Default is TRUE
    pub delete_pending: Boolean,
}

impl Default for FileDispositionInformation {
    fn default() -> Self {
        Self {
            delete_pending: true.into(),
        }
    }
}

/// Rename a file within the SMB2 protocol.
///
/// [MS-FSCC 2.4.42.2](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52aa0b70-8094-4971-862d-79793f41e6a8>) - FileRenameInformation for SMB2 protocol
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileRenameInformation {
    /// Set to TRUE to indicate that if a file with the given name already exists, it should be replaced with the given file. Set to FALSE if the rename operation should fail if a file with the given name already exists.
    pub replace_if_exists: Boolean,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u8,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved3: u32,
    /// A file handle for the root directory. For network operations, this value must be zero.
    pub root_directory: u64,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32,
    /// The new name for the file, including the full path.
    #[br(args { size: SizedStringSize::bytes(_file_name_length) })]
    pub file_name: SizedWideString,
}

/// Set the allocation size for a file.
///
/// The file system is passed a 64-bit signed integer containing the file allocation size, in bytes.
/// The file system rounds the requested allocation size up to an integer multiple of the cluster size for nonresident files,
/// or an implementation-defined multiple for resident files.
/// All unused allocation (beyond EOF) is freed on the last handle close.
///
/// [MS-FSCC 2.4.4](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0201c69b-50db-412d-bab3-dd97aeede13b>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileAllocationInformation {
    /// The new allocation size in bytes. Usually a multiple of the sector or cluster size of the underlying physical device.
    pub allocation_size: u64,
}

/// Create a hard link to an existing file via the SMB Version 2 Protocol, as specified in [MS-SMB2].
///
/// WARNING: This operation is currently unstable and untested, and may lead to data loss or corruption if used improperly!
///
/// [MS-FSCC 2.4.8.2](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/58f44021-120d-4662-bf2c-9905ed4940dc>) - FileLinkInformation for SMB2 protocol
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileLinkInformation {
    /// Set to TRUE to indicate that if a file with the given name already exists, it should be replaced with the given file. Set to FALSE if the link operation should fail if a file with the given name already exists.
    pub replace_if_exists: Boolean,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u8,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved2: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved3: u32,
    /// A file handle for the root directory. For network operations, this value must be zero.
    #[bw(calc = 0)]
    #[br(assert(root_directory == 0))]
    root_directory: u64,
    #[bw(try_calc = file_name.size().try_into())]
    _file_name_length: u32,
    /// The name to be assigned to the newly created link.
    #[br(args {size: SizedStringSize::bytes(_file_name_length)})]
    pub file_name: SizedWideString,
}

/// change a file's short name.
///
/// If the supplied name is of zero length, the file's existing short name, if any,
/// SHOULD be deleted.
/// Otherwise, the supplied name MUST be a valid short name as specified in section 2.1.5.2.1
/// and be unique among all file names and short names in the same directory as the file being operated on.
/// A caller changing the file's short name MUST have SeRestorePrivilege.
///
/// [MS-FSCC 2.4.46](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/80cecad8-9172-4c42-af90-f890a84f2abc>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileShortNameInformation {
    /// The short name information, following the same structure as FileNameInformation.
    inner: FileNameInformation,
}

impl Deref for FileShortNameInformation {
    type Target = FileNameInformation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// set the valid data length information for a file.
///
/// A file's valid data length is the length, in bytes, of the data that has been written to the file.
/// This valid data extends from the beginning of the file to the last byte in the file that has not been zeroed or left uninitialized
///
/// [MS-FSCC 2.4.49](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5c9f9d50-f0e0-40b1-9b84-0b78f59158b1>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileValidDataLengthInformation {
    /// The new valid data length for the file.
    /// This parameter must be a positive value that is greater than the current valid data length, but less than or equal to the current file size.
    pub valid_data_length: u64,
}

#[cfg(test)]
mod tests {
    use crate::FileAttributes;

    use super::*;
    use smb_tests::*;
    use time::macros::datetime;

    test_binrw! {
        struct FileAllocationInformation {
            allocation_size: 500,
        } => "f401000000000000"
    }

    test_binrw! {
        struct FileEndOfFileInformation {
            end_of_file: 777,
        } => "0903000000000000"
    }

    test_binrw! {
        struct FileDispositionInformation {
            delete_pending: true.into(),
        } => "01"
    }

    test_binrw_read! {
        struct FileRenameInformation {
            replace_if_exists: false.into(),
            root_directory: 0,
            file_name: SizedWideString::from("b.txt"),
        } => "0002750062006c0000000000000000000a00000062002e00740078007400"
    }

    test_binrw_write! {
        struct FileRenameInformation {
            replace_if_exists: false.into(),
            root_directory: 0,
            file_name: SizedWideString::from("b.txt"),
        } => "000000000000000000000000000000000a00000062002e00740078007400"
    }

    test_binrw! {
        struct FileBasicInformation {
            creation_time: FileTime::ZERO,
            last_access_time: FileTime::ZERO,
            last_write_time: datetime!(2025-04-11 17:24:47.489599300).into(),
            change_time: datetime!(2025-04-11 17:24:47.489599300).into(),
            file_attributes: FileAttributes::new(),
        } => "00000000000000000000000000000000790eb19f06abdb01790eb19f06abdb010000000000000000"
    }

    test_binrw! {
        struct FileValidDataLengthInformation {
            valid_data_length: 0x123456789,
        } => "8967452301000000"
    }

    test_binrw! {
        struct FileShortNameInformation {
            inner: FileNameInformation {
                file_name: SizedWideString::from("SHORTN~1.TXT"),
            },
        } => "18000000530048004f00520054004e007e0031002e00540058005400"
    }

    // TODO: the following test is currently missing.
    //     pub Link = 11,
}

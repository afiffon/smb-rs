//! Set Info Request/Response messages and related types.

use crate::FileId;

use super::{NullByte, common::*};
#[cfg(feature = "server")]
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use smb_dtyp::{SecurityDescriptor, binrw_util::prelude::*};
use smb_fscc::*;
use smb_msg_derive::*;

/// SMB2 SET_INFO request packet for setting information on a file or object store.
///
/// Used by clients to set file information, filesystem information, security information,
/// or quota information on files or underlying object stores.
/// The structure size is fixed at 33 bytes regardless of buffer length.
///
/// MS-SMB2 2.2.39
#[smb_request(size = 33)]
pub struct SetInfoRequest {
    /// Type of information being set (File=0x01, FileSystem=0x02, Security=0x03, Quota=0x04)
    #[bw(calc = data.info_type())]
    #[br(temp)]
    pub info_type: InfoType,
    /// Information class indicating the specific type of information to set
    pub info_class: SetInfoClass,
    /// Length in bytes of the information to be set
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    buffer_length: PosMarker<u32>,
    /// Offset from SMB2 header to the information buffer
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _buffer_offset: PosMarker<u16>,
    reserved: u16,
    /// Additional information for security operations or 0 for other operations
    pub additional_information: AdditionalInfo,
    /// File identifier of the file or named pipe on which to perform the set operation
    pub file_id: FileId,
    /// Variable-length buffer containing the information being set
    #[br(map_stream = |s| s.take_seek(buffer_length.value as u64))]
    #[br(args(info_type))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_buffer_offset, &buffer_length))]
    pub data: SetInfoData,
}

query_info_data! {
    SetInfoData
    File: RawSetInfoData<SetFileInfo>,
    FileSystem: RawSetInfoData<SetFileSystemInfo>,
    Security: SecurityDescriptor,
    Quota: ChainedItemList<FileQuotaInformation>,
}

/// Information class specifying the type of information to set.
///
/// Defines the specific information class for each info type category.
/// For Security and Quota operations, the class is set to null byte (0).
///
/// MS-SMB2 2.2.39
#[smb_message_binrw]
pub enum SetInfoClass {
    /// File information class (e.g., FileBasicInformation, FileRenameInformation)
    File(SetFileInfoClass),
    /// Filesystem information class (e.g., FileFsControlInformation)
    FileSystem(SetFileSystemInfoClass),
    /// Security information class (always 0)
    Security(NullByte),
    /// Quota information class (always 0)
    Quota(NullByte),
}

impl From<SetFileInfoClass> for SetInfoClass {
    fn from(val: SetFileInfoClass) -> Self {
        SetInfoClass::File(val)
    }
}

impl From<SetFileSystemInfoClass> for SetInfoClass {
    fn from(val: SetFileSystemInfoClass) -> Self {
        SetInfoClass::FileSystem(val)
    }
}

impl SetInfoData {
    /// Creates a SetInfoRequest from this data with the specified parameters.
    ///
    /// Validates that the info class and data combination are compatible before
    /// creating the request structure.
    ///
    /// # Panics
    ///
    /// Panics if the info class and data type combination is invalid
    /// (e.g., File class with FileSystem data).
    pub fn to_req(
        self,
        info_class: SetInfoClass,
        file_id: FileId,
        additional_info: AdditionalInfo,
    ) -> SetInfoRequest {
        // Validate the info class and data combination
        // to ensure they are compatible.
        match (&info_class, &self) {
            (SetInfoClass::File(_), SetInfoData::File(_)) => {}
            (SetInfoClass::FileSystem(_), SetInfoData::FileSystem(_)) => {}
            (SetInfoClass::Security(_), SetInfoData::Security(_)) => {}
            (SetInfoClass::Quota(_), SetInfoData::Quota(_)) => {}
            _ => panic!("Invalid info class and data combination"),
        }

        SetInfoRequest {
            info_class,
            additional_information: additional_info,
            file_id,
            data: self,
        }
    }
}

/// SMB2 SET_INFO response packet indicating successful completion.
///
/// Sent by the server to notify the client that the SET_INFO request
/// has been successfully processed. Contains only the structure size field.
///
/// MS-SMB2 2.2.40
#[smb_response(size = 2)]
#[derive(Default)]
pub struct SetInfoResponse {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use smb_dtyp::*;

    test_request! {
        SetInfo {
            info_class: SetInfoClass::File(SetFileInfoClass::RenameInformation),
            data: SetInfoData::from(RawSetInfoData::from(SetFileInfo::RenameInformation(FileRenameInformation {
                replace_if_exists: false.into(),
                root_directory: 0,
                file_name: "hello\\myNewFile.txt".into(),
            }))),
            file_id: make_guid!("00000042-000e-0000-0500-10000e000000").into(),
            additional_information: AdditionalInfo::new(),
        } => "2100010a3a0000006000000000000000420000000e000000050010000e0000000000000000000000000000000000000026000000680065006c006c006f005c006d0079004e0065007700460069006c0065002e00740078007400"
    }

    test_binrw_response! {
        struct SetInfoResponse {} => "0200"
    }
}

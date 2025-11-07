//! SMB2 Set Info Request/Response messages.

use crate::{FileId, query_info_data};

use super::{NullByte, common::*};
#[cfg(feature = "server")]
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use smb_dtyp::{SecurityDescriptor, binrw_util::prelude::*};
use smb_fscc::*;
use smb_msg_derive::*;

#[smb_request(size = 33)]
pub struct SetInfoRequest {
    #[bw(calc = data.info_type())]
    #[br(temp)]
    pub info_type: InfoType,
    pub info_class: SetInfoClass,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    buffer_length: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _buffer_offset: PosMarker<u16>,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,
    pub additional_information: AdditionalInfo,
    pub file_id: FileId,
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

/// A helper class for [SetInfoRequest] to contain the information
/// class to set. In cases of no class, it will be set to a null byte (0u8).
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub enum SetInfoClass {
    File(SetFileInfoClass),
    FileSystem(SetFileSystemInfoClass),
    Security(NullByte),
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
    /// This is a helper function to convert the [SetInfoData] to
    /// a [SetInfoRequest].
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

#[smb_response(size = 2)]
#[derive(Default)]
pub struct SetInfoResponse {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use smb_dtyp::*;
    use smb_tests::*;

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

    test_binrw! {
        struct SetInfoResponse {} => "0200"
    }
}

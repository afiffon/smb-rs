use binrw::{io::TakeSeekExt, prelude::*};
use smb_dtyp::SID;
use smb_dtyp::binrw_util::prelude::*;

/// Query or to set file quota information for a volume.
///
/// For queries, an optional buffer of FILE_GET_QUOTA_INFORMATION (section 2.4.41.1) data elements is provided by the client to specify the SIDs for which quota information is requested.
/// If the FILE_GET_QUOTA_INFORMATION buffer is not specified, information for all quotas is returned.
/// A buffer of FILE_QUOTA_INFORMATION data elements is returned by the server.
/// For sets, FILE_QUOTA_INFORMATION data elements are populated and sent by the client,
/// as specified in [MS-SMB] section 2.2.7.6.1 and [MS-SMB2] section 3.2.4.15.<145>
///
/// [MS-FSCC 2.4.41](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/acdc0738-ba3c-47a1-b11a-72e22d831c57>)
///
/// _Note_: This structure is partial: it does not contain the NextEntryOffset field, as it is intended to be used
/// in a chained list, see [`ChainedItemList<T>`][crate::ChainedItemList].
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileQuotaInformation {
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    sid_length: PosMarker<u32>,
    pub change_time: FileTime,
    pub quota_used: u64,
    pub quota_threshold: u64,
    pub quota_limit: u64,
    #[br(map_stream = |s| s.take_seek(sid_length.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&sid_length))]
    pub sid: SID,
}

impl FileQuotaInformation {
    /// Minimum size of this structure in bytes.
    pub const MIN_SIZE: usize = std::mem::size_of::<u32>()
        + std::mem::size_of::<FileTime>()
        + std::mem::size_of::<u64>()
        + std::mem::size_of::<u64>()
        + std::mem::size_of::<u64>()
        + SID::MIN_SIZE;
}

/// This structure is used to provide the list of SIDs for which quota query information is requested.
///
/// [MS-FSCC 2.4.41.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/56adae21-add4-4434-97ec-e40e87739d52>)
///
/// _Note_: This structure is partial: it does not contain the NextEntryOffset field, as it is intended to be used
/// in a chained list, see [`ChainedItemList<T>`][crate::ChainedItemList].
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileGetQuotaInformation {
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    sid_length: PosMarker<u32>,
    #[br(map_stream = |s| s.take_seek(sid_length.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&sid_length))]
    pub sid: SID,
}

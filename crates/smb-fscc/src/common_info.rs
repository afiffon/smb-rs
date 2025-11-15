//! File Information Classes for getting/setting file information, and common structs.
//!
//! See [crate::QueryFileInfo] and [crate::SetFileInfo] enums.
//!
//! [MS-FSCC 2.4](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1>)

#![allow(clippy::identity_op)]

use std::ops::Deref;

use binrw::{NullString, prelude::*};
use modular_bitfield::prelude::*;

use smb_dtyp::binrw_util::prelude::*;

use crate::{ChainedItemList, FileAttributes};

/// Query or Set file information.
///
/// [MS-FSCC 2.4.7](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/16023025-8a78-492f-8b96-c873b042ac50>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileBasicInformation {
    /// The time when the file was created.
    pub creation_time: FileTime,
    /// The time when the file was last accessed.
    pub last_access_time: FileTime,
    /// The time when data was last written to the file.
    pub last_write_time: FileTime,
    /// The time when the file was last changed.
    pub change_time: FileTime,
    /// The file attributes.
    pub file_attributes: FileAttributes,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u32,
}

/// Query or Set extended attribute (EA) information for a file.
///
/// [MS-FSCC 2.4.16](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFullEaInformationInner {
    /// Can contain zero or more of the following flag values. Unused bit fields should be set to 0.
    pub flags: EaFlags,
    #[bw(try_calc = ea_name.len().try_into())]
    ea_name_length: u8,
    #[bw(calc = ea_value.len() as u16)]
    ea_value_length: u16,
    /// The name of the extended attribute. This field is not null-terminated.
    #[br(assert(ea_name.len() == ea_name_length as usize))]
    pub ea_name: NullString,
    /// The value of the extended attribute. This field can be zero bytes in length.
    #[br(count = ea_value_length)]
    pub ea_value: Vec<u8>,
}

/// Extended Attribute (EA) Flags
///
/// See [`FileFullEaInformationInner`]
#[smb_dtyp::mbitfield]
#[repr(u8)]
pub struct EaFlags {
    #[skip]
    __: B7,
    /// If this flag is set, the file to which the EA belongs cannot be interpreted by applications that do not understand EAs.
    pub file_need_ea: bool,
}

pub type FileFullEaInformation = ChainedItemList<FileFullEaInformationInner, 4>;

/// Query or Set file mode information.
///
/// [MS-FSCC 2.4.31](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52df7798-8330-474b-ac31-9afe8075640c>)
#[smb_dtyp::mbitfield]
pub struct FileModeInformation {
    #[skip]
    __: bool,
    /// When set, system caching is not performed on the file.
    pub write_through: bool,
    /// When set, all access to the file is sequential.
    pub sequential_access: bool,
    /// When set, the file cannot be cached or buffered in a driver's internal buffers.
    pub no_intermediate_buffering: bool,

    /// When set, all operations on the file are performed synchronously. Waits in the system to synchronize I/O queuing and completion are alertable.
    pub synchronous_io_alert: bool,
    /// When set, all operations on the file are performed synchronously. Waits in the system to synchronize I/O queuing and completion are not alertable.
    pub synchronous_io_non_alert: bool,
    #[skip]
    __: B6,

    /// When set, the file will be deleted when the last handle to the file is closed.
    pub delete_on_close: bool,
    #[skip]
    __: B19,
}

/// Query or Set named pipe information.
///
/// [MS-FSCC 2.4.37](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/cd805dd2-9248-4024-ac0f-b87a702dd366>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePipeInformation {
    /// The named pipe read mode.
    pub read_mode: PipeReadMode,
    /// The named pipe completion mode.
    pub completion_mode: PipeCompletionMode,
}

/// Named pipe read mode values.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum PipeReadMode {
    /// Data is read from the pipe as a stream of bytes.
    Stream = 0,
    /// Data is read from the pipe as a stream of messages.
    Message = 1,
}

/// Named pipe completion mode values.
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum PipeCompletionMode {
    /// Blocking mode is enabled. When the pipe handle is specified in a call to the ReadFile or WriteFile function, the operations are not completed until there is data to read or all data is written.
    Queue = 0,
    /// Nonblocking mode is enabled. When the pipe handle is specified in a call to the ReadFile or WriteFile function, the operations complete immediately.
    Complete = 1,
}

/// Query or Set the current byte offset of the file pointer.
///
/// [MS-FSCC 2.4.40](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e3ce4a39-327e-495c-99b6-6b61606b6f16>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FilePositionInformation {
    /// The byte offset of the file pointer from the beginning of the file.
    pub current_byte_offset: u64,
}

/// Query the name of a file.
///
/// [MS-FSCC 2.4.32](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/cb30e415-54c5-4483-a346-822ea90e1e89>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileNameInformation {
    #[bw(try_calc = file_name.size().try_into())]
    file_name_length: u32,
    /// The full path name of the file.
    #[br(args { size: SizedStringSize::bytes(file_name_length)})]
    pub file_name: SizedWideString,
}

impl Deref for FileNameInformation {
    type Target = SizedWideString;

    fn deref(&self) -> &Self::Target {
        &self.file_name
    }
}

impl From<SizedWideString> for FileNameInformation {
    fn from(value: SizedWideString) -> Self {
        Self { file_name: value }
    }
}

impl From<&str> for FileNameInformation {
    fn from(value: &str) -> Self {
        Self {
            file_name: SizedWideString::from(value),
        }
    }
}

/// Reparse Tag Values
///
/// Each reparse point has a reparse tag.
/// The reparse tag uniquely identifies the owner of that reparse point.
/// The owner is the implementer of the file system filter driver associated with a reparse tag.
///
/// [MS-FSCC 2.1.2.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4>):
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[repr(u32)]
#[brw(repr(u32))]
pub enum ReparseTag {
    /// Reserved reparse tag value.
    ReservedZero = 0x00000000,

    /// Reserved reparse tag value.
    ReservedOne = 0x00000001,

    /// Reserved reparse tag value.
    ReservedTwo = 0x00000002,

    /// Used for mount point support, specified in section 2.1.2.5.
    MountPoint = 0xA0000003,

    /// Obsolete. Used by legacy Hierarchical Storage Manager Product.
    HSM = 0xC0000004,

    /// Home server drive extender.<3>
    DriveExtender = 0x80000005,

    /// Obsolete. Used by legacy Hierarchical Storage Manager Product.
    HSM2 = 0x80000006,

    /// Used by single-instance storage (SIS) filter driver. Server-side interpretation only, not meaningful over the wire.
    SIS = 0x80000007,

    /// Used by the WIM Mount filter. Server-side interpretation only, not meaningful over the wire.
    WIM = 0x80000008,

    /// Obsolete. Used by Clustered Shared Volumes (CSV) version 1 in Windows Server 2008 R2 operating system. Server-side interpretation only, not meaningful over the wire.
    CSV = 0x80000009,

    /// Used by the DFS filter. The DFS is described in the Distributed File System (DFS): Referral Protocol Specification [MS-DFSC]. Server-side interpretation only, not meaningful over the wire.
    DFS = 0x8000000A,

    /// Used by filter manager test harness.<4>
    FilterManager = 0x8000000B,

    /// Used for symbolic link support. See section 2.1.2.4.
    Symlink = 0xA000000C,

    /// Used by Microsoft Internet Information Services (IIS) caching. Server-side interpretation only, not meaningful over the wire.
    IISCache = 0xA0000010,

    /// Used by the DFS filter. The DFS is described in [MS-DFSC]. Server-side interpretation only, not meaningful over the wire.
    DFSR = 0x80000012,

    /// Used by the Data Deduplication (Dedup) filter. Server-side interpretation only, not meaningful over the wire.
    Dedup = 0x80000013,

    /// Not used.
    Appxstrm = 0xC0000014,

    /// Used by the Network File System (NFS) component. Server-side interpretation only, not meaningful over the wire.
    NFS = 0x80000014,

    /// Obsolete. Used by Windows Shell for legacy placeholder files in Windows 8.1. Server-side interpretation only, not meaningful over the wire.
    FilePlaceholder = 0x80000015,

    /// Used by the Dynamic File filter. Server-side interpretation only, not meaningful over the wire.
    DFM = 0x80000016,

    /// Used by the Windows Overlay filter, for either WIMBoot or single-file compression. Server-side interpretation only, not meaningful over the wire.
    WOF = 0x80000017,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WCI = 0x80000018,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    Wci1 = 0x90001018,

    /// Used by NPFS to indicate a named pipe symbolic link from a server silo into the host silo. Server-side interpretation only, not meaningful over the wire.
    GlobalReparse = 0xA0000019,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as Microsoft OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud = 0x9000001A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud1 = 0x9000101A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud2 = 0x9000201A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud3 = 0x9000301A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud4 = 0x9000401A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud5 = 0x9000501A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud6 = 0x9000601A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud7 = 0x9000701A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud8 = 0x9000801A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    Cloud9 = 0x9000901A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudA = 0x9000A01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudB = 0x9000B01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudC = 0x9000C01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudD = 0x9000D01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudE = 0x9000E01A,

    /// Used by the Cloud Files filter, for files managed by a sync engine such as OneDrive. Server-side interpretation only, not meaningful over the wire.
    CloudF = 0x9000F01A,

    /// Used by Universal Windows Platform (UWP) packages to encode information that allows the application to be launched by CreateProcess. Server-side interpretation only, not meaningful over the wire.
    Appexeclink = 0x8000001B,

    /// Used by the Windows Projected File System filter, for files managed by a user mode provider such as VFS for Git. Server-side interpretation only, not meaningful over the wire.
    Projfs = 0x9000001C,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX symbolic link. Server-side interpretation only, not meaningful over the wire.
    LxSymlink = 0xA000001D,

    /// Used by the Azure File Sync (AFS) filter. Server-side interpretation only, not meaningful over the wire.
    StorageSync = 0x8000001E,

    /// Used by the Azure File Sync (AFS) filter for folder. Server-side interpretation only, not meaningful over the wire.
    StorageSyncFolder = 0x90000027,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WciTombstone = 0xA000001F,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    Unhandled = 0x80000020,

    /// Not used.
    Onedrive = 0x80000021,

    /// Used by the Windows Projected File System filter, for files managed by a user mode provider such as VFS for Git. Server-side interpretation only, not meaningful over the wire.
    ProjfsTombstone = 0xA0000022,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX domain socket. Server-side interpretation only, not meaningful over the wire.
    AfUnix = 0x80000023,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX FIFO (named pipe). Server-side interpretation only, not meaningful over the wire.
    LxFifo = 0x80000024,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX character special file. Server-side interpretation only, not meaningful over the wire.
    LxChr = 0x80000025,

    /// Used by the Windows Subsystem for Linux (WSL) to represent a UNIX block special file. Server-side interpretation only, not meaningful over the wire.
    LxBlk = 0x80000026,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WciLink = 0xA0000027,

    /// Used by the Windows Container Isolation filter. Server-side interpretation only, not meaningful over the wire.
    WciLink1 = 0xA0001027,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_tests::*;

    test_binrw! {
        FileFullEaInformation: FileFullEaInformation::from(vec![
            FileFullEaInformationInner {
                flags: EaFlags::new(),
                ea_name: "$CI.CATALOGHINT".into(),
                ea_value: vec![0x1, 0x0, 0x63, 0x0, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2d, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x2d, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x2d, 0x52, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65, 0x64, 0x2d, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x30, 0x34, 0x31, 0x30, 0x32, 0x31, 0x7e, 0x33, 0x31, 0x62, 0x66, 0x33, 0x38, 0x35, 0x36, 0x61, 0x64, 0x33, 0x36, 0x34, 0x65, 0x33, 0x35, 0x7e, 0x61, 0x72, 0x6d, 0x36, 0x34, 0x7e, 0x7e, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x32, 0x32, 0x36, 0x32, 0x31, 0x2e, 0x35, 0x31, 0x38, 0x35, 0x2e, 0x63, 0x61, 0x74]
            },
            FileFullEaInformationInner {
                flags: EaFlags::new(),
                ea_name: "SKTEXT".into(),
                ea_value: vec![0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x72, 0x65, 0x61, 0x6c, 0x6c, 0x79, 0x20, 0x74, 0x68, 0x65, 0x20, 0x53, 0x4b, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x6a, 0x75, 0x73, 0x74, 0x20, 0x73, 0x6f, 0x6d, 0x65, 0x20, 0x66, 0x61, 0x6b, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x68, 0x61, 0x76, 0x65, 0x20, 0x73, 0x6f, 0x6d, 0x65, 0x20, 0x66, 0x75, 0x6e, 0x0]
            },
        ]) => "80000000000f67002443492e434154414c4f4748494e5400010063004d6963726f736f66742d57696e646f77732d436c69656e742d4465736b746f702d52657175697265642d5061636b6167653034313032317e333162663338353661643336346533357e61726d36347e7e31302e302e32323632312e353138352e636174000000000000064100534b544558540054686973206973206e6f74207265616c6c792074686520534b2c206974206973206a75737420736f6d652066616b6520746f206861766520736f6d652066756e00"
    }

    test_binrw! {
        struct FilePipeInformation {
            read_mode: PipeReadMode::Message,
            completion_mode: PipeCompletionMode::Queue,
        } => "0100000000000000"
    }
}

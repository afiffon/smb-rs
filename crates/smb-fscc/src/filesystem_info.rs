//! File System Information Classes
//!
//! This module defined [`QueryFileSystemInfo`] and [`SetFileSystemInfo`] enums,
//! and all the information structs in those.
//!
//! [MS-FSCC 2.5](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ee12042a-9352-46e3-9f67-c094b75fe6c3>)

use crate::file_info_classes;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::{Guid, binrw_util::prelude::*};

file_info_classes! {
    /// Query file system information classes.
    pub QueryFileSystemInfo {
        pub FsAttribute = 5,
        pub FsControl = 6,
        pub FsDevice = 4,
        pub FsFullSize = 7,
        pub FsObjectId = 8,
        pub FsSectorSize = 11,
        pub FsSize = 3,
        pub FsVolume = 1,
    }
}

file_info_classes! {
    /// Set file system information classes.
    pub SetFileSystemInfo {
        pub FsControl = 6,
        pub FsObjectId = 8,
    }
}

/// Query attribute information for a file system.
///
/// [MS-FSCC 2.5.1](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ebc7e6e5-4650-4e54-b17c-cf60f6fbeeaa>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsAttributeInformation {
    /// Contains a bitmask of flags that specify attributes of the specified file system as a combination of the following flags.
    /// The value of this field MUST be a bitwise OR of zero or more of the following with the exception that FILE_FILE_COMPRESSION and FILE_VOLUME_IS_COMPRESSED cannot both be set.
    /// Any flag values not explicitly mentioned here can be set to any value, and MUST be ignored.
    pub attributes: FileSystemAttributes,
    /// The maximum file name component length, in characters, supported by the specified file system.
    /// The value of this field MUST be greater than zero and MUST be no more than 255.
    pub maximum_component_name_length: u32,
    #[bw(calc = file_system_name.size() as u32)]
    pub file_system_name_length: u32,
    /// the name of the file system. This field is not null-terminated and MUST be handled as a sequence of FileSystemNameLength bytes.
    /// This field is intended to be informative only. A client SHOULD NOT infer file system type specific behavior from this field.
    #[br(args { size: SizedStringSize::bytes(file_system_name_length) })]
    pub file_system_name: SizedWideString,
}

/// File system attributes.
///
/// Used in [`FileFsAttributeInformation`]
#[smb_dtyp::mbitfield]
pub struct FileSystemAttributes {
    /// The file system supports case-sensitive file names when looking up (searching for) file names in a directory.
    pub case_sensitive_search: bool,
    /// The file system preserves the case of file names when it places a name on disk.
    pub case_preserved_names: bool,
    /// The file system supports Unicode in file and directory names. This flag applies only to file and directory names; the file system neither restricts nor interprets the bytes of data within a file.
    pub unicode_on_disk: bool,
    /// The file system preserves and enforces access control lists (ACLs).
    pub persistent_acls: bool,
    /// The file volume supports file-based compression. This flag is incompatible with the `volume_is_compressed` flag.
    pub file_compression: bool,
    /// The file system supports per-user quotas.
    pub volume_quotas: bool,
    /// The file system supports sparse files.
    pub supports_sparse_files: bool,
    /// The file system supports reparse points.
    pub supports_reparse_points: bool,
    /// The file system supports remote storage.
    pub supports_remote_storage: bool,
    #[skip]
    __: B6,
    /// The specified volume is a compressed volume. This flag is incompatible with the `file_compression` flag.
    pub volume_is_compressed: bool,
    /// The file system supports object identifiers.
    pub supports_object_ids: bool,
    /// The file system supports the Encrypted File System (EFS).
    pub supports_encryption: bool,
    /// The file system supports named streams.
    pub named_streams: bool,
    /// If set, the volume has been mounted in read-only mode.
    pub read_only_volume: bool,
    /// The underlying volume is write once.
    pub sequential_write_once: bool,
    /// The volume supports transactions.
    pub supports_transactions: bool,
    /// The file system supports hard linking files.
    pub supports_hard_links: bool,
    /// The file system persistently stores Extended Attribute information per file.
    pub supports_extended_attributes: bool,
    /// The file system supports opening a file by FileID or ObjectID.
    pub supports_open_by_file_id: bool,
    /// The file system implements a USN change journal.
    pub supports_usn_journal: bool,
    /// The file system supports integrity streams.
    pub support_integrity_streams: bool,
    /// The file system supports sharing logical clusters between files on the same volume. The file system reallocates on writes to shared clusters. Indicates that `FSCTL_DUPLICATE_EXTENTS_TO_FILE` is a supported operation.
    pub supports_block_refcounting: bool,
    /// The file system tracks whether each cluster of a file contains valid data (either from explicit file writes or automatic zeros) or invalid data (has not yet been written to or zeroed). File systems that use Sparse VDL do not store a valid data length and do not require that valid data be contiguous within a file.
    pub supports_sparse_vdl: bool,
    #[skip]
    __: B3,
}

/// Query or Set quota and content indexing control information for a file system volume.
///
/// Setting quota information requires the caller to have permission to open a volume handle or a handle to the quota index file for write access.
///
/// [MS-FSCC 2.5.2](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e5a70738-7ee4-46d9-a5f7-6644daa49a51>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsControlInformation {
    /// The minimum amount of free disk space, in bytes, that is required for the operating system's content indexing service to begin document filtering. This value SHOULD be set to 0 and MUST be ignored.
    pub free_space_start_filtering: u64,
    /// The minimum amount of free disk space, in bytes, that is required for the indexing service to continue to filter documents and merge word lists. This value SHOULD be set to 0 and MUST be ignored.
    pub free_space_threshold: u64,
    /// The minimum amount of free disk space, in bytes, that is required for the content indexing service to continue filtering. This value SHOULD be set to 0, and MUST be ignored.
    pub free_space_stop_filtering: u64,
    /// The default per-user disk quota warning threshold, in bytes, for the volume. A value of [`u64::MAX`] specifies that no default quota warning threshold per user is set.
    pub default_quota_threshold: u64,
    /// The default per-user disk quota limit, in bytes, for the volume. A value of [`u64::MAX`] specifies that no default quota limit per user is set.
    pub default_quota_limit: u64,
    /// Contains a bitmask of flags that control quota enforcement and logging of user-related quota events on the volume.
    pub file_system_control_flags: FileSystemControlFlags,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsDeviceInformation {
    /// This identifies the type of given volume.
    pub device_type: FsDeviceType,
    /// A bit field which identifies various characteristics about a given volume.
    pub characteristics: FsDeviceCharacteristics,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u32))]
pub enum FsDeviceType {
    /// Volume resides on a CD ROM.
    CdRom = 2,
    /// Volume resides on a disk.
    Disk = 7,
}

/// Characteristics of a file system volume.
///
/// See [`FileFsDeviceInformation`]
#[smb_dtyp::mbitfield]
pub struct FsDeviceCharacteristics {
    /// Indicates that the storage device supports removable media.
    /// Notice that this characteristic indicates removable media, not a removable device.
    /// For example, drivers for JAZ drive devices specify this characteristic, but drivers for PCMCIA flash disks do not.
    pub removable_media: bool,
    /// Indicates that the device cannot be written to.
    pub read_only: bool,
    /// Indicates that the device is a floppy disk device.
    pub floppy_diskette: bool,
    /// Indicates that the device supports write-once media.
    pub write_once_media: bool,

    /// Indicates that the volume is for a remote file system like SMB or CIFS.
    pub remote: bool,
    /// Indicates that a file system is mounted on the device.
    pub device_is_mounted: bool,
    /// Indicates that the volume does not directly reside on storage media but resides on some other type of media (memory for example).
    pub virtual_volume: bool,
    #[skip]
    __: bool,

    /// By default, volumes do not check the ACL associated with the volume, but instead use the ACLs associated with individual files on the volume.
    /// When this flag is set the volume ACL is also checked.
    pub secure_open: bool,
    #[skip]
    __: B3,

    /// Indicates that the device object is part of a Terminal Services device stack. See [MS-RDPBCGR] for more information.
    pub ts: bool,
    /// Indicates that a web-based Distributed Authoring and Versioning (WebDAV) file system is mounted on the device. See [MS-WDVME] for more information.
    pub webda: bool,
    #[skip]
    __: B3,

    /// The IO Manager normally performs a full security check for traverse access on every file open when the client is an appcontainer.
    /// Setting of this flag bypasses this enforced traverse access check if the client token already has traverse privileges.
    pub allow_appcontainer_traversal: bool,
    /// Indicates that the given device resides on a portable bus like USB or Firewire and that the entire device (not just the media) can be removed from the system.
    pub portable: bool,
    #[skip]
    __: B13,
}

/// File system control flags.
///
/// Used in [`FileFsControlInformation`]
#[smb_dtyp::mbitfield]
pub struct FileSystemControlFlags {
    /// Quotas are tracked on the volume, but they are not enforced.
    /// Tracked quotas enable reporting on the file system space used by system users.
    /// If both this flag and FILE_VC_QUOTA_ENFORCE are specified, FILE_VC_QUOTA_ENFORCE is ignored.
    ///
    /// Note: This flag takes precedence over FILE_VC_QUOTA_ENFORCE.
    /// In other words, if both FILE_VC_QUOTA_TRACK and FILE_VC_QUOTA_ENFORCE are set,
    /// the FILE_VC_QUOTA_ENFORCE flag is ignored.
    /// This flag will be ignored if a client attempts to set it.
    pub quota_track: bool,
    /// Quotas are tracked and enforced on the volume.
    ///
    /// Note: FILE_VC_QUOTA_TRACK takes precedence over this flag.
    /// In other words, if both FILE_VC_QUOTA_TRACK and FILE_VC_QUOTA_ENFORCE are set,
    /// the FILE_VC_QUOTA_ENFORCE flag is ignored.
    /// This flag will be ignored if a client attempts to set it.
    pub quota_enforce: bool,
    /// Content indexing is disabled.
    pub content_indexing_disabled: bool,
    #[skip]
    __: bool,

    /// An event log entry will be created when the user exceeds his or her assigned quota warning threshold.
    pub log_quota_threshold: bool,
    /// An event log entry will be created when the user exceeds the assigned disk quota limit.
    pub log_quota_limit: bool,
    /// An event log entry will be created when the volume's free space threshold is exceeded.
    pub log_volume_threshold: bool,
    /// An event log entry will be created when the volume's free space limit is exceeded.
    pub log_volume_limit: bool,

    /// The quota information for the volume is incomplete because it is corrupt, or the system is in the process of rebuilding the quota information.
    /// Note: This does not necessarily imply that FILE_VC_QUOTAS_REBUILDING is set. This flag will be ignored if a client attempts to set it.
    pub quotas_incomplete: bool,

    /// The file system is rebuilding the quota information for the volume.
    /// Note: This does not necessarily imply that FILE_VC_QUOTAS_INCOMPLETE is set. This flag will be ignored if a client attempts to set it.
    pub quotas_rebuilding: bool,
    #[skip]
    __: B22,
}

/// Query sector size information for a file system volume.
///
/// [MS-FSCC 2.5.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/63768db7-9012-4209-8cca-00781e7322f5)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsFullSizeInformation {
    pub total_allocation_units: u64,
    pub caller_available_allocation_units: u64,
    pub actual_available_allocation_units: u64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

/// Query or Set the object ID for a file system data element. The operation MUST fail if the file system does not support object IDs.
///
/// [MS-FSCC 2.5.6](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/dbf535ae-315a-4508-8bc5-84276ea106d4>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsObjectIdInformation {
    /// Identifies the file system volume on the disk. This value is not required to be unique on the system.
    pub object_id: Guid,
    /// A 48-byte value containing extended information on the file system volume. If no extended information has been written for this file system volume, the server MUST return 48 bytes of 0x00 in this field.
    pub extended_info: [u8; 48],
}

/// Query for the extended sector size and alignment information for a volume.
///
/// The message contains a FILE_FS_SECTOR_SIZE_INFORMATION data element.
///
/// [MS-FSCC 2.5.7](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/3e75d97f-1d0b-4e47-b435-73c513837a57>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsSectorSizeInformation {
    /// The number of bytes in a logical sector for the device backing the volume.
    /// This field is the unit of logical addressing for the device and is not the unit of atomic write.
    ///  Applications SHOULD NOT utilize this value for operations requiring physical sector alignment.
    pub logical_bytes_per_sector: u32,
    /// The number of bytes in a physical sector for the device backing the volume.
    /// Note that this is the reported physical sector size of the device and is the unit of atomic write.
    /// Applications SHOULD utilize this value for operations requiring sector alignment.
    pub physical_bytes_per_sector: u32,
    /// The number of bytes in a physical sector for the device backing the volume.
    /// This is the reported physical sector size of the device and is the unit of performance.
    /// Applications SHOULD utilize this value for operations requiring sector alignment.
    pub physical_bytes_per_sector_for_performance: u32,
    /// The unit, in bytes, that the file system on the volume will use for internal operations that require alignment and atomicity.
    pub effective_physical_bytes_per_sector_for_atomicity: u32,
    /// Flags for this operation.
    pub flags: SectorSizeInfoFlags,
    /// The logical sector offset within the first physical sector where the first logical sector is placed, in bytes.
    /// If this value is set to SSINFO_OFFSET_UNKNOWN (0XFFFFFFFF), there was insufficient information to compute this field.
    pub byte_offset_for_sector_alignment: u32,
    /// The byte offset from the first physical sector where the first partition is placed.
    /// If this value is set to SSINFO_OFFSET_UNKNOWN (0XFFFFFFFF),
    /// there was either insufficient information or an error was encountered in computing this field.
    pub byte_offset_for_partition_alignment: u32,
}

/// File system sector flags.
#[smb_dtyp::mbitfield]
pub struct SectorSizeInfoFlags {
    /// When set, this flag indicates that the first physical sector of the device is aligned with the first logical sector.
    /// When not set, the first physical sector of the device is misaligned with the first logical sector.
    pub aligned_device: bool,
    /// When set, this flag indicates that the partition is aligned to physical sector boundaries on the storage device.
    pub partition_aligned_on_device: bool,
    /// When set, the device reports that it does not incur a seek penalty (this typically indicates that the device does not have rotating media, such as flash-based disks).
    pub no_seek_penalty: bool,
    /// When set, the device supports TRIM operations, either T13 (ATA) TRIM or T10 (SCSI/SAS) UNMAP.
    pub trim_enabled: bool,
    #[skip]
    __: B28,
}

/// Query sector size information for a file system volume.
///
/// [MS-FSCC 2.5.8](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e13e068c-e3a7-4dd4-94fd-3892b492e6e7>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsSizeInformation {
    /// The total number of allocation units on the volume that are available to the user associated with the calling thread. This value MUST be greater than or equal to 0.
    pub total_allocation_units: u64,
    /// The total number of free allocation units on the volume that are available to the user associated with the calling thread. This value MUST be greater than or equal to 0.
    pub available_allocation_units: u64,
    /// The number of sectors in each allocation unit.
    pub sectors_per_allocation_unit: u32,
    /// The number of bytes in each sector.
    pub bytes_per_sector: u32,
}

/// Query information on a volume on which a file system is mounted.
///
/// [MS-FSCC 2.5.9](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/bf691378-c34e-4a13-976e-404ea1a87738>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct FileFsVolumeInformation {
    /// The time when the volume was created.
    pub volume_creation_time: FileTime,
    /// C contains the serial number of the volume.
    /// The serial number is an opaque value generated by the file system at format time,
    /// and is not necessarily related to any hardware serial number for the device on which the file system is located.
    /// No specific format or content of this field is required for protocol interoperation.
    /// This value is not required to be unique.
    pub volume_serial_number: u32,
    #[bw(calc = volume_label.size() as u32)]
    pub volume_label_length: u32,
    ///  Set to TRUE if the file system supports object-oriented file system objects; set to FALSE otherwise.
    pub supports_objects: Boolean,
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u8,
    /// The content of this field can be a null-terminated string or can be a string padded with the space character to be VolumeLabelLength bytes long.
    #[br(args { size: SizedStringSize::bytes(volume_label_length) })]
    pub volume_label: SizedWideString,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_dtyp::make_guid;
    use smb_tests::*;
    use time::macros::datetime;

    test_binrw! {
        struct FileFsVolumeInformation {
            volume_creation_time: datetime!(2025-10-13 12:35:04.593237).into(),
            volume_serial_number: 0x529d2cf4,
            volume_label: "MyShare".into(),
            supports_objects: false.into(),
        } => "525119cd3d3cdc01f42c9d520e00000000004d00790053006800610072006500"
    }

    test_binrw! {
        struct FileFsSizeInformation {
            total_allocation_units: 61202244,
            available_allocation_units: 45713576,
            sectors_per_allocation_unit: 2,
            bytes_per_sector: 512,
        } => "44dfa50300000000a888b902000000000200000000020000"
    }

    test_binrw! {
        struct FileFsFullSizeInformation {
            total_allocation_units: 0x03a5df44,
            actual_available_allocation_units: 0x02b98894,
            caller_available_allocation_units: 0x02b98894,
            sectors_per_allocation_unit: 2,
            bytes_per_sector: 512,
        } => "44dfa503000000009488b902000000009488b902000000000200000000020000"
    }

    test_binrw! {
        struct FileFsDeviceInformation {
            device_type: FsDeviceType::Disk,
            characteristics: FsDeviceCharacteristics::new().with_device_is_mounted(true),
        } => "0700000020000000"
    }

    test_binrw! {
        struct FileFsAttributeInformation {
            attributes: FileSystemAttributes::new()
                .with_case_sensitive_search(true)
                .with_case_preserved_names(true)
                .with_unicode_on_disk(true)
                .with_persistent_acls(true)
                .with_volume_quotas(true)
                .with_supports_sparse_files(true)
                .with_supports_object_ids(true)
                .with_named_streams(true),
            maximum_component_name_length: 255,
            file_system_name: "NTFS".into(),
        } => "6f000500ff000000080000004e00540046005300"
    }

    test_binrw! {
        struct FileFsSectorSizeInformation {
            logical_bytes_per_sector: 512,
            physical_bytes_per_sector: 512,
            physical_bytes_per_sector_for_performance: 512,
            effective_physical_bytes_per_sector_for_atomicity: 512,
            flags: SectorSizeInfoFlags::new()
                .with_aligned_device(true)
                .with_partition_aligned_on_device(true),
            byte_offset_for_sector_alignment: 0,
            byte_offset_for_partition_alignment: 0,
        } => "00020000000200000002000000020000030000000000000000000000"
    }

    test_binrw! {
        struct FileFsObjectIdInformation {
            object_id: make_guid!("ed3e2170-2733-48b3-e5c0-bd5334f85a37"),
            extended_info: [0x61, 0x42, 0x6d, 0x53, 0x0, 0x6, 0x14, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x34, 0x2e, 0x32, 0x30, 0x2e,
                            0x36, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
        } => "70213eed3327b348e5c0bd5334f85a3761426d5300061404000000000000000000000000342e32302e3600000000000000000000000000000000000000000000"
    }
}

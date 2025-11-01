//! File attributes definition.
//!
//! [MS-FSCC 2.6](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca28ec38-f155-4768-81d6-4bfeb8586fc9>)

use binrw::prelude::*;
use modular_bitfield::prelude::*;

/// Attributes of a file or directory.
///
/// They can be used in any combination unless noted in the description of the attribute's meaning
///
/// [MS-FSCC 2.6](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca28ec38-f155-4768-81d6-4bfeb8586fc9>)
#[smb_dtyp::mbitfield]
pub struct FileAttributes {
    /// A file or directory that is read-only.
    /// For a file, applications can read the file but cannot write to it or delete it.
    /// For a directory, applications cannot delete it,
    /// but applications can create and delete files from that directory.
    pub readonly: bool,
    /// A file or directory that is hidden.
    /// Files and directories marked with this attribute do not appear in an ordinary directory listing.
    pub hidden: bool,
    /// A file or directory that the operating system uses a part of or uses exclusively.
    pub system: bool,
    #[skip]
    __: bool,

    /// This item is a directory.
    pub directory: bool,
    /// A file or directory that requires to be archived.
    /// Applications use this attribute to mark files for backup or removal.
    pub archive: bool,
    #[skip]
    __: bool,
    /// A file that does not have other attributes set.
    /// This flag is used to clear all other flags by specifying it with no other flags set.
    /// This flag MUST be ignored if other flags are set.
    pub normal: bool,

    /// A file that is being used for temporary storage.
    /// The operating system can choose to store this file's data in memory rather than on mass storage,
    /// writing the data to mass storage only if data remains in the file when the file is closed.
    pub temporary: bool,
    /// A file that is a sparse file.
    pub sparse_file: bool,
    /// A file or directory that has an associated reparse point.
    pub reparse_point: bool,
    /// A file or directory that is compressed. For a file, all of the data in the file is compressed.
    /// For a directory, compression is the default for newly created files and subdirectories.
    pub compressed: bool,

    /// The data in this file is not available immediately.
    /// This attribute indicates that the file data is physically moved to offline storage.
    /// This attribute is used by Remote Storage, which is hierarchical storage management software.
    pub offline: bool,
    /// A file or directory that is not indexed by the content indexing service.
    pub not_content_indexed: bool,
    /// A file or directory that is encrypted.
    /// For a file, all data streams in the file are encrypted.
    /// For a directory, encryption is the default for newly created files and subdirectories.
    pub encrypted: bool,
    /// A file or directory that is configured with integrity support.
    /// For a file, all data streams in the file have integrity support.
    /// For a directory, integrity support is the default for newly created files and subdirectories, unless the caller specifies otherwise.
    pub integrity_stream: bool,

    #[skip]
    __: bool,
    /// A file or directory that is configured to be excluded from the data integrity scan.
    /// For a directory configured with FILE_ATTRIBUTE_NO_SCRUB_DATA,
    /// the default for newly created files and subdirectories is to inherit the FILE_ATTRIBUTE_NO_SCRUB_DATA attribute.
    pub no_scrub_data: bool,
    /// This attribute appears only in directory enumeration classes.
    /// When this attribute is set, it means that the file or directory has no physical representation on the local system; the item is virtual.
    /// Opening the item will be more expensive than usual because it will cause at least some of the file or directory content to be fetched from a remote store.
    /// This attribute can only be set by kernel-mode components. This attribute is for use with hierarchical storage management software.
    pub recall_on_open: bool,
    /// This attribute indicates user intent that the file or directory should be kept fully present locally even when not being actively accessed.
    /// This attribute is for use with hierarchical storage management software.
    pub pinned: bool,

    /// This attribute indicates that the file or directory should not be kept fully present locally except when being actively accessed.
    /// This attribute is for use with hierarchical storage management software.
    pub unpinned: bool,
    #[skip]
    __: bool,
    /// When this attribute is set, it means that the file or directory is not fully present locally.
    /// For a file this means that not all of its data is on local storage (for example, it may be sparse with some data still in remote storage).
    /// For a directory it means that some of the directory contents are being virtualized from another location.
    /// Reading the file or enumerating the directory will be more expensive than usual because it will cause at least some of the file or directory content to be fetched from a remote store.
    /// Only kernel-mode callers can set this attribute. This attribute is for use with hierarchical storage management software.
    pub recall_on_data_access: bool,
    #[skip]
    __: B9,
}

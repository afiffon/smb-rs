//! ## File System Control Codes ([MS-FSCC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/efbfe127-73ad-4140-9967-ec6500e66d5e)) For SMB
//!
//! The FSCC types are widely used in SMB messages.
//! This module contains implementation of many structs supported in SMB from the FSCC specification,
//! to allow a wide variety of SMB operations, with a well defined, convenient typing system,
//! and with an extensive set of structures.
//!
//! This crate also contains common utility structures to wrap around common FSCC structures.
//!
//! The crate contains the following implementations:
//! * File information [`QueryFileInfo`], [`SetFileInfo`]
//! * File system information [`QueryFileSystemInfo`], [`SetFileSystemInfo`]
//! * Directory query types [`QueryDirectoryInfo`]
//! * Change notifications [`FileNotifyInformation`]
//! * Access masks [`FileAccessMask`], [`DirAccessMask`]

#![allow(unused_parens)]
#![forbid(unsafe_code)]

mod access_masks;
mod chained_list;
mod common_info;
mod directory_info;
mod error;
mod file_attributes;
mod filesystem_info;
mod info_classes;
mod notify;
mod query_file_info;
mod quota;
mod set_file_info;

pub use access_masks::*;
pub use chained_list::{CHAINED_ITEM_PREFIX_SIZE, ChainedItemList};
pub use common_info::*;
pub use directory_info::*;
pub use error::SmbFsccError;
pub use file_attributes::*;
pub use filesystem_info::*;
pub use info_classes::*;
pub use notify::*;
pub use query_file_info::*;
pub use quota::*;
pub use set_file_info::*;

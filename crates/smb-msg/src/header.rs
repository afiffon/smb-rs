//! Plain Message Header and related types.

use std::io::Cursor;

use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_msg_derive::{smb_message_binrw, smb_request_response};

/// SMB2/SMB3 protocol command codes.
///
/// Reference: MS-SMB2 2.2.1.2
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum Command {
    Negotiate = 0,
    SessionSetup = 1,
    Logoff = 2,
    TreeConnect = 3,
    TreeDisconnect = 4,
    Create = 5,
    Close = 6,
    Flush = 7,
    Read = 8,
    Write = 9,
    Lock = 0xA,
    Ioctl = 0xB,
    Cancel = 0xC,
    Echo = 0xD,
    QueryDirectory = 0xE,
    ChangeNotify = 0xF,
    QueryInfo = 0x10,
    SetInfo = 0x11,
    OplockBreak = 0x12,
    ServerToClientNotification = 0x13,
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_as_string = match self {
            Command::Negotiate => "Negotiate",
            Command::SessionSetup => "Session Setup",
            Command::Logoff => "Logoff",
            Command::TreeConnect => "Tree Connect",
            Command::TreeDisconnect => "Tree Disconnect",
            Command::Create => "Create",
            Command::Close => "Close",
            Command::Flush => "Flush",
            Command::Read => "Read",
            Command::Write => "Write",
            Command::Lock => "Lock",
            Command::Ioctl => "Ioctl",
            Command::Cancel => "Cancel",
            Command::Echo => "Echo",
            Command::QueryDirectory => "Query Directory",
            Command::ChangeNotify => "Change Notify",
            Command::QueryInfo => "Query Info",
            Command::SetInfo => "Set Info",
            Command::OplockBreak => "Oplock Break",
            Command::ServerToClientNotification => "Server to Client Notification",
        };
        write!(f, "{} ({:#x})", message_as_string, *self as u16)
    }
}

macro_rules! make_status {
    (
        $($name:ident = $value:literal: $description:literal, )+
    ) => {

/// NT Status codes for SMB.
///
/// For each status code, a U32 constant is also provided for easier access.
/// for example, [`Status::U32_END_OF_FILE`] is `0xC0000011`, matching [`Status::EndOfFile`].
#[smb_message_binrw]
#[derive(Clone, Copy)]
#[repr(u32)]
#[brw(repr(u32))]
pub enum Status {
    $(
        #[doc = concat!($description, " (", stringify!($value), ")")]
        $name = $value,
    )+
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_as_string = match self {
            $(
                Status::$name => $description,
            )+
        };
        write!(f, "{} ({:#x})", message_as_string, *self as u32)
    }
}

impl Status {
    // Consts for easier status code as u32 access.
    pastey::paste! {
        $(
            #[doc = concat!("[`", stringify!($name), "`][Self::", stringify!($name), "] as u32")]
            pub const [<U32_ $name:snake:upper>]: u32 = $value;
        )+
    }

    /// A helper function that tries converting u32 to a [`Status`],
    /// and returns a string representation of the status. Otherwise,
    /// it returns the hex representation of the u32 value.
    /// This is useful for displaying NT status codes that are not necessarily
    /// defined in the [`Status`] enum.
    pub fn try_display_as_status(value: u32) -> String {
        match Self::try_from(value) {
            Ok(status) => format!("{}", status),
            Err(_) => format!("{:#06x}", value),
        }
    }
}

impl TryFrom<u32> for Status {
    type Error = crate::SmbMsgError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Status::read_le(&mut Cursor::new(value.to_le_bytes())).map_err(|_| {
            Self::Error::MissingErrorCodeDefinition(value)
        })
    }
}
    };
}

make_status! {
    Success = 0x00000000: "Success",
    Pending = 0x00000103: "Pending",
    NotifyCleanup = 0x0000010B: "Notify Cleanup",
    NotifyEnumDir = 0x0000010C: "Notify Enum Dir",
    InvalidSmb = 0x00010002: "Invalid SMB",
    SmbBadTid = 0x00050002: "SMB Bad TID",
    SmbBadCommand = 0x00160002: "SMB Bad Command",
    SmbBadUid = 0x005B0002: "SMB Bad UID",
    SmbUseStandard = 0x00FB0002: "SMB Use Standard",
    BufferOverflow = 0x80000005: "Buffer Overflow",
    NoMoreFiles = 0x80000006: "No More Files",
    StoppedOnSymlink = 0x8000002D: "Stopped on Symlink",
    NotImplemented = 0xC0000002: "Not Implemented",
    InvalidInfoClass = 0xC0000003: "Invalid Info Class",
    InfoLengthMismatch = 0xC0000004: "Info Length Mismatch",
    InvalidParameter = 0xC000000D: "Invalid Parameter",
    NoSuchDevice = 0xC000000E: "No Such Device",
    InvalidDeviceRequest0 = 0xC0000010: "Invalid Device Request",
    EndOfFile = 0xC0000011: "End of File",
    MoreProcessingRequired = 0xC0000016: "More Processing Required",
    AccessDenied = 0xC0000022: "Access Denied",
    BufferTooSmall = 0xC0000023: "Buffer Too Small",
    ObjectNameInvalid = 0xC0000033: "Object Name Invalid",
    ObjectNameNotFound = 0xC0000034: "Object Name Not Found",
    ObjectNameCollision = 0xC0000035: "Object Name Collision",
    SharingViolation = 0xC0000043: "Sharing Violation",
    ObjectPathNotFound = 0xC000003A: "Object Path Not Found",
    NoEasOnFile = 0xC0000044: "No EAs on File",
    LogonFailure = 0xC000006D: "Logon Failure",
    NotMapped = 0xC0000073: "Not Mapped",
    BadImpersonationLevel = 0xC00000A5: "Bad Impersonation Level",
    IoTimeout = 0xC00000B5: "I/O Timeout",
    FileIsADirectory = 0xC00000BA: "File is a Directory",
    NotSupported = 0xC00000BB: "Not Supported",
    NetworkNameDeleted = 0xC00000C9: "Network Name Deleted",
    BadNetworkName = 0xC00000CC: "Bad Network Name",
    RequestNotAccepted = 0xC00000D0: "Request Not Accepted",
    DirectoryNotEmpty = 0xC0000101: "Directory Not Empty",
    Cancelled = 0xC0000120: "Cancelled",
    UserSessionDeleted = 0xC0000203: "User Session Deleted",
    UserAccountLockedOut = 0xC0000234: "User Account Locked Out",
    PathNotCovered = 0xC0000257: "Path Not Covered",
    NetworkSessionExpired = 0xC000035C: "Network Session Expired",
    SmbTooManyUids = 0xC000205A: "SMB Too Many UIDs",
    DeviceFeatureNotSupported = 0xC0000463: "Device Feature Not Supported",
}

/// SMB2 Packet Header.
///
/// Common header structure for all SMB2/SMB3 messages, supporting both
/// synchronous and asynchronous operations.
///
/// Reference: MS-SMB2 2.2.1.1, 2.2.1.2
#[smb_request_response(size = 64)]
#[derive(Clone)]
#[brw(magic(b"\xfeSMB"), little)]
pub struct Header {
    /// Number of credits charged for this request.
    pub credit_charge: u16,
    /// NT status code. Use [`Header::status()`] to convert to [`Status`].
    pub status: u32,
    /// Command code identifying the request/response type.
    pub command: Command,
    /// Number of credits requested or granted.
    pub credit_request: u16,
    /// Header flags indicating message properties.
    pub flags: HeaderFlags,
    /// Offset to next message in a compounded request chain (0 if not compounded).
    pub next_command: u32,
    /// Unique message identifier.
    pub message_id: u64,

    // Option 1 - Sync: Reserved + TreeId. flags.async_command MUST NOT be set.
    #[brw(if(!flags.async_command()))]
    #[bw(calc = 0)]
    _reserved: u32,
    /// Tree identifier (synchronous operations only).
    #[br(if(!flags.async_command()))]
    #[bw(assert(tree_id.is_some() != flags.async_command()))]
    pub tree_id: Option<u32>,

    // Option 2 - Async: AsyncId. flags.async_command MUST be set manually.
    #[brw(if(flags.async_command()))]
    #[bw(assert(tree_id.is_none() == flags.async_command()))]
    pub async_id: Option<u64>,

    /// Unique session identifier.
    pub session_id: u64,
    /// Message signature for signed messages.
    pub signature: u128,
}

impl Header {
    pub const STRUCT_SIZE: usize = 64;

    /// Tries to convert the [`Header::status`] field to a [`Status`],
    /// returning it, if successful.
    pub fn status(&self) -> crate::Result<Status> {
        self.status.try_into()
    }

    /// Turns the current header into an async header,
    /// setting the [`async_id`][Self::async_id] and clearing the [`tree_id`][Self::tree_id].
    /// Also sets the [`HeaderFlags::async_command`] in [`flags`][Self::flags] to true.
    pub fn to_async(&mut self, async_id: u64) {
        self.flags.set_async_command(true);
        self.tree_id = None;
        self.async_id = Some(async_id);
    }
}

/// SMB2 header flags.
///
/// Indicates how to process the operation.
///
/// Reference: MS-SMB2 2.2.1.2
#[smb_dtyp::mbitfield]
pub struct HeaderFlags {
    /// Message is a server response (set in responses).
    pub server_to_redir: bool,
    /// Message is part of an asynchronous operation.
    pub async_command: bool,
    /// Request is a related operation in a compounded chain.
    pub related_operations: bool,
    /// Message is signed.
    pub signed: bool,
    /// Priority mask for quality of service.
    pub priority_mask: B3,
    #[skip]
    __: B21,
    /// Request is a DFS operation.
    pub dfs_operation: bool,
    /// Request is a replay operation for resilient handles.
    pub replay_operation: bool,
    #[skip]
    __: B2,
}

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use super::*;

    test_binrw! {
        Header => async: Header {
            credit_charge: 0,
            status: Status::Pending as u32,
            command: Command::ChangeNotify,
            credit_request: 1,
            flags: HeaderFlags::new()
                .with_async_command(true)
                .with_server_to_redir(true)
                .with_priority_mask(1),
            next_command: 0,
            message_id: 8,
            tree_id: None,
            async_id: Some(8),
            session_id: 0x00000000085327d7,
            signature: u128::from_le_bytes(u128::to_be_bytes(
                0x63f825deae02952fa3d8c8aaf46e7c99
            )),
        } => "fe534d4240000000030100000f000100130000000000000008000000000000000800000000000000d72753080000000063f825deae02952fa3d8c8aaf46e7c99"
    }
}

//! Change Notify Request and Response, and Server to Client Notification messages and related types.

#[cfg(feature = "client")]
use std::io::SeekFrom;

#[cfg(feature = "client")]
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_msg_derive::*;

use super::FileId;
use smb_dtyp::binrw_util::prelude::*;
use smb_fscc::*;

/// SMB2 CHANGE_NOTIFY Request packet sent by the client to request change
/// notifications on a directory. The client can monitor changes on any file
/// or directory contained beneath the specified directory.
///
/// Reference: MS-SMB2 2.2.35
#[smb_request(size = 32)]
pub struct ChangeNotifyRequest {
    /// Flags indicating how the operation must be processed.
    pub flags: NotifyFlags,
    /// Maximum number of bytes the server is allowed to return in the response.
    pub output_buffer_length: u32,
    /// File identifier of the directory to monitor for changes.
    pub file_id: FileId,
    /// Specifies the types of changes to monitor. Multiple trigger conditions can be chosen.
    pub completion_filter: NotifyFilter,
    reserved: u32,
}

/// Flags for SMB2 CHANGE_NOTIFY Request indicating how the operation must be processed.
///
/// Reference: MS-SMB2 2.2.35
#[smb_dtyp::mbitfield]
pub struct NotifyFlags {
    /// The request must monitor changes on any file or directory contained
    /// beneath the directory specified by FileId.
    pub watch_tree: bool,
    #[skip]
    __: B15,
}

/// Completion filter specifying the types of changes to monitor.
/// Multiple trigger conditions can be chosen. If any condition is met,
/// the client is notified and the CHANGE_NOTIFY operation is completed.
///
/// Reference: MS-SMB2 2.2.35
#[smb_dtyp::mbitfield]
pub struct NotifyFilter {
    /// Client is notified if a file name changes.
    pub file_name: bool,
    /// Client is notified if a directory name changes.
    pub dir_name: bool,
    /// Client is notified if a file's attributes change.
    pub attributes: bool,
    /// Client is notified if a file's size changes.
    pub size: bool,

    /// Client is notified if the last write time of a file changes.
    pub last_write: bool,
    /// Client is notified if the last access time of a file changes.
    pub last_access: bool,
    /// Client is notified if the creation time of a file changes.
    pub creation: bool,
    /// Client is notified if a file's extended attributes change.
    pub ea: bool,

    /// Client is notified of a file's access control list settings change.
    pub security: bool,
    /// Client is notified if a named stream is added to a file.
    pub stream_name: bool,
    /// Client is notified if the size of a named stream is changed.
    pub stream_size: bool,
    /// Client is notified if a named stream is modified.
    pub stream_write: bool,

    #[skip]
    __: B20,
}

impl NotifyFilter {
    pub fn all() -> Self {
        Self::new()
            .with_file_name(true)
            .with_dir_name(true)
            .with_attributes(true)
            .with_size(true)
            .with_last_write(true)
            .with_last_access(true)
            .with_creation(true)
            .with_ea(true)
            .with_security(true)
            .with_stream_name(true)
            .with_stream_size(true)
            .with_stream_write(true)
    }
}

/// SMB2 CHANGE_NOTIFY Response packet sent by the server to transmit the
/// results of a client's SMB2 CHANGE_NOTIFY Request. Contains an array of
/// FILE_NOTIFY_INFORMATION structures describing the changes.
///
/// Reference: MS-SMB2 2.2.36
#[smb_response(size = 9)]
pub struct ChangeNotifyResponse {
    /// Offset in bytes from the beginning of the SMB2 header to the change information.
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _output_buffer_offset: PosMarker<u16>,
    /// Length in bytes of the change information being returned.
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _output_buffer_length: PosMarker<u32>,
    /// Array of FILE_NOTIFY_INFORMATION structures containing the change information.
    #[br(seek_before = SeekFrom::Start(_output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(_output_buffer_length.value.into()))]
    #[bw(if(!buffer.is_empty()))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_output_buffer_offset, &_output_buffer_length))]
    pub buffer: ChainedItemList<FileNotifyInformation, 4>,
}

/// SMB2 Server to Client Notification packet sent by the server to indicate
/// an implementation-specific intent without expecting any response from the client.
///
/// Reference: MS-SMB2 2.2.44.1
#[smb_response_binrw]
pub struct ServerToClientNotification {
    /// Size of the SMB2_SERVER_TO_CLIENT_NOTIFICATION structure.
    structure_size: u16,
    reserved: u16,
    /// Valid SMB_NOTIFICATION_ID enumeration notification type value.
    #[bw(calc = notification.get_type())]
    notification_type: NotificationType,
    /// Corresponding structure type based on the notification type.
    #[br(args(notification_type))]
    pub notification: Notification,
}

/// SMB_NOTIFICATION_ID enumeration values for server to client notifications.
///
/// Reference: MS-SMB2 2.2.44.1
#[smb_response_binrw]
#[derive(Clone, Copy)]
#[brw(repr(u32))]
pub enum NotificationType {
    /// Indicates the notification structure is SMB2_NOTIFY_SESSION_CLOSED.
    NotifySessionClosed = 0,
}

/// Notification structure containing the specific notification data
/// based on the notification type.
///
/// Reference: MS-SMB2 2.2.44.1
#[smb_response_binrw]
#[br(import(notification_type: NotificationType))]
pub enum Notification {
    /// Session closed notification structure.
    #[br(pre_assert(notification_type == NotificationType::NotifySessionClosed))]
    NotifySessionClosed(NotifySessionClosed),
}

impl Notification {
    pub fn get_type(&self) -> NotificationType {
        match self {
            Notification::NotifySessionClosed(_) => NotificationType::NotifySessionClosed,
        }
    }
}

/// SMB2_NOTIFY_SESSION_CLOSED structure embedded within the
/// SMB2_SERVER_TO_CLIENT_NOTIFICATION structure when the notification
/// type is SmbNotifySessionClosed.
///
/// Reference: MS-SMB2 2.2.44.2
#[smb_response_binrw]
pub struct NotifySessionClosed {
    reserved: u32,
}

#[cfg(test)]
mod tests {
    use crate::*;
    use smb_dtyp::guid::Guid;

    use super::*;

    test_binrw_request! {
        struct ChangeNotifyRequest {
            flags: NotifyFlags::new(),
            output_buffer_length: 2048,
            file_id: "000005d1-000c-0000-1900-00000c000000"
                .parse::<Guid>()
                .unwrap()
                .into(),
            completion_filter: NotifyFilter::new()
                .with_file_name(true)
                .with_dir_name(true)
                .with_attributes(true)
                .with_last_write(true),
        } => "2000000000080000d10500000c000000190000000c0000001700000000000000"
    }

    test_binrw_response! {
        struct ChangeNotifyResponse => pending {
            buffer: Default::default(),
        } => "0900000000000000"
    }

    test_response! {
        change_notify_with_data: ChangeNotify {
            buffer: vec![
                FileNotifyInformation {
                    action: NotifyAction::RenamedOldName,
                    file_name: "New folder".into()
                },
                FileNotifyInformation {
                    action: NotifyAction::RenamedNewName,
                    file_name: "jdsa".into()
                }
            ]
            .into()
        } => "09004800340000002000000004000000140000004e0065007700200066006f006c006400650072000000000005000000080000006a00640073006100"
    }

    test_response_read! {
        change_notify_azure: ChangeNotify {
            buffer: vec![
                FileNotifyInformation {
                    action: NotifyAction::Added,
                    file_name: "11.txt".into()
                },
                FileNotifyInformation {
                    action: NotifyAction::Added,
                    file_name: "kernel.bin.til".into()
                },
                FileNotifyInformation {
                    action: NotifyAction::Added,
                    file_name: "ec2-3-70-222-69.eu-central-1.compute.amazonaws.com.rdp".into()
                },
                FileNotifyInformation {
                    action: NotifyAction::Added,
                    file_name: "ec2-18-198-51-98.eu-central-1.compute.amazonaws.com.rdp".into()
                },
                FileNotifyInformation {
                    action: NotifyAction::Added,
                    file_name: "Test DC.rdp".into()
                }
            ]
            .into()
        } => "090048006001000018000000010000000c000000310031002e0074007800740028000000010000001c0000006b00650072006e0065006c002e00620069006e002e00740069006c0078000000010000006c0000006500630032002d0033002d00370030002d003200320032002d00360039002e00650075002d00630065006e007400720061006c002d0031002e0063006f006d0070007500740065002e0061006d0061007a006f006e006100770073002e0063006f006d002e0072006400700080000000010000006e0000006500630032002d00310038002d003100390038002d00350031002d00390038002e00650075002d00630065006e007400720061006c002d0031002e0063006f006d0070007500740065002e0061006d0061007a006f006e006100770073002e0063006f006d002e007200640070006f557361676500000000010000001600000054006500730074002000440043002e00720064007000726e65744567"
    }
}

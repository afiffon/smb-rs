//! SMB2 Change Notify Request and Response, and Server to Client Notification
use std::io::SeekFrom;

use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_msg_derive::{smb_request, smb_response};

use super::FileId;
use smb_dtyp::binrw_util::prelude::*;
use smb_fscc::*;

#[smb_request(size = 32)]
pub struct ChangeNotifyRequest {
    pub flags: NotifyFlags,
    pub output_buffer_length: u32,
    pub file_id: FileId,
    pub completion_filter: NotifyFilter,
    #[bw(calc = 0)]
    _reserved: u32,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NotifyFlags {
    pub watch_tree: bool,
    #[skip]
    __: B15,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct NotifyFilter {
    pub file_name: bool,
    pub dir_name: bool,
    pub attributes: bool,
    pub size: bool,

    pub last_write: bool,
    pub last_access: bool,
    pub creation: bool,
    pub ea: bool,

    pub security: bool,
    pub stream_name: bool,
    pub stream_size: bool,
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

#[smb_response(size = 9)]
pub struct ChangeNotifyResponse {
    #[bw(calc = PosMarker::default())]
    _output_buffer_offset: PosMarker<u16>,
    #[bw(calc = PosMarker::default())]
    _output_buffer_length: PosMarker<u32>,
    #[br(seek_before = SeekFrom::Start(_output_buffer_offset.value.into()))]
    #[br(map_stream = |s| s.take_seek(_output_buffer_length.value.into()))]
    #[bw(if(!buffer.is_empty()))]
    #[bw(write_with = PosMarker::write_aoff_size, args(&_output_buffer_offset, &_output_buffer_length))]
    pub buffer: ChainedItemList<FileNotifyInformation, 4>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ServerToClientNotification {
    structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
    #[bw(calc = notification.get_type())]
    notification_type: NotificationType,
    #[br(args(notification_type))]
    pub notification: Notification,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u32))]
pub enum NotificationType {
    NotifySessionClosed = 0,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(notification_type: NotificationType))]
pub enum Notification {
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

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct NotifySessionClosed {
    #[bw(calc = 0)]
    _reserved: u32,
}

#[cfg(test)]
mod tests {
    use crate::*;
    use smb_dtyp::guid::Guid;
    use smb_tests::*;

    use super::*;

    test_binrw! {
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

    test_binrw! {
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

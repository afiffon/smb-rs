//! Full plain message implementation.

use binrw::prelude::*;

use super::header::*;
use super::*;
use smb_msg_derive::*;

/// Makes the [`RequestContent`] & [`ResponseContent`] methods
macro_rules! make_content_impl {
    (
        $struct_name:ident,
        $({$variant:ident, $struct_type:ty},)+
    ) => {
        pastey::paste! {

impl $struct_name {
    /// Returns the name of the content value.
    pub fn content_name(&self) -> &'static str {
        use $struct_name::*;
        match self {
            $(
                [<$variant>](_) => stringify!([<$variant>]),
            )+
        }
    }

    $(
        #[doc = concat!("Attempts to cast the current content type to [", stringify!($struct_type),"].")]
        pub fn [<to_ $variant:lower>](self) -> crate::Result<$struct_type> {
            match self {
                $struct_name::[<$variant>](req) => Ok(req),
                _ => Err(crate::SmbMsgError::UnexpectedContent{
                    expected: stringify!([<$variant>]),
                    actual: self.content_name(),
                }),
            }
        }

        #[doc = concat!("Attempts to cast the current content type to [", stringify!($struct_type),"].")]
        pub fn [<as_ $variant:lower>](&self) -> crate::Result<&$struct_type> {
            match self {
                $struct_name::[<$variant>](req) => Ok(req),
                _ => Err(crate::SmbMsgError::UnexpectedContent{
                    expected: stringify!([<$variant>]),
                    actual: self.content_name(),
                }),
            }
        }

        #[doc = concat!("Attempts to cast the current content type to [", stringify!($struct_type),"].")]
        pub fn [<as_mut_ $variant:lower>](&mut self) -> crate::Result<&mut $struct_type> {
            match self {
                $struct_name::[<$variant>](req) => Ok(req),
                _ => Err(crate::SmbMsgError::UnexpectedContent{
                    expected: stringify!([<$variant>]),
                    actual: self.content_name(),
                }),
            }
        }
    )+
}
        }
    };
}

/// Internal, one-use-macro to generate the request-response pairs for the [`RequestContent`] & [`ResponseContent`] enums.
/// In addition, it appends the special cases.
macro_rules! make_content {
    (
        $({$cmd:ident, $struct_pfx:ident},)+
    ) => {
        pastey::paste!{

/// Contains all the variants for a plain SMB2 request message.
///
/// For example - read/write/create/close requests, etc.
#[smb_request_binrw]
#[brw(import(command: &Command))]
#[brw(little)]
pub enum RequestContent {
    $(
        #[br(pre_assert(matches!(command, Command::$cmd)))]
        $cmd($struct_pfx::[<$cmd Request>]),
    )*

    // cancel request
    #[br(pre_assert(matches!(command, Command::Cancel)))]
    Cancel(cancel::CancelRequest),

    // oplock
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    OplockBreakAck(oplock::OplockBreakAck),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    LeaseBreakAck(oplock::LeaseBreakAck),
}

/// Contains all the variants for a plain SMB2 response message.
///
/// For example - read/write/create/close responses, etc.
#[smb_response_binrw]
#[brw(import(command: &Command))]
#[brw(little)]
pub enum ResponseContent {
    $(
        #[br(pre_assert(matches!(command, Command::$cmd)))]
        $cmd($struct_pfx::[<$cmd Response>]),
    )*

    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    OplockBreakNotify(oplock::OplockBreakNotify),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    LeaseBreakNotify(oplock::LeaseBreakNotify),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    OplockBreak(oplock::OplockBreakResponse),
    #[br(pre_assert(matches!(command, Command::OplockBreak)))]
    LeaseBreak(oplock::LeaseBreakResponse),

    // server to client notification
    #[br(pre_assert(matches!(command, Command::ServerToClientNotification)))]
    ServerToClientNotification(notify::ServerToClientNotification),

    // error response
    Error(error::ErrorResponse),
}

impl RequestContent {
    /// Get the command associated with this content.
    pub fn associated_cmd(&self) -> Command {
        use RequestContent::*;
        match self {
            $(
                $cmd(_) => Command::$cmd,
            )*

            Cancel(_) => Command::Cancel,
            OplockBreakAck(_)
            | LeaseBreakAck(_) => Command::OplockBreak,
        }
    }
}

impl ResponseContent {
    /// Get the command associated with this content.
    pub fn associated_cmd(&self) -> Command {
        use ResponseContent::*;
        match self {
            $(
                $cmd(_) => Command::$cmd,
            )*

            | OplockBreakNotify(_)
            | OplockBreak(_)
            | LeaseBreakNotify(_)
            | LeaseBreak(_) => Command::OplockBreak,
            ServerToClientNotification(_) => Command::ServerToClientNotification,
            Error(_) => panic!("Error has no matching command!"),
        }
    }
}

// Into<RequestContent> and Into<ResponseContent> implementations
// for all the common requests/responses pairs.
// the other type are a bit problematic, so they are currently
// not implemented, but can be added later if needed.
$(
    impl From<$struct_pfx::[<$cmd Request>]>
        for RequestContent
    {
        fn from(req: $struct_pfx::[<$cmd Request>]) -> Self {
            RequestContent::$cmd(req)
        }
    }
    impl From<$struct_pfx::[<$cmd Response>]>
        for ResponseContent
    {
        fn from(resp: $struct_pfx::[<$cmd Response>]) -> Self {
            ResponseContent::$cmd(resp)
        }
    }
)+

impl From<cancel::CancelRequest>
    for RequestContent
{
    fn from(req: cancel::CancelRequest) -> Self {
        RequestContent::Cancel(req)
    }
}

impl From<error::ErrorResponse>
    for ResponseContent
{
    fn from(resp: error::ErrorResponse) -> Self {
        ResponseContent::Error(resp)
    }
}

make_content_impl!{
    RequestContent,
    $(
        {$cmd, $struct_pfx::[<$cmd Request>]},
    )+
    {Cancel, cancel::CancelRequest},
    {OplockBreakAck, oplock::OplockBreakAck},
    {LeaseBreakAck, oplock::LeaseBreakAck},
}

make_content_impl!{
    ResponseContent,
    $(
        {$cmd, $struct_pfx::[<$cmd Response>]},
    )+
    {OplockBreakNotify, oplock::OplockBreakNotify},
    {LeaseBreakNotify, oplock::LeaseBreakNotify},
    {OplockBreak, oplock::OplockBreakResponse},
    {LeaseBreak, oplock::LeaseBreakResponse},
    {ServerToClientNotification, notify::ServerToClientNotification},
    {Error, error::ErrorResponse},
}
        }
    };
}

make_content!(
    {Negotiate, negotiate},
    {SessionSetup, session_setup},
    {Logoff, session_setup},
    {TreeConnect, tree_connect},
    {TreeDisconnect, tree_connect},
    {Create, create},
    {Close, create},
    {Flush, file},
    {Read, file},
    {Write, file},
    {Lock, lock},
    {Ioctl, ioctl},
    {Echo, echo},
    {QueryDirectory, query_dir},
    {ChangeNotify, notify},
    {QueryInfo, info},
    {SetInfo, info},
);

impl RequestContent {
    /// If this is a request has a payload, it returns the size of it.
    /// Otherwise, it returns 0.
    ///
    /// This method shall be used for calculating credits request & charge.
    pub fn req_payload_size(&self) -> u32 {
        use RequestContent::*;
        match self {
            // 3.3.5.13
            Write(req) => req.length,
            // 3.3.5.15: InputCount + OutputCount
            Ioctl(req) => req.buffer.get_size() + req.max_output_response,
            _ => 0,
        }
    }
    /// If this is a request that expects a response with size,
    /// it returns that expected size.
    ///
    /// This method shall be used for calculating credits request & charge.
    pub fn expected_resp_size(&self) -> u32 {
        use RequestContent::*;
        match self {
            // 3.3.5.12
            Read(req) => req.length,
            // 3.3.5.18
            QueryDirectory(req) => req.output_buffer_length,
            // 3.3.5.15: MaxInputCount + MaxOutputCount
            Ioctl(req) => req.max_input_response + req.max_output_response,
            _ => 0,
        }
    }
}

macro_rules! make_plain {
    ($suffix:ident, $server_to_redir:literal, $binrw_attr:ident) => {
        pastey::paste! {

        /// A plain, single, SMB2 message.
        #[$binrw_attr]
        #[brw(little)]
        pub struct [<Plain $suffix>] {
            #[brw(assert(header.flags.server_to_redir() == $server_to_redir))]
            pub header: Header,
            #[brw(args(&header.command))]
            pub content: [<$suffix Content>],
        }

        impl [<Plain $suffix>] {
            pub fn new(content: [<$suffix Content>]) -> [<Plain $suffix>] {
                let cmd = content.associated_cmd();
                Self::new_with_command(content, cmd)
            }

            pub fn new_with_command(content: [<$suffix Content>], command: Command) -> [<Plain $suffix>] {
                [<Plain $suffix>] {
                    // default is a sync command, so `tree_id` must be set, and `HeaderFlags::async_command` is false
                    header: Header {
                        credit_charge: 0,
                        status: Status::Success as u32,
                        command,
                        credit_request: 0,
                        flags: HeaderFlags::new(),
                        next_command: 0,
                        message_id: u64::MAX,
                        tree_id: Some(0),
                        async_id: None,
                        session_id: 0,
                        signature: 0,
                    },
                    content,
                }
            }
        }
                }
    };
}

make_plain!(Request, false, smb_request_binrw);
make_plain!(Response, true, smb_response_binrw);

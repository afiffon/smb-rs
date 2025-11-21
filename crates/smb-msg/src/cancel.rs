//! Cancel Request

use binrw::prelude::*;
use smb_msg_derive::*;

/// SMB2 CANCEL Request structure
///
/// Sent by the client to cancel a previously sent message on the same SMB2 transport connection.
///
/// Reference: MS-SMB2 2.2.30
#[smb_request(size = 4)]
#[derive(Default)]
pub struct CancelRequest {
    reserved: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    test_binrw_request! {
        struct CancelRequest {} => "04000000"
    }
}

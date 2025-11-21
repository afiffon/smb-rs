//! Echo request and response messages
use binrw::prelude::*;
use smb_msg_derive::*;

/// SMB2 Echo request/response.
///
/// MS-SMB2 2.2.28; 2.2.29
#[smb_request_response(size = 4)]
#[derive(Default)]
pub struct EchoMessage {
    reserved: u16,
}

/// Echo Request is the same as Echo Response (see: [`EchoMessage`])
pub use EchoMessage as EchoRequest;
/// Echo Response is the same as Echo Request (see: [`EchoMessage`])
pub use EchoMessage as EchoResponse;

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use super::*;

    test_binrw! {
        struct EchoMessage {} => "04000000"
    }
}

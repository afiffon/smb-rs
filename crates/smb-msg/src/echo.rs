//! Echo request and response messages
use binrw::prelude::*;
use smb_msg_derive::*;

/// SMB2 Echo request/response.
///
/// MS-SMB2 2.2.28; 2.2.29
#[smb_request_response(size = 4)]
#[derive(Default)]
pub struct EchoMessage {
    #[bw(calc = 0)]
    #[br(temp)]
    _reserved: u16,
}

pub use EchoMessage as EchoRequest;
pub use EchoMessage as EchoResponse;

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use super::*;

    test_binrw! {
        struct EchoMessage {} => "04000000"
    }
}

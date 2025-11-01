//! Cancel Request

use binrw::prelude::*;
use smb_msg_derive::*;

#[smb_request(size = 4)]
#[derive(Default)]
pub struct CancelRequest {
    #[bw(calc = 0)]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_tests::*;

    test_binrw! {
        struct CancelRequest {} => "04000000"
    }
}

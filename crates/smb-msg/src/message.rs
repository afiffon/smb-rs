//! Full Request & Response enums, including plain or transformed (encrypted/compressed).

use binrw::prelude::*;
use smb_msg_derive::*;

macro_rules! make_message {
    ($name:ident, $binrw_type:ident, $plain_type:ty) => {
        #[doc = concat!("This struct represents all the ", stringify!($name), "message types.")]
        /// - Plain, Encrypted, Compressed, directly after the NetBios header (magic + 24-bit size).
        #[$binrw_type]
        #[brw(little)]
        pub enum $name {
            Plain($plain_type),
            Encrypted($crate::EncryptedMessage),
            Compressed($crate::CompressedMessage),
        }
    };
}

make_message!(Request, smb_request_binrw, crate::PlainRequest);
make_message!(Response, smb_response_binrw, crate::PlainResponse);

#[cfg(feature = "client")]
impl TryFrom<&[u8]> for Response {
    type Error = binrw::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Response::read(&mut std::io::Cursor::new(value))
    }
}

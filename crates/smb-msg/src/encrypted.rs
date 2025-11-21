//! Encrypted message and header implementation.

use std::io::Cursor;

use binrw::prelude::*;
use smb_msg_derive::smb_message_binrw;
const SIGNATURE_SIZE: usize = 16;

/// The nonce used for encryption.
/// Depending on the encryption algorithm, the nonce may be trimmed to a smaller size when used,
/// or padded with zeroes to match the required size. When transmitted, the full 16 bytes are used.
pub type EncryptionNonce = [u8; 16];

/// This header is used by the client or server when sending encrypted messages
#[smb_message_binrw]
#[brw(little, magic(b"\xfdSMB"))]
pub struct EncryptedHeader {
    /// The 16-byte signature of the message generated using negotiated encryption algorithm
    pub signature: u128,
    /// An implementation-specific value assigned for every encrypted message. This MUST NOT be reused for all encrypted messages within a session.
    pub nonce: EncryptionNonce,
    /// The size, in bytes, of the SMB2 message.
    pub original_message_size: u32,
    reserved: u16,
    #[bw(calc = 1)]
    // MUST be set to 1, in SMB3.1.1 because encrypted, in others because encryption algorithm is AES128-CCM (0x1)
    #[br(assert(_flags == 1))]
    _flags: u16,
    /// Uniquely identifies the established session for the command.
    pub session_id: u64,
}

impl EncryptedHeader {
    const MAGIC_SIZE: usize = 4;
    pub const STRUCTURE_SIZE: usize = 4
        + size_of::<u128>()
        + size_of::<EncryptionNonce>()
        + size_of::<u32>()
        + size_of::<u16>()
        + size_of::<u16>()
        + size_of::<u64>();
    const AEAD_BYTES_SIZE: usize = Self::STRUCTURE_SIZE - Self::MAGIC_SIZE - SIGNATURE_SIZE;

    /// The bytes to use as the additional data for the AEAD out of this header.
    /// Make sure to call it after all fields (except signature) are finalized.
    ///
    /// Returns (according to MS-SMB2) the bytes of the header, excluding the magic and the signature.
    pub fn aead_bytes(&self) -> [u8; Self::AEAD_BYTES_SIZE] {
        let mut cursor = Cursor::new([0u8; Self::STRUCTURE_SIZE]);
        self.write(&mut cursor).unwrap();
        cursor.into_inner()[Self::MAGIC_SIZE + SIGNATURE_SIZE..Self::STRUCTURE_SIZE]
            .try_into()
            .unwrap()
    }
}

/// An entirely encrypted SMB2 message, that includes both the encrypted header and the encrypted message.
#[smb_message_binrw]
pub struct EncryptedMessage {
    pub header: EncryptedHeader,
    #[br(parse_with = binrw::helpers::until_eof)]
    pub encrypted_message: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use super::*;

    test_binrw! {
        EncryptedHeader => e0: EncryptedHeader {
            signature: u128::from_le_bytes([
                0x92, 0x2e, 0xe8, 0xf2, 0xa0, 0x6e, 0x7a, 0xd4, 0x70, 0x22, 0xd7, 0x1d, 0xb,
                0x2, 0x6b, 0x11,
            ]),
            nonce: [
                0xa, 0x57, 0x67, 0x55, 0x6d, 0xa0, 0x23, 0x73, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0,
            ],
            original_message_size: 104,
            session_id: 0x300024000055,
        } => "fd534d42922ee8f2a06e7ad47022d71d0b026b110a5767556da02373010000000000000068000000000001005500002400300000"
    }

    test_binrw! {
        EncryptedHeader => e1: EncryptedHeader {
            signature: u128::from_le_bytes([
                0x2a, 0x45, 0x6c, 0x5d, 0xd0, 0xc3, 0x2d, 0xd4, 0x47, 0x85, 0x21, 0xf7, 0xf6, 0xa8,
                0x87, 0x5b,
            ]),
            nonce: [
                0xbe, 0xe6, 0xbf, 0xe5, 0xa1, 0xe6, 0x7b, 0xb1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0,
            ],
            original_message_size: 248,
            session_id: 0x0000300024000055,
        } => "fd534d422a456c5dd0c32dd4478521f7f6a8875bbee6bfe5a1e67bb10000000000000000f8000000000001005500002400300000"
    }
}

//! Compressed messages

use std::io::SeekFrom;

use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::smb_message_binrw;

use super::negotiate::CompressionAlgorithm;
use binrw::io::TakeSeekExt;
use binrw::prelude::*;

/// SMB2 compression transform header variants for compressed messages.
///
/// Used by client or server when sending compressed messages in SMB 3.1.1 dialect.
/// The variant is determined by the compression flags.
///
/// MS-SMB2 2.2.42
#[smb_message_binrw]
#[brw(little)]
pub enum CompressedMessage {
    Unchained(CompressedUnchainedMessage),
    Chained(CompressedChainedMessage),
}

impl CompressedMessage {
    /// Calculates the total size of the compressed message including headers and data.
    pub fn total_size(&self) -> usize {
        match self {
            CompressedMessage::Unchained(m) => {
                m.data.len() + CompressedUnchainedMessage::STRUCT_SIZE
            }
            CompressedMessage::Chained(m) => {
                m.items.iter().map(|i| i.payload_data.len()).sum::<usize>()
                    + m.items.len() * 4
                    + CompressedChainedMessage::STRUCT_SIZE
            }
        }
    }
}

/// SMB2 compression transform header for unchained compressed messages.
///
/// Used when sending unchained compressed messages where the flags field is zero.
/// Only valid for SMB 3.1.1 dialect.
///
/// MS-SMB2 2.2.42.1
#[smb_message_binrw]
#[brw(magic(b"\xfcSMB"), little)]
pub struct CompressedUnchainedMessage {
    /// Size of the uncompressed data segment
    pub original_size: u32,
    /// Compression algorithm used (cannot be None for compressed messages)
    #[brw(assert(!matches!(compression_algorithm, CompressionAlgorithm::None)))]
    pub compression_algorithm: CompressionAlgorithm,
    /// Must be set to SMB2_COMPRESSION_FLAG_NONE (0x0000)
    #[br(assert(flags == 0))]
    #[bw(calc = 0)]
    flags: u16,
    /// Offset from end of structure to start of compressed data segment
    #[bw(calc = 0)]
    offset: u32,
    /// Compressed data payload
    #[br(seek_before = SeekFrom::Current(offset as i64))]
    #[br(parse_with = binrw::helpers::until_eof)]
    pub data: Vec<u8>,
}

impl CompressedUnchainedMessage {
    /// Size of the protocol identifier magic bytes
    const MAGIC_SIZE: usize = 4;
    /// Total size of the unchained compression header structure (excluding data)
    pub const STRUCT_SIZE: usize = Self::MAGIC_SIZE
        + std::mem::size_of::<u32>() * 2
        + std::mem::size_of::<CompressionAlgorithm>()
        + std::mem::size_of::<u16>();
}

/// SMB2 compression transform header for chained compressed messages.
///
/// Used when sending compressed and chained SMB2 messages where the flags field
/// is SMB2_COMPRESSION_FLAG_CHAINED (0x0001). Only valid for SMB 3.1.1 dialect.
///
/// MS-SMB2 2.2.42.2
#[smb_message_binrw]
#[brw(magic(b"\xfcSMB"), little)]
pub struct CompressedChainedMessage {
    /// Size of the uncompressed data segment
    pub original_size: u32,
    /// Variable length array of compression payload headers
    #[br(parse_with = binrw::helpers::until_eof)]
    pub items: Vec<CompressedChainedItem>,
}

impl CompressedChainedMessage {
    /// Total size of the chained compression header structure (excluding payload headers)
    pub const STRUCT_SIZE: usize = std::mem::size_of::<u32>() + 4;
}

/// Calculates additional bytes to include in length field when OriginalPayloadSize is present.
fn add_original_size_to_total_length(algo: &CompressionAlgorithm) -> u64 {
    if algo.original_size_required() {
        std::mem::size_of::<u32>() as u64
    } else {
        0
    }
}

/// SMB2 compression chained payload header.
///
/// Used when sending chained compressed payloads. This structure is added for each
/// compressed payload in a chained message. Only valid for SMB 3.1.1 dialect.
///
/// MS-SMB2 2.2.42.2.1
#[smb_message_binrw]
pub struct CompressedChainedItem {
    /// Compression algorithm used for this payload
    pub compression_algorithm: CompressionAlgorithm,
    /// Compression flags (SMB2_COMPRESSION_FLAG_NONE or SMB2_COMPRESSION_FLAG_CHAINED)
    pub flags: u16,
    /// Length of compressed payload including OriginalPayloadSize if present
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    length: PosMarker<u32>,
    /// Size of uncompressed payload (present only for LZNT1, LZ77, LZ77+Huffman, or LZ4)
    #[brw(if(compression_algorithm.original_size_required()))]
    #[bw(assert(original_size.is_none() ^ compression_algorithm.original_size_required()))]
    pub original_size: Option<u32>,
    /// Compressed payload data
    #[br(map_stream = |s| s.take_seek(length.value as u64 - (add_original_size_to_total_length(&compression_algorithm))), parse_with = binrw::helpers::until_eof)]
    #[bw(write_with = PosMarker::write_size_plus, args(&length, add_original_size_to_total_length(compression_algorithm)))]
    pub payload_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_tests::*;

    // TODO(TEST): unchained

    test_binrw! {
        CompressedMessage => chained0: CompressedMessage::Chained(CompressedChainedMessage {
                original_size: 368,
                items: vec![
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::None,
                        flags: 1,
                        original_size: None,
                        payload_data: vec![
                            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10,
                            0x0, 0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x91, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
                            0x7d, 0x0, 0x0, 0x28, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x29, 0x0, 0x1,
                            0xf, 0x2a, 0x2, 0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x8, 0x1, 0x0, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0xee, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0,
                            0x0, 0x8d, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0
                        ],
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::None,
                        flags: 0xb975,
                        original_size: None,
                        payload_data: vec![
                            0x0, 0x0, 0x0, 0x0, 0x15, 0x24, 0x4d, 0x70, 0x45, 0x61, 0x5f, 0x44,
                            0x32, 0x36, 0x32, 0x41, 0x43, 0x36, 0x32, 0x34, 0x34, 0x35, 0x31, 0x32,
                            0x39, 0x35
                        ],
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::PatternV1,
                        flags: 0,
                        original_size: None,
                        payload_data: vec![0x0, 0x0, 0x0, 0x0, 0xee, 0x0, 0x0, 0x0]
                    }
                ]
            }) => "fc534d42700100000000010068000000fe534d4240000100000000001000010030000000000000009100000000000000fffe0000010000007d00002800300000000000000000000000000000000000002900010f2a02000068000000080100000000000003000000ee0500000c0000008d0000000c000000000075b91a0000000000000015244d7045615f443236324143363234343531323935040000000800000000000000ee000000"
    }

    /// I do it for the sake of some real, big data.
    const CHAINED1_ITEM2_DATA: &'static str = "f2034d5a90000300000004000000ffff0000b8000\
    100124007000f02000af32e200100000e1fba0e00b409cd21b8014ccd21546869732070726f677\
    2616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a245a0084a98ee\
    eb9edef80ea0400d1996e86ebddef80ea9f6e83ebe81000b181ebe1ef80eabe9084ebec0800318\
    3ebe320003181ebef3800b181eaadef80eae49713eaf010003180ea7f38004088eb5ee94000318\
    5ebf310003184eb9008003183eba908001180500040996e7fea580031996e82100040526963684\
    400039f00d4005045000064862400bbf4ba231400f10bf00022000b020e260090a60000e01d000\
    0f061009002b100001022002040010700000c00561000000a00040001020030f044012800b126d\
    1c2000100604100000817002200200700013500000200004000030200010b00c17014008fb3010\
    028471400b86100f3144001288e030000700d00b4cf06000070c200b825000000904301dc5f000\
    0101004007040000f02000120a05b4200071a0057401400f80610000b0200b22e7264617461000\
    0305c0d91001360080007020062400000482e702800029400400d0000d09c00170d26000328001\
    26928002224267c0023003008000702000150001265280000fc00630070140000c00800070200c\
    14000004050524f54444154411b01223016a400000800070200005000a047464944530000002ca\
    9700043160000b0080007020081400000425061643113006110090000f0160b000c0200f200800\
    000422e746578740000000ba14cc5012db04c30008020000068504147454000f0008042440000b\
    06c000050440000a063130005020040200000602800f5044c4b00001c6402000000b1000070020\
    000f0a72400000200012800804f4f4c434f4445bef4012270b340012060aa1f00050200047800e\
    04b440000ea5d000000a0b300006024020d2800017800605652465919150e048fb400002003000\
    0f02800035048444c53760e032220b778002510ae740000020001a000904147454247465868694\
    50321b7008d021e402800f1005452414345535550a319000000c0b73d002d00b02800014001b24\
    34d5243f30e000000e0b7e0011dd0280050604b5641531801107e610413f0a0001de0280050684\
    b534350ac0010607f032220b850002010af1300050200004001904452565052580000b71600133\
    028001e20280050666f74686b240000ad03134028001e302800e0494e49544b444247a6f101000\
    0506e054e020000402800904d494e4945580000bc20032250ba68012040b162000502004020000\
    0625000001100ee1be009000080ba0000f0090000702800405061643228007100901b000070c40\
    b000c020052800000622e6f03400080291c690100ed0449000060bb2b00f104400000c8414c4d4\
    f5354524f409c00000030fc8d003d0050bc2800f2004341434845414c49008e000000d0fc20011\
    e70280000f80200c0037250b401000060fd50001d80280010c02800e056524644503c01000020f\
    f0000a0d8020e280000180100500030b41402f402017405390040bda00081200000c2506164331\
    50061801d000080023f040c020090800000c2434647524fe30001a80521200170031a505000001\
    8014150616434400050d01f00003022070e020080800000ca2e727372fe0301c4059d004001009\
    0030000805000c1422e72656c6f630000dc5501dc0578006001000010c15500500040000042";

    const CHAINED1_TEST_DATA: &'static str = const_format::concatcp!(
        "fc534d42501000000000010050000000fe534d424000010000000000080001001900000000000000070000000000000000000000010000001d00000000600000251698bc898e3e86aeb713557cfaf1bb1100500000100000000000000000000005000000f7040000c8070000",
        CHAINED1_ITEM2_DATA,
        "04000000080000000000000038080000"
    );

    test_binrw! {
        CompressedMessage => chained1: CompressedMessage::Chained(CompressedChainedMessage {
                original_size: 4176,
                items: vec![
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::None,
                        flags: 1,
                        original_size: None,
                        payload_data: vec![
                            0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8,
                            0x0, 0x1, 0x0, 0x19, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0,
                            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1d,
                            0x0, 0x0, 0x0, 0x0, 0x60, 0x0, 0x0, 0x25, 0x16, 0x98, 0xbc, 0x89, 0x8e,
                            0x3e, 0x86, 0xae, 0xb7, 0x13, 0x55, 0x7c, 0xfa, 0xf1, 0xbb, 0x11, 0x0,
                            0x50, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
                        ],
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::LZ4,
                        flags: 0,
                        original_size: Some(0x7c8),
                        payload_data: smb_tests::hex_to_u8_array! {CHAINED1_ITEM2_DATA}
                    },
                    CompressedChainedItem {
                        compression_algorithm: CompressionAlgorithm::PatternV1,
                        flags: 0,
                        original_size: None,
                        payload_data: vec![0x0, 0x0, 0x0, 0x0, 0x38, 0x8, 0x0, 0x0]
                    },
                ]
            }) => CHAINED1_TEST_DATA
    }

    test_binrw! {
        CompressedMessage => multiple2: CompressedMessage::Chained(CompressedChainedMessage {
            original_size: 368,
            items: vec![
                CompressedChainedItem {
                    compression_algorithm: CompressionAlgorithm::None,
                    flags: 1,
                    original_size: None,
                    payload_data: vec![
                        0xfe, 0x53, 0x4d, 0x42, 0x40, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x0,
                        0x1, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1e, 0x3, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0xff, 0xfe, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x9, 0x0,
                        0x0, 0x2c, 0x0, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x29, 0x0, 0x1, 0xf, 0x2a, 0x2,
                        0x0, 0x0, 0x68, 0x0, 0x0, 0x0, 0x8, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3,
                        0x0, 0x0, 0x0, 0x11, 0x7, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x69, 0x0, 0x20,
                        0x0, 0xc, 0x0, 0x0, 0x0,
                    ],
                },
                CompressedChainedItem {
                    compression_algorithm: CompressionAlgorithm::None,
                    flags: 0,
                    original_size: None,
                    payload_data: vec![
                        0x0, 0x0, 0x0, 0x0, 0x15, 0x24, 0x4d, 0x70, 0x45, 0x61, 0x5f, 0x44, 0x32,
                        0x36, 0x32, 0x41, 0x43, 0x36, 0x32, 0x34, 0x34, 0x35, 0x31, 0x32, 0x39,
                        0x35,
                    ],
                },
                CompressedChainedItem {
                    compression_algorithm: CompressionAlgorithm::PatternV1,
                    flags: 0,
                    original_size: None,
                    payload_data: vec![0x0, 0x0, 0x0, 0x0, 0xee, 0x0, 0x0, 0x0],
                },
            ],
        }) => "fc534d42700100000000010068000000fe534d4240000100000000001000010030000000000000001e03000000000000fffe0000050000000900002c00300000000000000000000000000000000000002900010f2a02000068000000080100000000000003000000110700000c000000690020000c000000000000001a0000000000000015244d7045615f443236324143363234343531323935040000000800000000000000ee000000"
    }
}

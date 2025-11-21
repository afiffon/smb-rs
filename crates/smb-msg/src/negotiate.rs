use binrw::io::{SeekFrom, TakeSeekExt};
use binrw::prelude::*;
use modular_bitfield::prelude::*;

use smb_dtyp::{binrw_util::prelude::*, guid::Guid};
use smb_msg_derive::*;

/// SMB2 NEGOTIATE Request.
///
/// Used by the client to notify the server what dialects of the SMB 2 Protocol
/// the client understands.
///
/// Reference: MS-SMB2 2.2.3
#[smb_request(size = 36)]
pub struct NegotiateRequest {
    #[bw(try_calc(u16::try_from(dialects.len())))]
    #[br(temp)]
    dialect_count: u16,
    /// Security mode flags indicating signing requirements.
    pub security_mode: NegotiateSecurityMode,
    reserved: u16,
    /// Client capabilities.
    pub capabilities: GlobalCapabilities,
    /// Client GUID, used to identify the client.
    pub client_guid: Guid,

    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    negotiate_context_offset: PosMarker<u32>,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    #[br(temp)]
    negotiate_context_count: u16,
    reserved: u16,
    /// List of SMB dialects supported by the client.
    #[br(count = dialect_count)]
    pub dialects: Vec<Dialect>,
    /// Negotiate contexts (SMB 3.1.1+ only).
    #[brw(if(dialects.contains(&Dialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_aoff, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

/// Flags for SMB2 negotiation security mode.
///
/// See [NegotiateSecurityMode].
///
/// Reference: MS-SMB2 2.2.3
#[smb_dtyp::mbitfield]
pub struct NegotiateSecurityMode {
    /// Signing is enabled.
    pub signing_enabled: bool,
    /// Signing is required.
    pub signing_required: bool,
    #[skip]
    __: B14,
}

/// Global capabilities flags for SMB2/SMB3.
///
/// Indicates various protocol capabilities supported by the client or server.
///
/// Reference: MS-SMB2 2.2.3
#[smb_dtyp::mbitfield]
pub struct GlobalCapabilities {
    /// DFS support.
    pub dfs: bool,
    /// File leasing support.
    pub leasing: bool,
    /// Large MTU support (multiple credit operations).
    pub large_mtu: bool,
    /// Multi-channel support.
    pub multi_channel: bool,

    /// Persistent handles support.
    pub persistent_handles: bool,
    /// Directory leasing support.
    pub directory_leasing: bool,
    /// Encryption support.
    pub encryption: bool,
    /// Change notifications support.
    pub notifications: bool,

    #[skip]
    __: B24,
}

/// SMB2 NEGOTIATE Response.
///
/// Sent by the server to notify the client of the preferred common dialect.
///
/// Reference: MS-SMB2 2.2.4
#[smb_response(size = 65)]
pub struct NegotiateResponse {
    /// Server security mode.
    pub security_mode: NegotiateSecurityMode,
    /// Selected dialect revision.
    pub dialect_revision: NegotiateDialect,
    #[bw(try_calc(u16::try_from(negotiate_context_list.as_ref().map(|v| v.len()).unwrap_or(0))))]
    #[br(assert(if dialect_revision == NegotiateDialect::Smb0311 { negotiate_context_count > 0 } else { negotiate_context_count == 0 }))]
    #[br(temp)]
    negotiate_context_count: u16,
    /// Server GUID.
    pub server_guid: Guid,
    /// Server capabilities.
    pub capabilities: GlobalCapabilities,
    /// Maximum transaction size supported by the server.
    pub max_transact_size: u32,
    /// Maximum read size supported by the server.
    pub max_read_size: u32,
    /// Maximum write size supported by the server.
    pub max_write_size: u32,
    /// Current system time on the server.
    pub system_time: FileTime,
    /// Server start time.
    pub server_start_time: FileTime,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _security_buffer_offset: PosMarker<u16>,
    #[bw(try_calc(u16::try_from(buffer.len())))]
    #[br(temp)]
    security_buffer_length: u16,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    negotiate_context_offset: PosMarker<u32>,
    /// Security buffer containing GSSAPI token.
    #[br(count = security_buffer_length)]
    #[bw(write_with = PosMarker::write_aoff, args(&_security_buffer_offset))]
    pub buffer: Vec<u8>,

    /// Negotiate contexts (SMB 3.1.1+ only).
    #[brw(if(matches!(dialect_revision, NegotiateDialect::Smb0311)), align_before = 8)]
    #[br(count = negotiate_context_count, seek_before = SeekFrom::Start(negotiate_context_offset.value as u64))]
    #[bw(write_with = PosMarker::write_aoff, args(&negotiate_context_offset))]
    pub negotiate_context_list: Option<Vec<NegotiateContext>>,
}

/// SMB2/SMB3 protocol dialect revisions.
///
/// Reference: MS-SMB2 2.2.3
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
#[brw(repr(u16))]
pub enum Dialect {
    Smb0202 = 0x0202,
    Smb021 = 0x0210,
    Smb030 = 0x0300,
    Smb0302 = 0x0302,
    Smb0311 = 0x0311,
}

impl Dialect {
    pub const MAX: Dialect = Dialect::Smb0311;
    pub const MIN: Dialect = Dialect::Smb0202;
    pub const ALL: [Dialect; 5] = [
        Dialect::Smb0202,
        Dialect::Smb021,
        Dialect::Smb030,
        Dialect::Smb0302,
        Dialect::Smb0311,
    ];

    /// Whether this is an SMB3 dialect.
    #[inline]
    pub fn is_smb3(&self) -> bool {
        self >= &Dialect::Smb030
    }
}

/// Dialects that may be used in the SMB Negotiate Response.
///
/// The same as [Dialect] but includes a wildcard revision for SMB 2.0.
///
/// Reference: MS-SMB2 2.2.4
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum NegotiateDialect {
    Smb0202 = Dialect::Smb0202 as isize,
    Smb021 = Dialect::Smb021 as isize,
    Smb030 = Dialect::Smb030 as isize,
    Smb0302 = Dialect::Smb0302 as isize,
    Smb0311 = Dialect::Smb0311 as isize,
    Smb02Wildcard = 0x02FF,
}

impl TryFrom<NegotiateDialect> for Dialect {
    type Error = crate::SmbMsgError;

    fn try_from(value: NegotiateDialect) -> Result<Self, Self::Error> {
        match value {
            NegotiateDialect::Smb0202 => Ok(Dialect::Smb0202),
            NegotiateDialect::Smb021 => Ok(Dialect::Smb021),
            NegotiateDialect::Smb030 => Ok(Dialect::Smb030),
            NegotiateDialect::Smb0302 => Ok(Dialect::Smb0302),
            NegotiateDialect::Smb0311 => Ok(Dialect::Smb0311),
            _ => Err(Self::Error::InvalidDialect(value)),
        }
    }
}

/// A single negotiate context item.
///
/// Used in SMB 3.1.1 to negotiate additional capabilities beyond the base protocol.
///
/// Note: This struct should usually be NOT used directly.
/// To construct it, use `impl From<ContextValueStruct> for NegotiateContext`:
/// ```
/// # use smb_msg::*;
/// let signing_ctx: NegotiateContext = SigningCapabilities {
///     signing_algorithms: vec![SigningAlgorithmId::AesGmac]
/// }.into();
/// ```
///
/// Reference: MS-SMB2 2.2.3.1
#[smb_message_binrw]
pub struct NegotiateContext {
    /// Type of the negotiate context.
    #[brw(align_before = 8)]
    pub context_type: NegotiateContextType,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    data_length: PosMarker<u16>,
    reserved: u32,
    /// Context-specific data.
    #[br(args(&context_type))]
    #[br(map_stream = |s| s.take_seek(data_length.value as u64))]
    #[bw(write_with = PosMarker::write_size, args(&data_length))]
    pub data: NegotiateContextValue,
}

macro_rules! negotiate_context_type {
    ($($name:ident = $id:literal,)+) => {
/// Negotiate context type identifiers.
///
/// Reference: MS-SMB2 2.2.3.1
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[brw(repr(u16))]
pub enum NegotiateContextType {
    $(
        $name = $id,
    )+
}

/// Negotiate context values.
///
/// Each variant corresponds to a specific negotiate context type.
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
#[br(import(context_type: &NegotiateContextType))]
pub enum NegotiateContextValue {
    $(
        #[br(pre_assert(context_type == &NegotiateContextType::$name))]
        $name($name),
    )+
}

impl NegotiateContextValue {
    /// Gets the matching negotiate context type for this value.
    pub fn get_matching_type(&self) -> NegotiateContextType {
        match self {
            $(
                NegotiateContextValue::$name(_) => {
                    NegotiateContextType::$name
                }
            )+
        }
    }
}

$(
    impl From<$name> for NegotiateContext {
        fn from(val: $name) -> Self {
            NegotiateContext {
                context_type: NegotiateContextType::$name,
                data: NegotiateContextValue::$name(val),
            }
        }
    }
)+

/// (Internal) Macro to generate impls for getting negotiate contexts from messages.
macro_rules! gen_impl_for_neg_msg_type {
    ($msg_type:ident) => {

impl $msg_type {
    $(
        pastey::paste! {
            #[doc = concat!("Gets the negotiate context of type [`", stringify!($name), "`] if present.")]
            ///
            /// _This method is auto-generated by the `negotiate_context_type!` macro._
            pub fn [<get_ctx_ $name:snake>] (&self) -> Option<& $name> {
                self.negotiate_context_list.as_ref().and_then(|contexts| {
                    contexts.iter().find_map(|context| match &context.context_type {
                        NegotiateContextType::$name => match &context.data {
                            NegotiateContextValue::$name(caps) => Some(caps),
                            _ => None,
                        },
                        _ => None,
                    })
                })
            }

        }
    )+
}

    }
}

gen_impl_for_neg_msg_type!(NegotiateRequest);
gen_impl_for_neg_msg_type!(NegotiateResponse);
    };
}

negotiate_context_type!(
    PreauthIntegrityCapabilities = 0x0001,
    EncryptionCapabilities = 0x0002,
    CompressionCapabilities = 0x0003,
    NetnameNegotiateContextId = 0x0005,
    TransportCapabilities = 0x0006,
    RdmaTransformCapabilities = 0x0007,
    SigningCapabilities = 0x0008,
);

/// Hash algorithms for pre-authentication integrity.
///
/// Reference: MS-SMB2 2.2.3.1.1
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum HashAlgorithm {
    Sha512 = 0x01,
}

/// (Context) Pre-authentication integrity capabilities.
///
/// Specifies the hash algorithm and salt used for pre-authentication integrity.
///
/// Reference: MS-SMB2 2.2.3.1.1
#[smb_message_binrw]
pub struct PreauthIntegrityCapabilities {
    #[bw(try_calc(u16::try_from(hash_algorithms.len())))]
    hash_algorithm_count: u16,
    #[bw(try_calc(u16::try_from(salt.len())))]
    salt_length: u16,
    /// Supported hash algorithms for pre-authentication integrity.
    #[br(count = hash_algorithm_count)]
    pub hash_algorithms: Vec<HashAlgorithm>,
    /// Salt value for pre-authentication integrity.
    #[br(count = salt_length)]
    pub salt: Vec<u8>,
}

/// (Context) Encryption capabilities.
///
/// Specifies the encryption ciphers supported by the client or server.
///
/// Reference: MS-SMB2 2.2.3.1.2
#[smb_message_binrw]
pub struct EncryptionCapabilities {
    #[bw(try_calc(u16::try_from(ciphers.len())))]
    cipher_count: u16,
    /// Supported encryption ciphers in preference order.
    #[br(count = cipher_count)]
    pub ciphers: Vec<EncryptionCipher>,
}

/// Encryption cipher identifiers.
///
/// Reference: MS-SMB2 2.2.3.1.2
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum EncryptionCipher {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004,
}

/// (Context) Compression capabilities.
///
/// Specifies the compression algorithms supported by the client or server.
///
/// Reference: MS-SMB2 2.2.3.1.3
#[smb_message_binrw]
#[derive(Clone)]
pub struct CompressionCapabilities {
    #[bw(try_calc(u16::try_from(compression_algorithms.len())))]
    compression_algorithm_count: u16,
    #[bw(calc = 0)]
    _padding: u16,
    /// Compression capability flags.
    pub flags: CompressionCapsFlags,
    /// Supported compression algorithms in preference order.
    #[br(count = compression_algorithm_count)]
    pub compression_algorithms: Vec<CompressionAlgorithm>,
}

/// Compression algorithm identifiers.
///
/// Reference: MS-SMB2 2.2.3.1.3
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
#[repr(u16)]
pub enum CompressionAlgorithm {
    None = 0x0000,
    LZNT1 = 0x0001,
    LZ77 = 0x0002,
    LZ77Huffman = 0x0003,
    PatternV1 = 0x0004,
    LZ4 = 0x0005,
}

impl CompressionAlgorithm {
    /// Relevant for processing compressed messages.
    pub fn original_size_required(&self) -> bool {
        matches!(
            self,
            CompressionAlgorithm::LZNT1
                | CompressionAlgorithm::LZ77
                | CompressionAlgorithm::LZ77Huffman
                | CompressionAlgorithm::LZ4
        )
    }
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message_as_string = match self {
            CompressionAlgorithm::None => "None",
            CompressionAlgorithm::LZNT1 => "LZNT1",
            CompressionAlgorithm::LZ77 => "LZ77",
            CompressionAlgorithm::LZ77Huffman => "LZ77+Huffman",
            CompressionAlgorithm::PatternV1 => "PatternV1",
            CompressionAlgorithm::LZ4 => "LZ4",
        };
        write!(f, "{} ({:#x})", message_as_string, *self as u16)
    }
}

/// Flags to indicate compression capabilities.
///
/// See [CompressionCapabilities].
///
/// Reference: MS-SMB2 2.2.3.1.3
#[smb_dtyp::mbitfield]
pub struct CompressionCapsFlags {
    /// Chained compression support.
    pub chained: bool,
    #[skip]
    __: B31,
}

/// Netname negotiate context.
///
/// Specifies the server name the client wants to connect to.
///
/// Reference: MS-SMB2 2.2.3.1.4
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq)]
pub struct NetnameNegotiateContextId {
    /// Server name the client intends to connect to.
    #[br(parse_with = binrw::helpers::until_eof)]
    pub netname: SizedWideString,
}

/// (Context) Transport capabilities.
///
/// Specifies whether QUIC transport is supported.
///
/// Reference: MS-SMB2 2.2.3.1.5
#[smb_dtyp::mbitfield]
pub struct TransportCapabilities {
    /// QUIC transport support.
    pub accept_transport_layer_security: bool,
    #[skip]
    __: B31,
}

/// (Context) RDMA transform capabilities.
///
/// Specifies RDMA transform IDs supported for SMB Direct connections.
///
/// Reference: MS-SMB2 2.2.3.1.6
#[smb_message_binrw]
pub struct RdmaTransformCapabilities {
    #[bw(try_calc(u16::try_from(transforms.len())))]
    transform_count: u16,

    reserved: u16,
    reserved: u32,

    /// Supported RDMA transform IDs.
    #[br(count = transform_count)]
    pub transforms: Vec<RdmaTransformId>,
}

/// RDMA transform identifiers.
///
/// Reference: MS-SMB2 2.2.3.1.6
#[smb_message_binrw]
#[brw(repr(u16))]
pub enum RdmaTransformId {
    None = 0x0000,
    Encryption = 0x0001,
    Signing = 0x0002,
}

/// (Context) Signing capabilities.
///
/// Specifies the signing algorithms supported by the client or server.
///
/// Reference: MS-SMB2 2.2.3.1.7
#[smb_message_binrw]
pub struct SigningCapabilities {
    #[bw(try_calc(u16::try_from(signing_algorithms.len())))]
    signing_algorithm_count: u16,
    /// Supported signing algorithms in preference order.
    #[br(count = signing_algorithm_count)]
    pub signing_algorithms: Vec<SigningAlgorithmId>,
}

/// Signing algorithm identifiers.
///
/// Reference: MS-SMB2 2.2.3.1.7
#[derive(BinRead, BinWrite, Debug, PartialEq, Eq, Clone, Copy)]
#[brw(repr(u16))]
pub enum SigningAlgorithmId {
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002,
}

#[cfg(test)]
mod tests {
    use smb_dtyp::make_guid;
    use smb_tests::hex_to_u8_array;
    use time::macros::datetime;

    use super::*;
    use crate::*;

    test_request! {
        Negotiate {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            capabilities: GlobalCapabilities::new()
                .with_dfs(true)
                .with_leasing(true)
                .with_large_mtu(true)
                .with_multi_channel(true)
                .with_persistent_handles(true)
                .with_directory_leasing(true)
                .with_encryption(true)
                .with_notifications(true),
            client_guid: make_guid!("{c12e0ddf-43dd-11f0-8b87-000c29801682}"),
            dialects: vec![
                Dialect::Smb0202,
                Dialect::Smb021,
                Dialect::Smb030,
                Dialect::Smb0302,
                Dialect::Smb0311,
            ],
            negotiate_context_list: Some(vec![
                PreauthIntegrityCapabilities {
                    hash_algorithms: vec![HashAlgorithm::Sha512],
                    salt: hex_to_u8_array! {"ed006c304e332890b2bd98617b5ad9ef075994154673696280ffcc0f1291a15d"}
                }.into(),
                EncryptionCapabilities { ciphers: vec![
                    EncryptionCipher::Aes128Gcm,
                    EncryptionCipher::Aes128Ccm,
                    EncryptionCipher::Aes256Gcm,
                    EncryptionCipher::Aes256Ccm,
                ] }.into(),
                CompressionCapabilities {
                    flags: CompressionCapsFlags::new().with_chained(true),
                    compression_algorithms: vec![
                        CompressionAlgorithm::PatternV1,
                        CompressionAlgorithm::LZ77,
                        CompressionAlgorithm::LZ77Huffman,
                        CompressionAlgorithm::LZNT1,
                        CompressionAlgorithm::LZ4,
                    ]
                }.into(),
                SigningCapabilities { signing_algorithms: vec![
                    SigningAlgorithmId::AesGmac,
                    SigningAlgorithmId::AesCmac,
                    SigningAlgorithmId::HmacSha256,
                ] }.into(),
                NetnameNegotiateContextId { netname: "localhost".into() }.into(),
                RdmaTransformCapabilities { transforms: vec![RdmaTransformId::Encryption, RdmaTransformId::Signing] }.into()
            ])
        } => "2400050001000000ff000000df0d2ec1dd43f0118b87000c298
        016827000000006000000020210020003020311030000010026000000
        0000010020000100ed006c304e332890b2bd98617b5ad9ef075994154
        673696280ffcc0f1291a15d000002000a000000000004000200010004
        000300000000000000030012000000000005000000010000000400020
        003000100050000000000000008000800000000000300020001000000
        05001200000000006c006f00630061006c0068006f007300740000000
        000000007000c0000000000020000000000000001000200"
    }

    test_response! {
        Negotiate {
            security_mode: NegotiateSecurityMode::new().with_signing_enabled(true),
            dialect_revision: NegotiateDialect::Smb0311,
            server_guid: Guid::from([
                0xb9, 0x21, 0xf8, 0xe0, 0x15, 0x7, 0xaa, 0x41, 0xbe, 0x38, 0x67, 0xfe, 0xbf,
                0x5e, 0x2e, 0x11
            ]),
            capabilities: GlobalCapabilities::new()
                .with_dfs(true)
                .with_leasing(true)
                .with_large_mtu(true)
                .with_multi_channel(true)
                .with_directory_leasing(true),
            max_transact_size: 8388608,
            max_read_size: 8388608,
            max_write_size: 8388608,
            system_time: datetime!(2025-01-18 16:24:39.448746400).into(),
            server_start_time: FileTime::default(),
            buffer: [
                0x60, 0x28, 0x6, 0x6, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x2, 0xa0, 0x1e, 0x30, 0x1c,
                0xa0, 0x1a, 0x30, 0x18, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2,
                0x2, 0x1e, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa
            ]
            .to_vec(),
            negotiate_context_list: Some(vec![
                PreauthIntegrityCapabilities {
                        hash_algorithms: vec![HashAlgorithm::Sha512],
                        salt: [
                            0xd5, 0x67, 0x1b, 0x24, 0xa1, 0xe9, 0xcc, 0xc8, 0x93, 0xf5, 0x55,
                            0x5a, 0x31, 0x3, 0x43, 0x5a, 0x85, 0x2b, 0xc3, 0xcb, 0x1a, 0xd3,
                            0x2d, 0xc5, 0x1f, 0x92, 0x80, 0x6e, 0xf3, 0xfb, 0x4d, 0xd4
                        ]
                        .to_vec()
                    }
                .into(),
                EncryptionCapabilities {
                    ciphers: vec![EncryptionCipher::Aes128Gcm]
                }
                .into(),
                SigningCapabilities {
                    signing_algorithms: vec![SigningAlgorithmId::AesGmac]
                }
                .into(),
                RdmaTransformCapabilities {
                    transforms: vec![RdmaTransformId::Encryption, RdmaTransformId::Signing]
                }
                .into(),
                CompressionCapabilities {
                    flags: CompressionCapsFlags::new().with_chained(true),
                    compression_algorithms: vec![
                        CompressionAlgorithm::LZ77,
                        CompressionAlgorithm::PatternV1
                    ]
                }
                .into(),
            ])
        } => "4100010011030500b921f8e01507aa41be3867febf5e2e112f000000000080000000800000008000a876d878c569db01000000000000000080002a00b0000000602806062b0601050502a01e301ca01a3018060a2b06010401823702021e060a2b06010401823702020a0000000000000100260000000000010020000100d5671b24a1e9ccc893f5555a3103435a852bc3cb1ad32dc51f92806ef3fb4dd40000020004000000000001000200000000000800040000000000010002000000000007000c00000000000200000000000000010002000000000003000c0000000000020000000100000002000400"
    }
}

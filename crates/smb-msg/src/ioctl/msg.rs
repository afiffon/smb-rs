use super::{
    common::{IoctlBuffer, IoctlRequestContent},
    fsctl::*,
};
#[cfg(feature = "server")]
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::binrw_util::prelude::*;
use smb_msg_derive::*;

#[cfg(feature = "client")]
use std::io::SeekFrom;

use crate::{
    FileId,
    dfsc::{ReqGetDfsReferral, ReqGetDfsReferralEx, RespGetDfsReferral},
};

/// SMB2 IOCTL request packet for issuing file system control or device control commands.
///
/// Used to send implementation-specific FSCTL/IOCTL commands across the network.
/// The structure size is fixed at 57 bytes regardless of the buffer size.
///
/// MS-SMB2 2.2.31
#[smb_request(size = 57)]
pub struct IoctlRequest {
    reserved: u16,
    /// Control code of the FSCTL/IOCTL method to execute
    pub ctl_code: u32,
    /// File identifier on which to perform the command
    pub file_id: FileId,
    /// Offset from SMB2 header to input data buffer
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _input_offset: PosMarker<u32>,
    /// Size in bytes of the input data
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _input_count: PosMarker<u32>,
    /// Maximum bytes server can return for input data in response
    pub max_input_response: u32,
    /// Must be set to 0 by client
    #[bw(calc = 0)]
    #[br(assert(output_offset == 0))]
    #[br(temp)]
    output_offset: u32,
    /// Must be set to 0 by client
    #[bw(calc = 0)]
    #[br(assert(output_count == 0))]
    #[br(temp)]
    output_count: u32,
    /// Maximum bytes server can return for output data in response
    pub max_output_response: u32,
    /// Indicates whether this is an IOCTL (0x00000000) or FSCTL (0x00000001) request
    pub flags: IoctlRequestFlags,
    reserved: u32,

    /// Variable-length buffer containing input data for the FSCTL/IOCTL command
    #[bw(write_with = PosMarker::write_aoff_size, args(&_input_offset, &_input_count))]
    #[br(map_stream = |s| s.take_seek(_input_count.value as u64), args(ctl_code, flags))]
    pub buffer: IoctlReqData,
}

#[cfg(all(feature = "client", not(feature = "server")))]
/// This is a helper trait that defines, for a certain FSCTL request type,
/// the response type and their matching FSCTL code.
pub trait FsctlRequest: for<'a> BinWrite<Args<'a> = ()> + Into<IoctlReqData> {
    type Response: FsctlResponseContent;
    const FSCTL_CODE: FsctlCodes;
}

#[cfg(all(feature = "server", not(feature = "client")))]
/// This is a helper trait that defines, for a certain FSCTL request type,
/// the response type and their matching FSCTL code.
pub trait FsctlRequest: for<'a> BinRead<Args<'a> = ()> + Into<IoctlReqData> {
    type Response: FsctlResponseContent;
    const FSCTL_CODE: FsctlCodes;
}

#[cfg(all(feature = "server", feature = "client"))]
/// This is a helper trait that defines, for a certain FSCTL request type,
/// the response type and their matching FSCTL code.
pub trait FsctlRequest:
    for<'a> BinWrite<Args<'a> = ()> + for<'b> BinRead<Args<'b> = ()> + Into<IoctlReqData>
{
    type Response: FsctlResponseContent;
    const FSCTL_CODE: FsctlCodes;
}

macro_rules! ioctl_req_data {
    ($($fsctl:ident: $model:ty, $response:ty, )+) => {
        pastey::paste! {

#[smb_request_binrw]
#[br(import(ctl_code: u32, flags: IoctlRequestFlags))]
pub enum IoctlReqData {
    $(
        #[doc = concat!(
            "Ioctl request for FSCTL code `",
            stringify!($fsctl),
            "`."
        )]
        #[br(pre_assert(ctl_code == FsctlCodes::$fsctl as u32 && flags.is_fsctl()))]
        [<Fsctl $fsctl:camel>]($model),
    )+

    /// General, non-smb FSCTL ioctl buffer.
    ///
    /// In case of an unsupported FSCTL code, this variant can be used to
    /// pass raw bytes.
    Ioctl(IoctlBuffer),
}

impl IoctlReqData {
    pub fn get_size(&self) -> u32 {
        use IoctlReqData::*;
        match self {
            $(
                [<Fsctl $fsctl:camel>](data) => data.get_bin_size(),
            )+
            Ioctl(data) => data.len() as u32,
        }
    }
}

$(
    impl FsctlRequest for $model {
        type Response = $response;
        const FSCTL_CODE: FsctlCodes = FsctlCodes::$fsctl;
    }

    impl From<$model> for IoctlReqData {
        fn from(model: $model) -> IoctlReqData {
            IoctlReqData::[<Fsctl $fsctl:camel>](model)
        }
    }
)+
        }
    }
}

// TODO: Enable non-fsctl ioctls. currently, we only support FSCTLs.
ioctl_req_data! {
    PipePeek: PipePeekRequest, PipePeekResponse,
    SrvEnumerateSnapshots: SrvEnumerateSnapshotsRequest, SrvEnumerateSnapshotsResponse,
    SrvRequestResumeKey: SrvRequestResumeKeyRequest, SrvRequestResumeKey,
    QueryNetworkInterfaceInfo: QueryNetworkInterfaceInfoRequest, NetworkInterfacesInfo,
    SrvCopychunk: SrvCopychunkCopy, SrvCopychunkResponse,
    SrvCopychunkWrite: SrvCopyChunkCopyWrite, SrvCopychunkResponse,
    SrvReadHash: SrvReadHashReq, SrvReadHashRes,
    LmrRequestResiliency: NetworkResiliencyRequest, LmrRequestResiliencyResponse,
    ValidateNegotiateInfo: ValidateNegotiateInfoRequest, ValidateNegotiateInfoResponse,
    DfsGetReferrals: ReqGetDfsReferral, RespGetDfsReferral,
    PipeWait: PipeWaitRequest, PipeWaitResponse,
    PipeTransceive: PipeTransceiveRequest, PipeTransceiveResponse,
    SetReparsePoint: SetReparsePointRequest, SetReparsePointResponse,
    DfsGetReferralsEx: ReqGetDfsReferralEx, RespGetDfsReferral,
    FileLevelTrim: FileLevelTrimRequest, FileLevelTrimResponse,
    QueryAllocatedRanges: QueryAllocRangesItem, QueryAllocRangesResult,
    OffloadRead: OffloadReadRequest, OffloadReadResponse,
}

/// Flags field indicating how to process the IOCTL operation.
///
/// MS-SMB2 2.2.31
#[smb_dtyp::mbitfield]
pub struct IoctlRequestFlags {
    /// When true (0x00000001), indicates this is an FSCTL request.
    /// When false (0x00000000), indicates this is an IOCTL request.
    pub is_fsctl: bool,
    #[skip]
    __: B31,
}

/// SMB2 IOCTL response packet containing results of an IOCTL request.
///
/// Sent by server to transmit the results of a client SMB2 IOCTL request.
/// The structure size is fixed at 49 bytes regardless of the buffer size.
///
/// MS-SMB2 2.2.32
#[smb_response(size = 49)]
pub struct IoctlResponse {
    reserved: u16,
    /// Control code of the FSCTL/IOCTL method that was executed
    pub ctl_code: u32,
    /// File identifier on which the command was performed
    pub file_id: FileId,
    /// Offset from SMB2 header to the Buffer field (should be set to buffer offset)
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    input_offset: PosMarker<u32>,
    /// Should be set to zero (exception for pass-through operations)
    #[bw(assert(in_buffer.is_empty()))] // there is an exception for pass-through operations.
    #[bw(try_calc = in_buffer.len().try_into())]
    #[br(assert(input_count == 0))]
    #[br(temp)]
    input_count: u32,

    /// Offset to output data buffer (either 0 or input_offset + input_count rounded to multiple of 8)
    #[br(assert(output_offset.value == 0 || output_offset.value == input_offset.value + input_count))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    output_offset: PosMarker<u32>,
    /// Size in bytes of the output data
    #[bw(try_calc = out_buffer.len().try_into())]
    #[br(temp)]
    output_count: u32,

    /// Flags
    reserved: u32,

    reserved: u32,

    /// Input data buffer (typically empty for responses except pass-through operations)
    #[br(seek_before = SeekFrom::Start(input_offset.value.into()))]
    #[br(count = input_count)]
    #[bw(write_with = PosMarker::write_aoff, args(&input_offset))]
    pub in_buffer: Vec<u8>,

    /// Output data buffer containing results of the FSCTL/IOCTL operation
    #[br(seek_before = SeekFrom::Start(output_offset.value.into()))]
    #[br(count = output_count)]
    #[bw(write_with = PosMarker::write_aoff, args(&output_offset))]
    pub out_buffer: Vec<u8>,
}

impl IoctlResponse {
    #[cfg(feature = "client")]
    /// Parses the FSCTL response output buffer into the specified response type.
    ///
    /// Validates that the control code matches the expected FSCTL codes for the
    /// response type before attempting to parse the output buffer.
    ///
    /// # Errors
    ///
    /// Returns `MissingFsctlDefinition` if the control code doesn't match
    /// any of the expected FSCTL codes for the response type.
    pub fn parse_fsctl<T>(&self) -> crate::Result<T>
    where
        T: FsctlResponseContent,
    {
        if !T::FSCTL_CODES.iter().any(|&f| f as u32 == self.ctl_code) {
            return Err(crate::SmbMsgError::MissingFsctlDefinition(self.ctl_code));
        }
        let mut cursor = std::io::Cursor::new(&self.out_buffer);
        Ok(T::read_le(&mut cursor).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use crate::*;

    use super::*;

    const REQ_IOCTL_BUFFER_CONTENT: &'static str = "0500000310000000980000000300000080000000010039000000000013f8a58f166fb54482c28f2dae140df50000000001000000000000000000020000000000010000000000000000000200000000000500000000000000010500000000000515000000173da72e955653f915dff280e9030000000000000000000000000000000000000000000001000000000000000000000002000000";

    test_request! {
        Ioctl {
            ctl_code: FsctlCodes::PipeTransceive as u32,
                file_id: [
                    0x28, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x85, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0,
                    0x0,
                ]
                .into(),
                max_input_response: 0,
                max_output_response: 1024,
                flags: IoctlRequestFlags::new().with_is_fsctl(true),
                buffer: IoctlReqData::FsctlPipeTransceive(
                    IoctlBuffer::from(
                        hex_to_u8_array! {REQ_IOCTL_BUFFER_CONTENT}
                    ).into(),
                ),
        } => const_format::concatcp!("3900000017c01100280500000c000000850000000c0000007800000098000000000000000000000000000000000400000100000000000000", REQ_IOCTL_BUFFER_CONTENT)
    }

    // Just to make things pretty; do NOT edit.
    const IOCTL_TEST_BUFFER_CONTENT: &'static str = "05000203100000000401000003000000ec00000001000000000002000000000001000000000000000000020000000000200000000000000001000000000000000c000e000000000000000200000000000000020000000000070000000000000000000000000000000600000000000000410056004900560056004d00000000000400000000000000010400000000000515000000173da72e955653f915dff28001000000000000000000020000000000010000000000000001000000000000000a000c00000000000000020000000000000000000000000006000000000000000000000000000000050000000000000061007600690076006e0000000100000000000000";

    test_response! {
        Ioctl {
                ctl_code: FsctlCodes::PipeTransceive as u32,
                file_id: [
                    0x28, 0x5, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x85, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0,
                    0x0,
                ]
                .into(),
                in_buffer: vec![],
                out_buffer: smb_tests::hex_to_u8_array! {IOCTL_TEST_BUFFER_CONTENT},
        } => const_format::concatcp!("3100000017c01100280500000c000000850000000c000000700000000000000070000000040100000000000000000000",IOCTL_TEST_BUFFER_CONTENT)
    }
}

use super::{
    common::{IoctlBuffer, IoctlRequestContent},
    fsctl::*,
};
use binrw::io::TakeSeekExt;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::binrw_util::prelude::*;
use std::io::SeekFrom;

use crate::{
    FileId,
    dfsc::{ReqGetDfsReferral, ReqGetDfsReferralEx, RespGetDfsReferral},
};

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct IoctlRequest {
    #[bw(calc = 57)]
    #[br(assert(struct_size == 57))]
    struct_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    _input_offset: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    _input_count: PosMarker<u32>,
    pub max_input_response: u32,
    #[bw(calc = 0)]
    #[br(assert(output_offset == 0))]
    output_offset: u32,
    #[bw(calc = 0)]
    #[br(assert(output_count == 0))]
    output_count: u32,
    pub max_output_response: u32,
    pub flags: IoctlRequestFlags,
    #[bw(calc = 0)]
    reserved2: u32,

    #[bw(write_with = PosMarker::write_aoff_size, args(&_input_offset, &_input_count))]
    #[br(map_stream = |s| s.take_seek(_input_count.value as u64), args(ctl_code, flags))]
    pub buffer: IoctlReqData,
}

/// This is a helper trait that defines, for a certain FSCTL request type,
/// the response type and their matching FSCTL code.
pub trait FsctlRequest: for<'a> BinWrite<Args<'a> = ()> + Into<IoctlReqData> {
    type Response: FsctlResponseContent;
    const FSCTL_CODE: FsctlCodes;
}

macro_rules! ioctl_req_data {
    ($($fsctl:ident: $model:ty, $response:ty, )+) => {
        pastey::paste! {

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(ctl_code: u32, flags: IoctlRequestFlags))]
pub enum IoctlReqData {
    $(
        #[br(pre_assert(ctl_code == FsctlCodes::$fsctl as u32 && flags.is_fsctl()))]
        [<Fsctl $fsctl:camel>]($model),
    )+

    /// General Ioctl request, providing a buffer as an input.
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

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct IoctlRequestFlags {
    pub is_fsctl: bool,
    #[skip]
    __: B31,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct IoctlResponse {
    #[bw(calc = 49)]
    #[br(assert(struct_size == 49))]
    struct_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
    pub ctl_code: u32,
    pub file_id: FileId,
    #[bw(calc = PosMarker::default())]
    input_offset: PosMarker<u32>,
    #[bw(assert(in_buffer.is_empty()))] // there is an exception for pass-through operations.
    #[bw(try_calc = in_buffer.len().try_into())]
    #[br(assert(input_count == 0))]
    input_count: u32,

    // is either (0) or (input_offset + input_count)
    #[br(assert(output_offset.value == 0 || output_offset.value == input_offset.value + input_count))]
    #[bw(calc = PosMarker::default())]
    output_offset: PosMarker<u32>,
    #[bw(try_calc = out_buffer.len().try_into())]
    output_count: u32,

    #[bw(calc = 0)] // reserved.
    #[br(assert(flags == 0))]
    flags: u32,
    #[bw(calc = 0)]
    reserved2: u32,

    #[br(seek_before = SeekFrom::Start(input_offset.value.into()))]
    #[br(count = input_count)]
    #[bw(write_with = PosMarker::write_aoff, args(&input_offset))]
    pub in_buffer: Vec<u8>,

    #[br(seek_before = SeekFrom::Start(output_offset.value.into()))]
    #[br(count = output_count)]
    #[bw(write_with = PosMarker::write_aoff, args(&output_offset))]
    pub out_buffer: Vec<u8>,
}

impl IoctlResponse {
    /// Parses the response content into the specified type.
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

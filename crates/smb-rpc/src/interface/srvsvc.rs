#![allow(unused_parens)]

use crate::{interface::*, pdu::DceRpcSyntaxId};
use smb_dtyp::make_guid;

use crate::ndr64::*;
use binrw::prelude::*;
use maybe_async::maybe_async;
use modular_bitfield::prelude::*;
/// [SHARE_ENUM_STRUCT](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/79ee052e-e16b-4ec5-b4b7-e99777c26eca>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct ShareEnumStruct {
    #[bw(calc = share_info.level().into())]
    level: NdrAlign<ShareInfoLevel>,
    #[br(args(*level))]
    share_info: NdrAlign<ShareEnumUnion>,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u32))]
pub enum ShareInfoLevel {
    Info0 = 0,
    Info1 = 1,
    Info2 = 2,
    Info501 = 501,
    Info502 = 502,
    Info503 = 503,
}

/// [`SHARE_ENUM_UNION`](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/7894d7e4-bb82-419c-b431-0247c8ae4dfe>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import(level: ShareInfoLevel))]
enum ShareEnumUnion {
    #[brw(magic = 0u64)]
    #[br(pre_assert(level == ShareInfoLevel::Info0))]
    Info0(NdrPtr<ShareInfoContainer<ShareInfo0>>),
    #[brw(magic = 1u64)]
    #[br(pre_assert(level == ShareInfoLevel::Info1))]
    Info1(NdrPtr<ShareInfoContainer<ShareInfo1>>),
}

impl ShareEnumUnion {
    /// Returns the level of the share info contained in this union.
    pub fn level(&self) -> ShareInfoLevel {
        match self {
            ShareEnumUnion::Info0(_) => ShareInfoLevel::Info0,
            ShareEnumUnion::Info1(_) => ShareInfoLevel::Info1,
        }
    }
}

/// [`SHARE_INFO_1_CONTAINER`](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/919abd5d-87d9-4ffa-b4b1-632a66053bc6>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct ShareInfoContainer<T>
where
    T: ShareInfo,
{
    #[bw(calc = (buffer.as_ref().map_or(0, |x| x.len() as u32)).into())]
    entries_read: NdrAlign<u32>,
    #[br(args(None, NdrPtrReadMode::NoArraySupport, (*entries_read as u64,)))]
    buffer: NdrPtr<NdrArray<T>>,
}

trait ShareInfo:
    for<'a> BinRead<Args<'a> = (Option<&'a Self>,)>
    + for<'a> BinWrite<Args<'a> = (NdrPtrWriteStage,)>
    + Clone
    + PartialEq
    + Eq
    + 'static
{
}

/// [`SHARE_INFO_1`](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/fc69f110-998d-4c16-9667-514e22fdd80b>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[bw(import(stage: NdrPtrWriteStage))]
#[br(import(prev: Option<&Self>))]
pub struct ShareInfo1 {
    #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
    #[br(args(prev.map(|x| &x.netname), NdrPtrReadMode::WithArraySupport, ()))]
    pub netname: NdrPtr<NdrString<u16>>,
    #[bw(if(stage == NdrPtrWriteStage::ArraySupportWriteRefId))]
    #[br(args(prev.map(|x| &**x.share_type)))]
    pub share_type: NdrArrayStructureElement<ShareType>,
    #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
    #[br(args(prev.map(|x| &x.remark), NdrPtrReadMode::WithArraySupport, ()))]
    pub remark: NdrPtr<NdrString<u16>>,
}

/// [`SHARE_INFO_0`](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/73a25288-8086-4975-91a3-5cbee5b590cc>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[bw(import(stage: NdrPtrWriteStage))]
#[br(import(prev: Option<&Self>))]
pub struct ShareInfo0 {
    #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
    #[br(args(prev.map(|x| &x.netname), NdrPtrReadMode::WithArraySupport, ()))]
    netname: NdrPtr<NdrString<u16>>,
}

impl ShareInfo for ShareInfo0 {}
impl ShareInfo for ShareInfo1 {}

#[derive(BitfieldSpecifier, Debug, Clone, Copy, PartialEq, Eq)]
#[bits = 2]
pub enum ShareKind {
    Disk = 0,
    PrintQ = 1,
    Device = 2,
    IPC = 3,
}

/// Share types
///
/// [MS-SRVS](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/6069f8c0-c93f-43a0-a5b4-7ed447eb4b84>)
#[smb_dtyp::mbitfield]
pub struct ShareType {
    pub kind: ShareKind,
    #[skip]
    __: B23,
    pub cluster_fs: bool,
    pub cluster_sofs: bool,
    pub cluster_dfs: bool,
    #[skip]
    __: B2,
    pub temporary: bool,
    pub special: bool,
}

impl ShareType {
    /// Returns whether this is the windows IPC share (IPC$)
    pub fn is_win_ipc(&self) -> bool {
        self.kind() == ShareKind::IPC && self.special()
    }
}

// FYI: RPC top-level stub data is aligned to min(8, arg_size0, arg_size1, ...) bytes.
// DCE/RPC Chap. 12.3: RPC PDU Encodings/Alignment.

/// Input arguments for [NetrShareEnum](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct NetrShareEnumIn {
    server_name: NdrAlign<NdrPtr<NdrString<u16>>, 4>,
    info_struct: NdrAlign<ShareEnumStruct, 4>,
    prefered_maximum_length: NdrAlign<u32, 4>,
    resume_handle: NdrAlign<NdrPtr<u32>, 4>,
}

/// Return value and out params of [NetrShareEnum](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
struct NetrShareEnumOut {
    info_struct: NdrAlign<ShareEnumStruct, 4>,
    total_entries: NdrAlign<u32, 4>,
    resume_handle: NdrAlign<NdrPtr<u32>, 4>,
}

impl RpcCall for NetrShareEnumIn {
    const OPNUM: u16 = 0xf;

    type ResponseType = NetrShareEnumOut;
}

pub struct SrvSvc<T>
where
    T: BoundRpcConnection,
{
    bound_pipe: T,
}

impl<T> SrvSvc<T>
where
    T: BoundRpcConnection,
{
    #[maybe_async]
    pub async fn netr_share_enum(&mut self, server_name: &str) -> crate::Result<Vec<ShareInfo1>> {
        let input_struct = NetrShareEnumIn {
            server_name: NdrPtr::from(server_name.parse::<NdrString<u16>>().unwrap()).into(),
            info_struct: ShareEnumStruct {
                share_info: ShareEnumUnion::Info1(NdrPtr::from(ShareInfoContainer::<ShareInfo1> {
                    buffer: NdrPtr::from(None),
                }))
                .into(),
            }
            .into(),
            prefered_maximum_length: u32::MAX.into(),
            resume_handle: NdrPtr::<u32>::from(None).into(),
        };
        let enum_result = self.bound_pipe.send_receive(input_struct).await?;
        let mut result: Vec<ShareInfo1> = vec![];
        if let ShareEnumUnion::Info1(container) = &*enum_result.info_struct.share_info {
            match &**container {
                None => {
                    return Err(crate::SmbRpcError::InvalidResponseData(
                        "NetrShareEnum returned no data",
                    ));
                }
                Some(x) => match &*x.buffer {
                    None => {
                        return Err(crate::SmbRpcError::InvalidResponseData(
                            "NetrShareEnum returned no data",
                        ));
                    }
                    Some(y) => {
                        for share_info in y.iter() {
                            let share_info = &**share_info;
                            result.push(share_info.clone());
                        }
                    }
                },
            }
        }
        Ok(result)
    }
}

impl<T> super::base::RpcInterface<T> for SrvSvc<T>
where
    T: BoundRpcConnection,
{
    const SYNTAX_ID: DceRpcSyntaxId = DceRpcSyntaxId {
        uuid: make_guid!("4b324fc8-1670-01d3-1278-5a47bf6ee188"),
        version: 3,
    };

    fn new(bound_pipe: T) -> Self {
        SrvSvc { bound_pipe }
    }
}

#[cfg(test)]
mod test {
    use smb_tests::*;

    use super::*;

    test_binrw_read! {
        struct NetrShareEnumOut {
                info_struct: ShareEnumStruct {
                    share_info: ShareEnumUnion::Info1(
                        ShareInfoContainer::<ShareInfo1> {
                            buffer: Into::<NdrArray<ShareInfo1>>::into(vec![
                                ShareInfo1 {
                                    netname: "ADMIN$".parse::<NdrString<u16>>().unwrap().into(),
                                    share_type: ShareType::new().with_special(true).into(),
                                    remark: "Remote Admin"
                                        .parse::<NdrString<u16>>()
                                        .unwrap()
                                        .into(),
                                },
                                ShareInfo1 {
                                    netname: "C$".parse::<NdrString<u16>>().unwrap().into(),
                                    share_type: ShareType::new().with_special(true).into(),
                                    remark: "Default share"
                                        .parse::<NdrString<u16>>()
                                        .unwrap()
                                        .into(),
                                },
                                ShareInfo1 {
                                    netname: "IPC$".parse::<NdrString<u16>>().unwrap().into(),
                                    share_type: ShareType::new()
                                        .with_special(true)
                                        .with_kind(ShareKind::IPC)
                                        .into(),
                                    remark: "Remote IPC".parse::<NdrString<u16>>().unwrap().into(),
                                },
                                ShareInfo1 {
                                    netname: "LocalAdminShare"
                                        .parse::<NdrString<u16>>()
                                        .unwrap()
                                        .into(),
                                    share_type: ShareType::new().into(),
                                    remark: "".parse::<NdrString<u16>>().unwrap().into(),
                                },
                                ShareInfo1 {
                                    netname: "MyShare".parse::<NdrString<u16>>().unwrap().into(),
                                    share_type: ShareType::new().into(),
                                    remark: "".parse::<NdrString<u16>>().unwrap().into(),
                                },
                                ShareInfo1 {
                                    netname: "PublicShare"
                                        .parse::<NdrString<u16>>()
                                        .unwrap()
                                        .into(),
                                    share_type: ShareType::new().into(),
                                    remark: "".parse::<NdrString<u16>>().unwrap().into(),
                                },
                            ])
                            .into()
                        }
                        .into()
                    )
                    .into()
                }
                .into(),
                total_entries: 6.into(),
                resume_handle: NdrPtr::<u32>::from(None).into(),
            } => "010000000000000001000000000000000000020000000000060000000000000000000200000000000600000000000000000002000000000000000080000000000000020000000000000002000000000000000080000000000000020000000000000002000000000003000080000000000000020000000000000002000000000000000000000000000000020000000000000002000000000000000000000000000000020000000000000002000000000000000000000000000000020000000000070000000000000000000000000000000700000000000000410044004d0049004e002400000000000d0000000000000000000000000000000d00000000000000520065006d006f00740065002000410064006d0069006e00000000000000000003000000000000000000000000000000030000000000000043002400000000000e0000000000000000000000000000000e00000000000000440065006600610075006c007400200073006800610072006500000000000000050000000000000000000000000000000500000000000000490050004300240000000000000000000b0000000000000000000000000000000b00000000000000520065006d006f00740065002000490050004300000000001000000000000000000000000000000010000000000000004c006f00630061006c00410064006d0069006e0053006800610072006500000001000000000000000000000000000000010000000000000000000000000000000800000000000000000000000000000008000000000000004d00790053006800610072006500000001000000000000000000000000000000010000000000000000000000000000000c0000000000000000000000000000000c000000000000005000750062006c00690063005300680061007200650000000100000000000000000000000000000001000000000000000000000006000000000000000000000000000000"
    }

    smb_tests::test_binrw_write! {
        struct NetrShareEnumIn {
            server_name: Into::<NdrPtr<_>>::into(r"\\localhost".parse::<NdrString<u16>>().unwrap())
                .into(),
            info_struct: ShareEnumStruct {
                share_info: ShareEnumUnion::Info1(NdrPtr::from(ShareInfoContainer::<ShareInfo1> {
                    buffer: NdrPtr::from(None),
                }))
                .into(),
            }
            .into(),
            prefered_maximum_length: 4294967295.into(),
            resume_handle: NdrPtr::<u32>::from(None).into(),
        } => "00000200000000000c0000000000000000000000000000000c000000000000005c005c006c006f00630061006c0068006f0073007400000001000000000000000100000000000000000002000000000000000000000000000000000000000000ffffffff000000000000000000000000"
    }
}

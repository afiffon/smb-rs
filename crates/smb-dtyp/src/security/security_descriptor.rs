//! MS-DTYP 2.4.6: Security Descriptor

use binrw::prelude::*;

use crate::binrw_util::prelude::*;

use super::{ACL, SID};

/// Security Descriptor - [MS-DTYP 2.4.6](<https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d>)
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
#[brw(little)]
pub struct SecurityDescriptor {
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _sd_begin: PosMarker<()>,

    #[bw(calc = 1)]
    #[br(temp)]
    #[br(assert(_revision == 1))]
    _revision: u8,
    pub sbz1: u8,
    #[brw(assert(control.self_relative()))]
    pub control: SecurityDescriptorControl,

    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    offset_owner: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    offset_group: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    offset_sacl: PosMarker<u32>,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    offset_dacl: PosMarker<u32>,

    #[br(if(offset_owner.value != 0))]
    #[bw(if(owner_sid.is_some()))]
    #[bw(write_with = PosMarker::write_roff_b, args(&offset_owner, &_sd_begin))]
    pub owner_sid: Option<SID>,

    #[br(if(offset_group.value != 0))]
    #[bw(if(group_sid.is_some()))]
    #[bw(write_with = PosMarker::write_roff_b, args(&offset_group, &_sd_begin))]
    pub group_sid: Option<SID>,

    #[bw(assert(sacl.is_some() == control.sacl_present()))]
    #[br(assert((offset_sacl.value != 0) == (control.sacl_present())))]
    #[bw(if(sacl.is_some()))]
    #[bw(write_with = PosMarker::write_roff_b, args(&offset_sacl, &_sd_begin))]
    #[br(if(offset_sacl.value != 0))]
    pub sacl: Option<ACL>,

    #[bw(assert(dacl.is_some() == control.dacl_present()))]
    #[br(assert((offset_dacl.value != 0) == control.dacl_present()))]
    #[bw(if(dacl.is_some()))]
    #[bw(write_with = PosMarker::write_roff_b, args(&offset_dacl, &_sd_begin))]
    #[br(if(offset_dacl.value != 0))]
    pub dacl: Option<ACL>,
}

#[smb_dtyp_derive::mbitfield]
pub struct SecurityDescriptorControl {
    pub owner_defaulted: bool,
    pub group_defaulted: bool,
    pub dacl_present: bool,
    pub dacl_defaulted: bool,

    pub sacl_present: bool,
    pub sacl_defaulted: bool,
    pub dacl_trusted: bool,
    pub server_security: bool,

    pub dacl_computed: bool,
    pub sacl_computed: bool,
    pub dacl_auto_inherited: bool,
    pub sacl_auto_inherited: bool,

    pub dacl_protected: bool,
    pub sacl_protected: bool,
    pub rm_control_valid: bool,
    pub self_relative: bool,
}

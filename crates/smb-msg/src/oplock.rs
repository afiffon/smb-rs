use crate::FileId;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::Guid;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct OplockBreakMsg {
    #[bw(calc = 24)]
    #[br(assert(_structure_size == 24))]
    _structure_size: u16,
    oplock_level: u8,
    #[bw(calc = 0)]
    _reserved: u8,
    #[bw(calc = 0)]
    reserved2: u32,
    file_id: FileId,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct LeaseBreakNotify {
    #[bw(calc = 44)]
    #[br(assert(_structure_size == 44))]
    _structure_size: u16,
    new_epoch: u16,
    ack_required: u32,
    lease_key: Guid,
    current_lease_state: LeaseState,
    new_lease_state: LeaseState,
    #[bw(calc = 0)]
    #[br(assert(break_reason == 0))]
    break_reason: u32,
    #[bw(calc = 0)]
    #[br(assert(access_mask_hint == 0))]
    access_mask_hint: u32,
    #[bw(calc = 0)]
    #[br(assert(share_mask_hint == 0))]
    share_mask_hint: u32,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[brw(repr(u8))]
pub enum OplockLevel {
    None = 0,
    II = 1,
    Exclusive = 2,
}

#[bitfield]
#[derive(BinWrite, BinRead, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[bw(map = |&x| Self::into_bytes(x))]
#[br(map = Self::from_bytes)]
pub struct LeaseState {
    pub read_caching: bool,
    pub handle_caching: bool,
    pub write_caching: bool,
    #[skip]
    __: B29,
}

// Those are all the same.
pub type OplockBreakNotify = OplockBreakMsg;
pub type OplockBreakAck = OplockBreakMsg;
pub type OplockBreakResponse = OplockBreakMsg;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct LeaseBreakAckResponse {
    #[bw(calc = 36)]
    #[br(assert(_structure_size == 36))]
    _structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
    #[bw(calc = 0)] // reserved
    #[br(assert(flags == 0))]
    flags: u32,
    lease_key: Guid,
    lease_state: LeaseState,
    #[bw(calc = 0)] // reserved
    #[br(assert(lease_duration == 0))]
    lease_duration: u64,
}

// Those are the same.
pub type LeaseBreakAck = LeaseBreakAckResponse;
pub type LeaseBreakResponse = LeaseBreakAckResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use smb_tests::*;

    test_binrw! {
        struct LeaseBreakNotify {
            new_epoch: 2,
            ack_required: 1,
            lease_key: "70c8619e-165d-315e-d492-a01b0cbb3af2".parse().unwrap(),
            current_lease_state: LeaseState::new()
                .with_read_caching(true)
                .with_handle_caching(true),
            new_lease_state: LeaseState::new(),
        } => "2c000200010000009e61c8705d165e31d492a01b0cbb3af20300000000000000000000000000000000000000"
    }

    test_binrw! {
        struct LeaseBreakAck {
            lease_key: "70c8619e-165d-315e-d492-a01b0cbb3af2".parse().unwrap(),
            lease_state: LeaseState::new(),
        } => "24000000000000009e61c8705d165e31d492a01b0cbb3af2000000000000000000000000"
    }

    test_binrw! {
        struct LeaseBreakAckResponse {
            lease_key: "70c8619e-165d-315e-d492-a01b0cbb3af2".parse().unwrap(),
            lease_state: LeaseState::new(),
        } => "24000000000000009e61c8705d165e31d492a01b0cbb3af2000000000000000000000000"
    }
}

use super::FileId;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_msg_derive::*;

#[smb_request(size = 48)]
pub struct LockRequest {
    #[bw(try_calc = locks.len().try_into())]
    lock_count: u16,
    pub lock_sequence: LockSequence,
    pub file_id: FileId,
    #[br(count = lock_count)]
    pub locks: Vec<LockElement>,
}

#[smb_dtyp::mbitfield]
pub struct LockSequence {
    pub number: B4,
    pub index: B28,
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct LockElement {
    pub offset: u64,
    pub length: u64,
    pub flags: LockFlag,
    #[bw(calc = 0)]
    _reserved: u32,
}

#[smb_dtyp::mbitfield]
pub struct LockFlag {
    pub shared: bool,
    pub exclusive: bool,
    pub unlock: bool,
    pub fail_immediately: bool,
    #[skip]
    __: B28,
}

#[smb_response(size = 4)]
#[derive(Default)]
pub struct LockResponse {
    #[bw(calc = 0)]
    pub _reserved: u16,
}

#[cfg(test)]
mod tests {

    // TODO: tests
}

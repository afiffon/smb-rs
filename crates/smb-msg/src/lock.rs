//! Classic Lock request & response.

use super::FileId;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_msg_derive::*;

/// SMB2 LOCK Request packet used to lock or unlock portions of a file.
/// Multiple segments of the file can be affected with a single request,
/// but they all must be within the same file.
///
/// Reference: MS-SMB2 2.2.26
#[smb_request(size = 48)]
pub struct LockRequest {
    /// Number of SMB2_LOCK_ELEMENT structures in the locks array.
    /// Must be greater than or equal to 1.
    #[bw(try_calc = locks.len().try_into())]
    lock_count: u16,
    /// Lock sequence information for the request.
    pub lock_sequence: LockSequence,
    /// File identifier on which to perform the byte range locks or unlocks.
    pub file_id: FileId,
    /// Array of lock elements defining the ranges to be locked or unlocked.
    #[br(count = lock_count)]
    pub locks: Vec<LockElement>,
}

/// Lock sequence information containing sequence number and index.
/// In SMB 2.0.2 dialect, this field is unused and must be reserved.
/// In all other dialects, contains sequence number and index fields.
///
/// Reference: MS-SMB2 2.2.26
#[smb_dtyp::mbitfield]
pub struct LockSequence {
    /// 4-bit integer value containing the lock sequence number.
    pub number: B4,
    /// 28-bit integer value that must contain a value from 0 to 64, where 0 is reserved.
    pub index: B28,
}

/// SMB2_LOCK_ELEMENT structure used to indicate segments of files
/// that are locked or unlocked in SMB2 LOCK requests.
///
/// Reference: MS-SMB2 2.2.26.1
#[smb_request_binrw]
pub struct LockElement {
    /// Starting offset in bytes from where the range being locked or unlocked starts.
    pub offset: u64,
    /// Length in bytes of the range being locked or unlocked.
    pub length: u64,
    /// Flags describing how the range is being locked or unlocked and how to process the operation.
    pub flags: LockFlag,
    reserved: u32,
}

/// Lock flags describing how the range is being locked or unlocked.
/// Valid combinations are: shared lock, exclusive lock, unlock,
/// or any of shared/exclusive combined with fail_immediately.
///
/// Reference: MS-SMB2 2.2.26.1
#[smb_dtyp::mbitfield]
pub struct LockFlag {
    /// Range must be locked shared, allowing other opens to read or take shared locks.
    /// Other opens must not be allowed to write within the range.
    pub shared: bool,
    /// Range must be locked exclusive, not allowing other opens to read, write, or lock within the range.
    pub exclusive: bool,
    /// Range must be unlocked from a previous lock. Unlock range must be identical to lock range.
    pub unlock: bool,
    /// Lock operation must fail immediately if it conflicts with an existing lock,
    /// instead of waiting for the range to become available.
    pub fail_immediately: bool,
    #[skip]
    __: B28,
}

/// SMB2 LOCK Response packet sent by the server in response to an SMB2 LOCK Request.
///
/// Reference: MS-SMB2 2.2.27
#[smb_response(size = 4)]
#[derive(Default)]
pub struct LockResponse {
    reserved: u16,
}

#[cfg(test)]
mod tests {

    // TODO: tests
}

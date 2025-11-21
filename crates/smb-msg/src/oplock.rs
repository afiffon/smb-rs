//! OpLock messages (requests, responses, notifications)

use crate::FileId;
use binrw::prelude::*;
use modular_bitfield::prelude::*;
use smb_dtyp::Guid;
use smb_msg_derive::*;

/// Oplock Break Notification/Acknowledgment/Response message.
///
/// Used for oplock break notification (server to client), acknowledgment (client to server),
/// and response (server to client) operations. The structure is identical for all three operations.
///
/// Reference: MS-SMB2 2.2.23.1, 2.2.24.1, 2.2.25.1
#[smb_request_response(size = 12)]
pub struct OplockBreakMsg {
    /// The oplock level. For notifications, this is the maximum level the server will accept.
    /// For acknowledgments, this is the lowered level the client accepts.
    /// For responses, this is the granted level.
    oplock_level: u8,
    reserved: u8,
    reserved: u32,
    /// The file identifier on which the oplock break occurred.
    file_id: FileId,
}

/// Lease Break Notification message.
///
/// Sent by the server when the underlying object store indicates that a lease is being broken,
/// representing a change in the lease state. Not valid for SMB 2.0.2 dialect.
///
/// Reference: MS-SMB2 2.2.23.2
#[smb_response(size = 44)]
pub struct LeaseBreakNotify {
    /// A 16-bit unsigned integer indicating a lease state change by the server.
    /// Only valid for SMB 3.x dialect family. For SMB 2.1, this field is reserved.
    new_epoch: u16,
    /// Flag indicating whether a Lease Break Acknowledgment is required.
    ack_required: u32,
    /// The client-generated key that identifies the owner of the lease.
    lease_key: Guid,
    /// The current lease state of the open.
    current_lease_state: LeaseState,
    /// The new lease state for the open.
    new_lease_state: LeaseState,
    #[bw(calc = 0)]
    #[br(assert(break_reason == 0))]
    #[br(temp)]
    break_reason: u32,
    #[bw(calc = 0)]
    #[br(assert(access_mask_hint == 0))]
    #[br(temp)]
    access_mask_hint: u32,
    #[bw(calc = 0)]
    #[br(assert(share_mask_hint == 0))]
    #[br(temp)]
    share_mask_hint: u32,
}

/// Oplock level values used in oplock break operations.
///
/// Reference: MS-SMB2 2.2.23.1
#[smb_message_binrw]
#[brw(repr(u8))]
pub enum OplockLevel {
    /// No oplock is available.
    None = 0,
    /// A level II oplock is available.
    II = 1,
    /// Exclusive oplock is available.
    Exclusive = 2,
}

/// Lease state bitfield representing different types of caching permissions.
///
/// Reference: MS-SMB2 2.2.23.2
#[smb_dtyp::mbitfield]
pub struct LeaseState {
    /// A read caching lease is granted/requested.
    pub read_caching: bool,
    /// A handle caching lease is granted/requested.
    pub handle_caching: bool,
    /// A write caching lease is granted/requested.
    pub write_caching: bool,
    #[skip]
    __: B29,
}

// Type aliases for oplock break operations that use the same structure.
// Reference: MS-SMB2 2.2.23.1, 2.2.24.1, 2.2.25.1

/// Oplock Break Notification - sent by server when an oplock is being broken.
pub type OplockBreakNotify = OplockBreakMsg;

/// Oplock Break Acknowledgment - sent by client in response to oplock break notification.
pub type OplockBreakAck = OplockBreakMsg;

/// Oplock Break Response - sent by server in response to oplock break acknowledgment.
pub type OplockBreakResponse = OplockBreakMsg;

/// Lease Break Acknowledgment/Response message.
///
/// Used for lease break acknowledgment (client to server) and response (server to client).
/// The structure is identical for both operations. Not valid for SMB 2.0.2 dialect.
///
/// Reference: MS-SMB2 2.2.24.2, 2.2.25.2
#[smb_request_response(size = 36)]
pub struct LeaseBreakAckResponse {
    reserved: u16,
    /// Flags (reserved)
    reserved: u32,

    /// The client-generated key that identifies the owner of the lease.
    lease_key: Guid,
    /// The lease state. For acknowledgments, this must be a subset of the lease state
    /// granted by the server. For responses, this is the requested lease state.
    lease_state: LeaseState,

    /// Lease duration (reserved)
    reserved: u64,
}

// Type aliases for lease break operations that use the same structure.
// Reference: MS-SMB2 2.2.24.2, 2.2.25.2

/// Lease Break Acknowledgment - sent by client in response to lease break notification.
pub type LeaseBreakAck = LeaseBreakAckResponse;

/// Lease Break Response - sent by server in response to lease break acknowledgment.
pub type LeaseBreakResponse = LeaseBreakAckResponse;

#[cfg(test)]
mod tests {
    use crate::*;

    use super::*;

    test_binrw_response! {
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

    test_binrw_response! {
        struct LeaseBreakAck {
            lease_key: "70c8619e-165d-315e-d492-a01b0cbb3af2".parse().unwrap(),
            lease_state: LeaseState::new(),
        } => "24000000000000009e61c8705d165e31d492a01b0cbb3af2000000000000000000000000"
    }

    test_binrw_response! {
        struct LeaseBreakAckResponse {
            lease_key: "70c8619e-165d-315e-d492-a01b0cbb3af2".parse().unwrap(),
            lease_state: LeaseState::new(),
        } => "24000000000000009e61c8705d165e31d492a01b0cbb3af2000000000000000000000000"
    }
}

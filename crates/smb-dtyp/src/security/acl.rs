//! MS-DTYP 2.4.5: ACL

use binrw::prelude::*;

use crate::binrw_util::prelude::*;

use super::ACE;

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ACL {
    pub acl_revision: AclRevision,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(sbz1 == 0))]
    sbz1: u8,
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    _acl_size: PosMarker<u16>,
    #[bw(calc = ace.len() as u16)]
    #[br(temp)]
    ace_count: u16,
    #[bw(calc = 0)]
    #[br(temp)]
    #[br(assert(sbz2 == 0))]
    sbz2: u16,

    #[br(count = ace_count)]
    #[bw(write_with = PosMarker::write_size_plus, args(&_acl_size, Self::HEADER_SIZE))]
    pub ace: Vec<ACE>,
}

impl ACL {
    const HEADER_SIZE: u64 = 8;

    /// Orders the ACEs in the ACL according to the standard order.
    ///
    /// Note that since we do not have sufficient information about the inheritance,
    /// we only apply order which is independent of inheritance.
    ///
    /// The following steps describe the preferred order:
    /// 1. ✅ All explicit ACEs are placed in a group before any inherited ACEs.
    /// 2. ✅ Within the group of explicit ACEs, access-denied ACEs are placed before access-allowed ACEs.
    /// 3. ❌ Inherited ACEs are placed in the order in which they are inherited. ACEs inherited from the child object's parent come first, then ACEs inherited from the grandparent, and so on up the tree of objects.
    /// 4. ❌ For each level of inherited ACEs, access-denied ACEs are placed before access-allowed ACEs.
    ///
    /// See more information on [Order of ACEs in a DACL - MSDN](<https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl>)
    pub fn order_aces(&mut self) {
        self.ace.sort_by(Self::sort_aces_by);
    }

    /// Whether ACE ordering rules apply to this ACL.
    ///
    /// See [`order_aces`][ACL::order_aces] for the ordering rules.
    pub fn is_ace_sorted(&self) -> bool {
        self.ace
            .is_sorted_by(|a, b| Self::sort_aces_by(a, b).is_le())
    }

    /// Sorting function for ACEs.
    ///
    /// See [`order_aces`][ACL::order_aces] for the ordering rules.
    fn sort_aces_by(a: &ACE, b: &ACE) -> std::cmp::Ordering {
        let a_inherited = a.ace_flags.inherited();
        let b_inherited = b.ace_flags.inherited();
        if a_inherited != b_inherited {
            return a_inherited.cmp(&b_inherited); // (1)
        }
        if a_inherited {
            return std::cmp::Ordering::Equal; // keep original order for inherited ACEs (3)
        }
        let a_denied = a.value.is_access_allowed();
        let b_denied = b.value.is_access_allowed();
        a_denied.cmp(&b_denied) // (2) on explicit ACEs, access-denied first <=> access-allowed last
        // Note: the sort is stable, so we keep the original order for inherited ACEs
    }

    /// Insert an ACE into the ACL, maintaining the correct order.
    /// See [`order_aces`][ACL::order_aces] for the ordering rules.
    pub fn insert_ace(&mut self, ace: ACE) {
        self.ace.push(ace);
        self.order_aces();
    }
}

#[binrw::binrw]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[brw(repr(u8))]
pub enum AclRevision {
    /// Windows NT 4.0
    Nt4 = 2,
    /// Active directory
    DS = 4,
}

#[cfg(test)]
mod tests {
    use crate::security::{AccessAce, AccessMask, AceFlags, AceValue, SID};
    use std::str::FromStr;

    use super::*;
    #[test]
    fn test_sort_acls() {
        let fake_access_ace = AccessAce {
            access_mask: AccessMask::new(),
            sid: SID::from_str(SID::S_EVERYONE).unwrap(),
        };
        let explicit_deny_first = ACE {
            ace_flags: AceFlags::new().with_inherited(false),
            value: AceValue::AccessDenied(fake_access_ace.clone()),
        };
        let explicit_allow_second = ACE {
            ace_flags: AceFlags::new().with_inherited(false),
            value: AceValue::AccessAllowed(fake_access_ace.clone()),
        };
        // Let's make sure inherited remain untouched (in allow/deny difference)
        let inherited_last_1 = ACE {
            ace_flags: AceFlags::new().with_inherited(true),
            value: AceValue::AccessAllowed(fake_access_ace.clone()),
        };
        let inherited_last_2 = ACE {
            ace_flags: AceFlags::new().with_inherited(true),
            value: AceValue::AccessDenied(fake_access_ace.clone()),
        };
        let dacl = ACL {
            acl_revision: AclRevision::Nt4,
            ace: vec![
                inherited_last_1.clone(),      // should go third - before inherited_last_2
                explicit_allow_second.clone(), // should go second
                explicit_deny_first.clone(),   // should go first
                inherited_last_2.clone(), // should stay in place - inherited_last_1 before inherited_last_2
            ],
        };

        assert!(!dacl.is_ace_sorted());

        let mut new_dacl = dacl.clone();
        new_dacl.order_aces();

        assert!(new_dacl.is_ace_sorted());

        assert_eq!(
            new_dacl,
            ACL {
                acl_revision: AclRevision::Nt4,
                ace: vec![
                    explicit_deny_first,
                    explicit_allow_second,
                    inherited_last_1,
                    inherited_last_2,
                ]
            }
        );
    }
}

//! Cancel Request

use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CancelRequest {
    #[br(assert(_structure_size == 4))]
    #[bw(calc = 4)]
    _structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_tests::*;

    test_binrw! {
        struct CancelRequest {} => "04000000"
    }
}

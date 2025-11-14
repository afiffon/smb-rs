//! Echo request and response messages
use binrw::prelude::*;

#[binrw::binrw]
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EchoMesasge {
    #[br(assert(_structure_size == 4))]
    #[bw(calc = 4)]
    _structure_size: u16,
    #[bw(calc = 0)]
    _reserved: u16,
}

pub type EchoRequest = EchoMesasge;
pub type EchoResponse = EchoMesasge;

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use super::*;

    test_binrw! {
        struct EchoRequest {} => "04000000"
    }

    test_binrw! {
        struct EchoResponse {} => "04000000"
    }
}

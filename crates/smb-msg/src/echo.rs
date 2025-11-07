//! Echo request and response messages
use binrw::prelude::*;
use smb_msg_derive::*;

macro_rules! make_echo {
    ($mtype:ident) => {
        pastey::paste! {
        #[doc = concat!("SMB2 Echo ", stringify!($mtype:camel), ".")]
        #[doc = concat!("Reference: MS-SMB2 2.2.28; 2.2.29")]
        #[[<smb_ $mtype>](size = 4)]
        #[derive(Default)]
        pub struct [<Echo $mtype:camel>] {
            #[bw(calc = 0)]
            _reserved: u16,
        }
                }
    };
}

make_echo!(request);
make_echo!(response);

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

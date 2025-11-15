//! This module is only used when testing the library.
//! Any `pub use` here is also imported in the [super] module.
//! It may only be used inside tests.

use binrw::prelude::*;

/// Implementation of reading plain content test
macro_rules! _test_generic_read {
    (
        $req_or_resp:ident => $test_name:ident, $command:expr => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_content_  $req_or_resp:lower _ $test_name:snake _read>]() {
                use ::binrw::{io::{Cursor, Write, Seek}, prelude::*};

                // Build some fake header bytes and concat before actual content bytes.

                let fake_header_for_test = Header {
                    async_id: None,
                    tree_id: Some(0),
                    command: $command,
                    flags: HeaderFlags::default().with_server_to_redir(stringify!([<$req_or_resp:lower>]) == "response"),
                    status: 0,
                    session_id: 0,
                    credit_charge: 0,
                    credit_request: 0,
                    message_id: 0,
                    signature: 0,
                    next_command: 0
                };
                let mut cursor = Cursor::new(Vec::new());
                fake_header_for_test.write(&mut cursor).unwrap();

                cursor.write(::smb_tests::hex_to_u8_array! { $hex }.as_slice()).unwrap();
                cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

                let msg: [<Plain $req_or_resp:camel>] = cursor.read_le().unwrap();
                let msg: [<$struct_name $req_or_resp:camel>] = msg.content.[<to_ $struct_name:lower>]().unwrap();
                assert_eq!(msg, [<$struct_name $req_or_resp:camel>] {
                    $(
                        $field_name: $field_value,
                    )*
                });
            }
        }
    };
}

/// Implementation of writing plain content test
macro_rules! _test_generic_write {
    (
        $req_or_resp:ident => $test_name:ident, $command:expr => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        pastey::paste! {
            #[test]
            fn [<test_content_ $req_or_resp:lower _ $test_name:snake _write>]() {
                use ::binrw::{io::Cursor, prelude::*};
                let response = [<$struct_name $req_or_resp:camel>] {
                    $(
                        $field_name: $field_value,
                    )*
                };
                let mut cursor = Cursor::new(Vec::new());
                let mut msg = [<Plain $req_or_resp:camel>]::new_with_command(response.into(), $command);

                msg.header.flags.set_server_to_redir(stringify!([<$req_or_resp:lower>]) == "response"); // Since we're writing a response, we must set this flag

                msg.write(&mut cursor).unwrap();
                let written_bytes = cursor.into_inner();
                let expected_bytes = ::smb_tests::hex_to_u8_array! { $hex };
                assert_eq!(&written_bytes[Header::STRUCT_SIZE..], &expected_bytes);
            }
        }
    }
}

/// This macro calls other macros to implement both read and write tests
/// It has all the variants of test macros in this module, eventually calling `$impl_macro`.
macro_rules! _test_generic_impl {
    (
        $impl_macro:ident, $req_or_resp:ident => $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        _test_generic_impl! {
            $impl_macro, $req_or_resp =>
            $struct_name: $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    (
        $impl_macro:ident, $req_or_resp:ident => $test_name:ident: $struct_name:ident {
            $($field_name:ident : $field_value:expr),* $(,)?
        } => $hex:expr
    ) => {
        _test_generic_impl! {
            $impl_macro, $req_or_resp =>
            $test_name, Command::$struct_name => $struct_name {
                $($field_name : $field_value),*
            } => $hex
        }
    };
    (
        $impl_macro:ident, $($v:tt)+
    ) => {
        $impl_macro! {
            $($v)+
        }
    };
}

pub(crate) use _test_generic_impl;
pub(crate) use _test_generic_read;
pub(crate) use _test_generic_write;

macro_rules! test_request {
    ($($v:tt)+) => {
        $crate::test_request_write! {
            $($v)+
        }
        $crate::test_request_read! {
            $($v)+
        }
    };
}

macro_rules! test_response {
    ($($v:tt)+) => {
        $crate::test_response_write! {
            $($v)+
        }
        $crate::test_response_read! {
            $($v)+
        }
    };
}

#[allow(unused_macros)]
macro_rules! test_request_read {
    ($($v:tt)+) => {
        #[cfg(feature = "server")]
        _test_generic_impl! {
            _test_generic_read, Request => $($v)+
        }
    };
}

macro_rules! test_response_read {
    ($($v:tt)+) => {
        #[cfg(feature = "client")]
        _test_generic_impl! {
            _test_generic_read, Response => $($v)*
        }
    };
}

#[allow(unused_macros)]
macro_rules! test_request_write {
    ($($v:tt)+) => {
        #[cfg(feature = "client")]
        _test_generic_impl! {
            _test_generic_write, Request => $($v)+
        }
    };
}

#[allow(unused_macros)]
macro_rules! test_response_write {
    ($($v:tt)+) => {
        #[cfg(feature = "server")]
        _test_generic_impl! {
            _test_generic_write, Response => $($v)+
        }
    };
}

macro_rules! test_binrw_request {
    (
        $($v:tt)+
    ) => {
        #[cfg(feature = "client")]
        ::smb_tests::test_binrw_write! {
            $($v)+
        }
        #[cfg(feature = "server")]
        ::smb_tests::test_binrw_read! {
            $($v)+
        }
    };
}

macro_rules! test_binrw_response {
    (
        $($v:tt)+
    ) => {
        #[cfg(feature = "server")]
        ::smb_tests::test_binrw_write! {
            $($v)+
        }
        #[cfg(feature = "client")]
        ::smb_tests::test_binrw_read! {
            $($v)+
        }
    };
}

pub(crate) use test_binrw_request;
pub(crate) use test_binrw_response;
pub(crate) use test_request;
#[allow(unused_imports)]
pub(crate) use test_request_read;
#[allow(unused_imports)]
pub(crate) use test_request_write;
pub(crate) use test_response;
pub(crate) use test_response_read;
#[allow(unused_imports)]
pub(crate) use test_response_write;

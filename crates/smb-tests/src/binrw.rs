//! Test utilities for binrw-related code.

pub fn __hex_stream_decode(hex_stream: &str) -> Vec<u8> {
    let hex_stream = hex_stream.split_whitespace().collect::<String>();
    ::hex::decode(hex_stream).expect("Invalid hex string")
}

/// Converts a byte array or hex stream into a `Vec<u8>`.
/// ```ignore
/// hex_to_u8_array! {
///     [0x01, 0x02, 0x03, 0x04]
/// }
/// // or
/// hex_to_u8_array! {
///   "01020304" // any valid expressions that results in &str
/// }
#[macro_export]
macro_rules! hex_to_u8_array {
    (
        [$($bytes:expr),* $(,)?]
    ) => {
        {
            vec![$($bytes),*]
        }
    };
    (
        $expr_for_string:expr
    ) => {
        {
            let s = $expr_for_string;
            $crate::__hex_stream_decode(s)
        }
    }
}

/// BinWrite test macro.
///
/// Creates a test
/// ```ignore
/// test_binrw_write! {
///     struct StructName {
///         field1: value1,
///         field2: value2,
///         // ...
///     }: [byte1, byte2, byte3, ...]
/// }
/// ```
#[macro_export]
macro_rules! test_binrw_write {
    // Struct
    (
        struct $name:ident $(=> $suffix:ident)? {
            $(
                $field:ident : $value:expr,
            )*
        } => $byte_arr_or_hex_stream:tt
    ) => {
        $crate::test_binrw_write! {
            $name $(=> $suffix)?: $name {
                $(
                    $field: $value,
                )*
            } => $byte_arr_or_hex_stream
        }
    };
    // Expression
    (
        $type:ty: $value_expr:expr => $byte_arr_or_hex_stream:tt
    ) => {
        $crate::pastey::paste! {
            #[test]
            fn [<test_ $type:snake _write>]() {
                let expr_eval = $value_expr;
                $crate::binrw_write_and_assert_eq!(
                    expr_eval,
                    $byte_arr_or_hex_stream
                );
            }
        }
    };

    // Full Expression with test name suffix
    (
        $type:ty => $suffix:ident: $value_expr:expr => $byte_arr_or_hex_stream:tt
    ) => {
        $crate::pastey::paste! {
            #[test]
            fn [<test_ $type:snake _write $suffix:lower>]() {
                let expr_eval = $value_expr;
                $crate::binrw_write_and_assert_eq!(
                    expr_eval,
                    $byte_arr_or_hex_stream
                );
            }
        }
    }
}

#[macro_export]
macro_rules! binrw_write_and_assert_eq {
    (
        $value:expr,
        $byte_arr_or_hex_stream:tt
    ) => {{
        use ::binrw::{io::Cursor, prelude::*};
        let mut writer = Cursor::new(Vec::new());
        $value.write_le(&mut writer).unwrap();
        let expected = $crate::hex_to_u8_array! { $byte_arr_or_hex_stream };
        assert_eq!(writer.into_inner(), expected);
    }};
}

/// BinRead test macro.
/// ```ignore
/// test_binrw_read! {
///     StructName {
///         field1: value1,
///         field2: value2,
///         // ...
///     }: [byte1, byte2, byte3, ...]
/// }
/// ```
#[macro_export]
macro_rules! test_binrw_read {
    // Struct
    (
        struct $name:ident $(=> $suffix:ident)? {
            $(
                $field:ident : $value:expr,
            )*
        } => $byte_arr_or_hex_stream:tt
    ) => {
        $crate::test_binrw_read! {
            $name $(=> $suffix)?: $name {
                $(
                    $field: $value,
                )*
            } => $byte_arr_or_hex_stream
        }
    };
    // Expression
    (
        $type:ty: $value_expr:expr => $byte_arr_or_hex_stream:tt
    ) => {
        $crate::pastey::paste! {
            #[test]
            fn [<test_ $type:snake _read>]() {
                $crate::binrw_read_and_assert_eq!(
                    $type,
                    $byte_arr_or_hex_stream,
                    $value_expr
                );
            }
        }
    };
    // Full Expression with test name suffix
    (
        $type:ty => $suffix:ident: $value_expr:expr => $byte_arr_or_hex_stream:tt
    ) => {
        $crate::pastey::paste! {
            #[test]
            fn [<test_ $type:snake _read $suffix:lower>]() {
                $crate::binrw_read_and_assert_eq!(
                    $type,
                    $byte_arr_or_hex_stream,
                    $value_expr
                );
            }
        }
    }
}

#[macro_export]
macro_rules! binrw_read_and_assert_eq {
    (
        $type:ty,
        $byte_arr_or_hex_stream:tt,
        $expected:expr
    ) => {{
        use ::binrw::{io::Cursor, prelude::*};
        let bytes = $crate::hex_to_u8_array! { $byte_arr_or_hex_stream };
        let mut reader = Cursor::new(bytes);
        let value: $type = <$type>::read_le(&mut reader).unwrap();
        assert_eq!(value, $expected);
    }};
}

/// BinRead + BinWrite test macro.
#[macro_export]
macro_rules! test_binrw {
    (
        $($v:tt)+
    ) => {
        $crate::test_binrw_read! {$($v)+}
        $crate::test_binrw_write! {$($v)+}
    };
}

#[macro_export]
macro_rules! test_binrw_read_fail {
    (
        $type:ty:
        $byte_arr_or_hex_stream:tt
    ) => {
        $crate::pastey::paste! {
            #[test]
            fn [<test_ $type:snake _read_fail>]() {
                use ::binrw::{io::Cursor, prelude::*};
                let bytes = $crate::hex_to_u8_array! { $byte_arr_or_hex_stream };
                let mut reader = Cursor::new(bytes);
                let result: ::binrw::BinResult<$type> = <$type>::read_le(&mut reader);
                assert!(result.is_err());
            }
        }
    };
}

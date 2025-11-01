//! [`Boolean`] implementation for binrw.

use binrw::{Endian, prelude::*};
use std::io::{Read, Seek, Write};

/// A simple Boolean type that reads and writes as a single byte.
/// Any non-zero value is considered `true`, as defined by MS-FSCC 2.1.8.
/// Similar to the WinAPI `BOOL` type.
///
/// This type supports `std::size_of::<Boolean>() == 1`, ensuring it is 1 byte in size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boolean(bool);

impl Boolean {
    const _VALIDATE_SIZE_OF: [u8; 1] = [0; size_of::<Self>()];
}

impl BinRead for Boolean {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        _: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let value: u8 = u8::read_options(reader, Endian::Little, ())?;
        Ok(Boolean(value != 0))
    }
}

impl BinWrite for Boolean {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        _: Endian,
        _: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let value: u8 = if self.0 { 1 } else { 0 };
        value.write_options(writer, Endian::Little, ())
    }
}

impl From<bool> for Boolean {
    fn from(value: bool) -> Self {
        Boolean(value)
    }
}

impl From<Boolean> for bool {
    fn from(val: Boolean) -> Self {
        val.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_tests::*;

    test_binrw! {
        Boolean => true: Boolean::from(true) => "01"
    }

    test_binrw! {
        Boolean => false: Boolean::from(false) => "00"
    }

    // Non-zero is considered true!
    test_binrw_read! {
        Boolean => true_non_zero: Boolean::from(true) => "17"
    }
}

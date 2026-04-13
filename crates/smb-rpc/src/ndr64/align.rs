use binrw::prelude::*;
use std::ops::{Deref, DerefMut};

pub const NDR64_ALIGNMENT: usize = 8;

/// Asserts that the writer is aligned to NDR64 alignment.
pub fn debug_assert_aligned<W: std::io::Seek>(stream: &mut W) -> binrw::BinResult<()> {
    let pos = stream.stream_position()?;
    debug_assert!(
        (pos as usize).is_multiple_of(NDR64_ALIGNMENT),
        "Writer is not aligned to NDR64"
    );
    Ok(())
}

/// A trait for types that are aligned according to NDR64 rules.
pub trait NdrAligned {}
/// Writes the inner value, and aligns the writer to
/// the NDR alignment BEFORE writing the value.
///
/// *Note:* NDR-encoded data can be of an unaligned length!
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
#[br(import_raw(args: <T as BinRead>::Args<'_>))]
#[bw(import_raw(args: <T as BinWrite>::Args<'_>))]
pub struct NdrAlign<T, const TO: usize = NDR64_ALIGNMENT>
where
    T: BinRead + BinWrite,
{
    #[brw(align_before = TO)]
    #[brw(args_raw(args))]
    pub value: T,
}

impl<T, const TO: usize> Deref for NdrAlign<T, TO>
where
    T: BinRead + BinWrite,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T, const TO: usize> DerefMut for NdrAlign<T, TO>
where
    T: BinRead + BinWrite,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T, const TO: usize> NdrAligned for NdrAlign<T, TO> where T: BinRead + BinWrite {}

impl<T, const TO: usize> From<T> for NdrAlign<T, TO>
where
    T: BinRead + BinWrite,
{
    fn from(value: T) -> Self {
        Self { value }
    }
}

impl<T, const TO: usize> Default for NdrAlign<T, TO>
where
    T: BinRead + BinWrite + Default,
{
    fn default() -> Self {
        T::default().into()
    }
}

impl<T, const TO: usize> Clone for NdrAlign<T, TO>
where
    T: BinRead + BinWrite + Clone,
{
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

pub type Ndr64Align<T> = NdrAlign<T, NDR64_ALIGNMENT>;

#[cfg(test)]
mod tests {
    use smb_tests::*;

    use super::*;

    #[binrw::binrw]
    #[derive(Debug, PartialEq, Eq)]
    struct TestNdrAlign {
        unalign: u8,
        unalign2: u16,
        should_align: NdrAlign<u32>,
    }

    test_binrw! {
        struct TestNdrAlign {
            unalign: 0,
            unalign2: 0,
            should_align: NdrAlign {
                value: 0x12345678,
            },
        } => "
                00
                00 00
                00 00 00 00 00
                78 56 34 12
            " // unalign; unalign2; alignment; aligned value
    }
}

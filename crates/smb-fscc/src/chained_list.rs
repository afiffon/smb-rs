//! A genric utility struct to wrap "chained"-encoded entries.
//! Many fscc-query structs have a common "next entry offset" field,
//! which is used to chain multiple entries together.
//! This struct wraps the value, and the offset, and provides a way to iterate over them.
//! See [`ChainedItemList<T>`][crate::ChainedItemList] to see how to write this type when in a list.

use std::io::{Read, Seek, SeekFrom, Write};

use binrw::{Endian, prelude::*};

const CHAINED_ITEM_DEFAULT_OFFSET_PAD: u32 = 4;

/// The size of added fields to the size of each entry in [`ChainedItemList<T>`],
/// when bin-writing the data, before the actual T data.
///
/// A possible additional padding of `OFFSET_PAD` bytes may be added after T,
/// to align the next entry offset field.
pub const CHAINED_ITEM_PREFIX_SIZE: usize = std::mem::size_of::<NextEntryOffsetType>();

type NextEntryOffsetType = u32;

/// Implements a chained item list.
///
/// A chained item list is a sequence of T entries,
/// where each entry contains a value of type `T` and an offset to the next entry before it.
/// The last entry in the list has a next entry offset of `0`.
///
/// This is a common pattern for Microsoft fscc-query responses, and is used to
/// represent lists of variable-length entries.
///
/// This struct provides conversion to and from [`Vec<T>`] for ease of use.
///
/// The struct supports data of length 0, and puts an empty vector in that case.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainedItemList<T, const OFFSET_PAD: u32 = CHAINED_ITEM_DEFAULT_OFFSET_PAD> {
    values: Vec<T>,
}

impl<T, const OFFSET_PAD: u32> ChainedItemList<T, OFFSET_PAD> {
    /// Returns an iterator over the values in the chained item list.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.values.iter()
    }

    /// Returns true if the chained item list is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns the number of items in the chained item list.
    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }
}

impl<T, const OFFSET_PAD: u32> BinWrite for ChainedItemList<T, OFFSET_PAD>
where
    T: BinWrite,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    type Args<'a> = ();

    #[allow(clippy::ptr_arg)] // writer accepts exact type.
    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<()> {
        for (i, item) in self.values.iter().enumerate() {
            let position_before = writer.stream_position()?;

            // Placeholder for next_entry_offset.
            let next_entry_offset_pos = writer.stream_position()?;
            NextEntryOffsetType::write_options(&0u32, writer, endian, ())?;

            // Write the value.
            item.write_options(writer, endian, Default::default())?;

            // Last item: don't align, next item offset is 0.
            if i == self.values.len() - 1 {
                break;
            }

            let position_after_item = writer.stream_position()?;
            let padding_needed =
                (OFFSET_PAD as u64 - (position_after_item % OFFSET_PAD as u64)) % OFFSET_PAD as u64;
            writer.seek(SeekFrom::Current(padding_needed as i64))?;
            debug_assert!(
                writer.stream_position()? % OFFSET_PAD as u64 == 0,
                "ChainedItemList item not aligned to OFFSET_PAD {} after padding",
                OFFSET_PAD
            );

            // Calculate and write the next_entry_offset.
            let position_after = writer.stream_position()?;
            let next_entry_offset = if i == self.values.len() - 1 {
                0u32
            } else {
                (position_after - position_before) as u32
            };

            // Seek back to write the next_entry_offset.
            writer.seek(SeekFrom::Start(next_entry_offset_pos))?;
            NextEntryOffsetType::write_options(&next_entry_offset, writer, endian, ())?;

            writer.seek(SeekFrom::Start(position_after))?;
        }
        Ok(())
    }
}

impl<T, const OFFSET_PAD: u32> BinRead for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead,
    for<'b> <T as BinRead>::Args<'b>: Default,
{
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        _args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let stream_end = {
            let current = reader.stream_position()?;
            // Determine the end of the stream.
            let end = reader.seek(SeekFrom::End(0))?;
            // Revert to original position.
            reader.seek(SeekFrom::Start(current))?;
            end
        };
        if reader.stream_position()? == stream_end {
            // No data to read, return empty vector.
            return Ok(Self { values: Vec::new() });
        }

        let mut values = Vec::new();
        loop {
            let position_before = reader.stream_position()?;

            if position_before % OFFSET_PAD as u64 != 0 {
                return Err(binrw::Error::AssertFail {
                    pos: position_before,
                    message: format!(
                        "ChainedItemList item not aligned to OFFSET_PAD {}",
                        OFFSET_PAD
                    ),
                });
            }

            let next_item_offset = NextEntryOffsetType::read_options(reader, endian, ())?;

            let item: T = T::read_options(reader, endian, Default::default())?;

            values.push(item);

            if next_item_offset == 0 {
                break;
            }
            reader.seek(SeekFrom::Start(position_before + next_item_offset as u64))?;
        }
        Ok(Self { values })
    }
}

impl<T, const OFFSET_PAD: u32> From<ChainedItemList<T, OFFSET_PAD>> for Vec<T> {
    fn from(value: ChainedItemList<T, OFFSET_PAD>) -> Self {
        value.values
    }
}

impl<T, const OFFSET_PAD: u32> From<Vec<T>> for ChainedItemList<T, OFFSET_PAD> {
    fn from(vec: Vec<T>) -> Self {
        Self { values: vec }
    }
}

impl<T, const OFFSET_PAD: u32> FromIterator<T> for ChainedItemList<T, OFFSET_PAD> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let values = iter.into_iter().collect();
        Self { values }
    }
}

impl<T, const OFFSET_PAD: u32> std::ops::Deref for ChainedItemList<T, OFFSET_PAD> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T, const OFFSET_PAD: u32> std::ops::DerefMut for ChainedItemList<T, OFFSET_PAD> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl<T, const OFFSET_PAD: u32> Default for ChainedItemList<T, OFFSET_PAD> {
    fn default() -> Self {
        Self { values: Vec::new() }
    }
}

//! A genric utility struct to wrap "chained"-encoded entries.
//! Many fscc-query structs have a common "next entry offset" field,
//! which is used to chain multiple entries together.
//! This struct wraps the value, and the offset, and provides a way to iterate over them.
//! See [`ChainedItemList<T>`][crate::ChainedItemList] to see how to write this type when in a list.

use std::{io::SeekFrom, ops::Deref};

use binrw::prelude::*;
use smb_dtyp::binrw_util::prelude::*;

const CHAINED_ITEM_DEFAULT_OFFSET_PAD: u32 = 4;

/// The size of added fields to the size of each entry in [`ChainedItemList<T>`],
/// when bin-writing the data, before the actual T data.
///
/// A possible additional padding of `OFFSET_PAD` bytes may be added after T,
/// to align the next entry offset field.
pub const CHAINED_ITEM_PREFIX_SIZE: usize = std::mem::size_of::<NextEntryOffsetType>();

type NextEntryOffsetType = u32;

/// A single item in a chained list.
///
/// Check out [`ChainedItemList<T>`][crate::ChainedItemList] for a list of these items.
/// This is the suggested use case for this struct - not using it directly.
#[binrw::binrw]
#[derive(Debug)]
#[bw(import(last: bool))]
#[allow(clippy::manual_non_exhaustive)]
pub struct ChainedItem<T, const OFFSET_PAD: u32 = CHAINED_ITEM_DEFAULT_OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[br(assert(next_entry_offset.value % OFFSET_PAD == 0))]
    #[bw(calc = PosMarker::default())]
    #[br(temp)]
    next_entry_offset: PosMarker<NextEntryOffsetType>,
    pub value: T,

    #[br(seek_before = next_entry_offset.seek_relative(false))] // If 0, make seek_relative go to position before parsing `next_entry_offset`.
    #[bw(if(!last))]
    #[bw(align_before = OFFSET_PAD)]
    #[bw(write_with = PosMarker::write_roff, args(&next_entry_offset))]
    _write_offset_placeholder: (),
}

impl<T, const OFFSET_PAD: u32> PartialEq for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite + PartialEq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T, const OFFSET_PAD: u32> Eq for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite + Eq,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
}

impl<T, const OFFSET_PAD: u32> Deref for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T, const OFFSET_PAD: u32> From<T> for ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(value: T) -> Self {
        Self {
            value,
            _write_offset_placeholder: (),
        }
    }
}

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
#[binrw::binrw]
#[derive(Debug, PartialEq, Eq)]
pub struct ChainedItemList<T, const OFFSET_PAD: u32 = CHAINED_ITEM_DEFAULT_OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[br(parse_with = ChainedItem::<T, OFFSET_PAD>::read_chained)]
    #[bw(write_with = ChainedItem::<T, OFFSET_PAD>::write_chained)]
    values: Vec<ChainedItem<T, OFFSET_PAD>>,
}

impl<T, const OFFSET_PAD: u32> ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    /// Returns an iterator over the values in the chained item list.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.values.iter().map(|item| &item.value)
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

impl<T, const OFFSET_PAD: u32> IntoIterator for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    type Item = T;

    type IntoIter = std::iter::Map<
        std::vec::IntoIter<ChainedItem<T, OFFSET_PAD>>,
        fn(ChainedItem<T, OFFSET_PAD>) -> T,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter().map(|item| item.value)
    }
}

impl<T, const OFFSET_PAD: u32> ChainedItem<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    #[binrw::parser(reader, endian)]
    pub fn read_chained() -> BinResult<Vec<Self>> {
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
            return Ok(Vec::new());
        }

        let mut items = Vec::new();
        loop {
            let position_before = reader.stream_position()?;
            let item: ChainedItem<T, OFFSET_PAD> =
                ChainedItem::read_options(reader, endian, Default::default())?;

            items.push(item);

            // After reading the item, we seek to the next item.
            // If the next_entry_offset is 0, we are done.
            // See comment in the definition of `_write_offset_placeholder`.
            let is_last = position_before == reader.stream_position()?;
            if is_last {
                break;
            }
        }
        Ok(items)
    }

    #[binrw::writer(writer, endian)]
    #[allow(clippy::ptr_arg)] // writer accepts exact type.
    pub fn write_chained(value: &Vec<Self>) -> BinResult<()> {
        for (i, item) in value.iter().enumerate() {
            item.write_options(writer, endian, (i == value.len() - 1,))?;
        }
        Ok(())
    }
}

impl<T, const OFFSET_PAD: u32> From<ChainedItemList<T, OFFSET_PAD>> for Vec<T>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(list: ChainedItemList<T, OFFSET_PAD>) -> Self {
        list.values.into_iter().map(|i| i.value).collect()
    }
}

impl<T, const OFFSET_PAD: u32> From<Vec<T>> for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from(vec: Vec<T>) -> Self {
        Self {
            values: vec.into_iter().map(|v| ChainedItem::from(v)).collect(),
        }
    }
}

impl<T, const OFFSET_PAD: u32> Default for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn default() -> Self {
        Self { values: Vec::new() }
    }
}

impl<T, const OFFSET_PAD: u32> FromIterator<T> for ChainedItemList<T, OFFSET_PAD>
where
    T: BinRead + BinWrite,
    for<'a> <T as BinRead>::Args<'a>: Default,
    for<'b> <T as BinWrite>::Args<'b>: Default,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let values = iter.into_iter().map(ChainedItem::from).collect();
        Self { values }
    }
}

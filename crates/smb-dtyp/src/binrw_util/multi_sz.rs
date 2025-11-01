//! [`MultiWSz`] type for reading and writing multiple null-terminated wide strings.

use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::ops::Deref;
use std::ops::DerefMut;

use binrw::prelude::*;
use binrw::{Endian, NullWideString};

/// A MultiWSz (Multiple Null-terminated Wide Strings) type that reads and writes a sequence of
/// null-terminated wide strings, ending with an additional null string.
///
/// Similar to the Registry [`REG_MULTI_SZ`](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types) type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiWSz(Vec<NullWideString>);

impl BinRead for MultiWSz {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<Self> {
        let mut strings = Vec::new();
        loop {
            let string: NullWideString = NullWideString::read_options(reader, endian, ())?;
            if string.is_empty() {
                break;
            }
            strings.push(string);
        }
        Ok(MultiWSz(strings))
    }
}

impl BinWrite for MultiWSz {
    type Args<'a> = ();

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        _: Self::Args<'_>,
    ) -> BinResult<()> {
        for string in &self.0 {
            string.write_options(writer, endian, ())?;
        }
        NullWideString::default().write_options(writer, endian, ())?;
        Ok(())
    }
}

impl Deref for MultiWSz {
    type Target = Vec<NullWideString>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MultiWSz {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> FromIterator<&'a str> for MultiWSz {
    fn from_iter<T: IntoIterator<Item = &'a str>>(iter: T) -> Self {
        MultiWSz(iter.into_iter().map(NullWideString::from).collect())
    }
}

impl IntoIterator for MultiWSz {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>()
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use crate::binrw_util::prelude::MultiWSz;
    use smb_tests::*;

    test_binrw! {
        MultiWSz: (vec![
            "FirstS",
            "AnOther",
            "ThirdS",
        ]).iter().copied().collect::<MultiWSz>() => "460069007200730074005300000041006e004f007400680065007200000054006800690072006400530000000000"
    }
}

use std::str::FromStr;

use smb::UncPath;

/// Remote (UNC) or local path.
///
/// See [`smb::UncPath`]
#[derive(Debug, Clone)]
pub enum Path {
    Local(std::path::PathBuf),
    Remote(UncPath),
}

impl Path {
    pub fn as_local(&self) -> Option<&std::path::Path> {
        if let Path::Local(path) = self {
            Some(path)
        } else {
            None
        }
    }
    pub fn as_remote(&self) -> Option<&UncPath> {
        if let Path::Remote(path) = self {
            Some(path)
        } else {
            None
        }
    }
}

impl FromStr for Path {
    type Err = smb::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.replace('/', r"\");
        if input.starts_with(r"\\") {
            Ok(Path::Remote(input.parse()?))
        } else {
            Ok(Path::Local(std::path::PathBuf::from(input)))
        }
    }
}

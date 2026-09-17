use alloc::string::String;
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidZip(&'static str),
    UnsupportedCompression(u16),
    InflateFailed,
    MissingPayloadApp,
    MissingInfoPlist,
    PlistParse(String),
    MissingBundleExecutable,
    MissingMainExecutable,
    EntryNotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidZip(m) => write!(f, "invalid zip: {m}"),
            Self::UnsupportedCompression(m) => write!(f, "unsupported compression method {m}"),
            Self::InflateFailed => write!(f, "deflate decompression failed"),
            Self::MissingPayloadApp => write!(f, "no Payload/*.app bundle found"),
            Self::MissingInfoPlist => write!(f, "Info.plist not found in app bundle"),
            Self::PlistParse(m) => write!(f, "plist parse error: {m}"),
            Self::MissingBundleExecutable => write!(f, "CFBundleExecutable missing from Info.plist"),
            Self::MissingMainExecutable => write!(f, "main executable not found in IPA"),
            Self::EntryNotFound(p) => write!(f, "entry not found: {p}"),
        }
    }
}

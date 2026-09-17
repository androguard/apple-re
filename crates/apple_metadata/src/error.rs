use alloc::string::String;
use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Macho(String),
    Truncated(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Macho(m) => write!(f, "macho: {m}"),
            Self::Truncated(m) => write!(f, "truncated: {m}"),
        }
    }
}

impl From<macho_core::Error> for Error {
    fn from(e: macho_core::Error) -> Self {
        Self::Macho(alloc::format!("{e}"))
    }
}

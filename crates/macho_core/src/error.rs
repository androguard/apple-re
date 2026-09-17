use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated(&'static str),
    BadMagic(u32),
    BadCsMagic(u32),
    NoArm64Slice,
    UnsupportedCpuType(u32),
    InvalidLoadCommand,
    VaddrNotMapped(u64),
    InvalidArchive(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated(m) => write!(f, "truncated macho: {m}"),
            Self::BadMagic(m) => write!(f, "bad macho magic: {m:#x}"),
            Self::BadCsMagic(m) => write!(f, "bad code signature magic: {m:#x}"),
            Self::NoArm64Slice => write!(f, "no ARM64 slice in fat binary"),
            Self::UnsupportedCpuType(t) => write!(f, "unsupported cpu type {t}"),
            Self::InvalidLoadCommand => write!(f, "invalid load command"),
            Self::VaddrNotMapped(v) => write!(f, "vaddr {v:#x} not mapped"),
            Self::InvalidArchive(m) => write!(f, "invalid archive: {m}"),
        }
    }
}

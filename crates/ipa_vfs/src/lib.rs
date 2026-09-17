#![no_std]
extern crate alloc;

mod bundle;
mod error;
mod plist;
mod zip;
mod zip_write;

pub use bundle::{IpaBundle, IpaVfs};
pub use error::{Error, Result};
pub use zip_write::write_stored_zip;


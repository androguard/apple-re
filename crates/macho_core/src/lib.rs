#![no_std]
extern crate alloc;

mod archive;
mod chained;
mod codesign;
mod dyld;
mod error;
mod file;
mod names;
mod types;

pub use archive::{split_archive_member, ArArchive, ArMember};
pub use chained::{ChainedFixups, FixupTarget};
pub use codesign::{CodeDirectory, CodeSignature, CsSlot};
pub use dyld::{parse_exports_trie, BindEntry, BindKind, ExportEntry};
pub use error::{Error, Result};
pub use file::{
    fat_arches, is_fat, BuildInfo, Checksec, DylibRef, EncryptionInfo, EntryPoint, FatArchEntry,
    LoadCommandIter, MachoFile, SectionIter, SegmentIter,
};
pub use names::{
    arch_matches, arch_name, cpu_type_name, filetype_name, flag_names, lc_name, version_string,
};
pub use types::*;

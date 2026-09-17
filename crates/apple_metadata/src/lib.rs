#![no_std]
extern crate alloc;

mod diff;
mod dump;
mod encode;
mod error;
mod objc;
mod refs;
mod symbols;

pub use diff::diff_objc;
pub use dump::{dump_all, format_category, format_class, format_protocol, DumpOptions};
pub use encode::{
    format_ivar_decl, format_method_decl, format_property_decl, format_type, split_method_types,
};
pub use error::{Error, Result};
pub use objc::{
    ObjcCategory, ObjcClass, ObjcIvar, ObjcMetadata, ObjcMethod, ObjcProperty, ObjcProtocol,
};
pub use refs::{apply_selector_map, ObjcRef, ObjcRefs};
pub use symbols::SymbolTable;

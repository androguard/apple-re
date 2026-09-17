#![no_std]
#![allow(non_camel_case_types)]

//! Pure Rust iOS IPA reverse-engineering toolchain.
//!
//! | Crate | Role |
//! |-------|------|
//! | [`ipa_vfs`] | In-memory IPA/ZIP VFS + Info.plist |
//! | [`macho_core`] | Zero-copy Mach-O / fat parser |
//! | [`apple_metadata`] | ObjC metadata + symbol resolution |
//! | [`arm_disassembler`] | Zero-allocation ARM64 decoder/formatter |
//! | [`arm_decompiler`] | ARM64 → C-like decompiler (CFG / IR / regions) |

extern crate alloc;

pub use apple_metadata;
pub use arm_disassembler;
pub use arm_decompiler;
pub use ipa_vfs;
pub use macho_core;

use alloc::string::String;
use alloc::vec::Vec;

use apple_metadata::SymbolTable;
use arm_disassembler::{Decoder, Formatter, Instruction, SymbolResolver};
use ipa_vfs::IpaVfs;
use macho_core::MachoFile;

/// High-level pipeline: IPA bytes → ARM64 disassembly of the main executable `__TEXT.__text`.
pub struct DisassemblyLine {
    pub vaddr: u64,
    pub raw: u32,
    pub text: String,
}

pub fn disassemble_ipa_main(ipa_bytes: &[u8], max_insns: usize) -> Result<Vec<DisassemblyLine>, String> {
    let vfs = IpaVfs::open(ipa_bytes).map_err(|e| alloc::format!("{e}"))?;
    let bundle = vfs.bundle().map_err(|e| alloc::format!("{e}"))?;
    disassemble_macho(bundle.main_executable, max_insns)
}

pub fn disassemble_macho(macho_bytes: &[u8], max_insns: usize) -> Result<Vec<DisassemblyLine>, String> {
    let file = MachoFile::parse(macho_bytes).map_err(|e| alloc::format!("{e}"))?;
    let text = file
        .find_section("__TEXT", "__text")
        .map_err(|e| alloc::format!("{e}"))?
        .ok_or_else(|| String::from("missing __TEXT.__text"))?;
    let code = file.section_data(text).map_err(|e| alloc::format!("{e}"))?;
    let symbols = SymbolTable::from_macho(&file).map_err(|e| alloc::format!("{e}"))?;

    struct Res<'a>(&'a SymbolTable);
    impl SymbolResolver for Res<'_> {
        fn resolve(&self, vaddr: u64) -> Option<&str> {
            self.0.get_symbol_str_at_vaddr(vaddr)
        }
    }

    let mut decoder = Decoder::new(code, text.addr);
    let fmt = Formatter::new();
    let resolver = Res(&symbols);
    let mut out = Vec::new();
    let mut n = 0usize;
    while decoder.can_decode() && n < max_insns {
        let ins: Instruction = decoder.decode();
        let text = fmt.format(&ins, &resolver);
        out.push(DisassemblyLine {
            vaddr: ins.vaddr,
            raw: ins.raw,
            text,
        });
        n += 1;
    }
    Ok(out)
}

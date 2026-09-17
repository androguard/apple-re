//! Dyld export trie + classic bind / lazy_bind opcode tables.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::file::MachoFile;

/// One exported symbol from the export trie.
#[derive(Debug, Clone)]
pub struct ExportEntry {
    pub name: String,
    pub flags: u64,
    /// Image-relative address (add preferred load / slide for VA).
    pub address: u64,
    pub other: u64,
    pub import_name: Option<String>,
}

/// One bind / lazy_bind / weak_bind record.
#[derive(Debug, Clone)]
pub struct BindEntry {
    pub segment_index: u8,
    pub segment_offset: u64,
    pub lib_ordinal: i64,
    pub symbol: String,
    pub flags: u8,
    pub addend: i64,
    pub bind_type: u8,
    /// Kind label: bind | lazy_bind | weak_bind
    pub kind: BindKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindKind {
    Bind,
    LazyBind,
    WeakBind,
}

impl BindKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::LazyBind => "lazy_bind",
            Self::WeakBind => "weak_bind",
        }
    }
}

const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

const BIND_OPCODE_DONE: u8 = 0x00;
const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_OPCODE_DO_BIND: u8 = 0x90;
const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;

fn read_uleb128(data: &[u8], off: &mut usize) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if *off >= data.len() {
            return Err(Error::Truncated("uleb128"));
        }
        let b = data[*off];
        *off += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::Truncated("uleb128 overflow"));
        }
    }
    Ok(result)
}

fn read_sleb128(data: &[u8], off: &mut usize) -> Result<i64> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut b;
    loop {
        if *off >= data.len() {
            return Err(Error::Truncated("sleb128"));
        }
        b = data[*off];
        *off += 1;
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 63 {
            return Err(Error::Truncated("sleb128 overflow"));
        }
    }
    if shift < 64 && (b & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result)
}

fn read_cstring(data: &[u8], off: &mut usize) -> Result<String> {
    if *off >= data.len() {
        return Err(Error::Truncated("cstring"));
    }
    let start = *off;
    while *off < data.len() && data[*off] != 0 {
        *off += 1;
    }
    let s = core::str::from_utf8(&data[start..*off]).unwrap_or("");
    if *off < data.len() {
        *off += 1; // NUL
    }
    Ok(String::from(s))
}

fn parse_export_node(
    data: &[u8],
    node_off: usize,
    prefix: &str,
    out: &mut Vec<ExportEntry>,
    depth: usize,
) -> Result<()> {
    if depth > 64 || node_off >= data.len() {
        return Ok(());
    }
    let mut off = node_off;
    let terminal_size = read_uleb128(data, &mut off)? as usize;
    let terminal_end = off + terminal_size;
    if terminal_size > 0 {
        if terminal_end > data.len() {
            return Err(Error::Truncated("export terminal"));
        }
        let mut t = off;
        let flags = read_uleb128(data, &mut t)?;
        let mut address = 0u64;
        let mut other = 0u64;
        let mut import_name = None;
        if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
            other = read_uleb128(data, &mut t)?;
            import_name = Some(read_cstring(data, &mut t)?);
        } else {
            address = read_uleb128(data, &mut t)?;
            if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
                other = read_uleb128(data, &mut t)?;
            }
        }
        let _ = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
        if !prefix.is_empty() {
            out.push(ExportEntry {
                name: String::from(prefix),
                flags,
                address,
                other,
                import_name,
            });
        }
        off = terminal_end;
    }
    if off >= data.len() {
        return Ok(());
    }
    let child_count = data[off] as usize;
    off += 1;
    for _ in 0..child_count {
        let edge = read_cstring(data, &mut off)?;
        let child = read_uleb128(data, &mut off)? as usize;
        let mut next = String::from(prefix);
        next.push_str(&edge);
        parse_export_node(data, child, &next, out, depth + 1)?;
    }
    Ok(())
}

/// Parse an export trie blob.
pub fn parse_exports_trie(data: &[u8]) -> Result<Vec<ExportEntry>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    parse_export_node(data, 0, "", &mut out, 0)?;
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn parse_bind_ops(data: &[u8], kind: BindKind) -> Result<Vec<BindEntry>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut seg_index = 0u8;
    let mut seg_offset = 0u64;
    let mut lib_ordinal = 0i64;
    let mut symbol = String::new();
    let mut flags = 0u8;
    let mut addend = 0i64;
    let mut bind_type = 1u8; // POINTER

    while off < data.len() {
        let imm = data[off] & 0x0f;
        let opcode = data[off] & 0xf0;
        off += 1;
        match opcode {
            BIND_OPCODE_DONE => break,
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                lib_ordinal = imm as i64;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                lib_ordinal = read_uleb128(data, &mut off)? as i64;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                if imm == 0 {
                    lib_ordinal = 0;
                } else {
                    // sign-extend 4-bit
                    lib_ordinal = (imm as i8 | !0x0fi8) as i64;
                }
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                flags = imm;
                symbol = read_cstring(data, &mut off)?;
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                bind_type = imm;
            }
            BIND_OPCODE_SET_ADDEND_SLEB => {
                addend = read_sleb128(data, &mut off)?;
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                seg_index = imm;
                seg_offset = read_uleb128(data, &mut off)?;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                seg_offset = seg_offset.wrapping_add(read_uleb128(data, &mut off)?);
            }
            BIND_OPCODE_DO_BIND => {
                out.push(BindEntry {
                    segment_index: seg_index,
                    segment_offset: seg_offset,
                    lib_ordinal,
                    symbol: symbol.clone(),
                    flags,
                    addend,
                    bind_type,
                    kind,
                });
                seg_offset = seg_offset.wrapping_add(8);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                out.push(BindEntry {
                    segment_index: seg_index,
                    segment_offset: seg_offset,
                    lib_ordinal,
                    symbol: symbol.clone(),
                    flags,
                    addend,
                    bind_type,
                    kind,
                });
                seg_offset = seg_offset
                    .wrapping_add(8)
                    .wrapping_add(read_uleb128(data, &mut off)?);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                out.push(BindEntry {
                    segment_index: seg_index,
                    segment_offset: seg_offset,
                    lib_ordinal,
                    symbol: symbol.clone(),
                    flags,
                    addend,
                    bind_type,
                    kind,
                });
                seg_offset = seg_offset.wrapping_add(8 + (imm as u64) * 8);
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let count = read_uleb128(data, &mut off)?;
                let skip = read_uleb128(data, &mut off)?;
                for _ in 0..count {
                    out.push(BindEntry {
                        segment_index: seg_index,
                        segment_offset: seg_offset,
                        lib_ordinal,
                        symbol: symbol.clone(),
                        flags,
                        addend,
                        bind_type,
                        kind,
                    });
                    seg_offset = seg_offset.wrapping_add(8).wrapping_add(skip);
                }
            }
            _ => {
                // Unknown / skip — stop to avoid infinite loops
                break;
            }
        }
    }
    Ok(out)
}

fn slice_linkedit<'a>(file: &MachoFile<'a>, off: u32, size: u32) -> Result<&'a [u8]> {
    if size == 0 {
        return Ok(&[]);
    }
    let start = off as usize;
    let end = start.saturating_add(size as usize);
    file.data
        .get(start..end)
        .ok_or(Error::Truncated("linkedit slice"))
}

impl<'a> MachoFile<'a> {
    /// Export trie bytes from `LC_DYLD_INFO(_ONLY)` or `LC_DYLD_EXPORTS_TRIE`.
    pub fn exports_trie_bytes(&self) -> Result<&'a [u8]> {
        if let Some(info) = self.dyld_info()? {
            if info.export_size > 0 {
                return slice_linkedit(self, info.export_off, info.export_size);
            }
        }
        if let Some(lc) = self.dyld_exports_trie_ref()? {
            return self.linkedit_payload(lc);
        }
        Ok(&[])
    }

    pub fn exports(&self) -> Result<Vec<ExportEntry>> {
        parse_exports_trie(self.exports_trie_bytes()?)
    }

    pub fn binds(&self) -> Result<Vec<BindEntry>> {
        let Some(info) = self.dyld_info()? else {
            return Ok(Vec::new());
        };
        let mut all = Vec::new();
        all.extend(parse_bind_ops(
            slice_linkedit(self, info.bind_off, info.bind_size)?,
            BindKind::Bind,
        )?);
        all.extend(parse_bind_ops(
            slice_linkedit(self, info.lazy_bind_off, info.lazy_bind_size)?,
            BindKind::LazyBind,
        )?);
        all.extend(parse_bind_ops(
            slice_linkedit(self, info.weak_bind_off, info.weak_bind_size)?,
            BindKind::WeakBind,
        )?);
        Ok(all)
    }

    /// Imports ≈ unique bind symbols (classic dyld info).
    pub fn imports(&self) -> Result<Vec<BindEntry>> {
        self.binds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_exports() {
        assert!(parse_exports_trie(&[]).unwrap().is_empty());
    }

    #[test]
    fn bind_done() {
        let ops = [BIND_OPCODE_DONE];
        assert!(parse_bind_ops(&ops, BindKind::Bind).unwrap().is_empty());
    }
}

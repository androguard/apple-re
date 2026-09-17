//! `LC_DYLD_CHAINED_FIXUPS` walker (slide = 0 / preferred load address).

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::file::MachoFile;

const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;

const DYLD_CHAINED_PTR_64: u16 = 2;
const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;

const DYLD_CHAINED_IMPORT: u32 = 1;
const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// Target of a chained fixup at a file offset.
#[derive(Debug, Clone)]
pub enum FixupTarget {
    /// Preferred virtual address (no ASLR slide).
    Rebase(u64),
    /// External bind; optional symbol name from the imports table.
    Bind {
        ordinal: u32,
        addend: i64,
        name: Option<String>,
    },
}

/// Parsed chained fixups for one thin Mach-O image.
#[derive(Debug, Clone, Default)]
pub struct ChainedFixups {
    /// File offset within the thin slice → fixup target.
    pub by_file_offset: BTreeMap<u64, FixupTarget>,
    pub image_base: u64,
}

impl ChainedFixups {
    pub fn lookup_file_offset(&self, file_off: u64) -> Option<&FixupTarget> {
        self.by_file_offset.get(&file_off)
    }

    /// Resolve a pointer at `vaddr` (chained fixup or raw absolute).
    pub fn resolve_vaddr(&self, file: &MachoFile<'_>, vaddr: u64) -> Result<Option<u64>> {
        let off = file.vaddr_to_offset(vaddr)? as u64;
        if let Some(t) = self.lookup_file_offset(off) {
            return match t {
                FixupTarget::Rebase(va) => Ok(Some(*va)),
                FixupTarget::Bind { .. } => Ok(None),
            };
        }
        Ok(Some(file.read_u64_vaddr(vaddr)?))
    }

    pub fn bind_name_at_vaddr(&self, file: &MachoFile<'_>, vaddr: u64) -> Result<Option<String>> {
        let off = file.vaddr_to_offset(vaddr)? as u64;
        Ok(match self.lookup_file_offset(off) {
            Some(FixupTarget::Bind { name, .. }) => name.clone(),
            _ => None,
        })
    }
}

impl<'a> MachoFile<'a> {
    /// Preferred image base (`__TEXT.vmaddr`, else first mapped segment).
    pub fn preferred_load_address(&self) -> Result<u64> {
        let mut first = None;
        for seg in self.segments()? {
            let (seg, _) = seg?;
            if crate::types::cstr16(&seg.segname) == "__TEXT" {
                return Ok(seg.vmaddr);
            }
            if first.is_none() && seg.filesize > 0 {
                first = Some(seg.vmaddr);
            }
        }
        Ok(first.unwrap_or(0))
    }

    /// Parse `LC_DYLD_CHAINED_FIXUPS` into a file-offset map (empty if absent).
    pub fn chained_fixups(&self) -> Result<ChainedFixups> {
        let Some(lc) = self.dyld_chained_fixups_ref()? else {
            return Ok(ChainedFixups {
                by_file_offset: BTreeMap::new(),
                image_base: self.preferred_load_address()?,
            });
        };
        let payload = self.linkedit_payload(lc)?;
        parse_chained_fixups(self, payload)
    }

    /// Read an 8-byte pointer at `vaddr`, applying chained fixups when present.
    ///
    /// Prefer [`ChainedFixups::resolve_vaddr`] when resolving many pointers.
    pub fn read_ptr_vaddr(&self, vaddr: u64) -> Result<Option<u64>> {
        self.chained_fixups()?.resolve_vaddr(self, vaddr)
    }
}

fn parse_chained_fixups(file: &MachoFile<'_>, payload: &[u8]) -> Result<ChainedFixups> {
    if payload.len() < 28 {
        return Err(Error::Truncated("chained fixups header"));
    }
    let fixups_version = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    if fixups_version != 0 {
        return Err(Error::Truncated("unsupported chained fixups version"));
    }
    let starts_offset = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
    let imports_offset = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;
    let symbols_offset = u32::from_le_bytes(payload[12..16].try_into().unwrap()) as usize;
    let imports_count = u32::from_le_bytes(payload[16..20].try_into().unwrap()) as usize;
    let imports_format = u32::from_le_bytes(payload[20..24].try_into().unwrap());
    let _symbols_format = u32::from_le_bytes(payload[24..28].try_into().unwrap());

    let image_base = file.preferred_load_address()?;
    let import_names = parse_imports(
        payload,
        imports_offset,
        symbols_offset,
        imports_count,
        imports_format,
    )?;

    let mut by_file_offset = BTreeMap::new();
    if starts_offset + 4 > payload.len() {
        return Err(Error::Truncated("chained starts"));
    }
    let seg_count = u32::from_le_bytes(payload[starts_offset..starts_offset + 4].try_into().unwrap())
        as usize;

    for seg_idx in 0..seg_count {
        let off_slot = starts_offset + 4 + seg_idx * 4;
        if off_slot + 4 > payload.len() {
            break;
        }
        let seg_info_off =
            u32::from_le_bytes(payload[off_slot..off_slot + 4].try_into().unwrap()) as usize;
        if seg_info_off == 0 {
            continue;
        }
        let abs = starts_offset + seg_info_off;
        if abs + 22 > payload.len() {
            continue;
        }
        let page_size = u16::from_le_bytes(payload[abs + 4..abs + 6].try_into().unwrap()) as u64;
        let pointer_format = u16::from_le_bytes(payload[abs + 6..abs + 8].try_into().unwrap());
        let segment_offset = u64::from_le_bytes(payload[abs + 8..abs + 16].try_into().unwrap());
        let page_count = u16::from_le_bytes(payload[abs + 20..abs + 22].try_into().unwrap()) as usize;
        let pages_off = abs + 22;
        if pages_off + page_count * 2 > payload.len() {
            continue;
        }

        let stride = pointer_stride(pointer_format);
        for page_idx in 0..page_count {
            let start = u16::from_le_bytes(
                payload[pages_off + page_idx * 2..pages_off + page_idx * 2 + 2]
                    .try_into()
                    .unwrap(),
            );
            if start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            let mut chain_starts = Vec::new();
            if start & DYLD_CHAINED_PTR_START_MULTI != 0 {
                let mut overflow_index = (start & 0x7fff) as usize;
                loop {
                    if pages_off + overflow_index * 2 + 2 > payload.len() {
                        break;
                    }
                    let s = u16::from_le_bytes(
                        payload[pages_off + overflow_index * 2..pages_off + overflow_index * 2 + 2]
                            .try_into()
                            .unwrap(),
                    );
                    chain_starts.push(s & !DYLD_CHAINED_PTR_START_LAST);
                    if s & DYLD_CHAINED_PTR_START_LAST != 0 {
                        break;
                    }
                    overflow_index += 1;
                }
            } else {
                chain_starts.push(start);
            }

            for s in chain_starts {
                let mut chain_off = segment_offset + page_idx as u64 * page_size + u64::from(s);
                loop {
                    let Some(raw) = read_u64_file(file, chain_off) else {
                        break;
                    };
                    if let Some(target) =
                        decode_ptr(raw, pointer_format, image_base, &import_names)
                    {
                        by_file_offset.insert(chain_off, target);
                    }
                    let next = next_delta(raw, pointer_format);
                    if next == 0 {
                        break;
                    }
                    chain_off += next * stride;
                }
            }
        }
    }

    Ok(ChainedFixups {
        by_file_offset,
        image_base,
    })
}

fn parse_imports(
    payload: &[u8],
    imports_offset: usize,
    symbols_offset: usize,
    imports_count: usize,
    imports_format: u32,
) -> Result<Vec<Option<String>>> {
    let mut names = Vec::with_capacity(imports_count);
    let entry_size = match imports_format {
        DYLD_CHAINED_IMPORT => 4,
        DYLD_CHAINED_IMPORT_ADDEND => 8,
        DYLD_CHAINED_IMPORT_ADDEND64 => 16,
        _ => return Ok(vec![None; imports_count]),
    };
    for i in 0..imports_count {
        let off = imports_offset + i * entry_size;
        if off + entry_size > payload.len() {
            names.push(None);
            continue;
        }
        let name_offset = match imports_format {
            DYLD_CHAINED_IMPORT => {
                let w = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap());
                // lib_ordinal:8, weak_import:1, name_offset:23
                (w >> 9) as usize
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                let w = u32::from_le_bytes(payload[off..off + 4].try_into().unwrap());
                (w >> 9) as usize
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                let w = u64::from_le_bytes(payload[off..off + 8].try_into().unwrap());
                // lib_ordinal:16, weak_import:1, reserved:15, name_offset:32
                (w >> 32) as usize
            }
            _ => 0,
        };
        let sym_off = symbols_offset + name_offset;
        names.push(read_cstr(payload, sym_off));
    }
    Ok(names)
}

fn read_cstr(data: &[u8], off: usize) -> Option<String> {
    let rest = data.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end])
        .ok()
        .map(|s| s.to_string())
}

fn read_u64_file(file: &MachoFile<'_>, file_off: u64) -> Option<u64> {
    let off = file_off as usize;
    let bytes = file.data.get(off..off + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn pointer_stride(format: u16) -> u64 {
    match format {
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => 8,
        DYLD_CHAINED_PTR_ARM64E_KERNEL => 4,
        _ => 4, // PTR_64 / PTR_64_OFFSET
    }
}

fn next_delta(raw: u64, format: u16) -> u64 {
    match format {
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        | DYLD_CHAINED_PTR_ARM64E_KERNEL => {
            // next:11 at bits 51..61 (unauth) — approximate via generic path for rebase/bind
            // arm64e next is in different places; use bit 51-61 for unauth
            (raw >> 51) & 0x7ff
        }
        _ => {
            // generic64: next at bits 51..62
            (raw >> 51) & 0xfff
        }
    }
}

fn decode_ptr(
    raw: u64,
    format: u16,
    image_base: u64,
    imports: &[Option<String>],
) -> Option<FixupTarget> {
    match format {
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
            let bind = (raw >> 63) & 1 != 0;
            if bind {
                let ordinal = (raw & ((1 << 24) - 1)) as u32;
                let addend = ((raw >> 24) & 0xff) as i64;
                let name = imports.get(ordinal as usize).and_then(|n| n.clone());
                Some(FixupTarget::Bind {
                    ordinal,
                    addend,
                    name,
                })
            } else {
                let target = raw & ((1 << 36) - 1);
                let high8 = (raw >> 36) & 0xff;
                let unpacked = (high8 << 56) | target;
                let va = if format == DYLD_CHAINED_PTR_64 {
                    unpacked
                } else {
                    image_base.wrapping_add(unpacked)
                };
                Some(FixupTarget::Rebase(va))
            }
        }
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24
        | DYLD_CHAINED_PTR_ARM64E_KERNEL => {
            // Minimal arm64e unauth support
            let bind = (raw >> 62) & 1 != 0;
            let auth = (raw >> 63) & 1 != 0;
            if auth {
                return None; // skip authenticated for now
            }
            if bind {
                let ordinal = (raw & ((1 << 16) - 1)) as u32;
                let name = imports.get(ordinal as usize).and_then(|n| n.clone());
                Some(FixupTarget::Bind {
                    ordinal,
                    addend: 0,
                    name,
                })
            } else {
                let target = raw & ((1 << 43) - 1);
                let high8 = (raw >> 43) & 0xff;
                let unpacked = (high8 << 56) | target;
                let va = if format == DYLD_CHAINED_PTR_ARM64E {
                    unpacked
                } else {
                    image_base.wrapping_add(unpacked)
                };
                Some(FixupTarget::Rebase(va))
            }
        }
        _ => None,
    }
}

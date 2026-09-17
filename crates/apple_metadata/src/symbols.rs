//! Symbol / string resolution helpers for the formatter.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use macho_core::{n_type, MachoFile, Nlist64, LC_SYMTAB, S_SYMBOL_STUBS, SECTION_TYPE};
use zerocopy::FromBytes;

use crate::error::{Error, Result};

/// Address → name map built from the Mach-O symbol table and C-string sections.
pub struct SymbolTable {
    by_addr: BTreeMap<u64, String>,
}

impl SymbolTable {
    /// Build a table from an explicit address → name map (ELF interim path, tests).
    pub fn from_addrs(by_addr: BTreeMap<u64, String>) -> Self {
        Self { by_addr }
    }

    pub fn empty() -> Self {
        Self {
            by_addr: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, vaddr: u64, name: String) {
        self.by_addr.insert(vaddr, name);
    }

    pub fn from_macho(file: &MachoFile<'_>) -> Result<Self> {
        let mut by_addr: BTreeMap<u64, String> = BTreeMap::new();

        if let Some(st) = file.symtab()? {
            let sym_off = st.symoff as usize;
            let nsyms = st.nsyms as usize;
            let str_off = st.stroff as usize;
            let str_size = st.strsize as usize;
            let syms_bytes = file
                .data
                .get(sym_off..sym_off + nsyms * core::mem::size_of::<Nlist64>())
                .ok_or(Error::Truncated("symtab"))?;
            let strings = file
                .data
                .get(str_off..str_off + str_size)
                .ok_or(Error::Truncated("strtab"))?;

            for i in 0..nsyms {
                let start = i * core::mem::size_of::<Nlist64>();
                let end = start + core::mem::size_of::<Nlist64>();
                let nl = Nlist64::read_from_bytes(&syms_bytes[start..end])
                    .map_err(|_| Error::Truncated("nlist"))?;
                // Skip undefined / stab; keep section symbols even at addr 0 (MH_OBJECT).
                if (nl.n_type & n_type::N_STAB) != 0 {
                    continue;
                }
                let typ = nl.n_type & n_type::N_TYPE;
                if typ == n_type::N_UNDF {
                    continue;
                }
                let name = cstr_at(strings, nl.n_strx as usize).unwrap_or("");
                if name.is_empty() || name.starts_with("ltmp") {
                    continue;
                }
                match by_addr.get(&nl.n_value) {
                    Some(existing)
                        if !existing.starts_with('_')
                            && !existing.starts_with("-[")
                            && !existing.starts_with("+[")
                            && (name.starts_with('_')
                                || name.starts_with("-[")
                                || name.starts_with("+[")) =>
                    {
                        by_addr.insert(nl.n_value, name.to_string());
                    }
                    None => {
                        by_addr.insert(nl.n_value, name.to_string());
                    }
                    _ => {}
                }
            }

            // Name __stubs entries via the indirect symbol table (objc_storeStrong, …).
            index_symbol_stubs(file, st, strings, syms_bytes, &mut by_addr)?;
        }

        // Index __cstring / __objc_methname for literal resolution
        for (sect_name, seg_name) in [
            ("__cstring", "__TEXT"),
            ("__objc_methname", "__TEXT"),
            ("__objc_classname", "__TEXT"),
            ("__objc_methtype", "__TEXT"),
            ("__cfstring", "__DATA"),
        ] {
            if let Some(sect) = file.find_section(seg_name, sect_name)? {
                if let Ok(data) = file.section_data(sect) {
                    index_cstrings(&mut by_addr, sect.addr, data);
                }
            }
        }

        let _ = LC_SYMTAB;
        Ok(Self { by_addr })
    }

    pub fn get_symbol_at_vaddr(&self, vaddr: u64) -> Option<String> {
        self.by_addr.get(&vaddr).cloned()
    }

    pub fn get_symbol_str_at_vaddr(&self, vaddr: u64) -> Option<&str> {
        self.by_addr.get(&vaddr).map(|s| s.as_str())
    }

    pub fn resolve_nearest(&self, vaddr: u64) -> Option<(u64, &str)> {
        self.by_addr
            .range(..=vaddr)
            .next_back()
            .map(|(a, n)| (*a, n.as_str()))
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.by_addr.iter().map(|(a, n)| (*a, n.as_str()))
    }

    pub fn len(&self) -> usize {
        self.by_addr.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }
}

fn cstr_at(strings: &[u8], off: usize) -> Option<&str> {
    let rest = strings.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end]).ok()
}

fn index_symbol_stubs(
    file: &MachoFile<'_>,
    st: &macho_core::SymtabCommand,
    strings: &[u8],
    syms_bytes: &[u8],
    by_addr: &mut BTreeMap<u64, String>,
) -> Result<()> {
    let Some(dy) = file.dysymtab()? else {
        return Ok(());
    };
    let indir_off = dy.indirectsymoff as usize;
    let indir_n = dy.nindirectsyms as usize;
    let Some(indir) = file.data.get(indir_off..indir_off + indir_n * 4) else {
        return Ok(());
    };
    let nlist_sz = core::mem::size_of::<Nlist64>();
    for sect in file.sections()? {
        let (sect, _) = sect?;
        if sect.flags & SECTION_TYPE != S_SYMBOL_STUBS {
            continue;
        }
        let stub_size = sect.reserved2 as u64;
        if stub_size == 0 || sect.size == 0 {
            continue;
        }
        let first = sect.reserved1 as usize;
        let count = (sect.size / stub_size) as usize;
        for i in 0..count {
            let slot = first + i;
            if slot >= indir_n {
                break;
            }
            let idx = u32::from_le_bytes(indir[slot * 4..slot * 4 + 4].try_into().unwrap());
            // Skip LOCAL / ABS sentinel values.
            if idx & 0x8000_0000 != 0 {
                continue;
            }
            let ni = idx as usize;
            if ni >= st.nsyms as usize {
                continue;
            }
            let nl_off = ni * nlist_sz;
            let Some(nl_bytes) = syms_bytes.get(nl_off..nl_off + nlist_sz) else {
                continue;
            };
            let Ok(nl) = Nlist64::read_from_bytes(nl_bytes) else {
                continue;
            };
            let Some(name) = cstr_at(strings, nl.n_strx as usize) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let va = sect.addr + i as u64 * stub_size;
            by_addr.entry(va).or_insert_with(|| name.to_string());
        }
    }
    Ok(())
}

fn index_cstrings(map: &mut BTreeMap<u64, String>, base: u64, data: &[u8]) {
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < data.len() && data[i] != 0 {
            i += 1;
        }
        if let Ok(s) = core::str::from_utf8(&data[start..i]) {
            if !s.is_empty() {
                map.entry(base + start as u64)
                    .or_insert_with(|| s.to_string());
            }
        }
        i += 1;
    }
}

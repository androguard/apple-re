//! ObjC reference sections (`__objc_classrefs`, `__objc_selrefs`, …).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use macho_core::{ChainedFixups, MachoFile};

use crate::error::Result;

#[derive(Debug, Clone)]
pub struct ObjcRef {
    /// Address of the reference slot.
    pub slot_vaddr: u64,
    /// Resolved target (class / protocol / selector string), when internal.
    pub target_vaddr: Option<u64>,
    /// Human-readable name.
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct ObjcRefs {
    pub class_refs: Vec<ObjcRef>,
    pub super_refs: Vec<ObjcRef>,
    pub proto_refs: Vec<ObjcRef>,
    pub sel_refs: Vec<ObjcRef>,
}

impl ObjcRefs {
    pub fn parse(file: &MachoFile<'_>) -> Result<Self> {
        let fixups = file.chained_fixups()?;
        Ok(Self {
            class_refs: parse_named_class_section(file, &fixups, "__objc_classrefs")?,
            super_refs: parse_named_class_section(file, &fixups, "__objc_superrefs")?,
            proto_refs: parse_proto_refs(file, &fixups)?,
            sel_refs: parse_sel_refs(file, &fixups)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.class_refs.is_empty()
            && self.super_refs.is_empty()
            && self.proto_refs.is_empty()
            && self.sel_refs.is_empty()
    }

    /// Text dump similar to ipsw `--refs`.
    pub fn format(&self) -> String {
        let mut out = String::new();
        dump_section(&mut out, "@protocol refs", &self.proto_refs);
        dump_section(&mut out, "@class refs", &self.class_refs);
        dump_section(&mut out, "@super refs", &self.super_refs);
        dump_section(&mut out, "@selectors refs", &self.sel_refs);
        out
    }
}

fn dump_section(out: &mut String, title: &str, refs: &[ObjcRef]) {
    if refs.is_empty() {
        return;
    }
    out.push_str(&format!("\n{title}\n"));
    for r in refs {
        match r.target_vaddr {
            Some(t) => out.push_str(&format!(
                "0x{:011x} => 0x{:011x}: {}\n",
                r.slot_vaddr, t, r.name
            )),
            None => out.push_str(&format!("0x{:011x} => (external): {}\n", r.slot_vaddr, r.name)),
        }
    }
}

fn find_ptr_section<'a>(
    file: &MachoFile<'a>,
    name: &str,
) -> Result<Option<(u64, &'a [u8])>> {
    for seg in ["__DATA_CONST", "__DATA", "__AUTH_CONST", "__AUTH"] {
        if let Some(sect) = file.find_section(seg, name)? {
            return Ok(Some((sect.addr, file.section_data(sect)?)));
        }
    }
    Ok(None)
}

fn parse_named_class_section(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    sect_name: &str,
) -> Result<Vec<ObjcRef>> {
    let mut out = Vec::new();
    let Some((base_va, data)) = find_ptr_section(file, sect_name)? else {
        return Ok(out);
    };
    for (i, _) in data.chunks_exact(8).enumerate() {
        let slot = base_va + (i as u64) * 8;
        match fixups.resolve_vaddr(file, slot)? {
            Some(target) if target != 0 => {
                let name = class_name_at(file, fixups, target)
                    .unwrap_or_else(|| format!("class_{target:#x}"));
                out.push(ObjcRef {
                    slot_vaddr: slot,
                    target_vaddr: Some(target),
                    name,
                });
            }
            None => {
                let name = fixups
                    .bind_name_at_vaddr(file, slot)?
                    .map(|s| {
                        s.strip_prefix("_OBJC_CLASS_$_")
                            .or_else(|| s.strip_prefix("_OBJC_METACLASS_$_"))
                            .unwrap_or(&s)
                            .to_string()
                    })
                    .unwrap_or_else(|| String::from("?"));
                out.push(ObjcRef {
                    slot_vaddr: slot,
                    target_vaddr: None,
                    name,
                });
            }
            _ => {}
        }
    }
    Ok(out)
}

fn parse_proto_refs(file: &MachoFile<'_>, fixups: &ChainedFixups) -> Result<Vec<ObjcRef>> {
    let mut out = Vec::new();
    let Some((base_va, data)) = find_ptr_section(file, "__objc_protorefs")? else {
        return Ok(out);
    };
    for (i, _) in data.chunks_exact(8).enumerate() {
        let slot = base_va + (i as u64) * 8;
        match fixups.resolve_vaddr(file, slot)? {
            Some(target) if target != 0 => {
                let name = protocol_name_at(file, fixups, target)
                    .unwrap_or_else(|| format!("protocol_{target:#x}"));
                out.push(ObjcRef {
                    slot_vaddr: slot,
                    target_vaddr: Some(target),
                    name,
                });
            }
            None => {
                let name = fixups
                    .bind_name_at_vaddr(file, slot)?
                    .map(|s| {
                        s.strip_prefix("_OBJC_PROTOCOL_$_")
                            .unwrap_or(&s)
                            .to_string()
                    })
                    .unwrap_or_else(|| String::from("?"));
                out.push(ObjcRef {
                    slot_vaddr: slot,
                    target_vaddr: None,
                    name,
                });
            }
            _ => {}
        }
    }
    Ok(out)
}

fn parse_sel_refs(file: &MachoFile<'_>, fixups: &ChainedFixups) -> Result<Vec<ObjcRef>> {
    let mut out = Vec::new();
    let Some((base_va, data)) = find_ptr_section(file, "__objc_selrefs")? else {
        return Ok(out);
    };
    for (i, _) in data.chunks_exact(8).enumerate() {
        let slot = base_va + (i as u64) * 8;
        match fixups.resolve_vaddr(file, slot)? {
            Some(target) if target != 0 => {
                // In-image methname, or shared/DSC VA we cannot map locally.
                let name = file
                    .read_cstr_vaddr(target)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| format!("sel_{target:#x}"));
                out.push(ObjcRef {
                    slot_vaddr: slot,
                    target_vaddr: Some(target),
                    name,
                });
            }
            None => {
                // Chained bind / external selector (often DSC-uniqued).
                let name = fixups
                    .bind_name_at_vaddr(file, slot)?
                    .map(|s| s.trim_start_matches('_').to_string())
                    .unwrap_or_else(|| String::from("?"));
                out.push(ObjcRef {
                    slot_vaddr: slot,
                    target_vaddr: None,
                    name,
                });
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Apply an external VA → selector string map (DSC / host extract) onto refs
/// whose names are still placeholders (`sel_0x…`, `?`, empty).
pub fn apply_selector_map(refs: &mut ObjcRefs, map: &[(u64, String)]) {
    if map.is_empty() {
        return;
    }
    for r in &mut refs.sel_refs {
        let needs = r.name.is_empty()
            || r.name == "?"
            || r.name.starts_with("sel_0x")
            || r.name.starts_with("sel_");
        if !needs {
            continue;
        }
        if let Some(t) = r.target_vaddr {
            if let Some((_, name)) = map.iter().find(|(va, _)| *va == t) {
                r.name = name.clone();
                continue;
            }
        }
        if let Some((_, name)) = map.iter().find(|(va, _)| *va == r.slot_vaddr) {
            r.name = name.clone();
        }
    }
}

fn class_name_at(file: &MachoFile<'_>, fixups: &ChainedFixups, class_va: u64) -> Option<String> {
    let data = fixups.resolve_vaddr(file, class_va + 0x20).ok().flatten()? & !1;
    let name_p = fixups
        .resolve_vaddr(file, data + 0x18)
        .ok()
        .flatten()
        .or_else(|| {
            // class_rw_t → ro at +8
            let ro = fixups.resolve_vaddr(file, data + 0x08).ok().flatten()? & !1;
            fixups.resolve_vaddr(file, ro + 0x18).ok().flatten()
        })?;
    file.read_cstr_vaddr(name_p).ok().map(|s| s.to_string())
}

fn protocol_name_at(file: &MachoFile<'_>, fixups: &ChainedFixups, proto_va: u64) -> Option<String> {
    let name_p = fixups.resolve_vaddr(file, proto_va + 0x08).ok().flatten()?;
    file.read_cstr_vaddr(name_p).ok().map(|s| s.to_string())
}

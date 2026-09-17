//! Objective-C runtime metadata walker (modern ABI).
//!
//! Parses `__objc_classlist`, `__objc_catlist`, and `__objc_protolist` into
//! structures suitable for class-dump-style header generation.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use macho_core::{ChainedFixups, MachoFile};

use crate::error::Result;

/// Reconstructed ObjC class.
#[derive(Debug, Clone)]
pub struct ObjcClass {
    pub name: String,
    pub class_vaddr: u64,
    pub superclass: Option<String>,
    pub instance_start: u32,
    pub instance_size: u32,
    pub methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub ivars: Vec<ObjcIvar>,
    pub properties: Vec<ObjcProperty>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ObjcMethod {
    pub name: String,
    pub types: String,
    pub imp: u64,
}

#[derive(Debug, Clone)]
pub struct ObjcIvar {
    pub name: String,
    pub types: String,
    pub offset: u64,
    pub alignment: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct ObjcProperty {
    pub name: String,
    pub attributes: String,
}

#[derive(Debug, Clone)]
pub struct ObjcCategory {
    pub name: String,
    pub class_name: String,
    pub methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub properties: Vec<ObjcProperty>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ObjcProtocol {
    pub name: String,
    pub protocols: Vec<String>,
    pub methods: Vec<ObjcMethod>,
    pub class_methods: Vec<ObjcMethod>,
    pub optional_methods: Vec<ObjcMethod>,
    pub optional_class_methods: Vec<ObjcMethod>,
    pub properties: Vec<ObjcProperty>,
}

pub struct ObjcMetadata {
    pub classes: Vec<ObjcClass>,
    pub categories: Vec<ObjcCategory>,
    pub protocols: Vec<ObjcProtocol>,
}

impl ObjcMetadata {
    pub fn parse(file: &MachoFile<'_>) -> Result<Self> {
        let fixups = file.chained_fixups()?;
        let classes = parse_classlist(file, &fixups)?;
        let categories = parse_catlist(file, &fixups).unwrap_or_default();
        let protocols = parse_protolist(file, &fixups).unwrap_or_default();
        Ok(Self {
            classes,
            categories,
            protocols,
        })
    }
}

fn ptr(file: &MachoFile<'_>, fixups: &ChainedFixups, vaddr: u64) -> Result<Option<u64>> {
    Ok(fixups.resolve_vaddr(file, vaddr)?)
}

fn cstr_at(file: &MachoFile<'_>, vaddr: u64) -> Option<String> {
    file.read_cstr_vaddr(vaddr).ok().map(|s| s.to_string())
}

fn find_ptr_section<'a>(
    file: &MachoFile<'a>,
    name: &str,
) -> Result<Option<&'a [u8]>> {
    for seg in ["__DATA_CONST", "__DATA", "__AUTH_CONST", "__AUTH"] {
        if let Some(sect) = file.find_section(seg, name)? {
            return Ok(Some(file.section_data(sect)?));
        }
    }
    Ok(None)
}

fn parse_classlist(file: &MachoFile<'_>, fixups: &ChainedFixups) -> Result<Vec<ObjcClass>> {
    let mut classes = Vec::new();
    let Some(data) = find_ptr_section(file, "__objc_classlist")? else {
        return Ok(classes);
    };
    // Section VA for resolving each slot via fixups
    let sect = file
        .find_section("__DATA_CONST", "__objc_classlist")?
        .or(file.find_section("__DATA", "__objc_classlist")?)
        .or(file.find_section("__AUTH_CONST", "__objc_classlist")?)
        .or(file.find_section("__AUTH", "__objc_classlist")?);
    let base_va = sect.map(|s| s.addr).unwrap_or(0);

    for (i, chunk) in data.chunks_exact(8).enumerate() {
        let slot_va = base_va + (i as u64) * 8;
        let class_vaddr = match ptr(file, fixups, slot_va)? {
            Some(v) if v != 0 => v,
            _ => {
                // Fallback: raw absolute (pre-chained binaries)
                let raw = u64::from_le_bytes(chunk.try_into().unwrap());
                if raw == 0 {
                    continue;
                }
                raw
            }
        };
        if let Ok(cls) = parse_class(file, fixups, class_vaddr) {
            classes.push(cls);
        }
    }
    Ok(classes)
}

fn parse_catlist(file: &MachoFile<'_>, fixups: &ChainedFixups) -> Result<Vec<ObjcCategory>> {
    let mut out = Vec::new();
    let Some(data) = find_ptr_section(file, "__objc_catlist")? else {
        return Ok(out);
    };
    let sect = file
        .find_section("__DATA_CONST", "__objc_catlist")?
        .or(file.find_section("__DATA", "__objc_catlist")?)
        .or(file.find_section("__AUTH_CONST", "__objc_catlist")?)
        .or(file.find_section("__AUTH", "__objc_catlist")?);
    let base_va = sect.map(|s| s.addr).unwrap_or(0);
    for (i, _) in data.chunks_exact(8).enumerate() {
        let slot_va = base_va + (i as u64) * 8;
        let Some(cat_vaddr) = ptr(file, fixups, slot_va)?.filter(|&p| p != 0) else {
            continue;
        };
        if let Ok(c) = parse_category(file, fixups, cat_vaddr) {
            out.push(c);
        }
    }
    Ok(out)
}

fn parse_protolist(file: &MachoFile<'_>, fixups: &ChainedFixups) -> Result<Vec<ObjcProtocol>> {
    let mut out = Vec::new();
    let Some(data) = find_ptr_section(file, "__objc_protolist")? else {
        return Ok(out);
    };
    let sect = file
        .find_section("__DATA_CONST", "__objc_protolist")?
        .or(file.find_section("__DATA", "__objc_protolist")?)
        .or(file.find_section("__AUTH_CONST", "__objc_protolist")?)
        .or(file.find_section("__AUTH", "__objc_protolist")?);
    let base_va = sect.map(|s| s.addr).unwrap_or(0);
    for (i, _) in data.chunks_exact(8).enumerate() {
        let slot_va = base_va + (i as u64) * 8;
        let Some(p_vaddr) = ptr(file, fixups, slot_va)?.filter(|&p| p != 0) else {
            continue;
        };
        if let Ok(p) = parse_protocol(file, fixups, p_vaddr) {
            if !out.iter().any(|x| x.name == p.name) {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// Resolve `class_ro_t*` from `objc_class.data` (may be class_rw_t).
fn class_ro_ptr(file: &MachoFile<'_>, fixups: &ChainedFixups, class_vaddr: u64) -> Result<u64> {
    let data_ptr = ptr(file, fixups, class_vaddr + 0x20)?.unwrap_or(0) & !1u64;
    if data_ptr == 0 {
        return Ok(0);
    }
    // Heuristic: if name* at +0x18 looks like a C-string in __TEXT, treat as RO.
    if let Ok(Some(name_p)) = ptr(file, fixups, data_ptr + 0x18) {
        if cstr_at(file, name_p).is_some() {
            return Ok(data_ptr);
        }
    }
    Ok(ptr(file, fixups, data_ptr + 0x08)?.unwrap_or(0) & !1u64)
}

fn parse_class(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    class_vaddr: u64,
) -> Result<ObjcClass> {
    let ro = class_ro_ptr(file, fixups, class_vaddr)?;
    let (name, instance_start, instance_size, methods, ivars, properties, protocols) =
        parse_class_ro(file, fixups, ro)?;

    let superclass = match ptr(file, fixups, class_vaddr + 0x08)? {
        Some(super_p) if super_p != 0 => class_ro_ptr(file, fixups, super_p)
            .ok()
            .and_then(|sro| ptr(file, fixups, sro + 0x18).ok().flatten())
            .and_then(|name_p| cstr_at(file, name_p)),
        None => {
            // External superclass (e.g. NSObject) — strip ObjC class symbol prefix
            fixups
                .bind_name_at_vaddr(file, class_vaddr + 0x08)
                .ok()
                .flatten()
                .map(|s| {
                    s.strip_prefix("_OBJC_CLASS_$_")
                        .unwrap_or(&s)
                        .to_string()
                })
        }
        _ => None,
    };

    let class_methods = match ptr(file, fixups, class_vaddr)? {
        Some(meta) if meta != 0 => class_ro_ptr(file, fixups, meta)
            .ok()
            .and_then(|mro| ptr(file, fixups, mro + 0x20).ok().flatten())
            .map(|methods_p| {
                if methods_p == 0 {
                    Vec::new()
                } else {
                    parse_method_list(file, fixups, methods_p).unwrap_or_default()
                }
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    Ok(ObjcClass {
        name,
        class_vaddr,
        superclass,
        instance_start,
        instance_size,
        methods,
        class_methods,
        ivars,
        properties,
        protocols,
    })
}

fn parse_class_ro(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    ro: u64,
) -> Result<(
    String,
    u32,
    u32,
    Vec<ObjcMethod>,
    Vec<ObjcIvar>,
    Vec<ObjcProperty>,
    Vec<String>,
)> {
    let instance_start = read_u32(file, ro + 0x04).unwrap_or(0);
    let instance_size = read_u32(file, ro + 0x08).unwrap_or(0);
    let name_ptr = ptr(file, fixups, ro + 0x18)?.unwrap_or(0);
    let name = cstr_at(file, name_ptr).unwrap_or_else(|| alloc::format!("class_{ro:#x}"));

    let methods_ptr = ptr(file, fixups, ro + 0x20)?.unwrap_or(0);
    let protocols_ptr = ptr(file, fixups, ro + 0x28)?.unwrap_or(0);
    let ivars_ptr = ptr(file, fixups, ro + 0x30)?.unwrap_or(0);
    let props_ptr = ptr(file, fixups, ro + 0x40)?.unwrap_or(0);

    let methods = if methods_ptr != 0 {
        parse_method_list(file, fixups, methods_ptr).unwrap_or_default()
    } else {
        Vec::new()
    };
    let protocols = if protocols_ptr != 0 {
        parse_protocol_list_names(file, fixups, protocols_ptr).unwrap_or_default()
    } else {
        Vec::new()
    };
    let ivars = if ivars_ptr != 0 {
        parse_ivar_list(file, fixups, ivars_ptr).unwrap_or_default()
    } else {
        Vec::new()
    };
    let properties = if props_ptr != 0 {
        parse_property_list(file, fixups, props_ptr).unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok((
        name,
        instance_start,
        instance_size,
        methods,
        ivars,
        properties,
        protocols,
    ))
}

fn parse_category(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    cat_vaddr: u64,
) -> Result<ObjcCategory> {
    let name_p = ptr(file, fixups, cat_vaddr)?.unwrap_or(0);
    let cls_p = ptr(file, fixups, cat_vaddr + 0x08)?;
    let inst_m = ptr(file, fixups, cat_vaddr + 0x10)?.unwrap_or(0);
    let class_m = ptr(file, fixups, cat_vaddr + 0x18)?.unwrap_or(0);
    let protos = ptr(file, fixups, cat_vaddr + 0x20)?.unwrap_or(0);
    let props = ptr(file, fixups, cat_vaddr + 0x28)?.unwrap_or(0);

    let name = cstr_at(file, name_p).unwrap_or_default();
    let class_name = match cls_p {
        Some(p) if p != 0 => class_ro_ptr(file, fixups, p)
            .ok()
            .and_then(|ro| ptr(file, fixups, ro + 0x18).ok().flatten())
            .and_then(|np| cstr_at(file, np))
            .unwrap_or_else(|| String::from("?")),
        None => fixups
            .bind_name_at_vaddr(file, cat_vaddr + 0x08)
            .ok()
            .flatten()
            .map(|s| {
                s.strip_prefix("_OBJC_CLASS_$_")
                    .unwrap_or(&s)
                    .to_string()
            })
            .unwrap_or_else(|| String::from("?")),
        _ => String::from("?"),
    };

    Ok(ObjcCategory {
        name,
        class_name,
        methods: if inst_m != 0 {
            parse_method_list(file, fixups, inst_m).unwrap_or_default()
        } else {
            Vec::new()
        },
        class_methods: if class_m != 0 {
            parse_method_list(file, fixups, class_m).unwrap_or_default()
        } else {
            Vec::new()
        },
        properties: if props != 0 {
            parse_property_list(file, fixups, props).unwrap_or_default()
        } else {
            Vec::new()
        },
        protocols: if protos != 0 {
            parse_protocol_list_names(file, fixups, protos).unwrap_or_default()
        } else {
            Vec::new()
        },
    })
}

fn parse_protocol(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    p_vaddr: u64,
) -> Result<ObjcProtocol> {
    let name_p = ptr(file, fixups, p_vaddr + 0x08)?.unwrap_or(0);
    let name = cstr_at(file, name_p).unwrap_or_default();
    let protos = ptr(file, fixups, p_vaddr + 0x10)?.unwrap_or(0);
    let inst_m = ptr(file, fixups, p_vaddr + 0x18)?.unwrap_or(0);
    let class_m = ptr(file, fixups, p_vaddr + 0x20)?.unwrap_or(0);
    let opt_inst = ptr(file, fixups, p_vaddr + 0x28)?.unwrap_or(0);
    let opt_class = ptr(file, fixups, p_vaddr + 0x30)?.unwrap_or(0);
    let props = ptr(file, fixups, p_vaddr + 0x38)?.unwrap_or(0);

    Ok(ObjcProtocol {
        name,
        protocols: if protos != 0 {
            parse_protocol_list_names(file, fixups, protos).unwrap_or_default()
        } else {
            Vec::new()
        },
        methods: if inst_m != 0 {
            parse_method_list(file, fixups, inst_m).unwrap_or_default()
        } else {
            Vec::new()
        },
        class_methods: if class_m != 0 {
            parse_method_list(file, fixups, class_m).unwrap_or_default()
        } else {
            Vec::new()
        },
        optional_methods: if opt_inst != 0 {
            parse_method_list(file, fixups, opt_inst).unwrap_or_default()
        } else {
            Vec::new()
        },
        optional_class_methods: if opt_class != 0 {
            parse_method_list(file, fixups, opt_class).unwrap_or_default()
        } else {
            Vec::new()
        },
        properties: if props != 0 {
            parse_property_list(file, fixups, props).unwrap_or_default()
        } else {
            Vec::new()
        },
    })
}

fn parse_method_list(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    list_vaddr: u64,
) -> Result<Vec<ObjcMethod>> {
    let entsize_raw = read_u32(file, list_vaddr)?;
    let count = read_u32(file, list_vaddr + 4)? as usize;
    let relative = (entsize_raw & 0x8000_0000) != 0;
    if relative {
        let direct = (entsize_raw & 0x4000_0000) != 0;
        return parse_relative_method_list(file, fixups, list_vaddr, count, direct);
    }
    let entsize = entsize_raw & !3;
    let ent = if entsize == 0 { 24 } else { u64::from(entsize) };
    let mut methods = Vec::with_capacity(count.min(8192));
    for i in 0..count.min(8192) {
        let base = list_vaddr + 8 + i as u64 * ent;
        let name_p = ptr(file, fixups, base)?.unwrap_or(0);
        let types_p = ptr(file, fixups, base + 8)?.unwrap_or(0);
        let imp = ptr(file, fixups, base + 16)?.unwrap_or(0);
        let name = cstr_at(file, name_p).unwrap_or_default();
        let types = cstr_at(file, types_p).unwrap_or_default();
        if !name.is_empty() {
            methods.push(ObjcMethod { name, types, imp });
        }
    }
    Ok(methods)
}

fn parse_relative_method_list(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    list_vaddr: u64,
    count: usize,
    direct_selectors: bool,
) -> Result<Vec<ObjcMethod>> {
    let mut methods = Vec::new();
    for i in 0..count.min(8192) {
        let base = list_vaddr + 8 + i as u64 * 12;
        let name_off = read_i32(file, base)? as i64;
        let types_off = read_i32(file, base + 4)? as i64;
        let imp_off = read_i32(file, base + 8)? as i64;
        let name_loc = (base as i64).wrapping_add(name_off) as u64;
        let types_p = (base as i64 + 4).wrapping_add(types_off) as u64;
        let imp = if imp_off == 0 {
            0
        } else {
            (base as i64 + 8).wrapping_add(imp_off) as u64
        };
        let name = if direct_selectors {
            cstr_at(file, name_loc).unwrap_or_default()
        } else {
            // name_loc is a selref pointer slot
            ptr(file, fixups, name_loc)?
                .and_then(|p| cstr_at(file, p))
                .unwrap_or_default()
        };
        let types = cstr_at(file, types_p).unwrap_or_default();
        if !name.is_empty() {
            methods.push(ObjcMethod { name, types, imp });
        }
    }
    Ok(methods)
}

fn parse_ivar_list(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    list_vaddr: u64,
) -> Result<Vec<ObjcIvar>> {
    let entsize = read_u32(file, list_vaddr)? as u64;
    let count = read_u32(file, list_vaddr + 4)? as usize;
    let ent = if entsize == 0 { 32 } else { entsize };
    let mut ivars = Vec::new();
    for i in 0..count.min(4096) {
        let base = list_vaddr + 8 + i as u64 * ent;
        let offset_p = ptr(file, fixups, base)?.unwrap_or(0);
        let name_p = ptr(file, fixups, base + 8)?.unwrap_or(0);
        let type_p = ptr(file, fixups, base + 16)?.unwrap_or(0);
        let alignment = read_u32(file, base + 24).unwrap_or(0);
        let size = read_u32(file, base + 28).unwrap_or(0);
        // offset* points to a u32/u64 holding the ivar offset (often not a fixup)
        let offset = if offset_p != 0 {
            read_u32(file, offset_p)
                .map(|v| v as u64)
                .or_else(|_| file.read_u64_vaddr(offset_p))
                .unwrap_or(0)
        } else {
            0
        };
        let name = cstr_at(file, name_p).unwrap_or_default();
        let types = cstr_at(file, type_p).unwrap_or_default();
        if !name.is_empty() {
            ivars.push(ObjcIvar {
                name,
                types,
                offset,
                alignment,
                size,
            });
        }
    }
    Ok(ivars)
}

fn parse_property_list(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    list_vaddr: u64,
) -> Result<Vec<ObjcProperty>> {
    let entsize = read_u32(file, list_vaddr)? as u64;
    let count = read_u32(file, list_vaddr + 4)? as usize;
    let ent = if entsize == 0 { 16 } else { entsize };
    let mut props = Vec::new();
    for i in 0..count.min(4096) {
        let base = list_vaddr + 8 + i as u64 * ent;
        let name_p = ptr(file, fixups, base)?.unwrap_or(0);
        let attr_p = ptr(file, fixups, base + 8)?.unwrap_or(0);
        let name = cstr_at(file, name_p).unwrap_or_default();
        let attributes = cstr_at(file, attr_p).unwrap_or_default();
        if !name.is_empty() {
            props.push(ObjcProperty { name, attributes });
        }
    }
    Ok(props)
}

fn parse_protocol_list_names(
    file: &MachoFile<'_>,
    fixups: &ChainedFixups,
    list_vaddr: u64,
) -> Result<Vec<String>> {
    let count = file.read_u64_vaddr(list_vaddr)? as usize;
    let mut names = Vec::new();
    for i in 0..count.min(512) {
        let Some(p) = ptr(file, fixups, list_vaddr + 8 + i as u64 * 8)?.filter(|&p| p != 0) else {
            continue;
        };
        if let Some(name_p) = ptr(file, fixups, p + 0x08)? {
            if let Some(n) = cstr_at(file, name_p) {
                names.push(n);
            }
        }
    }
    Ok(names)
}

fn read_u32(file: &MachoFile<'_>, vaddr: u64) -> Result<u32> {
    let b = file.read_vaddr(vaddr, 4)?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_i32(file: &MachoFile<'_>, vaddr: u64) -> Result<i32> {
    Ok(read_u32(file, vaddr)? as i32)
}

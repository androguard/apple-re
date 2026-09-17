//! Code-signing SuperBlob parser (`LC_CODE_SIGNATURE` payload).

use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::types::{cs_magic, cs_slot};

/// Parsed embedded / detached code signature.
#[derive(Debug, Clone)]
pub struct CodeSignature<'a> {
    pub magic: u32,
    pub length: u32,
    pub slots: Vec<CsSlot>,
    pub code_directory: Option<CodeDirectory<'a>>,
    pub alternate_code_directories: Vec<CodeDirectory<'a>>,
    /// XML entitlements blob payload (without SuperBlob header).
    pub entitlements_xml: Option<&'a [u8]>,
    /// DER entitlements blob payload.
    pub entitlements_der: Option<&'a [u8]>,
    /// CMS / PKCS#7 wrapper payload (`CSMAGIC_BLOBWRAPPER`).
    pub cms: Option<&'a [u8]>,
    pub requirements_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsSlot {
    pub slot_type: u32,
    pub offset: u32,
}

/// Subset of `CS_CodeDirectory` fields useful for RE / triage.
#[derive(Debug, Clone)]
pub struct CodeDirectory<'a> {
    pub magic: u32,
    pub length: u32,
    pub version: u32,
    pub flags: u32,
    pub hash_offset: u32,
    pub ident_offset: u32,
    pub n_special_slots: u32,
    pub n_code_slots: u32,
    pub code_limit: u32,
    pub hash_size: u8,
    pub hash_type: u8,
    pub platform: u8,
    pub page_size_log2: u8,
    pub identifier: Option<&'a str>,
    pub team_id: Option<&'a str>,
    pub code_limit_64: Option<u64>,
    pub exec_seg_base: Option<u64>,
    pub exec_seg_limit: Option<u64>,
    pub exec_seg_flags: Option<u64>,
    /// Full CodeDirectory blob bytes (for hashing externally).
    pub blob: &'a [u8],
}

pub fn parse_code_signature(blob: &[u8]) -> Result<CodeSignature<'_>> {
    if blob.len() < 12 {
        return Err(Error::Truncated("code signature"));
    }
    let magic = read_u32_be(blob, 0)?;
    if magic != cs_magic::EMBEDDED_SIGNATURE && magic != cs_magic::DETACHED_SIGNATURE {
        return Err(Error::BadCsMagic(magic));
    }
    let length = read_u32_be(blob, 4)?;
    let count = read_u32_be(blob, 8)? as usize;
    if length as usize > blob.len() || count > 256 {
        return Err(Error::Truncated("code signature slots"));
    }

    let mut slots = Vec::with_capacity(count.min(64));
    for i in 0..count {
        let off = 12 + i * 8;
        if off + 8 > blob.len() {
            break;
        }
        slots.push(CsSlot {
            slot_type: read_u32_be(blob, off)?,
            offset: read_u32_be(blob, off + 4)?,
        });
    }

    let mut result = CodeSignature {
        magic,
        length,
        slots: slots.clone(),
        code_directory: None,
        alternate_code_directories: Vec::new(),
        entitlements_xml: None,
        entitlements_der: None,
        cms: None,
        requirements_present: false,
    };

    for slot in &slots {
        let slot_off = slot.offset as usize;
        if slot_off + 8 > blob.len() {
            continue;
        }
        let m = read_u32_be(blob, slot_off)?;
        let l = read_u32_be(blob, slot_off + 4)? as usize;
        if l < 8 || slot_off + l > blob.len() {
            continue;
        }
        let sub = &blob[slot_off..slot_off + l];
        let payload = &sub[8..];

        match m {
            cs_magic::CODEDIRECTORY => {
                if let Ok(cd) = parse_code_directory(sub) {
                    if slot.slot_type == cs_slot::CODEDIRECTORY {
                        result.code_directory = Some(cd);
                    } else {
                        result.alternate_code_directories.push(cd);
                    }
                }
            }
            cs_magic::EMBEDDED_ENTITLEMENTS => {
                result.entitlements_xml = Some(payload);
            }
            cs_magic::EMBEDDED_DER_ENTITLEMENTS => {
                result.entitlements_der = Some(payload);
            }
            cs_magic::BLOBWRAPPER => {
                result.cms = Some(payload);
            }
            cs_magic::REQUIREMENTS | cs_magic::REQUIREMENT => {
                result.requirements_present = true;
            }
            _ => {}
        }
    }

    Ok(result)
}

fn parse_code_directory(blob: &[u8]) -> Result<CodeDirectory<'_>> {
    if blob.len() < 44 {
        return Err(Error::Truncated("code directory"));
    }
    let magic = read_u32_be(blob, 0)?;
    let length = read_u32_be(blob, 4)?;
    let version = read_u32_be(blob, 8)?;
    let flags = read_u32_be(blob, 12)?;
    let hash_offset = read_u32_be(blob, 16)?;
    let ident_offset = read_u32_be(blob, 20)?;
    let n_special_slots = read_u32_be(blob, 24)?;
    let n_code_slots = read_u32_be(blob, 28)?;
    let code_limit = read_u32_be(blob, 32)?;
    let hash_size = blob[36];
    let hash_type = blob[37];
    let platform = blob[38];
    let page_size_log2 = blob[39];

    let mut pos = 44; // after spare2
    let mut code_limit_64 = None;
    let mut exec_seg_base = None;
    let mut exec_seg_limit = None;
    let mut exec_seg_flags = None;
    let mut team_offset = 0u32;

    if version >= 0x20100 {
        // scatterOffset
        pos = checked_add(pos, 4)?;
    }
    if version >= 0x20200 {
        team_offset = read_u32_be(blob, pos)?;
        pos = checked_add(pos, 4)?;
    }
    if version >= 0x20300 {
        pos = checked_add(pos, 4)?; // spare3
        if pos + 8 <= blob.len() {
            code_limit_64 = Some(read_u64_be(blob, pos)?);
        }
        pos = checked_add(pos, 8)?;
    }
    if version >= 0x20400 && pos + 24 <= blob.len() {
        exec_seg_base = Some(read_u64_be(blob, pos)?);
        exec_seg_limit = Some(read_u64_be(blob, pos + 8)?);
        exec_seg_flags = Some(read_u64_be(blob, pos + 16)?);
    }

    let _ = pos;
    let identifier = cstr_at(blob, ident_offset as usize);
    let team_id = if team_offset != 0 {
        cstr_at(blob, team_offset as usize)
    } else {
        None
    };

    Ok(CodeDirectory {
        magic,
        length,
        version,
        flags,
        hash_offset,
        ident_offset,
        n_special_slots,
        n_code_slots,
        code_limit,
        hash_size,
        hash_type,
        platform,
        page_size_log2,
        identifier,
        team_id,
        code_limit_64,
        exec_seg_base,
        exec_seg_limit,
        exec_seg_flags,
        blob,
    })
}

fn cstr_at(data: &[u8], off: usize) -> Option<&str> {
    if off == 0 || off >= data.len() {
        return None;
    }
    let rest = &data[off..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len().min(512));
    core::str::from_utf8(&rest[..end]).ok().filter(|s| !s.is_empty())
}

fn checked_add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Truncated("code directory"))
}

fn read_u32_be(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or(Error::Truncated("cs u32"))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_be(data: &[u8], off: usize) -> Result<u64> {
    let b = data
        .get(off..off + 8)
        .ok_or(Error::Truncated("cs u64"))?;
    Ok(u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

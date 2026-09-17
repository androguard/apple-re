//! Minimal Info.plist reader (XML text + binary bplist00) for CFBundle keys.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct BundleInfo {
    pub bundle_id: String,
    pub bundle_executable: String,
    pub bundle_name: String,
}

pub fn parse_info_plist(data: &[u8]) -> Result<BundleInfo> {
    if data.starts_with(b"bplist00") {
        parse_bplist(data)
    } else {
        parse_xml_plist(data)
    }
}

fn parse_xml_plist(data: &[u8]) -> Result<BundleInfo> {
    let text = core::str::from_utf8(data)
        .map_err(|_| Error::PlistParse("xml plist is not utf-8".into()))?;
    let map = extract_xml_string_dict(text)?;
    Ok(BundleInfo {
        bundle_id: map
            .get("CFBundleIdentifier")
            .cloned()
            .unwrap_or_default(),
        bundle_executable: map
            .get("CFBundleExecutable")
            .cloned()
            .ok_or(Error::MissingBundleExecutable)?,
        bundle_name: map
            .get("CFBundleName")
            .cloned()
            .unwrap_or_default(),
    })
}

fn extract_xml_string_dict(text: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    let mut rest = text;
    while let Some(key_start) = rest.find("<key>") {
        rest = &rest[key_start + 5..];
        let key_end = rest
            .find("</key>")
            .ok_or_else(|| Error::PlistParse("unclosed <key>".into()))?;
        let key = rest[..key_end].trim().to_string();
        rest = &rest[key_end + 6..];
        let trimmed = rest.trim_start();
        if let Some(after) = trimmed.strip_prefix("<string>") {
            let end = after
                .find("</string>")
                .ok_or_else(|| Error::PlistParse("unclosed <string>".into()))?;
            let value = after[..end].to_string();
            map.insert(key, value);
            rest = &after[end + 9..];
        }
    }
    Ok(map)
}

/// Very small binary plist subset: top-level dict of ASCII/UTF-8 string values.
fn parse_bplist(data: &[u8]) -> Result<BundleInfo> {
    if data.len() < 40 {
        return Err(Error::PlistParse("bplist too short".into()));
    }
    let trailer = &data[data.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    let num_objects = read_be_int(&trailer[8..16])?;
    let top_object = read_be_int(&trailer[16..24])?;
    let offset_table_offset = read_be_int(&trailer[24..32])?;

    if offset_size == 0 || ref_size == 0 || num_objects == 0 {
        return Err(Error::PlistParse("invalid bplist trailer".into()));
    }

    let mut offsets = Vec::with_capacity(num_objects);
    for i in 0..num_objects {
        let off = offset_table_offset + i * offset_size;
        offsets.push(read_be_sized(data, off, offset_size)?);
    }

    let top = offsets
        .get(top_object)
        .copied()
        .ok_or_else(|| Error::PlistParse("bad top object".into()))?;
    let dict = read_dict(data, top, &offsets, ref_size)?;

    let get = |k: &str| dict.get(k).cloned().unwrap_or_default();
    let exec = dict
        .get("CFBundleExecutable")
        .cloned()
        .ok_or(Error::MissingBundleExecutable)?;

    Ok(BundleInfo {
        bundle_id: get("CFBundleIdentifier"),
        bundle_executable: exec,
        bundle_name: get("CFBundleName"),
    })
}

fn read_dict(
    data: &[u8],
    obj_off: usize,
    offsets: &[usize],
    ref_size: usize,
) -> Result<BTreeMap<String, String>> {
    let marker = *data
        .get(obj_off)
        .ok_or_else(|| Error::PlistParse("oob object".into()))?;
    let obj_type = marker >> 4;
    if obj_type != 0xD {
        return Err(Error::PlistParse("top object is not a dict".into()));
    }
    let (count, body_off) = read_size(data, obj_off, marker)?;
    let mut map = BTreeMap::new();
    for i in 0..count {
        let key_ref = read_be_sized(data, body_off + i * ref_size, ref_size)?;
        let val_ref = read_be_sized(data, body_off + (count + i) * ref_size, ref_size)?;
        let key_off = *offsets
            .get(key_ref)
            .ok_or_else(|| Error::PlistParse("bad key ref".into()))?;
        let val_off = *offsets
            .get(val_ref)
            .ok_or_else(|| Error::PlistParse("bad val ref".into()))?;
        let key = match read_string(data, key_off) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Ok(val) = read_string(data, val_off) {
            map.insert(key, val);
        }
    }
    Ok(map)
}

fn read_string(data: &[u8], obj_off: usize) -> Result<String> {
    let marker = *data
        .get(obj_off)
        .ok_or_else(|| Error::PlistParse("oob string".into()))?;
    let obj_type = marker >> 4;
    let (count, body_off) = read_size(data, obj_off, marker)?;
    match obj_type {
        0x5 => {
            // ASCII
            let end = body_off + count;
            let bytes = data
                .get(body_off..end)
                .ok_or_else(|| Error::PlistParse("oob ascii".into()))?;
            Ok(String::from_utf8_lossy(bytes).into_owned())
        }
        0x6 => {
            // UTF-16 BE
            let end = body_off + count * 2;
            let bytes = data
                .get(body_off..end)
                .ok_or_else(|| Error::PlistParse("oob utf16".into()))?;
            let mut u16s = Vec::with_capacity(count);
            for c in bytes.chunks_exact(2) {
                u16s.push(u16::from_be_bytes([c[0], c[1]]));
            }
            Ok(String::from_utf16_lossy(&u16s))
        }
        _ => Err(Error::PlistParse("not a string object".into())),
    }
}

fn read_size(data: &[u8], obj_off: usize, marker: u8) -> Result<(usize, usize)> {
    let inline = (marker & 0x0F) as usize;
    if inline != 0x0F {
        return Ok((inline, obj_off + 1));
    }
    let size_marker = *data
        .get(obj_off + 1)
        .ok_or_else(|| Error::PlistParse("oob size".into()))?;
    if size_marker >> 4 != 0x1 {
        return Err(Error::PlistParse("unexpected size object".into()));
    }
    let size_len = 1usize << (size_marker & 0x0F);
    let n = read_be_sized(data, obj_off + 2, size_len)?;
    Ok((n, obj_off + 2 + size_len))
}

fn read_be_int(bytes: &[u8]) -> Result<usize> {
    if bytes.len() != 8 {
        return Err(Error::PlistParse("expected 8-byte int".into()));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    let v = u64::from_be_bytes(buf);
    usize::try_from(v).map_err(|_| Error::PlistParse("int too large".into()))
}

fn read_be_sized(data: &[u8], off: usize, size: usize) -> Result<usize> {
    let slice = data
        .get(off..off + size)
        .ok_or_else(|| Error::PlistParse("oob sized int".into()))?;
    let mut v = 0usize;
    for &b in slice {
        v = (v << 8) | b as usize;
    }
    Ok(v)
}

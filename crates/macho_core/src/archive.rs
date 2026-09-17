//! BSD `ar` static archive reader (`!<arch>\n`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

const MAGIC: &[u8] = b"!<arch>\n";
const HEADER_LEN: usize = 60;

#[derive(Debug, Clone)]
pub struct ArMember {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub date: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

pub struct ArArchive<'a> {
    data: &'a [u8],
    members: Vec<ArMember>,
}

impl<'a> ArArchive<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self> {
        if data.len() < MAGIC.len() || &data[..MAGIC.len()] != MAGIC {
            return Err(Error::InvalidArchive("bad ar magic"));
        }
        let mut members = Vec::new();
        let mut off = MAGIC.len();
        let mut long_names: Option<&[u8]> = None;

        while off + HEADER_LEN <= data.len() {
            let hdr = &data[off..off + HEADER_LEN];
            if hdr[58] != b'`' || hdr[59] != b'\n' {
                // padding / end
                break;
            }
            let name_field = core::str::from_utf8(&hdr[0..16])
                .unwrap_or("")
                .trim();
            let date = parse_dec(&hdr[16..28]).unwrap_or(0);
            let uid = parse_dec(&hdr[28..34]).unwrap_or(0) as u32;
            let gid = parse_dec(&hdr[34..40]).unwrap_or(0) as u32;
            let mode = parse_oct(&hdr[40..48]).unwrap_or(0) as u32;
            let size = parse_dec(&hdr[48..58]).unwrap_or(0) as usize;
            let data_off = off + HEADER_LEN;
            let data_end = data_off
                .checked_add(size)
                .ok_or(Error::InvalidArchive("size overflow"))?;
            if data_end > data.len() {
                return Err(Error::InvalidArchive("truncated member"));
            }

            let mut name = resolve_name(name_field, long_names)?;
            let mut content_off = data_off;
            let mut content_size = size;
            // BSD long names: `#1/len` — name is prepended to file data
            if let Some(rest) = name_field.trim().strip_prefix("#1/") {
                if let Ok(nlen) = rest.trim().parse::<usize>() {
                    if nlen <= size && data_off + nlen <= data.len() {
                        let nb = &data[data_off..data_off + nlen];
                        let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
                        name = String::from_utf8_lossy(&nb[..end])
                            .trim_end_matches('/')
                            .to_string();
                        content_off = data_off + nlen;
                        content_size = size - nlen;
                    }
                }
            }

            if name == "//" || name == "ARFILENAMES/" {
                long_names = Some(&data[data_off..data_end]);
            }

            members.push(ArMember {
                name,
                offset: content_off,
                size: content_size,
                date,
                uid,
                gid,
                mode,
            });

            off = data_end;
            if off % 2 == 1 {
                off += 1;
            }
        }

        Ok(Self { data, members })
    }

    pub fn members(&self) -> &[ArMember] {
        &self.members
    }

    pub fn member_data(&self, m: &ArMember) -> Result<&'a [u8]> {
        self.data
            .get(m.offset..m.offset + m.size)
            .ok_or(Error::InvalidArchive("member oob"))
    }

    pub fn find(&self, name: &str) -> Option<&ArMember> {
        self.members
            .iter()
            .find(|m| m.name == name || m.name.trim_end_matches('/') == name)
    }
}

fn resolve_name(field: &str, long_names: Option<&[u8]>) -> Result<String> {
    let field = field.trim();
    if field.starts_with("#1/") {
        return Ok(field.to_string());
    }
    // SysV long name: /offset into "//" table
    if let Some(rest) = field.strip_prefix('/') {
        if rest.chars().all(|c| c.is_ascii_digit()) {
            if let (Ok(idx), Some(table)) = (rest.parse::<usize>(), long_names) {
                if let Some(slice) = table.get(idx..) {
                    let end = slice
                        .iter()
                        .position(|&b| b == b'\n' || b == b'/')
                        .unwrap_or(slice.len());
                    let s = core::str::from_utf8(&slice[..end]).unwrap_or("");
                    return Ok(s.trim().to_string());
                }
            }
        }
    }
    Ok(field.trim_end_matches('/').to_string())
}

fn parse_dec(b: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(b).ok()?.trim();
    if s.is_empty() {
        return Some(0);
    }
    s.parse().ok()
}

fn parse_oct(b: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(b).ok()?.trim();
    if s.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(s, 8).ok()
}

    /// Parse `lib.a(member.o)` → `(archive_path, member_name)`.
    pub fn split_archive_member(spec: &str) -> Option<(&str, &str)> {
        let open = spec.rfind('(')?;
        if !spec.ends_with(')') {
            return None;
        }
        let arch = &spec[..open];
        let member = &spec[open + 1..spec.len() - 1];
        if arch.is_empty() || member.is_empty() {
            return None;
        }
        Some((arch, member))
    }

#[cfg(test)]
mod tests {
    use super::*;

    fn pad_even(buf: &mut Vec<u8>) {
        if buf.len() % 2 == 1 {
            buf.push(b'\n');
        }
    }

    fn push_hdr(buf: &mut Vec<u8>, name: &str, size: usize) {
        let mut hdr = [b' '; 60];
        let nb = name.as_bytes();
        hdr[..nb.len().min(16)].copy_from_slice(&nb[..nb.len().min(16)]);
        let size_s = alloc::format!("{size}");
        let sb = size_s.as_bytes();
        hdr[48..48 + sb.len()].copy_from_slice(sb);
        hdr[58] = b'`';
        hdr[59] = b'\n';
        buf.extend_from_slice(&hdr);
    }

    #[test]
    fn roundtrip_simple_ar() {
        let mut buf = Vec::from(MAGIC);
        let body = b"hello";
        push_hdr(&mut buf, "foo.o/", body.len());
        buf.extend_from_slice(body);
        pad_even(&mut buf);
        let ar = ArArchive::open(&buf).unwrap();
        assert_eq!(ar.members().len(), 1);
        assert_eq!(ar.members()[0].name, "foo.o");
        assert_eq!(ar.member_data(&ar.members()[0]).unwrap(), b"hello");
    }

    #[test]
    fn split_member_syntax() {
        assert_eq!(
            split_archive_member("libx.a(foo.o)"),
            Some(("libx.a", "foo.o"))
        );
        assert!(split_archive_member("libx.a").is_none());
    }
}

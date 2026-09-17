//! Minimal in-memory ZIP writer (stored / method 0) for `no_std` + alloc.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};

const LFH_SIG: u32 = 0x0403_4b50;
const CDFH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

/// Write a ZIP archive using the store (no compression) method.
pub fn write_stored_zip(entries: &[(String, &[u8])]) -> Result<Vec<u8>> {
    if entries.len() > u16::MAX as usize {
        return Err(Error::InvalidZip("too many entries"));
    }

    let mut out = Vec::new();
    let mut offsets = Vec::with_capacity(entries.len());

    for (name, data) in entries {
        if name.len() > u16::MAX as usize || data.len() > u32::MAX as usize {
            return Err(Error::InvalidZip("entry too large"));
        }
        offsets.push(out.len() as u32);
        write_u32(&mut out, LFH_SIG);
        write_u16(&mut out, 20); // version needed
        write_u16(&mut out, 0); // flags
        write_u16(&mut out, 0); // stored
        write_u16(&mut out, 0); // mtime
        write_u16(&mut out, 0); // mdate
        write_u32(&mut out, crc32(data));
        write_u32(&mut out, data.len() as u32);
        write_u32(&mut out, data.len() as u32);
        write_u16(&mut out, name.len() as u16);
        write_u16(&mut out, 0); // extra
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
    }

    let cd_start = out.len() as u32;
    for (i, (name, data)) in entries.iter().enumerate() {
        write_u32(&mut out, CDFH_SIG);
        write_u16(&mut out, 20); // version made by
        write_u16(&mut out, 20); // version needed
        write_u16(&mut out, 0);
        write_u16(&mut out, 0); // stored
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u32(&mut out, crc32(data));
        write_u32(&mut out, data.len() as u32);
        write_u32(&mut out, data.len() as u32);
        write_u16(&mut out, name.len() as u16);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0); // comment
        write_u16(&mut out, 0); // disk start
        write_u16(&mut out, 0); // int attrs
        write_u32(&mut out, 0); // ext attrs
        write_u32(&mut out, offsets[i]);
        out.extend_from_slice(name.as_bytes());
    }
    let cd_size = (out.len() as u32).saturating_sub(cd_start);

    write_u32(&mut out, EOCD_SIG);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, entries.len() as u16);
    write_u16(&mut out, entries.len() as u16);
    write_u32(&mut out, cd_size);
    write_u32(&mut out, cd_start);
    write_u16(&mut out, 0);

    Ok(out)
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// IEEE CRC-32 (ZIP / PNG polynomial).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1); // 0 or 0xFFFFFFFF
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::ZipArchive;

    #[test]
    fn roundtrip_stored_zip() {
        let entries = [
            (String::from("a.txt"), b"hello".as_slice()),
            (String::from("dir/b.bin"), b"\x00\x01\x02".as_slice()),
        ];
        let bytes = write_stored_zip(&entries).unwrap();
        let zip = ZipArchive::open(&bytes).unwrap();
        assert_eq!(zip.entries().len(), 2);
        assert_eq!(zip.read(&zip.entries()[0]).unwrap(), b"hello");
        assert_eq!(zip.read(&zip.entries()[1]).unwrap(), b"\x00\x01\x02");
    }

    #[test]
    fn crc32_known() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}

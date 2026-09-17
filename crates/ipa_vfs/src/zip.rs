//! Minimal in-memory ZIP reader (store + deflate) for `no_std` + alloc.

use alloc::string::String;
use alloc::vec::Vec;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use miniz_oxide::inflate::decompress_to_vec;

use crate::error::{Error, Result};

const EOCD_SIG: u32 = 0x0605_4b50;
const CDFH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

#[derive(Clone)]
pub struct ZipEntry {
    pub name: String,
    pub compression: u16,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub local_header_offset: u32,
}

pub struct ZipArchive<'a> {
    data: &'a [u8],
    entries: Vec<ZipEntry>,
}

impl<'a> ZipArchive<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self> {
        let eocd = find_eocd(data)?;
        let cd_offset = read_u32(data, eocd + 16)? as usize;
        let cd_entries = read_u16(data, eocd + 10)? as usize;

        let mut entries = Vec::with_capacity(cd_entries);
        let mut off = cd_offset;
        for _ in 0..cd_entries {
            if off + 46 > data.len() {
                return Err(Error::InvalidZip("truncated central directory"));
            }
            if read_u32(data, off)? != CDFH_SIG {
                return Err(Error::InvalidZip("bad central directory signature"));
            }
            let compression = read_u16(data, off + 10)?;
            let compressed_size = read_u32(data, off + 20)?;
            let uncompressed_size = read_u32(data, off + 24)?;
            let name_len = read_u16(data, off + 28)? as usize;
            let extra_len = read_u16(data, off + 30)? as usize;
            let comment_len = read_u16(data, off + 32)? as usize;
            let local_header_offset = read_u32(data, off + 42)?;
            let name_start = off + 46;
            let name_end = name_start + name_len;
            if name_end > data.len() {
                return Err(Error::InvalidZip("truncated filename"));
            }
            let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
            entries.push(ZipEntry {
                name,
                compression,
                compressed_size,
                uncompressed_size,
                local_header_offset,
            });
            off = name_end + extra_len + comment_len;
        }

        Ok(Self { data, entries })
    }

    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    pub fn read(&self, entry: &ZipEntry) -> Result<Vec<u8>> {
        let lfh = entry.local_header_offset as usize;
        if lfh + 30 > self.data.len() {
            return Err(Error::InvalidZip("truncated local file header"));
        }
        if read_u32(self.data, lfh)? != LFH_SIG {
            return Err(Error::InvalidZip("bad local file header signature"));
        }
        let name_len = read_u16(self.data, lfh + 26)? as usize;
        let extra_len = read_u16(self.data, lfh + 28)? as usize;
        let data_start = lfh + 30 + name_len + extra_len;
        let data_end = data_start + entry.compressed_size as usize;
        if data_end > self.data.len() {
            return Err(Error::InvalidZip("truncated compressed data"));
        }
        let compressed = &self.data[data_start..data_end];

        match entry.compression {
            METHOD_STORED => Ok(compressed.to_vec()),
            METHOD_DEFLATE => inflate_raw(compressed, entry.uncompressed_size as usize),
            other => Err(Error::UnsupportedCompression(other)),
        }
    }
}

fn inflate_raw(compressed: &[u8], expected: usize) -> Result<Vec<u8>> {
    // ZIP uses raw DEFLATE (no zlib wrapper). Try raw first, then zlib as fallback.
    match decompress_to_vec(compressed) {
        Ok(v) => Ok(v),
        Err(_) => match decompress_to_vec_zlib(compressed) {
            Ok(v) => Ok(v),
            Err(_) => {
                // Bounded attempt via with_limit for oversized claims
                let _ = expected;
                Err(Error::InflateFailed)
            }
        },
    }
}

fn find_eocd(data: &[u8]) -> Result<usize> {
    // EOCD is at least 22 bytes; comment max 65535 → scan last ~66KB
    if data.len() < 22 {
        return Err(Error::InvalidZip("file too small"));
    }
    let start = data.len().saturating_sub(22 + 65535);
    let mut i = data.len() - 22;
    loop {
        if read_u32(data, i).ok() == Some(EOCD_SIG) {
            return Ok(i);
        }
        if i == start {
            break;
        }
        i -= 1;
    }
    Err(Error::InvalidZip("EOCD not found"))
}

fn read_u16(data: &[u8], off: usize) -> Result<u16> {
    let b = data
        .get(off..off + 2)
        .ok_or(Error::InvalidZip("truncated"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or(Error::InvalidZip("truncated"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

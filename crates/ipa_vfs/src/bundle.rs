use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::plist::parse_info_plist;
use crate::zip::ZipArchive;
use crate::zip_write::write_stored_zip;

/// Owned decompressed IPA contents (paths → bytes).
pub struct IpaVfs {
    files: BTreeMap<String, Vec<u8>>,
    app_prefix: String,
}

/// Zero-copy view over an opened [`IpaVfs`].
pub struct IpaBundle<'a> {
    pub bundle_id: String,
    pub main_executable: &'a [u8],
    pub frameworks: BTreeMap<String, &'a [u8]>,
    pub app_prefix: String,
}

impl IpaVfs {
    /// Parse an IPA (ZIP) from an in-memory byte slice. No filesystem access.
    pub fn open(ipa_bytes: &[u8]) -> Result<Self> {
        let zip = ZipArchive::open(ipa_bytes)?;
        let mut files = BTreeMap::new();
        for entry in zip.entries() {
            if entry.name.ends_with('/') {
                continue;
            }
            let data = zip.read(entry)?;
            files.insert(entry.name.clone(), data);
        }

        let app_prefix = find_app_prefix(&files)?;
        Ok(Self { files, app_prefix })
    }

    pub fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    pub fn app_prefix(&self) -> &str {
        &self.app_prefix
    }

    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(|v| v.as_slice())
    }

    /// Insert or replace a file path inside the IPA.
    pub fn insert(&mut self, path: impl Into<String>, data: Vec<u8>) {
        self.files.insert(path.into(), data);
    }

    /// Remove a file. Returns the previous contents if present.
    pub fn remove(&mut self, path: &str) -> Option<Vec<u8>> {
        self.files.remove(path)
    }

    /// Serialize the current VFS back to an IPA (ZIP, stored compression).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let entries: Vec<(String, &[u8])> = self
            .files
            .iter()
            .map(|(k, v)| (k.clone(), v.as_slice()))
            .collect();
        write_stored_zip(&entries)
    }

    /// Build the logical bundle view (main binary + frameworks).
    pub fn bundle(&self) -> Result<IpaBundle<'_>> {
        let plist_path = alloc::format!("{}Info.plist", self.app_prefix);
        let plist_bytes = self
            .files
            .get(&plist_path)
            .ok_or(Error::MissingInfoPlist)?;
        let info = parse_info_plist(plist_bytes)?;

        let main_path = alloc::format!("{}{}", self.app_prefix, info.bundle_executable);
        let main_executable = self
            .files
            .get(&main_path)
            .map(|v| v.as_slice())
            .ok_or(Error::MissingMainExecutable)?;

        let fw_prefix = alloc::format!("{}Frameworks/", self.app_prefix);
        let mut frameworks = BTreeMap::new();
        for (path, data) in &self.files {
            if let Some(rest) = path.strip_prefix(&fw_prefix) {
                if rest.ends_with(".framework") {
                    continue;
                }
                if rest.contains(".framework/") {
                    let name = rest.to_string();
                    if !name.contains('/') {
                        frameworks.insert(name, data.as_slice());
                    } else if let Some((fw, file)) = rest.split_once('/') {
                        if fw.ends_with(".framework") {
                            let stem = fw.trim_end_matches(".framework");
                            if file == stem {
                                frameworks.insert(fw.to_string(), data.as_slice());
                            }
                        }
                    }
                }
            }
        }

        Ok(IpaBundle {
            bundle_id: info.bundle_id,
            main_executable,
            frameworks,
            app_prefix: self.app_prefix.clone(),
        })
    }

    /// Absolute path of the main executable inside the IPA.
    pub fn main_executable_path(&self) -> Result<String> {
        let plist_path = alloc::format!("{}Info.plist", self.app_prefix);
        let plist_bytes = self
            .files
            .get(&plist_path)
            .ok_or(Error::MissingInfoPlist)?;
        let info = parse_info_plist(plist_bytes)?;
        Ok(alloc::format!("{}{}", self.app_prefix, info.bundle_executable))
    }
}

fn find_app_prefix(files: &BTreeMap<String, Vec<u8>>) -> Result<String> {
    for path in files.keys() {
        if let Some(rest) = path.strip_prefix("Payload/") {
            if let Some((app, _)) = rest.split_once('/') {
                if app.ends_with(".app") {
                    return Ok(alloc::format!("Payload/{app}/"));
                }
            }
        }
    }
    Err(Error::MissingPayloadApp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use miniz_oxide::deflate::compress_to_vec;

    fn write_u16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn write_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        let mut offsets = Vec::new();
        for (name, data) in entries {
            let compressed = compress_to_vec(data, 6);
            let _ = compressed;
            let method = 0u16;
            let payload = *data;
            offsets.push(out.len() as u32);
            write_u32(&mut out, 0x04034b50);
            write_u16(&mut out, 20);
            write_u16(&mut out, 0);
            write_u16(&mut out, method);
            write_u16(&mut out, 0);
            write_u16(&mut out, 0);
            write_u32(&mut out, 0);
            write_u32(&mut out, payload.len() as u32);
            write_u32(&mut out, payload.len() as u32);
            write_u16(&mut out, name.len() as u16);
            write_u16(&mut out, 0);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(payload);
        }
        let cd_start = out.len() as u32;
        for (i, (name, data)) in entries.iter().enumerate() {
            write_u32(&mut cd, 0x02014b50);
            write_u16(&mut cd, 20);
            write_u16(&mut cd, 20);
            write_u16(&mut cd, 0);
            write_u16(&mut cd, 0);
            write_u16(&mut cd, 0);
            write_u16(&mut cd, 0);
            write_u32(&mut cd, 0);
            write_u32(&mut cd, data.len() as u32);
            write_u32(&mut cd, data.len() as u32);
            write_u16(&mut cd, name.len() as u16);
            write_u16(&mut cd, 0);
            write_u16(&mut cd, 0);
            write_u16(&mut cd, 0);
            write_u16(&mut cd, 0);
            write_u32(&mut cd, 0);
            write_u32(&mut cd, offsets[i]);
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_size = cd.len() as u32;
        out.extend_from_slice(&cd);
        write_u32(&mut out, 0x06054b50);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, entries.len() as u16);
        write_u16(&mut out, entries.len() as u16);
        write_u32(&mut out, cd_size);
        write_u32(&mut out, cd_start);
        write_u16(&mut out, 0);
        out
    }

    #[test]
    fn open_fake_ipa() {
        let plist = br#"<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleExecutable</key><string>App</string>
</dict></plist>"#;
        let macho = b"\xcf\xfa\xed\xfe fake macho bytes............";
        let zip = make_zip(&[
            ("Payload/App.app/Info.plist", plist.as_slice()),
            ("Payload/App.app/App", macho.as_slice()),
            ("Payload/App.app/Frameworks/Foo.framework/Foo", b"framework"),
        ]);
        let vfs = IpaVfs::open(&zip).expect("open");
        let bundle = vfs.bundle().expect("bundle");
        assert_eq!(bundle.bundle_id, "com.example.app");
        assert_eq!(bundle.main_executable, macho.as_slice());
        assert!(bundle.frameworks.contains_key("Foo.framework"));
    }

    #[test]
    fn mutate_and_repack() {
        let plist = br#"<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleExecutable</key><string>App</string>
</dict></plist>"#;
        let zip = make_zip(&[
            ("Payload/App.app/Info.plist", plist.as_slice()),
            ("Payload/App.app/App", b"macho"),
        ]);
        let mut vfs = IpaVfs::open(&zip).unwrap();
        vfs.insert("Payload/App.app/extra.txt", b"hi".to_vec());
        assert!(vfs.remove("Payload/App.app/App").is_some());
        vfs.insert("Payload/App.app/App", b"new".to_vec());
        let out = vfs.to_bytes().unwrap();
        let vfs2 = IpaVfs::open(&out).unwrap();
        assert_eq!(vfs2.get("Payload/App.app/extra.txt"), Some(b"hi".as_slice()));
        assert_eq!(vfs2.get("Payload/App.app/App"), Some(b"new".as_slice()));
    }
}

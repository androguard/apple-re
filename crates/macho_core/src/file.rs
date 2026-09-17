use alloc::vec::Vec;
use core::mem::size_of;

use zerocopy::{FromBytes, Immutable, KnownLayout};

use crate::codesign::{self, CodeSignature};
use crate::error::{Error, Result};
use crate::names::{arch_matches, arch_name};
use crate::types::n_type;
use crate::types::{
    cstr16, format_packed_version, format_source_version, platform_name, BuildToolVersion,
    BuildVersionCommand, DylibCommand, DylibKind, DyldInfoCommand, DysymtabCommand,
    EncryptionInfoCommand, EncryptionInfoCommand64, EntryPointCommand, FatArch, FatArch64,
    FatHeader, LinkeditDataCommand, LoadCommand, MachFlags, MachHeader64, Nlist64, RpathCommand,
    Section64, SegmentCommand64, SourceVersionCommand, SymtabCommand, UuidCommand,
    VersionMinCommand, CPU_TYPE_ARM64, FAT_CIGAM, FAT_CIGAM_64, FAT_MAGIC, FAT_MAGIC_64,
    LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_DYLIB_CODE_SIGN_DRS, LC_DYSYMTAB,
    LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64, LC_FUNCTION_STARTS, LC_LINKER_OPTIMIZATION_HINT,
    LC_MAIN, LC_RPATH, LC_SEGMENT_64, LC_SEGMENT_SPLIT_INFO, LC_SOURCE_VERSION, LC_SYMTAB, LC_UUID,
    LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS,
    MH_CIGAM_64, MH_MAGIC_64,
};

/// Parsed ARM64 Mach-O view over borrowed bytes.
pub struct MachoFile<'a> {
    /// Bytes of the thin ARM64 Mach-O (may be a slice of a fat binary).
    pub data: &'a [u8],
    pub header: MachHeader64,
    /// Byte offset of this thin image within the original buffer (0 for thin).
    pub slice_offset: usize,
}

/// FairPlay / FairPlay-style encryption info from `LC_ENCRYPTION_INFO(_64)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionInfo {
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

impl EncryptionInfo {
    pub fn is_encrypted(&self) -> bool {
        self.cryptid != 0
    }
}

/// `LC_MAIN` entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPoint {
    pub entryoff: u64,
    pub stacksize: u64,
}

/// Platform / SDK version from `LC_BUILD_VERSION` or `LC_VERSION_MIN_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    pub platform: Option<u32>,
    pub platform_name: Option<&'static str>,
    pub min_os: (u16, u8, u8),
    pub sdk: (u16, u8, u8),
    pub tools: Vec<(u32, (u16, u8, u8))>,
}

/// Linked dylib reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DylibRef<'a> {
    pub kind: DylibKind,
    pub name: &'a str,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

/// High-level hardening / checksec-style summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checksec {
    pub pie: bool,
    pub nx_heap: bool,
    pub nx_stack: bool,
    pub two_level_namespace: bool,
    pub weak_defines: bool,
    pub has_tlv: bool,
    pub code_signed: bool,
    pub encrypted_fairplay: bool,
    pub stack_canary: bool,
    pub arc: bool,
    pub objc: bool,
    pub swift: bool,
}

/// One architecture slice inside a fat / universal binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatArchEntry {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

impl FatArchEntry {
    pub fn arch_name(&self) -> alloc::string::String {
        arch_name(self.cputype, self.cpusubtype)
    }
}

impl<'a> MachoFile<'a> {
    /// Open a thin or fat Mach-O and select the ARM64 slice.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Self::parse_arch(data, Some("arm64")).or_else(|_| Self::parse_arch(data, None))
    }

    /// Open Mach-O selecting a fat slice by arch name (`arm64`, `x86_64`, …).
    ///
    /// `None` prefers `arm64`, then `arm64e`, then the first 64-bit slice.
    pub fn parse_arch(data: &'a [u8], arch: Option<&str>) -> Result<Self> {
        let magic = read_u32_le(data, 0)?;
        match magic {
            MH_MAGIC_64 | MH_CIGAM_64 => {
                let file = Self::parse_thin_any(data, 0)?;
                if let Some(want) = arch {
                    if !arch_matches(want, file.header.cputype, file.header.cpusubtype) {
                        return Err(Error::UnsupportedCpuType(file.header.cputype));
                    }
                }
                Ok(file)
            }
            FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => {
                Self::parse_fat_select(data, arch)
            }
            other if other == FAT_MAGIC.swap_bytes() || other == FAT_MAGIC_64.swap_bytes() => {
                Self::parse_fat_select(data, arch)
            }
            other => Err(Error::BadMagic(other)),
        }
    }

    fn parse_fat_select(data: &'a [u8], arch: Option<&str>) -> Result<Self> {
        let arches = fat_arches(data)?;
        if arches.is_empty() {
            return Err(Error::NoArm64Slice);
        }
        let chosen = if let Some(want) = arch {
            arches
                .iter()
                .find(|a| arch_matches(want, a.cputype, a.cpusubtype))
                .ok_or(Error::NoArm64Slice)?
        } else {
            arches
                .iter()
                .find(|a| arch_matches("arm64", a.cputype, a.cpusubtype))
                .or_else(|| {
                    arches
                        .iter()
                        .find(|a| arch_matches("arm64e", a.cputype, a.cpusubtype))
                })
                .or_else(|| arches.iter().find(|a| a.cputype == CPU_TYPE_ARM64))
                .or_else(|| arches.first())
                .ok_or(Error::NoArm64Slice)?
        };
        Self::thin_from_range(data, chosen.offset as usize, chosen.size as usize)
    }

    fn thin_from_range(data: &'a [u8], offset: usize, size: usize) -> Result<Self> {
        let end = offset
            .checked_add(size)
            .ok_or(Error::Truncated("fat slice"))?;
        if end > data.len() {
            return Err(Error::Truncated("fat slice oob"));
        }
        Self::parse_thin_any(&data[offset..end], offset)
    }

    fn parse_thin_any(data: &'a [u8], slice_offset: usize) -> Result<Self> {
        let header = *MachHeader64::ref_from_prefix(data)
            .map_err(|_| Error::Truncated("mach_header_64"))?
            .0;
        if header.magic != MH_MAGIC_64 && header.magic != MH_CIGAM_64 {
            return Err(Error::BadMagic(header.magic));
        }
        Ok(Self {
            data,
            header,
            slice_offset,
        })
    }
}

/// Return whether `data` starts with a fat / universal magic.
pub fn is_fat(data: &[u8]) -> bool {
    read_u32_le(data, 0)
        .map(|m| {
            matches!(
                m,
                FAT_MAGIC
                    | FAT_CIGAM
                    | FAT_MAGIC_64
                    | FAT_CIGAM_64
            ) || m == FAT_MAGIC.swap_bytes()
                || m == FAT_MAGIC_64.swap_bytes()
        })
        .unwrap_or(false)
}

/// List all architecture slices in a fat binary (empty if thin).
pub fn fat_arches(data: &[u8]) -> Result<Vec<FatArchEntry>> {
    let magic = read_u32_le(data, 0)?;
    let (is64, be_magic_ok) = match magic {
        FAT_MAGIC | FAT_CIGAM => (false, true),
        FAT_MAGIC_64 | FAT_CIGAM_64 => (true, true),
        other if other == FAT_MAGIC.swap_bytes() => (false, true),
        other if other == FAT_MAGIC_64.swap_bytes() => (true, true),
        _ => return Ok(Vec::new()),
    };
    let _ = be_magic_ok;
    let nfat = fat_narch(data)?;
    let mut out = Vec::with_capacity(nfat);
    if is64 {
        let arch_size = size_of::<FatArch64>();
        for i in 0..nfat {
            let off = size_of::<FatHeader>() + i * arch_size;
            let chunk = data
                .get(off..off + arch_size)
                .ok_or(Error::Truncated("fat_arch_64"))?;
            let arch =
                FatArch64::ref_from_bytes(chunk).map_err(|_| Error::Truncated("fat_arch_64"))?;
            out.push(FatArchEntry {
                cputype: u32::from_be(arch.cputype),
                cpusubtype: u32::from_be(arch.cpusubtype),
                offset: u64::from_be(arch.offset),
                size: u64::from_be(arch.size),
                align: u32::from_be(arch.align),
            });
        }
    } else {
        let arch_size = size_of::<FatArch>();
        for i in 0..nfat {
            let off = size_of::<FatHeader>() + i * arch_size;
            let chunk = data
                .get(off..off + arch_size)
                .ok_or(Error::Truncated("fat_arch"))?;
            let arch = FatArch::ref_from_bytes(chunk).map_err(|_| Error::Truncated("fat_arch"))?;
            out.push(FatArchEntry {
                cputype: u32::from_be(arch.cputype),
                cpusubtype: u32::from_be(arch.cpusubtype),
                offset: u64::from(u32::from_be(arch.offset)),
                size: u64::from(u32::from_be(arch.size)),
                align: u32::from_be(arch.align),
            });
        }
    }
    Ok(out)
}

// Keep old private helpers removed — parse_fat32/64 replaced by fat_arches + parse_fat_select.

impl<'a> MachoFile<'a> {
    pub fn flags(&self) -> MachFlags {
        MachFlags::from_bits_truncate(self.header.flags)
    }

    pub fn load_commands(&self) -> Result<LoadCommandIter<'a>> {
        let start = size_of::<MachHeader64>();
        let end = start
            .checked_add(self.header.sizeofcmds as usize)
            .ok_or(Error::Truncated("sizeofcmds"))?;
        if end > self.data.len() {
            return Err(Error::Truncated("load commands"));
        }
        Ok(LoadCommandIter {
            data: &self.data[start..end],
            remaining: self.header.ncmds,
            offset: 0,
        })
    }

    pub fn segments(&self) -> Result<SegmentIter<'a>> {
        Ok(SegmentIter {
            inner: self.load_commands()?,
        })
    }

    pub fn sections(&self) -> Result<SectionIter<'a>> {
        Ok(SectionIter {
            segments: self.segments()?,
            current_sects: &[],
            sect_index: 0,
            segment: None,
        })
    }

    pub fn find_section(&self, seg: &str, sect: &str) -> Result<Option<&'a Section64>> {
        for item in self.sections()? {
            let (s64, _) = item?;
            if cstr16(&s64.segname) == seg && cstr16(&s64.sectname) == sect {
                return Ok(Some(s64));
            }
        }
        Ok(None)
    }

    pub fn section_data(&self, section: &Section64) -> Result<&'a [u8]> {
        let start = section.offset as usize;
        let end = start
            .checked_add(section.size as usize)
            .ok_or(Error::Truncated("section size"))?;
        self.data
            .get(start..end)
            .ok_or(Error::Truncated("section data"))
    }

    pub fn symtab(&self) -> Result<Option<&'a SymtabCommand>> {
        self.find_cmd(LC_SYMTAB)
    }

    pub fn dysymtab(&self) -> Result<Option<&'a DysymtabCommand>> {
        self.find_cmd(LC_DYSYMTAB)
    }

    pub fn dyld_info(&self) -> Result<Option<&'a DyldInfoCommand>> {
        for cmd in self.load_commands()? {
            let (lc, body) = cmd?;
            if lc.cmd == LC_DYLD_INFO || lc.cmd == LC_DYLD_INFO_ONLY {
                return Ok(Some(
                    DyldInfoCommand::ref_from_prefix(body)
                        .map_err(|_| Error::Truncated("dyld_info"))?
                        .0,
                ));
            }
        }
        Ok(None)
    }

    pub fn uuid(&self) -> Result<Option<[u8; 16]>> {
        Ok(self.find_cmd::<UuidCommand>(LC_UUID)?.map(|u| u.uuid))
    }

    pub fn encryption_info(&self) -> Result<Option<EncryptionInfo>> {
        for cmd in self.load_commands()? {
            let (lc, body) = cmd?;
            if lc.cmd == LC_ENCRYPTION_INFO_64 {
                let e = EncryptionInfoCommand64::ref_from_prefix(body)
                    .map_err(|_| Error::Truncated("encryption_info_64"))?
                    .0;
                return Ok(Some(EncryptionInfo {
                    cryptoff: e.cryptoff,
                    cryptsize: e.cryptsize,
                    cryptid: e.cryptid,
                }));
            }
            if lc.cmd == LC_ENCRYPTION_INFO {
                let e = EncryptionInfoCommand::ref_from_prefix(body)
                    .map_err(|_| Error::Truncated("encryption_info"))?
                    .0;
                return Ok(Some(EncryptionInfo {
                    cryptoff: e.cryptoff,
                    cryptsize: e.cryptsize,
                    cryptid: e.cryptid,
                }));
            }
        }
        Ok(None)
    }

    pub fn entry_point(&self) -> Result<Option<EntryPoint>> {
        Ok(self.find_cmd::<EntryPointCommand>(LC_MAIN)?.map(|e| EntryPoint {
            entryoff: e.entryoff,
            stacksize: e.stacksize,
        }))
    }

    pub fn source_version(&self) -> Result<Option<(u32, u16, u16, u16, u16)>> {
        Ok(self
            .find_cmd::<SourceVersionCommand>(LC_SOURCE_VERSION)?
            .map(|s| format_source_version(s.version)))
    }

    pub fn build_version(&self) -> Result<Option<BuildInfo>> {
        for cmd in self.load_commands()? {
            let (lc, body) = cmd?;
            if lc.cmd == LC_BUILD_VERSION {
                let hdr = BuildVersionCommand::ref_from_prefix(body)
                    .map_err(|_| Error::Truncated("build_version"))?
                    .0;
                let tools_off = size_of::<BuildVersionCommand>();
                let ntools = hdr.ntools as usize;
                let need = tools_off + ntools * size_of::<BuildToolVersion>();
                let mut tools = Vec::new();
                if body.len() >= need {
                    let tool_bytes = &body[tools_off..need];
                    if let Ok(arr) = <[BuildToolVersion]>::ref_from_bytes(tool_bytes) {
                        for t in arr {
                            tools.push((t.tool, format_packed_version(t.version)));
                        }
                    }
                }
                return Ok(Some(BuildInfo {
                    platform: Some(hdr.platform),
                    platform_name: platform_name(hdr.platform),
                    min_os: format_packed_version(hdr.minos),
                    sdk: format_packed_version(hdr.sdk),
                    tools,
                }));
            }
            if matches!(
                lc.cmd,
                LC_VERSION_MIN_IPHONEOS
                    | LC_VERSION_MIN_MACOSX
                    | LC_VERSION_MIN_TVOS
                    | LC_VERSION_MIN_WATCHOS
            ) {
                let v = VersionMinCommand::ref_from_prefix(body)
                    .map_err(|_| Error::Truncated("version_min"))?
                    .0;
                let (platform, name) = match lc.cmd {
                    LC_VERSION_MIN_IPHONEOS => (Some(crate::types::platform::IOS), Some("iOS")),
                    LC_VERSION_MIN_MACOSX => (Some(crate::types::platform::MACOS), Some("macOS")),
                    LC_VERSION_MIN_TVOS => (Some(crate::types::platform::TVOS), Some("tvOS")),
                    LC_VERSION_MIN_WATCHOS => {
                        (Some(crate::types::platform::WATCHOS), Some("watchOS"))
                    }
                    _ => (None, None),
                };
                return Ok(Some(BuildInfo {
                    platform,
                    platform_name: name,
                    min_os: format_packed_version(v.version),
                    sdk: format_packed_version(v.sdk),
                    tools: Vec::new(),
                }));
            }
        }
        Ok(None)
    }

    pub fn dylibs(&self) -> Result<Vec<DylibRef<'a>>> {
        let mut out = Vec::new();
        for cmd in self.load_commands()? {
            let (lc, body) = cmd?;
            let Some(kind) = DylibKind::from_cmd(lc.cmd) else {
                continue;
            };
            let d = DylibCommand::ref_from_prefix(body)
                .map_err(|_| Error::Truncated("dylib_command"))?
                .0;
            let name = path_in_command(body, d.name_offset as usize)?;
            out.push(DylibRef {
                kind,
                name,
                timestamp: d.timestamp,
                current_version: d.current_version,
                compatibility_version: d.compatibility_version,
            });
        }
        Ok(out)
    }

    pub fn id_dylib(&self) -> Result<Option<DylibRef<'a>>> {
        Ok(self
            .dylibs()?
            .into_iter()
            .find(|d| d.kind == DylibKind::Id))
    }

    pub fn rpaths(&self) -> Result<Vec<&'a str>> {
        let mut out = Vec::new();
        for cmd in self.load_commands()? {
            let (lc, body) = cmd?;
            if lc.cmd != LC_RPATH {
                continue;
            }
            let r = RpathCommand::ref_from_prefix(body)
                .map_err(|_| Error::Truncated("rpath_command"))?
                .0;
            out.push(path_in_command(body, r.path_offset as usize)?);
        }
        Ok(out)
    }

    /// Raw `linkedit_data_command` for a given cmd id.
    pub fn linkedit_data(&self, cmd: u32) -> Result<Option<&'a LinkeditDataCommand>> {
        self.find_cmd(cmd)
    }

    pub fn code_signature_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_CODE_SIGNATURE)
    }

    pub fn function_starts_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_FUNCTION_STARTS)
    }

    pub fn data_in_code_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_DATA_IN_CODE)
    }

    pub fn dyld_exports_trie_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_DYLD_EXPORTS_TRIE)
    }

    pub fn dyld_chained_fixups_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_DYLD_CHAINED_FIXUPS)
    }

    pub fn segment_split_info_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_SEGMENT_SPLIT_INFO)
    }

    pub fn code_sign_drs_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_DYLIB_CODE_SIGN_DRS)
    }

    pub fn linker_optimization_hint_ref(&self) -> Result<Option<&'a LinkeditDataCommand>> {
        self.linkedit_data(LC_LINKER_OPTIMIZATION_HINT)
    }

    /// Bytes pointed to by a `linkedit_data_command`.
    pub fn linkedit_payload(&self, lc: &LinkeditDataCommand) -> Result<&'a [u8]> {
        let start = lc.dataoff as usize;
        let end = start
            .checked_add(lc.datasize as usize)
            .ok_or(Error::Truncated("linkedit size"))?;
        self.data
            .get(start..end)
            .ok_or(Error::Truncated("linkedit payload"))
    }

    /// Parse the embedded code-signing SuperBlob, if present.
    pub fn code_signature(&self) -> Result<Option<CodeSignature<'a>>> {
        let Some(r) = self.code_signature_ref()? else {
            return Ok(None);
        };
        let blob = self.linkedit_payload(r)?;
        Ok(Some(codesign::parse_code_signature(blob)?))
    }

    /// Decode `LC_FUNCTION_STARTS` ULEB128 deltas into file-relative function offsets.
    ///
    /// Offsets are relative to the start of the `__TEXT` segment (Mach-O convention).
    pub fn function_starts(&self) -> Result<Vec<u64>> {
        let Some(r) = self.function_starts_ref()? else {
            return Ok(Vec::new());
        };
        let data = self.linkedit_payload(r)?;
        let text_base = self
            .segments()?
            .find_map(|s| match s {
                Ok((seg, _)) if cstr16(&seg.segname) == "__TEXT" => Some(seg.fileoff),
                _ => None,
            })
            .unwrap_or(0);

        let mut out = Vec::new();
        let mut addr = text_base;
        let mut i = 0usize;
        while i < data.len() {
            let (delta, n) = read_uleb128(&data[i..])?;
            i += n;
            if delta == 0 && out.is_empty() && i >= data.len() {
                break;
            }
            if delta == 0 {
                break;
            }
            addr = addr.saturating_add(delta);
            out.push(addr);
        }
        Ok(out)
    }

    /// Undefined (imported) external symbol names from the symbol table.
    pub fn imported_symbols(&self) -> Result<Vec<&'a str>> {
        let Some(st) = self.symtab()? else {
            return Ok(Vec::new());
        };
        let nsyms = st.nsyms as usize;
        let sym_off = st.symoff as usize;
        let str_off = st.stroff as usize;
        let str_size = st.strsize as usize;
        let entry = size_of::<Nlist64>();
        let syms = self
            .data
            .get(sym_off..sym_off + nsyms * entry)
            .ok_or(Error::Truncated("symtab"))?;
        let strings = self
            .data
            .get(str_off..str_off + str_size)
            .ok_or(Error::Truncated("strtab"))?;

        let mut out = Vec::new();
        for i in 0..nsyms {
            let chunk = &syms[i * entry..(i + 1) * entry];
            let nl = Nlist64::read_from_bytes(chunk).map_err(|_| Error::Truncated("nlist"))?;
            if nl.n_type & n_type::N_STAB != 0 {
                continue;
            }
            let is_undef = (nl.n_type & n_type::N_TYPE) == n_type::N_UNDF;
            let is_ext = (nl.n_type & n_type::N_EXT) != 0;
            if !(is_undef && is_ext) {
                continue;
            }
            if let Some(name) = cstr_at(strings, nl.n_strx as usize) {
                out.push(name);
            }
        }
        Ok(out)
    }

    /// Checksec-style summary from header flags, encryption, code signature, and imports.
    pub fn checksec(&self) -> Result<Checksec> {
        let flags = self.flags();
        let imported = self.imported_symbols()?;
        let has = |n: &str| imported.iter().any(|&s| s == n);
        let has_prefix = |p: &str| imported.iter().any(|s| s.starts_with(p));

        let stack_canary = has("___stack_chk_guard") || has("___stack_chk_fail");
        let objc_release = has("_objc_release")
            || has("_objc_release_x0")
            || has("_objc_release_x1")
            || has("_objc_release_x2")
            || has("_objc_release_x3");
        let swift_release = has("_swift_release");
        let swift = has_prefix("_swift_") || has_prefix("__swift_");
        let objc = has_prefix("_objc_") || has_prefix("_OBJC_");
        let encrypted = self
            .encryption_info()?
            .map(|e| e.is_encrypted())
            .unwrap_or(false);

        Ok(Checksec {
            pie: flags.contains(MachFlags::PIE),
            nx_heap: flags.contains(MachFlags::NO_HEAP_EXECUTION),
            nx_stack: !flags.contains(MachFlags::ALLOW_STACK_EXECUTION),
            two_level_namespace: flags.contains(MachFlags::TWOLEVEL),
            weak_defines: flags.contains(MachFlags::WEAK_DEFINES),
            has_tlv: flags.contains(MachFlags::HAS_TLV_DESCRIPTORS),
            code_signed: self.code_signature_ref()?.is_some(),
            encrypted_fairplay: encrypted,
            stack_canary,
            arc: objc_release || swift_release,
            objc,
            swift,
        })
    }

    /// Map a virtual address to a file offset within this thin image.
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Result<usize> {
        for seg in self.segments()? {
            let (seg, _) = seg?;
            if seg.filesize == 0 {
                continue;
            }
            if vaddr >= seg.vmaddr && vaddr < seg.vmaddr.saturating_add(seg.filesize) {
                let delta = vaddr - seg.vmaddr;
                return Ok((seg.fileoff + delta) as usize);
            }
        }
        Err(Error::VaddrNotMapped(vaddr))
    }

    /// Read bytes at a virtual address.
    pub fn read_vaddr(&self, vaddr: u64, len: usize) -> Result<&'a [u8]> {
        let off = self.vaddr_to_offset(vaddr)?;
        self.data
            .get(off..off + len)
            .ok_or(Error::Truncated("vaddr read"))
    }

    pub fn read_u64_vaddr(&self, vaddr: u64) -> Result<u64> {
        let bytes = self.read_vaddr(vaddr, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_cstr_vaddr(&self, vaddr: u64) -> Result<&'a str> {
        let off = self.vaddr_to_offset(vaddr)?;
        let rest = self.data.get(off..).ok_or(Error::Truncated("cstr"))?;
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        core::str::from_utf8(&rest[..end]).map_err(|_| Error::Truncated("cstr utf8"))
    }

    fn find_cmd<T: FromBytes + KnownLayout + Immutable>(&self, cmd: u32) -> Result<Option<&'a T>> {
        for c in self.load_commands()? {
            let (lc, body) = c?;
            if lc.cmd == cmd {
                return Ok(Some(
                    T::ref_from_prefix(body)
                        .map_err(|_| Error::Truncated("load command body"))?
                        .0,
                ));
            }
        }
        Ok(None)
    }
}

pub struct LoadCommandIter<'a> {
    data: &'a [u8],
    remaining: u32,
    offset: usize,
}

impl<'a> Iterator for LoadCommandIter<'a> {
    type Item = Result<(&'a LoadCommand, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        if self.offset + size_of::<LoadCommand>() > self.data.len() {
            return Some(Err(Error::Truncated("load_command")));
        }
        let lc = match LoadCommand::ref_from_prefix(&self.data[self.offset..]) {
            Ok((lc, _)) => lc,
            Err(_) => return Some(Err(Error::Truncated("load_command"))),
        };
        let size = lc.cmdsize as usize;
        if size < size_of::<LoadCommand>() || self.offset + size > self.data.len() {
            return Some(Err(Error::InvalidLoadCommand));
        }
        let body = &self.data[self.offset..self.offset + size];
        self.offset += size;
        Some(Ok((lc, body)))
    }
}

pub struct SegmentIter<'a> {
    inner: LoadCommandIter<'a>,
}

impl<'a> Iterator for SegmentIter<'a> {
    /// Segment header plus full load-command body (for trailing sections).
    type Item = Result<(&'a SegmentCommand64, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.inner.next()? {
                Err(e) => return Some(Err(e)),
                Ok((lc, body)) => {
                    if lc.cmd == LC_SEGMENT_64 {
                        return Some(
                            SegmentCommand64::ref_from_prefix(body)
                                .map(|(s, _)| (s, body))
                                .map_err(|_| Error::Truncated("segment_command_64")),
                        );
                    }
                }
            }
        }
    }
}

pub struct SectionIter<'a> {
    segments: SegmentIter<'a>,
    current_sects: &'a [Section64],
    sect_index: usize,
    segment: Option<&'a SegmentCommand64>,
}

impl<'a> Iterator for SectionIter<'a> {
    type Item = Result<(&'a Section64, &'a SegmentCommand64)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.sect_index < self.current_sects.len() {
                let s = &self.current_sects[self.sect_index];
                self.sect_index += 1;
                return Some(Ok((s, self.segment.unwrap())));
            }
            let (seg, body) = match self.segments.next()? {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            self.segment = Some(seg);
            let nsects = seg.nsects as usize;
            let sects_off = size_of::<SegmentCommand64>();
            let need = sects_off + nsects * size_of::<Section64>();
            if body.len() < need {
                return Some(Err(Error::Truncated("sections")));
            }
            let sect_bytes = &body[sects_off..need];
            match <[Section64]>::ref_from_bytes(sect_bytes) {
                Ok(s) => {
                    self.current_sects = s;
                    self.sect_index = 0;
                }
                Err(_) => return Some(Err(Error::Truncated("section_64 align"))),
            }
        }
    }
}

fn fat_narch(data: &[u8]) -> Result<usize> {
    let _ = FatHeader::ref_from_prefix(data).map_err(|_| Error::Truncated("fat_header"))?;
    let nfat = u32::from_be_bytes(data[4..8].try_into().unwrap()) as usize;
    if nfat == 0 || nfat > 64 {
        return Err(Error::Truncated("nfat_arch"));
    }
    Ok(nfat)
}

fn path_in_command(body: &[u8], offset: usize) -> Result<&str> {
    if offset >= body.len() {
        return Err(Error::Truncated("path offset"));
    }
    let rest = &body[offset..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end]).map_err(|_| Error::Truncated("path utf8"))
}

fn cstr_at(strings: &[u8], off: usize) -> Option<&str> {
    let rest = strings.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end]).ok().filter(|s| !s.is_empty())
}

fn read_uleb128(data: &[u8]) -> Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        if shift >= 64 {
            return Err(Error::Truncated("uleb128 overflow"));
        }
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(Error::Truncated("uleb128"))
}

fn read_u32_le(data: &[u8], off: usize) -> Result<u32> {
    let b = data
        .get(off..off + 4)
        .ok_or(Error::Truncated("magic"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        cs_magic, cs_slot, platform, CPU_TYPE_X86_64, LC_LOAD_DYLIB, MachFlags, MH_MAGIC_64,
    };
    use alloc::vec::Vec;

    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u32_be(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_be_bytes());
    }
    fn push_u64_be(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    fn push_padded_cmd(cmds: &mut Vec<u8>, cmd: u32, header: &[u8], path: &[u8]) {
        let raw = 8 + header.len() + path.len();
        let size = (raw + 7) & !7;
        push_u32(cmds, cmd);
        push_u32(cmds, size as u32);
        cmds.extend_from_slice(header);
        cmds.extend_from_slice(path);
        while cmds.len() % 8 != 0 {
            cmds.push(0);
        }
        debug_assert_eq!(size % 8, 0);
    }

    /// Minimal ARM64 execute with the load commands under test.
    fn build_fixture() -> Vec<u8> {
        let mut cmds = Vec::new();

        push_u32(&mut cmds, LC_SEGMENT_64);
        push_u32(&mut cmds, 72);
        cmds.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        push_u64(&mut cmds, 0x1000);
        push_u64(&mut cmds, 0x4000);
        push_u64(&mut cmds, 0);
        push_u64(&mut cmds, 0x4000);
        push_u32(&mut cmds, 7);
        push_u32(&mut cmds, 5);
        push_u32(&mut cmds, 0);
        push_u32(&mut cmds, 0);

        push_u32(&mut cmds, LC_UUID);
        push_u32(&mut cmds, 24);
        cmds.extend_from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ]);

        push_u32(&mut cmds, LC_ENCRYPTION_INFO_64);
        push_u32(&mut cmds, 24);
        push_u32(&mut cmds, 0x4000);
        push_u32(&mut cmds, 0x1000);
        push_u32(&mut cmds, 1);
        push_u32(&mut cmds, 0);

        push_u32(&mut cmds, LC_MAIN);
        push_u32(&mut cmds, 24);
        push_u64(&mut cmds, 0x1234);
        push_u64(&mut cmds, 0);

        push_u32(&mut cmds, LC_BUILD_VERSION);
        push_u32(&mut cmds, 32);
        push_u32(&mut cmds, platform::IOS);
        push_u32(&mut cmds, 0x0011_0000);
        push_u32(&mut cmds, 0x0011_0200);
        push_u32(&mut cmds, 1);
        push_u32(&mut cmds, 3);
        push_u32(&mut cmds, 0x0064_0000);

        let mut dylib_hdr = Vec::new();
        push_u32(&mut dylib_hdr, 24);
        push_u32(&mut dylib_hdr, 2);
        push_u32(&mut dylib_hdr, 0x0001_0000);
        push_u32(&mut dylib_hdr, 0x0001_0000);
        push_padded_cmd(
            &mut cmds,
            LC_LOAD_DYLIB,
            &dylib_hdr,
            b"/usr/lib/libSystem.B.dylib\0",
        );

        let mut rpath_hdr = Vec::new();
        push_u32(&mut rpath_hdr, 12);
        push_padded_cmd(
            &mut cmds,
            LC_RPATH,
            &rpath_hdr,
            b"@executable_path/Frameworks\0",
        );

        push_u32(&mut cmds, LC_SOURCE_VERSION);
        push_u32(&mut cmds, 16);
        push_u64(&mut cmds, (1u64 << 40) | (2 << 30) | (3 << 20) | (4 << 10) | 5);

        let fs_cmd_pos = cmds.len();
        push_u32(&mut cmds, LC_FUNCTION_STARTS);
        push_u32(&mut cmds, 16);
        push_u32(&mut cmds, 0);
        push_u32(&mut cmds, 0);

        let cs_cmd_pos = cmds.len();
        push_u32(&mut cmds, LC_CODE_SIGNATURE);
        push_u32(&mut cmds, 16);
        push_u32(&mut cmds, 0);
        push_u32(&mut cmds, 0);

        let sym_cmd_pos = cmds.len();
        push_u32(&mut cmds, LC_SYMTAB);
        push_u32(&mut cmds, 24);
        push_u32(&mut cmds, 0);
        push_u32(&mut cmds, 1);
        push_u32(&mut cmds, 0);
        push_u32(&mut cmds, 0);

        push_u32(&mut cmds, LC_DYSYMTAB);
        push_u32(&mut cmds, 80);
        for _ in 0..18 {
            push_u32(&mut cmds, 0);
        }

        push_u32(&mut cmds, LC_DYLD_INFO_ONLY);
        push_u32(&mut cmds, 48);
        for _ in 0..10 {
            push_u32(&mut cmds, 0);
        }

        let ncmds = 13u32;
        let sizeofcmds = cmds.len() as u32;
        let mut file = Vec::new();
        push_u32(&mut file, MH_MAGIC_64);
        push_u32(&mut file, CPU_TYPE_ARM64);
        push_u32(&mut file, 0);
        push_u32(&mut file, 2);
        push_u32(&mut file, ncmds);
        push_u32(&mut file, sizeofcmds);
        push_u32(
            &mut file,
            (MachFlags::PIE
                | MachFlags::DYLDLINK
                | MachFlags::TWOLEVEL
                | MachFlags::NO_HEAP_EXECUTION)
                .bits(),
        );
        push_u32(&mut file, 0);
        file.extend_from_slice(&cmds);

        let fs_off = file.len() as u32;
        file.extend_from_slice(&[0x10, 0x20, 0x00]);
        let fs_size = 3u32;

        let cs_off = file.len() as u32;
        let ent_xml = b"<?xml version=\"1.0\"?><plist></plist>";
        let mut cd = Vec::new();
        push_u32_be(&mut cd, cs_magic::CODEDIRECTORY);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 0x20400);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 88);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 0x1000);
        cd.extend_from_slice(&[32, 2, 0, 12]);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 0);
        push_u32_be(&mut cd, 0);
        push_u64_be(&mut cd, 0);
        push_u64_be(&mut cd, 0);
        push_u64_be(&mut cd, 0);
        push_u64_be(&mut cd, 0);
        assert_eq!(cd.len(), 88);
        cd.extend_from_slice(b"com.example.app\0");
        while cd.len() % 4 != 0 {
            cd.push(0);
        }
        let cd_len = cd.len() as u32;
        cd[4..8].copy_from_slice(&cd_len.to_be_bytes());

        let mut ent = Vec::new();
        push_u32_be(&mut ent, cs_magic::EMBEDDED_ENTITLEMENTS);
        let ent_len = (8 + ent_xml.len()) as u32;
        push_u32_be(&mut ent, ent_len);
        ent.extend_from_slice(ent_xml);

        let slot_table = 12 + 2 * 8;
        let cd_blob_off = slot_table as u32;
        let ent_blob_off = cd_blob_off + cd_len;
        let total = ent_blob_off + ent_len;

        let mut cs = Vec::new();
        push_u32_be(&mut cs, cs_magic::EMBEDDED_SIGNATURE);
        push_u32_be(&mut cs, total);
        push_u32_be(&mut cs, 2);
        push_u32_be(&mut cs, cs_slot::CODEDIRECTORY);
        push_u32_be(&mut cs, cd_blob_off);
        push_u32_be(&mut cs, cs_slot::ENTITLEMENTS);
        push_u32_be(&mut cs, ent_blob_off);
        cs.extend_from_slice(&cd);
        cs.extend_from_slice(&ent);
        let cs_size = cs.len() as u32;
        file.extend_from_slice(&cs);

        let strtab = b"\0___stack_chk_fail\0";
        let symoff = file.len() as u32;
        push_u32(&mut file, 1);
        file.push(0x01);
        file.push(0);
        file.extend_from_slice(&0u16.to_le_bytes());
        push_u64(&mut file, 0);
        let stroff = file.len() as u32;
        file.extend_from_slice(strtab);

        let base = 32usize;
        let fs_dataoff_pos = base + fs_cmd_pos + 8;
        file[fs_dataoff_pos..fs_dataoff_pos + 4].copy_from_slice(&fs_off.to_le_bytes());
        file[fs_dataoff_pos + 4..fs_dataoff_pos + 8].copy_from_slice(&fs_size.to_le_bytes());
        let cs_dataoff_pos = base + cs_cmd_pos + 8;
        file[cs_dataoff_pos..cs_dataoff_pos + 4].copy_from_slice(&cs_off.to_le_bytes());
        file[cs_dataoff_pos + 4..cs_dataoff_pos + 8].copy_from_slice(&cs_size.to_le_bytes());
        let st_pos = base + sym_cmd_pos + 8;
        file[st_pos..st_pos + 4].copy_from_slice(&symoff.to_le_bytes());
        file[st_pos + 4..st_pos + 8].copy_from_slice(&1u32.to_le_bytes());
        file[st_pos + 8..st_pos + 12].copy_from_slice(&stroff.to_le_bytes());
        file[st_pos + 12..st_pos + 16]
            .copy_from_slice(&(strtab.len() as u32).to_le_bytes());

        file
    }

    #[test]
    fn parses_security_and_metadata_lcs() {
        let bytes = build_fixture();
        let file = MachoFile::parse(&bytes).unwrap();

        assert_eq!(
            file.uuid().unwrap().unwrap(),
            [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00
            ]
        );

        let enc = file.encryption_info().unwrap().unwrap();
        assert!(enc.is_encrypted());
        assert_eq!(enc.cryptoff, 0x4000);

        let ep = file.entry_point().unwrap().unwrap();
        assert_eq!(ep.entryoff, 0x1234);

        let bv = file.build_version().unwrap().unwrap();
        assert_eq!(bv.platform_name, Some("iOS"));
        assert_eq!(bv.min_os, (17, 0, 0));
        assert_eq!(bv.sdk, (17, 2, 0));
        assert_eq!(bv.tools.len(), 1);

        let dylibs = file.dylibs().unwrap();
        assert_eq!(dylibs.len(), 1);
        assert_eq!(dylibs[0].name, "/usr/lib/libSystem.B.dylib");
        assert_eq!(dylibs[0].kind, DylibKind::Load);

        let rpaths = file.rpaths().unwrap();
        assert_eq!(rpaths, &["@executable_path/Frameworks"]);

        assert_eq!(file.source_version().unwrap().unwrap(), (1, 2, 3, 4, 5));
        assert!(file.dysymtab().unwrap().is_some());
        assert!(file.dyld_info().unwrap().is_some());

        let starts = file.function_starts().unwrap();
        assert_eq!(starts, &[0x10, 0x30]);

        let cs = file.code_signature().unwrap().unwrap();
        assert!(cs.entitlements_xml.is_some());
        let cd = cs.code_directory.unwrap();
        assert_eq!(cd.identifier, Some("com.example.app"));

        let chk = file.checksec().unwrap();
        assert!(chk.pie);
        assert!(chk.nx_heap);
        assert!(chk.nx_stack);
        assert!(chk.code_signed);
        assert!(chk.encrypted_fairplay);
        assert!(chk.stack_canary);
    }

    #[test]
    fn fat64_selects_arm64_slice() {
        let thin = build_fixture();
        let header_and_arches = 8 + 2 * size_of::<FatArch64>();
        let mut fat = Vec::new();
        push_u32_be(&mut fat, FAT_MAGIC_64);
        push_u32_be(&mut fat, 2);
        let slice_off = header_and_arches as u64;
        push_u32_be(&mut fat, CPU_TYPE_X86_64);
        push_u32_be(&mut fat, 0);
        push_u64_be(&mut fat, slice_off);
        push_u64_be(&mut fat, 0);
        push_u32_be(&mut fat, 0);
        push_u32_be(&mut fat, 0);
        push_u32_be(&mut fat, CPU_TYPE_ARM64);
        push_u32_be(&mut fat, 0);
        push_u64_be(&mut fat, slice_off);
        push_u64_be(&mut fat, thin.len() as u64);
        push_u32_be(&mut fat, 0);
        push_u32_be(&mut fat, 0);
        assert_eq!(fat.len(), header_and_arches);
        fat.extend_from_slice(&thin);

        let file = MachoFile::parse(&fat).unwrap();
        assert_eq!(file.slice_offset, header_and_arches);
        assert!(file.uuid().unwrap().is_some());
    }
}

//! Zero-copy Mach-O structure definitions.

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout};

pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;
pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_CIGAM: u32 = 0xbeba_feca;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
pub const FAT_CIGAM_64: u32 = 0xbfba_feca;

pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;

pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;

/// `section64.flags & SECTION_TYPE` — section type mask.
pub const SECTION_TYPE: u32 = 0xff;
/// Symbol stubs (`__TEXT,__stubs`); `reserved2` = stub entry size.
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub const LC_LINKER_OPTION: u32 = 0x2d;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;

/// Platform ids from `build_version_command.platform`.
pub mod platform {
    pub const MACOS: u32 = 1;
    pub const IOS: u32 = 2;
    pub const TVOS: u32 = 3;
    pub const WATCHOS: u32 = 4;
    pub const BRIDGEOS: u32 = 5;
    pub const MACCATALYST: u32 = 6;
    pub const IOSSIMULATOR: u32 = 7;
    pub const TVOSSIMULATOR: u32 = 8;
    pub const WATCHOSSIMULATOR: u32 = 9;
    pub const DRIVERKIT: u32 = 10;
    pub const VISIONOS: u32 = 11;
    pub const VISIONOSSIMULATOR: u32 = 12;
}

/// Code-signing SuperBlob / blob magics (big-endian on disk).
pub mod cs_magic {
    pub const REQUIREMENT: u32 = 0xfade_0c00;
    pub const REQUIREMENTS: u32 = 0xfade_0c01;
    pub const CODEDIRECTORY: u32 = 0xfade_0c02;
    pub const EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
    pub const DETACHED_SIGNATURE: u32 = 0xfade_0cc1;
    pub const BLOBWRAPPER: u32 = 0xfade_0b01;
    pub const EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
    pub const EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
}

/// SuperBlob slot types.
pub mod cs_slot {
    pub const CODEDIRECTORY: u32 = 0;
    pub const INFO: u32 = 1;
    pub const REQUIREMENTS: u32 = 2;
    pub const RESOURCEDIR: u32 = 3;
    pub const APPLICATION: u32 = 4;
    pub const ENTITLEMENTS: u32 = 5;
    pub const REPSPECIFIC: u32 = 6;
    pub const DER_ENTITLEMENTS: u32 = 7;
    pub const ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
    pub const SIGNATURE: u32 = 0x10000;
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct FatHeader {
    pub magic: u32,
    pub nfat_arch: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

/// 64-bit fat architecture entry (`fat_arch_64`). Fields after magic are big-endian on disk.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct FatArch64 {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct MachHeader64 {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct SegmentCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct Section64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct SymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct DysymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct DyldInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct Nlist64 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct TwolevelHintsCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

/// `dylib_table_of_contents` entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct DylibTableOfContents {
    pub symbol_index: u32,
    pub module_index: u32,
}

    /// `dylib_module_64` (56 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct DylibModule64 {
    pub module_name: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub irefsym: u32,
    pub nrefsym: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextrel: u32,
    pub nextrel: u32,
    pub iinit_iterm: u32,
    pub ninit_nterm: u32,
    pub objc_module_info_size: u32,
    pub objc_module_info_addr: u64,
}

/// Packed `dylib_reference`.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct DylibReference {
    pub packed: u32,
}

impl DylibReference {
    pub fn isym(&self) -> u32 {
        self.packed & 0x00ff_ffff
    }
    pub fn flags(&self) -> u32 {
        self.packed >> 24
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct UuidCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub uuid: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct LinkeditDataCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct EncryptionInfoCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct EncryptionInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct EntryPointCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct SourceVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub version: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct VersionMinCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub version: u32,
    pub sdk: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct BuildVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub ntools: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct BuildToolVersion {
    pub tool: u32,
    pub version: u32,
}

/// Fixed header of `dylib_command` / `rpath_command` before the path string.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct DylibCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub name_offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
pub struct RpathCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub path_offset: u32,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachFlags: u32 {
        const NOUNDEFS = 0x1;
        const INCRLINK = 0x2;
        const DYLDLINK = 0x4;
        const BINDATLOAD = 0x8;
        const PREBOUND = 0x10;
        const SPLIT_SEGS = 0x20;
        const TWOLEVEL = 0x80;
        const FORCE_FLAT = 0x100;
        const NOMULTIDEFS = 0x200;
        const NOFIXPREBINDING = 0x400;
        const PREBINDABLE = 0x800;
        const ALLMODSBOUND = 0x1000;
        const SUBSECTIONS_VIA_SYMBOLS = 0x2000;
        const CANONICAL = 0x4000;
        const WEAK_DEFINES = 0x8000;
        const BINDS_TO_WEAK = 0x10000;
        const ALLOW_STACK_EXECUTION = 0x20000;
        const ROOT_SAFE = 0x40000;
        const SETUID_SAFE = 0x80000;
        const NO_REEXPORTED_DYLIBS = 0x100000;
        const PIE = 0x200000;
        const DEAD_STRIPPABLE_DYLIB = 0x400000;
        const HAS_TLV_DESCRIPTORS = 0x800000;
        const NO_HEAP_EXECUTION = 0x1000000;
    }
}

/// `nlist.n_type` masks.
pub mod n_type {
    pub const N_STAB: u8 = 0xe0;
    pub const N_PEXT: u8 = 0x10;
    pub const N_TYPE: u8 = 0x0e;
    pub const N_EXT: u8 = 0x01;
    pub const N_UNDF: u8 = 0x0;
    pub const N_ABS: u8 = 0x2;
    pub const N_SECT: u8 = 0xe;
    pub const N_INDR: u8 = 0xc;
}

pub fn cstr16(bytes: &[u8; 16]) -> &str {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(16);
    core::str::from_utf8(&bytes[..end]).unwrap_or("")
}

/// Decode `LC_VERSION_*` / `build_version` packed version (`X.Y.Z`).
pub fn format_packed_version(v: u32) -> (u16, u8, u8) {
    let major = ((v >> 16) & 0xffff) as u16;
    let minor = ((v >> 8) & 0xff) as u8;
    let patch = (v & 0xff) as u8;
    (major, minor, patch)
}

/// Decode `LC_SOURCE_VERSION` packed `a.b.c.d.e`.
pub fn format_source_version(v: u64) -> (u32, u16, u16, u16, u16) {
    let a = ((v >> 40) & 0xff_ffff) as u32;
    let b = ((v >> 30) & 0x3ff) as u16;
    let c = ((v >> 20) & 0x3ff) as u16;
    let d = ((v >> 10) & 0x3ff) as u16;
    let e = (v & 0x3ff) as u16;
    (a, b, c, d, e)
}

pub fn platform_name(platform: u32) -> Option<&'static str> {
    match platform {
        platform::MACOS => Some("macOS"),
        platform::IOS => Some("iOS"),
        platform::TVOS => Some("tvOS"),
        platform::WATCHOS => Some("watchOS"),
        platform::BRIDGEOS => Some("bridgeOS"),
        platform::MACCATALYST => Some("macCatalyst"),
        platform::IOSSIMULATOR => Some("iOSSimulator"),
        platform::TVOSSIMULATOR => Some("tvOSSimulator"),
        platform::WATCHOSSIMULATOR => Some("watchOSSimulator"),
        platform::DRIVERKIT => Some("driverKit"),
        platform::VISIONOS => Some("visionOS"),
        platform::VISIONOSSIMULATOR => Some("visionOSSimulator"),
        _ => None,
    }
}

/// Kind of dylib load command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DylibKind {
    Load,
    Weak,
    Reexport,
    Lazy,
    Upward,
    Id,
}

impl DylibKind {
    pub fn from_cmd(cmd: u32) -> Option<Self> {
        match cmd {
            LC_LOAD_DYLIB => Some(Self::Load),
            LC_LOAD_WEAK_DYLIB => Some(Self::Weak),
            LC_REEXPORT_DYLIB => Some(Self::Reexport),
            LC_LAZY_LOAD_DYLIB => Some(Self::Lazy),
            LC_LOAD_UPWARD_DYLIB => Some(Self::Upward),
            LC_ID_DYLIB => Some(Self::Id),
            _ => None,
        }
    }
}

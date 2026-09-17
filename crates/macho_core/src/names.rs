//! Symbolic names for otool-style verbose dumps.

use crate::types::{
    MachFlags, CPU_TYPE_ARM64, CPU_TYPE_X86_64, LC_BUILD_VERSION, LC_CODE_SIGNATURE,
    LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY,
    LC_DYLIB_CODE_SIGN_DRS, LC_DYSYMTAB, LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64,
    LC_FUNCTION_STARTS, LC_ID_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LINKER_OPTIMIZATION_HINT,
    LC_LINKER_OPTION, LC_LOAD_DYLIB, LC_LOAD_DYLINKER, LC_LOAD_UPWARD_DYLIB, LC_LOAD_WEAK_DYLIB,
    LC_MAIN, LC_REEXPORT_DYLIB, LC_REQ_DYLD, LC_RPATH, LC_SEGMENT_64, LC_SEGMENT_SPLIT_INFO,
    LC_SOURCE_VERSION, LC_SYMTAB, LC_TWOLEVEL_HINTS, LC_UUID, LC_VERSION_MIN_IPHONEOS,
    LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS,
};

pub const CPU_TYPE_X86: u32 = 0x7;
pub const CPU_TYPE_ARM: u32 = 0xc;
pub const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
pub const CPU_TYPE_ANY: u32 = 0xffff_ffff;

pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
pub const CPU_SUBTYPE_MASK: u32 = 0x00ff_ffff;

pub fn filetype_name(ft: u32) -> &'static str {
    match ft {
        1 => "MH_OBJECT",
        2 => "MH_EXECUTE",
        3 => "MH_FVMLIB",
        4 => "MH_CORE",
        5 => "MH_PRELOAD",
        6 => "MH_DYLIB",
        7 => "MH_DYLINKER",
        8 => "MH_BUNDLE",
        9 => "MH_DYLIB_STUB",
        10 => "MH_DSYM",
        11 => "MH_KEXT_BUNDLE",
        12 => "MH_FILESET",
        _ => "UNKNOWN",
    }
}

pub fn cpu_type_name(cputype: u32) -> &'static str {
    match cputype {
        CPU_TYPE_X86 => "CPU_TYPE_X86",
        CPU_TYPE_X86_64 => "CPU_TYPE_X86_64",
        CPU_TYPE_ARM => "CPU_TYPE_ARM",
        CPU_TYPE_ARM64 => "CPU_TYPE_ARM64",
        CPU_TYPE_ARM64_32 => "CPU_TYPE_ARM64_32",
        _ => "CPU_TYPE_UNKNOWN",
    }
}

/// Short arch name used by `-arch` (e.g. `arm64`, `x86_64`, `arm64e`).
pub fn arch_name(cputype: u32, cpusubtype: u32) -> alloc::string::String {
    use alloc::string::String;
    let sub = cpusubtype & CPU_SUBTYPE_MASK;
    match cputype {
        CPU_TYPE_X86 => String::from("i386"),
        CPU_TYPE_X86_64 => String::from("x86_64"),
        CPU_TYPE_ARM => match sub {
            9 => String::from("armv7"),
            11 => String::from("armv7s"),
            12 => String::from("armv7k"),
            13 => String::from("armv8"),
            _ => String::from("arm"),
        },
        CPU_TYPE_ARM64 => match sub {
            CPU_SUBTYPE_ARM64E => String::from("arm64e"),
            CPU_SUBTYPE_ARM64_V8 => String::from("arm64v8"),
            _ => String::from("arm64"),
        },
        CPU_TYPE_ARM64_32 => String::from("arm64_32"),
        _ => alloc::format!("cpu_{cputype:#x}"),
    }
}

pub fn arch_matches(want: &str, cputype: u32, cpusubtype: u32) -> bool {
    let name = arch_name(cputype, cpusubtype);
    if want.eq_ignore_ascii_case(&name) {
        return true;
    }
    // Allow "arm64" to match arm64e / arm64v8 when user asks broadly? otool is exact.
    // Also accept cputype aliases.
    match want.to_ascii_lowercase().as_str() {
        "aarch64" => cputype == CPU_TYPE_ARM64,
        "arm64" => cputype == CPU_TYPE_ARM64 && (cpusubtype & CPU_SUBTYPE_MASK) != CPU_SUBTYPE_ARM64E,
        "arm64e" => {
            cputype == CPU_TYPE_ARM64 && (cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E
        }
        "x86_64" | "x86-64" => cputype == CPU_TYPE_X86_64,
        "i386" | "x86" => cputype == CPU_TYPE_X86,
        _ => false,
    }
}

pub fn lc_name(cmd: u32) -> &'static str {
    let base = cmd & !LC_REQ_DYLD;
    match cmd {
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_SYMTAB => "LC_SYMTAB",
        LC_DYSYMTAB => "LC_DYSYMTAB",
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
        LC_ID_DYLIB => "LC_ID_DYLIB",
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER",
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
        LC_TWOLEVEL_HINTS => "LC_TWOLEVEL_HINTS",
        LC_UUID => "LC_UUID",
        LC_RPATH => "LC_RPATH",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
        LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
        LC_DYLD_INFO => "LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        LC_LOAD_UPWARD_DYLIB => "LC_LOAD_UPWARD_DYLIB",
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        LC_MAIN => "LC_MAIN",
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS",
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
        LC_LINKER_OPTION => "LC_LINKER_OPTION",
        LC_LINKER_OPTIMIZATION_HINT => "LC_LINKER_OPTIMIZATION_HINT",
        LC_VERSION_MIN_TVOS => "LC_VERSION_MIN_TVOS",
        LC_VERSION_MIN_WATCHOS => "LC_VERSION_MIN_WATCHOS",
        LC_BUILD_VERSION => "LC_BUILD_VERSION",
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        _ => match base {
            0x1 => "LC_SEGMENT",
            0x4 => "LC_THREAD",
            0x5 => "LC_UNIXTHREAD",
            0xe => "LC_LOAD_DYLINKER",
            0x31 => "LC_NOTE",
            0x35 => "LC_FILESET_ENTRY",
            _ => "LC_UNKNOWN",
        },
    }
}

pub fn flag_names(flags: u32) -> alloc::vec::Vec<&'static str> {
    let f = MachFlags::from_bits_truncate(flags);
    let mut out = alloc::vec::Vec::new();
    let pairs: &[(MachFlags, &str)] = &[
        (MachFlags::NOUNDEFS, "NOUNDEFS"),
        (MachFlags::INCRLINK, "INCRLINK"),
        (MachFlags::DYLDLINK, "DYLDLINK"),
        (MachFlags::BINDATLOAD, "BINDATLOAD"),
        (MachFlags::PREBOUND, "PREBOUND"),
        (MachFlags::SPLIT_SEGS, "SPLIT_SEGS"),
        (MachFlags::TWOLEVEL, "TWOLEVEL"),
        (MachFlags::FORCE_FLAT, "FORCE_FLAT"),
        (MachFlags::NOMULTIDEFS, "NOMULTIDEFS"),
        (MachFlags::NOFIXPREBINDING, "NOFIXPREBINDING"),
        (MachFlags::PREBINDABLE, "PREBINDABLE"),
        (MachFlags::ALLMODSBOUND, "ALLMODSBOUND"),
        (MachFlags::SUBSECTIONS_VIA_SYMBOLS, "SUBSECTIONS_VIA_SYMBOLS"),
        (MachFlags::CANONICAL, "CANONICAL"),
        (MachFlags::WEAK_DEFINES, "WEAK_DEFINES"),
        (MachFlags::BINDS_TO_WEAK, "BINDS_TO_WEAK"),
        (MachFlags::ALLOW_STACK_EXECUTION, "ALLOW_STACK_EXECUTION"),
        (MachFlags::ROOT_SAFE, "ROOT_SAFE"),
        (MachFlags::SETUID_SAFE, "SETUID_SAFE"),
        (MachFlags::NO_REEXPORTED_DYLIBS, "NO_REEXPORTED_DYLIBS"),
        (MachFlags::PIE, "PIE"),
        (MachFlags::DEAD_STRIPPABLE_DYLIB, "DEAD_STRIPPABLE_DYLIB"),
        (MachFlags::HAS_TLV_DESCRIPTORS, "HAS_TLV_DESCRIPTORS"),
        (MachFlags::NO_HEAP_EXECUTION, "NO_HEAP_EXECUTION"),
    ];
    for &(bit, name) in pairs {
        if f.contains(bit) {
            out.push(name);
        }
    }
    out
}

/// Format packed `dylib` version as `X.Y.Z`.
pub fn version_string(v: u32) -> alloc::string::String {
    let major = (v >> 16) & 0xffff;
    let minor = (v >> 8) & 0xff;
    let patch = v & 0xff;
    alloc::format!("{major}.{minor}.{patch}")
}

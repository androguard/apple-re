//! otool(1)-compatible object dump subcommand.
//!
//! See `docs/OTOOL_PARITY.md` and
//! <https://leopard-adc.pepas.com/documentation/Darwin/Reference/ManPages/man1/otool.1.html>.

use std::fs;
use std::path::Path;

use apple_re::apple_metadata::SymbolTable;
use apple_re::arm_disassembler::{Decoder, Formatter, SymbolResolver};
use apple_re::ipa_vfs::IpaVfs;
use apple_re::macho_core::{
    arch_name, cpu_type_name, cstr16, fat_arches, filetype_name, flag_names, format_packed_version,
    is_fat, lc_name, split_archive_member, version_string, ArArchive, BuildVersionCommand,
    DyldInfoCommand, DylibCommand, DylibKind, DylibModule64, DylibReference, DylibTableOfContents,
    DysymtabCommand, EncryptionInfoCommand64, EntryPointCommand, LinkeditDataCommand, LoadCommand,
    MachoFile, RpathCommand, SegmentCommand64, SourceVersionCommand, SymtabCommand,
    TwolevelHintsCommand, UuidCommand, VersionMinCommand, LC_BUILD_VERSION, LC_CODE_SIGNATURE,
    LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO, LC_DYLD_INFO_ONLY,
    LC_DYLIB_CODE_SIGN_DRS, LC_DYSYMTAB, LC_ENCRYPTION_INFO_64, LC_FUNCTION_STARTS, LC_ID_DYLIB,
    LC_LINKER_OPTIMIZATION_HINT, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_MAIN, LC_REEXPORT_DYLIB,
    LC_RPATH, LC_SEGMENT_64, LC_SEGMENT_SPLIT_INFO, LC_SOURCE_VERSION, LC_SYMTAB, LC_TWOLEVEL_HINTS,
    LC_UUID, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
};
use clap::{ArgAction, Args};
use zerocopy::FromBytes;

#[derive(Args, Debug)]
#[command(disable_help_flag = true)]
pub struct OtoolArgs {
    /// Print help (use `--help`; `-h` is Mach header like otool)
    #[arg(long = "help", action = ArgAction::Help)]
    pub help: Option<bool>,
    /// Display fat / universal headers (`-f`)
    #[arg(short = 'f')]
    pub fat_headers: bool,
    /// Display Mach header (`-h`)
    #[arg(short = 'h')]
    pub header: bool,
    /// Display load commands (`-l`)
    #[arg(short = 'l')]
    pub load_commands: bool,
    /// Display shared library names (`-L`)
    #[arg(short = 'L')]
    pub libraries: bool,
    /// Display install name (`-D`)
    #[arg(short = 'D')]
    pub install_name: bool,
    /// Display `__TEXT,__text` (`-t`); with `-v`/`-V` disassemble
    #[arg(short = 't')]
    pub text: bool,
    /// Display `__DATA,__data` (`-d`)
    #[arg(short = 'd')]
    pub data: bool,
    /// Display section contents: `-s SEG SECT`
    #[arg(short = 's', num_args = 2, value_names = ["SEG", "SECT"])]
    pub section: Option<Vec<String>>,
    /// Display ObjC metadata (`-o`)
    #[arg(short = 'o')]
    pub objc: bool,
    /// Display relocation entries (`-r`)
    #[arg(short = 'r')]
    pub relocs: bool,
    /// Display indirect symbol table (`-I`)
    #[arg(short = 'I')]
    pub indirect: bool,
    /// Display archive headers (`-a`)
    #[arg(short = 'a')]
    pub archive_header: bool,
    /// Display `__.SYMDEF` contents (`-S`)
    #[arg(short = 'S')]
    pub symdef: bool,
    /// Do not assume archive(member) syntax (`-m`)
    #[arg(short = 'm')]
    pub no_archive_syntax: bool,
    /// Display dylib table of contents (`-T`)
    #[arg(short = 'T')]
    pub toc: bool,
    /// Display dylib reference table (`-R`)
    #[arg(short = 'R')]
    pub refs: bool,
    /// Display dylib module table (`-M`)
    #[arg(short = 'M')]
    pub modules: bool,
    /// Display two-level namespace hints (`-H`)
    #[arg(short = 'H')]
    pub hints: bool,
    /// Display argv/envp from a core file (`-c`)
    #[arg(short = 'c')]
    pub core_strings: bool,
    /// Start disassembly at symbol (`-p`, with `-t`)
    #[arg(short = 'p')]
    pub start_symbol: Option<String>,
    /// Verbose / symbolic (`-v`)
    #[arg(short = 'v')]
    pub verbose: bool,
    /// Symbolic disasm operands (`-V`, implies `-v`)
    #[arg(short = 'V')]
    pub very_verbose: bool,
    /// Omit leading addresses (`-X`)
    #[arg(short = 'X')]
    pub no_addresses: bool,
    /// Architecture slice (`-arch`), or `all`
    #[arg(long = "arch")]
    pub arch: Option<String>,
    /// Input file(s): Mach-O, fat, archive, IPA, or `lib.a(member.o)`
    pub files: Vec<std::path::PathBuf>,
}

pub fn run(args: &OtoolArgs) -> Result<(), String> {
    if args.files.is_empty() {
        return Err("otool: at least one file required".into());
    }
    let verbose = args.verbose || args.very_verbose;
    let any = args.fat_headers
        || args.header
        || args.load_commands
        || args.libraries
        || args.install_name
        || args.text
        || args.data
        || args.section.is_some()
        || args.objc
        || args.relocs
        || args.indirect
        || args.archive_header
        || args.symdef
        || args.toc
        || args.refs
        || args.modules
        || args.hints
        || args.core_strings;
    if !any {
        return Err(
            "otool: specify at least one of -f -h -l -L -D -t -d -s -o -r -I -a -S -T -R -M -H -c (see docs/OTOOL_PARITY.md)"
                .into(),
        );
    }

    for path in &args.files {
        let spec = path.to_string_lossy();
        println!("{spec}");
        let (bytes, label) = load_object_bytes(path, args.no_archive_syntax)?;
        if let Some(l) = label {
            println!("{l}:");
        }
        dump_file(&bytes, args, verbose)?;
    }
    Ok(())
}

/// Returns object bytes and optional archive member label.
fn load_object_bytes(
    path: &Path,
    no_archive_syntax: bool,
) -> Result<(Vec<u8>, Option<String>), String> {
    let spec = path.to_string_lossy();
    if !no_archive_syntax {
        if let Some((arch_path, member)) = split_archive_member(&spec) {
            let bytes = fs::read(arch_path).map_err(|e| format!("read {arch_path}: {e}"))?;
            let ar = ArArchive::open(&bytes).map_err(|e| e.to_string())?;
            let m = ar
                .find(member)
                .ok_or_else(|| format!("archive member not found: {member}"))?;
            let data = ar.member_data(m).map_err(|e| e.to_string())?.to_vec();
            return Ok((data, Some(format!("{arch_path}({member})"))));
        }
    }

    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ipa"))
        || looks_like_zip(&bytes)
    {
        if let Ok(vfs) = IpaVfs::open(&bytes) {
            if let Ok(bundle) = vfs.bundle() {
                return Ok((bundle.main_executable.to_vec(), None));
            }
        }
    }
    Ok((bytes, None))
}

fn looks_like_zip(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == b'P' && data[1] == b'K'
}

fn dump_file(bytes: &[u8], args: &OtoolArgs, verbose: bool) -> Result<(), String> {
    if args.archive_header || args.symdef {
        dump_archive_maybe_fat(bytes, args, verbose)?;
        let need_macho = args.fat_headers
            || args.header
            || args.load_commands
            || args.libraries
            || args.install_name
            || args.text
            || args.data
            || args.section.is_some()
            || args.objc
            || args.relocs
            || args.indirect
            || args.toc
            || args.refs
            || args.modules
            || args.hints
            || args.core_strings;
        if !need_macho {
            return Ok(());
        }
    }

    if args.fat_headers {
        dump_fat_headers(bytes, verbose)?;
    }

    let arch_arg = args.arch.as_deref();
    if arch_arg.is_some_and(|a| a.eq_ignore_ascii_case("all")) && is_fat(bytes) {
        let arches = fat_arches(bytes).map_err(|e| e.to_string())?;
        for a in &arches {
            let name = a.arch_name();
            println!("\n{name}:");
            let file = MachoFile::parse_arch(bytes, Some(&name)).map_err(|e| e.to_string())?;
            dump_thin(&file, args, verbose)?;
        }
        return Ok(());
    }

    let arch = match arch_arg {
        Some(a) if a.eq_ignore_ascii_case("all") => None,
        other => other,
    };
    // Only open thin view if we need something beyond fat headers alone.
    let need_thin = args.header
        || args.load_commands
        || args.libraries
        || args.install_name
        || args.text
        || args.data
        || args.section.is_some()
        || args.objc
        || args.relocs
        || args.indirect
        || args.toc
        || args.refs
        || args.modules
        || args.hints
        || args.core_strings;
    if !need_thin {
        return Ok(());
    }

    let file = MachoFile::parse_arch(bytes, arch).map_err(|e| e.to_string())?;
    dump_thin(&file, args, verbose)
}

fn dump_archive_maybe_fat(bytes: &[u8], args: &OtoolArgs, verbose: bool) -> Result<(), String> {
    if let Ok(ar) = ArArchive::open(bytes) {
        if args.archive_header {
            dump_archive_headers(&ar, verbose)?;
        }
        if args.symdef {
            dump_symdef(&ar)?;
        }
        return Ok(());
    }
    // Fat-wrapped archives (common for clang_rt *.a on macOS)
    if is_fat(bytes) {
        let arches = fat_arches(bytes).map_err(|e| e.to_string())?;
        let want = args.arch.as_deref();
        let selected: Vec<_> = if want.is_some_and(|a| a.eq_ignore_ascii_case("all")) || want.is_none()
        {
            arches.iter().collect()
        } else {
            arches
                .iter()
                .filter(|a| {
                    apple_re::macho_core::arch_matches(want.unwrap(), a.cputype, a.cpusubtype)
                })
                .collect()
        };
        let mut any = false;
        for a in selected {
            let start = a.offset as usize;
            let end = start + a.size as usize;
            let slice = bytes.get(start..end).ok_or("fat archive slice oob")?;
            if let Ok(ar) = ArArchive::open(slice) {
                any = true;
                println!("Archive (architecture {}):", a.arch_name());
                if args.archive_header {
                    dump_archive_headers(&ar, verbose)?;
                }
                if args.symdef {
                    dump_symdef(&ar)?;
                }
            }
        }
        if any {
            return Ok(());
        }
    }
    Err("not an archive".into())
}

fn dump_archive_headers(ar: &ArArchive<'_>, verbose: bool) -> Result<(), String> {
    println!("Archive :");
    for m in ar.members() {
        if verbose {
            println!(
                "    {} date {} uid {} gid {} mode {:o} size {}",
                m.name, m.date, m.uid, m.gid, m.mode, m.size
            );
        } else {
            println!("    {} size {}", m.name, m.size);
        }
    }
    Ok(())
}

fn dump_symdef(ar: &ArArchive<'_>) -> Result<(), String> {
    let Some(m) = ar
        .members()
        .iter()
        .find(|m| m.name == "__.SYMDEF" || m.name == "__.SYMDEF SORTED")
    else {
        return Err("no __.SYMDEF in archive".into());
    };
    let data = ar.member_data(m).map_err(|e| e.to_string())?;
    println!("Table of contents from {}", m.name);
    // BSD ranlib: uint32 size of ranlib array, then ranlibs (strx,off), then string table.
    if data.len() < 4 {
        return Ok(());
    }
    let sz = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let n = sz / 8;
    println!("size {sz}  nranlibs {n}");
    for i in 0..n {
        let off = 4 + i * 8;
        if off + 8 > data.len() {
            break;
        }
        let strx = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let obj_off = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        let strs_off = 4 + sz;
        let name = data
            .get(strs_off + strx as usize..)
            .and_then(|s| {
                let end = s.iter().position(|&b| b == 0).unwrap_or(s.len().min(256));
                core::str::from_utf8(&s[..end]).ok()
            })
            .unwrap_or("?");
        println!("  {name}  object_offset {obj_off}");
    }
    Ok(())
}

fn dump_fat_headers(bytes: &[u8], verbose: bool) -> Result<(), String> {
    if !is_fat(bytes) {
        if verbose {
            println!("Fat headers\n(not a fat file)");
        }
        return Ok(());
    }
    let arches = fat_arches(bytes).map_err(|e| e.to_string())?;
    println!("Fat headers");
    println!("fat_magic 0x{:08x}", u32::from_be_bytes(bytes[0..4].try_into().unwrap()));
    println!("nfat_arch {}", arches.len());
    for (i, a) in arches.iter().enumerate() {
        println!("architecture {i}");
        if verbose {
            println!("    cputype {}", cpu_type_name(a.cputype));
            println!("    cpusubtype {}", a.cpusubtype);
            println!("    capabilities 0x{:x}", (a.cpusubtype >> 24) & 0xff);
            println!("    offset {}", a.offset);
            println!("    size {}", a.size);
            println!("    align 2^{} ({})", a.align, 1u64 << a.align.min(63));
            println!("    ({})", a.arch_name());
        } else {
            println!(
                "    cputype {} cpusubtype {} offset {} size {} align {}",
                a.cputype, a.cpusubtype, a.offset, a.size, a.align
            );
        }
    }
    Ok(())
}

fn dump_thin(file: &MachoFile<'_>, args: &OtoolArgs, verbose: bool) -> Result<(), String> {
    if args.header {
        dump_mach_header(file, verbose);
    }
    if args.load_commands {
        dump_load_commands(file, verbose)?;
    }
    if args.libraries {
        dump_libraries(file)?;
    }
    if args.install_name {
        dump_install_name(file)?;
    }
    if let Some(pair) = &args.section {
        if pair.len() == 2 {
            dump_section(file, &pair[0], &pair[1], args.no_addresses, verbose)?;
        }
    }
    if args.data {
        dump_section(file, "__DATA", "__data", args.no_addresses, verbose)?;
    }
    if args.text {
        if args.verbose || args.very_verbose {
            dump_disasm(file, args)?;
        } else {
            dump_section(file, "__TEXT", "__text", args.no_addresses, verbose)?;
        }
    }
    if args.objc {
        dump_objc(file)?;
    }
    if args.relocs {
        dump_relocs(file, verbose)?;
    }
    if args.indirect {
        dump_indirect(file)?;
    }
    if args.toc {
        dump_toc(file)?;
    }
    if args.refs {
        dump_refs(file)?;
    }
    if args.modules {
        dump_modules(file)?;
    }
    if args.hints {
        dump_hints(file)?;
    }
    if args.core_strings {
        dump_core_strings(file)?;
    }
    Ok(())
}

fn dump_mach_header(file: &MachoFile<'_>, verbose: bool) {
    let h = &file.header;
    println!("Mach header");
    if verbose {
        println!(
            "      magic cputype cpusubtype  caps    filetype ncmds sizeofcmds      flags"
        );
        let flags = flag_names(h.flags).join(" ");
        println!(
            " 0x{:08x} {:>7} {:>10}  0x{:02x} {:>11} {:>5} {:>10} 0x{:08x}",
            h.magic,
            cpu_type_name(h.cputype).trim_start_matches("CPU_TYPE_"),
            h.cpusubtype & 0x00ff_ffff,
            (h.cpusubtype >> 24) & 0xff,
            filetype_name(h.filetype),
            h.ncmds,
            h.sizeofcmds,
            h.flags
        );
        if !flags.is_empty() {
            println!("      flags {flags}");
        }
        println!(
            "      arch {}",
            arch_name(h.cputype, h.cpusubtype)
        );
    } else {
        println!(
            "      magic {:#x} cputype {} cpusubtype {} filetype {} ncmds {} sizeofcmds {} flags {:#x}",
            h.magic, h.cputype, h.cpusubtype, h.filetype, h.ncmds, h.sizeofcmds, h.flags
        );
    }
}

fn dump_load_commands(file: &MachoFile<'_>, verbose: bool) -> Result<(), String> {
    println!("Load commands");
    let mut idx = 0u32;
    for cmd in file.load_commands().map_err(|e| e.to_string())? {
        let (lc, body) = cmd.map_err(|e| e.to_string())?;
        println!("Load command {idx}");
        idx += 1;
        let name = if verbose {
            lc_name(lc.cmd)
        } else {
            "cmd"
        };
        if verbose {
            println!("      cmd {name}");
        } else {
            println!("      cmd {:#x}", lc.cmd);
        }
        println!("  cmdsize {}", lc.cmdsize);
        dump_lc_body(lc, body, verbose)?;
    }
    Ok(())
}

fn dump_lc_body(lc: &LoadCommand, body: &[u8], verbose: bool) -> Result<(), String> {
    match lc.cmd {
        LC_SEGMENT_64 => {
            if let Ok((seg, _)) = SegmentCommand64::ref_from_prefix(body) {
                println!("  segname {}", cstr16(&seg.segname));
                println!("   vmaddr {:#018x}", seg.vmaddr);
                println!("   vmsize {:#018x}", seg.vmsize);
                println!("  fileoff {}", seg.fileoff);
                println!(" filesize {}", seg.filesize);
                println!("  maxprot {:#x}", seg.maxprot);
                println!(" initprot {:#x}", seg.initprot);
                println!("   nsects {}", seg.nsects);
                println!("    flags {:#x}", seg.flags);
                let sects_off = core::mem::size_of::<SegmentCommand64>();
                let n = seg.nsects as usize;
                let need = sects_off + n * core::mem::size_of::<apple_re::macho_core::Section64>();
                if body.len() >= need {
                    if let Ok(sects) = <[apple_re::macho_core::Section64]>::ref_from_bytes(
                        &body[sects_off..need],
                    ) {
                        for s in sects {
                            println!("Section");
                            println!("  sectname {}", cstr16(&s.sectname));
                            println!("   segname {}", cstr16(&s.segname));
                            println!("      addr {:#018x}", s.addr);
                            println!("      size {:#018x}", s.size);
                            println!("    offset {}", s.offset);
                            println!("     align 2^{}", s.align);
                            println!("    reloff {}", s.reloff);
                            println!("    nreloc {}", s.nreloc);
                            println!("     flags {:#x}", s.flags);
                        }
                    }
                }
            }
        }
        LC_SYMTAB => {
            if let Ok((st, _)) = SymtabCommand::ref_from_prefix(body) {
                println!("   symoff {}", st.symoff);
                println!("    nsyms {}", st.nsyms);
                println!("   stroff {}", st.stroff);
                println!("  strsize {}", st.strsize);
            }
        }
        LC_UUID => {
            if let Ok((u, _)) = UuidCommand::ref_from_prefix(body) {
                let b = &u.uuid;
                println!(
                    "    uuid {:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                    b[12], b[13], b[14], b[15]
                );
            }
        }
        LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
            if let Ok((d, _)) = DylibCommand::ref_from_prefix(body) {
                let name = path_in(body, d.name_offset as usize).unwrap_or("?");
                println!("    name {name} (offset {})", d.name_offset);
                println!(
                    "  time stamp {} {}",
                    d.timestamp,
                    if verbose { "" } else { "" }
                );
                println!(
                    "    current version {}",
                    version_string(d.current_version)
                );
                println!(
                    "compatibility version {}",
                    version_string(d.compatibility_version)
                );
            }
        }
        LC_RPATH => {
            if let Ok((r, _)) = RpathCommand::ref_from_prefix(body) {
                let p = path_in(body, r.path_offset as usize).unwrap_or("?");
                println!("    path {p} (offset {})", r.path_offset);
            }
        }
        LC_MAIN => {
            if let Ok((e, _)) = EntryPointCommand::ref_from_prefix(body) {
                println!("  entryoff {:#x}", e.entryoff);
                println!(" stacksize {:#x}", e.stacksize);
            }
        }
        LC_ENCRYPTION_INFO_64 => {
            if let Ok((e, _)) = EncryptionInfoCommand64::ref_from_prefix(body) {
                println!("  cryptoff {}", e.cryptoff);
                println!(" cryptsize {}", e.cryptsize);
                println!("   cryptid {}", e.cryptid);
            }
        }
        LC_BUILD_VERSION => {
            if let Ok((b, _)) = BuildVersionCommand::ref_from_prefix(body) {
                let (maj, min, pat) = format_packed_version(b.minos);
                let (smaj, smin, spat) = format_packed_version(b.sdk);
                println!(" platform {}", b.platform);
                println!("    minos {maj}.{min}.{pat}");
                println!("      sdk {smaj}.{smin}.{spat}");
                println!("   ntools {}", b.ntools);
            }
        }
        LC_VERSION_MIN_IPHONEOS
        | LC_VERSION_MIN_MACOSX
        | LC_VERSION_MIN_TVOS
        | LC_VERSION_MIN_WATCHOS => {
            if let Ok((v, _)) = VersionMinCommand::ref_from_prefix(body) {
                let (maj, min, pat) = format_packed_version(v.version);
                let (smaj, smin, spat) = format_packed_version(v.sdk);
                println!("  version {maj}.{min}.{pat}");
                println!("      sdk {smaj}.{smin}.{spat}");
            }
        }
        LC_SOURCE_VERSION => {
            if let Ok((s, _)) = SourceVersionCommand::ref_from_prefix(body) {
                println!("  version {:#x}", s.version);
            }
        }
        LC_DYSYMTAB => {
            if let Ok((d, _)) = DysymtabCommand::ref_from_prefix(body) {
                println!("            ilocalsym {}", d.ilocalsym);
                println!("            nlocalsym {}", d.nlocalsym);
                println!("           iextdefsym {}", d.iextdefsym);
                println!("           nextdefsym {}", d.nextdefsym);
                println!("            iundefsym {}", d.iundefsym);
                println!("            nundefsym {}", d.nundefsym);
                println!("               tocoff {}", d.tocoff);
                println!("                 ntoc {}", d.ntoc);
                println!("          modtaboff {}", d.modtaboff);
                println!("            nmodtab {}", d.nmodtab);
                println!("       extrefsymoff {}", d.extrefsymoff);
                println!("        nextrefsyms {}", d.nextrefsyms);
                println!("     indirectsymoff {}", d.indirectsymoff);
                println!("      nindirectsyms {}", d.nindirectsyms);
                println!("        extreloff {}", d.extreloff);
                println!("          nextrel {}", d.nextrel);
                println!("        locreloff {}", d.locreloff);
                println!("          nlocrel {}", d.nlocrel);
            }
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            if let Ok((d, _)) = DyldInfoCommand::ref_from_prefix(body) {
                println!("  rebase_off {}", d.rebase_off);
                println!(" rebase_size {}", d.rebase_size);
                println!("    bind_off {}", d.bind_off);
                println!("   bind_size {}", d.bind_size);
                println!(" weak_bind_off {}", d.weak_bind_off);
                println!("weak_bind_size {}", d.weak_bind_size);
                println!(" lazy_bind_off {}", d.lazy_bind_off);
                println!("lazy_bind_size {}", d.lazy_bind_size);
                println!("  export_off {}", d.export_off);
                println!(" export_size {}", d.export_size);
            }
        }
        LC_TWOLEVEL_HINTS => {
            if let Ok((t, _)) = TwolevelHintsCommand::ref_from_prefix(body) {
                println!("  offset {}", t.offset);
                println!("  nhints {}", t.nhints);
            }
        }
        LC_CODE_SIGNATURE
        | LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_DYLIB_CODE_SIGN_DRS
        | LC_SEGMENT_SPLIT_INFO
        | LC_LINKER_OPTIMIZATION_HINT
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS => {
            if let Ok((l, _)) = LinkeditDataCommand::ref_from_prefix(body) {
                println!("  dataoff {}", l.dataoff);
                println!(" datasize {}", l.datasize);
            }
        }
        _ => {}
    }
    let _ = verbose;
    Ok(())
}

fn path_in(body: &[u8], off: usize) -> Option<&str> {
    let rest = body.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end]).ok()
}

fn dump_libraries(file: &MachoFile<'_>) -> Result<(), String> {
    for d in file.dylibs().map_err(|e| e.to_string())? {
        if d.kind == DylibKind::Id {
            continue;
        }
        println!(
            "\t{} (compatibility version {}, current version {})",
            d.name,
            version_string(d.compatibility_version),
            version_string(d.current_version)
        );
    }
    Ok(())
}

fn dump_install_name(file: &MachoFile<'_>) -> Result<(), String> {
    if let Some(id) = file.id_dylib().map_err(|e| e.to_string())? {
        println!("{}", id.name);
    }
    Ok(())
}

fn dump_section(
    file: &MachoFile<'_>,
    seg: &str,
    sect: &str,
    no_addr: bool,
    verbose: bool,
) -> Result<(), String> {
    let Some(s) = file.find_section(seg, sect).map_err(|e| e.to_string())? else {
        return Err(format!("section ({seg},{sect}) not found"));
    };
    let data = file.section_data(s).map_err(|e| e.to_string())?;
    println!("Contents of ({seg},{sect}) section");

    // Typed verbose decode for common text sections
    if verbose
        && matches!(
            sect,
            "__cstring" | "__objc_methname" | "__objc_classname" | "__objc_methtype" | "__const"
        )
    {
        let mut addr = s.addr;
        let mut i = 0usize;
        while i < data.len() {
            if data[i] == 0 {
                i += 1;
                addr += 1;
                continue;
            }
            let start = i;
            while i < data.len() && data[i] != 0 {
                i += 1;
            }
            if let Ok(strv) = core::str::from_utf8(&data[start..i]) {
                if no_addr {
                    println!("{strv:?}");
                } else {
                    println!("{addr:016x}  {strv:?}");
                }
            }
            addr += (i - start) as u64 + 1;
            i += 1;
        }
        return Ok(());
    }

    let mut addr = s.addr;
    for chunk in data.chunks(16) {
        if !no_addr {
            print!("{addr:016x} ");
        }
        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                print!(" ");
            }
            print!("{b:02x} ");
        }
        println!();
        addr += chunk.len() as u64;
    }
    Ok(())
}

fn dump_disasm(file: &MachoFile<'_>, args: &OtoolArgs) -> Result<(), String> {
    let Some(text) = file
        .find_section("__TEXT", "__text")
        .map_err(|e| e.to_string())?
    else {
        return Err("(__TEXT,__text) not found".into());
    };
    let code = file.section_data(text).map_err(|e| e.to_string())?;
    let syms = SymbolTable::from_macho(file).map_err(|e| e.to_string())?;

    let mut start_off = 0usize;
    if let Some(name) = &args.start_symbol {
        let mut found = None;
        for (addr, n) in syms.iter() {
            if n == name || n.trim_start_matches('_') == name.trim_start_matches('_') {
                if addr >= text.addr && addr < text.addr + text.size {
                    found = Some((addr - text.addr) as usize);
                    break;
                }
            }
        }
        start_off = found.ok_or_else(|| format!("symbol not found in __text: {name}"))?;
        // Align to 4
        start_off &= !3;
    }

    let slice = &code[start_off.min(code.len())..];
    let base = text.addr + start_off as u64;
    println!("(__TEXT,__text) section");

    struct Res<'a>(&'a SymbolTable);
    impl SymbolResolver for Res<'_> {
        fn resolve(&self, vaddr: u64) -> Option<&str> {
            self.0.get_symbol_str_at_vaddr(vaddr)
        }
    }

    let mut dec = Decoder::new(slice, base);
    let fmt = Formatter::new();
    let resolver = Res(&syms);
    while dec.can_decode() {
        let ins = dec.decode();
        let text = if args.very_verbose {
            fmt.format(&ins, &resolver)
        } else {
            fmt.format_simple(&ins)
        };
        if args.no_addresses {
            println!("{text}");
        } else {
            println!("{:016x}\t{text}", ins.vaddr);
        }
    }
    Ok(())
}

fn dump_objc(file: &MachoFile<'_>) -> Result<(), String> {
    use apple_re::apple_metadata::ObjcMetadata;

    println!("Objective-C segment");
    // Classic `__OBJC` segment sections (pre-nonfragile ABI)
    let mut classic = 0usize;
    for item in file.sections().map_err(|e| e.to_string())? {
        let (sect, seg) = item.map_err(|e| e.to_string())?;
        if cstr16(&seg.segname) != "__OBJC" {
            continue;
        }
        classic += 1;
        let name = cstr16(&sect.sectname);
        let data = file.section_data(sect).unwrap_or(&[]);
        println!("Section __OBJC,{name}  size {} addr {:#x}", sect.size, sect.addr);
        // Symbolic hints for well-known classic section names
        match name {
            "__module_info" | "__class" | "__meta_class" | "__cat_cls_meth" | "__cat_inst_meth"
            | "__protocol" | "__string_object" | "__cls_meth" | "__inst_meth" | "__message_refs"
            | "__cls_refs" | "__class_vars" | "__instance_vars" | "__category" | "__class_ext"
            | "__property" => {
                println!("  (classic objc section)");
            }
            _ => {}
        }
        // Hex preview (first 64 bytes)
        for (i, chunk) in data.chunks(16).take(4).enumerate() {
            print!("  {:016x} ", sect.addr + (i * 16) as u64);
            for b in chunk {
                print!("{b:02x}");
            }
            println!();
        }
        if data.len() > 64 {
            println!("  …");
        }
    }
    if classic == 0 {
        println!("(no classic __OBJC segment sections)");
    }

    // Modern ABI sections inventory
    println!("Modern Objective-C image info / lists");
    for (seg, sect) in [
        ("__DATA_CONST", "__objc_classlist"),
        ("__DATA", "__objc_classlist"),
        ("__DATA_CONST", "__objc_catlist"),
        ("__DATA", "__objc_catlist"),
        ("__DATA_CONST", "__objc_protolist"),
        ("__DATA", "__objc_protolist"),
        ("__DATA_CONST", "__objc_imageinfo"),
        ("__DATA", "__objc_imageinfo"),
        ("__TEXT", "__objc_classname"),
        ("__TEXT", "__objc_methname"),
        ("__TEXT", "__objc_methtype"),
    ] {
        if let Ok(Some(s)) = file.find_section(seg, sect) {
            println!("  ({seg},{sect}) size {} addr {:#x}", s.size, s.addr);
        }
    }

    let meta = ObjcMetadata::parse(file).map_err(|e| e.to_string())?;
    println!("Classes ({})", meta.classes.len());
    for c in &meta.classes {
        println!("Class {}  @{:#x}", c.name, c.class_vaddr);
        for m in &c.methods {
            println!("    method {}  types {}  imp {:#x}", m.name, m.types, m.imp);
        }
    }
    Ok(())
}

fn dump_toc(file: &MachoFile<'_>) -> Result<(), String> {
    let dy = file.dysymtab().map_err(|e| e.to_string())?.ok_or("no LC_DYSYMTAB")?;
    let st = file.symtab().map_err(|e| e.to_string())?.ok_or("no LC_SYMTAB")?;
    println!("Table of contents ({} entries)", dy.ntoc);
    if dy.ntoc == 0 {
        return Ok(());
    }
    let off = dy.tocoff as usize;
    let n = dy.ntoc as usize;
    let bytes = file
        .data
        .get(off..off + n * 8)
        .ok_or("truncated TOC")?;
    let strtab = file
        .data
        .get(st.stroff as usize..(st.stroff + st.strsize) as usize)
        .ok_or("truncated strtab")?;
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        let toc = DylibTableOfContents::read_from_bytes(chunk).map_err(|_| "toc")?;
        let name = sym_name(file, st, strtab, toc.symbol_index);
        println!("[{i}] symbol {name} ({}) module {}", toc.symbol_index, toc.module_index);
    }
    Ok(())
}

fn dump_refs(file: &MachoFile<'_>) -> Result<(), String> {
    let dy = file.dysymtab().map_err(|e| e.to_string())?.ok_or("no LC_DYSYMTAB")?;
    let st = file.symtab().map_err(|e| e.to_string())?.ok_or("no LC_SYMTAB")?;
    println!("Reference table ({} entries)", dy.nextrefsyms);
    if dy.nextrefsyms == 0 {
        return Ok(());
    }
    let off = dy.extrefsymoff as usize;
    let n = dy.nextrefsyms as usize;
    let bytes = file
        .data
        .get(off..off + n * 4)
        .ok_or("truncated refs")?;
    let strtab = file
        .data
        .get(st.stroff as usize..(st.stroff + st.strsize) as usize)
        .ok_or("truncated strtab")?;
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let r = DylibReference::read_from_bytes(chunk).map_err(|_| "ref")?;
        let name = sym_name(file, st, strtab, r.isym());
        println!("[{i}] {name} ({}) flags {}", r.isym(), r.flags());
    }
    Ok(())
}

fn dump_modules(file: &MachoFile<'_>) -> Result<(), String> {
    let dy = file.dysymtab().map_err(|e| e.to_string())?.ok_or("no LC_DYSYMTAB")?;
    let st = file.symtab().map_err(|e| e.to_string())?.ok_or("no LC_SYMTAB")?;
    println!("Module table ({} entries)", dy.nmodtab);
    if dy.nmodtab == 0 {
        return Ok(());
    }
    let off = dy.modtaboff as usize;
    let n = dy.nmodtab as usize;
    let ent = core::mem::size_of::<DylibModule64>();
    let bytes = file
        .data
        .get(off..off + n * ent)
        .ok_or("truncated modules")?;
    let strtab = file
        .data
        .get(st.stroff as usize..(st.stroff + st.strsize) as usize)
        .ok_or("truncated strtab")?;
    for (i, chunk) in bytes.chunks_exact(ent).enumerate() {
        let m = DylibModule64::read_from_bytes(chunk).map_err(|_| "module")?;
        let name = cstr_at(strtab, m.module_name as usize).unwrap_or("?");
        println!(
            "[{i}] {name}  extdef {}+{} ref {}+{} local {}+{}",
            m.iextdefsym, m.nextdefsym, m.irefsym, m.nrefsym, m.ilocalsym, m.nlocalsym
        );
    }
    Ok(())
}

fn dump_hints(file: &MachoFile<'_>) -> Result<(), String> {
    let Some(h) = file
        .load_commands()
        .map_err(|e| e.to_string())?
        .find_map(|c| match c {
            Ok((lc, body)) if lc.cmd == LC_TWOLEVEL_HINTS => {
                TwolevelHintsCommand::ref_from_prefix(body)
                    .ok()
                    .map(|(t, _)| *t)
            }
            _ => None,
        })
    else {
        println!("Two-level namespace hints (none)");
        return Ok(());
    };
    println!("Two-level namespace hints ({} entries)", h.nhints);
    let off = h.offset as usize;
    let n = h.nhints as usize;
    let bytes = file
        .data
        .get(off..off + n * 4)
        .ok_or("truncated hints")?;
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let v = u32::from_le_bytes(chunk.try_into().unwrap());
        let isub = v & 0xff;
        let itoc = v >> 8;
        println!("[{i}] isub_image {isub} itoc {itoc}");
    }
    Ok(())
}

fn dump_core_strings(file: &MachoFile<'_>) -> Result<(), String> {
    // MH_CORE: walk __DATA-like segments for C-string runs near stack; best-effort argv/env dump.
    if file.header.filetype != 4 {
        println!("(not MH_CORE; dumping printable C-strings from sections anyway)");
    } else {
        println!("Core file strings (argv/envp heuristic)");
    }
    let mut found = 0usize;
    for item in file.sections().map_err(|e| e.to_string())? {
        let (sect, seg) = item.map_err(|e| e.to_string())?;
        let segn = cstr16(&seg.segname);
        if !segn.contains("DATA") && sect.size > 0x100_000 {
            continue;
        }
        let Ok(data) = file.section_data(sect) else {
            continue;
        };
        let mut i = 0usize;
        while i < data.len() {
            if data[i] == 0 {
                i += 1;
                continue;
            }
            let start = i;
            while i < data.len() && data[i] != 0 && i - start < 4096 {
                i += 1;
            }
            if let Ok(s) = core::str::from_utf8(&data[start..i]) {
                if s.len() >= 2
                    && s.is_ascii()
                    && s.chars()
                        .all(|c| c.is_ascii_graphic() || c == ' ' || c == '\t')
                {
                    // Prefer path-like / KEY=val env
                    if s.starts_with('/') || s.contains('=') || s.starts_with("./") {
                        println!("  {s}");
                        found += 1;
                        if found >= 256 {
                            println!("  …");
                            return Ok(());
                        }
                    }
                }
            }
            i += 1;
        }
    }
    if found == 0 {
        println!("(no candidate argv/env strings)");
    }
    Ok(())
}

fn sym_name(file: &MachoFile<'_>, st: &SymtabCommand, strtab: &[u8], idx: u32) -> String {
    let entry = 16usize;
    let nl_off = st.symoff as usize + idx as usize * entry;
    let Some(raw) = file.data.get(nl_off..nl_off + 4) else {
        return "?".into();
    };
    let strx = u32::from_le_bytes(raw.try_into().unwrap()) as usize;
    cstr_at(strtab, strx).unwrap_or("?").to_string()
}

fn cstr_at(strings: &[u8], off: usize) -> Option<&str> {
    let rest = strings.get(off..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    core::str::from_utf8(&rest[..end]).ok().filter(|s| !s.is_empty())
}

fn dump_relocs(file: &MachoFile<'_>, verbose: bool) -> Result<(), String> {
    println!("Relocation information");
    for item in file.sections().map_err(|e| e.to_string())? {
        let (sect, seg) = item.map_err(|e| e.to_string())?;
        if sect.nreloc == 0 {
            continue;
        }
        println!(
            "relocation section {}{} nreloc={}",
            cstr16(&seg.segname),
            cstr16(&sect.sectname),
            sect.nreloc
        );
        let off = sect.reloff as usize;
        let n = sect.nreloc as usize;
        // relocation_info is 8 bytes
        let bytes = file
            .data
            .get(off..off + n * 8)
            .ok_or("truncated relocs")?;
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            let r_address = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
            let packed = u32::from_le_bytes(chunk[4..8].try_into().unwrap());
            let r_symbolnum = packed & 0x00ff_ffff;
            let r_pcrel = (packed >> 24) & 1;
            let r_length = (packed >> 25) & 3;
            let r_extern = (packed >> 27) & 1;
            let r_type = (packed >> 28) & 0xf;
            if verbose {
                println!(
                    "  [{i}] address {:#x} symbolnum {r_symbolnum} pcrel {r_pcrel} len {r_length} extern {r_extern} type {r_type}",
                    r_address
                );
            } else {
                println!(
                    "  {:#x} {r_symbolnum} {r_pcrel} {r_length} {r_extern} {r_type}",
                    r_address
                );
            }
        }
    }
    Ok(())
}

fn dump_indirect(file: &MachoFile<'_>) -> Result<(), String> {
    let Some(dy) = file.dysymtab().map_err(|e| e.to_string())? else {
        return Err("no LC_DYSYMTAB".into());
    };
    let Some(st) = file.symtab().map_err(|e| e.to_string())? else {
        return Err("no LC_SYMTAB".into());
    };
    println!("Indirect symbols");
    let off = dy.indirectsymoff as usize;
    let n = dy.nindirectsyms as usize;
    let table = file
        .data
        .get(off..off + n * 4)
        .ok_or("truncated indirect symbols")?;
    let strtab = file
        .data
        .get(st.stroff as usize..(st.stroff + st.strsize) as usize)
        .ok_or("truncated strtab")?;
    let syms_off = st.symoff as usize;
    let entry = 16usize; // nlist_64
    for (i, chunk) in table.chunks_exact(4).enumerate() {
        let idx = u32::from_le_bytes(chunk.try_into().unwrap());
        // INDIRECT_SYMBOL_LOCAL / ABS specials
        if idx == 0x8000_0000 {
            println!("[{i}] LOCAL");
            continue;
        }
        if idx == 0x4000_0000 {
            println!("[{i}] ABSOLUTE");
            continue;
        }
        if idx == 0xc000_0000 {
            println!("[{i}] LOCAL|ABSOLUTE");
            continue;
        }
        let name = if (idx as usize) < st.nsyms as usize {
            let nl_off = syms_off + idx as usize * entry;
            if let Some(raw) = file.data.get(nl_off..nl_off + 4) {
                let strx = u32::from_le_bytes(raw.try_into().unwrap()) as usize;
                strtab
                    .get(strx..)
                    .and_then(|s| {
                        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                        core::str::from_utf8(&s[..end]).ok()
                    })
                    .unwrap_or("?")
            } else {
                "?"
            }
        } else {
            "?"
        };
        println!("[{i}] {idx} {name}");
    }
    Ok(())
}

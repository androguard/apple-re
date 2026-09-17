mod class_dump;
mod otool;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apple_re::apple_metadata::{ObjcMetadata, SymbolTable};
use apple_re::disassemble_macho;
use apple_re::ipa_vfs::IpaVfs;
use apple_re::macho_core::{cstr16, DylibKind, MachoFile};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "apple-re",
    about = "Inspect and manipulate iOS IPA archives",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// otool(1)-compatible Mach-O / fat object dumper
    Otool(otool::OtoolArgs),
    /// Generate Objective-C headers from Mach-O (class-dump compatible)
    #[command(name = "class-dump")]
    ClassDump(class_dump::ClassDumpArgs),
    /// Decompile an ARM64 function to C-like source (arm_decompiler)
    Decompile {
        /// IPA, Mach-O, or framework bundle
        file: PathBuf,
        /// Symbol name (e.g. `_main` or `-[Foo bar:]`). Required unless `--all`.
        #[arg(short = 'n', long, required_unless_present_any = ["all", "objc_methods", "swift_methods"])]
        symbol: Option<String>,
        /// Decompile every text-section symbol into `--out`
        #[arg(long)]
        all: bool,
        /// Output directory for `--all` (also used for single-symbol file write)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also decompile every ObjC method IMP (class-dump + bodies)
        #[arg(long)]
        objc_methods: bool,
        /// Decompile every Swift-mangled (`$s` / `_$s`) text symbol into `--out` as `.swift`
        #[arg(long)]
        swift_methods: bool,
        /// Emit JSON (CFG / IR / source) instead of or alongside C
        #[arg(long)]
        json: bool,
        /// Print value-flow findings (source→sink)
        #[arg(long)]
        findings: bool,
        /// Show asm as IR comments
        #[arg(long)]
        asm: bool,
        /// Decompilation mode: restructure (default), simple, or fallback
        #[arg(long, value_name = "MODE", default_value = "restructure")]
        mode: String,
        /// Alias for `--mode simple`
        #[arg(long)]
        simple: bool,
        /// Rename identifiers: `old=new` (repeatable). Symbols (`_foo`), selectors (`hello:`), else variables.
        #[arg(long = "rename", value_name = "OLD=NEW")]
        renames: Vec<String>,
        /// Optional selector map file for shared/DSC methnames (`VA name` or `VA=name` per line).
        #[arg(long = "sel-map", value_name = "FILE")]
        sel_map: Option<PathBuf>,
        /// Architecture from a universal binary
        #[arg(long)]
        arch: Option<String>,
    },
    /// List files inside an IPA
    List {
        ipa: PathBuf,
        /// Only show paths under Payload/*.app/
        #[arg(long)]
        app_only: bool,
    },
    /// Bundle + main Mach-O summary (uuid, encryption, checksec, …)
    Info {
        ipa: PathBuf,
        /// Also print linked dylibs / rpaths
        #[arg(long)]
        verbose: bool,
    },
    /// Extract files from an IPA to a directory
    Extract {
        ipa: PathBuf,
        /// Output directory
        #[arg(short, long)]
        out: PathBuf,
        /// Extract only the main executable
        #[arg(long)]
        main: bool,
        /// Extract only embedded framework Mach-Os
        #[arg(long)]
        frameworks: bool,
        /// Extract a specific IPA path (repeatable)
        #[arg(long = "path")]
        paths: Vec<String>,
    },
    /// Print one IPA entry to stdout
    Cat {
        ipa: PathBuf,
        /// Path inside the IPA (e.g. Payload/App.app/Info.plist)
        path: String,
    },
    /// Disassemble ARM64 `__TEXT.__text`
    Disasm {
        ipa: PathBuf,
        /// Max instructions to print
        #[arg(short = 'n', long, default_value_t = 64)]
        count: usize,
        /// Framework name (e.g. Foo.framework); default = main executable
        #[arg(long)]
        framework: Option<String>,
    },
    /// List ObjC classes / methods from the main binary
    Objc {
        ipa: PathBuf,
        /// Also print method names
        #[arg(long)]
        methods: bool,
        #[arg(long)]
        framework: Option<String>,
    },
    /// Dump symbols from the main binary
    Symbols {
        ipa: PathBuf,
        #[arg(long)]
        framework: Option<String>,
        /// Only print imported (undefined) symbols
        #[arg(long)]
        imports: bool,
    },
    /// Dump embedded entitlements XML (if code-signed)
    Entitlements {
        ipa: PathBuf,
        #[arg(long)]
        framework: Option<String>,
    },
    /// Add or overwrite a file inside the IPA and write a new archive
    Add {
        ipa: PathBuf,
        /// Destination path inside the IPA
        path: String,
        /// Local file to insert
        #[arg(long)]
        file: PathBuf,
        /// Output IPA path
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Remove a file from the IPA and write a new archive
    Rm {
        ipa: PathBuf,
        /// Path inside the IPA to remove
        path: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Replace the main executable (or a framework Mach-O) and write a new archive
    ReplaceBin {
        ipa: PathBuf,
        /// Local Mach-O file
        #[arg(long)]
        file: PathBuf,
        /// Framework name; default replaces the main executable
        #[arg(long)]
        framework: Option<String>,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Repack the IPA as a stored ZIP (normalize)
    Pack {
        ipa: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Otool(args) => otool::run(&args),
        Commands::ClassDump(args) => class_dump::run(&args),
        Commands::Decompile {
            file,
            symbol,
            all,
            out,
            objc_methods,
            swift_methods,
            json,
            findings,
            asm,
            mode,
            simple,
            renames,
            sel_map,
            arch,
        } => cmd_decompile(
            &file,
            symbol.as_deref(),
            all,
            out.as_deref(),
            objc_methods,
            swift_methods,
            json,
            findings,
            asm,
            &mode,
            simple,
            &renames,
            sel_map.as_deref(),
            arch.as_deref(),
        ),
        Commands::List { ipa, app_only } => cmd_list(&ipa, app_only),
        Commands::Info { ipa, verbose } => cmd_info(&ipa, verbose),
        Commands::Extract {
            ipa,
            out,
            main,
            frameworks,
            paths,
        } => cmd_extract(&ipa, &out, main, frameworks, &paths),
        Commands::Cat { ipa, path } => cmd_cat(&ipa, &path),
        Commands::Disasm {
            ipa,
            count,
            framework,
        } => cmd_disasm(&ipa, count, framework.as_deref()),
        Commands::Objc {
            ipa,
            methods,
            framework,
        } => cmd_objc(&ipa, methods, framework.as_deref()),
        Commands::Symbols {
            ipa,
            framework,
            imports,
        } => cmd_symbols(&ipa, framework.as_deref(), imports),
        Commands::Entitlements { ipa, framework } => {
            cmd_entitlements(&ipa, framework.as_deref())
        }
        Commands::Add {
            ipa,
            path,
            file,
            out,
        } => cmd_add(&ipa, &path, &file, &out),
        Commands::Rm { ipa, path, out } => cmd_rm(&ipa, &path, &out),
        Commands::ReplaceBin {
            ipa,
            file,
            framework,
            out,
        } => cmd_replace_bin(&ipa, &file, framework.as_deref(), &out),
        Commands::Pack { ipa, out } => cmd_pack(&ipa, &out),
    }
}

fn open_ipa(path: &Path) -> Result<IpaVfs, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    IpaVfs::open(&bytes).map_err(|e| e.to_string())
}

fn resolve_macho<'a>(
    vfs: &'a IpaVfs,
    framework: Option<&str>,
) -> Result<(&'a [u8], String), String> {
    let bundle = vfs.bundle().map_err(|e| e.to_string())?;
    if let Some(name) = framework {
        let key = if name.ends_with(".framework") {
            name.to_string()
        } else {
            format!("{name}.framework")
        };
        let data = bundle
            .frameworks
            .get(&key)
            .copied()
            .ok_or_else(|| format!("framework not found: {key}"))?;
        Ok((data, key))
    } else {
        let path = vfs.main_executable_path().map_err(|e| e.to_string())?;
        Ok((bundle.main_executable, path))
    }
}

fn cmd_list(ipa: &Path, app_only: bool) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    let prefix = vfs.app_prefix();
    for (path, data) in vfs.files() {
        if app_only && !path.starts_with(prefix) {
            continue;
        }
        println!("{:>10}  {path}", human_size(data.len()));
    }
    Ok(())
}

fn cmd_info(ipa: &Path, verbose: bool) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    let bundle = vfs.bundle().map_err(|e| e.to_string())?;
    let main_path = vfs.main_executable_path().map_err(|e| e.to_string())?;

    println!("ipa:          {}", ipa.display());
    println!("bundle id:    {}", bundle.bundle_id);
    println!("app prefix:   {}", bundle.app_prefix);
    println!(
        "main:         {main_path} ({} bytes)",
        bundle.main_executable.len()
    );
    println!("files:        {}", vfs.files().len());
    println!("frameworks:   {}", bundle.frameworks.len());
    for name in bundle.frameworks.keys() {
        println!("  - {name}");
    }

    let file = MachoFile::parse(bundle.main_executable).map_err(|e| e.to_string())?;
    println!();
    println!("=== main Mach-O ===");
    print_macho_summary(&file, verbose)?;
    Ok(())
}

fn print_macho_summary(file: &MachoFile<'_>, verbose: bool) -> Result<(), String> {
    if let Some(uuid) = file.uuid().map_err(|e| e.to_string())? {
        println!("uuid:         {}", format_uuid(&uuid));
    }
    if let Some(ep) = file.entry_point().map_err(|e| e.to_string())? {
        println!(
            "entryoff:     {:#x}  (stack {:#x})",
            ep.entryoff, ep.stacksize
        );
    }
    if let Some(b) = file.build_version().map_err(|e| e.to_string())? {
        let plat = b.platform_name.unwrap_or("?");
        println!(
            "platform:     {plat}  minOS {}.{}.{}  sdk {}.{}.{}",
            b.min_os.0, b.min_os.1, b.min_os.2, b.sdk.0, b.sdk.1, b.sdk.2
        );
    }
    if let Some(sv) = file.source_version().map_err(|e| e.to_string())? {
        println!(
            "source ver:   {}.{}.{}.{}.{}",
            sv.0, sv.1, sv.2, sv.3, sv.4
        );
    }
    if let Some(enc) = file.encryption_info().map_err(|e| e.to_string())? {
        println!(
            "encryption:   cryptid={}  off={:#x}  size={:#x}  encrypted={}",
            enc.cryptid,
            enc.cryptoff,
            enc.cryptsize,
            enc.is_encrypted()
        );
    } else {
        println!("encryption:   (none)");
    }

    let chk = file.checksec().map_err(|e| e.to_string())?;
    println!(
        "checksec:     pie={} nx_stack={} nx_heap={} canary={} arc={} signed={} fairplay={}",
        chk.pie,
        chk.nx_stack,
        chk.nx_heap,
        chk.stack_canary,
        chk.arc,
        chk.code_signed,
        chk.encrypted_fairplay
    );

    if let Some(cs) = file.code_signature().map_err(|e| e.to_string())? {
        if let Some(cd) = &cs.code_directory {
            println!(
                "codesign id:  {}  team={}",
                cd.identifier.unwrap_or("-"),
                cd.team_id.unwrap_or("-")
            );
        }
        println!(
            "ents:         xml={} der={}",
            cs.entitlements_xml.is_some(),
            cs.entitlements_der.is_some()
        );
    }

    let mut segs = 0usize;
    let mut sects = 0usize;
    for s in file.segments().map_err(|e| e.to_string())? {
        let (seg, _) = s.map_err(|e| e.to_string())?;
        segs += 1;
        sects += seg.nsects as usize;
        if verbose {
            println!(
                "  seg {:<16} vm={:#x}+{:#x} file={:#x}+{:#x} prot={}/{}",
                cstr16(&seg.segname),
                seg.vmaddr,
                seg.vmsize,
                seg.fileoff,
                seg.filesize,
                seg.initprot,
                seg.maxprot
            );
        }
    }
    println!("segments:     {segs}  sections: {sects}");

    if verbose {
        let dylibs = file.dylibs().map_err(|e| e.to_string())?;
        println!("dylibs:       {}", dylibs.len());
        for d in &dylibs {
            let kind = match d.kind {
                DylibKind::Load => "load",
                DylibKind::Weak => "weak",
                DylibKind::Reexport => "reexport",
                DylibKind::Lazy => "lazy",
                DylibKind::Upward => "upward",
                DylibKind::Id => "id",
            };
            println!("  [{kind}] {}", d.name);
        }
        let rpaths = file.rpaths().map_err(|e| e.to_string())?;
        if !rpaths.is_empty() {
            println!("rpaths:");
            for r in rpaths {
                println!("  {r}");
            }
        }
    }
    Ok(())
}

fn cmd_extract(
    ipa: &Path,
    out: &Path,
    main_only: bool,
    frameworks_only: bool,
    paths: &[String],
) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    fs::create_dir_all(out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;

    if !paths.is_empty() {
        for p in paths {
            let data = vfs
                .get(p)
                .ok_or_else(|| format!("path not in IPA: {p}"))?;
            write_extracted(out, p, data)?;
        }
        return Ok(());
    }

    if main_only {
        let path = vfs.main_executable_path().map_err(|e| e.to_string())?;
        let data = vfs.get(&path).ok_or("missing main executable")?;
        let name = Path::new(&path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("main");
        let dest = out.join(name);
        fs::write(&dest, data).map_err(|e| format!("write {}: {e}", dest.display()))?;
        println!("wrote {}", dest.display());
        return Ok(());
    }

    if frameworks_only {
        let bundle = vfs.bundle().map_err(|e| e.to_string())?;
        let fw_dir = out.join("Frameworks");
        fs::create_dir_all(&fw_dir).map_err(|e| e.to_string())?;
        for (name, data) in &bundle.frameworks {
            let stem = name.trim_end_matches(".framework");
            let dest = fw_dir.join(stem);
            fs::write(&dest, data).map_err(|e| format!("write {}: {e}", dest.display()))?;
            println!("wrote {}", dest.display());
        }
        return Ok(());
    }

    for (path, data) in vfs.files() {
        write_extracted(out, path, data)?;
    }
    println!(
        "extracted {} files to {}",
        vfs.files().len(),
        out.display()
    );
    Ok(())
}

fn write_extracted(out: &Path, ipa_path: &str, data: &[u8]) -> Result<(), String> {
    let dest = out.join(ipa_path);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(&dest, data).map_err(|e| format!("write {}: {e}", dest.display()))?;
    Ok(())
}

fn cmd_cat(ipa: &Path, path: &str) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    let data = vfs
        .get(path)
        .ok_or_else(|| format!("path not in IPA: {path}"))?;
    io::stdout()
        .write_all(data)
        .map_err(|e| format!("stdout: {e}"))?;
    Ok(())
}

fn cmd_disasm(ipa: &Path, count: usize, framework: Option<&str>) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    let (macho, label) = resolve_macho(&vfs, framework)?;
    println!("; disasm {label} (first {count} insns)");
    let lines = disassemble_macho(macho, count)?;
    for line in lines {
        println!("{:016x}:  {:08x}  {}", line.vaddr, line.raw, line.text);
    }
    Ok(())
}

fn cmd_decompile(
    path: &Path,
    symbol: Option<&str>,
    all: bool,
    out_dir: Option<&Path>,
    objc_methods: bool,
    swift_methods: bool,
    as_json: bool,
    show_findings: bool,
    show_asm: bool,
    mode: &str,
    simple: bool,
    renames: &[String],
    sel_map: Option<&Path>,
    arch: Option<&str>,
) -> Result<(), String> {
    use apple_re::arm_decompiler::{
        decompile_macho_all, decompile_macho_symbol, function_to_json, is_swift_mangled,
        list_macho_functions, parse_mode, parse_selector_map_text, rename_map_from_pairs,
        symbol_to_filename, DecompilationMode, DecompilerOptions,
    };
    use apple_re::apple_metadata::{dump_all, DumpOptions, ObjcMetadata};
    use apple_re::macho_core::MachoFile;

    let bytes = load_macho_bytes(path)?;
    let file = MachoFile::parse_arch(&bytes, arch).map_err(|e| e.to_string())?;
    let thin = file.data.to_vec();
    let mut mode = parse_mode(mode).ok_or_else(|| {
        format!("unknown --mode '{mode}' (expected restructure|simple|fallback)")
    })?;
    if simple {
        mode = DecompilationMode::Simple;
    }
    let rename_map = if renames.is_empty() {
        None
    } else {
        Some(rename_map_from_pairs(renames)?)
    };
    let selector_map = if let Some(p) = sel_map {
        let text = fs::read_to_string(p).map_err(|e| format!("read --sel-map: {e}"))?;
        parse_selector_map_text(&text)?
    } else {
        Vec::new()
    };
    let opts = DecompilerOptions {
        mode,
        show_asm_comments: show_asm,
        show_labels: matches!(mode, DecompilationMode::Simple | DecompilationMode::Fallback),
        rename_map,
        selector_map,
        ..DecompilerOptions::default()
    };

    if swift_methods {
        let out = out_dir.ok_or("--swift-methods requires --out <dir>")?;
        fs::create_dir_all(out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;
        let listed = list_macho_functions(&thin).map_err(|e| e.to_string())?;
        let mut ok = 0usize;
        for (_va, name) in listed {
            if !is_swift_mangled(&name) {
                continue;
            }
            // Skip metadata / type descriptors that are not callable bodies.
            if name.ends_with("Ma") || name.ends_with("Mn") || name.ends_with("Metadata") {
                continue;
            }
            match decompile_macho_symbol(&thin, &name, &opts) {
                Ok(f) => {
                    let stem = symbol_to_filename(&name);
                    fs::write(out.join(format!("{stem}.swift")), &f.source)
                        .map_err(|e| format!("write {stem}.swift: {e}"))?;
                    if as_json {
                        fs::write(out.join(format!("{stem}.json")), function_to_json(&f))
                            .map_err(|e| e.to_string())?;
                    }
                    ok += 1;
                }
                Err(e) => eprintln!("skip {name}: {e}"),
            }
        }
        eprintln!("wrote {ok} Swift function bodies → {}", out.display());
        return Ok(());
    }

    if objc_methods {
        let out = out_dir.ok_or("--objc-methods requires --out <dir>")?;
        fs::create_dir_all(out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;
        let meta = ObjcMetadata::parse(&file).map_err(|e| e.to_string())?;
        let headers = dump_all(&meta, &DumpOptions::default());
        fs::write(out.join("Classes.h"), &headers)
            .map_err(|e| format!("write Classes.h: {e}"))?;
        let listed = list_macho_functions(&thin).map_err(|e| e.to_string())?;
        let mut ok = 0usize;
        for (_va, name) in listed {
            if !(name.starts_with("-[") || name.starts_with("+[")) {
                continue;
            }
            match decompile_macho_symbol(&thin, &name, &opts) {
                Ok(f) => {
                    let stem = symbol_to_filename(&name);
                    fs::write(out.join(format!("{stem}.m")), &f.source)
                        .map_err(|e| format!("write {stem}.m: {e}"))?;
                    if as_json {
                        fs::write(out.join(format!("{stem}.json")), function_to_json(&f))
                            .map_err(|e| e.to_string())?;
                    }
                    ok += 1;
                }
                Err(e) => eprintln!("skip {name}: {e}"),
            }
        }
        eprintln!("wrote Classes.h + {ok} ObjC method bodies → {}", out.display());
        return Ok(());
    }

    if all {
        let out = out_dir.ok_or("--all requires --out <dir>")?;
        fs::create_dir_all(out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;
        let results = decompile_macho_all(&thin, &opts).map_err(|e| e.to_string())?;
        let mut ok = 0usize;
        let mut fail = 0usize;
        let mut nfindings = 0usize;
        for (name, res) in results {
            let stem = symbol_to_filename(&name);
            match res {
                Ok(f) => {
                    nfindings += f.findings.len();
                    let c_path = out.join(format!("{stem}.c"));
                    fs::write(&c_path, &f.source)
                        .map_err(|e| format!("write {}: {e}", c_path.display()))?;
                    if as_json {
                        let j_path = out.join(format!("{stem}.json"));
                        fs::write(&j_path, function_to_json(&f))
                            .map_err(|e| format!("write {}: {e}", j_path.display()))?;
                    }
                    if show_findings {
                        for finding in &f.findings {
                            println!("{name}: {}", finding.detail);
                        }
                    }
                    ok += 1;
                }
                Err(e) => {
                    eprintln!("skip {name}: {e}");
                    fail += 1;
                }
            }
        }
        eprintln!(
            "decompiled {ok} ok, {fail} skipped, {nfindings} findings → {}",
            out.display()
        );
        return Ok(());
    }

    let symbol = symbol.ok_or("-n/--symbol is required unless --all/--objc-methods")?;
    let result = decompile_macho_symbol(&thin, symbol, &opts).map_err(|e| e.to_string())?;
    if show_findings {
        for finding in &result.findings {
            println!("{}", finding.detail);
        }
        if result.findings.is_empty() {
            eprintln!("(no value-flow findings)");
        }
    }
    if let Some(dir) = out_dir {
        fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        let stem = symbol_to_filename(symbol);
        if as_json {
            let j_path = dir.join(format!("{stem}.json"));
            fs::write(&j_path, function_to_json(&result))
                .map_err(|e| format!("write {}: {e}", j_path.display()))?;
        } else {
            let c_path = dir.join(format!("{stem}.c"));
            fs::write(&c_path, &result.source)
                .map_err(|e| format!("write {}: {e}", c_path.display()))?;
        }
    } else if as_json {
        print!("{}", function_to_json(&result));
    } else if !show_findings {
        print!("{}", result.source);
    }
    Ok(())
}

fn load_macho_bytes(path: &Path) -> Result<Vec<u8>, String> {
    if path.is_dir() {
        return class_dump_load_framework(path);
    }
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ipa"))
        || (bytes.len() >= 2 && &bytes[..2] == b"PK")
    {
        if let Ok(vfs) = IpaVfs::open(&bytes) {
            if let Ok(bundle) = vfs.bundle() {
                return Ok(bundle.main_executable.to_vec());
            }
        }
    }
    Ok(bytes)
}

fn class_dump_load_framework(dir: &Path) -> Result<Vec<u8>, String> {
    let name = dir
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("bad framework path")?;
    let candidates = [
        dir.join(name),
        dir.join("Versions/Current").join(name),
        dir.join("Versions/A").join(name),
        dir.join("Versions/C").join(name),
    ];
    for c in &candidates {
        if let Ok(bytes) = fs::read(c) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
    }
    Err(format!("framework binary not found in {}", dir.display()))
}

fn cmd_objc(ipa: &Path, methods: bool, framework: Option<&str>) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    let (macho, _) = resolve_macho(&vfs, framework)?;
    let file = MachoFile::parse(macho).map_err(|e| e.to_string())?;
    let meta = ObjcMetadata::parse(&file).map_err(|e| e.to_string())?;
    for class in &meta.classes {
        println!("{}", class.name);
        if methods {
            for m in &class.class_methods {
                println!("  + {}  (imp {:#x})", m.name, m.imp);
            }
            for m in &class.methods {
                println!("  - {}  (imp {:#x})", m.name, m.imp);
            }
        }
    }
    for cat in &meta.categories {
        println!("{} ({})", cat.class_name, cat.name);
    }
    for p in &meta.protocols {
        println!("@protocol {}", p.name);
    }
    println!(
        "; {} classes, {} categories, {} protocols",
        meta.classes.len(),
        meta.categories.len(),
        meta.protocols.len()
    );
    Ok(())
}

fn cmd_symbols(ipa: &Path, framework: Option<&str>, imports: bool) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    let (macho, _) = resolve_macho(&vfs, framework)?;
    let file = MachoFile::parse(macho).map_err(|e| e.to_string())?;
    if imports {
        for name in file.imported_symbols().map_err(|e| e.to_string())? {
            println!("{name}");
        }
        return Ok(());
    }
    let syms = SymbolTable::from_macho(&file).map_err(|e| e.to_string())?;
    for (addr, name) in syms.iter() {
        println!("{addr:016x}  {name}");
    }
    println!("; {} symbols", syms.len());
    Ok(())
}

fn cmd_entitlements(ipa: &Path, framework: Option<&str>) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    let (macho, _) = resolve_macho(&vfs, framework)?;
    let file = MachoFile::parse(macho).map_err(|e| e.to_string())?;
    let Some(cs) = file.code_signature().map_err(|e| e.to_string())? else {
        return Err("no LC_CODE_SIGNATURE".into());
    };
    if let Some(xml) = cs.entitlements_xml {
        io::stdout()
            .write_all(xml)
            .map_err(|e| format!("stdout: {e}"))?;
        if !xml.ends_with(b"\n") {
            println!();
        }
        Ok(())
    } else {
        Err("no embedded entitlements XML".into())
    }
}

fn cmd_add(ipa: &Path, path: &str, file: &Path, out: &Path) -> Result<(), String> {
    let mut vfs = open_ipa(ipa)?;
    let data = fs::read(file).map_err(|e| format!("read {}: {e}", file.display()))?;
    vfs.insert(path.to_string(), data);
    write_ipa(&vfs, out)
}

fn cmd_rm(ipa: &Path, path: &str, out: &Path) -> Result<(), String> {
    let mut vfs = open_ipa(ipa)?;
    if vfs.remove(path).is_none() {
        return Err(format!("path not in IPA: {path}"));
    }
    write_ipa(&vfs, out)
}

fn cmd_replace_bin(
    ipa: &Path,
    file: &Path,
    framework: Option<&str>,
    out: &Path,
) -> Result<(), String> {
    let mut vfs = open_ipa(ipa)?;
    let dest = if let Some(name) = framework {
        let key = if name.ends_with(".framework") {
            name.to_string()
        } else {
            format!("{name}.framework")
        };
        let stem = key.trim_end_matches(".framework");
        format!("{}Frameworks/{key}/{stem}", vfs.app_prefix())
    } else {
        vfs.main_executable_path().map_err(|e| e.to_string())?
    };
    let data = fs::read(file).map_err(|e| format!("read {}: {e}", file.display()))?;
    vfs.insert(dest.clone(), data);
    println!("replaced {dest}");
    write_ipa(&vfs, out)
}

fn cmd_pack(ipa: &Path, out: &Path) -> Result<(), String> {
    let vfs = open_ipa(ipa)?;
    write_ipa(&vfs, out)
}

fn write_ipa(vfs: &IpaVfs, out: &Path) -> Result<(), String> {
    let bytes = vfs.to_bytes().map_err(|e| e.to_string())?;
    fs::write(out, &bytes).map_err(|e| format!("write {}: {e}", out.display()))?;
    println!(
        "wrote {} ({} bytes, {} files)",
        out.display(),
        bytes.len(),
        vfs.files().len()
    );
    Ok(())
}

fn format_uuid(u: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
        u[14], u[15]
    )
}

fn human_size(n: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    let n = n as f64;
    if n >= MB {
        format!("{:.1}M", n / MB)
    } else if n >= KB {
        format!("{:.1}K", n / KB)
    } else {
        format!("{n}")
    }
}

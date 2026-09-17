//! class-dump-compatible Objective-C header generator.
//!
//! Inspired by [nygard/class-dump](https://github.com/nygard/class-dump) and
//! [blacktop/ipsw class-dump](https://github.com/blacktop/ipsw/blob/master/cmd/ipsw/cmd/class_dump.go).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use apple_re::apple_metadata::{
    diff_objc, dump_all, format_category, format_class, format_protocol, DumpOptions, ObjcMetadata,
    ObjcRefs,
};
use apple_re::ipa_vfs::IpaVfs;
use apple_re::macho_core::{fat_arches, is_fat, MachoFile};
use clap::Args;

#[derive(Args, Debug)]
pub struct ClassDumpArgs {
    /// Show instance variable offsets (`-a`, nygard)
    #[arg(short = 'a')]
    pub ivar_offsets: bool,
    /// Show implementation addresses (`-A` / ipsw `--re`)
    #[arg(short = 'A', long = "re")]
    pub imp_addresses: bool,
    /// Architecture from a universal binary
    #[arg(long = "arch")]
    pub arch: Option<String>,
    /// Only display classes matching regex (`-C` / ipsw `--class`)
    #[arg(short = 'C', long = "class")]
    pub class_regex: Option<String>,
    /// Only display protocols matching regex (ipsw `--proto`)
    #[arg(long = "proto")]
    pub proto_regex: Option<String>,
    /// Only display categories matching regex (ipsw `--cat`)
    #[arg(long = "cat")]
    pub cat_regex: Option<String>,
    /// Find string in method name
    #[arg(short = 'f')]
    pub find_method: Option<String>,
    /// Generate header files (`-H` / ipsw `--headers`)
    #[arg(short = 'H', long = "headers")]
    pub headers: bool,
    /// Sort by inheritance (`-I`, overrides `-s`)
    #[arg(short = 'I')]
    pub sort_inheritance: bool,
    /// Output directory for `-H`
    #[arg(short = 'o', long = "output")]
    pub output_dir: Option<PathBuf>,
    /// Recursively expand IPA frameworks / linked images when possible (`-r`)
    #[arg(short = 'r')]
    pub recursive: bool,
    /// Sort classes and categories by name (`-s`)
    #[arg(short = 's')]
    pub sort_name: bool,
    /// Sort methods by name (`-S`)
    #[arg(short = 'S')]
    pub sort_methods: bool,
    /// Suppress banner header (`-t`)
    #[arg(short = 't')]
    pub suppress_banner: bool,
    /// Dump ObjC class/super/proto/selector refs (ipsw `--refs`)
    #[arg(long = "refs")]
    pub refs: bool,
    /// Structurally diff ObjC against another Mach-O / IPA / framework (ipsw `--diff`)
    #[arg(long = "diff")]
    pub diff: Option<PathBuf>,
    /// List arches in the file, then exit
    #[arg(long = "list-arches")]
    pub list_arches: bool,
    /// Mach-O file, framework bundle, or IPA
    pub file: PathBuf,
}

pub fn run(args: &ClassDumpArgs) -> Result<(), String> {
    if args.diff.is_some() && (args.headers || args.refs) {
        return Err("--diff cannot be combined with --headers/-H or --refs".into());
    }
    if args.headers
        && (args.class_regex.is_some() || args.proto_regex.is_some() || args.cat_regex.is_some())
    {
        return Err("cannot combine --headers/-H with --class/--proto/--cat filters".into());
    }

    let bytes = load_bytes(&args.file)?;

    if args.list_arches {
        return list_arches(&bytes);
    }

    let opts = DumpOptions {
        show_ivar_offsets: args.ivar_offsets,
        show_imp_addresses: args.imp_addresses,
        sort_by_name: args.sort_name,
        sort_methods: args.sort_methods,
        sort_by_inheritance: args.sort_inheritance,
        suppress_banner: args.suppress_banner,
    };

    if let Some(old_path) = &args.diff {
        return run_diff(args, &bytes, old_path);
    }

    let file = MachoFile::parse_arch(&bytes, args.arch.as_deref()).map_err(|e| e.to_string())?;

    if args.refs {
        let refs = ObjcRefs::parse(&file).map_err(|e| e.to_string())?;
        print!("{}", refs.format());
        // Still dump classes unless filters imply refs-only; match ipsw: refs after dump
    }

    let mut metas = Vec::new();
    metas.push((
        label_for(&args.file),
        ObjcMetadata::parse(&file).map_err(|e| e.to_string())?,
    ));

    if args.recursive {
        if let Ok(extra) = load_recursive_frameworks(&args.file) {
            for (name, data) in extra {
                if let Ok(mf) = MachoFile::parse_arch(&data, args.arch.as_deref()) {
                    if let Ok(meta) = ObjcMetadata::parse(&mf) {
                        metas.push((name, meta));
                    }
                }
            }
        }
    }

    let class_re = args
        .class_regex
        .as_ref()
        .map(|p| regex_simple(p))
        .transpose()?;
    let proto_re = args
        .proto_regex
        .as_ref()
        .map(|p| regex_simple(p))
        .transpose()?;
    let cat_re = args
        .cat_regex
        .as_ref()
        .map(|p| regex_simple(p))
        .transpose()?;

    let selective = class_re.is_some() || proto_re.is_some() || cat_re.is_some();

    let multi = metas.len() > 1;
    for (label, mut meta) in metas {
        filter_meta(
            &mut meta,
            class_re.as_ref(),
            proto_re.as_ref(),
            cat_re.as_ref(),
            selective,
            args.find_method.as_deref(),
        );
        if meta.classes.is_empty() && meta.categories.is_empty() && meta.protocols.is_empty() {
            continue;
        }
        if args.headers {
            write_headers(&label, &meta, &opts, args.output_dir.as_deref())?;
        } else {
            if !opts.suppress_banner && multi {
                println!("// ---- {} ----", label);
            }
            let text = dump_all(&meta, &opts);
            io::stdout()
                .write_all(text.as_bytes())
                .map_err(|e| format!("stdout: {e}"))?;
        }
    }
    Ok(())
}

fn run_diff(args: &ClassDumpArgs, newer_bytes: &[u8], old_path: &Path) -> Result<(), String> {
    let older_bytes = load_bytes(old_path)?;
    let newer = MachoFile::parse_arch(newer_bytes, args.arch.as_deref()).map_err(|e| e.to_string())?;
    let older = MachoFile::parse_arch(&older_bytes, args.arch.as_deref()).map_err(|e| e.to_string())?;
    let new_meta = ObjcMetadata::parse(&newer).map_err(|e| e.to_string())?;
    let old_meta = ObjcMetadata::parse(&older).map_err(|e| e.to_string())?;
    let name = label_for(&args.file);
    print!("{}", diff_objc(&name, &old_meta, &new_meta));
    Ok(())
}

fn label_for(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("binary")
        .to_string()
}

fn list_arches(bytes: &[u8]) -> Result<(), String> {
    if is_fat(bytes) {
        for a in fat_arches(bytes).map_err(|e| e.to_string())? {
            println!("{}", a.arch_name());
        }
    } else {
        let file = MachoFile::parse_arch(bytes, None).map_err(|e| e.to_string())?;
        println!(
            "{}",
            apple_re::macho_core::arch_name(file.header.cputype, file.header.cpusubtype)
        );
    }
    Ok(())
}

fn load_bytes(path: &Path) -> Result<Vec<u8>, String> {
    // Framework bundle → Versions/Current/Name or Name
    if path.is_dir() {
        return load_framework_binary(path);
    }
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    // IPA → main
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("ipa"))
        || (bytes.len() >= 4 && &bytes[..2] == b"PK")
    {
        if let Ok(vfs) = IpaVfs::open(&bytes) {
            if let Ok(bundle) = vfs.bundle() {
                return Ok(bundle.main_executable.to_vec());
            }
        }
    }
    Ok(bytes)
}

fn load_framework_binary(dir: &Path) -> Result<Vec<u8>, String> {
    let name = dir
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("bad framework path")?;
    let mut candidates = vec![
        dir.join(name),
        dir.join("Versions/Current").join(name),
        dir.join("Versions/A").join(name),
        dir.join("Versions/C").join(name),
    ];
    if let Ok(entries) = fs::read_dir(dir.join("Versions")) {
        for e in entries.flatten() {
            candidates.push(e.path().join(name));
        }
    }
    for c in &candidates {
        // Prefer real files; broken dyld-cache stubs fail the read and we keep looking.
        if let Ok(bytes) = fs::read(c) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
    }
    Err(format!(
        "framework binary not found in {} (on recent macOS, system frameworks may live only in the dyld shared cache)",
        dir.display()
    ))
}

fn load_recursive_frameworks(path: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut out = Vec::new();
    if let Ok(vfs) = IpaVfs::open(&bytes) {
        if let Ok(bundle) = vfs.bundle() {
            for (name, data) in &bundle.frameworks {
                out.push((name.clone(), data.to_vec()));
            }
        }
    }
    Ok(out)
}

fn filter_meta(
    meta: &mut ObjcMetadata,
    class_re: Option<&SimpleRe>,
    proto_re: Option<&SimpleRe>,
    cat_re: Option<&SimpleRe>,
    selective: bool,
    find_method: Option<&str>,
) {
    if selective {
        // ipsw-style: each filter applies to its own kind; unspecified kinds are dropped
        // when any of --class/--proto/--cat is set. `-C` alone still matches all kinds
        // (nygard behavior) unless --proto/--cat are also used.
        let nygard_combined = class_re.is_some() && proto_re.is_none() && cat_re.is_none();
        if nygard_combined {
            let re = class_re.unwrap();
            meta.classes.retain(|c| re.is_match(&c.name));
            meta.categories
                .retain(|c| re.is_match(&c.class_name) || re.is_match(&c.name));
            meta.protocols.retain(|p| re.is_match(&p.name));
        } else {
            if let Some(re) = class_re {
                meta.classes.retain(|c| re.is_match(&c.name));
            } else {
                meta.classes.clear();
            }
            if let Some(re) = proto_re {
                meta.protocols.retain(|p| re.is_match(&p.name));
            } else {
                meta.protocols.clear();
            }
            if let Some(re) = cat_re {
                meta.categories
                    .retain(|c| re.is_match(&c.class_name) || re.is_match(&c.name));
            } else {
                meta.categories.clear();
            }
        }
    }
    if let Some(needle) = find_method {
        let has = |methods: &[apple_re::apple_metadata::ObjcMethod]| {
            methods.iter().any(|m| m.name.contains(needle))
        };
        meta.classes.retain(|c| has(&c.methods) || has(&c.class_methods));
        meta.categories
            .retain(|c| has(&c.methods) || has(&c.class_methods));
        for c in &mut meta.classes {
            c.methods.retain(|m| m.name.contains(needle));
            c.class_methods.retain(|m| m.name.contains(needle));
        }
        for c in &mut meta.categories {
            c.methods.retain(|m| m.name.contains(needle));
            c.class_methods.retain(|m| m.name.contains(needle));
        }
    }
}

fn write_headers(
    label: &str,
    meta: &ObjcMetadata,
    opts: &DumpOptions,
    out_dir: Option<&Path>,
) -> Result<(), String> {
    let dir = out_dir.unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let _ = label;
    for c in &meta.classes {
        let path = dir.join(format!("{}.h", sanitize_filename(&c.name)));
        let text = format_class(c, opts);
        fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        println!("wrote {}", path.display());
    }
    for cat in &meta.categories {
        let path = dir.join(format!(
            "{}-{}.h",
            sanitize_filename(&cat.class_name),
            sanitize_filename(&cat.name)
        ));
        let text = format_category(cat, opts);
        fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        println!("wrote {}", path.display());
    }
    for p in &meta.protocols {
        let path = dir.join(format!("{}.h", sanitize_filename(&p.name)));
        let text = format_protocol(p, opts);
        fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// Minimal regex: supports `.*`, `.`, and literal chars (enough for `-C`).
struct SimpleRe {
    pattern: String,
}

fn regex_simple(pat: &str) -> Result<SimpleRe, String> {
    Ok(SimpleRe {
        pattern: pat.to_string(),
    })
}

impl SimpleRe {
    fn is_match(&self, text: &str) -> bool {
        // Convert simple glob-ish regex to matching
        let pat = self.pattern.as_str();
        if pat == ".*" || pat == "^.*$" {
            return true;
        }
        // Escape-aware: treat as substring if no regex metachars beyond .*
        if !pat.contains('.') && !pat.contains('*') && !pat.contains('^') && !pat.contains('$') {
            return text.contains(pat);
        }
        match_glob_regex(pat, text)
    }
}

fn match_glob_regex(pat: &str, text: &str) -> bool {
    // Very small matcher: anchors optional, `.` any char, `.*` any sequence
    let anchored_start = pat.starts_with('^');
    let anchored_end = pat.ends_with('$');
    let mut p = pat;
    if anchored_start {
        p = &p[1..];
    }
    if anchored_end {
        p = &p[..p.len() - 1];
    }
    let candidates: Vec<&str> = if anchored_start {
        vec![text]
    } else {
        (0..=text.len()).map(|i| &text[i..]).collect()
    };
    for cand in candidates {
        if match_from(p, cand, anchored_end) {
            return true;
        }
        if anchored_start {
            break;
        }
    }
    false
}

fn match_from(pat: &str, text: &str, must_end: bool) -> bool {
    let pb = pat.as_bytes();
    let tb = text.as_bytes();
    let mut pi = 0usize;
    let mut ti = 0usize;
    while pi < pb.len() {
        if pi + 1 < pb.len() && pb[pi] == b'.' && pb[pi + 1] == b'*' {
            pi += 2;
            if pi == pb.len() {
                return !must_end || true;
            }
            while ti <= tb.len() {
                if match_from(&pat[pi..], &text[ti..], must_end) {
                    return true;
                }
                if ti == tb.len() {
                    break;
                }
                ti += 1;
            }
            return false;
        }
        if pb[pi] == b'.' {
            if ti >= tb.len() {
                return false;
            }
            pi += 1;
            ti += 1;
            continue;
        }
        if ti >= tb.len() || pb[pi] != tb[ti] {
            return false;
        }
        pi += 1;
        ti += 1;
    }
    if must_end {
        ti == tb.len()
    } else {
        true
    }
}

# apple-re

Pure Rust iOS IPA reverse-engineering toolkit: open an IPA in memory, parse Mach-O, walk ObjC/symbols, and disassemble ARM64.

- `#![no_std]` + `alloc` (no `std::fs` / `std::path` in the libraries)
- Targets native and `wasm32-unknown-unknown`
- Zero-allocation ARM64 decode (iced-style decoder ≠ formatter)
- No external disassembly crates

## Crates

| Crate | Role |
|-------|------|
| [`apple_re`](crates/apple_re) | Umbrella + `disassemble_ipa_main` / `disassemble_macho` |
| [`ipa_vfs`](crates/ipa_vfs) | In-memory ZIP/IPA VFS, Info.plist, main binary + frameworks |
| [`macho_core`](crates/macho_core) | Zero-copy Mach-O / fat parse, sections, `vaddr_to_offset` |
| [`apple_metadata`](crates/apple_metadata) | ObjC `__objc_classlist`, symbol table, class-dump |
| [`arm_disassembler`](https://github.com/androguard/arm_disassembler) | ARM64 decoder + formatter (sibling: `../arm_disassembler`) |
| [`arm_decompiler`](https://github.com/androguard/arm_decompiler) | ARM64 → C-like decompiler (sibling repo: `../arm_decompiler`) |
| [`apple_re_cli`](crates/apple_re_cli) | `apple-re` CLI (inspect / extract / mutate IPA) |

## CLI

```bash
cargo run -p apple_re_cli -- info App.ipa
cargo run -p apple_re_cli -- list App.ipa
cargo run -p apple_re_cli -- extract App.ipa -o out/ --main
cargo run -p apple_re_cli -- disasm App.ipa -n 32
cargo run -p apple_re_cli -- add App.ipa Payload/App.app/extra.txt --file ./extra.txt -o out.ipa
cargo run -p apple_re_cli -- rm App.ipa Payload/App.app/extra.txt -o out.ipa
cargo run -p apple_re_cli -- replace-bin App.ipa --file ./App -o out.ipa

# otool(1)-compatible dumps (see docs/OTOOL_PARITY.md)
cargo run -p apple_re_cli -- otool -hv -L /usr/bin/true
cargo run -p apple_re_cli -- otool -tv -p _main App.ipa
cargo run -p apple_re_cli -- otool -f -v --arch all /bin/ls

# class-dump-compatible ObjC headers
# nygard: https://github.com/nygard/class-dump
# ipsw extras: https://github.com/blacktop/ipsw/blob/master/cmd/ipsw/cmd/class_dump.go
cargo run -p apple_re_cli -- class-dump App.ipa -s -S
cargo run -p apple_re_cli -- class-dump App.ipa -H -o ./headers
cargo run -p apple_re_cli -- class-dump Foo.framework --list-arches
cargo run -p apple_re_cli -- class-dump ./MyBinary -C 'MyClass' -a -A -t
cargo run -p apple_re_cli -- class-dump ./MyBinary --proto 'NSCopying' --cat 'MyClass'
cargo run -p apple_re_cli -- class-dump ./MyBinary --refs -t
cargo run -p apple_re_cli -- class-dump ./New.app/MyBinary --diff ./Old.app/MyBinary

# ARM64 function decompiler (see ../arm_decompiler/docs/ARM_DECOMPILER.md)
cargo run -p apple_re_cli -- decompile ./MyBinary -n _main
cargo run -p apple_re_cli -- decompile App.ipa -n _main --asm

# Decompiler fixture scoreboard (run in sibling ../arm_decompiler)
(cd ../arm_decompiler && cargo test --test decompiler_tests scoreboard -- --nocapture)
```


Install the binary:

```bash
cargo install --path crates/apple_re_cli
apple-re --help
```

Depend on the umbrella, or pull individual crates:

```toml
[dependencies]
apple_re = { path = "crates/apple_re" }
# or:
# ipa_vfs = { path = "crates/ipa_vfs" }
# macho_core = { path = "crates/macho_core" }
# apple_metadata = { path = "crates/apple_metadata" }
# arm_disassembler = { path = "../arm_disassembler" }
# arm_decompiler = { path = "../arm_decompiler" }
```

## Build

```bash
cargo build --workspace
cargo build -p apple_re --target wasm32-unknown-unknown
```

## Quick start — disassemble an IPA

Pass IPA (or Mach-O) **bytes**; the library never opens files itself.

```rust
use apple_re::{disassemble_ipa_main, disassemble_macho};

fn dump_ipa(ipa: &[u8]) {
    // First N instructions of the main executable __TEXT.__text
    let lines = disassemble_ipa_main(ipa, 64).expect("disasm");
    for line in lines {
        println!("{:016x}:  {:08x}  {}", line.vaddr, line.raw, line.text);
    }
}

fn dump_macho(macho: &[u8]) {
    let lines = disassemble_macho(macho, 64).expect("disasm");
    for line in &lines {
        println!("{}", line.text);
    }
}
```

With `std` in your binary / host tool:

```rust
let ipa = std::fs::read("App.ipa")?;
let lines = apple_re::disassemble_ipa_main(&ipa, 128)?;
```

## Lower-level usage

### IPA → main binary

```rust
use ipa_vfs::IpaVfs;

let vfs = IpaVfs::open(ipa_bytes)?;
let bundle = vfs.bundle()?;
println!("bundle id: {}", bundle.bundle_id);
let macho = bundle.main_executable; // &[u8]
// bundle.frameworks: name → Mach-O bytes
```

### Mach-O sections

```rust
use macho_core::MachoFile;

let file = MachoFile::parse(macho_bytes)?;
let text = file.find_section("__TEXT", "__text")?.expect("__text");
let code = file.section_data(text)?;
let off = file.vaddr_to_offset(text.addr)?;
```

### Symbols & ObjC

```rust
use apple_metadata::{ObjcMetadata, SymbolTable};
use macho_core::MachoFile;

let file = MachoFile::parse(macho_bytes)?;
let symbols = SymbolTable::from_macho(&file)?;
if let Some(name) = symbols.get_symbol_str_at_vaddr(0x100004000) {
    println!("{name}");
}

let objc = ObjcMetadata::parse(&file)?;
for class in &objc.classes {
    println!("{}", class.name);
}
```

### ARM64 decode / format

```rust
use arm_disassembler::{decode_raw, Decoder, Formatter, SymbolResolver};

// Stream decode
let mut dec = Decoder::new(code, text_base_vaddr);
let fmt = Formatter::new();
while dec.can_decode() {
    let ins = dec.decode();
    println!("{}", fmt.format_simple(&ins));
}

// Single word
let ins = decode_raw(0x1000, 0xD503201F); // nop
assert_eq!(ins.mnemonic.as_str(), "nop");

// Optional symbol names in the formatter
struct Res;
impl SymbolResolver for Res {
    fn resolve(&self, vaddr: u64) -> Option<&str> {
        (vaddr == 0x100004000).then_some("_main")
    }
}
let text = Formatter::new().format(&ins, &Res);
```

## Tests

```bash
cargo test --workspace

# Capstone AArch64 MC corpus (mnemonic checks) — run in sibling ../arm_disassembler
(cd ../arm_disassembler && cargo test --test capstone_mc_tests)
```

Corpus notes: [`../arm_disassembler/tests/capstone_mc/README.md`](../arm_disassembler/tests/capstone_mc/README.md).

Coverage focus is A64 + scalar FP; AdvSIMD / SVE / SME still have gaps versus Capstone.

## Design notes

- **IPA as `&[u8]`** — suitable for WASM and embedded hosts; load bytes outside the library.
- **Decoder vs formatter** — decode fills a flat `Instruction`; formatting (and symbol lookup) is separate and allocates only when you ask for a `String`.
- **Fat binaries** — `MachoFile::parse` selects the appropriate slice; section/vaddr APIs work on the active thin image.

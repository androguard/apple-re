//! Structural ObjC metadata diff (ipsw-style added/removed/changed).

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::objc::{ObjcCategory, ObjcClass, ObjcMetadata, ObjcMethod, ObjcProtocol};

/// Diff `newer` against `older` (newer is the left/“after” side).
pub fn diff_objc(name: &str, older: &ObjcMetadata, newer: &ObjcMetadata) -> String {
    let mut out = String::new();
    out.push_str(&format!("# ObjC diff: {name}\n\n```diff\n"));
    out.push_str(&diff_classes(&index_classes(older), &index_classes(newer)));
    out.push('\n');
    out.push_str(&diff_protocols(
        &index_protocols(older),
        &index_protocols(newer),
    ));
    out.push('\n');
    out.push_str(&diff_categories(
        &index_categories(older),
        &index_categories(newer),
    ));
    out.push_str("```\n");
    out
}

fn index_classes(m: &ObjcMetadata) -> BTreeMap<String, &ObjcClass> {
    m.classes.iter().map(|c| (c.name.clone(), c)).collect()
}

fn index_protocols(m: &ObjcMetadata) -> BTreeMap<String, &ObjcProtocol> {
    m.protocols.iter().map(|p| (p.name.clone(), p)).collect()
}

fn index_categories(m: &ObjcMetadata) -> BTreeMap<String, &ObjcCategory> {
    m.categories
        .iter()
        .map(|c| (format!("{}({})", c.class_name, c.name), c))
        .collect()
}

fn method_keys(inst: &[ObjcMethod], class: &[ObjcMethod]) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for m in inst {
        keys.insert(format!("-{}", m.name));
    }
    for m in class {
        keys.insert(format!("+{}", m.name));
    }
    keys
}

fn class_keys(c: &ObjcClass) -> BTreeSet<String> {
    let mut keys = method_keys(&c.methods, &c.class_methods);
    for p in &c.protocols {
        keys.insert(format!("<{p}>"));
    }
    for iv in &c.ivars {
        keys.insert(format!("ivar:{}", iv.name));
    }
    for p in &c.properties {
        keys.insert(format!("prop:{}", p.name));
    }
    keys
}

fn protocol_keys(p: &ObjcProtocol) -> BTreeSet<String> {
    let mut keys = method_keys(&p.methods, &p.class_methods);
    for m in &p.optional_methods {
        keys.insert(format!("-?{}", m.name));
    }
    for m in &p.optional_class_methods {
        keys.insert(format!("+?{}", m.name));
    }
    for pr in &p.protocols {
        keys.insert(format!("<{pr}>"));
    }
    keys
}

fn category_keys(c: &ObjcCategory) -> BTreeSet<String> {
    method_keys(&c.methods, &c.class_methods)
}

fn diff_classes(
    prev: &BTreeMap<String, &ObjcClass>,
    next: &BTreeMap<String, &ObjcClass>,
) -> String {
    diff_section(
        "Classes",
        prev,
        next,
        |c| class_keys(c),
        |c| {
            format!(
                "{} : {} ({} methods)",
                c.name,
                c.superclass.as_deref().unwrap_or("NSObject"),
                c.methods.len() + c.class_methods.len()
            )
        },
    )
}

fn diff_protocols(
    prev: &BTreeMap<String, &ObjcProtocol>,
    next: &BTreeMap<String, &ObjcProtocol>,
) -> String {
    diff_section("Protocols", prev, next, |p| protocol_keys(p), |p| p.name.clone())
}

fn diff_categories(
    prev: &BTreeMap<String, &ObjcCategory>,
    next: &BTreeMap<String, &ObjcCategory>,
) -> String {
    diff_section(
        "Categories",
        prev,
        next,
        |c| category_keys(c),
        |c| format!("{}({})", c.class_name, c.name),
    )
}

fn diff_section<T, FKeys, FLabel>(
    title: &str,
    prev: &BTreeMap<String, &T>,
    next: &BTreeMap<String, &T>,
    keys: FKeys,
    label: FLabel,
) -> String
where
    FKeys: Fn(&T) -> BTreeSet<String>,
    FLabel: Fn(&T) -> String,
{
    let mut out = String::new();
    out.push_str(&format!("### {title}\n"));

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for (name, n) in next {
        match prev.get(name) {
            None => added.push(label(n)),
            Some(p) => {
                let pk = keys(p);
                let nk = keys(n);
                if pk != nk {
                    let mut detail = format!("~ {}", label(n));
                    for k in nk.difference(&pk) {
                        detail.push_str(&format!("\n+   {k}"));
                    }
                    for k in pk.difference(&nk) {
                        detail.push_str(&format!("\n-   {k}"));
                    }
                    changed.push(detail);
                }
            }
        }
    }
    for (name, p) in prev {
        if !next.contains_key(name) {
            removed.push(label(p));
        }
    }

    for a in &added {
        out.push_str(&format!("+ {a}\n"));
    }
    for r in &removed {
        out.push_str(&format!("- {r}\n"));
    }
    for c in &changed {
        out.push_str(&format!("{c}\n"));
    }
    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        out.push_str("  (no changes)\n");
    }
    out
}

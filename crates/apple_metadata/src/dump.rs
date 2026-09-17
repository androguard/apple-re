//! Emit class-dump-style Objective-C headers from [`ObjcMetadata`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::encode::{format_ivar_decl, format_method_decl, format_property_decl};
use crate::objc::{ObjcCategory, ObjcClass, ObjcMetadata, ObjcProtocol};

#[derive(Debug, Clone, Copy)]
pub struct DumpOptions {
    pub show_ivar_offsets: bool,
    pub show_imp_addresses: bool,
    pub sort_by_name: bool,
    pub sort_methods: bool,
    pub sort_by_inheritance: bool,
    pub suppress_banner: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self {
            show_ivar_offsets: false,
            show_imp_addresses: false,
            sort_by_name: false,
            sort_methods: false,
            sort_by_inheritance: false,
            suppress_banner: false,
        }
    }
}

/// Render the full dump as a single string (stdout style).
pub fn dump_all(meta: &ObjcMetadata, opts: &DumpOptions) -> String {
    let mut classes = meta.classes.clone();
    let mut categories = meta.categories.clone();
    let mut protocols = meta.protocols.clone();

    if opts.sort_by_inheritance {
        classes = sort_by_inheritance(classes);
    } else if opts.sort_by_name {
        classes.sort_by(|a, b| a.name.cmp(&b.name));
        categories.sort_by(|a, b| (&a.class_name, &a.name).cmp(&(&b.class_name, &b.name)));
        protocols.sort_by(|a, b| a.name.cmp(&b.name));
    }
    if opts.sort_methods {
        for c in &mut classes {
            c.methods.sort_by(|a, b| a.name.cmp(&b.name));
            c.class_methods.sort_by(|a, b| a.name.cmp(&b.name));
        }
        for c in &mut categories {
            c.methods.sort_by(|a, b| a.name.cmp(&b.name));
            c.class_methods.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }

    let mut out = String::new();
    if !opts.suppress_banner {
        out.push_str("//\n// Generated with apple-re class-dump (class-dump compatible)\n");
        out.push_str("// https://github.com/nygard/class-dump\n//\n\n");
    }

    for p in &protocols {
        out.push_str(&format_protocol(p, opts));
        out.push('\n');
    }
    for c in &classes {
        out.push_str(&format_class(c, opts));
        out.push('\n');
    }
    for cat in &categories {
        out.push_str(&format_category(cat, opts));
        out.push('\n');
    }
    out
}

/// Header text for a single class (for `-H` file output).
pub fn format_class(c: &ObjcClass, opts: &DumpOptions) -> String {
    let mut out = String::new();
    let super_name = c.superclass.as_deref().unwrap_or("NSObject");
    if c.protocols.is_empty() {
        out.push_str(&format!("@interface {} : {}\n", c.name, super_name));
    } else {
        out.push_str(&format!(
            "@interface {} : {} <{}>\n",
            c.name,
            super_name,
            c.protocols.join(", ")
        ));
    }
    if !c.ivars.is_empty() {
        out.push_str("{\n");
        for iv in &c.ivars {
            let off = if opts.show_ivar_offsets {
                Some(iv.offset)
            } else {
                None
            };
            out.push_str(&format_ivar_decl(&iv.name, &iv.types, off));
            out.push('\n');
        }
        out.push_str("}\n");
    }
    for p in &c.properties {
        out.push_str(&format_property_decl(&p.name, &p.attributes));
        out.push('\n');
    }
    for m in &c.class_methods {
        let imp = if opts.show_imp_addresses {
            Some(m.imp)
        } else {
            None
        };
        out.push_str(&format_method_decl(true, &m.name, &m.types, imp));
        out.push('\n');
    }
    for m in &c.methods {
        let imp = if opts.show_imp_addresses {
            Some(m.imp)
        } else {
            None
        };
        out.push_str(&format_method_decl(false, &m.name, &m.types, imp));
        out.push('\n');
    }
    out.push_str("@end\n");
    out
}

pub fn format_category(c: &ObjcCategory, opts: &DumpOptions) -> String {
    let mut out = String::new();
    if c.protocols.is_empty() {
        out.push_str(&format!("@interface {} ({})\n", c.class_name, c.name));
    } else {
        out.push_str(&format!(
            "@interface {} ({}) <{}>\n",
            c.class_name,
            c.name,
            c.protocols.join(", ")
        ));
    }
    for p in &c.properties {
        out.push_str(&format_property_decl(&p.name, &p.attributes));
        out.push('\n');
    }
    for m in &c.class_methods {
        let imp = opts.show_imp_addresses.then_some(m.imp);
        out.push_str(&format_method_decl(true, &m.name, &m.types, imp));
        out.push('\n');
    }
    for m in &c.methods {
        let imp = opts.show_imp_addresses.then_some(m.imp);
        out.push_str(&format_method_decl(false, &m.name, &m.types, imp));
        out.push('\n');
    }
    out.push_str("@end\n");
    out
}

pub fn format_protocol(p: &ObjcProtocol, opts: &DumpOptions) -> String {
    let mut out = String::new();
    if p.protocols.is_empty() {
        out.push_str(&format!("@protocol {}\n", p.name));
    } else {
        out.push_str(&format!(
            "@protocol {} <{}>\n",
            p.name,
            p.protocols.join(", ")
        ));
    }
    for prop in &p.properties {
        out.push_str(&format_property_decl(&prop.name, &prop.attributes));
        out.push('\n');
    }
    if !p.methods.is_empty() || !p.class_methods.is_empty() {
        out.push_str("@required\n");
    }
    for m in &p.class_methods {
        let imp = opts.show_imp_addresses.then_some(m.imp);
        out.push_str(&format_method_decl(true, &m.name, &m.types, imp));
        out.push('\n');
    }
    for m in &p.methods {
        let imp = opts.show_imp_addresses.then_some(m.imp);
        out.push_str(&format_method_decl(false, &m.name, &m.types, imp));
        out.push('\n');
    }
    if !p.optional_methods.is_empty() || !p.optional_class_methods.is_empty() {
        out.push_str("@optional\n");
    }
    for m in &p.optional_class_methods {
        let imp = opts.show_imp_addresses.then_some(m.imp);
        out.push_str(&format_method_decl(true, &m.name, &m.types, imp));
        out.push('\n');
    }
    for m in &p.optional_methods {
        let imp = opts.show_imp_addresses.then_some(m.imp);
        out.push_str(&format_method_decl(false, &m.name, &m.types, imp));
        out.push('\n');
    }
    out.push_str("@end\n");
    out
}

fn sort_by_inheritance(mut classes: Vec<ObjcClass>) -> Vec<ObjcClass> {
    // Stable topological-ish: parents before children when both present.
    classes.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::with_capacity(classes.len());
    let mut remaining = classes;
    while !remaining.is_empty() {
        let mut progressed = false;
        let mut i = 0;
        while i < remaining.len() {
            let super_ok = remaining[i]
                .superclass
                .as_ref()
                .map(|s| {
                    s == "NSObject"
                        || out.iter().any(|c: &ObjcClass| &c.name == s)
                        || !remaining.iter().any(|c: &ObjcClass| &c.name == s)
                })
                .unwrap_or(true);
            if super_ok {
                out.push(remaining.remove(i));
                progressed = true;
            } else {
                i += 1;
            }
        }
        if !progressed {
            out.append(&mut remaining);
            break;
        }
    }
    out
}

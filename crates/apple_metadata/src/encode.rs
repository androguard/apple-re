//! Decode Objective-C type encodings into declaration fragments.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Format a full method type encoding into an ObjC method declaration line.
///
/// `is_class` selects `+` vs `-`.
pub fn format_method_decl(is_class: bool, name: &str, types: &str, show_imp: Option<u64>) -> String {
    let (ret, args) = split_method_types(types);
    let ret_s = format_type(&ret);
    let prefix = if is_class { '+' } else { '-' };
    let parts: Vec<&str> = name.split(':').filter(|s| !s.is_empty() || name.ends_with(':')).collect();
    // Rebuild using selectors: for "foo:bar:" parts are ["foo", "bar", ""]
    let sel_parts: Vec<&str> = if name.contains(':') {
        name.split(':').collect()
    } else {
        alloc::vec![name]
    };

    let mut out = alloc::format!("{prefix} ({ret_s})");
    // args[0] is self, args[1] is _cmd; remaining are parameters
    let params = if args.len() > 2 { &args[2..] } else { &[] };

    if !name.contains(':') {
        out.push_str(name);
    } else {
        let mut pi = 0usize;
        for (i, part) in sel_parts.iter().enumerate() {
            if part.is_empty() && i == sel_parts.len() - 1 {
                break;
            }
            out.push_str(part);
            out.push(':');
            let ty = params.get(pi).map(|t| format_type(t)).unwrap_or_else(|| String::from("id"));
            out.push_str(&alloc::format!("({ty})arg{pi}"));
            if i + 2 < sel_parts.len() || (i + 1 < sel_parts.len() && !sel_parts[i + 1].is_empty()) {
                out.push(' ');
            }
            pi += 1;
        }
    }
    out.push(';');
    if let Some(imp) = show_imp {
        if imp != 0 {
            out.push_str(&alloc::format!("  // Imp={imp:#x}"));
        }
    }
    let _ = parts;
    out
}

pub fn format_ivar_decl(name: &str, types: &str, show_offset: Option<u64>) -> String {
    let ty = format_type(types);
    let mut out = alloc::format!("    {ty} {name};");
    if let Some(off) = show_offset {
        out.push_str(&alloc::format!("  // {off:#x}"));
    }
    out
}

pub fn format_property_decl(name: &str, attributes: &str) -> String {
    let (ty, attrs) = parse_property_attrs(attributes);
    if attrs.is_empty() {
        alloc::format!("@property {ty} {name};")
    } else {
        alloc::format!("@property ({attrs}) {ty} {name};")
    }
}

/// Split method encoding into return type + list of argument type encodings.
pub fn split_method_types(types: &str) -> (String, Vec<String>) {
    let mut chars = types.chars().peekable();
    let ret = parse_one_type(&mut chars);
    // Skip frame/stack numbers between types
    skip_numbers(&mut chars);
    let mut args = Vec::new();
    while chars.peek().is_some() {
        let t = parse_one_type(&mut chars);
        if t.is_empty() {
            break;
        }
        args.push(t);
        skip_numbers(&mut chars);
    }
    (ret, args)
}

pub fn format_type(enc: &str) -> String {
    let mut chars = enc.chars().peekable();
    let t = parse_one_type(&mut chars);
    if t.is_empty() {
        String::from("id")
    } else {
        humanize(&t)
    }
}

fn humanize(enc: &str) -> String {
    let mut chars = enc.chars().peekable();
    match chars.peek().copied() {
        Some('v') => String::from("void"),
        Some('c') => String::from("char"),
        Some('C') => String::from("unsigned char"),
        Some('s') => String::from("short"),
        Some('S') => String::from("unsigned short"),
        Some('i') => String::from("int"),
        Some('I') => String::from("unsigned int"),
        Some('l') => String::from("long"),
        Some('L') => String::from("unsigned long"),
        Some('q') => String::from("long long"),
        Some('Q') => String::from("unsigned long long"),
        Some('f') => String::from("float"),
        Some('d') => String::from("double"),
        Some('B') => String::from("BOOL"),
        Some('*') => String::from("char *"),
        Some('#') => String::from("Class"),
        Some(':') => String::from("SEL"),
        Some('@') => {
            chars.next();
            if chars.peek() == Some(&'"') {
                chars.next();
                let mut name = String::new();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        break;
                    }
                    name.push(c);
                }
                if name.is_empty() {
                    String::from("id")
                } else {
                    alloc::format!("{name} *")
                }
            } else if chars.peek() == Some(&'?') {
                String::from("id /* block */")
            } else {
                String::from("id")
            }
        }
        Some('^') => {
            let inner = humanize(&enc[1..]);
            alloc::format!("{inner} *")
        }
        Some('[') => alloc::format!("/* array */ {enc}"),
        Some('{') => {
            // {Name=...} or {_Name=...}
            let body = &enc[1..enc.len().saturating_sub(1)];
            if let Some(eq) = body.find('=') {
                let name = &body[..eq];
                let name = name.trim_start_matches('_');
                if name.is_empty() {
                    String::from("struct")
                } else {
                    alloc::format!("struct {name}")
                }
            } else {
                alloc::format!("struct {body}")
            }
        }
        Some('(') => String::from("union"),
        Some('b') => String::from("unsigned int /* bitfield */"),
        Some('?') => String::from("/*unknown*/"),
        _ => enc.to_string(),
    }
}

fn parse_one_type<I: Iterator<Item = char>>(chars: &mut core::iter::Peekable<I>) -> String {
    while matches!(chars.peek(), Some('r' | 'n' | 'N' | 'o' | 'O' | 'R' | 'V' | 'A' | 'j')) {
        // qualifiers — skip for declaration type
        chars.next();
    }
    let Some(&c) = chars.peek() else {
        return String::new();
    };
    match c {
        'v' | 'c' | 'C' | 's' | 'S' | 'i' | 'I' | 'l' | 'L' | 'q' | 'Q' | 'f' | 'd' | 'B' | '*'
        | '#' | ':' | '?' => {
            chars.next();
            c.to_string()
        }
        '@' => {
            let mut s = String::from("@");
            chars.next();
            if chars.peek() == Some(&'"') {
                s.push('"');
                chars.next();
                while let Some(ch) = chars.next() {
                    s.push(ch);
                    if ch == '"' {
                        break;
                    }
                }
            } else if chars.peek() == Some(&'?') {
                s.push('?');
                chars.next();
            }
            s
        }
        '^' => {
            chars.next();
            let inner = parse_one_type(chars);
            alloc::format!("^{inner}")
        }
        '[' => {
            let mut s = String::from("[");
            chars.next();
            while let Some(ch) = chars.next() {
                s.push(ch);
                if ch == ']' {
                    break;
                }
            }
            s
        }
        '{' | '(' => {
            let open = c;
            let close = if c == '{' { '}' } else { ')' };
            let mut s = String::new();
            s.push(chars.next().unwrap());
            let mut depth = 1i32;
            while let Some(ch) = chars.next() {
                s.push(ch);
                if ch == open {
                    depth += 1;
                } else if ch == close {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            s
        }
        'b' => {
            let mut s = String::from("b");
            chars.next();
            while matches!(chars.peek(), Some('0'..='9')) {
                s.push(chars.next().unwrap());
            }
            s
        }
        _ => {
            chars.next();
            c.to_string()
        }
    }
}

fn skip_numbers<I: Iterator<Item = char>>(chars: &mut core::iter::Peekable<I>) {
    while matches!(chars.peek(), Some('0'..='9')) {
        chars.next();
    }
}

fn parse_property_attrs(attrs: &str) -> (String, String) {
    // T@"NSString",&,N,V_name  or  Ti,N,V_x
    let mut ty = String::from("id");
    let mut flags = Vec::new();
    for part in attrs.split(',') {
        if let Some(rest) = part.strip_prefix('T') {
            ty = format_type(rest);
        } else if part == "R" {
            flags.push("readonly");
        } else if part == "C" {
            flags.push("copy");
        } else if part == "&" {
            flags.push("strong");
        } else if part == "W" {
            flags.push("weak");
        } else if part == "N" {
            flags.push("nonatomic");
        } else if part.starts_with('G') {
            flags.push("getter");
        } else if part.starts_with('S') {
            flags.push("setter");
        }
    }
    (ty, flags.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_void_id() {
        let s = format_method_decl(false, "viewDidLoad", "v16@0:8", None);
        assert!(s.starts_with("- (void)viewDidLoad;"));
    }

    #[test]
    fn method_with_arg() {
        let s = format_method_decl(false, "setEnabled:", "v24@0:8B16", None);
        assert!(s.contains("setEnabled:"));
        assert!(s.contains("BOOL"));
    }

    #[test]
    fn id_class() {
        assert_eq!(format_type("@\"NSString\""), "NSString *");
        assert_eq!(format_type("@"), "id");
    }
}

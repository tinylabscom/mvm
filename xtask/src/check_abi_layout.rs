//! `xtask check-abi-layout`
//!
//! A `#[repr(C)]` type exists to match a layout defined somewhere else: a
//! kernel uapi header, a framework header, a C ABI another language reads.
//! Nothing in Rust ties the declaration to that external definition, so a
//! field added, reordered, or resized drifts silently and is discovered as
//! a misread value rather than a compile error — and because a same-size
//! reordering keeps `size_of` intact, a size-only assertion does not catch
//! the most common case.
//!
//! This gate requires every such type to carry a compile-time `size_of`
//! **and** `align_of` assertion in its own file, which turns drift into a
//! build failure. Field offsets are not machine-checkable here (the gate
//! cannot know which fields matter), so they are a review expectation
//! rather than a gate rule; the size + alignment pair is the floor.
//!
//! The gate ships with no exemption list on purpose. The first exemption
//! should require an argued pull request.

use crate::fs_walk::walk_files;
use anyhow::{Result, bail};
use std::path::Path;

/// Names of `repr(C)` items in `src` that lack a compile-time `size_of`
/// **and** `align_of` assertion somewhere in the same file.
///
/// The probe requires the measurement to appear on an `assert!` line, not
/// merely somewhere in the file: a doc comment reading "see
/// `size_of::<T>()`" is prose, and a scan that accepted it would report
/// green for a type with no contract at all.
fn missing_contracts(src: &str) -> Vec<String> {
    let asserted = |needle: &str| {
        src.lines()
            .any(|l| l.contains("assert!(") && l.contains(needle))
    };
    repr_c_item_names(src)
        .into_iter()
        .filter(|name| {
            let has_size = asserted(&format!("size_of::<{name}>()"));
            let has_align = asserted(&format!("align_of::<{name}>()"));
            !(has_size && has_align)
        })
        .collect()
}

/// Every `struct`/`union` name introduced under a `#[repr(C…)]` attribute.
///
/// Attribute lines between the repr and the item — derives, doc comments,
/// `cfg`s — are skipped, since they routinely sit in between.
fn repr_c_item_names(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut names = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if !(t.starts_with("#[repr(C)]") || t.starts_with("#[repr(C,")) {
            continue;
        }
        for follow in lines.iter().skip(i + 1).take(8) {
            let f = follow.trim();
            if f.is_empty() || f.starts_with('#') || f.starts_with("//") {
                continue;
            }
            if let Some(name) = item_name(f) {
                names.push(name);
            }
            break;
        }
    }
    names
}

/// `pub(crate) struct Foo {` -> `Foo`.
fn item_name(line: &str) -> Option<String> {
    let after = line
        .split_once("struct ")
        .or_else(|| line.split_once("union "))?
        .1;
    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

pub fn run(workspace: &Path) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut contracted = 0usize;

    walk_files(&workspace.join("crates"), &mut |path| {
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            return;
        }
        let Ok(src) = std::fs::read_to_string(path) else {
            return;
        };
        scanned += 1;
        let all = repr_c_item_names(&src);
        let missing = missing_contracts(&src);
        contracted += all.len() - missing.len();
        let rel = path.strip_prefix(workspace).unwrap_or(path);
        for name in missing {
            errors.push(format!(
                "{}: `{name}` is #[repr(C)] with no compile-time layout contract.\n         \
                 Add `const _: () = {{ use std::mem::{{align_of, offset_of, size_of}};\n         \
                 assert!(size_of::<{name}>() == N); assert!(align_of::<{name}>() == M); … }};`\n         \
                 with N and M derived from the header this type mirrors — read them out of\n         \
                 that header with cc/clang sizeof/offsetof/_Alignof, not off the Rust struct.\n         \
                 Asserting what the Rust definition already computes proves nothing.",
                rel.display()
            ));
        }
    })?;

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("[error] {e}");
        }
        bail!(
            "check-abi-layout: {} repr(C) type(s) without a layout contract",
            errors.len()
        );
    }

    eprintln!(
        "check-abi-layout: clean ({contracted} repr(C) type(s) contracted across {scanned} files)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repr_c_without_size_and_align_assertions_is_rejected() {
        let src = r#"
            #[repr(C)]
            pub struct Naked { pub a: u64 }
        "#;
        assert_eq!(missing_contracts(src), vec!["Naked".to_string()]);
    }

    #[test]
    fn repr_c_with_both_assertions_is_accepted() {
        let src = r#"
            #[repr(C)]
            pub struct Pinned { pub a: u64 }
            const _: () = {
                assert!(size_of::<Pinned>() == 8);
                assert!(align_of::<Pinned>() == 8);
            };
        "#;
        assert!(missing_contracts(src).is_empty());
    }

    #[test]
    fn size_assertion_alone_is_not_enough() {
        let src = r#"
            #[repr(C)]
            pub struct Half { pub a: u64 }
            const _: () = { assert!(size_of::<Half>() == 8); };
        "#;
        assert_eq!(missing_contracts(src), vec!["Half".to_string()]);
    }

    #[test]
    fn fully_qualified_mem_paths_count() {
        let src = r#"
            #[repr(C)]
            struct Q { a: u32 }
            const _: () = {
                assert!(std::mem::size_of::<Q>() == 4);
                assert!(core::mem::align_of::<Q>() == 4);
            };
        "#;
        assert!(missing_contracts(src).is_empty());
    }

    #[test]
    fn repr_c_packed_and_repr_c_align_are_both_in_scope() {
        let src = r#"
            #[repr(C, packed)]
            struct P { a: u8 }
            #[repr(C, align(8))]
            struct A { a: u8 }
        "#;
        let mut missing = missing_contracts(src);
        missing.sort();
        assert_eq!(missing, vec!["A".to_string(), "P".to_string()]);
    }

    #[test]
    fn derives_cfgs_and_docs_between_repr_and_item_are_skipped() {
        let src = r#"
            #[cfg(target_os = "linux")]
            #[repr(C)]
            #[derive(Clone, Copy, Default)]
            /// Doc comment.
            // Line comment.
            pub(crate) struct Spaced { a: u16 }
        "#;
        assert_eq!(missing_contracts(src), vec!["Spaced".to_string()]);
    }

    #[test]
    fn unions_are_in_scope() {
        let src = r#"
            #[repr(C)]
            union U { a: u32, b: f32 }
        "#;
        assert_eq!(missing_contracts(src), vec!["U".to_string()]);
    }

    #[test]
    fn a_type_named_only_in_prose_does_not_satisfy_the_gate() {
        // The shape most likely to fool a text scan: a comment that names
        // both measurements without asserting either.
        let src = r#"
            #[repr(C)]
            struct C1 { a: u64 }
            // See size_of::<C1>() and align_of::<C1>() in the header.
        "#;
        assert_eq!(missing_contracts(src), vec!["C1".to_string()]);
    }

    #[test]
    fn a_non_asserting_use_of_size_of_does_not_satisfy_the_gate() {
        // `size_of` is also used for real work — socklen arguments, buffer
        // sizing. Those uses are not contracts and must not count as one.
        let src = r#"
            #[repr(C)]
            struct C2 { a: u64 }
            fn bind_len() -> u32 { std::mem::size_of::<C2>() as u32 }
        "#;
        assert_eq!(missing_contracts(src), vec!["C2".to_string()]);
    }
}

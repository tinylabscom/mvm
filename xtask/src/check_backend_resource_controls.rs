//! `xtask check-backend-resource-controls`
//!
//! Every `BackendKind` must answer what it can bound. The exhaustive match in
//! `ResourceControls::for_backend` already makes a new variant a compile
//! error; this gate closes the way around that: a wildcard or bare-binding
//! arm, which would let a future backend silently inherit an answer nobody
//! chose for it.
//!
//! The function body is located by brace-depth counting, not by scanning for
//! the first unindented `}`: `for_backend` nests an `if cfg!(...) { } else {
//! }` inside one arm (CPU control is host-conditional, not kind-conditional,
//! because libkrun is a macOS workload default too), and a scan that stops at
//! the first bare `}` never reaches the arms that follow it.
//!
//! Rather than hardcode wildcard spellings, every *alternative* of every
//! arm's pattern (the text before its `=>`, split on top-level `|`) is
//! required to mention `BackendKind::` — the one thing every real, explicit
//! arm in this match does and a wildcard or bare binding, spelled any way,
//! never does. Checking the whole pattern as one string is not enough: an
//! or-pattern like `BackendKind::Mock | _` contains `BackendKind::`, so a
//! whole-pattern substring check waves it through even though it is a
//! catch-all — every *other* variant lands in that arm too. Splitting on `|`
//! first and checking each alternative on its own is what catches that.

use anyhow::{Result, bail};
use std::path::Path;

const CONTROLS_FILE: &str = "crates/mvm-contract/src/protocol/resource_controls.rs";
const FN_MARKER: &str = "pub const fn for_backend";
const ENUM_PATH: &str = "BackendKind::";

pub fn run(workspace: &Path) -> Result<()> {
    let path = workspace.join(CONTROLS_FILE);
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading {CONTROLS_FILE}: {e}"))?;
    let body = strip_comments(&raw);

    let fn_block = extract_marked_block(&body, FN_MARKER)
        .ok_or_else(|| anyhow::anyhow!("{CONTROLS_FILE} no longer defines for_backend"))?;

    // The parameter name has to come from the signature header, not the
    // body: the body's first `(` is `cfg!(target_os = "linux")`'s, not the
    // parameter list's, so reading it from `fn_block.body` would silently
    // derive the wrong binding name.
    let param = param_binding_name(fn_block.header).ok_or_else(|| {
        anyhow::anyhow!("{CONTROLS_FILE}'s for_backend has no parameter to read a binding from")
    })?;
    let match_marker = format!("match {param}");
    let match_block = extract_marked_block(fn_block.body, &match_marker).ok_or_else(|| {
        anyhow::anyhow!("{CONTROLS_FILE}'s for_backend no longer matches on its parameter")
    })?;

    for pattern in arm_patterns(match_block.body) {
        for alternative in pattern_alternatives(&pattern) {
            if alternative.trim().is_empty() {
                continue;
            }
            if !alternative.contains(ENUM_PATH) {
                bail!(
                    "for_backend has a match arm `{}` whose alternative `{}` never \
                     names {ENUM_PATH} — a wildcard or bare binding, alone or beside \
                     a real variant in an or-pattern. Every BackendKind variant must \
                     state its controls explicitly; inheriting a default nobody \
                     chose is exactly the dishonesty this seam exists to prevent.",
                    pattern.trim(),
                    alternative.trim()
                );
            }
        }
    }
    Ok(())
}

/// Drop `//` and `/* */` comments so prose that happens to mention
/// `BackendKind::` next to a wildcard or bare-binding arm can't be mistaken
/// for the arm naming it itself — `_ /* BackendKind::Mock */ =>` bypasses a
/// substring check that only strips line comments.
fn strip_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'/') {
            for c2 in chars.by_ref() {
                if c2 == '\n' {
                    out.push('\n');
                    break;
                }
            }
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = '\0';
            for c2 in chars.by_ref() {
                if prev == '*' && c2 == '/' {
                    break;
                }
                prev = c2;
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// A block found by locating `marker`, then the `{` that follows it: `header`
/// is the text between the marker and that brace (a function's parameter
/// list, or a `match`'s scrutinee), and `body` is the brace-depth-matched
/// `{ ... }`, inclusive. Depth counting — not a scan for the first unindented
/// `}` — is what survives a nested block like `for_backend`'s `if cfg!(...) {
/// } else { }`.
struct MarkedBlock<'a> {
    header: &'a str,
    body: &'a str,
}

fn extract_marked_block<'a>(haystack: &'a str, marker: &str) -> Option<MarkedBlock<'a>> {
    let marker_pos = haystack.find(marker)?;
    let open = haystack[marker_pos..].find('{')? + marker_pos;
    let mut depth = 0i32;
    for (offset, b) in haystack.as_bytes()[open..].iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(MarkedBlock {
                        header: &haystack[marker_pos..open],
                        body: &haystack[open..=open + offset],
                    });
                }
            }
            _ => {}
        }
    }
    None
}

/// The name bound by a function signature's first parameter, read out of the
/// signature itself so a rename of `for_backend`'s parameter doesn't desync
/// this gate from the `match` it's meant to check.
fn param_binding_name(fn_signature_header: &str) -> Option<&str> {
    let open_paren = fn_signature_header.find('(')?;
    let close_paren = fn_signature_header[open_paren..].find(')')? + open_paren;
    let params = &fn_signature_header[open_paren + 1..close_paren];
    let name = params.split(':').next()?.trim();
    if name.is_empty() { None } else { Some(name) }
}

/// Every top-level arm of a `{ ... }` match body, as the pattern text before
/// its `=>`. Depth counting over `{ } ( ) [ ]` is what keeps a comma inside an
/// arm's body (e.g. between `Self`'s fields) from being misread as the
/// separator between two arms.
fn arm_patterns(match_body: &str) -> Vec<String> {
    let inner = match_body
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(match_body);

    let mut arms = Vec::new();
    let mut depth = 0i32;
    let mut arm_start = 0usize;
    for (i, b) in inner.bytes().enumerate() {
        match b {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                push_arm_pattern(&mut arms, &inner[arm_start..i]);
                arm_start = i + 1;
            }
            _ => {}
        }
    }
    push_arm_pattern(&mut arms, &inner[arm_start..]);
    arms
}

/// The pattern half of one arm's raw text (before its `=>`). Empty text
/// (the tail after a match body's final trailing comma) yields no arm.
fn push_arm_pattern(arms: &mut Vec<String>, arm_text: &str) {
    if arm_text.trim().is_empty() {
        return;
    }
    if let Some((pattern, _arm_value)) = arm_text.split_once("=>") {
        arms.push(pattern.to_string());
    }
}

/// Every top-level alternative of a pattern, split on `|` at
/// `{ } ( ) [ ]`-depth zero. Every `BackendKind` variant matched here is a
/// unit variant, so no alternative can contain an unbalanced `|` nested
/// inside its own delimiters today — but the split is depth-aware anyway,
/// so a future tuple- or struct-patterned variant (whose own fields might
/// use `|` inside nested parens) would not silently defeat this rule.
fn pattern_alternatives(pattern: &str) -> Vec<String> {
    let mut alternatives = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, b) in pattern.bytes().enumerate() {
        match b {
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => depth -= 1,
            b'|' if depth == 0 => {
                alternatives.push(pattern[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    alternatives.push(pattern[start..].to_string());
    alternatives
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        run(&workspace).expect("the real for_backend match names every BackendKind explicitly");
    }

    #[test]
    fn missing_controls_file_fails_closed() {
        let tmp = fresh_tmp("missing-file");
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains(CONTROLS_FILE));
        cleanup(&tmp);
    }

    #[test]
    fn a_wildcard_arm_is_caught() {
        assert_arm_rejected(
            "wildcard",
            "_ => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn an_underscore_prefixed_named_binding_is_caught() {
        assert_arm_rejected(
            "underscore-named",
            "_kind => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_bare_binding_reusing_the_parameter_name_is_caught() {
        // `kind` (the parameter's own name) is a legal catch-all binding —
        // just as much a wildcard as `_`, and an easy one to reach for by
        // accident since it's already in scope.
        assert_arm_rejected(
            "bare-binding",
            "kind => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_differently_named_bare_binding_is_still_caught() {
        // Not just the parameter's own name — *any* identifier pattern that
        // never names BackendKind:: is a catch-all.
        assert_arm_rejected(
            "other-name",
            "other => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn unusual_spacing_before_the_arrow_is_still_caught() {
        assert_arm_rejected(
            "wide-spacing",
            "_  =>  Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_wildcard_split_across_a_newline_is_still_caught() {
        assert_arm_rejected(
            "newline-split",
            "_\n=> Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_real_variant_beside_a_wildcard_in_an_or_pattern_is_caught() {
        // `BackendKind::Mock | _` contains "BackendKind::" as a whole-pattern
        // substring, so a check that didn't split on `|` would wave this
        // through even though every variant besides Mock lands here silently.
        assert_arm_rejected(
            "or-pattern-wildcard-second",
            "BackendKind::Mock | _ => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_wildcard_first_in_an_or_pattern_is_caught() {
        assert_arm_rejected(
            "or-pattern-wildcard-first",
            "_ | BackendKind::Mock => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_bare_binding_beside_a_real_variant_in_an_or_pattern_is_caught() {
        assert_arm_rejected(
            "or-pattern-bare-binding",
            "BackendKind::Mock | k => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_block_comment_disguising_a_wildcard_is_caught() {
        // `_ /* BackendKind::Mock */ =>` contains "BackendKind::" only
        // inside a block comment; a check that only stripped `//` comments
        // would be fooled by it the same way the or-pattern case fools a
        // whole-pattern substring check.
        assert_arm_rejected(
            "block-comment-disguise",
            "_ /* BackendKind::Mock */ => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_legitimate_multi_variant_arm_is_accepted() {
        // The real production file has exactly this shape twice
        // (`Hvf | AppleContainer` and `Firecracker | Libkrun | Qemu`) — the
        // or-pattern fix must not turn a real multi-variant arm into a
        // false positive.
        let controls_body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Hvf | BackendKind::AppleContainer => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::SupervisorTimer,
            },
            BackendKind::Mock => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
        }
    }
"#;
        let tmp = write_controls_fixture("legitimate-multi-variant", controls_body);
        run(&tmp)
            .expect("a real multi-variant arm naming BackendKind:: on every alternative must pass");
        cleanup(&tmp);
    }

    #[test]
    fn a_wildcard_placed_after_the_nested_if_cfg_arm_is_still_caught() {
        // This is the exact shape that breaks a naive "scan to the first
        // `\n}`" extraction: the nested `if cfg!(...) { } else { }` inside
        // the first arm has its own (indented) closing braces, and only
        // depth counting reaches the wildcard arm that follows it.
        let controls_body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self {
                cpu: if cfg!(target_os = "linux") {
                    CpuControl::CgroupShare
                } else {
                    CpuControl::None
                },
                wall_clock: WallClockControl::SupervisorTimer,
            },
            _ => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },
        }
    }
"#;
        let tmp = write_controls_fixture("after-nested-if", controls_body);
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("never"));
        cleanup(&tmp);
    }

    #[test]
    fn a_wildcard_in_an_unrelated_nested_match_is_not_flagged() {
        // A wildcard is legitimate in a match that is not for_backend's own.
        // The gate must only look inside the braces owned by for_backend.
        let controls_body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
            BackendKind::Mock => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
        }
    }

    pub const fn unrelated_helper(n: u8) -> u8 {
        match n {
            0 => 0,
            _ => 1,
        }
    }
"#;
        let tmp = write_controls_fixture("unrelated-nested-match", controls_body);
        run(&tmp).expect("a wildcard outside for_backend's own match must not be flagged");
        cleanup(&tmp);
    }

    #[test]
    fn every_variant_explicit_passes() {
        let controls_body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
            BackendKind::Mock => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
        }
    }
"#;
        let tmp = write_controls_fixture("all-explicit", controls_body);
        run(&tmp).expect("every arm names BackendKind:: explicitly");
        cleanup(&tmp);
    }

    fn assert_arm_rejected(label: &str, wildcard_arm: &str) {
        let controls_body = format!(
            r#"
    pub const fn for_backend(kind: BackendKind) -> Self {{
        match kind {{
            BackendKind::Firecracker => Self {{
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            }},
            {wildcard_arm}
        }}
    }}
"#
        );
        let tmp = write_controls_fixture(label, &controls_body);
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("never"),
            "expected a rejection naming the missing BackendKind:: reference, got: {err}"
        );
        cleanup(&tmp);
    }

    fn fresh_tmp(label: &str) -> std::path::PathBuf {
        let tmp = std::env::temp_dir().join(format!(
            "xtask-check-backend-resource-controls-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        tmp
    }

    fn write_controls_fixture(label: &str, fn_body: &str) -> std::path::PathBuf {
        let tmp = fresh_tmp(label);
        let controls_path = tmp.join(CONTROLS_FILE);
        std::fs::create_dir_all(controls_path.parent().unwrap()).unwrap();
        let file = format!(
            "//! fixture\nuse crate::protocol::vm_backend::BackendKind;\n\nimpl ResourceControls {{\n{fn_body}\n}}\n"
        );
        std::fs::write(controls_path, file).unwrap();
        tmp
    }

    fn cleanup(tmp: &std::path::Path) {
        let _ = std::fs::remove_dir_all(tmp);
    }
}

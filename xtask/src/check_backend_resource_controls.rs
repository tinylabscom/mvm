//! `xtask check-backend-resource-controls`
//!
//! Every `BackendKind` must answer what it can bound and what it can observe.
//! The exhaustive matches in `ResourceControls::for_backend` and
//! `ResourceObservation::for_backend` already make a new variant a compile
//! error; this gate closes the way around that: a wildcard or bare-binding
//! arm, which would let a future backend silently inherit an answer nobody
//! chose for it.
//!
//! *Every* `for_backend` in the file is checked, and at least two must exist.
//! The original shape located its target with a first-match `find`, which
//! meant the moment the file grew a second exhaustive match the gate went on
//! inspecting only the first one and stayed green over an unchecked matrix.
//! The count floor is the other half of the same problem: a gate that passes
//! when a matrix has been deleted has stopped noticing that the matrix used
//! to exist.
//!
//! The function body is located by brace-depth counting, not by scanning for
//! the first unindented `}`: `for_backend` nests an `if cfg!(...) { } else {
//! }` inside one arm (CPU control is host-conditional, not kind-conditional,
//! because libkrun is a macOS workload default too), and a scan that stops at
//! the first bare `}` never reaches the arms that follow it.
//!
//! Rather than hardcode wildcard spellings, every *alternative* of every
//! arm's pattern (the text before its `=>`, split on top-level `|` and
//! recursively unwrapped through any matching parens) is required to mention
//! `BackendKind::` — the one thing every real, explicit arm in this match
//! does and a wildcard or bare binding, spelled any way, never does.
//! Checking the whole pattern as one string is not enough: an or-pattern
//! like `BackendKind::Mock | _` contains `BackendKind::`, so a whole-pattern
//! substring check waves it through even though it is a catch-all — every
//! *other* variant lands in that arm too. Splitting on `|` first and
//! checking each alternative on its own is what catches that. A single
//! split isn't enough either: `(BackendKind::Mock | _)` puts the `|` at
//! paren-depth one, so a depth-zero-only split treats the whole
//! parenthesized group as one alternative that still contains
//! `BackendKind::` from its first half. `pattern_alternatives` peels
//! matching outer parens before re-splitting, recursively, so arbitrary
//! nesting (`((BackendKind::Mock | _))`) can't hide a bare alternative
//! either.
//!
//! Comments and string literals are blanked first by the shared
//! [`crate::rust_source`] scanner. Comments alone are not enough: a guard arm
//! like `_ if reason == "BackendKind::Mock" =>` is a bare wildcard whose
//! pattern text names `BackendKind::` only inside a literal, and it passes a
//! scanner that reads strings as code. The scanner is shared with
//! `check-single-grants-projection` rather than copied — a second copy of
//! this text handling is what produced the hole in the first place.

use anyhow::{Result, bail};
use std::path::Path;

const CONTROLS_FILE: &str = "crates/mvm-contract/src/protocol/resource_controls.rs";
const FN_MARKER: &str = "pub const fn for_backend";
const ENUM_PATH: &str = "BackendKind::";
/// The control matrix and the observation matrix. Both are `for_backend`
/// blocks in this file, and neither may go missing without the gate saying so.
const MINIMUM_MATRICES: usize = 2;

pub fn run(workspace: &Path) -> Result<()> {
    let path = workspace.join(CONTROLS_FILE);
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading {CONTROLS_FILE}: {e}"))?;
    let body = crate::rust_source::blank_comments_and_strings(&raw);

    let fn_blocks = marked_blocks(&body, FN_MARKER);
    if fn_blocks.len() < MINIMUM_MATRICES {
        bail!(
            "{CONTROLS_FILE} must declare both the control and the observation matrix \
             as `{FN_MARKER}`; found {}. A matrix that has been deleted is a question \
             a new BackendKind no longer has to answer.",
            fn_blocks.len()
        );
    }

    for fn_block in fn_blocks {
        check_one_matrix(&fn_block)?;
    }
    Ok(())
}

/// Reject any arm of one `for_backend` match whose pattern has an alternative
/// that never names a `BackendKind` variant.
fn check_one_matrix(fn_block: &MarkedBlock<'_>) -> Result<()> {
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

/// A block found by locating `marker`, then the `{` that follows it: `header`
/// is the text between the marker and that brace (a function's parameter
/// list, or a `match`'s scrutinee), and `body` is the brace-depth-matched
/// `{ ... }`, inclusive. Depth counting — not a scan for the first unindented
/// `}` — is what survives a nested block like `for_backend`'s `if cfg!(...) {
/// } else { }`.
struct MarkedBlock<'a> {
    header: &'a str,
    body: &'a str,
    /// Absolute offset into the haystack one past the block's closing brace,
    /// so a walk over every occurrence of a marker can resume past this one.
    end: usize,
}

fn extract_marked_block<'a>(haystack: &'a str, marker: &str) -> Option<MarkedBlock<'a>> {
    let marker_pos = haystack.find(marker)?;
    block_at(haystack, marker_pos)
}

/// Every block in `haystack` introduced by `marker`, in source order.
///
/// A first-match lookup was the original shape, and it silently stopped
/// inspecting this file the moment it grew a second exhaustive match: the gate
/// stayed green while the new matrix went unchecked. Anything that must hold
/// for one `for_backend` must hold for all of them.
fn marked_blocks<'a>(haystack: &'a str, marker: &str) -> Vec<MarkedBlock<'a>> {
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = haystack[cursor..].find(marker) {
        let marker_pos = cursor + found;
        let Some(block) = block_at(haystack, marker_pos) else {
            break;
        };
        cursor = block.end;
        blocks.push(block);
    }
    blocks
}

/// The block introduced by a marker already located at `marker_pos`: the `{`
/// that follows it, brace-depth-matched to its close. Depth counting — not a
/// scan for the first unindented `}` — is what survives a nested block like
/// `for_backend`'s `if cfg!(...) { } else { }`, which both matrices contain.
fn block_at(haystack: &str, marker_pos: usize) -> Option<MarkedBlock<'_>> {
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
                        end: open + offset + 1,
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

/// Every leaf alternative of a pattern: split on `|` at `{ } ( ) [ ]`-depth
/// zero, then, for any resulting piece that is itself wrapped in one or more
/// matching outer paren pairs (`(BackendKind::Mock | _)`,
/// `((BackendKind::Mock | _))`), peel the parens and re-split the interior —
/// recursively, so nesting to any depth still bottoms out at real leaves.
fn pattern_alternatives(pattern: &str) -> Vec<String> {
    let mut alternatives = Vec::new();
    collect_alternatives(pattern, &mut alternatives);
    alternatives
}

/// Depth-first collection worker for `pattern_alternatives`. `text` is
/// peeled of any matching outer parens first — `(BackendKind::Mock | _)`
/// must be seen as the or-pattern `BackendKind::Mock | _`, not as one
/// alternative that happens to contain `BackendKind::` — and only then
/// split on its own top-level `|`. A piece with no top-level `|` left after
/// peeling is a genuine leaf and is recorded as-is.
fn collect_alternatives(text: &str, out: &mut Vec<String>) {
    let mut trimmed = text.trim();
    while let Some(inner) = strip_matching_outer_parens(trimmed) {
        trimmed = inner.trim();
    }
    let parts = split_top_level_alternatives(trimmed);
    if parts.len() <= 1 {
        out.push(trimmed.to_string());
        return;
    }
    for part in parts {
        collect_alternatives(&part, out);
    }
}

/// Every top-level alternative of a pattern, split on `|` at
/// `{ } ( ) [ ]`-depth zero. Every `BackendKind` variant matched here is a
/// unit variant, so no alternative can contain an unbalanced `|` nested
/// inside its own delimiters today — but the split is depth-aware anyway,
/// so a future tuple- or struct-patterned variant (whose own fields might
/// use `|` inside nested parens) would not silently defeat this rule.
fn split_top_level_alternatives(pattern: &str) -> Vec<String> {
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

/// If `s` is wrapped in one matching pair of outer parens — its first byte
/// is `(`, its last is `)`, and that opening paren's match is the closing
/// paren at the very end rather than one that closes early — returns the
/// text between them.
///
/// Checking that the first `(` *pairs with* the last `)` (not just that the
/// string starts and ends with those characters) is what keeps
/// `(A) | (B)` from being misread as one parenthesized group: its first `(`
/// closes right after `A`, long before the string ends, so this correctly
/// returns `None` and leaves the `|` between the two groups to be found by
/// `split_top_level_alternatives`. Requiring the string to *start* with `(`
/// at all (rather than stripping any paren found anywhere) is what keeps a
/// tuple-struct pattern like `Some(a | b)` from ever being unwrapped: it
/// starts with `S`, not `(`, so this returns `None` immediately and the `|`
/// inside `Some(...)` is correctly left alone as part of one bound value,
/// not treated as a `BackendKind` alternative separator.
fn strip_matching_outer_parens(s: &str) -> Option<&str> {
    if !s.starts_with('(') || !s.ends_with(')') || s.len() < 2 {
        return None;
    }
    let mut depth = 0i32;
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return if i == s.len() - 1 {
                        Some(&s[1..s.len() - 1])
                    } else {
                        None
                    };
                }
            }
            _ => {}
        }
    }
    None
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
    fn a_parenthesized_or_pattern_hiding_a_wildcard_is_caught() {
        // `(BackendKind::Mock | _)` puts the `|` at paren-depth one, so a
        // depth-zero-only split treats the whole group as one alternative
        // that still contains "BackendKind::" from its first half.
        assert_arm_rejected(
            "paren-wildcard-second",
            "(BackendKind::Mock | _) => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_parenthesized_or_pattern_with_wildcard_first_is_caught() {
        assert_arm_rejected(
            "paren-wildcard-first",
            "(_ | BackendKind::Mock) => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_double_nested_parenthesized_wildcard_is_caught() {
        assert_arm_rejected(
            "double-nested-paren-wildcard",
            "((BackendKind::Mock | _)) => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_bare_binding_inside_parens_beside_a_real_variant_is_caught() {
        assert_arm_rejected(
            "paren-bare-binding",
            "(BackendKind::Mock | k) => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_legitimate_parenthesized_or_pattern_is_accepted() {
        // Both alternatives name BackendKind:: — the parens alone must not
        // make this arm suspect.
        let controls_body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            (BackendKind::Mock | BackendKind::Wasm) => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
            BackendKind::Firecracker => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
        }
    }
"#;
        let tmp = write_paired_fixture("legitimate-paren-or-pattern", controls_body);
        run(&tmp).expect(
            "a parenthesized or-pattern naming BackendKind:: on every alternative must pass",
        );
        cleanup(&tmp);
    }

    #[test]
    fn a_leading_pipe_is_accepted() {
        // `| BackendKind::Mock` splits into an empty leading alternative and
        // the real one; the empty alternative is skipped in run(), not
        // treated as a missing BackendKind:: reference.
        let controls_body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            | BackendKind::Mock => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
            BackendKind::Firecracker => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
        }
    }
"#;
        let tmp = write_paired_fixture("leading-pipe", controls_body);
        run(&tmp).expect("a leading `|` must not be misread as a missing alternative");
        cleanup(&tmp);
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
        let tmp = write_paired_fixture("legitimate-multi-variant", controls_body);
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
        let tmp = write_paired_fixture("after-nested-if", controls_body);
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
        let tmp = write_paired_fixture("unrelated-nested-match", controls_body);
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
        let tmp = write_paired_fixture("all-explicit", controls_body);
        run(&tmp).expect("every arm names BackendKind:: explicitly");
        cleanup(&tmp);
    }

    #[test]
    fn a_guard_comparing_a_string_is_still_a_wildcard() {
        // `_ if reason == "BackendKind::Mock"` is a bare wildcard: every
        // variant reaches it. Its pattern text names BackendKind:: only
        // inside a literal, so a scanner that reads strings as code passes it.
        assert_arm_rejected(
            "guard-string-compare",
            "_ if matches!(reason, \"BackendKind::Mock\") => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },",
        );
    }

    #[test]
    fn a_wildcard_beside_a_stringified_variant_name_is_caught() {
        assert_arm_rejected(
            "stringified-variant",
            "other => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None /* \"BackendKind::Mock\" */ },",
        );
    }

    #[test]
    fn a_brace_inside_a_string_does_not_end_the_match_early() {
        // A `}` inside a literal is not a closing brace, but a scanner that
        // reads strings as code counts it as one — which ends the match block
        // at the first arm and leaves every arm after it, wildcard included,
        // unread. A gate that stops reading passes everything it never saw.
        let controls_body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
                note: "}",
            },
            _ => Self { cpu: CpuControl::None, wall_clock: WallClockControl::None },
        }
    }
"#;
        let tmp = write_paired_fixture("brace-in-string", controls_body);
        let err = run(&tmp).unwrap_err();
        assert!(
            err.to_string().contains("never"),
            "a brace inside a literal must not hide the arms after it, got: {err}"
        );
        cleanup(&tmp);
    }

    #[test]
    fn a_wildcard_in_a_later_for_backend_is_caught_not_skipped() {
        // The gate used to locate its target with a first-match find, so a second
        // exhaustive match in the same file was never inspected at all.
        let body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self { cpu: CpuControl::None },
            BackendKind::Libkrun => Self { cpu: CpuControl::None },
        }
    }
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self { cpu: CpuObservation::None },
            _ => Self { cpu: CpuObservation::None },
        }
    }
"#;
        let tmp = write_controls_fixture("later_wildcard", body);
        let err = run(&tmp).unwrap_err();
        assert!(err.to_string().contains("never"), "got: {err}");
        cleanup(&tmp);
    }

    #[test]
    fn both_for_backend_matches_must_be_present_for_the_gate_to_pass() {
        // A gate that passes when the second matrix has been deleted is a gate
        // that stops noticing when the second matrix stops existing.
        let body = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self { cpu: CpuControl::None },
        }
    }
"#;
        let tmp = write_controls_fixture("only_one", body);
        assert!(run(&tmp).is_err(), "one matrix is not both matrices");
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
        let tmp = write_paired_fixture(label, &controls_body);
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

    /// A second, unimpeachable `for_backend` to sit beside a fixture that is
    /// exercising one matrix. The gate requires both matrices to be present,
    /// so a fixture testing arm-level behaviour has to satisfy the count floor
    /// without that floor being what the test observes.
    const COMPANION_MATRIX: &str = r#"
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            BackendKind::Firecracker => Self { cpu: CpuObservation::None },
            BackendKind::Mock => Self { cpu: CpuObservation::None },
        }
    }
"#;

    /// Write a fixture whose sole subject is `fn_body`, paired with a valid
    /// companion matrix so only `fn_body` can be the reason the gate speaks.
    fn write_paired_fixture(label: &str, fn_body: &str) -> std::path::PathBuf {
        write_controls_fixture(label, &format!("{fn_body}{COMPANION_MATRIX}"))
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

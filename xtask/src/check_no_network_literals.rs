//! `xtask check-no-network-literals`
//!
//! Network addresses, ports, and socket paths belong in config, not baked into
//! production source. Swapping one hardcoded literal for another is not a fix —
//! the values are injected from `mvm_core::dev_network` (the dev subnet) and
//! `mvm_core::guest_netd` (the egress-proxy listen address), and per-VM sockets
//! live under the VM's own directory. This lint is the tripwire that keeps the
//! literals from creeping back in. Three rule classes:
//!
//! 1. `subnet-literal` — the dev subnet prefix `172.16.` in a string literal.
//!    The canonical home is `mvm_core::dev_network`; everywhere else routes
//!    through its consts / `default_guest_ip_for_index`.
//! 2. `egress-port` — the egress-proxy port `:1080` in a string literal (bare
//!    `127.0.0.1:1080` or embedded in a `socks5h://…` URL). The one definition
//!    site is `mvm_core::guest_netd`.
//! 3. `tmp-socket` — a *fixed* Unix-socket path under `/tmp` (`/tmp/….sock` or
//!    `/tmp/….socket`) in a string literal. A world-visible, collision-prone
//!    global singleton. A per-instance socket carrying a `{…}` format
//!    placeholder is not matched — that is unique per VM/job, not a singleton.
//!
//! Test code is never flagged: files under a `tests/` directory, files ending
//! `_test.rs`, and lines inside a `#[cfg(test)]` block are skipped. A genuine
//! non-production use (a dev-only smoke example) earns the narrowest possible
//! `EXEMPTIONS` entry, with a reason.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::Path;

/// The rule classes, so exemptions can be scoped to exactly the class a file
/// legitimately needs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    SubnetLiteral,
    EgressPort,
    TmpSocket,
}

impl Rule {
    fn label(self) -> &'static str {
        match self {
            Rule::SubnetLiteral => "subnet-literal",
            Rule::EgressPort => "egress-port",
            Rule::TmpSocket => "tmp-socket",
        }
    }
}

const ALL_RULES: &[Rule] = &[Rule::SubnetLiteral, Rule::EgressPort, Rule::TmpSocket];

/// (file, exempted rule classes, reason). Keep entries scoped to the narrowest
/// rule class that the file legitimately needs.
const EXEMPTIONS: &[(&str, &[Rule], &str)] = &[
    (
        "crates/mvm-core/src/dev_network.rs",
        &[Rule::SubnetLiteral],
        "the canonical dev-subnet definition: owns the 172.16.0.0/24 consts every other site routes through",
    ),
    (
        "crates/mvm-core/src/guest_netd.rs",
        &[Rule::EgressPort],
        "the one named-const definition site for the egress-proxy listen address / URL",
    ),
    (
        "crates/mvm-runtime/examples/hvf-agent-ping.rs",
        &[Rule::TmpSocket],
        "dev-only HVF agent-ping smoke example; the /tmp default is overridable via MVM_HVF_AGENT_SOCKET and the binary is never shipped",
    ),
    (
        "xtask/src/check_no_network_literals.rs",
        ALL_RULES,
        "defines the very patterns it scans for",
    ),
];

pub fn run(workspace: &Path) -> Result<()> {
    let matchers = Matchers::new();
    let mut hits: Vec<String> = Vec::new();

    for root in ["crates", "src", "xtask", "tests"] {
        walk(&workspace.join(root), &mut |path| {
            scan_file(workspace, path, &matchers, &mut hits);
        })?;
    }

    if !hits.is_empty() {
        bail!(
            "check-no-network-literals: {} baked network literal(s) in production code.\n\
             Route them through mvm_core::dev_network (dev subnet) / mvm_core::guest_netd\n\
             (egress-proxy address), or the VM's own directory (per-VM sockets). A genuine\n\
             non-production use gets the narrowest EXEMPTIONS entry in\n\
             xtask/src/check_no_network_literals.rs, with a reason.\n{}",
            hits.len(),
            hits.join("\n")
        );
    }
    eprintln!("check-no-network-literals: clean (no baked IPs/ports/tmp-sockets in production)");
    Ok(())
}

/// Compiled patterns, built once for the whole tree walk.
struct Matchers {
    tmp_socket: Regex,
}

impl Matchers {
    fn new() -> Self {
        Self {
            // A `/tmp`-rooted socket path with no `{…}` placeholder: the path
            // token stops at whitespace, a quote, or a brace, so a per-instance
            // `/tmp/foo-{id}.sock` never matches (its token breaks at `{`).
            tmp_socket: Regex::new(r#"/tmp/[^\s"{}]*\.(?:sock|socket)\b"#)
                .expect("tmp-socket regex is valid"),
        }
    }
}

fn scan_file(workspace: &Path, path: &Path, matchers: &Matchers, hits: &mut Vec<String>) {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return;
    }
    let rel = path
        .strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    if is_test_path(&rel) {
        return;
    }
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    for hit in scan_source(&rel, &src, matchers) {
        hits.push(hit);
    }
}

/// Scan one file's source; returns formatted hit lines. Pure so the unit tests
/// can drive it with fixture text.
fn scan_source(rel: &str, src: &str, matchers: &Matchers) -> Vec<String> {
    if file_is_all_test(src) {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let test_ranges = test_line_ranges(src);

    let mut push = |line: usize, rule: Rule, lit: &str| {
        hits.push(format!("  {rel}:{line}: [{}] {lit:?}", rule.label()));
    };

    for (line, lit) in rust_string_literals(src) {
        if in_ranges(line, &test_ranges) {
            continue;
        }
        if lit.contains("172.16.") && !exempt(rel, Rule::SubnetLiteral) {
            push(line, Rule::SubnetLiteral, &lit);
        }
        if lit.contains(":1080") && !exempt(rel, Rule::EgressPort) {
            push(line, Rule::EgressPort, &lit);
        }
        if matchers.tmp_socket.is_match(&lit) && !exempt(rel, Rule::TmpSocket) {
            push(line, Rule::TmpSocket, &lit);
        }
    }
    hits
}

fn exempt(rel: &str, rule: Rule) -> bool {
    EXEMPTIONS
        .iter()
        .any(|(path, rules, _reason)| *path == rel && rules.contains(&rule))
}

/// A file that is all test code (skipped wholesale): a `tests/` integration
/// directory or a `*_test.rs` file.
fn is_test_path(rel: &str) -> bool {
    rel.ends_with("_test.rs") || rel.split('/').any(|seg| seg == "tests")
}

/// A file gated entirely to test builds via the inner `#![cfg(test)]` attribute
/// (e.g. an all-tests `commands/tests.rs` pulled in by `mod tests;`). Only the
/// file header is inspected — inner attributes must precede all items, so a
/// non-attribute, non-doc, non-blank line means there is no whole-file gate.
fn file_is_all_test(src: &str) -> bool {
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if t.starts_with("#![") {
            if t.starts_with("#![cfg(test)]") {
                return true;
            }
            continue; // some other inner attribute (e.g. #![allow(...)])
        }
        break; // first real item — no whole-file test gate
    }
    false
}

/// Line ranges (1-based, inclusive) covered by a `#[cfg(test)]` item. Heuristic:
/// a test-cfg attribute opens a region that runs to the first later line whose
/// indentation is ≤ the attribute's and whose trimmed text is a lone `}` — the
/// matching outdented close brace of the attributed `mod`/`fn`. This keeps a
/// mid-file test module from bleeding into production code that follows it
/// (unlike a blunt "to EOF" rule). A textual tripwire, not a parser.
fn test_line_ranges(src: &str) -> Vec<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if is_test_cfg_opener(trimmed) {
            let indent = lines[i].len() - trimmed.len();
            let start = i + 1;
            let mut end = lines.len();
            let mut j = i + 1;
            while j < lines.len() {
                let l = lines[j];
                let li = l.len() - l.trim_start().len();
                if l.trim() == "}" && li <= indent {
                    end = j + 1;
                    break;
                }
                j += 1;
            }
            ranges.push((start, end));
            i = end;
        } else {
            i += 1;
        }
    }
    ranges
}

/// Whether a trimmed line opens a test-only region. Matches `#[cfg(test)]` and
/// the `all(test, …)` / `any(test, …)` combinators, but not `not(test)` (which
/// marks non-test code).
fn is_test_cfg_opener(trimmed: &str) -> bool {
    trimmed.starts_with("#[cfg(test)]")
        || trimmed.starts_with("#[cfg(all(test")
        || trimmed.starts_with("#[cfg(any(test")
}

fn in_ranges(line: usize, ranges: &[(usize, usize)]) -> bool {
    ranges.iter().any(|(a, b)| line >= *a && line <= *b)
}

/// Extract string-literal contents as (1-based start line, content) pairs.
/// Comments are skipped so an address mentioned in prose is not a "literal";
/// `r#*"…"#*` raw strings and `'…'` char literals are handled like the sibling
/// lints.
fn rust_string_literals(src: &str) -> Vec<(usize, String)> {
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1usize;
    while i < n {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        // Raw string: r, optional #*, then "
        if c == b'r' && i + 1 < n && (b[i + 1] == b'"' || b[i + 1] == b'#') {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < n && b[j] == b'#' {
                hashes += 1;
                j += 1;
            }
            if j < n && b[j] == b'"' {
                let close = format!("\"{}", "#".repeat(hashes));
                let after = j + 1;
                if let Some(pos) = src[after..].find(&close) {
                    let content = &src[after..after + pos];
                    out.push((line, content.to_string()));
                    line += content.matches('\n').count();
                    i = after + pos + close.len();
                    continue;
                }
                break;
            }
        }
        // Normal string
        if c == b'"' {
            let start_line = line;
            let content_start = i + 1;
            i += 1;
            while i < n {
                if b[i] == b'\\' {
                    // A backslash escapes the next byte. A backslash immediately
                    // before a newline is a string line-continuation — the byte
                    // it "escapes" is a real source newline that still advances
                    // the line count, or every literal after it is under-counted.
                    if i + 1 < n && b[i + 1] == b'\n' {
                        line += 1;
                    }
                    i += 2;
                    continue;
                }
                if b[i] == b'\n' {
                    line += 1;
                }
                if b[i] == b'"' {
                    break;
                }
                i += 1;
            }
            out.push((start_line, src[content_start..i.min(n)].to_string()));
            i += 1;
            continue;
        }
        // Char literal (best-effort; lifetimes carry no closing quote)
        if c == b'\'' && i + 1 < n {
            if b[i + 1] == b'\\' && i + 3 < n && b[i + 3] == b'\'' {
                i += 4;
                continue;
            }
            if i + 2 < n && b[i + 2] == b'\'' {
                i += 3;
                continue;
            }
        }
        // Line comment
        if c == b'/' && i + 1 < n && b[i + 1] == b'/' {
            while i < n && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment (nested)
        if c == b'/' && i + 1 < n && b[i + 1] == b'*' {
            i += 2;
            let mut depth = 1;
            while i < n && depth > 0 {
                if b[i] == b'\n' {
                    line += 1;
                    i += 1;
                } else if b[i] == b'/' && i + 1 < n && b[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && i + 1 < n && b[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        i += 1;
    }
    out
}

fn walk(dir: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if matches!(name, "target" | ".git" | "node_modules") {
                continue;
            }
            walk(&path, f)?;
        } else {
            f(&path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(rel: &str, src: &str) -> Vec<String> {
        scan_source(rel, src, &Matchers::new())
    }

    const PLAIN: &str = "crates/foo/src/lib.rs";

    #[test]
    fn flags_subnet_literal() {
        let out = hits(PLAIN, "let ip = \"172.16.0.2\";\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[subnet-literal]"), "{out:?}");
    }

    #[test]
    fn flags_bare_and_socks5h_egress_port() {
        let bare = hits(PLAIN, "let a = \"127.0.0.1:1080\";\n");
        assert_eq!(bare.len(), 1, "{bare:?}");
        assert!(bare[0].contains("[egress-port]"), "{bare:?}");

        let url = hits(PLAIN, "let a = \"socks5h://127.0.0.1:1080\";\n");
        assert_eq!(url.len(), 1, "{url:?}");
        assert!(url[0].contains("[egress-port]"), "{url:?}");
    }

    #[test]
    fn flags_fixed_tmp_socket() {
        for src in [
            "let s = \"/tmp/firecracker.socket\";\n",
            "let s = \"/tmp/mvm/host-signer.sock\";\n",
        ] {
            let out = hits(PLAIN, src);
            assert_eq!(out.len(), 1, "{src}: {out:?}");
            assert!(out[0].contains("[tmp-socket]"), "{out:?}");
        }
    }

    #[test]
    fn allows_parameterized_tmp_socket() {
        // Per-instance sockets carry a `{…}` placeholder — unique, not a
        // collision-prone singleton.
        assert!(hits(PLAIN, "format!(\"/tmp/mvm-vfs-{job_id}-{tag}.sock\");\n").is_empty());
        assert!(
            hits(
                PLAIN,
                "format!(\"/tmp/mvm-libkrun-{}-vsock-{port}.sock\", n);\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_literals_in_comments() {
        assert!(hits(PLAIN, "// collides on the 172.16.0.x bridge\nlet x = 1;\n").is_empty());
        assert!(hits(PLAIN, "/// default `127.0.0.1:1080`\nlet x = 1;\n").is_empty());
        assert!(hits(PLAIN, "// socket at /tmp/firecracker.socket\nlet x = 1;\n").is_empty());
    }

    #[test]
    fn skips_cfg_test_block_content() {
        let src = "fn prod() { let ok = \"10.0.0.1\"; }\n\
                   #[cfg(test)]\n\
                   mod tests {\n\
                   fn t() { let ip = \"172.16.0.2\"; let a = \"127.0.0.1:1080\"; }\n\
                   }\n";
        assert!(hits(PLAIN, src).is_empty(), "{:?}", hits(PLAIN, src));
    }

    #[test]
    fn cfg_test_block_does_not_bleed_into_following_production() {
        // A test mod in the middle must not mask a real hit after its close.
        let src = "#[cfg(test)]\n\
                   mod tests {\n\
                   fn t() { let ip = \"172.16.0.2\"; }\n\
                   }\n\
                   fn prod() -> &'static str { \"172.16.0.9\" }\n";
        let out = hits(PLAIN, src);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[subnet-literal]"), "{out:?}");
        assert!(
            out[0].contains(":5:"),
            "should flag the production line, {out:?}"
        );
    }

    #[test]
    fn skips_test_files_wholesale() {
        assert!(is_test_path("crates/foo/tests/cli.rs"));
        assert!(is_test_path("crates/foo/src/thing_test.rs"));
        assert!(!is_test_path("crates/foo/src/lib.rs"));
    }

    #[test]
    fn line_continuations_do_not_desync_line_numbers() {
        // A `\`-at-end-of-line string continuation in production code above must
        // not swallow the source newline, or a later literal's reported line
        // slips below a following test range and escapes the skip filter.
        let src = "fn prod() -> String {\n\
                   format!(\"a \\\n b \\\n c\")\n\
                   }\n\
                   #[cfg(test)]\n\
                   mod tests {\n\
                   fn t() { let ip = \"172.16.0.2\"; }\n\
                   }\n";
        // The only 172.16 literal is inside the test mod → no hit. A desync would
        // report it on a pre-mod line and wrongly flag it.
        assert!(hits(PLAIN, src).is_empty(), "{:?}", hits(PLAIN, src));
    }

    #[test]
    fn skips_whole_file_inner_cfg_test_attr() {
        // An all-tests module pulled in via `mod tests;` gates the whole file
        // with `#![cfg(test)]` — after doc + other inner attrs.
        let src = "//! integration tests\n\
                   #![cfg(test)]\n\
                   #![allow(clippy::all)]\n\
                   use super::*;\n\
                   fn t() { let s = \"/tmp/bridge.sock\"; let ip = \"172.16.0.2\"; }\n";
        assert!(hits(PLAIN, src).is_empty(), "{:?}", hits(PLAIN, src));
        // A production file whose first item is not an inner attr is unaffected.
        assert!(file_is_all_test("//! doc\n#![cfg(test)]\n"));
        assert!(!file_is_all_test("//! doc\npub fn prod() {}\n"));
    }

    #[test]
    fn exemptions_are_rule_scoped() {
        let dev = "crates/mvm-core/src/dev_network.rs";
        // dev_network is exempt for subnet literals…
        assert!(hits(dev, "let s = \"172.16.0.0/24\";\n").is_empty());
        // …but a stray egress port there still trips.
        let out = hits(dev, "let a = \"127.0.0.1:1080\";\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[egress-port]"), "{out:?}");

        let netd = "crates/mvm-core/src/guest_netd.rs";
        assert!(hits(netd, "const A: &str = \"socks5h://127.0.0.1:1080\";\n").is_empty());
        let out = hits(netd, "let s = \"172.16.0.2\";\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[subnet-literal]"), "{out:?}");
    }
}

//! `xtask check-single-home`
//!
//! Every host-side path lives under ONE root — `mvm_home()` (`MVM_HOME` |
//! `$HOME/.mvm`) — and `crates/mvm-core/src/config.rs` is the only place
//! allowed to derive it. This lint is the tripwire that keeps bypasses
//! from creeping back in. Four rule classes:
//!
//! 1. `home-literal` — a home-relative mvm path fragment (`.mvm`,
//!    `.cache/mvm`, …) in a string literal outside the resolver. Joining
//!    those by hand re-rolls the layout the resolver owns. `~/`-prefixed
//!    occurrences are prose about the default location, not a join, and
//!    are allowed.
//! 2. `deleted-env` — a removed per-subtree override env var named
//!    anywhere, or an `XDG_*` env *read*. The resolver consults no XDG
//!    variable; writing `XDG_*` into a guest's environment is fine and
//!    deliberately not matched.
//! 3. `home-read` — `env::var("HOME")` / `env::var_os("HOME")` /
//!    `std::env::home_dir`. Base-dir derivation from `$HOME` belongs in
//!    the resolver only.
//! 4. `vms-join` — `mvm_home` and `.join("vms"` in one statement: the
//!    re-rolled per-VM layout. Use `vms_dir()` / `vm_state_dir()`.
//!
//! A site that trips gets routed through `mvm_core::config`; only a
//! genuinely non-mvm use of `$HOME` (shell rc files, toolchain discovery,
//! tilde expansion of user-supplied paths) earns the narrowest possible
//! `EXEMPTIONS` entry, with a reason.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::Path;

/// The rule classes, so exemptions can be scoped to exactly the class a
/// file legitimately needs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Rule {
    HomeLiteral,
    DeletedEnv,
    HomeRead,
    VmsJoin,
}

impl Rule {
    fn label(self) -> &'static str {
        match self {
            Rule::HomeLiteral => "home-literal",
            Rule::DeletedEnv => "deleted-env",
            Rule::HomeRead => "home-read",
            Rule::VmsJoin => "vms-join",
        }
    }
}

const ALL_RULES: &[Rule] = &[
    Rule::HomeLiteral,
    Rule::DeletedEnv,
    Rule::HomeRead,
    Rule::VmsJoin,
];

/// (file, exempted rule classes, reason). Keep entries scoped to the
/// narrowest rule class that the file legitimately needs.
const EXEMPTIONS: &[(&str, &[Rule], &str)] = &[
    (
        "crates/mvm-conformance/src/lib.rs",
        &[Rule::HomeRead],
        "locates rustup's and cargo's own roots, not mvm state: a scenario replaces \
         HOME to isolate ~/.mvm, which also hides the installed Rust toolchain from \
         any command that compiles, so the real $HOME is read to pass RUSTUP_HOME / \
         CARGO_HOME through",
    ),
    (
        "crates/mvm-core/src/config.rs",
        ALL_RULES,
        "the single legitimate resolver: owns the MVM_HOME | $HOME/.mvm derivation and the child layout",
    ),
    (
        "xtask/src/check_mutation_witnesses.rs",
        &[Rule::HomeRead, Rule::HomeLiteral],
        "confines a mutation run away from the real state root, so it must read the real $HOME \
         before redirecting it (to keep CARGO_HOME/RUSTUP_HOME pointing at the toolchain) and \
         name .mvm/keys to refuse running if the redirect did not take",
    ),
    (
        "xtask/src/check_single_home.rs",
        ALL_RULES,
        "defines the very patterns it scans for",
    ),
    (
        "crates/mvm-core/src/util/test_env.rs",
        &[Rule::HomeRead],
        "the test env-guard's own unit test reads HOME to assert isolate_mvm_home sets it and Drop restores it; it derives no mvm path",
    ),
    (
        "crates/mvm-cli/src/shell_init.rs",
        &[Rule::HomeRead],
        "writes the user's shell rc file (~/.zshrc / ~/.bashrc); $HOME locates the rc file, not an mvm base dir",
    ),
    (
        "crates/mvm-cli/build_embed_cache.rs",
        &[Rule::HomeLiteral, Rule::HomeRead],
        "the build script's artifact store is a host-level build cache, not an mvm state root: it \
         must be shared across worktrees and so cannot live under MVM_HOME, which every worktree \
         redirects at itself",
    ),
    (
        "crates/mvm-build/src/embed_toolchain.rs",
        &[Rule::HomeRead],
        "host toolchain discovery (~/.cargo/bin/rustup, mise python installs) lives in the real $HOME",
    ),
    (
        "crates/mvm-cli/src/exec.rs",
        &[Rule::HomeRead],
        "tilde-expansion of user-supplied image paths",
    ),
    (
        "crates/mvm-cli/src/commands/shared/parse.rs",
        &[Rule::HomeRead],
        "tilde-expansion of user volume specs + non-mvm credential-store deny roots (~/.ssh, ~/.gnupg, ~/.aws)",
    ),
    (
        "crates/deps/libkrun-sys/examples/libkrun-smoke.rs",
        &[Rule::HomeRead, Rule::HomeLiteral],
        "manual smoke example in the FFI crate, which sits below mvm-core and cannot call the resolver",
    ),
    (
        "crates/mvm-client/src/audit/sanitize.rs",
        &[Rule::HomeLiteral],
        "the path-redaction detector: matches the .mvm literal inside untrusted audit text to \
         scrub it before UI exposure, and its tests feed .mvm-shaped fixtures to prove the scrub; \
         it derives no mvm path",
    ),
    (
        "crates/mvm-client/src/audit/normalize.rs",
        &[Rule::HomeLiteral],
        ".mvm-shaped test fixtures asserting host paths are redacted from normalized event detail; \
         it derives no mvm path",
    ),
    (
        "tests/release_assets.rs",
        &[Rule::HomeLiteral],
        "structural release tests inspect the boot workflow's shell command and pin its canonical \
         production cache path; the test derives no host path",
    ),
];

pub fn run(workspace: &Path) -> Result<()> {
    let matchers = Matchers::new();
    let mut hits: Vec<String> = Vec::new();

    for root in ["crates", "src", "xtask", "tests"] {
        crate::fs_walk::walk_files(&workspace.join(root), &mut |path| {
            scan_file(workspace, path, &matchers, &mut hits);
        })?;
    }

    if !hits.is_empty() {
        bail!(
            "check-single-home: {} site(s) bypass the single-root resolver.\n\
             Route them through mvm_core::config (mvm_home / vms_dir / vm_state_dir / mvm_audit_dir, …).\n\
             A genuinely non-mvm use of $HOME gets the narrowest EXEMPTIONS entry in\n\
             xtask/src/check_single_home.rs, with a reason.\n{}",
            hits.len(),
            hits.join("\n")
        );
    }
    eprintln!("check-single-home: clean (all host paths resolve through mvm-core::config)");
    Ok(())
}

/// Compiled patterns, built once for the whole tree walk.
struct Matchers {
    deleted_env: Regex,
    home_read: Regex,
}

impl Matchers {
    fn new() -> Self {
        Self {
            deleted_env: Regex::new(
                r#"\b(?:MVM_DATA_DIR|MVM_CACHE_DIR|MVM_CONFIG_DIR|MVM_RUNTIME_DIR|MVM_STATE_DIR|MVM_SHARE_DIR|MVM_DEPS_VOLUMES_DIR)\b|env::var(?:_os)?\s*\(\s*"XDG_"#,
            )
            .expect("deleted-env regex is valid"),
            home_read: Regex::new(r#"env::var(?:_os)?\s*\(\s*"HOME"\s*\)|std::env::home_dir"#)
                .expect("home-read regex is valid"),
        }
    }
}

/// Home-relative mvm path fragments that must never be joined by hand.
const HOME_PATH_FRAGMENTS: &[&str] = &[
    ".mvm",
    ".cache/mvm",
    ".config/mvm",
    ".local/state/mvm",
    ".local/share/mvm",
    "microvm/vms",
];

fn scan_file(workspace: &Path, path: &Path, matchers: &Matchers, hits: &mut Vec<String>) {
    if path.extension().and_then(|e| e.to_str()) != Some("rs") {
        return;
    }
    let rel = path
        .strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let Ok(src) = std::fs::read_to_string(path) else {
        return;
    };
    for hit in scan_source(&rel, &src, matchers) {
        hits.push(hit);
    }
}

/// Scan one file's source; returns formatted hit lines. Pure so the unit
/// tests can drive it with fixture text.
fn scan_source(rel: &str, src: &str, matchers: &Matchers) -> Vec<String> {
    let mut hits = Vec::new();
    let mut push = |line: usize, rule: Rule, excerpt: &str| {
        hits.push(format!(
            "  {rel}:{line}: [{}] {}",
            rule.label(),
            excerpt.trim()
        ));
    };

    if !exempt(rel, Rule::HomeLiteral) {
        for (line, lit) in rust_string_literals(src) {
            if let Some(frag) = literal_home_fragment(&lit) {
                push(line, Rule::HomeLiteral, &format!("\"…{frag}…\" in {lit:?}"));
            }
        }
    }
    if !exempt(rel, Rule::DeletedEnv) {
        for (idx, text) in src.lines().enumerate() {
            if matchers.deleted_env.is_match(text) {
                push(idx + 1, Rule::DeletedEnv, text);
            }
        }
    }
    if !exempt(rel, Rule::HomeRead) {
        for (idx, text) in src.lines().enumerate() {
            if matchers.home_read.is_match(text) {
                push(idx + 1, Rule::HomeRead, text);
            }
        }
    }
    if !exempt(rel, Rule::VmsJoin) {
        for (line, stmt) in logical_statements(src) {
            if stmt.contains("mvm_home") && stmt.contains(".join(\"vms\"") {
                push(line, Rule::VmsJoin, &stmt);
            }
        }
    }
    hits
}

fn exempt(rel: &str, rule: Rule) -> bool {
    EXEMPTIONS
        .iter()
        .any(|(path, rules, _reason)| *path == rel && rules.contains(&rule))
}

/// Does the literal contain a home-relative mvm fragment as a full path
/// component (start-of-literal or `/` before; `/` or end after)? A `~/`
/// prefix is prose about the default location and is allowed.
fn literal_home_fragment(lit: &str) -> Option<&'static str> {
    let bytes = lit.as_bytes();
    for frag in HOME_PATH_FRAGMENTS {
        let mut search = 0;
        while let Some(pos) = lit[search..].find(frag) {
            let at = search + pos;
            let end = at + frag.len();
            search = at + 1;
            let before_ok = at == 0 || bytes[at - 1] == b'/';
            let after_ok = end == lit.len() || bytes[end] == b'/';
            if !(before_ok && after_ok) {
                continue;
            }
            if at >= 2 && &lit[at - 2..at] == "~/" {
                continue;
            }
            return Some(frag);
        }
    }
    None
}

/// Extract string-literal contents as (1-based start line, content) pairs.
/// Comments are skipped so a path mentioned in prose is not a "literal";
/// `r#*"…"#*` raw strings and `'…'` char literals are handled like the
/// sibling comment-extraction lint.
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

/// Group physical lines into logical statements: a statement ends on a
/// line whose trailing character is `;`, `{`, or `}` (or a blank line).
/// Full-line comments are dropped so prose can't glue onto code. This is
/// a textual tripwire, not a parser; the cap bounds pathological input.
fn logical_statements(src: &str) -> Vec<(usize, String)> {
    const MAX_STATEMENT_LEN: usize = 2048;
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 0usize;
    for (idx, raw) in src.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with("//") {
            continue;
        }
        if buf.is_empty() {
            start = idx + 1;
        }
        buf.push_str(line);
        buf.push(' ');
        let ended =
            line.ends_with(';') || line.ends_with('{') || line.ends_with('}') || line.is_empty();
        if ended || buf.len() > MAX_STATEMENT_LEN {
            out.push((start, std::mem::take(&mut buf)));
        }
    }
    if !buf.is_empty() {
        out.push((start, buf));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hits(rel: &str, src: &str) -> Vec<String> {
        scan_source(rel, src, &Matchers::new())
    }

    const PLAIN: &str = "crates/foo/src/lib.rs";

    #[test]
    fn flags_hand_rolled_mvm_literal() {
        let out = hits(PLAIN, "let p = home.join(\".mvm/audit\");\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[home-literal]"), "{out:?}");
    }

    #[test]
    fn flags_bare_dot_mvm_component() {
        let out = hits(PLAIN, "let p = home.join(\".mvm\").join(\"keys\");\n");
        assert_eq!(out.len(), 1, "{out:?}");
    }

    #[test]
    fn allows_tilde_prose_and_non_component_names() {
        assert!(hits(PLAIN, "bail!(\"key missing under ~/.mvm/keys\");\n").is_empty());
        assert!(hits(PLAIN, "let marker = \".mvm-stage0-root\";\n").is_empty());
        assert!(hits(PLAIN, "let p = dir.join(\".mvm-test\");\n").is_empty());
    }

    #[test]
    fn ignores_path_mention_in_comment() {
        assert!(hits(PLAIN, "// legacy layout was $HOME/.cache/mvm\nlet x = 1;\n").is_empty());
    }

    #[test]
    fn flags_deleted_env_var_and_xdg_read() {
        let out = hits(PLAIN, "let d = std::env::var(\"MVM_DATA_DIR\");\n");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[deleted-env]"), "{out:?}");
        let out = hits(PLAIN, "let d = std::env::var(\"XDG_CACHE_HOME\");\n");
        assert_eq!(out.len(), 1, "{out:?}");
    }

    #[test]
    fn allows_guest_xdg_export_string() {
        // Writing XDG vars into a guest's env is an export, not a read.
        let src = "script.push_str(\"export XDG_CACHE_HOME=/root/.cache\\n\");\n";
        assert!(hits(PLAIN, src).is_empty());
    }

    #[test]
    fn flags_home_env_reads() {
        for src in [
            "let h = std::env::var(\"HOME\").unwrap();\n",
            "let h = std::env::var_os(\"HOME\");\n",
            "let h = std::env::home_dir();\n",
        ] {
            let out = hits(PLAIN, src);
            assert_eq!(out.len(), 1, "{src}: {out:?}");
            assert!(out[0].contains("[home-read]"), "{out:?}");
        }
    }

    #[test]
    fn allows_mvm_home_env_read() {
        assert!(hits(PLAIN, "let h = std::env::var_os(\"MVM_HOME\");\n").is_empty());
    }

    #[test]
    fn flags_rerolled_vms_join_single_and_multi_line() {
        let single = "let root = PathBuf::from(mvm_home()).join(\"vms\");\n";
        let out = hits(PLAIN, single);
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("[vms-join]"), "{out:?}");

        let multi = "let root = mvm_core::config::mvm_home_strict()?\n    .join(\"vms\")\n    .join(name);\n";
        let out = hits(PLAIN, multi);
        assert_eq!(out.len(), 1, "{out:?}");
    }

    #[test]
    fn allows_vms_dir_helper_and_unrelated_vms_join() {
        assert!(hits(PLAIN, "let root = mvm_core::config::vms_dir();\n").is_empty());
        assert!(hits(PLAIN, "let root = builder_vm_cache_dir().join(\"vms\");\n").is_empty());
    }

    #[test]
    fn resolver_file_is_exempt_from_all_rules() {
        let src = "let h = std::env::var(\"HOME\");\nlet p = format!(\"{}/.mvm\", h);\nlet v = PathBuf::from(mvm_home()).join(\"vms\");\n";
        assert!(hits("crates/mvm-core/src/config.rs", src).is_empty());
    }

    #[test]
    fn exemptions_are_rule_scoped() {
        // shell_init is exempt for home-read only; a hand-rolled .mvm
        // literal there must still trip.
        let rel = "crates/mvm-cli/src/shell_init.rs";
        assert!(hits(rel, "let h = std::env::var(\"HOME\")?;\n").is_empty());
        let out = hits(rel, "let p = home.join(\".mvm/keys\");\n");
        assert_eq!(out.len(), 1, "{out:?}");
    }
}

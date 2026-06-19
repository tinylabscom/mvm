//! `xtask check-guest-images-no-builder-tools`
//!
//! The guest-image trust-boundary invariant: a **workload guest image**
//! must not bake the host control plane (`mvmctl`) or the resident
//! builder daemon (`mvm-builderd`). Those are host / builder-VM tools;
//! the workload guest is a sealed, headless payload. mkGuest
//! (`nix/lib/mk-guest.nix`) is the workload + dev-shell image builder, so
//! this gate asserts its own code never installs those binaries.
//!
//! Source-grep, not a build: like `check-guest-agent-in-all-images`, this
//! gate cannot evaluate Nix on a contributor host, so it reads the
//! builder's source with comments stripped (a comment that *names*
//! `mvmctl` while explaining host-side surfaces is fine — only code that
//! installs the binary is a violation). The builder VM image legitimately
//! injects `mvm-host-vm-init` through mkGuest's generic `extraFiles`
//! mechanism; that is a separate, intentional consumer and not mkGuest's
//! own content, so `mvm-host-vm-init` is deliberately not in the forbidden
//! set here.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// The mkGuest source whose own code must not install builder/host tools.
const MK_GUEST: &str = "nix/lib/mk-guest.nix";

/// Binaries that must never be baked into a workload guest image by
/// mkGuest itself.
const FORBIDDEN: &[&str] = &["mvmctl", "mvm-builderd"];

pub fn run(workspace: &Path) -> Result<()> {
    let path = workspace.join(MK_GUEST);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading guest-image builder {MK_GUEST}"))?;
    let code = strip_nix_comments(&raw);

    let mut found: Vec<&str> = FORBIDDEN
        .iter()
        .copied()
        .filter(|tool| code.contains(tool))
        .collect();
    found.sort_unstable();

    if !found.is_empty() {
        bail!(
            "check-guest-images-no-builder-tools: `{MK_GUEST}` installs host/builder \
             tooling into workload guest images: {}\n\
             Workload guests are sealed headless payloads — `mvmctl` and `mvm-builderd` \
             are host / builder-VM tools and must never be baked in (ADR-089 / Plan 204 \
             §5). If this is a comment, the comment stripper missed it; if it is code, \
             remove the install.",
            found.join(", ")
        );
    }

    eprintln!(
        "check-guest-images-no-builder-tools: clean ({MK_GUEST} bakes none of: {})",
        FORBIDDEN.join(", ")
    );
    Ok(())
}

/// Strip Nix comments so a comment that merely *names* a forbidden tool
/// is not a false positive. Removes `/* ... */` block comments and `#`
/// line comments. A `#` is treated as a comment start anywhere it
/// appears; that can also strip a `#` inside a string literal, but for an
/// absence check that only risks a false negative on a token written
/// *after* a `#` on the same line — never a false positive — and a real
/// install line keeps its pre-`#` content.
fn strip_nix_comments(src: &str) -> String {
    // Block comments first (they can span lines). `str::find` returns
    // char-boundary byte indices, so slicing stays UTF-8 safe.
    let mut without_blocks = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(start) = rest.find("/*") {
        without_blocks.push_str(&rest[..start]);
        without_blocks.push(' ');
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => {
                rest = "";
                break;
            }
        }
    }
    without_blocks.push_str(rest);
    // Then `#` line comments — keep each line's pre-`#` content.
    without_blocks
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_line_and_block_comments() {
        let src = "install foo # mentions mvmctl in a note\n/* block mvmctl */ install bar\n";
        let code = strip_nix_comments(src);
        assert!(
            !code.contains("mvmctl"),
            "comments must be stripped: {code:?}"
        );
        assert!(code.contains("install foo"));
        assert!(code.contains("install bar"));
    }

    #[test]
    fn keeps_code_before_a_hash() {
        let code = strip_nix_comments("cp it mvmctl # then a comment\n");
        assert!(code.contains("mvmctl"), "pre-# code is preserved: {code:?}");
    }
}

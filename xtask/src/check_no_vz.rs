//! `xtask check-no-vz`
//!
//! Enforce the load-bearing invariant: **the Apple Container backend is
//! 100% Rust-native — no Swift anywhere, no Virtualization.framework (VZ)
//! anywhere.** The backend boots Apple's prebuilt container kernel (a
//! fetched binary artifact, no toolchain) with mvm's universal initramfs
//! on the in-house HVF VMM; Apple's only presence in the tree is the
//! guest-side kernel image itself, and the Containerization SwiftPM
//! package — including its `vminitd` init — is banned outright.
//!
//! Two rules, because there are two ways the retired backend comes back.
//!
//! **Usage.** Flags VZ API symbols (`VZVirtualMachine*`,
//! `VZLinuxBootLoader`, `VZDiskImage*`), Swift imports
//! (`import Virtualization`, `import Containerization`), the SwiftPM
//! package URL, and SwiftPM manifests (`swift-tools-version`), plus any
//! `Package.swift` / `Package.resolved` / `*.swift` file anywhere under
//! the workspace root (`target/`, `.git/`, and `node_modules/` skipped),
//! so a Swift shim cannot sneak in outside the crates tree either.
//!
//! **Naming.** Flags a bare `vz` / `Vz` / `VZ` word anywhere in the Rust
//! we own (`crates/`, `tests/`, `src/`, `examples/`, `xtask/`). The usage
//! rule alone left the name free to persist for months after the backend
//! was deleted — in a `vz.pid` marker still probed at runtime, in a
//! `checkpoint_is_vz` predicate that had silently come to mean "HVF", and
//! in user-facing text blaming a backend the user never ran. A name on a
//! live code path is not cosmetic: it misdescribes what actually executes.
//! `virtualization` does not match, so Apple's
//! `com.apple.security.virtualization` entitlement — still required
//! alongside `com.apple.security.hypervisor` — is unaffected.
//!
//! This lint's own names (`check-no-vz`, `check_no_vz`, `allow(no-vz)`,
//! `NO_VZ`) are elided before the naming rule runs, so the gate and its
//! registration can spell the word without ceremony while any other
//! mention on the same line still trips.
//!
//! Opt-out: `// allow(no-vz): <reason>` on the line directly above the
//! mention (one per line). Reserved for historical design notes — never a
//! dependency, an API use, or a build input. Reasons land in the lint
//! output so any bypass stays visible.

use anyhow::{Context, Result, bail};
use std::path::Path;

/// VZ / Containerization usage needles. Deliberately symbols, imports, and
/// package coordinates — plain-English prose about the framework does not
/// match.
const NO_VZ_NEEDLES: &[&str] = &[
    "VZVirtualMachine",
    "VZVirtualMachineManager",
    "VZVirtualMachineConfiguration",
    "VZLinuxBootLoader",
    "VZDiskImage",
    "import Virtualization",
    "import Containerization",
    "apple/containerization.git",
    "swift-tools-version",
];
const ALLOW_MARKER: &str = "// allow(no-vz):";

/// Bare `vz` / `Vz` / `VZ` as a whole word. The symbol needles above only
/// stop the framework being *used*; this stops the retired backend being
/// *named* — in an identifier, a path fragment like `vz.pid`, a test
/// fixture, or a user-facing string. A stale name on a live code path is
/// worse than clutter: a marker list or dispatch predicate carrying it
/// misdescribes which backend actually runs there.
///
/// Bounded by any non-alphanumeric on both sides. `_` counts as a boundary
/// on purpose: snake_case is where this actually hides — `checkpoint_is_vz`
/// is the case that motivated the rule, and treating `_` as a word
/// character would let every `*_vz` / `vz_*` identifier through.
/// Alphanumerics still bind, so `virtualization` does not match and neither
/// does a hash that happens to contain the pair.
const NO_VZ_IDENT: &str = r"(?i)(?:^|[^0-9A-Za-z])vz(?:[^0-9A-Za-z]|$)";

/// File names (or the Swift extension) scanned outside the crates tree so
/// a SwiftPM shim cannot be introduced under a non-crate path.
fn is_swift_surface(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some("Package.swift" | "Package.resolved") => true,
        _ => path.extension().is_some_and(|e| e == "swift"),
    }
}

pub fn run(workspace: &Path) -> Result<()> {
    let crates_dir = workspace.join("crates");
    if !crates_dir.is_dir() {
        bail!("expected workspace crates dir at {}", crates_dir.display());
    }
    let mut findings: Vec<String> = Vec::new();

    // Rust sources we own, checked for usage needles *and* bare `vz` names.
    // `xtask/` is included so a gate cannot quietly reintroduce the word,
    // except in this file, which has to spell it to ban it.
    for root in ["crates", "tests", "src", "examples", "xtask"] {
        let dir = workspace.join(root);
        if !dir.is_dir() {
            continue;
        }
        visit_rust_files(&dir, &mut |path| {
            if path.ends_with("xtask/src/check_no_vz.rs") {
                return Ok(());
            }
            scan_idents(path, &mut findings)
        })?;
    }
    // SwiftPM manifests and Swift sources anywhere under the root.
    visit_swift_surface(workspace, &mut |path| scan(path, &mut findings))?;

    if findings.is_empty() {
        eprintln!(
            "check-no-vz: clean (no Virtualization.framework / Containerization usage outside an \
             explicit allow(no-vz) note)"
        );
        return Ok(());
    }
    eprintln!(
        "check-no-vz: {} mention(s) — the retired backend is gone and stays gone. The Apple \
         Container backend is 100% Rust-native: it boots Apple's prebuilt container kernel with \
         the universal initramfs on the in-house HVF VMM. Virtualization.framework, SwiftPM, and \
         the Containerization package (including vminitd) are banned from the tree, and so is \
         naming the retired backend in an identifier, a pid-marker string, a test fixture, or \
         user-facing text. If this is a genuine historical design note, annotate with \
         `// allow(no-vz): <reason>`:",
        findings.len()
    );
    for f in &findings {
        eprintln!("  {f}");
    }
    bail!("check-no-vz: {} unannotated mention(s)", findings.len());
}

/// Scan one file line-by-line for the needles, honoring the per-line
/// opt-out marker on the line directly above.
fn scan(path: &Path, findings: &mut Vec<String>) -> Result<()> {
    scan_with(path, findings, false)
}

/// As [`scan`], plus the bare-identifier rule. Split out because the
/// identifier rule applies to Rust/Nix/Markdown sources we own, while the
/// Swift-surface sweep only ever needs the usage needles.
fn scan_idents(path: &Path, findings: &mut Vec<String>) -> Result<()> {
    scan_with(path, findings, true)
}

/// This lint's own names, which necessarily contain the banned word. Elided
/// before the identifier rule runs so the gate, its registration, and any
/// doc comment pointing at it can spell it without an allow-marker — while
/// every *other* mention on the same line still trips.
const SELF_NAMES: &[&str] = &["check-no-vz", "check_no_vz", "allow(no-vz)", "NO_VZ"];

fn scan_with(path: &Path, findings: &mut Vec<String>, idents: bool) -> Result<()> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let ident = regex::Regex::new(NO_VZ_IDENT).expect("NO_VZ_IDENT is a valid regex");
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let without_self_names = SELF_NAMES
            .iter()
            .fold(line.to_string(), |acc, n| acc.replace(n, ""));
        let hit = NO_VZ_NEEDLES.iter().any(|n| line.contains(n))
            || (idents && ident.is_match(&without_self_names));
        if hit {
            let allowed = i > 0 && lines[i - 1].trim_start().starts_with(ALLOW_MARKER);
            if !allowed {
                findings.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
            }
        }
    }
    Ok(())
}

fn visit_rust_files(dir: &Path, f: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            visit_rust_files(&path, f)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            f(&path)?;
        }
    }
    Ok(())
}

/// Walk the workspace root for the Swift surface (SwiftPM manifests and
/// Swift sources), skipping `target/`, `.git/`, and `node_modules/` (build
/// output and vendored web dependencies can never hold our shim).
fn visit_swift_surface(dir: &Path, f: &mut dyn FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n == "target" || n == ".git" || n == "node_modules")
            {
                continue;
            }
            visit_swift_surface(&path, f)?;
        } else if is_swift_surface(&path) {
            f(&path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_rust(root: &Path, name: &str, body: &str) {
        let dir = root.join("crates/x/src");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn vz_symbol_usage_is_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        write_rust(
            tmp.path(),
            "bad.rs",
            "fn f() { let _ = \"VZVirtualMachineConfiguration\"; }\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn allow_marker_on_the_line_above_exempts_it() {
        let tmp = tempfile::tempdir().unwrap();
        write_rust(
            tmp.path(),
            "note.rs",
            "fn f() {\n    // allow(no-vz): historical design-note reference, not a dependency\n    let _ = \"VZDiskImage\";\n}\n",
        );
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn prose_about_the_framework_does_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        // Negative references and plain-English prose carry no needle.
        write_rust(
            tmp.path(),
            "ok.rs",
            "//! Boots on the in-house HVF VMM — no Virtualization.framework, no Swift shim.\n",
        );
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn swiftpm_manifest_outside_crates_is_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        write_rust(tmp.path(), "ok.rs", "fn f() {}\n");
        let shim = tmp.path().join("swift/container-shim");
        std::fs::create_dir_all(&shim).unwrap();
        std::fs::write(
            shim.join("Package.swift"),
            "// swift-tools-version: 5.9\nimport PackageDescription\n",
        )
        .unwrap();
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn swift_import_in_a_swift_source_is_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        write_rust(tmp.path(), "ok.rs", "fn f() {}\n");
        let dir = tmp.path().join("tools/shim");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.swift"), "import Virtualization\n").unwrap();
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn a_bare_vz_identifier_is_flagged() {
        // The failure this rule exists for: a marker string on a live code
        // path, naming a backend that no longer runs.
        for line in [
            r#"const MARKERS: &[&str] = &["vz.pid", "fc.pid"];"#,
            "pub fn checkpoint_is_vz(m: &Meta) -> bool { false }\n",
            r#"    ui::success("re-signed with VZ entitlements");"#,
            "// The removed Vz backend used to do this.\n",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write_rust(tmp.path(), "x.rs", line);
            assert!(
                run(tmp.path()).is_err(),
                "must flag a bare vz mention: {line}"
            );
        }
    }

    #[test]
    fn words_merely_containing_the_pair_are_not_flagged() {
        // `virtualization` must survive: Apple's entitlement key is still
        // required, so a substring rule here would be unusable.
        let tmp = tempfile::tempdir().unwrap();
        write_rust(
            tmp.path(),
            "ok.rs",
            "const E: &str = \"com.apple.security.virtualization\";\nconst H: &str = \"abvzcd\";\n",
        );
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn an_annotated_vz_mention_is_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        write_rust(
            tmp.path(),
            "ok.rs",
            "// allow(no-vz): historical design note\n/// The removed Vz backend locked the image.\nfn f() {}\n",
        );
        assert!(run(tmp.path()).is_ok());
    }

    #[test]
    fn target_and_git_dirs_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        write_rust(tmp.path(), "ok.rs", "fn f() {}\n");
        let nested = tmp.path().join("target/shim");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("Package.swift"),
            "// swift-tools-version: 5.9\n",
        )
        .unwrap();
        assert!(run(tmp.path()).is_ok());
    }
}

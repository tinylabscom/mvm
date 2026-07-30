//! `xtask check-no-vz`
//!
//! Enforce the load-bearing invariant: **the Apple Container backend rides
//! the in-house HVF VMM only — Apple's Virtualization.framework (VZ) and
//! the Containerization Swift package are banned from the tree.** The
//! backend boots Apple's container kernel and the `initfs.ext4` that
//! carries `/sbin/vminitd` on mvm's own HVF supervisor; Apple's code runs
//! only guest-side, unmodified, from the cached artifacts. Any guest-side
//! vminitd need is routed through the builder-VM source build of the
//! artifacts — never through a SwiftPM dependency or a VZ API.
//!
//! Flags VZ API symbols (`VZVirtualMachine*`, `VZLinuxBootLoader`,
//! `VZDiskImage*`), Swift imports (`import Virtualization`,
//! `import Containerization`), the SwiftPM package URL, and SwiftPM
//! manifests (`swift-tools-version`) in `crates/*/src/**/*.rs`, plus any
//! `Package.swift` / `Package.resolved` / `*.swift` file anywhere under
//! the workspace root (`target/`, `.git/`, and `node_modules/` skipped), so a Swift shim
//! cannot sneak in outside the crates tree either. Prose references like
//! "no Virtualization.framework" do not match — the needles target usage
//! (symbols, imports, package coordinates), not words.
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

    // Rust sources under crates/.
    visit_rust_files(&crates_dir, &mut |path| scan(path, &mut findings))?;
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
        "check-no-vz: {} VZ/Containerization mention(s) — the Apple Container backend boots \
         Apple's container kernel + initfs on the in-house HVF VMM; Virtualization.framework and \
         the Containerization SwiftPM package are banned from the tree. Route any guest-side \
         vminitd need through the builder-VM source build of the artifacts. If this is a genuine \
         historical design note, annotate with `// allow(no-vz): <reason>`:",
        findings.len()
    );
    for f in &findings {
        eprintln!("  {f}");
    }
    bail!(
        "check-no-vz: {} unannotated VZ/Containerization mention(s)",
        findings.len()
    );
}

/// Scan one file line-by-line for the needles, honoring the per-line
/// opt-out marker on the line directly above.
fn scan(path: &Path, findings: &mut Vec<String>) -> Result<()> {
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if NO_VZ_NEEDLES.iter().any(|n| line.contains(n)) {
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

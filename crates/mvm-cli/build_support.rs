//! Small, I/O-free helpers shared by `mvm-cli`'s build script, kept out of it
//! so they can be unit-tested without running a real build.

use std::path::{Path, PathBuf};

/// Extract the quoted string after `key` on one line, e.g.
/// `name: "mvm-host-vm-init",` + `"name:"` → `Some("mvm-host-vm-init")`.
///
/// The build script reads its binary manifest out of the *text* of
/// `crates/mvm-cli/src/host_binaries/manifest.rs`, because a build script
/// cannot depend on the crate it is building.
pub(crate) fn extract_quoted_after(line: &str, key: &str) -> Option<String> {
    let i = line.find(key)? + key.len();
    let rest = &line[i..];
    let q1 = rest.find('"')? + 1;
    let q2 = rest[q1..].find('"')?;
    Some(rest[q1..q1 + q2].to_string())
}

/// Return a nested Cargo target shared by every feature fingerprint of the
/// same outer profile. Cargo gives each build-script fingerprint a different
/// `OUT_DIR`; placing nested builds directly below it makes identical embedded
/// binaries rebuild for clippy, feature tests, and examples. Their common
/// `build/` parent is still isolated from the outer Cargo lock while allowing
/// the nested Cargo invocation to reuse its own fingerprints.
pub(crate) fn shared_nested_target_dir(out_dir: &Path) -> PathBuf {
    let build_dir = out_dir
        .parent()
        .and_then(Path::parent)
        .expect("Cargo OUT_DIR must end in build/<package-fingerprint>/out");
    build_dir.join("mvm-cli-nested-target")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_quoted_after_reads_the_quoted_value() {
        assert_eq!(
            extract_quoted_after(r#"        name: "mvm-host-vm-init","#, "name:"),
            Some("mvm-host-vm-init".to_string())
        );
        assert_eq!(extract_quoted_after("no key here", "name:"), None);
    }

    #[test]
    fn nested_target_is_shared_across_package_fingerprints() {
        let first = Path::new("/target/debug/build/mvm-cli-first/out");
        let second = Path::new("/target/debug/build/mvm-cli-second/out");
        assert_eq!(
            shared_nested_target_dir(first),
            shared_nested_target_dir(second)
        );
    }
}

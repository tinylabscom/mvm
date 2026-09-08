//! Release-time validation for the boot-image line embedded in `mvmctl`.

use std::fs;
use std::path::Path;

use anyhow::{Result, bail};

const ARCHITECTURES: [&str; 2] = ["aarch64", "x86_64"];
const SDK_LIBCS: [&str; 2] = ["glibc", "musl"];

pub(crate) fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("tag") if args.len() == 1 => {
            println!("{}", mvm_core::config::DEFAULT_BOOT_IMAGE_TAG);
            Ok(())
        }
        Some("validate") if args.len() == 3 => validate_release(&args[1], Path::new(&args[2])),
        _ => bail!(
            "usage: release-boot-image tag | release-boot-image validate <tag> <artifact-dir>"
        ),
    }
}

fn validate_release(tag: &str, artifact_dir: &Path) -> Result<()> {
    let expected = mvm_core::config::DEFAULT_BOOT_IMAGE_TAG;
    if tag != expected {
        bail!(
            "release selected boot image tag {tag:?}, but the CLI embeds {expected:?}; refusing to validate different bytes"
        );
    }

    let missing = required_assets()
        .into_iter()
        .filter(|name| !is_nonempty_file(&artifact_dir.join(name)))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "{tag} is incomplete; refusing to ship a CLI release whose boot image would fail on first boot. Missing: {}",
            missing.join(" ")
        );
    }
    Ok(())
}

fn is_nonempty_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
}

fn required_assets() -> Vec<String> {
    let mut assets = Vec::new();
    for arch in ARCHITECTURES {
        assets.extend([
            format!("default-microvm-vmlinux-{arch}"),
            format!("default-microvm-rootfs-{arch}.ext4"),
            format!("default-microvm-meta-{arch}.json"),
            format!("default-microvm-{arch}-checksums-sha256.txt"),
            format!("builder-vm-vmlinux-{arch}"),
            format!("builder-vm-rootfs-{arch}.ext4"),
            format!("builder-vm-{arch}-checksums-sha256.txt"),
            format!("runtime-overlay-{arch}.tar.gz"),
        ]);
        for libc in SDK_LIBCS {
            assets.extend([
                format!("sdk-sidecar-{arch}-{libc}.tar.gz"),
                format!("sdk-sidecar-{arch}-{libc}.tar.gz.sha256"),
            ]);
        }
    }
    assets
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn complete_fixture() -> tempfile::TempDir {
        let fixture = tempfile::tempdir().expect("create release fixture");
        for asset in required_assets() {
            fs::write(fixture.path().join(asset), b"release bytes")
                .expect("write release fixture asset");
        }
        fixture
    }

    #[test]
    fn accepts_the_compiled_tag_with_the_complete_asset_matrix() {
        let fixture = complete_fixture();
        validate_release(mvm_core::config::DEFAULT_BOOT_IMAGE_TAG, fixture.path())
            .expect("the compiled tag and complete matrix must validate");
    }

    #[test]
    fn rejects_a_tag_that_diverges_from_the_compiled_default() {
        let fixture = complete_fixture();
        let error = validate_release("boot-image/v999.0.0", fixture.path())
            .expect_err("a different tag must fail closed");
        assert!(
            error
                .to_string()
                .contains("refusing to validate different bytes"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn rejects_an_incomplete_asset_matrix() {
        let fixture = complete_fixture();
        let missing = "sdk-sidecar-x86_64-musl.tar.gz.sha256";
        fs::remove_file(fixture.path().join(missing)).expect("remove fixture asset");

        let error = validate_release(mvm_core::config::DEFAULT_BOOT_IMAGE_TAG, fixture.path())
            .expect_err("an incomplete release must fail closed");
        assert!(
            error.to_string().contains(missing),
            "the error must name the missing asset: {error:#}"
        );
    }

    #[test]
    fn rejects_empty_assets_as_missing() {
        let fixture = complete_fixture();
        let empty = "runtime-overlay-aarch64.tar.gz";
        fs::write(fixture.path().join(empty), b"").expect("empty fixture asset");

        let error = validate_release(mvm_core::config::DEFAULT_BOOT_IMAGE_TAG, fixture.path())
            .expect_err("an empty release asset must fail closed");
        assert!(
            error.to_string().contains(empty),
            "the error must name the empty asset: {error:#}"
        );
    }

    #[test]
    fn required_matrix_covers_both_architectures_and_sdk_libcs() {
        let assets = required_assets();
        assert_eq!(assets.len(), 24, "the release matrix must stay exhaustive");
        for arch in ARCHITECTURES {
            assert!(
                assets.iter().any(|asset| asset.contains(arch)),
                "the matrix must include {arch}"
            );
            for libc in SDK_LIBCS {
                let needle = format!("sdk-sidecar-{arch}-{libc}");
                assert!(
                    assets.iter().any(|asset| asset.starts_with(&needle)),
                    "the matrix must include {arch}/{libc}"
                );
            }
        }
    }

    #[test]
    fn nonexistent_artifact_directory_is_an_incomplete_release() {
        let path = PathBuf::from("this-release-directory-does-not-exist");
        let error = validate_release(mvm_core::config::DEFAULT_BOOT_IMAGE_TAG, &path)
            .expect_err("a missing release fixture must fail closed");
        assert!(
            error.to_string().contains("Missing:"),
            "unexpected error: {error:#}"
        );
    }
}

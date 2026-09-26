//! Where a running builder guest finds mvm's own builder binaries.
//!
//! Standard library only: `mvm-builderd` `#[path]`-includes this file rather
//! than linking the `mvm-build` library, like the other builder bins.

use std::path::{Path, PathBuf};

/// Where the boot payload's binaries live in a running builder guest: a
/// directory on the `/run` tmpfs, which survives stage 1's pivot out of the
/// initramfs.
pub const RUNTIME_HOST_BIN_DIR: &str = "/run/mvm/host-bins";

/// Where a legacy builder image bakes its own copies of the builder binaries.
const LEGACY_HOST_BIN_DIR: &str = "/sbin";

/// The path of builder binary `name` inside a running builder guest: the
/// payload's copy when the guest booted with one, the image's baked copy
/// otherwise. Every in-guest caller resolves through here, so a builder booted
/// from the payload never runs a stale baked binary that shares its name.
pub fn guest_host_binary(name: &str) -> PathBuf {
    guest_host_binary_in(
        Path::new(RUNTIME_HOST_BIN_DIR),
        Path::new(LEGACY_HOST_BIN_DIR),
        name,
    )
}

fn guest_host_binary_in(runtime_dir: &Path, legacy_dir: &Path, name: &str) -> PathBuf {
    let from_payload = runtime_dir.join(name);
    if from_payload.is_file() {
        from_payload
    } else {
        legacy_dir.join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_copy_wins_over_the_baked_one() {
        let root = tempfile::tempdir().unwrap();
        let (run, sbin) = (root.path().join("run"), root.path().join("sbin"));
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir_all(&sbin).unwrap();
        std::fs::write(sbin.join("mvm-builderd"), b"baked").unwrap();
        assert_eq!(
            guest_host_binary_in(&run, &sbin, "mvm-builderd"),
            sbin.join("mvm-builderd")
        );
        std::fs::write(run.join("mvm-builderd"), b"payload").unwrap();
        assert_eq!(
            guest_host_binary_in(&run, &sbin, "mvm-builderd"),
            run.join("mvm-builderd")
        );
    }
}

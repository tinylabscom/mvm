//! Finding the seed's `nix` and CA bundle in a Nix store.

use std::path::{Path, PathBuf};

fn find_seed_bin_in(store: &Path, bin: &str) -> Result<PathBuf, String> {
    let entries = std::fs::read_dir(store).map_err(|e| format!("read {}: {e}", store.display()))?;
    for e in entries.flatten() {
        let cand = e.path().join("bin").join(bin);
        if cand.is_file() {
            return Ok(cand);
        }
    }
    Err(format!(
        "seed store has no bin/{bin} (is the nix tarball seed intact?)"
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn find_seed_bin(bin: &str) -> Result<PathBuf, String> {
    find_seed_bin_in(Path::new("/nix/store"), bin)
}

/// Find the seed's CA bundle (`nss-cacert`) for `NIX_SSL_CERT_FILE`.
fn find_seed_cacert_in(store: &Path) -> Result<PathBuf, String> {
    let entries = std::fs::read_dir(store).map_err(|e| format!("read {}: {e}", store.display()))?;
    for e in entries.flatten() {
        let name = e.file_name();
        if name.to_string_lossy().contains("nss-cacert") {
            let bundle = e.path().join("etc/ssl/certs/ca-bundle.crt");
            if bundle.is_file() {
                return Ok(bundle);
            }
        }
    }
    Err("seed store has no nss-cacert ca-bundle.crt".into())
}

#[cfg(target_os = "linux")]
pub(super) fn find_seed_cacert() -> Result<PathBuf, String> {
    find_seed_cacert_in(Path::new("/nix/store"))
}

pub(super) fn seed_store_has_required_runtime(store: &Path) -> Result<bool, String> {
    Ok(find_seed_bin_in(store, "nix").is_ok() && find_seed_cacert_in(store).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_store_runtime_check_requires_nix_and_cacert() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = root.path().join("store");
        std::fs::create_dir_all(store.join("abc-nix/bin")).expect("seed nix dir");
        std::fs::write(store.join("abc-nix/bin/nix"), b"#!/bin/sh\n").expect("seed nix bin");
        std::fs::create_dir_all(store.join("def-nss-cacert/etc/ssl/certs"))
            .expect("seed cacert dir");
        std::fs::write(
            store.join("def-nss-cacert/etc/ssl/certs/ca-bundle.crt"),
            b"dummy cert",
        )
        .expect("seed cacert bundle");
        assert!(
            seed_store_has_required_runtime(&store).expect("runtime check"),
            "store with nix + cacert should be reusable"
        );

        std::fs::remove_file(store.join("abc-nix/bin/nix")).expect("remove nix");
        assert!(
            !seed_store_has_required_runtime(&store).expect("runtime check"),
            "store missing nix must be re-seeded"
        );
    }
}

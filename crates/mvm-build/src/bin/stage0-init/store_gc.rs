//! When Stage 0 garbage-collects its persistent Nix store, and what it keeps.
//!
//! The store is Stage 0's build cache: a later bootstrap reuses the kernel and
//! host binaries it compiled. Nothing bounded it, so every source revision's
//! intermediates stayed until the image hit its 64 GiB ceiling. Stage 0 now
//! collects past the same cap the steady-state builder uses, which keeps a warm
//! cache below it.
//!
//! Collecting safely needs two things the store did not have. The seed's own
//! paths — the `nix` that runs Stage 0 and its CA bundle — were never loaded
//! into the Nix database, and Nix ignores a root that points at an unregistered
//! path and deletes unregistered paths as garbage. So the seed is registered
//! from its `.reginfo` and rooted before any collection, and the build output
//! is rooted so an unchanged next bootstrap is still a cache hit.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use mvm_build::builder_vm_runtime::{DEFAULT_BUILDER_STORE_GC_GIB, STAGE0_STORE_GC_KIB_CONF_KEY};

/// Where Nix looks for roots; a symlink here pins its target's closure.
pub(super) const GC_ROOTS_DIR: &str = "/nix/var/nix/gcroots";

/// The seed's `.reginfo`, copied out of the root disk before the persistent
/// store is bound over `/nix` and hides it.
pub(super) const SEED_REGINFO_STASH: &str = "/run/mvm-stage0-seed.reginfo";

/// The collection threshold, in KiB of used space, from the host's build
/// config. A config without the key — one written by an older host — gets the
/// default that host would have applied to its steady-state store.
pub(super) fn cap_kib(conf: &HashMap<String, String>) -> u64 {
    conf.get(STAGE0_STORE_GC_KIB_CONF_KEY)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|kib| *kib > 0)
        .unwrap_or(u64::from(DEFAULT_BUILDER_STORE_GC_GIB) * 1024 * 1024)
}

/// Whether a store using `used_kib` should be collected.
pub(super) fn over_cap(used_kib: u64, cap_kib: u64) -> bool {
    used_kib > cap_kib
}

/// Used space of a filesystem, in KiB, from its `statvfs` counters.
pub(super) fn used_kib(total_blocks: u64, free_blocks: u64, fragment_size: u64) -> u64 {
    total_blocks
        .saturating_sub(free_blocks)
        .saturating_mul(fragment_size)
        / 1024
}

/// The root pinning the last output of one Stage 0 output mode, so building
/// the kernel does not unroot the image and the reverse.
///
/// `None` for a mode that is not a plain token: it becomes a file name.
pub(super) fn output_root(mode: &str) -> Option<PathBuf> {
    plain_token(mode).then(|| Path::new(GC_ROOTS_DIR).join(format!("mvm-stage0-{mode}")))
}

/// The root pinning one seed component (`nix`, `cacert`).
pub(super) fn seed_root(component: &str) -> PathBuf {
    Path::new(GC_ROOTS_DIR).join(format!("mvm-stage0-seed-{component}"))
}

/// The top-level store path that contains `path`, e.g.
/// `/nix/store/<hash>-nix-2.34/bin/nix` → `/nix/store/<hash>-nix-2.34`.
pub(super) fn store_path_of(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    let prefix = [components.next()?, components.next()?, components.next()?];
    let [
        Component::RootDir,
        Component::Normal(nix),
        Component::Normal(store),
    ] = prefix
    else {
        return None;
    };
    if nix != "nix" || store != "store" {
        return None;
    }
    let Component::Normal(entry) = components.next()? else {
        return None;
    };
    Some(Path::new("/nix/store").join(entry))
}

fn plain_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn the_host_cap_governs_collection() {
        assert_eq!(
            cap_kib(&conf(&[(STAGE0_STORE_GC_KIB_CONF_KEY, "1048576")])),
            1_048_576
        );
    }

    #[test]
    fn a_config_from_an_older_host_gets_the_steady_state_default() {
        assert_eq!(cap_kib(&conf(&[])), 25_165_824);
    }

    #[test]
    fn a_zero_or_garbage_cap_does_not_collect_everything() {
        // Zero would collect on every run and throw away the warm cache.
        for bad in ["0", "", "lots", "-5"] {
            assert_eq!(
                cap_kib(&conf(&[(STAGE0_STORE_GC_KIB_CONF_KEY, bad)])),
                25_165_824,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn only_a_store_past_the_cap_is_collected() {
        assert!(!over_cap(100, 100), "at the cap is not over it");
        assert!(over_cap(101, 100));
        assert!(!over_cap(12 * 1024 * 1024, 24 * 1024 * 1024));
    }

    #[test]
    fn used_space_counts_allocated_blocks_in_kib() {
        assert_eq!(used_kib(1000, 250, 4096), 3000);
        assert_eq!(
            used_kib(10, 20, 4096),
            0,
            "free past total must not underflow"
        );
    }

    #[test]
    fn each_output_mode_has_its_own_root() {
        assert_eq!(
            output_root("kernel"),
            Some(PathBuf::from("/nix/var/nix/gcroots/mvm-stage0-kernel"))
        );
        assert_ne!(output_root("kernel"), output_root("image"));
    }

    #[test]
    fn a_mode_that_is_not_a_plain_token_gets_no_root() {
        for bad in ["", "../escape", "a/b", "sp ace"] {
            assert_eq!(output_root(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_seed_binary_resolves_to_its_whole_store_path() {
        assert_eq!(
            store_path_of(Path::new("/nix/store/abc123-nix-2.34.7/bin/nix")),
            Some(PathBuf::from("/nix/store/abc123-nix-2.34.7"))
        );
        assert_eq!(
            store_path_of(Path::new(
                "/nix/store/def456-nss-cacert-3.101/etc/ssl/certs/ca-bundle.crt"
            )),
            Some(PathBuf::from("/nix/store/def456-nss-cacert-3.101"))
        );
    }

    #[test]
    fn a_path_outside_the_store_has_no_store_path() {
        for path in [
            "/bin/sh",
            "/nix/var/nix/db",
            "nix/store/x/bin/nix",
            "/nix/store",
        ] {
            assert_eq!(store_path_of(Path::new(path)), None, "{path}");
        }
    }
}

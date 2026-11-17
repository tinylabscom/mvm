//! Builder-state and Stage 0 cache locations and repairs behind `mvmctl cache`.
//!
//! Each function runs the build layer's own logic and returns its typed
//! result; none adds authority. Every path honours `MVM_HOME`.

use std::path::PathBuf;

pub use mvm_build::builder_vm::BuilderStoreRepair;
pub use mvm_build::builder_vm_runtime::MVM_BUILDER_STORE_GC_GIB_ENV;
pub use mvm_build::runtime_overlay::RUNTIME_OVERLAY_TREE_CACHE_DIR;

/// `<cache>/builder-vm`: the parent of every persistent builder state dir
/// (`vms/<backend prefix>-*`), whatever the backend.
#[must_use]
pub fn builder_vm_cache_dir() -> PathBuf {
    mvm_build::builder_vm::builder_vm_cache_dir()
}

/// `<cache>/stage0`: where the Stage 0 bootstrap assets are materialized.
#[must_use]
pub fn stage0_cache_dir() -> PathBuf {
    mvm_build::stage0::stage0_cache_dir()
}

/// Cache file names of the Stage 0 blobs this host architecture uses.
#[must_use]
pub fn stage0_blob_filenames() -> Vec<&'static str> {
    mvm_build::stage0::assets_for_host_arch()
        .iter()
        .map(|asset| asset.cache_filename)
        .collect()
}

/// Remove the whole builder-VM cache dir, or only report with `dry_run`.
pub fn clear_builder_store(dry_run: bool) -> std::io::Result<BuilderStoreRepair> {
    mvm_build::builder_vm::clear_builder_store(dry_run)
}

/// Remove only the builder's Nix store image, or only report with `dry_run`.
pub fn clear_builder_store_image(dry_run: bool) -> std::io::Result<BuilderStoreRepair> {
    mvm_build::builder_vm::clear_builder_store_image(dry_run)
}

/// Remove the Stage 0 Nix store image, or only report with `dry_run`.
pub fn clear_stage0_store_image(dry_run: bool) -> std::io::Result<BuilderStoreRepair> {
    mvm_build::builder_vm::clear_stage0_store_image(dry_run)
}

/// The builder-store auto-GC cap in KiB, honouring
/// [`MVM_BUILDER_STORE_GC_GIB_ENV`].
#[must_use]
pub fn builder_store_gc_cap_kib() -> u64 {
    mvm_build::builder_vm_runtime::builder_store_gc_cap_kib()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn cache_dirs_live_under_the_mvm_cache_dir() {
        let _env = TestEnv::new();
        let cache = PathBuf::from(mvm_core::config::mvm_cache_dir());
        assert_eq!(builder_vm_cache_dir(), cache.join("builder-vm"));
        assert_eq!(stage0_cache_dir(), cache.join("stage0"));
    }

    #[test]
    fn stage0_blob_names_match_the_host_assets() {
        let names = stage0_blob_filenames();
        assert!(!names.is_empty());
        assert_eq!(names.len(), mvm_build::stage0::assets_for_host_arch().len());
    }

    #[test]
    fn a_dry_run_on_an_empty_home_reports_nothing_to_clear() {
        let _env = TestEnv::new();
        for repair in [
            clear_builder_store(true),
            clear_builder_store_image(true),
            clear_stage0_store_image(true),
        ] {
            let repair = repair.expect("dry run");
            assert!(repair.dry_run);
            assert!(!repair.existed);
            assert_eq!(repair.bytes_freed, 0);
        }
    }

    #[test]
    fn the_gc_cap_honours_its_env_override() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_STORE_GC_GIB_ENV, "7");
        assert_eq!(builder_store_gc_cap_kib(), 7 * 1024 * 1024);
    }
}

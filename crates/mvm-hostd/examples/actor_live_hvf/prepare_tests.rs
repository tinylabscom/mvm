use super::*;
use mvm_build::builder_vm::GuestSidecar;
use mvm_fs::tree_diff::{EntryKind, Ext4Tree, TreeSource};
use mvm_vmm::host::runtime_meta::admit_runtime_overlay_contract;

#[test]
fn rootfs_artifacts_match_sidecar_and_admit_independently() -> Result<()> {
    let evidence = tempfile::tempdir()?;
    let binary = evidence.path().join("actor.elf");
    let executable = b"\x7fELFfixture-only";
    std::fs::write(&binary, executable)?;
    for role in ["parent", "worker"] {
        let image = rootfs(evidence.path(), role, &binary)?;
        let dir = evidence.path().join(role);
        assert_eq!(image, dir.join("rootfs.ext4"));
        admit_runtime_overlay_contract(&dir)?;
        let meta = GuestSidecar::read_from_dir(&dir)?.context("fixture sidecar missing")?;
        assert_eq!(meta.name, format!("actor-live-{role}"));
        assert!(meta.overlay_aware && meta.runtime_lean);
        assert!(meta.accessible && !meta.sealed);
        assert!(meta.rootless_entrypoint);
        assert_eq!(meta.init_system, "initramfs-agent");
        assert_eq!(meta.hypervisor, "hvf");
        assert_eq!(meta.entrypoint_kind, "command");
        assert_eq!(meta.entrypoint_argv, ["/usr/lib/mvm/wrappers/actor"]);

        let tree = Ext4Tree::open(&image)?;
        let entries = tree.entries(100)?;
        for path in ["mvm/runtime", "mvm/sdk"] {
            assert_eq!(entries[path].kind, EntryKind::Directory, "{path}");
        }
        for path in [
            "usr/local/bin/mvm-guest-agent",
            "usr/local/bin/mvm-guest-netinit",
        ] {
            assert!(!entries.contains_key(path), "baked runtime at {path}");
        }
        assert_eq!(entries["etc/mvm/entrypoint"].mode, 0o444);
        assert_eq!(entries["usr/lib/mvm/wrappers/actor"].mode, 0o555);
        assert_eq!(
            tree.read_regular_file_no_symlinks("etc/mvm/entrypoint", 128)?,
            format!("{}\n", meta.entrypoint_argv[0]).as_bytes()
        );
        assert_eq!(
            tree.read_regular_file_no_symlinks("usr/lib/mvm/wrappers/actor", 128)?,
            executable
        );
        assert_eq!(
            tree.read_regular_file_no_symlinks("etc/mvm/variant", 16)?,
            b"dev\n"
        );

        for (overlay_aware, runtime_lean) in [(false, true), (true, false)] {
            let mut invalid = meta.clone();
            invalid.overlay_aware = overlay_aware;
            invalid.runtime_lean = runtime_lean;
            invalid.write_to_dir(&dir)?;
            assert!(admit_runtime_overlay_contract(&dir).is_err());
        }
        meta.write_to_dir(&dir)?;
    }
    std::fs::remove_file(GuestSidecar::path_in(&evidence.path().join("parent")))?;
    assert!(admit_runtime_overlay_contract(&evidence.path().join("parent")).is_err());
    admit_runtime_overlay_contract(&evidence.path().join("worker"))?;
    assert!(!GuestSidecar::path_in(evidence.path()).exists());
    Ok(())
}

//! Finding the built slot that serves a workload.
//!
//! A language SDK names a function workload by the id it was declared with.
//! The host boots slots, keyed by a hash of where their manifest lives, so the
//! id has to be looked up. The record that ties the two together is the image
//! sidecar every build writes beside a slot's rootfs: a compiled workload's
//! flake builds its guest as `mkGuest { name = <workload id>; }`, and the
//! sidecar records that name. The current revision of each slot is the one a
//! boot would use, so it is the one consulted.
//!
//! A caller that already knows its manifest — a path, or a slot address —
//! skips the lookup; that is resolved exactly as the CLI's `--manifest` is.

use anyhow::{Result, bail};

/// How a caller names the workload a call runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadSource<'a> {
    /// The workload id it was declared with.
    Workload(&'a str),
    /// A manifest path, the directory holding one, or a 64-hex slot address.
    Manifest(&'a str),
}

/// The slot a call boots from.
///
/// # Errors
/// A workload no built slot serves (or more than one does), a manifest that
/// does not resolve, or one that selects a wasm module.
pub fn resolve_slot(source: WorkloadSource<'_>) -> Result<String> {
    match source {
        WorkloadSource::Workload(id) => resolve_workload_slot(id),
        WorkloadSource::Manifest(arg) => {
            match crate::launch::manifest_ref::resolve_manifest_arg(arg)? {
                crate::launch::manifest_ref::ManifestArgRef::Slot { slot_hash } => Ok(slot_hash),
                crate::launch::manifest_ref::ManifestArgRef::WasmModule { .. } => {
                    bail!("wasm module manifests are not supported for entrypoint calls")
                }
            }
        }
    }
}

/// The one built slot whose current image was built for `workload_id`.
///
/// # Errors
/// No slot serves it (with how to build one), or several do (naming each, so
/// the caller can pass the manifest it means).
pub fn resolve_workload_slot(workload_id: &str) -> Result<String> {
    let candidates = slots_serving(workload_id);
    match candidates.as_slice() {
        [only] => Ok(only.slot.clone()),
        [] => bail!(
            "no built image named {workload_id:?} on this host: build it (compile the \
             script with `mvmctl build compile`, then `mvmctl machine build --flake <dir>`) \
             or pass its manifest"
        ),
        many => {
            let listed = many
                .iter()
                .map(|c| format!("{} ({})", c.slot, c.manifest_path))
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "{} built slots serve image {workload_id:?}: {listed}; pass the manifest \
                 to choose one",
                many.len()
            )
        }
    }
}

/// One slot that serves a workload.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    slot: String,
    /// Where the slot's manifest came from, for telling candidates apart.
    manifest_path: String,
}

/// Every slot whose current image records `workload_id` as its name, in slot
/// order so an ambiguity is reported the same way every time.
fn slots_serving(workload_id: &str) -> Vec<Candidate> {
    let base = mvm_core::template::templates_base_dir();
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Vec::new();
    };
    let mut slots: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| mvm_core::manifest::is_slot_hash_dirname(name))
        .collect();
    slots.sort();
    slots
        .into_iter()
        .filter(|slot| image_name(slot).as_deref() == Some(workload_id))
        .map(|slot| Candidate {
            manifest_path: mvm_runtime::vm::template::lifecycle::template_load_slot(&slot)
                .map(|m| m.manifest_path)
                .unwrap_or_else(|_| "manifest unreadable".to_string()),
            slot,
        })
        .collect()
}

/// The name recorded in the sidecar beside a slot's current rootfs, or `None`
/// when the slot has no current revision or no readable sidecar.
fn image_name(slot: &str) -> Option<String> {
    let revision = mvm_runtime::vm::template::lifecycle::current_revision_id_for_slot(slot).ok()?;
    let dir = mvm_core::manifest::slot_revision_dir(slot, &revision);
    mvm_build::builder_vm::GuestSidecar::read_from_dir(std::path::Path::new(&dir))
        .ok()
        .flatten()
        .map(|sidecar| sidecar.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_build::builder_vm::GuestSidecar;
    use mvm_core::util::test_env::TestEnv;

    fn isolated() -> (TestEnv, tempfile::TempDir) {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(home.path());
        (env, home)
    }

    /// Lay a slot out the way a build does: a revision directory holding the
    /// sidecar, the `current` link at it, and the slot's manifest record.
    fn built_slot(slot: &str, image_name: &str) {
        let revision = "rev1";
        let dir = mvm_core::manifest::slot_revision_dir(slot, revision);
        std::fs::create_dir_all(&dir).expect("revision dir");
        GuestSidecar::for_oci_run(image_name, true, true)
            .write_to_dir(std::path::Path::new(&dir))
            .expect("sidecar");
        std::os::unix::fs::symlink(
            format!("artifacts/revisions/{revision}"),
            mvm_core::manifest::slot_current_symlink(slot),
        )
        .expect("current link");
        let manifest = serde_json::json!({
            "manifest_path": format!("/src/{image_name}/mvm.toml"),
            "manifest_hash": slot,
            "flake_ref": ".",
            "profile": "default",
            "vcpus": 1,
            "mem_mib": 256,
            "data_disk_mib": 0,
            "backend": "mock",
            "provenance": {
                "toolchain_version": "0",
                "host_arch": "x",
                "built_at": "2026-01-01T00:00:00Z",
            },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        });
        std::fs::write(
            mvm_core::manifest::slot_manifest_path(slot),
            serde_json::to_vec(&manifest).expect("json"),
        )
        .expect("manifest record");
    }

    #[test]
    fn a_workload_built_once_resolves_to_its_slot() {
        let _home = isolated();
        let slot = "a".repeat(64);
        built_slot(&slot, "adder");
        built_slot(&"b".repeat(64), "other");
        assert_eq!(resolve_workload_slot("adder").expect("resolves"), slot);
    }

    #[test]
    fn a_workload_nobody_built_says_how_to_build_it() {
        let _home = isolated();
        let error = resolve_workload_slot("adder").expect_err("nothing built");
        let rendered = error.to_string();
        assert!(
            rendered.contains("no built image named \"adder\""),
            "{rendered}"
        );
        assert!(rendered.contains("mvmctl machine build"), "{rendered}");
    }

    #[test]
    fn a_workload_built_twice_names_both_candidates() {
        let _home = isolated();
        built_slot(&"a".repeat(64), "adder");
        built_slot(&"c".repeat(64), "adder");
        let error = resolve_workload_slot("adder").expect_err("ambiguous");
        let rendered = error.to_string();
        assert!(rendered.starts_with("2 built slots"), "{rendered}");
        assert!(rendered.contains(&"a".repeat(64)), "{rendered}");
        assert!(rendered.contains(&"c".repeat(64)), "{rendered}");
        assert!(rendered.contains("/src/adder/mvm.toml"), "{rendered}");
    }

    #[test]
    fn a_slot_without_a_current_revision_serves_nothing() {
        let _home = isolated();
        let slot = "d".repeat(64);
        std::fs::create_dir_all(mvm_core::manifest::slot_dir(&slot)).expect("slot dir");
        assert!(resolve_workload_slot("adder").is_err());
    }

    #[test]
    fn a_manifest_source_that_does_not_exist_is_refused() {
        let _home = isolated();
        assert!(resolve_slot(WorkloadSource::Manifest("/no/such/mvm.toml")).is_err());
    }

    #[test]
    fn a_workload_source_goes_through_the_lookup() {
        let _home = isolated();
        let slot = "e".repeat(64);
        built_slot(&slot, "echo");
        assert_eq!(
            resolve_slot(WorkloadSource::Workload("echo")).expect("resolves"),
            slot
        );
    }
}

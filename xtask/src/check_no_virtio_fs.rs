//! Ratchet on the virtio-fs surface: it may shrink, never grow.
//!
//! virtio-fs puts a FUSE server on the host — in a daemon for QEMU, in the
//! VMM's own address space for libkrun and HVF — and points it at a host
//! directory. Every request it parses arrives from the guest. That is a large,
//! guest-driven parser on the wrong side of the boundary, and it is the one
//! mechanism by which a guest addresses host filesystem *structure* rather than
//! opaque blocks. A block device is a byte array with no protocol to attack.
//!
//! No workload tier reaches it any more. What is left is builder-VM plumbing
//! and the libkrun C FFI, each pinned below with the reason it survives and
//! what would retire it. This check does not assert the surface is gone — it asserts
//! nothing has been *added* to it, and that entries disappear from the table as
//! the code disappears.
//!
//! The check counts only sites that **attach a device or construct a share**.
//! Prose mentioning virtio-fs is not counted: ~70 files discuss it, and a gate
//! that fired on the word would be noise, gamed by rewording rather than by
//! deleting code.

use anyhow::{Result, bail};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;

use crate::fs_walk::for_each_file;
use crate::rust_source::blank_comments_and_strings;

/// Sites that attach a virtio-fs device to a guest, or build the share value
/// that becomes one. Deliberately narrow — see the module comment.
const ATTACH_PATTERN: &str = r"add_virtiofs[0-9]?\(|VirtioFs::(new|with_tag)|VirtioFsShare\s*\{|HvfVirtioFsShare\s*\{|krun_add_virtiofs";

/// The pinned surface: `(path, count, why it is still here)`.
///
/// Lower a count when you delete a site; delete the row when it reaches zero.
/// The check fails on a count that is too high (something was added) *and* on
/// one that is too low (something was removed without updating this table), so
/// the number stays a true statement about the tree rather than a ceiling that
/// drifts.
const PINNED: &[(&str, usize, &str)] = &[
    // ── the C API, declared whether or not we call it ────────────────────────
    (
        "crates/deps/libkrun-sys/src/sys.rs",
        6,
        "the libkrun C FFI's safe wrapper; declares the API the dylib exports",
    ),
    (
        "crates/deps/libkrun-sys/src/start.rs",
        3,
        "maps SupervisorConfig mounts onto the libkrun C API for the builder VM",
    ),
    // ── builder VM: the trusted tier, still exchanging files as shares ───────
    (
        "crates/mvm-runtime/src/builder_runner/spec.rs",
        1,
        "the HVF *persistent* builder's work/mvm-bins/job/out shares. Retired by \
         moving the per-dispatch exchange onto the BuilderDispatch vsock channel \
         that already exists; the one-shot builder already uses the disk transport",
    ),
    // ── the seam every backend maps its shares through ───────────────────────
    (
        "crates/mvm-vmm/src/driver/spec.rs",
        1,
        "the VirtioFsShare type itself; empty for every workload spec",
    ),
    (
        "crates/mvm-vmm/src/host/hvf_supervisor.rs",
        1,
        "HvfVirtioFsShare on the supervisor wire config, builder VMs only",
    ),
    (
        "crates/mvm-backends/src/driver/hvf.rs",
        1,
        "maps spec shares onto the HVF supervisor config",
    ),
    (
        "crates/mvm-backends/src/driver/libkrun.rs",
        5,
        "one mapper plus tests asserting a workload spec carries no shares",
    ),
    (
        "crates/mvm-backends/src/driver/qemu.rs",
        2,
        "QEMU's vhost-user/virtiofsd wiring. Opt-in dev/test only — auto_select \
         never returns it and it carries no untrusted workload, so this is the \
         one backend where deleting the feature outright is defensible",
    ),
    (
        "crates/mvm-backends/src/driver/fc.rs",
        1,
        "a test: Firecracker must keep *refusing* a share",
    ),
    // ── the HVF device model ─────────────────────────────────────────────────
    (
        "crates/mvm-vmm/src/vmm/virtio.rs",
        1,
        "the VirtioFs MMIO device. Reachable only from a builder VM now that the \
         dev-tier virtio-fs root is gone",
    ),
    (
        "crates/mvm-runtime/src/backends/hvf/kernel_boot.rs",
        1,
        "attaches the builder's shares to the HVF device model",
    ),
];

pub fn run(workspace: &Path) -> Result<()> {
    let re = Regex::new(ATTACH_PATTERN).expect("attach pattern compiles");
    let mut found: BTreeMap<String, usize> = BTreeMap::new();

    for dir in ["crates", "src", "xtask"] {
        let root = workspace.join(dir);
        if !root.exists() {
            continue;
        }
        for_each_file(&root, Some("rs"), &mut |path, source| {
            // The FFI's generated bindings declare the C symbols and are not a
            // call site; counting them would pin bindgen output.
            let rel = match path.strip_prefix(workspace) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => return,
            };
            if rel.ends_with("libkrun_bindings.rs") || rel.starts_with("xtask/") {
                return;
            }
            let code = blank_comments_and_strings(source);
            let n = re.find_iter(&code).count();
            if n > 0 {
                found.insert(rel, n);
            }
        })?;
    }

    let pinned: BTreeMap<&str, (usize, &str)> =
        PINNED.iter().map(|(p, n, why)| (*p, (*n, *why))).collect();

    let mut problems: Vec<String> = Vec::new();

    for (path, n) in &found {
        match pinned.get(path.as_str()) {
            None => problems.push(format!(
                "NEW virtio-fs surface in {path} ({n} site(s)).\n    \
                 virtio-fs is being removed, not extended. Attach a block device \
                 instead — or, if this is genuinely builder-VM plumbing, add a \
                 row to PINNED in xtask/src/check_no_virtio_fs.rs saying why and \
                 what retires it."
            )),
            Some((want, _)) if n > want => problems.push(format!(
                "{path} grew from {want} to {n} virtio-fs site(s). The surface \
                 may shrink, never grow."
            )),
            Some((want, _)) if n < want => problems.push(format!(
                "{path} shrank from {want} to {n} virtio-fs site(s) — good. \
                 Lower its count in xtask/src/check_no_virtio_fs.rs so the table \
                 stays a true statement about the tree."
            )),
            Some(_) => {}
        }
    }

    for (path, (want, _)) in &pinned {
        if !found.contains_key(*path) {
            problems.push(format!(
                "{path} is pinned at {want} virtio-fs site(s) but has none left. \
                 Delete its row from xtask/src/check_no_virtio_fs.rs."
            ));
        }
    }

    if !problems.is_empty() {
        bail!(
            "check-no-virtio-fs failed:\n  - {}",
            problems.join("\n  - ")
        );
    }

    let total: usize = found.values().sum();
    println!(
        "check-no-virtio-fs: clean ({total} attach/construct sites across {} pinned \
         files, all builder-VM or FFI; no workload tier reaches virtio-fs)",
        found.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits under the workspace root")
            .to_path_buf()
    }

    #[test]
    fn passes_on_this_workspace() {
        run(&workspace()).expect("the pinned table matches the tree");
    }

    #[test]
    fn the_pattern_catches_every_way_a_share_is_attached_or_built() {
        // A gate that cannot fail is decoration. Each of these is a real form
        // that appears in the tree; if the pattern stops matching one, a whole
        // class of attach site goes invisible to the ratchet.
        let re = Regex::new(ATTACH_PATTERN).unwrap();
        for form in [
            "krun.add_virtiofs(&tag, path)",
            "krun.add_virtiofs2(&tag, path, shm)",
            "krun.add_virtiofs3(&tag, path, shm, true)",
            "bindings::krun_add_virtiofs(ctx, tag, path)",
            "VirtioFs::new(base, irq, ram, RAM_BASE, size, root)",
            "VirtioFs::with_tag(base, irq, ram, RAM_BASE, size, root, tag)",
            "let s = VirtioFsShare { tag, host_path, read_only, dax };",
            "HvfVirtioFsShare { path, tag }",
        ] {
            assert!(re.is_match(form), "pattern missed an attach form: {form}");
        }
    }

    #[test]
    fn prose_alone_does_not_count_as_surface() {
        // ~70 files discuss virtio-fs. Counting the word would make the gate
        // noise, and would let someone satisfy it by rewording a comment rather
        // than deleting code.
        let re = Regex::new(ATTACH_PATTERN).unwrap();
        let source = concat!(
            "/// libkrun's `krun_add_virtiofs` has no read-only toggle.\n",
            "// VirtioFsShare { .. } used to be built here.\n",
            "fn f() { let msg = \"krun_add_virtiofs\"; }\n",
        );
        let code = blank_comments_and_strings(source);
        assert_eq!(re.find_iter(&code).count(), 0);
    }

    #[test]
    fn every_pinned_row_names_a_distinct_file_and_gives_a_reason() {
        let mut seen = std::collections::BTreeSet::new();
        for (path, count, why) in PINNED {
            assert!(seen.insert(*path), "{path} is pinned twice");
            assert!(*count > 0, "{path} is pinned at zero; delete the row");
            assert!(
                why.len() > 20,
                "{path} needs a reason a reader can act on, not a label"
            );
        }
    }
}

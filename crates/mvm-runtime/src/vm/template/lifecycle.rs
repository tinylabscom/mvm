use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use mvm_core::template::{
    SnapshotInfo, TemplateSpec, template_dir, template_revision_dir, template_snapshot_dir,
    template_spec_path,
};

use tracing::{instrument, warn};

use crate::shell;
use crate::ui;
use mvm_core::pool::ArtifactPaths;
use mvm_core::template::{TemplateRevision, template_current_symlink};
use mvm_core::time::utc_now;

use super::registry::TemplateRegistry;

/// Run a shell command in the VM and check its exit code.
/// Returns an error with stderr context if the command fails.
fn vm_exec(script: &str) -> Result<()> {
    let out = shell::run_in_vm(script)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let first_line = script.lines().next().unwrap_or(script);
        return Err(anyhow!(
            "Command failed (exit {}): {}\n  command: {}",
            out.status.code().unwrap_or(-1),
            stderr,
            first_line,
        ));
    }
    Ok(())
}

/// Run a shell command in the VM, check exit code, and return stdout.
fn vm_exec_stdout(script: &str) -> Result<String> {
    let out = shell::run_in_vm(script)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let first_line = script.lines().next().unwrap_or(script);
        return Err(anyhow!(
            "Command failed (exit {}): {}\n  command: {}",
            out.status.code().unwrap_or(-1),
            stderr,
            first_line,
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[instrument(skip_all, fields(template_id = %spec.template_id))]
pub fn template_create(spec: &TemplateSpec) -> Result<()> {
    let dir = template_dir(&spec.template_id);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create template directory {}", dir))?;
    let path = template_spec_path(&spec.template_id);
    let json = serde_json::to_string_pretty(spec)?;
    std::fs::write(&path, json)
        .with_context(|| format!("Failed to write template spec {}", path))?;
    Ok(())
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_load(id: &str) -> Result<TemplateSpec> {
    let path = template_spec_path(id);
    // Read directly from host filesystem — ~/.mvm/ resolves to $HOME/.mvm
    // which is the same path on both host and Lima (home dir is mounted).
    let data = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "Failed to load template {} (does it exist? try `mvm template list`)",
            id
        )
    })?;
    let spec: TemplateSpec =
        serde_json::from_str(&data).with_context(|| format!("Corrupt template {}", id))?;
    Ok(spec)
}

#[instrument(skip_all)]
pub fn template_list() -> Result<Vec<String>> {
    let base = mvm_core::template::templates_base_dir();
    let entries = match std::fs::read_dir(&base) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to list templates dir {}", base));
        }
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    Ok(names)
}

#[instrument(skip_all, fields(template_id = id, force))]
pub fn template_delete(id: &str, force: bool) -> Result<()> {
    let dir = template_dir(id);
    let path = std::path::Path::new(&dir);
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && force => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to delete template {}", id)),
    }
}

/// Initialize an on-disk template directory layout (empty artifacts, no spec).
/// Safe to call multiple times; existing contents are preserved.
#[instrument(skip_all, fields(template_id = id))]
pub fn template_init(id: &str) -> Result<()> {
    let dir = template_dir(id);
    let artifacts = format!("{}/artifacts/revisions", dir);
    vm_exec(&format!("mkdir -p {dir} {artifacts}"))
        .with_context(|| format!("Failed to initialize template directory {}", dir))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan 38 slice 4: manifest-keyed slot primitives.
//
// These coexist with the legacy name-keyed primitives above. They operate on
// `~/.mvm/templates/<sha256(canonical_manifest_path)>/manifest.json` —
// `PersistedManifest` is the slot-resident JSON record from slice 2. Callers
// migrate slice-by-slice; nothing in the legacy path changes here.
// ---------------------------------------------------------------------------

use mvm_core::manifest::{
    PersistedManifest, Provenance, is_slot_hash_dirname, slot_current_symlink, slot_dir,
    slot_dir_for_manifest_path, slot_revision_dir,
};

/// One row produced by [`template_list_slots`]. Contains just the
/// fields a UI/MCP caller needs without re-loading every slot's
/// `manifest.json` per query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotEntry {
    pub slot_hash: String,
    pub manifest_path: String,
    pub name: Option<String>,
    pub updated_at: String,
}

/// Persist a [`PersistedManifest`] to its registry slot. The slot
/// directory is derived from the record's `manifest_hash`. Atomic
/// (write-temp-then-rename via [`PersistedManifest::write_to_slot`]).
#[instrument(skip_all, fields(slot_hash = %persisted.manifest_hash))]
pub fn template_persist_slot(persisted: &PersistedManifest) -> Result<()> {
    let dir = slot_dir(&persisted.manifest_hash);
    persisted.write_to_slot(std::path::Path::new(&dir))
}

/// Load the slot record for a given `slot_hash`. Returns the
/// deserialised [`PersistedManifest`] from
/// `~/.mvm/templates/<slot_hash>/manifest.json`.
#[instrument(skip_all, fields(slot_hash = slot_hash))]
pub fn template_load_slot(slot_hash: &str) -> Result<PersistedManifest> {
    let dir = slot_dir(slot_hash);
    PersistedManifest::read_from_slot(std::path::Path::new(&dir))
}

/// Convenience: load the slot record for a given manifest filesystem
/// path. Computes `sha256(canonical_path)` then delegates to
/// [`template_load_slot`].
#[instrument(skip_all, fields(manifest_path = %path.display()))]
pub fn template_load_slot_for_manifest_path(path: &std::path::Path) -> Result<PersistedManifest> {
    let dir = slot_dir_for_manifest_path(path)?;
    PersistedManifest::read_from_slot(std::path::Path::new(&dir))
}

/// Remove a slot directory by hash. With `force = true`, a missing
/// slot is not an error (idempotent cleanup). Mirrors today's
/// [`template_delete`] behaviour for the slot-keyed world.
#[instrument(skip_all, fields(slot_hash = slot_hash, force))]
pub fn template_delete_slot(slot_hash: &str, force: bool) -> Result<()> {
    let dir = slot_dir(slot_hash);
    let path = std::path::Path::new(&dir);
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && force => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to delete slot {}", slot_hash)),
    }
}

/// Pure helper: split a list of directory entries from
/// `~/.mvm/templates/` into modern hash-keyed and legacy name-keyed
/// buckets. Independent of the filesystem so it is straightforwardly
/// unit-testable.
fn classify_template_dir_entries<I>(entries: I) -> (Vec<String>, Vec<String>)
where
    I: IntoIterator<Item = String>,
{
    let mut hashes = Vec::new();
    let mut legacy = Vec::new();
    for name in entries {
        if is_slot_hash_dirname(&name) {
            hashes.push(name);
        } else {
            legacy.push(name);
        }
    }
    hashes.sort();
    legacy.sort();
    (hashes, legacy)
}

/// Read the immediate child directory names under
/// `~/.mvm/templates/`. Returns an empty vec when the base dir
/// doesn't exist yet (fresh install).
fn read_templates_base_subdir_names() -> Result<Vec<String>> {
    let base = mvm_core::template::templates_base_dir();
    let entries = match std::fs::read_dir(&base) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to list templates dir {}", base));
        }
    };
    let names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    Ok(names)
}

/// List modern hash-keyed slot directory names. Use
/// [`template_list_slots`] when you also need each slot's metadata.
#[instrument(skip_all)]
pub fn template_list_slot_hashes() -> Result<Vec<String>> {
    let names = read_templates_base_subdir_names()?;
    let (hashes, _) = classify_template_dir_entries(names);
    Ok(hashes)
}

/// List legacy name-keyed template directory names — anything in
/// `~/.mvm/templates/` whose dirname isn't a 64-char lowercase-hex
/// slot hash. Powers the §8a migration banner / `template list
/// --legacy` (slice 8).
#[instrument(skip_all)]
pub fn template_list_legacy_names() -> Result<Vec<String>> {
    let names = read_templates_base_subdir_names()?;
    let (_, legacy) = classify_template_dir_entries(names);
    Ok(legacy)
}

/// Read a slot's `current` symlink and return the revision hash it
/// points at. Mirrors [`current_revision_id`] for the slot-keyed world.
#[instrument(skip_all, fields(slot_hash = slot_hash))]
pub fn current_revision_id_for_slot(slot_hash: &str) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let link = slot_current_symlink(slot_hash);
    let target = std::fs::read_link(&link)
        .with_context(|| format!("Slot has no current revision: {}", link))?;
    let raw = target.as_os_str().as_bytes();
    let raw = std::str::from_utf8(raw)
        .unwrap_or_default()
        .trim()
        .to_string();
    // Symlink target is relative `artifacts/revisions/<rev>`; strip the
    // prefix to recover the bare revision hash.
    let rev = raw
        .strip_prefix("artifacts/revisions/")
        .unwrap_or(&raw)
        .to_string();
    if rev.is_empty() {
        anyhow::bail!("Slot current symlink is empty: {}", link);
    }
    Ok(rev)
}

/// Resolve a slot to its current artifact paths. Mirrors
/// [`template_artifacts`] but keyed by slot hash; returns the
/// [`PersistedManifest`] in place of [`TemplateSpec`].
///
/// Returns `(persisted_manifest, vmlinux, initrd, rootfs, revision_hash)`.
#[instrument(skip_all, fields(slot_hash = slot_hash))]
pub fn template_artifacts_for_slot(
    slot_hash: &str,
) -> Result<(PersistedManifest, String, Option<String>, String, String)> {
    let persisted = template_load_slot(slot_hash)?;
    let rev = current_revision_id_for_slot(slot_hash)?;
    let rev_dir = slot_revision_dir(slot_hash, &rev);

    let vmlinux = format!("{rev_dir}/vmlinux");
    let rootfs = format!("{rev_dir}/rootfs.ext4");
    let initrd_candidate = format!("{rev_dir}/initrd");

    if !std::path::Path::new(&vmlinux).exists() {
        anyhow::bail!(
            "Slot '{}' has no vmlinux (run `mvmctl build {}`)",
            slot_hash,
            persisted.manifest_path
        );
    }
    if !std::path::Path::new(&rootfs).exists() {
        anyhow::bail!(
            "Slot '{}' has no rootfs (run `mvmctl build {}`)",
            slot_hash,
            persisted.manifest_path
        );
    }

    let has_initrd = std::path::Path::new(&initrd_candidate).exists();
    let initrd_path = if has_initrd {
        Some(initrd_candidate)
    } else {
        None
    };

    Ok((persisted, vmlinux, initrd_path, rootfs, rev))
}

/// Whether the slot's current revision has a Firecracker snapshot.
pub fn template_has_snapshot_for_slot(slot_hash: &str) -> Result<bool> {
    let rev = current_revision_id_for_slot(slot_hash)?;
    let snap_dir = mvm_core::manifest::slot_snapshot_dir(slot_hash, &rev);
    let vmstate = std::path::Path::new(&snap_dir).join("vmstate.bin");
    let mem = std::path::Path::new(&snap_dir).join("mem.bin");
    Ok(vmstate.exists() && mem.exists())
}

/// Load snapshot metadata for the slot's current revision.
pub fn template_snapshot_info_for_slot(slot_hash: &str) -> Result<Option<SnapshotInfo>> {
    let rev = current_revision_id_for_slot(slot_hash)?;
    let rev_dir = slot_revision_dir(slot_hash, &rev);
    let meta_path = format!("{}/revision.json", rev_dir);
    let data = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("Failed to read revision.json for slot {}", slot_hash))?;
    let revision: TemplateRevision = serde_json::from_str(&data)
        .with_context(|| format!("Corrupt revision.json for slot {}", slot_hash))?;
    Ok(revision.snapshot)
}

/// Synthesize a [`TemplateSpec`] from a [`PersistedManifest`] so the
/// dispatched functions below can return a single shape regardless of
/// whether the caller passed a name or a slot hash.
///
/// `template_id` is set to the manifest hash; `role` is empty (manifest
/// schema doesn't carry a role); `default_network_policy` is `None`
/// (the manifest schema doesn't carry network policy either —
/// runtime policy comes from CLI flags / `~/.mvm/config.toml` / mvmd
/// per plan 38).
fn persisted_to_synthetic_spec(p: &PersistedManifest) -> TemplateSpec {
    TemplateSpec {
        schema_version: p.schema_version,
        template_id: p.manifest_hash.clone(),
        flake_ref: p.flake_ref.clone(),
        profile: p.profile.clone(),
        role: String::new(),
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        data_disk_mib: p.data_disk_mib,
        created_at: p.created_at.clone(),
        updated_at: p.updated_at.clone(),
        default_network_policy: None,
    }
}

/// Unified entry point that dispatches to the slot-keyed function when
/// `id_or_slot` looks like a 64-char lowercase-hex slot hash, or to
/// the legacy name-keyed function otherwise.
///
/// Used by `mvmctl up`/`run`/`exec` so the CLI can resolve a
/// `--template <PATH>` argument to a slot hash and pass it through
/// unchanged. Returns the same shape as [`template_artifacts`].
#[instrument(skip_all, fields(id_or_slot = id_or_slot))]
pub fn template_artifacts_dispatched(
    id_or_slot: &str,
) -> Result<(TemplateSpec, String, Option<String>, String, String)> {
    if is_slot_hash_dirname(id_or_slot) {
        let (persisted, vmlinux, initrd, rootfs, rev) =
            template_artifacts_for_slot(id_or_slot)?;
        Ok((
            persisted_to_synthetic_spec(&persisted),
            vmlinux,
            initrd,
            rootfs,
            rev,
        ))
    } else {
        template_artifacts(id_or_slot)
    }
}

/// Dispatched variant of [`template_load`] / [`template_load_slot`].
/// Returns a [`TemplateSpec`] regardless of which key shape was used.
pub fn template_load_dispatched(id_or_slot: &str) -> Result<TemplateSpec> {
    if is_slot_hash_dirname(id_or_slot) {
        let persisted = template_load_slot(id_or_slot)?;
        Ok(persisted_to_synthetic_spec(&persisted))
    } else {
        template_load(id_or_slot)
    }
}

/// Dispatched variant of [`template_snapshot_info`] /
/// [`template_snapshot_info_for_slot`].
pub fn template_snapshot_info_dispatched(id_or_slot: &str) -> Result<Option<SnapshotInfo>> {
    if is_slot_hash_dirname(id_or_slot) {
        template_snapshot_info_for_slot(id_or_slot)
    } else {
        template_snapshot_info(id_or_slot)
    }
}

/// Dispatched variant of [`template_has_snapshot`] /
/// [`template_has_snapshot_for_slot`].
pub fn template_has_snapshot_dispatched(id_or_slot: &str) -> Result<bool> {
    if is_slot_hash_dirname(id_or_slot) {
        template_has_snapshot_for_slot(id_or_slot)
    } else {
        template_has_snapshot(id_or_slot)
    }
}

/// Verify a slot's artifacts against its `checksums.json`. Returns
/// `Ok(())` if every recorded file matches; an error otherwise listing
/// which file mismatched. The checksums file is written by
/// `template_push_slot` (slice 8b) and is also produced inline by
/// `template_build_from_manifest` once push lands; until then a slot
/// without a `checksums.json` errors with a hint.
///
/// `revision` selects a specific revision; `None` resolves the slot's
/// `current` symlink.
#[instrument(skip_all, fields(slot_hash = slot_hash, revision = ?revision))]
pub fn template_verify_slot(slot_hash: &str, revision: Option<&str>) -> Result<()> {
    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id_for_slot(slot_hash)?,
    };
    let rev_dir = std::path::PathBuf::from(slot_revision_dir(slot_hash, &rev));
    let sums_path = rev_dir.join("checksums.json");
    let sums_bytes = std::fs::read(&sums_path).with_context(|| {
        format!(
            "Missing {} — checksums are written by `mvmctl manifest push` (slice 8b not yet shipped). Run `mvmctl build --force` to repopulate the slot, then verify will work after push lands.",
            sums_path.display()
        )
    })?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)
        .with_context(|| format!("Corrupt {}", sums_path.display()))?;

    let mut mismatches = Vec::new();
    for (name, expected_hex) in &checksums.files {
        let path = rev_dir.join(name);
        if !path.exists() {
            mismatches.push(format!("{}: missing", name));
            continue;
        }
        let actual = sha256_hex(&path)?;
        if &actual != expected_hex {
            mismatches.push(format!(
                "{}: expected {}, got {}",
                name,
                &expected_hex[..expected_hex.len().min(12)],
                &actual[..actual.len().min(12)]
            ));
        }
    }

    if !mismatches.is_empty() {
        anyhow::bail!(
            "Slot {} revision {} failed verification:\n  - {}",
            slot_hash,
            rev,
            mismatches.join("\n  - ")
        );
    }
    Ok(())
}

/// Cleanup pass — remove slots whose source manifest file is missing
/// on disk (e.g. the user `rm`'d their project directory or moved it
/// elsewhere, leaving the slot dangling under `~/.mvm/templates/`).
///
/// Returns `(removed_count, slots_removed)`. Errors on individual
/// slot deletes are logged at warn but don't abort the sweep — a
/// single corrupted slot shouldn't block cleaning up the rest.
///
/// Slots whose `manifest.json` is missing or unparseable are also
/// considered orphaned (we can't cross-reference them, so we treat
/// them as garbage to clean up).
#[instrument(skip_all)]
pub fn template_prune_orphan_slots() -> Result<(usize, Vec<String>)> {
    let mut removed = Vec::new();
    for slot_hash in template_list_slot_hashes()? {
        let persisted = match template_load_slot(&slot_hash) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(slot = %slot_hash, error = %e, "removing slot with unreadable manifest.json");
                if let Err(rm_err) = template_delete_slot(&slot_hash, true) {
                    tracing::warn!(slot = %slot_hash, error = %rm_err, "failed to remove unreadable slot");
                    continue;
                }
                removed.push(slot_hash);
                continue;
            }
        };

        if !std::path::Path::new(&persisted.manifest_path).exists() {
            tracing::info!(
                slot = %slot_hash,
                manifest_path = %persisted.manifest_path,
                "removing orphaned slot (manifest file gone)"
            );
            if let Err(e) = template_delete_slot(&slot_hash, true) {
                tracing::warn!(slot = %slot_hash, error = %e, "failed to remove orphaned slot");
                continue;
            }
            removed.push(slot_hash);
        }
    }
    let count = removed.len();
    Ok((count, removed))
}

/// List modern slots with their metadata (manifest path, optional
/// display name, last-updated timestamp). Slots whose
/// `manifest.json` is missing or unparseable are skipped with a
/// warn log — listing should never fail end-to-end on a single
/// corrupt slot.
#[instrument(skip_all)]
pub fn template_list_slots() -> Result<Vec<SlotEntry>> {
    let mut out = Vec::new();
    for slot_hash in template_list_slot_hashes()? {
        match template_load_slot(&slot_hash) {
            Ok(persisted) => out.push(SlotEntry {
                slot_hash,
                manifest_path: persisted.manifest_path,
                name: persisted.name,
                updated_at: persisted.updated_at,
            }),
            Err(e) => {
                tracing::warn!(slot = %slot_hash, error = %e, "skipping unreadable slot");
            }
        }
    }
    out.sort_by(|a, b| a.slot_hash.cmp(&b.slot_hash));
    Ok(out)
}

/// Build a manifest-keyed slot using the dev build pipeline (local Nix in
/// Lima or host). Mirrors [`template_build`] but operates on a
/// [`PersistedManifest`] from slice 2 instead of looking up by name.
///
/// On success, the slot's `current` symlink points at
/// `artifacts/revisions/<revision_hash>/`, the persisted manifest record
/// is refreshed (`updated_at` + `provenance`), and a `revision.json` is
/// written next to the artifacts. Returns the [`TemplateRevision`] for
/// display / further use.
///
/// `force` clears the dev build cache (`~/.mvm/dev/builds/`) so the
/// underlying Nix build runs from scratch. `update_hash` recomputes the
/// FOD hash in the flake first (rare; used after package version bumps).
#[instrument(skip_all, fields(slot_hash = %persisted.manifest_hash, force, update_hash))]
pub fn template_build_from_manifest(
    persisted: &PersistedManifest,
    force: bool,
    update_hash: bool,
) -> Result<TemplateRevision> {
    use crate::ui;

    let build_env = crate::build_env::default_build_env();
    let env = build_env.as_ref();

    ui::info(&format!(
        "Building manifest at '{}' (flake: {}, profile: {})",
        persisted.manifest_path, persisted.flake_ref, persisted.profile
    ));

    if update_hash {
        update_fod_hash(&persisted.flake_ref)?;
    }

    if force {
        ui::info("Force build: clearing dev build cache");
        let builds_dir = format!("{}/dev/builds", mvm_core::config::mvm_data_dir());
        if let Err(e) = env.shell_exec(&format!("rm -rf {builds_dir}")) {
            warn!("failed to clear dev build cache: {e}");
        }
    }

    let result =
        mvm_build::dev_build::dev_build(env, &persisted.flake_ref, Some(&persisted.profile))?;

    if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(env, &result) {
        ui::warn(&format!(
            "Could not verify guest agent ({}). If built with mvm's mkGuest, the agent is already included.",
            e
        ));
    }

    // Store artifacts under the slot's revision directory.
    let slot_hash = &persisted.manifest_hash;
    let rev = &result.revision_hash;
    let rev_dst = slot_revision_dir(slot_hash, rev);
    ui::info("Storing artifacts in slot revision directory...");
    shell::run_in_vm(&format!("mkdir -p {rev_dst}"))?;
    shell::run_in_vm(&format!("cp -a {} {rev_dst}/vmlinux", result.vmlinux_path))?;
    if let Some(initrd) = &result.initrd_path {
        shell::run_in_vm(&format!("cp -a {} {rev_dst}/initrd", initrd))?;
    }
    shell::run_in_vm(&format!(
        "cp -a {} {rev_dst}/rootfs.ext4 && chmod u+w {rev_dst}/rootfs.ext4",
        result.rootfs_path
    ))?;

    // Generate a minimal fc-base.json for reference. Same logic as
    // template_build: minimal guests (no initrd) need root= and init=
    // on the kernel cmdline; initrd-bearing guests rely on the initrd's
    // /init.
    let boot_args = if result.initrd_path.is_some() {
        "console=ttyS0 reboot=k panic=1 net.ifnames=0".to_string()
    } else {
        "root=/dev/vda rw rootwait init=/init console=ttyS0 reboot=k panic=1 net.ifnames=0"
            .to_string()
    };
    let mut boot_source = serde_json::json!({
        "kernel_image_path": "vmlinux",
        "boot_args": boot_args
    });
    if result.initrd_path.is_some() {
        boot_source["initrd_path"] = serde_json::json!("initrd");
    }
    let fc_config = serde_json::json!({
        "boot-source": boot_source,
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": "rootfs.ext4",
            "is_root_device": true,
            "is_read_only": false
        }],
        "machine-config": {
            "vcpu_count": persisted.vcpus,
            "mem_size_mib": persisted.mem_mib
        }
    });
    let fc_json = serde_json::to_string_pretty(&fc_config)?;
    shell::run_in_vm(&format!(
        "cat > {rev_dst}/fc-base.json << 'MVMEOF'\n{fc_json}\nMVMEOF"
    ))?;

    // Update the slot's `current` symlink (relative target so the slot
    // is portable across host filesystems).
    let current_link = slot_current_symlink(slot_hash);
    shell::run_in_vm(&format!(
        "ln -snf artifacts/revisions/{rev} {current_link}"
    ))?;

    // Compute the actual flake.lock hash for accurate cache keys.
    // Pool builds delegate this; dev/manifest builds compute it inline.
    // Falls back to revision hash for remote flakes (no flake.lock on disk).
    let flake_lock_hash = shell::run_in_vm_stdout(&format!(
        "if [ -f {flake}/flake.lock ]; then nix hash path {flake}/flake.lock; else echo ''; fi",
        flake = persisted.flake_ref
    ))
    .unwrap_or_default()
    .trim()
    .to_string();
    let flake_lock_hash = if flake_lock_hash.is_empty() {
        rev.clone()
    } else {
        flake_lock_hash
    };

    let sizes = result.artifact_sizes.clone();
    let revision = TemplateRevision {
        schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
        revision_hash: rev.clone(),
        flake_ref: persisted.flake_ref.clone(),
        flake_lock_hash,
        artifact_paths: ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
            initrd: if result.initrd_path.is_some() {
                Some("initrd".to_string())
            } else {
                None
            },
            sizes: Some(sizes.clone()),
        },
        built_at: utc_now(),
        profile: persisted.profile.clone(),
        // role is preserved on the on-disk struct for backward
        // compatibility with old revision.json files; manifest-built
        // slots emit an empty string. Plan 38 §3: cache_key drops
        // role (slice 3); this field is informational only.
        role: String::new(),
        vcpus: persisted.vcpus,
        mem_mib: persisted.mem_mib,
        data_disk_mib: persisted.data_disk_mib,
        snapshot: None,
    };
    let rev_json = serde_json::to_string_pretty(&revision)?;
    let rev_meta_path = format!("{rev_dst}/revision.json");
    shell::run_in_vm(&format!(
        "cat > {rev_meta_path} << 'MVMEOF'\n{rev_json}\nMVMEOF"
    ))?;

    // Refresh the slot's persisted manifest record with the new
    // updated_at + provenance. Caller can pre-supply provenance via
    // the `persisted` arg's `provenance` field; on rebuild we touch
    // it to reflect the current build.
    let refreshed = persisted.clone().touch(Provenance::current());
    template_persist_slot(&refreshed)?;

    use mvm_core::pool::format_bytes;
    ui::success(&format!(
        "Manifest at '{}' built successfully (revision: {}, rootfs: {}, kernel: {})",
        persisted.manifest_path,
        &rev[..rev.len().min(12)],
        format_bytes(sizes.rootfs_bytes),
        format_bytes(sizes.vmlinux_bytes),
    ));

    Ok(revision)
}

/// Recompute the Nix fixed-output derivation hash in a flake's `flake.nix`.
///
/// Blanks the `outputHash` field, runs `nix build` to trigger hash computation,
/// extracts the correct hash from the error output, and writes it back.
/// On failure, the original hash is restored.
#[instrument(skip_all, fields(flake_ref))]
fn update_fod_hash(flake_ref: &str) -> Result<()> {
    ui::info("Recomputing fixed-output derivation hash...");

    // Save original hash for recovery.
    let orig_hash = shell::run_in_vm_stdout(&format!(
        r#"sed -n 's/.*outputHash = "\([^"]*\)".*/\1/p' {flake}/flake.nix"#,
        flake = flake_ref
    ))?
    .trim()
    .to_string();

    // Blank the hash to trigger TOFU computation.
    shell::run_in_vm(&format!(
        r#"sed -i.bak 's|outputHash = "[^"]*"|outputHash = ""|' {flake}/flake.nix && rm -f {flake}/flake.nix.bak"#,
        flake = flake_ref
    ))?;

    // Run nix build and capture all output. It will fail with hash mismatch,
    // printing the correct hash. Phase 2/3 never execute; only the FOD runs.
    ui::info("Running nix build to compute hash (this downloads the package)...");
    let build_output = shell::run_in_vm_stdout(&format!(
        r#"cd {flake} && nix build '.#' --no-link 2>&1 || true"#,
        flake = flake_ref
    ))?;

    // Extract the "got: sha256-..." hash from the build output.
    let new_hash = build_output
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("got:") {
                Some(trimmed.trim_start_matches("got:").trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    if new_hash.is_empty() {
        // Show the nix output so the user can diagnose the failure.
        for line in build_output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                ui::info(&format!("  nix: {trimmed}"));
            }
        }
        // Restore original hash.
        if let Err(e) = shell::run_in_vm(&format!(
            r#"sed -i.bak 's|outputHash = "[^"]*"|outputHash = "{orig}"|' {flake}/flake.nix && rm -f {flake}/flake.nix.bak"#,
            orig = orig_hash,
            flake = flake_ref
        )) {
            warn!("failed to restore original FOD hash: {e}");
        }
        return Err(anyhow!("Could not extract FOD hash from nix build output."));
    }

    // Write the correct hash.
    shell::run_in_vm(&format!(
        r#"sed -i.bak 's|outputHash = "[^"]*"|outputHash = "{hash}"|' {flake}/flake.nix && rm -f {flake}/flake.nix.bak"#,
        hash = new_hash,
        flake = flake_ref
    ))?;

    ui::success(&format!("Updated outputHash: {}", new_hash));
    Ok(())
}

/// Build a template using the dev build pipeline (local Nix in Lima).
/// Artifacts are stored in ~/.mvm/templates/<id>/artifacts and the current symlink is updated.
#[instrument(skip_all, fields(template_id = id, force, update_hash))]
pub fn template_build(id: &str, force: bool, update_hash: bool) -> Result<()> {
    use crate::ui;

    let spec = template_load(id)?;
    let build_env = crate::build_env::default_build_env();
    let env = build_env.as_ref();

    ui::info(&format!(
        "Building template '{}' (flake: {}, profile: {})",
        id, spec.flake_ref, spec.profile
    ));

    // Recompute fixed-output derivation hash if requested (e.g. after version bump).
    if update_hash {
        update_fod_hash(&spec.flake_ref)?;
    }

    // Use dev_build to produce artifacts via Nix in Lima.
    // The dev build cache is keyed by Nix store hash at ~/.mvm/dev/builds/<hash>/,
    // so --force must clear the entire builds directory.
    if force {
        ui::info("Force build: clearing dev build cache");
        let builds_dir = format!("{}/dev/builds", mvm_core::config::mvm_data_dir());
        if let Err(e) = env.shell_exec(&format!("rm -rf {builds_dir}")) {
            warn!("failed to clear dev build cache: {e}");
        }
    }
    let result = mvm_build::dev_build::dev_build(env, &spec.flake_ref, Some(&spec.profile))?;
    // Best-effort: inject guest agent if not already present.
    // Non-fatal because flakes built with mvm's mkGuest already include
    // guest-agent.nix, and the loop-mount check can fail on virtiofs.
    // On host builds (macOS without Lima), the ext4 mount will fail
    // gracefully — flakes using mkGuest already include the agent.
    if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(env, &result) {
        ui::warn(&format!(
            "Could not verify guest agent ({}). If built with mvm's mkGuest, the agent is already included.",
            e
        ));
    }

    // Store artifacts in template revision directory
    ui::info("Storing artifacts in template revision directory...");
    let rev = &result.revision_hash;
    let rev_dst = template_revision_dir(id, rev);
    shell::run_in_vm(&format!("mkdir -p {rev_dst}"))?;
    shell::run_in_vm(&format!("cp -a {} {rev_dst}/vmlinux", result.vmlinux_path))?;
    if let Some(initrd) = &result.initrd_path {
        shell::run_in_vm(&format!("cp -a {} {rev_dst}/initrd", initrd))?;
    }
    shell::run_in_vm(&format!(
        "cp -a {} {rev_dst}/rootfs.ext4 && chmod u+w {rev_dst}/rootfs.ext4",
        result.rootfs_path
    ))?;

    // Generate a minimal fc-base.json config for reference.
    // Minimal guests (no initrd) need root= and init= on the kernel cmdline
    // so the kernel can mount the rootfs and exec /init directly.
    let boot_args = if result.initrd_path.is_some() {
        "console=ttyS0 reboot=k panic=1 net.ifnames=0".to_string()
    } else {
        "root=/dev/vda rw rootwait init=/init console=ttyS0 reboot=k panic=1 net.ifnames=0"
            .to_string()
    };
    let mut boot_source = serde_json::json!({
        "kernel_image_path": "vmlinux",
        "boot_args": boot_args
    });
    if result.initrd_path.is_some() {
        boot_source["initrd_path"] = serde_json::json!("initrd");
    }
    let fc_config = serde_json::json!({
        "boot-source": boot_source,
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": "rootfs.ext4",
            "is_root_device": true,
            "is_read_only": false
        }],
        "machine-config": {
            "vcpu_count": spec.vcpus,
            "mem_size_mib": spec.mem_mib
        }
    });
    let fc_json = serde_json::to_string_pretty(&fc_config)?;
    shell::run_in_vm(&format!(
        "cat > {rev_dst}/fc-base.json << 'MVMEOF'\n{fc_json}\nMVMEOF"
    ))?;

    // Update template current symlink
    let current_link = template_current_symlink(id);
    shell::run_in_vm(&format!("ln -snf revisions/{rev} {current_link}"))?;

    // Compute actual flake.lock hash for accurate cache keys.
    // Pool builds do this via the backend; template builds use dev_build directly,
    // so we compute it here. Falls back to revision hash for remote flakes.
    let flake_lock_hash = shell::run_in_vm_stdout(&format!(
        "if [ -f {flake}/flake.lock ]; then nix hash path {flake}/flake.lock; else echo ''; fi",
        flake = spec.flake_ref
    ))
    .unwrap_or_default()
    .trim()
    .to_string();
    let flake_lock_hash = if flake_lock_hash.is_empty() {
        rev.clone()
    } else {
        flake_lock_hash
    };

    // Record template revision metadata (with artifact sizes from dev_build)
    let sizes = result.artifact_sizes.clone();
    let revision = TemplateRevision {
        schema_version: mvm_core::template::CURRENT_SCHEMA_VERSION,
        revision_hash: rev.clone(),
        flake_ref: spec.flake_ref.clone(),
        flake_lock_hash,
        artifact_paths: ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
            initrd: if result.initrd_path.is_some() {
                Some("initrd".to_string())
            } else {
                None
            },
            sizes: Some(sizes.clone()),
        },
        built_at: utc_now(),
        profile: spec.profile.clone(),
        role: spec.role.clone(),
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
        data_disk_mib: spec.data_disk_mib,
        snapshot: None,
    };
    let rev_json = serde_json::to_string_pretty(&revision)?;
    let rev_meta_path = format!("{rev_dst}/revision.json");
    shell::run_in_vm(&format!(
        "cat > {rev_meta_path} << 'MVMEOF'\n{rev_json}\nMVMEOF"
    ))?;

    use mvm_core::pool::format_bytes;
    ui::success(&format!(
        "Template '{}' built successfully (revision: {}, rootfs: {}, kernel: {})",
        id,
        &rev[..rev.len().min(12)],
        format_bytes(sizes.rootfs_bytes),
        format_bytes(sizes.vmlinux_bytes),
    ));
    Ok(())
}

/// Load the current revision metadata for a template (if any).
///
/// Returns `None` if the template has no built revision or if `revision.json`
/// cannot be read/parsed.
pub fn template_load_current_revision(id: &str) -> Result<Option<TemplateRevision>> {
    let rev = match current_revision_id(id) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let rev_dir = template_revision_dir(id, &rev);
    let meta_path = format!("{}/revision.json", rev_dir);
    let data = match std::fs::read_to_string(&meta_path) {
        Ok(d) if !d.trim().is_empty() => d,
        _ => return Ok(None),
    };
    let revision: TemplateRevision = serde_json::from_str(&data)
        .with_context(|| format!("Corrupt revision.json for template {}", id))?;
    Ok(Some(revision))
}

/// Check if the current revision of a template has a snapshot.
pub fn template_has_snapshot(id: &str) -> Result<bool> {
    let rev = current_revision_id(id)?;
    let snap_dir = template_snapshot_dir(id, &rev);
    let vmstate = std::path::Path::new(&snap_dir).join("vmstate.bin");
    let mem = std::path::Path::new(&snap_dir).join("mem.bin");
    Ok(vmstate.exists() && mem.exists())
}

/// Load the snapshot metadata for a template revision.
pub fn template_snapshot_info(id: &str) -> Result<Option<SnapshotInfo>> {
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);
    let meta_path = format!("{}/revision.json", rev_dir);
    // Read directly from host filesystem
    let data = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("Failed to read revision.json for template {}", id))?;
    let revision: TemplateRevision = serde_json::from_str(&data)
        .with_context(|| format!("Corrupt revision.json for template {}", id))?;
    Ok(revision.snapshot)
}

/// Poll the guest agent via vsock until it responds, or timeout.
#[instrument(skip_all, fields(timeout_secs, interval_ms))]
pub fn wait_for_healthy(vsock_uds_path: &str, timeout_secs: u64, interval_ms: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut attempts = 0u32;
    loop {
        if mvm_guest::vsock::ping_at(vsock_uds_path).unwrap_or(false) {
            ui::success(&format!(
                "Guest agent healthy after {} attempts",
                attempts + 1
            ));
            return Ok(());
        }
        attempts += 1;
        if attempts.is_multiple_of(10) {
            ui::info(&format!(
                "Waiting for guest agent... ({} attempts, {}s remaining)",
                attempts,
                deadline.saturating_duration_since(Instant::now()).as_secs()
            ));
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "VM did not become healthy within {}s ({} attempts)",
                timeout_secs,
                attempts
            );
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
}

/// Check whether all integrations with health checks are healthy.
/// Returns `(all_healthy, unhealthy_names)`.
///
/// Integrations without a `health_cmd` (i.e., `health: None`) are skipped.
/// If there are no integrations or none have health checks, returns `(true, [])`.
fn check_integration_health(
    integrations: &[mvm_guest::integrations::IntegrationStateReport],
) -> (bool, Vec<String>) {
    let with_health: Vec<_> = integrations.iter().filter(|i| i.health.is_some()).collect();

    if with_health.is_empty() {
        return (true, vec![]);
    }

    let unhealthy: Vec<String> = with_health
        .iter()
        .filter(|i| !i.health.as_ref().is_some_and(|h| h.healthy))
        .map(|i| i.name.clone())
        .collect();

    (unhealthy.is_empty(), unhealthy)
}

/// Poll integration health status via vsock until all integrations with
/// health checks report healthy, or timeout.
///
/// If there are no integrations or none have `health_cmd` configured, returns
/// immediately (no-op).
#[instrument(skip_all, fields(timeout_secs, interval_ms))]
pub fn wait_for_integrations_healthy(
    vsock_uds_path: &str,
    timeout_secs: u64,
    interval_ms: u64,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut attempts = 0u32;

    loop {
        let integrations = match mvm_guest::vsock::query_integration_status_at(vsock_uds_path) {
            Ok(list) => list,
            Err(e) => {
                attempts += 1;
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "Timed out querying integration status after {}s ({} attempts): {}",
                        timeout_secs,
                        attempts,
                        e
                    );
                }
                if attempts.is_multiple_of(10) {
                    ui::warn(&format!(
                        "Failed to query integration status (attempt {}): {}",
                        attempts, e
                    ));
                }
                std::thread::sleep(Duration::from_millis(interval_ms));
                continue;
            }
        };

        if integrations.is_empty() {
            ui::info("No integrations registered, skipping integration health wait");
            return Ok(());
        }

        let (all_healthy, unhealthy) = check_integration_health(&integrations);

        if all_healthy {
            let names: Vec<&str> = integrations
                .iter()
                .filter(|i| i.health.is_some())
                .map(|i| i.name.as_str())
                .collect();
            ui::success(&format!(
                "All integrations healthy after {} attempts: [{}]",
                attempts + 1,
                names.join(", ")
            ));
            return Ok(());
        }

        attempts += 1;

        if attempts.is_multiple_of(10) {
            ui::info(&format!(
                "Waiting for integrations... ({} attempts, {}s remaining) unhealthy: [{}]",
                attempts,
                deadline.saturating_duration_since(Instant::now()).as_secs(),
                unhealthy.join(", ")
            ));
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "Integrations did not become healthy within {}s ({} attempts). Unhealthy: [{}]",
                timeout_secs,
                attempts,
                unhealthy.join(", ")
            );
        }

        std::thread::sleep(Duration::from_millis(interval_ms));
    }
}

/// Build a template and then create a Firecracker snapshot for instant starts.
///
/// 1. Runs `template_build()` to produce artifacts
/// 2. Boots a temporary Firecracker VM from those artifacts
/// 3. Waits for the guest agent to become healthy (vsock ping)
/// 4. Waits for all integration health checks to pass
/// 5. Pauses vCPUs and creates a full snapshot
/// 6. Stores snapshot files in the template revision directory
/// 7. Cleans up the temporary VM
#[instrument(skip_all, fields(template_id = id, force, update_hash))]
pub fn template_build_with_snapshot(id: &str, force: bool, update_hash: bool) -> Result<()> {
    use crate::config::BRIDGE_IP;
    use crate::vm::{microvm, network};

    // Step 1: Build artifacts (reuses existing template_build)
    template_build(id, force, update_hash)?;

    let spec = template_load(id)?;
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);
    let snap_dir = template_snapshot_dir(id, &rev);

    ui::info("Creating snapshot: booting temporary VM...");

    // Allocate a temporary network slot for the snapshot build
    let snapshot_vm_name = format!("__snapshot-{}", id);
    let slot = microvm::allocate_slot(&snapshot_vm_name)?;
    let abs_dir = microvm::resolve_vm_dir(&slot)?;
    let abs_socket = format!("{}/fc.socket", abs_dir);

    // Build boot args matching what run_from_build would use (minimal guest)
    let boot_args = format!(
        "root=/dev/vda rw rootwait init=/init console=ttyS0 reboot=k panic=1 net.ifnames=0 mvm.ip={ip}/24 mvm.gw={gw}",
        ip = slot.guest_ip,
        gw = BRIDGE_IP,
    );

    // Create a runtime directory in the template for shared snapshot drives.
    // Using template-relative paths ensures all instances can use symlinks
    // to their own config/secrets without path conflicts.
    let template_runtime_dir = format!("{}/runtime", template_dir(id));
    shell::run_in_vm(&format!("mkdir -p {}", template_runtime_dir))?;

    // Build a FlakeRunConfig for the temporary VM, using template runtime dir
    // for config/secrets so the snapshot has stable paths.
    // Verity sidecar lives next to the rootfs in the per-revision dir
    // when the flake was built with `verifiedBoot = true`. Probe for
    // both files together; present them as Some only when we can read
    // the roothash, and lift the absent case to None so callers stay
    // backward-compatible with pre-W3 templates.
    let verity_sidecar = format!("{}/rootfs.verity", rev_dir);
    let roothash_file = format!("{}/rootfs.roothash", rev_dir);
    let (verity_path, roothash) = match (
        shell::run_in_vm(&format!("[ -f {verity_sidecar} ]")),
        shell::run_in_vm_stdout(&format!("cat {roothash_file} 2>/dev/null")),
    ) {
        (Ok(_), Ok(hash)) if !hash.trim().is_empty() => {
            (Some(verity_sidecar.clone()), Some(hash.trim().to_string()))
        }
        _ => (None, None),
    };
    let run_config = microvm::FlakeRunConfig {
        name: snapshot_vm_name.clone(),
        slot: slot.clone(),
        vmlinux_path: format!("{}/vmlinux", rev_dir),
        initrd_path: None,
        rootfs_path: format!("{}/rootfs.ext4", rev_dir),
        verity_path,
        roothash,
        revision_hash: rev.clone(),
        flake_ref: spec.flake_ref.clone(),
        profile: Some(spec.profile.clone()),
        cpus: spec.vcpus as u32,
        memory: spec.mem_mib,
        volumes: vec![],
        config_files: vec![],
        secret_files: vec![],
        ports: vec![],
        network_policy: mvm_core::network_policy::NetworkPolicy::default(),
    };

    // Ensure bridge + TAP
    network::bridge_ensure()?;
    network::tap_create(&slot)?;

    // Clean up stale vsock socket from a previous template build.
    // start_vm_firecracker only cleans abs_dir/v.sock, but the vsock device
    // binds to template_runtime_dir/v.sock (a different path).
    if let Err(e) = shell::run_in_vm(&format!("rm -f {}/v.sock", template_runtime_dir)) {
        warn!("failed to remove stale vsock socket: {e}");
    }

    // Start Firecracker
    let start_result = microvm::start_vm_firecracker(&abs_dir, &abs_socket);
    if let Err(e) = start_result {
        if let Err(e) = network::tap_destroy(&slot) {
            warn!("failed to destroy TAP device on error: {e}");
        }
        return Err(e.context("Failed to start snapshot VM"));
    }

    // Configure and boot, using template runtime dir for config/secrets drives
    if let Err(e) = microvm::configure_flake_microvm_with_drives_dir(
        &run_config,
        &abs_dir,
        &abs_socket,
        &template_runtime_dir,
    ) {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to configure snapshot VM"));
    }

    ui::info("Booting snapshot VM...");
    std::thread::sleep(Duration::from_millis(15));
    if let Err(e) = microvm::api_put_socket(
        &abs_socket,
        "/actions",
        r#"{"action_type": "InstanceStart"}"#,
    ) {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to boot snapshot VM"));
    }

    // Make vsock accessible
    if let Err(e) = shell::run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir)) {
        warn!("failed to chmod vsock socket: {e}");
    }

    // Wait for guest agent to become healthy
    // Note: First boot can take 10-15 minutes on nested virtualization (macOS)
    // due to V8 compilation overhead. 900s (15 min) timeout ensures snapshot
    // creation succeeds even on slow systems.
    let vsock_path = format!("{}/v.sock", abs_dir);
    ui::info(
        "Waiting for guest agent to become healthy (may take up to 15 minutes on first boot)...",
    );
    let health_result = wait_for_healthy(&vsock_path, 900, 2000);

    if let Err(e) = health_result {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Snapshot VM did not become healthy"));
    }

    // Wait for all integration health checks to pass before snapshotting.
    // This ensures applications (e.g., OpenClaw) have fully started before
    // the VM state is captured.
    ui::info("Waiting for integration health checks to pass...");
    let integration_result = wait_for_integrations_healthy(&vsock_path, 900, 5000);

    if let Err(e) = integration_result {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Snapshot VM integrations did not become healthy"));
    }

    // Pause vCPUs
    ui::info("Pausing VM for snapshot...");
    let pause_result = microvm::api_patch_socket(&abs_socket, "/vm", r#"{"state": "Paused"}"#);
    if let Err(e) = pause_result {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to pause VM for snapshot"));
    }

    // Create snapshot directory in template
    shell::run_in_vm(&format!("mkdir -p {}", snap_dir))?;

    // Create snapshot via Firecracker API
    ui::info("Creating Firecracker snapshot...");
    let snapshot_result = shell::run_in_vm(&format!(
        r#"sudo curl -s --unix-socket {socket} -X PUT \
            -H 'Content-Type: application/json' \
            -d '{{"snapshot_type": "Full", "snapshot_path": "{snap}/vmstate.bin", "mem_file_path": "{snap}/mem.bin"}}' \
            'http://localhost/snapshot/create'"#,
        socket = abs_socket,
        snap = snap_dir,
    ));

    if let Err(e) = snapshot_result {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to create Firecracker snapshot"));
    }

    // Get snapshot file sizes
    let vmstate_size: u64 = shell::run_in_vm_stdout(&format!(
        "stat -c%s {}/vmstate.bin 2>/dev/null || echo 0",
        snap_dir
    ))?
    .trim()
    .parse()
    .unwrap_or(0);
    let mem_size: u64 = shell::run_in_vm_stdout(&format!(
        "stat -c%s {}/mem.bin 2>/dev/null || echo 0",
        snap_dir
    ))?
    .trim()
    .parse()
    .unwrap_or(0);

    // Update revision.json with snapshot metadata
    let snapshot_info = SnapshotInfo {
        created_at: utc_now(),
        vmstate_size_bytes: vmstate_size,
        mem_size_bytes: mem_size,
        boot_args: boot_args.clone(),
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
    };

    let rev_meta_path = format!("{}/revision.json", rev_dir);
    let rev_data = vm_exec_stdout(&format!("cat {}", rev_meta_path))?;
    let mut revision: TemplateRevision = serde_json::from_str(&rev_data)
        .with_context(|| "Failed to parse revision.json for snapshot update")?;
    revision.snapshot = Some(snapshot_info);

    let updated_json = serde_json::to_string_pretty(&revision)?;
    shell::run_in_vm(&format!(
        "cat > {} << 'MVMEOF'\n{}\nMVMEOF",
        rev_meta_path, updated_json
    ))?;

    // Clean up temporary VM
    cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);

    let total_mb = (vmstate_size + mem_size) / (1024 * 1024);
    ui::success(&format!(
        "Snapshot created for template '{}' ({}MB total)",
        id, total_mb
    ));
    ui::info("Use 'mvmctl run --template' for instant starts from this snapshot.");

    Ok(())
}

/// Clean up a temporary snapshot VM (best-effort).
fn cleanup_snapshot_vm(abs_dir: &str, abs_socket: &str, slot: &crate::config::VmSlot) {
    use crate::vm::network;

    // Kill Firecracker process
    if let Err(e) = shell::run_in_vm(&format!(
        r#"
        if [ -f {dir}/fc.pid ]; then
            sudo kill $(cat {dir}/fc.pid) 2>/dev/null || true
        fi
        sudo rm -f {socket}
        "#,
        dir = abs_dir,
        socket = abs_socket,
    )) {
        warn!("failed to kill snapshot firecracker process: {e}");
    }

    // Destroy TAP
    if let Err(e) = network::tap_destroy(slot) {
        warn!("failed to destroy snapshot TAP device: {e}");
    }

    // Remove temp VM directory
    if let Err(e) = shell::run_in_vm(&format!("rm -rf {}", abs_dir)) {
        warn!("failed to remove snapshot temp directory: {e}");
    }
}

/// Artifact integrity manifest used by template push/pull.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Checksums {
    #[serde(default)]
    pub schema_version: u32,
    pub template_id: String,
    pub revision_hash: String,
    pub files: std::collections::BTreeMap<String, String>,
}

fn require_local_template_fs() -> Result<()> {
    // Registry push/pull needs direct file access to ~/.mvm/templates.
    // On macOS, templates live inside Lima; run these commands inside the VM.
    if mvm_core::platform::current().needs_lima() && !crate::shell::inside_lima() {
        anyhow::bail!(
            "template push/pull/verify must be run inside the Linux VM (try `mvm shell`, then rerun)"
        );
    }
    Ok(())
}

/// Resolve a built template to its current artifact paths.
///
/// Returns `(spec, vmlinux, initrd, rootfs, revision_hash)`.
/// The artifact paths are absolute and valid inside the Lima VM.
#[instrument(skip_all, fields(template_id = id))]
pub fn template_artifacts(
    id: &str,
) -> Result<(TemplateSpec, String, Option<String>, String, String)> {
    let spec = template_load(id)?;
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);

    let vmlinux = format!("{rev_dir}/vmlinux");
    let rootfs = format!("{rev_dir}/rootfs.ext4");
    let initrd_candidate = format!("{rev_dir}/initrd");

    if !std::path::Path::new(&vmlinux).exists() {
        anyhow::bail!(
            "Template '{}' has no vmlinux (run `mvmctl template build {}`)",
            id,
            id
        );
    }
    if !std::path::Path::new(&rootfs).exists() {
        anyhow::bail!(
            "Template '{}' has no rootfs (run `mvmctl template build {}`)",
            id,
            id
        );
    }

    let has_initrd = std::path::Path::new(&initrd_candidate).exists();

    Ok((
        spec,
        vmlinux,
        if has_initrd {
            Some(initrd_candidate)
        } else {
            None
        },
        rootfs,
        rev,
    ))
}

#[instrument(skip_all, fields(template_id))]
pub fn current_revision_id(template_id: &str) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let link = template_current_symlink(template_id);
    let target = std::fs::read_link(&link)
        .with_context(|| format!("Template has no current revision: {}", template_id))?;
    let raw = target.as_os_str().as_bytes();
    let raw = std::str::from_utf8(raw)
        .unwrap_or_default()
        .trim()
        .to_string();
    let rev = raw.strip_prefix("revisions/").unwrap_or(&raw).to_string();
    if rev.is_empty() {
        anyhow::bail!("Template current symlink is empty: {}", link);
    }
    Ok(rev)
}

/// Compute the SHA-256 hex digest of a file.
pub fn sha256_hex(path: &std::path::Path) -> Result<String> {
    use sha2::Digest;

    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Download a template revision's artifacts from the registry to a local directory.
///
/// Downloads all artifact files listed in `checksums.json`, verifies SHA-256
/// integrity, and writes them to `output_dir`. The directory must already exist.
///
/// This is the core download logic shared by [`template_pull()`] (writes to
/// template dir) and fleet agents (write to pool artifacts dir).
///
/// Returns the revision hash and the list of downloaded file names.
#[instrument(skip_all, fields(template_id))]
pub fn registry_download_revision(
    registry: &TemplateRegistry,
    template_id: &str,
    revision: Option<&str>,
    output_dir: &std::path::Path,
) -> Result<(String, Vec<String>)> {
    // Resolve revision from registry "current" pointer if not specified.
    let rev = match revision {
        Some(r) => r.to_string(),
        None => {
            let current = registry
                .get_text(&registry.key_current(template_id))?
                .trim()
                .to_string();
            if current.is_empty() {
                anyhow::bail!(
                    "Registry current revision is empty for template {}",
                    template_id
                );
            }
            current
        }
    };

    // Download checksums manifest.
    let sums_key = registry.key_revision_file(template_id, &rev, "checksums.json");
    let sums_bytes = registry.get_bytes(&sums_key)?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)
        .with_context(|| format!("Invalid checksums.json for {}/{}", template_id, rev))?;

    // Download each file and verify SHA-256.
    let mut downloaded_files = Vec::new();
    for (name, expected_hex) in &checksums.files {
        let key = registry.key_revision_file(template_id, &rev, name);
        let data = registry.get_bytes(&key)?;
        let file_path = output_dir.join(name);
        mvm_core::atomic_io::atomic_write(&file_path, &data)
            .with_context(|| format!("Failed to write {}", file_path.display()))?;
        let got = sha256_hex(&file_path)?;
        if &got != expected_hex {
            anyhow::bail!(
                "checksum mismatch for {} (expected {}, got {})",
                name,
                expected_hex,
                got
            );
        }
        downloaded_files.push(name.clone());
    }

    // Write checksums.json alongside the artifacts for offline verification.
    mvm_core::atomic_io::atomic_write(&output_dir.join("checksums.json"), &sums_bytes)
        .context("Failed to write checksums.json")?;

    Ok((rev, downloaded_files))
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_push(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;
    let registry = TemplateRegistry::from_env()?.context("Template registry not configured")?;
    registry.require_configured()?;

    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id(id)?,
    };

    let template_dir = template_dir(id);
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));

    let files = [
        (
            "template.json",
            std::path::PathBuf::from(format!("{}/template.json", template_dir)),
        ),
        ("revision.json", rev_dir.join("revision.json")),
        ("vmlinux", rev_dir.join("vmlinux")),
        ("rootfs.ext4", rev_dir.join("rootfs.ext4")),
        ("fc-base.json", rev_dir.join("fc-base.json")),
    ];

    // Compute checksums for integrity.
    let mut sums = std::collections::BTreeMap::new();
    for (name, path) in &files {
        let hex = sha256_hex(path)?;
        sums.insert(name.to_string(), hex);
    }
    let checksums = Checksums {
        schema_version: 1,
        template_id: id.to_string(),
        revision_hash: rev.clone(),
        files: sums,
    };
    let checksums_json = serde_json::to_vec_pretty(&checksums)?;
    // Store checksums locally alongside the revision so `template verify` works offline.
    mvm_core::atomic_io::atomic_write(&rev_dir.join("checksums.json"), &checksums_json)
        .with_context(|| {
            format!(
                "Failed to write checksums.json for template {} revision {}",
                id, rev
            )
        })?;

    // Upload revision objects first, then current pointer.
    for (name, path) in &files {
        let key = registry.key_revision_file(id, &rev, name);
        let data =
            std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
        registry.put_bytes(&key, data)?;
    }
    registry.put_bytes(
        &registry.key_revision_file(id, &rev, "checksums.json"),
        checksums_json,
    )?;
    registry.put_text(&registry.key_current(id), &format!("{}\n", rev))?;

    tracing::info!(template = %id, revision = %rev, "Pushed template revision to registry");
    Ok(())
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_pull(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;
    let registry = TemplateRegistry::from_env()?.context("Template registry not configured")?;
    registry.require_configured()?;

    let base_dir = std::path::PathBuf::from(template_dir(id));
    std::fs::create_dir_all(&base_dir)?;

    // Download to a temp dir, then move into place.
    let tmp_label = revision.unwrap_or("latest");
    let tmp_dir = base_dir.join(format!("tmp-pull-{}", tmp_label));
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir).ok();
    }
    std::fs::create_dir_all(&tmp_dir)?;

    let (rev, _files) = match registry_download_revision(&registry, id, revision, &tmp_dir) {
        Ok(result) => result,
        Err(e) => {
            std::fs::remove_dir_all(&tmp_dir).ok();
            return Err(e);
        }
    };

    // Install into final revision dir.
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));
    std::fs::create_dir_all(rev_dir.parent().unwrap_or(&base_dir))?;
    if rev_dir.exists() {
        std::fs::remove_dir_all(&rev_dir).ok();
    }
    std::fs::rename(&tmp_dir, &rev_dir).with_context(|| {
        format!(
            "Failed to move {} to {}",
            tmp_dir.display(),
            rev_dir.display()
        )
    })?;

    // Update current symlink.
    let link = template_current_symlink(id);
    if let Err(e) = std::fs::remove_file(&link) {
        warn!("failed to remove old current symlink: {e}");
    }
    std::os::unix::fs::symlink(format!("revisions/{}", rev), &link)?;

    tracing::info!(template = %id, revision = %rev, "Pulled template revision from registry");
    Ok(())
}

#[instrument(skip_all, fields(template_id = id))]
pub fn template_verify(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;

    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id(id)?,
    };
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));
    let sums_path = rev_dir.join("checksums.json");
    let sums_bytes =
        std::fs::read(&sums_path).with_context(|| format!("Missing {}", sums_path.display()))?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)?;

    for (name, expected_hex) in &checksums.files {
        let p = rev_dir.join(name);
        let got = sha256_hex(&p)?;
        if &got != expected_hex {
            anyhow::bail!(
                "checksum mismatch for {} (expected {}, got {})",
                name,
                expected_hex,
                got
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_guest::integrations::{
        IntegrationHealthResult, IntegrationStateReport, IntegrationStatus,
    };

    fn healthy_report(name: &str) -> IntegrationStateReport {
        IntegrationStateReport {
            name: name.to_string(),
            status: IntegrationStatus::Active,
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: true,
                detail: "ok".to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }
    }

    fn unhealthy_report(name: &str, detail: &str) -> IntegrationStateReport {
        IntegrationStateReport {
            name: name.to_string(),
            status: IntegrationStatus::Error(detail.to_string()),
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: false,
                detail: detail.to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }
    }

    fn no_health_report(name: &str) -> IntegrationStateReport {
        IntegrationStateReport {
            name: name.to_string(),
            status: IntegrationStatus::Active,
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: None,
        }
    }

    #[test]
    fn test_check_integration_health_all_healthy() {
        let integrations = vec![healthy_report("openclaw"), healthy_report("redis")];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_some_unhealthy() {
        let integrations = vec![
            unhealthy_report("openclaw", "exit code 1"),
            healthy_report("redis"),
        ];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(!all_healthy);
        assert_eq!(unhealthy, vec!["openclaw"]);
    }

    #[test]
    fn test_check_integration_health_empty_list() {
        let (all_healthy, unhealthy) = check_integration_health(&[]);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_no_health_cmds() {
        let integrations = vec![no_health_report("plain-service")];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_mixed_health_and_no_health() {
        let integrations = vec![
            healthy_report("with-health"),
            no_health_report("without-health"),
        ];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_check_integration_health_pending_not_yet_checked() {
        let integrations = vec![IntegrationStateReport {
            name: "starting-up".to_string(),
            status: IntegrationStatus::Pending,
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: false,
                detail: "connection refused".to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(!all_healthy);
        assert_eq!(unhealthy, vec!["starting-up"]);
    }

    #[test]
    fn test_check_integration_health_error_status_but_healthy_check() {
        // Edge case: integration status is Error but health check passed.
        // We check health.healthy, not status — the health_cmd result is
        // the source of truth for readiness.
        let integrations = vec![IntegrationStateReport {
            name: "recovering".to_string(),
            status: IntegrationStatus::Error("previous crash".to_string()),
            last_checkpoint_at: None,
            state_size_bytes: 0,
            health: Some(IntegrationHealthResult {
                healthy: true,
                detail: "ok".to_string(),
                checked_at: "2026-03-01T00:00:00Z".to_string(),
            }),
        }];
        let (all_healthy, unhealthy) = check_integration_health(&integrations);
        assert!(all_healthy);
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_checksums_serde_roundtrip() {
        let mut files = std::collections::BTreeMap::new();
        files.insert("vmlinux".to_string(), "abc123".to_string());
        files.insert("rootfs.squashfs".to_string(), "def456".to_string());
        let checksums = Checksums {
            schema_version: 1,
            template_id: "gateway".to_string(),
            revision_hash: "rev-abc".to_string(),
            files,
        };
        let json = serde_json::to_string(&checksums).unwrap();
        let parsed: Checksums = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.template_id, "gateway");
        assert_eq!(parsed.revision_hash, "rev-abc");
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files["vmlinux"], "abc123");
    }

    #[test]
    fn test_checksums_empty_files() {
        let checksums = Checksums {
            schema_version: 1,
            template_id: "empty".to_string(),
            revision_hash: "rev-000".to_string(),
            files: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&checksums).unwrap();
        let parsed: Checksums = serde_json::from_str(&json).unwrap();
        assert!(parsed.files.is_empty());
    }

    #[test]
    fn test_checksums_files_sorted() {
        let mut files = std::collections::BTreeMap::new();
        files.insert("z-file".to_string(), "zzz".to_string());
        files.insert("a-file".to_string(), "aaa".to_string());
        files.insert("m-file".to_string(), "mmm".to_string());
        let checksums = Checksums {
            schema_version: 1,
            template_id: "t".to_string(),
            revision_hash: "r".to_string(),
            files,
        };
        let json = serde_json::to_string(&checksums).unwrap();
        // BTreeMap serializes in sorted order
        let keys: Vec<&str> = checksums.files.keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["a-file", "m-file", "z-file"]);
        // Roundtrip preserves order
        let parsed: Checksums = serde_json::from_str(&json).unwrap();
        let parsed_keys: Vec<&str> = parsed.files.keys().map(|s| s.as_str()).collect();
        assert_eq!(parsed_keys, vec!["a-file", "m-file", "z-file"]);
    }

    // -----------------------------------------------------------------
    // Plan 38 slice 4: classify_template_dir_entries (pure helper).
    //
    // Filesystem-independent unit tests. The slot-keyed
    // persist/load/delete/list_* wrappers are thin delegations to
    // mvm_core::manifest primitives that already have full coverage in
    // slice 2 (26 tests against tempdir-backed scenarios), so we
    // intentionally don't re-test the env-driven path resolution here:
    // doing so would force MVM_DATA_DIR mutation and serialise tests.
    // -----------------------------------------------------------------

    fn hex_dirname() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn classify_separates_hashes_from_legacy_names() {
        let h = hex_dirname();
        let entries = vec![
            "openclaw".to_string(),
            h.clone(),
            "agent-foo".to_string(),
            "claude-code-vm".to_string(),
        ];
        let (hashes, legacy) = classify_template_dir_entries(entries);
        assert_eq!(hashes, vec![h]);
        assert_eq!(
            legacy,
            vec![
                "agent-foo".to_string(),
                "claude-code-vm".to_string(),
                "openclaw".to_string(),
            ]
        );
    }

    #[test]
    fn classify_returns_sorted_within_each_bucket() {
        let h1 = "f".repeat(64);
        let h2 = "0".repeat(64);
        let entries = vec![
            h1.clone(),
            "z-tpl".to_string(),
            h2.clone(),
            "a-tpl".to_string(),
        ];
        let (hashes, legacy) = classify_template_dir_entries(entries);
        assert_eq!(hashes, vec![h2, h1]);
        assert_eq!(legacy, vec!["a-tpl".to_string(), "z-tpl".to_string()]);
    }

    #[test]
    fn classify_handles_empty_input() {
        let (hashes, legacy) = classify_template_dir_entries(Vec::<String>::new());
        assert!(hashes.is_empty());
        assert!(legacy.is_empty());
    }

    #[test]
    fn classify_treats_64_char_non_hex_as_legacy() {
        // 64 chars but contains non-hex characters → not a slot hash.
        let almost = "G".repeat(64);
        let (hashes, legacy) = classify_template_dir_entries(vec![almost.clone()]);
        assert!(hashes.is_empty());
        assert_eq!(legacy, vec![almost]);
    }

    #[test]
    fn classify_treats_uppercase_hex_as_legacy() {
        // is_slot_hash_dirname requires LOWERCASE hex; uppercase rejects.
        let upper = "ABCDEF0123456789".repeat(4);
        assert_eq!(upper.len(), 64);
        let (hashes, legacy) = classify_template_dir_entries(vec![upper.clone()]);
        assert!(hashes.is_empty());
        assert_eq!(legacy, vec![upper]);
    }

    #[test]
    fn classify_rejects_short_or_long_dirnames() {
        let short = "a".repeat(63);
        let long = "a".repeat(65);
        let (hashes, legacy) = classify_template_dir_entries(vec![short.clone(), long.clone()]);
        assert!(hashes.is_empty());
        let mut expected = vec![short, long];
        expected.sort();
        assert_eq!(legacy, expected);
    }

    #[test]
    fn slot_entry_clone_and_eq() {
        // Sanity: SlotEntry derives Clone/PartialEq for callers that
        // need to dedupe/compare in template list output.
        let a = SlotEntry {
            slot_hash: "abc".to_string(),
            manifest_path: "/abs/mvm.toml".to_string(),
            name: Some("openclaw".to_string()),
            updated_at: "2026-05-01T00:00:00Z".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}

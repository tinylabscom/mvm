//! Plan 60 Phase 4 — live drive-and-assert tests for the
//! `AuditPosture::Emits` rows in `tests/audit_total_coverage.rs`.
//!
//! The classification scaffold in `audit_total_coverage.rs`
//! declares which subcommands MUST emit an audit entry on success.
//! This file *executes* a handful of the easiest-to-fixture
//! subcommands end-to-end and asserts the named `LocalAuditKind`
//! actually appears in the audit log.
//!
//! Coverage today (intentionally minimal; expand per-row as commands
//! gain hermetic fixtures):
//!
//! - `mvmctl cache prune` → `CachePrune`
//! - `mvmctl cache prune --dry-run` → **no** audit entry
//!   (dry-runs are read-only; pinning the negative)
//! - `mvmctl network create <name>` → `NetworkCreate`
//! - `mvmctl network remove <name>` → `NetworkRemove`
//! - `mvmctl manifest prune --orphans` (empty registry) → `SlotPrune`
//!   (emitted with `count=0` — Plan 37 §6 invariant: every state-
//!   changing verb emits one record per attempt, even on no-op)
//! - `mvmctl manifest prune --orphans --dry-run` → **no** audit entry
//! - `mvmctl storage gc --apply --mock` (empty pool) → `StorageGc`
//!   (no-op attempt emits with `count=0` / `pool_unavailable=…`)
//! - `mvmctl storage gc --mock` (dry-run) → **no** audit entry
//! - `mvmctl manifest tag add <tpl> <tag>` → `ManifestTagAdd`
//! - `mvmctl manifest tag rm <tpl> <tag>` → `ManifestTagRemove`
//! - `mvmctl manifest tag ls <tpl>` → **no** audit entry
//! - `mvmctl manifest alias set <tpl> <alias> <rev>` → `ManifestAliasSet`
//! - `mvmctl manifest alias rm <tpl> <alias>` → `ManifestAliasRemove`
//! - `mvmctl manifest alias ls <tpl>` → **no** audit entry
//! - `mvmctl manifest rm <path> --force` → `SlotRemove`
//!   (idempotent against a missing slot — `--force` is the cleanup
//!   contract; the stub `mvm.toml` is enough to canonicalise the
//!   path key)
//! - `mvmctl config set <key> <value>` → `ConfigChange`
//! - `mvmctl config show` → **no** audit entry
//! - `mvmctl cleanup --keep 5` → `SlotPrune`
//!   (`source=cleanup removed=N`; the VM-dependent Step 1 / Step 3
//!   degrade to warnings when the dev VM isn't reachable, but
//!   Step 2 — the build-cache prune — runs on host fs and the
//!   audit emit always fires)
//! - `mvmctl up --hypervisor mock --detach --no-supervisor` (with
//!   `MVM_DIRECT_BOOT=1` + stub kernel/rootfs files) → `VmStart`
//!   (end-to-end exercise of the launchd-spawned direct-boot path
//!   against the in-memory `MockBackend`. The mock makes the
//!   backend dispatch hermetic; `MVM_DIRECT_BOOT` skips the
//!   build + template lookup. Together they let `mvmctl up` run
//!   to completion on a CI runner with no KVM / Nix / Apple
//!   Container / Docker / libkrun)
//! - `mvmctl set-ttl <vm> <duration>` (after `up --hypervisor mock`)
//!   → `VmTtlSet` (chains off the up-via-mock fixture; the verb
//!   operates on the persistent name registry that `up` populates)
//! - `mvmctl pause <vm> --hypervisor mock` (after `up`) →
//!   `WorkloadSleep` (Plan 65: pause routes through the SnapshotIO
//!   trait; `--hypervisor mock` swaps in `CannedIO` so the seal
//!   step writes deterministic 12-byte vmstate + 8-byte mem stubs
//!   instead of talking to a real Firecracker UDS)
//! - `mvmctl resume <vm> --hypervisor mock` (after `pause`) →
//!   `WorkloadWake` (mirrors; verify-and-resume against the sealed
//!   sidecar succeeds because the seal was written under
//!   deterministic-stubs round-trip)
//! - `mvmctl down` (no args, empty sandbox) → `VmStop`
//!   (`stop_all` is tolerant of an empty VM registry and emits
//!   with `detail=stop_all_ok`)
//! - `mvmctl down <name>` (empty sandbox) → `VmStop`
//!   (Firecracker's `stop_vm` is tolerant of missing VMs;
//!   audit emits `detail=ok`)
//! - `mvmctl snapshot rm <name>` → `SnapshotDelete`
//!   (test pre-creates `~/.mvm/instances/<name>/snapshot/` so the
//!   bail-when-missing branch doesn't short-circuit the emit)
//! - `mvmctl snapshot ls` → **no** audit entry
//! - `mvmctl audit tail` / `audit verify` / `audit show <id>` →
//!   **no** audit entry (the `AUDIT` leaves are all ReadOnly)
//! - `mvmctl attest status` / `attest export` → **no** audit
//!   entry (the `ATTEST` leaves are all ReadOnly)
//! - `mvmctl session ls` / `volume ls <vm>` → **no** audit entry
//!   (SESSION ls and VOLUME ls leaves are both ReadOnly)
//! - `mvmctl volume create <name> --root <encrypted-dir>` →
//!   `VolumeCreate`
//! - `mvmctl volume mount <vm> ...` → `VmVolumeAdd` (Plan 67:
//!   the verb operates purely on the host-side
//!   `~/.mvm/instances/<vm>/volume_mounts.json` registry — no
//!   virtio-fs daemon attach, no backend dispatch)
//! - `mvmctl volume unmount <vm> <guest>` → `VmVolumeRemove`
//! - `mvmctl ls` / `metrics` / `catalog list` → **no** audit entry
//!   (top-level ReadOnly verbs — three more rows from
//!   `AUDIT_POSTURE` pinned against a future regression that
//!   adds an emit to a read-only path)
//! - `mvmctl update` (against an `httpmock` server returning the
//!   current version) → `UpdateInstall` (Plan 69: the
//!   `MVM_UPDATE_API_URL` env-var redirects the
//!   `https://api.github.com/.../releases/latest` query to a local
//!   mock that returns the current binary's own version.
//!   `update::update` exits early with "already up to date" and
//!   the outer wrapper emits `UpdateInstall`. No real network, no
//!   binary swap.)
//! - `mvmctl uninstall --yes --all` (with `MVM_UNINSTALL_PATH_PREFIX`
//!   pointing at a sandbox sub-dir) → `Uninstall` (Plan 70: the
//!   override rewrites `/var/lib/mvm` and `/usr/local/bin/mvmctl`
//!   under the prefix and skips sudo, so the positive path is
//!   exercised end-to-end without sudo prompts or destruction of
//!   a developer's real install)
//! - `mvmctl uninstall --yes --dry-run` → **no** audit entry
//!   (the positive `Uninstall` path is real-system-destructive
//!   and not safely-hermetic, but the dry-run path is read-only
//!   by contract and can be pinned)
//! - `mvmctl secret put / get / ls / rm` → secret-side audit JSONL
//!   at `~/.mvm/audit/secrets.jsonl` carries one entry per call
//!   with `"action":"put"` / `"get"` / `"list"` / `"delete"`. The
//!   CLI verb and on-disk action name are decoupled — `ls` →
//!   `"list"`, `rm` → `"delete"` — so the negative tests also pin
//!   the rename surface against accidental drift. The sandbox
//!   sets `MVM_SECRET_STORE_BACKEND=file` so the test never
//!   touches the OS keystore (no DBus / Keychain dependency on
//!   any host).
//!
//! ## Hermetic setup
//!
//! Each test spawns the real `mvmctl` binary via `assert_cmd` with
//! `HOME` and `MVM_DATA_DIR` / `MVM_STATE_DIR` / `MVM_CACHE_DIR`
//! pointed at a per-test `tempfile::tempdir()`. The audit log
//! resolves to `<tempdir>/.local/state/mvm/log/audit.jsonl` (the
//! XDG-state path `mvm_core::policy::audit::default_audit_log()`
//! returns when no legacy `~/.mvm/log/` exists). Tests read that
//! file and assert the expected `LocalAuditKind` (in its
//! `serde(rename_all = "snake_case")` form, e.g. `"cache_prune"`)
//! appears.
//!
//! ## Why subprocess, not in-process
//!
//! `mvm_core::audit::emit` writes to a path computed from env vars
//! at call time. Running the command in-process and asserting on
//! the audit file would either need a process-global env mutex
//! (brittle under parallel `cargo test`) or in-process emit-to-path
//! plumbing. The subprocess gets its own env, which is naturally
//! hermetic across `cargo test`'s default thread-per-test
//! parallelism.

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A test sandbox: tempdir + the env vars wired to point every
/// mvmctl state path inside it.
struct AuditSandbox {
    home: TempDir,
}

impl AuditSandbox {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn home_path(&self) -> &Path {
        self.home.path()
    }

    /// Resolve the audit log path the subprocess will write to.
    /// `mvm_core::policy::audit::default_audit_log()` returns the
    /// XDG state path (`<state>/log/audit.jsonl`) when no legacy
    /// `<data>/log/audit.jsonl` exists. Since the tempdir is empty,
    /// the state path wins.
    fn audit_log_path(&self) -> PathBuf {
        self.home_path()
            .join(".local")
            .join("state")
            .join("mvm")
            .join("log")
            .join("audit.jsonl")
    }

    /// The `mvmctl secret` command writes its own per-action JSONL
    /// to `~/.mvm/audit/secrets.jsonl` (distinct from the
    /// `LocalAudit` stream). Entries have shape
    /// `{"action":"put","tenant":"...","name":"...","outcome":"ok",...}`.
    fn secret_audit_log_path(&self) -> PathBuf {
        self.home_path()
            .join(".mvm")
            .join("audit")
            .join("secrets.jsonl")
    }

    /// Build a Command pre-wired with `HOME` overridden so every
    /// mvmctl-derived path lands inside the sandbox.
    fn mvmctl(&self) -> Command {
        #[allow(deprecated)]
        let mut c = Command::cargo_bin("mvmctl").expect("cargo_bin mvmctl");
        // HOME drives every state dir helper in mvm_core::config —
        // mvm_data_dir, mvm_state_dir, mvm_cache_dir, mvm_share_dir,
        // mvm_config_dir all cascade off it when no XDG_* / MVM_*
        // override is set. Clearing those guarantees HOME wins so
        // the test runner's own XDG env doesn't leak into the
        // subprocess.
        c.env("HOME", self.home_path())
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("MVM_DATA_DIR")
            .env_remove("MVM_STATE_DIR")
            .env_remove("MVM_CACHE_DIR")
            .env_remove("MVM_SHARE_DIR")
            .env_remove("MVM_CONFIG_DIR")
            // Pin the file-backed secret store. The default
            // (`default_secret_store`) auto-picks the OS keyring
            // when reachable, which on Linux CI runners means the
            // libsecret / Secret-Service path — and the `keyring`
            // crate reports the backend reachable based on header
            // availability, not a live `set_password` round-trip.
            // CI runners with `libsecret` but no live Secret-Service
            // daemon would otherwise fail every secret_* test with
            // a socket-not-found error. Pinning `file` here makes
            // the suite hermetic: no DBus, no keychain, no
            // host-state dependency.
            .env("MVM_SECRET_STORE_BACKEND", "file");
        c
    }

    fn encrypted_volume_probe_path(&self) -> PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let bin = self.home_path().join("bin");
            std::fs::create_dir_all(&bin).expect("mkdir fake probe bin");
            let diskutil = bin.join("diskutil");
            std::fs::write(
                &diskutil,
                "#!/bin/sh\nprintf 'Device Identifier: disk-test\\nEncrypted: Yes\\n'\n",
            )
            .expect("write fake diskutil");
            std::fs::set_permissions(&diskutil, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake diskutil");

            let findmnt = bin.join("findmnt");
            std::fs::write(&findmnt, "#!/bin/sh\nprintf '/dev/mapper/mvm-test\\n'\n")
                .expect("write fake findmnt");
            std::fs::set_permissions(&findmnt, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake findmnt");

            let lsblk = bin.join("lsblk");
            std::fs::write(&lsblk, "#!/bin/sh\nprintf 'crypt\\n'\n").expect("write fake lsblk");
            std::fs::set_permissions(&lsblk, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake lsblk");

            let existing = std::env::var("PATH").unwrap_or_default();
            let sep = if existing.is_empty() { "" } else { ":" };
            PathBuf::from(format!("{}{}{}", bin.display(), sep, existing))
        }
        #[cfg(not(unix))]
        {
            PathBuf::from(std::env::var("PATH").unwrap_or_default())
        }
    }
}

/// Read the audit log into a string. Returns "" if the file doesn't
/// exist (an unaudited call leaves no file behind).
fn read_audit_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Count occurrences of `serde(rename_all = "snake_case")` form of
/// `kind` in the audit log. The on-disk JSON shape is
/// `{"kind":"cache_prune", ...}`, so a `kind` of `"cache_prune"`
/// matches one entry per occurrence.
fn count_entries_with_kind(log: &str, kind: &str) -> usize {
    let needle = format!("\"kind\":\"{kind}\"");
    log.matches(&needle).count()
}

#[test]
fn cache_prune_emits_cache_prune_audit_entry() {
    let sandbox = AuditSandbox::new();

    // Run `mvmctl cache prune` against an empty cache dir. The
    // command short-circuits with "Cache directory does not exist"
    // but still emits the audit entry — Plan 37 §6 invariant: every
    // state-changing CLI verb emits one record per attempt, success
    // or no-op.
    let output = sandbox
        .mvmctl()
        .args(["cache", "prune"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl cache prune failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "cache_prune");
    assert!(
        hits >= 1,
        "expected ≥1 cache_prune entry in audit log, got {hits}. \
         Full log content:\n{log}"
    );
}

#[test]
fn cache_prune_dry_run_does_not_emit_audit_entry() {
    // Pinning the negative: dry-run is read-only and must NOT
    // leave an audit entry. If this test fails, the dry-run path
    // grew an emission it shouldn't have.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["cache", "prune", "--dry-run"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl cache prune --dry-run failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "cache_prune");
    assert_eq!(
        hits, 0,
        "dry-run must not write audit entries, got {hits} cache_prune \
         entry/entries. Full log:\n{log}"
    );
}

#[test]
fn network_create_emits_network_create_audit_entry() {
    let sandbox = AuditSandbox::new();

    let output = sandbox
        .mvmctl()
        .args(["network", "create", "test-audit-net"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl network create failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "network_create");
    assert!(
        hits >= 1,
        "expected ≥1 network_create entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn network_remove_emits_network_remove_audit_entry() {
    // Create a network first, then remove it. Two audit entries
    // are expected: one `network_create`, one `network_remove`.
    let sandbox = AuditSandbox::new();

    let create = sandbox
        .mvmctl()
        .args(["network", "create", "test-rm-audit-net"])
        .output()
        .expect("spawn mvmctl create");
    assert!(
        create.status.success(),
        "create failed: stderr={}",
        String::from_utf8_lossy(&create.stderr)
    );

    let remove = sandbox
        .mvmctl()
        .args(["network", "remove", "test-rm-audit-net"])
        .output()
        .expect("spawn mvmctl remove");
    assert!(
        remove.status.success(),
        "remove failed: stderr={}",
        String::from_utf8_lossy(&remove.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "network_remove");
    assert!(
        hits >= 1,
        "expected ≥1 network_remove entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn manifest_prune_orphans_emits_slot_prune_audit_entry() {
    // Plan 37 §6 invariant: a state-changing verb emits one audit
    // record per attempt, even when the body of work is a no-op.
    // Running `manifest prune --orphans` against an empty registry
    // walks zero slots but still emits one `slot_prune` entry.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["manifest", "prune", "--orphans"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl manifest prune --orphans failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "slot_prune");
    assert!(
        hits >= 1,
        "expected ≥1 slot_prune entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn manifest_prune_orphans_dry_run_does_not_emit_audit_entry() {
    // Negative complement to `manifest_prune_orphans_emits_slot_prune…`.
    // Plan 37 §6 says state-changing verbs emit on every attempt; the
    // dry-run path is read-only by contract and must NOT emit. The
    // implementation routes dry-run to `run_dry` (manifest/prune.rs)
    // which returns before reaching the `audit::emit` call — this
    // test pins that against a future regression that moves the
    // emit above the dry-run branch.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["manifest", "prune", "--orphans", "--dry-run"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl manifest prune --orphans --dry-run failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "slot_prune");
    assert_eq!(
        hits, 0,
        "dry-run must not write audit entries, got {hits} slot_prune \
         entry/entries. Full log:\n{log}"
    );
}

#[test]
fn storage_gc_apply_emits_storage_gc_audit_entry_even_on_empty_pool() {
    // Plan 37 §6 invariant: a state-changing verb emits one audit
    // record per attempt, even when the body of work is a no-op.
    // Running `mvmctl storage gc --apply --mock` against a fresh
    // in-memory MockBackend lists zero volumes — but `--apply`
    // is the operator's commit signal, so the attempt must still
    // surface in the audit log. Failure here means the empty-pool
    // early-return in storage/gc.rs is skipping the emit.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["storage", "gc", "--apply", "--mock"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl storage gc --apply --mock failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "storage_gc");
    assert!(
        hits >= 1,
        "expected ≥1 storage_gc entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn storage_gc_dry_run_does_not_emit_audit_entry() {
    // Negative complement: dry-run is read-only and must not emit.
    // Plain `mvmctl storage gc --mock` (no `--apply`) is the dry-run
    // surface — pin it as a no-emit invariant against a future
    // regression that elevates the dry-run path into the emit branch.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["storage", "gc", "--mock"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl storage gc --mock failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "storage_gc");
    assert_eq!(
        hits, 0,
        "dry-run must not write audit entries, got {hits} storage_gc \
         entry/entries. Full log:\n{log}"
    );
}

#[test]
fn manifest_tag_add_emits_manifest_tag_add_audit_entry() {
    // `manifest tag add <template> <tag>` writes to
    // `~/.mvm/templates/<template>/tags.json` and emits
    // `ManifestTagAdd`. `TemplateTags::load` is forgiving — missing
    // templates yield an empty catalog — so the test runs against a
    // fresh sandbox without any pre-existing slot.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["manifest", "tag", "add", "test-tmpl", "live-test-tag"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl manifest tag add failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "manifest_tag_add");
    assert!(
        hits >= 1,
        "expected ≥1 manifest_tag_add entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn manifest_tag_rm_emits_manifest_tag_remove_audit_entry() {
    // Add a tag, then remove it. Two audit entries expected — one
    // `manifest_tag_add`, one `manifest_tag_remove` — but this test
    // pins only the remove half (the add half has its own test
    // above).
    let sandbox = AuditSandbox::new();
    let add = sandbox
        .mvmctl()
        .args(["manifest", "tag", "add", "test-tmpl", "to-remove"])
        .output()
        .expect("spawn mvmctl add");
    assert!(
        add.status.success(),
        "mvmctl manifest tag add failed: stderr={}",
        String::from_utf8_lossy(&add.stderr)
    );
    let rm = sandbox
        .mvmctl()
        .args(["manifest", "tag", "rm", "test-tmpl", "to-remove"])
        .output()
        .expect("spawn mvmctl rm");
    assert!(
        rm.status.success(),
        "mvmctl manifest tag rm failed: stderr={}",
        String::from_utf8_lossy(&rm.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "manifest_tag_remove");
    assert!(
        hits >= 1,
        "expected ≥1 manifest_tag_remove entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn manifest_tag_ls_does_not_emit_audit_entry() {
    // Negative complement: `manifest tag ls` is read-only and must
    // NOT emit. Pins the `MANIFEST_TAG` table's `ReadOnly` row in
    // `tests/audit_total_coverage.rs` against a future regression
    // that adds an emit to the list path.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["manifest", "tag", "ls", "test-tmpl"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl manifest tag ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let add_hits = count_entries_with_kind(&log, "manifest_tag_add");
    let rm_hits = count_entries_with_kind(&log, "manifest_tag_remove");
    assert_eq!(
        add_hits + rm_hits,
        0,
        "read-only `manifest tag ls` must not emit; got {add_hits} add \
         and {rm_hits} remove entries. Full log:\n{log}"
    );
}

#[test]
fn manifest_rm_emits_slot_remove_audit_entry() {
    // `manifest rm <path> --force` removes the slot keyed on the
    // canonicalised manifest path. The `--force` flag makes
    // `template_delete_slot` idempotent against missing slots, so
    // the test works against a fresh sandbox: write a stub
    // `mvm.toml`, then drive `manifest rm` — the audit entry lands
    // even though the slot directory was never created.
    let sandbox = AuditSandbox::new();
    let manifest_path = sandbox.home_path().join("mvm.toml");
    std::fs::write(&manifest_path, "[meta]\nname = \"live-test-rm\"\n")
        .expect("write stub mvm.toml");

    let output = sandbox
        .mvmctl()
        .args([
            "manifest",
            "rm",
            manifest_path.to_str().expect("utf-8 tempdir path"),
            "--force",
        ])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl manifest rm --force failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "slot_remove");
    assert!(
        hits >= 1,
        "expected ≥1 slot_remove entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn manifest_alias_rm_emits_manifest_alias_remove_audit_entry() {
    // Set an alias, then remove it. Pins the remove half of the
    // alias subgroup against a future regression that swaps the
    // emit kind or drops it entirely.
    let sandbox = AuditSandbox::new();
    let set = sandbox
        .mvmctl()
        .args([
            "manifest",
            "alias",
            "set",
            "test-tmpl",
            "to-remove",
            "abc123def456abc123def456abc123de",
        ])
        .output()
        .expect("spawn mvmctl set");
    assert!(
        set.status.success(),
        "mvmctl manifest alias set failed: stderr={}",
        String::from_utf8_lossy(&set.stderr)
    );
    let rm = sandbox
        .mvmctl()
        .args(["manifest", "alias", "rm", "test-tmpl", "to-remove"])
        .output()
        .expect("spawn mvmctl rm");
    assert!(
        rm.status.success(),
        "mvmctl manifest alias rm failed: stderr={}",
        String::from_utf8_lossy(&rm.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "manifest_alias_remove");
    assert!(
        hits >= 1,
        "expected ≥1 manifest_alias_remove entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn manifest_alias_ls_does_not_emit_audit_entry() {
    // Negative complement: `manifest alias ls` is read-only. Pins
    // the `MANIFEST_ALIAS` table's `ls → ReadOnly` row against a
    // future regression that adds an emit to the list path.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["manifest", "alias", "ls", "test-tmpl"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl manifest alias ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let set_hits = count_entries_with_kind(&log, "manifest_alias_set");
    let rm_hits = count_entries_with_kind(&log, "manifest_alias_remove");
    assert_eq!(
        set_hits + rm_hits,
        0,
        "read-only `manifest alias ls` must not emit; got {set_hits} set \
         and {rm_hits} remove entries. Full log:\n{log}"
    );
}

#[test]
fn manifest_alias_set_emits_manifest_alias_set_audit_entry() {
    // `manifest alias set <template> <alias> <rev>` writes to the
    // same `tags.json` and emits `ManifestAliasSet`. Same
    // forgiving-load story as `manifest tag add` above.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args([
            "manifest",
            "alias",
            "set",
            "test-tmpl",
            "latest",
            "abc123def456abc123def456abc123de",
        ])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl manifest alias set failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "manifest_alias_set");
    assert!(
        hits >= 1,
        "expected ≥1 manifest_alias_set entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn config_set_emits_config_change_audit_entry() {
    // `mvmctl config set <key> <value>` writes to
    // `~/.mvm/config.toml` and emits `ConfigChange` — config file
    // mutations are the only after-the-fact record of operator
    // intent on settings that change runtime behavior (default
    // backend, network policy, etc.).
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["ops", "config", "set", "default_cpus", "4"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl config set failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "config_change");
    assert!(
        hits >= 1,
        "expected ≥1 config_change entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
    // The key + value should also land in the detail field so an
    // operator scanning the audit log can see what changed.
    assert!(
        log.contains("key=default_cpus value=4"),
        "config_change detail must carry the key+value pair. \
         Full log:\n{log}"
    );
}

#[test]
fn config_show_does_not_emit_audit_entry() {
    // Negative: `config show` is read-only. Pins the
    // AUDIT_POSTURE classification (Emits at the top level, but
    // only `set` actually mutates).
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["ops", "config", "show"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl config show failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "config_change");
    assert_eq!(
        hits, 0,
        "read-only `config show` must not emit; got {hits} \
         config_change entry/entries. Full log:\n{log}"
    );
}

#[test]
fn cleanup_emits_slot_prune_audit_entry_even_with_no_builds() {
    // `mvmctl cleanup --keep 5` is the highest-friction Emits row
    // promoted to a live test: it runs three steps, two of which
    // (`run_in_vm` for /tmp cleanup + nix-collect-garbage) need a
    // running dev VM. Pre-refactor, the verb panicked out before
    // reaching the audit emit when the VM was unreachable. The
    // host-fallback in `cleanup_old_dev_builds` (now plain
    // `std::fs::read_dir` / `remove_dir_all`) lets Step 2 succeed
    // against `~/.mvm/dev/builds/` directly; the VM-dependent
    // steps degrade to warnings, and the emit lands at the end
    // regardless. The test asserts the empty-cache case (zero
    // build dirs to prune) — `count=0` is the Plan 37 §6
    // every-attempt-emits invariant in action.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["cleanup", "--keep", "5"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl cleanup --keep 5 failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "slot_prune");
    assert!(
        hits >= 1,
        "expected ≥1 slot_prune entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
    assert!(
        log.contains("source=cleanup"),
        "slot_prune detail must carry source=cleanup to disambiguate \
         from manifest-prune emits. Full log:\n{log}"
    );
}

/// Bring up an `--hypervisor mock` VM in the sandbox via the
/// `MVM_DIRECT_BOOT` direct-boot path. Returns when the VM is
/// registered in the name registry (which `up` does before
/// dispatching to the backend). Used as a fixture by tests of
/// state-changing verbs that operate on a registered VM
/// (`set-ttl`, future `pause`/`resume`/etc. work).
///
/// Pass-through env: `MVM_DIRECT_BOOT=1` + stub kernel/rootfs
/// files skip the build + template-lookup pre-flight that needs
/// real Nix; `--hypervisor mock` routes backend dispatch to
/// [`mvm_backend::MockBackend`]; `--detach` short-circuits the
/// Ctrl+C loop; `--no-supervisor` skips plan-64 admission.
fn bring_up_mock_vm(sandbox: &AuditSandbox, name: &str) {
    let stub_dir = sandbox.home_path().join("stub");
    std::fs::create_dir_all(&stub_dir).expect("mkdir stub");
    let kernel = stub_dir.join("vmlinux");
    let rootfs = stub_dir.join("rootfs.ext4");
    if !kernel.exists() {
        std::fs::write(&kernel, b"fake-kernel").expect("write stub kernel");
    }
    if !rootfs.exists() {
        std::fs::write(&rootfs, b"fake-rootfs").expect("write stub rootfs");
    }
    let output = sandbox
        .mvmctl()
        .env("MVM_DIRECT_BOOT", "1")
        .env("MVM_KERNEL_PATH", &kernel)
        .env("MVM_ROOTFS_PATH", &rootfs)
        .args([
            "up",
            "--hypervisor",
            "mock",
            "--name",
            name,
            "--no-supervisor",
            "--detach",
        ])
        .output()
        .expect("spawn mvmctl up");
    assert!(
        output.status.success(),
        "fixture: bring_up_mock_vm({name}) failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Per-test handle for a mock VM whose host-side vsock surface lives
/// in *this* (test) process. Pair with `mvmctl fs *` / `mvmctl proc *`
/// subprocesses — they discover the listener via the
/// filesystem-based mock detection in `instance_dir_for`.
///
/// Plan 66 W4. The `mvmctl up --hypervisor mock` subprocess pattern
/// used by `bring_up_mock_vm` doesn't work here because the
/// MockGuestAgent the subprocess spawns dies with the subprocess —
/// follow-up commands would find a stale socket and fail to connect.
/// Hosting the agent in the test process keeps it alive across every
/// subprocess invocation for the duration of the test.
struct MockVmAgentFixture {
    _agent: mvm_backend::mock_guest_agent::MockGuestAgent,
}

/// Create the mock-vms VM directory under the sandbox's HOME and
/// spawn a [`MockGuestAgent`](mvm_backend::mock_guest_agent::MockGuestAgent)
/// listening at `<vm_dir>/runtime/v.sock`. Returns when the listener
/// is ready to accept connections.
fn start_mock_vm_agent(sandbox: &AuditSandbox, name: &str) -> MockVmAgentFixture {
    // mvm_data_dir() resolves to `<HOME>/.mvm` by default. The
    // subprocess sees HOME=sandbox.home_path() and so will compute
    // the same path; we compute it here from the same root.
    let vm_dir = sandbox.home_path().join(".mvm").join("mock-vms").join(name);
    std::fs::create_dir_all(&vm_dir).expect("mkdir mock vm_dir");
    let agent = mvm_backend::mock_guest_agent::MockGuestAgent::start(&vm_dir)
        .expect("start mock guest agent");
    MockVmAgentFixture { _agent: agent }
}

#[test]
fn up_with_mock_backend_emits_vm_start_audit_entry() {
    // End-to-end test of `mvmctl up` against the in-memory
    // `MockBackend`. Pre-MockBackend this row needed a real
    // Firecracker / Apple Container / Docker / libkrun to
    // exercise — none of which are hermetic on a CI runner. The
    // MockBackend substrate + the `MVM_DIRECT_BOOT` direct-boot
    // path (see `bring_up_mock_vm`) together close that gap.
    let sandbox = AuditSandbox::new();
    bring_up_mock_vm(&sandbox, "test-up-vm");

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_start");
    assert!(
        hits >= 1,
        "expected ≥1 vm_start entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("\"vm_name\":\"test-up-vm\""),
        "vm_start must carry vm_name=test-up-vm. Full log:\n{log}"
    );
}

#[test]
fn set_ttl_emits_vm_ttl_set_audit_entry() {
    // `mvmctl set-ttl <vm> <duration>` operates on the persistent
    // name registry that `mvmctl up` populates. Bring up a mock
    // VM first (registers it), then update its TTL — the verb
    // emits `vm_ttl_set` with `expires_at=<RFC3339>` in detail.
    let sandbox = AuditSandbox::new();
    bring_up_mock_vm(&sandbox, "test-ttl-vm");

    let output = sandbox
        .mvmctl()
        .args(["vm", "set-ttl", "test-ttl-vm", "1h"])
        .output()
        .expect("spawn mvmctl set-ttl");
    assert!(
        output.status.success(),
        "mvmctl set-ttl failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_ttl_set");
    assert!(
        hits >= 1,
        "expected ≥1 vm_ttl_set entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("\"vm_name\":\"test-ttl-vm\""),
        "vm_ttl_set must carry vm_name=test-ttl-vm. Full log:\n{log}"
    );
    assert!(
        log.contains("expires_at="),
        "vm_ttl_set detail must record expires_at. Full log:\n{log}"
    );
}

#[test]
fn set_ttl_clear_emits_vm_ttl_set_with_cleared_detail() {
    // Negative-shape complement: `set-ttl --clear` removes the
    // TTL and emits the same `vm_ttl_set` kind but with
    // `detail=expires_at=cleared`. Pins both the verb's "set"
    // and "clear" paths in one suite.
    let sandbox = AuditSandbox::new();
    bring_up_mock_vm(&sandbox, "test-ttl-clear-vm");

    let output = sandbox
        .mvmctl()
        .args(["vm", "set-ttl", "test-ttl-clear-vm", "--clear"])
        .output()
        .expect("spawn mvmctl set-ttl --clear");
    assert!(
        output.status.success(),
        "mvmctl set-ttl --clear failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.contains("expires_at=cleared"),
        "set-ttl --clear must record expires_at=cleared. Full log:\n{log}"
    );
}

#[test]
fn pause_emits_workload_sleep_audit_entry() {
    // Plan 65 W3: `mvmctl pause --hypervisor mock` exercises the
    // snapshot-and-seal path against `CannedIO` (deterministic
    // 12-byte vmstate + 8-byte mem stubs). Pre-Plan-65 the verb
    // would have bailed on `resolve_running_vm_dir` because the
    // mock VM has no Lima-shaped vm_dir; the `--hypervisor mock`
    // selector routes through `MockBackend::vm_dir(name)` instead.
    let sandbox = AuditSandbox::new();
    bring_up_mock_vm(&sandbox, "pause-vm");

    let output = sandbox
        .mvmctl()
        .args(["vm", "pause", "pause-vm", "--hypervisor", "mock"])
        .output()
        .expect("spawn mvmctl pause");
    assert!(
        output.status.success(),
        "mvmctl pause failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "workload_sleep");
    assert!(
        hits >= 1,
        "expected ≥1 workload_sleep entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("\"vm_name\":\"pause-vm\""),
        "workload_sleep must carry vm_name=pause-vm. Full log:\n{log}"
    );
    assert!(
        log.contains("epoch="),
        "workload_sleep detail must record the epoch. Full log:\n{log}"
    );
}

#[test]
fn resume_emits_workload_wake_audit_entry() {
    // Plan 65 W3: pause-then-resume against the mock backend.
    // The seal-and-verify round-trip works because `CannedIO`
    // writes its stubs to disk and `verify_and_resume` reads
    // them back through the same HMAC-sealed sidecar.
    let sandbox = AuditSandbox::new();
    bring_up_mock_vm(&sandbox, "resume-vm");

    let pause = sandbox
        .mvmctl()
        .args(["vm", "pause", "resume-vm", "--hypervisor", "mock"])
        .output()
        .expect("spawn mvmctl pause");
    assert!(
        pause.status.success(),
        "mvmctl pause failed: stderr={}",
        String::from_utf8_lossy(&pause.stderr)
    );
    let resume = sandbox
        .mvmctl()
        .args(["vm", "resume", "resume-vm", "--hypervisor", "mock"])
        .output()
        .expect("spawn mvmctl resume");
    assert!(
        resume.status.success(),
        "mvmctl resume failed: stderr={}",
        String::from_utf8_lossy(&resume.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "workload_wake");
    assert!(
        hits >= 1,
        "expected ≥1 workload_wake entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("\"vm_name\":\"resume-vm\""),
        "workload_wake must carry vm_name=resume-vm. Full log:\n{log}"
    );
}

#[test]
fn down_no_args_emits_vm_stop_audit_entry() {
    // `mvmctl down` (no args, empty registry) calls `backend.stop_all`,
    // which Firecracker satisfies as a no-op when no VMs are running.
    // The verb emits `vm_stop` with `detail=stop_all_ok` regardless
    // — Plan 37 §6: every state-changing CLI verb emits one record
    // per attempt, even no-ops.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["down"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl down failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_stop");
    assert!(
        hits >= 1,
        "expected ≥1 vm_stop entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("stop_all_ok"),
        "vm_stop detail must record stop_all outcome. Full log:\n{log}"
    );
}

#[test]
fn down_with_name_emits_vm_stop_for_that_name() {
    // `mvmctl down <vm>` against a fresh sandbox: Firecracker's
    // `stop_vm` is tolerant of missing VMs (returns Ok), the verb
    // emits `vm_stop` with `vm_name=<vm>` and `detail=ok`.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["down", "ghost-vm"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl down ghost-vm failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_stop");
    assert!(
        hits >= 1,
        "expected ≥1 vm_stop entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("\"vm_name\":\"ghost-vm\""),
        "vm_stop must carry vm_name=ghost-vm. Full log:\n{log}"
    );
}

#[test]
fn snapshot_rm_emits_snapshot_delete_audit_entry() {
    // `mvmctl snapshot rm <vm>` removes the snapshot directory and
    // emits `SnapshotDelete`. `delete_instance_snapshot` returns
    // `Ok(false)` when the directory is missing — the CLI then
    // bails *before* the emit point. To exercise the emit branch
    // hermetically, pre-create the snapshot dir with stub bytes.
    // No real Firecracker / VM is involved.
    let sandbox = AuditSandbox::new();
    let snap_dir = sandbox
        .home_path()
        .join(".mvm")
        .join("instances")
        .join("test-snap")
        .join("snapshot");
    std::fs::create_dir_all(&snap_dir).expect("mkdir snapshot dir");
    std::fs::write(snap_dir.join("vmstate.bin"), b"stub").expect("write vmstate stub");

    let output = sandbox
        .mvmctl()
        .args(["vm", "snapshot", "rm", "test-snap"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl snapshot rm failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "snapshot_delete");
    assert!(
        hits >= 1,
        "expected ≥1 snapshot_delete entry in audit log, got {hits}. \
         Full log:\n{log}"
    );
    // The vm_name field should carry the snapshot identity so
    // operator searches by VM name find the matching emit.
    assert!(
        log.contains("\"vm_name\":\"test-snap\""),
        "snapshot_delete must carry vm_name=test-snap. Full log:\n{log}"
    );
}

#[test]
fn snapshot_ls_does_not_emit_audit_entry() {
    // Negative: `snapshot ls` is read-only. `SNAPSHOT_SUB` in
    // `audit_total_coverage.rs` classifies it as `ReadOnly`; this
    // test pins that against a future regression that adds an
    // emit to the list path.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["vm", "snapshot", "ls"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl snapshot ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "snapshot_delete");
    assert_eq!(
        hits, 0,
        "read-only `snapshot ls` must not emit snapshot_delete; \
         got {hits}. Full log:\n{log}"
    );
}

#[test]
fn audit_tail_does_not_emit_local_audit_entry() {
    // Negative: `audit tail` reads the LocalAudit stream. The audit
    // CLI itself is ReadOnly (classification in
    // `audit_total_coverage.rs`); reading the log must not add to it.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["audit", "tail"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl audit tail failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The LocalAudit stream (`<state>/log/audit.jsonl`) must be
    // empty — tail reads but does not write. The plan-64 chain at
    // `~/.mvm/audit/<tenant>.jsonl` always gains cmd.* entries
    // from the audit emitter middleware, which is by design and
    // separate from the LocalAudit stream this lint guards.
    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `audit tail` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn audit_verify_does_not_emit_local_audit_entry() {
    // Negative: `audit verify` validates the plan-64 chain.
    // Read-only against the LocalAudit stream. Note the verify
    // command itself appends cmd.* chain entries via the emitter
    // middleware — that's a separate stream and not in scope here.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["audit", "verify"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl audit verify failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `audit verify` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn top_level_ls_does_not_emit_audit_entry() {
    // `mvmctl ls` reports running VMs. Pure read. Top-level
    // `("ls", AuditPosture::ReadOnly)` row in `AUDIT_POSTURE`.
    // Pinning the empty-sandbox case — output is "No running VMs."
    // and the audit log stays empty.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["ls"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `mvmctl ls` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn metrics_does_not_emit_audit_entry() {
    // `mvmctl metrics` prints Prometheus exposition. Pure read.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["ops", "metrics"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl metrics failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `mvmctl metrics` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn catalog_list_does_not_emit_audit_entry() {
    // `mvmctl catalog list` enumerates bundled images. The catalog
    // is compiled in; no disk reads beyond mvmctl's binary itself.
    // Pure read.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["catalog", "list"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl catalog list failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `mvmctl catalog list` must not write to the \
         LocalAudit stream. Full log:\n{log}"
    );
}

#[test]
fn update_emits_update_install_audit_entry_against_mocked_github() {
    // Plan 69: `mvmctl update` reaches `api.github.com/releases/latest`
    // by default. The `MVM_UPDATE_API_URL` env-var redirects the
    // base URL to a local `httpmock` server, which returns the
    // current binary's own version. `update::update` then exits
    // early on the "already up to date" branch — Ok(()) without
    // swapping the binary — and the outer wrapper at
    // `commands/env/update.rs` emits `UpdateInstall`. No real
    // network, no binary swap, no install dance.
    let server = httpmock::MockServer::start();
    let current_version = env!("CARGO_PKG_VERSION");
    let _api_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_contains("/releases/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(format!(r#"{{"tag_name":"v{current_version}"}}"#));
    });

    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .env("MVM_UPDATE_API_URL", server.base_url())
        .args(["update"])
        .output()
        .expect("spawn mvmctl update");
    assert!(
        output.status.success(),
        "mvmctl update failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "update_install");
    assert!(
        hits >= 1,
        "expected ≥1 update_install entry, got {hits}. Full log:\n{log}"
    );
}

#[test]
fn update_check_does_not_emit_audit_entry() {
    // Negative: `update --check` short-circuits before the install
    // path AND before the outer wrapper's audit-emit branch
    // (`!args.check` guard at `commands/env/update.rs`). Read-only;
    // pins that against a future regression that emits on check.
    let server = httpmock::MockServer::start();
    let _api_mock = server.mock(|when, then| {
        when.method(httpmock::Method::GET)
            .path_contains("/releases/latest");
        then.status(200)
            .header("content-type", "application/json")
            .body(r#"{"tag_name":"v0.999.0"}"#);
    });

    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .env("MVM_UPDATE_API_URL", server.base_url())
        .args(["update", "--check"])
        .output()
        .expect("spawn mvmctl update --check");
    assert!(
        output.status.success(),
        "mvmctl update --check failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "update_install");
    assert_eq!(
        hits, 0,
        "read-only `update --check` must not emit; got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn uninstall_yes_all_emits_uninstall_audit_entry_via_prefix_override() {
    // Plan 70: the positive `Uninstall` path mutates real system
    // paths (`/var/lib/mvm`, `/usr/local/bin/mvmctl`) via sudo —
    // not safely-hermetic on a developer's machine. The
    // `MVM_UNINSTALL_PATH_PREFIX` env-var rewrites the targets
    // under a sandbox sub-dir and skips sudo. The audit emit fires
    // unconditionally at the end of the verb, so the test pins the
    // emit + the on-disk side-effect (the rewritten paths are
    // gone).
    let sandbox = AuditSandbox::new();
    let prefix = sandbox.home_path().join("system-root");
    let stub_state_dir = prefix.join("var/lib/mvm");
    let stub_bin = prefix.join("usr/local/bin/mvmctl");
    std::fs::create_dir_all(&stub_state_dir).expect("mkdir state stub");
    std::fs::create_dir_all(stub_bin.parent().unwrap()).expect("mkdir bin dir");
    std::fs::write(&stub_bin, b"#!/bin/sh\nexit 0\n").expect("write stub binary");

    let output = sandbox
        .mvmctl()
        .env("MVM_UNINSTALL_PATH_PREFIX", &prefix)
        .args(["uninstall", "--yes", "--all"])
        .output()
        .expect("spawn mvmctl uninstall");
    assert!(
        output.status.success(),
        "mvmctl uninstall failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "uninstall");
    assert!(
        hits >= 1,
        "expected ≥1 uninstall entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        !stub_state_dir.exists(),
        "stub state dir at {} must be removed",
        stub_state_dir.display()
    );
    assert!(
        !stub_bin.exists(),
        "stub binary at {} must be removed",
        stub_bin.display()
    );
}

#[test]
fn uninstall_dry_run_does_not_emit_audit_entry() {
    // `mvmctl uninstall --yes` emits `Uninstall` at the end, but
    // its three filesystem mutations (`/var/lib/mvm`, `~/.mvm/`,
    // `/usr/local/bin/mvmctl`) are real system paths that can't
    // safely be exercised in a hermetic test — a dev with an
    // actual install on the local machine would have sudo block
    // the test mid-run. The dry-run path returns before any of
    // those steps and (per the implementation) before the audit
    // emit; this test pins that contract.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["uninstall", "--yes", "--dry-run"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl uninstall --yes --dry-run failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "uninstall");
    assert_eq!(
        hits, 0,
        "dry-run must not write uninstall audit entries, got {hits}. \
         Full log:\n{log}"
    );
}

#[test]
fn session_ls_does_not_emit_audit_entry() {
    // Negative: `session ls` enumerates active sessions from the
    // on-disk registry. Read-only; the `SESSION_SUB.ls` row is
    // classified `ReadOnly`. Empty sandbox = empty session list,
    // no entries emitted.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["vm", "session", "ls"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl session ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `session ls` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn volume_ls_does_not_emit_audit_entry() {
    // Negative: `volume ls <vm>` lists registered volume mounts.
    // Read-only against the per-VM volume registry. `VOLUME_SUB.ls`
    // row is `ReadOnly`; empty sandbox = "(no volume mounts)",
    // no audit entries.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["vm", "volume", "ls", "test-vm"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl volume ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `volume ls` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn volume_mount_emits_vm_volume_add_audit_entry() {
    // Plan 67: `volume mount` operates purely on the host-side
    // `~/.mvm/instances/<vm>/volume_mounts.json` registry — no
    // virtio-fs daemon attach, no Firecracker socket. The audit
    // emit fires after the registry write. Hermetic out of the box.
    let sandbox = AuditSandbox::new();
    let host_share = sandbox.home_path().join("share");
    std::fs::create_dir_all(&host_share).expect("mkdir host share");
    let probe_path = sandbox.encrypted_volume_probe_path();

    let output = sandbox
        .mvmctl()
        .env("PATH", &probe_path)
        .args([
            "vm",
            "volume",
            "mount",
            "vol-test-vm",
            "--volume",
            "mydata",
            "--host",
            host_share.to_str().expect("utf-8 path"),
            "--guest",
            "/mnt/data",
        ])
        .output()
        .expect("spawn mvmctl volume mount");
    assert!(
        output.status.success(),
        "mvmctl volume mount failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_volume_add");
    assert!(
        hits >= 1,
        "expected ≥1 vm_volume_add entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("\"vm_name\":\"vol-test-vm\""),
        "vm_volume_add must carry vm_name=vol-test-vm. Full log:\n{log}"
    );
    assert!(
        log.contains("guest=/mnt/data"),
        "vm_volume_add detail must record guest=/mnt/data. Full log:\n{log}"
    );
}

#[test]
fn volume_create_emits_volume_create_audit_entry() {
    let sandbox = AuditSandbox::new();
    let root = sandbox.home_path().join("encrypted-root");
    std::fs::create_dir_all(&root).expect("mkdir encrypted root");
    let probe_path = sandbox.encrypted_volume_probe_path();

    let output = sandbox
        .mvmctl()
        .env("PATH", &probe_path)
        .args([
            "vm",
            "volume",
            "create",
            "managed",
            "--root",
            root.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("spawn mvmctl volume create");
    assert!(
        output.status.success(),
        "mvmctl volume create failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "volume_create");
    assert!(
        hits >= 1,
        "expected ≥1 volume_create entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("volume=managed"),
        "volume_create detail must record volume=managed. Full log:\n{log}"
    );
}

#[test]
fn volume_unlock_and_lock_emit_audit_entries() {
    let sandbox = AuditSandbox::new();
    let root = sandbox.home_path().join("mvm-volume-root");
    std::fs::create_dir_all(&root).expect("mkdir volume root");

    let create = sandbox
        .mvmctl()
        .args([
            "vm",
            "volume",
            "create",
            "managed",
            "--root",
            root.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("spawn mvmctl volume create");
    assert!(
        create.status.success(),
        "mvmctl volume create failed: stderr={}",
        String::from_utf8_lossy(&create.stderr)
    );

    let unlock = sandbox
        .mvmctl()
        .args(["vm", "volume", "unlock", "managed"])
        .output()
        .expect("spawn mvmctl volume unlock");
    assert!(
        unlock.status.success(),
        "mvmctl volume unlock failed: stderr={}",
        String::from_utf8_lossy(&unlock.stderr)
    );
    std::fs::write(
        root.join("unlocked").join("managed").join("proof.txt"),
        b"ok",
    )
    .expect("write unlocked volume proof");

    let lock = sandbox
        .mvmctl()
        .args(["vm", "volume", "lock", "managed"])
        .output()
        .expect("spawn mvmctl volume lock");
    assert!(
        lock.status.success(),
        "mvmctl volume lock failed: stderr={}",
        String::from_utf8_lossy(&lock.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        count_entries_with_kind(&log, "volume_open") >= 1,
        "expected volume_open entry. Full log:\n{log}"
    );
    assert!(
        count_entries_with_kind(&log, "volume_lock") >= 1,
        "expected volume_lock entry. Full log:\n{log}"
    );
}

#[test]
fn volume_unmount_emits_vm_volume_remove_audit_entry() {
    // Plan 67: mount-then-unmount round-trip. Both emits land in
    // the LocalAudit stream; this test pins the remove half.
    let sandbox = AuditSandbox::new();
    let host_share = sandbox.home_path().join("share");
    std::fs::create_dir_all(&host_share).expect("mkdir host share");
    let probe_path = sandbox.encrypted_volume_probe_path();

    let mount = sandbox
        .mvmctl()
        .env("PATH", &probe_path)
        .args([
            "vm",
            "volume",
            "mount",
            "vol-rm-vm",
            "--volume",
            "mydata",
            "--host",
            host_share.to_str().expect("utf-8 path"),
            "--guest",
            "/mnt/data",
        ])
        .output()
        .expect("spawn mvmctl volume mount");
    assert!(
        mount.status.success(),
        "mvmctl volume mount failed: stderr={}",
        String::from_utf8_lossy(&mount.stderr)
    );

    let unmount = sandbox
        .mvmctl()
        .args(["vm", "volume", "unmount", "vol-rm-vm", "/mnt/data"])
        .output()
        .expect("spawn mvmctl volume unmount");
    assert!(
        unmount.status.success(),
        "mvmctl volume unmount failed: stderr={}",
        String::from_utf8_lossy(&unmount.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_volume_remove");
    assert!(
        hits >= 1,
        "expected ≥1 vm_volume_remove entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("\"vm_name\":\"vol-rm-vm\""),
        "vm_volume_remove must carry vm_name=vol-rm-vm. Full log:\n{log}"
    );
}

#[test]
fn audit_show_does_not_emit_local_audit_entry() {
    // Negative: `audit show <plan_id>` filters chain entries by
    // plan_id. Read-only against the LocalAudit stream. With an
    // arbitrary plan_id the command reports "No audit entries
    // found" and exits 0 — the LocalAudit stream must remain
    // empty.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["audit", "show", "00000000-0000-0000-0000-000000000000"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl audit show failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `audit show` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn attest_export_does_not_emit_local_audit_entry() {
    // Negative: `attest export` prints the host's attestation
    // report as JSON. Pure read — the `ATTEST_SUB` table
    // classifies all three leaves (export / verify / status) as
    // ReadOnly.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["attest", "export"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl attest export failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `attest export` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

#[test]
fn attest_status_does_not_emit_local_audit_entry() {
    // Negative: `attest status` reports the host's attestation
    // identity — pure read. `ATTEST_SUB` classifies all three
    // leaves (export / verify / status) as ReadOnly.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .args(["attest", "status"])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl attest status failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    assert!(
        log.is_empty(),
        "read-only `attest status` must not write to the LocalAudit \
         stream. Full log:\n{log}"
    );
}

/// Common setup: put a secret into the sandbox so subsequent
/// `get` / `ls` / `rm` have something to operate on.
fn put_a_secret(sandbox: &AuditSandbox, tenant: &str, name: &str, value: &str) {
    let output = sandbox
        .mvmctl()
        .args(["secret", "put", name, "--tenant", tenant, "--value", value])
        .output()
        .expect("spawn mvmctl put");
    assert!(
        output.status.success(),
        "secret put pre-step failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn secret_put_emits_put_action_in_secret_audit_log() {
    // The `mvmctl secret` command writes per-action JSONL to a
    // separate audit file (`~/.mvm/audit/secrets.jsonl`); the
    // shape is `{"action":"put","tenant":...,"name":...,"outcome":"ok",...}`.
    // This pins the entry shape so a regression that flips
    // "action" → "verb" or relocates the file gets caught.
    let sandbox = AuditSandbox::new();
    let output = sandbox
        .mvmctl()
        .env("MVM_SECRET_STORE_BACKEND", "file")
        .args([
            "secret",
            "put",
            "api-key",
            "--tenant",
            "test-tenant",
            "--value",
            "deadbeef",
        ])
        .output()
        .expect("spawn mvmctl");
    assert!(
        output.status.success(),
        "mvmctl secret put failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = std::fs::read_to_string(sandbox.secret_audit_log_path()).unwrap_or_default();
    assert!(
        log.contains("\"action\":\"put\""),
        "expected an 'action':'put' entry in secrets audit log. Full log:\n{log}"
    );
    assert!(
        log.contains("\"tenant\":\"test-tenant\""),
        "audit entry must record the tenant. Full log:\n{log}"
    );
    assert!(
        log.contains("\"outcome\":\"ok\""),
        "audit entry must record outcome=ok on success. Full log:\n{log}"
    );
    assert!(
        log.contains("\"secret_visibility\":\"write_only\""),
        "audit entry must record write-only secret posture. Full log:\n{log}"
    );
    assert!(
        log.contains("\"storage_security\":\"encrypted_at_rest\""),
        "audit entry must record encrypted-at-rest storage posture. Full log:\n{log}"
    );
}

#[test]
fn secret_get_emits_get_action_in_secret_audit_log() {
    // Put first, then verify presence. `secret get` never prints
    // the raw value; it only asserts the entry exists and emits the
    // per-action audit JSONL.
    let sandbox = AuditSandbox::new();
    put_a_secret(&sandbox, "test-tenant", "api-key", "deadbeef");

    let output = sandbox
        .mvmctl()
        .args(["secret", "get", "api-key", "--tenant", "test-tenant"])
        .output()
        .expect("spawn mvmctl get");
    assert!(
        output.status.success(),
        "mvmctl secret get failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = std::fs::read_to_string(sandbox.secret_audit_log_path()).unwrap_or_default();
    assert!(
        log.contains("\"action\":\"get\""),
        "expected an 'action':'get' entry in secrets audit log. Full log:\n{log}"
    );
}

#[test]
fn secret_ls_emits_list_action_in_secret_audit_log() {
    // The clap verb is `ls` but `cmd_ls` records `action:"list"`
    // on-disk. The audit JSONL's `action` field is the *operation
    // name*, not the CLI verb. Pin both — flipping either side
    // without updating this test would mask a real audit shape
    // change.
    let sandbox = AuditSandbox::new();
    put_a_secret(&sandbox, "test-tenant", "api-key", "deadbeef");

    let output = sandbox
        .mvmctl()
        .args(["secret", "ls", "--tenant", "test-tenant"])
        .output()
        .expect("spawn mvmctl ls");
    assert!(
        output.status.success(),
        "mvmctl secret ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = std::fs::read_to_string(sandbox.secret_audit_log_path()).unwrap_or_default();
    assert!(
        log.contains("\"action\":\"list\""),
        "expected an 'action':'list' entry in secrets audit log. Full log:\n{log}"
    );
}

#[test]
fn secret_rm_emits_delete_action_in_secret_audit_log() {
    // Same op-name vs CLI-verb decoupling as `ls` above: clap
    // surface is `rm`, audit action is `"delete"`.
    let sandbox = AuditSandbox::new();
    put_a_secret(&sandbox, "test-tenant", "api-key", "deadbeef");

    let output = sandbox
        .mvmctl()
        .args(["secret", "rm", "api-key", "--tenant", "test-tenant"])
        .output()
        .expect("spawn mvmctl rm");
    assert!(
        output.status.success(),
        "mvmctl secret rm failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = std::fs::read_to_string(sandbox.secret_audit_log_path()).unwrap_or_default();
    assert!(
        log.contains("\"action\":\"delete\""),
        "expected an 'action':'delete' entry in secrets audit log. Full log:\n{log}"
    );
}

#[test]
fn build_emits_template_build_audit_entry_against_stub_outdir() {
    // Plan 68: `mvmctl build --flake <stub-flake> --profile minimal`
    // reaches `mvm_build::dev_build::dev_build`, which normally
    // shells out to `nix build`. With `MVM_BUILD_STUB_OUTDIR` set,
    // dev_build returns a synthetic `DevBuildResult` pointing at
    // the stub directory and skips both the Nix invocation and the
    // guest-agent injection step. The outer build_flake wrapper
    // still calls `audit_build_ok("flake", &resolved, "", &revision)`,
    // which emits one `template_build` record. Hermetic — no Nix,
    // no Lima, no Apple Container, no sudo.
    let sandbox = AuditSandbox::new();

    // Stub build output: a directory whose basename becomes the
    // revision hash (per dev_build's stub branch). `vmlinux` and
    // `rootfs.ext4` are placeholders so any downstream caller that
    // statted them sees real files.
    let stub_out = sandbox.home_path().join("stub-out");
    std::fs::create_dir_all(&stub_out).expect("mkdir stub_out");
    std::fs::write(stub_out.join("vmlinux"), b"fake-kernel").expect("write stub kernel");
    std::fs::write(stub_out.join("rootfs.ext4"), b"fake-rootfs").expect("write stub rootfs");

    // Stub flake source. `validate_flake_ref` accepts a local path
    // containing `flake.nix`; the stub-outdir branch never reads
    // it.
    let flake_dir = sandbox.home_path().join("flake");
    std::fs::create_dir_all(&flake_dir).expect("mkdir flake_dir");
    std::fs::write(flake_dir.join("flake.nix"), b"# stub\n").expect("write stub flake");

    let output = sandbox
        .mvmctl()
        .env("MVM_BUILD_STUB_OUTDIR", &stub_out)
        .args([
            "build",
            "--flake",
            flake_dir.to_str().expect("utf-8 flake path"),
            "--profile",
            "minimal",
        ])
        .output()
        .expect("spawn mvmctl build");
    assert!(
        output.status.success(),
        "mvmctl build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "template_build");
    assert!(
        hits >= 1,
        "expected ≥1 template_build entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("mode=flake"),
        "expected detail to record mode=flake. Full log:\n{log}"
    );
    assert!(
        log.contains("artifact=stub-out"),
        "expected detail to record artifact=stub-out (the stub-outdir basename). Full log:\n{log}"
    );
}

// ============================================================================
// Plan 66 W4 — `mvmctl fs *` and `mvmctl proc *` live tests.
//
// Each test stands up a `MockGuestAgent` in the test process, then
// drives the matching CLI subcommand as a subprocess. The CLI's
// `instance_dir_for` helper detects the mock-vms socket and routes
// the vsock request to the in-process agent instead of the
// Lima-era `microvm::resolve_running_vm_dir` shell-out.
// ============================================================================

#[test]
fn fs_write_emits_vm_fs_mutate_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-fsw");

    let output = sandbox
        .mvmctl()
        .args([
            "vm",
            "fs",
            "write",
            "t-fsw",
            "/tmp/hello",
            "--content",
            "hi",
        ])
        .output()
        .expect("spawn mvmctl fs write");
    assert!(
        output.status.success(),
        "mvmctl fs write failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_fs_mutate");
    assert!(
        hits >= 1,
        "expected ≥1 vm_fs_mutate entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("op=write path=/tmp/hello bytes=2"),
        "expected op=write detail with bytes=2. Full log:\n{log}"
    );
}

#[test]
fn fs_mkdir_emits_vm_fs_mutate_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-fsmk");

    let output = sandbox
        .mvmctl()
        .args(["vm", "fs", "mkdir", "t-fsmk", "/tmp/newdir"])
        .output()
        .expect("spawn mvmctl fs mkdir");
    assert!(
        output.status.success(),
        "mvmctl fs mkdir failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_fs_mutate");
    assert!(
        hits >= 1,
        "expected ≥1 vm_fs_mutate entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("op=mkdir path=/tmp/newdir"),
        "expected op=mkdir detail. Full log:\n{log}"
    );
}

#[test]
fn fs_rm_emits_vm_fs_mutate_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-fsrm");

    let output = sandbox
        .mvmctl()
        .args(["vm", "fs", "rm", "t-fsrm", "/tmp/stale"])
        .output()
        .expect("spawn mvmctl fs rm");
    assert!(
        output.status.success(),
        "mvmctl fs rm failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_fs_mutate");
    assert!(
        hits >= 1,
        "expected ≥1 vm_fs_mutate entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("op=rm path=/tmp/stale"),
        "expected op=rm detail. Full log:\n{log}"
    );
}

#[test]
fn fs_mv_emits_vm_fs_mutate_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-fsmv");

    let output = sandbox
        .mvmctl()
        .args(["vm", "fs", "mv", "t-fsmv", "/tmp/src", "/tmp/dst"])
        .output()
        .expect("spawn mvmctl fs mv");
    assert!(
        output.status.success(),
        "mvmctl fs mv failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_fs_mutate");
    assert!(
        hits >= 1,
        "expected ≥1 vm_fs_mutate entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("op=mv from=/tmp/src to=/tmp/dst"),
        "expected op=mv detail. Full log:\n{log}"
    );
}

#[test]
fn fs_ls_does_not_emit_mutation_audit_entry() {
    // Read-only: `fs ls` doesn't mutate state — must not emit
    // any *mutation-class* LocalAudit kind (`VmFsMutate`,
    // `SlotRemove`, …). It *does* emit a
    // `network_policy_allow` record per Plan 74 W2 / Plan 51
    // W6 (every host→guest vsock RPC is audited regardless of
    // whether the CLI verb is read-only); the two invariants
    // are orthogonal.
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-fsls");

    let output = sandbox
        .mvmctl()
        .args(["vm", "fs", "ls", "t-fsls", "/tmp"])
        .output()
        .expect("spawn mvmctl fs ls");
    assert!(
        output.status.success(),
        "mvmctl fs ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    // No mutation-class records. The only audit entries
    // allowed are the W2 vsock-RPC audit records.
    assert_eq!(
        count_entries_with_kind(&log, "vm_fs_mutate"),
        0,
        "read-only `mvmctl fs ls` must not write a mutation LocalAudit. Full log:\n{log}"
    );
    // Exactly one inbound vsock RPC audit (fs-list).
    assert!(
        log.contains("\"kind\":\"network_policy_allow\""),
        "fs ls must emit a network_policy_allow vsock-RPC record. Full log:\n{log}"
    );
    assert!(
        log.contains("verb=fs-list"),
        "vsock-RPC audit detail must name verb=fs-list. Full log:\n{log}"
    );
}

#[test]
fn proc_start_emits_vm_proc_start_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-ps");

    let output = sandbox
        .mvmctl()
        .args(["vm", "proc", "start", "t-ps", "--", "/bin/true"])
        .output()
        .expect("spawn mvmctl proc start");
    assert!(
        output.status.success(),
        "mvmctl proc start failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_proc_start");
    assert!(
        hits >= 1,
        "expected ≥1 vm_proc_start entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("argv0=/bin/true"),
        "expected argv0=/bin/true detail. Full log:\n{log}"
    );
}

#[test]
fn proc_signal_emits_vm_proc_signal_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-psg");

    let output = sandbox
        .mvmctl()
        .args(["vm", "proc", "signal", "t-psg", "proc-fake-token", "15"])
        .output()
        .expect("spawn mvmctl proc signal");
    assert!(
        output.status.success(),
        "mvmctl proc signal failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_proc_signal");
    assert!(
        hits >= 1,
        "expected ≥1 vm_proc_signal entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("token=proc-fake-token signum=15"),
        "expected token+signum detail. Full log:\n{log}"
    );
}

#[test]
fn proc_kill_emits_kill_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-pk");

    let output = sandbox
        .mvmctl()
        .args(["vm", "proc", "kill", "t-pk", "proc-fake-token"])
        .output()
        .expect("spawn mvmctl proc kill");
    assert!(
        output.status.success(),
        "mvmctl proc kill failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "kill");
    assert!(
        hits >= 1,
        "expected ≥1 kill entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("scope=guest_proc token=proc-fake-token"),
        "expected scope=guest_proc detail. Full log:\n{log}"
    );
}

#[test]
fn proc_stdin_emits_vm_proc_stdin_audit_entry() {
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-pst");

    let output = sandbox
        .mvmctl()
        .args([
            "vm",
            "proc",
            "stdin",
            "t-pst",
            "proc-fake-token",
            "--content",
            "hello",
        ])
        .output()
        .expect("spawn mvmctl proc stdin");
    assert!(
        output.status.success(),
        "mvmctl proc stdin failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    let hits = count_entries_with_kind(&log, "vm_proc_stdin");
    assert!(
        hits >= 1,
        "expected ≥1 vm_proc_stdin entry, got {hits}. Full log:\n{log}"
    );
    assert!(
        log.contains("token=proc-fake-token bytes=5"),
        "expected token+bytes=5 detail. Full log:\n{log}"
    );
}

#[test]
fn proc_ls_does_not_emit_mutation_audit_entry() {
    // Read-only: `proc ls` doesn't mutate process state — must
    // not emit any mutation-class LocalAudit kind. It *does*
    // emit a `network_policy_allow` record per Plan 74 W2 /
    // Plan 51 W6 (every host→guest vsock RPC is audited); the
    // two invariants are orthogonal.
    let sandbox = AuditSandbox::new();
    let _fixture = start_mock_vm_agent(&sandbox, "t-pls");

    let output = sandbox
        .mvmctl()
        .args(["vm", "proc", "ls", "t-pls"])
        .output()
        .expect("spawn mvmctl proc ls");
    assert!(
        output.status.success(),
        "mvmctl proc ls failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let log = read_audit_log(&sandbox.audit_log_path());
    // No mutation-class records. ProcStart / ProcSignal / etc.
    // emit those kinds; `proc ls` must NOT.
    for mutating in ["vm_proc_start", "vm_proc_signal", "vm_proc_stdin", "kill"] {
        assert_eq!(
            count_entries_with_kind(&log, mutating),
            0,
            "read-only `mvmctl proc ls` must not write {mutating} LocalAudit. Full log:\n{log}"
        );
    }
    // Exactly one inbound vsock RPC audit (proc-list).
    assert!(
        log.contains("\"kind\":\"network_policy_allow\""),
        "proc ls must emit a network_policy_allow vsock-RPC record. Full log:\n{log}"
    );
    assert!(
        log.contains("verb=proc-list"),
        "vsock-RPC audit detail must name verb=proc-list. Full log:\n{log}"
    );
}

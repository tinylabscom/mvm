//! Plan 60 Phase 4 — every CLI subcommand must declare its audit
//! posture, at every level of the clap tree.
//!
//! Plan 60 §"Phase 4 — Persistent observability" exit test
//! `every_command_emits_audit_entry` is the eventual goal: drive
//! every `mvmctl` subcommand end-to-end and assert ≥1 audit entry
//! per. That end-to-end coverage needs hermetic test fixtures for
//! every command (many need a running VM, lima, or network), so it
//! grows incrementally as commands gain testable setups.
//!
//! What this scaffold ships is the **enforcement that every command
//! has a declared audit posture**, recursively. The test walks
//! `mvm_cli::cli_command()` and checks each leaf — top-level
//! subcommands AND the leaves of every `DelegatesToSub` subgroup —
//! against a static [`AUDIT_POSTURE`] table. Adding a new CLI verb
//! (top-level or nested) without a corresponding entry fails the
//! test until the new verb is classified.
//!
//! Each subcommand is classified as one of:
//!
//! - [`AuditPosture::Emits`] — the command MUST emit ≥1 audit entry on
//!   success. The entry kind is named (`LocalAuditKind::*` or a
//!   `plan.*` chain event).
//! - [`AuditPosture::ReadOnly`] — the command only reads host state.
//!   No audit entry expected.
//! - [`AuditPosture::DelegatesToSub`] — the verb is a subcommand
//!   group; its inner table classifies the leaves. The walk
//!   descends recursively for each `DelegatesToSub`, so nested
//!   subgroups (e.g. `manifest tag add`) are covered to arbitrary
//!   depth without special-casing.
//! - [`AuditPosture::InteractiveOrControl`] — interactive PTY surface
//!   (`console`, `exec`, `dev`), shell/installer surfaces
//!   (`bootstrap`, `init`, `shell-init`), or pure control-plane
//!   commands (`mcp`) whose audit channel is the inner protocol.
//!
//! When a clap subcommand has its own subcommands but its posture
//! here is NOT `DelegatesToSub` (e.g. `audit` is `ReadOnly` even
//! though it has tail/verify/show leaves, all of which are read-
//! only), the walk doesn't drill — the operator-facing classification
//! is the unit. Promote to `DelegatesToSub(inner)` to enforce
//! per-leaf coverage there.

use std::collections::BTreeMap;

/// Audit classification for one CLI subcommand. See module docs for
/// the meaning of each variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditPosture {
    Emits(&'static str),
    ReadOnly,
    DelegatesToSub(&'static [(&'static str, AuditPosture)]),
    InteractiveOrControl,
}

// ──────────────────────────────────────────────────────────────────
// Per-subgroup leaf tables.
// ──────────────────────────────────────────────────────────────────

const MANIFEST_TAG: &[(&str, AuditPosture)] = &[
    ("add", AuditPosture::Emits("ManifestTagAdd")),
    ("rm", AuditPosture::Emits("ManifestTagRemove")),
    ("ls", AuditPosture::ReadOnly),
];

const MANIFEST_ALIAS: &[(&str, AuditPosture)] = &[
    ("set", AuditPosture::Emits("ManifestAliasSet")),
    ("rm", AuditPosture::Emits("ManifestAliasRemove")),
    ("ls", AuditPosture::ReadOnly),
];

const MANIFEST_SUB: &[(&str, AuditPosture)] = &[
    ("ls", AuditPosture::ReadOnly),
    ("info", AuditPosture::ReadOnly),
    ("rm", AuditPosture::Emits("SlotRemove")),
    ("prune", AuditPosture::Emits("SlotPrune")),
    ("verify", AuditPosture::ReadOnly),
    ("tag", AuditPosture::DelegatesToSub(MANIFEST_TAG)),
    ("alias", AuditPosture::DelegatesToSub(MANIFEST_ALIAS)),
    // `manifest export-oci` copies a slot's image.tar.gz onto the
    // host filesystem and emits `LocalAuditKind::ImageExportOci`.
    ("export-oci", AuditPosture::Emits("ImageExportOci")),
];

const STORAGE_SUB: &[(&str, AuditPosture)] = &[
    ("info", AuditPosture::ReadOnly),
    ("gc", AuditPosture::Emits("StorageGc")),
];

const SANDBOX_SUB: &[(&str, AuditPosture)] = &[("gc", AuditPosture::Emits("SandboxGc"))];

// Plan 178 (D5) — environment/install lifecycle grouped under `env <sub>`.
const ENV_SUB: &[(&str, AuditPosture)] = &[
    ("bootstrap", AuditPosture::InteractiveOrControl),
    ("cleanup", AuditPosture::Emits("SlotPrune")),
    ("uninstall", AuditPosture::Emits("Uninstall")),
    ("update", AuditPosture::Emits("UpdateInstall")),
    ("sign", AuditPosture::ReadOnly),
];

// Plan 178 — operational verbs grouped under `ops <sub>`. Postures unchanged.
const OPS_SUB: &[(&str, AuditPosture)] = &[
    ("metrics", AuditPosture::ReadOnly),
    ("bench", AuditPosture::DelegatesToSub(BENCH_SUB)),
    ("config", AuditPosture::Emits("ConfigChange")),
    ("mcp", AuditPosture::InteractiveOrControl),
];

// Plan 178 — the single-VM operational verbs grouped under `vm <sub>`. The
// audit postures are unchanged from when these were top-level (the CLI path
// moved, the audit taxonomy did not).
const VM_SUB: &[(&str, AuditPosture)] = &[
    ("pause", AuditPosture::Emits("VmStop")),
    ("resume", AuditPosture::Emits("VmStart")),
    ("snapshot", AuditPosture::DelegatesToSub(SNAPSHOT_SUB)),
    ("checkpoint", AuditPosture::DelegatesToSub(CHECKPOINT_SUB)),
    ("cp", AuditPosture::Emits("VmFileCopy")),
    ("fs", AuditPosture::Emits("VmFsMutate")),
    ("proc", AuditPosture::DelegatesToSub(PROC_SUB)),
    ("diff", AuditPosture::ReadOnly),
    ("wait", AuditPosture::ReadOnly),
    ("boot-report", AuditPosture::ReadOnly),
    ("set-ttl", AuditPosture::Emits("VmTtlSet")),
    ("forward", AuditPosture::ReadOnly),
    ("sandbox", AuditPosture::DelegatesToSub(SANDBOX_SUB)),
    ("session", AuditPosture::DelegatesToSub(SESSION_SUB)),
    ("volume", AuditPosture::DelegatesToSub(VOLUME_SUB)),
];

// `kernel build` compiles/downloads a microVM kernel into the local
// cache. Like `compile`, it produces build outputs but doesn't touch the
// security audit chain — the Stage-0 supply-chain events the compile arm
// may trigger are emitted by the shared bootstrap, same as `dev`.
const KERNEL_SUB: &[(&str, AuditPosture)] = &[("build", AuditPosture::ReadOnly)];

// Plan 178 (D1) — build-time verbs grouped under `build <sub>`. `build image`
// is the former top-level `build`. Postures unchanged.
const BUILD_SUB: &[(&str, AuditPosture)] = &[
    ("image", AuditPosture::Emits("TemplateBuild")),
    ("compile", AuditPosture::ReadOnly),
    ("validate", AuditPosture::ReadOnly),
    ("kernel", AuditPosture::DelegatesToSub(KERNEL_SUB)),
];

// Plan 93 Phase 2 Lever 0 — `mvmctl bench microvm-launch`. The live
// probe boots a throwaway guest through the signed-plan admission path
// (claim 8), so the documented posture is the same `plan.*`+`VmStart`
// chain `up` emits. (The live boot wiring is a tracked follow-up; the
// measurement substrate ships first.)
const BENCH_SUB: &[(&str, AuditPosture)] = &[(
    "microvm-launch",
    AuditPosture::Emits("plan.admitted+plan.launched+VmStart"),
)];

const NETWORK_SUB: &[(&str, AuditPosture)] = &[
    ("create", AuditPosture::Emits("NetworkCreate")),
    ("list", AuditPosture::ReadOnly),
    ("inspect", AuditPosture::ReadOnly),
    ("remove", AuditPosture::Emits("NetworkRemove")),
];

const CACHE_SUB: &[(&str, AuditPosture)] = &[
    ("info", AuditPosture::ReadOnly),
    ("prune", AuditPosture::Emits("CachePrune")),
    // #640 — clears a degraded builder store; emits CachePrune on the real run
    // (op=builder_store_repair). A `--dry-run` is read-only, but the posture
    // tracks the acting path.
    ("repair", AuditPosture::Emits("CachePrune")),
];

// Plan 118 WS-1 1b — `mvmctl pool`.
const POOL_SUB: &[(&str, AuditPosture)] = &[
    ("warm", AuditPosture::Emits("PoolWarm")),
    ("status", AuditPosture::ReadOnly),
];

const CHECKPOINT_SUB: &[(&str, AuditPosture)] = &[
    ("create", AuditPosture::Emits("CheckpointCreated")),
    ("restore", AuditPosture::Emits("CheckpointRestored")),
    ("fork", AuditPosture::Emits("CheckpointForked")),
    ("diff", AuditPosture::ReadOnly),
    ("ls", AuditPosture::ReadOnly),
    ("rm", AuditPosture::ReadOnly),
];

const IMAGE_SUB: &[(&str, AuditPosture)] = &[
    ("pull", AuditPosture::Emits("ImageFetch")),
    ("ls", AuditPosture::ReadOnly),
    ("inspect", AuditPosture::ReadOnly),
    ("rm", AuditPosture::Emits("CachePrune")),
];

// Plan 200 — beginner machine UX. `machine run` translates into the same
// transient-runner path as top-level `run`, so it shares `run`'s
// `InteractiveOrControl` posture (it streams guest output; the admitted
// execution path emits via the inner plan/run protocol). The persistent-spec
// mutations use `ConfigChange` because they rewrite the operator's machine
// inventory; lifecycle wrappers delegate to existing interactive/control
// surfaces after first resolving the named machine.
const MACHINE_SUB: &[(&str, AuditPosture)] = &[
    ("run", AuditPosture::InteractiveOrControl),
    ("create", AuditPosture::Emits("ConfigChange")),
    ("ls", AuditPosture::ReadOnly),
    ("inspect", AuditPosture::ReadOnly),
    ("rm", AuditPosture::Emits("ConfigChange")),
    ("start", AuditPosture::InteractiveOrControl),
    ("exec", AuditPosture::InteractiveOrControl),
    ("shell", AuditPosture::InteractiveOrControl),
    ("stop", AuditPosture::InteractiveOrControl),
];

const VOLUME_SUB: &[(&str, AuditPosture)] = &[
    ("create", AuditPosture::Emits("VolumeCreate")),
    ("unlock", AuditPosture::Emits("VolumeOpen")),
    ("lock", AuditPosture::Emits("VolumeLock")),
    ("catalog", AuditPosture::ReadOnly),
    ("mount", AuditPosture::Emits("VmVolumeAdd")),
    ("ls", AuditPosture::ReadOnly),
    ("unmount", AuditPosture::Emits("VmVolumeRemove")),
];

const SECRET_SUB: &[(&str, AuditPosture)] = &[
    ("put", AuditPosture::Emits("SecretPut")),
    ("set", AuditPosture::Emits("SecretSet")),
    ("get", AuditPosture::Emits("SecretGet")),
    ("ls", AuditPosture::ReadOnly),
    ("rm", AuditPosture::Emits("SecretRm")),
];

const ATTEST_SUB: &[(&str, AuditPosture)] = &[
    ("export", AuditPosture::ReadOnly),
    ("verify", AuditPosture::ReadOnly),
    ("status", AuditPosture::ReadOnly),
];

const SESSION_SUB: &[(&str, AuditPosture)] = &[
    ("start", AuditPosture::Emits("SessionStart")),
    ("ls", AuditPosture::ReadOnly),
    ("info", AuditPosture::ReadOnly),
    ("attach", AuditPosture::InteractiveOrControl),
    ("exec", AuditPosture::InteractiveOrControl),
    ("run-code", AuditPosture::InteractiveOrControl),
    ("console", AuditPosture::InteractiveOrControl),
    ("kill", AuditPosture::Emits("Kill")),
    ("set-timeout", AuditPosture::Emits("VmTtlSet")),
    ("reap", AuditPosture::Emits("Kill")),
];

const PROC_SUB: &[(&str, AuditPosture)] = &[
    ("start", AuditPosture::Emits("VmProcStart")),
    ("ls", AuditPosture::ReadOnly),
    ("signal", AuditPosture::Emits("VmProcSignal")),
    ("kill", AuditPosture::Emits("Kill")),
    ("stdin", AuditPosture::Emits("VmProcStdin")),
    ("wait", AuditPosture::ReadOnly),
];

// `snapshot` now covers only the Firecracker instance-snapshot inventory verbs
// (`ls` / `rm`). The Vz machine-state save/restore verbs were retired in favor
// of `checkpoint --class vm-full` / `checkpoint restore`.
const SNAPSHOT_SUB: &[(&str, AuditPosture)] = &[
    ("ls", AuditPosture::ReadOnly),
    ("rm", AuditPosture::Emits("SnapshotDelete")),
];

// Plan 76 Phase 6 — `mvmctl artifact pack/verify`. Both are
// disk-side operations: pack writes a new `.mvm` file but does
// not touch host audit chain state; verify is a pure read. The
// host signer's keypair is consulted (read-only) for both.
const ARTIFACT_SUB: &[(&str, AuditPosture)] = &[
    ("pack", AuditPosture::ReadOnly),
    ("verify", AuditPosture::ReadOnly),
    // Plan 76 follow-up — read manifest without signature check.
    ("inspect", AuditPosture::ReadOnly),
    // Plan 134 — architecture-aware artifact-model commands. All static
    // (read manifest / validate / emit a Firecracker config / build an
    // artifact via the builder); none touch the host audit chain — like
    // `pack`/`verify` above, they only produce local artifacts.
    ("model-inspect", AuditPosture::ReadOnly),
    ("model-validate", AuditPosture::ReadOnly),
    ("model-config", AuditPosture::ReadOnly),
    ("model-build", AuditPosture::ReadOnly),
];

// Sprint 52 W2 — bundle / trust subcommand tables.
//
// `bundle export` writes a `.mvmpkg` archive to disk under the
// host's `--out` path; that's a local artifact, not host-side
// state that the audit chain tracks, so it shipped as
// `InteractiveOrControl` rather than `Emits` for now. Bumping it
// to a `BundleExport` emission is the natural follow-up when the
// host-side bundle registry lands.
//
// `bundle fetch` is verify-only in this commit (no extraction),
// so it's `ReadOnly`. When the registry-replacement flow lands
// and fetch starts mutating `~/.mvm/templates/<bundle-sha256>/`,
// this row flips to `Emits("BundleFetch")`.
//
// `trust` mutates `~/.mvm/trusted-publishers/`. add/remove emit
// audit entries (publisher trust is host-trust-boundary state);
// list is `ReadOnly`.
const BUNDLE_SUB: &[(&str, AuditPosture)] = &[
    ("export", AuditPosture::InteractiveOrControl),
    ("fetch", AuditPosture::ReadOnly),
    // `bundle install` mutates the local bundle registry under
    // `~/.mvm/bundles/<sha>/` and emits
    // `LocalAuditKind::BundleInstall` via `mvm_core::audit::emit`.
    ("install", AuditPosture::Emits("BundleInstall")),
    // `bundle gc` removes one (or all) installed bundles and emits
    // `LocalAuditKind::BundleGc` on the success arm.
    ("gc", AuditPosture::Emits("BundleGc")),
];

// trust add/remove mutate `~/.mvm/trusted-publishers/` and emit
// `LocalAuditKind::{TrustAdd, TrustRemove}` via
// `mvm_core::audit::emit`. Sprint 52 W2 phase-3 close-out
// promoted these from `InteractiveOrControl` to `Emits(...)`.
const TRUST_SUB: &[(&str, AuditPosture)] = &[
    ("add", AuditPosture::Emits("TrustAdd")),
    ("list", AuditPosture::ReadOnly),
    ("remove", AuditPosture::Emits("TrustRemove")),
    // Plan 178 — provenance verbs folded into `trust <sub>`.
    ("attest", AuditPosture::DelegatesToSub(ATTEST_SUB)),
    ("receipt", AuditPosture::ReadOnly),
    ("audit", AuditPosture::ReadOnly),
];

// Plan 73 Followup C — sealed deps-volume cache. `deps inspect` is
// read-only (pretty-prints meta.json + sidecars without mutating
// the volume). `deps audit` re-runs the CVE scan, rewrites
// `cve.json`, bumps `meta.json.last_audit_at`, and atomically
// renames the volume directory to its new sealed hash — every
// processed volume gets one `LocalAuditKind::DepsAudit` line.
const DEPS_SUB: &[(&str, AuditPosture)] = &[
    ("inspect", AuditPosture::ReadOnly),
    ("audit", AuditPosture::Emits("DepsAudit")),
];

/// Every top-level `mvmctl` subcommand keyed by its clap name.
///
/// Order matches the `Commands` enum in
/// `crates/mvm-cli/src/commands/mod.rs`. Adding a new command? Add
/// an entry here — the test below fails until you do.
const AUDIT_POSTURE: &[(&str, AuditPosture)] = &[
    // Environment / installer surfaces. Plan 178 (D5) — bootstrap/cleanup/
    // uninstall/update/sign grouped under `env <sub>`.
    ("env", AuditPosture::DelegatesToSub(ENV_SUB)),
    ("dev", AuditPosture::InteractiveOrControl),
    ("doctor", AuditPosture::ReadOnly),
    ("shell-init", AuditPosture::InteractiveOrControl),
    ("init", AuditPosture::InteractiveOrControl),
    // VM lifecycle.
    (
        "up",
        AuditPosture::Emits("plan.admitted+plan.launched+VmStart"),
    ),
    ("down", AuditPosture::Emits("VmStop")),
    ("logs", AuditPosture::ReadOnly),
    ("ls", AuditPosture::ReadOnly),
    ("console", AuditPosture::InteractiveOrControl),
    ("run", AuditPosture::InteractiveOrControl),
    ("invoke", AuditPosture::Emits("plan.admitted+plan.launched")),
    // Plan 178 — single-VM operational verbs grouped under `vm <sub>`.
    ("vm", AuditPosture::DelegatesToSub(VM_SUB)),
    // Build / artifact / registry. Plan 178 (D1) — image/compile/validate/
    // kernel grouped under `build <sub>`.
    ("build", AuditPosture::DelegatesToSub(BUILD_SUB)),
    ("manifest", AuditPosture::DelegatesToSub(MANIFEST_SUB)),
    ("storage", AuditPosture::DelegatesToSub(STORAGE_SUB)),
    ("persistent-builder", AuditPosture::InteractiveOrControl),
    // Plan 166 Phase 2 — hidden internal helper: a long-running host-side
    // AF_VSOCK<->UNIX bridge for the QEMU workload backend. Pure transport
    // plumbing spawned by `mvm_backend::qemu`; never emits audit events.
    ("__qemu-vsock-bridge", AuditPosture::InteractiveOrControl),
    ("__ssh-agent-proxy", AuditPosture::InteractiveOrControl),
    ("catalog", AuditPosture::ReadOnly),
    ("image", AuditPosture::DelegatesToSub(IMAGE_SUB)),
    // Plan 200 — beginner microVM workflows.
    ("machine", AuditPosture::DelegatesToSub(MACHINE_SUB)),
    // Operational surfaces.
    // Plan 178 — metrics/bench/config/mcp grouped under `ops <sub>`.
    ("ops", AuditPosture::DelegatesToSub(OPS_SUB)),
    ("network", AuditPosture::DelegatesToSub(NETWORK_SUB)),
    ("cache", AuditPosture::DelegatesToSub(CACHE_SUB)),
    ("pool", AuditPosture::DelegatesToSub(POOL_SUB)),
    // Plan 170 WS-A — reconcile-on-entry convergence. The non-dry-run
    // path emits one `RegistryReconcile` per healed drift item.
    ("reconcile", AuditPosture::Emits("RegistryReconcile")),
    ("secret", AuditPosture::DelegatesToSub(SECRET_SUB)),
    // Sprint 52 W2 — bundles + trust store.
    ("bundle", AuditPosture::DelegatesToSub(BUNDLE_SUB)),
    ("trust", AuditPosture::DelegatesToSub(TRUST_SUB)),
    // Plan 73 Followup C — sealed deps-volume cache verbs.
    ("deps", AuditPosture::DelegatesToSub(DEPS_SUB)),
    // Plan 76 Phase 6 — portable signed `.mvm` artifacts.
    ("artifact", AuditPosture::DelegatesToSub(ARTIFACT_SUB)),
];

// ──────────────────────────────────────────────────────────────────
// Recursive walk helpers.
// ──────────────────────────────────────────────────────────────────

/// Path through the subcommand tree, e.g. `["manifest", "tag", "add"]`.
type Path<'a> = Vec<&'a str>;

/// Render a path for error messages: `manifest tag add`.
fn path_str(path: &[&str]) -> String {
    path.join(" ")
}

/// Walk the (declared, clap) trees in lockstep. Reports every leaf
/// in clap that's missing from the declared table (`missing`) and
/// every entry in the declared table that's stale w.r.t. clap
/// (`stale`).
fn audit_walk(
    declared: &[(&'static str, AuditPosture)],
    clap_sub: &clap::Command,
    parent_path: &[&str],
    missing: &mut Vec<String>,
    stale: &mut Vec<String>,
) {
    let declared_map: BTreeMap<&'static str, AuditPosture> = declared.iter().copied().collect();
    let clap_names: Vec<String> = clap_sub
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    let clap_set: std::collections::BTreeSet<&str> =
        clap_names.iter().map(String::as_str).collect();

    // Missing-in-table: clap names not present in declared.
    for name in &clap_names {
        if !declared_map.contains_key(name.as_str()) {
            let mut p: Path = parent_path.to_vec();
            p.push(name.as_str());
            missing.push(path_str(&p));
        }
    }
    // Stale-in-table: declared names not present in clap.
    for name in declared_map.keys() {
        if !clap_set.contains(name) {
            let mut p: Path = parent_path.to_vec();
            p.push(name);
            stale.push(path_str(&p));
        }
    }

    // Recurse into DelegatesToSub entries whose clap subgroup
    // actually exists.
    for (name, posture) in declared {
        if let AuditPosture::DelegatesToSub(inner) = posture
            && let Some(sub_clap) = clap_sub.find_subcommand(name)
        {
            let mut child_path: Path = parent_path.to_vec();
            child_path.push(name);
            audit_walk(inner, sub_clap, &child_path, missing, stale);
        }
    }
}

#[test]
fn every_subcommand_at_every_level_has_audit_posture_declared() {
    let cmd = mvm_cli::commands::cli_command();
    let mut missing: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    audit_walk(AUDIT_POSTURE, &cmd, &[], &mut missing, &mut stale);

    assert!(
        missing.is_empty(),
        "{} CLI subcommand path(s) lack an audit-posture declaration \
         in tests/audit_total_coverage.rs: {:?}. Add an entry \
         (Emits | ReadOnly | DelegatesToSub | InteractiveOrControl) \
         before merging the new command.",
        missing.len(),
        missing
    );
    assert!(
        stale.is_empty(),
        "{} stale audit-posture entry/entries for subcommand path(s) \
         the clap tree no longer exposes: {:?}. Remove or rename to \
         match the current clap subcommand name(s).",
        stale.len(),
        stale
    );
}

/// Visit every `(path, posture)` pair in the declared tree.
fn for_each_posture(
    declared: &[(&'static str, AuditPosture)],
    parent_path: &[&str],
    visit: &mut impl FnMut(&[&str], AuditPosture),
) {
    for (name, posture) in declared {
        let mut p: Path = parent_path.to_vec();
        p.push(name);
        visit(&p, *posture);
        if let AuditPosture::DelegatesToSub(inner) = posture {
            for_each_posture(inner, &p, visit);
        }
    }
}

#[test]
fn audit_posture_table_has_no_duplicate_subcommand_names_at_any_level() {
    // No duplicate name within a single (sub)group. A duplicate
    // across different parents is fine (e.g. `manifest ls` and
    // `network list` aren't the same).
    fn check(group: &[(&'static str, AuditPosture)], parent_path: &[&str]) {
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for (name, _) in group {
            assert!(
                seen.insert(*name),
                "duplicate AUDIT_POSTURE entry for subcommand {:?} \
                 inside parent path {:?}",
                name,
                path_str(parent_path)
            );
        }
        for (name, posture) in group {
            if let AuditPosture::DelegatesToSub(inner) = posture {
                let mut child: Path = parent_path.to_vec();
                child.push(name);
                check(inner, &child);
            }
        }
    }
    check(AUDIT_POSTURE, &[]);
}

#[test]
fn audit_posture_emits_entries_reference_known_audit_kinds() {
    // Best-effort lint: every `Emits(spec)` value should mention at
    // least one token that maps to a real audit category — either a
    // `LocalAuditKind` variant name (CamelCase) or a `plan.*` chain
    // event. This catches typos like `Emits("VmStrt")` without
    // needing reflection into the LocalAuditKind enum.
    //
    // The check uses a static allowlist; expanding the allowlist is
    // a deliberate change tied to the actual audit-emission code.
    const KNOWN_TOKENS: &[&str] = &[
        // LocalAuditKind variants the Emits rows reference. Keep
        // alphabetised within sections so a new audit kind's
        // addition is one obvious line.
        // Top-level + per-subgroup mutation kinds:
        "CachePrune",
        "ConfigChange",
        "DepsAudit",
        "Kill",
        "ManifestAliasRemove",
        "ManifestAliasSet",
        "ManifestTagAdd",
        "ManifestTagRemove",
        "CheckpointCreated",
        "CheckpointForked",
        "CheckpointRestored",
        "NetworkCreate",
        "NetworkRemove",
        "PoolWarm",
        "RegistryReconcile",
        "SecretGet",
        "SecretPut",
        "SecretRm",
        "SecretSet",
        "SandboxGc",
        "SessionStart",
        "SlotPrune",
        "SlotRemove",
        "SnapshotDelete",
        "StorageGc",
        "TemplateBuild",
        "Uninstall",
        "UpdateInstall",
        "VolumeCreate",
        "VolumeLock",
        "VolumeOpen",
        "VmFileCopy",
        "VmFsMutate",
        "VmProcSignal",
        "VmProcStart",
        "VmProcStdin",
        "BundleGc",
        "BundleInstall",
        "ImageExportOci",
        "ImageFetch",
        "TrustAdd",
        "TrustRemove",
        "VmStart",
        "VmStop",
        "VmTtlSet",
        "VmVolumeAdd",
        "VmVolumeRemove",
        // Plan-64 audit-chain events.
        "plan.admitted",
        "plan.launched",
    ];

    let mut failures: Vec<(String, &'static str)> = Vec::new();
    for_each_posture(AUDIT_POSTURE, &[], &mut |path, posture| {
        if let AuditPosture::Emits(spec) = posture {
            let hit = KNOWN_TOKENS.iter().any(|tok| spec.contains(tok));
            if !hit {
                failures.push((path_str(path), spec));
            }
        }
    });
    assert!(
        failures.is_empty(),
        "{} Emits row(s) name no known audit token — typo, or the \
         allowlist in audit_posture_emits_entries_reference_known_audit_kinds \
         needs the new token added alongside the new LocalAuditKind variant. \
         Offenders: {:?}",
        failures.len(),
        failures
    );
}

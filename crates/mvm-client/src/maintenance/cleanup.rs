//! `mvmctl cleanup` — remove old build artifacts (in-VM) and optionally
//! wipe host-side cache / state directories (`--cache` / `--state` /
//! `--nuclear`).
//!
//! Without any tier flag the command is the same lightweight in-VM
//! cleanup it has always been (clears the dev VM's `/tmp`, prunes
//! `~/.mvm/dev/builds/`, runs `nix-collect-garbage -d`). The tier
//! flags add host-side directory sweeps that run after the in-VM
//! step and are gated by a confirmation prompt.
//!
//! `--cache` and `--state` are selective, so they name the paths they
//! take. `--nuclear` is the opposite: it enumerates the mvm root and
//! removes every entry it finds, minus whatever `--keep-identity`
//! spares. Defining "everything" by subtraction is the point — the
//! allow-list this replaced spared any directory nobody remembered to
//! add to it, which had grown to most of the tree (`images`,
//! `machines`, `checkpoints`, `snapshots`, `instances`, `pool`,
//! `state`, `share`, `bin`, ...).
//!
//! Safety:
//! - Tier flags refuse to run if any VM is currently running, unless
//!   `--force` is set. Wiping `~/.mvm/vms/<id>/` or
//!   `~/.mvm/cache/builder-vm/vms/<id>/` while a supervisor is reading
//!   the state dir corrupts the running guest. Liveness goes through
//!   the shared `state_dir_has_live_process` probe so every backend's
//!   PID marker counts, not just libkrun's.
//! - `--nuclear` always requires an interactive text confirmation
//!   (`DELETE-EVERYTHING`). `--yes` does not bypass it.

use anyhow::{Result, anyhow};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use mvm_runtime::shell;
use mvm_vmm::host::process_liveness::state_dir_has_live_process;

/// Explicit authorization is required even for the in-VM step.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Intent {
    #[default]
    Preview,
    Apply,
    /// Acknowledges destruction of all non-retained entries under the configured home.
    DeleteEverything,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Cache,
    State,
    Nuclear,
}

impl Tier {
    pub fn name(self) -> &'static str {
        match self {
            Tier::Cache => "cache",
            Tier::State => "state",
            Tier::Nuclear => "nuclear",
        }
    }
}

/// Whether a nuclear sweep spares the host's cryptographic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// Delete identity material along with everything else.
    Wipe,
    /// Preserve [`IDENTITY_PATHS`] so past audit logs stay verifiable
    /// and stored secrets stay decryptable.
    Keep,
}

impl Identity {
    pub fn from_flag(keep: bool) -> Self {
        if keep { Identity::Keep } else { Identity::Wipe }
    }

    /// Entry names a sweep must skip under this setting.
    fn spared(self) -> &'static [&'static str] {
        match self {
            Identity::Wipe => &[],
            Identity::Keep => IDENTITY_PATHS,
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Identity::Wipe => "",
            Identity::Keep => " (identity preserved)",
        }
    }
}

/// Entries directly under the mvm root that `--keep-identity` spares.
///
/// Everything here is either a private key, material encrypted under
/// one, the audit chain those keys sign, or the hand-written
/// `config.toml` — the paths a rebuild cannot reproduce. They travel
/// together because sparing one without the others is useless:
/// dropping `keys` makes every past audit entry unverifiable, and
/// dropping `.secret-store.key` leaves `secrets` an undecryptable
/// blob. Everything else under the root is rebuildable, refetchable,
/// or regenerated on next use.
const IDENTITY_PATHS: &[&str] = &[
    "keys",
    "audit",
    "attestation",
    "secrets",
    "secret-bindings",
    "egress-ca",
    ".secret-store.key",
    "snapshot.key",
    "config.toml",
];

/// Build retention for the legacy in-VM cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    All,
    Newest(std::num::NonZeroUsize),
}

impl Default for Retention {
    fn default() -> Self {
        Self::Newest(std::num::NonZeroUsize::new(5).expect("five is nonzero"))
    }
}

impl Retention {
    pub fn count(self) -> usize {
        match self {
            Self::All => 0,
            Self::Newest(count) => count.get(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub retention: Retention,
    pub tier: Option<Tier>,
    pub identity: Identity,
    pub force: bool,
    pub intent: Intent,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            retention: Retention::default(),
            tier: None,
            identity: Identity::Wipe,
            force: false,
            intent: Intent::Preview,
        }
    }
}

/// An observation for rendering, never a policy or confirmation callback.
#[derive(Debug)]
pub enum Event {
    DiskBefore(u8),
    ClearingTemporaryFiles,
    BuildsRemoved {
        paths: Vec<String>,
        count: usize,
        retention: Retention,
    },
    GarbageCollectionSkipped,
    GarbageCollectionStarted,
    GarbageCollectionOutput(String),
    GarbageCollectionFailed(String),
    GarbageCollectionRetry,
    GarbageCollectionRetryFailed(String),
    DiskAfter {
        before: Option<u8>,
        after: u8,
    },
}

/// Opaque, configured-home plan. Its paths cannot be supplied or edited by callers.
#[derive(Debug)]
pub struct Prepared {
    request: Request,
    root: PathBuf,
    plan: CleanupPlan,
    identities: Vec<Option<FileIdentity>>,
    root_identity: Option<FileIdentity>,
}

impl Prepared {
    pub fn paths(&self) -> impl Iterator<Item = (&Path, u64)> {
        self.plan.paths.iter().map(|p| (p.as_path(), dir_size(p)))
    }

    pub fn is_empty(&self) -> bool {
        self.plan.paths.is_empty()
    }
}

/// Preview is side-effect free. Apply explicitly runs the legacy in-VM step,
/// even when the caller subsequently previews or declines the host sweep.
/// No whole-store lock exists: launch does not participate in cleanup locking.
/// The liveness probe is a best-effort guard, not exclusion; force bypasses it.
pub fn prepare(request: Request, mut observe: impl FnMut(Event)) -> Result<Prepared> {
    let root = PathBuf::from(mvm_core::config::mvm_home());
    prepare_with(request, root, &mut observe, run_vm_cleanup)
}

fn prepare_with(
    request: Request,
    root: PathBuf,
    observe: &mut impl FnMut(Event),
    run_vm: impl FnOnce(Retention, &mut dyn FnMut(Event)) -> Result<()>,
) -> Result<Prepared> {
    if request.identity == Identity::Keep && request.tier != Some(Tier::Nuclear) {
        anyhow::bail!("identity retention requires the nuclear tier");
    }
    check_running(&request, &mvm_core::config::vms_dir_at(&root))?;
    if request.intent != Intent::Preview {
        run_vm(request.retention, observe)?;
    }
    let plan = request.tier.map_or_else(CleanupPlan::default, |tier| {
        build_plan_at(&root, &root.join("cache"), tier, request.identity)
    });
    let identities = plan
        .paths
        .iter()
        .map(|p| file_identity(p))
        .collect::<Result<_>>()?;
    let root_identity = file_identity(&root)?;
    Ok(Prepared {
        request,
        root,
        plan,
        identities,
        root_identity,
    })
}

fn check_running(request: &Request, vms: &Path) -> Result<()> {
    if let Some(t) = request.tier
        && !request.force
        && let Some(running) = first_running_vm_at(vms)
    {
        anyhow::bail!(
            "refusing to run cleanup --{} while VM '{}' appears to be running.\n\
             Stop it first (`mvmctl machine stop {}`), or pass --force to wipe anyway.",
            t.name(),
            running,
            running,
        );
    }
    Ok(())
}

/// Apply only the exact preview, rechecking liveness and entry identities.
/// This detects replaced records, not mutations within a directory or a VM
/// starting after the probe. It is not whole-store deletion safety.
pub fn apply(prepared: Prepared, intent: Intent) -> Result<ExecutionReport> {
    if prepared.root != mvm_core::config::mvm_home() {
        anyhow::bail!("configured mvm home changed since cleanup preview");
    }
    let tier = prepared.request.tier;
    let report = apply_at(prepared, intent)?;
    if intent != Intent::Preview
        && let Some(tier) = tier
    {
        let tier_name = tier.name();
        let bytes = report.bytes_freed;
        let count = report.paths_removed;
        mvm_core::audit_emit!(
            Cleanup,
            "tier={tier_name} paths_removed={count} bytes_freed={bytes}"
        );
    }
    Ok(report)
}

fn apply_at(prepared: Prepared, intent: Intent) -> Result<ExecutionReport> {
    match intent {
        Intent::Preview => return Ok(ExecutionReport::default()),
        Intent::Apply if prepared.request.tier == Some(Tier::Nuclear) => {
            anyhow::bail!("nuclear cleanup requires DeleteEverything intent");
        }
        Intent::Apply | Intent::DeleteEverything => {}
    }
    check_running(
        &prepared.request,
        &mvm_core::config::vms_dir_at(&prepared.root),
    )?;
    if file_identity(&prepared.root)? != prepared.root_identity {
        anyhow::bail!("cleanup root changed since preview; prepare again");
    }
    for (path, identity) in prepared.plan.paths.iter().zip(&prepared.identities) {
        if &file_identity(path)? != identity {
            anyhow::bail!(
                "cleanup entry changed since preview: {}; prepare again",
                path.display()
            );
        }
    }
    execute_plan(&prepared.plan)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn file_identity(path: &Path) -> Result<Option<FileIdentity>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow!("inspecting {}: {error}", path.display())),
    }
}

trait VmOperations {
    fn disk_usage(&mut self) -> Option<u8>;
    fn run(&mut self, command: &str) -> Result<()>;
    fn stdout(&mut self, command: &str) -> Result<String>;
    fn prune(&mut self, keep: usize) -> Result<(usize, Vec<String>)>;
}

struct HostVm;

impl VmOperations for HostVm {
    fn disk_usage(&mut self) -> Option<u8> {
        vm_disk_usage_pct()
    }
    fn run(&mut self, command: &str) -> Result<()> {
        shell::run_in_vm(command).map(|_| ())
    }
    fn stdout(&mut self, command: &str) -> Result<String> {
        shell::run_in_vm_stdout(command)
    }
    fn prune(&mut self, keep: usize) -> Result<(usize, Vec<String>)> {
        let report = mvm_build::dev_build::cleanup_old_dev_builds(keep)?;
        Ok((report.removed_count, report.removed_paths))
    }
}

fn run_vm_cleanup(retention: Retention, observe: &mut dyn FnMut(Event)) -> Result<()> {
    let removed = run_vm_cleanup_with(&mut HostVm, retention, observe)?;
    mvm_core::audit_emit!(SlotPrune, "source=cleanup removed={removed}");
    Ok(())
}

fn run_vm_cleanup_with(
    vm: &mut impl VmOperations,
    retention: Retention,
    observe: &mut dyn FnMut(Event),
) -> Result<usize> {
    let before = vm.disk_usage();
    if let Some(pct) = before {
        observe(Event::DiskBefore(pct));
    }
    observe(Event::ClearingTemporaryFiles);
    let _ = vm.run("sudo rm -rf /tmp/* /var/tmp/* 2>/dev/null");
    let (count, paths) = vm.prune(retention.count())?;
    observe(Event::BuildsRemoved {
        paths,
        count,
        retention,
    });
    if before.is_none() {
        observe(Event::GarbageCollectionSkipped);
    } else {
        observe(Event::GarbageCollectionStarted);
        match vm.stdout("nix-collect-garbage -d 2>&1 | tail -3") {
            Ok(output) => observe(Event::GarbageCollectionOutput(output)),
            Err(error) => {
                observe(Event::GarbageCollectionFailed(error.to_string()));
                observe(Event::GarbageCollectionRetry);
                let _ = vm.run("rm -rf ~/.local/state/nix/profiles/* 2>/dev/null");
                match vm.stdout("nix-collect-garbage -d 2>&1 | tail -3") {
                    Ok(output) => observe(Event::GarbageCollectionOutput(output)),
                    Err(error) => observe(Event::GarbageCollectionRetryFailed(error.to_string())),
                }
            }
        }
    }
    if let Some(after) = vm.disk_usage() {
        observe(Event::DiskAfter { before, after });
    }
    Ok(count)
}

/// Returns the name of the first VM that appears to be running, or
/// None if none are. Errors during the probe are conservative: a
/// failed readdir returns None (the check is a guardrail, not a
/// guarantee).
/// `first_running_vm` against an explicit VM state root, so tests can
/// point it at a tempdir.
///
/// Liveness goes through the shared [`state_dir_has_live_process`]
/// probe rather than a local `libkrun.pid` read. That probe knows all
/// five supervisor PID markers; a `libkrun.pid`-only check reports a
/// running HVF, Firecracker or QEMU guest as stopped, and HVF is the
/// auto-detect default on macOS 26+. It also treats a zombie as dead,
/// which a bare `kill(pid, 0)` does not.
fn first_running_vm_at(vms_root: &Path) -> Option<String> {
    running_vms_at(vms_root).into_iter().next()
}

/// Every VM under `vms_root` whose state directory has a live supervisor,
/// sorted by name. Shares [`first_running_vm_at`]'s probe, so a caller that
/// must list every running machine cannot disagree with the cleanup guard
/// about which ones are running.
pub fn running_vms_at(vms_root: &Path) -> Vec<String> {
    running_vms_at_with(vms_root, state_dir_has_live_process)
}

fn running_vms_at_with(
    vms_root: &Path,
    mut has_live_process: impl FnMut(&Path) -> bool,
) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(vms_root) else {
        return Vec::new();
    };
    let mut running: Vec<String> = entries
        .flatten()
        .filter(|entry| has_live_process(&entry.path()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    running.sort();
    running
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CleanupPlan {
    paths: Vec<PathBuf>,
}

/// Build the set of paths a tier sweep would remove, anchored at the
/// supplied data + cache roots. Tests pass tempdirs; production passes
/// `mvm_home()` / `mvm_cache_dir()`. A path is only added if it
/// currently exists on disk — the plan IS the actual delete list, not
/// a hypothetical superset.
fn build_plan_at(
    data_root: &Path,
    cache_root: &Path,
    tier: Tier,
    identity: Identity,
) -> CleanupPlan {
    if tier == Tier::Nuclear {
        // No `cache_root`: `mvm_cache_dir()` is unconditionally
        // `<mvm_home>/cache`, so the root walk already covers it.
        return nuclear_plan(data_root, identity);
    }
    selective_plan(data_root, cache_root, tier)
}

/// The `--cache` / `--state` plan: enumerate the regenerable subdirs
/// those tiers are defined to take. Enumerating is correct here —
/// these tiers are selective by intent, so a directory that isn't
/// named is one they are supposed to leave alone.
fn selective_plan(data_root: &Path, cache_root: &Path, tier: Tier) -> CleanupPlan {
    let mut paths = Vec::new();
    if cache_root.exists() {
        paths.push(cache_root.to_path_buf());
    }
    if tier == Tier::State {
        for sub in &[
            "dev",
            "vms",
            "log",
            "dev-cluster",
            "mock-vms",
            "tool-staging",
        ] {
            let p = data_root.join(sub);
            if p.exists() {
                paths.push(p);
            }
        }
    }
    CleanupPlan { paths }
}

/// The `--nuclear` plan: every entry under the mvm root, minus the
/// identity material `--keep-identity` spares. The root directory
/// itself survives so its 0700 mode cannot be re-established wrong by
/// whichever command next writes under it. That used to name a helper
/// which nothing called, so the re-establishment it described never
/// happened; `mvm_core::config::create_private_dir` is what performs it
/// now, on the whole chain, from any writer.
///
/// This is deliberately defined by subtraction. The enumerated version
/// it replaced named thirteen paths and therefore spared every state
/// directory added after it was written — by then `images`,
/// `machines`, `checkpoints`, `snapshots`, `instances`, `pool`,
/// `state`, `share`, `bin`, `host-agent`, `observers` and `run`, or
/// most of the tree by size. A subsystem that adds a directory is now
/// covered the day it lands, with no list to remember.
fn nuclear_plan(data_root: &Path, identity: Identity) -> CleanupPlan {
    let spared = identity.spared();
    let mut paths: Vec<PathBuf> = match std::fs::read_dir(data_root) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| !spared.iter().any(|s| OsStr::new(s) == e.file_name()))
            .map(|e| e.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    // readdir order is unspecified; sort so the preview the user
    // confirms lists the same paths in the same order every run.
    paths.sort();
    CleanupPlan { paths }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExecutionReport {
    pub paths_removed: usize,
    pub bytes_freed: u64,
}

fn execute_plan(plan: &CleanupPlan) -> Result<ExecutionReport> {
    let mut report = ExecutionReport::default();
    for path in &plan.paths {
        let size = dir_size(path);
        if path.is_symlink() {
            std::fs::remove_file(path).map_err(|e| anyhow!("removing {}: {e}", path.display()))?;
        } else if path.is_dir() {
            std::fs::remove_dir_all(path)
                .map_err(|e| anyhow!("removing {}: {e}", path.display()))?;
        } else if path.exists() {
            std::fs::remove_file(path).map_err(|e| anyhow!("removing {}: {e}", path.display()))?;
        }
        report.paths_removed += 1;
        report.bytes_freed += size;
    }
    Ok(report)
}

/// Disk a delete of `path` would return. Shared with `cache prune` so the two
/// verbs never quote different numbers for the same tree.
fn dir_size(path: &Path) -> u64 {
    mvm_core::disk_usage::tree_bytes(path)
}

/// Read the dev VM root filesystem usage percentage.
fn vm_disk_usage_pct() -> Option<u8> {
    let output = shell::run_in_vm_stdout("df --output=pcent / 2>/dev/null | tail -1").ok()?;
    output.trim().trim_end_matches('%').trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn touch(p: &Path, bytes: usize) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, vec![b'x'; bytes]).unwrap();
    }

    fn populate(root: &Path) {
        touch(&root.join("keys/host-signer.ed25519"), 32);
        touch(&root.join("keys/host-signer.pub"), 32);
        touch(&root.join("audit/local.jsonl"), 4096);
        touch(&root.join("volumes/registry.json"), 64);
        touch(&root.join("secrets/master"), 128);
        touch(&root.join("templates/foo/artifacts/r1/build"), 2048);
        touch(&root.join("dev/builds/abc"), 1024);
        touch(&root.join("vms/dev/libkrun.pid"), 6);
        touch(&root.join("log/launch.log"), 512);
        touch(&root.join("dev-cluster/state"), 100);
        touch(&root.join("mock-vms/.keep"), 1);
        touch(&root.join("tool-staging/scratch"), 50);
        touch(&root.join("config.toml"), 80);
        // Directories that postdate the enumerated nuclear plan. On a
        // real host these are the bulk of the tree, and the allow-list
        // spared every one of them.
        touch(&root.join("images/sha256-abc/rootfs.ext4"), 8192);
        touch(&root.join("machines/web/machine.json"), 256);
        touch(&root.join("checkpoints/web/mem.snap"), 4096);
        touch(&root.join("snapshots/web/state.bin"), 2048);
        touch(&root.join("instances/one/meta.json"), 64);
        touch(&root.join("pool/standby/a"), 32);
        touch(&root.join("state/inventory.json"), 128);
        touch(&root.join("share/dev/socket"), 16);
        touch(&root.join("bin/mvm-libkrun-supervisor"), 1024);
        touch(&root.join("host-agent/local/agent.sock"), 8);
        touch(&root.join("observers/one.json"), 24);
        touch(&root.join("attestation/identity.ed25519"), 32);
        touch(&root.join("egress-ca/ca.key"), 32);
        touch(&root.join("secret-bindings/one.json"), 48);
        touch(&root.join(".secret-store.key"), 32);
        touch(&root.join("snapshot.key"), 32);
    }

    /// Entry names directly under `root`, for asserting plan contents.
    fn plan_names(plan: &CleanupPlan, root: &Path) -> Vec<PathBuf> {
        plan.paths
            .iter()
            .map(|p| p.strip_prefix(root).unwrap_or(p).to_path_buf())
            .collect()
    }

    fn populate_cache(root: &Path) {
        touch(&root.join("builder-vm/nix-store-aarch64.img"), 16384);
        touch(&root.join("stage0/nix-seed-aarch64.tar.xz"), 4096);
    }

    #[test]
    fn tier_cache_only_targets_cache_root() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Cache, Identity::Wipe);
        assert_eq!(plan.paths, vec![cache.path().to_path_buf()]);
    }

    #[test]
    fn tier_state_adds_regenerable_subdirs_preserves_identity_and_templates() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::State, Identity::Wipe);
        let names: Vec<_> = plan
            .paths
            .iter()
            .map(|p| p.strip_prefix(data.path()).unwrap_or(p).to_path_buf())
            .collect();
        assert!(plan.paths[0].starts_with(cache.path()));
        for sub in &[
            "dev",
            "vms",
            "log",
            "dev-cluster",
            "mock-vms",
            "tool-staging",
        ] {
            assert!(
                names.iter().any(|p| p == Path::new(sub)),
                "expected `{sub}` in state plan: {names:?}",
            );
        }
        for sub in &["keys", "audit", "volumes", "secrets", "templates"] {
            assert!(
                !names.iter().any(|p| p == Path::new(sub)),
                "state tier must not include `{sub}` (identity/template path)",
            );
        }
        assert!(
            !names.iter().any(|p| p == Path::new("config.toml")),
            "state tier must not include config.toml",
        );
    }

    #[test]
    fn tier_nuclear_takes_every_entry_under_the_root() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let names = plan_names(&plan, data.path());

        let mut on_disk: Vec<PathBuf> = std::fs::read_dir(data.path())
            .unwrap()
            .flatten()
            .map(|e| PathBuf::from(e.file_name()))
            .collect();
        on_disk.sort();
        let mut got = names.clone();
        got.sort();
        assert_eq!(got, on_disk, "nuclear must take every root entry");
    }

    /// The regression that motivated replacing the enumerated plan: a
    /// directory no list knows about must still be swept. This is the
    /// assertion the allow-list version cannot pass at any length,
    /// because the failure mode was always the next unlisted name.
    #[test]
    fn tier_nuclear_covers_a_directory_no_list_knows_about() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        touch(&data.path().join("some-future-subsystem/state.db"), 512);

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let names = plan_names(&plan, data.path());
        assert!(
            names
                .iter()
                .any(|p| p == Path::new("some-future-subsystem")),
            "nuclear plan missing the unlisted dir: {names:?}",
        );
    }

    #[test]
    fn tier_nuclear_keep_identity_spares_exactly_the_identity_paths() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Keep);
        let names = plan_names(&plan, data.path());

        for sub in IDENTITY_PATHS {
            assert!(
                !names.iter().any(|p| p == Path::new(sub)),
                "--keep-identity must spare `{sub}`: {names:?}",
            );
        }
        // Everything else still goes — sparing identity is not sparing
        // the workload state that makes nuclear worth running.
        for sub in &["images", "checkpoints", "snapshots", "templates", "dev"] {
            assert!(
                names.iter().any(|p| p == Path::new(sub)),
                "--keep-identity must still take `{sub}`: {names:?}",
            );
        }
    }

    #[test]
    fn tier_nuclear_empties_the_root_but_leaves_it_in_place() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        execute_plan(&plan).unwrap();

        assert!(data.path().is_dir(), "the mvm root itself must survive");
        assert_eq!(
            std::fs::read_dir(data.path()).unwrap().count(),
            0,
            "the mvm root must be empty",
        );
    }

    /// `mvm_cache_dir()` is always `<mvm_home>/cache`, so nuclear picks
    /// the cache up from the root walk and lists it exactly once.
    #[test]
    fn tier_nuclear_lists_the_in_root_cache_exactly_once() {
        let data = tempdir().unwrap();
        let cache = data.path().join("cache");
        populate(data.path());
        populate_cache(&cache);

        let plan = build_plan_at(data.path(), &cache, Tier::Nuclear, Identity::Wipe);
        let hits = plan.paths.iter().filter(|p| **p == cache).count();
        assert_eq!(
            hits, 1,
            "in-root cache listed {hits} times: {:?}",
            plan.paths
        );
    }

    #[test]
    fn plan_skips_paths_that_dont_exist() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        touch(&data.path().join("keys/host-signer.ed25519"), 32);
        touch(&data.path().join("dev/builds/x"), 8);

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let names: Vec<_> = plan
            .paths
            .iter()
            .map(|p| p.strip_prefix(data.path()).unwrap_or(p).to_path_buf())
            .collect();
        assert!(names.iter().any(|p| p == Path::new("dev")));
        assert!(names.iter().any(|p| p == Path::new("keys")));
        for sub in &["audit", "secrets", "templates", "vms", "config.toml"] {
            assert!(
                !names.iter().any(|p| p == Path::new(sub)),
                "missing `{sub}` should not be in plan",
            );
        }
    }

    #[test]
    fn execute_plan_removes_paths_and_reports_bytes() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let total_in_plan: u64 = plan.paths.iter().map(|p| dir_size(p)).sum();
        let report = execute_plan(&plan).unwrap();

        assert_eq!(report.paths_removed, plan.paths.len());
        assert_eq!(report.bytes_freed, total_in_plan);
        for p in &plan.paths {
            assert!(!p.exists(), "{} should be removed", p.display());
        }
    }

    /// The estimate must cover every file in the tree. It measures allocated
    /// blocks rather than apparent length, so the floor is the payload.
    #[test]
    fn dir_size_sums_recursive_file_bytes() {
        let dir = tempdir().unwrap();
        touch(&dir.path().join("a/b/c.bin"), 100);
        touch(&dir.path().join("a/d.bin"), 50);
        touch(&dir.path().join("e.bin"), 25);
        assert!(dir_size(dir.path()) >= 175, "{}", dir_size(dir.path()));
    }

    #[test]
    fn dir_size_handles_single_file() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("just-one.bin");
        touch(&f, 42);
        assert!(dir_size(&f) >= 42, "{}", dir_size(&f));
    }

    /// A `cleanup` estimate is quoted to an operator deciding whether to run
    /// it, so it must not promise disk that a delete cannot return. A tree of
    /// links to one payload frees the payload once.
    #[cfg(unix)]
    #[test]
    fn dir_size_is_not_inflated_by_links_to_one_payload() {
        let dir = tempdir().unwrap();
        let payload = dir.path().join("payload.bin");
        touch(&payload, 128 * 1024);
        let baseline = dir_size(dir.path());

        std::os::unix::fs::symlink(&payload, dir.path().join("soft")).unwrap();
        std::fs::hard_link(&payload, dir.path().join("hard")).unwrap();

        let with_links = dir_size(dir.path());
        assert!(
            with_links < baseline + 128 * 1024,
            "links must not multiply the estimate: {baseline} became {with_links}"
        );
    }

    /// HVF is the auto-detect default on macOS 26+, and its supervisor
    /// writes `hvf.pid`. A guard that only reads `libkrun.pid` waves
    /// the sweep through while that guest is running.
    #[test]
    fn running_vm_guard_sees_a_non_libkrun_backend() {
        for marker in &["hvf.pid", "fc.pid", "qemu.pid", "pid"] {
            let vms = tempdir().unwrap();
            let dir = vms.path().join("web");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(marker), std::process::id().to_string()).unwrap();
            assert_eq!(
                first_running_vm_at(vms.path()).as_deref(),
                Some("web"),
                "`{marker}` must read as running",
            );
        }
    }

    #[test]
    fn running_vm_guard_ignores_a_dead_pid() {
        let vms = tempdir().unwrap();
        let dir = vms.path().join("web");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("libkrun.pid"), "42").unwrap();
        // The same valid marker must be kept when observed live and excluded
        // when observed dead, without racing host PID reuse.
        for alive in [true, false] {
            let mut observed = Vec::new();
            let running = running_vms_at_with(vms.path(), |path| {
                assert_eq!(path, dir);
                assert_eq!(
                    mvm_vmm::host::process_liveness::read_pid_file(&path.join("libkrun.pid")),
                    Some(42)
                );
                observed.push(path.to_path_buf());
                alive
            });
            assert_eq!(observed, vec![dir.clone()]);
            assert_eq!(running.into_iter().next(), alive.then(|| "web".to_string()));
        }
    }

    #[test]
    fn running_vms_lists_every_live_machine_in_name_order() {
        let vms = tempdir().unwrap();
        for (name, pid) in [
            ("web", std::process::id()),
            ("api", std::process::id()),
            ("stopped", 42),
        ] {
            let dir = vms.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("hvf.pid"), pid.to_string()).unwrap();
        }
        let mut observed = Vec::new();
        let running = running_vms_at_with(vms.path(), |path| {
            observed.push(path.file_name().unwrap().to_string_lossy().into_owned());
            if path.file_name().unwrap() == "stopped" {
                assert_eq!(
                    mvm_vmm::host::process_liveness::read_pid_file(&path.join("hvf.pid")),
                    Some(42)
                );
                false
            } else {
                state_dir_has_live_process(path)
            }
        });
        observed.sort();
        assert_eq!(observed, vec!["api", "stopped", "web"]);
        assert_eq!(running, vec!["api", "web"]);
        // The real probe still drives the public list and guard. Remove the
        // synthetic stopped marker before asking the operating system.
        std::fs::remove_file(vms.path().join("stopped/hvf.pid")).unwrap();
        assert_eq!(running_vms_at(vms.path()), vec!["api", "web"]);
        assert_eq!(first_running_vm_at(vms.path()).as_deref(), Some("api"));
    }

    #[test]
    fn running_vm_guard_returns_none_on_an_empty_root() {
        let vms = tempdir().unwrap();
        assert_eq!(first_running_vm_at(vms.path()), None);
        assert_eq!(first_running_vm_at(&vms.path().join("nope")), None);
    }

    fn preview(root: &Path, tier: Tier, identity: Identity) -> Prepared {
        prepare_with(
            Request {
                tier: Some(tier),
                identity,
                ..Request::default()
            },
            root.to_path_buf(),
            &mut |_| panic!("preview must not emit VM events"),
            |_, _| panic!("preview must not perform VM operations"),
        )
        .unwrap()
    }

    #[test]
    fn default_intent_is_preview_and_requires_explicit_apply() {
        assert_eq!(Intent::default(), Intent::Preview);
        assert_eq!(Request::default().intent, Intent::Preview);
        let root = tempdir().unwrap();
        touch(&root.path().join("cache/payload"), 10);
        let plan = preview(root.path(), Tier::Cache, Identity::Wipe);
        assert_eq!(
            apply_at(plan, Intent::default()).unwrap(),
            ExecutionReport::default()
        );
        assert!(root.path().join("cache/payload").exists());
        let plan = preview(root.path(), Tier::Cache, Identity::Wipe);
        assert_eq!(apply_at(plan, Intent::Apply).unwrap().paths_removed, 1);
        assert!(!root.path().join("cache").exists());
    }

    #[test]
    fn nuclear_requires_distinct_intent_and_preserves_identity_and_private_root() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        touch(&root.path().join("keys/signer"), 32);
        touch(&root.path().join("cache/payload"), 10);
        let plan = preview(root.path(), Tier::Nuclear, Identity::Keep);
        assert!(
            apply_at(plan, Intent::Apply)
                .unwrap_err()
                .to_string()
                .contains("DeleteEverything")
        );
        assert!(root.path().join("cache/payload").exists());
        let plan = preview(root.path(), Tier::Nuclear, Identity::Keep);
        apply_at(plan, Intent::DeleteEverything).unwrap();
        assert!(root.path().join("keys/signer").exists());
        assert!(!root.path().join("cache").exists());
        assert_eq!(
            std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn replaced_plan_entry_is_refused_even_with_force() {
        let root = tempdir().unwrap();
        touch(&root.path().join("cache/payload"), 10);
        let mut plan = preview(root.path(), Tier::Cache, Identity::Wipe);
        plan.request.force = true;
        std::fs::rename(root.path().join("cache"), root.path().join("old-cache")).unwrap();
        touch(&root.path().join("cache/replacement"), 20);
        assert!(
            apply_at(plan, Intent::Apply)
                .unwrap_err()
                .to_string()
                .contains("changed since preview")
        );
        assert!(root.path().join("cache/replacement").exists());
        assert!(root.path().join("old-cache/payload").exists());
    }

    #[test]
    fn live_vm_refuses_before_operations_and_is_rechecked_at_apply() {
        let root = tempdir().unwrap();
        touch(&root.path().join("cache/payload"), 10);
        let plan = preview(root.path(), Tier::Cache, Identity::Wipe);
        let marker = root.path().join("vms/web/hvf.pid");
        std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
        std::fs::write(&marker, std::process::id().to_string()).unwrap();
        let request = Request {
            tier: Some(Tier::Cache),
            intent: Intent::Apply,
            ..Request::default()
        };
        let error = prepare_with(
            request.clone(),
            root.path().to_path_buf(),
            &mut |_| {},
            |_, _| panic!("live guard must precede VM operations"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("appears to be running"));
        assert!(apply_at(plan, Intent::Apply).is_err());
        let mut called = false;
        prepare_with(
            Request {
                force: true,
                ..request
            },
            root.path().to_path_buf(),
            &mut |_| {},
            |retention, _| {
                called = true;
                assert_eq!(retention.count(), 5);
                Ok(())
            },
        )
        .unwrap();
        assert!(called);
        assert!(root.path().join("cache/payload").exists());
    }

    #[test]
    fn invalid_identity_retention_is_refused_before_vm_operations() {
        let root = tempdir().unwrap();
        let request = Request {
            identity: Identity::Keep,
            intent: Intent::Apply,
            ..Request::default()
        };
        assert!(
            prepare_with(
                request,
                root.path().to_path_buf(),
                &mut |_| {},
                |_, _| panic!("invalid request must not run")
            )
            .is_err()
        );
    }

    #[test]
    fn nuclear_unlinks_links_without_deleting_their_targets() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        touch(&outside.path().join("payload"), 20);
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("missing"), root.path().join("dangling"))
            .unwrap();
        apply_at(
            preview(root.path(), Tier::Nuclear, Identity::Wipe),
            Intent::DeleteEverything,
        )
        .unwrap();
        assert!(outside.path().join("payload").exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[derive(Default)]
    struct FakeVm {
        running: bool,
        fail_prune: bool,
        calls: Vec<String>,
    }

    impl VmOperations for FakeVm {
        fn disk_usage(&mut self) -> Option<u8> {
            self.calls.push("disk".into());
            self.running.then_some(80)
        }
        fn run(&mut self, command: &str) -> Result<()> {
            self.calls.push(command.into());
            anyhow::bail!("best effort command failed")
        }
        fn stdout(&mut self, command: &str) -> Result<String> {
            self.calls.push(command.into());
            anyhow::bail!("gc failed")
        }
        fn prune(&mut self, keep: usize) -> Result<(usize, Vec<String>)> {
            self.calls.push(format!("prune:{keep}"));
            if self.fail_prune {
                anyhow::bail!("prune failed");
            }
            Ok((1, vec!["old-build".into()]))
        }
    }

    #[test]
    fn injected_vm_workflow_preserves_gc_retry_and_best_effort_failures() {
        let mut vm = FakeVm {
            running: true,
            ..FakeVm::default()
        };
        let mut events = Vec::new();
        assert_eq!(
            run_vm_cleanup_with(&mut vm, Retention::All, &mut |event| events.push(event)).unwrap(),
            1
        );
        assert_eq!(
            vm.calls,
            vec![
                "disk",
                "sudo rm -rf /tmp/* /var/tmp/* 2>/dev/null",
                "prune:0",
                "nix-collect-garbage -d 2>&1 | tail -3",
                "rm -rf ~/.local/state/nix/profiles/* 2>/dev/null",
                "nix-collect-garbage -d 2>&1 | tail -3",
                "disk"
            ]
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::GarbageCollectionRetryFailed(_)))
        );
    }

    #[test]
    fn stopped_vm_skips_gc_and_prune_errors_propagate() {
        let mut vm = FakeVm::default();
        let mut events = Vec::new();
        run_vm_cleanup_with(&mut vm, Retention::default(), &mut |e| events.push(e)).unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::GarbageCollectionSkipped))
        );
        assert!(!vm.calls.iter().any(|c| c.contains("nix-collect")));
        let mut vm = FakeVm {
            fail_prune: true,
            ..FakeVm::default()
        };
        assert!(run_vm_cleanup_with(&mut vm, Retention::default(), &mut |_| {}).is_err());
        assert_eq!(vm.calls.len(), 3);
    }
}

//! Connect to the automatically managed local policy-generation owner.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use mvm_hostd::policy_generation::coordinator::{Request, Response, call, socket_path};
pub use mvm_hostd::policy_generation::managed::{ManagedCoordinator, ManagedRefusal};
pub use mvm_hostd::policy_generation::{GENERATION_ASSET_PREFIX, ProjectPolicyCandidate};

/// Report the coordinator a systemd user manager runs for this MVM home.
///
/// Unlike [`ensure`], this never spawns one: a unit that is absent, stopped
/// or unverifiable is a refusal. The exchange with the coordinator is bounded
/// per read and per write (five seconds each), not five seconds in total. A
/// report is identity only — not readiness,
/// current authority, or permission to commit.
///
/// # Errors
///
/// A [`ManagedRefusal`] naming what is missing or does not match.
pub fn managed_status() -> Result<ManagedCoordinator, ManagedRefusal> {
    let home = PathBuf::from(mvm_core::config::mvm_home());
    let home = home.canonicalize().map_err(|error| {
        ManagedRefusal::InvalidHome(format!(
            "canonicalizing MVM home {}: {error}",
            home.display()
        ))
    })?;
    mvm_hostd::policy_generation::managed::managed_status(&home)
}

/// Connect to the resident owner, spawning its separate `mvm-hostd` process
/// under a serialized spawn lock if no process is listening.
///
/// # Errors
///
/// The private state or helper is unavailable, or its readiness check fails.
pub fn ensure() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        unix::ensure()
    }
    #[cfg(not(unix))]
    {
        bail!("local policy coordinator is supported only on Linux and macOS")
    }
}

/// Require the resident helper only after durable activation state exists.
///
/// The caller holds the shared activation barrier until launch or restore ends.
///
/// # Errors
///
/// Activation state is incomplete, or the required coordinator is unavailable.
pub fn ensure_if_activated() -> Result<()> {
    recover_interrupted_publication()?;
    if mvm_hostd::policy_generation::has_active_generation()? {
        ensure()?;
    }
    Ok(())
}

/// Ask the coordinator to resolve an interrupted publication before the
/// caller's own state check, which still refuses if recovery could not run.
fn recover_interrupted_publication() -> Result<()> {
    if mvm_hostd::policy_generation::has_unresolved_publication()? {
        call(&ensure()?, &Request::Recover)?;
    }
    Ok(())
}

/// Return a validated committed generation, if this project was never
/// activated returning `None`. Missing or corrupt active state never falls
/// back to the authored files.
///
/// The caller must hold the shared activation barrier until its admitted
/// launch or restore finishes.
///
/// # Errors
///
/// The coordinator is unavailable or refuses the generation.
pub fn read_committed(
    project: &Path,
    _barrier: &mvm_core::host_interface::activation_barrier::ActivationBarrier,
) -> Result<Option<ProjectPolicyCandidate>> {
    request(Request::Read {
        project: project.to_path_buf(),
    })
}

/// Read only when a host-wide activation has been attempted. Ordinary runs
/// before activation need neither a daemon nor a new dependency on its binary.
///
/// The caller holds `barrier` through source selection and backend start, so
/// activation cannot slip between this check and the admitted boot.
///
/// # Errors
///
/// An activated generation or marker is unavailable or malformed.
pub fn read_if_activated(
    project: &Path,
    barrier: &mvm_core::host_interface::activation_barrier::ActivationBarrier,
) -> Result<Option<ProjectPolicyCandidate>> {
    let root = mvm_core::config::policy_generations_dir();
    let mut attempted = false;
    let canonical = project
        .canonicalize()
        .with_context(|| format!("canonicalizing project {}", project.display()))?;
    let label = canonical.to_str().context("project path is not UTF-8")?;
    let project_key = mvm_core::manifest::key_for_manifest_identity(label);
    let record = format!("{project_key}.json");
    for name in ["activated.marker", "active.json", record.as_str()] {
        match std::fs::symlink_metadata(root.join(name)) {
            Ok(_) => attempted = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting policy activation {name}"));
            }
        }
    }
    if !attempted {
        return Ok(None);
    }
    let candidate = read_committed(project, barrier)?;
    if let Some(candidate) = &candidate {
        candidate.revalidate(&mvm_policy::PolicyStore::from_config())?;
    }
    Ok(candidate)
}

/// Resolve a committed manifest to its already-built slot without reopening
/// the staged manifest. Refuse a slot built from a different boot declaration.
///
/// # Errors
///
/// The committed manifest has no matching built Firecracker revision.
pub fn built_manifest_slot(candidate: &ProjectPolicyCandidate) -> Result<String> {
    candidate.built_manifest_slot()
}

/// Find a built slot's project directory from its absolute manifest source.
///
/// Missing or corrupt slots and nonlocal source identities return `None`; the
/// ordinary slot resolver remains responsible for reporting unusable slots.
#[must_use]
pub fn project_dir_for_slot(slot: &str) -> Option<PathBuf> {
    let built = mvm_runtime::vm::template::lifecycle::template_load_slot(slot).ok()?;
    let source = Path::new(&built.manifest_path);
    if source.is_absolute() {
        source.parent().map(Path::to_path_buf)
    } else {
        None
    }
}

/// Find a slot's active project generation from its persisted source identity.
///
/// # Errors
///
/// An activated project has missing, mismatched, or invalid committed state.
pub fn activated_for_slot(
    slot: &str,
    barrier: &mvm_core::host_interface::activation_barrier::ActivationBarrier,
) -> Result<Option<ProjectPolicyCandidate>> {
    let Ok(built) = mvm_runtime::vm::template::lifecycle::template_load_slot(slot) else {
        // The ordinary slot resolver reports a missing or corrupt slot. This
        // lookup is only to prevent a *valid* project slot bypassing activation.
        return Ok(None);
    };
    let path = Path::new(&built.manifest_path);
    if path.is_absolute()
        && path.file_name().is_some_and(|name| {
            mvm_core::manifest::MANIFEST_FILENAMES
                .iter()
                .any(|allowed| name == *allowed)
        })
        && let Some(project) = path.parent()
        && let Some(candidate) = read_if_activated(project, barrier)?
    {
        anyhow::ensure!(
            candidate.built_manifest_slot()? == slot,
            "slot {slot} no longer matches its committed project manifest"
        );
        return Ok(Some(candidate));
    }
    Ok(None)
}

/// Match an activated project's built slot to the generation identity
/// the forthcoming signed admission will carry.
///
/// # Errors
///
/// The slot names an activated project but its signed plan omits its generation.
pub fn verify_slot_generation(
    slot: &str,
    bound: Option<&mvm_core::plan::AssetIdentity>,
    barrier: &mvm_core::host_interface::activation_barrier::ActivationBarrier,
) -> Result<()> {
    if let Some(candidate) = activated_for_slot(slot, barrier)? {
        let expected = candidate.plan_asset()?;
        anyhow::ensure!(
            bound == Some(&expected),
            "slot {slot} belongs to an activated project but its signed admission does not bind that generation"
        );
    }
    Ok(())
}

/// Recheck a persistent machine's stored policy and resource bounds before
/// every boot; a spec edit cannot turn a committed denial into a grant.
///
/// # Errors
///
/// Its generation is missing or changed, or the spec asks for permissions
/// the committed policy cannot represent on this persistent path.
pub fn validate_machine_spec_generation(
    spec: &mvm_runtime::machine::persist::MachineSpec,
    barrier: &mvm_core::host_interface::activation_barrier::ActivationBarrier,
) -> Result<()> {
    let candidate = spec
        .manifest
        .as_deref()
        .map(|slot| activated_for_slot(slot, barrier))
        .transpose()?
        .flatten();
    let Some(candidate) = candidate else {
        anyhow::ensure!(
            spec.policy_generation.is_none(),
            "machine pins a project generation but no active project owns its source"
        );
        return Ok(());
    };
    let expected = candidate.plan_asset()?;
    anyhow::ensure!(
        spec.policy_generation.as_ref() == Some(&expected),
        "machine's committed generation differs from its project"
    );
    validate_spec_against_policy(spec, candidate.policy())
}

fn validate_spec_against_policy(
    spec: &mvm_runtime::machine::persist::MachineSpec,
    policy: &mvm_policy::PolicyBody,
) -> Result<()> {
    use mvm_contract::grants::{CpuGrant, WallClockGrant};

    anyhow::ensure!(
        policy.shares.is_empty()
            && policy.env.is_empty()
            && policy.secrets.is_empty()
            && policy.network.routes.is_empty(),
        "committed policy has sections this persistent machine spec cannot retain"
    );
    anyhow::ensure!(
        spec.routes.is_empty() && spec.peer.is_empty() && spec.ports.is_empty(),
        "persistent machine has network routes or ports outside the committed policy fold"
    );
    let grants = spec.grants.as_ref();
    let mut allow_host = spec.allow_host.clone();
    if let Some(egress) = grants.and_then(|grants| grants.egress.as_ref()) {
        allow_host.extend(egress.allow.iter().map(ToString::to_string));
    }
    let cpu_limit = match grants.and_then(|grants| grants.cpu) {
        Some(CpuGrant::Share { millicores }) => Some(millicores),
        _ => None,
    };
    let timeout = match grants.and_then(|grants| grants.wall_clock) {
        Some(WallClockGrant::Secs { secs }) => Some(u64::from(secs.get())),
        _ => None,
    };
    let folded = super::fold(
        policy,
        &super::LaunchFlags {
            allow_host,
            net: spec.net,
            cpu_limit,
            timeout,
            cpus: spec.cpus,
            memory_mib: u64::from(mvm_core::util::parse_human_size(&spec.memory)?),
            ..super::LaunchFlags::default()
        },
    )?;
    if let Some(limit) = folded.cpu_limit {
        anyhow::ensure!(
            cpu_limit.is_some_and(|requested| requested <= limit),
            "machine is missing the committed CPU-share bound"
        );
    }
    if let Some(limit) = folded.timeout {
        anyhow::ensure!(
            timeout.is_some_and(|requested| requested <= limit),
            "machine is missing the committed wall-clock bound"
        );
    }
    Ok(())
}

/// Recheck a restored VM's cached plan and committed generation before any
/// saved guest state is resumed. A cache miss is legacy-only before activation.
///
/// # Errors
///
/// The plan is absent after activation, corrupt, or pins a stale generation.
pub fn restore_plan(vm_name: &str) -> Result<Option<mvm_core::plan::ExecutionPlan>> {
    let _barrier = mvm_core::host_interface::activation_barrier::ActivationBarrier::shared()?;
    recover_interrupted_publication()?;
    let active = mvm_hostd::policy_generation::has_active_generation()?;
    let path = mvm_hostd::audit::plan_persist::plan_path(vm_name)?;
    let plan = match mvm_hostd::audit::plan_persist::read_plan(vm_name) {
        Ok(plan) => plan,
        Err(_) if !active => {
            // Legacy plans were a best-effort audit cache, not a restore
            // prerequisite. Once activation exists, the cache is required
            // so an opted-in generation cannot be silently forgotten.
            return Ok(None);
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "restoring {vm_name:?} requires its admitted plan at {}",
                    path.display()
                )
            });
        }
    };
    if plan.asset_identities.iter().any(|asset| {
        asset
            .name
            .starts_with(mvm_hostd::policy_generation::GENERATION_ASSET_PREFIX)
    }) {
        anyhow::ensure!(
            plan.workload.0 == vm_name,
            "restore plan belongs to {:?}, not {vm_name:?}",
            plan.workload.0
        );
        mvm_core::plan::verify_plan_id(&plan)?;
    }
    mvm_hostd::policy_generation::verify_plan_generation_assets(&plan)?;
    Ok(Some(plan))
}

/// Refuse a bare SDK slot source belonging to an activated project.
///
/// # Errors
///
/// The slot is generation-bound and this request carries no pin.
pub fn refuse_unbound_slot(
    slot: &str,
    barrier: &mvm_core::host_interface::activation_barrier::ActivationBarrier,
) -> Result<()> {
    verify_slot_generation(slot, None, barrier)
}

/// Ask the resident owner to publish an initial generation. There is no
/// `policy apply` or live rollover in this operation.
///
/// # Errors
///
/// The host is not proven quiescent or the project cannot be committed.
pub fn activate(project: &Path) -> Result<ProjectPolicyCandidate> {
    request(Request::Activate {
        project: project.to_path_buf(),
    })?
    .context("policy coordinator did not return the activated generation")
}

fn canonicalize_request(request: &mut Request) -> Result<PathBuf> {
    let (Request::Activate { project } | Request::Read { project }) = request else {
        bail!("a project request requires a project identity")
    };
    *project = project
        .canonicalize()
        .with_context(|| format!("canonicalizing project {}", project.display()))?;
    Ok(project.clone())
}

fn request(mut request: Request) -> Result<Option<ProjectPolicyCandidate>> {
    let project = canonicalize_request(&mut request)?;
    match call(&ensure()?, &request)? {
        Response::Policy { candidate } => {
            if let Some(candidate) = &candidate {
                anyhow::ensure!(
                    candidate.project_dir() == project,
                    "policy coordinator returned another project's generation"
                );
            }
            Ok(candidate.map(|candidate| *candidate))
        }
        Response::Refused { message } => bail!("policy coordinator refused: {message}"),
        Response::Unresolved { message } => bail!(
            "the outcome of the policy activation is unknown and the coordinator refuses policy reads until it recovers: {message}"
        ),
        Response::Ready | Response::Status { .. } => {
            bail!("unexpected policy coordinator response to a project request")
        }
    }
}

#[cfg(unix)]
mod unix {
    use std::{
        io,
        os::unix::net::UnixStream,
        thread,
        time::{Duration, Instant},
    };

    use mvm_vmm::host::{
        aux_bin::AuxBin,
        broker_services_spawn::{resolve_subprocess_bin_to_spawn, spawn_detached_with_config},
    };

    use super::*;

    pub(super) fn ensure() -> Result<PathBuf> {
        let home = PathBuf::from(mvm_core::config::mvm_home());
        anyhow::ensure!(
            home.is_absolute(),
            "MVM_HOME must be absolute for policy activation"
        );
        mvm_core::private_fs::create_owned_private_dir(&home)?;
        let dir = mvm_core::config::policy_generations_dir_at(&home);
        mvm_core::private_fs::create_owned_private_dir(&dir)?;
        let socket = socket_path(&home);
        mvm_core::private_fs::create_owned_private_dir(
            socket
                .parent()
                .context("policy coordinator socket has no parent")?,
        )?;
        let _spawn_lock = mvm_core::util::atomic_io::FileLock::acquire(&dir.join("spawn"))?;
        match UnixStream::connect(&socket) {
            Ok(_) => {
                ping(&socket)?;
                return Ok(socket);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("connecting to policy coordinator {}", socket.display())
                });
            }
        }
        let bin = resolve_subprocess_bin_to_spawn(&AuxBin::new(
            "mvm-policy-coordinator",
            "MVM_POLICY_COORDINATOR_PATH",
            "mvm-hostd",
        ))?;
        let mut child = spawn_detached_with_config(
            &bin,
            &serde_json::json!({"home": home}),
            "mvm-policy-coordinator",
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(()) = ping(&socket) {
                return Ok(socket);
            }
            if let Some(status) = child.try_wait()? {
                bail!("policy coordinator exited before readiness: {status}");
            }
            thread::sleep(Duration::from_millis(25));
        }
        bail!(
            "policy coordinator did not become ready at {}",
            socket.display()
        )
    }

    fn ping(socket: &Path) -> Result<()> {
        match call(socket, &Request::Ping)? {
            Response::Ready => Ok(()),
            Response::Refused { message } => {
                bail!("policy coordinator refused readiness: {message}")
            }
            Response::Policy { .. } | Response::Status { .. } | Response::Unresolved { .. } => {
                bail!("policy coordinator answered a ping with something else")
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use mvm_core::{
        manifest::{Manifest, PersistedManifest, Provenance, slot_dir, slot_revision_dir},
        pool::ArtifactPaths,
        template::{CURRENT_SCHEMA_VERSION, TemplateRevision},
        util::test_env::TestEnv,
    };
    use std::os::unix::fs::symlink;

    #[test]
    fn project_requests_bind_the_callers_directory_before_ipc() {
        const EXPECTED: &str = "MVM_TEST_POLICY_REQUEST_PROJECT";
        if let Some(expected) = std::env::var_os(EXPECTED) {
            let expected = PathBuf::from(expected).canonicalize().unwrap();
            for mut request in [
                Request::Activate {
                    project: PathBuf::from("."),
                },
                Request::Read {
                    project: PathBuf::from("."),
                },
            ] {
                assert_eq!(canonicalize_request(&mut request).unwrap(), expected);
                let (Request::Activate { project } | Request::Read { project }) = request else {
                    panic!("expected project request")
                };
                assert_eq!(project, expected);
                assert!(project.is_absolute());
            }
            return;
        }
        let root = tempfile::tempdir().unwrap();
        for name in ["coordinator-directory", "caller-directory"] {
            let directory = root.path().join(name);
            std::fs::create_dir(&directory).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "policy_profiles::coordinator::tests::project_requests_bind_the_callers_directory_before_ipc", "--nocapture"])
                .current_dir(&directory)
                .env(EXPECTED, &directory)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut missing = Request::Read {
            project: root.path().join("missing"),
        };
        assert!(canonicalize_request(&mut missing).is_err());
    }

    #[test]
    fn managed_status_refuses_without_spawning_a_detached_coordinator() {
        let mut environment = TestEnv::new();
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap();
        environment.isolate_mvm_home(&home);
        // A helper that records being run, so a spawn attempt cannot go unseen.
        let marker = home.join("helper-ran");
        let helper = home.join("helper");
        std::fs::write(
            &helper,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        environment.set("MVM_POLICY_COORDINATOR_PATH", &helper);
        // No unit for a scratch home exists on any host this runs on.
        let refusal = managed_status().unwrap_err();
        assert!(
            !matches!(refusal, ManagedRefusal::InvalidHome(_)),
            "{refusal}"
        );
        assert!(!socket_path(&home).exists());
        assert!(!marker.exists(), "a detached coordinator was spawned");

        environment.isolate_mvm_home(home.join("missing"));
        assert!(matches!(
            managed_status(),
            Err(ManagedRefusal::InvalidHome(_))
        ));
    }

    #[test]
    fn ordinary_launch_needs_no_coordinator_but_incomplete_activation_refuses() {
        let mut environment = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        environment.isolate_mvm_home(home.path());
        environment.set(
            "MVM_POLICY_COORDINATOR_PATH",
            home.path().join("missing-helper"),
        );
        let _barrier =
            mvm_core::host_interface::activation_barrier::ActivationBarrier::shared().unwrap();
        ensure_if_activated().unwrap();
        assert!(!socket_path(home.path()).exists());
        mvm_core::util::atomic_io::atomic_write_new(
            &home.path().join("policy-generations/activated.marker"),
            b"invalid",
        )
        .unwrap();
        let error = ensure_if_activated().unwrap_err();
        assert!(
            error.to_string().contains("invalid activation marker"),
            "{error:#}"
        );
        assert!(!socket_path(home.path()).exists());
    }

    #[test]
    fn slot_project_lookup_preserves_missing_corrupt_and_nonlocal_sources() {
        let mut environment = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        environment.isolate_mvm_home(home.path());
        let manifest = Manifest::from_toml_str("flake = \".\"\nprofile = \"default\"\n").unwrap();
        let path = home.path().join("mvm.toml");
        std::fs::write(&path, "flake = \".\"\n").unwrap();
        let canonical = path.canonicalize().unwrap();
        let mut persisted = PersistedManifest::from_manifest(
            &manifest,
            &canonical,
            "firecracker",
            Provenance::current(),
        )
        .unwrap();
        let slot = persisted.manifest_hash.clone();
        assert_eq!(project_dir_for_slot(&slot), None);
        let directory = PathBuf::from(slot_dir(&slot));
        persisted.write_to_slot(&directory).unwrap();
        assert_eq!(
            project_dir_for_slot(&slot),
            canonical.parent().map(Path::to_path_buf)
        );
        persisted.manifest_path = "relative/mvm.toml".into();
        persisted.write_to_slot(&directory).unwrap();
        assert_eq!(project_dir_for_slot(&slot), None);
        std::fs::write(directory.join("manifest.json"), "invalid").unwrap();
        assert_eq!(project_dir_for_slot(&slot), None);
    }

    #[test]
    fn committed_manifest_selects_the_built_revision_without_reopening_staged_text() {
        let mut environment = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        environment.isolate_mvm_home(home.path());
        let project = tempfile::tempdir().unwrap();
        let path = project.path().join("mvm.toml");
        let text = "flake = \".\"\nprofile = \"default\"\n";
        std::fs::write(&path, text).unwrap();
        let manifest = Manifest::read_file(&path).unwrap();
        let canonical = path.canonicalize().unwrap();
        let mut persisted = PersistedManifest::from_manifest(
            &manifest,
            &canonical,
            "firecracker",
            Provenance::current(),
        )
        .unwrap();
        persisted.flake_ref = project.path().display().to_string();
        let slot = persisted.manifest_hash.clone();
        let directory = PathBuf::from(slot_dir(&slot));
        persisted.write_to_slot(&directory).unwrap();
        // Builder jobs without a store-path sidecar use their job ID.
        let revision = "fallback-job-id".to_string();
        let revision_dir = PathBuf::from(slot_revision_dir(&slot, &revision));
        std::fs::create_dir_all(&revision_dir).unwrap();
        let mut record = TemplateRevision {
            schema_version: CURRENT_SCHEMA_VERSION,
            revision_hash: revision.clone(),
            flake_ref: persisted.flake_ref.clone(),
            flake_lock_hash: revision.clone(),
            artifact_paths: ArtifactPaths {
                vmlinux: "vmlinux".into(),
                rootfs: "rootfs.ext4".into(),
                fc_base_config: "fc-base.json".into(),
                initrd: None,
                sizes: None,
            },
            built_at: "2026-01-01T00:00:00Z".into(),
            profile: manifest.profile.clone(),
            vcpus: manifest.cpus,
            mem_mib: manifest.mem_mib().unwrap(),
            data_disk_mib: manifest.data_disk_mib().unwrap(),
            snapshot: None,
            build_mode: None,
        };
        std::fs::write(
            revision_dir.join("revision.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        symlink(
            format!("artifacts/revisions/{revision}"),
            directory.join("current"),
        )
        .unwrap();
        let candidate: ProjectPolicyCandidate = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "generation": 1,
            "project_dir": project.path(),
            "manifest_path": canonical,
            "manifest_text": text,
            "defaults": [],
            "platform": mvm_policy::Platform::default(),
            "sources": [],
            "effective": mvm_policy::PolicyBody::default(),
            "effective_sha256": "0".repeat(64),
            "closure_sha256": "0".repeat(64),
        }))
        .unwrap();

        std::fs::write(&path, "flake = \"staged-wider\"\n").unwrap();
        assert_eq!(built_manifest_slot(&candidate).unwrap(), slot);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(built_manifest_slot(&candidate).unwrap(), slot);
        std::fs::remove_file(directory.join("current")).unwrap();
        symlink("../escape", directory.join("current")).unwrap();
        assert!(
            built_manifest_slot(&candidate).is_err(),
            "a symlink that names a parent is not a revision"
        );
        std::fs::remove_file(directory.join("current")).unwrap();
        symlink(
            format!("artifacts/revisions/{revision}"),
            directory.join("current"),
        )
        .unwrap();
        record.flake_ref = "staged-wider".into();
        std::fs::write(
            revision_dir.join("revision.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert!(
            built_manifest_slot(&candidate).is_err(),
            "a staged rebuild must not replace the committed boot declaration"
        );
    }

    #[test]
    fn a_persisted_machine_cannot_drop_or_widen_the_generation_bounds() {
        use mvm_contract::grants::{CpuGrant, Grants, WallClockGrant};

        let request = crate::launch::LaunchRequest::builder(
            crate::launch::LifecycleMode::Persistent,
            "docker.io/library/alpine:3.20".parse().unwrap(),
        )
        .name("bounded")
        .build()
        .unwrap();
        let mut spec = crate::launch::persisted_spec_from_request(&request, "bounded");
        let mut policy = mvm_policy::PolicyBody::default();
        policy.network.deny.push("evil.test:443".into());
        policy.resources.max_cpus = Some(2);
        policy.resources.cpu_millicores = Some(750);
        policy.resources.wall_clock_secs = Some(40);

        assert!(
            validate_spec_against_policy(&spec, &policy).is_err(),
            "missing required resource grants must refuse"
        );
        spec.grants = Some(Grants {
            cpu: Some(CpuGrant::Share { millicores: 750 }),
            wall_clock: Some(WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(40).unwrap(),
            }),
            ..Grants::default()
        });
        assert!(validate_spec_against_policy(&spec, &policy).is_ok());
        spec.allow_host.push("evil.test:443".into());
        assert!(
            validate_spec_against_policy(&spec, &policy).is_err(),
            "a reconfigured host denied by the generation must refuse"
        );
        spec.allow_host.clear();
        spec.cpus = 3;
        assert!(validate_spec_against_policy(&spec, &policy).is_err());
        spec.cpus = 1;
        spec.routes.push(mvm_contract::policy::routes::EgressRoute {
            id: "unsanctioned".into(),
            host: "evil.test".into(),
            port: 443,
            rules: Vec::new(),
            otherwise: mvm_contract::policy::routes::RouteOutcome::Allow,
            intercept: false,
        });
        assert!(
            validate_spec_against_policy(&spec, &policy).is_err(),
            "a persisted route must not bypass the committed network policy"
        );
    }

    #[test]
    fn restore_keeps_legacy_absence_but_refuses_incomplete_activation() {
        let mut environment = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        environment.isolate_mvm_home(home.path());
        assert!(restore_plan("old-vm").unwrap().is_none());
        let _barrier =
            mvm_core::host_interface::activation_barrier::ActivationBarrier::shared().unwrap();
        mvm_core::util::atomic_io::atomic_write_new(
            &home.path().join("policy-generations/activated.marker"),
            b"policy-generation-v1\n",
        )
        .unwrap();
        let error = restore_plan("old-vm").unwrap_err();
        assert!(
            format!("{error:#}").contains("activation marker"),
            "restore must refuse an interrupted activation: {error:#}"
        );
    }
}

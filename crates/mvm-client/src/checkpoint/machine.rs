//! User-facing fork/restore surface for `mvmctl machine fork` and
//! `mvmctl machine restore`.
//!
//! These verbs sit on top of the consolidated `VmBackend`/checkpoint seam:
//! `fork` captures a running machine as a vm_full checkpoint and then branches
//! it into a fresh child VM; `restore` branches an existing vm_full checkpoint
//! into a fresh child VM. Both deliver new identity, authority, and
//! per-instance secrets through the same admit-and-boot path used by
//! `machine warm-restore`.

use super::{Checkpoints, ForkIntent, ForkReport, ForkRequest};
use anyhow::{Context, Result, bail};
use mvm_core::checkpoint::CheckpointClass;
use mvm_core::naming;
#[cfg(test)]
use mvm_runtime::checkpoint::CheckpointStore;

/// Input to [`Checkpoints::fork_machine`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ForkMachineInput {
    /// Parent machine name (must be running).
    pub parent_name: String,
    /// Explicit child VM name (`--as`). Refused when `count` is above 1:
    /// one name cannot name N children.
    pub child_name: Option<String>,
    /// Branch slug for auto-naming (`--branch`). Refused when `count` is
    /// above 1, for the same reason.
    pub branch: Option<String>,
    /// Children to fork from the single capture. 1 reproduces the original
    /// single-child behavior exactly; above 1 the children are named
    /// `<parent>-fork-<i>-<timestamp>`.
    pub count: u32,
    /// Secret bindings explicitly declared for the child.
    pub declared_secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Whether omitting a parent binding is intentional.
    pub allow_secret_drop: bool,
    /// Emit machine-readable JSON instead of human text.
    pub json: bool,
}

/// Input to [`Checkpoints::restore_machine`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RestoreMachineInput {
    /// vm_full checkpoint id to restore.
    pub checkpoint_id: String,
    /// Explicit child VM name (`--as`).
    pub child_name: Option<String>,
    /// Branch slug for auto-naming (`--branch`).
    pub branch: Option<String>,
    /// Secret bindings explicitly declared for the child.
    pub declared_secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Whether omitting a parent binding is intentional.
    pub allow_secret_drop: bool,
    /// Emit machine-readable JSON instead of human text.
    pub json: bool,
}

/// User-facing `machine fork`: capture a running machine and branch it into a
/// fresh child VM with a new identity.
///
/// The implementation first snapshots the parent as a vm_full checkpoint via
/// the backend's pause/save/resume control, then forks that checkpoint using
/// the same path as `machine warm-restore`. The intermediate checkpoint id is
/// left in the store so the caller can inspect or remove it.
impl Checkpoints {
    pub fn fork_machine(
        &self,
        input: ForkMachineInput,
        observer: &mut dyn crate::entrypoint::CallObserver,
    ) -> Result<ForkBatchReport> {
        if input.count == 0 {
            bail!("--count must be at least 1");
        }
        naming::validate_id(&input.parent_name, "machine name")
            .with_context(|| format!("invalid parent machine name {:?}", input.parent_name))?;
        if input.count > 1 && input.child_name.is_some() {
            bail!(
                "--as names a single child and cannot be combined with --count above 1;              batch children are named <parent>-fork-<i>-<timestamp>"
            );
        }
        if input.count > 1 && input.branch.is_some() {
            bail!(
                "--branch names a single child and cannot be combined with --count above 1;              batch children are named <parent>-fork-<i>-<timestamp>"
            );
        }
        // Resolve the single-child name before capturing so a bad --as/--branch
        // still fails before the parent is paused.
        let single_child_name = if input.count == 1 {
            Some(resolve_child_name(
                &input.parent_name,
                input.child_name.as_deref(),
                input.branch.as_deref(),
                false,
            )?)
        } else {
            None
        };
        // One capture serves the whole batch: every child resumes from the same
        // point by definition, so re-capturing would pause the parent N times
        // for an identical snapshot.
        let checkpoint_id = self
            .capture_for_fork(&input.parent_name, None)
            .with_context(|| format!("capturing full-VM snapshot of {}", input.parent_name))?;

        let mut children: Vec<ForkReport> = Vec::new();
        let batch_ts = super::capture::now_unix();
        for index in 1..=input.count {
            let child_name = match &single_child_name {
                Some(name) => name.clone(),
                None => batch_child_name(&input.parent_name, index, batch_ts),
            };
            match self.fork_vm_full_machine(
                ForkVmFullMachineInput {
                    checkpoint_id: checkpoint_id.as_str().to_string(),
                    child_vm_name: Some(child_name.clone()),
                    declared_secrets: input.declared_secrets.clone(),
                    allow_secret_drop: input.allow_secret_drop,
                    // Per-child documents stream into each other; the batch emits
                    // one array-shaped document after the loop instead.
                    json: input.json && input.count == 1,
                },
                observer,
            ) {
                Ok(report) => children.push(report),
                Err(error) => {
                    // Fail fast, but say what is still up: earlier children are
                    // live VMs the caller must clean up.
                    let forked: Vec<&str> = children
                        .iter()
                        .map(|report| report.child_vm_name.as_str())
                        .collect();
                    let detail = if forked.is_empty() {
                        "no children were forked".to_string()
                    } else {
                        format!(
                            "already-forked children are still running: {}",
                            forked.join(", ")
                        )
                    };
                    return Err(error.context(format!(
                        "forking child {index} of {} failed; {detail}",
                        input.count
                    )));
                }
            }
        }
        Ok(ForkBatchReport {
            schema_version: 1,
            action: "fork-batch".to_owned(),
            parent: input.parent_name,
            checkpoint_id,
            children,
        })
    }
}

/// Batch fork child name: `<parent>-fork-<index>-<timestamp>`. The index
/// keeps siblings distinct under one timestamp; the name is validated at the
/// fork boundary like any VM name.
fn batch_child_name(parent: &str, index: u32, now: u64) -> String {
    format!("{parent}-fork-{index}-{now}")
}

/// `--json` document for a batch fork: one array-shaped answer listing every
/// child, never N streamed single-child objects.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ForkBatchReport {
    pub schema_version: u8,
    pub action: String,
    pub parent: String,
    pub checkpoint_id: mvm_core::checkpoint::CheckpointId,
    pub children: Vec<ForkReport>,
}

/// User-facing `machine restore`: branch an existing vm_full checkpoint into a
/// fresh child VM with a new identity.
///
/// Unlike `vm checkpoint restore`, this does not resume the same identity; it
/// treats the checkpoint as an immutable parent and admits a new claim-8 plan
/// for the child.
impl Checkpoints {
    pub fn restore_machine(
        &self,
        input: RestoreMachineInput,
        observer: &mut dyn crate::entrypoint::CallObserver,
    ) -> Result<ForkReport> {
        let checkpoint = super::validated_id(&input.checkpoint_id)
            .with_context(|| format!("invalid checkpoint id {:?}", input.checkpoint_id))?;
        let parent_meta = self
            .read(&checkpoint)
            .with_context(|| format!("reading checkpoint {}", input.checkpoint_id))?;

        if parent_meta.class != CheckpointClass::VmFull {
            bail!(
                "checkpoint '{}' is class {:?}; restore only supports vm_full checkpoints",
                input.checkpoint_id,
                parent_meta.class,
            );
        }

        let child_name = resolve_child_name(
            input.checkpoint_id.as_str(),
            input.child_name.as_deref(),
            input.branch.as_deref(),
            false,
        )?;

        self.fork_vm_full_machine(
            ForkVmFullMachineInput {
                checkpoint_id: input.checkpoint_id,
                child_vm_name: Some(child_name),
                declared_secrets: input.declared_secrets,
                allow_secret_drop: input.allow_secret_drop,
                json: input.json,
            },
            observer,
        )
    }
}

/// Input to [`Checkpoints::fork_vm_full_machine`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ForkVmFullMachineInput {
    /// Checkpoint id to warm-restore.
    pub checkpoint_id: String,
    /// Desired child VM name; auto-generated if omitted.
    pub child_vm_name: Option<String>,
    /// Secret bindings explicitly declared for the child.
    pub declared_secrets: Vec<mvm_core::plan::SecretBinding>,
    /// Whether omitting a parent binding is intentional.
    pub allow_secret_drop: bool,
    /// Emit machine-readable JSON instead of human text.
    pub json: bool,
}

/// User-facing vm_full warm fork/restore.
///
/// Validates the checkpoint, generates a fresh child identity, admits a new
/// claim-8 plan, restores the saved machine state through the backend fork
/// path, and delivers the post-restore generation token. The parent may be
/// running: the Firecracker arm remaps the child's device paths into its own
/// state dir and no guest NIC exists to collide with the parent.
impl Checkpoints {
    pub fn fork_vm_full_machine(
        &self,
        input: ForkVmFullMachineInput,
        observer: &mut dyn crate::entrypoint::CallObserver,
    ) -> Result<ForkReport> {
        let checkpoint = super::validated_id(&input.checkpoint_id)
            .with_context(|| format!("invalid checkpoint id {:?}", input.checkpoint_id))?;
        let parent_meta = self
            .read(&checkpoint)
            .with_context(|| format!("reading checkpoint {}", input.checkpoint_id))?;

        if parent_meta.class != CheckpointClass::VmFull {
            bail!(
                "checkpoint '{}' is class {:?}; warm-restore only supports vm_full checkpoints",
                input.checkpoint_id,
                parent_meta.class,
            );
        }

        let child_vm_name = input.child_vm_name.unwrap_or_else(|| {
            format!(
                "{}-warm-{}",
                checkpoint.as_str(),
                super::capture::now_unix()
            )
        });
        naming::validate_vm_name(&child_vm_name)
            .with_context(|| format!("invalid child VM name {child_vm_name:?}"))?;

        self.fork(
            &ForkRequest {
                id: checkpoint,
                new_id: Some(child_vm_name),
                boot: true,
                hypervisor: "firecracker".to_owned(),
                cpus: None,
                memory: None,
                declared_secrets: input.declared_secrets,
                allow_secret_drop: input.allow_secret_drop,
                intent: ForkIntent::Ordinary,
                tenant: "local".to_owned(),
            },
            observer,
        )
    }
}

/// Resolve the child VM name from explicit `--as`, `--branch`, or a default.
///
/// * `--as <name>` is used verbatim.
/// * `--branch <slug>` produces `<parent>-<slug>-<timestamp>`.
/// * Neither produces `<parent>-fork-<timestamp>` unless `require_explicit` is
///   true (used by `restore`, where a long checkpoint id is a poor default).
fn resolve_child_name(
    parent: &str,
    explicit: Option<&str>,
    branch: Option<&str>,
    require_explicit: bool,
) -> Result<String> {
    if let Some(name) = explicit {
        naming::validate_id(name, "child machine name")
            .with_context(|| format!("invalid child name {name:?}"))?;
        return Ok(name.to_string());
    }
    let now = super::capture::now_unix();
    if let Some(branch) = branch {
        naming::validate_id(branch, "branch name")
            .with_context(|| format!("invalid branch name {branch:?}"))?;
        return Ok(format!("{parent}-{branch}-{now}"));
    }
    if require_explicit {
        bail!("--as <NAME> or --branch <BRANCH> is required");
    }
    Ok(format!("{parent}-fork-{now}"))
}

#[cfg(test)]
mod tests {
    fn fork_machine(input: super::ForkMachineInput) -> anyhow::Result<super::ForkBatchReport> {
        super::Checkpoints::open()
            .fork_machine(input, &mut crate::entrypoint::CapturedOutput::default())
    }
    fn fork_vm_full_machine(
        input: super::ForkVmFullMachineInput,
    ) -> anyhow::Result<super::ForkReport> {
        super::Checkpoints::open()
            .fork_vm_full_machine(input, &mut crate::entrypoint::CapturedOutput::default())
    }
    use super::*;
    use mvm_core::checkpoint::{
        CheckpointId, CheckpointMeta, ContentBlob, HVF_FRAME_BLOB, SUPERVISOR_CONFIG_BLOB,
    };

    fn write_vm_full_checkpoint(store: &CheckpointStore, id: &str, state_blob: &str) {
        let meta = CheckpointMeta::builder(
            CheckpointId::new(id),
            CheckpointClass::VmFull,
            "parent-machine",
        )
        .content(vec![ContentBlob {
            name: state_blob.to_string(),
            sha256: "00".repeat(32),
        }])
        .build();
        store.write_meta(&meta).unwrap();
        let signer = mvm_hostd::audit::host_keypair::load_or_init().unwrap();
        let emitter = mvm_hostd::audit::emitter::AuditEmitter::new(signer.signing).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("machine-checkpoint-test")
            .build();
        mvm_hostd::audit::bind::bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
    }

    #[test]
    fn batch_refuses_zero_before_capturing_parent() {
        let error = fork_machine(ForkMachineInput {
            parent_name: "parent".into(),
            child_name: None,
            branch: None,
            count: 0,
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            json: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("--count must be at least 1"));
    }

    #[test]
    fn batch_child_names_are_distinct_per_index() {
        let first = batch_child_name("parent", 1, 42);
        let second = batch_child_name("parent", 2, 42);
        assert_eq!(first, "parent-fork-1-42");
        assert_eq!(second, "parent-fork-2-42");
        assert_ne!(first, second);
        // The batch names must pass the same VM-name validation the fork
        // boundary applies.
        naming::validate_vm_name(&first).expect("batch child name is a valid VM name");
    }

    #[test]
    fn batch_refuses_explicit_child_name() {
        let err = fork_machine(ForkMachineInput {
            parent_name: "parent".to_string(),
            child_name: Some("only-child".to_string()),
            branch: None,
            count: 3,
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            json: false,
        })
        .expect_err("--as cannot name N children");
        assert!(
            format!("{err:#}").contains("--as names a single child"),
            "got: {err:#}"
        );
    }

    #[test]
    fn batch_refuses_branch_naming() {
        let err = fork_machine(ForkMachineInput {
            parent_name: "parent".to_string(),
            child_name: None,
            branch: Some("feature-x".to_string()),
            count: 3,
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            json: false,
        })
        .expect_err("--branch cannot name N children");
        assert!(
            format!("{err:#}").contains("--branch names a single child"),
            "got: {err:#}"
        );
    }

    #[test]
    fn fork_batch_json_lists_every_child() {
        let meta = CheckpointMeta::builder(
            CheckpointId::new("ck-child"),
            CheckpointClass::VmFull,
            "parent-fork-1-7",
        )
        .content(Vec::new())
        .build();
        let checkpoint_id = CheckpointId::new("ck-parent");
        let doc = ForkBatchReport {
            schema_version: 1,
            action: "fork-batch".into(),
            parent: "parent".into(),
            checkpoint_id: checkpoint_id.clone(),
            children: vec![ForkReport {
                schema_version: 1,
                action: "fork".into(),
                parent_id: checkpoint_id,
                child_vm_name: "parent-fork-1-7".into(),
                booted: true,
                checkpoint: meta,
            }],
        };
        let value = serde_json::to_value(&doc).expect("serialize");
        assert_eq!(value["action"], "fork-batch");
        assert_eq!(value["parent"], "parent");
        assert_eq!(value["checkpoint_id"], "ck-parent");
        assert_eq!(value["children"].as_array().expect("array").len(), 1);
        assert_eq!(value["children"][0]["child_vm_name"], "parent-fork-1-7");
        assert_eq!(value["children"][0]["parent_id"], "ck-parent");
        let decoded: ForkBatchReport = serde_json::from_value(value).unwrap();
        assert_eq!(
            decoded.children[0].child_vm_name,
            doc.children[0].child_vm_name
        );
    }

    #[test]
    fn resolve_explicit_child_name() {
        assert_eq!(
            resolve_child_name("parent", Some("child"), None, false).unwrap(),
            "child"
        );
    }

    #[test]
    fn resolve_branch_child_name() {
        let name = resolve_child_name("parent", None, Some("feature-x"), false).unwrap();
        assert!(name.starts_with("parent-feature-x-"), "got {name}");
    }

    #[test]
    fn resolve_default_child_name() {
        let name = resolve_child_name("parent", None, None, false).unwrap();
        assert!(name.starts_with("parent-fork-"), "got {name}");
    }

    #[test]
    fn resolve_restore_requires_explicit_or_branch() {
        assert!(resolve_child_name("ckpt-abc", None, None, true).is_err());
    }

    #[test]
    fn resolve_rejects_invalid_explicit() {
        assert!(resolve_child_name("parent", Some("Bad Name"), None, false).is_err());
    }

    #[test]
    fn resolve_rejects_invalid_branch() {
        assert!(resolve_child_name("parent", None, Some("bad/name"), false).is_err());
    }

    #[test]
    fn machine_restore_dispatches_hvf_checkpoint_away_from_firecracker() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        write_vm_full_checkpoint(&store, "hvf-parent", HVF_FRAME_BLOB);

        let error = fork_vm_full_machine(ForkVmFullMachineInput {
            checkpoint_id: "hvf-parent".to_string(),
            child_vm_name: Some("hvf-child".to_string()),
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            json: false,
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            !message.contains("Firecracker machine state"),
            "an HVF checkpoint must never enter the Firecracker arm: {message}"
        );
    }

    #[test]
    fn machine_restore_refuses_retired_backend_through_shared_dispatch() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let store = CheckpointStore::open();
        write_vm_full_checkpoint(&store, "retired-parent", SUPERVISOR_CONFIG_BLOB);

        let error = fork_vm_full_machine(ForkVmFullMachineInput {
            checkpoint_id: "retired-parent".to_string(),
            child_vm_name: Some("retired-child".to_string()),
            declared_secrets: Vec::new(),
            allow_secret_drop: false,
            json: false,
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("backend that has been removed"),
            "the shared dispatcher must preserve the retired-backend refusal: {error:#}"
        );
    }
}

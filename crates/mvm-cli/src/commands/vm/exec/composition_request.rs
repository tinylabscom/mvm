//! Run-only composition and SDK transport flags, separate from machine run.

#[cfg(feature = "pr-test-synthetic-base")]
use anyhow::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
#[cfg(feature = "pr-test-synthetic-base")]
use std::path::Path;
use std::path::PathBuf;

use super::RunProfile;
use super::{ComposeBase, RunMode, RunVerbArgs, composition};

/// The SDK transport surface, carried by `mvmctl run` alone.
///
/// These are kept out of [`super::RunArgs`] deliberately. `RunArgs` is flattened into
/// both `run` and `machine run` so a shared flag is declared exactly once;
/// `--mode`/`--dev`/`--ack-divergence` are not shared — `machine run` is the
/// beginner contract and has no business growing an SDK transport — so putting
/// them here is what lets the rest be flattened.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct SdkTransportArgs {
    /// Assemble a signed, digest-pinned pack recipe and run its entrypoint.
    #[arg(long = "compose", value_name = "PACK.TOML", conflicts_with_all = ["mode", "dev"])]
    pub compose: Option<PathBuf>,
    /// Select the locked signed default or an explicitly supplied local base.
    #[arg(long = "compose-base", value_enum, requires = "compose")]
    pub compose_base: Option<ComposeBase>,
    /// Local schema-3 image-set manifest declaring the selected kernel and tar.
    #[arg(long = "compose-base-manifest", requires_all = ["compose", "compose_base_kernel", "compose_base_tar"])]
    pub compose_base_manifest: Option<PathBuf>,
    /// Kernel declared by the local image-set manifest.
    #[arg(long = "compose-base-kernel", requires_all = ["compose", "compose_base_manifest", "compose_base_tar"])]
    pub compose_base_kernel: Option<PathBuf>,
    /// Composition tar declared by the local image-set manifest (not its ext4).
    #[arg(long = "compose-base-tar", requires_all = ["compose", "compose_base_manifest", "compose_base_kernel"])]
    pub compose_base_tar: Option<PathBuf>,
    /// Test-only, keyless-signed PR runtime quartet directory; requires local development.
    #[cfg(feature = "pr-test-guest-runtime")]
    #[arg(long = "compose-pr-test-runtime-dir", requires_all = ["compose", "compose_pr_test_pull_request"])]
    pub compose_pr_test_runtime_dir: Option<PathBuf>,
    /// Exact PR whose workflow signed the runtime input, never a release identity.
    #[cfg(feature = "pr-test-guest-runtime")]
    #[arg(long = "compose-pr-test-pull-request", requires_all = ["compose", "compose_pr_test_runtime_dir"])]
    pub compose_pr_test_pull_request: Option<u64>,
    /// SDK transport mode for `mvmctl run`.
    ///
    /// - `--mode plan`: synthesize an ExecutionPlan per Sandbox call
    ///   and route through `mvm_hostd::supervisor::admit_for_run`; no
    ///   microVM ever boots.
    /// - `--mode live`: spawn the user's script with `MVM_SDK_MODE=live`
    ///   so the SDK shells each `Sandbox` operation to existing
    ///   `mvmctl` verbs against a real microVM.
    /// - `--mode record` redirects users to `mvmctl dev compile` (where
    ///   record is the default mode).
    ///
    /// When unset, the verb behaves as a transient-sandbox runner
    /// over the trailing argv.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<RunMode>,
    /// Friendly alias for `--mode live`.
    #[arg(long = "dev", conflicts_with_all = ["prod", "mode"])]
    pub dev: bool,
    /// Acknowledge a divergence class on the plan-mode admission
    /// path (repeatable). Unacknowledged divergence refuses
    /// admission: what you previewed is not what would ship.
    #[arg(long = "ack-divergence", value_name = "KIND")]
    pub ack_divergence: Vec<String>,
}

pub(in crate::commands) fn validate_composition_request(
    machine: &crate::commands::machine::MachineRunArgs,
) -> Result<()> {
    let run = &machine.run;
    super::application_source::require_held_entrypoint_request(run)?;
    anyhow::ensure!(
        run.source.is_none()
            && run.application.is_none()
            && run.image.is_none()
            && run.manifest.is_none()
            && run.flake.is_none()
            && run.deployment.is_none()
            && run.runtime.is_none()
            && !run.runtime_pack
            && !run.prod
            && run.profile == RunProfile::Dev
            && !run.dry_run
            && run.launch_plan.is_none()
            && run.argv.is_empty()
            && !machine.interactive()
            && !machine.persistent()
            && !machine.attach,
        "--compose requires --profile dev and an unambiguous transient run without another boot source or command"
    );
    Ok(())
}

pub(super) fn prepare_composition(
    args: &mut RunVerbArgs,
) -> Result<Option<composition::PreparedComposition>> {
    let Some(path) = args.sdk.compose.take() else {
        return Ok(None);
    };
    validate_composition_request(&args.machine)?;
    #[cfg(feature = "pr-test-synthetic-base")]
    let synthetic = pr_test_base_input(
        std::env::var_os("MVM_PR_TEST_BASE_DIR"),
        std::env::var_os("MVM_PR_TEST_PULL_REQUEST"),
    )?;
    #[cfg(feature = "pr-test-synthetic-base")]
    if synthetic.is_some() {
        anyhow::ensure!(
            args.sdk.compose_base.is_none()
                && args.sdk.compose_base_manifest.is_none()
                && args.sdk.compose_base_kernel.is_none()
                && args.sdk.compose_base_tar.is_none()
                && args.machine.run.profile == RunProfile::Dev
                && !args.machine.run.prod,
            "PR synthetic base requires plain --compose and --profile dev"
        );
    }
    let base = match args.sdk.compose_base {
        Some(ComposeBase::Local) => {
            let (Some(manifest), Some(kernel), Some(tar)) = (
                args.sdk.compose_base_manifest.as_deref(),
                args.sdk.compose_base_kernel.as_deref(),
                args.sdk.compose_base_tar.as_deref(),
            ) else {
                anyhow::bail!(
                    "--compose-base local requires --compose-base-manifest, --compose-base-kernel and --compose-base-tar"
                );
            };
            #[cfg(feature = "pr-test-guest-runtime")]
            let pr_test = match (
                args.sdk.compose_pr_test_runtime_dir.as_deref(),
                args.sdk.compose_pr_test_pull_request,
            ) {
                (Some(directory), Some(pull_request)) => {
                    anyhow::ensure!(
                        pull_request > 0
                            && args.machine.run.profile == RunProfile::Dev
                            && !args.machine.run.prod,
                        "PR test runtime requires --compose-base local, --profile dev and no --prod"
                    );
                    Some(composition::PrTestInput {
                        directory,
                        pull_request,
                    })
                }
                (None, None) => None,
                _ => anyhow::bail!(
                    "PR test runtime requires both the quartet directory and pull request"
                ),
            };
            composition::Base::Local {
                manifest,
                kernel,
                tar,
                #[cfg(feature = "pr-test-guest-runtime")]
                pr_test,
            }
        }
        Some(ComposeBase::SignedDefault) | None => {
            #[cfg(feature = "pr-test-guest-runtime")]
            {
                #[cfg(feature = "pr-test-synthetic-base")]
                let synthetic_selected = synthetic.is_some();
                #[cfg(not(feature = "pr-test-synthetic-base"))]
                let synthetic_selected = false;
                if !synthetic_selected {
                    anyhow::ensure!(
                        args.sdk.compose_pr_test_runtime_dir.is_none()
                            && args.sdk.compose_pr_test_pull_request.is_none(),
                        "PR test runtime requires --compose-base local or a PR synthetic base"
                    );
                }
            }
            anyhow::ensure!(
                args.sdk.compose_base_manifest.is_none()
                    && args.sdk.compose_base_kernel.is_none()
                    && args.sdk.compose_base_tar.is_none(),
                "local base paths require --compose-base local"
            );
            composition::Base::SignedDefault
        }
    };
    #[cfg(feature = "pr-test-synthetic-base")]
    let base = if let Some(fixture) = synthetic {
        #[cfg(feature = "pr-test-guest-runtime")]
        let pr_test = pr_test_runtime_for_fixture(&args.sdk, &fixture)?;
        composition::Base::Synthetic {
            fixture,
            #[cfg(feature = "pr-test-guest-runtime")]
            pr_test,
        }
    } else {
        base
    };
    let built = composition::prepare(&path, base)?;
    args.machine.run.manifest = Some(built.archive().to_string_lossy().into_owned());
    args.machine.entrypoint = true;
    Ok(Some(built))
}

#[cfg(feature = "pr-test-synthetic-base")]
fn pr_test_base_input(
    directory: Option<std::ffi::OsString>,
    number: Option<std::ffi::OsString>,
) -> Result<Option<mvm_build::pr_test_synthetic_base::PrTestSyntheticBase>> {
    match (directory, number) {
        (None, None) => Ok(None),
        (Some(directory), Some(number)) => {
            let number = number
                .to_str()
                .context("PR synthetic base number is not UTF-8")?
                .parse::<u64>()
                .context("PR synthetic base number must be a positive integer")?;
            Ok(Some(
                mvm_build::pr_test_synthetic_base::PrTestSyntheticBase::new(
                    Path::new(&directory),
                    number,
                )?,
            ))
        }
        _ => anyhow::bail!("PR synthetic base requires both directory and pull request"),
    }
}

#[cfg(all(feature = "pr-test-synthetic-base", feature = "pr-test-guest-runtime"))]
fn pr_test_runtime_for_fixture<'a>(
    sdk: &'a SdkTransportArgs,
    fixture: &mvm_build::pr_test_synthetic_base::PrTestSyntheticBase,
) -> Result<composition::PrTestInput<'a>> {
    match (
        sdk.compose_pr_test_runtime_dir.as_deref(),
        sdk.compose_pr_test_pull_request,
    ) {
        (Some(directory), Some(pull_request)) if pull_request == fixture.pull_request() => {
            Ok(composition::PrTestInput {
                directory,
                pull_request,
            })
        }
        _ => anyhow::bail!(
            "PR synthetic base requires a PR test runtime quartet signed for the same pull request"
        ),
    }
}

#[cfg(all(test, feature = "pr-test-synthetic-base"))]
mod tests {
    use super::pr_test_base_input;

    #[test]
    fn pr_test_base_input_is_opt_in_and_refuses_partial_selection() {
        assert!(pr_test_base_input(None, None).unwrap().is_none());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().as_os_str().to_owned();
        assert!(pr_test_base_input(Some(path.clone()), None).is_err());
        assert!(pr_test_base_input(None, Some("42".into())).is_err());
        assert!(pr_test_base_input(Some(path.clone()), Some("0".into())).is_err());
        assert!(pr_test_base_input(Some(path.clone()), Some("invalid".into())).is_err());
        assert_eq!(
            pr_test_base_input(Some(path), Some("42".into()))
                .unwrap()
                .unwrap()
                .pull_request(),
            42
        );
    }

    #[cfg(feature = "pr-test-guest-runtime")]
    #[test]
    fn synthetic_base_and_pr_runtime_must_name_the_same_signed_pull_request() {
        use super::{SdkTransportArgs, pr_test_runtime_for_fixture};

        let directory = tempfile::tempdir().unwrap();
        let fixture =
            mvm_build::pr_test_synthetic_base::PrTestSyntheticBase::new(directory.path(), 42)
                .unwrap();
        let mut sdk = SdkTransportArgs::default();
        assert!(pr_test_runtime_for_fixture(&sdk, &fixture).is_err());
        sdk.compose_pr_test_runtime_dir = Some(directory.path().to_path_buf());
        sdk.compose_pr_test_pull_request = Some(43);
        assert!(pr_test_runtime_for_fixture(&sdk, &fixture).is_err());
        sdk.compose_pr_test_pull_request = Some(42);
        assert_eq!(
            pr_test_runtime_for_fixture(&sdk, &fixture)
                .unwrap()
                .pull_request,
            42
        );
    }
}

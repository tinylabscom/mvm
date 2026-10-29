//! A signed bundle's advisory resources as the launch's defaults.
//!
//! A bundle's environment descriptor records the vCPUs and memory its
//! publisher sized the workload for. A launch that names neither `--cpus` nor
//! `--memory` starts from those instead of this host's defaults; a flag the
//! user typed always wins. The values that result are ordinary launch
//! resources: admission measures them against the host's memory ceiling and
//! budget exactly as it would a typed `--memory`, and refuses rather than
//! clamps a value over the ceiling. The signature proves who sized the
//! workload; it grants nothing.

use clap::ArgMatches;
use clap::parser::ValueSource;
use mvm_core::plan::EnvironmentDescriptor;

use super::RunArgs;

/// Which resource flags the command line named, read from clap's value
/// sources after parsing. A flag set from its environment variable counts as
/// named: the user chose it, not the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::commands) struct ExplicitResources {
    pub cpus: bool,
    pub memory: bool,
}

impl ExplicitResources {
    /// What `matches` (the `run` subcommand's own matches) says was named.
    pub(in crate::commands) fn from_matches(matches: &ArgMatches) -> Self {
        let named = |id: &str| {
            matches!(
                matches.value_source(id),
                Some(ValueSource::CommandLine | ValueSource::EnvVariable)
            )
        };
        Self {
            cpus: named("cpus"),
            memory: named("memory"),
        }
    }
}

/// The defaults [`apply`] took from a descriptor, for the line that tells the
/// user where their VM's size came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct AppliedDefaults {
    pub cpus: Option<u32>,
    pub memory_mib: Option<u32>,
}

impl AppliedDefaults {
    fn is_empty(&self) -> bool {
        self.cpus.is_none() && self.memory_mib.is_none()
    }
}

/// Fill the resources `args` left at their defaults from `environment`'s
/// advisory resources. Returns what was taken, or `None` when nothing was.
pub(in crate::commands) fn apply(
    args: &mut RunArgs,
    environment: &EnvironmentDescriptor,
) -> Option<AppliedDefaults> {
    let resources = environment.resources.as_ref()?;
    let applied = AppliedDefaults {
        cpus: (!args.explicit_resources.cpus).then_some(u32::from(resources.cpu_cores)),
        memory_mib: (!args.explicit_resources.memory).then_some(resources.memory_mb),
    };
    if let Some(cpus) = applied.cpus {
        args.cpus = cpus;
    }
    if let Some(mib) = applied.memory_mib {
        args.memory = format!("{mib}M");
    }
    (!applied.is_empty()).then_some(applied)
}

/// Apply the defaults of the installed bundle `args.manifest` names, if it
/// names one carrying a descriptor, and say so on stderr.
pub(in crate::commands) fn apply_installed_bundle_defaults(
    args: &mut RunArgs,
) -> anyhow::Result<()> {
    let Some(environment) = args
        .manifest
        .as_deref()
        .map(mvm_client::admission::bundle_environment::installed_bundle_environment)
        .transpose()?
        .flatten()
    else {
        return Ok(());
    };
    if let Some(applied) = apply(args, &environment) {
        tracing::info!(
            cpus = ?applied.cpus,
            memory_mib = ?applied.memory_mib,
            "launch resources default to the bundle's signed environment descriptor"
        );
        if !args.json {
            eprintln!(
                "Using the bundle's advisory resources ({} vCPU, {}); pass --cpus / --memory to \
                 override",
                args.cpus, args.memory
            );
        }
    }
    Ok(())
}

/// Check required capabilities against the effective launch, not just the
/// publisher's posture. A declaration is a requirement, never a grant.
pub(in crate::commands) fn check_application_requirements(args: &RunArgs) -> anyhow::Result<()> {
    if args.application_policy.is_none() {
        return Ok(());
    }
    let environment = args
        .manifest
        .as_deref()
        .map(mvm_client::admission::bundle_environment::installed_bundle_environment)
        .transpose()?
        .flatten()
        .ok_or_else(|| anyhow::anyhow!("installed application has no signed environment"))?;
    check_capabilities(args, &environment)
}

fn check_capabilities(args: &RunArgs, environment: &EnvironmentDescriptor) -> anyhow::Result<()> {
    use mvm_core::plan::EnvironmentCapability;
    for capability in &environment.capabilities {
        let granted = match capability {
            EnvironmentCapability::Egress => {
                !args.allow_host.is_empty() || !args.policy_routes.is_empty()
            }
            EnvironmentCapability::HostVolumes => !args.mounts.is_empty(),
            EnvironmentCapability::InteractiveTerminal => {
                args.pty && args.profile == mvm_client::profile::RunProfile::Dev
            }
        };
        anyhow::ensure!(
            granted,
            "local policy or launch settings prevent required application capability {}; \
             select a compatible local --policy and explicit supported bindings; \
             application terminals require an explicit development package and --profile dev -it",
            capability.as_str()
        );
    }
    for required in &environment.volumes {
        let mut present = false;
        for raw in &args.mounts {
            use crate::commands::vm::shared::VolumeSpec;
            let guest = match crate::commands::vm::shared::parse_volume_spec(raw)? {
                VolumeSpec::DirShare { guest_mount, .. } => guest_mount,
                VolumeSpec::Disk { guest, .. } => guest,
            };
            present |= guest == required.guest_path;
        }
        anyhow::ensure!(
            present,
            "required application volume {} at {} has no binding; supply an explicitly \
             authorized --mount for that guest path",
            required.name,
            required.guest_path
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(resources: Option<(u16, u32)>) -> EnvironmentDescriptor {
        let mut value = serde_json::json!({
            "descriptor_version": 1,
            "target": "x86_64-linux",
            "entrypoint": { "argv": ["/bin/app"] },
        });
        if let Some((cpu_cores, memory_mb)) = resources {
            value["resources"] =
                serde_json::json!({ "cpu_cores": cpu_cores, "memory_mb": memory_mb });
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn unnamed_flags_take_the_descriptor_resources() {
        let mut args = RunArgs::default();
        let applied = apply(&mut args, &environment(Some((3, 1536)))).expect("applied");
        assert_eq!(args.cpus, 3);
        assert_eq!(args.memory, "1536M");
        assert_eq!(
            mvm_core::util::parse_human_size(&args.memory).unwrap(),
            1536
        );
        assert_eq!(applied.cpus, Some(3));
        assert_eq!(applied.memory_mib, Some(1536));
    }

    #[test]
    fn a_named_flag_wins_over_the_descriptor() {
        let mut args = RunArgs {
            cpus: 8,
            memory: "4G".to_string(),
            explicit_resources: ExplicitResources {
                cpus: true,
                memory: false,
            },
            ..RunArgs::default()
        };
        apply(&mut args, &environment(Some((2, 1024)))).expect("memory applied");
        assert_eq!(args.cpus, 8, "--cpus was typed");
        assert_eq!(args.memory, "1024M");

        args.explicit_resources.memory = true;
        args.memory = "4G".to_string();
        assert_eq!(apply(&mut args, &environment(Some((2, 1024)))), None);
        assert_eq!(args.memory, "4G");
    }

    #[test]
    fn a_descriptor_without_resources_changes_nothing() {
        let mut args = RunArgs::default();
        let before = (args.cpus, args.memory.clone());
        assert_eq!(apply(&mut args, &environment(None)), None);
        assert_eq!((args.cpus, args.memory), before);
    }

    #[test]
    fn a_required_capability_is_not_an_automatic_grant() {
        let mut environment = environment(None);
        environment.capabilities = vec![mvm_core::plan::EnvironmentCapability::Egress];
        let mut args = RunArgs::default();
        assert!(
            check_capabilities(&args, &environment)
                .unwrap_err()
                .to_string()
                .contains("required application capability egress")
        );
        args.allow_host.push("api.example.test:443".into());
        check_capabilities(&args, &environment).unwrap();
        environment.capabilities = vec![mvm_core::plan::EnvironmentCapability::InteractiveTerminal];
        assert!(check_capabilities(&args, &environment).is_err());
    }

    #[test]
    fn a_volume_requirement_needs_the_declared_guest_path() {
        let mut environment = environment(None);
        environment.volumes = vec![mvm_contract::plan::environment::EnvironmentVolume {
            name: "workspace".into(),
            guest_path: "/work".into(),
        }];
        let mut args = RunArgs::default();
        args.mounts.push("/tmp/input:/other:ro".into());
        assert!(
            check_capabilities(&args, &environment)
                .unwrap_err()
                .to_string()
                .contains("workspace at /work has no binding")
        );
        args.mounts = vec!["/tmp/input:/work:ro".into()];
        check_capabilities(&args, &environment).unwrap();
    }

    #[test]
    fn value_sources_tell_typed_flags_from_defaults() {
        let command = clap::Command::new("run")
            .arg(clap::Arg::new("cpus").long("cpus").default_value("2"))
            .arg(
                clap::Arg::new("memory")
                    .long("memory")
                    .default_value("512M"),
            );
        let typed = command
            .clone()
            .try_get_matches_from(["run", "--cpus", "4"])
            .unwrap();
        assert_eq!(
            ExplicitResources::from_matches(&typed),
            ExplicitResources {
                cpus: true,
                memory: false
            }
        );
        let bare = command.try_get_matches_from(["run"]).unwrap();
        assert_eq!(
            ExplicitResources::from_matches(&bare),
            ExplicitResources::default()
        );
    }
}

//! A signed bundle's recorded sizing as the launch's defaults.
//!
//! A bundle records the vCPUs and memory its publisher sized the workload for,
//! in its environment descriptor and in its manifest's resources. A launch that
//! names neither `--cpus` nor `--memory` starts from those instead of this
//! host's defaults; a flag the user typed always wins. The values are defaults,
//! not grants. The descriptor's are taken as recorded and refused at admission
//! when over a ceiling. The manifest's memory is capped at the host's
//! per-workload ceiling and the headroom left in its host-wide budget, and a
//! cap that lowers it is recorded on the plan's `plan.admitted` labels. vCPUs
//! are not capped: the host's CPU bounds are millicore shares, not a count.

use clap::ArgMatches;
use clap::parser::ValueSource;
use mvm_client::admission::bundle_resources::{
    AppliedSizing, NamedSizing, SizingDefaults, memory_cap_mib, seed,
};

use super::RunArgs;

/// Which resource flags the command line named, read from clap's value
/// sources after parsing. A flag set from its environment variable counts as
/// named: the user chose it, not the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::commands) struct ExplicitResources {
    pub cpus: bool,
    pub memory: bool,
    /// What the launch took from its bundle's manifest sizing; not a flag.
    pub bundle: AppliedSizing,
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
            bundle: AppliedSizing::default(),
        }
    }
}

/// What an installed bundle records, by where it records it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::commands) struct RecordedSizing {
    /// The signed environment descriptor's resources. Taken as before: a value
    /// over a host ceiling is refused at admission, never lowered.
    pub descriptor: SizingDefaults,
    /// The manifest's resources. Memory is capped and a cap is recorded.
    pub manifest: SizingDefaults,
}

/// Fill the resources `args` left at their defaults: the descriptor's first,
/// then the manifest's for what the descriptor did not record, with the
/// manifest's memory capped at `cap`. Returns whether anything was taken. Only
/// the manifest's share is kept in `args.explicit_resources.bundle` for the audit labels.
pub(in crate::commands) fn apply(
    args: &mut RunArgs,
    recorded: RecordedSizing,
    cap: Option<u64>,
) -> bool {
    let mut named = NamedSizing {
        cpus: args.explicit_resources.cpus,
        memory: args.explicit_resources.memory,
    };
    let from_descriptor = seed(recorded.descriptor, named, None);
    named.cpus |= from_descriptor.cpus.is_some();
    named.memory |= from_descriptor.memory_mib.is_some();
    let from_manifest = seed(recorded.manifest, named, cap);
    for applied in [from_descriptor, from_manifest] {
        if let Some(cpus) = applied.cpus {
            args.cpus = cpus;
        }
        if let Some(mib) = applied.memory_mib {
            args.memory = format!("{mib}M");
        }
    }
    args.explicit_resources.bundle = from_manifest;
    !(from_descriptor.is_empty() && from_manifest.is_empty())
}

/// What the installed bundle `key` records.
pub(in crate::commands) fn installed_bundle_sizing(key: &str) -> anyhow::Result<RecordedSizing> {
    use mvm_client::admission::bundle_environment as installed;
    Ok(RecordedSizing {
        descriptor: installed::installed_bundle_environment(key)?
            .map(|environment| SizingDefaults::from_environment(&environment))
            .unwrap_or_default(),
        manifest: installed::installed_bundle_resources(key)?
            .map(|resources| SizingDefaults::from_manifest(&resources))
            .unwrap_or_default(),
    })
}

/// What this host lets a defaulted memory size take, read from its own config.
fn host_memory_cap() -> Option<u64> {
    let config = mvm_core::user_config::load(None);
    memory_cap_mib(
        &config.grant_ceiling(),
        &config.host_budget(),
        mvm_hostd::admission_budget::committed().memory_mib,
    )
}

/// Apply the defaults of the installed bundle `key` names, if it records any,
/// and say so on stderr.
pub(in crate::commands) fn apply_bundle_defaults(
    args: &mut RunArgs,
    key: &str,
) -> anyhow::Result<()> {
    let defaults = installed_bundle_sizing(key)?;
    if !apply(args, defaults, host_memory_cap()) {
        return Ok(());
    }
    let applied = args.explicit_resources.bundle;
    tracing::info!(
        cpus = ?applied.cpus,
        memory_mib = ?applied.memory_mib,
        memory_requested_mib = ?applied.memory_requested_mib,
        "launch resources default to the bundle's recorded sizing"
    );
    if !args.json {
        eprintln!(
            "Using the bundle's recorded sizing ({} vCPU, {}); pass --cpus / --memory to \
             override",
            args.cpus, args.memory
        );
        if let Some(requested) = applied.memory_requested_mib {
            eprintln!(
                "The bundle asked for {requested} MiB; this host's limits lowered it to {}",
                args.memory
            );
        }
    }
    Ok(())
}

/// Apply the defaults of the installed bundle `args.manifest` names, if it
/// names one.
pub(in crate::commands) fn apply_installed_bundle_defaults(
    args: &mut RunArgs,
) -> anyhow::Result<()> {
    match args.manifest.clone() {
        Some(key) => apply_bundle_defaults(args, &key),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sizing(cpus: u32, memory_mib: u32) -> SizingDefaults {
        SizingDefaults {
            cpus: Some(cpus),
            memory_mib: Some(memory_mib),
        }
    }

    fn manifest_only(cpus: u32, memory_mib: u32) -> RecordedSizing {
        RecordedSizing {
            descriptor: SizingDefaults::default(),
            manifest: sizing(cpus, memory_mib),
        }
    }

    #[test]
    fn unnamed_flags_take_the_manifest_sizing() {
        let mut args = RunArgs::default();
        assert!(apply(&mut args, manifest_only(3, 1536), None));
        assert_eq!(args.cpus, 3);
        assert_eq!(args.memory, "1536M");
        assert_eq!(
            mvm_core::util::parse_human_size(&args.memory).unwrap(),
            1536
        );
        assert_eq!(args.explicit_resources.bundle.memory_mib, Some(1536));
    }

    #[test]
    fn a_bundle_size_wins_over_a_smaller_unnamed_default() {
        // A smaller built-in default is still a default, not a typed value.
        let mut args = RunArgs {
            cpus: 1,
            memory: "128M".to_string(),
            ..RunArgs::default()
        };
        assert!(apply(&mut args, manifest_only(2, 512), None));
        assert_eq!((args.cpus, args.memory.as_str()), (2, "512M"));
    }

    #[test]
    fn a_named_flag_wins_over_the_manifest_sizing() {
        let mut args = RunArgs {
            cpus: 8,
            memory: "4G".to_string(),
            explicit_resources: ExplicitResources {
                cpus: true,
                memory: false,
                ..Default::default()
            },
            ..RunArgs::default()
        };
        assert!(apply(&mut args, manifest_only(2, 1024), None));
        assert_eq!(args.cpus, 8, "--cpus was typed");
        assert_eq!(args.memory, "1024M");

        args.explicit_resources.memory = true;
        args.memory = "4G".to_string();
        assert!(!apply(&mut args, manifest_only(2, 1024), None));
        assert_eq!(args.memory, "4G");
        assert!(args.explicit_resources.bundle.is_empty());
    }

    #[test]
    fn a_ceiling_lowers_the_manifest_default_and_records_both_figures() {
        let mut args = RunArgs::default();
        assert!(apply(&mut args, manifest_only(2, 4096), Some(1024)));
        assert_eq!(args.memory, "1024M");
        assert_eq!(
            args.explicit_resources.bundle.memory_requested_mib,
            Some(4096)
        );
        let labels = args.explicit_resources.bundle.audit_labels();
        assert_eq!(labels["sizing_memory_requested_mib"], "4096");
        assert_eq!(labels["sizing_memory_mib"], "1024");
        assert_eq!(labels["sizing_clamped"], "true");
    }

    #[test]
    fn a_typed_value_over_the_ceiling_is_not_capped_here() {
        let mut args = RunArgs {
            memory: "4G".to_string(),
            explicit_resources: ExplicitResources {
                cpus: false,
                memory: true,
                ..Default::default()
            },
            ..RunArgs::default()
        };
        apply(&mut args, manifest_only(2, 4096), Some(1024));
        assert_eq!(args.memory, "4G", "admission refuses it, as before");
    }

    #[test]
    fn descriptor_resources_are_never_capped_and_win_per_dimension() {
        let mut args = RunArgs::default();
        let recorded = RecordedSizing {
            descriptor: SizingDefaults {
                cpus: None,
                memory_mib: Some(4096),
            },
            manifest: sizing(6, 512),
        };
        assert!(apply(&mut args, recorded, Some(1024)));
        assert_eq!(args.memory, "4096M", "left for admission to refuse");
        assert_eq!(args.cpus, 6, "the manifest fills what the descriptor left");
        assert!(
            args.explicit_resources.bundle.memory_mib.is_none(),
            "no manifest memory was taken, so nothing is labelled"
        );
    }

    #[test]
    fn a_bundle_recording_no_sizing_changes_nothing() {
        let mut args = RunArgs::default();
        let before = (args.cpus, args.memory.clone());
        assert!(!apply(&mut args, RecordedSizing::default(), Some(1)));
        assert_eq!((args.cpus, args.memory.clone()), before);
        assert!(args.explicit_resources.bundle.audit_labels().is_empty());
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
                memory: false,
                ..Default::default()
            }
        );
        let bare = command.try_get_matches_from(["run"]).unwrap();
        assert_eq!(
            ExplicitResources::from_matches(&bare),
            ExplicitResources::default()
        );
    }
}

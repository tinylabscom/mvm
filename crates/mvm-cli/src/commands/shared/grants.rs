//! Where the CLI's grant surfaces meet: flags, a JSON grants file, the
//! project manifest, and the operator's host config are folded into one
//! permission set, and the egress policy the gate enforces is derived from it
//! in the same step.
//!
//! Resolving the grants and deriving the policy together is deliberate. Two
//! separate calls could be made in one order here and the other order there,
//! and then the enforced policy would depend on which call site a launch went
//! through. One function, one answer.

use anyhow::{Context, Result};
use std::path::Path;

use mvm_contract::grants::{CpuGrant, EgressGrant, Grants, WallClockGrant};
use mvm_core::grants_resolve::{
    GrantLayer, GrantProvenance, GrantSurface, load_grants_file, resolve_grants,
};
use mvm_core::network_policy::{AiPolicy, NetworkPolicy};
use mvm_core::user_config::MvmConfig;

/// The grant-authoring flags of one invocation, plus the lower surfaces it
/// should fall back to. Grouped rather than passed positionally because they
/// are one decision's inputs and threading six arguments through the CLI would
/// invite a caller to swap two of them.
pub(in crate::commands) struct GrantInputs<'a> {
    /// `--cpu-limit`: the share of host CPU time, in millicores. Distinct from
    /// `--cpus`, which is the vCPU count the guest sees.
    pub cpu_limit_millicores: Option<u32>,
    /// `--timeout`: the wall-clock bound on the run, in seconds.
    pub timeout_secs: Option<u64>,
    /// `--allow-host`: the CLI's egress allow-list, in `HOST[:PORT]` form.
    pub allow_host: &'a [String],
    /// `--net`: the dev-tier preset. It has no grant representation — it names
    /// a preset rather than destinations — so it only reaches the policy when
    /// nothing authored an egress grant.
    pub net: bool,
    /// `--grants-file`: a JSON document naming any subset of the dimensions.
    pub grants_file: Option<&'a Path>,
    /// The project manifest's `[grants]` table, already typed.
    pub manifest: Option<&'a Grants>,
    /// The operator's host config, for the dimensions nothing above named.
    pub config: &'a MvmConfig,
    /// Optional AI egress metering/budget policy, usually from the
    /// project manifest's `[network.ai]` table.
    pub ai: Option<&'a AiPolicy>,
}

/// One invocation's resolved permission set and the egress policy that follows
/// from it.
#[derive(Debug, Clone, PartialEq)]
pub(in crate::commands) struct RunGrants {
    /// What the signed plan carries. `None` when no surface authored anything.
    pub plan_grants: Option<Grants>,
    /// What the egress gate enforces for this run.
    pub network_policy: NetworkPolicy,
    /// Which surface won each dimension, for diagnostics.
    pub provenance: GrantProvenance,
}

/// Fold every surface, highest precedence first, and derive the egress policy.
///
/// Precedence is per dimension: a `--cpu-limit` on the command line does not
/// discard an egress allow-list the manifest declared.
pub(in crate::commands) fn resolve_run_grants(inputs: GrantInputs<'_>) -> Result<RunGrants> {
    let cli = cli_layer(&inputs)?;
    let file = match inputs.grants_file {
        Some(path) => load_grants_file(path)?,
        None => Grants::default(),
    };

    let mut layers = vec![
        GrantLayer::new(GrantSurface::Cli, cli),
        GrantLayer::new(GrantSurface::GrantsFile, file),
    ];
    if let Some(manifest) = inputs.manifest {
        layers.push(GrantLayer::new(GrantSurface::Manifest, manifest.clone()));
    }
    layers.push(GrantLayer::new(
        GrantSurface::HostConfig,
        inputs.config.default_grants(),
    ));

    let resolved = resolve_grants(&layers);
    let provenance = *resolved.provenance();
    let plan_grants = resolved.into_plan_grants();
    if let Some(grants) = plan_grants.as_ref() {
        refuse_over_ceiling(grants, &provenance, inputs.config)?;
    }
    let network_policy = enforced_network_policy(
        plan_grants.as_ref().and_then(|g| g.egress.as_ref()),
        inputs.net,
        inputs.allow_host,
    )?
    .with_ai(inputs.ai.cloned());
    Ok(RunGrants {
        plan_grants,
        network_policy,
        provenance,
    })
}

/// Refuse a resolved grant this host's ceiling will not admit, naming the
/// surface that asked for it.
///
/// Admission runs the same ceiling against host config it reads itself, and
/// that check is the authoritative one — nothing here can be skipped to get
/// past it. What this adds is the one fact only the resolver holds: with four
/// places a grant can come from, "this host allows at most 1000" leaves the
/// user to guess which of them to edit, and the provenance says which.
fn refuse_over_ceiling(
    grants: &Grants,
    provenance: &GrantProvenance,
    config: &MvmConfig,
) -> Result<()> {
    let Err(violation) = config.grant_ceiling().admits_grants(grants) else {
        return Ok(());
    };
    let source = match provenance.surface_for_dimension(violation.dimension) {
        Some(surface) => format!(", asked for by the {} surface", surface.as_str()),
        None => String::new(),
    };
    anyhow::bail!(
        "grant exceeds this host's ceiling: {dimension} requested {requested}, host allows \
         at most {ceiling}{source}",
        dimension = violation.dimension,
        requested = violation.requested,
        ceiling = violation.ceiling,
    )
}

/// The egress policy a run enforces.
///
/// Takes the egress dimension rather than the whole permission set because
/// that dimension is all the projection reads; nothing else about a grant
/// bears on where a workload may connect.
///
/// A granted allow-list is projected — that projection is the only permitted
/// derivation of egress policy from a grant. With no egress grant the legacy
/// `--net` / `--allow-host` resolution stands, which is deny-all unless the
/// caller asked for something.
pub(in crate::commands) fn enforced_network_policy(
    egress: Option<&EgressGrant>,
    net: bool,
    allow_host: &[String],
) -> Result<NetworkPolicy> {
    match egress {
        Some(egress) => Ok(
            mvm_contract::grants::projection::network_policy_from_grants(&Grants {
                egress: Some(egress.clone()),
                ..Default::default()
            }),
        ),
        None => super::resolve_run_network_policy(net, allow_host),
    }
}

/// The command line's own contribution.
fn cli_layer(inputs: &GrantInputs<'_>) -> Result<Grants> {
    let cpu = match inputs.cpu_limit_millicores {
        None => None,
        Some(0) => anyhow::bail!(
            "--cpu-limit must be > 0 millicores; omit it to leave CPU uncapped \
             (--cpu-limit bounds the share of host CPU time, --cpus sets the vCPU count)"
        ),
        Some(millicores) => Some(CpuGrant::Share { millicores }),
    };

    let wall_clock = match inputs.timeout_secs {
        None | Some(0) => None,
        Some(secs) => {
            let secs = u32::try_from(secs)
                .ok()
                .and_then(std::num::NonZeroU32::new)
                .with_context(|| format!("--timeout {secs} does not fit a wall-clock grant"))?;
            Some(WallClockGrant::Secs { secs })
        }
    };

    let egress = if inputs.allow_host.is_empty() {
        None
    } else {
        // Reuse the one `--allow-host` parser so the granted allow-list and the
        // legacy policy path agree on what `HOST` without a port means, and on
        // which ports are refused outright.
        let policy = super::resolve_run_network_policy(false, inputs.allow_host)?;
        Some(EgressGrant {
            allow: policy.resolve_rules().unwrap_or_default(),
        })
    };

    Ok(Grants {
        cpu,
        wall_clock,
        egress,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::HostPort;

    fn inputs<'a>(config: &'a MvmConfig, allow_host: &'a [String]) -> GrantInputs<'a> {
        GrantInputs {
            cpu_limit_millicores: None,
            timeout_secs: None,
            allow_host,
            net: false,
            grants_file: None,
            manifest: None,
            config,
            ai: None,
        }
    }

    #[test]
    fn no_surface_authors_anything_and_the_plan_stays_grant_free() {
        let cfg = MvmConfig::default();
        let resolved = resolve_run_grants(inputs(&cfg, &[])).expect("resolves");
        assert_eq!(resolved.plan_grants, None);
        assert_eq!(
            resolved.network_policy.resolve_rules().as_deref(),
            Some(&[][..]),
            "no grant and no flags is deny-all"
        );
    }

    #[test]
    fn ai_policy_from_input_is_attached_to_network_policy() {
        let cfg = MvmConfig::default();
        let ai = AiPolicy::metered_with_total_budget(100_000);
        let resolved = resolve_run_grants(GrantInputs {
            ai: Some(&ai),
            ..inputs(&cfg, &[])
        })
        .expect("resolves");
        assert_eq!(
            resolved.network_policy.ai(),
            Some(&ai),
            "the input AI policy must ride through to the enforced network policy"
        );
    }

    #[test]
    fn cli_overrides_the_manifest_per_dimension_not_wholesale() {
        // The CLI caps CPU; the manifest declared egress. Both must survive —
        // whole-object precedence would drop the allow-list silently.
        let cfg = MvmConfig::default();
        let manifest = Grants {
            egress: Some(EgressGrant {
                allow: vec![HostPort::new("api.example.com", 443)],
            }),
            ..Default::default()
        };
        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: Some(500),
            manifest: Some(&manifest),
            ..inputs(&cfg, &[])
        })
        .expect("resolves");

        let grants = resolved.plan_grants.expect("something was authored");
        assert_eq!(grants.cpu, Some(CpuGrant::Share { millicores: 500 }));
        assert_eq!(
            grants.egress.as_ref().map(|e| e.allow.as_slice()),
            Some(&[HostPort::new("api.example.com", 443)][..]),
            "the manifest's allow-list must survive a CLI CPU cap"
        );
        assert_eq!(resolved.provenance.cpu, Some(GrantSurface::Cli));
        assert_eq!(resolved.provenance.egress, Some(GrantSurface::Manifest));
    }

    #[test]
    fn a_manifest_egress_grant_is_what_the_gate_enforces() {
        let cfg = MvmConfig::default();
        let manifest = Grants {
            egress: Some(EgressGrant {
                allow: vec![HostPort::new("api.example.com", 443)],
            }),
            ..Default::default()
        };
        // `--net` would otherwise select the broad dev preset; the granted
        // allow-list is narrower and is what the gate gets.
        let resolved = resolve_run_grants(GrantInputs {
            net: true,
            manifest: Some(&manifest),
            ..inputs(&cfg, &[])
        })
        .expect("resolves");

        let rules = resolved
            .network_policy
            .resolve_rules()
            .expect("an allow-list resolves to rules");
        assert_eq!(rules, vec![HostPort::new("api.example.com", 443)]);
        assert!(!resolved.network_policy.is_unrestricted());
    }

    #[test]
    fn an_empty_manifest_allow_list_is_not_an_egress_grant() {
        // An empty `[grants]` egress must not shadow `--net`: nothing was
        // granted, so the legacy resolution still applies. (Had it been an
        // explicit empty allow-list, the projection would deny all — also
        // closed, but a different answer, and the manifest cannot express it.)
        let cfg = MvmConfig::default();
        let manifest = Grants::default();
        let resolved = resolve_run_grants(GrantInputs {
            net: true,
            manifest: Some(&manifest),
            ..inputs(&cfg, &[])
        })
        .expect("resolves");
        assert!(
            !resolved
                .network_policy
                .resolve_rules()
                .unwrap_or_default()
                .is_empty(),
            "--net still selects the dev preset when nothing granted egress"
        );
    }

    #[test]
    fn the_cli_allow_host_flag_becomes_a_granted_allow_list() {
        let cfg = MvmConfig::default();
        let allow = vec![
            "api.example.com".to_string(),
            "db.internal:5432".to_string(),
        ];
        let resolved = resolve_run_grants(inputs(&cfg, &allow)).expect("resolves");
        let grants = resolved.plan_grants.expect("egress authored");
        assert_eq!(
            grants.egress.expect("egress").allow,
            vec![
                HostPort::new("api.example.com", 443),
                HostPort::new("db.internal", 5432),
            ],
            "a bare host defaults to 443, matching the legacy parser"
        );
    }

    #[test]
    fn a_zero_cpu_limit_is_refused_rather_than_read_as_uncapped() {
        let cfg = MvmConfig::default();
        let err = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: Some(0),
            ..inputs(&cfg, &[])
        })
        .expect_err("zero millicores is not a bound");
        assert!(format!("{err:#}").contains("--cpu-limit"));
    }

    #[test]
    fn host_config_defaults_fill_only_unnamed_dimensions() {
        let cfg = MvmConfig {
            default_cpu_millicores: Some(2000),
            ..MvmConfig::default()
        };
        let resolved = resolve_run_grants(inputs(&cfg, &[])).expect("resolves");
        assert_eq!(
            resolved.plan_grants.and_then(|g| g.cpu),
            Some(CpuGrant::Share { millicores: 2000 })
        );
        assert_eq!(resolved.provenance.cpu, Some(GrantSurface::HostConfig));

        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: Some(500),
            ..inputs(&cfg, &[])
        })
        .expect("resolves");
        assert_eq!(
            resolved.plan_grants.and_then(|g| g.cpu),
            Some(CpuGrant::Share { millicores: 500 })
        );
    }

    #[test]
    fn an_unknown_grants_file_field_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("grants.json");
        std::fs::write(&path, r#"{"cpu_limt":{"unit":"share","millicores":1500}}"#).expect("write");
        let cfg = MvmConfig::default();
        let err = resolve_run_grants(GrantInputs {
            grants_file: Some(&path),
            ..inputs(&cfg, &[])
        })
        .expect_err("a misspelled key must refuse the run");
        assert!(format!("{err:#}").contains("unknown field"));
    }

    #[test]
    fn the_grants_file_loses_a_contested_dimension_to_the_cli() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("grants.json");
        std::fs::write(
            &path,
            r#"{"cpu":{"unit":"share","millicores":4000},
                "egress":{"allow":[{"host":"api.example.com","port":443}]}}"#,
        )
        .expect("write");
        let cfg = MvmConfig::default();
        let resolved = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: Some(500),
            grants_file: Some(&path),
            ..inputs(&cfg, &[])
        })
        .expect("resolves");
        let grants = resolved.plan_grants.expect("authored");
        assert_eq!(grants.cpu, Some(CpuGrant::Share { millicores: 500 }));
        assert_eq!(
            grants.egress.map(|e| e.allow),
            Some(vec![HostPort::new("api.example.com", 443)]),
            "the file's egress survives a CLI CPU cap"
        );
    }

    #[test]
    fn a_timeout_becomes_a_wall_clock_grant() {
        let cfg = MvmConfig::default();
        let resolved = resolve_run_grants(GrantInputs {
            timeout_secs: Some(600),
            ..inputs(&cfg, &[])
        })
        .expect("resolves");
        assert_eq!(
            resolved.plan_grants.and_then(|g| g.wall_clock),
            Some(WallClockGrant::Secs {
                secs: std::num::NonZeroU32::new(600).expect("nonzero")
            })
        );
    }
}

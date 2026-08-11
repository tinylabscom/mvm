//! Per-dimension resolution of a workload's [`Grants`] across the surfaces
//! that may author one.
//!
//! **Per dimension, not per object.** A CLI flag that sets a CPU share must not
//! discard an egress allow-list the project's manifest declared: the two are
//! independent decisions that happen to share a struct. Whole-object precedence
//! would drop the allow-list silently, and the symptom would surface much later
//! as "my allow-list stopped applying".
//!
//! A higher surface may *loosen* a lower one. The manifest is a project
//! default and the command line belongs to the developer running it, so there
//! is no monotonic-narrowing rule between surfaces. What bounds the outcome is
//! the ceiling, which no surface here can reach — it is read at admission from
//! host configuration, never from anything resolved in this module.

use std::path::Path;

use anyhow::{Context, Result};
use mvm_contract::grants::Grants;

/// A surface that may author a grant, named so a resolved dimension can say
/// where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantSurface {
    /// Command-line flags on the invocation.
    Cli,
    /// A JSON document named by `--grants-file`.
    GrantsFile,
    /// The `[grants]` table of the project's `mvm.toml` / `Mvmfile.toml`.
    Manifest,
    /// The operator's `~/.mvm/config/config.toml` defaults.
    HostConfig,
}

impl GrantSurface {
    /// Operator-facing name, for diagnostics and audit labels.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::GrantsFile => "grants-file",
            Self::Manifest => "manifest",
            Self::HostConfig => "host-config",
        }
    }
}

/// One surface's contribution. Every dimension of `grants` is optional, and an
/// absent dimension means "this surface said nothing about it" — which is what
/// lets a lower surface supply it.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantLayer {
    pub surface: GrantSurface,
    pub grants: Grants,
}

impl GrantLayer {
    #[must_use]
    pub fn new(surface: GrantSurface, grants: Grants) -> Self {
        Self { surface, grants }
    }
}

/// Which surface won each dimension. Carried alongside the resolution so a
/// refusal can name the surface that asked for the refused thing, rather than
/// leaving the user to guess which of four places to edit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GrantProvenance {
    pub cpu: Option<GrantSurface>,
    pub wall_clock: Option<GrantSurface>,
    pub egress: Option<GrantSurface>,
}

impl GrantProvenance {
    /// The surface that authored the dimension a ceiling violation names.
    ///
    /// Takes the violation's own dotted path (`cpu.share_millicores`,
    /// `wall_clock.secs`) rather than a bare dimension name, so a caller can
    /// hand the refusal straight through without translating it. A path naming
    /// something no surface authors — `memory_mib`, which is sized rather than
    /// granted — yields `None`.
    #[must_use]
    pub fn surface_for_dimension(&self, dimension: &str) -> Option<GrantSurface> {
        match dimension.split('.').next()? {
            "cpu" => self.cpu,
            "wall_clock" => self.wall_clock,
            "egress" => self.egress,
            _ => None,
        }
    }
}

/// The outcome of resolving every surface.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedGrants {
    grants: Grants,
    provenance: GrantProvenance,
}

impl ResolvedGrants {
    /// The resolved permission set.
    #[must_use]
    pub fn grants(&self) -> &Grants {
        &self.grants
    }

    /// Which surface supplied each resolved dimension.
    #[must_use]
    pub fn provenance(&self) -> &GrantProvenance {
        &self.provenance
    }

    /// True when no surface authored anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants == Grants::default()
    }

    /// What the plan should carry: `None` when nothing was authored, so a run
    /// with no grants keeps producing exactly the plan it produced before this
    /// resolver existed rather than an empty-but-present grant object.
    #[must_use]
    pub fn into_plan_grants(self) -> Option<Grants> {
        if self.is_empty() {
            None
        } else {
            Some(self.grants)
        }
    }
}

/// Resolve `layers` — highest precedence first — one dimension at a time.
///
/// The first layer that names a dimension wins it. Layers below still supply
/// the dimensions the winner left unset, which is the whole point: an
/// invocation that caps CPU on the command line keeps the manifest's egress
/// allow-list.
#[must_use]
pub fn resolve_grants(layers: &[GrantLayer]) -> ResolvedGrants {
    let mut resolved = ResolvedGrants::default();
    for layer in layers {
        if resolved.grants.cpu.is_none()
            && let Some(cpu) = layer.grants.cpu
        {
            resolved.grants.cpu = Some(cpu);
            resolved.provenance.cpu = Some(layer.surface);
        }
        if resolved.grants.wall_clock.is_none()
            && let Some(wall_clock) = layer.grants.wall_clock
        {
            resolved.grants.wall_clock = Some(wall_clock);
            resolved.provenance.wall_clock = Some(layer.surface);
        }
        if resolved.grants.egress.is_none()
            && let Some(egress) = layer.grants.egress.as_ref()
        {
            resolved.grants.egress = Some(egress.clone());
            resolved.provenance.egress = Some(layer.surface);
        }
    }
    resolved
}

/// Read a `--grants-file`.
///
/// The document deserializes into [`Grants`] directly, which carries
/// `deny_unknown_fields`: a misspelled key is a refusal, never a silently
/// dropped cap. A cap the user believes is in force and is not is strictly
/// worse than no cap at all, because it is believed.
pub fn load_grants_file(path: &Path) -> Result<Grants> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading grants file {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing grants file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU32;
    use mvm_contract::grants::{CpuGrant, EgressGrant, WallClockGrant};
    use mvm_contract::policy::network_policy::HostPort;

    fn cpu(millicores: u32) -> Grants {
        Grants {
            cpu: Some(CpuGrant::Share { millicores }),
            ..Default::default()
        }
    }

    fn egress(host: &str, port: u16) -> Grants {
        Grants {
            egress: Some(EgressGrant {
                allow: vec![HostPort::new(host, port)],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn nothing_authored_resolves_to_no_plan_grants() {
        let resolved = resolve_grants(&[]);
        assert!(resolved.is_empty());
        assert_eq!(resolved.into_plan_grants(), None);
    }

    #[test]
    fn the_highest_surface_wins_a_contested_dimension() {
        let resolved = resolve_grants(&[
            GrantLayer::new(GrantSurface::Cli, cpu(500)),
            GrantLayer::new(GrantSurface::Manifest, cpu(4000)),
        ]);
        assert_eq!(
            resolved.grants().cpu,
            Some(CpuGrant::Share { millicores: 500 })
        );
        assert_eq!(resolved.provenance().cpu, Some(GrantSurface::Cli));
    }

    #[test]
    fn a_cli_cpu_grant_does_not_discard_a_manifest_egress_grant() {
        // The defect this resolver exists to prevent: whole-object precedence
        // would drop the allow-list the manifest declared.
        let resolved = resolve_grants(&[
            GrantLayer::new(GrantSurface::Cli, cpu(500)),
            GrantLayer::new(GrantSurface::Manifest, egress("api.example.com", 443)),
        ]);
        assert_eq!(
            resolved.grants().cpu,
            Some(CpuGrant::Share { millicores: 500 })
        );
        assert_eq!(
            resolved
                .grants()
                .egress
                .as_ref()
                .map(|e| e.allow.as_slice()),
            Some(&[HostPort::new("api.example.com", 443)][..])
        );
        assert_eq!(resolved.provenance().egress, Some(GrantSurface::Manifest));
    }

    #[test]
    fn a_higher_surface_may_loosen_a_lower_one() {
        // The manifest is a project default; the command line belongs to the
        // developer running it. Only the ceiling bounds the outcome.
        let resolved = resolve_grants(&[
            GrantLayer::new(GrantSurface::Cli, cpu(8000)),
            GrantLayer::new(GrantSurface::Manifest, cpu(500)),
        ]);
        assert_eq!(
            resolved.grants().cpu,
            Some(CpuGrant::Share { millicores: 8000 })
        );
    }

    #[test]
    fn host_config_supplies_only_what_nothing_above_it_set() {
        let wall = Grants {
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(60).expect("nonzero"),
            }),
            ..Default::default()
        };
        let resolved = resolve_grants(&[
            GrantLayer::new(GrantSurface::Cli, cpu(500)),
            GrantLayer::new(GrantSurface::HostConfig, wall),
        ]);
        assert_eq!(resolved.provenance().cpu, Some(GrantSurface::Cli));
        assert_eq!(
            resolved.provenance().wall_clock,
            Some(GrantSurface::HostConfig)
        );
        assert_eq!(resolved.provenance().egress, None);
    }

    #[test]
    fn a_ceiling_violations_dimension_resolves_to_its_authoring_surface() {
        // The violation's dotted path is what a refusal has in hand, so that is
        // what the lookup has to accept.
        let provenance = GrantProvenance {
            cpu: Some(GrantSurface::Manifest),
            wall_clock: Some(GrantSurface::Cli),
            egress: None,
        };
        assert_eq!(
            provenance.surface_for_dimension("cpu.share_millicores"),
            Some(GrantSurface::Manifest)
        );
        assert_eq!(
            provenance.surface_for_dimension("wall_clock.secs"),
            Some(GrantSurface::Cli)
        );
        // Memory is sized, not granted, so no surface authored it.
        assert_eq!(provenance.surface_for_dimension("memory_mib"), None);
        assert_eq!(provenance.surface_for_dimension("egress"), None);
    }

    #[test]
    fn an_unknown_grants_file_field_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("grants.json");
        std::fs::write(&path, r#"{"cpu_limt":{"unit":"share","millicores":1500}}"#).expect("write");
        let err = load_grants_file(&path).expect_err("a misspelled key must be refused");
        assert!(
            format!("{err:#}").contains("unknown field"),
            "expected an unknown-field refusal, got: {err:#}"
        );
    }

    #[test]
    fn a_well_formed_grants_file_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("grants.json");
        std::fs::write(
            &path,
            r#"{"cpu":{"unit":"share","millicores":1500},
                "egress":{"allow":[{"host":"api.example.com","port":443}]}}"#,
        )
        .expect("write");
        let grants = load_grants_file(&path).expect("parses");
        assert_eq!(grants.cpu, Some(CpuGrant::Share { millicores: 1500 }));
        assert_eq!(
            grants.egress.as_ref().map(|e| e.allow.as_slice()),
            Some(&[HostPort::new("api.example.com", 443)][..])
        );
    }

    #[test]
    fn a_missing_grants_file_names_the_path() {
        let err = load_grants_file(Path::new("/nonexistent/grants.json"))
            .expect_err("a missing file must not resolve to no grants");
        assert!(format!("{err:#}").contains("/nonexistent/grants.json"));
    }
}

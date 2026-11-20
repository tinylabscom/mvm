//! `mvmctl bench fit` — does a declared deployment fit on this host?
//!
//! Wiring only: the arithmetic lives in [`crate::bench::fit`]. This module
//! picks the report section, builds one [`FitReport`] from the verdict, and
//! renders that report as text or JSON.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use serde::Serialize;
use std::fmt::Write as _;
use std::path::PathBuf;

use mvm_contract::plan::topology::{Topology, check_requirements};
use mvm_contract::protocol::resource_controls::ResourceControls;
use mvm_contract::protocol::vm_backend::BackendKind;

use crate::bench::fit::{
    Demand, Deployment, DiskCheck, Fit, Headroom, Provenance, Resource, Shortfall,
};
use crate::bench::resource_report::{ResourceReport, Section, WakeupQuantity};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct FitArgs {
    /// Number of identical machines to place.
    #[arg(long, value_name = "N", required_unless_present = "topology")]
    pub units: Option<u32>,
    /// vCPUs per machine.
    #[arg(long, value_name = "N", required_unless_present = "topology")]
    pub vcpus: Option<u32>,
    /// Guest memory per machine, in MiB.
    #[arg(long, value_name = "N", required_unless_present = "topology")]
    pub memory_mib: Option<u64>,
    /// Disk per machine, in MiB. Defaults to the report's measurement.
    #[arg(long, value_name = "N")]
    pub disk_mib: Option<u64>,
    /// Topology JSON whose units are summed instead of N identical machines.
    /// Its structure and the backend's enforcement of its requirements are
    /// checked first; its signature is not.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["units", "vcpus", "memory_mib", "disk_mib"]
    )]
    pub topology: Option<PathBuf>,
    /// Resource report JSON (from `mvmctl bench report`) supplying host costs.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,
    /// Report section to use, by backend. With `--topology`, also the backend
    /// whose controls must enforce its requirements; the report section's
    /// backend is used when absent.
    #[arg(long, value_name = "NAME")]
    pub backend: Option<String>,
    /// Report section to use, by architecture.
    #[arg(long, value_name = "NAME")]
    pub architecture: Option<String>,
    /// Host capacity JSON to use instead of probing this host.
    #[arg(long, value_name = "FILE")]
    pub inventory: Option<PathBuf>,
    /// Print the verdict as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct ResourceLine {
    resource: &'static str,
    unit: &'static str,
    /// `None` when the resource was not checked.
    required: Option<u128>,
    available: Option<u128>,
    not_checked_reason: Option<&'static str>,
    /// For a missing core: its ID and the topology unit holding it.
    #[serde(skip_serializing_if = "Option::is_none")]
    core: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workload: Option<String>,
}

#[derive(Serialize)]
struct ProvenanceLine {
    input: &'static str,
    source: &'static str,
}

#[derive(Serialize)]
struct FitReport {
    fits: bool,
    /// The first resource that does not fit.
    failed: Option<&'static str>,
    /// Which report section supplied host costs.
    basis: String,
    resources: Vec<ResourceLine>,
    provenance: Vec<ProvenanceLine>,
}

const fn resource_name(r: Resource) -> &'static str {
    match r {
        Resource::Memory => "memory",
        Resource::Vcpu => "vcpu",
        Resource::Disk => "disk",
        Resource::Core => "core",
    }
}

const fn source_name(s: crate::bench::fit::Source) -> &'static str {
    use crate::bench::fit::Source;
    match s {
        Source::Measured => "measured",
        Source::Declared => "declared",
        Source::Fallback => "fallback",
    }
}

fn line(resource: Resource, h: Headroom) -> ResourceLine {
    ResourceLine {
        resource: resource_name(resource),
        unit: match resource {
            Resource::Vcpu | Resource::Core => "vCPUs",
            Resource::Memory | Resource::Disk => "MiB",
        },
        required: Some(h.required),
        available: Some(h.available),
        not_checked_reason: None,
        core: None,
        workload: None,
    }
}

fn shortfall_line(short: &Shortfall) -> ResourceLine {
    let mut l = line(short.resource, short.headroom);
    if let Some((core, unit)) = &short.core {
        l.core = Some(core.0);
        l.workload = Some(unit.0.clone());
    }
    l
}

fn provenance_lines(p: &Provenance) -> Vec<ProvenanceLine> {
    let mut v = vec![
        ProvenanceLine {
            input: "fixed memory cost",
            source: source_name(p.fixed_memory),
        },
        ProvenanceLine {
            input: "per-unit memory overhead",
            source: source_name(p.unit_overhead),
        },
        ProvenanceLine {
            input: "fixed disk cost",
            source: source_name(p.fixed_disk),
        },
    ];
    if let Some(s) = p.unit_disk {
        v.push(ProvenanceLine {
            input: "per-unit disk",
            source: source_name(s),
        });
    }
    v
}

fn summarize(verdict: &Result<Fit, Shortfall>, basis: &str) -> FitReport {
    match verdict {
        Ok(fit) => FitReport {
            fits: true,
            failed: None,
            basis: basis.to_string(),
            resources: vec![
                line(Resource::Memory, fit.memory),
                line(Resource::Vcpu, fit.vcpu),
                match fit.disk {
                    DiskCheck::Checked(h) => line(Resource::Disk, h),
                    DiskCheck::NotChecked { reason } => ResourceLine {
                        resource: "disk",
                        unit: "MiB",
                        required: None,
                        available: None,
                        not_checked_reason: Some(reason),
                        core: None,
                        workload: None,
                    },
                },
            ],
            provenance: provenance_lines(&fit.provenance),
        },
        Err(short) => FitReport {
            fits: false,
            failed: Some(resource_name(short.resource)),
            basis: basis.to_string(),
            resources: vec![shortfall_line(short)],
            provenance: provenance_lines(&short.provenance),
        },
    }
}

fn render_text(r: &FitReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Host costs from: {}", r.basis);
    for l in &r.resources {
        match (l.required, l.available) {
            (Some(_), Some(avail)) if l.core.is_some() => {
                let _ = writeln!(
                    out,
                    "core    {} of unit {}: the host has {avail} vCPUs",
                    l.core.unwrap_or_default(),
                    l.workload.as_deref().unwrap_or("unknown")
                );
            }
            (Some(req), Some(avail)) => {
                let _ = writeln!(
                    out,
                    "{:<7} required {req} {unit}, available {avail} {unit}",
                    l.resource,
                    unit = l.unit
                );
            }
            _ => {
                let _ = writeln!(
                    out,
                    "{:<7} not checked: {}",
                    l.resource,
                    l.not_checked_reason.unwrap_or("unknown")
                );
            }
        }
    }
    for p in &r.provenance {
        let _ = writeln!(out, "{}: {}", p.input, p.source);
    }
    match r.failed {
        None => out.push_str("fits\n"),
        Some(res) => {
            let _ = writeln!(out, "does not fit: {res}");
        }
    }
    out
}

fn load_topology(path: &std::path::Path) -> Result<Topology> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading topology {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing topology {}", path.display()))
}

/// The topology's demand, once its structure is valid and `controls` enforce
/// every requirement it states. No failover is measured here, so a stated
/// recovery bound is refused.
fn topology_demand(topology: &Topology, controls: ResourceControls) -> Result<Demand> {
    topology
        .validate()
        .context("the topology is structurally invalid")?;
    check_requirements(topology, controls, None)
        .context("the backend does not enforce a requirement of the topology")?;
    Ok(Demand::from(topology))
}

/// Pick the report section named by the flags; a lone section needs no flags.
fn select_section<'a>(
    report: &'a ResourceReport,
    backend: Option<&str>,
    architecture: Option<&str>,
) -> Result<&'a Section> {
    let matching: Vec<&Section> = report
        .sections
        .iter()
        .filter(|s| backend.is_none_or(|b| s.backend == b))
        .filter(|s| architecture.is_none_or(|a| s.architecture == a))
        .collect();
    let single_unfiltered = backend.is_none() && architecture.is_none();
    if let [only] = matching[..] {
        return Ok(only);
    }
    let pairs = report
        .sections
        .iter()
        .map(|s| format!("{}/{}", s.backend, s.architecture))
        .collect::<Vec<_>>()
        .join(", ");
    let why = if matching.is_empty() {
        "no section matches"
    } else if single_unfiltered {
        "the report has several sections; name one with --backend/--architecture"
    } else {
        "the flags match more than one section"
    };
    bail!("{why}; available (backend/architecture): {pairs}")
}

pub(in crate::commands) fn run_fit(args: FitArgs) -> Result<()> {
    let host = match &args.inventory {
        Some(path) => crate::bench::host_probe::load_inventory(path)?,
        None => crate::bench::host_probe::probe_host_capacity()?,
    };
    let (section, basis) = match &args.report {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading report {}", path.display()))?;
            let report: ResourceReport = serde_json::from_str(&text)
                .with_context(|| format!("parsing report {}", path.display()))?;
            let s = select_section(
                &report,
                args.backend.as_deref(),
                args.architecture.as_deref(),
            )?
            .clone();
            let basis = format!("{} ({}/{})", path.display(), s.backend, s.architecture);
            (s, basis)
        }
        None => (
            Section::unmeasured("none", "none", WakeupQuantity::LinuxProcfs),
            "no report (every report-dependent input falls back)".to_string(),
        ),
    };
    let demand = match &args.topology {
        Some(path) => {
            let backend = args.backend.as_deref().unwrap_or(&section.backend);
            let kind = BackendKind::from_label(backend).with_context(|| {
                format!("--topology needs a known backend to check requirements against, got {backend:?}; name one with --backend")
            })?;
            // shortcut: with --inventory there is no host here to probe for a
            // delegated cpuset, so the backend's placement is assumed present;
            // admission on the real host still checks it.
            let scope_cpuset =
                args.inventory.is_some() || mvm_core::spawn_scope::cpuset_gap().is_none();
            topology_demand(
                &load_topology(path)?,
                ResourceControls::on_host(kind, scope_cpuset),
            )?
        }
        None => Demand::from(&Deployment {
            units: args.units.context("--units is required")?,
            vcpus_per_unit: args.vcpus.context("--vcpus is required")?,
            memory_mib_per_unit: args.memory_mib.context("--memory-mib is required")?,
            disk_mib_per_unit: args.disk_mib,
        }),
    };
    let summary = summarize(
        &crate::bench::fit::check_demand(&demand, &host, &section),
        &basis,
    );
    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        print!("{}", render_text(&summary));
    }
    if let Some(res) = summary.failed {
        bail!("the deployment does not fit: {res}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::fit::{Source, check_fit};
    use mvm_core::mvmd_iface::host_inventory::HostCapacity;

    fn host(vcpus: u32, mem: u64, disk_gib: u64) -> HostCapacity {
        HostCapacity {
            total_vcpus: vcpus,
            total_mem_mib: mem,
            total_disk_gib: disk_gib,
        }
    }

    fn dep(units: u32, mem: u64, disk: Option<u64>) -> Deployment {
        Deployment {
            units,
            vcpus_per_unit: 1,
            memory_mib_per_unit: mem,
            disk_mib_per_unit: disk,
        }
    }

    fn unmeasured() -> Section {
        Section::unmeasured("hvf", "aarch64", WakeupQuantity::MacosLibproc)
    }

    fn text(d: &Deployment, h: &HostCapacity) -> String {
        render_text(&summarize(&check_fit(d, h, &unmeasured()), "test"))
    }

    #[test]
    fn a_fit_lists_every_resource_and_ends_with_fits() {
        let out = text(&dep(2, 256, Some(100)), &host(8, 65536, 100));
        assert!(out.contains("memory  required"), "{out}");
        assert!(
            out.contains("vcpu    required 2 vCPUs, available 8 vCPUs"),
            "{out}"
        );
        assert!(
            out.contains("disk    required 200 MiB, available 102400 MiB"),
            "{out}"
        );
        assert!(out.trim_end().ends_with("fits"), "{out}");
    }

    #[test]
    fn a_memory_shortfall_names_memory_and_the_amounts() {
        let out = text(&dep(10, 1024, None), &host(64, 2048, 100));
        assert!(out.contains("memory  required"), "{out}");
        assert!(out.contains("available 2048 MiB"), "{out}");
        assert!(out.trim_end().ends_with("does not fit: memory"), "{out}");
    }

    #[test]
    fn an_undeclared_unmeasured_disk_is_reported_as_not_checked() {
        let out = text(&dep(1, 256, None), &host(8, 65536, 100));
        assert!(
            out.contains("disk    not checked: no declared per-unit disk"),
            "{out}"
        );
        assert!(out.trim_end().ends_with("fits"), "{out}");
    }

    #[test]
    fn provenance_names_fallback_and_declared() {
        let out = text(&dep(1, 256, Some(10)), &host(8, 65536, 100));
        assert!(out.contains("per-unit memory overhead: fallback"), "{out}");
        assert!(out.contains("fixed memory cost: fallback"), "{out}");
        assert!(out.contains("per-unit disk: declared"), "{out}");
        assert_eq!(source_name(Source::Measured), "measured");
    }

    #[test]
    fn json_carries_the_same_facts() {
        let s = summarize(
            &check_fit(&dep(10, 1024, None), &host(64, 2048, 100), &unmeasured()),
            "x",
        );
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["fits"], false);
        assert_eq!(v["failed"], "memory");
        assert_eq!(v["resources"][0]["available"], 2048);
    }

    fn report(pairs: &[(&str, &str)]) -> ResourceReport {
        ResourceReport {
            sections: pairs
                .iter()
                .map(|(b, a)| Section::unmeasured(*b, *a, WakeupQuantity::LinuxProcfs))
                .collect(),
            ..ResourceReport::default()
        }
    }

    #[test]
    fn a_single_section_needs_no_flags() {
        let r = report(&[("hvf", "aarch64")]);
        assert_eq!(select_section(&r, None, None).unwrap().backend, "hvf");
    }

    #[test]
    fn flags_pick_among_several_sections() {
        let r = report(&[("hvf", "aarch64"), ("firecracker", "x86_64")]);
        let s = select_section(&r, Some("firecracker"), None).unwrap();
        assert_eq!(s.architecture, "x86_64");
        let s = select_section(&r, None, Some("aarch64")).unwrap();
        assert_eq!(s.backend, "hvf");
    }

    #[test]
    fn an_ambiguous_choice_lists_the_available_pairs() {
        let r = report(&[("hvf", "aarch64"), ("firecracker", "x86_64")]);
        let err = select_section(&r, None, None).unwrap_err().to_string();
        assert!(
            err.contains("hvf/aarch64") && err.contains("firecracker/x86_64"),
            "{err}"
        );
    }

    #[test]
    fn no_match_lists_the_available_pairs() {
        let r = report(&[("hvf", "aarch64")]);
        let err = select_section(&r, Some("qemu"), None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no section matches") && err.contains("hvf/aarch64"),
            "{err}"
        );
    }

    fn placing_controls() -> ResourceControls {
        ResourceControls::on_host(BackendKind::Firecracker, true)
    }

    #[test]
    fn an_invalid_topology_is_refused_before_any_arithmetic() {
        use crate::bench::fit::tests::{topology, unit};
        // Units out of order: structurally invalid whatever the host holds.
        let t = topology(
            vec![unit("b", 1, 1, 1, &[]), unit("a", 1, 1, 1, &[])],
            vec![],
        );
        let err = format!("{:#}", topology_demand(&t, placing_controls()).unwrap_err());
        assert!(err.contains("structurally invalid"), "{err}");
    }

    #[test]
    fn an_unenforced_requirement_is_refused_before_any_arithmetic() {
        use crate::bench::fit::tests::{topology, unit};
        let t = topology(vec![unit("a", 1, 1, 1, &[0])], vec![]);
        let controls = ResourceControls::on_host(BackendKind::Hvf, false);
        let err = format!("{:#}", topology_demand(&t, controls).unwrap_err());
        assert!(
            err.contains("does not enforce") && err.contains("exclusive core placement"),
            "{err}"
        );
        assert!(topology_demand(&t, placing_controls()).is_ok());
    }

    #[test]
    fn a_missing_core_keeps_the_report_shape_and_names_its_unit() {
        use crate::bench::fit::check_demand;
        use crate::bench::fit::tests::{topology, unit};
        let t = topology(vec![unit("ctl", 1, 1, 1, &[12])], vec![]);
        let demand = topology_demand(&t, placing_controls()).unwrap();
        let report = summarize(
            &check_demand(&demand, &host(8, 65536, 100), &unmeasured()),
            "x",
        );
        let v = serde_json::to_value(&report).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["basis", "failed", "fits", "provenance", "resources"],
            "{v}"
        );
        assert_eq!(v["failed"], "core");
        assert_eq!(v["resources"][0]["core"], 12);
        assert_eq!(v["resources"][0]["workload"], "ctl");
        let out = render_text(&report);
        assert!(out.contains("core    12 of unit ctl"), "{out}");
        assert!(out.trim_end().ends_with("does not fit: core"), "{out}");
    }

    #[test]
    fn json_for_the_n_unit_path_carries_no_core_fields() {
        let s = summarize(
            &check_fit(&dep(10, 1024, None), &host(64, 2048, 100), &unmeasured()),
            "x",
        );
        let v = serde_json::to_value(&s).unwrap();
        assert!(v["resources"][0].get("core").is_none(), "{v}");
        assert!(v["resources"][0].get("workload").is_none(), "{v}");
    }
}

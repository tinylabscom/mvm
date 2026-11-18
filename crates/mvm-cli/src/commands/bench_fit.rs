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

use crate::bench::fit::{Deployment, DiskCheck, Fit, Headroom, Provenance, Resource, Shortfall};
use crate::bench::resource_report::{ResourceReport, Section, WakeupQuantity};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct FitArgs {
    /// Number of identical machines to place.
    #[arg(long, value_name = "N")]
    pub units: u32,
    /// vCPUs per machine.
    #[arg(long, value_name = "N")]
    pub vcpus: u32,
    /// Guest memory per machine, in MiB.
    #[arg(long, value_name = "N")]
    pub memory_mib: u64,
    /// Disk per machine, in MiB. Defaults to the report's measurement.
    #[arg(long, value_name = "N")]
    pub disk_mib: Option<u64>,
    /// Resource report JSON (from `mvmctl bench report`) supplying host costs.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,
    /// Report section to use, by backend.
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
        unit: if resource == Resource::Vcpu {
            "vCPUs"
        } else {
            "MiB"
        },
        required: Some(h.required),
        available: Some(h.available),
        not_checked_reason: None,
    }
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
                    },
                },
            ],
            provenance: provenance_lines(&fit.provenance),
        },
        Err(short) => FitReport {
            fits: false,
            failed: Some(resource_name(short.resource)),
            basis: basis.to_string(),
            resources: vec![line(short.resource, short.headroom)],
            provenance: provenance_lines(&short.provenance),
        },
    }
}

fn render_text(r: &FitReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Host costs from: {}", r.basis);
    for l in &r.resources {
        match (l.required, l.available) {
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
    let deployment = Deployment {
        units: args.units,
        vcpus_per_unit: args.vcpus,
        memory_mib_per_unit: args.memory_mib,
        disk_mib_per_unit: args.disk_mib,
    };
    let summary = summarize(
        &crate::bench::fit::check_fit(&deployment, &host, &section),
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
}

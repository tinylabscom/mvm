//! A versioned resource report: what a backend costs on a host with nothing
//! running, what each unit costs by residency and standby class, and how long
//! launches take.
//!
//! Every figure is either measured or unmeasured with a reason, so a quantity
//! nobody observed cannot appear as a zero. The report carries one section per
//! (backend, architecture) pair; sections are never merged across pairs.
//!
//! `mvm_core::usage_capture::Metric` is not reused here: it carries only a
//! `u64` and a collection mechanism, has no place for a reason, and cannot
//! hold a latency summary. [`Figure`] mirrors its shape (a choice between an
//! observation and nothing) with those two additions.

use serde::{Deserialize, Serialize};

use super::cold_launch::SpanStats;

/// Schema version of [`ResourceReport`].
pub const RESOURCE_REPORT_SCHEMA_VERSION: u32 = 1;

/// Reason carried by figures whose measurement does not exist yet.
pub const NOT_IMPLEMENTED_REASON: &str = "feature not implemented";

/// Reason carried by figures nobody has attempted to measure.
pub const NOT_MEASURED_REASON: &str = "not measured";

const DASH: &str = "—";

/// One figure: an observed value, or the reason there is none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Figure<T> {
    Measured { value: T },
    Unmeasured { reason: String },
}

impl<T> Figure<T> {
    #[must_use]
    pub const fn measured(value: T) -> Self {
        Self::Measured { value }
    }

    #[must_use]
    pub fn unmeasured(reason: impl Into<String>) -> Self {
        Self::Unmeasured {
            reason: reason.into(),
        }
    }

    /// A figure for a feature that does not exist yet.
    #[must_use]
    pub fn not_implemented() -> Self {
        Self::unmeasured(NOT_IMPLEMENTED_REASON)
    }

    /// The value, when there is one.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Measured { value } => Some(value),
            Self::Unmeasured { .. } => None,
        }
    }
}

impl<T> Default for Figure<T> {
    fn default() -> Self {
        Self::unmeasured(NOT_MEASURED_REASON)
    }
}

/// Which quantity a wakeup rate is. The two sources count different events,
/// so a Linux figure and a macOS figure are never comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeupQuantity {
    /// Voluntary context switches, summed over a process's tasks, read from
    /// procfs.
    LinuxProcfs,
    /// `ri_pkg_idle_wkups + ri_interrupt_wkups` from libproc rusage.
    MacosLibproc,
}

impl WakeupQuantity {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LinuxProcfs => "Linux procfs-derived",
            Self::MacosLibproc => "macOS libproc-derived",
        }
    }
}

/// Which quantity a memory figure is. A physical footprint and a proportional
/// set size charge shared pages differently, so they are never comparable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryQuantity {
    /// `ri_phys_footprint` from libproc rusage.
    #[default]
    PhysicalFootprint,
    /// `Pss` from `/proc/<pid>/smaps_rollup`.
    ProportionalSetSize,
}

impl MemoryQuantity {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::PhysicalFootprint => "physical footprint",
            Self::ProportionalSetSize => "proportional set size",
        }
    }
}

/// A wakeup rate together with the quantity it counts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wakeups {
    pub quantity: WakeupQuantity,
    pub per_second: Figure<f64>,
}

impl Wakeups {
    #[must_use]
    pub fn unmeasured(quantity: WakeupQuantity) -> Self {
        Self {
            quantity,
            per_second: Figure::default(),
        }
    }
}

/// Cost of the host with zero units running.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedHostCost {
    pub memory_bytes: Figure<u64>,
    pub idle_cpu_millicores: Figure<f64>,
    pub wakeups: Wakeups,
    pub disk_bytes: Figure<u64>,
}

impl FixedHostCost {
    #[must_use]
    pub fn unmeasured(wakeups: WakeupQuantity) -> Self {
        Self {
            memory_bytes: Figure::default(),
            idle_cpu_millicores: Figure::default(),
            wakeups: Wakeups::unmeasured(wakeups),
            disk_bytes: Figure::default(),
        }
    }
}

/// Marginal cost of one unit in one state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitCost {
    pub memory_bytes: Figure<u64>,
    pub cpu_millicores: Figure<f64>,
    pub wakeups: Wakeups,
    pub disk_bytes: Figure<u64>,
}

impl UnitCost {
    #[must_use]
    pub fn unmeasured(wakeups: WakeupQuantity) -> Self {
        Self {
            memory_bytes: Figure::default(),
            cpu_millicores: Figure::default(),
            wakeups: Wakeups::unmeasured(wakeups),
            disk_bytes: Figure::default(),
        }
    }
}

/// Per-unit cost by residency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidencyCosts {
    pub running: UnitCost,
    pub idle: UnitCost,
    pub parked: UnitCost,
}

impl ResidencyCosts {
    #[must_use]
    pub fn unmeasured(wakeups: WakeupQuantity) -> Self {
        Self {
            running: UnitCost::unmeasured(wakeups),
            idle: UnitCost::unmeasured(wakeups),
            parked: UnitCost::unmeasured(wakeups),
        }
    }
}

/// Per-unit cost by standby class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyCosts {
    /// Standbys held by a resident VMM process each.
    pub resident: UnitCost,
    /// Standbys held as an on-disk snapshot with no process. The two classes
    /// are different quantities and are never merged.
    pub warm: UnitCost,
}

impl StandbyCosts {
    #[must_use]
    pub fn unmeasured(wakeups: WakeupQuantity) -> Self {
        Self {
            resident: UnitCost::unmeasured(wakeups),
            warm: UnitCost::unmeasured(wakeups),
        }
    }
}

/// Latency summaries in milliseconds, reusing the launch benchmark's
/// percentile type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Latencies {
    pub cold_launch_ms: Figure<SpanStats>,
    pub warm_launch_ms: Figure<SpanStats>,
    pub failover_ms: Figure<SpanStats>,
    pub state_cell_update_ms: Figure<SpanStats>,
    pub mailbox_round_trip_ms: Figure<SpanStats>,
}

impl Default for Latencies {
    fn default() -> Self {
        Self {
            cold_launch_ms: Figure::default(),
            warm_launch_ms: Figure::default(),
            failover_ms: Figure::not_implemented(),
            state_cell_update_ms: Figure::not_implemented(),
            mailbox_round_trip_ms: Figure::not_implemented(),
        }
    }
}

/// Everything reported for one (backend, architecture) pair.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    pub backend: String,
    pub architecture: String,
    /// The quantity every memory figure in this section measures.
    #[serde(default)]
    pub memory_quantity: MemoryQuantity,
    pub fixed_host_cost: FixedHostCost,
    pub by_residency: ResidencyCosts,
    pub by_standby: StandbyCosts,
    pub latencies: Latencies,
}

impl Section {
    /// A section where nothing is measured yet. Failover, state-cell and
    /// mailbox latencies are declared empty because those features do not
    /// exist; the rest are simply not measured.
    #[must_use]
    pub fn unmeasured(
        backend: impl Into<String>,
        architecture: impl Into<String>,
        wakeups: WakeupQuantity,
    ) -> Self {
        Self {
            backend: backend.into(),
            architecture: architecture.into(),
            memory_quantity: MemoryQuantity::default(),
            fixed_host_cost: FixedHostCost::unmeasured(wakeups),
            by_residency: ResidencyCosts::unmeasured(wakeups),
            by_standby: StandbyCosts::unmeasured(wakeups),
            latencies: Latencies::default(),
        }
    }
}

/// The source tree the measured binaries were built from, as the density
/// harness recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevision {
    pub commit: String,
    /// The tree carried uncommitted changes, so the commit alone does not
    /// say what was measured.
    pub dirty: bool,
}

/// The versioned report.
///
/// ```
/// use mvm_cli::bench::resource_report::{
///     render_markdown, ResourceReport, Section, WakeupQuantity,
/// };
///
/// let mut report = ResourceReport::default();
/// report
///     .sections
///     .push(Section::unmeasured("hvf", "aarch64", WakeupQuantity::MacosLibproc));
/// let table = render_markdown(&report);
/// assert!(table.contains("### hvf / aarch64"));
/// assert!(table.contains("—"));
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReport {
    pub schema_version: u32,
    /// Absent only in reports written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceRevision>,
    pub sections: Vec<Section>,
}

impl Default for ResourceReport {
    fn default() -> Self {
        Self {
            schema_version: RESOURCE_REPORT_SCHEMA_VERSION,
            source: None,
            sections: Vec::new(),
        }
    }
}

fn bytes_cell(f: &Figure<u64>) -> String {
    f.value()
        .map_or_else(|| DASH.to_string(), |v| format!("{v} B"))
}

fn float_cell(f: &Figure<f64>, unit: &str) -> String {
    f.value()
        .map_or_else(|| DASH.to_string(), |v| format!("{v:.2}{unit}"))
}

fn ms_cell(v: Option<f64>) -> String {
    v.map_or_else(|| DASH.to_string(), |ms| format!("{ms:.1}"))
}

fn unit_row(name: &str, cost: &UnitCost) -> String {
    format!(
        "| {name} | {} | {} | {} | {} |\n",
        bytes_cell(&cost.memory_bytes),
        float_cell(&cost.cpu_millicores, " m"),
        float_cell(&cost.wakeups.per_second, ""),
        bytes_cell(&cost.disk_bytes)
    )
}

fn latency_row(name: &str, f: &Figure<SpanStats>) -> String {
    match f.value() {
        Some(s) => format!(
            "| {name} | {} | {} | {} | {} | {} |\n",
            s.samples,
            ms_cell(s.p50),
            ms_cell(s.p95),
            ms_cell(s.p99),
            ms_cell(s.max)
        ),
        None => format!("| {name} | {DASH} | {DASH} | {DASH} | {DASH} | {DASH} |\n"),
    }
}

fn render_section(out: &mut String, s: &Section) {
    out.push_str(&format!("### {} / {}\n\n", s.backend, s.architecture));

    let fixed = &s.fixed_host_cost;
    out.push_str("Fixed host cost with zero units:\n\n");
    out.push_str(
        "| Memory | Memory quantity | Idle CPU | Wakeups per second | Wakeup quantity | Disk |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} |\n\n",
        bytes_cell(&fixed.memory_bytes),
        s.memory_quantity.label(),
        float_cell(&fixed.idle_cpu_millicores, " m"),
        float_cell(&fixed.wakeups.per_second, ""),
        fixed.wakeups.quantity.label(),
        bytes_cell(&fixed.disk_bytes),
    ));

    out.push_str(&format!(
        "Per-unit cost (memory is {}):\n\n",
        s.memory_quantity.label()
    ));
    out.push_str(
        "| State | Memory | CPU | Wakeups per second | Disk |\n| --- | --- | --- | --- | --- |\n",
    );
    out.push_str(&unit_row("running", &s.by_residency.running));
    out.push_str(&unit_row("idle", &s.by_residency.idle));
    out.push_str(&unit_row("parked", &s.by_residency.parked));
    out.push_str(&unit_row(
        "standby resident process",
        &s.by_standby.resident,
    ));
    out.push_str(&unit_row("standby on-disk snapshot", &s.by_standby.warm));

    let l = &s.latencies;
    out.push_str("\nLatency (ms):\n\n");
    out.push_str("| Operation | Samples | p50 | p95 | p99 | max |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    out.push_str(&latency_row(
        "cold launch (plan admitted to dispatch)",
        &l.cold_launch_ms,
    ));
    out.push_str(&latency_row(
        "warm launch (plan admitted to dispatch)",
        &l.warm_launch_ms,
    ));
    out.push_str(&latency_row("failover", &l.failover_ms));
    out.push_str(&latency_row("state-cell update", &l.state_cell_update_ms));
    out.push_str(&latency_row("mailbox round trip", &l.mailbox_round_trip_ms));
    out.push('\n');
}

fn source_line(source: Option<&SourceRevision>) -> String {
    match source {
        None => "Source commit: not recorded.\n\n".to_string(),
        Some(SourceRevision {
            commit,
            dirty: false,
        }) => format!("Source commit: `{commit}`.\n\n"),
        Some(SourceRevision {
            commit,
            dirty: true,
        }) => format!(
            "**Measured from a modified tree**: commit `{commit}` with uncommitted \
             changes. These figures are not publishable.\n\n"
        ),
    }
}

/// Render the report as markdown tables. An unmeasured figure is a dash; its
/// reason is only in the JSON form.
#[must_use]
pub fn render_markdown(report: &ResourceReport) -> String {
    let mut out = format!(
        "## Resource report (schema version {})\n\n",
        report.schema_version
    );
    out.push_str(&source_line(report.source.as_ref()));
    for section in &report.sections {
        render_section(&mut out, section);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_section() -> Section {
        Section::unmeasured("firecracker", "x86_64", WakeupQuantity::LinuxProcfs)
    }

    fn report_with(section: Section) -> ResourceReport {
        ResourceReport {
            sections: vec![section],
            ..ResourceReport::default()
        }
    }

    #[test]
    fn serde_round_trip() {
        let mut section = empty_section();
        section.fixed_host_cost.memory_bytes = Figure::measured(4096);
        section.latencies.cold_launch_ms =
            Figure::measured(SpanStats::from_samples(&[10.0, 20.0, 30.0]));
        let mut report = report_with(section);
        report.source = Some(SourceRevision {
            commit: "abc123".into(),
            dirty: true,
        });
        let json = serde_json::to_string(&report).unwrap();
        let back: ResourceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn unknown_fields_are_refused() {
        let mut v = serde_json::to_value(report_with(empty_section())).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ResourceReport>(v).is_err());

        let mut v = serde_json::to_value(report_with(empty_section())).unwrap();
        v["sections"][0]["fixed_host_cost"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ResourceReport>(v).is_err());

        let mut v = serde_json::to_value(report_with(empty_section())).unwrap();
        v["sections"][0]["by_residency"]["running"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ResourceReport>(v).is_err());
    }

    #[test]
    fn unmeasured_cells_render_as_dashes_never_zero() {
        let md = render_markdown(&report_with(empty_section()));
        let mut rows = 0;
        for line in md.lines().filter(|l| l.starts_with("| ")) {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            if cells[0] == "Memory" || cells[0] == "State" || cells[0] == "Operation" {
                continue;
            }
            if cells[0].starts_with("---") {
                continue;
            }
            rows += 1;
            for cell in cells.iter().skip(1) {
                // The quantity labels are text, not figures.
                if cell.ends_with("derived") || *cell == MemoryQuantity::default().label() {
                    continue;
                }
                assert_eq!(*cell, DASH, "row {line}");
            }
        }
        assert!(rows >= 11);
    }

    #[test]
    fn a_measured_figure_renders_its_value() {
        let mut section = empty_section();
        section.fixed_host_cost.memory_bytes = Figure::measured(123_456);
        section.by_residency.running.cpu_millicores = Figure::measured(12.5);
        section.by_standby.warm.disk_bytes = Figure::measured(777);
        section.latencies.warm_launch_ms = Figure::measured(SpanStats::from_samples(&[50.0, 60.0]));
        let md = render_markdown(&report_with(section));
        assert!(md.contains("123456 B"));
        assert!(md.contains("12.50 m"));
        assert!(md.contains("777 B"));
        assert!(md.contains("| warm launch (plan admitted to dispatch) | 2 |"));
    }

    #[test]
    fn declared_empty_sections_are_unmeasured_by_construction() {
        let l = empty_section().latencies;
        for f in [
            &l.failover_ms,
            &l.state_cell_update_ms,
            &l.mailbox_round_trip_ms,
        ] {
            assert_eq!(
                f,
                &Figure::Unmeasured {
                    reason: NOT_IMPLEMENTED_REASON.to_string()
                }
            );
        }
    }

    #[test]
    fn unmeasured_reason_is_in_json() {
        let json = serde_json::to_string(&report_with(empty_section())).unwrap();
        assert!(json.contains("feature not implemented"));
    }

    #[test]
    fn wakeup_quantities_are_labelled_differently() {
        let linux = render_markdown(&report_with(empty_section()));
        let mac = render_markdown(&report_with(Section::unmeasured(
            "hvf",
            "aarch64",
            WakeupQuantity::MacosLibproc,
        )));
        assert!(linux.contains("Linux procfs-derived"));
        assert!(mac.contains("macOS libproc-derived"));
        assert_ne!(
            WakeupQuantity::LinuxProcfs.label(),
            WakeupQuantity::MacosLibproc.label()
        );
    }

    #[test]
    fn memory_quantities_are_labelled_differently() {
        let mut section = empty_section();
        let footprint = render_markdown(&report_with(section.clone()));
        section.memory_quantity = MemoryQuantity::ProportionalSetSize;
        let pss = render_markdown(&report_with(section));
        assert!(footprint.contains("physical footprint"));
        assert!(pss.contains("proportional set size"));
        assert!(!pss.contains("physical footprint"));
    }

    #[test]
    fn a_report_without_memory_quantity_reads_as_physical_footprint() {
        let mut value = serde_json::to_value(empty_section()).unwrap();
        value.as_object_mut().unwrap().remove("memory_quantity");
        let section: Section = serde_json::from_value(value).unwrap();
        assert_eq!(section.memory_quantity, MemoryQuantity::PhysicalFootprint);
    }

    #[test]
    fn a_report_from_a_modified_tree_says_so_in_markdown() {
        let mut report = report_with(empty_section());
        report.source = Some(SourceRevision {
            commit: "abc123".into(),
            dirty: true,
        });
        let md = render_markdown(&report);
        assert!(md.contains("Measured from a modified tree"), "{md}");
        assert!(
            md.contains("`abc123`") && md.contains("not publishable"),
            "{md}"
        );
        report.source.as_mut().unwrap().dirty = false;
        let md = render_markdown(&report);
        assert!(md.contains("Source commit: `abc123`.") && !md.contains("modified"));
        report.source = None;
        assert!(render_markdown(&report).contains("Source commit: not recorded."));
    }

    #[test]
    fn default_report_has_no_sections() {
        let md = render_markdown(&ResourceReport::default());
        assert!(md.starts_with("## Resource report (schema version 1)"));
        assert!(!md.contains("###"));
    }
}

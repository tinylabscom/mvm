//! Build a [`Section`] of the resource report from the artifacts a density run
//! leaves behind (`summary.tsv`, `metadata.json`, the per-wave capture files)
//! and from existing launch reports.
//!
//! The rule throughout: a quantity the run did not record stays unmeasured
//! with a reason naming what was missing, and a quantity the run recorded
//! badly (a partial wave, a missing baseline, an unparseable number) is an
//! error. Neither ever becomes a zero.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::cold_launch::{ColdLaunchReport, LaunchLane, SpanStats};
use super::resource_report::{
    Figure, MemoryQuantity, ResourceReport, Section, UnitCost, WakeupQuantity, Wakeups,
};

/// Launch mode the harness records in `metadata.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Cold,
    Warm,
    Standby,
}

struct Summary(BTreeMap<String, String>);

impl Summary {
    fn parse(text: &str) -> Result<Self> {
        let mut rows = BTreeMap::new();
        for (n, line) in text.lines().enumerate().skip(1) {
            if line.is_empty() {
                continue;
            }
            let (key, value) = line
                .split_once('\t')
                .with_context(|| format!("summary.tsv line {}: no tab separator", n + 1))?;
            if rows.insert(key.to_string(), value.to_string()).is_some() {
                bail!("summary.tsv records `{key}` twice");
            }
        }
        Ok(Self(rows))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    fn require(&self, key: &str) -> Result<&str> {
        self.get(key)
            .with_context(|| format!("summary.tsv has no `{key}`"))
    }

    fn number(&self, key: &str) -> Result<f64> {
        let raw = self.require(key)?;
        match raw.parse::<f64>() {
            Ok(v) if v.is_finite() && v >= 0.0 => Ok(v),
            _ => bail!("summary.tsv `{key}` is `{raw}`, not a non-negative number"),
        }
    }

    fn count(&self, key: &str) -> Result<u64> {
        let raw = self.require(key)?;
        raw.parse::<u64>()
            .with_context(|| format!("summary.tsv `{key}` is `{raw}`, not a count"))
    }
}

/// CPU and wakeups summed over every component a sampler reported.
#[derive(Debug, Clone, Copy)]
struct IdleTotals {
    cpu_millicores: f64,
    wakeups_per_second: f64,
    /// Same totals divided by the standby count, when the harness recorded it.
    per_standby: Option<(f64, f64)>,
}

enum Idle {
    Measured(IdleTotals),
    /// The sampler did not run; the string is the harness's own marker.
    Unavailable(String),
}

fn idle_totals(s: &Summary, wave: u32, standby: bool) -> Result<Idle> {
    if let Some(marker) = s.get(&format!("wave_{wave}_idle_sampler")) {
        return Ok(Idle::Unavailable(marker.to_string()));
    }
    s.require(&format!("wave_{wave}_idle_window_seconds"))
        .with_context(|| format!("wave {wave} has no idle sample"))?;
    let prefix = format!("wave_{wave}_idle_");
    let mut cpu = 0.0;
    let mut wakeups = 0.0;
    let (mut cpu_per, mut wake_per) = (0.0, 0.0);
    for key in s.0.keys() {
        let Some(component) = key
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix("_cpu_millicores"))
        else {
            continue;
        };
        cpu += s.number(key)?;
        wakeups += s
            .number(&format!("{prefix}{component}_wakeups_per_second"))
            .with_context(|| format!("wave {wave} component `{component}` is partial"))?;
        if standby {
            cpu_per += s
                .number(&format!("{key}_per_standby"))
                .with_context(|| format!("wave {wave} component `{component}` is partial"))?;
            wake_per += s
                .number(&format!(
                    "{prefix}{component}_wakeups_per_second_per_standby"
                ))
                .with_context(|| format!("wave {wave} component `{component}` is partial"))?;
        }
    }
    Ok(Idle::Measured(IdleTotals {
        cpu_millicores: cpu,
        wakeups_per_second: wakeups,
        per_standby: standby.then_some((cpu_per, wake_per)),
    }))
}

/// Everything one wave contributes, after refusing a wave that did not finish.
struct Wave {
    units: u64,
    idle: Idle,
    vm_state_bytes: u64,
}

fn read_wave(s: &Summary, wave: u32, standby: bool) -> Result<Wave> {
    let key = |name: &str| format!("wave_{wave}_{name}");
    let units = s.count(&key("vmm_processes"))?;
    if units == 0 {
        bail!("wave {wave} observed no VMM process; refusing to divide by zero units");
    }
    // The process count is host-wide, so a stray VM from another session shows up
    // here as a count that is not the wave's declared size.
    if units != u64::from(wave) {
        bail!("wave {wave} observed {units} VMM processes; the count must equal the wave size");
    }
    if s.count(&key("launch_failures"))? != 0 {
        bail!("wave {wave} recorded launch failures");
    }
    if s.count(&key("cleanup_ok"))? != 1 {
        bail!("wave {wave} did not clean up");
    }
    Ok(Wave {
        units,
        idle: idle_totals(s, wave, standby)?,
        vm_state_bytes: s.count(&key("vm_state_du_kib"))?.saturating_mul(1024),
    })
}

/// The capture's quantity; a capture that names none predates Linux support and
/// is a physical footprint.
fn capture_quantity(json: &Value, path: &Path) -> Result<MemoryQuantity> {
    match json["quantity"].as_str() {
        None | Some("physical_footprint") => Ok(MemoryQuantity::PhysicalFootprint),
        Some("proportional_set_size") => Ok(MemoryQuantity::ProportionalSetSize),
        Some(other) => bail!("{} has unknown memory quantity `{other}`", path.display()),
    }
}

fn bytes_key(quantity: MemoryQuantity) -> &'static str {
    match quantity {
        MemoryQuantity::PhysicalFootprint => "physical_footprint_bytes",
        MemoryQuantity::ProportionalSetSize => "proportional_set_size_bytes",
    }
}

fn footprint(path: &Path, expected: MemoryQuantity) -> Result<std::result::Result<u64, String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}; the harness always writes it", path.display()))?;
    let json: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    match json["status"].as_str() {
        Some("measured") => {}
        Some("unavailable") => {
            return Ok(Err(format!(
                "{} has status `unavailable` on this host ({})",
                path.display(),
                json["reason"].as_str().unwrap_or("no reason recorded")
            )));
        }
        other => bail!("{} has status {other:?}", path.display()),
    }
    let quantity = capture_quantity(&json, path)?;
    if quantity != expected {
        bail!(
            "{} measured {}, but this host reports {}",
            path.display(),
            quantity.label(),
            expected.label()
        );
    }
    let processes = json["processes"]
        .as_array()
        .with_context(|| format!("{} is measured but has no processes array", path.display()))?;
    let mut total = 0u64;
    for process in processes {
        total += process[bytes_key(quantity)].as_u64().with_context(|| {
            format!(
                "{} has a process without a {}",
                path.display(),
                quantity.label()
            )
        })?;
    }
    Ok(Ok(total))
}

/// Per-unit physical footprint: what the wave added between its `before` and
/// `settled` captures, divided by the units it launched.
fn wave_memory(wave_dir: &Path, units: u64, quantity: MemoryQuantity) -> Result<Figure<u64>> {
    let before = footprint(&wave_dir.join("physical-memory-before.json"), quantity)?;
    let settled = footprint(&wave_dir.join("physical-memory-settled.json"), quantity)?;
    match (before, settled) {
        (Ok(before), Ok(settled)) => {
            // The captures are host-wide, so a shrink is other processes' doing.
            Ok(match settled.checked_sub(before) {
                Some(added) => Figure::measured(added / units),
                None => Figure::unmeasured(
                    "the host footprint shrank during the wave, so the wave's share is unknowable",
                ),
            })
        }
        (Err(reason), _) | (_, Err(reason)) => Ok(Figure::unmeasured(reason)),
    }
}

/// Fixed host memory: the summed physical footprint of the MVM host processes
/// the zero-unit capture found. Runs recorded before wave 0 captured memory
/// stay unmeasured.
fn baseline_memory(dir: &Path, quantity: MemoryQuantity) -> Result<Figure<u64>> {
    let path = dir.join("wave-0/physical-memory-settled.json");
    if !path.exists() {
        return Ok(Figure::unmeasured("the run has no wave-0 memory capture"));
    }
    Ok(match footprint(&path, quantity)? {
        Ok(bytes) => Figure::measured(bytes),
        Err(reason) => Figure::unmeasured(reason),
    })
}

/// Fixed host disk: blocks held by the run's isolated MVM home with zero units.
fn baseline_disk(s: &Summary) -> Result<Figure<u64>> {
    const KEY: &str = "wave_0_mvm_home_du_kib";
    if s.get(KEY).is_none() {
        return Ok(Figure::unmeasured("the run has no wave-0 storage capture"));
    }
    Ok(Figure::measured(s.count(KEY)?.saturating_mul(1024)))
}

fn unit_cost(
    quantity: WakeupQuantity,
    base: &Idle,
    wave: &Wave,
    memory: Figure<u64>,
    standby: bool,
) -> Result<UnitCost> {
    let units = wave.units as f64;
    let (cpu, wakeups) = match (base, &wave.idle) {
        (Idle::Measured(b), Idle::Measured(w)) => {
            let (cpu, wake) = match w.per_standby.filter(|_| standby) {
                // Per-standby keys already divide the wave total by the count;
                // the baseline's share is removed the same way.
                Some((c, k)) => (
                    c - b.cpu_millicores / units,
                    k - b.wakeups_per_second / units,
                ),
                None => (
                    (w.cpu_millicores - b.cpu_millicores) / units,
                    (w.wakeups_per_second - b.wakeups_per_second) / units,
                ),
            };
            if cpu < 0.0 || wake < 0.0 {
                bail!("the zero-unit baseline exceeds the wave's total; the host was not quiet");
            }
            (Figure::measured(cpu), Figure::measured(wake))
        }
        (Idle::Unavailable(m), _) | (_, Idle::Unavailable(m)) => (
            Figure::unmeasured(format!("idle sampler: {m}")),
            Figure::unmeasured(format!("idle sampler: {m}")),
        ),
    };
    Ok(UnitCost {
        memory_bytes: memory,
        cpu_millicores: cpu,
        wakeups: Wakeups {
            quantity,
            per_second: wakeups,
        },
        disk_bytes: Figure::measured(wave.vm_state_bytes / wave.units),
    })
}

fn string_at<'a>(meta: &'a Value, path: &[&str]) -> Result<&'a str> {
    let mut cur = meta;
    for part in path {
        cur = &cur[*part];
    }
    cur.as_str()
        .with_context(|| format!("metadata.json has no `{}`", path.join(".")))
}

fn mode_of(raw: &str) -> Result<Mode> {
    match raw {
        "cold" => Ok(Mode::Cold),
        "warm" => Ok(Mode::Warm),
        "standby" => Ok(Mode::Standby),
        other => bail!("metadata.json launch_mode `{other}` is not cold, warm or standby"),
    }
}

fn quantity_of(os: &str) -> Result<WakeupQuantity> {
    match os {
        "Darwin" => Ok(WakeupQuantity::MacosLibproc),
        "Linux" => Ok(WakeupQuantity::LinuxProcfs),
        other => bail!("metadata.json host os `{other}` has no wakeup quantity"),
    }
}

fn memory_quantity_of(os: &str) -> MemoryQuantity {
    match os {
        "Linux" => MemoryQuantity::ProportionalSetSize,
        _ => MemoryQuantity::PhysicalFootprint,
    }
}

fn architecture_of(raw: &str) -> &str {
    match raw {
        "arm64" => "aarch64",
        "amd64" => "x86_64",
        other => other,
    }
}

/// Build one section from a density run directory.
///
/// The largest recorded wave supplies the per-unit figures; every wave the
/// run declared must be complete, so a run that stopped early is refused
/// rather than reported from its surviving waves.
pub fn from_density_dir(dir: &Path) -> Result<Section> {
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .with_context(|| format!("reading {}", dir.join(name).display()))
    };
    let summary = Summary::parse(&read("summary.tsv")?)?;
    let meta: Value =
        serde_json::from_str(&read("metadata.json")?).context("parsing metadata.json")?;

    let backend = string_at(&meta, &["configuration", "backend"])?;
    let mode = mode_of(string_at(&meta, &["configuration", "launch_mode"])?)?;
    if meta["guards"]["native_host_bypassed"]
        .as_bool()
        .context("metadata.json does not record guards.native_host_bypassed")?
    {
        bail!("the run bypassed the native-host guard; its figures are not attributable");
    }
    let quantity = quantity_of(string_at(&meta, &["host", "os"])?)?;
    let architecture = architecture_of(string_at(&meta, &["host", "architecture"])?);
    let waves = string_at(&meta, &["configuration", "waves"])?
        .split_whitespace()
        .map(|w| {
            w.parse::<u32>()
                .with_context(|| format!("wave `{w}` is not a number"))
        })
        .collect::<Result<Vec<_>>>()?;
    let Some(&largest) = waves.iter().max() else {
        bail!("metadata.json declares no waves");
    };
    if largest == 0 {
        bail!("metadata.json declares only the zero-unit wave");
    }

    if mode == Mode::Warm {
        bail!("warm-mode density runs are not ingested yet");
    }
    let standby = mode == Mode::Standby;
    let memory_quantity = memory_quantity_of(string_at(&meta, &["host", "os"])?);
    let mut section = Section::unmeasured(backend, architecture, quantity);
    section.memory_quantity = memory_quantity;

    summary
        .count("wave_0_matching_processes")
        .context("the zero-unit baseline is missing")?;
    let baseline = idle_totals(&summary, 0, false).context("the zero-unit baseline is missing")?;

    let mut chosen = None;
    for wave in waves {
        let read = read_wave(&summary, wave, standby)?;
        if wave == largest {
            chosen = Some(read);
        }
    }
    let wave = chosen.context("the largest wave was not read")?;
    let memory = wave_memory(
        &dir.join(format!("wave-{largest}")),
        wave.units,
        memory_quantity,
    )?;

    match &baseline {
        Idle::Measured(b) => {
            section.fixed_host_cost.idle_cpu_millicores = Figure::measured(b.cpu_millicores);
            section.fixed_host_cost.wakeups.per_second = Figure::measured(b.wakeups_per_second);
        }
        Idle::Unavailable(m) => {
            section.fixed_host_cost.idle_cpu_millicores =
                Figure::unmeasured(format!("idle sampler: {m}"));
            section.fixed_host_cost.wakeups.per_second =
                Figure::unmeasured(format!("idle sampler: {m}"));
        }
    }
    section.fixed_host_cost.memory_bytes = baseline_memory(dir, memory_quantity)?;
    section.fixed_host_cost.disk_bytes = baseline_disk(&summary)?;

    let cost = unit_cost(quantity, &baseline, &wave, memory, standby)?;
    if standby {
        section.by_standby.resident = cost;
    } else {
        section.by_residency.running = cost;
    }
    Ok(section)
}

/// Fold launch reports into the section's cold and warm latencies. A lane with
/// no slot, or two reports for one slot, is refused: percentiles of different
/// runs cannot be merged.
pub fn fold_launch_reports(section: &mut Section, reports: &[ColdLaunchReport]) -> Result<()> {
    let (mut cold, mut warm) = (None, None);
    for report in reports {
        let (slot, name) = match report.lane {
            LaunchLane::PreparedCold => (&mut cold, "prepared_cold"),
            LaunchLane::WarmClaim => (&mut warm, "warm_claim"),
            other => bail!(
                "launch report lane `{}` has no cold or warm launch slot",
                other.as_str()
            ),
        };
        let attributed = match (&report.backend, &report.architecture) {
            (Some(b), Some(a)) if *b == section.backend && *a == section.architecture => true,
            (Some(b), Some(a)) => bail!(
                "the `{name}` launch report ran on {b}/{a}, the density run on {}/{}",
                section.backend,
                section.architecture
            ),
            _ => false,
        };
        let stats: SpanStats = report.stats.dispatch_window_ms;
        if stats.samples == 0 {
            bail!("the `{name}` launch report carries no samples");
        }
        if slot.replace((stats, attributed)).is_some() {
            bail!("two launch reports for lane `{name}`");
        }
    }
    let figure = |slot: Option<(SpanStats, bool)>| match slot {
        Some((s, true)) => Some(Figure::measured(s)),
        Some((_, false)) => Some(Figure::unmeasured(
            "launch report does not record its backend and architecture",
        )),
        None => None,
    };
    if let Some(f) = figure(cold) {
        section.latencies.cold_launch_ms = f;
    }
    if let Some(f) = figure(warm) {
        section.latencies.warm_launch_ms = f;
    }
    Ok(())
}

/// The whole report: one density section plus any launch reports.
pub fn assemble(density_dir: &Path, launch_reports: &[PathBuf]) -> Result<ResourceReport> {
    let mut section = from_density_dir(density_dir)?;
    let reports = launch_reports
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str::<ColdLaunchReport>(&text)
                .with_context(|| format!("{} is not a launch report", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    fold_launch_reports(&mut section, &reports)?;
    let mut report = ResourceReport::default();
    report.sections.push(section);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::cold_launch::build_cold_launch_report;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/density-run")
    }

    /// A copy of the fixture whose summary.tsv has been rewritten by `edit`.
    fn edited(edit: impl FnOnce(String) -> String) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let from = fixture();
        std::fs::create_dir(tmp.path().join("wave-0")).unwrap();
        std::fs::create_dir(tmp.path().join("wave-2")).unwrap();
        for file in [
            "metadata.json",
            "wave-0/physical-memory-settled.json",
            "wave-2/physical-memory-before.json",
            "wave-2/physical-memory-settled.json",
        ] {
            std::fs::copy(from.join(file), tmp.path().join(file)).unwrap();
        }
        let summary = std::fs::read_to_string(from.join("summary.tsv")).unwrap();
        std::fs::write(tmp.path().join("summary.tsv"), edit(summary)).unwrap();
        tmp
    }

    fn measured<T: Copy>(f: &Figure<T>) -> T {
        *f.value().expect("figure should be measured")
    }

    #[test]
    fn the_recorded_fixture_ingests_with_per_unit_arithmetic() {
        let s = from_density_dir(&fixture()).unwrap();
        assert_eq!(
            (s.backend.as_str(), s.architecture.as_str()),
            ("hvf", "aarch64")
        );
        assert_eq!(
            s.fixed_host_cost.wakeups.quantity,
            WakeupQuantity::MacosLibproc
        );
        assert_eq!(measured(&s.fixed_host_cost.idle_cpu_millicores), 10.0);
        assert_eq!(measured(&s.fixed_host_cost.wakeups.per_second), 5.0);
        assert_eq!(measured(&s.fixed_host_cost.memory_bytes), 7_000_000);
        assert_eq!(measured(&s.fixed_host_cost.disk_bytes), 4096 * 1024);

        // Wave 2: (6 + 12) - 10 baseline = 8 millicores over 2 observed units.
        let run = &s.by_residency.running;
        assert_eq!(measured(&run.cpu_millicores), 4.0);
        assert_eq!(measured(&run.wakeups.per_second), 2.5);
        assert_eq!(measured(&run.disk_bytes), 2048 * 1024 / 2);
        assert_eq!(measured(&run.memory_bytes), 20_000_000);
        assert!(s.by_standby.resident.cpu_millicores.value().is_none());
        assert!(s.by_residency.idle.cpu_millicores.value().is_none());
    }

    #[test]
    fn a_missing_baseline_is_an_error() {
        let dir = edited(|s| {
            s.lines()
                .filter(|l| !l.starts_with("wave_0_idle_"))
                .collect::<Vec<_>>()
                .join("\n")
        });
        let err = from_density_dir(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("baseline"), "{err:#}");
    }

    #[test]
    fn a_partial_wave_is_an_error() {
        let dir = edited(|s| {
            s.lines()
                .filter(|l| !l.starts_with("wave_2_cleanup_ok"))
                .collect::<Vec<_>>()
                .join("\n")
        });
        let err = from_density_dir(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("wave_2_cleanup_ok"), "{err:#}");

        let dir = edited(|s| s.replace("wave_2_idle_mvm-host-agent_wakeups_per_second\t6.0", ""));
        let err = from_density_dir(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("partial"), "{err:#}");
    }

    #[test]
    fn a_declared_wave_with_no_record_is_an_error() {
        let dir = edited(|s| s.replace("waves\t1 2", "waves\t1 2 5"));
        // metadata.json decides the declared waves; edit the copy too.
        let meta = std::fs::read_to_string(dir.path().join("metadata.json")).unwrap();
        std::fs::write(
            dir.path().join("metadata.json"),
            meta.replace("\"1 2\"", "\"1 2 5\""),
        )
        .unwrap();
        assert!(from_density_dir(dir.path()).is_err());
    }

    #[test]
    fn an_unparseable_number_is_an_error() {
        let dir = edited(|s| {
            s.replace(
                "wave_2_idle_mvm-hvf-supervisor_cpu_millicores\t6.0",
                "wave_2_idle_mvm-hvf-supervisor_cpu_millicores\tfast",
            )
        });
        let err = from_density_dir(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("fast"), "{err:#}");
    }

    #[test]
    fn a_baseline_above_the_wave_is_an_error() {
        let dir = edited(|s| {
            s.replace(
                "wave_0_idle_mvm-host-agent_cpu_millicores\t10.0",
                "wave_0_idle_mvm-host-agent_cpu_millicores\t99.0",
            )
        });
        assert!(from_density_dir(dir.path()).is_err());
    }

    #[test]
    fn an_unrun_sampler_leaves_cpu_unmeasured_with_its_marker() {
        let dir = edited(|s| {
            s.lines()
                .filter(|l| !l.starts_with("wave_0_idle_"))
                .chain(["wave_0_idle_sampler\tnot_requested"])
                .collect::<Vec<_>>()
                .join("\n")
        });
        let s = from_density_dir(dir.path()).unwrap();
        match &s.by_residency.running.cpu_millicores {
            Figure::Unmeasured { reason } => assert!(reason.contains("not_requested")),
            Figure::Measured { .. } => panic!("cpu cannot be measured without a baseline sample"),
        }
    }

    #[test]
    fn standby_mode_uses_the_per_standby_keys_for_the_resident_class() {
        let dir = edited(|s| {
            format!(
                "{s}\nwave_2_idle_mvm-hvf-supervisor_cpu_millicores_per_standby\t3.0\n\
                 wave_2_idle_mvm-hvf-supervisor_wakeups_per_second_per_standby\t2.0\n\
                 wave_2_idle_mvm-host-agent_cpu_millicores_per_standby\t6.0\n\
                 wave_2_idle_mvm-host-agent_wakeups_per_second_per_standby\t3.0\n"
            )
        });
        let meta = std::fs::read_to_string(dir.path().join("metadata.json")).unwrap();
        std::fs::write(
            dir.path().join("metadata.json"),
            meta.replace("\"cold\"", "\"standby\"")
                .replace("\"1 2\"", "\"2\""),
        )
        .unwrap();
        let s = from_density_dir(dir.path()).unwrap();
        // (3 + 6) per standby, less the baseline's 10 / 2 units.
        assert_eq!(measured(&s.by_standby.resident.cpu_millicores), 4.0);
        assert_eq!(measured(&s.by_standby.resident.wakeups.per_second), 2.5);
        assert!(s.by_residency.running.cpu_millicores.value().is_none());
    }

    fn launch_report(lane: LaunchLane, samples: &[f64]) -> ColdLaunchReport {
        let mut report = build_cold_launch_report(lane, 0, Vec::new());
        report.stats.dispatch_window_ms = SpanStats::from_samples(samples);
        report.backend = Some("hvf".into());
        report.architecture = Some("aarch64".into());
        report
    }

    /// The fixture with `metadata.json` and the memory captures rewritten.
    fn with_meta(edit: impl FnOnce(String) -> String) -> tempfile::TempDir {
        let dir = edited(|s| s);
        let path = dir.path().join("metadata.json");
        let meta = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, edit(meta)).unwrap();
        dir
    }

    fn write_capture(dir: &tempfile::TempDir, file: &str, body: &str) {
        std::fs::write(dir.path().join("wave-2").join(file), body).unwrap();
    }

    fn error_of(dir: &tempfile::TempDir) -> String {
        format!("{:#}", from_density_dir(dir.path()).unwrap_err())
    }

    #[test]
    fn a_linux_firecracker_run_reports_procfs_wakeups_and_unmeasured_memory() {
        let dir = with_meta(|m| {
            m.replace("Darwin", "Linux")
                .replace("arm64", "x86_64")
                .replace("\"hvf\"", "\"firecracker\"")
        });
        let unavailable = r#"{"status": "unavailable", "processes": []}"#;
        write_capture(&dir, "physical-memory-before.json", unavailable);
        write_capture(&dir, "physical-memory-settled.json", unavailable);
        std::fs::write(
            dir.path().join("wave-0/physical-memory-settled.json"),
            unavailable,
        )
        .unwrap();
        let s = from_density_dir(dir.path()).unwrap();
        assert_eq!(s.backend, "firecracker");
        assert_eq!(
            s.by_residency.running.wakeups.quantity,
            WakeupQuantity::LinuxProcfs
        );
        match &s.by_residency.running.memory_bytes {
            Figure::Unmeasured { reason } => assert!(reason.contains("unavailable")),
            Figure::Measured { .. } => panic!("memory must stay unmeasured"),
        }
    }

    fn linux_run(wave_0: &str, before: &str, settled: &str) -> tempfile::TempDir {
        let dir = with_meta(|m| {
            m.replace("Darwin", "Linux")
                .replace("arm64", "x86_64")
                .replace("\"hvf\"", "\"firecracker\"")
        });
        std::fs::write(
            dir.path().join("wave-0/physical-memory-settled.json"),
            wave_0,
        )
        .unwrap();
        write_capture(&dir, "physical-memory-before.json", before);
        write_capture(&dir, "physical-memory-settled.json", settled);
        dir
    }

    fn pss_capture(bytes: u64) -> String {
        format!(
            r#"{{"status": "measured", "quantity": "proportional_set_size", "processes": [{{"proportional_set_size_bytes": {bytes}}}]}}"#
        )
    }

    #[test]
    fn a_linux_run_reports_proportional_set_size_and_says_so() {
        let dir = linux_run(&pss_capture(5000), &pss_capture(1000), &pss_capture(5000));
        let s = from_density_dir(dir.path()).unwrap();
        assert_eq!(s.memory_quantity, MemoryQuantity::ProportionalSetSize);
        assert_eq!(s.fixed_host_cost.memory_bytes, Figure::measured(5000));
        assert_eq!(s.by_residency.running.memory_bytes, Figure::measured(2000));
        let md = crate::bench::resource_report::render_markdown(&ResourceReport {
            sections: vec![s],
            ..ResourceReport::default()
        });
        assert!(md.contains("proportional set size"));
    }

    #[test]
    fn a_capture_of_the_other_quantity_is_refused() {
        let footprint = r#"{"status": "measured", "processes": [{"physical_footprint_bytes": 1}]}"#;
        let dir = linux_run(&pss_capture(5000), footprint, &pss_capture(5000));
        assert!(error_of(&dir).contains("measured physical footprint"));
    }

    #[test]
    fn a_macos_run_with_an_unlabelled_capture_is_a_physical_footprint() {
        let s = from_density_dir(&fixture()).unwrap();
        assert_eq!(s.memory_quantity, MemoryQuantity::PhysicalFootprint);
        assert_eq!(s.fixed_host_cost.memory_bytes, Figure::measured(7_000_000));
    }

    #[test]
    fn a_launch_report_from_another_backend_is_an_error() {
        let mut s = from_density_dir(&fixture()).unwrap();
        let mut report = launch_report(LaunchLane::PreparedCold, &[1.0]);
        report.backend = Some("firecracker".into());
        assert!(fold_launch_reports(&mut s, &[report]).is_err());
        let mut report = launch_report(LaunchLane::PreparedCold, &[1.0]);
        report.architecture = Some("x86_64".into());
        assert!(fold_launch_reports(&mut s, &[report]).is_err());
    }

    #[test]
    fn a_launch_report_without_its_platform_stays_unmeasured() {
        let mut s = from_density_dir(&fixture()).unwrap();
        let mut report = launch_report(LaunchLane::PreparedCold, &[1.0]);
        report.backend = None;
        fold_launch_reports(&mut s, &[report]).unwrap();
        match &s.latencies.cold_launch_ms {
            Figure::Unmeasured { reason } => {
                assert_eq!(
                    reason,
                    "launch report does not record its backend and architecture"
                );
            }
            Figure::Measured { .. } => panic!("an unattributed report must not be published"),
        }
    }

    #[test]
    fn an_observed_count_that_is_not_the_wave_size_is_an_error() {
        let dir = edited(|s| s.replace("wave_2_vmm_processes\t2", "wave_2_vmm_processes\t3"));
        assert!(error_of(&dir).contains("must equal the wave size"));
        let dir = edited(|s| s.replace("wave_2_vmm_processes\t2", "wave_2_vmm_processes\t0"));
        assert!(from_density_dir(dir.path()).is_err());
    }

    #[test]
    fn a_warm_mode_run_is_not_ingested() {
        let dir = with_meta(|m| m.replace("\"cold\"", "\"warm\""));
        assert!(error_of(&dir).contains("not ingested yet"));
    }

    #[test]
    fn a_shrinking_host_footprint_is_unmeasured_not_an_error() {
        let dir = edited(|s| s);
        write_capture(
            &dir,
            "physical-memory-settled.json",
            r#"{"status": "measured", "processes": [{"physical_footprint_bytes": 1}]}"#,
        );
        let s = from_density_dir(dir.path()).unwrap();
        match &s.by_residency.running.memory_bytes {
            Figure::Unmeasured { reason } => assert!(reason.contains("shrank")),
            Figure::Measured { .. } => panic!("a shrink cannot be a measurement"),
        }
    }

    fn reason_of<T>(f: &Figure<T>) -> &str {
        match f {
            Figure::Unmeasured { reason } => reason,
            Figure::Measured { .. } => panic!("figure must stay unmeasured"),
        }
    }

    #[test]
    fn a_run_without_wave_0_captures_leaves_fixed_memory_and_disk_unmeasured() {
        let dir = edited(|s| s.replace("wave_0_mvm_home_du_kib\t4096\n", ""));
        std::fs::remove_file(dir.path().join("wave-0/physical-memory-settled.json")).unwrap();
        let s = from_density_dir(dir.path()).unwrap();
        assert_eq!(
            reason_of(&s.fixed_host_cost.memory_bytes),
            "the run has no wave-0 memory capture"
        );
        assert_eq!(
            reason_of(&s.fixed_host_cost.disk_bytes),
            "the run has no wave-0 storage capture"
        );
    }

    #[test]
    fn an_unavailable_wave_0_capture_carries_its_own_reason() {
        let dir = edited(|s| s);
        std::fs::write(
            dir.path().join("wave-0/physical-memory-settled.json"),
            r#"{"schema_version": 1, "status": "unavailable", "reason": "unsupported_platform"}"#,
        )
        .unwrap();
        let s = from_density_dir(dir.path()).unwrap();
        assert!(reason_of(&s.fixed_host_cost.memory_bytes).contains("unsupported_platform"));
        assert_eq!(measured(&s.fixed_host_cost.disk_bytes), 4096 * 1024);
    }

    #[test]
    fn an_unparseable_wave_0_disk_figure_is_an_error() {
        let dir = edited(|s| s.replace("wave_0_mvm_home_du_kib\t4096", "wave_0_mvm_home_du_kib\t"));
        assert!(error_of(&dir).contains("wave_0_mvm_home_du_kib"));
    }

    #[test]
    fn a_missing_memory_capture_is_an_error() {
        let dir = edited(|s| s);
        std::fs::remove_file(dir.path().join("wave-2/physical-memory-settled.json")).unwrap();
        assert!(error_of(&dir).contains("physical-memory-settled.json"));
    }

    #[test]
    fn a_measured_capture_without_processes_is_an_error() {
        let dir = edited(|s| s);
        write_capture(
            &dir,
            "physical-memory-before.json",
            r#"{"status": "measured"}"#,
        );
        assert!(error_of(&dir).contains("no processes array"));
    }

    #[test]
    fn a_bypassed_native_host_guard_is_an_error() {
        let dir = with_meta(|m| {
            m.replace(
                "\"native_host_bypassed\": false",
                "\"native_host_bypassed\": true",
            )
        });
        assert!(error_of(&dir).contains("bypassed"));
        let dir = with_meta(|m| m.replace("\"native_host_bypassed\": false, ", ""));
        assert!(from_density_dir(dir.path()).is_err());
    }

    #[test]
    fn launch_reports_fold_into_cold_and_warm_latencies() {
        let mut s = from_density_dir(&fixture()).unwrap();
        fold_launch_reports(
            &mut s,
            &[
                launch_report(LaunchLane::PreparedCold, &[100.0, 110.0]),
                launch_report(LaunchLane::WarmClaim, &[20.0]),
            ],
        )
        .unwrap();
        assert_eq!(measured(&s.latencies.cold_launch_ms).samples, 2);
        assert_eq!(measured(&s.latencies.warm_launch_ms).samples, 1);
        assert!(s.latencies.failover_ms.value().is_none());
    }

    #[test]
    fn a_duplicate_empty_or_unslotted_launch_report_is_refused() {
        let mut s = from_density_dir(&fixture()).unwrap();
        let cold = launch_report(LaunchLane::PreparedCold, &[1.0]);
        assert!(fold_launch_reports(&mut s, &[cold.clone(), cold]).is_err());
        let empty = launch_report(LaunchLane::PreparedCold, &[]);
        assert!(fold_launch_reports(&mut s, &[empty]).is_err());
        let mount = launch_report(LaunchLane::MountMiss, &[1.0]);
        assert!(fold_launch_reports(&mut s, &[mount]).is_err());
    }
}

//! Observed resource figures and the reproducibility compare.
//!
//! A resource report is read as plain JSON: a section's scalar fields are
//! named in [`SECTION_SCALARS`], every object carrying a `status` key is a
//! figure, and every other object is walked. xtask does not link the CLI
//! crate, so the schema is followed by field name only; a checked-in report
//! written by the CLI's own serializer keeps the two from drifting.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Leaves of a latency summary that the compare checks; the rest are listed
/// as observed but never compared (max and p99 are single-sample noise).
const COMPARED_STATS: [&str; 2] = ["p50", "p95"];

/// Section fields that are not figure groups: labels, and the per-thread
/// wakeup attribution, whose thread names are not stable enough to compare.
const SECTION_SCALARS: [&str; 5] = [
    "backend",
    "architecture",
    "memory_quantity",
    "endpoint_form",
    "thread_wakeups",
];

/// What a section's memory figures mean when it predates the label.
const DEFAULT_MEMORY_QUANTITY: &str = "physical_footprint";

/// The endpoint a section measured when the CLI omits the label.
const DEFAULT_ENDPOINT_FORM: &str = "collector_only";

/// The flag that lets a comparison run on reports that cannot be published.
const ALLOW_UNPUBLISHABLE: &str = "--allow-unpublishable";

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Reading {
    Measured(f64),
    Unmeasured(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Figure {
    pub path: String,
    pub reading: Reading,
    pub compared: bool,
}

#[derive(Debug)]
pub(super) struct Section {
    pub backend: String,
    pub architecture: String,
    pub memory_quantity: String,
    pub endpoint_form: String,
    pub figures: Vec<Figure>,
}

#[derive(Debug, Clone, PartialEq)]
pub(super) struct Source {
    pub commit: String,
    pub dirty: bool,
}

#[derive(Debug)]
pub(super) struct Report {
    pub schema_version: u64,
    /// `None` for a report written before the CLI recorded its source.
    pub source: Option<Source>,
    pub sections: Vec<Section>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct Observed {
    pub source: String,
    pub backend: String,
    pub architecture: String,
    pub figure: String,
    pub status: &'static str,
    pub value: Option<f64>,
    pub unit: &'static str,
    pub reason: Option<String>,
}

fn unit_for(path: &str) -> &'static str {
    if path.contains("bytes") {
        "bytes"
    } else if path.contains("millicores") {
        "millicores"
    } else if path.contains("_ms") {
        "ms"
    } else if path.ends_with("per_second") {
        "per_second"
    } else {
        ""
    }
}

pub(super) fn parse_report(name: &str, text: &str) -> Result<Report> {
    let root: Value =
        serde_json::from_str(text).with_context(|| format!("{name}: invalid JSON"))?;
    let schema_version = root
        .get("schema_version")
        .and_then(Value::as_u64)
        .with_context(|| format!("{name}: schema_version missing or not an integer"))?;
    let sections = root
        .get("sections")
        .and_then(Value::as_array)
        .with_context(|| format!("{name}: sections missing or not an array"))?;
    let mut out = Vec::new();
    for (i, s) in sections.iter().enumerate() {
        let at = format!("sections[{i}]");
        let obj = s
            .as_object()
            .with_context(|| format!("{name}: {at} is not an object"))?;
        let text_field = |key: &str| -> Result<String> {
            obj.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .with_context(|| format!("{name}: {at}.{key} missing or not a string"))
        };
        let mut figures = Vec::new();
        for (key, v) in obj {
            if !SECTION_SCALARS.contains(&key.as_str()) {
                walk(name, &format!("{at}.{key}"), v, &mut figures)?;
            }
        }
        let memory_quantity = match obj.get("memory_quantity") {
            None => DEFAULT_MEMORY_QUANTITY.to_owned(),
            Some(_) => text_field("memory_quantity")?,
        };
        let endpoint_form = match obj.get("endpoint_form") {
            None => DEFAULT_ENDPOINT_FORM.to_owned(),
            Some(_) => text_field("endpoint_form")?,
        };
        out.push(Section {
            backend: text_field("backend")?,
            architecture: text_field("architecture")?,
            memory_quantity,
            endpoint_form,
            figures,
        });
    }
    Ok(Report {
        schema_version,
        source: parse_source(name, root.get("source"))?,
        sections: out,
    })
}

fn parse_source(name: &str, v: Option<&Value>) -> Result<Option<Source>> {
    let Some(v) = v else {
        return Ok(None);
    };
    let commit = v
        .get("commit")
        .and_then(Value::as_str)
        .with_context(|| format!("{name}: source.commit missing or not a string"))?;
    let dirty = v
        .get("dirty")
        .and_then(Value::as_bool)
        .with_context(|| format!("{name}: source.dirty missing or not a boolean"))?;
    Ok(Some(Source {
        commit: commit.to_owned(),
        dirty,
    }))
}

/// `at` is the path for error messages; the figure path drops the
/// `sections[i].` prefix.
fn walk(name: &str, at: &str, v: &Value, out: &mut Vec<Figure>) -> Result<()> {
    let path = at.split_once('.').map_or(at, |(_, rest)| rest).to_owned();
    let obj = v
        .as_object()
        .with_context(|| format!("{name}: {at} is not an object"))?;
    if obj.contains_key("status") {
        return figure(name, at, &path, obj, out);
    }
    for (k, child) in obj {
        // `quantity` labels a wakeup rate; it is a string, not a figure.
        if child.is_string() {
            continue;
        }
        walk(name, &format!("{at}.{k}"), child, out)?;
    }
    Ok(())
}

fn figure(
    name: &str,
    at: &str,
    path: &str,
    obj: &serde_json::Map<String, Value>,
    out: &mut Vec<Figure>,
) -> Result<()> {
    match obj.get("status").and_then(Value::as_str) {
        Some("unmeasured") => {
            let reason = obj
                .get("reason")
                .and_then(Value::as_str)
                .with_context(|| format!("{name}: {at}.reason missing or not a string"))?;
            out.push(Figure {
                path: path.to_owned(),
                reading: Reading::Unmeasured(reason.to_owned()),
                compared: true,
            });
        }
        Some("measured") => match obj.get("value") {
            Some(Value::Number(n)) => out.push(Figure {
                path: path.to_owned(),
                reading: Reading::Measured(n.as_f64().unwrap_or(f64::NAN)),
                compared: true,
            }),
            Some(Value::Object(stats)) => {
                for (stat, sv) in stats {
                    let reading = match sv {
                        Value::Number(n) => Reading::Measured(n.as_f64().unwrap_or(f64::NAN)),
                        Value::Null => {
                            Reading::Unmeasured("too few samples for this percentile".to_owned())
                        }
                        _ => bail!("{name}: {at}.value.{stat} is not a number"),
                    };
                    out.push(Figure {
                        path: format!("{path}.{stat}"),
                        reading,
                        compared: COMPARED_STATS.contains(&stat.as_str()),
                    });
                }
            }
            _ => bail!("{name}: {at}.value missing or not a number or stats object"),
        },
        _ => bail!("{name}: {at}.status must be \"measured\" or \"unmeasured\""),
    }
    Ok(())
}

pub(super) fn load_report(path: &Path) -> Result<Report> {
    let name = path.display().to_string();
    let text = std::fs::read_to_string(path).with_context(|| format!("{name}: cannot read"))?;
    parse_report(&name, &text)
}

/// Reports committed in `dir`, sorted by file name. A missing directory is
/// an empty set.
pub(super) fn committed_reports(dir: &Path) -> Result<Vec<(String, Report)>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let file = p
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            Ok((file, load_report(&p)?))
        })
        .collect()
}

pub(super) fn observed_rows(reports: &[(String, Report)]) -> Vec<Observed> {
    let mut rows = Vec::new();
    for (source, report) in reports {
        for s in &report.sections {
            for f in &s.figures {
                let (status, value, reason) = match &f.reading {
                    Reading::Measured(v) => ("measured", Some(*v), None),
                    Reading::Unmeasured(r) => ("unmeasured", None, Some(r.clone())),
                };
                rows.push(Observed {
                    source: source.clone(),
                    backend: s.backend.clone(),
                    architecture: s.architecture.clone(),
                    figure: f.path.clone(),
                    status,
                    value,
                    unit: unit_for(&f.path),
                    reason,
                });
            }
        }
    }
    rows
}

pub(super) fn render_observed_human(rows: &[Observed]) {
    eprintln!();
    eprintln!("observed figures (not budgets) — {} row(s)", rows.len());
    for r in rows {
        let shown = match (r.value, &r.reason) {
            (Some(v), _) => format!("{v} {}", r.unit),
            (None, reason) => format!("unmeasured ({})", reason.as_deref().unwrap_or("")),
        };
        eprintln!(
            "  [{}] {}/{} {} = {}",
            r.source, r.backend, r.architecture, r.figure, shown
        );
    }
}

fn relative_percent(a: f64, b: f64) -> f64 {
    let larger = a.abs().max(b.abs());
    if larger == 0.0 {
        0.0
    } else {
        (a - b).abs() / larger * 100.0
    }
}

/// Err names the first figure outside `tolerance` percent.
pub(super) fn compare(a: &Report, b: &Report, tolerance: f64) -> Result<()> {
    if a.schema_version != b.schema_version {
        bail!(
            "schema_version differs: {} vs {}",
            a.schema_version,
            b.schema_version
        );
    }
    for sa in &a.sections {
        let id = format!("{}/{}", sa.backend, sa.architecture);
        let Some(sb) = b
            .sections
            .iter()
            .find(|s| s.backend == sa.backend && s.architecture == sa.architecture)
        else {
            bail!("section {id} is present in A only");
        };
        if sa.memory_quantity != sb.memory_quantity {
            bail!(
                "section {id} measures memory as {} in A and {} in B; the two are not comparable",
                sa.memory_quantity,
                sb.memory_quantity
            );
        }
        if sa.endpoint_form != sb.endpoint_form {
            bail!(
                "section {id} measured a {} endpoint in A and a {} endpoint in B; the two are not comparable",
                sa.endpoint_form,
                sb.endpoint_form
            );
        }
        if let Some(fb) = sb
            .figures
            .iter()
            .filter(|f| f.compared)
            .find(|f| !sa.figures.iter().any(|x| x.path == f.path))
        {
            bail!("{id} {}: present in B only", fb.path);
        }
        for fa in sa.figures.iter().filter(|f| f.compared) {
            let Some(fb) = sb.figures.iter().find(|f| f.path == fa.path) else {
                bail!("{id} {}: present in A only", fa.path);
            };
            match (&fa.reading, &fb.reading) {
                (Reading::Unmeasured(_), Reading::Unmeasured(_)) => {}
                (Reading::Measured(x), Reading::Measured(y)) => {
                    let pct = relative_percent(*x, *y);
                    if pct.is_nan() || pct > tolerance {
                        bail!(
                            "{id} {}: {x} vs {y}, relative difference {pct:.2}% exceeds {tolerance}%",
                            fa.path
                        );
                    }
                }
                (x, y) => bail!(
                    "{id} {}: measured in one report and unmeasured in the other ({x:?} vs {y:?})",
                    fa.path
                ),
            }
        }
    }
    if let Some(sb) = b.sections.iter().find(|sb| {
        !a.sections
            .iter()
            .any(|sa| sa.backend == sb.backend && sa.architecture == sb.architecture)
    }) {
        bail!(
            "section {}/{} is present in B only",
            sb.backend,
            sb.architecture
        );
    }
    Ok(())
}

/// Why the pair cannot back a published figure; empty when it can.
pub(super) fn unpublishable_reasons(a: &Report, b: &Report) -> Vec<String> {
    let mut reasons = Vec::new();
    for (label, r) in [("A", a), ("B", b)] {
        match &r.source {
            None => reasons.push(format!("{label} does not record its source commit")),
            Some(s) if s.dirty => reasons.push(format!(
                "{label} was measured from a modified tree at {}",
                s.commit
            )),
            Some(_) => {}
        }
    }
    if let (Some(sa), Some(sb)) = (&a.source, &b.source)
        && sa.commit != sb.commit
    {
        reasons.push(format!(
            "A and B were built from different commits ({} vs {})",
            sa.commit, sb.commit
        ));
    }
    reasons
}

pub(super) fn compare_subcommand(args: &[String]) -> Result<()> {
    let mut files = Vec::new();
    let mut tolerance = None;
    let mut allow_unpublishable = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == ALLOW_UNPUBLISHABLE {
            allow_unpublishable = true;
        } else if a == "--tolerance" {
            let v = it.next().context("--tolerance needs a percent value")?;
            let t: f64 = v.parse().with_context(|| format!("bad tolerance {v:?}"))?;
            if !t.is_finite() || t < 0.0 {
                bail!("tolerance must be a non-negative number, got {v:?}");
            }
            tolerance = Some(t);
        } else {
            files.push(a);
        }
    }
    let (Some(tolerance), [fa, fb]) = (tolerance, files.as_slice()) else {
        bail!(
            "usage: perf resource-compare <A.json> <B.json> --tolerance <PERCENT> [{ALLOW_UNPUBLISHABLE}]"
        );
    };
    let (a, b) = (load_report(Path::new(fa))?, load_report(Path::new(fb))?);
    let reasons = unpublishable_reasons(&a, &b);
    if !reasons.is_empty() && !allow_unpublishable {
        bail!(
            "refusing to compare: {}. Pass {ALLOW_UNPUBLISHABLE} to compare anyway; \
             the result cannot be published",
            reasons.join("; ")
        );
    }
    compare(&a, &b, tolerance)?;
    if reasons.is_empty() {
        eprintln!("resource reports agree within {tolerance}%");
    } else {
        eprintln!(
            "resource reports agree within {tolerance}%, but the comparison is NOT publishable: {}",
            reasons.join("; ")
        );
    }
    Ok(())
}

/// The `--json` body: the bare budget array unless observed rows exist.
pub(super) fn budgets_json<B: serde::Serialize>(
    budgets: &B,
    observed: &[Observed],
) -> Result<String> {
    Ok(if observed.is_empty() {
        serde_json::to_string_pretty(budgets)?
    } else {
        serde_json::to_string_pretty(
            &serde_json::json!({ "budgets": budgets, "observed": observed }),
        )?
    })
}

pub(super) fn committed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("data/evidence/performance/resource")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(mem: u64, p50: f64, idle: &str) -> String {
        let idle_fig = if idle.is_empty() {
            r#"{"status":"measured","value":7.5}"#.to_owned()
        } else {
            format!(r#"{{"status":"unmeasured","reason":"{idle}"}}"#)
        };
        format!(
            r#"{{"schema_version":1,"sections":[{{"backend":"testvmm","architecture":"testarch",
"fixed_host_cost":{{"memory_bytes":{{"status":"measured","value":{mem}}},
"idle_cpu_millicores":{idle_fig},
"wakeups":{{"quantity":"linux_procfs","per_second":{{"status":"unmeasured","reason":"not measured"}}}}}},
"latencies":{{"cold_launch_ms":{{"status":"measured","value":{{"samples":3,"p50":{p50},"p95":20.0,"p99":null,"max":999.0}}}}}}}}]}}"#
        )
    }

    fn parse(t: &str) -> Report {
        parse_report("t.json", t).unwrap()
    }

    #[test]
    fn observed_rows_list_values_with_units_and_unmeasured_reasons() {
        let r = parse(&fixture(1000, 10.0, "needs a quiet host"));
        let rows = observed_rows(&[("t.json".into(), r)]);
        let mem = rows
            .iter()
            .find(|x| x.figure == "fixed_host_cost.memory_bytes")
            .unwrap();
        assert_eq!(
            (mem.value, mem.unit, mem.backend.as_str()),
            (Some(1000.0), "bytes", "testvmm")
        );
        let idle = rows
            .iter()
            .find(|x| x.figure == "fixed_host_cost.idle_cpu_millicores")
            .unwrap();
        assert_eq!(
            (idle.value, idle.reason.as_deref()),
            (None, Some("needs a quiet host"))
        );
        let p50 = rows
            .iter()
            .find(|x| x.figure == "latencies.cold_launch_ms.p50")
            .unwrap();
        assert_eq!((p50.value, p50.unit), (Some(10.0), "ms"));
        let p99 = rows
            .iter()
            .find(|x| x.figure == "latencies.cold_launch_ms.p99")
            .unwrap();
        assert_eq!(p99.status, "unmeasured");
        assert_eq!(
            p99.reason.as_deref(),
            Some("too few samples for this percentile")
        );
        assert!(rows.iter().all(|x| x.source == "t.json"));
    }

    #[test]
    fn budgets_json_is_the_bare_array_without_reports() {
        let budgets = ["a", "b"];
        assert_eq!(
            budgets_json(&budgets, &[]).unwrap(),
            serde_json::to_string_pretty(&budgets).unwrap()
        );
        let rows = observed_rows(&[("t.json".into(), parse(&fixture(1, 1.0, "")))]);
        let v: Value = serde_json::from_str(&budgets_json(&budgets, &rows).unwrap()).unwrap();
        assert!(v["budgets"].is_array() && v["observed"].is_array());
    }

    #[test]
    fn a_missing_directory_has_no_reports() {
        assert!(
            committed_reports(Path::new("/nonexistent/mvm-5695"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn committed_reports_parse_and_a_bad_file_is_refused_by_name() {
        committed_reports(&committed_dir()).unwrap();
        let dir = std::env::temp_dir().join(format!("mvm-5695-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("broken.json"), "{").unwrap();
        let e = committed_reports(&dir).unwrap_err().to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            e.contains("broken.json") && e.contains("invalid JSON"),
            "{e}"
        );
    }

    #[test]
    fn compare_passes_within_tolerance_and_ignores_max() {
        let a = parse(&fixture(1000, 10.0, ""));
        let b = parse(&fixture(1040, 10.2, ""));
        compare(&a, &b, 5.0).unwrap();
    }

    #[test]
    fn compare_names_the_first_figure_outside_tolerance() {
        let a = parse(&fixture(1000, 10.0, ""));
        let b = parse(&fixture(2000, 10.0, ""));
        let e = compare(&a, &b, 5.0).unwrap_err().to_string();
        assert!(
            e.contains("fixed_host_cost.memory_bytes") && e.contains("1000") && e.contains("2000"),
            "{e}"
        );
        assert!(e.contains("50.00%"), "{e}");
    }

    #[test]
    fn compare_fails_on_measured_versus_unmeasured_but_not_both_unmeasured() {
        let m = parse(&fixture(1000, 10.0, ""));
        let u = parse(&fixture(1000, 10.0, "why"));
        let e = compare(&m, &u, 100.0).unwrap_err().to_string();
        assert!(
            e.contains("idle_cpu_millicores") && e.contains("unmeasured"),
            "{e}"
        );
        compare(&u, &parse(&fixture(1000, 10.0, "other")), 0.0).unwrap();
    }

    #[test]
    fn compare_fails_on_a_missing_section_and_on_schema_mismatch() {
        let a = parse(&fixture(1, 1.0, ""));
        let empty = parse(r#"{"schema_version":1,"sections":[]}"#);
        assert!(
            compare(&a, &empty, 1.0)
                .unwrap_err()
                .to_string()
                .contains("A only")
        );
        assert!(
            compare(&empty, &a, 1.0)
                .unwrap_err()
                .to_string()
                .contains("B only")
        );
        let v2 = parse(r#"{"schema_version":2,"sections":[]}"#);
        assert!(
            compare(&empty, &v2, 1.0)
                .unwrap_err()
                .to_string()
                .contains("schema_version")
        );
    }

    #[test]
    fn compare_fails_on_a_figure_only_in_b() {
        let a = parse(&fixture(1, 1.0, ""));
        let mut b = parse(&fixture(1, 1.0, ""));
        b.sections[0].figures.push(Figure {
            path: "fixed_host_cost.disk_bytes".into(),
            reading: Reading::Measured(1.0),
            compared: true,
        });
        let e = compare(&a, &b, 100.0).unwrap_err().to_string();
        assert!(e.contains("disk_bytes") && e.contains("B only"), "{e}");
    }

    /// Written by the CLI's own serializer and held current by a CLI test.
    const CLI_REPORT: &str =
        include_str!("../../../crates/mvm-cli/tests/fixtures/resource-report.json");

    fn cli_report_with(edit: impl FnOnce(&mut Value)) -> Report {
        let mut v: Value = serde_json::from_str(CLI_REPORT).unwrap();
        edit(&mut v);
        parse(&v.to_string())
    }

    #[test]
    fn a_report_from_the_cli_serializer_parses_and_compares_with_itself() {
        let r = parse(CLI_REPORT);
        let s = &r.sections[0];
        assert_eq!(s.memory_quantity, "physical_footprint");
        assert!(
            s.figures
                .iter()
                .any(|f| f.path == "fixed_host_cost.memory_bytes")
        );
        assert!(r.source.is_some());
        compare(&r, &parse(CLI_REPORT), 0.0).unwrap();
        assert!(unpublishable_reasons(&r, &parse(CLI_REPORT)).is_empty());
    }

    #[test]
    fn sections_measuring_different_memory_quantities_are_not_compared() {
        let a = parse(CLI_REPORT);
        let b = cli_report_with(|v| {
            v["sections"][0]["memory_quantity"] = "proportional_set_size".into();
        });
        let e = compare(&a, &b, 100.0).unwrap_err().to_string();
        assert!(
            e.contains("physical_footprint") && e.contains("proportional_set_size"),
            "{e}"
        );
        let unlabelled = cli_report_with(|v| {
            v["sections"][0]
                .as_object_mut()
                .unwrap()
                .remove("memory_quantity");
        });
        compare(&a, &unlabelled, 0.0).unwrap();
    }

    #[test]
    fn sections_measuring_different_endpoint_forms_are_not_compared() {
        let a = parse(CLI_REPORT);
        assert_eq!(a.sections[0].endpoint_form, "collector_only");
        let serving = cli_report_with(|v| v["sections"][0]["endpoint_form"] = "serving".into());
        let e = compare(&a, &serving, 100.0).unwrap_err().to_string();
        assert!(e.contains("collector_only") && e.contains("serving"), "{e}");
        compare(&serving, &serving, 0.0).unwrap();
    }

    #[test]
    fn an_unknown_scalar_in_a_section_is_still_refused() {
        let e = parse_report(
            "bad.json",
            r#"{"schema_version":1,"sections":[{"backend":"b","architecture":"a","note":"x"}]}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("sections[0].note is not an object"), "{e}");
    }

    #[test]
    fn dirty_unrecorded_or_mismatched_sources_are_unpublishable() {
        let clean = parse(CLI_REPORT);
        let dirty = cli_report_with(|v| v["source"]["dirty"] = true.into());
        let other = cli_report_with(|v| v["source"]["commit"] = "feedface".into());
        let unrecorded = cli_report_with(|v| {
            v.as_object_mut().unwrap().remove("source");
        });
        let reasons = |a: &Report, b: &Report| unpublishable_reasons(a, b).join("; ");
        assert!(reasons(&clean, &dirty).contains("B was measured from a modified tree"));
        assert!(reasons(&other, &clean).contains("different commits (feedface vs"));
        assert!(reasons(&unrecorded, &clean).contains("A does not record its source commit"));
    }

    #[test]
    fn the_compare_command_refuses_a_dirty_pair_unless_allowed_and_says_so() {
        let dir = std::env::temp_dir().join(format!("mvm-resource-compare-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut v: Value = serde_json::from_str(CLI_REPORT).unwrap();
        v["source"]["dirty"] = true.into();
        let (a, b) = (dir.join("a.json"), dir.join("b.json"));
        std::fs::write(&a, CLI_REPORT).unwrap();
        std::fs::write(&b, v.to_string()).unwrap();
        let args = |extra: &[&str]| -> Vec<String> {
            [a.to_str().unwrap(), b.to_str().unwrap(), "--tolerance", "1"]
                .iter()
                .chain(extra)
                .map(|s| (*s).to_owned())
                .collect()
        };
        let refused = compare_subcommand(&args(&[])).unwrap_err().to_string();
        let allowed = compare_subcommand(&args(&[ALLOW_UNPUBLISHABLE]));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            refused.contains("modified tree") && refused.contains(ALLOW_UNPUBLISHABLE),
            "{refused}"
        );
        allowed.unwrap();
    }

    #[test]
    fn two_zeros_are_equal() {
        assert_eq!(relative_percent(0.0, 0.0), 0.0);
        assert_eq!(relative_percent(0.0, 5.0), 100.0);
    }

    #[test]
    fn malformed_reports_are_refused_naming_file_and_path() {
        let cases = [
            ("not json", "invalid JSON"),
            (r#"{"schema_version":1}"#, "sections missing"),
            (r#"{"sections":[]}"#, "schema_version"),
            (
                r#"{"schema_version":1,"sections":[{"backend":"b","architecture":"a","x":{"status":"unmeasured"}}]}"#,
                "sections[0].x.reason",
            ),
            (
                r#"{"schema_version":1,"sections":[{"backend":"b","architecture":"a","x":{"status":"measured","value":"7"}}]}"#,
                "sections[0].x.value",
            ),
            (
                r#"{"schema_version":1,"sections":[{"backend":"b","architecture":"a","x":{}}]}"#,
                "",
            ),
            (
                r#"{"schema_version":1,"sections":[{"architecture":"a"}]}"#,
                "sections[0].backend",
            ),
        ];
        for (text, want) in cases {
            let e = parse_report("bad.json", text);
            if want.is_empty() {
                // an empty object is a branch with no figures, not a figure
                assert!(e.is_ok());
                continue;
            }
            let e = e.unwrap_err().to_string();
            assert!(e.starts_with("bad.json:") && e.contains(want), "{e}");
        }
    }
}

//! Observed resource figures and the reproducibility compare.
//!
//! A resource report is read as plain JSON: every object carrying a `status`
//! key is a figure, every other object is walked, and `backend` /
//! `architecture` name the section. xtask does not link the CLI crate, so the
//! schema is followed by field name only.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Leaves of a latency summary that the compare checks; the rest are listed
/// as observed but never compared (max and p99 are single-sample noise).
const COMPARED_STATS: [&str; 2] = ["p50", "p95"];

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
    pub figures: Vec<Figure>,
}

#[derive(Debug)]
pub(super) struct Report {
    pub schema_version: u64,
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
            if key != "backend" && key != "architecture" {
                walk(name, &format!("{at}.{key}"), v, &mut figures)?;
            }
        }
        out.push(Section {
            backend: text_field("backend")?,
            architecture: text_field("architecture")?,
            figures,
        });
    }
    Ok(Report {
        schema_version,
        sections: out,
    })
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
                        Value::Null => Reading::Unmeasured("no samples".to_owned()),
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

pub(super) fn compare_subcommand(args: &[String]) -> Result<()> {
    let mut files = Vec::new();
    let mut tolerance = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--tolerance" {
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
        bail!("usage: perf resource-compare <A.json> <B.json> --tolerance <PERCENT>");
    };
    compare(
        &load_report(Path::new(fa))?,
        &load_report(Path::new(fb))?,
        tolerance,
    )?;
    eprintln!("resource reports agree within {tolerance}%");
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

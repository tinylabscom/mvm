//! `trust audit usage`: the read side of AI egress metering. Walks the
//! tenant's verified chain, keeps the `host.ai.usage` entries, and rolls
//! them up to one row per destination. The chain walk, the envelope parser,
//! and the JSON emitter are the ones every other chain verb uses; this
//! module is filter + aggregation + rendering.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::Serialize;

use mvm_client::audit::follow::{ChainLine, parse_chain_line};

use super::sessions::verified_lines;
use super::ui;

/// The event the AI egress seam records for each metered request.
const AI_USAGE_EVENT: &str = "host.ai.usage";

/// The attribution label the per-VM recorder adds to its entries.
const VM_NAME_LABEL: &str = "vm_name";

pub(in crate::commands) fn audit_usage(tenant: &str, vm: Option<&str>, json: bool) -> Result<()> {
    let Some(lines) = verified_lines(tenant)? else {
        if json {
            return crate::json_out::emit_json(&UsageReport::empty(tenant, vm));
        }
        ui::info(&format!("No audit chain for tenant '{tenant}'."));
        return Ok(());
    };
    let report = usage_report_from_lines(&lines, tenant, vm);
    if json {
        return crate::json_out::emit_json(&report);
    }
    if report.destinations.is_empty() {
        println!("no AI egress usage recorded");
        return Ok(());
    }
    print!("{}", render_human(&report));
    Ok(())
}

/// The aggregate over `lines`: every parseable `host.ai.usage` entry whose
/// `vm_name` label matches the filter (all of them when no filter is set),
/// grouped by destination and totalled.
fn usage_report_from_lines<'a>(
    lines: &[String],
    tenant: &'a str,
    vm: Option<&'a str>,
) -> UsageReport<'a> {
    let mut rows: BTreeMap<Destination, UsageAcc> = BTreeMap::new();
    let mut budget_exceeded = 0u64;
    for line in lines {
        let ChainLine::Entry(entry) = parse_chain_line(line) else {
            continue;
        };
        if entry.event != AI_USAGE_EVENT {
            continue;
        }
        let labels = &entry.labels;
        if let Some(want) = vm
            && labels.get(VM_NAME_LABEL).map(String::as_str) != Some(want)
        {
            continue;
        }
        if labels.get("budget_exceeded").map(String::as_str) == Some("true") {
            budget_exceeded = budget_exceeded.saturating_add(1);
        }
        let destination = Destination {
            provider: label_or_empty(labels, "provider"),
            host: label_or_empty(labels, "host"),
            path: label_or_empty(labels, "path"),
            model: labels.get("model").cloned().filter(|m| !m.is_empty()),
        };
        let acc = rows.entry(destination).or_default();
        acc.requests = acc.requests.saturating_add(1);
        let input = token_label(labels, "input_tokens");
        let output = token_label(labels, "output_tokens");
        let total = token_label(labels, "total_tokens");
        if input.is_none() && output.is_none() && total.is_none() {
            acc.unmetered_requests = acc.unmetered_requests.saturating_add(1);
        }
        add_tokens(&mut acc.input_tokens, input);
        add_tokens(&mut acc.output_tokens, output);
        add_tokens(&mut acc.total_tokens, total);
    }
    UsageReport::from_rows(tenant, vm, rows, budget_exceeded)
}

fn label_or_empty(labels: &BTreeMap<String, String>, key: &str) -> String {
    labels.get(key).cloned().unwrap_or_default()
}

/// A token count from the labels. An absent or unparseable value is unknown,
/// never zero.
fn token_label(labels: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    labels.get(key)?.parse().ok()
}

fn add_tokens(sum: &mut Option<u64>, value: Option<u64>) {
    if let Some(n) = value {
        *sum = Some(sum.unwrap_or(0).saturating_add(n));
    }
}

/// One row's grouping key: the destination a request went to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Destination {
    provider: String,
    host: String,
    path: String,
    model: Option<String>,
}

/// Running sums for one destination. A `None` token field means no
/// aggregated entry carried that count; it stays unknown, never zero.
#[derive(Debug, Default)]
struct UsageAcc {
    requests: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    unmetered_requests: u64,
}

/// One destination's aggregate in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DestinationUsage {
    provider: String,
    host: String,
    path: String,
    model: Option<String>,
    requests: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    /// Requests whose entries carried no provider-reported token counts.
    unmetered_requests: u64,
}

/// The totals row across destinations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UsageTotals {
    requests: u64,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    unmetered_requests: u64,
    /// Entries whose `budget_exceeded` label was true.
    budget_exceeded: u64,
}

/// The `--json` shape of `trust audit usage`, and what `render_human`
/// renders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct UsageReport<'a> {
    tenant: &'a str,
    /// The `--vm` filter in effect, when one was given.
    vm: Option<&'a str>,
    destinations: Vec<DestinationUsage>,
    totals: UsageTotals,
}

impl<'a> UsageReport<'a> {
    fn empty(tenant: &'a str, vm: Option<&'a str>) -> Self {
        Self::from_rows(tenant, vm, BTreeMap::new(), 0)
    }

    fn from_rows(
        tenant: &'a str,
        vm: Option<&'a str>,
        rows: BTreeMap<Destination, UsageAcc>,
        budget_exceeded: u64,
    ) -> Self {
        let mut totals = UsageTotals {
            requests: 0,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            unmetered_requests: 0,
            budget_exceeded,
        };
        let destinations = rows
            .into_iter()
            .map(|(destination, acc)| {
                totals.requests = totals.requests.saturating_add(acc.requests);
                totals.unmetered_requests = totals
                    .unmetered_requests
                    .saturating_add(acc.unmetered_requests);
                add_tokens(&mut totals.input_tokens, acc.input_tokens);
                add_tokens(&mut totals.output_tokens, acc.output_tokens);
                add_tokens(&mut totals.total_tokens, acc.total_tokens);
                DestinationUsage {
                    provider: destination.provider,
                    host: destination.host,
                    path: destination.path,
                    model: destination.model,
                    requests: acc.requests,
                    input_tokens: acc.input_tokens,
                    output_tokens: acc.output_tokens,
                    total_tokens: acc.total_tokens,
                    unmetered_requests: acc.unmetered_requests,
                }
            })
            .collect();
        UsageReport {
            tenant,
            vm,
            destinations,
            totals,
        }
    }
}

/// An unknown token count renders as `-`, never `0`.
fn tokens_or_dash(count: Option<u64>) -> String {
    count.map_or_else(|| "-".to_string(), |n| n.to_string())
}

fn render_human(report: &UsageReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(
        out,
        "{:<10} {:<24} {:<28} {:<16} {:>8} {:>10} {:>10} {:>10}",
        "PROVIDER", "HOST", "PATH", "MODEL", "REQUESTS", "INPUT", "OUTPUT", "TOTAL"
    )
    .expect("writing to a String cannot fail");
    for d in &report.destinations {
        writeln!(
            out,
            "{:<10} {:<24} {:<28} {:<16} {:>8} {:>10} {:>10} {:>10}",
            d.provider,
            d.host,
            d.path,
            d.model.as_deref().unwrap_or("-"),
            d.requests,
            tokens_or_dash(d.input_tokens),
            tokens_or_dash(d.output_tokens),
            tokens_or_dash(d.total_tokens),
        )
        .expect("writing to a String cannot fail");
    }
    let t = &report.totals;
    writeln!(
        out,
        "{:<10} {:<24} {:<28} {:<16} {:>8} {:>10} {:>10} {:>10}",
        "TOTAL",
        "",
        "",
        "",
        t.requests,
        tokens_or_dash(t.input_tokens),
        tokens_or_dash(t.output_tokens),
        tokens_or_dash(t.total_tokens),
    )
    .expect("writing to a String cannot fail");
    if t.unmetered_requests > 0 {
        writeln!(
            out,
            "{} request(s) carried no provider-reported token counts; \
             token sums cover the metered remainder.",
            t.unmetered_requests
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(out, "budget-exceeded requests: {}", t.budget_exceeded)
        .expect("writing to a String cannot fail");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::{PlanId, TenantId};
    use mvm_core::policy::audit::ai_usage::AiUsageRecord;
    use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};
    use rand::Rng;

    fn base_record() -> AiUsageRecord {
        AiUsageRecord {
            trace_id: String::new(),
            span_id: String::new(),
            host: "api.openai.com".to_string(),
            port: 443,
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            provider: "openai".to_string(),
            model: Some("gpt-4".to_string()),
            input_tokens: Some(10),
            output_tokens: Some(5),
            total_tokens: Some(15),
            status: 200,
            budget_exceeded: false,
        }
    }

    fn unmetered_record() -> AiUsageRecord {
        AiUsageRecord {
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            ..base_record()
        }
    }

    /// Sign `entries` — `(event, vm_name, record)` triples — into a fresh
    /// chain and return its raw lines: the same `SignedEnvelope` JSON the
    /// verified reader hands the report builder.
    fn chain_lines(entries: &[(&str, Option<&str>, AiUsageRecord)]) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            ed25519_dalek::SigningKey::from_bytes(&seed)
        };
        let signer = FileAuditSigner::open(key, dir.path()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (event, vm, record) in entries {
            let mut labels: BTreeMap<String, String> = record.to_labels().into_iter().collect();
            if let Some(vm) = vm {
                labels.insert(VM_NAME_LABEL.to_string(), (*vm).to_string());
            }
            let entry = PlanAuditEntry {
                timestamp: chrono::Utc::now(),
                tenant: TenantId("local".to_string()),
                plan_id: PlanId(mvm_hostd::supervisor::UNBOUND_PLAN_ID.to_string()),
                plan_version: 0,
                bundle_id: None,
                bundle_version: None,
                image_name: mvm_hostd::supervisor::UNBOUND_IMAGE_NAME.to_string(),
                image_sha256: mvm_hostd::supervisor::UNBOUND_IMAGE_SHA256.to_string(),
                event: (*event).to_string(),
                caller_commitment: None,
                labels,
            };
            rt.block_on(signer.sign_and_emit(&entry)).unwrap();
        }
        std::fs::read_to_string(dir.path().join("local.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn mixed_known_and_unknown_counts_sum_the_known_ones() {
        let lines = chain_lines(&[
            (AI_USAGE_EVENT, None, base_record()),
            (AI_USAGE_EVENT, None, unmetered_record()),
        ]);
        let report = usage_report_from_lines(&lines, "local", None);
        assert_eq!(report.destinations.len(), 1);
        let d = &report.destinations[0];
        assert_eq!(d.requests, 2);
        assert_eq!(d.input_tokens, Some(10));
        assert_eq!(d.output_tokens, Some(5));
        assert_eq!(d.total_tokens, Some(15));
        assert_eq!(d.unmetered_requests, 1);
        assert_eq!(report.totals.requests, 2);
        assert_eq!(report.totals.input_tokens, Some(10));
        assert_eq!(report.totals.unmetered_requests, 1);
    }

    #[test]
    fn all_unknown_counts_stay_unknown_not_zero() {
        let lines = chain_lines(&[(AI_USAGE_EVENT, None, unmetered_record())]);
        let report = usage_report_from_lines(&lines, "local", None);
        let d = &report.destinations[0];
        assert_eq!(d.requests, 1);
        assert_eq!(d.input_tokens, None);
        assert_eq!(d.output_tokens, None);
        assert_eq!(d.total_tokens, None);
        assert_eq!(report.totals.total_tokens, None);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["destinations"][0]["input_tokens"],
            serde_json::Value::Null
        );
        assert_eq!(json["totals"]["total_tokens"], serde_json::Value::Null);
    }

    #[test]
    fn budget_exceeded_entries_are_counted() {
        let exceeded = AiUsageRecord {
            budget_exceeded: true,
            ..base_record()
        };
        let lines = chain_lines(&[
            (AI_USAGE_EVENT, None, base_record()),
            (AI_USAGE_EVENT, None, exceeded),
        ]);
        let report = usage_report_from_lines(&lines, "local", None);
        assert_eq!(report.totals.budget_exceeded, 1);
        assert_eq!(report.totals.requests, 2);
    }

    #[test]
    fn malformed_and_unrelated_lines_are_skipped() {
        let mut lines = chain_lines(&[
            (AI_USAGE_EVENT, None, base_record()),
            ("cmd.up.completed", None, base_record()),
        ]);
        lines.push("this is not json".to_string());
        lines.push(r#"{"entry":{"event":"host.ai.usage"}}"#.to_string());
        let report = usage_report_from_lines(&lines, "local", None);
        assert_eq!(report.totals.requests, 1);
        assert_eq!(report.destinations.len(), 1);
    }

    #[test]
    fn vm_filter_keeps_only_attributed_matching_entries() {
        let lines = chain_lines(&[
            (AI_USAGE_EVENT, Some("vm-a"), base_record()),
            (AI_USAGE_EVENT, Some("vm-b"), base_record()),
            (AI_USAGE_EVENT, None, base_record()),
        ]);
        let report = usage_report_from_lines(&lines, "local", Some("vm-a"));
        assert_eq!(report.totals.requests, 1);
        assert_eq!(report.vm, Some("vm-a"));
        let all = usage_report_from_lines(&lines, "local", None);
        assert_eq!(all.totals.requests, 3);
    }

    #[test]
    fn destinations_group_and_sort_by_provider_host_path_model() {
        let other_path = AiUsageRecord {
            path: "/v1/responses".to_string(),
            ..base_record()
        };
        let other_model = AiUsageRecord {
            model: Some("gpt-4o-mini".to_string()),
            ..base_record()
        };
        let lines = chain_lines(&[
            (AI_USAGE_EVENT, None, other_model),
            (AI_USAGE_EVENT, None, other_path),
            (AI_USAGE_EVENT, None, base_record()),
        ]);
        let report = usage_report_from_lines(&lines, "local", None);
        let paths: Vec<(&str, Option<&str>)> = report
            .destinations
            .iter()
            .map(|d| (d.path.as_str(), d.model.as_deref()))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("/v1/chat/completions", Some("gpt-4")),
                ("/v1/chat/completions", Some("gpt-4o-mini")),
                ("/v1/responses", Some("gpt-4")),
            ]
        );
        assert_eq!(report.totals.requests, 3);
        assert_eq!(report.totals.total_tokens, Some(45));
    }

    #[test]
    fn empty_input_is_an_empty_report() {
        let report = usage_report_from_lines(&[], "local", None);
        assert!(report.destinations.is_empty());
        assert_eq!(report.totals.requests, 0);
        assert_eq!(report.totals.input_tokens, None);
        assert_eq!(report.totals.budget_exceeded, 0);
        let json = crate::json_out::to_json_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tenant"], "local");
        assert!(v["vm"].is_null());
        assert_eq!(v["destinations"], serde_json::json!([]));
        assert_eq!(v["totals"]["requests"], 0);
    }

    #[test]
    fn human_output_renders_table_totals_and_notes() {
        let exceeded_unmetered = AiUsageRecord {
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            budget_exceeded: true,
            ..base_record()
        };
        let lines = chain_lines(&[
            (AI_USAGE_EVENT, None, base_record()),
            (AI_USAGE_EVENT, None, exceeded_unmetered),
        ]);
        let report = usage_report_from_lines(&lines, "local", None);
        let out = render_human(&report);
        assert!(out.contains("PROVIDER"), "{out}");
        assert!(out.contains("api.openai.com"), "{out}");
        assert!(out.contains("/v1/chat/completions"), "{out}");
        assert!(out.contains("gpt-4"), "{out}");
        assert!(out.contains("TOTAL"), "{out}");
        assert!(out.contains("budget-exceeded requests: 1"), "{out}");
        assert!(
            out.contains("1 request(s) carried no provider-reported token counts"),
            "{out}"
        );
    }

    #[test]
    fn human_output_dashes_unknown_token_columns() {
        let lines = chain_lines(&[(AI_USAGE_EVENT, None, unmetered_record())]);
        let report = usage_report_from_lines(&lines, "local", None);
        let out = render_human(&report);
        let row = out.lines().nth(1).expect("a header and a data row");
        let fields: Vec<&str> = row.split_whitespace().collect();
        assert!(fields[fields.len() - 3..] == ["-", "-", "-"], "{row}");
        assert!(out.contains("budget-exceeded requests: 0"), "{out}");
    }

    #[test]
    fn json_output_carries_tenant_filter_rows_and_totals() {
        let lines = chain_lines(&[(AI_USAGE_EVENT, Some("vm-a"), base_record())]);
        let report = usage_report_from_lines(&lines, "local", Some("vm-a"));
        let json = crate::json_out::to_json_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["tenant"], "local");
        assert_eq!(v["vm"], "vm-a");
        assert_eq!(v["destinations"][0]["provider"], "openai");
        assert_eq!(v["destinations"][0]["host"], "api.openai.com");
        assert_eq!(v["destinations"][0]["model"], "gpt-4");
        assert_eq!(v["destinations"][0]["requests"], 1);
        assert_eq!(v["destinations"][0]["input_tokens"], 10);
        assert_eq!(v["destinations"][0]["unmetered_requests"], 0);
        assert_eq!(v["totals"]["total_tokens"], 15);
        assert_eq!(v["totals"]["budget_exceeded"], 0);
    }
}

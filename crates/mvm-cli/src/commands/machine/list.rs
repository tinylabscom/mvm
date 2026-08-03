//! `mvmctl machine ls` — the single listing of every microVM on the host.
//!
//! The spec×live join, the typed record, and the visibility semantics all
//! live in the shared inventory service (`mvm_client::inventory`), so this
//! module is presentation only: it maps the CLI flags onto an
//! [`InventoryQuery`], fetches the canonical records, and renders them as a
//! table or as JSON. The JSON output *is* the serialized inventory record —
//! the same typed shape any other consumer of the service sees.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use mvm_client::inventory::{InventoryQuery, MachineInventoryRecord, list_local_inventory};
use mvm_client::{LocalBackend, MachineStatus};

use super::{MachineListArgs, health_cell, humanize_age};

pub(super) fn list_machines(args: MachineListArgs) -> Result<()> {
    let query = query_from_args(&args)?;
    let records = fetch_local_inventory()?;
    let now = chrono::Utc::now();

    let visible: Vec<MachineInventoryRecord> = records
        .into_iter()
        .filter(|record| query.matches(record, now))
        .collect();

    if args.json {
        // The listing's JSON is the canonical inventory record, verbatim —
        // SDK facades parse `name` / `status` / `build_mode` / `kind` out of
        // it, and those keys are pinned by the record's wire contract.
        crate::json_out::emit_json(&visible)?;
        return Ok(());
    }
    if visible.is_empty() {
        println!("no machines");
        return Ok(());
    }
    println!("{}", format_table(&visible, now));
    Ok(())
}

/// The canonical unfiltered inventory, via the shared service.
fn fetch_local_inventory() -> Result<Vec<MachineInventoryRecord>> {
    let client = LocalBackend::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for machine listing")?;
    runtime
        .block_on(list_local_inventory(&client))
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("listing machines")
}

/// Map the CLI flags onto the shared visibility query: `--all` includes
/// stopped transients, `--show-expired` includes elapsed-TTL machines, and
/// each `--tag KEY=VALUE` adds a must-match constraint.
pub(super) fn query_from_args(args: &MachineListArgs) -> Result<InventoryQuery> {
    let mut tags = BTreeMap::new();
    for raw in &args.tags {
        let (k, v) = mvm_core::crypto::policy::InputValidator::parse_tag_arg(raw)
            .with_context(|| format!("Invalid --tag value: {:?}", raw))?;
        tags.insert(k, v);
    }
    Ok(InventoryQuery {
        include_stopped_transient: args.all,
        include_expired: args.show_expired,
        tags,
    })
}

/// STATUS cell: the typed wire label, with a failure reason kept visible
/// beside it rather than dropped.
pub(super) fn status_cell(record: &MachineInventoryRecord) -> String {
    match (&record.status, &record.status_detail) {
        (MachineStatus::Failed, Some(reason)) => format!("failed ({reason})"),
        (status, _) => status.wire_label().to_string(),
    }
}

fn ports_cell(record: &MachineInventoryRecord) -> String {
    if record.ports.is_empty() {
        return "-".to_string();
    }
    record
        .ports
        .iter()
        .map(|p| format!("{}→{}", p.host, p.guest))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One rendered row, already stringified for display.
struct Cells {
    name: String,
    kind: String,
    status: String,
    health: String,
    backend: String,
    ports: String,
    source: String,
    age: String,
}

impl Cells {
    fn header() -> Self {
        Self {
            name: "NAME".into(),
            kind: "KIND".into(),
            status: "STATUS".into(),
            health: "HEALTH".into(),
            backend: "BACKEND".into(),
            ports: "PORTS".into(),
            source: "SOURCE".into(),
            age: "AGE".into(),
        }
    }

    fn from_record(record: &MachineInventoryRecord, now: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            name: record.name.clone(),
            kind: record.kind.label().to_string(),
            status: status_cell(record),
            health: health_cell(record.readiness.as_ref()).to_string(),
            backend: record.backend.clone().unwrap_or_else(|| "-".to_string()),
            ports: ports_cell(record),
            source: record.source.clone().unwrap_or_else(|| "-".to_string()),
            age: humanize_age(record.created_at.as_deref(), now),
        }
    }
}

/// Render the table: a header plus left-aligned columns padded to their widest
/// cell, so a column nothing populates collapses to its header width. Pure so
/// the alignment is unit-testable.
pub(super) fn format_table(
    records: &[MachineInventoryRecord],
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let rows: Vec<Cells> = records
        .iter()
        .map(|record| Cells::from_record(record, now))
        .collect();

    let header = Cells::header();
    let all = || std::iter::once(&header).chain(rows.iter());
    let width = |pick: fn(&Cells) -> &String| all().map(|r| pick(r).len()).max().unwrap_or(0);
    let (wn, wk, ws, wh, wb, wp, wsrc) = (
        width(|r| &r.name),
        width(|r| &r.kind),
        width(|r| &r.status),
        width(|r| &r.health),
        width(|r| &r.backend),
        width(|r| &r.ports),
        width(|r| &r.source),
    );

    all()
        .map(|r| {
            // AGE is the last column, so it needs no trailing pad.
            format!(
                "{:<wn$}  {:<wk$}  {:<ws$}  {:<wh$}  {:<wb$}  {:<wp$}  {:<wsrc$}  {}",
                r.name, r.kind, r.status, r.health, r.backend, r.ports, r.source, r.age
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;

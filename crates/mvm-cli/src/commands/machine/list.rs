//! `mvmctl machine ls` — the single listing of every microVM on the host.
//!
//! Three stores describe a microVM and none of them is complete on its own:
//! the persisted spec registry (a machine the user created by name), the live
//! backend scan joined with the VM name registry (what is actually booted), and
//! the per-VM state dirs underneath both. A machine started from a spec, a
//! transient `machine run`, and a direct-boot VM must all appear here, so this
//! joins the spec registry against the live listing by name.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use mvm_client::{LocalBackend, MachineFilter, MachineState, MachineStatus, MvmClient};
use mvm_runtime::machine::persist::MachineSpec;

use super::{MachineListArgs, health_cell, humanize_age, list_machine_specs, machine_status_label};

/// Where a listed microVM's definition lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MachineKind {
    /// Backed by a persisted spec: survives a stop, restartable by name.
    Persistent,
    /// Live only. A `machine run` or a direct-boot VM; it leaves nothing
    /// behind once it exits.
    Transient,
}

impl MachineKind {
    fn label(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::Transient => "transient",
        }
    }
}

/// One microVM, from whichever stores know about it. A persistent machine that
/// is not booted has `live: None`; a transient one always has `live: Some`.
pub(super) struct ListedMachine {
    kind: MachineKind,
    name: String,
    live: Option<MachineState>,
    spec: Option<MachineSpec>,
}

impl ListedMachine {
    /// Status label, lowercase. SDK facades parse this field out of
    /// `--json` (`running` / `starting` / `failed`, anything else read as
    /// stopped), so it stays the snake_case `MachineStatus` wire form. A
    /// machine with no live row falls back to the pid-file probe.
    fn status(&self) -> String {
        let Some(live) = &self.live else {
            return machine_status_label(&self.name).to_string();
        };
        let label = status_label(live.status);
        // `MachineStatus::Failed` is a unit variant, so the reason rides
        // alongside it; keep it visible rather than dropping it.
        match (&live.status, &live.status_detail) {
            (MachineStatus::Failed, Some(reason)) => format!("{label} ({reason})"),
            _ => label,
        }
    }

    /// `"dev"` / `"prod"`, resolved the same way as the boot-time SDK
    /// envelope. Read by `Sandbox.connect(id)` to inherit the dev-only exec
    /// guard when attaching to a running machine from a fresh process, so a
    /// transient machine resolves it too — fail-closed to `prod`.
    fn build_mode(&self) -> &'static str {
        super::runtime::resolve_machine_build_mode(
            self.spec.as_ref().and_then(|s| s.manifest.as_deref()),
            &self.name,
        )
    }

    /// What the machine was made from: the spec's image/manifest for a
    /// persistent machine, and whatever the backend knows for a transient one.
    fn source(&self) -> String {
        let from_spec = self
            .spec
            .as_ref()
            .and_then(|spec| spec.image.as_deref().or(spec.manifest.as_deref()));
        if let Some(source) = from_spec {
            return source.to_string();
        }
        self.live
            .as_ref()
            .and_then(|live| live.flake_ref.as_deref().or(live.profile.as_deref()))
            .unwrap_or("-")
            .to_string()
    }

    fn backend(&self) -> &str {
        self.live
            .as_ref()
            .map(|live| live.backend.as_str())
            .unwrap_or("-")
    }

    fn ports(&self) -> String {
        let Some(live) = &self.live else {
            return "-".to_string();
        };
        if live.ports.is_empty() {
            return "-".to_string();
        }
        live.ports
            .iter()
            .map(|p| format!("{}→{}", p.host, p.guest))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn health(&self) -> &'static str {
        let readiness = self
            .live
            .as_ref()
            .and_then(|live| live.readiness.clone())
            .or_else(|| mvm_client::readiness_of(&self.name));
        health_cell(readiness.as_ref())
    }

    /// Age from the spec's creation time. A transient machine was never
    /// created as a spec, so it has none.
    fn age(&self, now: chrono::DateTime<chrono::Utc>) -> String {
        humanize_age(
            self.spec.as_ref().and_then(|s| s.created_at.as_deref()),
            now,
        )
    }
}

pub(super) fn list_machines(args: MachineListArgs) -> Result<()> {
    let tag_filter = parse_tag_filter(&args.tags)?;
    let specs = list_machine_specs()?;
    let live = live_machines()?;
    let now = chrono::Utc::now();

    let machines: Vec<ListedMachine> = join_by_name(specs, live)
        .into_iter()
        .filter(|m| passes_filters(m, args.all, &tag_filter, args.show_expired, now))
        .collect();

    if args.json {
        return emit_json(&machines, now);
    }
    if machines.is_empty() {
        println!("no machines");
        return Ok(());
    }
    println!("{}", format_table(&machines, now));
    Ok(())
}

/// Every VM a backend currently knows about, joined with the VM name registry.
fn live_machines() -> Result<Vec<MachineState>> {
    let client = LocalBackend::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for machine listing")?;
    runtime
        .block_on(client.list_machines(MachineFilter::all()))
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("listing machines")
}

/// Join the two stores by name: every spec becomes a persistent row (carrying
/// its live state when booted), and every live VM left over is transient.
/// Persistent rows come first, each block name-sorted, so the listing is
/// stable and the two kinds read as groups.
pub(super) fn join_by_name(specs: Vec<MachineSpec>, live: Vec<MachineState>) -> Vec<ListedMachine> {
    let mut by_name: BTreeMap<String, MachineState> = live
        .into_iter()
        .map(|state| (state.name.clone(), state))
        .collect();

    let mut persistent: Vec<ListedMachine> = specs
        .into_iter()
        .map(|spec| ListedMachine {
            kind: MachineKind::Persistent,
            live: by_name.remove(&spec.name),
            name: spec.name.clone(),
            spec: Some(spec),
        })
        .collect();
    persistent.sort_by(|a, b| a.name.cmp(&b.name));

    // Whatever the spec registry did not claim is running without a spec.
    let transient = by_name.into_values().map(|state| ListedMachine {
        kind: MachineKind::Transient,
        name: state.name.clone(),
        live: Some(state),
        spec: None,
    });

    persistent.into_iter().chain(transient).collect()
}

fn parse_tag_filter(raw_tags: &[String]) -> Result<BTreeMap<String, String>> {
    let mut filter = BTreeMap::new();
    for raw in raw_tags {
        let (k, v) = mvm_core::crypto::policy::InputValidator::parse_tag_arg(raw)
            .with_context(|| format!("Invalid --tag value: {:?}", raw))?;
        filter.insert(k, v);
    }
    Ok(filter)
}

/// Visibility policy. A persistent machine always lists — it exists whether or
/// not it is booted, and hiding it would lose the only record of it. A
/// transient machine exists only while it runs, so a stopped one is leftover
/// state and stays hidden unless asked for.
pub(super) fn passes_filters(
    m: &ListedMachine,
    all: bool,
    tag_filter: &BTreeMap<String, String>,
    show_expired: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let stopped = m
        .live
        .as_ref()
        .map(|live| live.status == MachineStatus::Stopped)
        .unwrap_or(true);
    if !all && m.kind == MachineKind::Transient && stopped {
        return false;
    }
    if !tag_filter.is_empty() {
        let tags = m.live.as_ref().map(|live| &live.tags);
        let matches = tags.is_some_and(|tags| {
            tag_filter
                .iter()
                .all(|(k, v)| tags.get(k).map(String::as_str) == Some(v.as_str()))
        });
        if !matches {
            return false;
        }
    }
    if !show_expired && expired(m, now) {
        return false;
    }
    true
}

/// Whether a machine's TTL has elapsed. A missing or unparseable `expires_at`
/// is treated as "no TTL" (never expired).
fn expired(m: &ListedMachine, now: chrono::DateTime<chrono::Utc>) -> bool {
    m.live
        .as_ref()
        .and_then(|live| live.expires_at.as_deref())
        .and_then(mvm_core::util::time::parse_iso8601)
        .map(|t| t < now)
        .unwrap_or(false)
}

/// The snake_case wire label for a status, as SDK facades parse it.
fn status_label(status: MachineStatus) -> String {
    match serde_json::to_value(status) {
        Ok(serde_json::Value::String(label)) => label,
        _ => "stopped".to_string(),
    }
}

/// Serialize one row. The persisted spec is flattened at the top level and
/// `status` / `build_mode` sit beside it — the shape SDK facades already
/// parse. A transient machine has no spec to flatten, so it carries the
/// common fields alone. Built as a map rather than a struct because
/// `#[serde(flatten)]` over an optional spec would emit `name` twice.
fn json_row(m: &ListedMachine, now: chrono::DateTime<chrono::Utc>) -> Result<serde_json::Value> {
    let mut obj = match &m.spec {
        Some(spec) => match serde_json::to_value(spec)? {
            serde_json::Value::Object(map) => map,
            other => anyhow::bail!("machine spec must serialize to a JSON object, got {other}"),
        },
        None => serde_json::Map::new(),
    };

    let mut set = |key: &str, value: serde_json::Value| {
        obj.insert(key.to_string(), value);
    };
    set("name", m.name.clone().into());
    set("kind", serde_json::to_value(m.kind)?);
    set("status", m.status().into());
    set("build_mode", m.build_mode().into());
    set("health", m.health().into());
    set("backend", m.backend().into());
    set("source", m.source().into());
    set("age", m.age(now).into());
    set("expired", expired(m, now).into());
    if let Some(live) = &m.live {
        set("live", serde_json::to_value(live)?);
    }

    Ok(serde_json::Value::Object(obj))
}

fn emit_json(machines: &[ListedMachine], now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    let rows = machines
        .iter()
        .map(|m| json_row(m, now))
        .collect::<Result<Vec<_>>>()?;
    crate::json_out::emit_json(&rows)?;
    Ok(())
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
}

/// Render the table: a header plus left-aligned columns padded to their widest
/// cell, so a column nothing populates collapses to its header width. Pure so
/// the alignment is unit-testable.
pub(super) fn format_table(
    machines: &[ListedMachine],
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let rows: Vec<Cells> = machines
        .iter()
        .map(|m| Cells {
            name: m.name.clone(),
            kind: m.kind.label().to_string(),
            status: m.status(),
            health: m.health().to_string(),
            backend: m.backend().to_string(),
            ports: m.ports(),
            source: m.source(),
            age: m.age(now),
        })
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

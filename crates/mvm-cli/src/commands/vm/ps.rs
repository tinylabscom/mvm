//! `mvmctl ls` / `mvmctl ps` — list running VMs.

use std::collections::BTreeMap;

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::{LocalBackend, MachineFilter, MachineState, MachineStatus, MvmClient};
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Show all VMs (including stopped)
    #[arg(short, long)]
    pub all: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Filter by sandbox tag (`KEY=VALUE`). Repeatable; all must match.
    #[arg(long = "tag", value_name = "KEY=VALUE")]
    pub tags: Vec<String>,
    /// Include VMs whose TTL has expired but the reaper has not yet
    /// torn down. By default these are hidden from the listing.
    #[arg(long)]
    pub show_expired: bool,
}

impl Args {
    pub(in crate::commands) fn touches_vm_state(&self) -> bool {
        // `ls --all` is the historical listing surface. It must render
        // registry-only stopped rows before any convergence pass can sweep them.
        !self.all
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    use anyhow::Context;

    // Parse the tag filter early so an invalid `--tag` errors out before we go
    // talk to backends. Validation is shared with `mvmctl up`, keeping
    // charset/length invariants consistent.
    let mut tag_filter: BTreeMap<String, String> = BTreeMap::new();
    for raw in &args.tags {
        let (k, v) = mvm_core::crypto::policy::InputValidator::parse_tag_arg(raw)
            .with_context(|| format!("Invalid --tag value: {:?}", raw))?;
        tag_filter.insert(k, v);
    }

    // The facade owns data acquisition: it aggregates every backend's live VMs
    // and joins them with the persistent name registry (tags / TTLs / readiness)
    // in one call. The CLI keeps presentation only — filtering, columns, JSON.
    let client = LocalBackend::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build runtime for machine listing")?;
    let mut machines = runtime
        .block_on(client.list_machines(MachineFilter::all()))
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("listing machines")?;

    let now = chrono::Utc::now();
    machines.retain(|m| passes_filters(m, args.all, &tag_filter, args.show_expired, now));

    if args.json {
        return emit_json(&machines, now);
    }

    if machines.is_empty() {
        println!("No running VMs.");
        return Ok(());
    }

    print_table(&machines);
    Ok(())
}

/// Whether a machine passes the `ps` visibility filters. Split out so the
/// column/JSON rendering stays declarative and this policy is unit-testable.
fn passes_filters(
    m: &MachineState,
    all: bool,
    tag_filter: &BTreeMap<String, String>,
    show_expired: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    // Hide registered-but-stopped machines unless `--all`. A paused machine is
    // NOT stopped, so it stays visible by default.
    if !all && m.status == MachineStatus::Stopped {
        return false;
    }
    // Tag filter: every key/value in `tag_filter` must be present.
    if !tag_filter.is_empty()
        && !tag_filter
            .iter()
            .all(|(k, v)| m.tags.get(k).map(String::as_str) == Some(v.as_str()))
    {
        return false;
    }
    // Expiry filter: hide machines past their TTL unless asked.
    if !show_expired && machine_expired(m, now) {
        return false;
    }
    true
}

/// Whether a machine's TTL has elapsed relative to `now`. A missing or
/// unparseable `expires_at` is treated as "no TTL" (never expired).
fn machine_expired(m: &MachineState, now: chrono::DateTime<chrono::Utc>) -> bool {
    m.expires_at
        .as_deref()
        .and_then(mvm_core::util::time::parse_iso8601)
        .map(|t| t < now)
        .unwrap_or(false)
}

/// The STATUS column text: `MachineStatus`'s debug form, reconstructing the
/// `Failed { reason: … }` shape so a failed machine's reason stays visible even
/// though `MachineStatus::Failed` is a unit variant.
fn render_status(m: &MachineState) -> String {
    match (&m.status, &m.status_detail) {
        (MachineStatus::Failed, Some(reason)) => format!("Failed {{ reason: {reason:?} }}"),
        (status, _) => format!("{status:?}"),
    }
}

fn emit_json(machines: &[MachineState], now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    // Row shape mirrors the historical `ls --json` output so SDK callers keep
    // getting tags / expiry / readiness in one round-trip. The `status` value
    // now serializes as the snake_case facade `MachineStatus` (the intended
    // shift from the old raw-VmStatus PascalCase). `expired` is computed here.
    #[derive(serde::Serialize)]
    struct LsRow<'a> {
        id: &'a str,
        name: &'a str,
        status: MachineStatus,
        // The detail behind a non-happy status (e.g. a `Failed` reason). The old
        // JSON carried this inside the raw `VmStatus::Failed { reason }`; it now
        // rides here so the reason survives the shift to the flat contract status.
        #[serde(skip_serializing_if = "Option::is_none")]
        status_detail: Option<&'a str>,
        guest_ip: Option<&'a str>,
        cpus: u32,
        memory_mib: u32,
        profile: Option<&'a str>,
        revision: Option<&'a str>,
        flake_ref: Option<&'a str>,
        ports: &'a [mvm_client::PortMapping],
        tags: &'a BTreeMap<String, String>,
        expires_at: Option<&'a str>,
        auto_resume: bool,
        expired: bool,
        readiness: Option<&'a mvm_core::domain::instance::InstanceReadiness>,
        last_readiness_change_at: Option<&'a str>,
    }
    let rows: Vec<LsRow<'_>> = machines
        .iter()
        .map(|m| LsRow {
            id: &m.id.0,
            name: &m.name,
            status: m.status,
            status_detail: m.status_detail.as_deref(),
            guest_ip: m.guest_ip.as_deref(),
            cpus: m.cpus,
            memory_mib: m.memory_mib,
            profile: m.profile.as_deref(),
            revision: m.revision.as_deref(),
            flake_ref: m.flake_ref.as_deref(),
            ports: &m.ports,
            tags: &m.tags,
            expires_at: m.expires_at.as_deref(),
            auto_resume: m.auto_resume,
            expired: machine_expired(m, now),
            readiness: m.readiness.as_ref(),
            last_readiness_change_at: m.last_readiness_change_at.as_deref(),
        })
        .collect();
    crate::json_out::emit_json(&rows)?;
    Ok(())
}

fn print_table(machines: &[MachineState]) {
    // Docker-style table output.
    println!(
        "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} IMAGE",
        "NAME", "BACKEND", "STATUS", "CPUS", "MEMORY", "PORTS"
    );
    for m in machines {
        let status = render_status(m);
        let mem = if m.memory_mib > 0 {
            format!("{}Mi", m.memory_mib)
        } else {
            "-".to_string()
        };
        let image = m
            .flake_ref
            .as_deref()
            .or(m.profile.as_deref())
            .unwrap_or("-");
        let ports = if m.ports.is_empty() {
            "-".to_string()
        } else {
            m.ports
                .iter()
                .map(|p| format!("{}→{}", p.host, p.guest))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{:<20} {:<18} {:<10} {:<8} {:<10} {:<20} {}",
            m.name,
            m.backend,
            status,
            if m.cpus > 0 {
                m.cpus.to_string()
            } else {
                "-".to_string()
            },
            mem,
            ports,
            image,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::{MachineId, MachineState, MachineStatus};

    fn machine(name: &str, status: MachineStatus) -> MachineState {
        MachineState {
            id: MachineId(name.to_string()),
            name: name.to_string(),
            status,
            ..Default::default()
        }
    }

    #[test]
    fn running_machine_shown_by_default() {
        let m = machine("web", MachineStatus::Running);
        assert!(passes_filters(
            &m,
            false,
            &BTreeMap::new(),
            false,
            chrono::Utc::now()
        ));
    }

    #[test]
    fn stopped_machine_hidden_without_all_and_shown_with_all() {
        let m = machine("web", MachineStatus::Stopped);
        assert!(!passes_filters(
            &m,
            false,
            &BTreeMap::new(),
            false,
            chrono::Utc::now()
        ));
        assert!(passes_filters(
            &m,
            true,
            &BTreeMap::new(),
            false,
            chrono::Utc::now()
        ));
    }

    #[test]
    fn paused_machine_stays_visible_by_default() {
        // The regression this migration fixes: a paused machine must not fold
        // into stopped and vanish from the default listing.
        let m = machine("web", MachineStatus::Paused);
        assert!(passes_filters(
            &m,
            false,
            &BTreeMap::new(),
            false,
            chrono::Utc::now()
        ));
    }

    #[test]
    fn tag_filter_requires_every_pair() {
        let mut m = machine("web", MachineStatus::Running);
        m.tags.insert("env".into(), "prod".into());
        let now = chrono::Utc::now();

        let mut want = BTreeMap::new();
        want.insert("env".to_string(), "prod".to_string());
        assert!(passes_filters(&m, false, &want, false, now));

        // A second required pair the machine lacks excludes it.
        want.insert("job".to_string(), "etl".to_string());
        assert!(!passes_filters(&m, false, &want, false, now));
    }

    #[test]
    fn tag_filter_excludes_untagged_machine() {
        let m = machine("web", MachineStatus::Running);
        let mut want = BTreeMap::new();
        want.insert("env".to_string(), "prod".to_string());
        assert!(!passes_filters(&m, false, &want, false, chrono::Utc::now()));
    }

    #[test]
    fn expired_machine_hidden_unless_requested() {
        let mut m = machine("web", MachineStatus::Running);
        m.expires_at = Some("2000-01-01T00:00:00Z".into());
        let now = chrono::Utc::now();
        assert!(!passes_filters(&m, false, &BTreeMap::new(), false, now));
        assert!(passes_filters(&m, false, &BTreeMap::new(), true, now));
    }

    #[test]
    fn future_ttl_is_not_expired() {
        let mut m = machine("web", MachineStatus::Running);
        m.expires_at = Some("2999-01-01T00:00:00Z".into());
        assert!(!machine_expired(&m, chrono::Utc::now()));
    }

    #[test]
    fn render_status_reconstructs_failure_reason() {
        // The failure reason survives the STATUS column even though
        // MachineStatus::Failed is a unit variant.
        let mut m = machine("web", MachineStatus::Failed);
        m.status_detail = Some("boom".into());
        assert_eq!(render_status(&m), "Failed { reason: \"boom\" }");
    }

    #[test]
    fn render_status_uses_debug_for_plain_variants() {
        assert_eq!(
            render_status(&machine("a", MachineStatus::Running)),
            "Running"
        );
        assert_eq!(
            render_status(&machine("a", MachineStatus::Paused)),
            "Paused"
        );
    }
}

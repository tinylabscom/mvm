//! `mvmctl metrics` — emit Prometheus-style metrics.
//!
//! Without arguments, dumps the global host-process counters
//! (`mvm_requests_total`, etc.) plus the per-VM registry's
//! Prometheus exposition concatenated. With `--instance <id>`,
//! filters to a single VM's labels + values (and only that VM's).

use anyhow::{Result, bail};
use clap::Args as ClapArgs;

use mvm_core::observability::instance_metrics;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Restrict output to one VM's per-instance metrics. Without
    /// this flag, both global host counters and every registered
    /// VM's metrics are emitted.
    #[arg(long, value_name = "INSTANCE_ID")]
    pub instance: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let global_metrics = mvm_core::observability::metrics::global();
    let per_vm = instance_metrics::global();

    if let Some(id) = args.instance.as_deref() {
        // Per-VM filter mode. Look the instance up; emit only its
        // labels + values rather than the full registry. Fail
        // explicitly when the VM isn't registered so callers can
        // tell "VM gone" from "VM idle, all zeros."
        let Some((labels, values)) = per_vm.get(id) else {
            bail!(
                "instance {:?} is not registered with the metrics sampler",
                id
            );
        };
        if args.json {
            #[derive(serde::Serialize)]
            struct OneVm<'a> {
                labels: &'a instance_metrics::InstanceLabels,
                values: &'a instance_metrics::InstanceMetricsValues,
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&OneVm {
                    labels: &labels,
                    values: &values,
                })?
            );
        } else {
            // Render only the requested instance by registering it
            // into a private registry; this keeps the output shape
            // identical to the full prometheus_exposition() form
            // (same headers, same label set) without leaking other
            // VMs' values when the caller asked for one.
            let one = instance_metrics::InstanceMetricsRegistry::new();
            one.register(labels);
            one.update(id, values);
            print!("{}", one.prometheus_exposition());
        }
        return Ok(());
    }

    if args.json {
        #[derive(serde::Serialize)]
        struct CombinedSnapshot {
            global: mvm_core::observability::metrics::MetricsSnapshot,
            instances: Vec<(
                instance_metrics::InstanceLabels,
                instance_metrics::InstanceMetricsValues,
            )>,
        }
        let snap = CombinedSnapshot {
            global: global_metrics.snapshot(),
            instances: per_vm.snapshot(),
        };
        println!("{}", serde_json::to_string_pretty(&snap)?);
    } else {
        // Concatenated exposition: global counters first, then
        // per-VM. Prometheus parsers tolerate repeated `# HELP` /
        // `# TYPE` lines for distinct metric names.
        print!("{}", global_metrics.prometheus_exposition());
        print!("{}", per_vm.prometheus_exposition());
        // Span timings are deliberately absent here. They accumulate in the
        // process that ran the instrumented code, and this command renders
        // before doing any, so the series would always be empty. The scrape
        // served by `metrics_server` carries them, because there the serving
        // process is the one doing the work.
    }
    Ok(())
}

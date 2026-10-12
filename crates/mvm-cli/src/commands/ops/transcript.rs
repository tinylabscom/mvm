//! Operator arguments, rendering, and export destinations for forensic captures.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use mvm_client::transcript::{CaptureSummary, TranscriptService};
use mvm_core::transcript::CaptureBounds;

const DEFAULT_TENANT: &str = "local";
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_CHUNKS: u64 = 100_000;
const DEFAULT_MAX_DURATION_SECS: u64 = 3600;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum TranscriptAction {
    /// Arm a forensic capture for a tenant/VM (optionally a session). Prints
    /// the new capture id.
    Arm {
        /// VM name the capture is bound to.
        vm: String,
        /// Tenant. Defaults to `local`.
        #[arg(long, default_value = DEFAULT_TENANT)]
        tenant: String,
        /// Optional session id.
        #[arg(long)]
        session: Option<String>,
        /// Max captured payload bytes before capture fails closed.
        #[arg(long, default_value_t = DEFAULT_MAX_BYTES)]
        max_bytes: u64,
        /// Max captured chunks before capture fails closed.
        #[arg(long, default_value_t = DEFAULT_MAX_CHUNKS)]
        max_chunks: u64,
        /// Max capture wall-clock seconds.
        #[arg(long, default_value_t = DEFAULT_MAX_DURATION_SECS)]
        max_duration: u64,
    },
    /// Seal (disarm) an armed capture — records that no further bytes will be
    /// captured.
    Disarm {
        /// Capture id (as printed by `arm`).
        capture_id: String,
        #[arg(long, default_value = DEFAULT_TENANT)]
        tenant: String,
    },
    /// Reconcile one sealed capture's authenticated retention deadline.
    Reconcile {
        capture_id: String,
        #[arg(long, default_value = DEFAULT_TENANT)]
        tenant: String,
    },
    /// List captures, optionally filtered by tenant.
    List {
        #[arg(long)]
        tenant: Option<String>,
        /// Emit a JSON array instead of the human table.
        #[arg(long)]
        json: bool,
    },
    /// Verify + decrypt a sealed capture to `--out` (or stdout).
    Export {
        capture_id: String,
        #[arg(long, default_value = DEFAULT_TENANT)]
        tenant: String,
        /// Destination file. Omit to write the decrypted bytes to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

pub(in crate::commands) fn run(action: TranscriptAction) -> Result<()> {
    run_with(
        &TranscriptService::from_config(),
        action,
        &mut std::io::stdout().lock(),
    )
}

fn run_with(
    ctx: &TranscriptService,
    action: TranscriptAction,
    output: &mut impl Write,
) -> Result<()> {
    match action {
        TranscriptAction::Arm {
            vm,
            tenant,
            session,
            max_bytes,
            max_chunks,
            max_duration,
        } => {
            let bounds = CaptureBounds {
                max_duration_secs: max_duration,
                max_bytes,
                max_chunks,
            };
            let id = ctx.arm(&tenant, &vm, session.as_deref(), bounds)?;
            writeln!(output, "{id}")?;
        }
        TranscriptAction::Disarm { capture_id, tenant } => ctx.disarm(&tenant, &capture_id)?,
        TranscriptAction::Reconcile { capture_id, tenant } => {
            let outcome = ctx.reconcile(&tenant, &capture_id)?;
            writeln!(output, "{outcome:?}")?;
        }
        TranscriptAction::List { tenant, json } => {
            render_list(&ctx.list(tenant.as_deref())?, json, output)?
        }
        TranscriptAction::Export {
            capture_id,
            tenant,
            out,
        } => {
            let bytes = ctx.export(&tenant, &capture_id)?;
            write_export(&bytes, out.as_deref(), output)?;
        }
    }
    Ok(())
}

fn render_list(rows: &[CaptureSummary], json: bool, output: &mut impl Write) -> Result<()> {
    if json {
        writeln!(output, "{}", serde_json::to_string_pretty(rows)?)?;
    } else if rows.is_empty() {
        writeln!(output, "no captures")?;
    } else {
        for r in rows {
            writeln!(
                output,
                "{}  tenant={} vm={} session={} chunks={} bytes={}",
                r.capture_id,
                r.tenant,
                r.vm,
                r.session.as_deref().unwrap_or("-"),
                r.chunks,
                r.bytes
            )?;
        }
    }
    Ok(())
}

fn write_export(bytes: &[u8], out: Option<&Path>, output: &mut impl Write) -> Result<()> {
    match out {
        Some(path) => std::fs::write(path, bytes)
            .with_context(|| format!("writing decrypted transcript to {}", path.display())),
        None => output
            .write_all(bytes)
            .context("writing decrypted transcript to stdout"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_preserves_json_and_human_rendering() {
        let rows = vec![CaptureSummary {
            capture_id: "capture".into(),
            tenant: "local".into(),
            vm: "vm".into(),
            session: None,
            chunks: 2,
            bytes: 19,
        }];
        let mut output = Vec::new();
        render_list(&rows, false, &mut output).unwrap();
        assert_eq!(
            output,
            b"capture  tenant=local vm=vm session=- chunks=2 bytes=19\n"
        );
        output.clear();
        render_list(&rows, true, &mut output).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
            serde_json::to_value(&rows).unwrap()
        );
        output.clear();
        render_list(&[], false, &mut output).unwrap();
        assert_eq!(output, b"no captures\n");
    }

    #[test]
    fn export_destinations_preserve_binary_bytes_and_report_failures() {
        let bytes = b"\0\xffprivate transcript\n";
        let mut output = Vec::new();
        write_export(bytes, None, &mut output).unwrap();
        assert_eq!(output, bytes);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export");
        output.clear();
        write_export(bytes, Some(&path), &mut output).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(output.is_empty());
        assert!(write_export(bytes, Some(dir.path()), &mut output).is_err());
        assert!(write_export(bytes, None, &mut &mut [0u8; 0][..]).is_err());
    }

    #[test]
    fn failed_verification_never_opens_the_export_destination() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let service = TranscriptService::at_home(&home);
        let destination = dir.path().join("export");
        std::fs::write(&destination, b"keep existing destination").unwrap();
        let mut output = Vec::new();
        let result = run_with(
            &service,
            TranscriptAction::Export {
                capture_id: "unknown".into(),
                tenant: "local".into(),
                out: Some(destination.clone()),
            },
            &mut output,
        );
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(destination).unwrap(),
            b"keep existing destination"
        );
        assert!(output.is_empty());
        assert!(!home.exists());
    }

    #[test]
    fn cli_arm_list_disarm_and_export_use_the_client_service() {
        let dir = tempfile::tempdir().unwrap();
        let service = TranscriptService::at_home(dir.path());
        let mut output = Vec::new();
        run_with(
            &service,
            TranscriptAction::Arm {
                vm: "vm1".into(),
                tenant: "local".into(),
                session: None,
                max_bytes: 1024,
                max_chunks: 10,
                max_duration: 60,
            },
            &mut output,
        )
        .unwrap();
        let id = String::from_utf8(output.clone()).unwrap().trim().to_owned();
        output.clear();
        run_with(
            &service,
            TranscriptAction::List {
                tenant: None,
                json: true,
            },
            &mut output,
        )
        .unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(rows[0]["capture_id"], id);
        assert!(rows[0].get("wrapped_data_key_b64").is_none());
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("vm1")
            .build();
        let vm_dir = dir.path().join("vms/vm1");
        std::fs::create_dir_all(&vm_dir).unwrap();
        mvm_core::util::atomic_io::write_private(
            &vm_dir.join(mvm_hostd::audit::plan_persist::PLAN_FILENAME),
            &serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();
        output.clear();
        run_with(
            &service,
            TranscriptAction::Disarm {
                capture_id: id.clone(),
                tenant: "local".into(),
            },
            &mut output,
        )
        .unwrap();
        let destination = dir.path().join("export");
        run_with(
            &service,
            TranscriptAction::Export {
                capture_id: id,
                tenant: "local".into(),
                out: Some(destination.clone()),
            },
            &mut output,
        )
        .unwrap();
        assert!(std::fs::read(destination).unwrap().is_empty());
        assert!(output.is_empty());
    }
}

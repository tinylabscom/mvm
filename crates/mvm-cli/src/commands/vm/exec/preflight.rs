//! What `machine run` reports about a launch: the `--json` summary and the
//! `--preflight` view, in both machine and human form.
//!
//! Split out of `exec.rs` because rendering a decision is a separate
//! concern from making one, and the two share nothing but the receipt
//! types they read.

use super::{
    ReceiptCommand, ReceiptInput, ReceiptMount, ReceiptOutcome, RunArgs, parse_env_pair, sha256_hex,
};
use anyhow::{Context, Result};
use mvm_core::util::parse_human_size;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RunJsonSummary {
    pub(super) schema_version: u32,
    pub(super) invocation: ReceiptInput,
    pub(super) outcome: ReceiptOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) phase_timing: Option<crate::commands::vm::phase_timing::RunPhaseTimingReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RunPreflightSummary {
    pub(super) schema_version: u32,
    pub(super) dry_run: bool,
    pub(super) will_execute: bool,
    pub(super) invocation: RunPreflightInvocation,
    pub(super) resources: RunPreflightResources,
    pub(super) image: RunPreflightImage,
    pub(super) receipt: RunPreflightReceipt,
    pub(super) notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RunPreflightReceipt {
    pub(super) requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RunPreflightInvocation {
    pub(super) profile: String,
    /// Requested egress posture the run would boot with.
    pub(super) network_posture: String,
    /// Honest per-backend enforcement fidelity for that posture (see
    /// `ReceiptInput::egress_enforcement`).
    pub(super) egress_enforcement: String,
    /// Admitted peer routes, as `name:port -> addr:port`.
    ///
    /// Reported separately from `network_posture` because a peer route is not
    /// egress: a workload dialing only its own database prints `deny-all`, and
    /// without this line a reader would take that to mean it can reach nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) peers: Vec<String>,
    pub(super) command: ReceiptCommand,
    pub(super) env_keys: Vec<String>,
    pub(super) mounts: Vec<ReceiptMount>,
    pub(super) timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RunPreflightResources {
    pub(super) cpus: u32,
    pub(super) memory: String,
    pub(super) memory_mib: u32,
    pub(super) timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum RunPreflightImage {
    DefaultMicrovm,
    Manifest { argument_sha256: String },
    Oci { reference_sha256: String },
    RuntimePack,
}

impl RunJsonSummary {
    pub(super) fn from_parts(
        invocation: ReceiptInput,
        output: &crate::exec::ExecOutput,
        receipt_path: Option<PathBuf>,
    ) -> Self {
        Self {
            schema_version: 1,
            invocation,
            outcome: ReceiptOutcome::from_exec_output(output),
            phase_timing: output.phase_timing.clone(),
            receipt_path,
        }
    }
}

impl RunPreflightSummary {
    pub(super) fn from_args(args: &RunArgs) -> Result<Self> {
        Self::from_args_with_backend_override(args, None)
    }

    pub(super) fn from_args_with_backend_override(
        args: &RunArgs,
        backend_override: Option<&str>,
    ) -> Result<Self> {
        let memory_mib = parse_human_size(&args.memory).context("Invalid --memory")?;
        for kv in &args.env {
            parse_env_pair(kv)?;
        }
        // Force mount parsing now so dry-run rejects the same malformed or
        // disallowed host-share specs as an actual run, without resolving an
        // image or touching the VM runtime.
        for spec in &args.mounts {
            crate::commands::parse_dir_share_spec(spec)?;
        }
        let image = match args.manifest.as_ref() {
            _ if args.runtime_pack => RunPreflightImage::RuntimePack,
            Some(manifest) if args.image.is_none() => RunPreflightImage::Manifest {
                argument_sha256: sha256_hex(manifest.as_bytes()),
            },
            None if args.image.is_some() => RunPreflightImage::Oci {
                reference_sha256: sha256_hex(
                    args.image
                        .as_deref()
                        .expect("matched image presence")
                        .as_bytes(),
                ),
            },
            None => RunPreflightImage::DefaultMicrovm,
            Some(_) => unreachable!("clap conflicts_with prevents --manifest + --image"),
        };
        let mut notes = vec![
            "preflight only; no image was resolved, built, booted, or executed".to_string(),
            "raw argv, env values, and host paths are intentionally omitted".to_string(),
        ];
        if args.receipt.is_some() {
            notes.push(
                "receipt path is hashed, but no receipt is written during dry-run".to_string(),
            );
        }

        // Report the backend the real run would auto-select, so the dry-run's
        // enforcement tier matches what an actual boot would record.
        let policy = super::super::shared::resolve_run_network_policy_with_peers(
            args.net,
            &args.allow_host,
            &args.peer,
        )?;
        let backend = match backend_override {
            Some(backend) => backend.to_string(),
            None => crate::exec::select_exec_backend(
                args.image.is_some(),
                &policy,
                args.hypervisor.as_deref(),
            )?
            .name()
            .to_string(),
        };
        let receipt_input = ReceiptInput::from_run_args(args, &backend)?;

        Ok(Self {
            schema_version: 1,
            dry_run: true,
            will_execute: false,
            invocation: RunPreflightInvocation {
                profile: receipt_input.profile,
                network_posture: receipt_input.network_posture,
                egress_enforcement: receipt_input.egress_enforcement,
                peers: policy
                    .peers()
                    .iter()
                    .map(|b| format!("{}:{} -> {}:{}", b.name, b.port, b.host_addr, b.host_port))
                    .collect(),
                command: receipt_input.command,
                env_keys: receipt_input.env_keys,
                mounts: receipt_input.mounts,
                timeout_secs: receipt_input.timeout_secs,
            },
            resources: RunPreflightResources {
                cpus: args.cpus,
                memory: args.memory.clone(),
                memory_mib,
                timeout_secs: args.timeout.unwrap_or(60),
            },
            image,
            receipt: RunPreflightReceipt {
                requested: args.receipt.is_some(),
                path_sha256: args
                    .receipt
                    .as_ref()
                    .map(|path| sha256_hex(path.to_string_lossy().as_bytes())),
            },
            notes,
        })
    }
}

pub(super) fn print_run_preflight_human(summary: &RunPreflightSummary) {
    println!("mvmctl run dry-run: no VM will be booted");
    match &summary.image {
        RunPreflightImage::DefaultMicrovm => {
            println!("image: bundled default microVM (not resolved)");
        }
        RunPreflightImage::Manifest { argument_sha256 } => {
            println!("image: manifest/template argument sha256={argument_sha256} (not resolved)");
        }
        RunPreflightImage::Oci { reference_sha256 } => {
            println!("image: OCI reference sha256={reference_sha256} (not resolved)");
        }
        RunPreflightImage::RuntimePack => {
            println!("image: verified attested runtime pack (not resolved)");
        }
    }
    println!(
        "resources: cpus={} memory={} ({} MiB) timeout={}s",
        summary.resources.cpus,
        summary.resources.memory,
        summary.resources.memory_mib,
        summary.resources.timeout_secs
    );
    println!("profile: {}", summary.invocation.profile);
    println!("network: {}", summary.invocation.network_posture);
    if !summary.invocation.peers.is_empty() {
        println!("peers: {}", summary.invocation.peers.join(", "));
    }
    println!("enforced: {}", summary.invocation.egress_enforcement);
    println!("command: {}", summary.invocation.command.describe());
    if summary.invocation.env_keys.is_empty() {
        println!("env: none");
    } else {
        println!("env keys: {}", summary.invocation.env_keys.join(","));
    }
    if summary.invocation.mounts.is_empty() {
        println!("host shares: none");
    } else {
        println!("host shares:");
        for dir in &summary.invocation.mounts {
            println!(
                "  host_sha256={} -> {} ({})",
                dir.host_path_sha256,
                dir.guest_path,
                if dir.read_only { "ro" } else { "rw" }
            );
        }
    }
    if summary.receipt.requested {
        if let Some(path_sha256) = &summary.receipt.path_sha256 {
            println!("receipt: requested path_sha256={path_sha256} (not written in dry-run)");
        } else {
            println!("receipt: requested (not written in dry-run)");
        }
    }
}

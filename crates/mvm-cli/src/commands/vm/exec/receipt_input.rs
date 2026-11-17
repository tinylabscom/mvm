//! Build the redacted invocation recorded in a signed run receipt.

use anyhow::{Context, Result};
use clap::ValueEnum as _;

use super::super::shared;
use super::{ReceiptCommand, ReceiptInput, ReceiptMount, RunArgs, boots_oci_for_run, sha256_hex};

impl ReceiptInput {
    pub(super) fn from_run_args(args: &RunArgs, backend: &str) -> Result<Self> {
        let policy = shared::resolve_run_network_policy(
            args.net,
            args.network_preset,
            &args.allow_host,
            &args.peer,
        )?
        .with_ai(shared::resolve_ai_policy(args.ai_token_budget));
        let command = if let Some(path) = &args.launch_plan {
            ReceiptCommand::LaunchPlan {
                path_sha256: sha256_hex(path.as_bytes()),
            }
        } else {
            let argv_bytes =
                serde_json::to_vec(&args.argv).context("serializing argv for receipt hash")?;
            ReceiptCommand::Inline {
                argv_len: args.argv.len(),
                argv_sha256: sha256_hex(&argv_bytes),
            }
        };

        let boots_oci = boots_oci_for_run(args, None)?;
        let capabilities =
            mvm_client::boot::image_egress_capabilities(backend, boots_oci, &policy)?;
        let mut env_keys = crate::exec::oci_proxy_env(boots_oci, &capabilities, &policy)
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>();
        env_keys.reserve(args.env.len());
        for kv in &args.env {
            let (key, _) = kv
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--env '{kv}': expected KEY=VALUE"))?;
            env_keys.push(key.to_string());
        }
        env_keys.sort();
        env_keys.dedup();

        let mut mounts = Vec::with_capacity(args.mounts.len());
        for spec in &args.mounts {
            let parsed = shared::parse_volume_spec(spec)?;
            let (host_path, guest_path, read_only) = match parsed {
                shared::VolumeSpec::DirShare {
                    host_dir,
                    guest_mount,
                    read_only,
                    ..
                } => (host_dir, guest_mount, read_only),
                shared::VolumeSpec::Disk {
                    host,
                    guest,
                    read_only,
                    ..
                } => (host, guest, read_only),
            };
            mounts.push(ReceiptMount {
                host_path_sha256: sha256_hex(host_path.as_bytes()),
                guest_path,
                read_only,
            });
        }

        Ok(Self {
            manifest: args.manifest.clone(),
            image: args.image.clone(),
            cpus: args.cpus,
            memory: args.memory.clone(),
            profile: args
                .profile
                .to_possible_value()
                .context("profile has no command-line name")?
                .get_name()
                .to_string(),
            network_posture: policy.posture_label(),
            egress_enforcement: shared::egress_enforcement_label(backend, &policy),
            ai_token_budget: args.ai_token_budget,
            command,
            env_keys,
            mounts,
            timeout_secs: args.timeout.unwrap_or(60),
        })
    }
}

//! `mvmctl exec` one-shot command (boot transient microVM, run argv, tear down).

use anyhow::{Context, Result};

use mvm_core::util::parse_human_size;

use super::ensure_default_microvm_image;
use crate::ui;

pub(super) struct OneshotParams<'a> {
    pub template: Option<String>,
    pub cpus: u32,
    pub memory: &'a str,
    pub add_dir: &'a [String],
    pub env: &'a [String],
    pub timeout: u64,
    pub launch_plan: Option<String>,
    pub argv: Vec<String>,
}

pub(super) fn run_oneshot(p: OneshotParams<'_>) -> Result<()> {
    let OneshotParams {
        template,
        cpus,
        memory,
        add_dir,
        env,
        timeout,
        launch_plan,
        argv,
    } = p;
    let target = match (launch_plan.as_ref(), argv.is_empty()) {
        (Some(_), false) => {
            anyhow::bail!("--launch-plan and a trailing argv are mutually exclusive");
        }
        (Some(path), true) => {
            let entrypoint = crate::exec::load_launch_plan(std::path::Path::new(path))?;
            crate::exec::ExecTarget::LaunchPlan { entrypoint }
        }
        (None, true) => {
            anyhow::bail!("`mvmctl exec` requires a command (after `--`) or `--launch-plan <PATH>`")
        }
        (None, false) => crate::exec::ExecTarget::Inline { argv },
    };
    let memory_mib = parse_human_size(memory).context("Invalid --memory")?;
    let mut add_dirs = Vec::with_capacity(add_dir.len());
    for spec in add_dir {
        add_dirs.push(crate::exec::AddDir::parse(spec)?);
    }
    let mut env_pairs = Vec::with_capacity(env.len());
    for kv in env {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--env '{kv}': expected KEY=VALUE"))?;
        if k.is_empty() {
            anyhow::bail!("--env '{kv}': KEY must not be empty");
        }
        if !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || k.starts_with(|c: char| c.is_ascii_digit())
        {
            anyhow::bail!("--env '{kv}': KEY must match [A-Za-z_][A-Za-z0-9_]* (got '{k}')");
        }
        env_pairs.push((k.to_string(), v.to_string()));
    }
    let image = match template {
        Some(name) => crate::exec::ImageSource::Template(name),
        None => {
            ui::info("No --template specified; using bundled default microVM image.");
            let (kernel_path, rootfs_path) = ensure_default_microvm_image()?;
            crate::exec::ImageSource::Prebuilt {
                kernel_path,
                rootfs_path,
                initrd_path: None,
                label: "default-microvm".to_string(),
            }
        }
    };
    let req = crate::exec::ExecRequest {
        image,
        cpus,
        memory_mib,
        add_dirs,
        env: env_pairs,
        target,
        timeout_secs: timeout,
    };
    let exit_code = crate::exec::run(req)?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

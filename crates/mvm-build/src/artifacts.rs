use anyhow::Result;
use std::collections::BTreeMap;
#[cfg(not(test))]
use std::path::{Path, PathBuf};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::config::{ARCH, fc_version, fc_version_short};
use mvm_core::pool::pool_artifacts_dir;

use crate::build::{BUILDER_AGENT_GUEST_BIN, BUILDER_AGENT_SERVICE, BUILDER_DIR};
use crate::scripts::render_script;

#[cfg(test)]
fn resolve_builder_agent_binary(_env: &dyn BuildEnvironment) -> Result<String> {
    Ok("target/debug/mvm-builder-agent".to_string())
}

#[cfg(not(test))]
fn resolve_builder_agent_binary(env: &dyn BuildEnvironment) -> Result<String> {
    if let Ok(v) = std::env::var("MVM_BUILDER_AGENT_BIN") {
        let p = PathBuf::from(v.trim());
        if p.is_file() {
            return Ok(p.to_string_lossy().to_string());
        }
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(bin_dir) = exe.parent()
    {
        let sibling = bin_dir.join("mvm-builder-agent");
        if sibling.is_file() {
            return Ok(sibling.to_string_lossy().to_string());
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir.clone());
    let mut target_roots = vec![workspace_root.join("target")];
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR")
        && !td.trim().is_empty()
    {
        let p = PathBuf::from(td.trim());
        let normalized = if p.is_absolute() {
            p
        } else {
            workspace_root.join(p)
        };
        if !target_roots.iter().any(|r| r == &normalized) {
            target_roots.push(normalized);
        }
    }
    if let Ok(vm_td) = env.shell_exec_stdout("printf \"%s\" \"$CARGO_TARGET_DIR\"")
        && !vm_td.trim().is_empty()
    {
        let p = PathBuf::from(vm_td.trim());
        let normalized = if p.is_absolute() {
            p
        } else {
            workspace_root.join(p)
        };
        if !target_roots.iter().any(|r| r == &normalized) {
            target_roots.push(normalized);
        }
    }

    let mut candidates = Vec::new();
    for root in &target_roots {
        candidates.push(root.join("debug/mvm-builder-agent"));
        candidates.push(root.join("release/mvm-builder-agent"));
    }
    if let Some(found) = candidates.iter().find(|p| p.is_file()) {
        return Ok(found.to_string_lossy().to_string());
    }

    let manifest = workspace_root.join("Cargo.toml");
    let build_marker = env.shell_exec_stdout(&format!(
        "if cargo build -q --manifest-path '{}' -p mvm-guest --bin mvm-builder-agent; then echo __MVM_OK__; else echo __MVM_ERR__; fi",
        manifest.to_string_lossy()
    ))?;
    if !build_marker.contains("__MVM_OK__") {
        return Err(anyhow::anyhow!(
            "failed to build mvm-builder-agent binary (set MVM_BUILDER_AGENT_BIN to override)"
        ));
    }

    if let Some(found) = candidates.iter().find(|p| p.is_file()) {
        return Ok(found.to_string_lossy().to_string());
    }

    Err(anyhow::anyhow!(
        "failed to locate/build mvm-builder-agent binary (searched: {})",
        candidates
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Ensure the builder kernel and rootfs exist.
pub(crate) fn ensure_builder_artifacts(env: &dyn BuildEnvironment) -> Result<()> {
    let kernel_path = format!("{}/vmlinux", BUILDER_DIR);
    let rootfs_path = format!("{}/rootfs.ext4", BUILDER_DIR);
    let exists = env.shell_exec_stdout(&format!(
        "test -f {} && test -f {} && echo yes || echo no",
        kernel_path, rootfs_path
    ))?;

    // Ensure host-side builder agent binary exists for injection into builder rootfs.
    let agent_bin = resolve_builder_agent_binary(env)?;
    env.log_info(&format!("Using builder agent binary: {}", agent_bin));

    if exists.trim() == "yes" {
        env.log_info("Builder artifacts found.");
        let mut refresh_ctx = BTreeMap::new();
        refresh_ctx.insert("builder_dir", BUILDER_DIR.to_string());
        refresh_ctx.insert("agent_src", agent_bin.clone());
        refresh_ctx.insert("agent_dst", BUILDER_AGENT_GUEST_BIN.to_string());
        refresh_ctx.insert("agent_service", BUILDER_AGENT_SERVICE.to_string());
        env.shell_exec(&render_script("refresh_builder_rootfs", &refresh_ctx)?)?;
        env.log_success("Builder artifacts ready.");
        return Ok(());
    }

    env.log_info("Downloading builder artifacts (first time only)...");
    env.shell_exec(&format!(
        "sudo mkdir -p {dir} && sudo chown $(whoami) {dir}",
        dir = BUILDER_DIR,
    ))?;

    // Ensure required tools are present (wget/curl, unsquashfs, mkfs.ext4)
    env.shell_exec_visible(
        "sudo apt-get update -qq && sudo apt-get install -y -qq wget curl squashfs-tools e2fsprogs",
    )?;

    let fc_short = fc_version_short();
    let fc_full = fc_version();
    let mut download_ctx = BTreeMap::new();
    download_ctx.insert("builder_dir", BUILDER_DIR.to_string());
    download_ctx.insert("fc_short", fc_short);
    download_ctx.insert("fc_full", fc_full);
    download_ctx.insert("arch", ARCH.to_string());
    download_ctx.insert("agent_src", agent_bin);
    download_ctx.insert("agent_dst", BUILDER_AGENT_GUEST_BIN.to_string());
    download_ctx.insert("agent_service", BUILDER_AGENT_SERVICE.to_string());
    env.shell_exec_visible(&render_script("download_builder_artifacts", &download_ctx)?)?;

    env.log_success("Builder artifacts ready.");
    Ok(())
}

pub(crate) fn extract_artifacts_from_output_disk(
    env: &dyn BuildEnvironment,
    out_disk: &str,
    tenant_id: &str,
    pool_id: &str,
) -> Result<String> {
    let revision_hash = env
        .shell_exec_stdout(&format!("sha256sum {out_disk} | cut -c1-12"))?
        .trim()
        .to_string();
    let artifacts_dir = pool_artifacts_dir(tenant_id, pool_id);
    let rev_dir = format!("{}/revisions/{}", artifacts_dir, revision_hash);
    env.shell_exec(&format!("mkdir -p {}", rev_dir))?;

    let mut ctx = BTreeMap::new();
    ctx.insert("disk", out_disk.to_string());
    ctx.insert("rev", rev_dir);
    env.shell_exec_visible(&render_script("extract_artifacts_vsock_disk", &ctx)?)?;
    Ok(revision_hash)
}

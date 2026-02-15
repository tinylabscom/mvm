use anyhow::Result;
use std::collections::BTreeMap;
use std::env;
use std::fs;
#[cfg(not(test))]
use std::path::{Path, PathBuf};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::config::{ARCH, fc_version, fc_version_short};
use mvm_core::pool::pool_artifacts_dir;

use crate::build::{
    BUILDER_AGENT_GUEST_BIN, BUILDER_AGENT_SERVICE, BUILDER_DIR, builder_ssh_key_path,
};
use crate::scripts::render_script;

fn builder_ssh_pub_path() -> String {
    format!("{}/id_rsa.pub", BUILDER_DIR)
}

#[cfg(test)]
fn resolve_builder_agent_binary(_env: &dyn BuildEnvironment) -> Result<String> {
    Ok("target/debug/mvm-builder-agent".to_string())
}

#[cfg(not(test))]
fn resolve_builder_agent_binary(env: &dyn BuildEnvironment) -> Result<String> {
    if let Ok(v) = env::var("MVM_BUILDER_AGENT_BIN") {
        let p = PathBuf::from(v.trim());
        if p.is_file() {
            return Ok(p.to_string_lossy().to_string());
        }
    }

    if let Ok(exe) = env::current_exe()
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
    if let Ok(td) = env::var("CARGO_TARGET_DIR")
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
pub(crate) fn ensure_builder_artifacts(
    env: &dyn BuildEnvironment,
    require_ssh_keys: bool,
) -> Result<()> {
    let kernel_path = format!("{}/vmlinux", BUILDER_DIR);
    let rootfs_path = format!("{}/rootfs.ext4", BUILDER_DIR);
    let exists = env.shell_exec_stdout(&format!(
        "test -f {} && test -f {} && echo yes || echo no",
        kernel_path, rootfs_path
    ))?;

    // Always refresh builder SSH key pair to match injected authorized_keys
    let key_path = builder_ssh_key_path();
    let pub_path = builder_ssh_pub_path();
    let mut keygen_ctx = BTreeMap::new();
    keygen_ctx.insert("builder_dir", BUILDER_DIR.to_string());
    keygen_ctx.insert("key", key_path.clone());
    keygen_ctx.insert("pub", pub_path.clone());
    env.shell_exec(&render_script("builder_keygen", &keygen_ctx)?)?;

    // Ensure host-side builder agent binary exists for injection into builder rootfs.
    let agent_bin = resolve_builder_agent_binary(env)?;
    env.log_info(&format!("Using builder agent binary: {}", agent_bin));

    let builder_pub = fs::read_to_string(&pub_path)
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut extra_keys = Vec::new();
    if let Ok(home) = env::var("HOME") {
        for name in ["id_ed25519.pub", "id_rsa.pub"] {
            let p = format!("{home}/.ssh/{name}");
            if let Ok(k) = fs::read_to_string(&p) {
                let t = k.trim();
                if !t.is_empty() {
                    extra_keys.push(t.to_string());
                }
            }
        }
    }
    if let Ok(k) = env::var("MVM_BUILDER_AUTHORIZED_KEY") {
        let t = k.trim();
        if !t.is_empty() {
            extra_keys.push(t.to_string());
        }
    }
    let mut all_keys = Vec::new();
    if !builder_pub.is_empty() {
        all_keys.push(builder_pub);
    }
    all_keys.extend(extra_keys);

    let inject_ssh = !all_keys.is_empty();
    if !inject_ssh {
        if require_ssh_keys {
            return Err(anyhow::anyhow!(
                "No SSH pubkeys found for builder (set MVM_BUILDER_AUTHORIZED_KEY or ensure ~/.ssh/id_ed25519.pub exists)"
            ));
        }
        env.log_warn("No SSH pubkeys found for builder; continuing in vsock-only mode");
    } else {
        env.log_info(&format!(
            "Injecting {} SSH key(s) into builder rootfs",
            all_keys.len()
        ));
    }
    let auth_keys = all_keys.join("\n");
    let auth_keys_escaped = auth_keys.replace('\'', "'\\''");

    if exists.trim() == "yes" {
        env.log_info("Builder artifacts found (refreshing SSH keys)...");
        let mut refresh_ctx = BTreeMap::new();
        refresh_ctx.insert("builder_dir", BUILDER_DIR.to_string());
        refresh_ctx.insert(
            "inject_ssh",
            if inject_ssh { "yes" } else { "no" }.to_string(),
        );
        refresh_ctx.insert("auth_keys", auth_keys_escaped.clone());
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

    // Ensure builder SSH key exists (used to access the builder VM).
    let pub_path = builder_ssh_pub_path();
    env.shell_exec(&format!(
        r#"
        if [ ! -f {key} ]; then
            ssh-keygen -t ed25519 -N '' -f {key} -q
        fi
        chmod 600 {key}
        chmod 644 {pub}
        "#,
        key = key_path,
        pub = pub_path,
    ))?;

    // Ensure required tools are present (wget/curl, unsquashfs, mkfs.ext4)
    env.shell_exec_visible(
        "sudo apt-get update -qq && sudo apt-get install -y -qq wget curl squashfs-tools e2fsprogs",
    )?;

    let fc_short = fc_version_short();
    let fc_full = fc_version();
    let builder_pub = builder_ssh_pub_path();

    let mut download_ctx = BTreeMap::new();
    download_ctx.insert("builder_dir", BUILDER_DIR.to_string());
    download_ctx.insert("fc_short", fc_short);
    download_ctx.insert("fc_full", fc_full);
    download_ctx.insert("arch", ARCH.to_string());
    download_ctx.insert("builder_pub", builder_pub);
    download_ctx.insert(
        "inject_ssh",
        if inject_ssh { "yes" } else { "no" }.to_string(),
    );
    download_ctx.insert("auth_keys", auth_keys_escaped.clone());
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

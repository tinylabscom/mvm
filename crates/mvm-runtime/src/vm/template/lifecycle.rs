use anyhow::{Context, Result};
use mvm_core::template::{TemplateSpec, template_dir, template_spec_path};

use crate::build_env::RuntimeBuildEnv;
use crate::shell;
use mvm_core::pool::ArtifactPaths;
use mvm_core::template::{TemplateRevision, template_current_symlink, template_revision_dir};
use mvm_core::time::utc_now;

use super::registry::TemplateRegistry;

pub fn template_create(spec: &TemplateSpec) -> Result<()> {
    let dir = template_dir(&spec.template_id);
    shell::run_in_vm(&format!("mkdir -p {dir}"))?;
    let path = template_spec_path(&spec.template_id);
    let json = serde_json::to_string_pretty(spec)?;
    shell::run_in_vm(&format!("cat > {path} << 'MVMEOF'\n{json}\nMVMEOF"))?;
    Ok(())
}

pub fn template_load(id: &str) -> Result<TemplateSpec> {
    let path = template_spec_path(id);
    let data = shell::run_in_vm_stdout(&format!("cat {path}"))
        .with_context(|| format!("Failed to load template {}", id))?;
    let spec: TemplateSpec =
        serde_json::from_str(&data).with_context(|| format!("Corrupt template {}", id))?;
    Ok(spec)
}

pub fn template_list() -> Result<Vec<String>> {
    let out = shell::run_in_vm_stdout("ls -1 /var/lib/mvm/templates 2>/dev/null || true")?
        .trim()
        .to_string();
    Ok(out
        .lines()
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect())
}

pub fn template_delete(id: &str, force: bool) -> Result<()> {
    let dir = template_dir(id);
    let flag = if force { "-rf" } else { "-r" };
    shell::run_in_vm(&format!("rm {flag} {dir}"))?;
    Ok(())
}

/// Initialize an on-disk template directory layout (empty artifacts, no spec).
/// Safe to call multiple times; existing contents are preserved.
pub fn template_init(id: &str) -> Result<()> {
    let dir = template_dir(id);
    let artifacts = format!("{}/artifacts/revisions", dir);
    shell::run_in_vm(&format!("mkdir -p {dir} {artifacts}"))?;
    Ok(())
}

/// Build a template using the dev build pipeline (local Nix in Lima).
/// Artifacts are stored in /var/lib/mvm/templates/<id>/artifacts and the current symlink is updated.
pub fn template_build(id: &str, force: bool) -> Result<()> {
    let spec = template_load(id)?;
    let env = RuntimeBuildEnv;

    // Use dev_build to produce artifacts via Nix in Lima
    let result = if force {
        // Force: remove any cached artifacts to trigger a fresh build
        let cache_dir = format!("/var/lib/mvm/dev-builds/{}", spec.flake_ref);
        let _ = shell::run_in_vm(&format!("rm -rf {cache_dir}"));
        mvm_build::dev_build::dev_build(&env, &spec.flake_ref, Some(&spec.profile))?
    } else {
        mvm_build::dev_build::dev_build(&env, &spec.flake_ref, Some(&spec.profile))?
    };
    mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result)?;

    // Store artifacts in template revision directory
    let rev = &result.revision_hash;
    let rev_dst = template_revision_dir(id, rev);
    shell::run_in_vm(&format!("mkdir -p {rev_dst}"))?;
    shell::run_in_vm(&format!("cp -a {} {rev_dst}/vmlinux", result.vmlinux_path))?;
    if let Some(initrd) = &result.initrd_path {
        shell::run_in_vm(&format!("cp -a {} {rev_dst}/initrd", initrd))?;
    }
    shell::run_in_vm(&format!(
        "cp -a {} {rev_dst}/rootfs.ext4",
        result.rootfs_path
    ))?;

    // Generate a minimal fc-base.json config for reference
    let mut boot_source = serde_json::json!({
        "kernel_image_path": "vmlinux",
        "boot_args": "console=ttyS0 reboot=k panic=1 net.ifnames=0"
    });
    if result.initrd_path.is_some() {
        boot_source["initrd_path"] = serde_json::json!("initrd");
    }
    let fc_config = serde_json::json!({
        "boot-source": boot_source,
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": "rootfs.ext4",
            "is_root_device": true,
            "is_read_only": false
        }],
        "machine-config": {
            "vcpu_count": spec.vcpus,
            "mem_size_mib": spec.mem_mib
        }
    });
    let fc_json = serde_json::to_string_pretty(&fc_config)?;
    shell::run_in_vm(&format!(
        "cat > {rev_dst}/fc-base.json << 'MVMEOF'\n{fc_json}\nMVMEOF"
    ))?;

    // Update template current symlink
    let current_link = template_current_symlink(id);
    shell::run_in_vm(&format!("ln -snf revisions/{rev} {current_link}"))?;

    // Compute actual flake.lock hash for accurate cache keys.
    // Pool builds do this via the backend; template builds use dev_build directly,
    // so we compute it here. Falls back to revision hash for remote flakes.
    let flake_lock_hash = shell::run_in_vm_stdout(&format!(
        "if [ -f {flake}/flake.lock ]; then nix hash path {flake}/flake.lock; else echo ''; fi",
        flake = spec.flake_ref
    ))
    .unwrap_or_default()
    .trim()
    .to_string();
    let flake_lock_hash = if flake_lock_hash.is_empty() {
        rev.clone()
    } else {
        flake_lock_hash
    };

    // Record template revision metadata
    let revision = TemplateRevision {
        revision_hash: rev.clone(),
        flake_ref: spec.flake_ref.clone(),
        flake_lock_hash,
        artifact_paths: ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
        },
        built_at: utc_now(),
        profile: spec.profile.clone(),
        role: spec.role.clone(),
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
        data_disk_mib: spec.data_disk_mib,
    };
    let rev_json = serde_json::to_string_pretty(&revision)?;
    let rev_meta_path = format!("{rev_dst}/revision.json");
    shell::run_in_vm(&format!(
        "cat > {rev_meta_path} << 'MVMEOF'\n{rev_json}\nMVMEOF"
    ))?;

    Ok(())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Checksums {
    template_id: String,
    revision_hash: String,
    files: std::collections::BTreeMap<String, String>,
}

fn require_local_template_fs() -> Result<()> {
    // Registry push/pull needs direct file access to /var/lib/mvm/templates.
    // On macOS, templates live inside Lima; run these commands inside the VM.
    if mvm_core::platform::current().needs_lima() && !crate::shell::inside_lima() {
        anyhow::bail!(
            "template push/pull/verify must be run inside the Linux VM (try `mvm shell`, then rerun)"
        );
    }
    Ok(())
}

fn current_revision_id(template_id: &str) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;

    let link = template_current_symlink(template_id);
    let target = std::fs::read_link(&link)
        .with_context(|| format!("Template has no current revision: {}", template_id))?;
    let raw = target.as_os_str().as_bytes();
    let raw = std::str::from_utf8(raw)
        .unwrap_or_default()
        .trim()
        .to_string();
    let rev = raw.strip_prefix("revisions/").unwrap_or(&raw).to_string();
    if rev.is_empty() {
        anyhow::bail!("Template current symlink is empty: {}", link);
    }
    Ok(rev)
}

fn sha256_hex(path: &std::path::Path) -> Result<String> {
    use sha2::Digest;

    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn template_push(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;
    let registry = TemplateRegistry::from_env()?.context("Template registry not configured")?;
    registry.require_configured()?;

    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id(id)?,
    };

    let template_dir = template_dir(id);
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));

    let files = [
        (
            "template.json",
            std::path::PathBuf::from(format!("{}/template.json", template_dir)),
        ),
        ("revision.json", rev_dir.join("revision.json")),
        ("vmlinux", rev_dir.join("vmlinux")),
        ("rootfs.ext4", rev_dir.join("rootfs.ext4")),
        ("fc-base.json", rev_dir.join("fc-base.json")),
    ];

    // Compute checksums for integrity.
    let mut sums = std::collections::BTreeMap::new();
    for (name, path) in &files {
        let hex = sha256_hex(path)?;
        sums.insert(name.to_string(), hex);
    }
    let checksums = Checksums {
        template_id: id.to_string(),
        revision_hash: rev.clone(),
        files: sums,
    };
    let checksums_json = serde_json::to_vec_pretty(&checksums)?;
    // Store checksums locally alongside the revision so `template verify` works offline.
    std::fs::write(rev_dir.join("checksums.json"), &checksums_json).with_context(|| {
        format!(
            "Failed to write checksums.json for template {} revision {}",
            id, rev
        )
    })?;

    // Upload revision objects first, then current pointer.
    for (name, path) in &files {
        let key = registry.key_revision_file(id, &rev, name);
        let data =
            std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
        registry.put_bytes(&key, data)?;
    }
    registry.put_bytes(
        &registry.key_revision_file(id, &rev, "checksums.json"),
        checksums_json,
    )?;
    registry.put_text(&registry.key_current(id), &format!("{}\n", rev))?;

    tracing::info!(template = %id, revision = %rev, "Pushed template revision to registry");
    Ok(())
}

pub fn template_pull(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;
    let registry = TemplateRegistry::from_env()?.context("Template registry not configured")?;
    registry.require_configured()?;

    let rev = match revision {
        Some(r) => r.to_string(),
        None => registry
            .get_text(&registry.key_current(id))?
            .trim()
            .to_string(),
    };
    if rev.is_empty() {
        anyhow::bail!("Registry current revision is empty for template {}", id);
    }

    // Download checksums first.
    let sums_key = registry.key_revision_file(id, &rev, "checksums.json");
    let sums_bytes = registry.get_bytes(&sums_key)?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)
        .with_context(|| format!("Invalid checksums.json for {}/{}", id, rev))?;

    let base_dir = std::path::PathBuf::from(template_dir(id));
    std::fs::create_dir_all(&base_dir)?;
    let tmp_dir = base_dir.join(format!("tmp-pull-{}", rev));
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir).ok();
    }
    std::fs::create_dir_all(&tmp_dir)?;

    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));
    std::fs::create_dir_all(rev_dir.parent().unwrap_or(&base_dir))?;

    // Download required files into tmp and verify.
    for (name, expected_hex) in &checksums.files {
        let key = registry.key_revision_file(id, &rev, name);
        let data = registry.get_bytes(&key)?;
        let tmp_path = tmp_dir.join(name);
        std::fs::write(&tmp_path, &data)?;
        let got = sha256_hex(&tmp_path)?;
        if &got != expected_hex {
            std::fs::remove_dir_all(&tmp_dir).ok();
            anyhow::bail!(
                "checksum mismatch for {} (expected {}, got {})",
                name,
                expected_hex,
                got
            );
        }
    }
    // Keep checksums.json in the installed revision so `template verify` can run locally.
    std::fs::write(tmp_dir.join("checksums.json"), &sums_bytes)?;

    // Install into final revision dir.
    if rev_dir.exists() {
        std::fs::remove_dir_all(&rev_dir).ok();
    }
    std::fs::create_dir_all(&rev_dir)?;
    for name in checksums.files.keys() {
        std::fs::rename(tmp_dir.join(name), rev_dir.join(name))?;
    }
    std::fs::rename(
        tmp_dir.join("checksums.json"),
        rev_dir.join("checksums.json"),
    )?;
    std::fs::remove_dir_all(&tmp_dir).ok();

    // Update current symlink (keep existing "revisions/<rev>" convention).
    let link = template_current_symlink(id);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(format!("revisions/{}", rev), &link)?;

    tracing::info!(template = %id, revision = %rev, "Pulled template revision from registry");
    Ok(())
}

pub fn template_verify(id: &str, revision: Option<&str>) -> Result<()> {
    require_local_template_fs()?;

    let rev = match revision {
        Some(r) => r.to_string(),
        None => current_revision_id(id)?,
    };
    let rev_dir = std::path::PathBuf::from(template_revision_dir(id, &rev));
    let sums_path = rev_dir.join("checksums.json");
    let sums_bytes =
        std::fs::read(&sums_path).with_context(|| format!("Missing {}", sums_path.display()))?;
    let checksums: Checksums = serde_json::from_slice(&sums_bytes)?;

    for (name, expected_hex) in &checksums.files {
        let p = rev_dir.join(name);
        let got = sha256_hex(&p)?;
        if &got != expected_hex {
            anyhow::bail!(
                "checksum mismatch for {} (expected {}, got {})",
                name,
                expected_hex,
                got
            );
        }
    }

    Ok(())
}

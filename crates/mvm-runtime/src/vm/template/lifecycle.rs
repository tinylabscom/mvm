use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use mvm_core::template::{
    SnapshotInfo, TemplateSpec, template_dir, template_revision_dir, template_snapshot_dir,
    template_spec_path,
};

use crate::build_env::RuntimeBuildEnv;
use crate::shell;
use crate::ui;
use mvm_core::pool::ArtifactPaths;
use mvm_core::template::{TemplateRevision, template_current_symlink};
use mvm_core::time::utc_now;

use super::registry::TemplateRegistry;

/// Run a shell command in the VM and check its exit code.
/// Returns an error with stderr context if the command fails.
fn vm_exec(script: &str) -> Result<()> {
    let out = shell::run_in_vm(script)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let first_line = script.lines().next().unwrap_or(script);
        return Err(anyhow!(
            "Command failed (exit {}): {}\n  command: {}",
            out.status.code().unwrap_or(-1),
            stderr,
            first_line,
        ));
    }
    Ok(())
}

/// Run a shell command in the VM, check exit code, and return stdout.
fn vm_exec_stdout(script: &str) -> Result<String> {
    let out = shell::run_in_vm(script)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let first_line = script.lines().next().unwrap_or(script);
        return Err(anyhow!(
            "Command failed (exit {}): {}\n  command: {}",
            out.status.code().unwrap_or(-1),
            stderr,
            first_line,
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn template_create(spec: &TemplateSpec) -> Result<()> {
    let dir = template_dir(&spec.template_id);
    vm_exec(&format!("mkdir -p {dir}"))
        .with_context(|| format!("Failed to create template directory {}", dir))?;
    let path = template_spec_path(&spec.template_id);
    let json = serde_json::to_string_pretty(spec)?;
    vm_exec(&format!("cat > {path} << 'MVMEOF'\n{json}\nMVMEOF"))
        .with_context(|| format!("Failed to write template spec {}", path))?;
    Ok(())
}

pub fn template_load(id: &str) -> Result<TemplateSpec> {
    let path = template_spec_path(id);
    let data = vm_exec_stdout(&format!("cat {path}")).with_context(|| {
        format!(
            "Failed to load template {} (does it exist? try `mvm template list`)",
            id
        )
    })?;
    let spec: TemplateSpec =
        serde_json::from_str(&data).with_context(|| format!("Corrupt template {}", id))?;
    Ok(spec)
}

pub fn template_list() -> Result<Vec<String>> {
    let base = mvm_core::template::templates_base_dir();
    let out = shell::run_in_vm_stdout(&format!("ls -1 {base} 2>/dev/null || true"))?
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
    vm_exec(&format!("rm {flag} {dir}"))
        .with_context(|| format!("Failed to delete template {}", id))?;
    Ok(())
}

/// Initialize an on-disk template directory layout (empty artifacts, no spec).
/// Safe to call multiple times; existing contents are preserved.
pub fn template_init(id: &str) -> Result<()> {
    let dir = template_dir(id);
    let artifacts = format!("{}/artifacts/revisions", dir);
    vm_exec(&format!("mkdir -p {dir} {artifacts}"))
        .with_context(|| format!("Failed to initialize template directory {}", dir))?;
    Ok(())
}

/// Build a template using the dev build pipeline (local Nix in Lima).
/// Artifacts are stored in ~/.mvm/templates/<id>/artifacts and the current symlink is updated.
pub fn template_build(id: &str, force: bool) -> Result<()> {
    use crate::ui;

    let spec = template_load(id)?;
    let env = RuntimeBuildEnv;

    ui::info(&format!(
        "Building template '{}' (flake: {}, profile: {})",
        id, spec.flake_ref, spec.profile
    ));

    // Use dev_build to produce artifacts via Nix in Lima.
    // The dev build cache is keyed by Nix store hash at ~/.mvm/dev/builds/<hash>/,
    // so --force must clear the entire builds directory.
    if force {
        ui::info("Force build: clearing dev build cache");
        let builds_dir = format!("{}/dev/builds", mvm_core::config::mvm_data_dir());
        let _ = shell::run_in_vm(&format!("rm -rf {builds_dir}"));
    }
    let result = mvm_build::dev_build::dev_build(&env, &spec.flake_ref, Some(&spec.profile))?;
    // Best-effort: inject guest agent if not already present.
    // Non-fatal because flakes built with mvm's mkGuest already include
    // guest-agent.nix, and the loop-mount check can fail on virtiofs.
    if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(&env, &result) {
        ui::warn(&format!(
            "Could not verify guest agent ({}). If built with mvm's mkGuest, the agent is already included.",
            e
        ));
    }

    // Store artifacts in template revision directory
    ui::info("Storing artifacts in template revision directory...");
    let rev = &result.revision_hash;
    let rev_dst = template_revision_dir(id, rev);
    shell::run_in_vm(&format!("mkdir -p {rev_dst}"))?;
    shell::run_in_vm(&format!("cp -a {} {rev_dst}/vmlinux", result.vmlinux_path))?;
    if let Some(initrd) = &result.initrd_path {
        shell::run_in_vm(&format!("cp -a {} {rev_dst}/initrd", initrd))?;
    }
    shell::run_in_vm(&format!(
        "cp -a {} {rev_dst}/rootfs.ext4 && chmod u+w {rev_dst}/rootfs.ext4",
        result.rootfs_path
    ))?;

    // Generate a minimal fc-base.json config for reference.
    // Minimal guests (no initrd) need root= and init= on the kernel cmdline
    // so the kernel can mount the rootfs and exec /init directly.
    let boot_args = if result.initrd_path.is_some() {
        "console=ttyS0 reboot=k panic=1 net.ifnames=0".to_string()
    } else {
        "root=/dev/vda rw rootwait init=/init console=ttyS0 reboot=k panic=1 net.ifnames=0"
            .to_string()
    };
    let mut boot_source = serde_json::json!({
        "kernel_image_path": "vmlinux",
        "boot_args": boot_args
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
            initrd: None,
        },
        built_at: utc_now(),
        profile: spec.profile.clone(),
        role: spec.role.clone(),
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
        data_disk_mib: spec.data_disk_mib,
        snapshot: None,
    };
    let rev_json = serde_json::to_string_pretty(&revision)?;
    let rev_meta_path = format!("{rev_dst}/revision.json");
    shell::run_in_vm(&format!(
        "cat > {rev_meta_path} << 'MVMEOF'\n{rev_json}\nMVMEOF"
    ))?;

    ui::success(&format!(
        "Template '{}' built successfully (revision: {})",
        id,
        &rev[..rev.len().min(12)]
    ));
    Ok(())
}

/// Check if the current revision of a template has a snapshot.
pub fn template_has_snapshot(id: &str) -> Result<bool> {
    let rev = current_revision_id(id)?;
    let snap_dir = template_snapshot_dir(id, &rev);
    let out = shell::run_in_vm_stdout(&format!(
        "test -f {dir}/vmstate.bin && test -f {dir}/mem.bin && echo yes || echo no",
        dir = snap_dir,
    ))?;
    Ok(out.trim() == "yes")
}

/// Load the snapshot metadata for a template revision.
pub fn template_snapshot_info(id: &str) -> Result<Option<SnapshotInfo>> {
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);
    let meta_path = format!("{}/revision.json", rev_dir);
    let data = vm_exec_stdout(&format!("cat {}", meta_path))?;
    let revision: TemplateRevision = serde_json::from_str(&data)
        .with_context(|| format!("Corrupt revision.json for template {}", id))?;
    Ok(revision.snapshot)
}

/// Poll the guest agent via vsock until it responds, or timeout.
pub fn wait_for_healthy(vsock_uds_path: &str, timeout_secs: u64, interval_ms: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut attempts = 0u32;
    loop {
        if mvm_guest::vsock::ping_at(vsock_uds_path).unwrap_or(false) {
            ui::success(&format!(
                "Guest agent healthy after {} attempts",
                attempts + 1
            ));
            return Ok(());
        }
        attempts += 1;
        if attempts.is_multiple_of(10) {
            ui::info(&format!(
                "Waiting for guest agent... ({} attempts, {}s remaining)",
                attempts,
                deadline.saturating_duration_since(Instant::now()).as_secs()
            ));
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "VM did not become healthy within {}s ({} attempts)",
                timeout_secs,
                attempts
            );
        }
        std::thread::sleep(Duration::from_millis(interval_ms));
    }
}

/// Build a template and then create a Firecracker snapshot for instant starts.
///
/// 1. Runs `template_build()` to produce artifacts
/// 2. Boots a temporary Firecracker VM from those artifacts
/// 3. Waits for the guest agent to become healthy (vsock ping)
/// 4. Pauses vCPUs and creates a full snapshot
/// 5. Stores snapshot files in the template revision directory
/// 6. Cleans up the temporary VM
pub fn template_build_with_snapshot(id: &str, force: bool) -> Result<()> {
    use crate::config::BRIDGE_IP;
    use crate::vm::{microvm, network};

    // Step 1: Build artifacts (reuses existing template_build)
    template_build(id, force)?;

    let spec = template_load(id)?;
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);
    let snap_dir = template_snapshot_dir(id, &rev);

    ui::info("Creating snapshot: booting temporary VM...");

    // Allocate a temporary network slot for the snapshot build
    let snapshot_vm_name = format!("__snapshot-{}", id);
    let slot = microvm::allocate_slot(&snapshot_vm_name)?;
    let abs_dir = microvm::resolve_vm_dir(&slot)?;
    let abs_socket = format!("{}/fc.socket", abs_dir);

    // Build boot args matching what run_from_build would use (minimal guest)
    let boot_args = format!(
        "root=/dev/vda rw rootwait init=/init console=ttyS0 reboot=k panic=1 net.ifnames=0 mvm.ip={ip}/24 mvm.gw={gw}",
        ip = slot.guest_ip,
        gw = BRIDGE_IP,
    );

    // Create a runtime directory in the template for shared snapshot drives.
    // Using template-relative paths ensures all instances can use symlinks
    // to their own config/secrets without path conflicts.
    let template_runtime_dir = format!("{}/runtime", template_dir(id));
    shell::run_in_vm(&format!("mkdir -p {}", template_runtime_dir))?;

    // Build a FlakeRunConfig for the temporary VM, using template runtime dir
    // for config/secrets so the snapshot has stable paths.
    let run_config = microvm::FlakeRunConfig {
        name: snapshot_vm_name.clone(),
        slot: slot.clone(),
        vmlinux_path: format!("{}/vmlinux", rev_dir),
        initrd_path: None,
        rootfs_path: format!("{}/rootfs.ext4", rev_dir),
        revision_hash: rev.clone(),
        flake_ref: spec.flake_ref.clone(),
        profile: Some(spec.profile.clone()),
        cpus: spec.vcpus as u32,
        memory: spec.mem_mib,
        volumes: vec![],
        config_files: vec![],
        secret_files: vec![],
        ports: vec![],
    };

    // Ensure bridge + TAP
    network::bridge_ensure()?;
    network::tap_create(&slot)?;

    // Start Firecracker
    let start_result = microvm::start_vm_firecracker(&abs_dir, &abs_socket);
    if let Err(e) = start_result {
        let _ = network::tap_destroy(&slot);
        return Err(e.context("Failed to start snapshot VM"));
    }

    // Configure and boot, using template runtime dir for config/secrets drives
    if let Err(e) = microvm::configure_flake_microvm_with_drives_dir(
        &run_config,
        &abs_dir,
        &abs_socket,
        &template_runtime_dir,
    ) {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to configure snapshot VM"));
    }

    ui::info("Booting snapshot VM...");
    std::thread::sleep(Duration::from_millis(15));
    if let Err(e) = microvm::api_put_socket(
        &abs_socket,
        "/actions",
        r#"{"action_type": "InstanceStart"}"#,
    ) {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to boot snapshot VM"));
    }

    // Make vsock accessible
    let _ = shell::run_in_vm(&format!("sudo chmod 0666 {}/v.sock 2>/dev/null", abs_dir));

    // Wait for guest agent to become healthy
    // Note: First boot can take 10-15 minutes on nested virtualization (macOS)
    // due to V8 compilation overhead. 900s (15 min) timeout ensures snapshot
    // creation succeeds even on slow systems.
    let vsock_path = format!("{}/v.sock", abs_dir);
    ui::info(
        "Waiting for guest agent to become healthy (may take up to 15 minutes on first boot)...",
    );
    let health_result = wait_for_healthy(&vsock_path, 900, 2000);

    if let Err(e) = health_result {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Snapshot VM did not become healthy"));
    }

    // Pause vCPUs
    ui::info("Pausing VM for snapshot...");
    let pause_result = microvm::api_patch_socket(&abs_socket, "/vm", r#"{"state": "Paused"}"#);
    if let Err(e) = pause_result {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to pause VM for snapshot"));
    }

    // Create snapshot directory in template
    shell::run_in_vm(&format!("mkdir -p {}", snap_dir))?;

    // Create snapshot via Firecracker API
    ui::info("Creating Firecracker snapshot...");
    let snapshot_result = shell::run_in_vm(&format!(
        r#"sudo curl -s --unix-socket {socket} -X PUT \
            -H 'Content-Type: application/json' \
            -d '{{"snapshot_type": "Full", "snapshot_path": "{snap}/vmstate.bin", "mem_file_path": "{snap}/mem.bin"}}' \
            'http://localhost/snapshot/create'"#,
        socket = abs_socket,
        snap = snap_dir,
    ));

    if let Err(e) = snapshot_result {
        cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);
        return Err(e.context("Failed to create Firecracker snapshot"));
    }

    // Get snapshot file sizes
    let vmstate_size: u64 = shell::run_in_vm_stdout(&format!(
        "stat -c%s {}/vmstate.bin 2>/dev/null || echo 0",
        snap_dir
    ))?
    .trim()
    .parse()
    .unwrap_or(0);
    let mem_size: u64 = shell::run_in_vm_stdout(&format!(
        "stat -c%s {}/mem.bin 2>/dev/null || echo 0",
        snap_dir
    ))?
    .trim()
    .parse()
    .unwrap_or(0);

    // Update revision.json with snapshot metadata
    let snapshot_info = SnapshotInfo {
        created_at: utc_now(),
        vmstate_size_bytes: vmstate_size,
        mem_size_bytes: mem_size,
        boot_args: boot_args.clone(),
        vcpus: spec.vcpus,
        mem_mib: spec.mem_mib,
    };

    let rev_meta_path = format!("{}/revision.json", rev_dir);
    let rev_data = vm_exec_stdout(&format!("cat {}", rev_meta_path))?;
    let mut revision: TemplateRevision = serde_json::from_str(&rev_data)
        .with_context(|| "Failed to parse revision.json for snapshot update")?;
    revision.snapshot = Some(snapshot_info);

    let updated_json = serde_json::to_string_pretty(&revision)?;
    shell::run_in_vm(&format!(
        "cat > {} << 'MVMEOF'\n{}\nMVMEOF",
        rev_meta_path, updated_json
    ))?;

    // Clean up temporary VM
    cleanup_snapshot_vm(&abs_dir, &abs_socket, &slot);

    let total_mb = (vmstate_size + mem_size) / (1024 * 1024);
    ui::success(&format!(
        "Snapshot created for template '{}' ({}MB total)",
        id, total_mb
    ));
    ui::info("Use 'mvmctl run --template' for instant starts from this snapshot.");

    Ok(())
}

/// Clean up a temporary snapshot VM (best-effort).
fn cleanup_snapshot_vm(abs_dir: &str, abs_socket: &str, slot: &crate::config::VmSlot) {
    use crate::vm::network;

    // Kill Firecracker process
    let _ = shell::run_in_vm(&format!(
        r#"
        if [ -f {dir}/fc.pid ]; then
            sudo kill $(cat {dir}/fc.pid) 2>/dev/null || true
        fi
        sudo rm -f {socket}
        "#,
        dir = abs_dir,
        socket = abs_socket,
    ));

    // Destroy TAP
    let _ = network::tap_destroy(slot);

    // Remove temp VM directory
    let _ = shell::run_in_vm(&format!("rm -rf {}", abs_dir));
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Checksums {
    template_id: String,
    revision_hash: String,
    files: std::collections::BTreeMap<String, String>,
}

fn require_local_template_fs() -> Result<()> {
    // Registry push/pull needs direct file access to ~/.mvm/templates.
    // On macOS, templates live inside Lima; run these commands inside the VM.
    if mvm_core::platform::current().needs_lima() && !crate::shell::inside_lima() {
        anyhow::bail!(
            "template push/pull/verify must be run inside the Linux VM (try `mvm shell`, then rerun)"
        );
    }
    Ok(())
}

/// Resolve a built template to its current artifact paths.
///
/// Returns `(spec, vmlinux, initrd, rootfs, revision_hash)`.
/// The artifact paths are absolute and valid inside the Lima VM.
pub fn template_artifacts(
    id: &str,
) -> Result<(TemplateSpec, String, Option<String>, String, String)> {
    let spec = template_load(id)?;
    let rev = current_revision_id(id)?;
    let rev_dir = template_revision_dir(id, &rev);

    let vmlinux = format!("{rev_dir}/vmlinux");
    let rootfs = format!("{rev_dir}/rootfs.ext4");
    let initrd_candidate = format!("{rev_dir}/initrd");

    vm_exec(&format!("test -f {vmlinux}")).with_context(|| {
        format!(
            "Template '{}' has no vmlinux (run `mvm template build {}`)",
            id, id
        )
    })?;
    vm_exec(&format!("test -f {rootfs}")).with_context(|| {
        format!(
            "Template '{}' has no rootfs (run `mvm template build {}`)",
            id, id
        )
    })?;

    let has_initrd = vm_exec(&format!("test -f {initrd_candidate}")).is_ok();

    Ok((
        spec,
        vmlinux,
        if has_initrd {
            Some(initrd_candidate)
        } else {
            None
        },
        rootfs,
        rev,
    ))
}

pub fn current_revision_id(template_id: &str) -> Result<String> {
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

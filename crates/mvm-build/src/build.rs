use anyhow::{Context, Result};

use mvm_core::build_env::BuildEnvironment;
use mvm_core::config::{ARCH, fc_version_short};
use mvm_core::instance::InstanceNet;
use mvm_core::naming;
use mvm_core::pool::{ArtifactPaths, BuildRevision, pool_artifacts_dir};
use mvm_core::tenant::{TenantNet, tenant_ssh_key_path};
use mvm_core::time::utc_now;

use crate::nix_manifest::NixManifest;

/// Base directory for builder infrastructure.
const BUILDER_DIR: &str = "/var/lib/mvm/builder";

/// Builder VM resource defaults.
const BUILDER_VCPUS: u8 = 4;
const BUILDER_MEM_MIB: u32 = 4096;

/// IP offset reserved for the builder VM within each tenant subnet.
const BUILDER_IP_OFFSET: u8 = 2;

/// Default build timeout in seconds (30 minutes).
const DEFAULT_TIMEOUT_SECS: u64 = 1800;

/// Optional overrides for pool builds.
#[derive(Default)]
pub struct PoolBuildOpts {
    pub timeout_secs: Option<u64>,
    pub builder_vcpus: Option<u8>,
    pub builder_mem_mib: Option<u32>,
}

fn maybe_skip_by_lock_hash(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    flake_ref: &str,
) -> Result<bool> {
    if flake_ref.contains(':') {
        return Ok(false); // remote ref: don't hash
    }

    let hash = match env.shell_exec_stdout(&format!(
        r#"if [ -f {}/flake.lock ]; then nix hash path {}/flake.lock; else echo ""; fi"#,
        flake_ref, flake_ref
    )) {
        Ok(h) => h,
        Err(_) => return Ok(false),
    };
    let trimmed = hash.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }

    let artifacts_dir = pool_artifacts_dir(tenant_id, pool_id);
    let lock_hash_path = format!("{}/last_flake_lock.hash", artifacts_dir);
    let current_exists = env
        .shell_exec_stdout(&format!(
            "test -L {}/current && echo yes || echo no",
            artifacts_dir
        ))
        .unwrap_or_default();
    let existing = env
        .shell_exec_stdout(&format!("cat {} 2>/dev/null || echo ''", lock_hash_path))
        .unwrap_or_default();

    if current_exists.trim() == "yes" && existing.trim() == trimmed {
        env.log_success("flake.lock unchanged — skipping rebuild (cache hit)");
        return Ok(true);
    }

    Ok(false)
}

/// Build artifacts for a pool using an ephemeral Firecracker builder microVM.
pub fn pool_build(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    timeout_secs: Option<u64>,
) -> Result<()> {
    let opts = PoolBuildOpts {
        timeout_secs,
        builder_vcpus: None,
        builder_mem_mib: None,
    };
    pool_build_with_opts(env, tenant_id, pool_id, opts)
}

/// Build artifacts for a pool with optional resource overrides.
pub fn pool_build_with_opts(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    opts: PoolBuildOpts,
) -> Result<()> {
    let timeout = opts.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let spec = env.load_pool_spec(tenant_id, pool_id)?;
    let tenant = env.load_tenant_config(tenant_id)?;

    env.log_info(&format!(
        "Building {}/{} (flake: {}, profile: {})",
        tenant_id, pool_id, spec.flake_ref, spec.profile
    ));

    if maybe_skip_by_lock_hash(env, tenant_id, pool_id, &spec.flake_ref)? {
        return Ok(());
    }

    // Step 1: Ensure builder artifacts exist
    ensure_builder_artifacts(env)?;

    // Step 2: Ensure tenant bridge is up
    env.ensure_bridge(&tenant.net)?;

    // Step 3: Create a unique build ID for this run
    let build_id = naming::generate_instance_id().replace("i-", "b-");
    let build_run_dir = format!("{}/run/{}", BUILDER_DIR, build_id);

    env.shell_exec(&format!("mkdir -p {}", build_run_dir))?;

    env.log_info(&format!("Build ID: {}", build_id));

    // Step 4: Boot ephemeral builder VM
    let builder_net = builder_instance_net(&tenant.net);
    let builder_pid = boot_builder(
        env,
        &build_run_dir,
        &builder_net,
        &tenant.net,
        opts.builder_vcpus.unwrap_or(BUILDER_VCPUS),
        opts.builder_mem_mib.unwrap_or(BUILDER_MEM_MIB),
    )?;

    // Optional: sync local flake into builder if needed
    let synced_flake = sync_local_flake_if_needed(
        env,
        &builder_net.guest_ip,
        &tenant_ssh_key_path(tenant_id),
        &spec.flake_ref,
    );
    let flake_ref = synced_flake.as_deref().unwrap_or(&spec.flake_ref);

    let lock_hash = flake_lock_hash(
        env,
        &builder_net.guest_ip,
        &tenant_ssh_key_path(tenant_id),
        flake_ref,
    );

    ensure_nix_installed(env, &builder_net.guest_ip, &tenant_ssh_key_path(tenant_id))?;

    // Step 5: Wait for builder to be ready, then run the build
    let result = run_nix_build(
        env,
        &builder_net.guest_ip,
        &tenant_ssh_key_path(tenant_id),
        flake_ref,
        &spec.role,
        &spec.profile,
        timeout,
    );

    // Step 6: Extract artifacts if possible, then always tear down
    let build_result = match result {
        Ok(nix_output_path) => {
            env.log_info("Build completed, extracting artifacts...");
            extract_artifacts(
                env,
                &builder_net.guest_ip,
                &tenant_ssh_key_path(tenant_id),
                &nix_output_path,
                tenant_id,
                pool_id,
            )
        }
        Err(e) => Err(e),
    };

    // Step 7: Always tear down builder
    teardown_builder(env, builder_pid, &builder_net, &build_run_dir)?;

    // Propagate build result after cleanup
    let revision_hash = build_result?;

    // Step 8: Record revision
    let revision = BuildRevision {
        revision_hash: revision_hash.clone(),
        flake_ref: spec.flake_ref.clone(),
        flake_lock_hash: lock_hash.clone().unwrap_or_else(|| revision_hash.clone()),
        artifact_paths: ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
        },
        built_at: utc_now(),
    };

    env.record_revision(tenant_id, pool_id, &revision)?;
    record_build_history(env, tenant_id, pool_id, &revision)?;

    if let Some(hash) = lock_hash {
        let artifacts_dir = pool_artifacts_dir(tenant_id, pool_id);
        let lock_hash_path = format!("{}/last_flake_lock.hash", artifacts_dir);
        env.shell_exec(&format!(
            "mkdir -p {dir} && echo '{hash}' > {path}",
            dir = artifacts_dir,
            hash = hash,
            path = lock_hash_path
        ))?;
    }

    env.log_success(&format!(
        "Build complete: {}/{} revision {}",
        tenant_id, pool_id, revision_hash
    ));

    Ok(())
}

/// Construct the InstanceNet for the builder VM (always uses IP offset 2).
fn builder_instance_net(tenant_net: &TenantNet) -> InstanceNet {
    let ip_offset = BUILDER_IP_OFFSET;
    let base_ip = &tenant_net.ipv4_subnet;

    let ip_parts: Vec<&str> = base_ip
        .split('/')
        .next()
        .unwrap_or("10.240.0.0")
        .split('.')
        .collect();
    let prefix = format!("{}.{}.{}", ip_parts[0], ip_parts[1], ip_parts[2]);

    let cidr_str = base_ip.split('/').nth(1).unwrap_or("24");
    let cidr: u8 = cidr_str.parse().unwrap_or(24);

    InstanceNet {
        tap_dev: naming::tap_name(tenant_net.tenant_net_id, ip_offset),
        mac: naming::mac_address(tenant_net.tenant_net_id, ip_offset),
        guest_ip: format!("{}.{}", prefix, ip_offset),
        gateway_ip: tenant_net.gateway_ip.clone(),
        cidr,
    }
}

/// Ensure the builder kernel and rootfs exist.
fn ensure_builder_artifacts(env: &dyn BuildEnvironment) -> Result<()> {
    let kernel_path = format!("{}/vmlinux", BUILDER_DIR);
    let rootfs_path = format!("{}/rootfs.ext4", BUILDER_DIR);
    let exists = env.shell_exec_stdout(&format!(
        "test -f {} && test -f {} && echo yes || echo no",
        kernel_path, rootfs_path
    ))?;

    if exists.trim() == "yes" {
        env.log_info("Builder artifacts found.");
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
    env.shell_exec_visible(&format!(
        r#"
        set -euo pipefail
        cd {dir}

        if [ ! -f vmlinux ]; then
            echo '[mvm] Downloading builder kernel...'
            latest_kernel_key=$(wget -q \
                "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/{fc_short}/{arch}/vmlinux-5.10&list-type=2" \
                -O - | grep -oP '(?<=<Key>)(firecracker-ci/{fc_short}/{arch}/vmlinux-5\.10\.[0-9]{{3}})(?=</Key>)')
            wget -q --show-progress -O vmlinux \
                "https://s3.amazonaws.com/spec.ccfc.min/$latest_kernel_key"
        fi

        # If rootfs.ext4 is missing, (re)build it from squashfs
        if [ ! -f rootfs.ext4 ]; then
            echo '[mvm] Downloading builder rootfs (fresh)...'
            latest_ubuntu_key=$(curl -s \
                "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/{fc_short}/{arch}/ubuntu-&list-type=2" \
                | grep -oP '(?<=<Key>)(firecracker-ci/{fc_short}/{arch}/ubuntu-[0-9]+\\.[0-9]+\\.squashfs)(?=</Key>)' \
                | sort -V | tail -1)

            rm -f rootfs.squashfs
            wget -q --show-progress -O rootfs.squashfs \
                "https://s3.amazonaws.com/spec.ccfc.min/$latest_ubuntu_key"

            echo '[mvm] Preparing builder rootfs...'
            rm -rf squashfs-root
            if ! unsquashfs -d squashfs-root rootfs.squashfs; then
                echo '[mvm] Corrupt squashfs; re-downloading...'
                rm -f rootfs.squashfs
                wget -q --show-progress -O rootfs.squashfs \
                    "https://s3.amazonaws.com/spec.ccfc.min/$latest_ubuntu_key"
                rm -rf squashfs-root
                unsquashfs -d squashfs-root rootfs.squashfs
            fi

            mkdir -p squashfs-root/root/.ssh
            mkdir -p squashfs-root/nix

            rm -f rootfs.ext4
            truncate -s 4G rootfs.ext4
            mkfs.ext4 -d squashfs-root -F rootfs.ext4

            rm -rf squashfs-root rootfs.squashfs
            echo '[mvm] Builder rootfs prepared.'
        fi
        "#,
        dir = BUILDER_DIR,
        arch = ARCH,
        fc_short = fc_short,
    ))?;

    env.log_success("Builder artifacts ready.");
    Ok(())
}

/// Boot an ephemeral Firecracker builder VM. Returns the FC process PID.
fn boot_builder(
    env: &dyn BuildEnvironment,
    run_dir: &str,
    builder_net: &InstanceNet,
    tenant_net: &TenantNet,
    vcpus: u8,
    mem_mib: u32,
) -> Result<u32> {
    env.log_info("Booting builder VM...");

    // Set up TAP device for builder
    env.setup_tap(builder_net, &tenant_net.bridge_name)?;

    // Generate FC config inline as JSON (avoids depending on mvm-runtime FcConfig types)
    let fc_config_json = serde_json::json!({
        "boot-source": {
            "kernel_image_path": format!("{}/vmlinux", BUILDER_DIR),
            "boot_args": format!(
                "keep_bootcon console=ttyS0 reboot=k panic=1 pci=off ip={}::{}:255.255.255.0::eth0:off",
                builder_net.guest_ip, builder_net.gateway_ip,
            ),
        },
        "drives": [{
            "drive_id": "rootfs",
            "path_on_host": format!("{}/rootfs.ext4", BUILDER_DIR),
            "is_root_device": true,
            "is_read_only": false,
        }],
        "network-interfaces": [{
            "iface_id": "net1",
            "guest_mac": builder_net.mac,
            "host_dev_name": builder_net.tap_dev,
        }],
        "machine-config": {
            "vcpu_count": vcpus,
            "mem_size_mib": mem_mib,
        },
    });

    let config_json = serde_json::to_string_pretty(&fc_config_json)?;
    let config_path = format!("{}/fc-builder.json", run_dir);
    let socket_path = format!("{}/firecracker.socket", run_dir);
    let log_path = format!("{}/firecracker.log", run_dir);
    let pid_path = format!("{}/fc.pid", run_dir);

    // Write FC config
    env.shell_exec(&format!(
        "cat > {} << 'MVMEOF'\n{}\nMVMEOF",
        config_path, config_json
    ))?;

    // Launch Firecracker in background
    env.shell_exec(&format!(
        r#"
        rm -f {socket}
        firecracker \
            --api-sock {socket} \
            --config-file {config} \
            --log-path {log} \
            --level Info \
            &
        FC_PID=$!
        echo $FC_PID > {pid}
        "#,
        socket = socket_path,
        config = config_path,
        log = log_path,
        pid = pid_path,
    ))?;

    // Read the PID
    let pid_str = env.shell_exec_stdout(&format!("cat {}", pid_path))?;
    let pid: u32 = pid_str
        .trim()
        .parse()
        .with_context(|| format!("Failed to parse builder PID: {:?}", pid_str))?;

    env.log_info(&format!("Builder VM started (PID: {})", pid));

    // Wait for builder VM to be SSH-accessible
    env.log_info("Waiting for builder VM to become ready...");
    env.shell_exec(&format!(
        r#"
        for i in $(seq 1 60); do
            if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
                   -o BatchMode=yes -i /dev/null \
                   root@{ip} true 2>/dev/null; then
                echo "Builder ready after ${{i}}s"
                exit 0
            fi
            sleep 1
        done
        echo "Builder VM did not become ready in 60s" >&2
        exit 1
        "#,
        ip = builder_net.guest_ip,
    ))?;

    Ok(pid)
}

/// If flake_ref is a local path, sync it into the builder VM so `nix build .` works.
fn sync_local_flake_if_needed(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
    flake_ref: &str,
) -> Option<String> {
    if flake_ref.contains(':') {
        return None; // remote ref, nothing to do
    }

    // Canonicalize inside the Lima/host environment.
    let realpath = env
        .shell_exec_stdout(&format!("realpath {} 2>/dev/null", flake_ref))
        .ok()?;

    if realpath.is_empty() {
        env.log_info(&format!(
            "Local flake '{}' not found; skipping sync",
            flake_ref
        ));
        return None;
    }

    let tmp_tar = env
        .shell_exec_stdout("mktemp /tmp/mvm-flake-XXXX.tar.gz")
        .ok()?;
    let script = format!(
        r#"
        set -euo pipefail
        tar czf {tmp} -C {src} .
        scp -o StrictHostKeyChecking=no -i {key} {tmp} root@{ip}:/tmp/flake.tar.gz
        ssh -o StrictHostKeyChecking=no -i {key} root@{ip} \
            'rm -rf /root/project && mkdir -p /root/project && tar xzf /tmp/flake.tar.gz -C /root/project'
        rm -f {tmp}
        "#,
        tmp = tmp_tar,
        src = realpath,
        key = ssh_key_path,
        ip = builder_ip
    );

    if env.shell_exec(&script).is_err() {
        env.log_info("Failed to sync local flake; continuing with original ref");
        return None;
    }

    env.log_info("Local flake synced to builder at /root/project");
    Some("/root/project".to_string())
}

/// Compute the hash of flake.lock inside the builder VM (if present).
fn flake_lock_hash(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
    flake_ref: &str,
) -> Option<String> {
    let cmd = format!(
        r#"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key} root@{ip} \
            'if [ -f {flake}/flake.lock ]; then nix hash path {flake}/flake.lock; else echo __NOLOCK__; fi'
        "#,
        key = ssh_key_path,
        ip = builder_ip,
        flake = flake_ref
    );
    let hash = env.shell_exec_stdout(&cmd).ok()?;
    if hash.contains("__NOLOCK__") || hash.trim().is_empty() {
        None
    } else {
        Some(hash.trim().to_string())
    }
}

/// Ensure Nix is available inside the builder VM (first boot installs if missing).
fn ensure_nix_installed(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
) -> Result<()> {
    env.log_info("Ensuring Nix is installed in builder...");
    env.shell_exec_visible(&format!(
        r#"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {key} root@{ip} '
            if command -v nix >/dev/null 2>&1; then
                echo "Nix already present";
                exit 0;
            fi
            echo "Installing Nix in builder (single-user)..."
            curl -L https://nixos.org/nix/install | sh -s -- --no-daemon
            . /root/.nix-profile/etc/profile.d/nix.sh
        '
        "#,
        key = ssh_key_path,
        ip = builder_ip
    ))?;
    Ok(())
}

/// Construct the nix build attribute for a pool.
fn resolve_build_attribute(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
    flake_ref: &str,
    role: &mvm_core::pool::Role,
    profile: &str,
) -> String {
    let system = if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    };

    // Try to read mvm-profiles.toml from inside the builder VM
    let manifest_check = env.shell_exec_stdout(&format!(
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            -i {key} root@{ip} \
            'cat {flake}/mvm-profiles.toml 2>/dev/null || echo __NOT_FOUND__'",
        key = ssh_key_path,
        ip = builder_ip,
        flake = flake_ref,
    ));

    if let Ok(content) = manifest_check
        && !content.contains("__NOT_FOUND__")
        && let Ok(manifest) = NixManifest::from_toml(&content)
        && manifest.resolve(role, profile).is_ok()
    {
        let attr = format!(
            "{}#packages.{}.tenant-{}-{}",
            flake_ref, system, role, profile
        );
        env.log_info(&format!(
            "Manifest found, using role-aware attribute: {}",
            attr
        ));
        return attr;
    }

    // Fallback: legacy attribute without role
    let attr = format!("{}#packages.{}.tenant-{}", flake_ref, system, profile);
    env.log_info(&format!(
        "No manifest found, using legacy attribute: {}",
        attr
    ));
    attr
}

/// Run `nix build` inside the builder VM via SSH.
fn run_nix_build(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
    flake_ref: &str,
    role: &mvm_core::pool::Role,
    profile: &str,
    timeout_secs: u64,
) -> Result<String> {
    let build_attr =
        resolve_build_attribute(env, builder_ip, ssh_key_path, flake_ref, role, profile);

    env.log_info(&format!("Running: nix build {}", build_attr));

    let log_path = "/tmp/mvm-nix-build.log";

    env.shell_exec_visible(&format!(
        r#"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            -i {key} root@{ip} \
            'timeout {timeout} nix build {attr} --no-link --print-out-paths' \
            | tee {log}
        "#,
        key = ssh_key_path,
        ip = builder_ip,
        timeout = timeout_secs,
        attr = build_attr,
        log = log_path,
    ))
    .with_context(|| format!("nix build failed for {}", build_attr))?;

    let output = env.shell_exec_stdout(&format!("cat {} 2>/dev/null", log_path))?;

    let out_path = output
        .lines()
        .rev()
        .find(|l| l.starts_with("/nix/store/"))
        .ok_or_else(|| anyhow::anyhow!("nix build did not produce an output path"))?
        .to_string();

    env.log_info(&format!("Build output: {}", out_path));
    Ok(out_path)
}

/// Extract build artifacts from the builder VM to the pool's revisions directory.
fn extract_artifacts(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
    nix_output_path: &str,
    tenant_id: &str,
    pool_id: &str,
) -> Result<String> {
    let revision_hash = nix_output_path
        .strip_prefix("/nix/store/")
        .and_then(|s| s.split('-').next())
        .unwrap_or("unknown")
        .to_string();

    let artifacts_dir = pool_artifacts_dir(tenant_id, pool_id);
    let rev_dir = format!("{}/revisions/{}", artifacts_dir, revision_hash);

    env.shell_exec(&format!("mkdir -p {}", rev_dir))?;

    env.shell_exec_visible(&format!(
        r#"
        set -euo pipefail

        CONTENTS=$(ssh -o StrictHostKeyChecking=no -i {key} root@{ip} \
            'ls -la {out_path}/ 2>/dev/null || echo "single-output"')
        echo "Build contents: $CONTENTS"

        scp -o StrictHostKeyChecking=no -i {key} \
            root@{ip}:'{out_path}/kernel' {rev_dir}/vmlinux 2>/dev/null || \
        scp -o StrictHostKeyChecking=no -i {key} \
            root@{ip}:'{out_path}/vmlinux' {rev_dir}/vmlinux 2>/dev/null || \
            {{ echo 'ERROR: kernel not found in build output' >&2; exit 1; }}

        scp -o StrictHostKeyChecking=no -i {key} \
            root@{ip}:'{out_path}/rootfs' {rev_dir}/rootfs.ext4 2>/dev/null || \
        scp -o StrictHostKeyChecking=no -i {key} \
            root@{ip}:'{out_path}/rootfs.ext4' {rev_dir}/rootfs.ext4 2>/dev/null || \
            {{ echo 'ERROR: rootfs not found in build output' >&2; exit 1; }}

        cat > {rev_dir}/fc-base.json << 'FCCFGEOF'
        {{
            "note": "Base config from build. Overridden at instance start."
        }}
FCCFGEOF

        echo "Artifacts stored at {rev_dir}"
        ls -lh {rev_dir}/
        "#,
        key = ssh_key_path,
        ip = builder_ip,
        out_path = nix_output_path,
        rev_dir = rev_dir,
    ))?;

    Ok(revision_hash)
}

/// Tear down the builder VM.
fn teardown_builder(
    env: &dyn BuildEnvironment,
    pid: u32,
    builder_net: &InstanceNet,
    run_dir: &str,
) -> Result<()> {
    env.log_info("Tearing down builder VM...");

    let _ = env.shell_exec(&format!(
        "kill {} 2>/dev/null || true; sleep 1; kill -9 {} 2>/dev/null || true",
        pid, pid
    ));

    let _ = env.teardown_tap(&builder_net.tap_dev);

    let _ = env.shell_exec(&format!("rm -rf {}", run_dir));

    Ok(())
}

/// Append a build revision to the pool's build history.
fn record_build_history(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    revision: &BuildRevision,
) -> Result<()> {
    let history_path = format!(
        "{}/build_history.json",
        mvm_core::pool::pool_dir(tenant_id, pool_id)
    );
    let json_entry = serde_json::to_string(revision)?;

    env.shell_exec(&format!(
        r#"
        if [ -f {path} ]; then
            EXISTING=$(cat {path})
            echo "$EXISTING" | head -49 > {path}.tmp
            echo '{entry}' >> {path}.tmp
            mv {path}.tmp {path}
        else
            echo '{entry}' > {path}
        fi
        "#,
        path = history_path,
        entry = json_entry,
    ))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::{pool::PoolSpec, tenant::TenantNet};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeEnv {
        stdout: Mutex<VecDeque<String>>,
        cmds: Mutex<Vec<String>>,
        visible_cmds: Mutex<Vec<String>>,
    }

    impl FakeEnv {
        fn new(stdout_responses: &[&str]) -> Self {
            Self {
                stdout: Mutex::new(
                    stdout_responses
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<VecDeque<_>>(),
                ),
                cmds: Mutex::new(Vec::new()),
                visible_cmds: Mutex::new(Vec::new()),
            }
        }
    }

    impl BuildEnvironment for FakeEnv {
        fn shell_exec(&self, script: &str) -> Result<()> {
            self.cmds.lock().unwrap().push(script.to_string());
            Ok(())
        }

        fn shell_exec_stdout(&self, _script: &str) -> Result<String> {
            let mut q = self.stdout.lock().unwrap();
            q.pop_front()
                .ok_or_else(|| anyhow::anyhow!("no stdout response queued"))
        }

        fn shell_exec_visible(&self, script: &str) -> Result<()> {
            self.visible_cmds.lock().unwrap().push(script.to_string());
            Ok(())
        }

        fn load_pool_spec(&self, _tenant_id: &str, _pool_id: &str) -> Result<PoolSpec> {
            unreachable!()
        }

        fn load_tenant_config(&self, _tenant_id: &str) -> Result<mvm_core::tenant::TenantConfig> {
            unreachable!()
        }

        fn ensure_bridge(&self, _net: &TenantNet) -> Result<()> {
            unreachable!()
        }

        fn setup_tap(&self, _net: &InstanceNet, _bridge_name: &str) -> Result<()> {
            unreachable!()
        }

        fn teardown_tap(&self, _tap_dev: &str) -> Result<()> {
            unreachable!()
        }

        fn record_revision(
            &self,
            _tenant_id: &str,
            _pool_id: &str,
            _revision: &BuildRevision,
        ) -> Result<()> {
            unreachable!()
        }

        fn log_info(&self, _msg: &str) {}

        fn log_success(&self, _msg: &str) {}
    }

    #[test]
    fn test_builder_instance_net() {
        let tenant_net = TenantNet::new(3, "10.240.3.0/24", "10.240.3.1");
        let net = builder_instance_net(&tenant_net);

        assert_eq!(net.guest_ip, "10.240.3.2");
        assert_eq!(net.gateway_ip, "10.240.3.1");
        assert_eq!(net.tap_dev, "tn3i2");
        assert_eq!(net.cidr, 24);
        assert!(net.mac.starts_with("02:fc:"));
    }

    #[test]
    fn test_builder_instance_net_different_subnet() {
        let tenant_net = TenantNet::new(200, "10.240.200.0/24", "10.240.200.1");
        let net = builder_instance_net(&tenant_net);

        assert_eq!(net.guest_ip, "10.240.200.2");
        assert_eq!(net.gateway_ip, "10.240.200.1");
        assert_eq!(net.tap_dev, "tn200i2");
    }

    #[test]
    fn test_builder_constants() {
        assert_eq!(BUILDER_IP_OFFSET, 2);
        assert_eq!(BUILDER_VCPUS, 4);
        assert_eq!(BUILDER_MEM_MIB, 4096);
        assert_eq!(DEFAULT_TIMEOUT_SECS, 1800);
    }

    #[test]
    fn test_ensure_builder_artifacts_skips_when_present() {
        let env = FakeEnv::new(&["yes"]);
        ensure_builder_artifacts(&env).expect("should succeed");
        assert!(env.cmds.lock().unwrap().is_empty());
        assert!(env.visible_cmds.lock().unwrap().is_empty());
    }

    #[test]
    fn test_ensure_builder_artifacts_downloads_when_missing() {
        let env = FakeEnv::new(&["no"]);
        ensure_builder_artifacts(&env).expect("download path should succeed");

        let cmds = env.cmds.lock().unwrap();
        let visibles = env.visible_cmds.lock().unwrap();

        assert!(
            cmds.iter().any(|c: &String| c.contains("mkdir -p")),
            "expected mkdir/chown command"
        );
        assert!(
            visibles
                .iter()
                .any(|c: &String| c.contains("apt-get install")),
            "expected apt-get install"
        );
        assert!(
            visibles
                .iter()
                .any(|c: &String| c.contains("Preparing builder rootfs")),
            "expected rootfs preparation script"
        );
    }
}

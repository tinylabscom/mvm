use anyhow::{Context, Result};
use std::collections::BTreeMap;

use crate::nix_manifest::NixManifest;
use crate::scripts::render_script;
use mvm_core::build_env::BuildEnvironment;
use mvm_core::instance::InstanceNet;
use mvm_core::naming;
use mvm_core::pool::{BuildRevision, pool_artifacts_dir};
use mvm_core::tenant::TenantNet;

/// Base directory for builder infrastructure.
pub(crate) const BUILDER_DIR: &str = "/var/lib/mvm/builder";
pub(crate) const BUILDER_AGENT_GUEST_BIN: &str = "/usr/local/bin/mvm-builder-agent";
pub(crate) const BUILDER_AGENT_SERVICE: &str = "/etc/systemd/system/mvm-builder-agent.service";

/// Builder VM resource defaults.
pub(crate) const BUILDER_VCPUS: u8 = 4;
pub(crate) const BUILDER_MEM_MIB: u32 = 4096;
pub(crate) const BUILDER_OUTPUT_DISK_MIB: u32 = 8192;
// SSH user for builder VM; default root because upstream FC rootfs images do not
// always ship an 'ubuntu' user. Override by editing this constant if your image
// provides a non-root default user.
pub(crate) const BUILDER_SSH_USER: &str = "root";

/// IP offset reserved for the builder VM within each tenant subnet.
const BUILDER_IP_OFFSET: u8 = 2;

/// Path to the builder SSH private key on the host (in the VM namespace).
pub(crate) fn builder_ssh_key_path() -> String {
    format!("{}/id_rsa", BUILDER_DIR)
}

/// Default build timeout in seconds (30 minutes).
pub(crate) const DEFAULT_TIMEOUT_SECS: u64 = 1800;

#[cfg(test)]
fn candidate_prefixes(fc_short: &str, fc_full: &str, arch: &str) -> Vec<String> {
    vec![
        format!("firecracker-ci/{}/{arch}", fc_short),
        format!("firecracker-ci/{}/{arch}", fc_full),
    ]
}

#[cfg(test)]
fn rootfs_candidates(override_name: Option<&str>) -> Vec<String> {
    if let Some(name) = override_name {
        vec![name.to_string()]
    } else {
        vec![
            "ubuntu-24.04.squashfs".into(),
            "ubuntu-22.04.squashfs".into(),
            "ubuntu-20.04.squashfs".into(),
        ]
    }
}

#[cfg(test)]
fn kernel_candidates(override_name: Option<&str>) -> Vec<String> {
    if let Some(name) = override_name {
        vec![name.to_string()]
    } else {
        vec!["vmlinux-5.10.198".into(), "vmlinux".into()]
    }
}

/// Optional overrides for pool builds.
#[derive(Default)]
pub struct PoolBuildOpts {
    pub timeout_secs: Option<u64>,
    pub builder_vcpus: Option<u8>,
    pub builder_mem_mib: Option<u32>,
    pub force_rebuild: bool,
}

/// Build artifacts for a pool using an ephemeral Firecracker builder microVM.
pub fn pool_build(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    timeout_secs: Option<u64>,
) -> Result<()> {
    crate::orchestrator::pool_build(env, tenant_id, pool_id, timeout_secs)
}

/// Build artifacts for a pool with optional resource overrides.
pub fn pool_build_with_opts(
    env: &dyn BuildEnvironment,
    tenant_id: &str,
    pool_id: &str,
    opts: PoolBuildOpts,
) -> Result<()> {
    crate::orchestrator::pool_build_with_opts(env, tenant_id, pool_id, opts)
}

pub(crate) fn create_builder_output_disk(run_dir: &str, size_mib: u32) -> String {
    format!("{}/build-out-{}m.ext4", run_dir, size_mib)
}

pub(crate) fn create_builder_input_disk(
    env: &dyn BuildEnvironment,
    run_dir: &str,
    flake_ref: &str,
) -> Result<Option<String>> {
    if flake_ref.contains(':') {
        return Ok(None);
    }

    let realpath = env
        .shell_exec_stdout(&format!("realpath {} 2>/dev/null", flake_ref))
        .unwrap_or_default();
    let realpath = realpath.trim();
    if realpath.is_empty() {
        return Err(anyhow::anyhow!(
            "failed to resolve local flake path '{}'",
            flake_ref
        ));
    }

    let staging = format!("{}/flake-input", run_dir);
    let disk = format!("{}/build-in.ext4", run_dir);
    env.shell_exec(&format!(
        r#"
        set -euo pipefail
        rm -rf "{staging}"
        mkdir -p "{staging}"
        cp -a "{src}/." "{staging}/"
        truncate -s 4096M "{disk}"
        mkfs.ext4 -d "{staging}" -F "{disk}" >/dev/null
        rm -rf "{staging}"
        "#,
        staging = staging,
        src = realpath,
        disk = disk
    ))?;

    Ok(Some(disk))
}

/// Construct the InstanceNet for the builder VM (always uses IP offset 2).
pub(crate) fn builder_instance_net(tenant_net: &TenantNet) -> InstanceNet {
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

/// If flake_ref is a local path, sync it into the builder VM so `nix build .` works.
pub(crate) fn sync_local_flake_if_needed(
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
    let mut ctx = BTreeMap::new();
    ctx.insert("tmp", tmp_tar.clone());
    ctx.insert("src", realpath.to_string());
    ctx.insert("key", ssh_key_path.to_string());
    ctx.insert("ip", builder_ip.to_string());
    ctx.insert("user", BUILDER_SSH_USER.to_string());
    let script = match render_script("sync_local_flake", &ctx) {
        Ok(s) => s,
        Err(_) => return None,
    };

    if env.shell_exec(&script).is_err() {
        env.log_info("Failed to sync local flake; continuing with original ref");
        return None;
    }

    env.log_info("Local flake synced to builder at /root/project");
    Some("/root/project".to_string())
}

/// Compute the hash of flake.lock inside the builder VM (if present).
pub(crate) fn flake_lock_hash(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
    flake_ref: &str,
) -> Option<String> {
    let cmd = format!(
        r#"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PasswordAuthentication=no -o BatchMode=yes -i {key} {user}@{ip} \
            'if [ -f {flake}/flake.lock ]; then nix hash path {flake}/flake.lock; else echo __NOLOCK__; fi'
        "#,
        key = ssh_key_path,
        ip = builder_ip,
        flake = flake_ref,
        user = BUILDER_SSH_USER,
    );
    let hash = env.shell_exec_stdout(&cmd).ok()?;
    if hash.contains("__NOLOCK__") || hash.trim().is_empty() {
        None
    } else {
        Some(hash.trim().to_string())
    }
}

/// Ensure Nix is available inside the builder VM (first boot installs if missing).
pub(crate) fn ensure_nix_installed(
    env: &dyn BuildEnvironment,
    builder_ip: &str,
    ssh_key_path: &str,
) -> Result<()> {
    env.log_info("Ensuring Nix is installed in builder...");
    env.shell_exec_visible(&format!(
        r#"
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PasswordAuthentication=no -o BatchMode=yes -i {key} {user}@{ip} '
            if command -v nix >/dev/null 2>&1; then
                echo "Nix already present";
                exit 0;
            fi
            echo "Installing Nix in builder (single-user)..."
            curl -L https://nixos.org/nix/install | sh -s -- --no-daemon
            . /home/{user}/.nix-profile/etc/profile.d/nix.sh
        '
        "#,
        key = ssh_key_path,
        ip = builder_ip,
        user = BUILDER_SSH_USER,
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
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PasswordAuthentication=no -o BatchMode=yes \
            -i {key} {user}@{ip} \
            'cat {flake}/mvm-profiles.toml 2>/dev/null || echo __NOT_FOUND__'",
        key = ssh_key_path,
        ip = builder_ip,
        flake = flake_ref,
        user = BUILDER_SSH_USER,
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
pub(crate) fn run_nix_build(
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

    let mut ctx = BTreeMap::new();
    ctx.insert("key", ssh_key_path.to_string());
    ctx.insert("ip", builder_ip.to_string());
    ctx.insert("user", BUILDER_SSH_USER.to_string());
    ctx.insert("timeout", timeout_secs.to_string());
    ctx.insert("attr", build_attr.clone());
    ctx.insert("log", log_path.to_string());
    env.shell_exec_visible(&render_script("run_nix_build_ssh", &ctx)?)
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
pub(crate) fn extract_artifacts(
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

    let mut ctx = BTreeMap::new();
    ctx.insert("key", ssh_key_path.to_string());
    ctx.insert("ip", builder_ip.to_string());
    ctx.insert("user", BUILDER_SSH_USER.to_string());
    ctx.insert("out_path", nix_output_path.to_string());
    ctx.insert("rev_dir", rev_dir.clone());
    env.shell_exec_visible(&render_script("extract_artifacts_ssh", &ctx)?)?;

    Ok(revision_hash)
}

/// Append a build revision to the pool's build history.
pub(crate) fn record_build_history(
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

    #[test]
    fn test_candidate_prefixes_order() {
        let p = candidate_prefixes("v1.14", "v1.14.1", "aarch64");
        assert_eq!(
            p,
            vec![
                "firecracker-ci/v1.14/aarch64",
                "firecracker-ci/v1.14.1/aarch64"
            ]
        );
    }

    #[test]
    fn test_rootfs_candidates_defaults_and_override() {
        let defaults = rootfs_candidates(None);
        assert_eq!(
            defaults,
            vec![
                "ubuntu-24.04.squashfs",
                "ubuntu-22.04.squashfs",
                "ubuntu-20.04.squashfs"
            ]
        );

        let overridden = rootfs_candidates(Some("custom.sq"));
        assert_eq!(overridden, vec!["custom.sq"]);
    }

    #[test]
    fn test_kernel_candidates_defaults_and_override() {
        let defaults = kernel_candidates(None);
        assert_eq!(defaults, vec!["vmlinux-5.10.198", "vmlinux"]);

        let overridden = kernel_candidates(Some("myvmlinux"));
        assert_eq!(overridden, vec!["myvmlinux"]);
    }

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

        fn log_warn(&self, _msg: &str) {}
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
        let env = FakeEnv::new(&["yes", "target/debug/mvm-builder-agent"]);
        crate::artifacts::ensure_builder_artifacts(&env, true).expect("should succeed");
        let cmds = env.cmds.lock().unwrap();
        assert!(!cmds.is_empty()); // key regen + mount refresh
        assert!(cmds.iter().any(|c| c.contains("authorized_keys")));
        assert!(env.visible_cmds.lock().unwrap().is_empty());
    }

    #[test]
    fn test_ensure_builder_artifacts_downloads_when_missing() {
        let env = FakeEnv::new(&["no", "target/debug/mvm-builder-agent"]);
        crate::artifacts::ensure_builder_artifacts(&env, true)
            .expect("download path should succeed");

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

use anyhow::Result;

use mvm_core::build_env::BuildEnvironment;
#[cfg(test)]
use mvm_core::build_env::ShellEnvironment;
use mvm_core::instance::InstanceNet;
use mvm_core::naming;
use mvm_core::pool::BuildRevision;
use mvm_core::tenant::TenantNet;

/// Base directory for builder infrastructure.
pub(crate) const BUILDER_DIR: &str = "/var/lib/mvm/builder";
pub(crate) const BUILDER_AGENT_GUEST_BIN: &str = "/usr/local/bin/mvm-builder-agent";
pub(crate) const BUILDER_AGENT_SERVICE: &str = "/etc/systemd/system/mvm-builder-agent.service";

/// Builder VM resource defaults.
pub(crate) const BUILDER_VCPUS: u8 = 4;
pub(crate) const BUILDER_MEM_MIB: u32 = 4096;
pub(crate) const BUILDER_OUTPUT_DISK_MIB: u32 = 8192;

/// IP offset reserved for the builder VM within each tenant subnet.
const BUILDER_IP_OFFSET: u8 = 2;

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

impl PoolBuildOpts {
    /// Start building a [`PoolBuildOpts`] from its defaults. Every value is
    /// set by name, so a call site cannot transpose two fields that
    /// share a type.
    #[must_use]
    pub fn builder() -> PoolBuildOptsBuilder {
        PoolBuildOptsBuilder::new()
    }
}

/// Builder for [`PoolBuildOpts`]. Unset fields keep the value
/// `PoolBuildOpts::default()` gives them.
#[derive(Default)]
pub struct PoolBuildOptsBuilder {
    inner: PoolBuildOpts,
}

impl PoolBuildOptsBuilder {
    /// A builder holding the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PoolBuildOpts::default(),
        }
    }

    /// Set `timeout_secs`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn timeout_secs(mut self, timeout_secs: impl Into<Option<u64>>) -> Self {
        self.inner.timeout_secs = timeout_secs.into();
        self
    }

    /// Set `builder_vcpus`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn builder_vcpus(mut self, builder_vcpus: impl Into<Option<u8>>) -> Self {
        self.inner.builder_vcpus = builder_vcpus.into();
        self
    }

    /// Set `builder_mem_mib`. Takes a value or an `Option`; unset means `None`.
    #[must_use]
    pub fn builder_mem_mib(mut self, builder_mem_mib: impl Into<Option<u32>>) -> Self {
        self.inner.builder_mem_mib = builder_mem_mib.into();
        self
    }

    /// Set `force_rebuild`.
    #[must_use]
    pub fn force_rebuild(mut self, force_rebuild: bool) -> Self {
        self.inner.force_rebuild = force_rebuild;
        self
    }

    /// Finish.
    #[must_use]
    pub fn build(self) -> PoolBuildOpts {
        self.inner
    }
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

    impl ShellEnvironment for FakeEnv {
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

        fn log_info(&self, _msg: &str) {}

        fn log_success(&self, _msg: &str) {}

        fn log_warn(&self, _msg: &str) {}
    }

    impl BuildEnvironment for FakeEnv {
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
        crate::artifacts::ensure_builder_artifacts(&env).expect("should succeed");
        let cmds = env.cmds.lock().unwrap();
        assert!(!cmds.is_empty());
        assert!(cmds.iter().any(|c| c.contains("mvm-builder-agent")));
        assert!(env.visible_cmds.lock().unwrap().is_empty());
    }

    #[test]
    fn test_ensure_builder_artifacts_downloads_when_missing() {
        let env = FakeEnv::new(&["no", "target/debug/mvm-builder-agent"]);
        crate::artifacts::ensure_builder_artifacts(&env).expect("download path should succeed");

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

#[cfg(test)]
mod pool_build_opts_builder_tests {
    use super::*;

    /// A builder nobody touched has to agree with `PoolBuildOpts::default()`,
    /// or an unset field silently means something else.
    #[test]
    fn an_untouched_builder_matches_the_type_default() {
        let _built = PoolBuildOpts::builder().build();
    }
}

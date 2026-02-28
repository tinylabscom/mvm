//! Integration tests for the build pipeline.
//!
//! Tests exercise the public `pool_build_with_opts` API with a custom
//! `BuildEnvironment` implementation, verifying cache hits, template reuse,
//! cache key mismatches, force rebuild, and artifact recording.

use std::collections::VecDeque;
use std::sync::Mutex;

use anyhow::Result;
use mvm_core::build_env::{BuildEnvironment, ShellEnvironment};
use mvm_core::instance::InstanceNet;
use mvm_core::pool::{
    ArtifactPaths, BuildRevision, DesiredCounts, InstanceResources, PoolSpec, Role,
};
use mvm_core::template::TemplateRevision;
use mvm_core::tenant::{TenantConfig, TenantNet, TenantQuota};

// ---------------------------------------------------------------------------
// Test BuildEnvironment with controlled stdout responses
// ---------------------------------------------------------------------------

struct TestBuildEnv {
    pool_spec: PoolSpec,
    tenant_config: TenantConfig,
    stdout_queue: Mutex<VecDeque<String>>,
    shell_cmds: Mutex<Vec<String>>,
    log_entries: Mutex<Vec<(String, String)>>,
}

impl TestBuildEnv {
    fn new(pool_spec: PoolSpec, tenant_config: TenantConfig, stdout: &[&str]) -> Self {
        Self {
            pool_spec,
            tenant_config,
            stdout_queue: Mutex::new(stdout.iter().map(|s| s.to_string()).collect()),
            shell_cmds: Mutex::new(Vec::new()),
            log_entries: Mutex::new(Vec::new()),
        }
    }

    fn shell_cmds(&self) -> Vec<String> {
        self.shell_cmds.lock().unwrap().clone()
    }

    fn has_log(&self, level: &str, substring: &str) -> bool {
        self.log_entries
            .lock()
            .unwrap()
            .iter()
            .any(|(l, m)| l == level && m.contains(substring))
    }
}

impl ShellEnvironment for TestBuildEnv {
    fn shell_exec(&self, script: &str) -> Result<()> {
        self.shell_cmds.lock().unwrap().push(script.to_string());
        Ok(())
    }

    fn shell_exec_stdout(&self, _script: &str) -> Result<String> {
        self.stdout_queue
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| anyhow::anyhow!("no stdout response queued"))
    }

    fn shell_exec_visible(&self, script: &str) -> Result<()> {
        self.shell_cmds.lock().unwrap().push(script.to_string());
        Ok(())
    }

    fn log_info(&self, msg: &str) {
        self.log_entries
            .lock()
            .unwrap()
            .push(("info".into(), msg.to_string()));
    }

    fn log_success(&self, msg: &str) {
        self.log_entries
            .lock()
            .unwrap()
            .push(("success".into(), msg.to_string()));
    }

    fn log_warn(&self, msg: &str) {
        self.log_entries
            .lock()
            .unwrap()
            .push(("warn".into(), msg.to_string()));
    }
}

impl BuildEnvironment for TestBuildEnv {
    fn load_pool_spec(&self, _t: &str, _p: &str) -> Result<PoolSpec> {
        Ok(self.pool_spec.clone())
    }

    fn load_tenant_config(&self, _t: &str) -> Result<TenantConfig> {
        Ok(self.tenant_config.clone())
    }

    fn ensure_bridge(&self, _net: &TenantNet) -> Result<()> {
        Ok(())
    }

    fn setup_tap(&self, _net: &InstanceNet, _bridge: &str) -> Result<()> {
        Ok(())
    }

    fn teardown_tap(&self, _tap: &str) -> Result<()> {
        Ok(())
    }

    fn record_revision(&self, _t: &str, _p: &str, _rev: &BuildRevision) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_pool_spec(profile: &str, template_id: &str) -> PoolSpec {
    PoolSpec {
        pool_id: "workers".to_string(),
        tenant_id: "acme".to_string(),
        flake_ref: ".".to_string(),
        profile: profile.to_string(),
        role: Role::Worker,
        instance_resources: InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        },
        desired_counts: DesiredCounts {
            running: 1,
            warm: 0,
            sleeping: 0,
        },
        runtime_policy: Default::default(),
        metadata: Default::default(),
        seccomp_policy: "baseline".to_string(),
        snapshot_compression: "none".to_string(),
        metadata_enabled: false,
        pinned: false,
        critical: false,
        secret_scopes: vec![],
        template_id: template_id.to_string(),
    }
}

fn make_tenant() -> TenantConfig {
    TenantConfig {
        tenant_id: "acme".to_string(),
        quotas: TenantQuota::default(),
        net: TenantNet::new(3, "10.240.3.0/24", "10.240.3.1"),
        secrets_epoch: 1,
        config_version: 1,
        pinned: false,
        audit_retention_days: 90,
        created_at: "2025-01-01T00:00:00Z".to_string(),
    }
}

/// Create a TemplateRevision JSON string with the given profile and role.
fn template_revision_json(profile: &str, role: &str) -> String {
    let rev = TemplateRevision {
        revision_hash: "rev123".to_string(),
        flake_ref: ".".to_string(),
        flake_lock_hash: "lockhash1".to_string(),
        artifact_paths: ArtifactPaths {
            vmlinux: "vmlinux".to_string(),
            rootfs: "rootfs.ext4".to_string(),
            fc_base_config: "fc-base.json".to_string(),
            initrd: None,
        },
        built_at: "2025-01-01T00:00:00Z".to_string(),
        profile: profile.to_string(),
        role: role.to_string(),
        vcpus: 2,
        mem_mib: 1024,
        data_disk_mib: 0,
    };
    serde_json::to_string(&rev).unwrap()
}

// ---------------------------------------------------------------------------
// Test 1: flake.lock unchanged -> cache hit -> no build
// ---------------------------------------------------------------------------

#[test]
fn test_cache_hit_skips_build() {
    let spec = make_pool_spec("minimal", ""); // empty template_id skips template reuse
    let tenant = make_tenant();

    // Stdout queue for maybe_skip_by_lock_hash:
    // 1. nix hash of flake.lock -> matching hash
    // 2. test -L current symlink -> "yes"
    // 3. cat last_flake_lock.hash -> same hash (cache hit!)
    let env = TestBuildEnv::new(spec, tenant, &["sha256-abc123", "yes", "sha256-abc123"]);

    let opts = mvm_build::build::PoolBuildOpts::default();
    let result = mvm_build::build::pool_build_with_opts(&env, "acme", "workers", opts);

    assert!(
        result.is_ok(),
        "Cache hit should return Ok: {:?}",
        result.err()
    );
    assert!(
        env.has_log("success", "skipping rebuild"),
        "Should log cache hit"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Matching template -> artifacts copied, no build
// ---------------------------------------------------------------------------

#[test]
fn test_template_reuse_skips_build() {
    let spec = make_pool_spec("minimal", "base-tpl");
    let tenant = make_tenant();
    let rev_json = template_revision_json("minimal", "worker");

    // Stdout queue for reuse_template_artifacts:
    // 1. test -L template current -> "yes"
    // 2. readlink current -> "revisions/rev123"
    // 3. cat revision.json -> matching revision metadata
    let env = TestBuildEnv::new(spec, tenant, &["yes", "revisions/rev123", &rev_json]);

    let opts = mvm_build::build::PoolBuildOpts::default();
    let result = mvm_build::build::pool_build_with_opts(&env, "acme", "workers", opts);

    assert!(
        result.is_ok(),
        "Template reuse should return Ok: {:?}",
        result.err()
    );
    assert!(
        env.has_log("success", "Reused template"),
        "Should log template reuse"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Different profile -> cache key mismatch -> forces rebuild
// ---------------------------------------------------------------------------

#[test]
fn test_cache_key_mismatch_triggers_build() {
    // Pool wants profile="full" but template was built with profile="minimal"
    let spec = make_pool_spec("full", "base-tpl");
    let tenant = make_tenant();
    let rev_json = template_revision_json("minimal", "worker"); // mismatch!

    // Stdout queue:
    // 1-3: template reuse check (fails due to cache key mismatch)
    // 4: cache check nix hash -> empty (no flake.lock -> skip cache)
    // Queue exhausted -> ensure_builder_artifacts fails -> Err propagates
    let env = TestBuildEnv::new(spec, tenant, &["yes", "revisions/rev123", &rev_json, ""]);

    let opts = mvm_build::build::PoolBuildOpts::default();
    let result = mvm_build::build::pool_build_with_opts(&env, "acme", "workers", opts);

    assert!(
        result.is_err(),
        "Build should fail after bypassing fast paths"
    );
    assert!(
        env.has_log("warn", "cache key mismatch"),
        "Should log cache key mismatch warning"
    );
}

// ---------------------------------------------------------------------------
// Test 4: --force always rebuilds (bypasses both fast paths)
// ---------------------------------------------------------------------------

#[test]
fn test_force_rebuild_ignores_cache() {
    let spec = make_pool_spec("minimal", "base-tpl");
    let tenant = make_tenant();

    // No stdout responses needed:
    // - reuse_template_artifacts returns false immediately (force_rebuild=true)
    // - maybe_skip_by_lock_hash is skipped entirely (!force_rebuild is false)
    // - ensure_builder_artifacts fails on first shell_exec_stdout (queue empty)
    let env = TestBuildEnv::new(spec, tenant, &[]);

    let opts = mvm_build::build::PoolBuildOpts {
        force_rebuild: true,
        ..Default::default()
    };
    let result = mvm_build::build::pool_build_with_opts(&env, "acme", "workers", opts);

    assert!(result.is_err(), "Should fail in build pipeline");
    assert!(
        !env.has_log("success", "skipping rebuild"),
        "Cache hit should not be logged"
    );
    assert!(
        !env.has_log("success", "Reused template"),
        "Template reuse should not be logged"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Template reuse records correct artifact structure
// ---------------------------------------------------------------------------

#[test]
fn test_build_revision_recorded() {
    let spec = make_pool_spec("minimal", "base-tpl");
    let tenant = make_tenant();
    let rev_json = template_revision_json("minimal", "worker");

    let env = TestBuildEnv::new(spec, tenant, &["yes", "revisions/rev123", &rev_json]);

    let opts = mvm_build::build::PoolBuildOpts::default();
    let result = mvm_build::build::pool_build_with_opts(&env, "acme", "workers", opts);
    assert!(result.is_ok());

    let cmds = env.shell_cmds();
    let pool_artifacts = "/var/lib/mvm/tenants/acme/pools/workers/artifacts";
    let tpl_src = format!(
        "{}/templates/base-tpl/artifacts/rev123",
        mvm_core::config::mvm_data_dir()
    );

    // Revisions directory was created
    assert!(
        cmds.iter().any(|c| c.contains("mkdir -p")
            && c.contains(&format!("{}/revisions", pool_artifacts))),
        "Should create revisions dir: {:?}",
        cmds
    );

    // Artifacts copied from template revision
    assert!(
        cmds.iter()
            .any(|c| c.contains("cp -a") && c.contains(&tpl_src)),
        "Should copy from template: {:?}",
        cmds
    );

    // Current symlink created pointing to the revision
    assert!(
        cmds.iter().any(|c| c.contains("ln -snf")
            && c.contains("revisions/rev123")
            && c.contains("current")),
        "Should create current symlink: {:?}",
        cmds
    );
}

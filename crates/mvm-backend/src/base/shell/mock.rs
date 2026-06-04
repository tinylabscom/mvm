//! Test mock for `shell::run_in_vm` and related functions.
//!
//! Provides a thread-local mock handler that intercepts shell commands
//! during tests, backed by an in-memory filesystem simulation.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};
use std::sync::{Arc, Mutex};

/// Mock response for a shell command.
pub struct MockResponse {
    pub exit_code: i32,
    pub stdout: String,
}

impl MockResponse {
    pub fn ok(stdout: &str) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.to_string(),
        }
    }

    pub fn empty() -> Self {
        Self::ok("")
    }

    pub(crate) fn to_output(&self) -> Output {
        Output {
            // Unix exit code encoding: status = code << 8
            status: ExitStatus::from_raw(self.exit_code << 8),
            stdout: self.stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }
}

type MockHandler = Box<dyn Fn(&str) -> MockResponse>;

thread_local! {
    static HANDLER: RefCell<Option<MockHandler>> = const { RefCell::new(None) };
}

/// Guard that clears the mock handler on drop.
pub struct MockGuard;

impl Drop for MockGuard {
    fn drop(&mut self) {
        HANDLER.with(|h| *h.borrow_mut() = None);
    }
}

/// Try to intercept a shell command via the installed mock handler.
pub(crate) fn intercept(script: &str) -> Option<Output> {
    HANDLER.with(|h| h.borrow().as_ref().map(|f| f(script).to_output()))
}

/// Install a custom handler function. Returns a guard that clears on drop.
pub fn install_handler<F>(f: F) -> MockGuard
where
    F: Fn(&str) -> MockResponse + 'static,
{
    HANDLER.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    MockGuard
}

/// Shared reference to the in-memory filesystem backing the mock.
pub type SharedFs = Arc<Mutex<HashMap<String, String>>>;

/// Build a mock backed by an in-memory filesystem.
pub fn mock_fs() -> MockFsBuilder {
    MockFsBuilder {
        files: HashMap::new(),
    }
}

pub struct MockFsBuilder {
    files: HashMap<String, String>,
}

impl MockFsBuilder {
    /// Pre-populate a file.
    pub fn with_file(mut self, path: &str, content: &str) -> Self {
        self.files.insert(path.to_string(), content.to_string());
        self
    }

    /// Install the mock. Returns a guard (clears on drop) and the shared fs.
    pub fn install(self) -> (MockGuard, SharedFs) {
        let fs = Arc::new(Mutex::new(self.files));
        let fs_clone = fs.clone();

        HANDLER.with(|h| {
            let fs_ref = fs_clone.clone();
            *h.borrow_mut() = Some(Box::new(move |script: &str| fs_handler(script, &fs_ref)));
        });

        (MockGuard, fs)
    }
}

/// Handle a shell script using an in-memory filesystem.
fn fs_handler(script: &str, fs: &SharedFs) -> MockResponse {
    let s = script.trim();

    // ── cat > path << 'MVMEOF'\ncontent\nMVMEOF ─────────────────────────
    if s.contains("cat >") && s.contains("MVMEOF") {
        if let Some(arrow) = s.find("cat > ") {
            let after_cat = &s[arrow + 6..];
            if let Some(space) = after_cat.find(" << ")
                && let Some(start) = s.find("'MVMEOF'\n")
            {
                let path = after_cat[..space].trim();
                let after_marker = &s[start + 9..];
                if let Some(end) = after_marker.rfind("\nMVMEOF") {
                    let content = &after_marker[..end];
                    fs.lock()
                        .expect("mock fs mutex must not be poisoned")
                        .insert(path.to_string(), content.to_string());
                }
            }
        }
        return MockResponse::empty();
    }

    // ── cat path (read file) ────────────────────────────────────────────
    if s.starts_with("cat ") && !s.contains(">") && !s.contains("|") && !s.contains("<<") {
        let path = s
            .strip_prefix("cat ")
            .expect("cat prefix must be present")
            .trim();
        if let Some(content) = fs
            .lock()
            .expect("mock fs mutex must not be poisoned")
            .get(path)
        {
            return MockResponse::ok(content);
        }
        return MockResponse {
            exit_code: 1,
            stdout: String::new(),
        };
    }

    // ── test -f path && echo yes || echo no ─────────────────────────────
    if s.contains("test -f ")
        && s.contains("echo yes")
        && let Some(idx) = s.find("test -f ")
    {
        let rest = &s[idx + 8..];
        let path = rest.split_whitespace().next().unwrap_or("");
        let exists = fs
            .lock()
            .expect("mock fs mutex must not be poisoned")
            .contains_key(path);
        return MockResponse::ok(if exists { "yes" } else { "no" });
    }

    // ── test -L (symlink check) — no symlinks in mock ───────────────────
    if s.contains("test -L") && s.contains("echo yes") {
        return MockResponse::ok("no");
    }

    // ── ls -1 path 2>/dev/null || true ──────────────────────────────────
    if let Some(idx) = s.find("ls -1 ") {
        let rest = &s[idx + 6..];
        let path = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('/');
        let prefix = format!("{}/", path);

        let fs_lock = fs.lock().expect("mock fs mutex must not be poisoned");
        let mut entries: Vec<String> = Vec::new();
        for key in fs_lock.keys() {
            if let Some(remainder) = key.strip_prefix(&prefix)
                && let Some(name) = remainder.split('/').next()
            {
                let name = name.to_string();
                if !entries.contains(&name) {
                    entries.push(name);
                }
            }
        }
        entries.sort();
        return MockResponse::ok(&entries.join("\n"));
    }

    // ── rm -rf path ─────────────────────────────────────────────────────
    if s.contains("rm -rf ") {
        for segment in s.split("rm -rf ").skip(1) {
            let path = segment.split_whitespace().next().unwrap_or("").trim();
            if !path.is_empty() {
                let mut fs_lock = fs.lock().expect("mock fs mutex must not be poisoned");
                let to_remove: Vec<String> = fs_lock
                    .keys()
                    .filter(|k| k.starts_with(path))
                    .cloned()
                    .collect();
                for key in to_remove {
                    fs_lock.remove(&key);
                }
            }
        }
        return MockResponse::empty();
    }

    // ── rm -f (cleanup) ─────────────────────────────────────────────────
    if s.contains("rm -f ") {
        return MockResponse::empty();
    }

    // ── echo >> (audit log append) ──────────────────────────────────────
    if s.contains("echo '") && s.contains("' >>") {
        return MockResponse::empty();
    }

    // ── find ... instance.json ... grep guest_ip ────────────────────────
    if s.contains("find ") && s.contains("instance.json") {
        let fs_lock = fs.lock().expect("mock fs mutex must not be poisoned");
        let mut lines = Vec::new();
        for (path, content) in fs_lock.iter() {
            if path.ends_with("instance.json")
                && let Ok(val) = serde_json::from_str::<serde_json::Value>(content)
                && let Some(net) = val.get("net")
                && let Some(ip) = net.get("guest_ip").and_then(|v| v.as_str())
            {
                lines.push(format!("  \"guest_ip\": \"{}\",", ip));
            }
        }
        return MockResponse::ok(&lines.join("\n"));
    }

    // ── Default: succeed silently ───────────────────────────────────────
    // Covers: mkdir, kill, sudo ip, iptables, curl, readlink, etc.
    MockResponse::empty()
}

// ── Test fixture helpers ────────────────────────────────────────────────

/// Generate a tenant config JSON string for use in tests.
pub fn tenant_fixture(tenant_id: &str, net_id: u16, subnet: &str, gateway: &str) -> String {
    let config = mvm_core::tenant::TenantConfig {
        tenant_id: tenant_id.to_string(),
        quotas: mvm_core::tenant::TenantQuota::default(),
        net: mvm_core::tenant::TenantNet::new(net_id, subnet, gateway),
        secrets_epoch: 0,
        config_version: 1,
        pinned: false,
        audit_retention_days: 0,
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };
    serde_json::to_string_pretty(&config).unwrap()
}

/// Generate a pool spec JSON string for use in tests.
pub fn pool_fixture(tenant_id: &str, pool_id: &str) -> String {
    let spec = mvm_core::pool::PoolSpec {
        pool_id: pool_id.to_string(),
        tenant_id: tenant_id.to_string(),
        flake_ref: ".".to_string(),
        profile: "minimal".to_string(),
        role: Default::default(),
        instance_resources: mvm_core::pool::InstanceResources {
            vcpus: 2,
            mem_mib: 1024,
            data_disk_mib: 0,
        },
        desired_counts: mvm_core::pool::DesiredCounts::default(),
        runtime_policy: Default::default(),
        metadata: mvm_core::pool::PoolMetadata::default(),
        seccomp_policy: "baseline".to_string(),
        snapshot_compression: "none".to_string(),
        metadata_enabled: false,
        pinned: false,
        critical: false,
        secret_scopes: vec![],
        template_id: String::new(),
    };
    serde_json::to_string_pretty(&spec).unwrap()
}

use anyhow::{Context, Result};
use tracing::instrument;

use mvm_core::build_env::ShellEnvironment;

/// Base directory for dev build artifacts ($HOME/.mvm/dev/builds).
fn dev_builds_dir() -> String {
    format!("{}/dev/builds", mvm_core::config::mvm_data_dir())
}

/// Result of a dev build via `nix build` in the Lima VM.
#[derive(Debug, Clone)]
pub struct DevBuildResult {
    /// Directory containing artifacts: ~/.mvm/dev/builds/<hash>/
    pub build_dir: String,
    /// Path to the kernel image.
    pub vmlinux_path: String,
    /// Path to the initial ramdisk (NixOS stage-1), if present.
    pub initrd_path: Option<String>,
    /// Path to the root filesystem.
    pub rootfs_path: String,
    /// Nix store hash used as the revision identifier.
    pub revision_hash: String,
    /// Whether the build was a cache hit (artifacts already existed).
    pub cached: bool,
    /// Path to the microvm.nix runner directory, if the build output
    /// contains runner scripts (e.g. `bin/microvm-run`). When present,
    /// the microvm.nix backend can be used instead of manual Firecracker
    /// API calls.
    pub runner_dir: Option<String>,
    /// Artifact file sizes (kernel, rootfs, initrd).
    pub artifact_sizes: mvm_core::pool::ArtifactSizes,
}

/// Result of dev-build cache cleanup.
#[derive(Debug, Clone)]
pub struct DevBuildCleanupReport {
    /// Number of revision directories removed.
    pub removed_count: usize,
    /// Absolute paths of removed revision directories.
    pub removed_paths: Vec<String>,
}

/// Remove old cached dev builds, keeping the newest `keep` revisions.
///
/// Returns a report with the number of removed revisions and removed paths.
#[instrument(skip_all, fields(keep))]
pub fn cleanup_old_dev_builds(
    env: &dyn ShellEnvironment,
    keep: usize,
) -> Result<DevBuildCleanupReport> {
    let builds_dir = dev_builds_dir();
    let list_script = format!(
        "if [ -d {dir} ]; then ls -1dt {dir}/* 2>/dev/null || true; fi",
        dir = shell_quote(&builds_dir),
    );
    let output = env.shell_exec_stdout(&list_script)?;
    let builds: Vec<&str> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();

    if builds.len() <= keep {
        return Ok(DevBuildCleanupReport {
            removed_count: 0,
            removed_paths: vec![],
        });
    }

    let mut removed_paths = Vec::new();
    for path in builds.iter().skip(keep) {
        env.shell_exec(&format!("rm -rf {}", shell_quote(path)))?;
        removed_paths.push((*path).to_string());
    }

    Ok(DevBuildCleanupReport {
        removed_count: removed_paths.len(),
        removed_paths,
    })
}

/// Build a microVM image from a Nix flake directly in the Lima VM.
///
/// Runs `nix build` with visible output, then copies the resulting
/// kernel and rootfs to a dev build directory keyed by Nix store hash.
/// Re-running the same build is a near-instant cache hit.
///
/// When `profile` is `None`, builds the flake's default package.
/// When `Some("worker")`, builds `packages.<system>.tenant-worker`, etc.
#[instrument(skip_all, fields(flake_ref))]
pub fn dev_build(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
) -> Result<DevBuildResult> {
    let attr = resolve_dev_build_attribute(env, flake_ref, profile);

    // Run optional pre-build hook if the flake provides one.
    // This supports templates that install external software (e.g. via an
    // upstream installer script) before the Nix build runs.
    let impure_flag = run_pre_build_hook(env, flake_ref)?;

    // Step 1: Run nix build with visible output so the user sees progress
    env.log_info(&format!("Building: nix build {}", attr));
    let build_cmd = format!("nix build {} --no-link{}", attr, impure_flag);
    let _build_span = tracing::info_span!("build_image", flake = %flake_ref).entered();
    let build_start = std::time::Instant::now();
    env.shell_exec_visible(&build_cmd)
        .with_context(|| format!("nix build failed for {}", attr))?;
    mvm_core::observability::metrics::global()
        .build_image_duration_ms
        .store(
            build_start.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

    // Step 2: Capture the output path (instant, uses Nix cache)
    let output = env
        .shell_exec_stdout(&format!(
            "nix build {} --no-link --print-out-paths{}",
            attr, impure_flag,
        ))
        .with_context(|| "Failed to get nix build output path")?;

    let nix_output_path = output
        .lines()
        .rev()
        .find(|l| l.starts_with("/nix/store/"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "nix build did not produce an output path. Output:\n{}",
                output
            )
        })?
        .trim()
        .to_string();

    env.log_info(&format!("Build output: {}", nix_output_path));

    // Step 3: Extract revision hash from /nix/store/<hash>-...
    let revision_hash = extract_revision_hash(&nix_output_path);
    let build_dir = dev_build_dir(&revision_hash);

    // Step 4: Check cache — skip copy if artifacts already exist
    if check_cache(env, &revision_hash)? {
        env.log_success(&format!("Cache hit: {}", build_dir));
        let initrd_path = detect_initrd(env, &build_dir);
        let runner_dir = detect_runner(env, &build_dir);
        let artifact_sizes = measure_artifact_sizes(env, &build_dir, initrd_path.is_some());
        return Ok(DevBuildResult {
            vmlinux_path: format!("{}/vmlinux", build_dir),
            initrd_path,
            rootfs_path: format!("{}/rootfs.ext4", build_dir),
            build_dir,
            revision_hash,
            cached: true,
            runner_dir,
            artifact_sizes,
        });
    }

    // Step 5: Copy artifacts from Nix store to dev build directory
    copy_dev_artifacts(env, &nix_output_path, &build_dir)?;

    env.log_success(&format!("Artifacts stored at {}", build_dir));

    let initrd_path = detect_initrd(env, &build_dir);
    let runner_dir = detect_runner(env, &build_dir);
    let artifact_sizes = measure_artifact_sizes(env, &build_dir, initrd_path.is_some());
    Ok(DevBuildResult {
        vmlinux_path: format!("{}/vmlinux", build_dir),
        initrd_path,
        rootfs_path: format!("{}/rootfs.ext4", build_dir),
        build_dir,
        revision_hash,
        cached: false,
        runner_dir,
        artifact_sizes,
    })
}

/// Run the flake's `pre-build.sh` hook if it exists.
///
/// Some templates install external software (e.g. via an upstream installer
/// script) before the Nix build. If `<flake_ref>/pre-build.sh` exists and
/// is executable, it is run with visible output. Returns `" --impure"` when
/// the hook ran (so `nix build` can reference host paths), or `""` otherwise.
fn run_pre_build_hook(env: &dyn ShellEnvironment, flake_ref: &str) -> Result<&'static str> {
    let pre_build = format!("{}/pre-build.sh", flake_ref);
    let check = env
        .shell_exec_stdout(&format!(
            "test -f {} && test -x {} && echo yes || echo no",
            shell_quote(&pre_build),
            shell_quote(&pre_build),
        ))
        .unwrap_or_default();

    if check.trim() != "yes" {
        return Ok("");
    }

    env.log_info("Running pre-build hook (pre-build.sh)...");
    env.shell_exec_visible(&format!("bash {}", shell_quote(&pre_build)))
        .with_context(|| "pre-build.sh hook failed")?;

    // The hook may install files outside the Nix store (e.g. /opt/openclaw)
    // that the flake references via builtins.path. --impure is required for
    // nix build to access these host paths.
    Ok(" --impure")
}

/// Resolve the Nix attribute for a dev build.
///
/// - `None` → builds the flake's `default` package (convention: `default = worker`).
/// - `Some(profile)` → builds `packages.<system>.tenant-<profile>`.
fn resolve_dev_build_attribute(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
) -> String {
    match profile {
        Some(p) if p != "default" => {
            let system = nix_system();
            let attr = format!("{}#packages.{}.tenant-{}", flake_ref, system, p);
            env.log_info(&format!("Build attribute: {}", attr));
            attr
        }
        _ => {
            // No profile or "default": build the flake's default package.
            env.log_info(&format!("Build attribute: {} (default)", flake_ref));
            flake_ref.to_string()
        }
    }
}

/// Extract the Nix store hash from an output path like `/nix/store/<hash>-name`.
fn extract_revision_hash(nix_output_path: &str) -> String {
    nix_output_path
        .strip_prefix("/nix/store/")
        .and_then(|s| s.split('-').next())
        .unwrap_or("unknown")
        .to_string()
}

/// Return the dev build directory for a given revision hash.
fn dev_build_dir(revision_hash: &str) -> String {
    format!("{}/{}", dev_builds_dir(), revision_hash)
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\\''"))
}

/// Check whether cached artifacts exist for a revision hash.
fn check_cache(env: &dyn ShellEnvironment, revision_hash: &str) -> Result<bool> {
    let build_dir = dev_build_dir(revision_hash);
    let result = env.shell_exec_stdout(&format!(
        "test -f {dir}/vmlinux && test -f {dir}/rootfs.ext4 && echo yes || echo no",
        dir = build_dir,
    ))?;
    Ok(result.trim() == "yes")
}

/// Copy kernel, initrd, and rootfs from a Nix store output to the dev build directory.
fn copy_dev_artifacts(
    env: &dyn ShellEnvironment,
    nix_output_path: &str,
    build_dir: &str,
) -> Result<()> {
    env.shell_exec(&format!(
        r#"
        set -euo pipefail
        mkdir -p {dir}

        # Copy kernel (try 'kernel' then 'vmlinux')
        if [ -e {out}/kernel ]; then
            cp -L {out}/kernel {dir}/vmlinux
        elif [ -e {out}/vmlinux ]; then
            cp -L {out}/vmlinux {dir}/vmlinux
        else
            echo 'ERROR: kernel not found in build output' >&2
            ls -la {out}/ >&2
            exit 1
        fi

        # Copy initrd if present (NixOS stage-1 for proper activation)
        if [ -e {out}/initrd ]; then
            cp -L {out}/initrd {dir}/initrd
        fi

        # Copy rootfs (try 'rootfs' then 'rootfs.ext4')
        if [ -e {out}/rootfs ]; then
            cp -L {out}/rootfs {dir}/rootfs.ext4
        elif [ -e {out}/rootfs.ext4 ]; then
            cp -L {out}/rootfs.ext4 {dir}/rootfs.ext4
        else
            echo 'ERROR: rootfs not found in build output' >&2
            ls -la {out}/ >&2
            exit 1
        fi

        # Copy microvm.nix runner scripts if present
        if [ -d {out}/bin ] && [ -x {out}/bin/microvm-run ]; then
            mkdir -p {dir}/bin
            cp -rL {out}/bin/* {dir}/bin/
            chmod +x {dir}/bin/*
        fi

        echo "Artifacts:"
        ls -lh {dir}/
        "#,
        out = nix_output_path,
        dir = build_dir,
    ))
    .with_context(|| format!("Failed to copy artifacts to {}", build_dir))
}

/// Measure artifact file sizes in the build directory using `stat -c%s`.
fn measure_artifact_sizes(
    env: &dyn ShellEnvironment,
    build_dir: &str,
    has_initrd: bool,
) -> mvm_core::pool::ArtifactSizes {
    let parse_size = |path: &str| -> u64 {
        env.shell_exec_stdout(&format!("stat -c%s {} 2>/dev/null || echo 0", path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };

    let vmlinux_bytes = parse_size(&format!("{}/vmlinux", build_dir));
    let rootfs_bytes = parse_size(&format!("{}/rootfs.ext4", build_dir));
    let initrd_bytes = if has_initrd {
        Some(parse_size(&format!("{}/initrd", build_dir)))
    } else {
        None
    };

    mvm_core::pool::ArtifactSizes {
        vmlinux_bytes,
        rootfs_bytes,
        initrd_bytes,
        nix_closure_bytes: None,
    }
}

/// Check whether an initrd exists in the build directory.
fn detect_initrd(env: &dyn ShellEnvironment, build_dir: &str) -> Option<String> {
    let path = format!("{}/initrd", build_dir);
    let result = env
        .shell_exec_stdout(&format!("test -f {} && echo yes || echo no", path))
        .ok()?;
    if result.trim() == "yes" {
        Some(path)
    } else {
        None
    }
}

/// Check whether a microvm.nix runner script exists in the build directory.
///
/// The root flake's `mkGuest` copies the runner to `$out/bin/microvm-run`
/// when the microvm.nix runner is available. If found, returns the runner
/// directory path (parent of `bin/`).
fn detect_runner(env: &dyn ShellEnvironment, build_dir: &str) -> Option<String> {
    let runner_path = format!("{}/bin/microvm-run", build_dir);
    let result = env
        .shell_exec_stdout(&format!("test -x {} && echo yes || echo no", runner_path))
        .ok()?;
    if result.trim() == "yes" {
        Some(build_dir.to_string())
    } else {
        None
    }
}

/// Return the Nix system identifier for the current architecture.
fn nix_system() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    }
}

// ============================================================================
// Guest agent auto-injection
// ============================================================================

/// Detect the mvm workspace root for building the guest-agent from source.
///
/// Tries in order:
/// 1. `MVM_SRC` environment variable (explicit override)
/// 2. Compile-time `CARGO_MANIFEST_DIR` — the build crate lives at
///    `<workspace>/crates/mvm-build`, so we go up 2 levels.
fn detect_mvm_src() -> Option<String> {
    if let Ok(p) = std::env::var("MVM_SRC")
        && !p.is_empty()
    {
        return Some(p);
    }

    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent()?.parent()?;
    if workspace.join("crates/mvm-guest").is_dir() {
        return Some(workspace.to_string_lossy().to_string());
    }

    None
}

/// Best-effort guest agent injection after a dev build.
///
/// Auto-detects the mvm workspace root and injects the guest agent into the
/// rootfs if it's not already present. Never fails the overall build — logs
/// a message and returns `Ok(())` if injection cannot be performed.
#[instrument(skip_all)]
pub fn ensure_guest_agent_if_needed(
    env: &dyn ShellEnvironment,
    build_result: &DevBuildResult,
) -> Result<()> {
    let mvm_src = match detect_mvm_src() {
        Some(p) => p,
        None => {
            env.log_info(
                "Cannot detect mvm source tree for guest-agent injection. \
                 Include the guest-agent module in your flake manually.",
            );
            return Ok(());
        }
    };
    ensure_guest_agent(env, build_result, &mvm_src)
}

/// Ensure the guest agent is present in the built rootfs.
///
/// Checks whether `mvm-guest-agent` exists in the rootfs. If not, builds it
/// from the mvm workspace and injects it (binary + systemd service + drop-in dir)
/// into the ext4 image. This guarantees every mvm-built image has the guest agent
/// regardless of whether the user's flake explicitly includes it.
fn ensure_guest_agent(
    env: &dyn ShellEnvironment,
    build_result: &DevBuildResult,
    mvm_src_path: &str,
) -> Result<()> {
    let rootfs = &build_result.rootfs_path;

    // Step 1: Check if agent is already in the rootfs
    let check_script = [
        "MOUNT=$(mktemp -d)",
        &format!("sudo mount -o loop,ro {} \"$MOUNT\"", rootfs),
        "FOUND=$(find \"$MOUNT/nix/store\" -name mvm-guest-agent -type f 2>/dev/null | head -1)",
        "sudo umount \"$MOUNT\"",
        "rmdir \"$MOUNT\"",
        "if [ -n \"$FOUND\" ]; then echo found; else echo missing; fi",
    ]
    .join(" && ");

    let check = env.shell_exec_stdout(&check_script)?;

    if check.trim() == "found" {
        env.log_info("Guest agent already present in rootfs");
        return Ok(());
    }

    env.log_info("Guest agent not found in rootfs — injecting...");

    // Step 2: Build the guest-agent from the mvm workspace
    let build_cmd = format!(
        "nix-build --no-out-link {}/nix/guest-lib/guest-agent-pkg.nix \
         --arg pkgs 'import <nixpkgs> {{}}' \
         --arg mvmSrc {} \
         --arg rustPlatform '(import <nixpkgs> {{}}).rustPlatform'",
        mvm_src_path, mvm_src_path,
    );

    let agent_store_path = match env.shell_exec_stdout(&build_cmd) {
        Ok(p) if p.trim().starts_with("/nix/store/") => p.trim().to_string(),
        _ => {
            env.log_info(
                "Could not build guest-agent for injection. \
                 Add the guest-agent module to your flake manually.",
            );
            return Ok(());
        }
    };

    // Step 3: Get the full nix store closure
    let closure = env
        .shell_exec_stdout(&format!("nix-store -qR {}", agent_store_path))
        .with_context(|| "Failed to query guest-agent closure")?;

    // Step 4: Inject into rootfs
    inject_agent_into_rootfs(env, rootfs, &agent_store_path, closure.trim())
}

/// Mount the rootfs, copy the agent closure, create systemd service, unmount.
fn inject_agent_into_rootfs(
    env: &dyn ShellEnvironment,
    rootfs: &str,
    agent_store_path: &str,
    closure_lines: &str,
) -> Result<()> {
    // Build the injection script. All paths come from nix-store output
    // (trusted, not user input).
    let mut script = String::new();
    script.push_str("set -euo pipefail\n");
    script.push_str("MOUNT=$(mktemp -d)\n");
    script.push_str(&format!("sudo mount -o loop {} \"$MOUNT\"\n", rootfs));

    // Copy each store path if not already present
    for line in closure_lines.lines() {
        let path = line.trim();
        if path.is_empty() || !path.starts_with("/nix/store/") {
            continue;
        }
        script.push_str(&format!(
            "[ -e \"$MOUNT{}\" ] || sudo cp -a {} \"$MOUNT{}\"\n",
            path, path, path
        ));
    }

    // Create systemd service file
    script.push_str("sudo mkdir -p \"$MOUNT/etc/systemd/system\"\n");
    script.push_str(&format!(
        concat!(
            "printf '[Unit]\\nDescription=MVM Guest Agent\\nAfter=basic.target\\n\\n",
            "[Service]\\nType=simple\\nExecStart={}/bin/mvm-guest-agent\\n",
            "Restart=on-failure\\nRestartSec=2s\\n\\n",
            "[Install]\\nWantedBy=multi-user.target\\n' ",
            "| sudo tee \"$MOUNT/etc/systemd/system/mvm-guest-agent.service\" > /dev/null\n"
        ),
        agent_store_path,
    ));

    // Enable for multi-user.target
    script.push_str(
        "sudo mkdir -p \"$MOUNT/etc/systemd/system/multi-user.target.wants\"\n\
         sudo ln -sf /etc/systemd/system/mvm-guest-agent.service \
         \"$MOUNT/etc/systemd/system/multi-user.target.wants/mvm-guest-agent.service\"\n",
    );

    // Create integrations drop-in directory
    script.push_str("sudo mkdir -p \"$MOUNT/etc/mvm/integrations.d\"\n");

    // Unmount
    script.push_str("sudo umount \"$MOUNT\"\nrmdir \"$MOUNT\"\n");

    env.shell_exec(&script)
        .with_context(|| "Failed to inject guest-agent into rootfs")?;

    env.log_success("Guest agent injected into rootfs");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock ShellEnvironment for testing dev_build logic without a real VM.
    struct TestEnv {
        stdout_responses: Mutex<HashMap<String, String>>,
        exec_log: Mutex<Vec<String>>,
        logs: Mutex<Vec<String>>,
    }

    impl TestEnv {
        fn new() -> Self {
            Self {
                stdout_responses: Mutex::new(HashMap::new()),
                exec_log: Mutex::new(Vec::new()),
                logs: Mutex::new(Vec::new()),
            }
        }

        fn stub_stdout(&self, pattern: &str, response: &str) {
            self.stdout_responses
                .lock()
                .unwrap()
                .insert(pattern.to_string(), response.to_string());
        }
    }

    impl ShellEnvironment for TestEnv {
        fn shell_exec(&self, script: &str) -> Result<()> {
            self.exec_log.lock().unwrap().push(script.to_string());
            Ok(())
        }

        fn shell_exec_stdout(&self, script: &str) -> Result<String> {
            self.exec_log.lock().unwrap().push(script.to_string());
            let responses = self.stdout_responses.lock().unwrap();
            for (pattern, response) in responses.iter() {
                if script.contains(pattern) {
                    return Ok(response.clone());
                }
            }
            Ok(String::new())
        }

        fn shell_exec_visible(&self, script: &str) -> Result<()> {
            self.exec_log.lock().unwrap().push(script.to_string());
            Ok(())
        }

        fn log_info(&self, msg: &str) {
            self.logs.lock().unwrap().push(format!("INFO: {}", msg));
        }

        fn log_success(&self, msg: &str) {
            self.logs.lock().unwrap().push(format!("SUCCESS: {}", msg));
        }
    }

    #[test]
    fn test_extract_revision_hash_valid() {
        let hash = extract_revision_hash("/nix/store/abc123def456-tenant-worker-minimal");
        assert_eq!(hash, "abc123def456");
    }

    #[test]
    fn test_extract_revision_hash_no_prefix() {
        let hash = extract_revision_hash("/some/other/path");
        assert_eq!(hash, "unknown");
    }

    #[test]
    fn test_extract_revision_hash_empty() {
        let hash = extract_revision_hash("");
        assert_eq!(hash, "unknown");
    }

    #[test]
    fn test_dev_build_dir() {
        let dir = dev_build_dir("abc123");
        assert!(dir.ends_with("/dev/builds/abc123"), "got: {}", dir);
    }

    #[test]
    fn test_dev_build_dir_preserves_full_hash() {
        let dir = dev_build_dir("abc123def456ghi789");
        assert!(
            dir.ends_with("/dev/builds/abc123def456ghi789"),
            "got: {}",
            dir
        );
    }

    #[test]
    fn test_nix_system() {
        let system = nix_system();
        assert!(
            system == "aarch64-linux" || system == "x86_64-linux",
            "unexpected system: {}",
            system
        );
    }

    #[test]
    fn test_cleanup_old_dev_builds_no_directory() {
        let env = TestEnv::new();
        env.stub_stdout("ls -1dt", "");

        let report = cleanup_old_dev_builds(&env, 2).unwrap();
        assert_eq!(report.removed_count, 0);
        assert!(report.removed_paths.is_empty());
    }

    #[test]
    fn test_cleanup_old_dev_builds_keeps_newest() {
        let env = TestEnv::new();
        env.stub_stdout(
            "ls -1dt",
            concat!(
                "/home/test/.mvm/dev/builds/newest\n",
                "/home/test/.mvm/dev/builds/middle\n",
                "/home/test/.mvm/dev/builds/oldest\n"
            ),
        );

        let report = cleanup_old_dev_builds(&env, 1).unwrap();
        assert_eq!(report.removed_count, 2);
        assert_eq!(
            report.removed_paths,
            vec![
                "/home/test/.mvm/dev/builds/middle".to_string(),
                "/home/test/.mvm/dev/builds/oldest".to_string()
            ]
        );

        let exec_log = env.exec_log.lock().unwrap();
        assert!(
            exec_log
                .iter()
                .any(|cmd| cmd.contains("rm -rf '/home/test/.mvm/dev/builds/middle'"))
        );
        assert!(
            exec_log
                .iter()
                .any(|cmd| cmd.contains("rm -rf '/home/test/.mvm/dev/builds/oldest'"))
        );
    }

    #[test]
    fn test_resolve_attribute_with_profile() {
        let env = TestEnv::new();

        let attr = resolve_dev_build_attribute(&env, "/home/user/my-project", Some("worker"));

        let system = nix_system();
        assert_eq!(
            attr,
            format!("/home/user/my-project#packages.{}.tenant-worker", system)
        );
    }

    #[test]
    fn test_resolve_attribute_custom_profile() {
        let env = TestEnv::new();

        let attr = resolve_dev_build_attribute(&env, "/tmp/flake", Some("gateway"));

        let system = nix_system();
        assert_eq!(
            attr,
            format!("/tmp/flake#packages.{}.tenant-gateway", system)
        );
    }

    #[test]
    fn test_resolve_attribute_default() {
        let env = TestEnv::new();

        let attr = resolve_dev_build_attribute(&env, "/tmp/flake", None);

        assert_eq!(attr, "/tmp/flake");
    }

    #[test]
    fn test_check_cache_hit() {
        let env = TestEnv::new();
        env.stub_stdout("test -f", "yes");

        let cached = check_cache(&env, "abc123").unwrap();
        assert!(cached);
    }

    #[test]
    fn test_check_cache_miss() {
        let env = TestEnv::new();
        env.stub_stdout("test -f", "no");

        let cached = check_cache(&env, "abc123").unwrap();
        assert!(!cached);
    }

    #[test]
    fn test_dev_build_cached() {
        let env = TestEnv::new();

        // nix build --no-link (visible) succeeds
        // nix build --print-out-paths returns the path
        env.stub_stdout(
            "--print-out-paths",
            "/nix/store/abc123-tenant-worker-minimal\n",
        );
        // Cache check returns yes
        env.stub_stdout("test -f", "yes");

        let result = dev_build(&env, "/home/user/project", Some("minimal")).unwrap();

        assert!(result.cached);
        assert_eq!(result.revision_hash, "abc123");
        let expected_dir = dev_build_dir("abc123");
        assert_eq!(result.build_dir, expected_dir);
        assert_eq!(result.vmlinux_path, format!("{expected_dir}/vmlinux"));
        assert_eq!(result.rootfs_path, format!("{expected_dir}/rootfs.ext4"));
    }

    #[test]
    fn test_dev_build_fresh() {
        let env = TestEnv::new();

        env.stub_stdout("--print-out-paths", "/nix/store/xyz789-tenant-minimal\n");
        // Cache miss
        env.stub_stdout("test -f", "no");

        let result = dev_build(&env, "/tmp/flake", Some("minimal")).unwrap();

        assert!(!result.cached);
        assert_eq!(result.revision_hash, "xyz789");
        assert_eq!(result.build_dir, dev_build_dir("xyz789"));

        // Verify a copy script was executed
        let exec_log = env.exec_log.lock().unwrap();
        let has_copy = exec_log.iter().any(|s| s.contains("cp -L"));
        assert!(has_copy, "Expected copy script in exec log");
    }

    #[test]
    fn test_dev_build_result_paths_consistent() {
        let dir = dev_build_dir("hash123");
        let result = DevBuildResult {
            build_dir: dir.clone(),
            vmlinux_path: format!("{dir}/vmlinux"),
            initrd_path: Some(format!("{dir}/initrd")),
            rootfs_path: format!("{dir}/rootfs.ext4"),
            revision_hash: "hash123".to_string(),
            cached: false,
            runner_dir: None,
            artifact_sizes: Default::default(),
        };

        assert!(result.vmlinux_path.starts_with(&result.build_dir));
        assert!(result.rootfs_path.starts_with(&result.build_dir));
        assert!(
            result
                .initrd_path
                .as_ref()
                .unwrap()
                .starts_with(&result.build_dir)
        );
    }

    #[test]
    fn test_dev_build_result_with_runner() {
        let dir = dev_build_dir("hash456");
        let result = DevBuildResult {
            build_dir: dir.clone(),
            vmlinux_path: format!("{dir}/vmlinux"),
            initrd_path: None,
            rootfs_path: format!("{dir}/rootfs.ext4"),
            revision_hash: "hash456".to_string(),
            cached: false,
            runner_dir: Some(dir.clone()),
            artifact_sizes: Default::default(),
        };

        assert!(result.runner_dir.is_some());
        assert_eq!(result.runner_dir.as_ref().unwrap(), &dir);
    }

    #[test]
    fn test_pre_build_hook_skipped_when_absent() {
        let env = TestEnv::new();
        // Default: shell_exec_stdout returns "" for unknown commands,
        // so the hook check returns "no" equivalent → skip.
        let flag = run_pre_build_hook(&env, "/tmp/flake").unwrap();
        assert_eq!(flag, "");
    }

    #[test]
    fn test_pre_build_hook_runs_when_present() {
        let env = TestEnv::new();
        env.stub_stdout("test -f", "yes");

        let flag = run_pre_build_hook(&env, "/tmp/flake").unwrap();
        assert_eq!(flag, " --impure");

        // Verify the hook script was executed.
        let exec_log = env.exec_log.lock().unwrap();
        assert!(
            exec_log.iter().any(|s| s.contains("pre-build.sh")),
            "Expected pre-build.sh in exec log"
        );
    }

    #[test]
    fn test_dev_build_with_pre_build_hook() {
        let env = TestEnv::new();

        // Pre-build hook exists.
        env.stub_stdout("test -f", "yes");
        // nix build output.
        env.stub_stdout("--print-out-paths", "/nix/store/abc123-tenant-minimal\n");

        let result = dev_build(&env, "/tmp/flake", Some("minimal")).unwrap();

        // Verify --impure was added to nix build commands.
        let exec_log = env.exec_log.lock().unwrap();
        let nix_build_cmds: Vec<_> = exec_log
            .iter()
            .filter(|s| s.contains("nix build"))
            .collect();
        assert!(
            nix_build_cmds.iter().all(|s| s.contains("--impure")),
            "Expected --impure in nix build commands: {:?}",
            nix_build_cmds
        );

        assert_eq!(result.revision_hash, "abc123");
    }

    #[test]
    fn test_measure_artifact_sizes() {
        let env = TestEnv::new();
        env.stub_stdout("vmlinux", "12345678");
        env.stub_stdout("rootfs.ext4", "45678901");

        let sizes = measure_artifact_sizes(&env, "/tmp/build", false);
        assert_eq!(sizes.vmlinux_bytes, 12_345_678);
        assert_eq!(sizes.rootfs_bytes, 45_678_901);
        assert!(sizes.initrd_bytes.is_none());
        assert!(sizes.nix_closure_bytes.is_none());
    }

    #[test]
    fn test_measure_artifact_sizes_with_initrd() {
        let env = TestEnv::new();
        env.stub_stdout("vmlinux", "12345678");
        env.stub_stdout("rootfs.ext4", "45678901");
        env.stub_stdout("initrd", "2345678");

        let sizes = measure_artifact_sizes(&env, "/tmp/build", true);
        assert_eq!(sizes.vmlinux_bytes, 12_345_678);
        assert_eq!(sizes.rootfs_bytes, 45_678_901);
        assert_eq!(sizes.initrd_bytes, Some(2_345_678));
    }

    #[test]
    fn test_dev_build_includes_artifact_sizes() {
        let env = TestEnv::new();

        env.stub_stdout("--print-out-paths", "/nix/store/xyz789-tenant-minimal\n");
        env.stub_stdout("test -f", "no");
        // stat calls return sizes
        env.stub_stdout("stat -c%s", "99999");

        let result = dev_build(&env, "/tmp/flake", Some("minimal")).unwrap();
        // Sizes should be populated (exact value depends on stub matching)
        assert!(result.artifact_sizes.vmlinux_bytes > 0 || result.artifact_sizes.rootfs_bytes > 0);
    }
}

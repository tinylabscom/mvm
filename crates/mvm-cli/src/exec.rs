//! `mvmctl exec` — boot a transient microVM, run one command, tear down.
//!
//! Composes existing primitives: template artifact resolution → backend
//! start → vsock guest agent → backend stop. The "what to run" is modeled
//! as a tagged enum so future variants (mvmforge `launch.json`, baked-in
//! template entrypoint) can be added without churning the inline-command
//! surface.
//!
//! Dev-mode only: inherits the existing `policy.access.debug_exec` gate
//! enforced by the guest agent.

use anyhow::{Context, Result};
use mvm_core::vm_backend::{VmId, VmStartConfig, VmVolume};
use mvm_runtime::vm::backend::AnyBackend;
use mvm_runtime::vm::microvm;

use crate::ui;

/// Where to source the command that runs inside the transient microVM.
///
/// Marked `non_exhaustive` so future variants (mvmforge launch plan,
/// baked-in template entrypoint) can be added without breaking match arms
/// in callers outside this crate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ExecTarget {
    /// Argv supplied directly on the CLI.
    Inline { argv: Vec<String> },
    // Future variants (do not implement until needed):
    // LaunchPlan { path: PathBuf },     // mvmforge launch.json
    // TemplateEntrypoint,               // entrypoint baked into template metadata
}

/// One `--add-dir host:guest` mapping.
///
/// v1: read-only only. The host directory is materialized into a small
/// ext4 image attached as an extra Firecracker drive, then mounted at
/// `guest_path` by a wrapper script before the user's command runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddDir {
    pub host_path: String,
    pub guest_path: String,
}

impl AddDir {
    /// Parse a `host:guest` spec.
    ///
    /// The first colon splits host from guest; subsequent colons are part
    /// of the guest path (rare but legal). Both sides must be non-empty,
    /// and the guest path must be absolute.
    pub fn parse(spec: &str) -> Result<Self> {
        let (host, guest) = spec.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("--add-dir '{spec}': expected 'host:guest', missing ':'")
        })?;
        if host.is_empty() {
            anyhow::bail!("--add-dir '{spec}': host path must not be empty");
        }
        if guest.is_empty() {
            anyhow::bail!("--add-dir '{spec}': guest path must not be empty");
        }
        if !guest.starts_with('/') {
            anyhow::bail!("--add-dir '{spec}': guest path must be absolute (start with '/')");
        }
        Ok(Self {
            host_path: expand_tilde(host),
            guest_path: guest.to_string(),
        })
    }
}

fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    path.to_string()
}

/// Where the VM's disk image and kernel come from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ImageSource {
    /// A registered template (resolved via `template::lifecycle::template_artifacts`).
    Template(String),
    /// Pre-built kernel + rootfs paths (e.g., the cached dev image).
    Prebuilt {
        kernel_path: String,
        rootfs_path: String,
        initrd_path: Option<String>,
        /// Display label used in messages and `flake_ref` (no functional effect).
        label: String,
    },
}

/// All inputs to the orchestrator.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub image: ImageSource,
    pub cpus: u32,
    pub memory_mib: u32,
    pub add_dirs: Vec<AddDir>,
    pub env: Vec<(String, String)>,
    pub target: ExecTarget,
    /// Timeout for the in-guest command in seconds.
    pub timeout_secs: u64,
}

impl ExecRequest {
    /// Convert the target into a single shell command string suitable for
    /// `GuestRequest::Exec`. Inline argv is shell-quoted with `exec` so the
    /// process inherits the wrapper's stdio.
    pub fn target_command(&self) -> String {
        match &self.target {
            ExecTarget::Inline { argv } => {
                let quoted: Vec<String> = argv.iter().map(|a| shell_quote(a)).collect();
                format!("exec {}", quoted.join(" "))
            }
        }
    }
}

/// Quote a single argument for inclusion in a shell command line.
///
/// Wraps in single quotes and escapes embedded single quotes the
/// portable POSIX way (`'` → `'\''`).
pub fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Build the wrapper script that runs inside the guest:
///   1. mounts each `--add-dir` ext4 image read-only by label
///   2. exports each `--env` variable
///   3. execs the user's command
///
/// `add_dir_labels` is the parallel list of ext4 labels assigned to each
/// `AddDir` (in the same order as `req.add_dirs`).
pub fn build_guest_wrapper(req: &ExecRequest, add_dir_labels: &[String]) -> String {
    let mut script = String::from("set -e\n");
    for (dir, label) in req.add_dirs.iter().zip(add_dir_labels.iter()) {
        let mount_point = shell_quote(&dir.guest_path);
        let label_q = shell_quote(label);
        script.push_str(&format!(
            "mkdir -p {mount_point}\nmount LABEL={label_q} {mount_point} -o ro\n",
        ));
    }
    for (k, v) in &req.env {
        script.push_str(&format!("export {k}={}\n", shell_quote(v)));
    }
    script.push_str(&req.target_command());
    script.push('\n');
    script
}

/// Generate a transient VM name for an exec invocation.
pub fn transient_vm_name() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    format!("exec-{pid:x}-{nanos:08x}")
}

/// Run the request: boot, run, tear down.
///
/// Returns the guest command's exit code. On orchestrator failure (boot,
/// agent unreachable, vsock error), returns an error; the VM is torn down
/// best-effort before returning.
pub fn run(req: ExecRequest) -> Result<i32> {
    let backend = AnyBackend::default_backend();

    // Resolve image artifacts: either a named template or a pre-built pair.
    let (vmlinux, initrd, rootfs, revision, flake_ref, profile) = match &req.image {
        ImageSource::Template(name) => {
            let (spec, vmlinux, initrd, rootfs, rev) =
                mvm_runtime::vm::template::lifecycle::template_artifacts(name)
                    .with_context(|| format!("Loading template '{name}'"))?;
            (
                vmlinux,
                initrd,
                rootfs,
                rev,
                spec.flake_ref.clone(),
                Some(spec.profile.clone()),
            )
        }
        ImageSource::Prebuilt {
            kernel_path,
            rootfs_path,
            initrd_path,
            label,
        } => (
            kernel_path.clone(),
            initrd_path.clone(),
            rootfs_path.clone(),
            String::new(),
            label.clone(),
            None,
        ),
    };

    // Build read-only ext4 images for each --add-dir, staged in a transient
    // VMS subdirectory so cleanup is straightforward.
    let vm_name = transient_vm_name();
    let staging_dir = format!("{}/{}/extras", mvm_runtime::config::VMS_DIR, vm_name);
    let mut volumes: Vec<mvm_runtime::vm::image::RuntimeVolume> = Vec::new();
    let mut add_dir_labels: Vec<String> = Vec::new();
    for (idx, dir) in req.add_dirs.iter().enumerate() {
        let label = format!("mvm-extra-{idx}");
        let image_path = format!("{staging_dir}/extra-{idx}.ext4");
        mvm_runtime::vm::image::build_dir_image_ro(&dir.host_path, &label, &image_path)
            .with_context(|| {
                format!(
                    "preparing --add-dir image for '{}' -> '{}'",
                    dir.host_path, dir.guest_path
                )
            })?;
        volumes.push(mvm_runtime::vm::image::RuntimeVolume {
            host: image_path,
            guest: dir.guest_path.clone(),
            size: String::new(),
            read_only: true,
        });
        add_dir_labels.push(label);
    }

    // Boot the VM (cold boot — snapshot path is intentionally skipped in
    // v1: extra drives don't match the snapshot's recorded drive layout).
    let start_config = VmStartConfig {
        name: vm_name.clone(),
        rootfs_path: rootfs,
        kernel_path: Some(vmlinux),
        initrd_path: initrd,
        revision_hash: revision,
        flake_ref,
        profile,
        cpus: req.cpus,
        memory_mib: req.memory_mib,
        ports: Vec::new(),
        volumes: volumes
            .iter()
            .map(|v| VmVolume {
                host: v.host.clone(),
                guest: v.guest.clone(),
                size: v.size.clone(),
                read_only: v.read_only,
            })
            .collect(),
        config_files: Vec::new(),
        secret_files: Vec::new(),
        runner_dir: None,
    };

    ui::info(&format!("Booting transient VM '{vm_name}'..."));
    if let Err(e) = backend.start(&start_config) {
        let _ = mvm_runtime::shell::run_in_vm(&format!("rm -rf {staging_dir}"));
        return Err(e).context("starting transient microVM");
    }

    // Install Ctrl-C handler that tears the VM down.
    let interrupted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let interrupted = interrupted.clone();
        let vm_name = vm_name.clone();
        let _ = ctrlc::set_handler(move || {
            interrupted.store(true, std::sync::atomic::Ordering::SeqCst);
            let backend = AnyBackend::default_backend();
            let _ = backend.stop(&VmId(vm_name.clone()));
        });
    }

    // Run the command + always tear down.
    let result = run_in_guest(&vm_name, &req, &add_dir_labels);

    let _ = backend.stop(&VmId(vm_name.clone()));
    let _ = mvm_runtime::shell::run_in_vm(&format!("rm -rf {staging_dir}"));

    if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
        anyhow::bail!("interrupted");
    }
    result
}

/// Send the wrapped command to the guest agent and stream stdout/stderr.
fn run_in_guest(vm_name: &str, req: &ExecRequest, labels: &[String]) -> Result<i32> {
    if !wait_for_agent(vm_name, 30) {
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    let wrapper = build_guest_wrapper(req, labels);
    let resp = send_request(vm_name, &wrapper, req.timeout_secs)?;
    match resp {
        mvm_guest::vsock::GuestResponse::ExecResult {
            exit_code,
            stdout,
            stderr,
        } => {
            if !stdout.is_empty() {
                print!("{stdout}");
            }
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            Ok(exit_code)
        }
        mvm_guest::vsock::GuestResponse::Error { message } => {
            anyhow::bail!("guest exec error: {message}")
        }
        other => anyhow::bail!("unexpected guest response: {other:?}"),
    }
}

fn wait_for_agent(vm_name: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    while std::time::Instant::now() < deadline {
        if mvm_apple_container::vsock_connect(vm_name, mvm_guest::vsock::GUEST_AGENT_PORT).is_ok() {
            return true;
        }
        if let Ok(instance_dir) = microvm::resolve_running_vm_dir(vm_name) {
            let uds = mvm_guest::vsock::vsock_uds_path(&instance_dir);
            if mvm_guest::vsock::ping_at(&uds).unwrap_or(false) {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

fn send_request(
    vm_name: &str,
    command: &str,
    timeout_secs: u64,
) -> Result<mvm_guest::vsock::GuestResponse> {
    if let Ok(mut stream) =
        mvm_apple_container::vsock_connect(vm_name, mvm_guest::vsock::GUEST_AGENT_PORT)
    {
        return mvm_guest::vsock::send_request(
            &mut stream,
            &mvm_guest::vsock::GuestRequest::Exec {
                command: command.to_string(),
                stdin: None,
                timeout_secs: Some(timeout_secs),
            },
        );
    }
    let instance_dir = microvm::resolve_running_vm_dir(vm_name)?;
    mvm_guest::vsock::exec_at(
        &mvm_guest::vsock::vsock_uds_path(&instance_dir),
        command,
        None,
        timeout_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_dir_parse_happy_path() {
        let d = AddDir::parse("/tmp/src:/work").unwrap();
        assert_eq!(d.host_path, "/tmp/src");
        assert_eq!(d.guest_path, "/work");
    }

    #[test]
    fn add_dir_parse_rejects_missing_colon() {
        let err = AddDir::parse("/tmp/src").unwrap_err();
        assert!(err.to_string().contains("missing ':'"));
    }

    #[test]
    fn add_dir_parse_rejects_empty_host() {
        let err = AddDir::parse(":/work").unwrap_err();
        assert!(err.to_string().contains("host path"));
    }

    #[test]
    fn add_dir_parse_rejects_empty_guest() {
        let err = AddDir::parse("/tmp/src:").unwrap_err();
        assert!(err.to_string().contains("guest path"));
    }

    #[test]
    fn add_dir_parse_rejects_relative_guest() {
        let err = AddDir::parse("/tmp/src:relative/path").unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn add_dir_expands_tilde_in_host_path() {
        // SAFETY: test process is single-threaded for env access.
        unsafe {
            std::env::set_var("HOME", "/tmp/fakehome");
        }
        let d = AddDir::parse("~/configs:/etc/configs").unwrap();
        assert_eq!(d.host_path, "/tmp/fakehome/configs");
        assert_eq!(d.guest_path, "/etc/configs");
    }

    #[test]
    fn add_dir_extra_colons_belong_to_guest_path() {
        let d = AddDir::parse("/host:/weird:path").unwrap();
        assert_eq!(d.host_path, "/host");
        assert_eq!(d.guest_path, "/weird:path");
    }

    #[test]
    fn shell_quote_basic() {
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("hello world"), "'hello world'");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn target_command_inline_quotes_each_arg() {
        let req = ExecRequest {
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["uname".into(), "-a".into()],
            },
            timeout_secs: 30,
        };
        assert_eq!(req.target_command(), "exec 'uname' '-a'");
    }

    #[test]
    fn build_guest_wrapper_no_extras() {
        let req = ExecRequest {
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: Vec::new(),
            env: Vec::new(),
            target: ExecTarget::Inline {
                argv: vec!["true".into()],
            },
            timeout_secs: 30,
        };
        let script = build_guest_wrapper(&req, &[]);
        assert!(script.starts_with("set -e\n"));
        assert!(script.contains("exec 'true'"));
        assert!(!script.contains("mount"));
        assert!(!script.contains("export"));
    }

    #[test]
    fn build_guest_wrapper_mounts_and_env() {
        let req = ExecRequest {
            image: ImageSource::Template("t".into()),
            cpus: 1,
            memory_mib: 256,
            add_dirs: vec![AddDir {
                host_path: "/h".into(),
                guest_path: "/g".into(),
            }],
            env: vec![("FOO".into(), "bar baz".into())],
            target: ExecTarget::Inline {
                argv: vec!["echo".into(), "$FOO".into()],
            },
            timeout_secs: 30,
        };
        let script = build_guest_wrapper(&req, &["mvm-extra-0".to_string()]);
        assert!(script.contains("mkdir -p '/g'"));
        assert!(script.contains("mount LABEL='mvm-extra-0' '/g' -o ro"));
        assert!(script.contains("export FOO='bar baz'"));
        assert!(script.contains("exec 'echo' '$FOO'"));
    }

    #[test]
    fn transient_vm_name_format() {
        let n = transient_vm_name();
        assert!(n.starts_with("exec-"));
        assert!(n.len() > "exec-".len());
        assert!(!n.contains(' '));
        assert!(!n.contains('/'));
    }
}

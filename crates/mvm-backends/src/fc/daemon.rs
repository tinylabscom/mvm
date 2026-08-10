//! Firecracker daemon lifecycle + the raw HTTP-over-UDS API client:
//! socket/uds path helpers, process spawn, and the PUT/PATCH call plumbing.

use anyhow::{Context, Result};
use tracing::instrument;

use mvm_vmm::host::shell::{run_in_vm_stdout, run_in_vm_visible, shell_quote};
use mvm_vmm::host::ui;

use super::{firecracker_vsock_uds_path, resolve_running_vm_dir};

/// Resolve the path to the per-VM serial console log file.
///
/// The host-side netinit-audit emitter
/// (`netinit_audit::emit_for_vm`) reads this file after the
/// agent is ready and parses the netinit Report from the
/// captured `__MVM_NETINIT_REPORT__` line. The path follows the
/// existing convention (`<vm_dir>/console.log`); a backend
/// that doesn't split console + hypervisor logs returns a
/// path that may not exist, which the caller treats as
/// "no netinit report available" rather than an error.
pub fn vm_console_log_path(vm_name: &str) -> Result<std::path::PathBuf> {
    let abs_dir = resolve_running_vm_dir(vm_name)?;
    Ok(std::path::PathBuf::from(format!("{abs_dir}/console.log")))
}

/// Start a Firecracker daemon in a per-VM directory with its own socket.
#[instrument(skip_all)]
pub fn start_vm_firecracker(abs_dir: &str, abs_socket: &str) -> Result<()> {
    start_vm_firecracker_inner(abs_dir, abs_socket, true, "")
}

/// Start a Firecracker daemon bounded by the CPU share this launch was admitted
/// under.
///
/// Separate from [`start_vm_firecracker`] rather than a wider signature on it:
/// the snapshot-restore and standby callers resume a VM whose grant is not
/// theirs to decide, and giving them a parameter to fill would invite one of
/// them to invent a bound the run was never admitted under.
#[instrument(skip_all)]
pub fn start_vm_firecracker_bounded(
    abs_dir: &str,
    abs_socket: &str,
    machine_id: &str,
    grant: Option<&mvm_contract::grants::CpuGrant>,
) -> Result<()> {
    let prefix = cpu_scope_prefix(machine_id, std::path::Path::new(abs_dir), grant);
    start_vm_firecracker_inner(abs_dir, abs_socket, true, &prefix)
}

/// Start Firecracker without unlinking a mounted child vsock UDS.
pub fn start_vm_firecracker_for_snapshot(abs_dir: &str, abs_socket: &str) -> Result<()> {
    start_vm_firecracker_inner(abs_dir, abs_socket, false, "")
}

/// The `systemd-run` scope prefix for the launch line, shell-quoted, or empty
/// when nothing is to be bound.
///
/// Firecracker is the one per-VM process this repo starts through a shell
/// rather than a `Command` — it is `sudo`-elevated and detaches itself with
/// `nohup setsid` — so it needs the prefix as text. The tokens come from the
/// same builder the `Command` path uses, so the two cannot drift into bounding
/// different things.
fn cpu_scope_prefix(
    machine_id: &str,
    state_dir: &std::path::Path,
    grant: Option<&mvm_contract::grants::CpuGrant>,
) -> String {
    match mvm_core::cpu_scope::scope_prefix_for_grant(machine_id, state_dir, grant) {
        Some(tokens) => {
            let quoted: Vec<String> = tokens.iter().map(|t| shell_quote(t)).collect();
            format!("{} ", quoted.join(" "))
        }
        None => String::new(),
    }
}

fn start_vm_firecracker_inner(
    abs_dir: &str,
    abs_socket: &str,
    clean_vsock: bool,
    cpu_scope: &str,
) -> Result<()> {
    ui::info("Starting Firecracker...");
    run_in_vm_visible(&firecracker_launch_script(
        abs_dir,
        abs_socket,
        clean_vsock,
        cpu_scope,
    ))
}

/// The launch script, built rather than run.
///
/// Pure so a test can read back whether the CPU scope actually reached the
/// launch line. An unwrapped Firecracker boots identically and is simply not
/// bounded, which is precisely the failure that needs a test rather than an
/// inspection.
fn firecracker_launch_script(
    abs_dir: &str,
    abs_socket: &str,
    clean_vsock: bool,
    cpu_scope: &str,
) -> String {
    let vsock = firecracker_vsock_uds_path(abs_dir);
    let vsock_cleanup = if clean_vsock {
        format!("rm -f {vsock} {abs_dir}/v.sock")
    } else {
        String::new()
    };
    format!(
        r#"
        mkdir -p {dir}
        sudo rm -f {socket}
        {vsock_cleanup}
        touch {dir}/console.log {dir}/firecracker.log
        {cpu_scope}sudo bash -c 'nohup setsid firecracker --api-sock {socket} --enable-pci \
            </dev/null >{dir}/console.log 2>{dir}/firecracker.log &
            echo $! > {dir}/fc.pid'

        echo "[mvm] Waiting for API socket..."
        for i in $(seq 1 30); do
            [ -S {socket} ] && break
            sleep 0.1
        done

        if [ ! -S {socket} ]; then
            echo "[mvm] ERROR: API socket did not appear." >&2
            exit 1
        fi
        echo "[mvm] Firecracker started."
        "#,
        socket = abs_socket,
        dir = abs_dir,
        vsock_cleanup = vsock_cleanup,
        cpu_scope = cpu_scope,
    )
}

/// Send API PUT request to a specific Firecracker socket.
///
/// `data` is written to a temp file and passed via `curl --data @<file>`
/// so the body never traverses the shell — guards against the
/// `--data '{json}'` shape where a single-quote in `data` would
/// escape into the host shell (`specs/01-project.md` flagged the v1
/// shape's quoting fragility). `socket` and `path` are
/// `shell_quote`d defensively.
#[instrument(skip_all, fields(path))]
pub fn api_put_socket(socket: &str, path: &str, data: &str) -> Result<()> {
    fc_api_call("PUT", socket, path, Some(data))
}

/// Hand the Firecracker-created vsock multiplexer socket to the mvmctl user.
///
/// Firecracker runs as root and consequently creates this socket as root. Only
/// the invoking user needs to dial it, so transfer ownership and keep the mode
/// private instead of making the control plane world-writable.
pub fn secure_vsock_socket_for_caller(vsock: &str) -> Result<()> {
    let quoted = shell_quote(vsock);
    run_in_vm_visible(&format!(
        "set -eu\nsudo chown -- \"$(id -u):$(id -g)\" {quoted}\nchmod 0600 {quoted}"
    ))
}

/// Shared body for FC's PUT/PATCH calls. Writes `data` (if Some) to a
/// `NamedTempFile`, then shells out to curl with `--data @<file>` so
/// the JSON body never goes through bash. All paths flowing into the
/// script are `shell_quote`d.
fn fc_api_call(method: &str, socket: &str, path: &str, data: Option<&str>) -> Result<()> {
    use std::io::Write;
    let q_socket = shell_quote(socket);
    let url = format!("http://localhost{path}");
    let q_url = shell_quote(&url);
    let q_path = shell_quote(path);

    let (data_arg, _body_holder) = match data {
        Some(body) => {
            let mut tmp = tempfile::NamedTempFile::new()
                .with_context(|| "creating temp file for FC API body")?;
            tmp.write_all(body.as_bytes())
                .with_context(|| "writing FC API body to temp file")?;
            tmp.flush()
                .with_context(|| "flushing FC API body to temp file")?;
            let path_str = tmp.path().to_string_lossy().into_owned();
            let q_body_path = shell_quote(&path_str);
            (
                format!(
                    "--data @{q_body_path} -H 'Content-Type: application/json'",
                    q_body_path = &q_body_path[..]
                ),
                Some(tmp),
            )
        }
        None => (String::new(), None),
    };

    let script = format!(
        r#"
        set -eu
        response=$(sudo curl -s -w "\n%{{http_code}}" -X {method} --unix-socket {q_socket} \
            {data_arg} {q_url})
        code=$(printf '%s' "$response" | tail -n1)
        body=$(printf '%s' "$response" | sed '$d')
        if [ "$code" -ge 400 ]; then
            echo "[mvm] ERROR: {method} $(printf '%s' {q_path}) returned $code: $body" >&2
            exit 1
        fi
        "#,
    );
    run_in_vm_visible(&script)
    // _body_holder drops at function exit, deleting the temp file.
}

/// Read the pid recorded by [`start_vm_firecracker`].
pub fn read_firecracker_pid(abs_dir: &str) -> Result<u32> {
    let q_dir = shell_quote(abs_dir);
    let output = run_in_vm_stdout(&format!("cat {q_dir}/fc.pid"))?;
    output
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parse Firecracker pid from {abs_dir}/fc.pid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_socket_access_is_private_to_the_invoking_user() {
        use mvm_vmm::host::shell::mock as shell_mock;
        use std::sync::{Arc, Mutex};

        let scripts = Arc::new(Mutex::new(Vec::new()));
        let captured = scripts.clone();
        let _guard = shell_mock::install_handler(move |script| {
            captured.lock().unwrap().push(script.to_string());
            shell_mock::MockResponse::empty()
        });

        secure_vsock_socket_for_caller("/tmp/vm with quote'/runtime/v.sock")
            .expect("secure socket");

        let scripts = scripts.lock().unwrap();
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("sudo chown -- \"$(id -u):$(id -g)\""));
        assert!(scripts[0].contains("chmod 0600"));
        assert!(scripts[0].contains("'/tmp/vm with quote'\\''/runtime/v.sock'"));
        assert!(!scripts[0].contains("chmod 0666"));
    }

    /// Firecracker is the one per-VM process started through a shell, so its
    /// bound has to reach the launch *line* rather than a `Command`.
    #[test]
    fn a_granted_share_prefixes_the_firecracker_launch_line() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::cpu_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");

        let prefix = cpu_scope_prefix(
            "vm-bounded",
            scratch.path(),
            Some(&mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
        );
        let script = firecracker_launch_script("/tmp/vm", "/tmp/vm/fc.socket", true, &prefix);

        assert!(script.contains("CPUQuota=150%"), "{script}");
        // The unit carries a per-boot suffix, so match the stem rather than a
        // name that can no longer be reconstructed from the machine id.
        assert!(script.contains("vm-bounded-"), "{script}");
        assert!(script.contains(".scope"), "{script}");
        // Ahead of the launch, not merely somewhere in the script: Firecracker
        // has to be born inside the scope.
        assert!(
            script.contains("systemd-run"),
            "the scope must precede the launch: {script}"
        );
        let scope_at = script.find("systemd-run").expect("prefix present");
        let launch_at = script.find("sudo bash -c").expect("launch present");
        assert!(scope_at < launch_at, "{script}");
    }

    #[test]
    fn an_ungranted_launch_line_carries_no_scope() {
        let script = firecracker_launch_script("/tmp/vm", "/tmp/vm/fc.socket", true, "");
        assert!(!script.contains("systemd-run"), "{script}");
        assert!(
            script.contains("sudo bash -c 'nohup setsid firecracker"),
            "{script}"
        );
    }

    #[test]
    fn an_unbindable_grant_leaves_the_launch_line_untouched() {
        // No mechanism on this host, or a share too small to express: either
        // way the boot proceeds unbounded rather than failing.
        let scratch = tempfile::tempdir().expect("scratch");
        assert_eq!(cpu_scope_prefix("vm-x", scratch.path(), None), "");
    }
}

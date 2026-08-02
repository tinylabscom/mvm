//! Firecracker daemon lifecycle + the raw HTTP-over-UDS API client:
//! socket/uds path helpers, process spawn, and the PUT/PATCH call plumbing.

use anyhow::{Context, Result};
use tracing::instrument;

use crate::base::shell::{run_in_vm_stdout, run_in_vm_visible, shell_quote};
use crate::base::ui;

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
pub(crate) fn start_vm_firecracker(abs_dir: &str, abs_socket: &str) -> Result<()> {
    start_vm_firecracker_inner(abs_dir, abs_socket, true)
}

/// Start Firecracker without unlinking a mounted child vsock UDS.
pub(crate) fn start_vm_firecracker_for_snapshot(abs_dir: &str, abs_socket: &str) -> Result<()> {
    start_vm_firecracker_inner(abs_dir, abs_socket, false)
}

fn start_vm_firecracker_inner(abs_dir: &str, abs_socket: &str, clean_vsock: bool) -> Result<()> {
    ui::info("Starting Firecracker...");
    let vsock = firecracker_vsock_uds_path(abs_dir);
    let vsock_cleanup = if clean_vsock {
        format!("rm -f {vsock} {abs_dir}/v.sock")
    } else {
        String::new()
    };
    run_in_vm_visible(&format!(
        r#"
        mkdir -p {dir}
        sudo rm -f {socket}
        {vsock_cleanup}
        touch {dir}/console.log {dir}/firecracker.log
        sudo bash -c 'nohup setsid firecracker --api-sock {socket} --enable-pci \
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
    ))
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
pub(crate) fn api_put_socket(socket: &str, path: &str, data: &str) -> Result<()> {
    fc_api_call("PUT", socket, path, Some(data))
}

/// Hand the Firecracker-created vsock multiplexer socket to the mvmctl user.
///
/// Firecracker runs as root and consequently creates this socket as root. Only
/// the invoking user needs to dial it, so transfer ownership and keep the mode
/// private instead of making the control plane world-writable.
pub(crate) fn secure_vsock_socket_for_caller(vsock: &str) -> Result<()> {
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
        use crate::base::shell_mock;
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
}

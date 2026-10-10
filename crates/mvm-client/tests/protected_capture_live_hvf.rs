//! Native admitted boot-UART capture, read after the launcher has exited.
//!
//! Run only through scripts/test-protected-capture-live-hvf.sh. Missing inputs
//! are errors, never successful skips. This increment covers cold detached
//! boot capture and controlled stop, not bytes emitted after launcher exit,
//! synthetic UART injection, warm ownership transfer, or crash recovery.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use mvm_client::stream::{
    FramedStreamReader, OutputRequest, RecordOrigin, StreamOpts, StreamReader, open_vm_output,
};
use mvm_contract::stream::StreamSource;
use mvm_core::config;

const COMMAND_LIMIT: Duration = Duration::from_secs(120);
const OUTPUT_LIMIT: Duration = Duration::from_secs(30);

fn required_path(key: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os(key).with_context(|| format!("{key} is required"))?);
    ensure!(path.is_absolute(), "{key} must be absolute");
    Ok(path)
}

struct Inputs {
    root: PathBuf,
    cli: PathBuf,
    image: String,
}

impl Inputs {
    fn read() -> Result<Self> {
        let root = required_path("MVM_PROTECTED_WITNESS_ROOT")?.canonicalize()?;
        ensure!(
            root.starts_with("/private/tmp") || root.starts_with("/tmp"),
            "isolated /tmp root required"
        );
        ensure!(
            fs::read(root.join("protected-witness-owned"))? == b"cold-boot-uart-v1\n",
            "use the dedicated witness script"
        );
        ensure!(
            required_path("MVM_HOME")?.canonicalize()? == root.join("mvm"),
            "MVM_HOME is not isolated"
        );
        ensure!(
            required_path("HOME")?.canonicalize()? == root.join("home"),
            "HOME must isolate default-cache imports"
        );
        ensure!(
            required_path("TMPDIR")?.canonicalize()? == root.join("tmp"),
            "TMPDIR is not isolated"
        );
        let cli = required_path("MVM_E2E_MVMCTL")?;
        let rootfs = required_path("MVM_E2E_ROOTFS")?;
        for (key, path) in [
            ("MVM_E2E_MVMCTL", cli.clone()),
            ("MVM_E2E_ROOTFS", rootfs.clone()),
            ("MVM_E2E_KERNEL", required_path("MVM_E2E_KERNEL")?),
            (
                "MVM_HVF_SUPERVISOR_PATH",
                required_path("MVM_HVF_SUPERVISOR_PATH")?,
            ),
        ] {
            ensure!(path.is_file(), "{key} must name an existing regular file");
        }
        ensure!(
            rootfs.canonicalize()?.starts_with(root.join("mvm/cache"))
                && required_path("MVM_E2E_KERNEL")?
                    .canonicalize()?
                    .starts_with(root.join("mvm/cache")),
            "fixtures must be in the isolated cache"
        );
        let cache = root.join("mvm/cache/oci");
        let index: serde_json::Value =
            serde_json::from_slice(&fs::read(cache.join("index.json"))?)?;
        let rootfs = rootfs.canonicalize()?;
        let image = index["images"]
            .as_array()
            .context("fixture OCI index missing images")?
            .iter()
            .find(|image| {
                image["rootfs_path"].as_str().is_some_and(|path| {
                    cache
                        .join(path)
                        .canonicalize()
                        .is_ok_and(|path| path == rootfs)
                })
            })
            .context("fixture rootfs has no OCI provenance entry")?;
        let digest = image["resolved_digest"]
            .as_str()
            .context("fixture digest missing")?;
        ensure!(
            digest.strip_prefix("sha256:").is_some_and(
                |hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            ),
            "invalid fixture OCI digest"
        );
        let image = format!(
            "{}/{}@{digest}",
            image["registry"]
                .as_str()
                .context("fixture registry missing")?,
            image["repository"]
                .as_str()
                .context("fixture repository missing")?
        );
        Ok(Self { root, cli, image })
    }
}

/// The handle, not a PID search, owns every launcher this harness can kill.
/// Tokio owns exit notification and reaping; the supervisor exit observer is
/// unsuitable here because it discards an owned child's exit status.
fn run_command(command: Command) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut command = tokio::process::Command::from(command);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        match tokio::time::timeout(COMMAND_LIMIT, child.wait()).await {
            Ok(status) => ensure!(status?.success(), "owned command failed"),
            Err(_) => {
                child.kill().await?;
                anyhow::bail!("owned command exceeded its deadline");
            }
        }
        Ok(())
    })
}

/// Armed before launch, so partial admission/boot failures also get cleanup.
/// Never sweeps names or signals a PID discovered outside this unique machine.
struct MachineGuard {
    cli: PathBuf,
    name: String,
    removed: bool,
}

impl MachineGuard {
    fn command(&self, verb: &str) -> Command {
        let mut command = Command::new(&self.cli);
        command.args(["machine", verb, "--yes", &self.name]);
        command
    }

    fn stop(&self) -> Result<()> {
        run_command(self.command("stop"))
    }

    fn remove(&mut self) -> Result<()> {
        run_command(self.command("rm"))?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for MachineGuard {
    fn drop(&mut self) {
        if !self.removed {
            if self.stop().is_err() {
                eprintln!("owned witness machine cleanup failed: {}", self.name);
            } else if self.remove().is_err() {
                eprintln!("owned witness definition cleanup failed: {}", self.name);
            }
        }
    }
}

/// Scan regular files without following symlinks or reading sockets/devices.
/// Streaming overlap catches a plaintext marker across read boundaries without
/// loading rootfs images into memory.
fn assert_no_plaintext(dir: &Path, marker: &[u8], deadline: Instant) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        ensure!(
            Instant::now() < deadline,
            "plaintext inventory exceeded its deadline"
        );
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            assert_no_plaintext(&entry.path(), marker, deadline)?;
        } else if kind.is_file() {
            let mut file = File::open(entry.path())?;
            let mut buffer = vec![0_u8; 64 * 1024 + marker.len()];
            let mut carry = 0;
            loop {
                ensure!(
                    Instant::now() < deadline,
                    "plaintext inventory exceeded its deadline"
                );
                let read = file.read(&mut buffer[carry..])?;
                if read == 0 {
                    break;
                }
                let end = carry + read;
                ensure!(
                    !buffer[..end]
                        .windows(marker.len())
                        .any(|bytes| bytes == marker),
                    "plaintext witness payload persisted at {}",
                    entry.path().display()
                );
                carry = end.min(marker.len() - 1);
                buffer.copy_within(end - carry..end, 0);
            }
        }
    }
    Ok(())
}

fn inventory(root: &Path, marker: &[u8]) -> Result<()> {
    let deadline = Instant::now() + COMMAND_LIMIT;
    assert_no_plaintext(root, marker, deadline)
}

#[test]
fn plaintext_inventory_detects_read_boundary_marker() -> Result<()> {
    let root = tempfile::tempdir()?;
    let marker = b"synthetic-inventory-marker";
    let mut bytes = vec![b'x'; 64 * 1024 + marker.len() - 4];
    bytes.extend_from_slice(marker);
    fs::write(root.path().join("capture"), bytes)?;
    ensure!(
        assert_no_plaintext(root.path(), marker, Instant::now() + OUTPUT_LIMIT).is_err(),
        "inventory missed a marker across read boundaries"
    );
    Ok(())
}

#[test]
fn plaintext_inventory_does_not_follow_external_symlinks() -> Result<()> {
    let root = tempfile::tempdir()?;
    let external = tempfile::tempdir()?;
    let marker = b"synthetic-external-marker";
    fs::write(external.path().join("capture"), marker)?;
    std::os::unix::fs::symlink(external.path(), root.path().join("outside"))?;
    assert_no_plaintext(root.path(), marker, Instant::now() + OUTPUT_LIMIT)
}

#[test]
fn owned_launcher_reports_failure() -> Result<()> {
    ensure!(
        run_command(Command::new("/usr/bin/false")).is_err(),
        "unsuccessful launcher was accepted"
    );
    run_command(Command::new("/usr/bin/true"))
}

#[test]
#[ignore = "explicit native HVF witness; dedicated script supplies isolated verified fixtures; missing inputs FAIL"]
fn boot_uart_is_readable_after_launcher_exit_and_public_stop() -> Result<()> {
    let inputs = Inputs::read()?;
    let nonce: u128 = rand::random();
    let name = format!("pc-{:x}-{nonce:032x}", std::process::id());
    let mut machine = MachineGuard {
        cli: inputs.cli,
        name,
        removed: false,
    };
    let mut launch = Command::new(&machine.cli);
    launch.args([
        "machine",
        "run",
        "--hypervisor",
        "hvf",
        "--profile",
        "dev",
        "-d",
        "--name",
        &machine.name,
        "--image",
    ]);
    launch.arg(&inputs.image);
    // A normal persistent machine remains available after this command and
    // its launcher exit. Nothing injects a marker into the boot configuration.
    launch.args(["--", "true"]);
    run_command(launch).context("admitted detached launch")?;

    let supervisor: serde_json::Value = serde_json::from_slice(&fs::read(
        config::vm_state_dir(&machine.name).join("supervisor.json"),
    )?)?;
    ensure!(
        supervisor["console_capture"] == "encrypted",
        "native supervisor did not require encrypted capture"
    );
    ensure!(
        supervisor["vm_name"] == machine.name,
        "supervisor capture was bound to a different machine"
    );
    let boot_kernel = supervisor["kernel"]
        .as_str()
        .context("supervisor kernel missing")?;
    ensure!(
        Path::new(boot_kernel).canonicalize()?
            == required_path("MVM_E2E_KERNEL")?.canonicalize()?,
        "launcher did not use the declared verified kernel fixture"
    );
    let run = mvm_core::stream_client::protected::ProtectedRun::read(
        &config::vm_protected_stream_dir(&machine.name),
    )?
    .context("supervisor did not publish protected capture")?;
    ensure!(
        run.persists,
        "detached witness requires durable capture, not live-only standby"
    );

    let socket = UnixStream::connect(config::vm_stream_socket(&machine.name))?;
    let deadline = Instant::now() + OUTPUT_LIMIT;
    socket.set_read_timeout(Some(OUTPUT_LIMIT))?;
    let timeout_socket = socket.try_clone()?;
    let mut live = FramedStreamReader::new(socket, StreamOpts::builder().follow(true).build());
    let mut observed = Vec::new();
    let probe = b"Booting Linux on physical CPU";
    let marker = loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("live marker deadline exceeded")?;
        timeout_socket.set_read_timeout(Some(remaining))?;
        let record = live
            .next_record()?
            .context("live stream ended before retained boot UART output")?;
        ensure!(
            record.source == StreamSource::Console,
            "witness output was not captured from the console"
        );
        observed.extend_from_slice(&record.payload);
        ensure!(
            observed.len() <= 8 * 1024 * 1024,
            "live witness byte bound exceeded"
        );
        ensure!(live.gap().is_none(), "live capture reported loss");
        // Match a genuine kernel boot message, then use the complete emitted
        // line (including its runtime timestamp/CPU formatting) for absence
        // checks. The bare format string legitimately exists in the kernel
        // fixture. This asserts availability after detach, not emission time.
        if let Some(line) = observed
            .split_inclusive(|byte| *byte == b'\n')
            .find(|line| {
                line.ends_with(b"\n") && line.windows(probe.len()).any(|bytes| bytes == probe)
            })
        {
            break line.to_vec();
        }
    };
    inventory(&inputs.root, &marker)?;
    drop(live);
    drop(timeout_socket);
    machine.stop().context("controlled native shutdown")?;

    // Read the original production location, never a copied/re-signed fixture.
    // Deleting history during stop is a failure, not permission to weaken this.
    ensure!(
        !config::vm_stream_socket(&machine.name).exists(),
        "controlled stop left a broker socket; refusing an unbounded live read"
    );
    let mut history = open_vm_output(&machine.name, OutputRequest::default())
        .context("verified history after public machine stop")?;
    let mut payload = Vec::new();
    while let Some(record) = history.next_output()? {
        ensure!(
            record.origin == RecordOrigin::Durable,
            "history fell back to a non-durable source"
        );
        payload.extend_from_slice(&record.payload);
        ensure!(
            payload.len() <= 8 * 1024 * 1024,
            "history witness byte bound exceeded"
        );
    }
    ensure!(
        history.truncation().is_none(),
        "sealed capture was truncated"
    );
    ensure!(
        payload
            .windows(marker.len())
            .any(|bytes| bytes == marker.as_slice()),
        "sealed encrypted history lost retained boot UART output"
    );
    inventory(&inputs.root, &marker)?;
    machine.remove()?;
    eprintln!(
        "PASS: genuine boot UART readable after launcher exit, verified live/history, public stop, plaintext inventory; no post-detach emission claim"
    );
    Ok(())
}

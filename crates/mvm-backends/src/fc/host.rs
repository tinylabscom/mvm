use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::ContentBlob;

use mvm_core::config::{ARCH, FC_CI_ASSETS_VERSION, fc_version};
use mvm_vmm::host::config::*;
use mvm_vmm::host::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible};
use mvm_vmm::host::ui;

/// Check if Firecracker is installed on the Linux host.
pub fn is_installed() -> Result<bool> {
    let output = run_in_vm("command -v firecracker >/dev/null 2>&1")?;
    Ok(output.status.success())
}

/// Check if the kernel image exists in ~/microvm/.
pub fn has_kernel() -> Result<bool> {
    let output = run_in_vm(&format!(
        "ls {dir}/vmlinux-* >/dev/null 2>&1",
        dir = MICROVM_DIR,
    ))?;
    Ok(output.status.success())
}

/// Check if the upstream squashfs rootfs exists in ~/microvm/.
pub fn has_squashfs() -> Result<bool> {
    let output = run_in_vm(&format!(
        "ls {dir}/ubuntu-*.squashfs.upstream >/dev/null 2>&1",
        dir = MICROVM_DIR,
    ))?;
    Ok(output.status.success())
}

/// Check if both kernel and squashfs assets are present.
pub fn has_base_assets() -> Result<bool> {
    Ok(has_kernel()? && has_squashfs()?)
}

/// Check if the jailer binary is installed.
fn jailer_is_installed() -> Result<bool> {
    let output = run_in_vm("command -v jailer >/dev/null 2>&1")?;
    Ok(output.status.success())
}

/// Install Firecracker (and jailer) on the Linux host.
///
/// Idempotent: skips if both binaries are already present. If firecracker
/// is installed but the jailer is missing, downloads the release tarball
/// and extracts just the jailer.
pub fn install() -> Result<()> {
    let fc_present = is_installed()?;
    let jailer_present = jailer_is_installed()?;

    if fc_present && jailer_present {
        let version = run_in_vm_stdout("firecracker --version 2>&1 | head -1")?;
        ui::info(&format!(
            "Firecracker + jailer already installed: {}",
            version
        ));
        return Ok(());
    }

    let version = fc_version();

    if fc_present && !jailer_present {
        ui::info("Jailer not found, installing from Firecracker release tarball...");
        install_jailer_from_tarball(&version)?;
        return Ok(());
    }

    ui::info(&format!("Installing Firecracker {}...", version));
    run_in_vm_visible(&format!(
        r#"
        cd /tmp
        wget --progress=bar:force:noscroll https://github.com/firecracker-microvm/firecracker/releases/download/{fc_version}/firecracker-{fc_version}-{arch}.tgz
        tar -xzf firecracker-{fc_version}-{arch}.tgz
        sudo mv release-{fc_version}-{arch}/firecracker-{fc_version}-{arch} /usr/local/bin/firecracker
        sudo chmod +x /usr/local/bin/firecracker
        if [ -f release-{fc_version}-{arch}/jailer-{fc_version}-{arch} ]; then
            sudo mv release-{fc_version}-{arch}/jailer-{fc_version}-{arch} /usr/local/bin/jailer
            sudo chmod +x /usr/local/bin/jailer
        fi
        rm -rf firecracker-{fc_version}-{arch}.tgz release-{fc_version}-{arch}
        firecracker --version
        "#,
        fc_version = version,
        arch = ARCH,
    ))?;

    ui::success("Firecracker installed.");
    Ok(())
}

/// Download the release tarball and extract just the jailer binary.
fn install_jailer_from_tarball(version: &str) -> Result<()> {
    run_in_vm_visible(&format!(
        r#"
        cd /tmp
        wget -q https://github.com/firecracker-microvm/firecracker/releases/download/{fc_version}/firecracker-{fc_version}-{arch}.tgz
        tar -xzf firecracker-{fc_version}-{arch}.tgz
        if [ -f release-{fc_version}-{arch}/jailer-{fc_version}-{arch} ]; then
            sudo mv release-{fc_version}-{arch}/jailer-{fc_version}-{arch} /usr/local/bin/jailer
            sudo chmod +x /usr/local/bin/jailer
            echo "Jailer installed."
        else
            echo "Jailer binary not found in release tarball."
        fi
        rm -rf firecracker-{fc_version}-{arch}.tgz release-{fc_version}-{arch}
        "#,
        fc_version = version,
        arch = ARCH,
    ))?;
    Ok(())
}

/// Download kernel and rootfs into ~/microvm/ on the Linux host.
///
/// Downloads run in parallel when both are needed.
pub fn download_assets() -> Result<()> {
    let fc_short = FC_CI_ASSETS_VERSION;
    ui::info("Downloading kernel and rootfs...");
    run_in_vm_visible(&format!(
        r#"
        set -euo pipefail
        mkdir -p {dir} && cd {dir}

        need_kernel=0
        need_rootfs=0
        ls vmlinux-* >/dev/null 2>&1 || need_kernel=1
        ls ubuntu-*.squashfs.upstream >/dev/null 2>&1 || need_rootfs=1

        if [ "$need_kernel" -eq 0 ] && [ "$need_rootfs" -eq 0 ]; then
            echo '[mvm] Kernel and rootfs already downloaded.'
            exit 0
        fi

        # Resolve latest versions from S3 index
        if [ "$need_kernel" -eq 1 ]; then
            echo '[mvm] Looking up latest kernel...'
            latest_kernel_key=$(wget "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/{fc_short}/{arch}/vmlinux-5.10&list-type=2" -O - 2>/dev/null \
                | grep -oP '(?<=<Key>)(firecracker-ci/{fc_short}/{arch}/vmlinux-5\.10\.[0-9]{{3}})(?=</Key>)')
            if [ -z "$latest_kernel_key" ]; then
                echo '[mvm] ERROR: Failed to find kernel.' >&2
                exit 1
            fi
        fi

        if [ "$need_rootfs" -eq 1 ]; then
            echo '[mvm] Looking up latest rootfs...'
            latest_ubuntu_key=$(curl -s "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/{fc_short}/{arch}/ubuntu-&list-type=2" \
                | grep -oP '(?<=<Key>)(firecracker-ci/{fc_short}/{arch}/ubuntu-[0-9]+\.[0-9]+\.squashfs)(?=</Key>)' \
                | sort -V | tail -1)
            if [ -z "$latest_ubuntu_key" ]; then
                echo '[mvm] ERROR: Failed to find rootfs.' >&2
                exit 1
            fi
            ubuntu_version=$(basename $latest_ubuntu_key .squashfs | grep -oE '[0-9]+\.[0-9]+')
        fi

        # Download in parallel when both are needed
        pids=""
        if [ "$need_kernel" -eq 1 ]; then
            echo '[mvm] Downloading kernel...'
            wget -q --show-progress --progress=bar:force:noscroll \
                "https://s3.amazonaws.com/spec.ccfc.min/$latest_kernel_key" &
            pids="$pids $!"
        else
            echo '[mvm] Kernel already downloaded.'
        fi

        if [ "$need_rootfs" -eq 1 ]; then
            echo '[mvm] Downloading rootfs...'
            wget -q --show-progress --progress=bar:force:noscroll \
                -O "ubuntu-${{ubuntu_version}}.squashfs.upstream" \
                "https://s3.amazonaws.com/spec.ccfc.min/$latest_ubuntu_key" &
            pids="$pids $!"
        else
            echo '[mvm] RootFS already downloaded.'
        fi

        # Wait for all background downloads and fail if any failed
        for pid in $pids; do
            wait "$pid" || {{ echo '[mvm] ERROR: A download failed.' >&2; exit 1; }}
        done

        [ "$need_kernel" -eq 1 ] && echo '[mvm] Kernel downloaded.'
        [ "$need_rootfs" -eq 1 ] && echo "[mvm] RootFS downloaded (Ubuntu ${{ubuntu_version:-unknown}})."
        "#,
        dir = MICROVM_DIR,
        arch = ARCH,
        fc_short = fc_short,
    ))?;

    Ok(())
}

/// Prepare the ext4 root filesystem from the downloaded squashfs.
///
/// No SSH is configured in the rootfs. MicroVMs run headless and
/// communicate via vsock only.
pub fn prepare_rootfs() -> Result<()> {
    ui::info("Preparing root filesystem...");
    run_in_vm_visible(&format!(
        r#"
        set -euo pipefail
        cd {dir}

        squashfs_file=$(ls ubuntu-*.squashfs.upstream 2>/dev/null | tail -1)
        if [ -z "$squashfs_file" ]; then
            echo '[mvm] ERROR: No squashfs file found.' >&2
            exit 1
        fi
        ubuntu_version=$(echo $squashfs_file | grep -oE '[0-9]+\.[0-9]+')

        if ls ubuntu-*.ext4 >/dev/null 2>&1; then
            echo '[mvm] ext4 rootfs already exists, skipping.'
        else
            echo '[mvm] Extracting squashfs...'
            sudo rm -rf squashfs-root
            sudo unsquashfs $squashfs_file

            echo '[mvm] Creating ext4 filesystem (1GB)...'
            truncate -s 1G "ubuntu-${{ubuntu_version}}.ext4"
            sudo mkfs.ext4 -d squashfs-root -F "ubuntu-${{ubuntu_version}}.ext4"

            sudo rm -rf squashfs-root
            echo '[mvm] Root filesystem prepared.'
        fi

        echo ''
        echo 'Setup Summary:'
        KERNEL=$(ls vmlinux-* 2>/dev/null | tail -1)
        [ -f "$KERNEL" ] && echo "  Kernel:  $KERNEL" || echo "  ERROR: Kernel not found"
        ROOTFS=$(ls *.ext4 2>/dev/null | tail -1)
        [ -f "$ROOTFS" ] && echo "  Rootfs:  $ROOTFS" || echo "  ERROR: Rootfs not found"
        "#,
        dir = MICROVM_DIR,
    ))?;

    Ok(())
}

/// Write the state file with discovered asset filenames.
pub fn write_state() -> Result<()> {
    run_in_vm(&format!(
        r#"
        cd {dir}
        cat > .mvm-state <<STATEEOF
{{
    "kernel": "$(ls vmlinux-* 2>/dev/null | tail -1)",
    "rootfs": "$(ls *.ext4 2>/dev/null | tail -1)"
}}
STATEEOF
        "#,
        dir = MICROVM_DIR,
    ))?;
    Ok(())
}

/// Check whether the downloaded squashfs file is intact.
pub fn validate_rootfs_squashfs() -> Result<bool> {
    let output = run_in_vm(&format!(
        "unsquashfs -l {dir}/ubuntu-*.squashfs.upstream >/dev/null 2>&1",
        dir = MICROVM_DIR,
    ))?;
    Ok(output.status.success())
}

/// Check if the Firecracker process is running on the Linux host.
pub fn is_running() -> Result<bool> {
    let output = run_in_vm("pgrep -x firecracker >/dev/null 2>&1")?;
    Ok(output.status.success())
}

/// Check if a specific VM's Firecracker process is alive (by PID file path).
/// Uses `/proc/<pid>/comm` instead of kill -0 because firecracker runs as root.
pub fn is_vm_running(pid_file: &str) -> Result<bool> {
    let result = run_in_vm_stdout(&format!(
        r#"[ -f {pid} ] && p=$(cat {pid}) && [ -f "/proc/$p/comm" ] && [ "$(cat /proc/$p/comm)" = "firecracker" ] && echo yes || echo no"#,
        pid = pid_file,
    ))?;
    Ok(result.trim() == "yes")
}

/// Check whether one already-captured PID still names a Firecracker process.
///
/// Unlike [`is_vm_running`], this probe does not depend on the PID marker still
/// existing. Teardown captures the marker once, then uses this identity until
/// the process is proven gone so a concurrently removed marker cannot turn a
/// live process into a false "stopped" result.
pub fn is_firecracker_pid_running(pid: u32) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        comm_path_is_firecracker(&std::path::PathBuf::from(format!("/proc/{pid}/comm")))
    }

    #[cfg(not(target_os = "linux"))]
    let result = run_in_vm_stdout(&format!(
        r#"[ -f "/proc/{pid}/comm" ] && [ "$(cat /proc/{pid}/comm)" = "firecracker" ] && echo yes || echo no"#,
    ))?;
    #[cfg(not(target_os = "linux"))]
    Ok(result.trim() == "yes")
}

/// Whether `pid` is the Firecracker serving the API socket `api_socket`.
///
/// Stronger than [`is_firecracker_pid_running`], which accepts any Firecracker:
/// a pid file left from before a reboot can name a pid that now belongs to
/// another VM's Firecracker. Every Firecracker mvm starts is given its own
/// socket with `--api-sock`, so the socket on its command line identifies
/// which VM it serves. Callers that are about to signal a recorded pid use this.
///
/// `Ok(false)` only when the answer is positively "not ours": the process is
/// gone, is not Firecracker, or is a Firecracker serving a different socket.
/// A live process whose identity cannot be confirmed — its `/proc` entry
/// hidden, its command line unreadable, no `--api-sock` on it — is an error,
/// because a caller treats "not ours" as "already stopped".
pub fn is_firecracker_for_socket(pid: u32, api_socket: &Path) -> Result<bool> {
    identity_from(observe_process(pid)?, api_socket)
        .with_context(|| format!("confirming which VM pid {pid} serves"))
}

/// What the process table says about one pid.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProcessView {
    /// No such process.
    Gone,
    /// The process exists but its `/proc` entry cannot be read.
    Hidden,
    /// A process that is not Firecracker.
    NotFirecracker,
    /// A Firecracker, with its command line (`None` if unreadable) and working
    /// directory (`None` if unreadable), which resolves a relative socket.
    Firecracker {
        args: Option<Vec<String>>,
        cwd: Option<PathBuf>,
    },
}

#[cfg(target_os = "linux")]
fn observe_process(pid: u32) -> Result<ProcessView> {
    observe_process_at(PathBuf::from(format!("/proc/{pid}")), || {
        mvm_vmm::host::process_liveness::pid_is_alive(pid as i32)
    })
}

/// Read one process view from `proc_dir` (a `/proc/<pid>` entry), consulting
/// `is_alive` only when the entry itself cannot be read — an unreadable entry
/// for a live process is `Hidden`, for a dead one `Gone`. Split out from
/// [`observe_process`] so the classification is witnessable against a fixture
/// directory instead of a live pid.
#[cfg(any(target_os = "linux", test))]
fn observe_process_at(proc_dir: PathBuf, is_alive: impl Fn() -> bool) -> Result<ProcessView> {
    match std::fs::read_to_string(proc_dir.join("comm")) {
        Ok(comm) if comm.trim() != "firecracker" => Ok(ProcessView::NotFirecracker),
        Ok(_) => Ok(ProcessView::Firecracker {
            args: std::fs::read(proc_dir.join("cmdline"))
                .ok()
                .map(|cmdline| split_cmdline(&cmdline)),
            cwd: std::fs::read_link(proc_dir.join("cwd")).ok(),
        }),
        Err(_) if !is_alive() => Ok(ProcessView::Gone),
        // The process exists but its entry is unreadable: `hidepid`, or a
        // permission this user lacks.
        Err(_) => Ok(ProcessView::Hidden),
    }
}

#[cfg(any(target_os = "linux", test))]
fn split_cmdline(cmdline: &[u8]) -> Vec<String> {
    cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn observe_process(pid: u32) -> Result<ProcessView> {
    let listing = run_in_vm_stdout(&format!(
        r#"if [ ! -e /proc/{pid} ]; then
  if kill -0 {pid} 2>/dev/null || sudo -n kill -0 {pid} 2>/dev/null; then echo hidden; else echo gone; fi
elif [ ! -r /proc/{pid}/comm ]; then echo hidden
elif [ "$(cat /proc/{pid}/comm)" != firecracker ]; then echo other
else
  echo firecracker
  echo "cwd:$(readlink /proc/{pid}/cwd 2>/dev/null)"
  if [ -r /proc/{pid}/cmdline ]; then tr '\0' '\n' < /proc/{pid}/cmdline; else echo '!unreadable'; fi
fi"#,
    ))?;
    parse_process_listing(&listing)
}

/// Parse the listing the non-Linux probe prints. Anything unexpected is an
/// error, never a "not ours".
#[cfg(any(not(target_os = "linux"), test))]
fn parse_process_listing(listing: &str) -> Result<ProcessView> {
    let mut lines = listing.lines();
    match lines.next().map(str::trim) {
        Some("gone") => Ok(ProcessView::Gone),
        Some("hidden") => Ok(ProcessView::Hidden),
        Some("other") => Ok(ProcessView::NotFirecracker),
        Some("firecracker") => {
            let cwd = lines
                .next()
                .and_then(|line| line.strip_prefix("cwd:"))
                .filter(|cwd| !cwd.is_empty())
                .map(PathBuf::from);
            let rest: Vec<String> = lines
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect();
            let args = (rest.first().map(String::as_str) != Some("!unreadable")).then_some(rest);
            Ok(ProcessView::Firecracker { args, cwd })
        }
        other => anyhow::bail!("unexpected process probe output: {other:?}"),
    }
}

/// Decide from a [`ProcessView`] whether the process serves `api_socket`.
fn identity_from(view: ProcessView, api_socket: &Path) -> Result<bool> {
    match view {
        ProcessView::Gone | ProcessView::NotFirecracker => Ok(false),
        ProcessView::Hidden => {
            anyhow::bail!("the process exists but its /proc entry cannot be read")
        }
        ProcessView::Firecracker { args: None, .. } => {
            anyhow::bail!("it is Firecracker but its command line cannot be read")
        }
        ProcessView::Firecracker {
            args: Some(args),
            cwd,
        } => {
            let socket = api_socket_arg(&args)
                .context("it is Firecracker but its command line names no --api-sock")?;
            let socket = Path::new(socket);
            let resolved = if socket.is_absolute() {
                socket.to_path_buf()
            } else {
                cwd.context("its --api-sock is relative and its working directory is unreadable")?
                    .join(socket)
            };
            Ok(same_file_path(&resolved, api_socket))
        }
    }
}

/// The value a Firecracker command line passes to `--api-sock`, either as the
/// next argument or as `--api-sock=<path>`.
fn api_socket_arg(args: &[String]) -> Option<&str> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--api-sock" {
            return args.next().map(String::as_str);
        }
        if let Some(value) = arg.strip_prefix("--api-sock=") {
            return Some(value);
        }
    }
    None
}

/// Whether two paths name the same file, comparing their parent directories
/// after resolving symlinks (`/tmp` and `/private/tmp` are one directory) and
/// relative components. A socket file may be gone, so only the directories are
/// resolved; a directory that cannot be resolved is compared as written.
fn same_file_path(a: &Path, b: &Path) -> bool {
    fn resolved(path: &Path) -> PathBuf {
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        match (absolute.parent(), absolute.file_name()) {
            (Some(parent), Some(name)) => parent
                .canonicalize()
                .map(|parent| parent.join(name))
                .unwrap_or(absolute.clone()),
            _ => absolute,
        }
    }
    resolved(a) == resolved(b)
}

#[cfg(target_os = "linux")]
fn comm_path_is_firecracker(path: &std::path::Path) -> Result<bool> {
    match std::fs::read_to_string(path) {
        Ok(comm) => Ok(comm.trim() == "firecracker"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Name of the Firecracker VM-state file produced by `PUT /snapshot/create`.
pub const FC_VMSTATE_FILENAME: &str = "vmstate.bin";

/// Bridges the checkpoint `VmFullControl` trait to a running Firecracker VM.
///
/// `save_memory(memory_path)` pauses the VM (via `PATCH /vm`), creates a full
/// snapshot (`PUT /snapshot/create`) that writes:
///   - `vmstate.bin` alongside `memory_path` (i.e. `parent(memory_path)/vmstate.bin`)
///   - `memory_path` itself (the guest memory image)
///
/// `extra_content(content_dir)` returns a [`ContentBlob`] for `vmstate.bin` so
/// the checkpoint manifest captures it.
///
/// The machine-id sidecar (`<memory_path>.machine-id`) is NOT written — FC has
/// no notion of a persistent machine identifier; `capture_vm_full` skips the
/// blob when the sidecar file is absent.
///
/// `rootfs_path()` is read from the `mode.json` sidecar that `record_from_rootfs`
/// writes at FC start time.
pub struct FcVmFullControl {
    vm_name: String,
}

impl FcVmFullControl {
    pub fn new(vm_name: impl Into<String>) -> Self {
        Self {
            vm_name: vm_name.into(),
        }
    }
}

impl mvm_vmm::checkpoint::VmFullControl for FcVmFullControl {
    fn pause(&self) -> Result<()> {
        super::pause_vm(&self.vm_name)
            .with_context(|| format!("pausing Firecracker VM '{}'", self.vm_name))
    }

    fn resume(&self) -> Result<()> {
        super::resume_vm(&self.vm_name)
            .with_context(|| format!("resuming Firecracker VM '{}'", self.vm_name))
    }

    fn save_memory(&self, memory_path: &Path) -> Result<()> {
        anyhow::ensure!(
            memory_path.is_absolute(),
            "save_memory requires an absolute path, got {}",
            memory_path.display()
        );
        let vmstate_path = memory_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("memory_path has no parent dir"))?
            .join(FC_VMSTATE_FILENAME);
        super::create_snapshot_files(&self.vm_name, &vmstate_path, memory_path).with_context(|| {
            format!(
                "creating Firecracker snapshot for VM '{}' (vmstate={}, mem={})",
                self.vm_name,
                vmstate_path.display(),
                memory_path.display(),
            )
        })
    }

    fn rootfs_path(&self) -> Result<PathBuf> {
        let meta = mvm_vmm::host::runtime_meta::read(&self.vm_name)
            .with_context(|| {
                format!(
                    "reading mode.json for Firecracker VM '{}' to resolve rootfs path",
                    self.vm_name
                )
            })?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no mode.json found for VM '{}'; was it started with `mvmctl machine run`?",
                    self.vm_name
                )
            })?;
        let rootfs_str = meta.rootfs_path.ok_or_else(|| {
            anyhow::anyhow!(
                "mode.json for VM '{}' has no rootfs_path field (started before rootfs tracking?)",
                self.vm_name
            )
        })?;
        Ok(PathBuf::from(rootfs_str))
    }

    fn device_anchors(&self) -> anyhow::Result<mvm_core::checkpoint::DeviceAnchors> {
        let vm_dir = super::resolve_running_vm_dir(&self.vm_name)
            .with_context(|| format!("resolving VM dir for '{}'", self.vm_name))?;
        // A fork finds the parent's state dir as the vsock socket's
        // grandparent, which only holds while the sockets live there.
        super::ensure_fc_sockets_in_state_dir(&vm_dir, "a Firecracker full-VM snapshot")?;
        let rootfs = self.rootfs_path()?;
        let rootfs_dir = rootfs
            .parent()
            .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent directory"))?;

        let mut anchors = mvm_core::checkpoint::DeviceAnchors {
            rootfs: rootfs.clone(),
            rootfs_verity: None,
            config: None,
            secrets: None,
            vsock: PathBuf::from(crate::fc::firecracker_vsock_uds_path(&vm_dir)),
        };

        let verity = rootfs_dir.join("rootfs.verity");
        if verity.exists() {
            anchors.rootfs_verity = Some(verity);
        }
        let config = PathBuf::from(&vm_dir).join("config.ext4");
        if config.exists() {
            anchors.config = Some(config);
        }
        let secrets = PathBuf::from(&vm_dir).join("secrets.ext4");
        if secrets.exists() {
            anchors.secrets = Some(secrets);
        }

        Ok(anchors)
    }

    fn extra_content(&self, content_dir: &Path) -> Result<Vec<ContentBlob>> {
        let vmstate = content_dir.join(FC_VMSTATE_FILENAME);
        if !vmstate.exists() {
            // save_memory was not yet called or failed; return empty so capture
            // fails on the missing memory.bin rather than here.
            return Ok(vec![]);
        }
        let sha256 = mvm_core::crypto::image_verify::sha256_file(&vmstate)
            .with_context(|| format!("hashing {}", vmstate.display()))?;
        Ok(vec![ContentBlob {
            name: FC_VMSTATE_FILENAME.into(),
            sha256,
        }])
    }
}

/// Boots a forked child from a Firecracker checkpoint triple cloned into
/// `child_dir`. Supplies the fork-restore callback for the
/// FC path.
///
/// On `restore_fork`:
/// 1. Renames `memory.bin` → `mem.bin` inside `child_dir` so the snapshot
///    loader finds Firecracker's canonical memory filename.
/// 2. Reads the parent's device anchors and bind-mounts the child's copies over
///    those paths in a private mount namespace, so the snapshot bitcode resolves
///    to the child's files without editing `vmstate.bin`.
/// 3. Starts a fresh Firecracker and loads the cloned snapshot. The fork
///    caller delivers the real generation token and optional grant over vsock
///    after `restore_fork` returns.
pub struct FcForkRestorer;

impl FcForkRestorer {
    /// Prepare a forked child and return its paused Firecracker API handle.
    fn prepare_fork_load(
        &self,
        child_vm_name: &str,
        child_dir: &std::path::Path,
        cpu_grant: Option<mvm_contract::grants::CpuGrant>,
    ) -> anyhow::Result<super::io::FirecrackerIO> {
        use anyhow::Context as _;
        // FC saves memory as `memory.bin`; the snapshot loader expects
        // `mem.bin`, Firecracker's canonical load filename.
        let memory_bin = child_dir.join("memory.bin");
        let mem_bin = child_dir.join("mem.bin");
        if memory_bin.exists() && !mem_bin.exists() {
            std::fs::rename(&memory_bin, &mem_bin).with_context(|| {
                format!(
                    "renaming memory.bin → mem.bin for FC fork of '{}'",
                    child_vm_name
                )
            })?;
        }

        // Remap the absolute parent paths baked into vmstate.bin to the child's
        // copies inside a private mount namespace, so the snapshot loads the
        // child's devices without editing Firecracker bitcode.
        let anchors_path = child_dir.join("device-anchors.json");
        let anchors: mvm_core::checkpoint::DeviceAnchors =
            serde_json::from_slice(&std::fs::read(&anchors_path).with_context(|| {
                format!(
                    "reading required FC fork device anchors {}",
                    anchors_path.display()
                )
            })?)
            .with_context(|| {
                format!(
                    "parsing required FC fork device anchors {}",
                    anchors_path.display()
                )
            })?;
        let child_vm_dir = super::resolve_running_vm_dir(child_vm_name)
            .with_context(|| format!("resolving VM dir for child '{child_vm_name}'"))?;
        super::ensure_fc_sockets_in_state_dir(&child_vm_dir, "a Firecracker fork")?;
        let mut mappings = Vec::new();
        mappings.push((anchors.rootfs, child_dir.join("rootfs.ext4")));
        if let Some(parent) = anchors.rootfs_verity {
            mappings.push((parent, child_dir.join("rootfs.verity")));
        }
        // The snapshot encodes absolute paths under the parent's VM state dir
        // (vsock UDS, config drive, secrets drive). Remap the whole parent dir
        // onto the child's state dir in a private mount namespace so every
        // parent-prefixed path resolves to the child's copy without editing
        // Firecracker bitcode. A file-level remap of the vsock UDS alone fails
        // because the child socket does not exist until Firecracker creates it
        // during snapshot load.
        let parent_vm_dir = anchors
            .vsock
            .parent()
            .and_then(|p| p.parent())
            .ok_or_else(|| anyhow::anyhow!("FC fork anchors.vsock has no VM-dir parent"))?;
        mappings.push((
            parent_vm_dir.to_path_buf(),
            std::path::PathBuf::from(&child_vm_dir),
        ));
        std::fs::create_dir_all(child_dir.join("runtime")).ok();
        super::remap_paths_for_fork(&mappings)
            .context("remapping parent device paths for FC fork")?;

        // The namespace is already active, so preserve the mounted child vsock
        // path while Firecracker loads the cloned VM state. The CLI delivers
        // the real generation token and optional grant after the guest agent
        // becomes reachable.
        //
        // The load leaves vCPUs paused, so the no-NIC device-model guard runs
        // before the child executes anything. The claim resumes it only after
        // fresh host channels have been wired.
        Ok(child_io(child_vm_name, child_dir, cpu_grant))
    }

    /// Load and guard a forked child without resuming it. Pool refill uses this
    /// to keep Firecracker and the restored device model outside the claim
    /// latency window.
    ///
    /// Unbounded by construction: a preload runs before any claim, so there is
    /// no admitted plan yet and no grant to bind. What that costs is recorded on
    /// `resume_preloaded_child`, which inherits this VMM rather than starting
    /// one of its own.
    pub(crate) fn restore_fork_paused(
        &self,
        child_vm_name: &str,
        child_dir: &std::path::Path,
    ) -> anyhow::Result<()> {
        let io = self.prepare_fork_load(child_vm_name, child_dir, None)?;
        mvm_vmm::snapshot::guarded_fork_load_paused(&io, child_dir)
            .with_context(|| format!("FC warm-restore for forked child '{child_vm_name}' failed"))
    }
}

/// The API handle a forked child's snapshot load runs through, carrying the
/// child's name and the CPU bound its admitted plan grants so the Firecracker
/// the load starts is born inside the child's own scope.
///
/// A free function so the composition under test is the same one the restore
/// performs: drop the grant here, or drop the bound from the launch, and
/// `a_firecracker_restored_child_is_cpu_bounded_by_its_admitted_grant` goes red.
fn child_io(
    child_vm_name: &str,
    child_dir: &std::path::Path,
    cpu_grant: Option<mvm_contract::grants::CpuGrant>,
) -> super::io::FirecrackerIO {
    super::io::FirecrackerIO::new(child_dir.join("fc.socket")).bounded_by(super::io::RestoreBound {
        machine_id: child_vm_name.to_string(),
        cpu_grant,
    })
}

impl FcForkRestorer {
    /// Stage the child's snapshot and resume it. The fork-restore callback
    /// `fork_vm_full_fc` takes.
    pub fn restore_fork(
        &self,
        child_vm_name: &str,
        child_dir: &std::path::Path,
        cpu_grant: Option<mvm_contract::grants::CpuGrant>,
    ) -> anyhow::Result<()> {
        let io = self.prepare_fork_load(child_vm_name, child_dir, cpu_grant)?;
        mvm_vmm::snapshot::guarded_fork_load_resume(&io, child_dir)
            .with_context(|| format!("FC warm-restore for forked child '{child_vm_name}' failed"))
    }
}

#[cfg(test)]
mod tests {

    fn proc_entry(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            std::fs::write(dir.path().join(name), body).unwrap();
        }
        dir
    }

    #[test]
    fn observe_process_classifies_a_fixture_proc_entry() {
        let firecracker = proc_entry(&[
            ("comm", b"firecracker\n"),
            ("cmdline", b"firecracker\0--api-sock\0/state/a.sock\0"),
        ]);
        let view = observe_process_at(firecracker.path().to_path_buf(), || true).unwrap();
        match view {
            ProcessView::Firecracker { args, cwd } => {
                assert_eq!(
                    args.unwrap(),
                    vec!["firecracker", "--api-sock", "/state/a.sock"]
                );
                assert!(cwd.is_none(), "a fixture carries no cwd symlink");
            }
            other => panic!("expected Firecracker, got {other:?}"),
        }

        let systemd = proc_entry(&[("comm", b"systemd\n")]);
        assert_eq!(
            observe_process_at(systemd.path().to_path_buf(), || true).unwrap(),
            ProcessView::NotFirecracker,
            "a live non-Firecracker comm is positively not ours"
        );

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            observe_process_at(empty.path().to_path_buf(), || false).unwrap(),
            ProcessView::Gone,
            "an unreadable entry for a dead pid is Gone"
        );
        assert_eq!(
            observe_process_at(empty.path().to_path_buf(), || true).unwrap(),
            ProcessView::Hidden,
            "an unreadable entry for a live pid is Hidden, never silently Gone"
        );
    }

    #[test]
    fn split_cmdline_splits_on_nul_and_drops_empty_arguments() {
        assert_eq!(
            split_cmdline(b"firecracker\0--api-sock\0/state/a.sock\0"),
            vec!["firecracker", "--api-sock", "/state/a.sock"]
        );
        assert!(split_cmdline(b"").is_empty());
        assert_eq!(split_cmdline(b"only\0\0"), vec!["only"]);
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    fn firecracker(list: &[&str]) -> ProcessView {
        ProcessView::Firecracker {
            args: Some(args(list)),
            cwd: None,
        }
    }

    #[test]
    fn the_api_socket_on_the_command_line_identifies_the_vm() {
        let mine = std::path::Path::new("/state/vms/vm-a/fc.socket");
        let spawned = firecracker(&[
            "firecracker",
            "--api-sock",
            "/state/vms/vm-a/fc.socket",
            "--enable-pci",
        ]);
        assert!(identity_from(spawned, mine).unwrap());
        let equals = firecracker(&["firecracker", "--api-sock=/state/vms/vm-a/fc.socket"]);
        assert!(identity_from(equals, mine).unwrap());
    }

    /// Only a positively different answer is "not ours": a process that is
    /// gone, is not Firecracker, or serves another VM's socket.
    #[test]
    fn another_vms_firecracker_is_not_this_vms() {
        let mine = std::path::Path::new("/state/vms/vm-a/fc.socket");
        let other = firecracker(&["firecracker", "--api-sock", "/state/vms/vm-b/fc.socket"]);
        assert!(!identity_from(other, mine).unwrap());
        assert!(!identity_from(ProcessView::Gone, mine).unwrap());
        assert!(!identity_from(ProcessView::NotFirecracker, mine).unwrap());
    }

    /// A live process whose identity cannot be confirmed is an error, never
    /// "not ours": a caller would report it stopped while it runs.
    #[test]
    fn an_unconfirmable_identity_is_an_error() {
        let mine = std::path::Path::new("/state/vms/vm-a/fc.socket");
        // `hidepid`: the process exists, its /proc entry is not readable.
        identity_from(ProcessView::Hidden, mine).expect_err("hidden");
        // Firecracker whose command line cannot be read.
        let unreadable = ProcessView::Firecracker {
            args: None,
            cwd: None,
        };
        identity_from(unreadable, mine).expect_err("unreadable cmdline");
        // Firecracker with no --api-sock on its command line.
        identity_from(firecracker(&["firecracker"]), mine).expect_err("no socket");
        identity_from(firecracker(&["firecracker", "--api-sock"]), mine).expect_err("no value");
        // A relative socket and no readable working directory to resolve it.
        let relative = firecracker(&["firecracker", "--api-sock", "vms/vm-a/fc.socket"]);
        identity_from(relative, mine).expect_err("unresolvable relative socket");
    }

    /// Paths are compared after resolving symlinks and relative components,
    /// so `/tmp` against `/private/tmp`, or a relative `MVM_HOME`, is not a
    /// false "not ours".
    #[test]
    fn a_socket_path_through_a_symlink_or_relative_to_cwd_is_the_same_socket() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("vm-a")).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mine = real.join("vm-a/fc.socket");

        let through_link = firecracker(&[
            "firecracker",
            "--api-sock",
            link.join("vm-a/fc.socket").to_str().unwrap(),
        ]);
        assert!(identity_from(through_link, &mine).unwrap());

        let relative = ProcessView::Firecracker {
            args: Some(args(&["firecracker", "--api-sock", "vm-a/fc.socket"])),
            cwd: Some(link.clone()),
        };
        assert!(identity_from(relative, &mine).unwrap());
    }

    #[test]
    fn the_remote_probe_listing_parses_and_never_guesses() {
        assert_eq!(parse_process_listing("gone\n").unwrap(), ProcessView::Gone);
        assert_eq!(
            parse_process_listing("hidden\n").unwrap(),
            ProcessView::Hidden
        );
        assert_eq!(
            parse_process_listing("other\n").unwrap(),
            ProcessView::NotFirecracker
        );
        assert_eq!(
            parse_process_listing("firecracker\ncwd:/w\nfirecracker\n--api-sock\n/s\n").unwrap(),
            ProcessView::Firecracker {
                args: Some(args(&["firecracker", "--api-sock", "/s"])),
                cwd: Some(PathBuf::from("/w")),
            }
        );
        assert_eq!(
            parse_process_listing("firecracker\ncwd:\n!unreadable\n").unwrap(),
            ProcessView::Firecracker {
                args: None,
                cwd: None
            }
        );
        parse_process_listing("").expect_err("empty output is not an answer");
        parse_process_listing("yes\n").expect_err("unknown output is not an answer");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_process_that_is_not_firecracker_serves_no_socket() {
        let socket = std::path::Path::new("/nonexistent/fc.socket");
        assert!(!super::is_firecracker_for_socket(std::process::id(), socket).unwrap());
    }

    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use mvm_vmm::checkpoint::VmFullControl as _;

    /// Firecracker's restore launches through a shell rather than a `Command`,
    /// so its bound reaches the launch *line* as a prefix. This asserts the
    /// prefix the snapshot load will actually use — the same value
    /// `load_snapshot_inner` passes to the launcher — carries the quota.
    #[test]
    fn a_firecracker_restored_child_is_cpu_bounded_by_its_admitted_grant() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let child_dir = scratch.path().join("child-state");
        std::fs::create_dir_all(&child_dir).unwrap();

        let io = child_io(
            "restored-child",
            &child_dir,
            Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
        );

        // Shell-quoted, because Firecracker's launch is a script: the prefix is
        // spliced ahead of the launch line rather than exec'd as argv.
        let prefix = io.restore_scope_prefix(&child_dir, 512);
        let launcher = scratch
            .path()
            .join("bin/systemd-run")
            .canonicalize()
            .expect("fake launcher has an absolute path");
        assert!(
            prefix.starts_with(&format!("'{}'", launcher.display())),
            "{prefix}"
        );
        assert!(prefix.contains("'CPUQuota=150%'"), "{prefix}");
        assert!(prefix.contains("'MemoryMax=768M'"), "{prefix}");
        assert!(prefix.contains("'TasksMax=1024'"), "{prefix}");
        assert!(prefix.trim_end().ends_with("'--'"), "{prefix}");
    }

    /// A plan granting no share adds no CPU quota, but the fresh VMM is still
    /// born inside its memory and task ceilings.
    #[test]
    fn a_restored_child_without_a_grant_is_still_memory_and_task_bounded() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::spawn_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");
        let child_dir = scratch.path().join("child-state");
        std::fs::create_dir_all(&child_dir).unwrap();

        let io = child_io("restored-child", &child_dir, None);

        let prefix = io.restore_scope_prefix(&child_dir, 1024);
        assert!(!prefix.contains("CPUQuota"), "{prefix}");
        assert!(prefix.contains("'MemoryMax=1280M'"), "{prefix}");
        assert!(prefix.contains("restored-child-"), "{prefix}");
    }

    /// The snapshot's memory file is the guest's RAM, so its length sizes the
    /// restored VMM's ceiling — rounded up, never down.
    #[test]
    fn a_snapshot_sizes_its_guest_from_the_memory_file() {
        let dir = tempfile::tempdir().expect("snapshot dir");
        assert_eq!(crate::fc::io::snapshot_guest_memory_mib(dir.path()), 0);
        let mem = std::fs::File::create(
            dir.path()
                .join(mvm_core::crypto::snapshot_hmac::MEM_FILENAME),
        )
        .expect("memory file");
        mem.set_len(512 * 1024 * 1024 + 1).expect("sparse length");
        assert_eq!(crate::fc::io::snapshot_guest_memory_mib(dir.path()), 513);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firecracker_comm_probe_accepts_only_the_exact_process_name() {
        let tmp = tempfile::tempdir().unwrap();
        let comm = tmp.path().join("comm");

        std::fs::write(&comm, "firecracker\n").unwrap();
        assert!(comm_path_is_firecracker(&comm).unwrap());

        std::fs::write(&comm, "firecracker-helper\n").unwrap();
        assert!(!comm_path_is_firecracker(&comm).unwrap());

        std::fs::remove_file(&comm).unwrap();
        assert!(!comm_path_is_firecracker(&comm).unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firecracker_comm_probe_surfaces_non_missing_read_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let error = comm_path_is_firecracker(tmp.path()).unwrap_err();
        assert!(error.to_string().contains("read"), "got: {error}");
    }

    /// `save_memory` requires an absolute path — a relative path would be
    /// misinterpreted by the Firecracker API.
    #[test]
    fn fc_vm_full_control_save_memory_requires_absolute_path() {
        let ctl = FcVmFullControl::new("any");
        let err = ctl
            .save_memory(std::path::Path::new("relative/mem.bin"))
            .unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "error must mention absolute path requirement: {err}"
        );
    }

    /// `extra_content` returns an empty vec when `vmstate.bin` is absent
    /// (before `save_memory` is called, or after a failed capture).
    #[test]
    fn fc_vm_full_control_extra_content_empty_when_no_vmstate() {
        let tmp = tempfile::tempdir().unwrap();
        let ctl = FcVmFullControl::new("any");
        let blobs = ctl.extra_content(tmp.path()).unwrap();
        assert!(
            blobs.is_empty(),
            "extra_content must return empty vec when vmstate.bin is absent"
        );
    }

    /// `extra_content` returns a single blob for `vmstate.bin` when the file
    /// exists, with a non-empty sha256.
    #[test]
    fn fc_vm_full_control_extra_content_returns_vmstate_blob_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(FC_VMSTATE_FILENAME), b"fake-vmstate").unwrap();
        let ctl = FcVmFullControl::new("any");
        let blobs = ctl.extra_content(tmp.path()).unwrap();
        assert_eq!(blobs.len(), 1, "exactly one blob expected for vmstate.bin");
        assert_eq!(blobs[0].name, FC_VMSTATE_FILENAME);
        assert!(!blobs[0].sha256.is_empty(), "sha256 must be non-empty");
    }

    /// `device_anchors` gathers the absolute paths Firecracker has open for
    /// a VM, including optional verity/config/secrets sidecars when they exist.
    #[test]
    fn fc_vm_full_control_device_anchors_collects_present_sidecars() {
        let _g = mvm_vmm::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = socket_short_home();
        env.set("MVM_HOME", tmp.path());

        let vm_name = "anchor-test";
        let vm_dir = mvm_core::config::vm_state_dir(vm_name);
        let rootfs_parent = vm_dir.join("rootfs");
        std::fs::create_dir_all(&rootfs_parent).unwrap();
        let rootfs = rootfs_parent.join("rootfs.ext4");
        std::fs::File::create(&rootfs).unwrap();
        std::fs::File::create(rootfs_parent.join("rootfs.verity")).unwrap();
        std::fs::File::create(vm_dir.join("config.ext4")).unwrap();
        // secrets.ext4 intentionally absent.

        let meta = serde_json::json!({
            "mode": "attached",
            "rootfs_path": rootfs.to_string_lossy(),
        });
        std::fs::write(vm_dir.join("mode.json"), meta.to_string()).unwrap();

        let ctl = FcVmFullControl::new(vm_name);
        let anchors = ctl.device_anchors().unwrap();
        assert_eq!(anchors.rootfs, rootfs);
        assert_eq!(
            anchors.rootfs_verity,
            Some(rootfs_parent.join("rootfs.verity"))
        );
        assert_eq!(anchors.config, Some(vm_dir.join("config.ext4")));
        assert_eq!(anchors.secrets, None);
        assert_eq!(
            anchors.vsock,
            std::path::PathBuf::from(crate::fc::firecracker_vsock_uds_path(
                &vm_dir.to_string_lossy()
            ))
        );
    }

    /// `device_anchors` fails with a clear message when the VM has no persisted
    /// mode.json (e.g. it was never started with runtime metadata tracking).
    #[test]
    fn fc_vm_full_control_device_anchors_errors_when_mode_json_missing() {
        let _g = mvm_vmm::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = socket_short_home();
        env.set("MVM_HOME", tmp.path());

        let ctl = FcVmFullControl::new("no-mode-vm");
        let err = ctl.device_anchors().unwrap_err();
        assert!(
            err.to_string().contains("mode.json"),
            "error must mention missing mode.json: {err}"
        );
    }

    /// A home deep enough to move the sockets out of the state dir cannot be
    /// snapshotted for a fork, and says so rather than recording anchors a
    /// fork would remap wrongly.
    #[test]
    fn fc_vm_full_control_device_anchors_refuses_relocated_sockets() {
        let _g = mvm_vmm::host::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = socket_short_home();
        let deep = tmp.path().join("d".repeat(90));
        env.set("MVM_HOME", &deep);

        let err = FcVmFullControl::new("deep-vm")
            .device_anchors()
            .expect_err("relocated sockets must refuse");
        assert!(err.to_string().contains("MVM_HOME"), "{err}");
    }

    /// A temporary `MVM_HOME` short enough that Firecracker's sockets stay in
    /// the state dir. The platform temp dir is not: on macOS it is deep enough
    /// that they move to the fallback namespace.
    fn socket_short_home() -> tempfile::TempDir {
        tempfile::Builder::new().tempdir_in("/tmp").unwrap()
    }
}

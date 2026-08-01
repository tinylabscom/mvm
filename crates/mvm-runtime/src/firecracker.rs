use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::checkpoint::ContentBlob;

use crate::base::config::*;
use crate::base::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible};
use crate::base::ui;
use mvm_core::config::{ARCH, fc_version, fc_version_short};

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
    let fc_short = fc_version_short();
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
    let result = run_in_vm_stdout(&format!(
        r#"[ -f "/proc/{pid}/comm" ] && [ "$(cat /proc/{pid}/comm)" = "firecracker" ] && echo yes || echo no"#,
    ))?;
    Ok(result.trim() == "yes")
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

impl crate::checkpoint::VmFullControl for FcVmFullControl {
    fn pause(&self) -> Result<()> {
        crate::microvm::pause_vm(&self.vm_name)
            .with_context(|| format!("pausing Firecracker VM '{}'", self.vm_name))
    }

    fn resume(&self) -> Result<()> {
        crate::microvm::resume_vm(&self.vm_name)
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
        crate::microvm::create_snapshot_files(&self.vm_name, &vmstate_path, memory_path)
            .with_context(|| {
                format!(
                    "creating Firecracker snapshot for VM '{}' (vmstate={}, mem={})",
                    self.vm_name,
                    vmstate_path.display(),
                    memory_path.display(),
                )
            })
    }

    fn rootfs_path(&self) -> Result<PathBuf> {
        let meta = crate::base::runtime_meta::read(&self.vm_name)
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

    fn device_anchors(&self) -> anyhow::Result<crate::checkpoint::DeviceAnchors> {
        let vm_dir = crate::microvm::resolve_running_vm_dir(&self.vm_name)
            .with_context(|| format!("resolving VM dir for '{}'", self.vm_name))?;
        let rootfs = self.rootfs_path()?;
        let rootfs_dir = rootfs
            .parent()
            .ok_or_else(|| anyhow::anyhow!("rootfs path has no parent directory"))?;

        let mut anchors = crate::checkpoint::DeviceAnchors {
            rootfs: rootfs.clone(),
            rootfs_verity: None,
            config: None,
            secrets: None,
            vsock: PathBuf::from(crate::microvm::firecracker_vsock_uds_path(&vm_dir)),
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
/// `child_dir`. Implements [`crate::checkpoint::ForkVmFullRestorer`] for the
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

impl crate::checkpoint::ForkVmFullRestorer for FcForkRestorer {
    fn restore_fork(&self, child_vm_name: &str, child_dir: &std::path::Path) -> anyhow::Result<()> {
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
        let anchors: crate::checkpoint::DeviceAnchors =
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
        let child_vm_dir = crate::microvm::resolve_running_vm_dir(child_vm_name)
            .with_context(|| format!("resolving VM dir for child '{child_vm_name}'"))?;
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
        crate::microvm::remap_paths_for_fork(&mappings)
            .context("remapping parent device paths for FC fork")?;

        // The namespace is already active, so preserve the mounted child vsock
        // path while Firecracker loads the cloned VM state. The CLI delivers
        // the real generation token and optional grant after the guest agent
        // becomes reachable.
        //
        // The load leaves vCPUs paused, so the no-NIC device-model guard runs
        // before the child executes anything and the resume happens here — a
        // fork inherits its parent's device model and gets the same check every
        // other restore does.
        let io = crate::vm::instance_snapshot::FirecrackerIO::new(child_dir.join("fc.socket"));
        crate::vm::instance_snapshot::guarded_fork_load_resume(&io, child_dir)
            .with_context(|| format!("FC warm-restore for forked child '{child_vm_name}' failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::VmFullControl as _;
    use mvm_core::util::test_env::TestEnv;

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
        let _g = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
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
            std::path::PathBuf::from(crate::microvm::firecracker_vsock_uds_path(
                &vm_dir.to_string_lossy()
            ))
        );
    }

    /// `device_anchors` fails with a clear message when the VM has no persisted
    /// mode.json (e.g. it was never started with runtime metadata tracking).
    #[test]
    fn fc_vm_full_control_device_anchors_errors_when_mode_json_missing() {
        let _g = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let tmp = tempfile::tempdir().unwrap();
        env.set("MVM_HOME", tmp.path());

        let ctl = FcVmFullControl::new("no-mode-vm");
        let err = ctl.device_anchors().unwrap_err();
        assert!(
            err.to_string().contains("mode.json"),
            "error must mention missing mode.json: {err}"
        );
    }
}

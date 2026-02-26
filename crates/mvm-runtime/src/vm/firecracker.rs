use anyhow::Result;

use crate::config::*;
use crate::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible};
use crate::ui;
use mvm_core::config::{ARCH, fc_version, fc_version_short};

/// Check if Firecracker is installed inside the Lima VM.
pub fn is_installed() -> Result<bool> {
    let output = run_in_vm("command -v firecracker >/dev/null 2>&1")?;
    Ok(output.status.success())
}

/// Check if the jailer binary is installed.
fn jailer_is_installed() -> Result<bool> {
    let output = run_in_vm("command -v jailer >/dev/null 2>&1")?;
    Ok(output.status.success())
}

/// Install Firecracker (and jailer) inside the Lima VM.
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

/// Download kernel and rootfs into ~/microvm/ inside the Lima VM.
pub fn download_assets() -> Result<()> {
    let fc_short = fc_version_short();
    ui::info("Downloading kernel and rootfs...");
    run_in_vm_visible(&format!(
        r#"
        set -euo pipefail
        mkdir -p {dir} && cd {dir}

        if ls vmlinux-* >/dev/null 2>&1; then
            echo '[mvm] Kernel already downloaded.'
        else
            echo '[mvm] Downloading kernel...'
            latest_kernel_key=$(wget "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/{fc_short}/{arch}/vmlinux-5.10&list-type=2" -O - 2>/dev/null \
                | grep -oP '(?<=<Key>)(firecracker-ci/{fc_short}/{arch}/vmlinux-5\.10\.[0-9]{{3}})(?=</Key>)')
            if [ -z "$latest_kernel_key" ]; then
                echo '[mvm] ERROR: Failed to find kernel.' >&2
                exit 1
            fi
            wget --progress=bar:force:noscroll "https://s3.amazonaws.com/spec.ccfc.min/$latest_kernel_key"
            echo '[mvm] Kernel downloaded.'
        fi

        if ls ubuntu-*.squashfs.upstream >/dev/null 2>&1; then
            echo '[mvm] RootFS already downloaded.'
        else
            echo '[mvm] Downloading Ubuntu rootfs...'
            latest_ubuntu_key=$(curl -s "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/{fc_short}/{arch}/ubuntu-&list-type=2" \
                | grep -oP '(?<=<Key>)(firecracker-ci/{fc_short}/{arch}/ubuntu-[0-9]+\.[0-9]+\.squashfs)(?=</Key>)' \
                | sort -V | tail -1)
            if [ -z "$latest_ubuntu_key" ]; then
                echo '[mvm] ERROR: Failed to find rootfs.' >&2
                exit 1
            fi
            ubuntu_version=$(basename $latest_ubuntu_key .squashfs | grep -oE '[0-9]+\.[0-9]+')
            wget --progress=bar:force:noscroll -O "ubuntu-${{ubuntu_version}}.squashfs.upstream" "https://s3.amazonaws.com/spec.ccfc.min/$latest_ubuntu_key"
            echo "[mvm] RootFS downloaded (Ubuntu ${{ubuntu_version}})."
        fi
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
    "rootfs": "$(ls *.ext4 2>/dev/null | tail -1)",
    "ssh_key": "$(ls *.id_rsa 2>/dev/null | tail -1)"
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

/// Check if the Firecracker process is running inside the Lima VM.
pub fn is_running() -> Result<bool> {
    let output = run_in_vm("pgrep -x firecracker >/dev/null 2>&1")?;
    Ok(output.status.success())
}

/// Check if a specific VM's Firecracker process is alive (by PID file path).
/// Uses /proc/<pid>/comm instead of kill -0 because firecracker runs as root.
pub fn is_vm_running(pid_file: &str) -> Result<bool> {
    let result = run_in_vm_stdout(&format!(
        r#"[ -f {pid} ] && p=$(cat {pid}) && [ -f "/proc/$p/comm" ] && [ "$(cat /proc/$p/comm)" = "firecracker" ] && echo yes || echo no"#,
        pid = pid_file,
    ))?;
    Ok(result.trim() == "yes")
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{firecracker, lima};
use crate::config::MICROVM_DIR;
use crate::shell::{run_in_vm, run_in_vm_stdout, run_in_vm_visible};
use crate::ui;

// ---------------------------------------------------------------------------
// Mvmfile.toml config structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MvmImageConfig {
    pub image: ImageSection,
    #[serde(default)]
    pub resources: ResourceSection,
    #[serde(default)]
    pub packages: PackageSection,
    #[serde(default)]
    pub run: Vec<RunSection>,
    #[serde(default)]
    pub volumes: Vec<VolumeSection>,
    #[serde(default)]
    pub services: Vec<ServiceSection>,
}

#[derive(Debug, Deserialize)]
pub struct ImageSection {
    pub name: String,
    #[serde(default = "default_base")]
    pub base: String,
    #[serde(default = "default_disk")]
    pub disk: String,
}

fn default_base() -> String {
    "ubuntu".to_string()
}
fn default_disk() -> String {
    "4G".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ResourceSection {
    #[serde(default = "default_memory")]
    pub memory: u32,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
}

impl Default for ResourceSection {
    fn default() -> Self {
        Self {
            memory: default_memory(),
            cpus: default_cpus(),
        }
    }
}

fn default_memory() -> u32 {
    2048
}
fn default_cpus() -> u32 {
    2
}

#[derive(Debug, Deserialize, Default)]
pub struct PackageSection {
    #[serde(default)]
    pub apt: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RunSection {
    pub command: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VolumeSection {
    pub guest: String,
    pub size: String,
    #[serde(default)]
    pub default_host: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServiceSection {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default = "default_restart")]
    pub restart: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

fn default_restart() -> String {
    "on-failure".to_string()
}

// ---------------------------------------------------------------------------
// Runtime config (for `mvm start --config`)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub cpus: Option<u32>,
    #[serde(default)]
    pub memory: Option<u32>,
    #[serde(default)]
    pub volumes: Vec<RuntimeVolume>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RuntimeVolume {
    pub host: String,
    pub guest: String,
    pub size: String,
    /// Mark the underlying drive read-only at the Firecracker level.
    /// Defaults to false for backwards compatibility with persistent volumes.
    #[serde(default)]
    pub read_only: bool,
}

// ---------------------------------------------------------------------------
// Config discovery and parsing
// ---------------------------------------------------------------------------

/// Find the built-in images directory (e.g., images/openclaw/).
/// Same lookup pattern as config::find_lima_template().
fn find_images_dir() -> Result<PathBuf> {
    let exe_dir = std::env::current_exe()?
        .parent()
        .expect("executable path must have a parent directory")
        .to_path_buf();

    // Next to binary
    let candidate = exe_dir.join("images");
    if candidate.exists() {
        return Ok(candidate);
    }

    // Source tree (development mode)
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest_dir.join("images");
    if candidate.exists() {
        return Ok(candidate);
    }

    anyhow::bail!("Cannot find built-in images directory")
}

/// Find Mvmfile.toml by name (built-in) or path.
///
/// - If `name_or_path` is a directory, look for Mvmfile.toml inside it.
/// - If `name_or_path` is a file, use it directly.
/// - Otherwise, treat it as a built-in image name (e.g., "openclaw").
pub fn find_config(name_or_path: &str) -> Result<(PathBuf, MvmImageConfig)> {
    let path = Path::new(name_or_path);

    // Direct path to a file
    if path.is_file() {
        let config = parse_config(path)?;
        return Ok((path.parent().unwrap_or(path).to_path_buf(), config));
    }

    // Directory containing Mvmfile.toml
    if path.is_dir() {
        let toml_path = path.join("Mvmfile.toml");
        if toml_path.exists() {
            let config = parse_config(&toml_path)?;
            return Ok((path.to_path_buf(), config));
        }
        anyhow::bail!("No Mvmfile.toml found in {}", path.display());
    }

    // Built-in image name
    let images_dir = find_images_dir()?;
    let toml_path = images_dir.join(name_or_path).join("Mvmfile.toml");
    if toml_path.exists() {
        let config = parse_config(&toml_path)?;
        return Ok((
            toml_path
                .parent()
                .expect("toml path must have parent")
                .to_path_buf(),
            config,
        ));
    }

    anyhow::bail!(
        "Image '{}' not found. Looked in:\n  - {}\n  - built-in images at {}",
        name_or_path,
        Path::new(name_or_path).display(),
        images_dir.display(),
    )
}

/// Parse a Mvmfile.toml file.
pub fn parse_config(path: &Path) -> Result<MvmImageConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let config: MvmImageConfig =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(config)
}

/// Parse a runtime config file (for `mvm start --config`).
pub fn parse_runtime_config(path: &str) -> Result<RuntimeConfig> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {}", path))?;
    let config: RuntimeConfig =
        toml::from_str(&content).with_context(|| format!("Failed to parse {}", path))?;
    Ok(config)
}

// ---------------------------------------------------------------------------
// Service unit generation
// ---------------------------------------------------------------------------

/// Generate a systemd .service unit from a ServiceSection.
fn generate_service_unit(svc: &ServiceSection) -> String {
    let after = svc.after.as_deref().unwrap_or("network-online.target");
    let wants = after;

    let env_lines: String = svc
        .env
        .iter()
        .map(|(k, v)| format!("Environment={}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"[Unit]
Description={name}
After={after} ssh.service
Wants={wants}

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'for i in $(seq 1 60); do ip route show default 2>/dev/null | grep -q default && exit 0; sleep 1; done; exit 0'
ExecStart={command}
Restart={restart}
RestartSec=5
{env_lines}

[Install]
WantedBy=multi-user.target
"#,
        name = svc.name,
        after = after,
        wants = wants,
        command = svc.command,
        restart = svc.restart,
        env_lines = env_lines,
    )
}

// ---------------------------------------------------------------------------
// host_init.sh generation
// ---------------------------------------------------------------------------

/// Generate the host_init.sh script from the image config.
/// This script is embedded in the ELF and runs on the host before the VM boots.
fn generate_host_init(config: &MvmImageConfig) -> String {
    let name = &config.image.name;
    let cpus = config.resources.cpus;
    let memory = config.resources.memory;

    // Generate volume creation blocks
    let mut volume_blocks = String::new();
    for vol in &config.volumes {
        let fallback = format!("$HOME/.{}", name);
        let host_default = vol.default_host.as_deref().unwrap_or(fallback.as_str());
        let guest_basename = vol.guest.trim_start_matches('/').replace('/', "-");
        volume_blocks.push_str(&format!(
            r#"
VOL_PATH="{host}/{basename}.img"
if [ ! -e "$VOL_PATH" ]; then
    mkdir -p "$(dirname "$VOL_PATH")"
    echo "[{name}] Creating volume {guest} ({size})..."
    truncate --size {size} "$VOL_PATH.tmp"
    mke2fs -t ext4 -q "$VOL_PATH.tmp"
    mv "$VOL_PATH.tmp" "$VOL_PATH"
fi
DEFAULT_VOLS+=(-v "$VOL_PATH:{guest}:ext4")
"#,
            host = host_default,
            basename = guest_basename,
            name = name,
            guest = vol.guest,
            size = vol.size,
        ));
    }

    format!(
        r##"#!/bin/bash
set -e

CPUS={cpus}
MEMORY={memory}
BAKE_ARGS=()
CLI_VOLS=()
DEFAULT_VOLS=()

# Parse CLI args
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--cpus) CPUS="$2"; shift 2 ;;
        -m|--memory) MEMORY="$2"; shift 2 ;;
        -v|--volume) CLI_VOLS+=("$2"); shift 2 ;;
        --) shift; BAKE_ARGS+=("$@"); break ;;
        *) BAKE_ARGS+=("$1"); shift ;;
    esac
done

# Create default volume disk images
{volume_blocks}

# Use CLI volumes if provided, otherwise defaults
if [ ${{#CLI_VOLS[@]}} -gt 0 ]; then
    for v in "${{CLI_VOLS[@]}}"; do
        IFS=':' read -r host guest size <<< "$v"
        if [ ! -e "$host" ]; then
            mkdir -p "$(dirname "$host")"
            echo "[{name}] Creating volume $guest ($size)..."
            truncate --size "$size" "$host.tmp"
            mke2fs -t ext4 -q "$host.tmp"
            mv "$host.tmp" "$host"
        fi
        BAKE_ARGS+=(-v "$host:$guest:ext4")
    done
else
    BAKE_ARGS+=("${{DEFAULT_VOLS[@]}}")
fi

# Check /dev/kvm
[ -c /dev/kvm ] || {{ echo "ERROR: /dev/kvm not found. KVM is required."; exit 1; }}
[ -r /dev/kvm ] || {{ echo "ERROR: Cannot read /dev/kvm. Check permissions."; exit 1; }}

export BAKE_RUN_VM=1
exec "$BAKE_EXE" --cpus "$CPUS" --memory "$MEMORY" "${{BAKE_ARGS[@]}}"
"##,
        cpus = cpus,
        memory = memory,
        volume_blocks = volume_blocks,
        name = name,
    )
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Repair /dev/null inside the Lima VM if it has wrong permissions or was
/// deleted.  This can happen when a previous `mvm build` was Ctrl-C'd while
/// bind mounts were active, causing `rm -rf` to destroy device nodes through
/// the mount.
fn repair_dev_null() -> Result<()> {
    // Test if /dev/null is writable.  We redirect to /dev/zero so bash won't
    // skip the command if /dev/null itself is broken.
    let check = run_in_vm("test -c /dev/null -a -w /dev/null")?;
    if !check.status.success() {
        ui::warn("Repairing /dev/null in Lima VM...");
        run_in_vm(
            "sudo rm -f /dev/null && sudo mknod /dev/null c 1 3 && sudo chmod 666 /dev/null",
        )?;
    }
    Ok(())
}

/// Ensure the base rootfs (S3 squashfs) and kernel are available and valid.
fn ensure_base_assets() -> Result<()> {
    let sp = ui::spinner("Checking base assets...");

    if !firecracker::has_base_assets()? {
        sp.finish_and_clear();
        ui::info("Downloading base assets...");
        firecracker::download_assets()?;
        return Ok(());
    }

    // Verify squashfs integrity (a previous interrupted build may have corrupted it)
    // Use -l to list all files, which reads inode/directory tables — catches more
    // corruption than -s which only reads the superblock.
    sp.set_message("Validating base rootfs integrity...");
    if !firecracker::validate_rootfs_squashfs()? {
        sp.finish_and_clear();
        ui::warn("Base rootfs is corrupted. Re-downloading...");
        run_in_vm(&format!(
            "rm -f {dir}/ubuntu-*.squashfs.upstream",
            dir = MICROVM_DIR
        ))?;
        firecracker::download_assets()?;
    } else {
        sp.finish_and_clear();
    }
    Ok(())
}

/// Ensure squashfs-tools is available in the Lima VM.
fn ensure_squashfs_tools() -> Result<()> {
    let has_it = run_in_vm("command -v mksquashfs >/dev/null 2>&1")?;
    if !has_it.status.success() {
        ui::info("Installing squashfs-tools...");
        run_in_vm_visible("sudo apt-get update -qq && sudo apt-get install -y squashfs-tools")?;
    }
    Ok(())
}

/// Ensure the bake binary is available in the Lima VM.
fn ensure_bake() -> Result<()> {
    let has_it = run_in_vm(&format!("test -x {dir}/tools/bake", dir = MICROVM_DIR))?;
    if has_it.status.success() {
        return Ok(());
    }

    ui::info("Downloading bake tool...");
    run_in_vm_visible(&format!(
        r#"
        mkdir -p {dir}/tools
        ARCH=$(uname -m)
        if [ "$ARCH" = "aarch64" ]; then BAKE_ARCH="arm64"; else BAKE_ARCH="amd64"; fi

        # Extract bake binary from the container image
        # The bake tool is distributed as a container image at ghcr.io/losfair/bake
        # We pull it with Docker or download the binary directly if available
        if command -v docker >/dev/null 2>&1; then
            CID=$(docker create --platform "linux/$BAKE_ARCH" ghcr.io/losfair/bake:sha-42fbc25 true)
            docker cp "$CID:/opt/bake/bake.$BAKE_ARCH" {dir}/tools/bake
            docker rm "$CID" >/dev/null
        else
            echo "[mvm] Docker not available. Installing Docker to fetch bake..."
            curl -fsSL https://get.docker.com | sudo sh
            sudo usermod -aG docker $(whoami)
            newgrp docker <<EONG
            CID=\$(docker create --platform "linux/$BAKE_ARCH" ghcr.io/losfair/bake:sha-42fbc25 true)
            docker cp "\$CID:/opt/bake/bake.$BAKE_ARCH" {dir}/tools/bake
            docker rm "\$CID" >/dev/null
EONG
        fi

        chmod +x {dir}/tools/bake
        echo "[mvm] bake installed."
        "#,
        dir = MICROVM_DIR,
    ))?;
    Ok(())
}

/// Build a microVM image from a Mvmfile.toml config.
///
/// Returns the path to the built .elf file.
pub fn build(name_or_path: &str, output: Option<&str>) -> Result<String> {
    let (_config_dir, config) = find_config(name_or_path)?;
    let name = &config.image.name;

    lima::require_running()?;

    // Repair /dev/null if a previous interrupted build destroyed it
    repair_dev_null()?;

    // Ensure Firecracker is installed (needed for bake packaging)
    firecracker::install()?;

    // Ensure prerequisites
    ensure_base_assets()?;
    ensure_squashfs_tools()?;

    // Phase 1: Build rootfs via chroot
    ui::info(&format!("Building image '{}'...", name));

    // Build the apt-get install line
    let packages = if config.packages.apt.is_empty() {
        String::new()
    } else {
        format!(
            "sudo chroot \"$BUILD_DIR\" env DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=\"--force-confdef\" -o Dpkg::Options::=\"--force-confold\" {}",
            config.packages.apt.join(" ")
        )
    };

    // Build the run commands
    let run_commands: String = config
        .run
        .iter()
        .map(|r| {
            format!(
                "echo '[mvm] Running: {}...'\nsudo chroot \"$BUILD_DIR\" env DEBIAN_FRONTEND=noninteractive bash -c '{}'",
                r.command.chars().take(60).collect::<String>(),
                r.command.replace('\'', "'\\''"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Build the service injection
    let service_injection: String = config
        .services
        .iter()
        .map(|svc| {
            let unit = generate_service_unit(svc);
            format!(
                r#"
sudo tee "$BUILD_DIR/etc/systemd/system/{name}.service" > /dev/null << 'SVCEOF'
{unit}
SVCEOF
sudo chroot "$BUILD_DIR" systemctl enable {name}.service 2>/dev/null || true
"#,
                name = svc.name,
                unit = unit,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Phase 1: chroot build
    run_in_vm_visible(&format!(
        r#"
set -euo pipefail
BUILD_DIR="$HOME/microvm/build-{name}"
IMAGES_DIR="$HOME/microvm/images"
mkdir -p "$IMAGES_DIR"

# Clean previous build (unmount any leftover bind mounts first)
# NOTE: Do NOT redirect to /dev/null here — if a previous interrupted build
# destroyed /dev/null via the bind mount, the redirect fails and bash skips
# the umount entirely, making the next rm -rf even more destructive.
if [ -d "$BUILD_DIR" ]; then
    sudo umount "$BUILD_DIR/dev/pts" 2>/dev/zero || true
    sudo umount "$BUILD_DIR/dev" 2>/dev/zero || true
    sudo umount "$BUILD_DIR/sys" 2>/dev/zero || true
    sudo umount "$BUILD_DIR/proc" 2>/dev/zero || true
    # Safety: verify no bind mounts remain before removing
    if mountpoint -q "$BUILD_DIR/dev" 2>/dev/zero; then
        echo "[mvm] ERROR: $BUILD_DIR/dev is still mounted. Aborting cleanup." >&2
        exit 1
    fi
    sudo rm -rf "$BUILD_DIR"
fi

# Extract base rootfs
SQUASHFS=$(ls $HOME/microvm/ubuntu-*.squashfs.upstream 2>/dev/null | tail -1)
if [ -z "$SQUASHFS" ]; then
    echo "[mvm] ERROR: No base rootfs found. Run 'mvmctl setup' first." >&2
    exit 1
fi
echo "[mvm] Extracting base rootfs..."
sudo unsquashfs -d "$BUILD_DIR" "$SQUASHFS"

# Bind mount for chroot
sudo mount --bind /proc "$BUILD_DIR/proc"
sudo mount --bind /sys "$BUILD_DIR/sys"
sudo mount --bind /dev "$BUILD_DIR/dev"
sudo mount --bind /dev/pts "$BUILD_DIR/dev/pts"

cleanup() {{
    sudo umount "$BUILD_DIR/dev/pts" 2>/dev/zero || true
    sudo umount "$BUILD_DIR/dev" 2>/dev/zero || true
    sudo umount "$BUILD_DIR/sys" 2>/dev/zero || true
    sudo umount "$BUILD_DIR/proc" 2>/dev/zero || true
}}
trap cleanup EXIT

# Set up resolv.conf for network access inside chroot
sudo cp /etc/resolv.conf "$BUILD_DIR/etc/resolv.conf" 2>/dev/null || true

# Ensure /tmp is writable inside chroot (needed by apt for GPG temp files)
sudo chmod 1777 "$BUILD_DIR/tmp"

# Ensure apt cache directories exist inside chroot
sudo mkdir -p "$BUILD_DIR/var/cache/apt/archives/partial"
sudo mkdir -p "$BUILD_DIR/var/lib/apt/lists/partial"
sudo mkdir -p "$BUILD_DIR/var/log/apt"

# Suppress all interactive prompts during package installation
export DEBIAN_FRONTEND=noninteractive

# Install packages
echo "[mvm] Installing packages..."
sudo chroot "$BUILD_DIR" env DEBIAN_FRONTEND=noninteractive apt-get update -qq
{packages}

# Configure SSH
echo "[mvm] Configuring SSH..."
sudo chroot "$BUILD_DIR" env DEBIAN_FRONTEND=noninteractive bash -c '
    apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" openssh-server 2>/dev/null || true
    mkdir -p /run/sshd /root/.ssh
    chmod 700 /root/.ssh
    sed -i "s/#PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config
    sed -i "s/#PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config
'

# Run custom commands
{run_commands}

# Inject systemd services
{service_injection}

# Generate SSH keypair
echo "[mvm] Generating SSH keys..."
rm -f "$IMAGES_DIR/{name}.id_rsa" "$IMAGES_DIR/{name}.id_rsa.pub"
ssh-keygen -f "$IMAGES_DIR/{name}.id_rsa" -N '' -q
sudo mkdir -p "$BUILD_DIR/root/.ssh"
sudo cp "$IMAGES_DIR/{name}.id_rsa.pub" "$BUILD_DIR/root/.ssh/authorized_keys"
sudo chown -R root:root "$BUILD_DIR/root/.ssh"
rm -f "$IMAGES_DIR/{name}.id_rsa.pub"

# Clean up chroot mounts
cleanup
trap - EXIT

echo "[mvm] Phase 1 complete: rootfs built."
        "#,
        name = name,
        packages = packages,
        run_commands = run_commands,
        service_injection = service_injection,
    ))?;

    // Phase 2: Create squashfs
    ui::info("Creating squashfs...");
    run_in_vm_visible(&format!(
        r#"
set -euo pipefail
BUILD_DIR="$HOME/microvm/build-{name}"
IMAGES_DIR="$HOME/microvm/images"

sudo mksquashfs "$BUILD_DIR" "$IMAGES_DIR/{name}.squashfs" -comp zstd -noappend
sudo rm -rf "$BUILD_DIR"
echo "[mvm] Phase 2 complete: squashfs created."
        "#,
        name = name,
    ))?;

    // Generate host_init.sh
    let host_init = generate_host_init(&config);
    // Write it into the Lima VM
    run_in_vm(&format!(
        r#"cat > $HOME/microvm/images/{name}.host_init.sh << 'HOSTINITEOF'
{host_init}
HOSTINITEOF
chmod +x $HOME/microvm/images/{name}.host_init.sh"#,
        name = name,
        host_init = host_init,
    ))?;

    // Phase 3: Package with bake
    ui::info("Packaging with bake...");
    ensure_bake()?;

    run_in_vm_visible(&format!(
        r#"
set -euo pipefail
IMAGES_DIR="$HOME/microvm/images"
BAKE="$HOME/microvm/tools/bake"
KERNEL=$(ls $HOME/microvm/vmlinux-* 2>/dev/null | tail -1)
FC=$(which firecracker)

if [ -z "$KERNEL" ]; then
    echo "[mvm] ERROR: No kernel found." >&2
    exit 1
fi

"$BAKE" \
    --input "$BAKE" \
    --kernel "$KERNEL" \
    --firecracker "$FC" \
    --rootfs "$IMAGES_DIR/{name}.squashfs" \
    --entrypoint /sbin/init \
    --init-script "$IMAGES_DIR/{name}.host_init.sh" \
    --output "$IMAGES_DIR/{name}.$(uname -m).elf"

echo ""
echo "[mvm] Build complete!"
ls -lh "$IMAGES_DIR/{name}.$(uname -m).elf"
        "#,
        name = name,
    ))?;

    // Get the default path inside the Lima VM
    let vm_elf_path = run_in_vm_stdout(&format!(
        "echo $HOME/microvm/images/{name}.$(uname -m).elf",
        name = name,
    ))?;

    // If --output was given, copy the ELF to the requested host path
    let final_path = if let Some(out) = output {
        use std::process::Command;
        let status = Command::new("limactl")
            .args([
                "copy",
                &format!("{}:{}", crate::config::VM_NAME, vm_elf_path.trim()),
                out,
            ])
            .status()
            .context("Failed to copy ELF from Lima VM")?;
        if !status.success() {
            anyhow::bail!("Failed to copy ELF to {}", out);
        }
        out.to_string()
    } else {
        vm_elf_path
    };

    Ok(final_path)
}

// ---------------------------------------------------------------------------
// Read-only host-directory volume images (used by `mvmctl exec --add-dir`)
// ---------------------------------------------------------------------------

/// Build a read-only ext4 image populated with the contents of a host
/// directory.
///
/// Used by `mvmctl exec --add-dir host:guest` to share a host directory
/// into a transient microVM without virtio-fs. The image is created inside
/// the Linux build environment (Lima VM on macOS, host on Linux) and sized
/// from the directory's actual contents plus headroom.
///
/// `host_dir` must already be reachable inside the Linux build environment
/// (Lima auto-mounts the host home; Linux passes paths through directly).
/// `label` is used as the ext4 volume label (max 16 chars, ASCII).
/// `dest_image_path` is where the resulting `.ext4` file is written.
///
/// Returns the absolute image path on success.
pub fn build_dir_image_ro(host_dir: &str, label: &str, dest_image_path: &str) -> Result<String> {
    if label.is_empty()
        || label.len() > 16
        || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        anyhow::bail!("ext4 label '{label}' must be 1-16 ASCII alphanumeric/dash chars",);
    }
    let parent = std::path::Path::new(dest_image_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let mkdir_parent = if parent.is_empty() {
        String::new()
    } else {
        format!("mkdir -p {parent}")
    };

    // Compute size: directory content + 8 MiB headroom + 16 MiB minimum,
    // rounded up to the next 4-MiB boundary so mkfs.ext4 is happy.
    // We do this inside the Linux env so `du` sees the same view as `cp`.
    let script = format!(
        r#"
        set -e
        {mkdir_parent}
        rm -f {dest}
        SRC_KB=$(du -sk {src} 2>/dev/null | awk '{{print $1}}')
        SIZE_MIB=$(( (SRC_KB / 1024) + 8 ))
        if [ "$SIZE_MIB" -lt 16 ]; then SIZE_MIB=16; fi
        SIZE_MIB=$(( ((SIZE_MIB + 3) / 4) * 4 ))
        truncate -s "${{SIZE_MIB}}M" {dest}
        mkfs.ext4 -q -L {label} {dest}

        MOUNT_DIR=$(mktemp -d)
        sudo mount {dest} "$MOUNT_DIR"
        if [ -d {src} ]; then
            sudo cp -aT {src} "$MOUNT_DIR" 2>/dev/null || true
        else
            sudo cp -a {src} "$MOUNT_DIR/" 2>/dev/null || true
        fi
        sudo umount "$MOUNT_DIR"
        rmdir "$MOUNT_DIR"
        chmod 0644 {dest}
        "#,
        mkdir_parent = mkdir_parent,
        src = host_dir,
        dest = dest_image_path,
        label = label,
    );

    run_in_vm(&script).with_context(|| {
        format!("building read-only ext4 image from '{host_dir}' at '{dest_image_path}'")
    })?;
    Ok(dest_image_path.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dir_image_ro_rejects_oversized_label() {
        let err = build_dir_image_ro("/tmp/x", "this-label-is-too-long-by-far", "/tmp/x.ext4")
            .unwrap_err();
        assert!(err.to_string().contains("ext4 label"));
    }

    #[test]
    fn build_dir_image_ro_rejects_invalid_chars() {
        let err = build_dir_image_ro("/tmp/x", "extra/0", "/tmp/x.ext4").unwrap_err();
        assert!(err.to_string().contains("ext4 label"));
    }

    #[test]
    fn build_dir_image_ro_rejects_empty_label() {
        let err = build_dir_image_ro("/tmp/x", "", "/tmp/x.ext4").unwrap_err();
        assert!(err.to_string().contains("ext4 label"));
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[image]
name = "test"
"#;
        let config: MvmImageConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.image.name, "test");
        assert_eq!(config.image.base, "ubuntu");
        assert_eq!(config.image.disk, "4G");
        assert_eq!(config.resources.memory, 2048);
        assert_eq!(config.resources.cpus, 2);
        assert!(config.packages.apt.is_empty());
        assert!(config.run.is_empty());
        assert!(config.volumes.is_empty());
        assert!(config.services.is_empty());
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
[image]
name = "openclaw"
base = "ubuntu"
disk = "4G"

[resources]
memory = 4096
cpus = 4

[packages]
apt = ["curl", "wget"]

[[run]]
command = "echo hello"

[[run]]
command = "echo world"

[[volumes]]
guest = "/data"
size = "2G"
default_host = "~/.mydata"

[[services]]
name = "myservice"
command = "/usr/bin/myapp"
after = "network-online.target"
restart = "always"
"#;
        let config: MvmImageConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.image.name, "openclaw");
        assert_eq!(config.resources.memory, 4096);
        assert_eq!(config.resources.cpus, 4);
        assert_eq!(config.packages.apt, vec!["curl", "wget"]);
        assert_eq!(config.run.len(), 2);
        assert_eq!(config.volumes.len(), 1);
        assert_eq!(config.volumes[0].guest, "/data");
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.services[0].name, "myservice");
    }

    #[test]
    fn test_generate_service_unit() {
        let svc = ServiceSection {
            name: "test".to_string(),
            command: "/usr/bin/test".to_string(),
            after: Some("network.target".to_string()),
            restart: "always".to_string(),
            env: HashMap::from([("HOME".to_string(), "/root".to_string())]),
        };
        let unit = generate_service_unit(&svc);
        assert!(unit.contains("Description=test"));
        assert!(unit.contains("ExecStart=/usr/bin/test"));
        assert!(unit.contains("After=network.target"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("Environment=HOME=/root"));
    }

    #[test]
    fn test_generate_host_init() {
        let config = MvmImageConfig {
            image: ImageSection {
                name: "test".to_string(),
                base: "ubuntu".to_string(),
                disk: "4G".to_string(),
            },
            resources: ResourceSection {
                memory: 2048,
                cpus: 2,
            },
            packages: PackageSection::default(),
            run: vec![],
            volumes: vec![VolumeSection {
                guest: "/data".to_string(),
                size: "2G".to_string(),
                default_host: Some("~/.testdata".to_string()),
            }],
            services: vec![],
        };
        let script = generate_host_init(&config);
        assert!(script.contains("CPUS=2"));
        assert!(script.contains("MEMORY=2048"));
        assert!(script.contains("/data"));
        assert!(script.contains("2G"));
        assert!(script.contains("BAKE_RUN_VM=1"));
    }

    #[test]
    fn test_parse_runtime_config() {
        let toml = r#"
cpus = 4
memory = 4096

[[volumes]]
host = "~/.mydata"
guest = "/data"
size = "8G"
"#;
        let config: RuntimeConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.cpus, Some(4));
        assert_eq!(config.memory, Some(4096));
        assert_eq!(config.volumes.len(), 1);
        assert_eq!(config.volumes[0].host, "~/.mydata");
    }

    #[test]
    fn test_parse_empty_runtime_config() {
        let toml = "";
        let config: RuntimeConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.cpus, None);
        assert_eq!(config.memory, None);
        assert!(config.volumes.is_empty());
    }

    #[test]
    fn test_find_builtin_config() {
        // Should find the built-in openclaw config in the source tree
        let result = find_config("openclaw");
        if let Ok((dir, config)) = result {
            assert_eq!(config.image.name, "openclaw");
            assert!(dir.ends_with("openclaw"));
        }
    }

    #[test]
    fn test_find_builtin_example_config() {
        let result = find_config("example");
        if let Ok((dir, config)) = result {
            assert_eq!(config.image.name, "example");
            assert_eq!(config.resources.memory, 1024);
            assert_eq!(config.resources.cpus, 1);
            assert_eq!(config.packages.apt.len(), 6);
            assert_eq!(config.run.len(), 2);
            assert_eq!(config.volumes.len(), 1);
            assert_eq!(config.volumes[0].guest, "/data");
            assert_eq!(config.services.len(), 1);
            assert_eq!(config.services[0].name, "myapp");
            assert!(dir.ends_with("example"));
        }
    }
}

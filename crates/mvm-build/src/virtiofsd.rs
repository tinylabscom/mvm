//! Shared `virtiofsd` spawning helpers for QEMU-backed paths.
//!
//! Both the builder VM (`qemu_builder`) and the workload QEMU driver need to
//! start one `virtiofsd` process per virtio-fs share before launching QEMU,
//! then tear them down when the VM exits. This module isolates that logic so
//! both callers share one implementation.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Which `virtiofsd` implementation is installed. The two share the
/// `--socket-path` flag but nothing else: the QEMU-bundled **C** daemon takes
/// `-o source=DIR` and sandboxes with `-o sandbox=...`; the standalone **Rust**
/// daemon takes `--shared-dir=DIR --sandbox ...`. Detect once and build the
/// right argv per flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtiofsdFlavor {
    /// QEMU-bundled C virtiofsd (`-o source=`).
    C,
    /// Standalone Rust virtiofsd (`--shared-dir=`).
    Rust,
}

/// Locate a `virtiofsd` binary and detect its flavour.
pub fn locate_virtiofsd() -> Result<(PathBuf, VirtiofsdFlavor)> {
    let bin = [
        "/usr/lib/qemu/virtiofsd",
        "/usr/libexec/virtiofsd",
        "/usr/lib/virtiofsd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
    .or_else(|| which::which("virtiofsd").ok())
    .ok_or_else(|| {
        anyhow::anyhow!(
            "`virtiofsd` not found (looked in /usr/lib/qemu, /usr/libexec, /usr/lib, and \
             $PATH). Install it (`apt install virtiofsd`; it also ships alongside \
             qemu-system on many distros)."
        )
    })?;
    let flavor = detect_virtiofsd_flavor(&bin)?;
    Ok((bin, flavor))
}

fn detect_virtiofsd_flavor(bin: &Path) -> Result<VirtiofsdFlavor> {
    let out = Command::new(bin)
        .arg("--help")
        .output()
        .with_context(|| format!("probing {} --help", bin.display()))?;
    let help = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if help.contains("--shared-dir") {
        Ok(VirtiofsdFlavor::Rust)
    } else {
        Ok(VirtiofsdFlavor::C)
    }
}

/// Owns the per-share `virtiofsd` child processes for one VM.
#[derive(Default)]
pub struct VirtiofsdGuard {
    procs: Vec<(Child, PathBuf)>,
}

/// Parameters for spawning a single `virtiofsd` instance.
///
/// Uses a builder so the call site stays readable as more options accrue.
pub struct SpawnParams<'a> {
    pub bin: &'a Path,
    pub flavor: VirtiofsdFlavor,
    pub tag: &'a str,
    pub sock: &'a Path,
    pub dir: &'a Path,
    pub read_only: bool,
    pub dax: bool,
}

impl<'a> SpawnParams<'a> {
    pub fn new(
        bin: &'a Path,
        flavor: VirtiofsdFlavor,
        tag: &'a str,
        sock: &'a Path,
        dir: &'a Path,
    ) -> Self {
        Self {
            bin,
            flavor,
            tag,
            sock,
            dir,
            read_only: false,
            dax: false,
        }
    }

    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    pub fn dax(mut self, dax: bool) -> Self {
        self.dax = dax;
        self
    }
}

impl VirtiofsdGuard {
    /// Spawn a `virtiofsd` exporting `dir` on the unix socket `sock`.
    pub fn spawn(&mut self, params: SpawnParams<'_>) -> Result<()> {
        let SpawnParams {
            bin,
            flavor,
            tag,
            sock,
            dir,
            read_only,
            dax,
        } = params;
        let _ = std::fs::remove_file(sock);
        let mut cmd = Command::new(bin);
        cmd.arg(format!("--socket-path={}", sock.display()));
        match flavor {
            VirtiofsdFlavor::Rust => {
                cmd.arg(format!("--shared-dir={}", dir.display()))
                    .args(["--sandbox", "none"]);
                if read_only {
                    cmd.arg("--readonly");
                }
                if dax {
                    // DAX acceleration requires the daemon to keep host pages
                    // mapped and answer FUSE_SETUPMAPPING.
                    cmd.args(["--cache", "always"]);
                }
            }
            VirtiofsdFlavor::C => {
                let mut opt = format!("source={}", dir.display());
                if read_only {
                    opt.push_str(",readonly");
                }
                cmd.arg("-o").arg(opt);
                if dax {
                    cmd.arg("-o").arg("cache=always");
                }
            }
        }
        let child = cmd
            .spawn()
            .with_context(|| format!("spawning {} for tag {tag}", bin.display()))?;
        self.procs.push((child, sock.to_path_buf()));
        wait_for_socket(sock, Duration::from_secs(10)).with_context(|| {
            format!(
                "virtiofsd for tag {tag} never created its socket {}",
                sock.display()
            )
        })?;
        Ok(())
    }
}

impl Drop for VirtiofsdGuard {
    fn drop(&mut self) {
        for (child, sock) in &mut self.procs {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(sock);
        }
    }
}

fn wait_for_socket(sock: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if sock.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("timed out after {timeout:?}")
}

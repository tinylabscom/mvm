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
use mvm_contract::builder::BuilderError;

/// Which `virtiofsd` implementation is installed. The two share the
/// `--socket-path` flag but nothing else: the QEMU-bundled **C** daemon takes
/// `-o source=DIR` and `-o sandbox=...`; the standalone **Rust** daemon takes
/// `--shared-dir=DIR --sandbox ...`. Both are explicitly confined with Linux
/// namespaces; detect once and build the right argv per flavour.
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
    /// Start building a [`SpawnParams`]. Every value is set by name, so a
    /// call site cannot transpose two fields that share a type.
    #[must_use]
    pub fn builder() -> SpawnParamsBuilder<'a> {
        SpawnParamsBuilder::new()
    }
}

/// Builder for [`SpawnParams`]. Required fields are checked by
/// [`SpawnParamsBuilder::build`] rather than defaulted, so an unset one is a
/// reported error and never a silently empty value.
pub struct SpawnParamsBuilder<'a> {
    bin: Option<&'a Path>,
    flavor: Option<VirtiofsdFlavor>,
    tag: Option<&'a str>,
    sock: Option<&'a Path>,
    dir: Option<&'a Path>,
    read_only: Option<bool>,
    dax: Option<bool>,
}

impl<'a> SpawnParamsBuilder<'a> {
    /// An empty builder: nothing set yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bin: None,
            flavor: None,
            tag: None,
            sock: None,
            dir: None,
            read_only: None,
            dax: None,
        }
    }

    /// Set `bin`.
    #[must_use]
    pub fn bin(mut self, bin: &'a Path) -> Self {
        self.bin = Some(bin);
        self
    }

    /// Set `flavor`.
    #[must_use]
    pub fn flavor(mut self, flavor: VirtiofsdFlavor) -> Self {
        self.flavor = Some(flavor);
        self
    }

    /// Set `tag`.
    #[must_use]
    pub fn tag(mut self, tag: &'a str) -> Self {
        self.tag = Some(tag);
        self
    }

    /// Set `sock`.
    #[must_use]
    pub fn sock(mut self, sock: &'a Path) -> Self {
        self.sock = Some(sock);
        self
    }

    /// Set `dir`.
    #[must_use]
    pub fn dir(mut self, dir: &'a Path) -> Self {
        self.dir = Some(dir);
        self
    }

    /// Set `read_only`.
    #[must_use]
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = Some(read_only);
        self
    }

    /// Set `dax`.
    #[must_use]
    pub fn dax(mut self, dax: bool) -> Self {
        self.dax = Some(dax);
        self
    }

    /// Finish, or name the first required field left unset.
    pub fn build(self) -> Result<SpawnParams<'a>, BuilderError> {
        Ok(SpawnParams {
            bin: self
                .bin
                .ok_or(BuilderError::missing("SpawnParams", "bin"))?,
            flavor: self
                .flavor
                .ok_or(BuilderError::missing("SpawnParams", "flavor"))?,
            tag: self
                .tag
                .ok_or(BuilderError::missing("SpawnParams", "tag"))?,
            sock: self
                .sock
                .ok_or(BuilderError::missing("SpawnParams", "sock"))?,
            dir: self
                .dir
                .ok_or(BuilderError::missing("SpawnParams", "dir"))?,
            read_only: self
                .read_only
                .ok_or(BuilderError::missing("SpawnParams", "read_only"))?,
            dax: self
                .dax
                .ok_or(BuilderError::missing("SpawnParams", "dax"))?,
        })
    }
}

impl<'a> Default for SpawnParamsBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
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
        configure_command(&mut cmd, flavor, sock, dir, read_only, dax);
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

fn configure_command(
    cmd: &mut Command,
    flavor: VirtiofsdFlavor,
    sock: &Path,
    dir: &Path,
    read_only: bool,
    dax: bool,
) {
    cmd.arg(format!("--socket-path={}", sock.display()));
    match flavor {
        VirtiofsdFlavor::Rust => {
            cmd.arg(format!("--shared-dir={}", dir.display()))
                .args(["--sandbox", "namespace"]);
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
            cmd.arg("-o").arg(opt).arg("-o").arg("sandbox=namespace");
            if dax {
                cmd.arg("-o").arg("cache=always");
            }
        }
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

#[cfg(test)]
mod spawn_params_builder_tests {
    use super::*;

    fn args_for(flavor: VirtiofsdFlavor) -> Vec<String> {
        let mut command = Command::new("virtiofsd");
        configure_command(
            &mut command,
            flavor,
            Path::new("/tmp/virtiofs.sock"),
            Path::new("/workspace"),
            true,
            true,
        );
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    /// An empty builder must refuse to finish, naming the first
    /// required field it is missing — never substituting a default.
    #[test]
    fn an_empty_builder_names_the_first_missing_field() {
        let Err(err) = SpawnParams::builder().build() else {
            panic!("an empty SpawnParams builder must not build");
        };
        assert_eq!(err, BuilderError::missing("SpawnParams", "bin"));
    }

    #[test]
    fn rust_daemon_is_explicitly_namespace_sandboxed() {
        assert_eq!(
            args_for(VirtiofsdFlavor::Rust),
            [
                "--socket-path=/tmp/virtiofs.sock",
                "--shared-dir=/workspace",
                "--sandbox",
                "namespace",
                "--readonly",
                "--cache",
                "always",
            ]
        );
    }

    #[test]
    fn c_daemon_is_explicitly_namespace_sandboxed() {
        assert_eq!(
            args_for(VirtiofsdFlavor::C),
            [
                "--socket-path=/tmp/virtiofs.sock",
                "-o",
                "source=/workspace,readonly",
                "-o",
                "sandbox=namespace",
                "-o",
                "cache=always",
            ]
        );
    }
}

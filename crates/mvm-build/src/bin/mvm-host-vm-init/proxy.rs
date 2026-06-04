//! Egress-proxy lifecycle hook for the application-deps install
//! pipeline (Plan 73 Followup B.2.x, ADR-047 §"Build-time gates"
//! → "Registry allowlist").
//!
//! `mvm-host-vm-init` runs the installer (`uv` / `pnpm`) with
//! `HTTP_PROXY` + `HTTPS_PROXY` pointing at `mvm-egress-proxy`,
//! which sits between the installer and the network and refuses
//! anything outside ADR-047's four-hostname allowlist.
//!
//! The proxy is a separate Linux binary
//! (`crates/mvm-egress-proxy`); we drive it as a subprocess:
//!
//! 1. **Spawn** at install start — bind `127.0.0.1:8443`.
//! 2. **Wait for ready** — TCP-connect-probe up to 2s.
//! 3. **Inject env** into the installer's command: `HTTP_PROXY` +
//!    `HTTPS_PROXY` set to `http://127.0.0.1:8443`. (`HTTPS_PROXY`
//!    is what `uv`/`pip`/`pnpm` honor for HTTPS fetches; both keys
//!    are set so any case-insensitive variant is covered.)
//! 4. **Shutdown** after the installer exits — SIGTERM, wait up to
//!    1s, then SIGKILL.
//!
//! The lifecycle abstraction is split into a [`ProxyLifecycle`]
//! trait so unit tests can supply a noop / fake controller. The
//! production implementation [`ChildProxyLifecycle`] shells out to
//! `mvm-egress-proxy`; tests use [`NoopProxyLifecycle`] (does
//! nothing) or [`FakeProxyLifecycle`] (records start/stop calls).
//!
//! ## Future B.2.y — complementary iptables drop-rule
//!
//! The proxy is currently the only enforcement mechanism. A future
//! followup will add a defense-in-depth iptables rule that drops
//! outbound traffic *not* originating from the proxy's UID, so a
//! pathological installer that ignores `HTTPS_PROXY` can't slip
//! around the allowlist. Tracked as B.2.y in plan 73.

use std::net::{SocketAddr, TcpStream};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Where the in-VM proxy listens. mvm-egress-proxy's
/// `DEFAULT_BIND` constant; duplicated here so we don't pull the
/// proxy crate into our dep closure just to share a string.
pub const PROXY_BIND_ADDR: &str = "127.0.0.1:8443";

/// Proxy URL the installer sees in `HTTP_PROXY` / `HTTPS_PROXY`.
pub const PROXY_URL: &str = "http://127.0.0.1:8443";

/// Lifecycle hook trait. The installer's pre/post-spawn dance
/// goes through this so tests can verify the proxy was started +
/// stopped without binding a real socket.
pub trait ProxyLifecycle {
    /// Start the proxy. Called before the installer spawns.
    /// Returns `Ok(())` once the proxy is listening; the caller
    /// then sets `HTTP_PROXY` / `HTTPS_PROXY` and spawns the
    /// installer.
    fn start(&mut self) -> Result<(), String>;

    /// Stop the proxy. Called after the installer exits. Best-
    /// effort — a failure here is logged but doesn't fail the
    /// install (the volume artifacts are already on disk).
    fn stop(&mut self);

    /// Whether the lifecycle's start() succeeded. Used to decide
    /// whether to inject `HTTPS_PROXY` env into the installer:
    /// if the proxy didn't come up, the installer runs without
    /// proxy env vars + the host treats the volume as compromised
    /// via a separate gate. (Currently the proxy is hard-required;
    /// future B.2.y may relax this for offline-only builds.)
    fn is_running(&self) -> bool;
}

/// Production lifecycle — spawns `mvm-egress-proxy` as a child
/// process. The binary's location defaults to `PATH` lookup; the
/// builder VM flake (`nix/images/builder-vm/flake.nix`) installs
/// it at `/sbin/mvm-egress-proxy` and prepends `/sbin` to PATH
/// via the standard kernel default. Set `program` explicitly to
/// override for tests / staging builds.
pub struct ChildProxyLifecycle {
    program: PathBuf,
    child: Option<Child>,
    started: bool,
}

impl ChildProxyLifecycle {
    /// Construct a lifecycle that will spawn `program` (looked up
    /// against PATH if relative) when [`Self::start`] is called.
    pub fn new<P: Into<PathBuf>>(program: P) -> Self {
        Self {
            program: program.into(),
            child: None,
            started: false,
        }
    }

    /// Convenience: lifecycle that spawns the default binary name
    /// (`mvm-egress-proxy`), relying on PATH lookup.
    pub fn default_binary() -> Self {
        Self::new("mvm-egress-proxy")
    }
}

impl ProxyLifecycle for ChildProxyLifecycle {
    fn start(&mut self) -> Result<(), String> {
        if self.started {
            return Ok(());
        }
        let mut cmd = Command::new(&self.program);
        // Inherit stderr so the proxy's ALLOW / DENY log lines
        // land in the same console the host scrapes via libkrun's
        // `krun_set_console_output`. stdout is discarded — the
        // proxy prints one "listening on <addr>" line that's
        // informational, not contractually consumed.
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::inherit());
        // Drop to the dedicated low-priv uid that the in-VM
        // iptables OUTPUT rule matches (Plan 73 Followup B.2.y).
        // Without this the proxy inherits PID 1's uid (root) and
        // the `--uid-owner` rule wouldn't match, so the lockdown
        // would block the proxy too. Linux-only: macOS dev/test
        // builds don't run the lockdown.
        #[cfg(target_os = "linux")]
        cmd.uid(crate::network::PROXY_UID);
        let child = cmd
            .spawn()
            .map_err(|e| format!("spawn `{}`: {e}", self.program.display()))?;
        self.child = Some(child);

        // TCP-probe loop: try to connect to PROXY_BIND_ADDR every
        // 50ms up to 2s. The proxy binds the listener in its main
        // thread before forking the accept loop; the first
        // successful connect means it's accepting.
        let target: SocketAddr = PROXY_BIND_ADDR
            .parse()
            .map_err(|e| format!("parse {PROXY_BIND_ADDR}: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if Instant::now() >= deadline {
                self.stop();
                return Err(format!(
                    "egress proxy did not become ready at {PROXY_BIND_ADDR} within 2s"
                ));
            }
            // Check the child is still alive — early exit means
            // the proxy crashed.
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                return Err(format!(
                    "egress proxy exited before becoming ready (status: {status})"
                ));
            }
            if TcpStream::connect_timeout(&target, Duration::from_millis(200)).is_ok() {
                self.started = true;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // SIGTERM first — the proxy's main loop installs a SIGTERM
        // handler that drops the listener and joins the accept
        // thread cleanly.
        #[cfg(target_os = "linux")]
        {
            // SAFETY: passing a valid pid to libc::kill. Failure
            // is acceptable (the child may have already exited).
            unsafe {
                let _ = libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Non-Linux hosts only see this code path in test
            // builds (the production caller is the libkrun builder
            // VM, which is Linux). `Child::kill()` sends SIGKILL
            // on Unix and `TerminateProcess` on Windows; both are
            // acceptable for the test paths (no graceful-shutdown
            // contract under test). The deadline loop below then
            // observes the exit immediately.
            let _ = child.kill();
        }

        // Wait up to 1s for graceful exit.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.started = false;
                    return;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    eprintln!("mvm-host-vm-init: proxy try_wait failed: {e}");
                    break;
                }
            }
        }

        // SIGKILL fallback.
        eprintln!("mvm-host-vm-init: egress proxy did not exit on SIGTERM, sending SIGKILL");
        let _ = child.kill();
        let _ = child.wait();
        self.started = false;
    }

    fn is_running(&self) -> bool {
        self.started
    }
}

impl Drop for ChildProxyLifecycle {
    fn drop(&mut self) {
        // Belt-and-braces: if the caller forgot to call stop()
        // before the controller drops, kill the child here so we
        // don't leave a zombie proxy listening on 8443.
        self.stop();
    }
}

/// Test-only lifecycle that does nothing. Used by tests that
/// exercise the install pipeline without caring about the proxy
/// side. The installer's env vars are still injected (B.2's
/// install-pipeline tests assert that) but no real socket is
/// bound.
pub struct NoopProxyLifecycle {
    started: bool,
}

impl NoopProxyLifecycle {
    pub fn new() -> Self {
        Self { started: false }
    }
}

impl Default for NoopProxyLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyLifecycle for NoopProxyLifecycle {
    fn start(&mut self) -> Result<(), String> {
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) {
        self.started = false;
    }

    fn is_running(&self) -> bool {
        self.started
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_is_http_127_8443() {
        // Lock the contract — installers honor HTTPS_PROXY env
        // pointing at an HTTP URL (CONNECT tunneling). 127.0.0.1
        // because the proxy + installer share the VM's network
        // namespace.
        assert_eq!(PROXY_URL, "http://127.0.0.1:8443");
        assert_eq!(PROXY_BIND_ADDR, "127.0.0.1:8443");
    }

    #[test]
    fn noop_lifecycle_tracks_started_state() {
        let mut p = NoopProxyLifecycle::new();
        assert!(!p.is_running());
        p.start().unwrap();
        assert!(p.is_running());
        p.stop();
        assert!(!p.is_running());
    }
}

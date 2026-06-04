//! In-process hardening applied before the runtime touches stdin or
//! spawns the language interpreter.
//!
//! The single load-bearing primitive is `prctl(PR_SET_DUMPABLE, 0)` on
//! Linux: combined with mvm's agent-side `RLIMIT_CORE = 0`, this is
//! belt-and-suspenders against in-flight payload bytes hitting a
//! coredump if the runtime or the interpreter crashes (ADR-0009 prod
//! invariants). The seccomp tier is applied agent-side per ADR-007 §6;
//! the runtime does not duplicate it.
//!
//! On non-Linux hosts (the cargo-test path during local development on
//! macOS) the `prctl` shim is a no-op; tests assert the function
//! returns `Ok` regardless. The guest target is always Linux at boot.

use std::io::{self, Read};

#[cfg(target_os = "linux")]
mod platform {
    /// Linux `prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)`. Sets the calling
    /// process's "dumpable" attribute to 0, suppressing coredumps and
    /// `/proc/<pid>/mem` access from non-root processes. Combined with
    /// the agent-side `RLIMIT_CORE = 0`, prevents payload bytes from
    /// ever reaching a coredump file.
    pub fn disable_coredump() -> std::io::Result<()> {
        // SAFETY: `prctl` is a vararg-shaped syscall wrapper; the args
        // we pass are scalars and the call has no out-pointer. A
        // negative return is converted to `Err`.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    /// Non-Linux fallback. The runtime only ships into Linux guests at
    /// boot; this shim exists so `cargo test` on developer hosts
    /// (macOS, including the maintainer's primary dev machine) can
    /// exercise the surrounding control flow without the real
    /// `prctl` syscall.
    pub fn disable_coredump() -> std::io::Result<()> {
        Ok(())
    }
}

/// Apply prod-mode hardening before the first stdin byte is read.
/// Currently a single primitive — the entry point exists so future
/// invariants (e.g. a per-language seccomp tier set guest-side as a
/// follow-up to plan 0003) can land without touching `main.rs`.
pub fn apply_prod_hardening() -> std::io::Result<()> {
    platform::disable_coredump()
}

/// Read stdin to a `Vec<u8>` capped at `cap` bytes. Returns
/// `Err(StdinCapExceeded)` if more bytes are available — preventing
/// the dispatched child from ever seeing a payload over the cap. Reads
/// in chunks so a payload that hits the cap exactly is still accepted.
#[derive(Debug)]
pub enum StdinReadError {
    Io(io::Error),
    CapExceeded,
}

pub fn read_stdin_capped<R: Read>(mut reader: R, cap: usize) -> Result<Vec<u8>, StdinReadError> {
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader.read(&mut chunk).map_err(StdinReadError::Io)?;
        if n == 0 {
            return Ok(buf);
        }
        if buf.len() + n > cap {
            // Best effort: drain to confirm there really is more, then
            // refuse. We prefer a cheap "cap exceeded" surface to
            // letting unbounded bytes flow into the dispatched child.
            return Err(StdinReadError::CapExceeded);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn apply_prod_hardening_returns_ok_on_dev_hosts() {
        // On Linux this calls real prctl; on macOS it's a no-op shim.
        // The assertion is that the surface returns `Ok` in both cases
        // when invoked from a regular cargo test process.
        apply_prod_hardening().expect("hardening succeeds");
    }

    #[test]
    fn reads_full_stdin_under_cap() {
        let payload = b"hello world";
        let got = read_stdin_capped(Cursor::new(&payload[..]), 1024).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn reads_full_stdin_at_exact_cap() {
        let payload = vec![0xab; 1024];
        let got = read_stdin_capped(Cursor::new(&payload[..]), 1024).unwrap();
        assert_eq!(got.len(), 1024);
    }

    #[test]
    fn rejects_stdin_over_cap() {
        let payload = vec![0xab; 1025];
        let err = read_stdin_capped(Cursor::new(&payload[..]), 1024).unwrap_err();
        assert!(matches!(err, StdinReadError::CapExceeded));
    }

    #[test]
    fn empty_stdin_is_ok() {
        let got = read_stdin_capped(Cursor::new(&[][..]), 1024).unwrap();
        assert!(got.is_empty());
    }
}

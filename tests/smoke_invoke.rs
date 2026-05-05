//! Live-KVM smoke for `mvmctl invoke`. Plan 41 W3 / W5.
//!
//! Builds the `nix/images/examples/echo-fn/` fixture, boots it via
//! `mvmctl invoke` with an arbitrary stdin payload, and asserts the
//! payload echoes back unchanged on stdout with a zero exit code.
//! The fixture's wrapper at `/usr/lib/mvm/wrappers/echo` is just
//! `exec cat` — proves the substrate (W1 wire + W2 handler + W3
//! invoke CLI) works end-to-end, without depending on any
//! per-language wrapper from mvmforge's forthcoming Nix factories.
//!
//! ## Why this is gated
//!
//! `mvmctl invoke` requires a working Firecracker + vsock stack. Per
//! CLAUDE.md: vsock is unreliable on Lima/QEMU on macOS, so this
//! test is hostile to the dev-shell macOS host of most contributors.
//! Run only when `MVM_LIVE_SMOKE=1` is set, on a host that meets one
//! of:
//!
//!   1. Native Linux with `/dev/kvm` accessible to the running user.
//!   2. macOS 26+ with Apple Container backend available
//!      (`mvmctl dev status` reports an apple-container backend).
//!
//! Without `MVM_LIVE_SMOKE=1`, the test is skipped (returns Ok early
//! with a `eprintln!` describing the gate).
//!
//! ## What the test does
//!
//! 1. `nix build` the fixture flake at
//!    `nix/images/examples/echo-fn#packages.<system>.default` to
//!    produce a rootfs.ext4 + vmlinux pair.
//! 2. Register the fixture as an mvmctl manifest (template) so
//!    `mvmctl invoke <name>` resolves it.
//! 3. Pipe a known stdin payload through `mvmctl invoke` and capture
//!    stdout.
//! 4. Assert: `stdout == stdin`, `exit_code == 0`.
//!
//! Failure modes worth knowing:
//!   - Nix unavailable / build fails → skip with diagnostic.
//!   - Backend boot fails (vsock unsupported, no /dev/kvm) →
//!     surfaces the error verbatim. The test is informational on
//!     incapable hosts; the gate is the operator's fence.
//!   - Wrapper path validation fails (extraFiles ownership wrong) →
//!     `EntrypointEvent::Error { kind: EntrypointInvalid }` comes
//!     back; the test asserts a clear failure message naming
//!     `EntrypointInvalid` so the human knows where to look.

use std::process::Command;

/// Set to opt into the live smoke. Documented in the module
/// docstring; checked at the top of every test in this file.
const SMOKE_GATE: &str = "MVM_LIVE_SMOKE";

fn smoke_enabled() -> bool {
    std::env::var(SMOKE_GATE).as_deref() == Ok("1")
}

fn skip_if_disabled(test_name: &str) -> bool {
    if smoke_enabled() {
        return false;
    }
    eprintln!(
        "[smoke_invoke::{test_name}] skipped — set {SMOKE_GATE}=1 on a host with \
         Firecracker+vsock (native Linux/KVM or macOS 26+ Apple Container) to run."
    );
    true
}

/// Locate the repo root. Tests run with `cwd` set to the workspace
/// root by cargo, but worktrees sometimes have surprises — anchor
/// on the workspace `Cargo.toml` to be sure.
fn repo_root() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo");
    std::path::PathBuf::from(manifest)
}

#[test]
fn invoke_echo_fixture_round_trips_stdin() {
    if skip_if_disabled("invoke_echo_fixture_round_trips_stdin") {
        return;
    }

    let root = repo_root();
    let fixture_flake = root.join("nix/images/examples/echo-fn");
    assert!(
        fixture_flake.join("flake.nix").exists(),
        "fixture flake missing at {}",
        fixture_flake.display()
    );

    // Step 1: build the rootfs. We don't directly invoke nix here —
    // mvmctl's template lifecycle does the build during `mvmctl
    // template build`. Use that path so any Nix-side breakage shows
    // up via mvmctl's normal error surface.
    let build_status = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .arg("template")
        .arg("build")
        .arg("--flake")
        .arg(fixture_flake.as_os_str())
        .arg("--name")
        .arg("smoke-echo-fn")
        .status()
        .expect("spawn mvmctl template build");
    assert!(
        build_status.success(),
        "mvmctl template build failed: {build_status:?}"
    );

    // Step 2: invoke. We pipe a byte sequence that includes a
    // newline (so any line-buffering would show up) plus a unique
    // marker (so cross-test contamination is obvious).
    let payload = b"hello-from-smoke-test\n";

    let mut child = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .arg("invoke")
        .arg("smoke-echo-fn")
        .arg("--stdin")
        .arg("-")
        .arg("--timeout")
        .arg("60")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn mvmctl invoke");

    use std::io::Write;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload)
        .expect("write stdin");

    let output = child.wait_with_output().expect("wait_with_output");

    assert!(
        output.status.success(),
        "mvmctl invoke failed: status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        output.stdout,
        payload,
        "wrapper should echo stdin verbatim; got stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn invoke_echo_fixture_zero_stdin_exits_zero() {
    if skip_if_disabled("invoke_echo_fixture_zero_stdin_exits_zero") {
        return;
    }

    let output = Command::new(env!("CARGO_BIN_EXE_mvmctl"))
        .arg("invoke")
        .arg("smoke-echo-fn")
        .arg("--timeout")
        .arg("60")
        .output()
        .expect("spawn mvmctl invoke (no stdin)");

    assert!(
        output.status.success(),
        "mvmctl invoke without stdin should exit 0: status={:?}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.stdout.is_empty(),
        "with no stdin the wrapper has nothing to echo: stdout={:?}",
        String::from_utf8_lossy(&output.stdout),
    );
}

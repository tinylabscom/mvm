# Plan 169 — Plan 152 WS-A: guest `/init` exit-code + poweroff parity (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.
>
> **Design source:** `specs/notes/plan-152-wsa-init-exit-poweroff-design.md`.
> **Parent:** `specs/plans/152-rust-native-vz-and-init-lifecycle-parity.md`
> WS-A (roadmap S2 in `specs/plans/163-...`).

**Goal:** A finished one-shot sealed workload writes its exit code to the
host over a dedicated control vsock port, then `poweroff -f`; the host
captures it, surfaces `VmExitStatus`, records a chain-signed `plan.exited`
audit entry, and `mvmctl up --wait` returns it as its own exit status.

**Architecture:** Guest PID-1 `/init` runs the workload as a child
(setpriv without `exec`), captures `$?`, calls a tiny static
`mvm-exit-report` helper that connects `AF_VSOCK` CID=host port 5251 and
writes a 4-byte LE `i32`, then `sync` + `poweroff -f`. The libkrun
supervisor binds a host `UnixListener` for that control port
(`add_vsock_port2(listen=false)`), an accept-thread reads the code into
`<vm_state_dir>/workload.exit`; the backend's `wait()` reads that file
into `VmExitStatus`; `mvmctl` emits `plan.exited` and exits with the code.
Guest contract + the host-capture unit are backend-agnostic so WS-B reuses
them for Vz.

**Tech Stack:** Rust (`libc` AF_VSOCK, `std::os::unix::net`), Nix
(`mkGuest` `/init`), libkrun-sys FFI, anyhow, the chain-signed audit log.

---

## Guardrails (every task)

- Never regress claims 1–14; no SSH; persistent function-services
  (Model A, `exec sleep infinity`) must keep idling unchanged.
- `mvm-libkrun-supervisor` is a separate feature-gated binary — rebuild it
  explicitly: `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor
  --features libkrun-sys` (`reference_libkrun_supervisor_required_features`).
- `mvm-backend` test bins can SIGKILL on this macOS host
  (`reference_mvm_backend_test_binary_macos_codesign_sigkill`) — scope
  nextest to the crate under test; lean on Linux CI for mvm-backend.
- CI fmt is nightly: `rustup run nightly cargo fmt --all` before each
  commit (`reference_ci_lint_uses_nightly_rustfmt`).
- Never run `core_demo_e2e` unbounded
  (`feedback_never_run_core_demo_e2e_unbounded`).
- Per-task: `cargo clippy -p <crate> --all-targets -- -D warnings` clean.

## File Structure

Created:
- `crates/mvm-guest-helpers/src/bin/mvm-exit-report.rs` — the in-guest
  helper (T1.2).
- `nix/packages/mvm-exit-report.nix` — Nix build of the helper (T1.3).
- `crates/mvm-vm-host/src/exit_capture.rs` — backend-agnostic capture +
  read unit (T2.1). WS-B reuses this.
- `crates/mvm-cli/examples/exit_code_run.rs` *or* a fixture flake under
  `examples/exit_code/` — non-zero-exit regression (T3.4).

Modified:
- `crates/mvm-guest/src/vsock.rs` — `WORKLOAD_EXIT_PORT` const (T1.1).
- `crates/mvm-guest-helpers/Cargo.toml` — third `[[bin]]` (T1.2).
- `nix/lib/mk-guest.nix` — bake the helper; `setprivWrap` drop-`exec`;
  `/init` terminal contract (T1.3, T1.4).
- `crates/deps/libkrun-sys/src/lib.rs` — `listen=false` control-port
  builder support (T2.2).
- `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` + the crate lib
  (`exit_capture` mod) — bind listener + accept-thread (T2.3).
- `crates/mvm-backend/src/libkrun.rs` — `wait()` reads `workload.exit`
  (T3.1).
- `crates/mvm-cli/src/commands/vm/audit_chain.rs` — `emit_exited` (T3.2).
- `crates/mvm-cli/src/commands/vm/up.rs` — `--wait` propagation (T3.3).

---

# Phase 1 — Guest exit-code contract (backend-agnostic)

### Task 1.1: `WORKLOAD_EXIT_PORT` constant + wire format

**Files:**
- Modify: `crates/mvm-guest/src/vsock.rs`

- [ ] **Step 1: Failing test** (append to the `#[cfg(test)] mod tests` in `vsock.rs`)

```rust
#[test]
fn workload_exit_port_is_distinct_and_reserved() {
    assert_eq!(WORKLOAD_EXIT_PORT, 5251);
    assert_ne!(WORKLOAD_EXIT_PORT, GUEST_AGENT_PORT);
    assert!(WORKLOAD_EXIT_PORT < PORT_FORWARD_BASE);
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo nextest run -p mvm-guest workload_exit_port_is_distinct_and_reserved`
Expected: FAIL — `WORKLOAD_EXIT_PORT` not found.

- [ ] **Step 3: Add the constant** (next to `GUEST_AGENT_PORT` at `vsock.rs:42`)

```rust
/// Control vsock port the guest's `/init` connects to (host side) to
/// report a one-shot workload's exit code before `poweroff -f`. The host
/// supervisor binds the listener (`add_vsock_port2(listen=false)`). Wire
/// format: a single 4-byte little-endian `i32`. Plan 152 WS-A.
pub const WORKLOAD_EXIT_PORT: u32 = 5251;
```

- [ ] **Step 4: Run — expect PASS**

Run: `cargo nextest run -p mvm-guest workload_exit_port_is_distinct_and_reserved`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-guest/src/vsock.rs
git commit -m "feat(mvm-guest): WORKLOAD_EXIT_PORT control vsock constant"
```

### Task 1.2: `mvm-exit-report` in-guest helper

**Files:**
- Create: `crates/mvm-guest-helpers/src/bin/mvm-exit-report.rs`
- Modify: `crates/mvm-guest-helpers/Cargo.toml`

- [ ] **Step 1: Add the `[[bin]]`** to `crates/mvm-guest-helpers/Cargo.toml` (after the existing two `[[bin]]` entries)

```toml
[[bin]]
name = "mvm-exit-report"
path = "src/bin/mvm-exit-report.rs"
```

- [ ] **Step 2: Create the helper** `crates/mvm-guest-helpers/src/bin/mvm-exit-report.rs`

```rust
//! `mvm-exit-report <code>` — in-guest one-shot helper. Connects to the
//! host over AF_VSOCK (CID=host, WORKLOAD_EXIT_PORT) and writes the exit
//! code as a 4-byte little-endian i32, then exits. Called by mkGuest's
//! `/init` after a one-shot workload finishes, before `poweroff -f`.
//! Plan 152 WS-A. Linux-only (AF_VSOCK); a no-op stub off Linux so the
//! workspace builds on macOS dev hosts.

use std::process::ExitCode;

const VMADDR_CID_HOST: u32 = 2;
const WORKLOAD_EXIT_PORT: u32 = mvm_guest::vsock::WORKLOAD_EXIT_PORT;

fn main() -> ExitCode {
    let code: i32 = match std::env::args().nth(1).and_then(|s| s.parse().ok()) {
        Some(c) => c,
        None => {
            eprintln!("usage: mvm-exit-report <exit-code>");
            return ExitCode::from(2);
        }
    };
    match report(code) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Best-effort: /init still powers off. Log to console only.
            eprintln!("mvm-exit-report: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn report(code: i32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::FromRawFd;

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: WORKLOAD_EXIT_PORT,
        svm_cid: VMADDR_CID_HOST,
        svm_zero: [0; 4],
    };
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    // SAFETY: fd is a valid connected AF_VSOCK stream we own.
    let mut stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    stream.write_all(&code.to_le_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn report(_code: i32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "mvm-exit-report is Linux-only (AF_VSOCK)",
    ))
}
```

(`UnixStream::from_raw_fd` on an `AF_VSOCK` fd is a thin wrapper for
`write`/`flush` — we only need the byte sink, not Unix-domain semantics.
`libc` is already a `mvm-guest-helpers` dependency.)

- [ ] **Step 3: Build for the host (compiles everywhere)**

Run: `cargo build -p mvm-guest-helpers --bin mvm-exit-report`
Expected: builds (the `not(linux)` arm keeps macOS dev hosts green).

- [ ] **Step 4: Add a wire-format test** (append to the file)

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn exit_code_wire_is_4_byte_le() {
        let code: i32 = -7;
        let bytes = code.to_le_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(i32::from_le_bytes(bytes), -7);
    }
}
```

Run: `cargo nextest run -p mvm-guest-helpers exit_code_wire_is_4_byte_le`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-guest-helpers/
git commit -m "feat(mvm-guest-helpers): mvm-exit-report AF_VSOCK exit reporter"
```

### Task 1.3: Nix package + bake `mvm-exit-report` into the rootfs

**Files:**
- Create: `nix/packages/mvm-exit-report.nix`
- Modify: `nix/lib/mk-guest.nix`

- [ ] **Step 1: Create the package** `nix/packages/mvm-exit-report.nix` (clone of `nix/packages/mvm-addon-dns.nix`, retargeted)

```nix
{ pkgs, mvmSrc }:
pkgs.rustPlatform.buildRustPackage {
  pname = "mvm-exit-report";
  version = "0.16.1";
  src = mvmSrc;
  cargoLock.lockFile = mvmSrc + "/Cargo.lock";
  cargoBuildFlags = [
    "--package" "mvm-guest-helpers"
    "--bin" "mvm-exit-report"
  ];
  cargoTestFlags = [ "--package" "mvm-guest-helpers" ];
  doCheck = false;
}
```

(Match the exact attribute shape/version of `mvm-addon-dns.nix` in this
tree if it differs — read it first; copy its `version` and any
`buildInputs`/`nativeBuildInputs`.)

- [ ] **Step 2: Reference + bake it** in `nix/lib/mk-guest.nix`. Near the
  `addonDnsPkg` callPackage (`:155`) add:

```nix
  exitReportPkg = pkgs.callPackage ../packages/mvm-exit-report.nix {
    inherit mvmSrc;
  };
```

  Near `mvmAddonDnsBinary` (`:625`) add:

```nix
  mvmExitReportBinary = "${exitReportPkg}/bin/mvm-exit-report";
```

  In the rootfs assembly, alongside the agent/netinit copies (`:811-821`),
  add an **unconditional** copy (it must be on every prod/sealed image —
  do NOT gate behind `bakeAddonDns`):

```nix
    cp ${mvmExitReportBinary} "$out/usr/local/bin/mvm-exit-report"
    chmod 0555 "$out/usr/local/bin/mvm-exit-report"
```

- [ ] **Step 3: Verify the flake evaluates** (no build — just eval the guest derivation)

Run: `cd /Users/auser/work/tinylabs/mvmco/mvm-plan-152-wsa && nix flake check 2>&1 | tail -5` (Linux-eval; on macOS use the repo's standard eval recipe). Expected: evaluates without error referencing `mvm-exit-report`.

(If a builder VM round-trip isn't available here, the eval + the T3.4
E2E on the libkrun host is the gate. Builder tools route through the
builder VM — `feedback_builder_tools_on_host`.)

- [ ] **Step 4: Commit**

```bash
git add nix/packages/mvm-exit-report.nix nix/lib/mk-guest.nix
git commit -m "feat(nix): bake mvm-exit-report into the guest rootfs"
```

### Task 1.4: `/init` terminal contract (capture `$?` → report → poweroff)

**Files:**
- Modify: `nix/lib/mk-guest.nix`

- [ ] **Step 1: Drop `exec` from `setprivWrap`** (`mk-guest.nix:209-214`) so
  the workload runs as a child of `/init` and PID 1 regains control to
  capture `$?`. Change the uid != 0 arm from
  `exec ${utillinux}/bin/setpriv … -- ${cmd}` to
  `${utillinux}/bin/setpriv … -- ${cmd}` (remove the leading `exec ` only).
  The uid == 0 arm already returns (bare command, no `exec`). Read the
  exact current text first and remove only the `exec ` token.

  > **Why this is safe for persistent services:** `mkFunctionService`'s
  > boot fragment ends in `exec sleep infinity`, which still execs
  > *inside* the (now non-exec'd) setpriv child and blocks forever — so
  > `/init`'s source never returns and the VM stays warm (Model A
  > unchanged). Only a workload whose command *returns* reaches the
  > terminal block below.

- [ ] **Step 2: Replace the panic fallthrough** (`mk-guest.nix:530-540`)
  with the terminal contract. Replace:

```nix
    MVM_BOOT=/etc/mvm/entrypoint
    [ -e /etc/mvm/boot ] && MVM_BOOT=/etc/mvm/boot
    . "$MVM_BOOT"

    # If the boot command exits or doesn't exec, the kernel panics.
    echo "mvm: $MVM_BOOT returned without exec — kernel will panic"
    /bin/busybox sleep 5
```

  with:

```nix
    MVM_BOOT=/etc/mvm/entrypoint
    [ -e /etc/mvm/boot ] && MVM_BOOT=/etc/mvm/boot
    # Run the workload as a child (setprivWrap no longer execs) so PID 1
    # can capture its exit code. Persistent services exec `sleep infinity`
    # inside and never return here. Plan 152 WS-A.
    set +e
    . "$MVM_BOOT"
    MVM_CODE=$?
    set -e
    # Report the code to the host (best-effort) then power off — never
    # reboot. The host reads it from the control vsock port.
    /usr/local/bin/mvm-exit-report "$MVM_CODE" || \
      echo "mvm: exit-report failed (code=$MVM_CODE); powering off anyway"
    /bin/busybox sync
    /bin/busybox poweroff -f
```

  (If `/init` does not already run under `set -e`, drop the `set +e`/`set
  -e` pair and keep `. "$MVM_BOOT"; MVM_CODE=$?`. Check the script head
  first.)

- [ ] **Step 3: Verify eval**

Run: `nix flake check 2>&1 | tail -5` (or the repo eval recipe). Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add nix/lib/mk-guest.nix
git commit -m "feat(nix): /init captures workload exit code, reports, poweroff -f"
```

---

# Phase 2 — Host capture (backend-agnostic unit + libkrun wiring)

### Task 2.1: Shared exit-capture unit

**Files:**
- Create: `crates/mvm-vm-host/src/exit_capture.rs`
- Modify: `crates/mvm-vm-host/src/lib.rs` (add `pub mod exit_capture;`)

- [ ] **Step 1: Write the unit + tests** `crates/mvm-vm-host/src/exit_capture.rs`

```rust
//! Backend-agnostic workload exit-code capture (Plan 152 WS-A).
//!
//! The guest `/init` writes a 4-byte little-endian `i32` to the control
//! vsock port before `poweroff -f`. The supervisor binds a host
//! `UnixListener` at the control socket (libkrun `add_vsock_port2(
//! listen=false)`), accepts one connection, reads the code, and persists
//! it to `<vm_state_dir>/workload.exit`. The backend reads that file
//! after the VM stops. WS-B's Vz supervisor reuses this module.

use std::io::Read;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// File name under `vm_state_dir` holding the captured exit code (decimal).
pub const WORKLOAD_EXIT_FILE: &str = "workload.exit";

pub fn exit_file_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join(WORKLOAD_EXIT_FILE)
}

/// Block on `listener` for one guest connection, read the 4-byte LE i32,
/// and persist it to `<vm_state_dir>/workload.exit`. Returns the code.
/// Best-effort: any error leaves no file (read as "unknown" downstream).
pub fn capture_once(listener: &UnixListener, vm_state_dir: &Path) -> std::io::Result<i32> {
    let (mut stream, _addr) = listener.accept()?;
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    let code = i32::from_le_bytes(buf);
    std::fs::write(exit_file_path(vm_state_dir), code.to_string())?;
    Ok(code)
}

/// Read a previously-captured exit code, if present.
pub fn read_captured(vm_state_dir: &Path) -> Option<i32> {
    std::fs::read_to_string(exit_file_path(vm_state_dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn capture_persists_le_i32_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock-5251.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let handle = std::thread::spawn({
            let sock = sock.clone();
            move || {
                let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
                c.write_all(&(-7i32).to_le_bytes()).unwrap();
            }
        });

        let code = capture_once(&listener, dir.path()).unwrap();
        handle.join().unwrap();
        assert_eq!(code, -7);
        assert_eq!(read_captured(dir.path()), Some(-7));
    }

    #[test]
    fn read_captured_is_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_captured(dir.path()), None);
    }
}
```

  Add `pub mod exit_capture;` to `crates/mvm-vm-host/src/lib.rs`. Confirm
  `tempfile` is a dev-dependency of `mvm-vm-host` (add it under
  `[dev-dependencies]` if absent: `tempfile.workspace = true`).

- [ ] **Step 2: Run tests**

Run: `cargo nextest run -p mvm-vm-host exit_capture`
Expected: PASS (both).

- [ ] **Step 3: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-vm-host/
git commit -m "feat(mvm-vm-host): backend-agnostic workload exit-capture unit"
```

### Task 2.2: libkrun-sys — `listen=false` control-port support

**Files:**
- Modify: `crates/deps/libkrun-sys/src/lib.rs`

- [ ] **Step 1: Failing test** (in the libkrun-sys test module — find the existing `#[cfg(test)]`)

```rust
#[test]
fn control_listen_port_is_registered_listen_false() {
    let ctx = KrunContext::builder("t")
        .add_vsock_port(5252)
        .add_host_listen_port(5251);
    assert!(ctx.host_listen_ports.contains(&5251));
    assert!(!ctx.vsock_ports.contains(&5251));
}
```

(Adjust the builder constructor call to the real `KrunContext`/builder
API — read `lib.rs:543` and the surrounding builder. The point: a new
`add_host_listen_port` records ports to register with `listen=false`,
kept separate from `vsock_ports` which are `listen=true`.)

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo nextest run -p libkrun-sys control_listen_port_is_registered_listen_false`
Expected: FAIL — field/method missing.

- [ ] **Step 3: Add the field + builder method.** Add
  `host_listen_ports: Vec<u32>` to `KrunContext` (sibling to
  `vsock_ports`, `lib.rs:261`), default empty. Add the builder method near
  `add_vsock_port` (`lib.rs:543`):

```rust
    /// Append a control vsock port the HOST listens on (the guest
    /// connects). Registered with `add_vsock_port2(listen=false)` so the
    /// supervisor binds the unix listener at `<vsock_socket_dir>/vsock-
    /// <port>.sock` and libkrun proxies guest connects to it. Plan 152 WS-A.
    pub fn add_host_listen_port(mut self, port: u32) -> Self {
        self.host_listen_ports.push(port);
        self
    }
```

  In the `configure` loop that registers ports (`lib.rs:1039-1048`), after
  the existing `listen=true` loop add:

```rust
    for &port in &ctx.host_listen_ports {
        let socket = ctx.vsock_socket_path(port);
        // listen=false: the host (supervisor) binds the listener; do NOT
        // pre-unlink — the supervisor created it. libkrun proxies guest
        // connects on `port` to that socket. Plan 152 WS-A.
        krun.add_vsock_port2(port, &socket, /* listen = */ false)?;
    }
```

  **Ordering note for T2.3:** the supervisor must `UnixListener::bind` the
  control socket *before* `configure`/`start_enter` runs, since
  `listen=false` means libkrun expects the file to already be a bound
  listener.

- [ ] **Step 4: Run — expect PASS**

Run: `cargo nextest run -p libkrun-sys control_listen_port_is_registered_listen_false`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/deps/libkrun-sys/src/lib.rs
git commit -m "feat(libkrun-sys): add_host_listen_port (listen=false control port)"
```

### Task 2.3: Supervisor binds the control listener + accept-thread

**Files:**
- Modify: `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs`

- [ ] **Step 1: Wire the control port** before the `run_legacy`/
  `run_with_bridge` dispatch (`mvm-libkrun-supervisor.rs:~110`, after the
  `SupervisorConfig` is parsed and before either run path — both block in
  `krun_start_enter`). Insert:

```rust
    // Plan 152 WS-A: bind the workload-exit control listener and capture
    // the guest's exit code on a background thread. Bind BEFORE start so
    // libkrun's listen=false proxy has a live socket. Best-effort: a bind
    // failure must not block boot — the workload.exit file simply stays
    // absent and the host reads "unknown".
    {
        let state_dir = std::path::PathBuf::from(&cfg.vm_state_dir);
        let control_sock = state_dir.join(format!(
            "vsock-{}.sock",
            mvm_guest::vsock::WORKLOAD_EXIT_PORT
        ));
        let _ = std::fs::remove_file(&control_sock);
        match std::os::unix::net::UnixListener::bind(&control_sock) {
            Ok(listener) => {
                std::thread::spawn(move || {
                    if let Err(e) =
                        mvm_vm_host::exit_capture::capture_once(&listener, &state_dir)
                    {
                        eprintln!("mvm-libkrun-supervisor: exit capture: {e}");
                    }
                });
            }
            Err(e) => eprintln!("mvm-libkrun-supervisor: bind control socket: {e}"),
        }
    }
```

  Then register the control port on the `KrunContext` builder where the
  agent port is added (the config builds `KrunContext`; add
  `.add_host_listen_port(mvm_guest::vsock::WORKLOAD_EXIT_PORT)` to that
  chain). Read how `cfg.krun` / the builder is assembled and add the call
  there (it may be in `build_supervisor_config` on the backend side — see
  T3 note; if the ports are fixed at backend config-build time, the
  `add_host_listen_port` call belongs in `build_supervisor_config` in
  `libkrun.rs` instead, and the supervisor only binds + spawns. Implement
  whichever matches: the **builder** registers the port; the
  **supervisor** binds the socket + spawns the thread.)

- [ ] **Step 2: Rebuild the supervisor explicitly**

Run: `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys`
Expected: builds.

- [ ] **Step 3: Build-level check** (no unit test — this is integration; covered E2E in T3.4)

Run: `cargo clippy -p mvm-vm-host --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs
git commit -m "feat(supervisor): bind workload-exit control listener + capture thread"
```

---

# Phase 3 — Surface, audit, propagate

### Task 3.1: libkrun backend registers the port + `wait()` reads the code

**Files:**
- Modify: `crates/mvm-backend/src/libkrun.rs`

- [ ] **Step 1: Register the control port** in `build_supervisor_config`
  (where the agent port is added to the `KrunContext`, `libkrun.rs:~111`):
  add `.add_host_listen_port(mvm_guest::vsock::WORKLOAD_EXIT_PORT)` to the
  builder chain (sibling to `.add_vsock_port(GUEST_AGENT_PORT)`).

- [ ] **Step 2: Failing test** (in the libkrun.rs test module)

```rust
#[test]
fn wait_reads_workload_exit_file() {
    let dir = tempfile::tempdir().unwrap();
    // Simulate vm_state_dir layout by writing the captured file directly.
    std::fs::write(
        mvm_vm_host::exit_capture::exit_file_path(dir.path()),
        "3",
    )
    .unwrap();
    let status = read_exit_status_from(dir.path());
    assert_eq!(status.code, Some(3));
    assert!(!status.success);
}
```

(Introduce a small testable helper `read_exit_status_from(&Path) ->
VmExitStatus` so the file→status mapping is unit-tested without a VM.)

- [ ] **Step 3: Run — expect FAIL**

Run: `cargo nextest run -p mvm-backend wait_reads_workload_exit_file`
Expected: FAIL (or SIGKILL on macOS — if so, `cargo build -p mvm-backend --tests` to confirm it compiles and lean on Linux CI).

- [ ] **Step 4: Implement** the helper + `wait()` override

```rust
fn read_exit_status_from(state_dir: &std::path::Path) -> mvm_core::vm_backend::VmExitStatus {
    match mvm_vm_host::exit_capture::read_captured(state_dir) {
        Some(code) => mvm_core::vm_backend::VmExitStatus {
            code: Some(code),
            success: code == 0,
        },
        None => mvm_core::vm_backend::VmExitStatus::UNKNOWN,
    }
}
```

  In `impl VmBackend for LibkrunBackend`, override `wait` (the trait
  default bails — `vm_backend.rs:657`): poll for the supervisor PID to
  exit (reuse `vm_libkrun_pid` + `pid_alive`, `libkrun.rs:383-410`), then
  return `read_exit_status_from(&vm_state_dir(&id.0))`:

```rust
    fn wait(&self, id: &VmId) -> Result<mvm_core::vm_backend::VmExitStatus> {
        let pid_path = vm_libkrun_pid(&id.0);
        // Block until the supervisor (and thus the guest) has exited.
        loop {
            match read_pid(&pid_path) {
                Some(pid) if pid_alive(pid) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => break,
            }
        }
        Ok(read_exit_status_from(&vm_state_dir(&id.0)))
    }
```

  (Confirm `mvm_vm_host` is a dependency of `mvm-backend`; if not, add
  `mvm-vm-host.workspace = true`. If that introduces an unwanted dep
  direction, move `exit_capture::read_captured` + `exit_file_path` to
  `mvm-core` instead and have both crates use it — decide during impl and
  keep the capture/bind side, which needs the supervisor, in mvm-vm-host.)

- [ ] **Step 5: Run — expect PASS** (or compile-clean on macOS per the SIGKILL caveat)

Run: `cargo nextest run -p mvm-backend wait_reads_workload_exit_file`

- [ ] **Step 6: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-backend/src/libkrun.rs crates/mvm-backend/Cargo.toml
git commit -m "feat(mvm-backend): libkrun wait() surfaces workload exit code"
```

### Task 3.2: `plan.exited` audit event

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/audit_chain.rs`

- [ ] **Step 1: Add `emit_exited`** (model on `emit_launched`, `audit_chain.rs:230`)

```rust
    /// Emit `plan.exited` — fires after a waited-for workload powers off,
    /// carrying its captured exit code. Plan 152 WS-A.
    pub fn emit_exited(&self, plan: &ExecutionPlan, exit_code: i32, backend: &str) -> Result<()> {
        self.emit(
            plan,
            "plan.exited",
            [
                ("exit_code".to_string(), exit_code.to_string()),
                ("backend".to_string(), backend.to_string()),
            ],
        )
    }
```

- [ ] **Step 2: Test** (mirror an existing audit-emit test in that file; if the file has a roundtrip test that asserts an event lands in the chain, add one for `plan.exited`)

```rust
#[test]
fn emit_exited_writes_plan_exited_with_code() {
    let dir = tempfile::tempdir().unwrap();
    let (emitter, plan) = test_emitter_and_plan(&dir); // reuse existing test helper
    emitter.emit_exited(&plan, 3, "libkrun").unwrap();
    let entries = read_chain(dir.path()); // reuse existing helper
    assert!(entries.iter().any(|e| e.event == "plan.exited"
        && e.extras_get("exit_code").as_deref() == Some("3")));
}
```

(Use whatever existing test helpers the file already has for constructing
an emitter + reading the chain; if none, mirror the closest existing
audit_chain test exactly.)

- [ ] **Step 3: Run**

Run: `cargo nextest run -p mvm-cli emit_exited_writes_plan_exited_with_code`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/vm/audit_chain.rs
git commit -m "feat(mvm-cli): plan.exited audit event"
```

### Task 3.3: `mvmctl up --wait` propagates the exit code

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/up.rs`

- [ ] **Step 1: Add the flag** to `up`'s `Args` (find the struct; add near `detach`)

```rust
    /// Block until the workload powers off, then exit with its code
    /// (one-shot workloads). Mutually useful with sealed images that run
    /// to completion. Plan 152 WS-A.
    #[arg(long)]
    pub wait: bool,
```

- [ ] **Step 2: Parse test** (in `crates/mvm-cli/src/commands/tests.rs`)

```rust
#[test]
fn test_up_wait_parses() {
    let cli = Cli::try_parse_from(["mvmctl", "up", "--flake", ".", "--wait"]).unwrap();
    match cli.command {
        Commands::Up(ref a) => assert!(a.wait),
        _ => panic!("expected up"),
    }
}
```

Run: `cargo nextest run -p mvm-cli test_up_wait_parses` → expect FAIL then PASS after Step 1.

- [ ] **Step 3: Propagate** at the libkrun terminal block (after the
  agent-ready success, `up.rs:1963-1991`). When `args.wait` and the
  backend is libkrun, block on `backend.wait(...)`, emit `plan.exited`,
  and exit with the code:

```rust
    if args.wait && matches!(effective_hypervisor, "libkrun") {
        let id = mvm_core::vm_backend::VmId(vm_name_owned.clone());
        let status = backend.wait(&id)?;
        let code = status.code.unwrap_or(1);
        if let Some(ctx) = &admission_main {
            if let Err(e) = ctx.emitter.emit_exited(&ctx.admitted.plan, code, effective_hypervisor) {
                tracing::warn!(error = %e, "audit emit_exited failed (non-fatal)");
            }
        }
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
```

(Place this after `emit_launched_if` + the agent-ready check, before the
existing `return Ok(())`. Match the real variable names `admission_main`
/ `effective_hypervisor` / `vm_name_owned` from the surrounding code.)

- [ ] **Step 4: Run**

Run: `cargo nextest run -p mvm-cli test_up_wait_parses && cargo build -p mvm-cli`
Expected: PASS + builds.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/vm/up.rs crates/mvm-cli/src/commands/tests.rs
git commit -m "feat(mvm-cli): up --wait propagates workload exit code + plan.exited"
```

### Task 3.4: Non-zero-exit E2E fixture + live verification

**Files:**
- Create: a minimal one-shot fixture flake under `examples/exit_code/`
  (mirror the smallest existing `examples/` flake that builds a sealed
  workload whose command runs and *returns* a chosen non-zero code).

- [x] **Step 1: Create the fixture** — DONE (commit `76a46751`).
  `examples/exit_code/flake.nix`: direct `mkGuest { entrypoint.command =
  [ "/bin/busybox" "sh" "-c" "exit 7" ]; hypervisor = "libkrun"; }` — a
  sealed prod one-shot whose PID-1 command returns 7. Evaluates cleanly:
  `passthru.mvm` = `{sealed:true, entrypointKind:command,
  hypervisor:libkrun, rootlessEntrypoint:true, agentBinary:real, ...}`;
  the ext4 derivation is plannable. There is **no one-shot factory** —
  direct `mkGuest` with `entrypoint.command` (and no `bootCommand`) is the
  correct shape; `mkFunctionService` is persistent-only.

- [~] **Step 2: Live E2E on the libkrun host — ATTEMPTED, BLOCKED on
  fixture/builder staging (NOT on WS-A code).** Two successive
  non-WS-A walls on this host:
  1. The **Vz builder** needs the Swift `mvm-vz-supervisor` binary
     (`reference_mvm_vz_supervisor_separate_swiftpm_binary`), absent in
     the worktree → `--builder libkrun` to sidestep.
  2. With `--builder libkrun`: Stage 0 booted, the builder VM ran, and
     `nix build` started — but the fixture flake failed to evaluate:
     `path '/work/nix/lib/workspace-filter.nix' does not exist`. The
     `up --flake` builder stages **only the flake's own dir** at `/work`,
     so the in-repo `workspaceRoot + "/nix/lib"` reference (mirrored from
     the built-in `default-tenant` image, which is built with the whole
     repo staged) does not resolve. The WS-A code path (guest `/init`
     report → control vsock → supervisor capture → `wait()` →
     `plan.exited` → exit propagation) is therefore **never exercised by
     this fixture** — the image won't build.

  **Resolution (follow-up):** author the fixture to reference mvm as a
  proper flake **input** (as an external user flake would), OR build it
  via the workspace-root-staged path the default image uses. Then re-run:

```bash
MVM_WORKSPACE_PATH="$(pwd)" ./target/debug/mvmctl up \
  --flake ./examples/exit_code --builder libkrun --hypervisor libkrun --wait
echo "exit: $?"   # expect 7
./target/debug/mvmctl audit show <plan_id> --json | grep plan.exited   # exit_code=7
```

  **What IS verified without the live boot:** the host-side capture path
  end-to-end on real sockets
  (`mvm_vm_host::exit_capture::capture_once` test: bind listener →
  connect → write 4-byte LE i32 → `workload.exit` → `read_captured`); the
  backend mapping (`read_exit_status_from`: code→VmExitStatus,
  absent→UNKNOWN); control-port registration
  (`build_supervisor_config_registers_control_port`); `plan.exited`
  chain emission (`emit_exited_writes_plan_exited_with_code` +
  `verify_audit_chain`); `up --wait` parse + `conflicts_with`
  detach/up-json; the guest `/init` rewrite (nix parse + opus security
  review). The only unverified link is the live guest→libkrun-vsock→
  supervisor proxy hop, which needs a buildable fixture.

- [x] **Step 3: Commit the fixture** — DONE (commit `76a46751`).

---

## Deferred (tracked, not in this plan)

- [ ] **Vz host-side capture** → Plan 152 WS-B: the Rust-objc2 supervisor
  binds the control listener and calls
  `mvm_vm_host::exit_capture::capture_once` (the same unit). The guest
  contract + this unit already work; WS-B only adds the Vz registration.
- [ ] Firecracker / apple_container exit capture (no per-VM supervisor today).
- [ ] `run`/transient propagation beyond `up --wait` if a Model-B one-shot
  `run` mode is later wanted.

## Self-review notes

- **Spec coverage:** D1 one-shot PID-1 contract → T1.4; D2 control vsock
  port 5251 + 4-byte LE → T1.1/T1.2/T2.2/T2.3; D3 backend-agnostic guest +
  shared unit, libkrun-first, Vz deferred → T1.x/T2.1 (shared) + T2.2/T2.3/
  T3.1 (libkrun) + Deferred (Vz). `mvm-exit-report` helper → T1.2/T1.3;
  `VmExitStatus` → T3.1; `plan.exited` → T3.2; mvmctl propagation → T3.3;
  regression fixture → T3.4. Error handling (absent/partial → UNKNOWN,
  fail-closed) → T2.1 `read_captured`/`capture_once` + T3.1
  `read_exit_status_from`.
- **Type consistency:** `WORKLOAD_EXIT_PORT` (mvm-guest) used by helper +
  supervisor + libkrun-sys port registration; `exit_capture::{capture_once,
  read_captured, exit_file_path, WORKLOAD_EXIT_FILE}` used by supervisor +
  backend; `VmExitStatus{code,success}` from mvm-core; `emit_exited(plan,
  i32, &str)` signature consistent T3.2 ↔ T3.3.
- **Open integration points flagged for the implementer** (not
  placeholders — each names the exact file + the decision): T2.3 whether
  `add_host_listen_port` is called on the builder in `build_supervisor_
  config` (libkrun.rs) vs in the supervisor; T3.1 the `mvm-vm-host` dep
  direction for `exit_capture::read_captured` (move the read half to
  mvm-core if the dep is unwanted).

## References

- Design: `specs/notes/plan-152-wsa-init-exit-poweroff-design.md`
- `nix/lib/mk-guest.nix` (`setprivWrap` `:209`, `/init` `:483-561`, bake
  `:811-835`), `nix/packages/mvm-addon-dns.nix` (clone source)
- `crates/mvm-guest-helpers/` (helper crate + `addon_vsock_bridge.rs:181`
  connect template)
- `crates/deps/libkrun-sys/src/lib.rs:543,1039`, `src/sys.rs:247`
- `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs:62-133`
- `crates/mvm-backend/src/libkrun.rs:246-430`,
  `crates/mvm-core/src/protocol/vm_backend.rs:354-670`
- `crates/mvm-cli/src/commands/vm/audit_chain.rs:230-387`,
  `.../vm/up.rs:907,1943-1991`, `.../vm/exec.rs:379-399`
</content>

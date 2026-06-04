# Install & Download Experience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the curl-able `install.sh`, a Homebrew tap formula + auto-bump workflow, user-facing kernel-download and release docs, and live progress logging for the `mvmctl kernel build` compile path.

**Architecture:** Five independent components. (A) Compile logging threads a `verbose` bool through the libkrun Stage 0 wait path so `console.log` streams under `--verbose`, plus a host-side elapsed-time heartbeat. (B) `install.sh` mirrors `update.rs` verification (sha256 + optional cosign + macOS codesign). (C) A Homebrew formula template rendered + pushed to a tap repo on release. (D)+(E) Two Astro doc pages.

**Tech Stack:** Rust (mvm-build, mvm-cli), POSIX `sh`, Ruby (Homebrew formula), GitHub Actions YAML, Astro/Starlight Markdown.

**Worktree:** `../mvm-install-experience` on branch `feat/install-download-experience` (already created off `origin/main`).

**Reference design:** `docs/superpowers/specs/2026-06-03-install-download-experience-design.md`.

**Conventions:**
- Run `rustup run nightly cargo fmt --all` before every commit (CI Lint uses nightly rustfmt — stable under-formats).
- Commit messages: NO `Co-Authored-By: Claude` trailer.
- `cargo clippy --workspace --all-targets -- -D warnings` must be clean.

---

## Phase A — Compile-path logging

The libkrun Stage 0 build (`mvmctl kernel build --source compile`, and `dev up`'s first build) calls `LibkrunBuilderVm::run_stage0_impl` → `spawn_supervisor_and_wait` → `wait_with_panic_detector_until` → `panic_watcher`, which already tails `console.log` for the kernel panic banner. We extend that tail to echo bytes to stderr under `--verbose`, and add a host-side heartbeat in `build_kernel_via_stage0`.

### Task A1: Add the `echo_console_chunk` helper + test (mvm-build)

**Files:**
- Modify: `crates/mvm-build/src/libkrun_builder.rs` (add helper near `panic_watcher`, ~line 1763)
- Test: same file, `#[cfg(test)] mod tests` (already exists in this file)

- [ ] **Step 1: Write the failing test**

Add to the existing test module in `crates/mvm-build/src/libkrun_builder.rs`:

```rust
#[test]
fn echo_console_chunk_writes_only_when_verbose() {
    let mut sink: Vec<u8> = Vec::new();
    echo_console_chunk(&mut sink, false, b"hello");
    assert!(sink.is_empty(), "quiet mode must not echo");
    echo_console_chunk(&mut sink, true, b"hello");
    assert_eq!(sink, b"hello", "verbose mode echoes the chunk verbatim");
    echo_console_chunk(&mut sink, true, b"");
    assert_eq!(sink, b"hello", "empty chunk is a no-op");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-build echo_console_chunk_writes_only_when_verbose`
Expected: FAIL — `cannot find function echo_console_chunk`.

- [ ] **Step 3: Write minimal implementation**

Add above `panic_watcher` (just before line 1726) in `crates/mvm-build/src/libkrun_builder.rs`:

```rust
/// Under `--verbose`, forward freshly-read console bytes to `sink`
/// (stderr in production). Extracted so the verbose-gating is unit
/// testable without capturing process stderr. Best-effort: a write
/// error just drops the echo — it must never fail the build.
fn echo_console_chunk(sink: &mut impl std::io::Write, verbose: bool, chunk: &[u8]) {
    if verbose && !chunk.is_empty() {
        let _ = sink.write_all(chunk);
        let _ = sink.flush();
    }
}
```

Confirm `use std::io::Write;` is in scope in this module (the file already uses `Read`; add `Write` to the existing `use std::io::...` import or add `use std::io::Write;` at the top of the file if absent).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-build echo_console_chunk_writes_only_when_verbose`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-build/src/libkrun_builder.rs
git commit -m "feat(builder): add verbose-gated console echo helper"
```

### Task A2: Thread `verbose` through the wait path (mvm-build)

**Files:**
- Modify: `crates/mvm-build/src/libkrun_builder.rs`
  - `panic_watcher` (~1726): add `verbose` param, echo each chunk
  - `wait_with_panic_detector_until` (~1617) + `#[cfg(test)] wait_with_panic_detector` (~1609): add `verbose` param, forward to `panic_watcher`
  - `spawn_supervisor_and_wait` (~1385): add `verbose` param, forward
  - `run_stage0_impl` (~450) + `run_shell_script` (call to `spawn_supervisor_and_wait`): pass `self.verbose`
  - The other `wait_with_panic_detector_until` caller (~1056, `LibkrunBuilderBackend`): pass `false`
  - `LibkrunBuilderVm` struct (~239) + `Default` (~290): add `verbose: bool`
  - Add `with_verbose` builder method in `impl LibkrunBuilderVm` (~301)

- [ ] **Step 1: Write the failing test**

Add to the test module:

```rust
#[test]
fn libkrun_builder_vm_with_verbose_sets_flag() {
    let vm = LibkrunBuilderVm::default();
    assert!(!vm.verbose, "default is quiet");
    let vm = LibkrunBuilderVm::default().with_verbose(true);
    assert!(vm.verbose, "with_verbose(true) flips the flag");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-build libkrun_builder_vm_with_verbose_sets_flag`
Expected: FAIL — no field `verbose` / no method `with_verbose`.

- [ ] **Step 3: Write minimal implementation**

In the `LibkrunBuilderVm` struct (after `image_override`):

```rust
    /// Stream the guest `console.log` to stderr as the build runs.
    /// Set by the CLI from `--verbose`. Default false (heartbeat only).
    pub verbose: bool,
```

In `impl Default for LibkrunBuilderVm`, add `verbose: false,` to the struct literal.

In `impl LibkrunBuilderVm`, add:

```rust
    /// Stream guest console output to stderr during the build (`--verbose`).
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
```

Change `panic_watcher` signature + body:

```rust
fn panic_watcher(
    console_log: &Path,
    panic_line: &Arc<Mutex<Option<String>>>,
    stop: &Arc<AtomicBool>,
    poll_interval: Duration,
    verbose: bool,
) {
```

Inside its loop, right after `buf.extend_from_slice(&chunk);`, add:

```rust
                echo_console_chunk(&mut std::io::stderr(), verbose, &chunk);
```

Change `wait_with_panic_detector_until` signature to take `verbose: bool` (add as last param) and pass it into the `panic_watcher(...)` call inside the watcher closure:

```rust
            panic_watcher(&watcher_path, &watcher_panic, &watcher_stop, poll_interval, verbose);
```

Change the `#[cfg(test)] wait_with_panic_detector` helper to take `verbose: bool` and forward it:

```rust
fn wait_with_panic_detector(
    child: &mut Child,
    console_log: Option<&Path>,
    poll_interval: Duration,
    verbose: bool,
) -> std::io::Result<WaitOutcome> {
    wait_with_panic_detector_until(child, console_log, poll_interval, None, verbose)
}
```

Change `spawn_supervisor_and_wait` signature to add `verbose: bool` (last param) and forward at its `wait_with_panic_detector_until` call (line ~1402):

```rust
    let outcome = wait_with_panic_detector_until(
        &mut child,
        console_log.as_deref(),
        DEFAULT_PANIC_POLL_INTERVAL,
        Some(timeout),
        verbose,
    );
```

Update the two `spawn_supervisor_and_wait` call sites to pass `self.verbose`:
- `run_stage0_impl` line 450: `spawn_supervisor_and_wait(&supervisor_path, &cfg, &vm_state_dir, self.verbose)?;`
- `run_shell_script`: find its `spawn_supervisor_and_wait(...)` call and append `, self.verbose`.

Update the other direct `wait_with_panic_detector_until` caller (the `LibkrunBuilderBackend` impl near line 1056) to pass `false` as the new last arg.

Update any `#[cfg(test)]` callers of `wait_with_panic_detector` (search the test module) to pass `false`.

- [ ] **Step 4: Run test + full build to verify it passes**

Run: `cargo test -p mvm-build libkrun_builder_vm_with_verbose_sets_flag && cargo build -p mvm-build`
Expected: PASS + clean build (all call sites updated). If the build errors on a missing arg, fix that call site — every `spawn_supervisor_and_wait` / `wait_with_panic_detector*` / `panic_watcher` call must pass the new param.

- [ ] **Step 5: Run the existing panic-detector tests (regression)**

Run: `cargo test -p mvm-build panic`
Expected: PASS — existing panic-detection tests still green with the new param threaded.

- [ ] **Step 6: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-build/src/libkrun_builder.rs
git commit -m "feat(builder): thread --verbose to stream Stage 0 console to stderr"
```

### Task A3: Heartbeat formatter + host-side wiring (mvm-cli)

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/apple_container.rs` (`build_kernel_via_stage0`, ~2301–2320; the inline `LibkrunBuilderVm::default()` at ~2310; and the `run_stage0_root_dir` backend construction at ~2362)
- Modify: `crates/mvm-cli/src/commands/kernel.rs` (`run`, `run_build`, `compile_host_arch`, `acquire_kernel`, `build_kernel_via_stage0` call — thread `verbose`)
- Test: `crates/mvm-cli/src/commands/env/apple_container.rs` test module (add heartbeat-format unit test)

The heartbeat formatter is pure and testable; the thread wiring is exercised by the existing build path.

- [ ] **Step 1: Write the failing test**

Add a test module entry (or extend the existing one) in `apple_container.rs`:

```rust
// Gated to the same feature as `format_compile_elapsed`, which only
// exists under `builder-vm`.
#[cfg(all(test, feature = "builder-vm"))]
mod heartbeat_tests {
    use super::format_compile_elapsed;
    use std::time::Duration;

    #[test]
    fn format_compile_elapsed_renders_minutes_and_seconds() {
        assert_eq!(format_compile_elapsed(Duration::from_secs(5)), "still compiling… (0m05s elapsed)");
        assert_eq!(format_compile_elapsed(Duration::from_secs(130)), "still compiling… (2m10s elapsed)");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-cli --features builder-vm format_compile_elapsed_renders_minutes_and_seconds`
Expected: FAIL — `cannot find function format_compile_elapsed`.

- [ ] **Step 3: Write minimal implementation**

Add near `build_kernel_via_stage0` in `apple_container.rs` (gated to the same feature as the caller — `#[cfg(feature = "builder-vm")]`):

```rust
/// Render the compile heartbeat line. Pure (testable); the live
/// heartbeat thread routes it through `ui::info`.
#[cfg(feature = "builder-vm")]
fn format_compile_elapsed(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    format!("still compiling… ({}m{:02}s elapsed)", secs / 60, secs % 60)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-cli --features builder-vm format_compile_elapsed_renders_minutes_and_seconds`
Expected: PASS.

- [ ] **Step 5: Wire the heartbeat thread + verbose into the compile call**

Change `build_kernel_via_stage0` to accept `verbose: bool`. Update its signature and the `LibkrunBuilderVm` construction, and wrap the `run_stage0` call with a heartbeat thread.

First, the function signature (find `fn build_kernel_via_stage0`; it currently takes `variant: KernelVariant`):

```rust
#[cfg(feature = "builder-vm")]
pub(crate) fn build_kernel_via_stage0(
    variant: KernelVariant,
    verbose: bool,
) -> Result<std::path::PathBuf> {
```

Replace the existing `ui::info(...)` + `run_stage0` block (lines ~2301–2320) with:

```rust
    ui::info(&format!(
        "Compiling {} kernel ({arch}) via Stage 0 — first build is slow \
         (3-10 min); later runs hit the nix store cache.",
        variant.label()
    ));

    {
        use mvm_build::builder_vm::BuilderVm;
        use mvm_build::libkrun_builder::LibkrunBuilderVm;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        // Host-side heartbeat so a quiet (non-verbose) compile is never
        // dead-silent. In verbose mode the streamed console output is
        // the liveness signal, so the heartbeat stays off.
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = if verbose {
            None
        } else {
            let stop = Arc::clone(&stop);
            Some(std::thread::spawn(move || {
                let start = std::time::Instant::now();
                // Poll the stop flag every 500ms but only print every ~20s.
                let mut ticks: u64 = 0;
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    ticks += 1;
                    if ticks % 40 == 0 {
                        ui::info(&format_compile_elapsed(start.elapsed()));
                    }
                }
            }))
        };

        let backend: &dyn BuilderVm = &LibkrunBuilderVm::default().with_verbose(verbose);
        let result = backend.run_stage0(
            &root_dir,
            "/init",
            &workspace_root,
            &staging_dir,
            &host_bin_dir,
        );

        stop.store(true, Ordering::SeqCst);
        if let Some(handle) = heartbeat {
            let _ = handle.join();
        }

        result.map_err(|e| anyhow::anyhow!("Stage 0 kernel build: {e}"))?;
    }
```

- [ ] **Step 6: Update callers to pass `verbose`**

In `crates/mvm-cli/src/commands/kernel.rs`, thread `verbose` from the CLI:
- `run`: change `Cmd::Build(b) => run_build(b),` to `Cmd::Build(b) => run_build(b, _cli.verbose),` and rename `_cli` to `cli` in the `run` signature (`pub(in crate::commands) fn run(cli: &Cli, ...)`).
- `run_build`: add `verbose: bool` param: `fn run_build(args: BuildArgs, verbose: bool) -> Result<()>`.
- `acquire_kernel`: add `verbose: bool` param and pass to `compile_host_arch`.
- `compile_host_arch`: add `verbose: bool` param; change the call to `build_kernel_via_stage0(variant, verbose)`.
- In `run_build`, change `acquire_kernel(args.source, variant, label, &arch)?` to `acquire_kernel(args.source, variant, label, &arch, verbose)?`.
- In the `#[cfg(not(feature = "builder-vm"))] fn run_build`, update the signature to `fn run_build(_args: BuildArgs, _verbose: bool)`.

(Leave `run_stage0_root_dir`'s backend construction as-is for now — it can adopt `.with_verbose(...)` in a later dev-up pass; this task scopes to `mvmctl kernel build`.)

- [ ] **Step 7: Build + clippy**

Run: `cargo build -p mvm-cli --features builder-vm && cargo clippy -p mvm-cli --features builder-vm --all-targets -- -D warnings`
Expected: clean. Fix any caller the compiler flags.

- [ ] **Step 8: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/env/apple_container.rs crates/mvm-cli/src/commands/kernel.rs
git commit -m "feat(kernel): elapsed heartbeat + --verbose console stream on compile"
```

### Task A4: Update the kernel.rs module doc

**Files:**
- Modify: `crates/mvm-cli/src/commands/kernel.rs` (module doc-comment, lines 1–14)

- [ ] **Step 1: Update the doc-comment**

Append to the module doc (after line 14, before `use`):

```rust
//!
//! Progress: the compile path prints an elapsed-time heartbeat every
//! ~20s; `--verbose` streams the builder VM's `console.log` (the inner
//! `nix build` output) to stderr live.
```

- [ ] **Step 2: Build to verify doc compiles**

Run: `cargo build -p mvm-cli --features builder-vm`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-cli/src/commands/kernel.rs
git commit -m "docs(kernel): note heartbeat + verbose streaming in module doc"
```

---

## Phase B — `install.sh`

### Task B1: Write `install.sh`

**Files:**
- Create: `install.sh` (repo root)

- [ ] **Step 1: Write the script**

Create `install.sh`:

```sh
#!/bin/sh
# mvmctl installer. Downloads the released binary for this platform from
# GitHub releases, verifies its sha256 (and cosign signature if cosign is
# present), installs it, and on macOS re-codesigns with the
# Hypervisor.framework entitlement.
#
# Env knobs:
#   MVM_VERSION            pin a release tag (e.g. v0.15.2); default: latest
#   MVM_INSTALL_DIR        install dir; default: ~/.local/bin
#   MVM_SKIP_HASH_VERIFY   set to 1 to skip checksum (emergency only)
#   MVM_SKIP_CODESIGN      set to 1 to skip macOS codesign
#   MVM_UPDATE_API_URL     override https://api.github.com (tests)
#   MVM_UPDATE_DOWNLOAD_URL override https://github.com (tests)
set -eu

REPO="tinylabscom/mvm"
API_BASE="${MVM_UPDATE_API_URL:-https://api.github.com}"
DL_BASE="${MVM_UPDATE_DOWNLOAD_URL:-https://github.com}"
INSTALL_DIR="${MVM_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '[mvm] %s\n' "$1"; }
warn() { printf '[mvm] WARN: %s\n' "$1" >&2; }
die() { printf '[mvm] ERROR: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

need curl
need tar

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin) case "$arch" in
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        x86_64) echo "x86_64-apple-darwin" ;;
        *) die "unsupported macOS arch: $arch" ;;
      esac ;;
    Linux) case "$arch" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) die "unsupported Linux arch: $arch" ;;
      esac ;;
    *) die "unsupported OS: $os" ;;
  esac
}

resolve_version() {
  if [ -n "${MVM_VERSION:-}" ]; then
    echo "$MVM_VERSION"
    return
  fi
  curl -fsSL "$API_BASE/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' \
    | grep . || die "could not resolve latest release tag"
}

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    die "need shasum or sha256sum to verify the download"
  fi
}

TARGET="$(detect_target)"
VERSION="$(resolve_version)"
ARCHIVE="mvmctl-${TARGET}.tar.gz"
REL="$DL_BASE/$REPO/releases/download/$VERSION"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "Installing mvmctl $VERSION ($TARGET) to $INSTALL_DIR"

curl -fsSL "$REL/$ARCHIVE" -o "$TMP/$ARCHIVE" \
  || die "download failed: $REL/$ARCHIVE"

if [ "${MVM_SKIP_HASH_VERIFY:-}" = "1" ]; then
  warn "MVM_SKIP_HASH_VERIFY=1 — skipping checksum verification"
else
  curl -fsSL "$REL/checksums-sha256.txt" -o "$TMP/checksums.txt" \
    || die "could not download checksums-sha256.txt"
  want="$(grep " $ARCHIVE\$" "$TMP/checksums.txt" | awk '{print $1}' | head -n1)"
  [ -n "$want" ] || die "no checksum for $ARCHIVE in checksums-sha256.txt"
  got="$(sha256_of "$TMP/$ARCHIVE")"
  if [ "$want" != "$got" ]; then
    rm -f "$TMP/$ARCHIVE"
    die "checksum mismatch for $ARCHIVE (want $want, got $got)"
  fi
  say "Checksum verified."
fi

# Optional cosign provenance — non-fatal if cosign is absent.
if command -v cosign >/dev/null 2>&1; then
  if curl -fsSL "$REL/$ARCHIVE.bundle" -o "$TMP/$ARCHIVE.bundle" 2>/dev/null; then
    if cosign verify-blob \
        --bundle "$TMP/$ARCHIVE.bundle" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        --certificate-identity-regexp "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/.*" \
        "$TMP/$ARCHIVE" >/dev/null 2>&1; then
      say "Signature verified."
    else
      die "cosign signature verification failed for $ARCHIVE"
    fi
  else
    warn "no cosign bundle published for this release — skipping signature check"
  fi
else
  warn "cosign not installed — skipping signature verification"
fi

tar xzf "$TMP/$ARCHIVE" -C "$TMP"
SRC="$TMP/mvmctl-${TARGET}"
[ -f "$SRC/mvmctl" ] || die "archive missing mvmctl-${TARGET}/mvmctl"

mkdir -p "$INSTALL_DIR" 2>/dev/null || true
if [ -w "$INSTALL_DIR" ] || mkdir -p "$INSTALL_DIR" 2>/dev/null; then
  SUDO=""
else
  warn "$INSTALL_DIR not writable — using sudo"
  SUDO="sudo"
fi

$SUDO install -m 0755 "$SRC/mvmctl" "$INSTALL_DIR/mvmctl"
if [ -d "$SRC/resources" ]; then
  $SUDO rm -rf "$INSTALL_DIR/resources"
  $SUDO cp -R "$SRC/resources" "$INSTALL_DIR/resources"
fi

# macOS: Hypervisor.framework needs the entitlement. Best-effort —
# a re-sign failure warns but doesn't fail the install (the binary
# still runs for non-hypervisor uses; `codesign` can be re-run).
if [ "$(uname -s)" = "Darwin" ] && [ "${MVM_SKIP_CODESIGN:-}" != "1" ]; then
  ent="$INSTALL_DIR/resources/mvmctl.entitlements"
  if command -v codesign >/dev/null 2>&1 && [ -f "$ent" ]; then
    if $SUDO codesign --entitlements "$ent" -f -s - "$INSTALL_DIR/mvmctl" 2>/dev/null; then
      say "Codesigned with Hypervisor.framework entitlement."
    else
      warn "codesign failed — re-run: codesign --entitlements $ent -f -s - $INSTALL_DIR/mvmctl"
    fi
  fi
fi

say "Installed: $INSTALL_DIR/mvmctl"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "Add to PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
say "Run 'mvmctl doctor' to check your host."
```

- [ ] **Step 2: Make it executable + shellcheck locally**

Run: `chmod +x install.sh && shellcheck -S warning install.sh`
Expected: no warnings. (If `shellcheck` isn't installed: `brew install shellcheck` / `apt-get install shellcheck`.)

- [ ] **Step 3: Commit**

```bash
git add install.sh
git commit -m "feat(install): add curl-able install.sh"
```

### Task B2: Integration test for `install.sh`

**Files:**
- Create: `tests/install_sh.rs`

This test serves release fixtures over a loopback `TcpListener`, points the script's URL/dir overrides at it, runs the script, and asserts the binary lands and a tampered checksum is rejected.

- [ ] **Step 1: Write the failing test**

Create `tests/install_sh.rs`:

```rust
//! Integration test for the repo-root install.sh. Serves fake release
//! assets over a loopback HTTP server and drives the script with its
//! documented env overrides.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

fn host_target() -> &'static str {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-unknown-linux-gnu"
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d: [u8; 32] = Sha256::digest(bytes).into();
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Build a gzipped tar containing `mvmctl-<target>/mvmctl` (+ a
/// resources dir) where mvmctl is a shell stub printing a version.
fn make_tarball(target: &str) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let dir = format!("mvmctl-{target}");
    let stub = b"#!/bin/sh\necho 'mvmctl 9.9.9'\n";
    let mut tar = tar::Builder::new(Vec::new());
    let mut hdr = tar::Header::new_gnu();
    hdr.set_size(stub.len() as u64);
    hdr.set_mode(0o755);
    hdr.set_cksum();
    tar.append_data(&mut hdr, format!("{dir}/mvmctl"), &stub[..]).unwrap();
    let ent = b"<plist></plist>\n";
    let mut h2 = tar::Header::new_gnu();
    h2.set_size(ent.len() as u64);
    h2.set_mode(0o644);
    h2.set_cksum();
    tar.append_data(&mut h2, format!("{dir}/resources/mvmctl.entitlements"), &ent[..]).unwrap();
    let tar_bytes = tar.into_inner().unwrap();
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

/// Minimal loopback HTTP server. `routes` maps request-path → body.
/// Runs until the returned sender is dropped.
fn serve(routes: Vec<(String, Vec<u8>)>) -> (String, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || loop {
        if rx.try_recv().is_ok() {
            return;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/");
                let body = routes.iter().find(|(p, _)| p == path).map(|(_, b)| b.clone());
                match body {
                    Some(b) => {
                        let hdr = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len());
                        let _ = stream.write_all(hdr.as_bytes());
                        let _ = stream.write_all(&b);
                    }
                    None => {
                        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    }
                }
            }
            Err(_) => thread::sleep(std::time::Duration::from_millis(10)),
        }
    });
    (format!("http://{addr}"), tx)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn install_sh_downloads_verifies_and_installs() {
    let target = host_target();
    let tarball = make_tarball(target);
    let archive = format!("mvmctl-{target}.tar.gz");
    let checks = format!("{}  {}\n", sha256_hex(&tarball), archive);
    let routes = vec![
        (format!("/tinylabscom/mvm/releases/download/v9.9.9/{archive}"), tarball.clone()),
        ("/tinylabscom/mvm/releases/download/v9.9.9/checksums-sha256.txt".to_string(), checks.into_bytes()),
    ];
    let (base, _stop) = serve(routes);

    let install_dir = tempfile::tempdir().unwrap();
    let status = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .env("MVM_VERSION", "v9.9.9")
        .env("MVM_UPDATE_DOWNLOAD_URL", &base)
        .env("MVM_INSTALL_DIR", install_dir.path())
        .env("MVM_SKIP_CODESIGN", "1")
        .status()
        .unwrap();
    assert!(status.success(), "install.sh should succeed");
    assert!(install_dir.path().join("mvmctl").exists(), "binary installed");
}

#[test]
fn install_sh_rejects_tampered_checksum() {
    let target = host_target();
    let tarball = make_tarball(target);
    let archive = format!("mvmctl-{target}.tar.gz");
    // Wrong checksum on purpose.
    let checks = format!("{}  {}\n", "0".repeat(64), archive);
    let routes = vec![
        (format!("/tinylabscom/mvm/releases/download/v9.9.9/{archive}"), tarball),
        ("/tinylabscom/mvm/releases/download/v9.9.9/checksums-sha256.txt".to_string(), checks.into_bytes()),
    ];
    let (base, _stop) = serve(routes);

    let install_dir = tempfile::tempdir().unwrap();
    let status = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .env("MVM_VERSION", "v9.9.9")
        .env("MVM_UPDATE_DOWNLOAD_URL", &base)
        .env("MVM_INSTALL_DIR", install_dir.path())
        .env("MVM_SKIP_CODESIGN", "1")
        .status()
        .unwrap();
    assert!(!status.success(), "tampered checksum must fail the install");
    assert!(!install_dir.path().join("mvmctl").exists(), "no binary on failure");
}
```

- [ ] **Step 2: Add test-only dev-dependencies**

Confirm the root `Cargo.toml` `[dev-dependencies]` has `sha2`, `flate2`, `tar`, and `tempfile`. Add any missing (these are already used elsewhere in the workspace — prefer the versions in `Cargo.lock`):

```toml
[dev-dependencies]
sha2 = "0.10"
flate2 = "1"
tar = "0.4"
tempfile = "3"
```

(Check first with `grep -n "^\[dev-dependencies\]" Cargo.toml` and only add entries that are absent.)

- [ ] **Step 3: Run test to verify it passes**

Run: `cargo test --test install_sh`
Expected: PASS (both tests). On macOS the codesign step is skipped via `MVM_SKIP_CODESIGN=1`.

- [ ] **Step 4: Commit**

```bash
git add tests/install_sh.rs Cargo.toml Cargo.lock
git commit -m "test(install): hermetic install.sh download + tamper-reject test"
```

### Task B3: shellcheck in CI

**Files:**
- Modify: `.github/workflows/ci.yml` (lint job — add a step after "Check formatting", ~line 56)

- [ ] **Step 1: Add the shellcheck step**

In the `lint` job's `steps`, after the `- name: Check formatting` step, insert:

```yaml
      - name: Shellcheck install.sh
        run: |
          sudo apt-get install -y shellcheck
          shellcheck -S warning install.sh
```

(`apt-get update` already ran in the "Install system build deps" step above.)

- [ ] **Step 2: Validate YAML locally**

Run: `cargo run -p xtask -- --help >/dev/null 2>&1 || true; python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"`
Expected: `yaml ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: shellcheck install.sh in lint job"
```

---

## Phase C — Homebrew tap

### Task C1: Formula template + render script + test

**Files:**
- Create: `packaging/homebrew/mvmctl.rb.tmpl` (template with `@@VERSION@@` / `@@SHA_*@@` placeholders)
- Create: `packaging/homebrew/render-formula.sh` (fills the template from release checksums)
- Create: `tests/homebrew_render.rs` (golden-render check)

- [ ] **Step 1: Write the template**

Create `packaging/homebrew/mvmctl.rb.tmpl`:

```ruby
# typed: false
# frozen_string_literal: true

# mvmctl — Firecracker microVM development tool.
# This file is generated on release by render-formula.sh; do not edit by hand.
class Mvmctl < Formula
  desc "Build and run Firecracker microVMs on macOS and Linux"
  homepage "https://github.com/tinylabscom/mvm"
  version "@@VERSION@@"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/tinylabscom/mvm/releases/download/v@@VERSION@@/mvmctl-aarch64-apple-darwin.tar.gz"
      sha256 "@@SHA_AARCH64_DARWIN@@"
    end
    on_intel do
      url "https://github.com/tinylabscom/mvm/releases/download/v@@VERSION@@/mvmctl-x86_64-apple-darwin.tar.gz"
      sha256 "@@SHA_X86_64_DARWIN@@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/tinylabscom/mvm/releases/download/v@@VERSION@@/mvmctl-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "@@SHA_AARCH64_LINUX@@"
    end
    on_intel do
      url "https://github.com/tinylabscom/mvm/releases/download/v@@VERSION@@/mvmctl-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "@@SHA_X86_64_LINUX@@"
    end
  end

  def install
    bin.install "mvmctl"
    (prefix/"resources").install Dir["resources/*"] if Dir.exist?("resources")
    # macOS: Hypervisor.framework requires the entitlement; re-sign ad-hoc.
    if OS.mac? && File.exist?("resources/mvmctl.entitlements")
      system "codesign", "--entitlements", "resources/mvmctl.entitlements",
             "-f", "-s", "-", bin/"mvmctl"
    end
  end

  def caveats
    <<~EOS
      macOS (non-Apple-Silicon-26+) needs the libkrun trio:
        brew install slp/krun/libkrun slp/krun/libkrunfw slp/krun/gvproxy
      Run `mvmctl doctor` to verify your host.
    EOS
  end

  test do
    assert_match "mvmctl", shell_output("#{bin}/mvmctl --version")
  end
end
```

- [ ] **Step 2: Write the render script**

Create `packaging/homebrew/render-formula.sh`:

```sh
#!/bin/sh
# Render mvmctl.rb from the template + a checksums-sha256.txt file.
# Usage: render-formula.sh <version-no-v> <checksums-file> <out.rb>
set -eu
VERSION="$1"; CHECKSUMS="$2"; OUT="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"

sha_for() { grep " $1\$" "$CHECKSUMS" | awk '{print $1}' | head -n1; }

A_DARWIN="$(sha_for mvmctl-aarch64-apple-darwin.tar.gz)"
X_DARWIN="$(sha_for mvmctl-x86_64-apple-darwin.tar.gz)"
A_LINUX="$(sha_for mvmctl-aarch64-unknown-linux-gnu.tar.gz)"
X_LINUX="$(sha_for mvmctl-x86_64-unknown-linux-gnu.tar.gz)"

for v in "$A_DARWIN" "$X_DARWIN" "$A_LINUX" "$X_LINUX"; do
  [ -n "$v" ] || { echo "missing a checksum in $CHECKSUMS" >&2; exit 1; }
done

sed \
  -e "s/@@VERSION@@/$VERSION/g" \
  -e "s/@@SHA_AARCH64_DARWIN@@/$A_DARWIN/g" \
  -e "s/@@SHA_X86_64_DARWIN@@/$X_DARWIN/g" \
  -e "s/@@SHA_AARCH64_LINUX@@/$A_LINUX/g" \
  -e "s/@@SHA_X86_64_LINUX@@/$X_LINUX/g" \
  "$HERE/mvmctl.rb.tmpl" > "$OUT"
```

- [ ] **Step 3: Write the failing test**

Create `tests/homebrew_render.rs`:

```rust
//! Verifies render-formula.sh fills every placeholder from a checksums file.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn render_formula_fills_all_placeholders() {
    let tmp = tempfile::tempdir().unwrap();
    let checks = tmp.path().join("checksums-sha256.txt");
    std::fs::write(
        &checks,
        "aaaa  mvmctl-aarch64-apple-darwin.tar.gz\n\
         bbbb  mvmctl-x86_64-apple-darwin.tar.gz\n\
         cccc  mvmctl-aarch64-unknown-linux-gnu.tar.gz\n\
         dddd  mvmctl-x86_64-unknown-linux-gnu.tar.gz\n",
    )
    .unwrap();
    let out = tmp.path().join("mvmctl.rb");

    let status = Command::new("sh")
        .arg(repo_root().join("packaging/homebrew/render-formula.sh"))
        .arg("0.15.2")
        .arg(&checks)
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());

    let rendered = std::fs::read_to_string(&out).unwrap();
    assert!(!rendered.contains("@@"), "no placeholder should remain");
    assert!(rendered.contains("version \"0.15.2\""));
    assert!(rendered.contains("sha256 \"aaaa\""));
    assert!(rendered.contains("sha256 \"dddd\""));
}
```

- [ ] **Step 4: Run test to verify it fails, then passes**

Run: `chmod +x packaging/homebrew/render-formula.sh && cargo test --test homebrew_render`
Expected: PASS (after the script + template exist). If it fails before they exist, that's the red step.

- [ ] **Step 5: shellcheck the render script**

Run: `shellcheck -S warning packaging/homebrew/render-formula.sh`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add packaging/homebrew/mvmctl.rb.tmpl packaging/homebrew/render-formula.sh tests/homebrew_render.rs
git commit -m "feat(homebrew): formula template + render script + test"
```

### Task C2: Auto-bump-to-tap workflow

**Files:**
- Create: `.github/workflows/update-homebrew-tap.yml`

- [ ] **Step 1: Write the workflow**

Create `.github/workflows/update-homebrew-tap.yml`:

```yaml
name: Update Homebrew tap

# On a published release, render the formula from the release's
# checksums and push it to the tinylabscom/homebrew-mvm tap repo.
# Requires the HOMEBREW_TAP_TOKEN secret (push access to the tap repo);
# the default GITHUB_TOKEN cannot push to a second repository.
on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      tag:
        description: "Release tag (e.g. v0.15.2)"
        required: true

permissions:
  contents: read

jobs:
  update-tap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Resolve tag
        id: tag
        env:
          EVENT_TAG: ${{ github.event.release.tag_name }}
          INPUT_TAG: ${{ github.event.inputs.tag }}
        run: |
          TAG="${EVENT_TAG:-$INPUT_TAG}"
          echo "tag=$TAG" >> "$GITHUB_OUTPUT"
          echo "version=${TAG#v}" >> "$GITHUB_OUTPUT"

      - name: Download release checksums
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TAG: ${{ steps.tag.outputs.tag }}
        run: |
          gh release download "$TAG" --repo tinylabscom/mvm \
            --pattern checksums-sha256.txt --dir .

      - name: Render formula
        env:
          VERSION: ${{ steps.tag.outputs.version }}
        run: |
          chmod +x packaging/homebrew/render-formula.sh
          packaging/homebrew/render-formula.sh "$VERSION" checksums-sha256.txt mvmctl.rb
          echo "=== rendered formula ===" && cat mvmctl.rb

      - name: Audit formula
        run: |
          brew style mvmctl.rb || true
          brew audit --formula --new mvmctl.rb || true

      - name: Push to tap
        env:
          TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
          VERSION: ${{ steps.tag.outputs.version }}
        run: |
          if [ -z "$TAP_TOKEN" ]; then
            echo "::error::HOMEBREW_TAP_TOKEN not set — see reference/releases docs for tap setup" >&2
            exit 1
          fi
          git clone "https://x-access-token:${TAP_TOKEN}@github.com/tinylabscom/homebrew-mvm.git" tap
          mkdir -p tap/Formula
          cp mvmctl.rb tap/Formula/mvmctl.rb
          cd tap
          git config user.name "mvm-release-bot"
          git config user.email "release-bot@users.noreply.github.com"
          git add Formula/mvmctl.rb
          git commit -m "mvmctl ${VERSION}" || { echo "no change"; exit 0; }
          git push
```

- [ ] **Step 2: Validate YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/update-homebrew-tap.yml')); print('yaml ok')"`
Expected: `yaml ok`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/update-homebrew-tap.yml
git commit -m "ci: render + push Homebrew formula to tap on release"
```

---

## Phase D — Kernel docs

### Task D1: `guides/kernels.md`

**Files:**
- Create: `public/src/content/docs/guides/kernels.md`
- Modify: the Astro sidebar config (find with `grep -rl "guides/builder-vm" public/ astro.config.* 2>/dev/null`; if the sidebar is autogenerated from the directory, no edit is needed — verify)

- [ ] **Step 1: Write the page**

Create `public/src/content/docs/guides/kernels.md`:

```markdown
---
title: "Custom microVM kernels"
description: "Build or download the slim builder/workload kernels mvm boots, with mvmctl kernel build."
---

mvm boots slim, custom-configured Linux kernels for the builder VM and for
workload microVMs. Because the config is custom, the public Nix cache has no
substitute for them — a fresh machine compiles from source, which is the slow,
memory-heavy step a first `mvmctl dev up` otherwise hits implicitly.
`mvmctl kernel build` makes that step explicit and one-time.

## Build a kernel

```bash
# Compile the builder kernel for this host (slow on first run, then cached)
mvmctl kernel build --which builder --source compile

# Download the prebuilt, hash-verified kernel that shipped with this mvmctl
mvmctl kernel build --which workload --source download

# Download if a prebuilt exists for this release, else compile locally
mvmctl kernel build --all --source auto
```

Flags:

- `--which {builder,workload}` — which kernel (default `builder`).
- `--all` — build both variants.
- `--source {compile,download,auto}` — where the kernel comes from (default `compile`).
- `--arch {aarch64,x86_64}` — target arch (default: host arch).

The compiled or downloaded kernel is cached at
`~/.cache/mvm/builder-vm/<arch>/kernels/<variant>/vmlinux` and reused by every
later `dev up`.

## compile vs download

- **compile** builds locally through the Stage 0 bootstrap. It can only build
  the **host** architecture — Stage 0 boots a host-arch VM, so it cannot
  cross-compile. First compile is 3–10 min; later runs hit the persistent Nix
  store. The compile path prints an elapsed-time heartbeat, and `--verbose`
  streams the live `nix build` console output.
- **download** fetches a prebuilt `vmlinux-<arch>-<variant>` from the GitHub
  release whose tag matches **this mvmctl's own version**. A given mvmctl can
  only ever fetch the kernel that shipped with it — never a substitute for an
  in-tree kernel-config edit (a source checkout compiles instead). This is the
  only way to obtain the **other** architecture's kernel.

## Integrity

Downloaded kernels are SHA-256-verified against the release's
`kernel-<arch>-checksums-sha256.txt` before being admitted to the cache; a
mismatch deletes the download and aborts. `MVM_SKIP_HASH_VERIFY=1` is the
documented emergency escape — never use it in CI.

The kernels themselves are published by the `kernel-build` GitHub Actions
workflow on every `v*` release tag. See [Releases & downloads](/reference/releases/)
for the full pipeline.
```

- [ ] **Step 2: Add a link from the builder-VM guide**

In `public/src/content/docs/guides/builder-vm.md` (verify it exists with `ls public/src/content/docs/guides/builder-vm.md`), add a "See also" line near the top or bottom:

```markdown
See also: [Custom microVM kernels](/guides/kernels/) for `mvmctl kernel build`.
```

- [ ] **Step 3: Verify doc gates pass**

Run: `cargo run -p xtask -- check-doc-claims && cargo run -p xtask -- check-no-overclaim`
Expected: both pass (exit 0).

- [ ] **Step 4: Commit**

```bash
git add public/src/content/docs/guides/kernels.md public/src/content/docs/guides/builder-vm.md
git commit -m "docs: guide for mvmctl kernel build (compile/download/auto)"
```

---

## Phase E — Releases & downloads doc

### Task E1: `reference/releases.md`

**Files:**
- Create: `public/src/content/docs/reference/releases.md`

- [ ] **Step 1: Write the page**

Create `public/src/content/docs/reference/releases.md`:

```markdown
---
title: "Releases & downloads"
description: "How mvm's v* release tags publish binaries, kernels, and images — and how each install path consumes them."
---

Every `v*` git tag fires two GitHub Actions workflows that publish a single
GitHub Release:

- **`release.yml`** builds `mvmctl` for all four targets
  (`aarch64`/`x86_64` × macOS/Linux), packages each as
  `mvmctl-<target>.tar.gz` (binary + `resources/` + man pages), generates
  `checksums-sha256.txt`, cosign-signs every tarball, and also builds the
  dev / builder / default-microvm / builder-vm / runtime-overlay images.
- **`kernel-build.yml`** builds the slim builder + workload kernels on native
  aarch64 and x86_64 runners and uploads `vmlinux-<arch>-<variant>` +
  `kernel-<arch>-checksums-sha256.txt`.

## How each install path consumes a release

| Path | What it pulls |
|------|---------------|
| `install.sh` (curl one-liner) | `mvmctl-<target>.tar.gz` + `checksums-sha256.txt` (+ cosign `.bundle` if cosign present) |
| `brew install tinylabscom/mvm/mvmctl` | the same tarball, via the tap formula |
| `cargo install mvmctl` | source from crates.io (published by `publish-crates.yml`) |
| `mvmctl update` | the tarball for the latest release, in-place swap |
| `mvmctl kernel build --source download` | `vmlinux-<arch>-<variant>` + `kernel-<arch>-checksums-sha256.txt`, pinned to the binary's own release tag |

## Verifying provenance

All release tarballs are cosign-signed (keyless, GitHub OIDC). To verify
manually:

```bash
cosign verify-blob \
  --bundle mvmctl-<target>.tar.gz.bundle \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/.*' \
  mvmctl-<target>.tar.gz
```

`install.sh` and `mvmctl update` run this automatically when `cosign` is on
`PATH`.

## Homebrew tap setup (one-time, maintainers)

The `update-homebrew-tap.yml` workflow renders the formula on each release and
pushes it to the `tinylabscom/homebrew-mvm` tap. To enable it once:

1. Create an empty public repo `tinylabscom/homebrew-mvm` with a `Formula/`
   directory.
2. Add a repository secret `HOMEBREW_TAP_TOKEN` to `tinylabscom/mvm` — a token
   (fine-grained PAT or deploy key) with **push** access to the tap repo. The
   default `GITHUB_TOKEN` cannot push to a second repository.

After that, every `v*` release auto-updates `Formula/mvmctl.rb` in the tap, and
`brew install tinylabscom/mvm/mvmctl` resolves the latest version.
```

- [ ] **Step 2: Verify doc gates pass**

Run: `cargo run -p xtask -- check-doc-claims && cargo run -p xtask -- check-no-overclaim`
Expected: both pass.

- [ ] **Step 3: Commit**

```bash
git add public/src/content/docs/reference/releases.md
git commit -m "docs: releases & downloads reference"
```

---

## Final verification

- [ ] **Full workspace gates**

```bash
rustup run nightly cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --test install_sh --test homebrew_render
shellcheck -S warning install.sh packaging/homebrew/render-formula.sh
```

Expected: all green.

- [ ] **Smoke the heartbeat/verbose manually (this Mac builds via Vz/libkrun)**

Run (background + timeout per the never-run-unbounded rule):
```bash
gtimeout 600 cargo run -- kernel build --verbose 2>&1 | tee /tmp/mvm-kernel-verbose.log
```
Expected: streamed `console.log` output (nix build lines) appears live, not 4 minutes of silence. Then without `--verbose`:
```bash
gtimeout 600 cargo run -- kernel build 2>&1 | tee /tmp/mvm-kernel-quiet.log
```
Expected: `still compiling… (Nm SSs elapsed)` lines every ~20s.

- [ ] **Open the PR**

```bash
git push -u origin feat/install-download-experience
gh pr create --title "Install & download experience: install.sh, Homebrew tap, kernel/release docs, compile logging" --body "Implements docs/superpowers/specs/2026-06-03-install-download-experience-design.md"
```

---

## Self-review notes (for the implementer)

- The `verbose` flag is named `verbose` consistently from `Cli.verbose` →
  `with_verbose` → `spawn_supervisor_and_wait` → `wait_with_panic_detector_until`
  → `panic_watcher`. Don't rename it mid-path.
- `format_compile_elapsed` and `echo_console_chunk` are the only pure helpers
  added; both have unit tests.
- Every new shell script is shellchecked (`install.sh`, `render-formula.sh`).
- The Homebrew tap workflow fails loudly if `HOMEBREW_TAP_TOKEN` is unset
  rather than silently no-op'ing.
- Out of scope (per spec): pre-fetching kernels in install.sh, `install.ps1`,
  cask/source formula, filtered verbose output, wiring `--verbose` into the
  `dev up` `run_stage0_root_dir` path (left for a dev-up pass).
```

# Plan 137 — Vendor gvproxy under `libgvproxy-sys` (drop the brew dep)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop requiring `brew install slp/krun/gvproxy` on macOS. Build gvproxy from a commit-pinned source at build time, embed it in a new `crates/deps/libgvproxy-sys` crate, and have the existing gvproxy locator fall back to the embedded copy when no system gvproxy is found. The version becomes deterministic and lockstep-pinned.

**Honest framing (read first):** this delivers **~0 third-party-dependency-count reduction** — gvproxy is a *system binary*, not a Rust crate, so vendoring it does not shrink the Cargo graph (ADR-066 §"Dependency-reduction reality", L71). The only wins are: (a) one fewer `brew install` on macOS, and (b) a deterministic, hash-pinned gvproxy. It also trades a *runtime* brew dep for a *build-time* Go-toolchain dep on source-checkout contributors (see Prereqs). Do not sell this as dep reduction.

**Architecture:** ADR-066 §2 (the `crates/deps/*-sys` FFI/vendoring directory) reserves `libgvproxy-sys` as the "anticipated, highest-value" add. ADR-055 owns the gateway story (passt on Linux, gvproxy on macOS). The **process model is unchanged**: gvproxy stays a spawned subprocess owning a unixgram socket that libkrun attaches via `krun_add_net_unixgram`. We keep our own spawn-layer abstraction — `NetworkingMode` (`crates/mvm-libkrun/src/lib.rs:329`), `GatewayHandle` (`lib.rs:665`), the per-impl `GvproxyHandle`/`PasstHandle`, and the Vz-detached `crates/mvm-backend/src/host_gvproxy.rs`. **No new trait is introduced** (krunai's `NetworkProxy` trait was evaluated; our enum/handle dispatch already covers it and carries two reap models its single-`Child` handle does not).

**Why not `c-shared` (the literal ADR-066 wording):** building gvproxy `-buildmode=c-shared` and linking it in-process would pull the Go runtime (GC + signal handling) into the host supervisor, conflict with Rust signal handling, require a patched gvproxy fork exposing a callable entry, and dissolve the per-process jailer boundary (ADR-066 §3 / `mvm-jailer-lite`). The libkrun author's own reference, [`slp/krunai`](https://github.com/slp/krunai), keeps gvproxy a spawned subprocess (`src/gvproxy.rs`: `which gvproxy` over `$PATH` + `/usr/libexec/podman/gvproxy`, then `Command::spawn`; `build.rs` links only libkrun). That validates the subprocess model and rules out c-shared. Recorded here as considered-and-rejected.

**Tech Stack:** new `crates/deps/libgvproxy-sys` (build-from-source + `include_bytes!` + extract-to-cache); `crates/mvm-libkrun/src/gvproxy.rs` (locator); `crates/mvm-backend/src/host_gvproxy.rs` (Vz locator); `crates/mvm-cli/src/doctor.rs` (probe); docs + CI. Build-time Go toolchain. No new third-party Rust crates.

**Prereqs:**
- ADR-066 §2 (accepted) reserves the crate home.
- **Coordination with Plan 121** (the 32→17 crate consolidation that physically creates `crates/deps/` and the `mvm-network` consumer). On the current tree `crates/deps/` does not exist yet and `libkrun-sys` still lives inside `mvm-libkrun`. Plan 137 creates `crates/deps/libgvproxy-sys`; if Plan 121 lands first it owns the consumer relocation. The two must not collide on the directory.
- **Go toolchain at build time** for source-checkout contributors — the analog of the existing zig + cargo-zigbuild requirement (CLAUDE.md "source-checkout contributors only"). End-users running a downloaded `mvmctl` get the embedded binary and need neither Go nor brew.

---

## Phase A — `crates/deps/libgvproxy-sys` (vendor + build + embed)

### Task A1: crate skeleton + pinned source
- [ ] Create `crates/deps/libgvproxy-sys/` (Cargo member). Pin gvproxy by **commit SHA + recorded sha256** of `containers/gvisor-tap-vsock` in a `vendor.lock`-style constant; document the **bump-in-lockstep / review-on-CVE** cadence rule (mirror the existing zig pin discipline) in the crate's `CLAUDE.md`.
- [ ] Decide source acquisition that honors hermeticity (no external build-cache providers): vendored source tree or a fetch-and-verify-sha256 in `build.rs`.

### Task A2: `build.rs` builds the Go binary
- [ ] `build.rs` invokes the Go toolchain to build the pinned gvproxy for the host arch (model on `crates/mvm-cli/build.rs`'s cross-compile/toolchain-probe pattern). Feature-gate so the build is skippable where the embedded binary is not wanted.
- [ ] Emit the built binary to `OUT_DIR`; record its sha256 for the reproducibility check.

### Task A3: embed + extract API
- [ ] `include_bytes!` the built binary; expose `pub fn ensure_gvproxy() -> io::Result<PathBuf>` that extracts to a stable cache path (under `~/.cache/mvm/`) with mode 0700, idempotent, returns the executable path.
- [ ] Unit test: `ensure_gvproxy()` yields an existing, executable file; second call is a no-op hit.

---

## Phase B — wire the embedded fallback into the existing locator

### Task B1: layered locator (libkrun lane)
- [ ] `crates/mvm-libkrun/src/gvproxy.rs::locate_gvproxy()` (≈L116): resolve **system PATH → `/usr/libexec/podman/gvproxy` → `libgvproxy_sys::ensure_gvproxy()`** instead of `which::which("gvproxy")` alone. Spawn/socket/reap (`GvproxyHandle`, Drop SIGTERM→SIGKILL) unchanged.
- [ ] `install_hint()` (≈L101) becomes a build-config/diagnostic message, not a `brew install slp/krun/gvproxy` string.

### Task B2: layered locator (Vz lane)
- [ ] `crates/mvm-backend/src/host_gvproxy.rs::spawn_detached()` (≈L76) uses the same layered resolution. Detached PID-file reap unchanged.

---

## Phase C — doctor, docs, CI lane

### Task C1: doctor
- [ ] `crates/mvm-cli/src/doctor.rs::network_backend_check()` (≈L1015–1078): report the embedded/pinned gvproxy version (and whether a system gvproxy shadowed it) instead of failing when PATH has none. Install hint reflects the embedded model.

### Task C2: docs
- [ ] `CLAUDE.md` L20–31 + L46–47: drop `slp/krun/gvproxy` from the Homebrew trio; state gvproxy is embedded (no brew needed on macOS); keep `libkrun` + `libkrunfw`.
- [ ] `public/src/content/docs/contributing/development.md` L69–71: remove gvproxy from the E2E prerequisites.
- [ ] `specs/adrs/055-passt-virtio-net.md` §"Cross-platform backends": note gvproxy is now vendored/embedded on macOS.

### Task C3: Plan 120 core-demo CI lane
- [ ] `.github/workflows/ci.yml:1061–1071` ("Verify Homebrew prerequisites"): drop `gvproxy` from the package loop; trim the install hint to `slp/krun/libkrun slp/krun/libkrunfw`. The `core_demo_e2e.rs` test and Plan 120's design are unchanged — gvproxy resolves via the embedded fallback at runtime. The lane gets one prereq more hermetic.

### Task C4: ADR-066 §2 amendment
- [ ] Change the `libgvproxy-sys` row note (ADR-066 L64) from "vendored as a lib" to "vendored + built-from-pinned-source, embedded binary (not c-shared — keeps the jailable subprocess boundary; see Plan 137)". Leave ADR-064's `bubblewrap` rejection intact.

---

## Verification

- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` all green.
- [ ] Unit: `ensure_gvproxy()` extracts an executable; idempotent on second call.
- [ ] With **no** gvproxy on PATH and none at the podman path, `mvmctl doctor` reports the embedded pinned version (not MISSING).
- [ ] With a system gvproxy present, the locator prefers it (no behavior change for existing installs).
- [ ] The Plan 120 `core_demo_e2e` libkrun lane still boots and pings (gvproxy socket still wired) on a box **without** `brew install gvproxy`.
- [ ] Reproducibility: same pinned source SHA → identical embedded bytes (recorded sha256 matches).

## Deferred follow-ups

- [ ] `c-shared` in-process gvproxy — **rejected** (Go-runtime-in-host + jailer-boundary rationale above). Recorded, not scheduled.
- [ ] `e2fsprogs-sys` — still deferred per ADR-066 L72 (ext4 assembly runs under the nix-pinned `e2fsprogs` in the builder VM; vendor only if that work leaves the nix env).
- [ ] A pure-Rust vfkit-unixgram gateway on `smoltcp`/`netstack-smoltcp` — strategic, large; would yield first-party fuzzable Rust and close the ADR-055 L148 gap (gvproxy's parser is upstream Go). Out of scope here.

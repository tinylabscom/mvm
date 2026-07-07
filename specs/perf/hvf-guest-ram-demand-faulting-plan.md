# HVF Guest RAM Demand-Faulting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Back HVF guest RAM with a demand-zero `mmap` region owned by a small RAII type, so host memory tracks a guest's working set instead of its allocation.

**Architecture:** Introduce a `GuestRam` type in a new `crates/mvm-backend/src/hvf/guest_ram.rs` module that owns an `mmap(MAP_ANON | MAP_PRIVATE)` region and `munmap`s on `Drop`. Rework `kernel_boot.rs` to allocate through it, deleting the `alloc_zeroed` call and the three hand-rolled free paths. Confirm the shipped supervisor is release-built, re-measure, then record a data-backed decision on the smaller levers.

**Tech Stack:** Rust, `libc` (already a workspace dep of `mvm-backend`), Hypervisor.framework (`hv_vm_map`), `cargo nextest`.

## Global Constraints

- HVF only — do not touch libkrun / Firecracker / Vz / QEMU guest-memory paths.
- No guest-visible change: same `hv_vm_map` flags, cmdline, boot protocol.
- Demand-zero is load-bearing: never memset the region (that re-touches every page and defeats the change). `MAP_ANON` pages are kernel-zeroed on first fault.
- No spec/plan/PR/ADR identifiers in code comments (CI-gated).
- No `Co-Authored-By: Claude` trailer on commits; attribute to the user.
- Zero clippy warnings; `#[allow(clippy::too_many_arguments)]` is banned.
- All work stays on the worktree branch `worktree-hvf-ram-demandfault-spike`.
- Build/test with rustup cargo: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH`.
- Aux binaries for live boots: `MVM_HVF_SUPERVISOR_PATH=<worktree>/target/debug/mvm-hvf-supervisor`, `MVM_SUBSTITUTION_ENDPOINT_PATH=<main>/target/debug/mvm-substitution-endpoint`.

---

## File Structure

- Create: `crates/mvm-backend/src/hvf/guest_ram.rs` — the `GuestRam` RAII type + its unit tests.
- Modify: `crates/mvm-backend/src/hvf/mod.rs` — declare the `guest_ram` module.
- Modify: `crates/mvm-backend/src/hvf/kernel_boot.rs` — allocate via `GuestRam`; delete `alloc_zeroed`/`dealloc`/`munmap` bookkeeping and the `Layout` import.
- Doc: `specs/perf/hvf-guest-ram-demand-faulting.md` — record Phase 2 measurements and the Phase 3 decision.

---

## Phase 1 — Productionize demand-faulting

### Task 1: `GuestRam` RAII type

**Files:**
- Create: `crates/mvm-backend/src/hvf/guest_ram.rs`
- Modify: `crates/mvm-backend/src/hvf/mod.rs`

**Interfaces:**
- Consumes: `HvfError` (from `crates/mvm-backend/src/hvf/mod.rs`; has an `Alloc` variant).
- Produces:
  - `pub(crate) struct GuestRam`
  - `GuestRam::new(len: usize) -> Result<GuestRam, HvfError>`
  - `GuestRam::as_ptr(&self) -> *mut u8`
  - `GuestRam::len(&self) -> usize`
  - `impl Drop for GuestRam` (calls `munmap`)

- [x] **Step 1: Declare the module**

In `crates/mvm-backend/src/hvf/mod.rs`, add alongside the other `mod` lines:

```rust
mod guest_ram;
```

- [x] **Step 2: Write the failing tests**

Create `crates/mvm-backend/src/hvf/guest_ram.rs`:

```rust
//! Guest physical RAM backed by a demand-zero anonymous mapping.
//!
//! Pages fault in on first guest access, so host residency follows the
//! guest's working set rather than its allocation, and each page is
//! kernel-zeroed on first fault so the guest never observes host memory.

use std::ptr::NonNull;

use super::HvfError;

pub(crate) struct GuestRam {
    ptr: NonNull<u8>,
    len: usize,
}

impl GuestRam {
    pub(crate) fn new(len: usize) -> Result<Self, HvfError> {
        unimplemented!()
    }

    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl Drop for GuestRam {
    fn drop(&mut self) {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 16 * 1024; // Apple-silicon hypervisor page size

    #[test]
    fn rejects_zero_length() {
        assert!(GuestRam::new(0).is_err());
    }

    #[test]
    fn allocates_requested_size_page_aligned() {
        let ram = GuestRam::new(PAGE * 4).expect("mmap");
        assert_eq!(ram.len(), PAGE * 4);
        assert!(!ram.as_ptr().is_null());
        assert_eq!(ram.as_ptr() as usize % PAGE, 0, "region must be page-aligned");
    }

    #[test]
    fn fresh_region_reads_as_zero() {
        let ram = GuestRam::new(PAGE * 2).expect("mmap");
        // Sample a few offsets across the region; demand-zero guarantees 0.
        for off in [0usize, PAGE, PAGE * 2 - 1] {
            let byte = unsafe { *ram.as_ptr().add(off) };
            assert_eq!(byte, 0, "offset {off} not zero-initialized");
        }
    }

    #[test]
    fn create_and_drop_many_does_not_exhaust_memory() {
        // Exercises the Drop/munmap path: leaking 64 MiB x 200 would OOM.
        for _ in 0..200 {
            let ram = GuestRam::new(64 * 1024 * 1024).expect("mmap");
            unsafe { *ram.as_ptr() = 1 }; // touch one page
        }
    }
}
```

- [x] **Step 3: Run tests to verify they fail**

Run: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH cargo nextest run -p mvm-backend guest_ram`
Expected: FAIL (panics at `unimplemented!()` / `not yet implemented`).

- [x] **Step 4: Implement `new` and `Drop`**

Replace the two `unimplemented!()` bodies:

```rust
    pub(crate) fn new(len: usize) -> Result<Self, HvfError> {
        if len == 0 {
            return Err(HvfError::Alloc);
        }
        // SAFETY: null hint + fixed args; MAP_ANON gives a fresh, page-aligned,
        // demand-zero mapping. Ownership is released via munmap in Drop.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(HvfError::Alloc);
        }
        let ptr = NonNull::new(raw.cast::<u8>()).ok_or(HvfError::Alloc)?;
        Ok(Self { ptr, len })
    }
```

```rust
impl Drop for GuestRam {
    fn drop(&mut self) {
        // SAFETY: ptr/len come from a successful mmap in new(); unmapped once.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}
```

- [x] **Step 5: Run tests to verify they pass**

Run: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH cargo nextest run -p mvm-backend guest_ram`
Expected: PASS (4 tests).

- [x] **Step 6: Clippy clean**

Run: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH cargo clippy -p mvm-backend -- -D warnings`
Expected: no warnings.

- [x] **Step 7: Commit**

```bash
git add crates/mvm-backend/src/hvf/guest_ram.rs crates/mvm-backend/src/hvf/mod.rs
git commit -m "feat(hvf): demand-zero GuestRam mmap type"
```

---

### Task 2: Allocate guest RAM through `GuestRam` in `kernel_boot.rs`

**Files:**
- Modify: `crates/mvm-backend/src/hvf/kernel_boot.rs`

**Interfaces:**
- Consumes: `GuestRam::new`, `GuestRam::as_ptr`, `GuestRam::len` (Task 1).
- Produces: no new public interface; `boot`/`run` internals switch from a raw `*mut u8` + `Layout` to a `GuestRam` owner. `run()` keeps its `ram: *mut u8` parameter, fed by `guest_ram.as_ptr()`.

- [x] **Step 1: Confirm current live baseline still reproduces**

The spike hack is already in this file. Reconfirm the number before refactoring so the refactor is proven behavior-preserving.

Run (from worktree, env per Global Constraints):
```bash
./target/debug/mvmctl machine run --image alpine --memory 512M --name kb1 -d
ps -o rss= -p "$(pgrep -f "$PWD/target/debug/mvm-hvf-supervisor")" | awk '{print int($1/1024)" MB"}'
./target/debug/mvmctl machine stop kb1; ./target/debug/mvmctl machine rm kb1
pkill -f "$PWD/target/debug/mvm-hvf-supervisor" 2>/dev/null || true
```
Expected: ~140–150 MB (matches the spike; NOT ~638 MB).

- [x] **Step 2: Replace the allocation site**

In `kernel_boot.rs`, replace the current spike block (the `Layout` line, the `let _ = &layout;` line, the `mmap` block, the `MAP_FAILED` check, and `let ram = ram as *mut u8;`) with:

```rust
    let guest_ram = GuestRam::new(ram_size)?;
    let ram = guest_ram.as_ptr();
```

Add the import near the top of the file:

```rust
use super::guest_ram::GuestRam;
```

Remove the now-unused `use std::alloc::Layout;` import.

- [x] **Step 3: Delete the manual free paths**

Remove all three teardown calls that free `ram` (the two error-path frees and the success-path free) — RAII now unmaps when `guest_ram` leaves scope. The error paths become bare `return Err(...)`; the success path drops `guest_ram` at function end. Concretely, delete these lines wherever they appear:

```rust
        unsafe { libc::munmap(ram.cast(), ram_size); };
```
```rust
            libc::munmap(ram.cast(), ram_size);
```
```rust
    unsafe { libc::munmap(ram.cast(), ram_size); };
```

Ensure `guest_ram` stays in scope until after `hv_vm_destroy()` (it is a local in `boot`, so it drops after the `run(...)` block that calls destroy — correct ordering).

- [x] **Step 4: Build the supervisor**

Run: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH cargo build -p mvm-vm-host --bin mvm-hvf-supervisor`
Expected: compiles, no `unused` warnings for `Layout`/`libc`.

- [x] **Step 5: Live re-verify (behavior-preserving + functional)**

Run (env per Global Constraints):
```bash
./target/debug/mvmctl machine run --image alpine --memory 512M -- sh -c 'echo GUEST_OK; grep MemTotal /proc/meminfo'
./target/debug/mvmctl machine run --image alpine --memory 512M --name kb2 -d
ps -o rss= -p "$(pgrep -f "$PWD/target/debug/mvm-hvf-supervisor")" | awk '{print int($1/1024)" MB"}'
./target/debug/mvmctl machine stop kb2; ./target/debug/mvmctl machine rm kb2
pkill -f "$PWD/target/debug/mvm-hvf-supervisor" 2>/dev/null || true
```
Expected: `GUEST_OK`, `MemTotal ~497424 kB`, idle RSS ~140–150 MB (unchanged from Step 1 — the type refactor preserves behavior).

- [x] **Step 6: Full HVF test + clippy**

Run: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH cargo nextest run -p mvm-backend`
Run: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH cargo clippy -p mvm-backend -p mvm-vm-host -- -D warnings`
Expected: pass; zero warnings. (If mvm-backend tests hit the macOS codesign SIGKILL noted in project memory, run with `-E 'not test(/boot_smoke/)'` locally and rely on the live check in Step 5.)

- [x] **Step 7: Commit**

```bash
git add crates/mvm-backend/src/hvf/kernel_boot.rs
git commit -m "refactor(hvf): allocate guest RAM through GuestRam RAII"
```

---

## Phase 2 — Release baseline + measurement

### Task 3: Confirm the shipped supervisor is release-built

**Files:**
- Inspect only (packaging/build scripts); Doc update if a fix is needed.

- [x] **Step 1: Find how the supervisor ships**

Run:
```bash
rg -n 'mvm-hvf-supervisor|release|--release|profile' crates/mvm-cli/build.rs Justfile .github/workflows/*.yml 2>/dev/null | rg -i 'hvf|release|supervisor' | head -30
```
Determine whether the packaged/embedded supervisor is built with `--release`.

- [x] **Step 2: Record the finding**

- If already release-built: note it in `specs/perf/hvf-guest-ram-demand-faulting.md` under Phase 2 and proceed to Task 4.
- If debug-built in the shipping path: that is a real defect — capture the exact file/line in the doc and add a follow-up task here to switch it to `--release` (with the build command and the before/after verification). Do not guess; base it on the packaging code found in Step 1.

- [x] **Step 3: Commit the doc update**

```bash
git add specs/perf/hvf-guest-ram-demand-faulting.md
git commit -m "docs(perf): record supervisor release-build posture"
```

---

### Task 4: Measure the release-build density baseline

**Files:**
- Doc: `specs/perf/hvf-guest-ram-demand-faulting.md`

- [x] **Step 1: Build the release supervisor**

Run: `RUSTC=$HOME/.cargo/bin/rustc PATH=$HOME/.cargo/bin:$PATH cargo build --release -p mvm-vm-host --bin mvm-hvf-supervisor`

- [x] **Step 2: Measure idle RSS at two allocations**

Run (env per Global Constraints, but point `MVM_HVF_SUPERVISOR_PATH` at `target/release/mvm-hvf-supervisor`):
```bash
for M in 128M 512M; do
  ./target/debug/mvmctl machine run --image alpine --memory "$M" --name relm -d
  ps -o rss= -p "$(pgrep -f "$PWD/target/release/mvm-hvf-supervisor")" | awk -v m="$M" '{print m": "int($1/1024)" MB"}'
  ./target/debug/mvmctl machine stop relm; ./target/debug/mvmctl machine rm relm
  pkill -f "$PWD/target/release/mvm-hvf-supervisor" 2>/dev/null || true
done
```
Expected: idle RSS well below the debug ~144 MB (fixed VMM overhead shrinks in release). Derive per-VM fixed overhead = RSS(512M) − 384 MB slope check against RSS(128M).

- [x] **Step 3: Record the density baseline**

In `specs/perf/hvf-guest-ram-demand-faulting.md` Phase 2 section, fill a table: release idle RSS at 128M/512M, derived fixed overhead, and the projected 1000-VM figure (idle-working-set × 1000). This is the number Phase 3 decisions are judged against.

- [x] **Step 4: Commit**

```bash
git add specs/perf/hvf-guest-ram-demand-faulting.md
git commit -m "docs(perf): record release density baseline"
```

---

## Phase 3 — Decide the smaller levers on real numbers

### Task 5: Written go/defer/drop decision

**Files:**
- Doc: `specs/perf/hvf-guest-ram-demand-faulting.md`

- [x] **Step 1: Default `--memory` sizing decision**

Find the current default:
```bash
rg -n 'memory|mem_mib|default.*512|512.*default' crates/mvm-cli/src/commands crates/mvm-backend/src/base/config.rs | rg -i 'default|512|mem' | head
```
Using the Phase 2 baseline, write a decision: keep default + document that idle allocation no longer costs its size, or a specific modest change (with the exact file/line and value). Justify against the OOM risk of under-provisioning real workloads.

- [x] **Step 2: Kernel-sharing decision**

State whether a shared read-only kernel-image mapping across VMs is worth a dedicated follow-on plan, quantified from the per-VM kernel-text residency observed in Phase 2. If yes, note it as a separate spec to file (do not implement here).

- [x] **Step 3: Kernel-slimming decision**

State whether to fold the ~few-MB Slab trim into existing in-repo kernel-slimming work or drop it. One or two sentences with the measured Slab figure.

- [x] **Step 4: Commit**

```bash
git add specs/perf/hvf-guest-ram-demand-faulting.md
git commit -m "docs(perf): decide default-sizing, kernel-sharing, slimming"
```

---

## Self-Review

- **Spec coverage:** Phase 1 (Tasks 1–2) implements the `GuestRam` demand-fault change + tests + live verification. Phase 2 (Tasks 3–4) covers the release-build check and baseline. Phase 3 (Task 5) covers the default-sizing, kernel-sharing, and kernel-slimming decisions. Non-goals (other backends, overcommit) are excluded by Global Constraints. All spec sections map to a task.
- **Placeholders:** none — every code step shows the code; investigative steps (Tasks 3/5) give exact commands and require recording concrete findings, not vague TODOs.
- **Type consistency:** `GuestRam::new/as_ptr/len` and the `HvfError::Alloc` variant are used identically in Tasks 1 and 2; `run()` keeps its `*mut u8` param fed by `as_ptr()`.

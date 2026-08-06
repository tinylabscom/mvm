# Witness rigor: ABI layout contracts, a real nextest profile, and mutation-tested claim witnesses

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three gaps in how this repo proves things about itself: (1) 13 of 17 `#[repr(C)]` types cross a foreign ABI boundary with no compile-time layout contract at all, and the other four assert size only, (2) the `ci` nextest profile every `just test-ci` invocation names does not exist, and (3) nothing establishes that a claim's named witness would actually go red if the code it ratifies were wrong.

**Architecture:** Three workstreams. WS1 adds `const _: () = assert!(...)` layout contracts to every `repr(C)` type plus an `xtask check-abi-layout` gate (shipped, #1940). WS2 adds `.config/nextest.toml`, fixing a Justfile recipe that had never run (shipped, #1943). WS3 was a by-hand planted-defect sweep across every code-level witness; `check-mutation-witnesses` (#1934) shipped that mechanically while this plan was in flight. **WS3 and WS4 are both struck in favour of plan 272**, which now carries the corrected sweep — four claims, not the three WS3 had hand-copied. With WS1 and WS2 shipped, this plan is closed.

**Tech Stack:** Rust 1.96 (`offset_of!` stable since 1.77), `xtask`, `cargo-nextest` 0.9.122, `cargo-mutants`, GitHub Actions (`ci.yml` Lint job, `security.yml` nightly).

**Sequencing rationale, and what changed.** WS1 and WS2 were near-certain
wins and landed first. The original argument for a by-hand sweep before
any automation was that establishing "this witness discriminates" is
cheap and needs no tooling. That argument died when #1934 merged: the
tooling exists, derives its surface from the ledger rather than a
hand-kept list, and covers the mutable witnesses exhaustively. Keeping
the sweep would have been duplicated effort against a better mechanism.
What no mechanism covers is a claim whose only witness is a CI lane, and
that is what WS3 is now.

## Numbering and overlap with plan 272 — RESOLVED

This plan was authored as 272 and renumbered to 274: another session
independently claimed 272 for `specs/plans/272-mutation-tested-claim-witnesses.md`
and published it first (PR #1934), so that one keeps the number. The worktree
and branch slugs below still read `plan272`; they are sandbox identifiers, not
the plan number, and are left alone.

**Owner decision made: WS3 and WS4 are both struck in favour of plan 272.**
WS1 (ABI layout contracts, #1940) and WS2 (the missing nextest profile,
#1943) are unique to this plan, shipped, and unaffected. With WS3 and WS4
struck, **this plan is closed** — all remaining witness-bite work lives in
plan 272 §WS-3.

The deciding argument is not tidiness. WS3 hand-copied the list of claims
that mutation testing cannot reach into prose and recorded **three**
(MVM-SEC-04/05/07). `check-mutation-witnesses` _derives_ that list from the
ledger and reports **four** — it also names **MVM-SEC-16**, whose three
witnesses are real Rust functions that cargo-mutants skips only because they
live in `crates/mvm-hostd/tests/`. A hand-maintained copy of a computed list
had already drifted before either workstream started. Plan 272 §WS-3 now
carries the corrected four-claim sweep, next to the gate that computes it.

## Provenance

The three techniques come from a review of an unrelated public Rust
kernel-interfaces crate: its structural-invariant table (one falsifiable
row per ABI struct: size, alignment, field offset), its nextest profile,
and its mutation-score gate. What was **not** taken, and why, is recorded
under "Non-goals" below. Read that section before extending this plan;
it exists so the rejected parts do not get re-proposed.

## Global Constraints

- Work in the dedicated worktree `../.worktrees/mvm-plan272-witness-rigor` on branch `docs/plan-272-witness-rigor` (already created); git via `git -C <wt-abs>`. Each workstream is its own PR — WS1, WS2, WS3, and (if Task 10 says go) WS4 share no code. Land them in that order; WS4 depends on WS3 having run.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs-in-comments`); reword to the concept. Spec docs may reference them.
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push (CI Lint uses nightly rustfmt); `cargo nextest run --workspace` green before any task is marked done; `cargo test --workspace --doc` for doc-fence coverage.
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or PR body.
- Scratch files go under `/tmp/`, never in the working tree.
- Every new `xtask` gate must be added to **both** `.github/workflows/ci.yml` (Lint job) and `.github/workflows/ci-full.yml` (Lint job) — the gate list is duplicated across the two lanes and a gate added to only one silently does not run on the path CI actually takes.
- Every new gate gets a row in `specs/VERIFICATION.md` §"Falsifiability" recording the defect that was planted to prove it fires. A gate nobody has seen fail is indistinguishable from a gate that cannot.
- Tick this plan's checkboxes and update `specs/SPRINT.md` in the same commit as the work.

---

## Security considerations — settle these before writing code

Seven items surfaced reviewing this plan against the threat model. Four
are constraints on how the work is done; three change what gets built.
None is a reason not to proceed.

**S1 — Do not publish captured test output as a CI artifact.** The
obvious `store-failure-output = true` bulk-captures stdout/stderr from
failing tests in a suite that handles host signer keys, grant tokens, the
secret store, and audit chains. `check-no-display-on-secret-types`
protects types _named_ like secrets; it does nothing about a raw byte
buffer, a key path, or a token surfaced by a debug assertion. WS2 Task 5
therefore sets `store-failure-output = false`. The job log remains the
place to read a failure.

**S2 — Mutation testing executes deliberately-broken security code.**
WS4 mutates plan verification, seccomp filter construction, the egress
policy resolver, and the host signer, then _runs the suite against the
mutant_. That is, by design, running the code with a safety check
removed: it can write to a real `~/.mvm`, mint keys at the wrong path or
mode, install firewall rules nothing cleans up, and leave VMs running.
The lane runs under an isolated `MVM_HOME` **and** `HOME`
(`TestEnv::isolate_mvm_home`, `check-test-home-isolation`) inside a
disposable container, and never on a developer machine. WS4 Task 10 Step
1 makes this a precondition, not a recommendation.

**S3 — Both new gates are gameable in the weakening direction.**
`enforced_by` can be narrowed to a trivial file and a mutation baseline
can be lowered; either makes a claim look backed while reducing its
backing, and both read as routine in a diff. WS4 Task 14 makes
`--check-baseline` refuse a _lowered_ baseline unless an explicit
`--rebaseline` flag and a written reason are supplied. Narrowing
`enforced_by` is a review red flag on par with deleting a witness; say so
in the PR that introduces the field.

**S4 — WS1 is claim-bearing, not hygiene, and should be scoped
accordingly.** Three of the unprotected structs sit on enforcement paths:

| Struct                     | Path                     | Claim                                      | Failure direction if layout drifts                                     |
| -------------------------- | ------------------------ | ------------------------------------------ | ---------------------------------------------------------------------- |
| `CapHeader` / `CapData`    | `capset(2)`              | MVM-SEC-02 (no elevation to uid 0)         | Writes the wrong capability word — can _widen_ privileges              |
| `DmIoctl` / `DmTargetSpec` | device-mapper table load | MVM-SEC-03 (tampered rootfs fails to boot) | Possibly loads a device that is not verity-backed                      |
| `MvmHsvcBuf`               | broker C ABI             | MVM-SEC-12 / MVM-SEC-13                    | Over-read in an SDK process whose heap holds signed broker credentials |

MVM-SEC-03's entry in `model/claims.toml` lists only a CI lane, but the
ADR-001 ledger also names `fn:verify_and_resume_rejects_tampered_mem` —
the two files had drifted and nothing gated the relationship. WS1
reconciles both and adds the missing cross-check. WS1 Task 4 registers
`check-abi-layout` as an additional witness for claims 2 and 3.

**S5 — Derived layout values are architecture-scoped.** Deriving Linux
struct layouts on an x86_64 host and applying them to aarch64 guest
builds is an assumption, not a fact. `sockaddr_vm` and `dm_target_spec`
are arch-stable; assert that rather than assume it. `just check-linux`
compiles both `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`,
so a wrong assumption fails the build rather than shipping — the safe
direction, but only if the step is actually run, which is why it is a
required step in Tasks 2 and 3 rather than an optional check.

**S6 — Pin new CI actions by SHA.** `.github/workflows/nightly.yml`
pins (`actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`) while
other lanes float on tags. Every action step this plan adds uses a SHA,
matching the stricter existing convention rather than the looser one.
`cargo-mutants` and its dependency tree are also outside `deny.toml` and
`cargo-audit` coverage — acceptable for a nightly-only dev tool, worth
knowing.

**S7 — WS4's gate is invisible on PRs.** `security.yml` runs on release
tags, nightly cron, and manual dispatch. A PR that weakens a witness
merges green and the nightly goes red later, on someone else's watch.
That is the right trade for a multi-hour job, but WS4 Task 14 also wires
the single fastest claim into the PR lane so the feedback is not wholly
deferred.

---

# WS1 — ABI layout contracts ✅ shipped in #1940

**Why.** Seventeen `#[repr(C)]` items live under `crates/`. Four carry a
compile-time **size** assertion (`SockaddrVm` in `qemu.rs:858` and
`substitution_proxy.rs:1395`, `DmIoctl` in `guest_mount.rs:350` and
`mvm-verity-init.rs:417`). None of the seventeen asserts alignment, and
none asserts a single field offset — so a same-size field reordering, the
most common ABI drift there is, compiles clean everywhere in the tree
today. The thirteen with nothing at all include the two worst cases:

- `MvmHsvcBuf` (`crates/mvm-sdk/src/host_services_ffi.rs:72`) — the C-ABI
  struct **every language SDK dlopens**. Layout drift here is not a
  Rust-side bug; it is an out-of-bounds read inside somebody else's
  Python or Node runtime, with no Rust diagnostic anywhere.
- `hv_vcpu_exit_t` / `hv_vcpu_exit_exception_t`
  (`crates/mvm-runtime/src/hvf/sys.rs:63,71`) — hand-written mirrors of
  Apple Hypervisor.framework types. These are populated _by the
  framework_; a field-offset mismatch silently misreads the vCPU exit
  reason, which is the control-flow input of the whole HVF backend.

There is also a duplication problem the assertions will make visible:
`sockaddr_vm` is hand-declared **seven times** across six files under two
spellings (`SockAddrVm` in `guest-agent/socket.rs`, `console.rs`,
`mvm-host-vm-init.rs`, `mvm-builderd.rs`; `SockaddrVm` in `qemu.rs`,
`substitution_proxy.rs` twice). Two of the seven are asserted. One of the
unasserted copies is a test-local double at
`substitution_proxy.rs:2034` — a double of a kernel ABI type that is free
to disagree with the kernel cannot falsify anything the real type does.

**The one rule that makes this real.** Every asserted number must be
derived from the **authoritative external header**, never from the
current Rust definition. Printing `size_of::<T>()` and pasting the result
asserts that the code equals itself — a tautology, and precisely the
failure mode of the reviewed crate's Kani "proofs"
(`kani::assume(val <= 1000); assert!(val <= 1000)`). Each assertion block
carries a comment naming the header it was derived from and the command
used to derive it.

## Task 1: Layout contracts for the C-ABI and Hypervisor.framework types

**Files:**

- Modify: `crates/mvm-sdk/src/host_services_ffi.rs` (after line 78)
- Modify: `crates/mvm-runtime/src/hvf/sys.rs` (after line 76)

**Interfaces:**

- Produces: the `const _: () = assert!(...)` house pattern that Tasks 2–3 replicate, and the header-derivation comment convention that `check-abi-layout` (Task 4) does _not_ verify but reviewers do.
- Consumes: nothing.

- [x] **Step 1: Derive the Hypervisor.framework values from the SDK header**

  Do not read them off the Rust struct. Run, on an Apple Silicon host:

  ```sh
  cat > /tmp/hvabi.c <<'EOF'
  #include <Hypervisor/Hypervisor.h>
  #include <stddef.h>
  #include <stdio.h>
  int main(void) {
      printf("exit_t         size=%zu align=%zu\n",
             sizeof(hv_vcpu_exit_t), _Alignof(hv_vcpu_exit_t));
      printf("exit_t.reason    off=%zu\n", offsetof(hv_vcpu_exit_t, reason));
      printf("exit_t.exception off=%zu\n", offsetof(hv_vcpu_exit_t, exception));
      printf("exception_t    size=%zu align=%zu\n",
             sizeof(hv_vcpu_exit_exception_t), _Alignof(hv_vcpu_exit_exception_t));
      printf("exception_t.syndrome         off=%zu\n",
             offsetof(hv_vcpu_exit_exception_t, syndrome));
      printf("exception_t.virtual_address  off=%zu\n",
             offsetof(hv_vcpu_exit_exception_t, virtual_address));
      printf("exception_t.physical_address off=%zu\n",
             offsetof(hv_vcpu_exit_exception_t, physical_address));
      return 0;
  }
  EOF
  clang -framework Hypervisor /tmp/hvabi.c -o /tmp/hvabi && /tmp/hvabi
  ```

  Record the printed values. They are the contract. If any disagrees with
  the current Rust definition, **the Rust definition is the bug** — fix
  the struct, do not weaken the assertion.

- [x] **Step 2: Add the assertion block to `hvf/sys.rs`**

  Insert immediately after the `hv_vcpu_exit_t` definition (line 76).
  Substitute the Step 1 values for the ones below if they differ:

  ```rust
  // Layout contract with Hypervisor.framework. These structs are populated
  // by the framework across the FFI boundary, so a size, alignment, or
  // field-offset mismatch silently misreads the vCPU exit reason rather
  // than failing loudly. Values derived from <Hypervisor/Hypervisor.h> via
  // `clang -framework Hypervisor` sizeof/offsetof/_Alignof; re-derive
  // against the SDK header before changing any of them.
  const _: () = {
      use core::mem::{align_of, offset_of, size_of};

      assert!(size_of::<hv_vcpu_exit_exception_t>() == 24);
      assert!(align_of::<hv_vcpu_exit_exception_t>() == 8);
      assert!(offset_of!(hv_vcpu_exit_exception_t, syndrome) == 0);
      assert!(offset_of!(hv_vcpu_exit_exception_t, virtual_address) == 8);
      assert!(offset_of!(hv_vcpu_exit_exception_t, physical_address) == 16);

      assert!(size_of::<hv_vcpu_exit_t>() == 32);
      assert!(align_of::<hv_vcpu_exit_t>() == 8);
      assert!(offset_of!(hv_vcpu_exit_t, reason) == 0);
      assert!(offset_of!(hv_vcpu_exit_t, exception) == 8);
  };
  ```

- [x] **Step 3: Verify the assertion fires**

  Temporarily change `syndrome: u64` to `syndrome: u32` in
  `hv_vcpu_exit_exception_t`. Run:

  ```sh
  cargo check -p mvm-runtime
  ```

  Expected: FAIL — `evaluation of constant value failed` /
  `assertion failed` on the `size_of` line. Revert the field change and
  re-run; expected: PASS. A layout contract that has not been seen to
  fail has not been tested.

- [x] **Step 4: Add the `MvmHsvcBuf` contract**

  Insert after line 78 of `crates/mvm-sdk/src/host_services_ffi.rs`. This
  one is pointer-width-dependent, so it is gated rather than weakened
  into a tautology (`size_of::<T>() == 2 * size_of::<usize>()` would pass
  for any two pointer-sized fields in any order and is worth nothing):

  ```rust
  // Layout contract for the dlopen'd C ABI. Every language SDK reads this
  // struct through its own FFI declaration; a reordered or added field is
  // an out-of-bounds read inside that runtime with no Rust-side
  // diagnostic. Any change here is a breaking ABI change and must be
  // mirrored in every `sdks/` binding in the same commit.
  #[cfg(target_pointer_width = "64")]
  const _: () = {
      use core::mem::{align_of, offset_of, size_of};

      assert!(size_of::<MvmHsvcBuf>() == 16);
      assert!(align_of::<MvmHsvcBuf>() == 8);
      assert!(offset_of!(MvmHsvcBuf, data) == 0);
      assert!(offset_of!(MvmHsvcBuf, len) == 8);
  };
  ```

- [x] **Step 5: Verify and commit**

  ```sh
  cargo check -p mvm-sdk -p mvm-runtime
  cargo nextest run -p mvm-sdk -p mvm-runtime
  rustup run nightly cargo fmt --all
  git -C /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan272-witness-rigor add \
    crates/mvm-sdk/src/host_services_ffi.rs crates/mvm-runtime/src/hvf/sys.rs
  git -C /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan272-witness-rigor commit -m \
    "feat(abi): pin the C-ABI and Hypervisor.framework struct layouts at compile time"
  ```

## Task 2: Layout contracts for the seven `sockaddr_vm` copies

**Files:**

- Modify: `crates/mvm-agentd/src/bin/mvm-guest-agent/socket.rs:13`
- Modify: `crates/mvm-agentd/src/console.rs:103`
- Modify: `crates/mvm-build/src/bin/mvm-host-vm-init.rs:1846`
- Modify: `crates/mvm-build/src/bin/mvm-builderd.rs:66`
- Modify: `crates/mvm-hostd/src/supervisor/substitution_proxy.rs:2034` (the test-local double)
- Modify: `crates/mvm-runtime/src/qemu.rs:858` and `crates/mvm-hostd/src/supervisor/substitution_proxy.rs:1395` — these two already assert size; replace the one-line assertion with the full block so they also carry alignment and field offsets

**Interfaces:**

- Consumes: the assertion pattern from Task 1.
- Produces: an identical contract on all seven copies, so a future consolidation can prove the copies were interchangeable.

- [x] **Step 1: Confirm the authoritative values**

  `struct sockaddr_vm` from `linux/vm_sockets.h` is
  `svm_family: u16`, `svm_reserved1: u16`, `svm_port: u32`,
  `svm_cid: u32`, `svm_flags: u8`, `svm_zero: [u8; 3]` — size 16, align 4.
  (`svm_flags` arrived in Linux 6.0; every mvm copy mirrors the older
  four-byte `svm_zero`, which is the defect this task fixes.) Confirm on a
  Linux host (the KVM box, `ssh -i ~/.ssh/hetzner-rvproxy root@…`) rather
  than trusting this paragraph:

  ```sh
  printf '#include <linux/vm_sockets.h>\n#include <stddef.h>\n#include <stdio.h>\nint main(void){printf("size=%%zu align=%%zu port=%%zu cid=%%zu\\n", sizeof(struct sockaddr_vm), _Alignof(struct sockaddr_vm), offsetof(struct sockaddr_vm, svm_port), offsetof(struct sockaddr_vm, svm_cid));return 0;}\n' > /tmp/vsabi.c
  cc /tmp/vsabi.c -o /tmp/vsabi && /tmp/vsabi
  ```

- [x] **Step 2: Add the same block after each of the seven definitions**

  Field names differ slightly between the copies — read each struct and
  use its own field identifiers. The shape, using
  `guest-agent/socket.rs` as the worked example:

  ```rust
  // Layout contract with the kernel's `struct sockaddr_vm`
  // (linux/vm_sockets.h). This struct is handed to bind(2)/connect(2) by
  // pointer and length; a size or offset mismatch binds the wrong port or
  // CID rather than erroring.
  const _: () = {
      use core::mem::{align_of, offset_of, size_of};
      assert!(size_of::<SockAddrVm>() == 16);
      assert!(align_of::<SockAddrVm>() == 4);
      assert!(offset_of!(SockAddrVm, svm_family) == 0);
      assert!(offset_of!(SockAddrVm, svm_reserved1) == 2);
      assert!(offset_of!(SockAddrVm, svm_port) == 4);
      assert!(offset_of!(SockAddrVm, svm_cid) == 8);
      assert!(offset_of!(SockAddrVm, svm_flags) == 12);
      assert!(offset_of!(SockAddrVm, svm_zero) == 13);
  };
  ```

  For the test-local double at `substitution_proxy.rs:2034`, add the
  identical block. A test double of a foreign ABI that is free to
  disagree with the real thing cannot falsify anything — that is the
  whole reason it needs the contract more than the production copy, not
  less.

- [x] **Step 3: Verify one of them fires**

  Reorder `svm_port` and `svm_cid` in `console.rs`. Run
  `cargo check -p mvm-agentd`. Expected: FAIL on the `offset_of!` lines.
  Revert.

- [x] **Step 4: Cross-compile check**

  The guest and builder binaries are Linux-target; a host-only
  `cargo check` does not compile them.

  ```sh
  just check-linux
  ```

  Expected: PASS with no warnings (the recipe sets `RUSTFLAGS=-D warnings`).

- [x] **Step 5: Commit**

  ```sh
  rustup run nightly cargo fmt --all
  git -C /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan272-witness-rigor commit -am \
    "feat(abi): pin every hand-declared sockaddr_vm to the kernel layout"
  ```

## Task 3: Layout contracts for the remaining kernel-ABI types

**Files:**

- Modify: `crates/mvm-agentd/src/bin/mvm-setpriv.rs:230,238` — `CapHeader`, `CapData` (`linux/capability.h`: `__user_cap_header_struct`, `__user_cap_data_struct`)
- Modify: `crates/mvm-agentd/src/guest_mount.rs:352` — `DmTargetSpec` (`linux/dm-ioctl.h`), and top up the existing size-only `DmIoctl` assertion at :350 with alignment and offsets
- Modify: `crates/mvm-agentd/src/bin/mvm-verity-init.rs:419` — `DmTargetSpec` (same header), and the same `DmIoctl` top-up at :417
- Modify: `crates/mvm-agentd/src/console.rs:113` — `Winsize` (`struct winsize`, `sys/ioctl.h`)

**Interfaces:**

- Consumes: the pattern from Tasks 1–2.
- Produces: full `repr(C)` coverage, which is the precondition for the Task 4 gate to pass on a clean tree.

- [x] **Step 1: Derive each family's values from its header**

  Use the same `cc` + `sizeof`/`offsetof`/`_Alignof` technique as Task 2,
  on a Linux host, one small program per header. Record the outputs into
  `/tmp/abi-values.txt`; they go into the assertion comments.

- [x] **Step 2: Promote the existing runtime `Winsize` assertion to compile time**

  `crates/mvm-agentd/src/console.rs:647` currently asserts
  `assert_eq!(std::mem::size_of::<Winsize>(), 8)` inside a `#[test]`. A
  layout contract belongs at compile time, where it also protects
  cross-compiled builds that never run the host test suite. Delete the
  runtime assertion from the test and add, after the struct:

  ```rust
  // Layout contract with `struct winsize` (sys/ioctl.h): four u16 fields,
  // passed by pointer to the TIOCSWINSZ ioctl.
  const _: () = {
      use core::mem::{align_of, offset_of, size_of};
      assert!(size_of::<Winsize>() == 8);
      assert!(align_of::<Winsize>() == 2);
      assert!(offset_of!(Winsize, ws_row) == 0);
      assert!(offset_of!(Winsize, ws_col) == 2);
      assert!(offset_of!(Winsize, ws_xpixel) == 4);
      assert!(offset_of!(Winsize, ws_ypixel) == 6);
  };
  ```

  Use the struct's actual field identifiers if they differ.

- [x] **Step 3: Add the capability contracts**

  Both structs in `mvm-setpriv.rs` sit under `#[cfg(target_os = "linux")]`,
  so the assertion block needs the same cfg or it fails to resolve on a
  macOS host build. `pid: libc::pid_t` is `i32` on Linux. Expected values,
  from `linux/capability.h` `__user_cap_header_struct` and
  `__user_cap_data_struct` — confirm with the Step 1 output before
  committing:

  ```rust
  // Layout contract with linux/capability.h. These two are passed by
  // pointer to capset(2)/capget(2); a mismatch sets the wrong capability
  // word rather than erroring, which silently widens the guest's
  // privileges instead of narrowing them.
  #[cfg(target_os = "linux")]
  const _: () = {
      use core::mem::{align_of, offset_of, size_of};

      assert!(size_of::<CapHeader>() == 8);
      assert!(align_of::<CapHeader>() == 4);
      assert!(offset_of!(CapHeader, version) == 0);
      assert!(offset_of!(CapHeader, pid) == 4);

      assert!(size_of::<CapData>() == 12);
      assert!(align_of::<CapData>() == 4);
      assert!(offset_of!(CapData, effective) == 0);
      assert!(offset_of!(CapData, permitted) == 4);
      assert!(offset_of!(CapData, inheritable) == 8);
  };
  ```

- [x] **Step 4: Add the device-mapper contracts**

  `DmTargetSpec` is the highest-value struct in this task: it is the
  payload the verity-init path hands to the device-mapper ioctl, so
  layout drift is a dm-verity setup failure at boot reported as an
  unrelated errno. Add to **both** `guest_mount.rs` (inside the
  `linux_impl` module, next to the existing `DmIoctl` assertion) and
  `mvm-verity-init.rs`:

  ```rust
  // Layout contract with linux/dm-ioctl.h `struct dm_target_spec`.
  const _: () = {
      use core::mem::{align_of, offset_of, size_of};

      assert!(size_of::<DmTargetSpec>() == 40);
      assert!(align_of::<DmTargetSpec>() == 8);
      assert!(offset_of!(DmTargetSpec, sector_start) == 0);
      assert!(offset_of!(DmTargetSpec, length) == 8);
      assert!(offset_of!(DmTargetSpec, status) == 16);
      assert!(offset_of!(DmTargetSpec, next) == 20);
      assert!(offset_of!(DmTargetSpec, target_type) == 24);
  };
  ```

  Then top up the existing `DmIoctl` line. It currently reads

  ```rust
  const _: () = assert!(DM_IOCTL_STRUCT_SIZE as usize == std::mem::size_of::<DmIoctl>());
  ```

  which pins size but not alignment, and pins it against an in-repo
  constant rather than the header. Keep that assertion — the constant is
  what the ioctl payload advertises, so the two must agree — and add
  `assert!(core::mem::align_of::<DmIoctl>() == 8);` plus offsets for the
  fields the verity setup actually writes. The gate in Task 4 requires
  size **and** alignment, so the size-only form does not satisfy it.

- [x] **Step 5: Determine whether device-mapper layout drift can fail open**

  This is the question that decides whether the whole plan's highest
  severity sits here. MVM-SEC-03 says a tampered rootfs fails to boot,
  enforced by a dm-verity target built from `DmIoctl` + `DmTargetSpec`.
  If a _misparsed_ target can produce a device that loads successfully
  but is not verity-backed, the drift is fail-open and the claim is
  silently void on any host where it occurs.

  Determine it empirically on the Linux box rather than by reading code.
  Build the guest with a deliberately wrong `DmTargetSpec` — shift
  `target_type` by four bytes, which is what a same-size field
  reordering would do — and observe what `DM_TABLE_LOAD` does:

  - **Rejects with an errno** → fail-closed. Record that; the contract is
    still worth having (a boot failure with a misleading errno is a bad
    day) but it is not a claim-3 hole.
  - **Loads a working non-verity device** → fail-open. Record it as a
    finding, raise it in the WS1 PR, and file it as its own issue — a
    layout contract is then the _mitigation_ for a real gap, not just
    drift insurance.

  Either answer goes into the WS1 PR body. Do not skip this step because
  the contract is going in regardless; the answer changes how MVM-SEC-03
  is described in the ledger.

  **Answered: fail-closed.** Measured on Linux 6.8 by submitting a
  `dm_target_spec` to `DM_TABLE_LOAD` with `target_type` displaced by 4
  and by 8 bytes. The correct layout loads and resumes a live table; both
  displacements return `EINVAL`, because the kernel resolves the target by
  name before any target-specific parsing and a displaced field names no
  registered target. MVM-SEC-03 was not at risk. Recorded in
  `specs/VERIFICATION.md`.

- [x] **Step 6: Confirm the values are architecture-stable**

  Per S5. Re-derive `dm_target_spec` and the capability structs on both
  an x86_64 and an aarch64 Linux host (the KVM box covers x86_64; an
  aarch64 guest or a cross-toolchain header dump covers the other). If
  they differ, the assertion needs `#[cfg(target_arch)]` arms rather than
  a single value. Record the two outputs in the assertion comment.

- [x] **Step 7: Verify, cross-check, commit**

  Everything in Steps 3–4 is Linux-gated, so a macOS `cargo check` never
  compiles it and cannot tell you the assertions hold. `just check-linux`
  is the step that actually validates this task.

  ```sh
  cargo nextest run -p mvm-agentd
  just check-linux
  rustup run nightly cargo fmt --all
  git -C /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan272-witness-rigor commit -am \
    "feat(abi): pin the capability, device-mapper, and winsize struct layouts"
  ```

## Task 4: `xtask check-abi-layout`

**Files:**

- Create: `xtask/src/check_abi_layout.rs`
- Modify: `xtask/src/main.rs` (register the subcommand)
- Modify: `.github/workflows/ci.yml` (Lint job, after the `check-claim-catalog` step)
- Modify: `.github/workflows/ci-full.yml` (Lint job, same position)
- Modify: `specs/VERIFICATION.md` (falsifiability row)

**Interfaces:**

- Consumes: nothing from Tasks 1–3 at the code level, but requires them merged or it fails on a clean tree.
- Produces: `cargo run -p xtask -- check-abi-layout`, exit 0 on clean, exit 1 with a per-struct diagnostic otherwise.

- [x] **Step 1: Write the failing gate test**

  In `xtask/src/check_abi_layout.rs`:

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn repr_c_without_size_and_align_assertions_is_rejected() {
          let src = r#"
              #[repr(C)]
              pub struct Naked { pub a: u64 }
          "#;
          let missing = missing_contracts(src);
          assert_eq!(missing, vec!["Naked".to_string()]);
      }

      #[test]
      fn repr_c_with_both_assertions_is_accepted() {
          let src = r#"
              #[repr(C)]
              pub struct Pinned { pub a: u64 }
              const _: () = {
                  assert!(size_of::<Pinned>() == 8);
                  assert!(align_of::<Pinned>() == 8);
              };
          "#;
          assert!(missing_contracts(src).is_empty());
      }

      #[test]
      fn size_assertion_alone_is_not_enough() {
          let src = r#"
              #[repr(C)]
              pub struct Half { pub a: u64 }
              const _: () = { assert!(size_of::<Half>() == 8); };
          "#;
          assert_eq!(missing_contracts(src), vec!["Half".to_string()]);
      }

      #[test]
      fn repr_c_packed_and_repr_c_align_are_both_in_scope() {
          let src = r#"
              #[repr(C, packed)]
              struct P { a: u8 }
              #[repr(C, align(8))]
              struct A { a: u8 }
          "#;
          let mut missing = missing_contracts(src);
          missing.sort();
          assert_eq!(missing, vec!["A".to_string(), "P".to_string()]);
      }
  }
  ```

- [x] **Step 2: Run the tests to confirm they fail**

  ```sh
  cargo nextest run -p xtask -E 'test(abi_layout)'
  ```

  Expected: FAIL — `cannot find function missing_contracts`.

- [x] **Step 3: Implement `missing_contracts` and `run`**

  Text-scan, matching the house style of the sibling gates
  (`check_claim_catalog.rs`, `check_single_home.rs`) — no `syn`
  dependency, the workspace limits dependencies deliberately.

  ```rust
  //! `xtask check-abi-layout`
  //!
  //! A `#[repr(C)]` type exists to match a layout defined somewhere else:
  //! a kernel uapi header, a framework header, a C ABI another language
  //! reads. Nothing in Rust ties the declaration to that external
  //! definition, so a field added, reordered, or resized drifts silently
  //! and is discovered as a misread value rather than a compile error.
  //! This gate requires every such type to carry a compile-time size and
  //! alignment assertion, which turns drift into a build failure.

  use anyhow::{Result, bail};
  use std::path::Path;

  /// Names of `repr(C)` items in `src` that lack a compile-time
  /// `size_of` **and** `align_of` assertion somewhere in the same file.
  fn missing_contracts(src: &str) -> Vec<String> {
      let mut missing = Vec::new();
      for name in repr_c_item_names(src) {
          let has_size = src.contains(&format!("size_of::<{name}>()"));
          let has_align = src.contains(&format!("align_of::<{name}>()"));
          if !(has_size && has_align) {
              missing.push(name);
          }
      }
      missing
  }

  /// Every `struct`/`union` name introduced under a `#[repr(C…)]`
  /// attribute. Attribute lines between the repr and the item (derives,
  /// doc comments, cfgs) are skipped.
  fn repr_c_item_names(src: &str) -> Vec<String> {
      let lines: Vec<&str> = src.lines().collect();
      let mut names = Vec::new();
      for (i, line) in lines.iter().enumerate() {
          let t = line.trim();
          if !(t.starts_with("#[repr(C)]") || t.starts_with("#[repr(C,")) {
              continue;
          }
          for follow in lines.iter().skip(i + 1).take(8) {
              let f = follow.trim();
              if f.starts_with('#') || f.starts_with("///") || f.starts_with("//") || f.is_empty() {
                  continue;
              }
              if let Some(name) = item_name(f) {
                  names.push(name);
              }
              break;
          }
      }
      names
  }

  /// `pub(crate) struct Foo {` -> `Foo`.
  fn item_name(line: &str) -> Option<String> {
      let after = line
          .split_once("struct ")
          .or_else(|| line.split_once("union "))?
          .1;
      let name: String = after
          .chars()
          .take_while(|c| c.is_alphanumeric() || *c == '_')
          .collect();
      (!name.is_empty()).then_some(name)
  }

  pub fn run(workspace: &Path) -> Result<()> {
      let mut errors: Vec<String> = Vec::new();
      let mut checked = 0usize;

      for entry in walk_rust_files(&workspace.join("crates"))? {
          let src = std::fs::read_to_string(&entry)?;
          for name in missing_contracts(&src) {
              errors.push(format!(
                  "{}: `{name}` is #[repr(C)] with no compile-time layout contract. \
                   Add `const _: () = {{ assert!(size_of::<{name}>() == N); \
                   assert!(align_of::<{name}>() == M); … }};` with N and M derived \
                   from the header this type mirrors — not from the Rust definition.",
                  entry.display()
              ));
          }
          checked += 1;
      }

      if !errors.is_empty() {
          for e in &errors {
              eprintln!("[error] {e}");
          }
          bail!("check-abi-layout: {} repr(C) type(s) without a layout contract", errors.len());
      }

      eprintln!("check-abi-layout: clean ({checked} files scanned)");
      Ok(())
  }
  ```

  There is no `walkdir` dependency in `xtask/Cargo.toml`; three gates
  have each hand-rolled the same `std::fs::read_dir` recursion —
  `check_claim_catalog.rs:311`, `check_single_home.rs:387` (as
  `fn walk(dir: &Path, f: &mut dyn FnMut(&Path))`), and
  `check_no_spec_refs_in_comments.rs:253`. Do not write a fourth. Lift
  `check_single_home`'s `walk` into a new `xtask/src/fs_walk.rs`, point
  all three existing callers at it, and use it here. That refactor is
  part of this task, not a follow-up: a plan about drift that adds its
  own fourth copy of a helper is not credible.

- [x] **Step 4: Run the tests to confirm they pass**

  ```sh
  cargo nextest run -p xtask -E 'test(abi_layout)'
  ```

  Expected: PASS, 4 tests.

- [x] **Step 5: Register the subcommand — all four places**

  `xtask/src/main.rs` dispatches on a string match, not a clap enum, and
  the command name is repeated in two human-facing lists. Miss either
  list and the gate works but is undiscoverable.

  1. Module declaration, alphabetically among the `mod check_*;` block at
     lines 10–51:

     ```rust
     mod check_abi_layout;
     ```

  2. Dispatch arm, matching the shape of the `check-single-home` arm at
     line 161:

     ```rust
     Some("check-abi-layout") => {
         let workspace = workspace_root();
         check_abi_layout::run(&workspace)
     }
     ```

  3. The `Unknown xtask: … Available: …` string at line 242 — append
     `check-abi-layout` to the comma-separated list.

  4. The help text block around line 330 — add, matching the existing
     column alignment:

     ```rust
     "  check-abi-layout                       Verify every #[repr(C)] type carries a compile-time size + alignment contract"
     ```

- [x] **Step 6: Run the gate against the real tree**

  ```sh
  cargo run -p xtask -- check-abi-layout
  ```

  Expected: `check-abi-layout: clean (N files scanned)`. If it reports a
  struct, either Tasks 1–3 missed it or it is a genuine new gap — add the
  contract, do not add an exemption. This gate ships with no exemption
  list on purpose; the first exemption should require an argued PR.

- [x] **Step 7: Wire into both CI Lint jobs**

  In `.github/workflows/ci.yml` and `.github/workflows/ci-full.yml`, after
  the `Conformance claim catalog` step:

  ```yaml
  - name: repr(C) types carry a layout contract
    run: cargo run -p xtask -- check-abi-layout
  ```

- [x] **Step 8: Plant a defect and record that the gate fired**

  Add `#[repr(C)] struct Unpinned { a: u64 }` to
  `crates/mvm-runtime/src/hvf/sys.rs`, run
  `cargo run -p xtask -- check-abi-layout`, confirm it exits nonzero
  naming `Unpinned`, then delete the struct. Add the row to
  `specs/VERIFICATION.md` §"Falsifiability":

  ```markdown
  | `check-abi-layout` | Add a `#[repr(C)]` struct with no `size_of`/`align_of` assertion | yes |
  ```

- [x] **Step 9: Register the gate as a claim witness**

  Per S4, these contracts back three claims, and MVM-SEC-03 has no
  code-level witness of any kind today. Add `ci:check-abi-layout` to the
  witness lists of MVM-SEC-02 and MVM-SEC-03 in `model/claims.toml`, and
  the matching rows in the ADR-001 ledger table between the
  `claims-catalog` markers. Both edits are required: the `.toml` is the
  R1 source and the ledger table is what `check-claim-catalog` parses.

  The `ci:` token resolves against `.github/workflows/*`, which Step 7
  satisfied. Verify:

  ```sh
  cargo run -p xtask -- check-claim-catalog
  cargo run -p xtask -- check-conformance
  ```

  Expected: both PASS with the witness count up by two.

  Do **not** add it to MVM-SEC-12/13 in this change. Those already have
  code witnesses, and the honest scope of an `MvmHsvcBuf` layout contract
  is "the SDK reads the buffer the supervisor wrote", which is narrower
  than either claim's statement. Mention the relationship in the PR body
  and leave the ledger alone.

- [x] **Step 10: Full gate run and commit**

  ```sh
  rustup run nightly cargo fmt --all
  cargo clippy --workspace --all-targets -- -D warnings
  cargo nextest run --workspace
  cargo test --workspace --doc
  git -C /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan272-witness-rigor commit -am \
    "feat(xtask): gate repr(C) types on a compile-time layout contract"
  ```

- [x] **Step 11: Open the WS1 PR**

  Title: `feat(abi): pin every repr(C) layout to its authoritative header and gate it`.
  The body states the 13-of-17 gap, names `MvmHsvcBuf` and
  `hv_vcpu_exit_t` as the motivating cases, records that the gate was
  seen to fail, and leads with the Task 3 Step 5 finding — whether
  device-mapper layout drift fails open or closed is the most
  security-relevant thing this PR establishes, more than the contracts
  themselves.

## WS1 follow-up (deferred, not in this plan)

- [ ] Consolidate the seven `sockaddr_vm` declarations. Blocked on a
      question this plan does not answer: `mvm-setpriv`,
      `mvm-verity-init`, and `mvm-guest-agent` are size-budgeted static
      guest binaries (`xtask check-binary-size`), so a shared definition
      must not drag a crate dependency into them. File as its own plan
      once WS1 has proved the seven copies are byte-identical.

---

# WS2 — a nextest profile that exists ✅ shipped in #1943

**Why.** `Justfile:157` defines:

```
test-ci:
    cargo nextest run --workspace --profile ci
```

There is no `.config/nextest.toml` anywhere in the repo. The recipe
fails immediately:

```
$ cargo nextest show-config test-groups --profile ci
error: profile `ci` not found (known profiles: default, default-miri)
```

So `just test-ci` — the recipe whose comment promises "retries, JUnit
output" — has never run. Fixing it is the deliverable; the profile
content is where the actual value is.

**Deliberate scope limit.** This workstream does **not** add
`[test-groups]` up front. Serialization groups are worth adding only for
a demonstrated cross-process shared resource, and nextest already gives
every test its own process, so the in-process `ENV_LOCK` in
`crates/mvm-core/src/util/test_env.rs` is not evidence of one — under
nextest it is redundant, under the documented `cargo test` fallback it is
load-bearing, and both are correct. Task 6 measures whether any real
contention exists before Task 7 decides what to do about it.

**There is already one known target.** `specs/SPRINT.md` records, in the
hermetic-`$HOME` entry, that
`mvmctl::audit_emissions_live update_check_does_not_emit_audit_entry`
(`tests/audit_emissions_live.rs:1560`) "fails intermittently under full
workspace concurrency", that its `AuditSandbox` already isolates both
`MVM_HOME` and `HOME`, and that it passed 47/47 across four consecutive
runs of its own binary — i.e. it is a **concurrency** flake, not a
hermeticity one, and it was explicitly deferred for separate triage.
That triage is Task 6. Whatever resource it contends on is by definition
process-external, since per-test process isolation does not help it.

## Task 5: Create the profile

**Files:**

- Create: `.config/nextest.toml`
- Modify: `Justfile` (comment on `test-ci` now describes what it does)

**Interfaces:**

- Produces: profiles `default` and `ci`, consumed by `just test`, `just test-ci`, and the `ci-full.yml` test job.

- [x] **Step 1: Confirm the failure first**

  ```sh
  cargo nextest show-config test-groups --profile ci
  ```

  Expected: `error: profile 'ci' not found`.

- [x] **Step 2: Write `.config/nextest.toml`**

  ```toml
  # cargo-nextest configuration.
  #
  # `just test-ci` names the `ci` profile; without this file that recipe
  # fails before running a single test.

  [profile.default]
  # No retries, ever. A test that passes on the second attempt is a test
  # whose result carries no information, and a retry budget turns a real
  # race into a green run that nobody investigates.
  retries = 0
  # Warn on tests creeping toward the wall-clock budget of the VM-boot
  # paths without killing them; the warning is the signal.
  slow-timeout = { period = "60s" }
  fail-fast = false

  [profile.ci]
  retries = 0
  # Warn only. A hard `terminate-after` here would newly kill any test
  # that legitimately runs long — a live backend lane, a builder boot —
  # turning a passing job red on a timing guess. Step 3 measures the
  # real distribution; a kill threshold can be added afterwards with a
  # number behind it.
  slow-timeout = { period = "120s" }
  # Report every failure in one run. `fail-fast = true` costs a round trip
  # per failure on a suite this size.
  fail-fast = false
  status-level = "fail"
  final-status-level = "flaky"

  [profile.ci.junit]
  path = "junit.xml"
  # Structure only, never payloads. Captured stdout/stderr from a failing
  # test in this suite can contain key paths, grant tokens, or raw buffers,
  # and the JUnit file is uploaded as a downloadable CI artifact. The job
  # log remains the place to read a failure.
  store-success-output = false
  store-failure-output = false
  ```

- [x] **Step 3: Verify both profiles resolve, and measure the slow tail**

  ```sh
  cargo nextest show-config test-groups --profile ci
  cargo nextest show-config test-groups --profile default
  ```

  Expected: no `profile not found` error (an empty test-group table is
  the correct output — none are defined yet).

  Then find the actual slowest tests, because a kill threshold set
  without this number is a guess that turns a passing lane red:

  ```sh
  cargo nextest run --workspace --profile ci 2>&1 | rg 'SLOW' | tee /tmp/nextest-slow.txt
  ```

  Record the slowest five and their durations in the WS2 PR body. If the
  slowest is comfortably under a candidate threshold, a follow-up may add
  `terminate-after`; if a legitimate test runs long, note that a hard
  kill is off the table and warning-only is the permanent answer.

- [x] **Step 4: Run the suite under the ci profile**

  ```sh
  cargo nextest run --workspace --profile ci
  ```

  Expected: PASS, and `target/nextest/ci/junit.xml` exists and is
  non-empty. Confirm the JUnit path — nextest resolves `path` relative to
  `target/nextest/<profile>/`, so check the file actually landed there
  before claiming this step done.

  Then confirm S1 holds in practice rather than in theory. Force a
  failure (temporarily invert an assertion in a fast test), re-run, and
  grep the emitted XML for the failing test's output:

  ```sh
  rg -c 'system-out|system-err' target/nextest/ci/junit.xml || echo "no captured output — correct"
  ```

  Expected: no captured output sections. Revert the inverted assertion.

- [x] **Step 5: Add the JUnit artifact to the CI test job**

  In `.github/workflows/ci-full.yml`, change the workspace test step
  (currently `cargo nextest run --workspace --all-targets` around line 213) to add `--profile ci`, and add an upload step guarded by
  `if: always()` so a failing run still publishes the report. Pin the
  action by SHA per S6 — resolve the current `v4` SHA with
  `gh api repos/actions/upload-artifact/git/ref/tags/v4 -q .object.sha`
  and substitute it below rather than copying this one blind:

  ```yaml
  - name: Upload test report
    if: always()
    uses: actions/upload-artifact@<sha> # v4
    with:
      name: nextest-junit
      path: target/nextest/ci/junit.xml
      if-no-files-found: warn
      retention-days: 14
  ```

- [x] **Step 6: Commit**

  ```sh
  git -C /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan272-witness-rigor add .config/nextest.toml
  git -C /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan272-witness-rigor commit -am \
    "feat(test): add the nextest profile that just test-ci has always named"
  ```

## Task 6: Measure whether any test actually contends

**Files:**

- No source changes. Output goes to `/tmp/` and into the Task 7 decision.

**Interfaces:**

- Produces: the list of tests, if any, that fail under parallel load but pass serially. Task 7 consumes it.

- [x] **Step 1: Establish the serial baseline**

  ```sh
  cargo nextest run --workspace --test-threads=1 2>&1 | tee /tmp/nextest-serial.log
  ```

  Expected: PASS. If anything fails here it is an ordinary bug, not
  contention — fix it before continuing.

- [x] **Step 2: Run five parallel passes**

  ```sh
  for i in 1 2 3 4 5; do
    echo "=== pass $i ===" >> /tmp/nextest-parallel.log
    cargo nextest run --workspace >> /tmp/nextest-parallel.log 2>&1 || echo "PASS $i FAILED" >> /tmp/nextest-parallel.log
  done
  grep -E 'FAILED|FAIL \[' /tmp/nextest-parallel.log | sort | uniq -c | sort -rn
  ```

  Do **not** swallow failures with `|| true` — the whole point is the
  failure list.

- [x] **Step 3: Start from the known flake**

  Run the recorded intermittent one directly, many times, under load:

  ```sh
  for i in $(seq 1 20); do
    cargo nextest run --workspace -E 'test(update_check_does_not_emit_audit_entry)' \
      >> /tmp/nextest-audit-flake.log 2>&1 || echo "iteration $i FAILED" >> /tmp/nextest-audit-flake.log
  done
  grep -c FAILED /tmp/nextest-audit-flake.log
  ```

  A filtered run may not reproduce it — the SPRINT.md note says it passed
  47/47 in isolation, so the trigger is the _rest of the suite_ running
  alongside. If the filtered loop is clean, reproduce it the way it was
  observed: full `cargo nextest run --workspace` passes, watching only
  that name. Then determine what it shares with the rest of the suite:
  the update-check code path, the audit log directory, or a network/port
  resource. Whatever it is, it is process-external.

- [x] **Step 4: Classify every other name that appears**

  For every test that fails in a parallel pass but passed serially,
  identify the shared resource: a fixed path outside a per-test tempdir,
  a fixed port, the Stage 0 `flock`, or the real `~/.mvm`. The Stage 0
  lock tests are the other prior suspects —
  `stage0_lock_refuses_concurrent_acquisition`,
  `stage0_lock_creates_missing_cache_parent`,
  `stage0_in_flight_tracks_the_lock`,
  `sweep_skips_when_stage0_lock_is_held`,
  `sweep_dry_run_reports_orphan_without_removing`,
  `sweep_real_run_removes_orphan_and_leaves_siblings`
  in `crates/mvm-cli/src/commands/env/builder_vm/builder_vm_bootstrap_tests.rs`,
  whose own comments document an `EWOULDBLOCK` false positive under
  parallel load. Confirm or rule them out; do not assume.

- [x] **Step 5: Write the finding into the Task 7 step**

  Record, for each contended test, the name and the shared resource. If
  the only entry is the audit flake and its resource turns out to be
  fixable in the test itself, say so — Task 7 Step 1 prefers the fix over
  the group. If the whole list is empty, say so in the WS2 PR body and
  mark Task 7 "not needed — no contention observed in five passes",
  leaving the checkbox ticked with that note. An empty result is a
  result, and it retires the SPRINT.md deferral either way: the flake is
  reproduced and explained, or it is documented as not reproducible under
  the measurement that was actually run.

## Task 7: Add test groups only for what Task 6 found

**Files:**

- Modify: `.config/nextest.toml`

**Interfaces:**

- Consumes: the contended-test list from Task 6.
- Produces: a `[test-groups]` table and matching overrides, or a recorded finding that none are needed.

- [x] **Step 1: Prefer fixing the test over serializing it**

  A test that needs a unique tempdir and does not have one is a bug in
  the test, and a test group would paper over it. Serialize only what
  genuinely shares a process-external resource _by design_ — the Stage 0
  advisory lock is the plausible case, because its whole subject _is_ a
  cross-process lock on a fixed path. `update_check_does_not_emit_audit_entry`
  is more likely a test-side fix than a group; decide from what Task 6
  Step 3 found, and record the reasoning either way.

- [x] **Step 2: If serialization is warranted, add the group**

  ```toml
  [test-groups]
  # The Stage 0 builder-cache advisory flock is a real cross-process lock
  # on a fixed path. nextest's process-per-test isolation does not help
  # here — that is the resource under test — so these run one at a time.
  stage0-lock = { max-threads = 1 }

  [[profile.default.overrides]]
  filter = 'package(mvm-cli) and test(/stage0_lock|sweep_/)'
  test-group = "stage0-lock"

  [[profile.ci.overrides]]
  filter = 'package(mvm-cli) and test(/stage0_lock|sweep_/)'
  test-group = "stage0-lock"
  ```

  Narrow the filter to exactly the names Task 6 produced. A broad filter
  serializes tests that did not need it and hides the next real race.

- [x] **Step 3: Verify the group binds**

  ```sh
  cargo nextest show-config test-groups --profile ci
  ```

  Expected: the `stage0-lock` group listed with exactly the tests from
  Task 6 and no others.

- [x] **Step 4: Re-run the five parallel passes**

  Repeat Task 6 Step 2. Expected: zero failures across all five.

- [x] **Step 5: Commit and open the WS2 PR**

  Title: `feat(test): give nextest the ci profile the Justfile has always named`.
  Body states that `just test-ci` was broken, quotes the
  `profile 'ci' not found` error, and reports the Task 6 measurement
  (including "no contention found" if that is the answer).

---

# WS3 — the witnesses mutation testing cannot reach ❌ STRUCK → plan 272 §WS-3

**Struck. Do not execute this workstream — it lives in plan 272 §WS-3.**

It was first cut down after WS1/WS2 shipped: it originally planned a
by-hand planted-defect sweep across all 34 `fn:` witnesses, and
`check-mutation-witnesses` (#1934, merged 2026-07-30) does that job
mechanically and exhaustively. What appeared to survive was the part
#1934 structurally cannot reach — the text below.

That text is **wrong in one respect**, which is why the whole workstream
moved rather than staying here: it says three claims are unreachable. The
gate reports **four**. It also names MVM-SEC-16, whose witnesses are real
Rust functions that cargo-mutants skips only because they sit in
`crates/mvm-hostd/tests/` — so claim 16 needs a planted defect in the
enforcement code, not a CI-lane falsification. A hand-kept copy of a
computed list drifted from it immediately; the corrected sweep therefore
lives beside the gate that computes the list. Retained below for the
reasoning behind each falsification, which plan 272 §WS-3 cites.

## What #1934 cannot reach

Two of the sixteen claims have no `fn:` witness at all: **MVM-SEC-05**
(fuzz targets) and **MVM-SEC-07** (dependency audit). Their witnesses are a
fuzz lane and a `cargo deny` job. There is no Rust function body whose
mutation exercises either of them, and
`check-mutation-witnesses` correctly reports them as reaching no mutable
file rather than inventing a surface.

A `ci:` witness nobody has seen fail is the same problem as a `fn:` one.
These need the hand treatment, once, recorded in `specs/VERIFICATION.md`.

## Task 8: Falsify the remaining CI-lane witnesses

**Files:**

- Modify: `specs/VERIFICATION.md` (extend the falsifiability table)
- No source changes survive this task — every edit is reverted.

- [x] **Step 1: MVM-SEC-04 — runtime guest-agent boundary**

  The compile-time feature fork was retired. The runtime-boundary unit and
  conformance tests enumerate DevOnly requests and fail if a production-safe
  grant permits any of them.

- [ ] **Step 2: MVM-SEC-07 — the dependency audit**

  Add a crate with a disallowed licence to a scratch branch and confirm
  `cargo deny` fails. Cheap and fast; the point is that nobody has
  watched it fail on this repo's actual configuration.

- [ ] **Step 3: MVM-SEC-05 — the fuzz lane**

  Break a parser the fuzz targets cover — the `GuestRequest` framing is
  the obvious one — and confirm a short local `cargo fuzz` run finds it.
  Record the wall-clock to find, since a lane that needs hours to catch a
  planted defect is weaker evidence than one that catches it in seconds.

- [ ] **Step 4: Record all three**

  Add to `specs/VERIFICATION.md` §"Falsifiability", in the claim-witness
  table:

  ```markdown
  | Claim      | Witness                           | Planted defect                                                                        | Fired |
  | ---------- | --------------------------------- | ------------------------------------------------------------------------------------- | ----- |
  | MVM-SEC-04 | `ci:guest-agent-runtime-boundary` | Remove the runtime profile or signed-grant check before dispatching a DevOnly request | yes   |
  ```

  Fill the verdicts from Steps 1-3. A `did not fire` is a finding, not a
  failure of the task.

## Task 9: Triage the first full mutation run

**Why this and not a hand sweep.** #1934's nightly is
`continue-on-error: true` until its baseline covers the whole surface —
seeded only for the claim-10 anchor today. Establishing that baseline and
reading the survivors is the human work, and it is where the findings
actually are. The score is bookkeeping.

- [ ] **Step 1: Establish the baseline hermetically**

  Blocked on #1946. `--run` executes mutated security code and neither
  the nightly lane nor `just mutation-witnesses` isolates `MVM_HOME` and
  `HOME` today. Do not run it against a real `~/.mvm`.

- [ ] **Step 2: Triage every survivor**

  For each: a **real hole** gets the test that catches it; an
  **equivalent mutant** gets an `accepted_misses` entry with a stated
  reason. `check_accepted_reasons` already refuses an unexplained entry,
  so the reason is enforced rather than merely encouraged.

- [ ] **Step 3: Arm the lane**

  Once the baseline covers the surface, drop `continue-on-error: true`
  from the `mutation-witnesses` job in `security.yml`.

---

## Superseded by #1934

The original WS4 in this plan — `enforced_by` in `model/claims.toml`, an
`xtask mutants-witnesses` driver, a per-claim `mutation_baseline` and a
`--rebaseline` ratchet — is **struck**. #1934 shipped the same idea and
is better on four counts:

| This plan proposed                                   | #1934 does                                                                                                                                                 |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A hand-maintained `enforced_by` list per claim       | Derives the surface from the ledger — a `fn:` witness resolves to its declaring file, using the repo's `#[cfg(test)] mod tests`-beside-the-impl convention |
| Nightly-only, so invisible on PRs                    | A millisecond **surface pin** every PR plus the hours-long `--run` nightly, so a claim losing coverage is a reviewable diff                                |
| A `--rebaseline` flag guarding a lowered number      | `check_accepted_reasons` requires a stated reason per accepted miss, and names the failure mode it prevents                                                |
| `mutation = "not-applicable"` + reason, hand-written | Reports claims reaching no mutable file and pins them, rather than fabricating a value                                                                     |

Do not re-propose the struck design. The one gap found reviewing #1934
is filed as #1946 (hermetic execution), not reimplemented here.

**A note on why the hand sweep was dropped, beyond redundancy.** A
spot-check ran MVM-SEC-10's seven witnesses before this re-scope. Six
fired; one appeared not to. The apparent miss was the _defect in the
wrong place_ — `resolve_run_network_policy` calls `NetworkPolicy::deny_all()`
directly rather than going through `Default`, so neutering the `Default`
impl never touched the path that witness guards. Re-run against the
correct line, it fired. A hand sweep's "did not fire" is ambiguous
between a weak witness and a badly-chosen defect, and disambiguating it
costs a human read per witness. Mutating the witness's own declaring
file, as #1934 does, does not have that ambiguity.

## Non-goals

Recorded so they are not re-proposed. Each was examined in the
reviewed crate and rejected for a stated reason.

- **Contract YAML compiled by `build.rs`.** The reviewed crate's
  `build.rs` reads binding metadata from a sibling directory outside its
  own repository; on a missing file it records "no binding" and proceeds. It
  is fail-open by construction and violates the invariant that a source
  checkout builds from in-repo inputs only. `model/claims.toml` plus
  `check-conformance` already covers the same ground, in-tree and
  fail-closed.
- **A `verification_specs.rs`-style module.** The reviewed crate gates
  Verus code behind `#[cfg(verus)]` importing a `builtin` crate that is not a
  dependency, so it never compiles anywhere; the "contracts" are
  `#[requires(...)]` inside doc comments, which are inert prose; and the
  Kani proofs are tautologies (`kani::assume(val <= 1000); assert!(val <= 1000)`).
  `check-honesty` and `check-no-overclaim` exist to stop exactly this. If
  Kani is ever wanted here, point it at a real invariant — the vsock
  frame parser's length arithmetic is the obvious first candidate — and
  register it as a ledger witness.
- **A line-coverage percentage gate.** This suite is largely integration
  and BDD against VM backends; a coverage floor rewards testing whatever
  is cheapest to reach. Mutation score on witness functions measures the
  property actually wanted.
- **An asserted mutation-score floor before measuring.** See the WS4
  honesty constraint.
- **`deny.toml` `[sources.allow-org]`.** The reviewed crate allow-lists a
  GitHub org's git sources; this repo's `allow-git = []` is stricter and
  stays.
- **A 100-point falsification checklist as a document.** In the reviewed
  crate, eighty of the hundred rows are unbound aspirations (fio IOPS
  floors, KASLR, CFI, SMAP/SMEP) with no test behind them. WS1 takes the
  technique from the structural-invariant rows only; the aspirational
  table is the overclaim pattern the honesty gates block.

## Deferred follow-ups

- [ ] Weekly repeat-run lane (suite × N under `--test-threads=1`) as a
      standing flake detector. WS2 Task 6 does this once, by hand; making
      it a scheduled job is separate work and only worth it if Task 6
      finds anything.
- [ ] `if_falsified` field on each `[[claim]]` — one line stating what an
      observer would see if the claim were false. Cheap, and it makes the
      ledger readable by someone who is not already fluent in the
      witnesses. Not bundled here because it touches every claim row and
      would collide with WS4's Task 11 edit to the same file.
- [ ] Consolidate the seven `sockaddr_vm` declarations (see WS1
      follow-up).

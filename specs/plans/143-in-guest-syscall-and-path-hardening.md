# Plan 143 — In-guest syscall + path hardening (defense-in-depth)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans /
> subagent-driven-development. Checkbox (`- [ ]`) steps track progress.
>
> **Save-only note:** this document is the captured plan. It is sequenced as a
> hardening refinement on top of the refactor (plans 120–132) and **does not stand
> alone or execute ahead of its prereqs** — R1 lands only after Plan 120's
> `core_demo_e2e` is green; R1/R2/R3's CI gates wire through Plan 128 (the
> claim-gate plan, Stage D). Verify the `143` prefix against `main` + open PRs
> before merge (`cargo xtask check-spec-numbers` is CI-gated; 142 was taken by
> `142-network-no-bypass-egress-audit.md` mid-authoring, hence 143).

**Origin:** a comparison of mvm against an unprivileged userspace
*application-kernel* Linux sandbox (seccomp-unotify, Landlock, namespaces,
`openat2(2)`, ioctl-command filtering, verified exec) that confines ordinary
processes without a VM. Verdict: ~80% of it is **not** applicable — mvm has a
hardware boundary (KVM/VMM) that such a sandbox deliberately lacks, so adopting
its software-isolation model would be a downgrade. Three sharp, transferable
ideas remain; they are this plan.

**Goal:** Close two concrete in-guest hardening gaps surfaced by the comparison,
and record the architectural positioning in ADR-002. (1) Add `ioctl` command-code
filtering (TIOCSTI/TIOCLINUX terminal-injection) to the guest seccomp profile,
which today allowlists `ioctl` with no argument filtering. (2) Replace the OCI
unpacker's check-then-use symlink-parent walk with an atomic
`openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` resolution, deleting a TOCTTOU /
path-parsing bug class. (3) A one-paragraph ADR-002 note on why mvm chose a
hardware boundary over a userspace application-kernel sandbox.

**Architecture / framing:** mvm's workload isolation is hardware virtualization
(Firecracker/libkrun + KVM); ADR-002 trusts the host + VMM. The reference sandbox
exists precisely *because* it has no hardware boundary, so it over-invests in
syscall-surface compat and TOCTTOU correctness. This plan adopts only the two
ideas that harden mvm's layer *inside* the already-virtualized guest (R1) or its
host-side untrusted-input parser (R2). Everything else from it is explicitly
rejected (table at end).

**Dependency / sequencing:**
- **Task 1 (R1, ioctl seccomp) is GATED behind `specs/plans/120-core-demo.md`
  reaching green** (`core_demo_e2e` passing on macOS/libkrun). R1 modifies the
  workload-guest boot path (`mvm-seccomp-apply` applies the filter at boot); Plan
  120 Task 4 is stabilizing exactly that path under a "no speculative fixes"
  discipline. Landing R1 first would inject a fresh boot-failure variable
  (a wrong `arg0` condition surfaces as "agent never answered" — Task 4's exact
  symptom). After core-demo green, that E2E *becomes R1's regression guard*.
- **Task 2 (R2, OCI unpacker) and Task 3 (R3, ADR) are independent of Plan 120**
  (different crate / doc; not in the flake spine) and may land anytime.
- **CI gates coordinate with Plan 128** (testing/fuzz/claim-gates, Stage D, "run
  last"). R1's seccomp ioctl-denylist assertion, R2's extended `unpack_layer`
  fuzz corpus, and R3's ADR-002/`CLAUDE.md` security-section reconcile are wired
  there alongside the other claim gates — the same pattern as Plan 129 §F. This
  plan delivers the *behavior*; Plan 128 owns the *gate*.

**Tech stack:** Rust (`mvm-security`, `mvm-guest`, `mvm-oci`), `seccompiler`
(already a dep), `libc`/`openat2` (Linux ≥ 5.6; the unpacker runs only in the
Linux builder VM — ADR-050), `cargo-fuzz`.

**Out of scope:** Landlock-for-workloads, ptrace mediation, seccomp-unotify
application-kernel model, transparent file encryption — all rejected (see table).

---

## Task 1 — ioctl command-code denylist in the guest seccomp profile  *(gated on Plan 120 green)*

The guest seccomp tiers allowlist `ioctl` as a bare syscall with no `arg0`
condition: `crates/mvm-security/src/seccomp.rs:296` (standard tier),
`crates/mvm/src/security/seccomp.rs:65,127,214` (older JSON profile), and
`crates/mvm-guest/src/bin/mvm-seccomp-apply.rs:182` maps `ioctl → SYS_ioctl` with
no `SeccompCondition` (the file notes it "doesn't filter on syscall arguments").
The reference sandbox filters ioctl by command code; the classic escape is
**TIOCSTI/TIOCLINUX** (inject characters into the controlling terminal's input
queue → parent shell executes them), reachable when a workload shares a PTY
console (`mvmctl console`, dev-mode). The VMM boundary does not close this — it is
an escape *within* the guest's trust domain onto the console.

- [ ] **Step 0 (gate):** confirm `core_demo_e2e` is green on macOS/libkrun before
      starting (Plan 120 Task 4 acceptance box ticked).
- [ ] **Step 1 (red):** unit test in `mvm-guest` asserting the compiled BPF
      *denies* `ioctl(_, TIOCSTI, _)` and `ioctl(_, TIOCLINUX, _)` and still
      *allows* `ioctl(_, TIOCSWINSZ, _)` / `ioctl(_, TCGETS, _)`.
- [ ] **Step 2 (green):** extend the tier→manifest lowering with a fixed `ioctl`
      `arg0` denylist (`TIOCSTI`, `TIOCLINUX`, consider `TIOCSETD`), emitted as a
      `SeccompCondition` in `mvm-seccomp-apply.rs` with the tier's action. Keep
      `ioctl` otherwise allowed — a *denylist* on top of the existing allowlist,
      not a full ioctl allowlist (brittle across arch/libc — see the
      `libc::Ioctl` width note at `crates/mvm-host-vm-init/src/main.rs:1919`).
      Apply once in the lowering so all filtering tiers inherit it; unrestricted
      stays unfiltered. **Files:** `crates/mvm-security/src/seccomp.rs`,
      `crates/mvm-guest/src/bin/mvm-seccomp-apply.rs`; mirror or mark-superseded
      `crates/mvm/src/security/seccomp.rs`.
- [ ] **Step 3 (guard):** rebuild the supervisor explicitly
      (`cargo build -p mvm-libkrun-supervisor --features libkrun-sys` — stale-binary
      trap), then re-run `core_demo_e2e` (the regression guard) — boot→ping still
      green, proving the denylist didn't kill the agent/workload.
- [ ] **Step 4:** extend the seccomp CI gate with the ioctl-denylist assertion
      (coordinate with Plan 128); `just lint`; commit.

## Task 2 — close the OCI-unpacker TOCTTOU with `openat2(RESOLVE_BENEATH)`  *(independent)*

`crates/mvm-oci/src/unpack.rs` has a documented 5-layer defense (`:85-114`):
reject absolute/`..`, `starts_with(output_root)` (`:562`), parent-chain symlink
walk via `symlink_metadata` (`:576`, `parent_chain_has_symlink` at `:904`), and
`O_NOFOLLOW` on the leaf (`:104`). Step 5 is a **check-then-use**: it walks parents
with `symlink_metadata` (check), then a later call writes (use); `O_NOFOLLOW` only
guards the *leaf* open, not the intermediate dirs the kernel traverses. This is the
hazard the reference sandbox eliminates with one atomic `openat2(2)` resolution.

- [ ] **Step 1 (red):** regression test — swap a parent component to a symlink
      mid-unpack and assert refusal; a `..`/symlink/separator-quirk escape corpus.
- [ ] **Step 2 (green):** on `cfg(target_os="linux")`, open each entry's parent
      dir relative to an `output_root` dirfd via `openat2` with
      `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, then create the leaf with `*at`
      calls against that dirfd. Keep the string checks as cheap fail-fast, but make
      `openat2` the **authority**; map refusals to the existing
      `RefusalReason::SymlinkInParent` / `JoinedPathEscape`. Non-Linux keeps the
      current logic (test-only build). **Files:** `unpack.rs` (`unpack_layer:470`,
      the write/dir/symlink helpers at `:1128/:1179/:1287/:1325`,
      `parent_chain_has_symlink:904`).
- [ ] **Step 3:** extend `fuzz/fuzz_targets/unpack_layer.rs` with the escape
      corpus (coordinate with Plan 128's fuzz re-homing); confirm
      reproducible-unpack byte-identity still holds; `just lint`; commit.

## Task 3 — ADR-002 positioning note  *(independent)*

Add one paragraph to `specs/adrs/002-microvm-security-posture.md` (Threat model /
Out-of-scope discussion) stating *why* mvm chose a hardware boundary over a
userspace application-kernel sandbox — stronger isolation, no syscall-compat
surface, no in-process TOCTTOU class — and citing that class of sandbox as the
reference for the in-guest hardening layer (Tasks 1–2). Pre-empts the recurring
"why not seccomp/Landlock in a namespace?" review question. This is *positioning
prose, not a new claim* — keep it out of the numbered claim table (only list items
in the same threat model as a claim under §Out of scope; adjacent-threat
positioning goes in §Threat model).

- [ ] **Step 1:** write the paragraph; reference the Landlock + seccomp-unotify
      application-kernel sandbox literature as the comparison points.
      `xtask check-spec-numbers` + ADR lint pass.

## Acceptance (Plan 143 is done when)

- [ ] Guest seccomp denies `ioctl(_, TIOCSTI/TIOCLINUX, _)` while preserving
      legitimate ioctls; `core_demo_e2e` still green (Task 1, post-gate).
- [ ] OCI unpack resolves paths via `openat2(RESOLVE_*)`; the symlink-swap +
      escape-corpus regressions pass; fuzz target extended (Task 2).
- [ ] ADR-002 records the hardware-boundary-vs-application-kernel rationale
      (Task 3).
- [ ] `just lint` + `cargo test --workspace` green.

## Considered and rejected (reference-sandbox features NOT adopted)

| Feature | Verdict for mvm |
|---|---|
| seccomp-unotify as an application kernel | **Reject** — the VMM is a stronger boundary; this rebuilds in software what KVM enforces, with a huge compat surface. |
| Landlock for workloads | **Reject** — guest rootfs is user-controlled; already used for the host-side bridge (`crates/mvm-jailer-lite/src/landlock.rs`); dm-verity (claim 3) gives stronger whole-fs integrity. |
| Per-binary verified exec (Veriexec) | **Reject** — dm-verity roothash (`crates/mvm-guest/src/bin/mvm-verity-init.rs`) already does whole-rootfs verified boot. |
| Transparent AES-CTR file encryption | **Reject** — mvm has AES-256-GCM snapshot enc (`crates/mvm-security/src/snapshot_encryption.rs`) + planned LUKS2-in-guest (ADR-058); authenticated GCM beats CTR. |
| Network firewall / pledge-style categories | **Already convergent** — default-deny egress + mandatory-deny ranges (`crates/mvm-core/src/policy/network_policy.rs:466`) + tiered seccomp categories. |
| `--bounding-set=-all` cap drop | **Verify, not learn** — documented (`crates/mvm-guest/src/fs_rpc.rs:12`) but not visible in the `setpriv` call (`nix/lib/mk-guest.nix:193`); confirm it's actually applied. Independent of the comparison. |

## Self-review

- Real symbols only: every file:line above was read during research (seccomp
  `ioctl` allowlist sites; `unpack.rs` 5-layer defense + helper offsets).
- The one residual unknown (Task 1 Step 2's exact `SeccompCondition` shape) is an
  honest red→green step, not a guess.
- Plan 120 dependency is explicit and one-directional (R1 waits; R2/R3 free); CI
  gates route through Plan 128 (Stage D), matching Plan 129 §F.

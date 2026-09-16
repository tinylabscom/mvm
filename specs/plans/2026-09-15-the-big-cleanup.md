# The big cleanup

Backing: preview
Validation: none — the measurements below are reproducible from the
commands recorded with them, but the remediation this plan sequences is proposed,
not landed.

The tree grew faster than it was pruned. Generated code added call paths beside
existing ones instead of into them, named things after the process that produced
them, and left a residue of stubs the existing gates do not reach. This plan is
the inventory of that residue and the order in which it comes out.

The constraint that shapes every item below: **no ADR contradicted, no numbered
security claim weakened, no new attack surface.** Where a simplification would
cost one of those, the item records the trade instead of taking it.

**Issues:** #3303 (two launch stacks) · #3304 (grant audited as enforced) ·
#3305 (gate validates an orphan file) · #3306 (delete the dead KVM VMM) ·
#3307 (**claim 1** — unadmitted `--mount` shares) · #3308 (config path + layout
re-rolls) · #3309 (ADR parity, twelve findings) · #3310 (permissive test
doubles) · #3311 (`specs/` cleanup) · #3313 (miscalibrated size gate) ·
#3314 (`mvm-core` split) · #3315 (naming + the real section-D work) · #3316 (**claims 11 and 13** — a
dead control and an ambiguous witness) · #3317 (no citation gate on ADRs) ·
#3318 (ADR-001 internal defects) ·
#3319 (four Accepted ADRs describing nothing) · #3334 (re-exports satisfy the
dormant-control caller gate). Pre-existing and folded in: #3257–#3264,
#3265–#3277 (the two design-plan epics), #3283–#3288, #3297, #3300–#3302.

## How to use this plan

One workstream per section. One worktree and one PR per workstream — never a
mega-PR. Each unit of work has a GitHub issue; the checkbox here and the issue
move together.

`bdd` and `e2e` must be green before a workstream is called done, and you must
run them *before* you change anything so you know what was already red.

## A. Inventory

**The single most important structural finding.** `check-claim-catalog` checks that a
named witness *exists*; it never checks that anything calls the code that witness
tests. ADR-001:740-742 says so honestly. Three numbered claims are paying for
it right now — claim 1 (#3307), claim 11 (#3316) and claim 13 (#3316) — and in
each case the witness passes because it calls the gate function directly with
hand-built inputs while no production path calls it at all.

`xtask check-dormant-controls` is the right gate and already exists. It
inspects four hand-listed symbols. **Feeding it every `fn:` witness from the
ADR-001 ledger turns this whole class from a review discovery into a CI
failure**, and it is the highest-leverage single change in this plan.

- [x] **A0.1 Harden the dormant-control caller test (#3334).** Exclude plain,
      public, restricted-visibility, and multiline `use` items from caller
      evidence. A re-export moves a control's name into scope; it does not
      prove production invokes the control.

The inventory is the gate for everything else — the later sections are scoped by
what it found. Measured 2026-09-15 against `bad9ebe561`.

### A1. What the existing gates already cover

Two gates already suppress most of the classes this cleanup was written to hunt,
which is why the residue looks the way it does:

- `xtask check-deferrals` rejects `TODO` / `FIXME` / `unimplemented!`, but only
  under `crates/`, `xtask/` and root `*.md`. It never walks `nix/`, `src/`,
  `install.sh` or the `Justfile`.
- `xtask check-no-spec-refs-in-comments` rejects `Plan N`, `ADR-N`, `Sprint N`,
  `W<n>.<n>` and `#<digits>` in comments. Those patterns return **zero** in
  non-exempt source.

So the surviving residue is precisely what those two regexes miss. Widening the
regexes is the durable fix, but each widening fails on the existing sites, so
each one needs its sweep landed first.

- [ ] **A1.1** Extend `check-deferrals` to `nix/`, `src/`, `install.sh` and the
      `Justfile`, after A3.1 lands.
- [ ] **A1.2** Extend `check-no-spec-refs-in-comments` to `follow-up` and
      `Phase <N>`, after E1 lands. 67 `follow-up` and 57 `Phase N` sites exist
      today; roughly 15 of the `Phase N` hits are algorithm steps and must be
      excluded by the sweep, not by an `#[allow]`.

### A2. Parity: where the tree and the ADRs disagree

Twelve disagreements, none of which weakens a claim and all of which mislead a
reader who trusts the ADR. Full table in issue #3309. The shape of the drift is
consistent: ADRs cite file paths and line spans that moved during the crate
consolidation, and two of them describe a mechanism in the present tense that
was never built (ADR-033's `vmm-rustvmm-queue` feature gate, ADR-025's
freeze-time page-cache priming — the only page-cache symbol in the tree is the
opposite one, `drop_page_cache`).

- [ ] **A2.1** Land #3309 — amend the eleven `ADR-WRONG` / `BOTH-STALE` entries
      and fix the one tree-side residue
      (`crates/mvm-cli/src/commands/mod.rs:128` allows
      `clippy::large_enum_variant` for an `Up` variant ADR-027 deleted).
- [ ] **A2.2** **Claim 11's CVE gate has no production caller.**
      `apply_install_gate` (`crates/mvm-build/src/app_deps_gate.rs:149`) has 14
      in-edges and every one is a test or the nightly fixture example.
      `machine run` never reaches it, so ADR-001:151's "a production launch
      fails closed on a high or critical CVE finding" describes a control that
      does not run. And claim 13's **sole** witness `fn:substitute` matches
      **six** definitions under `content.contains("fn substitute(")`, one of
      them a trait default returning `None` — delete the real implementation
      and the gate stays green. #3316.
- [ ] **A2.3** No citation gate covers `specs/adrs/`. ADR-041 says
      `mvm_hostd::nodectl` is implemented and the module has zero bytes;
      ADR-015 pins `PROTOCOL_VERSION = 2` against a tree that says `3`, with a
      witness name that resolves to nothing; nine more citations name deleted
      crates. All mechanically catchable by extending
      `check-witness-citations` to ADRs. #3317.
- [ ] **A2.4** ADR-001 is internally wrong in three places. Claim 1's
      Enforcement cell (`:141`) names `setpriv --bounding-set=-all`, a flag the
      sealed guest's `mvm-setpriv` does not implement and actively rejects
      (`crates/mvm-agentd/tests/mvm_setpriv.rs:64`) — the real drop is
      `PR_CAPBSET_DROP` in the agent
      (`crates/mvm-agentd/src/guest_mount.rs:895`), and the flag is correct
      only for the builder VM. Claim 3's row (`:754`) and its backend-scoping
      section (`:889-893`) cite **ADR-106** and **ADR-107**, neither of which
      exists — and ADR-107 is the sole stated authority for why virtiofs-root
      does not witness claim 3. And `CLAUDE.md`'s "no ADR above 051" is false;
      052 and 110 exist and are cited by six other ADRs. #3318.
- [ ] **A2.5** Two `Accepted` ADRs describe subsystems with zero bytes:
      ADR-041 (`mvm_hostd::nodectl`) and ADR-049 §2 (`WebLinuxBackend` is a
      unit struct whose every method returns `unavailable()`). Eleven
      duplicate/overlapping ADR pairs, of which the **045↔046↔051** cluster and
      a five-ADR networking cluster are the real consolidation candidates.
      Folded into #3311 and #3317.
- [ ] **A2.6** Four `Accepted` ADRs describe implementations that are not in
      the tree — a different class from a stale citation, because there is
      nothing to re-point at. ADR-038 says "implemented end to end" and every
      symbol it names returns zero hits; ADR-023's nftables REDIRECT mechanism
      has no NIC to redirect from (`install_default_deny_nft` has only test
      callers) though its substitution machinery is real and wired; ADR-026 §2
      asserts a build-time setuid check its own §3 defers; ADR-025's
      same-family merging gate does not exist, so the property holds vacuously.
      #3319.
- [ ] **A2.7** ADR-025's refusal of transparent host-socket networking argues
      from "the cost mvm already chose to pay by **staying on virtio-net**".
      mvm has no virtio-net in the workload tier and no network bridge. The
      refusal's *conclusion* survives — its own second paragraph gives the
      correct reason, that the mechanism would move enforcement off the vsock
      seam — but its stated rationale contradicts the shipped design, and
      anyone reasoning forward from it will get the egress model wrong. #3319.
- [ ] **A2.8** **CLAUDE.md understates what ships, in one place.** `:643` says
      "wasm fuel/epoch is declared and unwired". It is wired:
      `cfg.consume_fuel(bounds.fuel.is_some())` and
      `cfg.epoch_interruption(bounds.wall_clock_secs.is_some())` at
      `crates/mvm-runtime/src/wasm_backend.rs:882-883`, `set_epoch_deadline` at
      `:1364`. ADR-001's "(CLOSED.)" at `:310` is the correct one. Every other
      drift found in this audit runs the other way, which is why this one is
      worth calling out separately. Folded into #3309.
- [ ] **A2.9** ADR-001:150 describes the `stages.rs` scan chain as the live
      libkrun egress mechanism, contradicting the same ADR at :441-448
      ("enforced at **one** seam"). The scan chain is dead (§A4). Fix the prose
      as part of #3297, not separately — the two must move together.

### A3. Incomplete, stubbed and placeholder paths

Totals: 43 `TODO`/`FIXME`/`XXX`/`HACK` (9 actionable — 20 are `REDACTION_MASK`
domain vocabulary in `mvm-core/src/pii.rs:379`, 14 are the gate's own
machinery); 74 `unimplemented!`/`todo!`/`unreachable!` (2 actionable — all 18
production `unreachable!` are genuine invariants, all 8 `todo!()` are string
fixtures in xtask gate tests); ~95 real stubs out of ~1,800 raw term hits, the
rest being the secrets-substitution domain noun.

- [x] **A3.1** `nix/profiles/minimal.nix:15-22` carries five security TODOs
      (per-service uid, read-only `/etc`, setpriv, seccomp tier, dm-verity)
      gated on "the security port from `../mvm/crates/mvm-security`". That crate
      does not exist in this 19-crate workspace, so the completion event cannot
      occur, and `check-deferrals` does not scan `nix/`. The profile is an
      internal test fixture, not a user template. Decide per line: land it on
      the real profile, or delete the line.
      Resolved: all five deleted. The fixture runs no services and is never
      sealed, so none applies; its header now says so, and `check-deferrals`
      walks `nix/`, `src/`, `install.sh` and the `Justfile`.
- [ ] **A3.2** `NoopChecker` (`crates/mvm-hostd/src/supervisor/services/binary_integrity.rs:287`)
      is `pub`, returns `Ok(())` unconditionally, and is not `#[cfg(test)]`
      gated — in the crate that gates subprocess binary integrity. Its own doc
      says "never register in production" and nothing enforces that. Same shape
      at `network/stages.rs:62` (`NoopSubstitution`) and `:337` (`NoopScan`).
      All three have only test callers. Gate them behind `cfg(test)` or a
      `test-support` feature so a production registration cannot compile.
- [ ] **A3.3** `crates/mvm-hostd/tests/prelaunch_live.rs:143` —
      `valid_attach_boots_and_agent_reachable` is `#[ignore]`d and its body is a
      comment describing a harness plus `unimplemented!()`. A test that can
      never pass. Write the harness or delete the test.
- [ ] **A3.4** Stub clusters that ship as production behaviour: attestation boot
      measurement is 64 zero hex chars; `mvm-contract/src/policy/policies.rs`
      ships five fields as the literal string `Stub.`; addon signature
      verification does nothing; PII `redact` mode detects but does not redact.
      Each gets finished or deleted — a security-shaped stub that returns the
      permissive answer is worse than an absent one.
- [ ] **A3.5** `crates/mvm-build/src/builder_protocol.rs:7-8` asserts the
      `Workload*` variants are stubbed and that "the guest-side arm panics with
      `unimplemented!()`". Both are false: the arms are implemented at
      `mvm-host-vm-init.rs:2346/2387/2407`, and `mvm-build` contains no
      `unimplemented!()`. Correct the comment.
- [ ] **A3.6** 63 `#[allow(dead_code)]` sites. Each is either a real unused path
      (delete it) or a cross-feature false positive (restructure the `cfg`).
      The project bans `#[allow]` on clippy lints; `dead_code` is rustc's, but
      the same argument applies.

### A4. Duplicate paths

The cold-boot funnel is in better shape than the brief assumed: there is exactly
one production `driver.boot(&spec)` site
(`crates/mvm-runtime/src/workload_runner/runner.rs:404`), pinned by an xtask
gate. The duplication is one layer up, in what happens *around* the boot.

- [ ] **A4.1** Two launch stacks, and the CLI one is missing three enforcement
      steps: the host-budget charge, fatal grant application, and
      `undo_launch` rollback. #3303.
- [ ] **A4.2** A grant that failed to apply is audited as enforced. #3304.
- [ ] **A4.3** `mvmctl run --mount` attaches host-fs shares the signed plan
      never admitted — claim 1 and claim 19's share half. #3307. **Highest
      severity item in this plan.**
- [ ] **A4.4** `check-single-network-path` validates an orphan file the
      compiler never compiles. #3305.
- [x] **A4.5** `mvmctl config edit` opens the wrong path; seven sites re-roll
      the `~/.mvm` layout past the gate. #3308.
- [ ] **A4.6** Egress: three decision sites, three APIs, one of them behind an
      `Option` that can be `None`. #3301, #3297, #3288, #3302 — all four
      verified against the tree during this audit.
- [ ] **A4.7** `VmStartConfig` is constructed at 31 files. A builder exists
      (`crates/mvm-cli/src/commands/shared/start.rs:10` `VmStartParams`) and
      one caller uses it. Make it the owner.
- [ ] **A4.8** `resolve_workload_kernel` exists three times. Two are a
      divergent duplicate: `commands/vm/up/kernel.rs:19` decides "does this
      backend need a kernel" with a **stringly-typed** `matches!` that omits
      `qemu` and `apple-container`, which the typed
      `LocalBackend::resolve_workload_kernel` (`mvm-client/src/launch/mod.rs:221`)
      covers. That exact class of bug already bit once — the code says so at
      `launch/mod.rs:225-230`.
- [ ] **A4.9** `boot_session_vm`'s `admit` parameter is `Option`, documented as
      "Session VMs default to the legacy no-admission path"
      (`crates/mvm-cli/src/exec/session.rs:105-107`). Both production callers
      pass `Some`, so it is dead surface — but the `None` arm is representable
      and the comment invites its use. Make it non-optional.
- [ ] **A4.10** Two compat shims in `mvm-runtime` are pure migration
      re-exports that say so in their own headers:
      `src/driver/{mod,spec,traits}.rs` (61 call sites still name `driver::`)
      and `src/microvm/{mod,boot_config}.rs`. Mechanical; touches no claim.
- [ ] **A4.11** 397 distinct `MVM_*` identifiers in Rust source, 111 read from
      non-test `crates/*/src/**` across 110 files, **no registry** — only four
      are named consts. Eight distinct configuration-reading mechanisms. Start
      with the two worst clusters
      (`mvm-runtime/src/vm/template/registry.rs:29-60`,
      `mvm-cli/src/template_cmd.rs:275-377`) and an xtask gate asserting every
      `env::var("MVM_…")` literal resolves to a declared const.

### A5. Agent-specific content in source

46 sites across 27 files, of which 14 are actionable. The ~250 `anthropic` /
`openai` hits are product domain — egress destinations, AI metering in
`ai_meter.rs`, LLM template generation — not residue, and stay. Zero hits for
every other assistant vendor.

- [ ] **A5.1** `crates/mvm-cli/src/commands/env/builder_vm/bootstrap.rs:492`
      emits a **user-facing runtime error** citing `AGENTS.md` / `CLAUDE.md`. A
      downloaded `mvmctl` ships neither file. Rewrite the message against the
      published contributor docs.

## B. One path for everything

### B1. Is the boot path a reinvention?

**Half. Not as stated.** Having an in-house VMM is an ADR-backed decision
(macOS 26+ needs Hypervisor.framework; libkrun is a third-party Homebrew
dependency), and calling it duplication would be re-litigating an ADR rather
than cleaning up. The boot funnel itself is singular and gate-pinned.

What *is* reinvention: four pieces hand-rolled where a rust-vmm crate from a
family already in the lockfile covers the job.

| | Hand-rolled | Standard |
|---|---|---|
| R1 | `FdtBuilder` — raw FDT token emission, string interning, 40-byte header (`crates/mvm-vmm/src/vmm/fdt.rs:9-151`) | `vm-fdt` |
| R2 | `Arm64ImageHeader::parse` (`crates/mvm-vmm/src/vmm/kernel_image.rs:7-33`) | `linux-loader`'s PE loader |
| R3 | `setup_boot` — GDT, 4-level page tables, e820, zero page, long-mode regs, 499 lines (`crates/mvm-runtime/src/kvm/x86_boot.rs:45-332`) | `linux-loader` `BzImage` + `LinuxBootConfigurator` |
| R4 | `Serial16550` (`crates/mvm-runtime/src/kvm/serial.rs:14`) | `vm-superio::Serial` |

- [ ] **B1.1** Delete `crates/mvm-runtime/src/kvm/` — 1,125 lines of a second
      in-house VMM with zero production callers, citing a `spikes/` directory
      that does not exist. #3306. **R3 and R4 live only in that tree, so this
      deletion removes two of the four reinventions for free.** Do it first,
      then re-scope R1/R2 against what remains.
- [ ] **B1.2** Do **not** collapse the virtio-mmio transport, virtio-blk state
      machine or virtio-vsock. They already reuse `virtio-queue` and
      `virtio-vsock` for the hard parts; the state machines around them carry
      mvm-specific behaviour (snapshot device state, HVF handoff, the egress
      bridge) and upstream `vm-virtio` is less mature. Recorded so nobody
      re-opens it.
- [ ] **B1.3** Do **not** list PL011 as a reinvention. `vm-superio` ships
      16550A and a PL031 RTC only; Firecracker and Cloud Hypervisor each carry
      their own PL011. Recorded for the same reason.

### B2. The SDKs must never shell out to `mvmctl`

- [ ] **B2.1** Note before starting: `crates/mvm-sdk/src/facade.rs:398`
      already carries `impl MvmClient for SubprocessBackend` — the convergence
      ADR-027 calls "not yet done" — with **zero non-test callers**. It is not
      the fix: it implements the target trait *over the argv transport*, so the
      process-per-call and the second entrypoint both survive. Decide whether
      it is a stepping stone or a distraction, and delete it if the latter,
      before it gets cited as progress. Tracked in #3261 against the design in
      `specs/plans/2026-09-15-agent-sandbox-drive-plane.md` WS2. The cycle
      ADR-027 cites is real (`mvm-client` → `mvm-hostd` → `mvm-sdk`), so the fix
      is a new top-of-graph crate exposing one versioned C ABI — **not** a new
      edge out of `mvm-sdk`. Amend ADR-027:167-174 in the same PR.

## C. Shrink the code

The 1500-line rule the brief asks for **already exists as a gate** —
`xtask/src/check_file_size.rs`, `MAX_PROD_LINES = 1500` — and it passes clean
because it is miscalibrated. Fix the counter before splitting anything, or the
next oversized file arrives unnoticed.

- [x] **C1** `check-file-size` counts lines *before the first* `#[cfg(test)]`
      rather than lines outside test spans. `libkrun_builder.rs` carries 4,632
      production lines and is charged 887; `backends/hvf/kernel_boot.rs` carries
      2,208 and is charged 25 — an 88× undercount. **The initial spot audit found
      ten files over the limit while the gate read green; the repaired census
      found 20.** 81 non-test files exceed 1500
      total lines; 83 more are in the 1000–1500 band. #3313. **Do this first.**
      The repair must scan `crates/`, root `src/`, `xtask/`, and `build.rs`,
      exempt modules gated at their declaration site, and pin every current
      oversized file to a shrinking-only allowance.
- [ ] **C2** Split `network_endpoint_proxy.rs` — 5,281 lines. #3302.
- [ ] **C3** `mvm-core`: 2,197 LOC across 13 public modules is referenced by
      nothing; the pack subsystem (2,448 LOC) is a real seam; 1,850 LOC belongs
      to exactly one crate each. The remaining five core modules have
      *overlapping* consumer sets — `plan` and `crypto` have identical ones —
      so there is no clean split and the rest stays whole. #3314.
- [ ] **C4** Three byte-identical hex-encode implementations, one owner.
- [ ] **C5** `CLAUDE.md` says nothing depends on `mvm-agentd` as a library.
      Nine crates do, and at 31,436 LOC it sits mid-graph. Fix the
      dependency-direction paragraph. Folded into #3314.
- [ ] **C2** `mvm-contract/src/ir/hash.rs:22-32` and
      `mvm-sdk/src/compile/source.rs:368-377` are byte-identical `nibble` +
      hex-encode implementations. There is a third at
      `mvm-hostd/src/supervisor/services/binary_integrity.rs:300`. One owner,
      two deletions.

## D. Rust craft

Most of section D is already done, and the measurement says so. `.unwrap()` in
strict production is **26** across 402k LOC, with zero in `mvm-hostd`,
`mvm-agentd`, `mvm-contract`, `mvm-fs`, `mvm-client`, `mvm-http`, `mvm-net` and
`mvm-backends`. `panic!` is **8**. `#[allow(clippy::too_many_arguments)]` is
**one**, in bindgen FFI — the carve-out the rule names. Named constants
outnumber high-signal unnamed ones 2,569 to 413.

So the remaining work is not where the brief pointed.

- [ ] **D1** **502 production `.expect()` calls**, 119 in `mvm-hostd` alone
      (admission, audit chain, egress gate). The migration off `.unwrap()`
      happened; nothing checks that the messages name the violated invariant
      rather than restating the call. Audit the messages. #3315.
- [ ] **D2** **181 unnamed `Duration::from_*` literals**, concentrated in the
      supervisor code Preview claim 18's wall-clock bound is built from. The
      brief's "every magic length gets a name, a reason, and a test" applies
      hardest here, because these timeouts *are* the bound. #3315.
- [ ] **D3** 62 `f` / `f_with_X` public sibling pairs — `capture_vm_full` has
      two extended forms, `network_policy.rs` has four pairs in one file.
      Collapse each to one function taking a params struct, per the rule
      CLAUDE.md already states. Per-module, not one sweep. #3315.
- [ ] **D4** Four of the eight `panic!`s vanish if `Entrypoint` is split so
      builder methods exist only on the variant they apply to — an
      unrepresentable-illegal-states fix, not a panic-removal exercise.
- [ ] **D5** `#[allow(clippy::large_enum_variant)]` at
      `crates/mvm-cli/src/commands/mod.rs:128` names an `Up` variant ADR-027
      deleted. Box the offending variant and delete the attribute.
- [ ] **D6** 63 `#[allow(dead_code)]` sites. Folded into #3310.

**Measurement caveat for whoever re-runs this.** A line-local tokenizer gets
this codebase wrong: multi-line `r#"…"#` JSON fixtures contain braces that close
the enclosing `#[cfg(test)] mod tests` early, so a naive scan counts test code
as production. The first pass of this audit reported 655 non-test `.unwrap()`;
the true figure is 90, and 26 under the strict definition. The repo also marks
test code four ways, including **21 whole files** gated at their `mod X;`
declaration site. Any tool that re-derives these numbers — including the
`check-file-size` fix in C1 — has to handle all of it.

## E. Comments, TODOs, placeholders

145 process-noise comments across 83 files: 67 `follow-up`, 57 `Phase N`, the
rest assorted. Roughly 15 `Phase N` hits are algorithm steps and must survive.

- [ ] **E1** Sweep the 145 sites, then widen the gate (A1.2).

## F. Tests

- [ ] **F1** A test that would pass with the implementation deleted is not a
      test, and this tree has a named instance of the class: claim 1's and
      claim 19's share witnesses pass by calling `enforce_admitted_shares`
      directly with hand-built inputs, while no transient boot ever calls it
      (#3307). `check-claim-catalog` cannot catch this — it checks that a witness
      exists, never that production calls the code the witness tests. Audit
      every claim witness for a production caller, with `graft callers` on the
      subject rather than on the test.
- [ ] **F2** `crates/mvm-hostd/tests/prelaunch_live.rs:143`
      `valid_attach_boots_and_agent_reachable` is `#[ignore]`d with a body of
      comment plus `unimplemented!()` — a test that can never pass. Write the
      harness or delete it.

## G. Dependencies

- [ ] **G1** Deleting `crates/mvm-runtime/src/kvm/` (#3306) may free
      `kvm-ioctls` and `kvm-bindings` (`crates/mvm-runtime/Cargo.toml:102-103`)
      — check for other consumers before removing them.
- [ ] **G2** ADR-032 says hickory is not pulled; three manifests pull it
      (#3309). Decide whether the dependency stays and record the budget
      rationale either way — this is a decision that was made in code and never
      written down.

## H. Nix

- [x] **H1** `nix/packages/mvmctl.nix:54` hardcodes `0.18.0-rc.1`. Read the
      version from the manifest.
- [x] **H2** Replace the hand-maintained vendor hash with lockfile-derived
      vendoring, so an unrelated lock bump cannot turn the package red.
      Already true: `nix/lib/static-crates-cargo-deps.nix` is `importCargoLock`
      over the committed `Cargo.lock`; there was no vendor hash to replace.
- [x] **H3** Write down the boundary: a Nix check provides the package and the
      session environment; the Rust harness owns the behavioural assertions.
- [x] **H4** `nix/ops/README.md` still tells contributors to install Lima and
      run `mvmctl dev up`. Both were removed. Sweep it.

## I. `specs/` and the repo surface

Measured 2026-09-15: `specs/` holds 243 plans (3.6M), 239 sprint-delivery files
(1.2M), 54 ADRs, plus `benchmarks`, `contracts`, `evidence`, `notes`,
`references`, `refactor` and `research`.

Of the 243 plans: **96 are fully checked** (no open boxes), 136 carry open
boxes, and 11 have no checkboxes at all. 112 are number-named — the style
`xtask check-plan-names` freezes for existing files and rejects for new ones.

- [ ] **I1** Delete the 96 fully-checked plans. They are history, and history
      lives in git.
- [ ] **I2** Reconcile the 136 plans with open boxes against the tree before
      carrying any forward. Known inversion:
      `specs/plans/2026-08-18-durable-agent-sessions.md` has its CLI workstream
      ticked over unticked store and transition workstreams.
- [ ] **I3** Fold the 11 checkbox-less plans into whatever they actually are —
      research, a note, or nothing.
- [ ] **I4** Collapse `specs/` to the directories that carry live work.
      Combine all research into one place.
- [ ] **I5** Clean out `specs/SPRINT.md`; consolidate ADRs where two decide the
      same thing; remove `specs/REFACTOR-STATUS.md` once the plans it indexes
      are cut down.
- [ ] **I6** Clean the top-level directory. Present and unexplained today:
      `MIGRATION-269.md`, `DEMO-BUILD-GUIDE.md`, `out/`, `artifacts/`, `keys/`,
      and editor/assistant config for six different tools.
- [ ] **I7** Do not break the workflow doing it — gates, CI and the Justfile
      recipes keep working. `xtask check-agent-notes` and the workflow-structure
      tests both pin file locations.

## J. Machine hygiene

Measured and partly executed 2026-09-15.

- [x] **J1** 81 of 98 directories under `.worktrees/` were orphaned — git had
      already pruned their admin dirs, so nothing tracked them and nothing
      reclaimed them. Deleted their regenerable state: `target/`,
      `node_modules/`, `.venv/`, `.ruff_cache/`, `.wrangler/`, `out/`, and —
      the real consumer — `.mvm-test/`, the per-worktree `MVM_HOME` test state
      root, which held up to **70 GB in a single dead worktree**. Source trees
      left in place. **208 GB reclaimed** (147 GiB → 355 GiB free).
- [ ] **J2** Remove the 81 orphaned source trees themselves, after confirming
      none holds uncommitted work git can no longer see.
- [ ] **J3** Eight branches have a merged PR whose head matches the branch tip
      **and** still have a live worktree: `docs/pr-attribution-rule`,
      `feat/gitignore-outputs`, `fix/3249-security-lane`,
      `fix/3250-claim-witness`, `fix/m1-e2e-prereqs`,
      `fix/m1-reconfigure-handshake`, `release/v0.18.0-rc.2`,
      `release/v0.18.0-rc.2-evidence`. Their sessions have shipped. Retire the
      worktrees once each session reports it is finished.
- [ ] **J4** 21 remote branches have a CLOSED (not merged) PR and 24 have no PR
      at all. Classify and sweep. Use the merged-PR-head signal, not
      `git branch --merged` — this repo squash-merges, so `--merged` reports
      false negatives.
- [ ] **J5** `~/.mvm` holds **296 GB**: `cache/builder-vm` 115 GB (two sparse
      nix-store images at 53 GB and 32 GB), `cache/oci` 65 GB,
      `cache/guest-agent-build` 46 GB, `checkpoints/` 31 GB, `snapshots/` 25 GB.
      The builder images are live — deleting them forces a full rebuild and
      would break any in-flight session. Prune through `mvmctl cache prune`
      rather than `rm -rf`, and only when no build is running.
- [ ] **J6** In-repo: `target/` 173 GB and `.mvm-test/` 15 GB.

## K. Known findings

- [x] **K1** *A credential is sitting in this file.* Resolved, and the finding
      as written was wrong about the exposure. `specs/scratch.md` is gitignored
      (`.gitignore:63`), the `sk-ws-` string is absent from the working tree and
      from all of history (`git log --all -S`), and the only `sk-ant-`-shaped
      string in the tree is a synthetic BDD fixture
      (`features/suites/s3_secrets_pii/secrets_never_enter_guest.feature:8`).
      Nothing to rotate on the repo's account. Whoever held that key should
      still rotate it — it was pasted into a working file — but it never
      reached git.
- [ ] **K2** The AI-agent claim is half-backed and a published page contradicts
      it. Issues #3257, #3258, #3259.
- [ ] **K3** `host.secrets.v1` is named by claim 13 and by `CLAUDE.md`, and no
      handler is registered. Issue #3263.
- [ ] **K4** `agent-session resume --boot` starts a hypervisor and has no
      coverage. Issue #3264.
- [ ] **K5** Install and packaging lifecycle. Epic #3277.
- [ ] **K6** The signature hole in claim 20. Issue #3272.

## Definition of done

- [ ] `bdd` and `e2e` green.
- [ ] `just ci` green.
- [ ] `just check-gated` green.
- [ ] Every xtask gate derived from the workflows, not a subset.
- [ ] No ADR contradicted; no claim's witness weakened or removed.
- [ ] This plan's checkboxes, `specs/SPRINT.md` and any surviving rollup all
      match the tree.

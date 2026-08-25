# Sprint: v1 Clean Restructure & Radical Simplification

**Status:** IN PROGRESS — Phase 0 executing
**Date opened:** 2026-07-14
**Branch:** `plan/mvm-simplification`
**Supersedes:** Plan 231 (radical-simplification, on hold) and the previous rolling `SPRINT.md` (archived in git history).

> The current tree is treated as a **disposable v1**. This sprint restructures it completely.
> **No legacy paths, no compatibility shims, no aliases.** Hard renames only.

## In progress

- [x] **AI egress metering and token budgets.**
      `specs/plans/2026-08-21-ai-egress-metering-and-budget.md`.
      Provider-reported token counts at the host substitution endpoint,
      per-VM Prometheus metrics, chain-signed audit records, and an optional
      token budget that refuses further AI egress when exhausted. OpenAI and
      Anthropic in v1; provider additions are macro-declared.
      All phases are complete and green (`cargo check`, `cargo clippy`,
      `just check-gated`, unit/integration tests, and SDK tests).

- [ ] **Merge-queue throughput recovery.**
      `specs/plans/2026-08-15-merge-queue-throughput.md`.
      The `aarch64-no-kvm-smoke` job was promoted to a required merge-queue
      gate and can take hours under QEMU TCG, serializing every merge. Moved
      the job to `ci-full.yml` (nightly + manual dispatch) and removed it from
      the `Test` aggregate so the queue can move. Structural tests assert the
      new separation. Remaining: land the change, measure post-change queue
      latency, and record the result.

## Delivered (archive — closed to new entries)

> **Do not append here.** A new delivery entry goes in its own file under
> `specs/sprint/delivery/`. This section was a single append point that every
> concurrent session wrote to, so it conflicted on essentially every rebase and
> cost the other sessions a full re-gate of code that had not changed — see
> `specs/sprint/delivery/README.md` and issue #2353. `xtask check-sprint-append`
> fails if this list grows.

- [x] Long-running interactive consoles no longer lose their input relay after
      15 minutes without keyboard activity. Guest output can continue
      indefinitely while later `Ctrl+C` bytes still reach the PTY foreground
      job; host disconnect closes both relay directions and terminates the PTY
      process group; and the documented line-start `~.` escape now provides a
      host-local exit path. A concurrent `machine stop` is distinguished from a
      live-VM control failure, so its expected exit-code-channel EOF ends the
      attached console cleanly without hiding real framing errors. The
      raw-terminal state is restored through an RAII guard. Focused console
      regressions, the full serial workspace suite
      (including 631 `mvm-agentd` and 1,661 `mvm-cli` library tests), workspace
      check, macOS workspace all-target Clippy, and the aarch64 Linux guest-agent
      cross-build pass. The default parallel workspace run exposes unrelated
      global test environment races; the affected tests pass in isolation and
      serially.

- [x] Bootstrap machine readiness — **plan 315**. `mvmctl bootstrap` now
      prepares both the builder VM and verified dm-verity workload kernel, so a
      successful bootstrap does not defer an infrastructure build to the next
      `machine run`. Kernel downloads verify before replacement, local Stage 0
      builds validate every artifact before per-file atomic publication, and
      verified reads reject any crash-skewed cache. Interrupted staging is swept
      on retry while the persistent Nix store remains warm. Local capability validation
      uses the resolved kernel config instead of searching a KALLSYMS-free raw
      image for symbol strings. QEMU Stage 0 now has a reusable Nix-store disk,
      an accurate guest clock, architecture-correct console wiring, and a
      two-hour cold-build window. ARM64 workload kernels carry the console
      drivers required by Firecracker and HVF/QEMU, while bounded OCI blob
      redirects reach only exact trusted Docker CDN origins without forwarding
      registry authorization. The required console dependencies move only the
      ARM64 built-in-symbol ratchet from 944 to its measured 959; x86_64 stays
      at 917. Formatting, workspace check, host workspace
      all-target Clippy, the complete serialized workspace suite and doctests,
      the exact 461-test `xtask --features man` CI lane, and all 172 BDD
      scenarios pass. A KVM-backed ARM64 acceptance run completed cold
      bootstrap and kernel publication, then ran Alpine twice from a fully warm
      cache without launching Stage 0.
      Store reuse additionally requires a clean ext4 superblock alongside the
      external seed marker; the in-process formatter prevents lazy inode-table
      races, and Stage 0 flushes, checks, and unmounts the store before
      reporting success. A live ARM64 cold repair and warm-cache rerun both
      completed without ext4 errors. The Linux all-target Clippy rerun for this
      change remains for CI or a supported builder-VM entry point.

- [x] HVF large-response integrity — **plan 315**. Restored bounded
      virtio-vsock host-to-guest credit accounting that had been removed while
      its relay-side readers remained. Every guest header refreshes the actual
      `buf_alloc`/`fwd_cnt` window before dispatch; unknown credit fails closed,
      32-bit counters wrap per the protocol, and connection/device teardown,
      connection-wide idle eviction, and snapshot guards cover the new state.
      Active traffic in either direction keeps the whole stream alive, so a
      download is not reset merely because its request side has been quiet for
      60 seconds. The focused
      suite proves stop/resume behavior and byte-for-byte delivery of a 32 MiB
      reply; a simulated continuous 4 GiB transfer proves the refillable rate
      budget is not a lifetime quota. A live BDD scenario pins the documented
      `python:3.12` pandas
      install through PyPI. All 503 `mvm-vmm` tests on the macOS host,
      workspace check, macOS workspace all-target Clippy, the serial aggregate
      workspace suite, and the focused x86_64 and aarch64 Linux cross-builds
      are green. The CI test-linux and lint-core lanes passed on PR #2324;
      local Linux-native builder-VM gates are tracked in Plan 316.
- [x] Issue-closeout batch — **#2165, #2321, #2323**. Closed 2026-08-13.
      #2165 closed as
      completed by PR #2330: workload-runner root bootargs now agree with
      read-only block attachments across the selected drivers. #2321 and #2323
      were previously closed; the batch is complete.

- [x] Release-artifact download failures no longer send macOS users into a
      host-Nix setup that writes SSH credentials under `/etc/nix` and forces a
      fresh `sudo` password prompt. Recovery guidance now matches the product
      boundary: mvm manages its own Linux builder, release users retry or inspect
      the versioned release assets, and source-checkout users bootstrap from the
      in-repo builder image. A focused regression test forbids the stale
      `sudo`, `darwin.linux-builder`, and `/etc/nix` instructions.

- [x] The hostd eBPF observability-target test now uses the shared environment
      guard for `MVM_HOME`, preventing parallel tests from observing a temporary
      home and restoring the original value when the test completes. Admission
      tests that read the host's configured grant ceiling now also hold that
      guard and use an explicit isolated host configuration, so bounded-host
      fixtures cannot leak their ceiling into parallel admission tests.

- [x] Span-timing profiling — **plan 318**. The workspace's ~60 `#[instrument]`
      attributes produced no timing data: no layer consumed span close events,
      and both subscriber setups attached `EnvFilter` to the registry, so at the
      CLI's default `error` filter the INFO spans were never constructed at all.
      Plan 318 adds the missing consumer (a `SpanTimingLayer` over a bounded
      log-scale histogram, reporting self time as well as inclusive total),
      moves the log filter onto the fmt layer so spans are constructed
      regardless of verbosity, and instruments the OCI/ext4 paths in `mvm-fs`
      (which carried no `tracing` dependency at all) plus the four backend
      `boot` entry points and HVF restore. Opt-in via `MVM_SPAN_TIMINGS=1|json`;
      off by default. This is the systematic form of the ad-hoc measurement
      behind the Plan 311 findings below.

      Instrumentation then extends to the launch critical path — `mvm-cli` had
      none at all, and it owns the orchestration upstream of where
      `launch_trace`'s six marks begin. `sha256_file` and its cached wrapper are
      timed separately so the re-hash below is a row in the profile rather than
      an inference, and the `ps` process-table scan and OCI pull/layer paths are
      named. Daemon and build entry points (`admit_for_run`, `admit_and_start`,
      `verify_audit_chain_entries`, `pool_build_with_opts`, `build_via_vsock`,
      `workload_build_fingerprint`, `launch_transient`) follow. Guest-side
      `mvm-agentd` is deliberately excluded — its spans would land on the
      guest's stderr, which needs a collection path that does not exist yet.

- [ ] Launch critical-path waste on real-sized images — **issues #2273–#2276,
      plan 311**. Plan 299's prepared-cold baseline runs `alpine`, whose cached
      rootfs is 9.9 MB, and reports the ≤200 ms p50 contract as met. Three
      per-launch costs do not appear at that size. On `python:3.12` — 1.1 GB,
      116x larger, same code path, same warm cache — a profile attributes
      ~557 ms to re-hashing the cached rootfs for the claim-14 provenance record
      (`emit_oci_run_admission` calls the uncached `sha256_file` while every
      sibling admission path uses `sha256_file_cached`, and the sidecar holding
      the identical digest is already on disk beside the file), ~67 ms to a `ps`
      subprocess reaping orphaned VM helpers from inside the image-resolution
      path, and ~28 ms to an `O(n*m)` `windows().any()` scan for dm-verity
      markers across the whole 8.2 MB `vmlinux`. The microVM itself is 74 ms of
      the run. The re-hash does not shrink in release — it is already hardware
      SHA-256 at ~2.0 GB/s — so optimization level is not the lever. The Plan 299
      lane gate cannot catch any of this: it refuses a sample that pulled, built,
      materialized a mount image, or claimed a standby, and a re-hash of a cached
      artifact is none of those, so the sample reports itself clean while scaling
      with image size. Plan 311 fixes the three call sites and adds a large-image
      lane plus a bytes-hashed work flag so the regression class becomes visible.
      Current numbers are from a debug binary and are not comparable to Plan
      299's release baseline; establishing that comparison is the plan's first
      phase and no percentile is published before it.

- [x] Event-driven process lifecycle and shutdown — **Plan 314**. The shared
      macOS kqueue/Linux pidfd process observer now drives normal HVF,
      Firecracker, libkrun, and QEMU shutdown with bounded fallback, final
      liveness verification, and fail-closed escalation. The authorized
      1,000-cycle HVF run records zero SIGKILL escalations; 100 Firecracker
      cycles and 25-cycle libkrun/QEMU runs leave zero processes, PID markers,
      or owned sockets. Internal HVF profiling shows the 5 ms watchdog is not
      the dominant span, so no new control protocol was justified. The
      foreground-wait audit and repository event/timer/reconciliation rule are
      complete. Formatting, workspace check, the complete workspace test
      suite, macOS focused clippy, and Linux all-target clippy pass. A
      post-completion HVF builder fix now stages the work input through the
      shared source filter before packing its ext4 disk, preventing host
      `target/` and other scratch trees from inflating a small flake into a
      multi-gigabyte guest input. The transport-boundary regression test proves
      source files remain present while `work/target` is absent. The authorized
      live sleeper command reduced the HVF work disk from 55.7 GB to 57.1 MiB
      and produced a successful builder result; its subsequent workload boot
      reached a separate guest-agent readiness timeout.

- [x] README CLI/code-example contract — README shell examples and every
      declared CLI option have executable cucumber help witnesses; all 26
      fenced examples are covered by the test-owned manifest, and README
      status text matches the shipped `deploy` and `watch` commands.

- [x] Automatic macOS VM entitlement signing — installers and self-update now
      sign `mvmctl` and shipped supervisors before reporting success, with
      role-specific entitlement profiles. `doctor` validates the active launch
      targets and points normal users to reinstall/update; `mvmctl env sign`
      remains an advanced repair path for source and legacy installations.
      Focused Rust and CLI tests plus installer shell validation cover the
      changed behavior; see `specs/plans/312-automatic-macos-entitlement-signing.md`.

- [x] Audit-chain verification failure no longer reports as "never audited" —
      **issue #2258, plan 302 WS6**. `SignedChainAnchor` remembers the chains
      that failed verification and returns `Err` naming them when a lookup
      misses, instead of an `Ok(None)` the caller renders as "this checkpoint
      has no signed audit entry". The record may well be audited; the ledger is
      what cannot be read, and the two call for opposite responses. A miss with
      every chain clean keeps the old message, which is then true. The verdict
      is fail-closed either way — only the reason changes. `NO_SIGNED_ENTRY` and
      `LEDGER_UNVERIFIABLE` are now shared sentinels rather than retyped
      literals, the warm-pool seam gained `ClaimRefusal::LedgerUnverifiable`
      (an unreadable ledger used to fall through to "parent tampered"), and
      `mvmctl doctor` grows an `audit chain` line that fails when a chain does
      not verify. No repair/reset verb: a chain that can be reset on demand
      cannot detect tampering. Running the new doctor line on a real host
      immediately caught a latent mis-scan this work would otherwise have
      promoted into a hard failure: the unsigned `secrets.jsonl` operator log
      matches the `<tenant>.jsonl` lifecycle shape by accident, and only
      `mvm-client` excluded it. `SECRETS_OPERATOR_LOG` now lives in
      `mvm-core::config` and one predicate serves all three sweeps. 14 new
      tests, all against a synthesized and deliberately damaged chain in a temp
      `MVM_HOME`.
- [x] HVF save/restore for checkpoint and fork — **plan 304**. The HVF backend
      now advertises `SnapshotCapability::SaveRestore`, and
      `machine checkpoint create --class vm-full`, `checkpoint restore`, and
      `checkpoint fork` work on it end to end. Capture dispatches through the
      backend that owns the VM (`AnyBackend::vm_full_control`) instead of a
      hardcoded Firecracker control; the fork-liveness probe reads the shared
      marker list so `hvf.pid` counts, held to the backend catalog by
      `vm_is_running_covers_every_catalog_pid_marker`; the checkpoint origin is
      classified from the machine-state blob (`vm_full_origin`) rather than from
      the supervisor-config blob, which every HVF checkpoint also carries and so
      would have misread all of them. Restore
      now runs the signed-chain lineage gate — previously it verified content
      hashes only. A capture is refused when the VM has a writable disk, since
      a snapshot carries no device backing bytes. 6 new BDD scenarios under
      `features/suites/s11_snapshot/hvf_save_restore.feature`; workspace
      nextest 10600 passed / 24 skipped.

- [~] Open issue reconciliation — **plan 300**. Every open issue is inventoried
      against `origin/main` with an explicit disposition, closure gate, and
      dependency-ordered execution phase. The count has moved 39 → 31 → 28 → 23.
      Closed 2026-08-13: #2165, #2289, #2333, #2423 as completed by merged PRs;
      #2180, #2181, #2305, #2413 as not planned / superseded by Plan 316 or Plan
      313. Then #2292 (PR #2463 — driver_boot split, no sudo bash launch,
      in-process API client), #2307, and #2318 (PR #2465 — the receipt is a
      record not a control, the redundant head `sync_all` is removed, torn-head
      recovery is under test, KVM `emit: receipt` re-measure p50 ~45.4 ms).
      The 2026-08-14 pass closed five more, all combinations rather than
      completions: #2347 into #2299 (both say the launch numbers are
      untrustworthy — one because the test host is 7200rpm, one because
      `guest_kernel_entry_ms` is 0.038 ms and the backends are not measured at
      the same boundaries); #2281 into #2280 (two axes of one substrate, one
      harness, one blocked-on-native-hosts prerequisite); #2199 into #2198 (a
      contract and its enforcement gate, neither meaningful alone); #2193 into
      #2194/#2196 (the prewarm substrate is merged; the residual per-backend
      factory is only testable through each backend's live matrix); and the
      #2166 epic into #2169 (three of four workstreams closed). Every
      transferred criterion is recorded in the surviving issue. Two discrepancies
      surfaced: Plan 316 Phase 2 was marked COMPLETE with six of seven boxes
      unchecked and two verifiably undone, and Plan 316's phase ordering has
      already slipped — Phase 3 is ahead of Phase 2. Both are corrected in the
      plan. **23 issues remain open**, three of them blocked outside this
      repository: #2299 and #2280 need an NVMe `/dev/kvm` host, #2083 needs
      `mvm-studio#18`. #2135 has PR #2472 open with Security run 31817896244
      pending.
- [~] Runtime hardening for production — **plan 303**. Closes gaps between the
      binary CI witnesses and the binary that ships. Landed: trapping integer
      overflow in `[profile.release]` plus a `release-witness` CI lane over the
      crates that parse hostile input (until now every test ran under different
      arithmetic than production); audit-chain appends as a single `write_all`
      + `sync_data`, with a torn tail reported as truncation instead of
      tampering; a cap on the OCI manifest body before it is buffered, and
      decompressed-byte / entry-count caps on layer unpack; fail-closed
      handling of a panicking payload-tapping observer. WS5's scope was
      corrected during implementation — the blanket version would have let a
      panicking metrics counter take down builder-VM networking. Also landed: a
      redacting panic hook across seven daemon bins, reusing the existing
      `SecretsScanner` (a panic payload is the one string the
      no-`Display`-on-secret-types gate cannot reach), and an advisory Miri
      lane over `mvm-contract`. Remaining: extending `jailer::confine_self` to
      the four unconfined moat roles — the Landlock machinery already exists,
      but each role needs an audited seccomp allowlist validated on live Linux,
      which should follow the `feat/seccomp-audit` tooling.

- [x] Durable agent session and event contract — **issue #2167**, plan
      `specs/plans/2167-agent-session-contract.md`. Added the versioned
      transport-neutral contract in `mvm-contract`, with strict public IDs,
      lifecycle commands, durable/ephemeral event envelopes, bounded cursor
      history, retention, idempotent retries, cancellation confirmation,
      adapter-restart replay, and committed transcript/audit references.
      Prompt and output bytes never enter durable history. `mvm-client` and
      `mvm-sdk` re-export the shared surface. Serialization/security tests and
      three non-`@wip` BDD scenarios pass.

- [x] Unified runtime policy and human approval — **issue #2168**, plan
      `specs/plans/2168-runtime-approval.md`. Added typed fail-closed policy
      evaluation bound to signed admission, deterministic rule precedence,
      digest-only approval metadata, and durable approval lifecycle events on
      the agent-session cursor. Authorization, first-valid-response, expiry,
      cancellation, replay, duplicate, and stale-response paths are covered
      by contract tests and three non-`@wip` BDD scenarios. `mvm-client` and
      `mvm-sdk` re-export the shared policy surface; existing network, secret,
      sealed-production, guest, and command-gate enforcement remains in force.

- [x] Typed capability bindings — **issue #2170**, plan
      `specs/plans/2170-typed-capability-bindings.md`. The implementation is
      complete through per-verb descriptors, exact signed admission bindings,
      bounded typed invocation, digest-only audit events, refusal witnesses,
      and a real UDS round trip. The PR carries the remaining host-specific
      BDD execution note.

- [x] Kernel pin freshness — **issue #2289**. Closed as completed by PR
      #2301. The libkrunfw bundle and custom guest kernel now synchronize on
      the verified Linux 6.12.103 LTS tarball, replacing the stale 6.12.102
      pin. Structural parity tests keep both consumers on one version/hash,
      and the existing freshness check refuses a point release that trails
      kernel.org. The prior #2128 closeout remains the history for the
      preceding 6.12.102 bump.

- [x] Runtime SDK parity — **issue #2163**. Added the live process-handle and
      filesystem surface to Python and TypeScript, with a Rust-owned
      `runtime-v0` schema and generated language models instead of duplicated
      handwritten contracts. Client-side production guards cover every
      development-only verb; SSH remains absent. Python (210 passed, 7 skipped)
      and TypeScript (133 passed) SDK suites, machine fixtures, schema drift,
      workspace check, and workspace all-target Clippy are green. The workspace
      test run reached 1,436 passing mvm-cli tests; its sole failure was the
      host-toolchain probe under isolated `CARGO_HOME`, and that test passed
      when rerun with the normal Cargo home.

- [x] Claim-witness CI documentation — **issue #2104**. Corrected the
      `security.yml` trigger and merge-blocking claims, removed three
      unreachable pull-request guards, and aligned the claim descriptions with
      the workflows that actually run them.

- [~] Security mutation-witness repair — **issue #2135**. PR #2448 merged
      witnesses for the `mvm-core` and `mvm-contract` survivors. The remaining
      backend and runtime survivors are accepted in the mutation-witness
      baseline with reasons pointing to live backend integration tests and BDD
      scenarios. PR #2472 (`fix/2135-security-lane-mutants`) is open and the
      pin-only surface gate passes; Security workflow run 31817896244 is the
      final verification gate before merge and issue closure.

- [x] `mvmctl deps capture` — **plan 291 WS3**. Reseals a sandbox-captured
      dependency tree with fresh audit sidecars, updates the lockfile index,
      refuses tampered or unpinned source volumes, and can emit the canonical
      `Dependencies` declaration after verifying the matching lockfile pin;
      implementation is merged. PR #2132 passed branch and merge-group Test,
      Lint, and Nix gates.

- [x] `mvmctl watch` — **plan 291 WS2**. A file-backed Workload IR watcher
      polls local source inputs, recompiles only when the semantic IR address
      or source fingerprint changes, and reports rebuild/no-op iterations.
      Long-running mode now waits for the next change after transient input or
      compile errors, while `--once` remains fail-fast for automation. PR
      #2109 is merged and its required queue gates passed.
- [~] Develop → build → deploy an attested workload image — **plan 291**.
      WS1–WS3 are merged with their queue-gate evidence. WS4 remains open:
      local `machine run --deployment` now verifies and persists an exact
      deploy record/rootfs binding, remote record extraction and boot are
      merged, and persistent-OCI console pre-open is limited to dev profiles
      (PR #2157). The universal-agent design decision and guest-image
      conformance remain open. Tracking issues #2144/#208 own the final
      local/remote boot acceptance matrix.
- [x] `mvmctl deploy` — **plan 291 WS1**. Local deployment now has a durable
      sealed archive and deploy record path, with BLAKE3 as the native artifact
      identity, SHA-256 retained for interoperability, optional environment
      pinning, and fail-closed verification of an explicitly supplied sealed
      dependency volume. A configured remote now ships the record and bundle
      through mvmd’s authenticated upload contract. PR #2131 passed branch and
      merge-group Test, Lint, and Nix gates and merged into main.
- [x] `mvmctl deps install` runs the lockfile-pinned development install in the
      builder boundary and publishes its sealed volume. `mvmctl deps
      capture-live` exports bounded guest content and sidecars before handing
      them to the atomic reseal path, and requires a running development VM;
      implementation is merged through PR #2132, whose branch and merge-group
      Test, Lint, and Nix gates passed.

- [x] Backend crate separation + HVF DAX + QEMU virtio-fs — **PR #2220**,
      branch `feat/backend-crate-separation`. Consolidated HVF under
      `mvm-runtime/src/backends/hvf`, extracted the shared `mvm-vmm` crate for
      VMM primitives, made `VmmSpec` backend-agnostic for virtio-fs shares, and
      wired DAX through HVF, libkrun, and QEMU (via standalone `virtiofsd`).
      Guest kernel configs enable `FS_DAX`/`FUSE_DAX` and Linux cross-compile
      stubs keep the HVF crate building without Hypervisor.framework. The
      pre-existing console-streaming test was fixed by isolating `MVM_HOME`.
      `cargo test -p mvm-runtime` passes (1163 passed, 0 failed, 6 ignored)
      on macOS; `cargo nextest run --workspace` passes on the x86_64 Linux
      builder VM (10372 passed, 19 skipped); and
      `cargo clippy --workspace --all-targets -- -D warnings` is clean on both
      hosts. The follow-up extraction of an `mvm-backends` crate is captured in
      `specs/plans/298-extract-mvm-backends-crate.md`.

- [~] Extract `mvm-backends` crate — **plan 298**, branch
      `feat/298-extract-mvm-backends`. Moved the `VmmDriver`/`RunningVm`
      seam, post-restore signal/primed-barrier helpers, `VmFullControl`, and
      the host `virtiofsd` helper into `mvm-vmm`; `mvm-runtime` and
      `mvm-build` keep compiling via re-exports. Also moved `DeviceAnchors`
      to `mvm-core::checkpoint` so the seam stays substrate-clean.
      `cargo check --workspace`, `cargo clippy --workspace -- -D warnings`, and
      per-crate `cargo test --lib` (single-threaded for `mvm-runtime` to avoid
      a pre-existing cross-crate `MVM_HOME` env race) are green on macOS.
      The `mvm-backends` crate is scaffolded and the test-only `MockDriver` has
      moved under a `test-support` feature; the remaining concrete drivers
      (Fc, Hvf, Libkrun, QEMU) and legacy `VmBackend` shells are still in
      `mvm-runtime`. Tracked in `specs/plans/298-extract-mvm-backends-crate.md`.

- [~] Sensitive egress redaction — **plan 290**. The first delivery establishes
      a validated byte-span detector contract and supplements the curated
      scanner with LeakGuard's reviewed JWT, URL-credential, full private-key,
      Azure connection-string, Telegram-token and Discord-token detectors.
      Arbitrary payloads are scanned as bounded UTF-8 islands without losing
      byte offsets; invalid or overlapping detector spans fail closed and no
      finding carries matched bytes. The same detector feeds one-way masking
      and request-scoped reversible replacement. Default curated secret/PII
      protection now arms compressed and over-cap refusal before forwarding.
      The serial workspace test suite, workspace check, host workspace
      all-target Clippy, cargo-deny and RustSec gates pass. Linux builder-VM
      all-target Clippy remains before WS1 acceptance; streaming bodies, policy
      lowering, admission posture and claim witnesses remain in WS2-WS4.

- [x] Host-side machine logs — **plan 289**. `machine logs` now reads backend
      console captures directly from the isolated host VM state directory, so
      macOS no longer attempts to connect to or auto-start the retired
      interactive dev VM. Isolated test state resolves through the canonical
      explicit-root config helper (`vms_dir_at` / `vm_state_dir_at`), and the
      CLI subprocess receives an isolated home. Workspace tests, check,
      all-target clippy, formatting, and both home policy gates are green.
      The reader itself was then replaced by plan 295's stream plane, which
      keeps the host-side property and reads the files in-process rather than
      spawning `tail`; see that plan doc for which of 289's constraints the
      replacement holds.

- [x] Runtime and decorator SDK parity — **issue #2163 / PR #2171**. The
      Python and TypeScript decorator surfaces and record/live runtime surfaces
      now lower through Rust-owned workload and runtime schemas. Contract DTOs
      are regenerated by `cargo xtask gen-stubs`; native wrappers remain
      language-specific only where decorators, callbacks, async behavior, or
      subprocess policy require them. The BDD suite now executes both SDK
      languages across both surfaces and runs the generated-artifact drift
      check. Python fixture tests, TypeScript build/tests, BDD SDK scenarios,
      focused Rust tests, formatting, and all-target Clippy passed. The full
      workspace test run reached 1,436 passing mvm-cli tests; its sole failure
      was the host-toolchain probe under isolated `CARGO_HOME`, and that test
      passed when rerun with the normal Cargo home.

- [x] Source-checkout kernel bootstrap reliability. `just kernel-workload` and
      `mvmctl kernel build --which workload` now embed the Stage 0 egress client
      they need to reach Nix caches, so a first-time local compile completes
      instead of failing with an opaque source-fetch error. `MVM_KERNEL_SOURCE`
      provides a persistent compile/download/auto choice, with explicit CLI
      flags taking precedence. Covered by manifest, policy, and end-to-end
      builder-kernel validation.
- [x] One-command local microVM UX. A cold source checkout now builds the
      dedicated dm-verity workload kernel automatically during the first
      `machine run --image`, reports the first-run cost, and caches the result;
      installed binaries download the matching hash-verified release kernel,
      while `MVM_KERNEL_SOURCE=download|auto` remains explicit. Admission-path
      tests now share the process-environment guard even under the default
      grant ceiling, preventing parallel tests from observing another test's
      temporary host configuration. The landing page and security docs now
      state the warm-millisecond promise alongside first-run behavior and the
      default-deny trust model.

- [~] Extract `mvm-backends` crate — **plan 298**
      (`specs/plans/298-extract-mvm-backends-crate.md`). Rebased
      `feat/298-extract-mvm-backends` onto `origin/main` and resolved the
      resulting conflicts. Host-side orchestration helpers
      (`host_agent_spawn`, `substitution_spawn`, `broker_services_spawn`,
      `netd_spawn`, `aux_bin`, `egress_shared`, `workload_wait`, `drive_file`,
      `process_liveness`, `boot_config`, `egress_bridge`) now live in
      `mvm-vmm::host`, and substrate helpers
      (`open_console_capture`, `runtime_meta`/`observability_target`, `ui`)
      have also moved there. The new `mvm-backends` crate now owns the
      HVF, libkrun, QEMU, and Mock `VmmDriver` implementations plus the
      legacy `FirecrackerBackend`, `HvfBackend`, `LibkrunBackend`, and
      `QemuBackend` shells; `mvm-runtime` depends on `mvm-backends` and
      re-exports the driver surface for backward compatibility. Workspace
      `cargo nextest run --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo xtask check-claim-catalog`, and `cargo xtask check-dormant-controls`
      are green. Host command execution (`shell`, `linux_env`) also moved to
      `mvm-vmm::host`, closing the last non-FC back-edge from the legacy
      backends into `mvm-runtime`.

      The Firecracker extraction that finishes this is complete —
      `specs/plans/298-extract-firecracker-driver.md`. All five drivers now
      live in `mvm-backends`; `mvm-runtime::driver` is re-exports only, and
      `mvm-backends` depends on neither `mvm-runtime` nor `mvm-build`. The
      backend-agnostic snapshot seam (`SnapshotIO`, the guarded load paths,
      the vsock-only device-model guard, one merged `CannedIO` double) sits
      in `mvm-vmm`; the Firecracker mechanics sit in `mvm-backends::fc`.

      Held to zero new traits and zero new structs and came out negative:
      `ForkVmFullRestorer` became a callback, the two `SnapshotIO` doubles
      became one, and the guard takes a count rather than gaining a view
      trait. Deleted along the way: the retired raw flake launcher (four
      functions, no callers), the `require_linux_env` no-op (seven call
      sites, asserted nothing), and a duplicate `bind_unix_listener`.
      `base/config.rs` moved to `mvm-vmm::host` — the dependency-free leaf
      that was pinning the FC modules — so neither `RuntimeVolume` nor
      `VmSlot` had to move.

      Workspace tests (10,582), doctests, `clippy --workspace --all-targets
      -- -D warnings`, and eleven xtask gates are green.

- [~] NANDA-style execution receipts and conformance badges — **plan 298**
      (`specs/plans/298-nanda-receipts-and-conformance-badges.md`). WS1 RFC
      approved, WS2 core types landed in `mvm-core`, WS3 read-only receipt
      exporter landed, and WS4 runtime emission landed: `AuditEmitter` now
      optionally persists signed `ExecutionReceipt`s under
      `<audit_dir>/receipts/<tenant>/` with `prev_receipt_id` chain continuity
      for `plan.admitted` / `plan.launched` / `plan.exited` and checkpoint
      events. All `mvm-core` / `mvm-hostd` / `mvm-cli` / `mvm-client` unit
      tests and integration tests pass; workspace `cargo check` / `cargo clippy`
      are clean. WS5–WS6 (conformance badge generator, docs) are next.

### mvm-studio local-service wave (issues #2078–#2082; #2083 deferred)

Wave 0 scaffolded the `mvm-client` service module seams (`inventory`,
`volume`, `secret`, `audit`). Each issue lands via its own PR; each PR
updates only its own entry below.

- [x] #2078 — canonical unified machine inventory through mvm-client.
      `mvm_core::client::inventory` adds the typed `MachineInventoryRecord`
      contract (identity/name, persistent-vs-transient kind, status +
      detail incl. paused, fail-closed `build_mode` posture where any
      unknown label deserializes to prod, source/backend, cpu/memory,
      readiness, TTL, created/last-started, tags, host-path-free volume
      attachment summaries, secret-reference count only) plus the shared
      `InventoryQuery` visibility semantics (stopped persistent
      definitions stay visible; stopped transients hide unless included;
      expired hide unless included). `mvm_client::inventory` hosts the
      spec×live join (duplicate live names collapse with the live row
      winning), the fail-closed posture resolver the SDK envelope now
      delegates to, and the read-only `list_local_inventory` composition
      over any `MvmClient` — mock backend included; the `MvmClient` trait
      and gateway are unchanged. `mvmctl machine ls` now renders the
      shared records and its `--json` is the serialized record verbatim
      (SDK-parsed `name`/`status`/`build_mode`/`kind` keys pinned by
      tests). 41 new/updated unit tests across the three crates cover the
      persistent-only/transient-only/joined/paused/failed/stopped/expired/
      duplicate-name/unknown-posture matrix, serde round-trips,
      unknown-field rejection, and the no-secret/no-host-path guarantees.

- [x] #2080 — reusable local encrypted-volume lifecycle service.
      `mvm_client::volume` now owns the canonical lifecycle behind the
      object-safe `VolumeService` contract with strict secret-free DTOs:
      encrypted block-volume create, unlock/lock with DEK-binding tamper
      refusal, typed attachments (mount allow-roots, read-only default,
      dev-profile gate for read-write), exclusive persistent launch leases
      with RAII rollback, just-in-time unlock with re-seal on final release,
      idempotent crash/orphan recovery, and immutable snapshot/restore. The
      CLI volume commands, launch merge, and stop-path release are thin shims
      over the service (host-encryption probe injected from doctor); the
      former CLI-private lifecycle is deleted, not duplicated. 41 service
      tests plus 8 CLI shim tests cover create/list, RO + permitted RW
      attach, duplicate guest paths, exclusive-lease refusal, profile
      refusal, detach/relock, failed-launch cleanup, orphan recovery,
      persistent restart, tampered-ciphertext refusal, and key-material
      absence from DTOs/debug output. The live KVM BDD scenario extends to
      prove relock after the final release; guest write/read + restart remain
      covered by the existing `s26_volumes` firecracker scenarios.

- [x] #2081 — reusable write-only local secret lifecycle service.
      Delivered `mvm_client::secret::SecretService`: one canonical service
      composing `SecretStore` (unchanged keyring/file selection),
      `BindingStore` egress bindings, a new per-machine secret-reference
      sidecar (`secret-refs.json`, metadata only), and JSONL +
      chain-signed audit (`secret.create/replace/bind/unbind/remove/
      remove_refused`). Inputs are `SecretValueInput` (zeroize-on-drop,
      redacted Debug, crate-private accessor); no reveal method or
      value-carrying response type exists. `remove` refuses while an
      existing persistent machine references the secret (no force path);
      `validate_for_admission` fails closed on missing secrets,
      missing/malformed bindings, unauthorized destinations (via
      `host_matches`), and cross-scope references. `mvmctl secret
      put/set/get/ls/rm` now consumes the service (`get` is a pure
      presence check — no decryption). 53 new/ported tests (36 in
      mvm-client, 17 in mvm-cli) including no-leak assertions across
      responses, serialization, Debug, errors, audit records, and
      persisted sidecars.

- [x] #2082 — normalized verified local audit events for UI consumers.
      Delivered `mvm_client::audit::LocalAuditReader`: discovers the
      per-tenant lifecycle chains and per-VM workload chains under
      `<mvm_home>/audit/`, verifies each through the canonical seams
      (`mvm_hostd::supervisor::verify_audit_chain_entries` and the new
      `mvm_hostd::audit_signer::verify::verify_workload_chain_entries`,
      extracted from the existing count-only verifier), enforces a
      per-source tenant-scope check, and returns normalized
      `VerifiedAuditEvent`s (stable `(source, seq)` identity; newest-first
      ordering by signed timestamp → source rank → chain position) with
      typed per-source `AuditSourceRefusal`s — a failed source yields zero
      events, never a partial prefix. Bounded reads with typed cursor plus
      machine/tenant/kind/time filters; all free text sanitized (ANSI/OSC
      strip, control-char drop, length caps, sensitive-label exclusion,
      host-path redaction) at the service boundary; workload `fields`
      payloads are never rendered. `mvmctl audit verify` now runs through
      the same `verify_sources` seam. 53 new tests including the
      refusal matrix (tamper, reorder, truncation, wrong key, cross-scope),
      pagination walk, serde/unknown-field pins, and seeded property loops
      over untrusted audit input.

- [ ] #2079 — persistent + transient launch lifecycle through
      `LocalBackend` (starts after #2078/#2080/#2081 land the shared
      inventory/volume/secret types).

- [x] #2091 — no workload runs as root. `mvm-oci-init` is pid 1 and spawned
      the agent as a root child, so `is_pid1()` was false, `apply_activation`
      returned before `drop_privilege`, and the agent kept uid 0 — and since
      none of its five workload-spawn sites sets a uid, every workload launched
      through it ran as root. Firecracker boots the agent as pid 1 and so
      already dropped to 901; the variable was the init, not the backend. The
      OCI init now spawns the agent with the workload identity, and
      `Verb::spawns_workload_process` plus one check on the shared request path
      refuse any workload-spawning verb served at uid 0, so a boot path that
      never reaches the drop fails closed instead of silently running as root.
      Live: HVF moves from `uid=0(root)` to `uid=901`, Firecracker stays at
      `uid=901`; reverting the mechanism makes the gate refuse with a
      self-describing error. Evidence in
      `specs/research/no-root-workload-live-witness.md`.

- [x] Guest-kernel hardware floor — **plan 286**. Audit the resolved Linux
      6.12.100 configs and remove unsupported physical hardware, radio/input,
      filesystem, power-management, tracing/debug, keyring, task-accounting,
      NetLabel, swap/huge-page and legacy crypto/ABI plumbing while preserving
      every supported virtual-device and security contract. The workload
      configs are ratcheted from 1,189 to 902 x86_64 built-ins and from 1,314
      to 936 aarch64 built-ins. The x86_64 workload `bzImage` falls from
      7,656,448 to 4,072,448 bytes (46.8%) and reaches PID 1 under Firecracker
      1.14.1; the 955-symbol builder config retains cgroups, namespaces,
      netfilter, FUSE and virtio-fs, and its 4,977,664-byte kernel also boots to
      PID 1. Config generation now fails if Kconfig silently restores an
      audited cut. The checksum-verified native aarch64 PR artifact contains
      exactly 936 built-ins in an 8,216,584-byte `Image` (3,339,345 bytes
      gzip-compressed); the raw-HVF block-root harness reached
      `Run /init as init process` at 36.6 ms.

- [x] Continuous guest entropy — **plan 285 / issue #2060**. A portable
      virtio-rng device now fills bounded, validated guest split-queue buffers
      directly from the host CSPRNG, fails closed without consuming a request
      when entropy acquisition fails, and retains no generated bytes that a
      snapshot could replay. HVF advertises the device at a stable MMIO/SPI
      allocation on every boot while preserving the fresh `/chosen/rng-seed`
      for early initialization. Nine focused device tests plus FDT and entropy
      gate tests pass. A live Alpine 3.20 HVF guest bound `virtio_rng.0`, exposed
      `/dev/hwrng`, and returned distinct digests for successive entropy reads.
      PR #2065 passed the complete pull-request and merge-group matrices and
      merged through the queue at `12debbfcb`, closing #2060.

- [x] Zero-open-issue reconciliation tranche: the original 19-issue queue is fully
      classified, with completed, superseded, duplicate, and intentionally
      unplanned items closed with evidence. Queued fixes for #2007, #2028, and
      #2029 have merged. The remaining delivery updates Wasmtime to the patched
      46.0.2 family, synchronizes and actually builds both Linux 6.12.100
      kernel consumers, hardens the installer HTTP fixture, and removes the
      Linux-only 128-second initramfs build from the cold-cache unit test.
      Full-suite validation also made the plan-mode integration test override
      the worktree's `MVM_HOME`, preventing it from reusing another test's
      mutable host-signing key.
      The remaining delivery merged in #2045, closing #1937, #1972, #1983,
      and #2035; #2039 merged separately in #2041. The #2042 helper-lifecycle
      repair merged in #2051. #2050 also resolved the BusyBox-mediated-tool
      defect reported as #2052, and the exact Apple-container E2E now passes on
      current main, closing #2054. #2048 now caches confirmed default-release
      404s per version and architecture for 24 hours while mirrors and transient
      failures remain retryable. The production-volume epic #2040 was closed
      with the then-available evidence, but was subsequently reopened after the
      claimed cross-worker proof was found to cover gateway-local directories
      rather than the gateway→agent→hostd data plane. The subsequently filed
      entropy issue #2060 is closed with merged evidence. The historical
      open-issue query at that point returned zero results.
      A scheduled run on an older commit subsequently filed #2067: the no-SSH
      scanner had not classified a protected-credential-path refusal test as
      deny-only, and the `mvm-cli` mutation shard lacked the pinned Zig
      toolchain required by its build script. The exact rerun also exposed
      missing mutation witnesses for the new L3 privilege-drop path and an
      unclassified, semantically equivalent deletion of libkrun's explicit
      `l3_vsock: false` capability (whose derived default is also `false`). The
      follow-up audits that deny test, installs Zig only for the affected shard,
      adds a PR-time structural regression test, proves in an isolated
      privileged child that `NoNewPrivs` and every capability set are actually
      cleared, and pins the libkrun L3 declaration; its merge closes #2067 and
      restores the zero-open-issue state. A fresh full-security run on the
      merged head then exposed one remaining bounding-set result-classification
      mutant. The follow-up extracts a pure syscall-result classifier with a
      fail-closed truth-table test; the exact Linux `mvm-agentd` mutation shard
      is clean with 27 relevant privilege-drop mutants caught.
      Tracked in plan 284.

- [x] Production object-store volumes — **plan 283 / issue #2040**. Standardize
      remote volume I/O on Apache Arrow `object_store` while preserving the
      accepted mvm↔mvmd ownership boundary and mvmd's distinction between
      multi-attach `StorageBucket` and exclusive block `VolumeRecord`. Completion
      requires canonical contracts, removal of the dead S3/OpenDAL split, live
      local/block attachment, encrypted durable checkpoints and cross-worker
      restore, working remote CLI/API policy, MinIO integration, and Linux/KVM
      persistence/restore proof. Registry-only, compile-only, and mocked-only
      paths do not satisfy the issue. Follow-up verification closed the original
      gateway-local proof gap with the canonical gateway→agent→hostd worker data
      plane; mvm PR #2100 and mvmd PR #203 are merged with green final matrices.
  - [x] WS1: external implementations can run the canonical trait-object
        contract; the unregistered member-only S3 mount provider is removed;
        template-registry S3 remains independently gated; the two-surface gate
        enforces fleet ownership. Focused tests, workspace check/doctests,
        optional-feature check, host all-target clippy, format, model gates,
        audit, and deny are green. The one failure among 8,516 nextest cases was
        an installer-script flake that passed on its focused rerun.
    - The contract, conformance fixture, and local implementation now live in
      the dependency-light `mvm-contract` leaf and are re-exported by
      core and runtime. This lets mvmd depend on the exact mvm-owned type without
      linking either repository's unrelated crypto/VMM dependency graph; the
      leaf's four contract, symlink-refusal, listing, and serde tests pass, and
      its default closure remains async-runtime-free. The isolated full `cargo
      test --workspace --no-fail-fast` gate passes with zero failures after the
      audit posture and process-global test-isolation fixes.
  - [x] WS2: live attachment is complete. Portable encrypted ext4 images,
      launch-time typed resolution, admitted VMM/guest handoff, crash recovery,
      durable exclusive attachment leases, and canonical immutable local
      snapshot/restore with tamper refusal and interrupted-restore convergence
      are covered by focused tests. The local CLI lifecycle and runtime registry
      suites pass 19 and 21 tests respectively. Five new hermetic volume BDD
      scenarios pass in the 88-scenario/442-step suite. Live KVM proves
      failed-start lease cleanup, writable restart persistence (23/23 steps),
      and guest read-only refusal (17/17 steps). The restart uses the driver's
      authenticated stop-time filesystem flush; PID monitoring proves every
      observed Firecracker is reaped. The run also fixed root-owned process
      reconciliation incorrectly treating `kill(pid, 0)` `EPERM` as a dead PID.
      On the final integrated Linux tree, 24 guest-mount tests, 9 OCI-init tests,
      and workspace all-target clippy pass with warnings denied; the host
      all-target commit gate is also green.
  - [x] WS3: mvmd now consumes the canonical mvm leaf contract and implements
        it over Apache Arrow `object_store` 0.14.1 for S3-compatible, GCS,
        Azure, and R2 providers. Remote data and names remain mandatorily
        encrypted with tenant-scoped, zeroizing key material; credential
        resolution has no environment fallback, and provider errors are
        redacted. OpenDAL and its unused closure are gone. The secure dependency
        graph keeps cloud XML parsing on `quick-xml` 0.41 while isolating iroh's
        prerelease digest graph through a tested compatibility re-export.
        mvmd PR #198 carries the implementation; 1,497 gateway library tests,
        1,632 integration tests, the remaining workspace tests/doctests, check,
        all-target clippy, formatting, focused docs, audit, and deny pass.
  - [x] WS5 client increment: the remote stub is gone. The authenticated,
        HTTPS-or-loopback `GatewayBackend` now carries tenant volume create,
        list, attach, detach, checkpoint, restore, and delete operations with
        typed failures and percent-encoded resource IDs. `mvmctl volume
        --remote` reads its URL, in-memory-only bearer token, and tenant from
        dedicated environment variables while local behavior stays unchanged.
        Twenty-one gateway client tests, including one real loopback HTTP request, nine CLI
        lifecycle parser tests, touched-crate checks, all-target Clippy, and the
        complete 115-scenario / 523-step BDD suite pass.
  - [x] WS4/WS5 policy/WS6/WS7: mvmd PRs #199, #201, and #202 deliver durable
        manifests and encrypted checkpoints, gateway-local restore, fencing,
        retention/GC, API policy, metrics, signed lifecycle/refusal audits, and
        operator documentation. The real MinIO lane proves encrypted multipart
        I/O, conditional conflict handling, pagination beyond 1,000 objects,
        and cleanup. A live Firecracker/KVM run proves encrypted attach, restart
        persistence, checkpoint, mutation, restore into fresh state, digest
        recovery, and clean teardown. mvm PR #2064 supplies the authenticated
        remote CLI. The follow-up now supplies the missing canonical
        `VolumeRecord` gateway→agent→hostd transfer, exact-node placement,
        worker-local LUKS derivation, lease renewal/watchdog, and protocol v3.
        The composed Linux/KVM proof is now green: two isolated production
        workers preserve boot counts 1→2 across a source restart, transfer the
        encrypted image through gateway→agent→hostd, and observe boot count 3
        after destination restore. Both follow-up PR matrices are green, mvm
        PR #2100 passed its full merge-group matrix including the Nix 50 MB
        guest-artifact footprint gate, and mvmd PR #203 passed all 11 final-head
        checks before both changes landed.

- [x] Merge-queue auto-requeue: bounded recovery for transiently ejected pull
      requests, with conflict refusal, persistent attempt counting, no checkout
      of untrusted code, and structural security tests. The label counter now
      toggles on every retry so its persistent timeline count cannot stick at
      one. Workflow validation, focused tests, workspace check, clippy, and
      formatting pass. Tracked in plan 282.

- [x] Merge-queue latency audit and workflow hardening: measured 50 recent
      queued merges and 101 merge-group jobs, confirmed runner admission and
      long required-job execution as the dominant critical path, and found
      regenerated speculative groups adding up to 2h04m of rebuild delay. The
      two required workflows now declare `checks_requested` explicitly, cancel
      only superseded pull-request runs, never cancel merge-group validation,
      and give manual runs unique concurrency keys. All five required check
      names and exact-merge-commit validation remain intact. Plan 281 records
      the measured 38m26s p50 / 2h14m03s p95 queue latency. The live ruleset is
      now set to build concurrency 3, group wait 0, and timeout 90 minutes.
      Plan 316 supersedes those capacity settings after a later timeout loop:
      build concurrency 2, minimum batch 1 with no wait, and timeout 240
      minutes.

- [x] Build-cache invalidation: narrowed `nix/lib/workspace-filter.nix` from a
      basename deny-list over the whole workspace root to an allow-list of the
      top-level entries cargo can actually read. The filtered tree is `mvmSrc`,
      so every surviving file was a cache key for every guest binary — a
      Markdown edit, which the contribution rules require on essentially every
      change, forced a full guest-agent rebuild. 416 of 1872 files (22%) stop
      being cache keys, including all 111 spec files and 167 doc-site pages.
      The soundness binding inverts with the list (the fingerprint's walked
      entries must now be a *superset* of the filter's, not a subset), so both
      directions are enforced by tests that parse the specific named nix list;
      both were planted against and recorded in `specs/VERIFICATION.md`.

- [x] Two-verifier oracle bar — **plan 276 WS4**. A signed audit chain frozen
      at `tests/vectors/audit-chain-v1.jsonl`, read by both the host verifier
      and the `no_std` mirror. The previous parity test compared them over a
      chain generated fresh with a random key each run, so neither ever saw
      bytes the other could also see. Diverging the mirror's serialization of
      an absent optional field now fails over the shared corpus. riscv32 stays
      a compile oracle — bare metal has no test harness.

- [~] Content-address replay vectors — **plan 276 WS3**. Frozen
      input→address vectors for `ir_hash`, the RFC-6962 leaf/interior/root
      helpers, `compute_plan_id` and `bundle_sha256`. The tests that covered
      these were relational only: hashing the canonical form with a trailing
      newline moved every address and all four `ir_hash` unit tests stayed
      green. `compute_plan_id` matters most — it does not use JCS, relying on
      serde_json's default key ordering, so the gate pinned the feature flag
      while nothing pinned the address it protects. Remaining: the audit
      `prev_hash` spine, which needs a fixed keypair and belongs with WS4.

- [x] Claim evidence pinned — **plan 276 WS1**. Each claim in
      `model/claims.toml` now declares the `witness_kinds` it rests on, and
      `check-claim-catalog` fails if a declared kind has no live witness, or if
      a present kind is undeclared. Retiring a witness is now an explicit edit
      to that declaration rather than a deletion nothing notices. Before this,
      delisting a witness from both the model and the ADR-001 ledger left the
      board green — claim 1 lost its only CI evidence and the run still
      reported `clean (16 claims, 48 witnesses verified)`.

- [~] Build cache verify-on-read — **plan 276 WS6**. `~/.mvm/dev/builds/
      <rev>/` was served on a hit if `rootfs.ext4` merely existed as a file: no
      digest, no signature, so content substitution went undetected and the
      provenance recorder then signed whatever bytes were on disk — the audit
      log faithfully recording a substituted image as legitimate.
  - [x] Dev-build artifact cache closed in #2053: `mvm_core::action` +
        `verify_artifacts_on_disk`, verified on read, failing closed to a cold
        miss, and evicting both the record and the build directory. Evicting
        only the record would leave the poisoned tree under a name a later
        build can re-adopt. Also closed a mid-build leak of `dev_builds_dir()`
        on failure paths. This unblocks plan 279 WS1.
  - [ ] Kernel cache still open: `resolve_kernel` returns `Cached` on
        `path.exists()`, and `verify_fetched_kernel` has no production caller,
        so neither the fetch nor the read path checks a kernel against its pin.
        Scoped as **plan 288** (`specs/plans/288-kernel-cache-verify-on-read.md`);
        Proposed, not yet scheduled.

- [ ] Build action identity + artifact manifest — **plan 279**
      (`specs/plans/279-build-action-identity-and-artifact-manifest.md`).
      Sourced from `specs/research/deterministic-attestable-builds-and-lean4.md`.
      Wrap Nix rather than replace it: the CAS, the SLSA-shaped pack manifest,
      the deterministic ext4 writer and the signing chain already exist; what is
      missing is a typed action identity and a tree manifest that can see a
      permission bit.

- [x] Transcript evidence is now authenticated as one ordered ciphertext
      evidence set before decryption. Version-2 manifests carry an RFC-6962
      Merkle root over capture bindings, bounds, wrapped-key metadata, and
      ordered ciphertext chunk records; the gateway persists the sealed
      manifest atomically before emitting a chain-signed
      `gateway.transcript_sealed` entry. Export requires exactly one matching
      tenant audit-chain anchor before KEK unwrap and fails closed for legacy
      version-1 manifests or any root, binding, chunk, or chain drift. The real
      `mvmctl trust audit transcript export` path is covered by success and
      tamper-refusal scenarios; 8,403 workspace tests, doctests, clippy/model
      gates, and all 76 BDD scenarios pass. Tracked in
      `specs/plans/280-transcript-root-audit-binding.md`.
- [x] L3 TUN-over-vsock network mode (plan 285 / ADR-036): a workload that
      declares `raw_ip_stack` gets a real in-guest IP stack with no guest
      NIC. There is no operator-facing mode selector — the transport is
      derived from what the workload declares and recorded in the signed
      plan. Shared no_std wire protocol, pure policy core (anti-spoof,
      canonical-egress admission, bounded flows, controlled DNS, declared
      ingress), guest `mvm-net-agent`, machine-scoped host gateway, Linux
      host-TUN/nftables datapath, `CONFIG_TUN` in the workload kernel, and
      the amendment's backend-neutral guest channel, per-boot VM identity,
      signed network lease, and capability-gated forwarding. Wired through
      the launch path: synthesis derives the L3 spec from the admitted mode,
      the workload runner starts the gateway and waits for it to bind before
      the guest boots, and every stop path reaps it. Privileged Linux lane
      run on a KVM host (6/6, live forwarding witness, clean teardown); 23
      hermetic BDD scenarios in `s25_l3_vsock`. macOS is capability-declared
      and refuses; native Windows is not claimed.
      **Retired and deleted by plan 316 (ADR-042).** The historical path has
      been removed from the contract, guest, host, VMM, packaging, kernel, CI,
      dependency, and live-test surfaces. FlowMux is now the only production
      workload-networking implementation; permanent invariants and the final
      backend evidence matrix remain in the active closeout plan.

- [~] Workload stream plane — 22 tasks, **Phase 1 complete, Phase 2 landed
      dormant**. Tracked in `specs/plans/295-workload-stream-plane.md` and
      `specs/adrs/035-workload-stream-plane.md`.
      Phase 1 (output, T1–T10 plus T5b/T6b/T9b–T9d) ships: the guest pump emits
      as produced instead of buffering to exit, the 1 MiB cap that *killed* a
      chatty workload is replaced by ring retention with recorded gap markers,
      records are redacted at one seam then hash-chained and sealed to an
      RFC-6962 root, and `mvmctl machine logs`/`machine run` attach/`mvm-client`
      read the same verified stream from broker, transcript, or console. Three
      limits are stated rather than deferred: the console fallback is
      unredacted, a detached VM's later output reaches no recorder, and a
      spliced read repeats its adopted prefix.
      Phase 2 (input, T11–T16) builds the host→guest stdin channel — grant in
      the signed plan (`host.stream.v1`), single-writer lease, cross-frame
      secret scan, explicit EOF, chain-signed refusals, and a sealed-tier
      refusal of the grant for a shell-shaped entrypoint. ADR-001 reworded
      claim 15 from enforced-by-absence to enforced-by-policy and added claim
      17 at `Preview`; ADR-035 records why the trade was worth making. T16
      documented the channel (`guides/workload-input.md`) and reconciled the
      user-facing prose that still asserted claim 15 in its absence form.
      T17 made it reachable and did so with a live entrypoint resolver in the
      same change, which the plan required: `machine run --entrypoint --stdin
      -` opens the route under the plan that boot was admitted under, pumps the
      caller's stdin through the gate in acceptance order on its own thread,
      keeps the lease alive on a ticker, and closes the workload's stdin on the
      caller's EOF; the grant is minted only for a call that asked. The
      entrypoint now comes from the image's own `mvm-meta.json` sidecar (a new
      `entrypointArgv` field, written by the `mkGuest` and OCI build paths,
      because the host cannot read inside a materialized ext4), and admission
      **fails closed** when it cannot resolve one — so the shell refusal cannot
      go dormant again by a caller forgetting to resolve.
      Plan 293 WS1 then closed the last dormant leg: the per-VM substitution
      endpoint — the one process holding a workload's credentials in the clear
      — fingerprints each secret it resolves and reports `(length, rolling
      hash, category)` on its ready handshake, and `StreamPlane::open_input`
      installs that set on the gate. No plaintext crosses into `mvmctl`.
      Holding fingerprints instead of values costs the scan its live-prefix
      precision, so it withholds a blanket `longest_secret - 1` tail — a
      *precise* carry would make withhold-or-deliver depend on content, which
      is a prefix oracle — and the gate releases that tail after 50ms of writer
      silence, on elapsed time alone, which is what lets a workload reading one
      request line at a time ever receive one.
      Claim 17 stays `Preview`, now for what the enforcement *is* rather than
      whether it runs: a fingerprint match is a length-and-hash match, not an
      identity, and encoding, derivation, a window-straddling split and a split
      the sender separated by a deliberate pause defeat the scan permanently.

- [x] BDD / conformance integration: introduced `model/*.toml` as the single
      source for conformance claims, generated `CONFORMANCE.md`, and added
      `xtask` gates for R1 (`check-conformance`), R2 (`check-honesty`), and R4
      (`check-deferrals`). Added an R3 meta-gate in `mvm-conformance/tests/meta.rs`
      tying registered IDs to Gherkin scenarios and witnesses. Wired the gates
      into `just lint`, added hermetic BDD smoke coverage to PR CI's existing
      test runner, and documented falsifiability in `specs/VERIFICATION.md`.
      Full workspace clippy, xtask tests, and the meta-gate pass.

- [x] Restore the accepted four-job development CI budget: consolidate
      no-std and real-kernel filesystem checks into the existing test runner,
      keep the SDK publication dry-run in the manual full matrix, and remove
      speculative pre-PR and redundant post-merge `main` runs without changing
      required check names.

- [x] Plan 284 CI latency: stop the lint lane from repeating the full workspace
      under `test-support`, remove unshareable multi-gigabyte `target/` caches,
      share `mvm-cli`'s nested build graph across feature fingerprints, move
      man-page tests onto Test's warm compile graph, and keep the removed MCP
      server and smoke lane out of CI. Structural, targeted feature, full
      workspace, and Linux verification are green. The first
      post-change run measured 19–21 minutes of runner wait; its 37m36s Lint
      execution did not beat the 36-minute cold-run baseline because the
      remaining `mvm-cli` and live audit tests dominate the lane.

- [x] #1840 faithful flake-image revert: boot the recorded slot revision,
      reconcile signed artifact hashes, and preserve the admitted restore path.
      Implementation, focused tests, workspace tests, check, and clippy pass;
      branch is ready for pull request review.

- [x] #1839 kernel pin freshness remediation: update the synchronized
      libkrunfw and custom guest kernel pins to Linux 6.12.98. Both pins now
      use the verified upstream hash; focused coverage, freshness checking,
      workspace tests, check, clippy, and formatting pass. Published as PR
      #1845 for review.
- [x] #1813 workload-lifetime firewall state: key installs by `(tenant,
      workload)` so hot plan revisions replace prior rules without orphaning
      firewalls. Focused regression coverage, workspace check, full tests,
      clippy, and formatting pass; published as PR #1847 for review.
- [x] #1827 vsock overload hardening is complete: guest-selected connection
      state and host bridge sockets are capped; idle eviction, shared egress
      budgets, and teardown cancellation are implemented. Null-node routing was
      evaluated and deferred with no production-path change. Delivered through
      #1876 and #1878; tracked in
      `specs/plans/266-vsock-overload-hardening.md`.

- [x] Claim witnesses are now mutation-tested, not merely present.
      `check-claim-catalog` proves a witness exists; nothing proved it can
      fail. Added `xtask check-mutation-witnesses`, which derives the
      mutation surface *from the claims ledger* (each `fn:` witness resolves
      to its declaring file — this repo keeps `#[cfg(test)] mod tests`
      beside the implementation, so a witness lands on the code it guards)
      and pins it to `xtask/mutation-witness-baseline.json`: 26 files across
      8 packages. The cheap default mode runs on every PR and fails when the
      surface moves, so a claim quietly leaving mutation coverage is a
      reviewable diff; `--run` mutates the surface nightly in `security.yml`
      and ratchets survivors, failing only on a *new* hole. Claims that reach
      no mutable file are reported and pinned rather than silently absent:
      4, 5 and 7 are witnessed only by CI lanes, and claim 16's three
      witnesses all live in an integration test, which cargo-mutants does not
      mutate. The first real run (claim-10 anchor, 52 mutants) found **4
      survivors** — including `NetworkPreset::is_deny_all` surviving
      replacement by both `true` and `false`, because it has no production
      caller anywhere in the tree and its only assertion lives in another
      crate's tests. Seeded as triaged baseline entries; the nightly lane
      ships `continue-on-error` until the baseline covers the whole surface.
      Also extracted the shared ledger parser into `xtask/src/claims_ledger.rs`
      so both gates read one table. `specs/plans/272-mutation-tested-claim-witnesses.md`.
      307/307 xtask nextest.

      **Now also owns the witnesses this gate cannot reach,** folded in from
      plan 274 whose WS3/WS4 are struck. That plan's prose named three such
      claims; the gate derives four. The fourth, MVM-SEC-16, is qualitatively
      different — its witnesses are ordinary Rust functions skipped only for
      living in `crates/mvm-hostd/tests/`, so it needs a planted defect in the
      enforcement code rather than a CI-lane falsification. Keeping the sweep
      beside the gate that computes the list is what stops the two diverging
      again. #1946 was closed by #1958, which exports `HOME`/`MVM_HOME` to a
      runner temp dir in the nightly job and carries `CARGO_HOME`/
      `RUSTUP_HOME` across. That covers the CI lane; `just
      mutation-witnesses` still runs against a developer's real `~/.mvm`,
      which is the entry point #1946 called the sharper of the two.
- [x] Non-hermetic `$HOME` test class closed. `default_mvm_cache_dir` is the
      only resolver that reads `$HOME` while `MVM_HOME` is set (it seeds the
      builder image / runtime overlay from the host's shared cache), so a test
      that moved only `MVM_HOME` still read the developer's real cache — an
      assertion that an artifact is *absent* then passed only on a machine that
      had never built one. Added `TestEnv::isolate_mvm_home` (sets both roots),
      migrated the 25 tests in files that provably reach a seed site, and added
      the `check-test-home-isolation` xtask gate: `default_mvm_cache_dir` is now
      allowlist-only, and tests in seed-reaching files must isolate `HOME`.
      Reachability was measured empirically by running the suite against an
      empty vs. a populated fixture `$HOME` rather than inferred from the call
      graph. 8021/8021 nextest on a host with a populated `~/.mvm`.
      **Deferred → closed.** `mvmctl::audit_emissions_live
      update_check_does_not_emit_audit_entry` failed intermittently under full
      workspace concurrency and was correctly ruled out of the `$HOME` class.
      Triaged in the nextest-profile work: not a concurrency flake but a bug in
      the shared `serve_release_latest_fixture` helper it and its sibling use.
      The fixture's listener is non-blocking, and on macOS the accepted socket
      inherits `O_NONBLOCK` (proven against both platforms — Linux does not
      inherit), so its read returned `WouldBlock` before the request landed and
      the loop treated that as "request complete". The fixture then answered an
      empty request with a 404 and half-closed, which the client saw as that
      404 or as a reset mid-send. macOS-only, which is why CI never saw it.

- [x] Cross-root cache-seed hardening (#1925, #1926, #1927, #1928). The three
      opportunistic seeds that populate an isolated cache root from the host's
      shared one now share `mvm_build::cache_install`, which owns the single
      derivation of the default cache root — so the set of places that can read
      `$HOME` while `MVM_HOME` is set is exactly one, and the
      `check-test-home-isolation` allowlist shrank from four entries to two.
      `install_initramfs_into_cache` now verifies the staged image against its
      `initramfs.hash` sidecar before the rename, closing the one real
      integrity asymmetry: the hash is SHA-256 of the *uncompressed* cpio (the
      size sidecar is the compressed length), so this gunzips rather than
      hashing the file, and it runs at cache-root admission rather than on
      every resolve to keep a decompress off the boot path. Abandoned
      `<arch>.tmp.<pid>` staging dirs are now reaped by age (a real 6-day-old
      orphan was found on a dev host), and the initramfs seed asks the resolver
      for its artifact dir instead of recovering it from a file path. Three
      test fixtures had to become realistic — they wrote `b"image"` with a
      `b"hash"` sidecar, which is why the gap survived review.

- [x] Builder-image seed verified at admission (#1932). The cross-root seed
      copied four artifacts and left the integrity sidecars behind, so the
      seeded cache could not be verified afterwards *and* read as
      `MissingArtifactDigestManifest` to a later bootstrap — which then
      rebuilt the ~775 MB it had just copied. The seed now carries the
      sidecars and checks `.mvm-artifacts.sha256` before admitting bytes,
      declining (not erroring) on drift so a damaged shared cache falls
      through to a fresh local build. Measured cost of digesting the image is
      ~2.1s, which is why the check sits at admission and not in
      `validate_builder_vm_image_cache`, which runs on every builder VM
      start. The digest logic moved into `mvm_build::cache_install` and is
      now shared with the bootstrap readiness check — that also fixed two
      latent defects in it: the old version read each artifact wholly into
      memory (775 MB) instead of streaming, and compared whole manifest
      strings, so a reordered manifest read as tampering.

- [x] Restore the claim witnesses that had gone red in the nightly. The
      `security.yml` cron had failed **ten consecutive nights** (2026-07-21
      through 07-30), starting the night after the crate consolidation
      (`d115fcebe`) merged. Two of the five red jobs were the named witness
      for a numbered claim, so those claims had been unwitnessed the whole
      time, not merely noisy.

      **MVM-SEC-05's only witness ran nothing at all.** The fuzz lane's
      first step still declared `working-directory: crates/mvm-guest`, a
      crate the consolidation deleted; the step failed to *start*, and
      because the fourteen targets were sequential steps in one job, every
      later target was skipped too. Four of the nine directories were stale
      (`mvm-guest`, `mvm-oci`, `mvm-vm-host`, `mvm-ext4`); the corpus-upload
      block had been updated to the new paths, so the rename was done
      halfway. Fixed independently and first in #1958, which corrected the
      fourteen `working-directory` values in place; this branch's matrix
      rebuild was dropped in favour of it.
      **Residual, since closed:** the targets remain sequential steps in
      one job, but the nightly budget was `secs=1800` with no
      `timeout-minutes`, so 14 x 1800s was 7 hours of fuzzing against
      GitHub's 6-hour ceiling — before per-target sanitizer builds. That is
      exactly what happened: by 2026-08-16 the lane had grown to seventeen
      targets and every cron run was killed partway down the list. The
      budget is now 720s per target under `timeout-minutes: 300`, and
      `xtask check-workflow-paths` multiplies the two so target eighteen
      fails a PR rather than silently pushing the lane back over the
      ceiling. A matrix (one cell per target, `fail-fast: false`) remains
      the shape that would also stop one stale entry skipping every target
      after it.

      **MVM-SEC-07's two witnesses failed for unrelated reasons.**
      `cargo-audit`: `quick-xml 0.37.5` carried RUSTSEC-2026-0194/0195 (both
      7.5) via `object_store 0.11`; bumped to `object_store 0.14`, the first
      release requiring `quick-xml >= 0.41`. Fixed, not ignored — and the
      step's ten `--ignore` flags, whose comment claimed to mirror
      `deny.toml`'s `ignore = []`, were removed after confirming none still
      matched anything in the graph. `cargo-deny`'s duplicate-dalek failure
      was diagnosed independently and fixed first in #1952; `deny.toml` had
      never carried those entries while `check-duplicate-majors` had — the
      two-gate drift that let the PR-visible gate stay green while the
      nightly stayed red.

      Also restored: the flake-lock gate (two probe examples pinning
      `inputs.mvm` to this repo were missing from a hardcoded exclusion list
      — replaced with a check for the property itself, anchored so
      `nix/flake.nix`'s documentation comment does not match) and
      builder-VM reproducibility (`mvm-builderd` joined the host-binary
      manifest but not the cross-compile step).

      Two new gates make both rot classes PR-visible, each with a planted
      defect recorded in `specs/VERIFICATION.md`:
      `check-workflow-paths` resolves every workflow `working-directory`
      and `cargo fuzz run` target against the tree, and
      `check-mvm-host-binaries-sync` now treats the cross-compile step as a
      third mirror of the binary manifest. Claim 5's witness was retyped
      from `ci:fuzz` — which matched the job key and stayed green through
      all ten dead nightlies — to the three fuzz targets it actually names.

- [x] A claim-bearing CI lane can stop backing its claim two ways, and only
      one was watched. #1970 reports a *red* Security lane, but it triggers on
      `workflow_run: completed`, so it fires only when Security finishes —
      when the schedule itself stops firing, nothing completes, nothing
      reports, and silence reads as health. That is not hypothetical: Security
      ran nightly to 2026-06-16 and not again until 2026-07-21. Five weeks in
      which sixteen claims kept green ledger entries with no evidence behind
      them, and no watcher could have said so.

      `xtask check-claim-witness-freshness` covers absence, on its own
      schedule rather than on `workflow_run`, because the whole point is to
      notice a lane that never ran. It maps each `ci:` witness onto the
      workflow anchoring it (reusing #1980's resolver, lifted into
      `claims_ledger` so one implementation serves both gates), derives the
      allowance from the cron, and fails when the newest run is older than
      three missed firings. It deliberately does *not* re-check conclusions —
      that is #1970's job, and two gates on one property would eventually
      disagree. Lanes with no daily-or-better cron are reported as notes, not
      judged: a pull-request lane is legitimately idle. Falsified by making
      Security's cron hourly, which reported it 14h stale and named all eight
      claims it backs.

      Bundled: `ci-full.yml` now `cargo check`s the cargo-fuzz crates. They
      are workspace-excluded, so no lane compiled them and the nightly aborts
      on its first failure — which is how a syntactically invalid harness
      survived eleven days. Run against main the step rediscovered both real
      defects in seconds.

- [ ] Witness rigor (`specs/plans/274-witness-rigor.md`). **WS1 shipped
      (#1940):** 13 of 17 `#[repr(C)]` types carried no compile-time layout
      contract and the other four asserted size only, so nothing was protected
      against a same-size field reorder. Deriving the values from the headers
      rather than the Rust structs found that all seven hand-declared
      `sockaddr_vm` copies mirror the pre-Linux-6.0 layout (`svm_flags` landed
      at offset 12 in 6.0, shrinking `svm_zero`; the total stayed 16, which is
      why a size-only assertion could never have caught it). Also answered the
      question the contracts raised: device-mapper layout drift **fails
      closed** — `DM_TABLE_LOAD` returns `EINVAL` for a displaced
      `target_type`, measured against Linux 6.8 — so MVM-SEC-03 was never at
      risk. **WS2 shipped (#1943):** `just test-ci` named a nextest `ci`
      profile that did not exist and had therefore never run. Adding it, with
      no captured test output in the uploaded JUnit, surfaced that the
      `update_check_does_not_emit_audit_entry` flake deferred above was not a
      concurrency flake at all but a macOS-only fixture bug — an accepted
      socket inherits `O_NONBLOCK` there but not on Linux, so the fixture read
      an empty request and answered 404. Fixed; that deferral is closed.
      **WS3 and WS4 struck; plan closed.** `check-mutation-witnesses`
      (#1934) shipped the mutation-testing idea mid-flight and does it
      better, so both workstreams fold into
      `specs/plans/272-mutation-tested-claim-witnesses.md` §WS-3. The
      deciding argument was a live drift: WS3 hand-copied the list of
      claims mutation testing cannot reach and recorded **three**
      (MVM-SEC-04/05/07), while the gate *derives* that list from the
      ledger and reports **four** — it also names MVM-SEC-16, whose three
      witnesses are ordinary Rust functions cargo-mutants skips only
      because they live in `crates/mvm-hostd/tests/`. Claim 16 therefore
      needs a planted defect in the enforcement code rather than a CI-lane
      falsification, which is a different task from the other three. The
      corrected four-claim sweep now sits next to the gate that computes
      the list, so the two cannot drift again. #1946 is fixed: `--run`
      confines `HOME` and `MVM_HOME` to a temp root, applied where
      cargo-mutants is spawned so the nightly job and the local recipe
      share one implementation.

- [ ] Plan 272 WS-2 — the full-surface mutation baseline, and what
      establishing it found. The surface had never been measured end to
      end, and the first complete run says 1221 mutants, 359 surviving.
      Most of the finding is not the survivors.

      **Eight of the twenty-six files could not be measured at all.** The
      lane is package-scoped, and three packages were green under
      `--workspace` and red alone: `mvm-sdk` never enabled
      `mvm-core/test-support`, so its tests did not compile; `mvm-cli` has
      42 tests driving the root package's `mvmctl`, so
      `CARGO_BIN_EXE_mvmctl` is unset; `mvm-runtime` had a test spawning
      an `mvm-hostd` binary. Claims 1, 3, 10, 11, 14 and 15 were affected.
      Two of the eight reported `total=0 missed=0 caught=0` — what a
      fully-covered file reports — because `ensure_mutants_actually_ran`
      enumerated the one baseline verdict it had seen (`Failure`) and a
      timed-out baseline reports `Timeout`. It now requires `Success` and
      a nonzero count.

      **Two files carry 242 of the 359 survivors**, both the same shape: a
      witness resolving to a large multi-purpose file. `mvm-host-vm-init.rs`
      (claim 2, 164) and `console.rs` (claim 15, 78) each have their own
      witness fully caught while the rest of the file answers to no claim.
      Both are scoped through the new `SurfaceScope`, which cannot be
      produced by resolution, demands a written reason and a tracking
      issue, and survives a re-pin — so narrowing a claim's surface costs
      an argued diff. Filed as #2006 and #2021 with the measurements.

      **The in-claim survivors were nearly all real holes**, closed with
      tests and each verified by planting its mutant. The sharpest:
      `validate_guest_mount` and `denied_host_roots` — claim 1's Tier-0
      host-filesystem guard, which would have admitted any guest mount
      path and made the host signer key, the audit chain and `~/.ssh`
      shareable into a guest — and `set_no_new_privs`, claim 2's own named
      `fn:` witness, which had no test at all. Also two fail-open egress
      mutants in `stages.rs` (the L4 allow-list's DNS carve-out widened to
      pass every UDP packet; the SSH banner detector silently ceasing to
      detect) and two in `plan_admission.rs` (a size cap that admits
      everything above it, and a stale verb-grant that survives into a
      reused VM name).

      Three affordability defects fixed alongside: the flat 300s
      per-mutant timeout (too short for three packages, 5× too long for
      another — now derived from each package's baseline);
      `seed_guest_runtime_cache` seeding the guest-binary cache under a
      key the resolver never reads, so three `pull_core` tests
      cross-compiled the guest agent at 55s each (mvm-cli's suite 86s →
      2s); and `just mutation-witnesses` running `--run` against the
      developer's real `~/.mvm` — the isolation now lives at the single
      cargo-mutants spawn site, which is what the entry above already
      claimed. Detail in `specs/VERIFICATION.md` §"Mutation-tested
      witnesses".

- [ ] Tier-1 edge path: the build → sign → export → install-on-another-host →
      admit → boot chain now runs end to end on aarch64, delivered through
      #1888 (ARM64 `Image` kernels reach Firecracker), #1891 (guest reads the
      host-signer pubkey off the cmdline when no config drive is attached),
      #1893 (`bundle export` carries the guest sidecar) and #1894 (fail-closed
      kernel-cmdline guard). The guest boots and its agent pins its grant.
      **Outstanding:** the host↔agent readiness handshake cannot be witnessed
      under nested KVM on a dev Mac — proven not to be an mvm defect, since the
      same handshake succeeds on bare-metal x86_64 KVM with the identical
      Firecracker build. One run on non-nested aarch64 hardware closes it;
      tracked in
      `specs/plans/268-nonnested-aarch64-machine-run-witness.md`.
      **Update 2026-08-18:** hardware is no longer the blocker — a Pi 4 (8 GB,
      real non-nested KVM, EL2, nVHE) is available and boots a Firecracker
      guest to userspace in 0.28 s, settling `console=ttyS0` and GICv2 on real
      silicon. The hermetic half shipped: #2658 (the release tarball carries
      every per-VM binary `mvmctl` spawns — the "needs the full aarch64
      host-side runtime" gap), #2664 (no panic on a fresh `MVM_HOME`), #2679
      (foreign-arch bundle refused at boot and admission), #2682 (workspace
      suite runs natively on aarch64).
      **Update 2026-08-20:** the aarch64 GNU host binaries were cross-built on
      macOS (`mvmctl` + `mvm-hostd` per-VM set), copied to the Pi, and the
      signed `examples/sleeper` bundle installed and verified. The correct CLI
      invocation is transient `machine run --manifest <bundle-sha> --hypervisor
      firecracker -- <cmd>`; `--detach` / named-machine paths still expect a
      templates slot and fail. Two host-side prerequisites surfaced:
      `firecracker` must be on `root`'s `PATH` (the launch script uses `sudo`),
      and the `0.18.0/aarch64` runtime overlay must be seeded in
      `~/.mvm/cache` because the release download 404s. With those satisfied
      the VM reaches `InstanceStart`, but the HVF-builder-produced bundle
      kernel lacks Firecracker PCI virtio-blk/vsock drivers (`error -524`), so
      a Firecracker-compatible bundle (or kernel override) is still required
      before the guest agent can answer. The invocation gap is closed; the
      remaining blocker is the bundle's kernel target.
      **Update 2026-08-20 (later):** the HVF builder VM boot panic was traced
      to `/bin/mvm-setpriv` missing from the builder rootfs PATH; fixing
      `nix/lib/mk-guest.nix` to install the helper allowed the builder VM to
      boot and build a fresh workload kernel. A new Firecracker-compatible
      `examples/exit_code` bundle was exported at `/tmp/exit-code.mvmpkg`
      (24 MiB) with `virtio_pci` and `virtio_vsock` built into the kernel.
      The only remaining blocker is that `rpi1.local` is no longer reachable
      via mDNS, so Pi-side validation is on hold until network access returns.
      **Update 2026-08-21:** the merge-group QEMU-TCG witness exposed a second
      distribution boundary: enabling the published builder bootstrap also
      selected release-only runtime-overlay downloads in CI, where the source
      checkout is intentionally available. The feature split now keeps
      `release-artifact-bootstrap` independent from `release-channel`; release
      and security builds opt into both explicitly, while the aarch64 witness
      can build its checked-out overlay and still download the published
      builder image.

- [x] **Backend shim removal — invert the driver/backend relationship.**
      `FcDriver`, `HvfDriver`, `LibkrunDriver`, and `QemuDriver` now own their
      VMM mechanics directly; the legacy `FirecrackerBackend`, `HvfBackend`,
      `LibkrunBackend`, and `QemuBackend` shells are deleted. Every selectable
      microVM backend reaches production through the blanket
      `impl VmBackend for WorkloadRunner<D: VmmDriver, ...>`. `WasmBackend`
      remains a documented direct `VmBackend` exemption (WASI container, not a
      microVM). QEMU stays an opt-in Tier-2 dev/test backend, never
      workload-bearing. Verification: workspace `cargo nextest run`, workspace
      all-target Clippy, and `cargo xtask check-claim-catalog` are green; the
      migration boundary is recorded in `MIGRATION-269.md`.
- [x] Lightweight guest WS-3: runtime-overlay guest executables now build
      static-musl without the shared loader bundle; the glibc SDK FFI is
      published as a separate `sdk-sidecar` output with an explicit
      `/mvm/sdk/lib` contract.
- [x] Lightweight guest WS-3 follow-up — automatic SDK-sidecar attachment. The
      signed `ExecutionPlan` now carries a `services` host-service binding set
      (surfaced by `--host-service`), and the launch path attaches the sidecar
      read-only at `/mvm/sdk` if and only if one of those bindings is
      SDK-served. `mvm_hostd::plan_admission::enforce_sdk_sidecar_attachment`
      gates both directions on the one admission path every backend reaches, so
      a dev or mock backend cannot acquire a posture production would refuse.
      The artifact ships as `sdk-sidecar-image` (ext4 + VERSION + checksum
      manifest) and is resolved through the same version-keyed,
      manifest-verified discipline as the runtime overlay; missing, drifted,
      tampered, unreadable, and cdylib-less artifacts all fail closed. Two
      build-backed CI gates pin the split in both directions
      (`runtime-overlay-no-glibc`, `sdk-sidecar-carries-glibc`), and
      `xtask perf footprint --sdk-sidecar` reports the sidecar on its own
      ledger line against its own 8 MiB ceiling, never folded into the base
      50,000,000-byte contract. Source checkouts build the sidecar from the
      flake.
- [x] Plan 273 — SDK sidecar release acquisition. Closes the end-user half of
      the WS-3 follow-up: `release.yml`'s new `sdk-sidecar-image` job publishes
      a per-arch `sdk-sidecar-<arch>.tar.gz` plus its `.sha256`, copying the
      derivation's own `checksums-sha256.txt` through rather than regenerating
      it so the bytes the resolver verifies are the bytes Nix produced. The new
      `mvm_build::sdk_sidecar` fetches the archive checksum before the payload,
      hash-verifies the archive, safe-extracts it through the runtime overlay's
      now-generalized entry validator, re-checks the archive's own manifest
      against the extracted bytes, installs stage-then-rename, and ends with a
      `SdkSidecarResolver::resolve` against the *installed* entry so a transport
      bug cannot cache something that only fails at boot. The launch path
      consults the overlay's own build-vs-download resolver, so a contributor
      never silently downloads; a source checkout keeps the fail-closed refusal
      naming `nix build ./nix/images/runtime-overlay#sdk-sidecar-image`.
      `tests/release_assets.rs` pins the workflow's asset names to the Rust
      constructor that requests them. 10 downloader unit tests, 5 launch-path
      tests, 4 release-asset gates, and 2 BDD scenarios (acquire-and-boot,
      checksum-drift refusal), taking the BDD suite to 57 scenarios / 279 steps.
- [x] Plan 277 — cosign-verify the downloaded runtime overlay and SDK sidecar.
      Closes plan 273's one deferred gap. Both archives are now verified against
      the release workflow's cosign-keyless signing identity before extraction,
      through `mvm_core::crypto::image_verify` and the existing
      `release_trust` root — no new dependency. Two findings shaped it: the
      published `*.tar.gz.bundle` files are in the legacy cosign format the
      in-binary Rust verifier *rejects*, so `release.yml`'s signing step is
      split (binary tarballs keep legacy for the cosign-CLI consumers,
      image tarballs move to `--new-bundle-format`); and no released version has
      ever shipped a runtime-overlay tarball, so mandatory verification costs
      zero compatibility. Fails closed: a build without `manifest-verify`
      refuses the download rather than downgrading to digest-only, and
      `MVM_SKIP_COSIGN_VERIFY` — documented but until now never read by any
      code — is the emergency escape. Drive-by: made
      `initramfs::resolve_returns_missing_when_cache_empty` hermetic; it read
      the developer's real `$HOME` cache and failed on any machine that had
      built an initramfs.
- [ ] Plan 278 — transparent connect interception for non-cooperative
      workloads. Proposed, nothing implemented. Closes the app-compat gap left
      by cooperative interception (proxy env + loopback SOCKS5h): a workload
      that ignores proxy env fails closed today, which is correct security and a
      real compatibility wall. Design is seccomp user-notify on `connect(2)`,
      redirected into the existing loopback proxy via `ADDFD_FLAG_SETFD`, adding
      no NIC and no second egress gate. Two findings shaped it: `seccompiler`
      0.5 can express no notify action and its install helper discards the
      listener fd, so the notify filter stacks as a second hand-written BPF
      program alongside the tier filter; and the notify TOCTOU is harmless here
      because the authorization decision is made at the host endpoint from the
      SOCKS request, not from the address read out of guest memory. **W0 is
      measured and it refuted the plan's own framing.** A four-case matrix on
      Linux 6.8.0 (`ptrace_scope=1`, supervisor as parent, both read routes
      probed) shows the two candidate resolutions are a conjunction, not a
      choice: same-uid alone is denied under `DUMPABLE=0`, and `DUMPABLE=1`
      alone is denied across a uid boundary. Exactly one configuration reads.
      Separately, a privilege drop leaves the process at `dumpable = 2`
      (`SUID_DUMP_ROOT`), so "relax `DUMPABLE`" means *affirmatively raising* it
      after the drop in the launch path, not deleting a `prctl` in
      `hardening.rs`. `CAP_SYS_PTRACE` was considered and rejected against the
      emptied bounding set. One maintainer decision remains — accept the
      surviving design (workload `/proc/<pid>/mem` readable at its own uid, for
      a feature that is explicitly not a security control) or close the plan.
      W1–W3 stay frozen until it lands.
- [x] Lightweight guest WS-2: replace the static util-linux privilege-drop
      binary with the dedicated static-musl `mvm-setpriv` helper, including
      UID/GID, group, no-new-privileges, and optional loopback capability paths.
- [x] Lightweight guest WS-5/WS-6 slice: the Nix-built rootfs keeps only the
      kernel module dependency index, the runtime overlay allocation is capped
      at 16 MiB, and CI measures rootfs + overlay + dm-verity sidecars + kernel
      against the literal 50 MB complete-artifact contract. The default tenant
      now omits its redundant dynamic busybox input and copies the CA bundle
      without retaining the source `cacert` store path. A build-backed gate caps
      the lean registered runtime closure at two paths, and the same footprint
      ledger now reports those exact hash-anchored paths. `mkGuest` re-minimizes
      the immutable ext4 after nixpkgs adds its generic 16 MiB growth reserve.
      The measured rootfs is 10,499,072 bytes, and the all-in footprint with
      overlay, both verity sidecars, and the 14,460,936-byte kernel is 33,917,960
      bytes (32.35 MiB), leaving 16,082,040 bytes of headroom.
- [x] Persistent builder completion reliability: the egress helper writes stderr
      to its VM-scoped log instead of retaining the caller's pipe, and dispatch
      completion follows the authoritative child exit after draining available
      stderr even if a detached descendant still holds a writer.

---

## 1. Why

AI-driven development left the tree far larger and more tangled than the product warrants. Measured on `main` @ `6632527a8`:

| Symptom                                 | Measured today                            | Target                                                                           |
| --------------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------- |
| Workspace crates                        | 19 members (+xtask, +root)                | **~11**, named by domain area                                                    |
| Cargo.lock packages                     | **490** (~72 direct)                      | material cut (dedupe TLS/net/ext4/compression stacks; drop dead deps)            |
| Cargo features                          | **28 names, 396 `#[cfg(feature)]` sites** | **2** (`user`, `host`) + the prod/dev guest-agent build split                    |
| Production binaries                     | **~29** (15 host, 13 guest, 1 CLI)        | **1 host + 1 guest + 1 CLI**                                                     |
| Base directories                        | **6 roots** + stray `~/microvm/vms`       | **1** (`~/.mvm`)                                                                 |
| Files > 1500 lines                      | **39** (worst 7,997)                      | **0** non-test                                                                   |
| Egress through the auditable vsock seam | **2 of 4 backends** (libkrun/HVF only)    | **100%** of workload backends                                                    |
| specs/                                  | 512 files / 156k lines                    | ADRs only (consolidated)                                                         |
| Top-level directories                   | ~30                                       | **~8** (`crates` `features` `nix` `specs` `xtask` `examples` `public` `scripts`) |
| Open worktrees                          | 77                                        | the working set                                                                  |

The bar: a codebase an **expert human can read and navigate**, fully tested, following the Rust guidelines in the referenced gist. **Non-negotiable:** security, auditability, attestation-via-nix, and data governance are preserved or strengthened, never traded away.

**Core goal — wasm containers from the same architecture.** The `VmBackend` seam + `Workload` IR + one host egress/audit boundary must also run a workload as a **wasm container** (a `WasmBackend`, WASI wasm module), not only a microVM — supporting more backends from one model and reaching hosts without KVM/HVF (CI, edge, the browser). This is enabled by, and makes non-optional, a **`no_std` core**: `mvm-contract` builds `#![no_std] + alloc` on `wasm32` with tests, CI-gated. Full design in `specs/refactor/02-architecture.md` §Wasm-container; workstream is WS11 (promoted to core).

### Reference models (studied, not copied)

- **A compact pooled microVM runtime** (single crate, few binaries, minimal features, bundled kernel, HVF/KVM backends, lightweight event loop, low memory, and sub-100ms snapshot restore). Reference for lean dependencies, low memory, and a small external API shape (`Image`/`Vm`/`Pool`/`ExecBuilder`, warmup/snapshot/streaming-exec/`expose_tcp`/live host mounts).
- **Modular runtime crate naming:** `agentd`, `cli`, `filesystem`, `image`, `network`, `protocol`, `runtime`, `utils`. Adopted (with `mvm-` prefix).
- **holospaces**: `default-features = false` no_std core with `std` as an opt-in feature; `unsafe_code = "forbid"` at the workspace; no_std OCI layer decoders → the wasm/browser path.
- **Rust guidelines** (gist `c3161f55…`): builder pattern over many-arg fns; traits over duplicated fns; newtypes over stringly-typed APIs; `thiserror` in libs; minimal deps; minimal default features; `mlock`/`zeroize`/`subtle` for secrets; small functions; `[lints]` with pedantic; release profile tuning.

---

## 2. Target architecture

### 2.1 Crate map (~19 → ~11, named by domain area)

| New crate        | Absorbs                                                                  | Role                                                                                                                                                          | `no_std`?                    |
| ---------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| **mvm-contract** | `mvm-sdk::ir` + protocol wire types + policy types + `mvm-verify`        | Workload IR, wire protocol, policy/audit types, audit-log verifier. The wasm/browser-capable core.                                                            | **yes** (`no_std` + `alloc`) |
| **mvm-core**     | `mvm-core` (std parts)                                                   | Single-dir config/paths, crypto (keystore/attestation/signing), catalog.                                                                                      | no (std)                     |
| **mvm-fs**       | `mvm-ext4` + `mvm-oci` + build's rootfs/overlay/unpack                   | Turn any image (OCI **or** nix) into a mountable rootfs + `vmlinux`; ext4 writer/reader; runtime overlay; mount ordering/policy; OCI registry fetch + unpack. | no                           |
| **mvm-net**      | `mvm-network` + hostd gateway/dns + guest net/netinit                  | vsock/UDS transport, host-mediated egress, DNS, network-policy enforcement, secret-substitution + PII-redaction seam.                                      | no                           |
| **mvm-runtime**  | `mvm` + `mvm-backend`                                                    | `VmBackend` trait + libkrun/hvf/firecracker impls (mock behind `test-support`); VM lifecycle, templates, pool, warm-start.                                    | no                           |
| **mvm-build**    | `mvm-build`                                                              | Nix builder-VM pipeline (the nix-execution engine).                                                                                                           | no                           |
| **mvm-hostd**    | `mvm-hostd` + `mvm-vm-host` + host-side builder bins                     | **The single host binary.** Resident single-process daemon; all host roles as in-process tasks.                                                               | no                           |
| **mvm-agentd**   | `mvm-guest` + `mvm-guest-helpers` + `mvm-host-services-ffi`              | **The single guest binary.** Shipped in the runtime-overlay volume.                                                                                           | no                           |
| **mvm-sdk**      | `mvm-sdk` (minus `ir`)                                                   | Decorator + runtime authoring + the **tree-sitter → Workload IR → nix template** pipeline.                                                                    | no                           |
| **mvm-client**   | `mvm-client`                                                             | Facade (`MvmClient`). **Every CLI command routes through it.** The stable surface mvmd consumes.                                                              | no                           |
| **mvm-cli**      | `mvm-cli`                                                                | `mvmctl`. Thin; delegates to `mvm-client`.                                                                                                                    | no                           |

Kept as-is: `crates/deps/libkrun-sys` (FFI), `xtask`. **Dropped/folded:** `mvm-ext4`, `mvm-network`, `mvm-verify`, `mvm-guest-helpers`, `mvm-vm-host`, `mvm-host-services-ffi`, `mvm-mcp` (folded into `mvmctl serve` behind an `AgentProtocol` trait — MCP now, ACP later, no per-protocol crate; see WS7), the orphan Swift supervisor dir, `qemu` backend, dead deps (`colored`, `names`, `hickory-server`, stale `mvm-egress-proxy` path).

Logging is **`mvm-core::log`** (a module, not a crate): structured `tracing` for operational logs (→ `~/.mvm/logs`) **and** the seam that emits chain-signed, tamper-evident entries to the audit log for every security-relevant action. Secrets/PII are redacted at the boundary — never logged. "Auditable everywhere" means every guest↔host RPC and every egress byte is traceable through the vsock seam and the chain-signed audit log.

**Dependency direction (high → low), acyclic:**
`mvm-cli → mvm-client → mvm-runtime → {mvm-build, mvm-net, mvm-fs} → mvm-core → mvm-contract`, with `mvm-hostd`/`mvm-agentd` at the top (bin crates nothing depends on), and `libkrun-sys` a near-leaf pulled by runtime/build.

### 2.2 Binary model — 1 host + 1 guest, no subprocess forks

- `mvm-hostd` and `mvm-agentd` are each **one process**. Roles (supervisor, broker, signer, audit, substitution, DNS; and in the guest: agent, runner, netinit, oci-init, verity-init) are **in-process async tasks / threads**, never fork-`exec`'d helpers.
- **No `std::process::Command` / `tokio::process::Command` anywhere** in the host, runtime, or guest-agent paths. All former shell-outs become native Rust: ext4 (pure-Rust writer/reader), supervisor L4 policy, tar/gzip/zstd (Rust crates). CI lint enforces zero `Command` in these crates.
- **Two carved exemptions** (the process _is_ the workload, not a helper we spawn for our own logic): (1) launching the **Firecracker** VMM process; (2) the **builder VM** invoking `nix` — the builder VM is a nix-execution engine and that is its sole purpose. Both are allow-listed explicitly in the lint.
- **Secrets isolation (Option A):** keys/secrets live in a dedicated module — `mlock`ed, `zeroize`-on-drop, constant-time compare (`subtle`), never logged; the whole daemon runs under seccomp + landlock; the vsock parsers stay fuzzed. This trades the previous address-space process-moat for in-process isolation + memory hygiene; the primary guarantee (_secrets never enter the guest_) is untouched.
- **Multi-role dispatch** is by subcommand/argv0 within the single binary (no fork). PID-1 variants (verity-init, oci-init) are selected by the overlay's init symlink.
- The **builder VM runs the same single guest binary** (`mvm-agentd` in a "builder" role: drive the nix build, report status/outcome, emit the artifact location) — one guest binary across workload _and_ builder VMs, not a separate builder-VM binary set.
- **Host daemon state store = append-only, signed `jsonl`** (the tamper-evident shape the audit chain already uses), never an embedded SQL / `libSQL` database — fewer deps, smaller attack surface, and it doubles as an audit artifact.

### 2.3 Feature model — exactly two

Two workspace surfaces, enforced by `xtask check-two-surfaces`:

- **`user`** (default): CLI + SDK + build + run microVMs locally.
- **`host`**: library subset — everything to build and run a microVM, no authoring niceties.

The 28 member features collapse: `builder-vm`/`pure-mkfs`/`manifest-verify` become always-on (the default and only path); `schema` moves to build-time codegen in `xtask`; `s3`/`template-registry-s3`/`custom-dns`/`dev-watch`/`mcp`/`remote`/`attestation-*` are folded in or runtime-detected. The **one** remaining compile-time capability boundary is the **prod vs dev guest-agent build** (`dev-shell`) — a security boundary (no console / `do_exec` in prod), a separately compiled artifact, not a convenience flag.

### 2.4 Directory model — single `~/.mvm`

One base root, `~/.mvm` (override `MVM_HOME`; keep `MVM_DATA_DIR` as an alias only for the transition, then drop):

```
~/.mvm/
  state/     vms, machines, instances, pool
  cache/     builder-vm, stage0, images, packs, nix-store
  run/        per-VM UDS sockets (was scattered; closes #1654)
  keys/  audit/  volumes/  overlays/  images/  builder/  logs/  config.toml
```

Kill: `~/.cache/mvm`, `~/.config/mvm`, `~/.local/{state,share}/mvm`, `$XDG_RUNTIME_DIR/mvm`, and the hardcoded `~/microvm/vms` const. Every path flows through one `mvm-core::config` module; a CI lint bans inline `$HOME/.mvm` / `dirs::` / ad-hoc `.join(".cache")`. The only intentional out-of-tree path is the AF_UNIX 108-byte socket fallback, itself rooted under `~/.mvm/run` via a short hash.

### 2.5 Backend & egress model

- Backends: **libkrun** (macOS 13–25 + Linux), **HVF** (macOS 26+), **Firecracker** (Linux workload), and **wasm** (`WasmBackend` — WASI wasm-container; core goal, see §1 + WS11). **QEMU** stays as an opt-in Tier-2 dev/test backend, never workload-bearing and never auto-selected. `mock` behind `test-support`.
- Selected via the existing `BackendKind` enum + `backend_catalog!` registry — **never string-matched**. The ~6 remaining `backend.name() == "…"` sites in `mvm-cli` and the dead retired-backend arms are removed.
- **One host-mediated, default-deny, audited egress boundary on every workload backend**, transport-abstracted via `VmDuplexTransport`: vsock/UDS for the microVM backends, WASI host-calls for the wasm backend. Firecracker, libkrun, and HVF all use the `WorkloadRunner` endpoint seam; any backend that cannot mediate egress through the host fails closed on `--network-allow`.
- Mount ordering is `rootfs → runtime-overlay → custom`, with an **explicit no-shadow rule**: a later mount may never shadow an earlier target; `/mvm` and `/mvm/runtime` join the deny-prefix set.

### 2.6 Security & data-governance model (preserved/strengthened)

- **Guest sees no secrets, emits no PII** becomes a _universal_ invariant once all egress crosses the host seam: bidirectional secret **substitution** (user-named `${NAME}` placeholders in the guest, real secret injected host-side on egress only for the secret's bound destination) + bidirectional **PII redaction/masking**, both written to the chain-signed audit log. Backed by a CI witness across all workload backends. (Architecture guarantees the host inspects every byte; ruleset completeness is a policy concern.)
- Verified boot (dm-verity rootfs + sealed runtime overlay), signed `ExecutionPlan` admission, content-addressed bundles, and the chain-signed audit log are all retained. Attestation via nix templates and the machine-checked claims catalog stay.
- **Auditable logging everywhere:** `mvm-core::log` emits operational logs _and_ chain-signed audit entries for every security-relevant action; secrets/PII redacted at the boundary; the audit chain stays verifiable via `mvmctl trust audit verify`.
- The guest binary ships **only** as the read-only, dm-verity-sealed **runtime-overlay volume** every microVM mounts — updating the overlay updates every microVM; it is never baked per-rootfs.

### 2.7 Testing model — BDD-first

Every user-facing behavior and every security claim begins as a Gherkin `.feature` scenario, becomes a green cucumber-rs test, then a parametric implementation. **Nothing is "done" until its scenario is green and CI-gated.**

- Top-level `features/suites/sN_<name>/*.feature`, numbered by area — e.g. `s0_cli`, `s1_build_run`, `s2_egress_vsock`, `s3_secrets_pii`, `s4_verified_boot`, `s5_lifecycle`, `s6_admission_audit`.
- A dev-only **cucumber-rs runner** (`crates/mvm-conformance`, _not_ one of the ~11 product crates) wires step definitions to `mvm-client`, so scenarios drive the real facade rather than mocks.
- The **claims catalog becomes executable**: each numbered security claim maps to a scenario, complementing (not replacing) the existing machine-checked witnesses.
- `just bdd` runs the suite; folded into `just ci` / the full local gate.

### 2.8 Top-level layout (root ~30 dirs → ~8)

```
crates/    every crate, incl. the SDKs (Rust + language bindings): the old sdks/ folds in here
features/  BDD suites (cucumber-rs)
nix/       flakes / derivations (absorbs packaging/ + ops/ deploy bits)
specs/     ADRs only (post-sweep)
xtask/     Rust tooling + the BDD runner glue
examples/  example workloads
public/    the website (stray docs/ + web/ fold in); kept current
scripts/   the few remaining dev/CI shell scripts
```

Root files kept: `Cargo.*`, `Justfile`, `README`/`LICENSE`/`SECURITY`/`CHANGELOG`, `AGENTS.md`, `CLAUDE.md`, `deny.toml`, `rust-toolchain.toml`, `treefmt.toml`, `cliff.toml`, `install.sh`, `.github/`, `.githooks/`. Everything else is moved or deleted (WS0.3).

### 2.9 Consolidated vsock networking (one standardized protocol)

ALL workload guest ingress/egress rides vsock through a single authenticated,
default-deny, auditable boundary. Workload backends expose no guest NIC surface
to the runner; Firecracker's former guest-TAP Model-A path is deleted. Data path:

```
guest app → guest loopback / guest egress client → authenticated vsock
  → RealEndpointSpawner + broker/substitution gate → approved endpoints
```

Two capabilities over that one seam:

- **Typed connectors** — secret-bearing requests; the host holds the credential and performs the request; secrets never enter the guest. Reuses the existing broker and the live supervisor L4 gate.
- **Raw admitted egress** — the guest egress client sends approved host/port flows over vsock to the host endpoint spawner; no guest NIC, TUN, TAP, smoltcp, or L3 tunnel is involved.

**Standardized protocol**: workload control and egress requests use the
authenticated vsock transports and strict host/guest protocol types already
owned by the runtime runner, broker, substitution endpoint, and supervisor L4
gate. Default-deny admission, destination policy, secret binding, and audit
are enforced at those typed seams; there is no raw packet stream or L3 worker.

---

## 3. Workstreams

Checkbox legend: `- [ ]` todo. Each WS lists its acceptance gate. Execution is subagent-driven (fresh task + two-stage review per WS), `cargo nextest run --workspace` + `cargo clippy --workspace -- -D warnings` + `cargo fmt --all --check` green before any WS is marked done.

### Phase 0 — Repo & spec hygiene (low-risk, unblocks a clean base)

**Done so far:** `specs/` sweep (`72a4214a7`) · claims/compliance/threat-models consolidated into their topic ADRs (`985225f4e`; `check-claim-catalog` verifies 16 claims / 38 witnesses from ADR-002) · dead workspace deps dropped (`dfc70f6a7`) · worktrees swept to the 2-tree working set.

**WS0.2 — ADR consolidation + renumber (~92 → ~15)**

- [ ] Merge the 13 clusters (Appendix A) into ~15 canonical ADRs; **renumber to a clean `0001..NN` sequence** (updating every cross-reference, the claim witnesses, and CLAUDE.md/AGENTS.md); delete merged files (no decision lost); fix the dup 008/010 titles + the 012 mismatch. Keep ADR-002's content as the security SoT; no mega-ADRs.
- Gate: ADR set ~15 files, cleanly numbered; `check-claim-catalog` + `check-adr-coverage` green.

**WS0.3 — top-level directory compression** (target layout in §2.8)

- [ ] `sdks/` — the SDK _layout_ is **deferred to WS1g** (which creates `crates/mvm-sdk/languages/`, co-locates the Python/TS/… surfaces, and moves the `.argv` machine-fixtures → `tests/`). This WS does only the non-SDK moves below.
- [ ] Fold `ops/` + `packaging/` into `nix/` (+ `scripts/` for the shell bits); move `resources/` into the owning crate's `assets/` (or a shared top-level `assets/`); merge stray `docs/` + `web/` into `public/`.
- [ ] Delete `spikes/`, `web/audit-verify/` (superseded by wasm `mvm-contract`), `schema/` (regenerated by xtask), `bin/`, `out/`, `.mvm-test/`, `.DS_Store` — each after confirming no CI gate depends on it.
- Gate: root matches §2.8; CI green; nothing a gate needs is lost.

**WS0.4 — dep-hygiene CI** (dead deps already dropped)

- [ ] Add a `cargo machete` (unused-dep) gate to CI so dead deps can't creep back.
- Gate: `cargo machete` clean in CI.

**WS0.6 — BDD conformance harness (cucumber-rs)** (see §2.7)

- [ ] Add `features/suites/sN_<name>/` + the `crates/mvm-conformance` cucumber-rs runner + a `just bdd` recipe (folded into `just ci`); seed scenarios for the current security claims and the top-level CLI verbs, wired through `mvm-client`.
  - [x] Gate every software-publication path on a reusable GitHub Actions workflow that runs `just bdd`: runtime releases, kernel release assets, SDK registry releases, and crates.io publication. Keep emergency revocation-list publication independent of the product suite.
- [ ] Standing rule for every later WS: land its Gherkin scenarios in the same change (feature-first — the scenario is written and red before the implementation).
- Gate: `just bdd` green in CI; each security claim has a scenario.

### Phase 1 — Foundations

- [x] **Cross-cutting guest protocol hardening (Plan 254):** made the logical
      control/data-plane split executable with exhaustive verb classification,
      64 total / 48 data request admission, symmetric 256 KiB frame limits,
      48 KiB filesystem/process chunks, offset-addressed `fs`/`cp` transfers,
      host-CID-only console data admission, and mandatory authenticated /
      encrypted host↔guest control sessions on every backend. Guest protocol v2 is a hard cutover;
      schemas and Python/TypeScript bindings are regenerated. Host workspace tests
      and checks plus affected-crate clippy are green; Linux workspace-wide clippy
      remains the required merge-CI gate.

**WS1 — crate restructure** (the spine; each sub-step keeps tests green)

- [ ] 1a `mvm-contract`: extract `mvm-sdk::ir` + wire + policy + `mvm-verify`; make it `#![no_std]` + `alloc`; add a `wasm32-unknown-unknown` CI build; `unsafe_code = "forbid"`.
- [ ] 1b `mvm-core`: rebuild on `mvm-contract`; own single-dir config, crypto, keystore, attestation, catalog, `log`.
- [x] 1c `mvm-fs`: fold `mvm-ext4` + `mvm-oci` + rootfs/overlay/unpack; one ext4 writer + one reader; "image → rootfs + vmlinux" is its public surface. _(`mvm-ext4`+`mvm-oci` merged into `mvm-fs` with `ext4`/`oci` submodules;_ **`oci_to_rootfs` moved mvm-build→mvm-fs `67e492f87`** _— the OCI-image→ext4-rootfs materializer (unpack/path-validation/ext4-materialize/verity-seal, ~2000 LOC + its integration tests) now lives in `mvm_fs::oci_to_rootfs`, using `crate::ext4`; mvm-fs stays a zero-mvm-dep leaf (+uuid). The builder-VM-orchestrated `rootfs.rs` (builder_backend_select/builder_vm) + `runtime_overlay.rs` (guest_agent_build) STAY in mvm-build — correctly a build concern, not fs. **1c.1 walker/materializer unification landed `a28f583b2`** (subagent-driven, spec ✅ + quality Approved): the two duplicate mid-layer tree-walk+materialize implementations (`mvm_build::rootfs::{collect_nodes,UnsupportedNodePolicy,materialize_ext4_pure*}` and `oci_to_rootfs::ext4`'s private `collect_nodes`) are now ONE `mvm_fs::rootfs` module (unconditional; xattr-aware walker + pure materializer + options); `oci_to_rootfs::ext4` = thin adapter (keeps `StagedRootfs` entry, `OciUnpackError` mapping, mke2fs escape hatch); `mvm_build::rootfs` = builder-VM dispatcher only; mvm-runtime `image.rs` rewired to the source. One disclosed behavior change: the OCI in-process arm inherits widen+restore read of owner-unreadable files (error→success only; emitted bytes unchanged, xattr policy pinned `Ignore`). 7518/7518 nextest (+10 net moved/new tests), all gates + Linux zigbuild cross-check green. Review Minor (follow-up): the widen/restore chmod-read-chmod has a narrow pre-existing TOCTOU window — consider open-then-fstat hardening. **1c.2 landed `c944a5bc2`** (subagent-driven, spec ✅ + quality Approved): the runtime-overlay cache-RESOLVE half (`RuntimeOverlayLayout`/`Artifact`/`ArtifactNames`/`Resolver`, `read_overlay_artifact_from_dir`) moved to a new **`mvm_fs::overlay`** module — a pure local probe (seed-from-default-cache deliberately relocated to build-side `resolve_or_seed_from_default_cache`; reviewer traced every in-repo caller still seeds); arch crosses as the dir-name string so **mvm-fs stays a zero-mvm-dep leaf** (`cargo tree` verified); new `OverlayError` with `#[error(transparent)]` mapping keeps messages byte-identical; build/nix-build/download/install/orchestrator stay in `mvm_build::runtime_overlay`; consumers (up.rs, both runtime_overlay commands, xtask version-check) rewired to the source. 7522/7522 (+4 tests), all gates + zigbuild green. **1c is now COMPLETE** — deferred: virtiofs-root-for-OCI (Phase 2), ext4-read facade, the fleet-repo one-line `resolve` switch, the pre-existing-broken Linux+nix `build_produces_resolver_compatible_artifact` test (stages no checksums manifest). `oci_verity_sealing.rs` test stayed in mvm-build (uses mvm-build-only `run_image::seal_run_rootfs_with_verity`). DEFERRED to the pre-PR CI-YAML sweep: `.github/workflows/{ci-full,security}.yml` OCI path-filters/comments are stale across BOTH the old `mvm-oci`→`mvm-fs` merge AND this move (+ nix flake comments) — fix all at once, not piecemeal.)_ Prefer **virtiofs-root for OCI** (boot directly off the unpacked OCI dir, skipping ext4 materialize) where the backend supports it; keep materialize as the fallback.
- [x] 1d `mvm-net`: fold `mvm-network` + guest/host network helpers; vsock transport + egress seam. The DNS codec, policy guard, loopback stub, resolver seeding, and claim-10 wiring are complete; the former L3 tunnel and guest-netd absorption is deleted in the uniform-vsock convergence.
- [x] 1e `mvm-runtime`: fold `mvm` + `mvm-backend`; `VmBackend` trait + libkrun/hvf/firecracker. _(merged flat, workspace green; `qemu.rs` KEPT as the opt-in Linux dev substrate — drop **ratified against**: QEMU stays a Tier-2 dev/test backend, never workload-bearing)_
- [ ] 1f `mvm-build`: slim the builder pipeline.
- [ ] 1g `mvm-sdk`: authoring + the tree-sitter → Workload IR → **nix-template** pipeline (IR from `mvm-contract`); user-specified **base OCI image** as the template base.
  - **`PackageType` trait** under `crates/mvm-sdk/languages/` (moved off the root): each language detects its manifest and surfaces a **locked** dependency set — prefer `uv.lock`/`poetry.lock` over `requirements.txt`, the lockfile over `package.json`, `Cargo.lock`, `Package.resolved`; fall back to the loose manifest and flag it. Built-ins: Python / TypeScript / Rust / Swift; **users register their own**.
  - Custom package types run in the user's trust domain, but the deps they produce still flow through the sealed app-deps audit (claim 11) — extensibility never bypasses the hash-lock/CVE/SBOM seal. Polyglot repos use explicit or ordered detection (no silent first-wins). Co-locate `sdks/python` + fixtures here.
  - **Runtime SDK + decorator are first-class / enabled** (control a live microVM via `mvm-client`). Security boundary = **no shell in prod**: lifecycle + the declared entrypoint + audited output / `expose_tcp` / snapshot / fork are allowed; arbitrary interactive `exec` or console into a _sealed prod_ VM stays dev-only (`dev-shell`; claims 4 + 15).
- [ ] 1h `mvm-client`: facade covering every runtime operation the CLI needs.
- [ ] 1i `mvm-cli`: delete direct reaches into runtime internals; route through `mvm-client`.
- Gate: `cargo build --workspace` for both `user` and `host` surfaces; full suite green; dependency graph acyclic and matches §2.1.

**WS1 execution progress (structure-first, single green branch — `cargo check --workspace --all-targets` green after each; crate count 20→15):**

- [x] `mvm-network`→`mvm-net` rename — `6ae57b438`
- [x] `mvm-ext4`+`mvm-oci`→`mvm-fs` (`ext4`/`oci` submodules) — `10977e915`
- [x] `mvm-vm-host`→`mvm-hostd` (flat; 3 supervisor bins) — `3fc1dae6d`
- [x] `mvm-mcp`→`mvm-cli` `crate::mcp` (behind `mcp` feature) — `42b432b89`
- [x] `mvm`+`mvm-backend`→`mvm-runtime` (flat, 96 files) — `764b7d897`
- [x] `mvm-guest`+`mvm-guest-helpers`→`mvm-agentd` (214 files) — `19f1830ba`. **`mvm-host-services-ffi` kept SEPARATE** — it is a `cdylib` (`mvm_host_services`) the SDK runtimes `dlopen` + nix bakes into the overlay; folding it would break that FFI/nix contract (deviation from §2.1).
- [x] `mvm-contract` extraction (staged, `no_std`+wasm-clean each step) — **ALL 3 INCREMENTS COMPLETE**: **Increment 1** — `mvm-verify` → `mvm_contract::verify`; crate born `#![no_std]+alloc+forbid(unsafe)`, builds on `wasm32` (`13c2a46dd`). **Increment 2** — Workload IR (`mvm-sdk::ir`) → `mvm_contract::ir` + `detect_shell_entrypoint_argv` down from `mvm-core`; 35 consumers rewired, `mvm-net`/`mvm-runtime`/`mvm-storage` dropped `mvm-sdk` for `mvm-contract` (dep-graph tightened); schemars gated behind a `schema` feature so the default/wasm build stays truly `no_std` (`9aa8ba372`). **Increment 3 (DESIGNED — execution remaining, the hard one)**: pull the pure wire/policy DTOs out of `mvm-core`'s `plan/`+`policy/`+`protocol/` (~126 `crate::` refs into `config`/`crypto`/`security`/`instance`/`tenant`) down to `mvm-contract`, logic stays in `mvm-core` on top. Full design of record in `specs/refactor/10-increment3-protocol-core-split.md`: per-module cut (moves/stays/split across all three folders), the byte-identity invariant guarding the mvm↔mvmd signed contract (relocate DTOs **verbatim** — no serde-shape change), four resolved mechanics (keep `DateTime<Utc>` via scoped no_std `chrono`; `std::net`→`core::net`; scoped `thiserror`; orphan-rule crypto-method→free-fn rewrite), companion moves (`lifecycle::SnapshotAt`, `RedactionPolicy`+`ReversibleReplacementPolicy`, `{TenantId,PlanId,WorkloadId}`) that unblock `ExecutionPlan`, the `BundleNetworkPolicy` rename, explicit deferrals (`security_profile`, `HostdRequest`, `VmStartConfig`/`VerbGrantEnvelope`), and the leaf-first Tier 0→4 extraction order (green + wasm-clean after every step).
  - [x] **Tier 0 — GO** (`6577d06ba`): moved `plan/{types,verb,verb_trust}.rs` whole + split `validity.rs` (`FreshnessClaims`→protocol, `checked()`→`mvm-core` free fn) down to `mvm-contract::plan`; added scoped no_std `chrono`+`thiserror` + the FIRST `mvm-core`→`mvm-contract` dep edge. **Proved all four mechanics**: `DateTime<Utc>` compiles no_std on wasm32 + serializes byte-identical RFC-3339 (`"2026-07-16T12:34:56Z"`), `thiserror 2` no_std works, orphan-rule rewrite works, facade re-export keeps every consumer path unchanged. Green (wasm build + nextest 6595/0 + clippy + xtask). Reviewed: spec ✅ / quality approved, byte-identity `git show`-verified pre/post.
  - [x] **Tier 1 — COMPLETE** (all pure/PathBuf leaves across plan/policy/protocol now in mvm-contract; `{TenantId,PlanId,WorkloadId}` rode `types.rs` in Tier 0):
    - [x] **Batch A — protocol leaves** (`d157ff5ff`): `protocol/{signing[SignedPayload],host_cost,host_time,host_audit,broker,routing,network_tunnel}` → `mvm-contract`. All 7 confirmed genuine leaves; verbatim serde; `anyhow`→`RoutingError`(thiserror), `HashSet`→`BTreeSet`, `std::net`→`core::net`, `std::time`→`core::time`. Facade re-exports keep `SignedPayload` + all paths resolving. Caught a stale hardcoded path in `mvm-hostd/net_l3.rs` guard test. Green (wasm + nextest 6595/0). Reviewed: spec ✅ / approved. Minor (deferred to final review): `RoutingError::InvalidJson` also names the to_json serialize-fail case (cosmetic). Stale ADR-020 broker.rs path fixed in the ledger commit.
    - [x] **Batch B1 — policy standalone leaves** (`0509e1403`): `policy/{security,reversible_replacement}` → `mvm-contract` (security's `SignedPayload` import repointed to its mvm-contract path; `std::fmt`→`core::fmt` on a redacted Debug). Verbatim serde (git-show byte-identity confirmed: only `alloc::`/`core::` import lines changed). Green (wasm + nextest 6595/0 + clippy + xtask). NOTE: implementer wedged on a phantom background clippy job pre-commit; controller verified the gate + committed.
    - [x] **Batch B2 — coupled leaves + rename** (`1c5785912`): hard-renamed `policies.rs` `NetworkPolicy`→`BundleNetworkPolicy` (10 files, compiler-guided, serde-invisible; `network_policy::NetworkPolicy` enum untouched, ~250 occ verified) + moved mutually-referential `redaction.rs`+`policies.rs` → `mvm-contract`. `toml` added dev-only (test roundtrips; not in wasm lib build). Verbatim serde (byte-identity confirmed: only the rename line changed). Green (wasm + nextest 6595/0 + clippy + xtask + doctests).
    - [x] **Batch C** (`da40b772`): `protocol/{host_signer,audit_signer}` → `mvm-contract`. host_signer whole; audit_signer's 2 `PathBuf` fields → wire `String` (IPC DTOs, not signed → serde-byte-identical). 2 `mvm-hostd` call sites got `Path::new`/`to_string_lossy` adapters bridging the untouched `broker_control::RegisterVm` (PathBuf) → moved `SignerHelperRegisterVm` (String). Green (wasm + nextest 6595/0). Byte-identity confirmed.
  - [~] **Tier 2** — the SPLITS (orphan-rule crypto-method→free-fn rewrites) + a few clean whole-moves that were mis-classified as splits:
    - [x] **Batch D** (`fc3a05bf3`): `plan/verb_grant.rs` + `policy/bundle.rs` → `mvm-contract`, BOTH clean whole-moves (NOT splits). verb_grant moves whole incl. `verify()`/`signing_bytes()`/`permits()` — they use only chrono/ed25519/serde_json (all mvm-contract deps; edge-consumer grant verification belongs beside the audit verifier, mirroring `mvm_contract::verify`), zero call-site churn. policy/bundle pure DTO (TenantId down). Byte-identity clean; green (wasm + nextest 6595/0). Deviation: added `"chrono"` to schemars `schema`-feature (VerbGrant = first schemars+DateTime type; opt-in only, not in wasm build).
    - [ ] KNOWN COSMETIC (test-only, masked): `mvm-contract/protocol/host_signer.rs` test mod uses `.to_string()` w/o `use alloc::string::ToString` — harmless (mvm-contract tests only build under `schema`→std via workspace unification; standalone no_std test build isn't feasible since libtest needs std). Sweep opportunistically.
    - [x] **Batch E** (`2b5c87a7`): `protocol/{handler,signed_config}` splits. handler: `ServiceError`/`ServiceDispatchResult`→protocol, `ServiceHandler` trait + `ServiceCallCtx` stay. signed_config: `SignedConfigEnvelope`/`SignedConfigError`→protocol, `key_id_for()`→mvm-core free fn (orphan rule, 4 call sites), wrap/encode/decode/verify stay. Deviation: `SignedConfigError::BadEncoding` field `base64::DecodeError`→`String` (base64 err is std-only; enum is thiserror-only NOT serde → serde-safe). Byte-identity clean; green (wasm + nextest 6595/0).
    - [x] **Batch F** (`1b195c572`): `protocol/broker_control` split — DTOs (RegisterVm[4 PathBuf→String], DeregisterVm, ControlRequest, SignedControl, ControlResponse)→mvm-contract; serde_jcs+ed25519 sign/sign_with_key_bytes/verify→mvm-core free fns (serde_jcs not in mvm-contract); ControlError stayed. **Pinned JCS canonical-bytes fixture `control_request_canonical_bytes_are_pinned` PASSES** + full sign/verify rejection ladder green → JCS-signed contract byte-identical proven. Byte-identity full-field verified (all serde attrs/order preserved, sig was already String). Green (wasm + nextest 6596/0). NOTE: impl wedged on phantom background nextest → controller ran gate + committed (2nd wedge; briefs say run synchronous).
    - [x] **Batch G** (`1f227805`): `policy/{secret_binding,dns_pin}` splits. secret_binding: DTO+builders+`FromStr`/`Display`(anyhow→typed `SecretBindingParseError`)→P; `resolve_value()`(std::env)→core free fn. dns_pin: `DnsPin`(`ips`→`core::net::IpAddr`)+`DnsPinRegistry`+chrono-parse methods→P; `new_pin()`(Utc::now clock) + `resolve_network_policy_pins()`(ToSocketAddrs+NetworkPolicy) stay core free fns. Byte-identity clean; green (wasm + nextest 6596/0 + doctests). Impl actively polled (no wedge).
    - [x] **Batch H** (`ccbd926ea`): `policy/network_policy` (1449) split — DTOs (`HostPort`,`NetworkPreset`,`EgressMode`,`NetworkPolicy` + `BANNED_SSH_PORT`/`MANDATORY_DENY_RANGES` consts + `is_banned_ssh_port` + all pure ctors/accessors)→P; `FromStr`/`Display` anyhow→typed `NetworkPolicyParseError`; `iptables_script`/`iptables_cleanup_script` inherent methods→core free fns (1 call site `mvm-runtime/network.rs`); `mandatory_deny_*`/`is_mandatory_deny`(ipnet/std::net) STAY. Acyclic=0 crate:: refs. Byte-identity clean (tag/rename_all/default/skip_serializing_if/deny_unknown_fields all preserved). Green (wasm + nextest 6597/0).
    - [x] **Batch I** (`4813a6c2`): `plan/bundle.rs` (2360) split — DTOs (`KeyId`+`is_well_formed`, `ArtifactRole`, `BundleArtifact`, `BundleResources`, `VerityInfo`, `BundleManifest`+`find_by_*`, `PlanArtifact`+`new`/`signature_bytes`, schema/filename consts, base64 sig helpers)→P; `KeyId::from_pubkey`/`from_identity` + `BundleManifest::canonical_bytes`→core free fns (~45 call sites); `sha256_hex`/`bundle_sha256` + all tar/fs/registry/resolver/truststore/verify STAY. Acyclic clean. Byte-identity clean (all `transparent`/`deny_unknown_fields`/`default`/`skip_serializing_if` preserved — claim-9 contract intact). Green (wasm + nextest 6597/0).
  - [x] **Tier 2 COMPLETE** — every policy/protocol/plan DTO split done; the whole `protocol/` folder + all `plan/`+`policy/` DTOs now in `mvm-contract`.
  - [~] **Tier 3** — the big/gated splits:
    - [x] **Batch J** (`4dfefed6`): `policy/{resolver,audit}` splits. resolver: `EmergencyDeny`(+`is_active`, keeps `Option<DateTime<Utc>>`)+`EffectivePolicy`→P; `resolve`/`pick` stay. audit: `LocalAuditKind`/`LocalAuditEvent`/`AuditAction`/`AuditEntry`→P; `LocalAuditEvent::now()`→core free fn `now_event` (Utc::now clock; 2 call sites); `LocalAuditLog`/`audit_emit!` macro/`event`/`emit`/`read_last_*`(std::fs) stay. Byte-identity clean; green (wasm + nextest 6597/0).
    - [x] **Batch K** (`0d966d018`): `protocol/vm_backend.rs` (2693) split — ~28 DTOs (`VmPortMapping`/`VmVolume`/`VmFile`/`VmStatus`/`VmId`/`VmExitStatus`/`VmCapabilities`/`RequiredCapabilities`/`SnapshotCapability`/`WarmStart*`/`Standby{Spec,Compat,Handle,State,Error}`/`Balloon`/`ClaimStatus`/`LayerCoverage`/`BackendSecurityProfile`/`VmInfo`/`BackendKind`/`RuntimeSource*`/`GuestChannelInfo`/`VmNetworkInfo`) + 4 pure cmdline encode fns→P; `GuestChannelInfo`/`StandbySpec`/`StandbyHandle` path fields→wire String. `VmBackend` trait + `VmStartConfig`/`VerbGrantEnvelope`/`StandbyClaim` (embed those + VerbGrant) + `select_runtime_source_policy` + anyhow cmdline codecs STAY. Byte-identity clean (serde attrs preserved; StandbyClaim keeps PathBuf). Green (wasm + nextest 6596/0 + `check-no-string-backend-dispatch`). Impl yielded on auto-backgrounded nextest → controller ran gate + committed.
    - [x] **Batch L — FINAL DTO move** (`51471dd7`): `plan/execution_plan.rs` (claim-8 signed `ExecutionPlan` + `SCHEMA_VERSION`) + companion `lifecycle.rs` (`SnapshotAt`+`LifecycleMarker`) → `mvm-contract`. **ExecutionPlan byte-identity PERFECT** (46/46 field+attr lines identical; only diff = 2 field-type path qualifications `policy::X`→`policy::x::X`, serde-invisible). Roundtrip test rebuilt inline (core `sample_plan` unreachable). Green (wasm + nextest 6596/0 incl. plan signing/verify/admission). **The entire signed plan now compiles no_std on wasm32.**
  - [x] **Tier 3 COMPLETE.** **ALL Increment-3 DTO extraction DONE** — every `plan/`+`policy/`+`protocol/` wire/policy DTO (leaves + splits + the 2 biggest files + the signed ExecutionPlan) now lives in `#![no_std]+alloc` `mvm-contract`; all logic (signing/verify/synthesis/resolve/fs/net/tar) stays in `mvm-core` on top. 13 batches, every one green + byte-identity verified.
  - [x] **Tier 4 — COMPLETE** (the substantive rewire happened incrementally; each split repointed its own facade + fixed imports, so the workspace was green after every batch — no broken imports remained). Closeout was documentation: the 2 "deferred" items resolved to **permanent `mvm-core` residents**, NOT pending moves — `policy/security_profile` (a `Copy` runtime value, not a serde DTO, + `crypto::seccomp` dep) and `protocol/protocol.rs` `HostdRequest`/`HostdResponse` (host-side mvmd↔hostd IPC embedding `domain::{VolumeAttach,TenantNet}` — which stay in core per architecture — over `hostd-transport` tokio framing; nothing runs in guest/browser). This is the clean line: **mvm-contract = DTOs a no_std/edge/guest/browser consumer needs; host-only IPC + orchestration domain stay in mvm-core.** Design doc `10-…` updated to Status:COMPLETE. (Cosmetic: 1 masked test-only `ToString` import left as-is — adding it risks a redundant-import lint under the std/schema build.)
  - [x] **INCREMENT 3 COMPLETE** — the `mvm-core`→`mvm-contract` DTO inversion (the Phase 1a long pole) is done. Entire signed plan + all wire/policy/plan DTOs compile no_std on wasm32; the wasm-container core-goal (WS11) foundation is real.
  - [ ] **Tier 4** — logic rewire (imports→mvm_contract) + `mod.rs` re-export shims; deferred items (`security_profile`, `protocol.rs` HostdRequest/domain).
- [x] `mvm-storage` placement — folded into `mvm-runtime` as `crate::storage::volume` (nested under the pre-existing `crate::storage` dm-thin CoW pool module — a naming collision the original decision didn't anticipate — to avoid clashing `backend.rs`/`mod.rs` filenames and a second unrelated `StorageError`). The original fold renamed its S3 prototype to `storage-s3`; plan 283 later removed that unregistered member-only provider to restore the fleet ownership boundary while retaining the independent S3 template registry. Linux `tempfile` dep was already an unconditional normal dep of `mvm-runtime`, no change needed; `SnapshotUpper` import in `libkrun.rs` repointed. Crate deleted, workspace member + `[workspace.dependencies]` entries removed. Crate count 15 → 14.
- [x] Full `nextest --workspace` ran — **6598 passed / 0 failed** (`176adc793`) after fixing a class the ident-rewrites missed: **stale crate-name STRING literals** (dir paths, `-p` pkgs, features, allowlist paths) in the builder-VM guest-build/libkrun-supervisor paths. Excl `mvm-runtime` (macOS codesign-SIGKILL) + `mvm-conformance` (cucumber `harness=false` → `just bdd`). Also unblocked **5 xtask claim gates that were failing-open** (paths pointed at renamed `crates/mvm-guest`) + a vacuous `no_backend_dep` cycle guard. Lesson: after crate renames, grep strings, not just idents; `nextest --no-fail-fast` catches runtime-wrong-but-compiling.
- [x] **CI/ADR stale-ref sweep** (`b0a9d2477`): the workflows + `ADR-022` were never updated through the 7 consolidations, so several jobs invoked deleted packages. Remapped every functional `cargo -p <gone>` (`mvm-guest`→`mvm-agentd`, `mvm-ext4`/`mvm-oci`→`mvm-fs`, `mvm-vm-host`→`mvm-hostd`, +3 stray `mvm-build`→`mvm-fs` test invocations) **verified by RUNNING each** (mvm-agentd 560/560, mvm-fs oci 25/25 + hermetic 4/4 + the 3 ext4 examples, mvm-hostd bins build); repointed `ci-full` OCI path-filters + `architecture` globs + `security` fuzz-cache paths; refreshed the `ADR-022` crate table (dropped `mvm-verify`). Both dead-crate-`-p` + stale-path-filter rg sweeps now EMPTY; all 5 YAMLs still parse. Config/doc only. **STILL DEFERRED (cosmetic/frozen/pre-existing, reported):** prose crate-name mentions in ADRs 001/002/009/010/014/016/020/024; the `security.yml` FROZEN fuzz-lane `working-directory: crates/mvm-{guest,oci,vm-host,ext4}` (needs care re pinned locks); two OLDER broken refs `mvm-jailer-lite`/`mvm-host-vm-init` (pre-this-session consolidation); a non-breaking `crates/mvm/src/hostd/**` glob + an `ext4-real-mount` job label. `scripts/*.sh` not yet swept.
- [ ] **Follow-up (WS2↔WS10):** `check-guest-agent-runtime-free` now FAILS — merging the tokio addon bins (`addon-dns`/`vsock-bridge`/`egress-client`) into the single guest binary drags tokio into the guest closure, against the tokio-free/~8 MB goal. Single guest binary requires de-tokio'ing the addons (WS10) or a per-binary check scope.

**WS4 — single `~/.mvm`** (can land alongside 1b)

- [x] Reparent cache/state/share/runtime/config under `~/.mvm`; `MVM_HOME` override; delete the `~/microvm/vms` const; move per-VM UDS under `~/.mvm/run` (#1654). _(**WS4.1 landed `1b62d8212`** + review-fix `31d793bd0`, subagent-driven, spec ✅ + quality Approved: one root resolver pair `mvm_home()`/`mvm_home_strict()` (`MVM_HOME` | `$HOME/.mvm`; lenient keeps the documented `/tmp` fallback, strict errors — security-sensitive callers verified on strict), children `cache/ config/ run/ state/ share/ vms/`, data at root; SIX per-dir env vars + ALL XDG consultation DELETED with no fallback reads (138 files, +831/−1044; ~220 test refs swept via `TestEnv`); `VMS_DIR` tilde const deleted, `vms_dir()`/`vm_state_dir()` absolute; doctor/cache/prune + Justfile/dev-env/CI YAML on `MVM_HOME`; no migration (first-version). 7517/7517 (−5 = obsolete XDG-order tests consolidated). Review caught the root-`tests/` boot-bench hand-built FC path (outside the grep scope) → fixed by deriving both bench arms from `vm_state_dir`. Grep survivors, both justified: in-guest XDG exports in the builder-VM runtime (guest env, not host resolution) + 2 stale comments in untouched `mvm-contract` (→ WS4.2).)_
- [x] Route the remaining bypass sites through `mvm-core::config`; add the anti-bypass CI lint. _(**WS4.2 landed `2b85a8ff6` + `cc16c511d`**, subagent-driven, spec ✅ + quality Approved with NO findings: the new `xtask check-single-home` lint (4 rule classes — literal home-relative mvm paths, deleted env vars + XDG reads, raw `HOME` reads, re-rolled `mvm_home+"vms"` joins; 12 self-tests; CI Lint step) baselined at **117 hits → all FIXED, not allowlisted** (49 files; only 7 narrow rule-scoped allowlist entries incl. the resolver itself). The sweep surfaced real bypass BUGS beyond the review's 10: observer allowlist, tenant policy root, metrics scrape, attestation key dir, tenant config.toml all read raw `$HOME` and ignored `MVM_HOME` — now resolver-routed with per-site fail-closed posture REVIEW-VERIFIED preserved (strict-guard table in the review), and one prior gap closed: the volume-mount `denied_host_roots` used to be EMPTY when `$HOME` was unset, now unconditionally denies keys/audit roots. secret_store's cwd last-resort fallback renamed `./.mvm/secrets`→`./.mvm-secrets` (stops mimicking the home layout). Dead in-VM `echo` tilde-expansion round-trip in `microvm.rs::resolve_vm_dir` deleted (5 callers inlined). 7529/7529 (+12 lint self-tests), all gates green.)_
- [x] Gate: fresh run creates exactly one root; lint green. _(check-single-home clean on the tree; reviewer re-ran it independently.)_

**WS4 is COMPLETE.**

**WS5 — two features** _(root collapse DONE earlier; member-feature audit done — remaining items are maintainer-ratification calls, not mechanical work)_

- [x] Root surfaces collapsed to exactly `host`/`user` (+ `dev` union + a 7-entry internal allowlist); `check-two-surfaces` enforces it. The per-crate member features are the composition units the surfaces aggregate — correct Cargo layering, NOT sprawl to delete.
- [x] **mcp composed into `user`** (`e77c90230`): the implemented+tested MCP server was gated by no surface → shipped in no build; folded into `user` (zero extra deps). Builds clean; two-surfaces stays green.
- [~] **Member-feature decision matrix (audited; the below need a maintainer call, so NOT executed blindly):**
  - `manifest-verify` "always-on" is **REJECTED** — it pulls the sigstore stack (tokio) into mvm-core's default closure and would break the shipped `check-core-runtime-free` gate + the runtime-free invariant. It stays opt-in (the SPRINT "always-on" wording was over-simplified). `builder-vm`/`pure-mkfs` stay member composition units (a VM-driving consumer must be able to skip the builder pipeline); not made unconditional.
  - `attestation-tpm2`/`attestation-sev-snp`/`attestation-tdx` are **stub providers** (return `NotYetImplemented`) gating hardware-backed key attestation, which ADR-002 lists **out of scope**. Candidate for YAGNI deletion (3 features + `HwProviderKind` arms + stub impls) — but that removes documented future scaffolding, so it's a maintainer ratification call, flagged not executed.
  - `wasm-backend` remains a legitimate heavy-dependency member opt-in. The prior `storage-s3` conclusion is superseded by plan 283: the provider had no production registrant, bypassed both shipped surfaces, and crossed the accepted fleet storage boundary, so it was removed and `check-two-surfaces` now guards that boundary.
  - `schema` is already codegen/tooling-only (in no product surface); "move to build-time" is satisfied in spirit — the schemars derives can't be build-time-only without the feature enabling the derive, so the feature stays as the codegen knob.
- Gate: `xtask check-two-surfaces` green (2 surfaces, 7 internal). **WS5 substantially COMPLETE**; only the attestation-stub deletion awaits ratification.

**WS6 — trait dispatch + zero hardcoding**

- [x] Replace `backend.name() == "…"` sites with `BackendKind` matches; delete the dead retired-backend arms. `VmBackend::kind()` is now a required trait method (every backend implements it); `xtask check-no-string-backend-dispatch` guards the regression.
- [x] Remove baked network literals (`172.16.x`, `127.0.0.1:1080`, `/tmp/firecracker.socket`); inject via config; name `DEFAULT_MEM_MIB`/`DEFAULT_CPUS`; add a CI lint for hardcoded IPs/ports. _(**WS6.2 landed `3d098ecb0` (sweep) + `30a531141` (lint)**, subagent-driven, spec ✅ + quality Approved, value-preservation reviewer-verified byte-for-byte per const: dev subnet `172.16.x` → `mvm_core::dev_network` consts (`DEFAULT_SUBNET_CIDR`/`DEFAULT_GATEWAY_IP`/`DEFAULT_GUEST_IP`/`DEFAULT_GATEWAY_CIDR` + `default_guest_ip_for_index`); `127.0.0.1:1080` → `mvm_core::guest_netd::DEFAULT_EGRESS_PROXY_LISTEN`/`_URL` (5 sites); `DEFAULT_MEM_MIB=2048`/`DEFAULT_CPUS=2` named at the image-manifest defaults (other differently-valued mem/cpu defaults deliberately left); the `API_SOCKET="/tmp/firecracker.socket"` process-global DELETED → per-VM `firecracker_api_socket_path(dir)="{dir}/fc.socket"` (start/stop resolve the same socket; matches the per-VM start path + `FirecrackerGuard` cleanup that already expected it). New `xtask check-no-network-literals` (3 rule classes: subnet/egress-port/fixed-tmp-socket; skips test code incl. whole-file `#![cfg(test)]`; per-instance `{…}` sockets allowed; narrow rule-scoped exemptions for the 2 definition sites + 1 dev smoke example; CI-wired). Controller-takeover (implementer wedged): I ran all gates + FIXED 2 real lint bugs — a whole-file `#![cfg(test)]` skip gap and a line-continuation newline-counting desync that under-counted hit line numbers (both now regression-tested). 7543/7543 nextest, workspace clippy, fmt, wasm32 all green. Zero mvm-contract diff.)_
- Gate: hardcoding lint green; no string-typed backend dispatch remains. **WS6 COMPLETE.**

### Phase 2 — Binaries, egress invariant, lifecycle

**WS2 — single host + single guest binary, no forks**

- [ ] `mvm-agentd`: merge `mvm-guest` + `mvm-guest-helpers` + `mvm-host-services-ffi` **and the builder-VM guest bins** (`mvm-host-vm-init`/`mvm-builderd`/`stage0-init`/`mvm-rootfs-patcher` → a "builder" role); one binary, subcommand/argv0 dispatch; ship via the runtime-overlay volume.
- [ ] `mvm-hostd`: fold `mvm-vm-host` + host-side builder bins; single-process resident daemon; roles as tasks; state in append-only signed `jsonl` (§2.2).
- [ ] Remove every `Command` shell-out (host/runtime/agent); native Rust replacements; the two carved exemptions (FC launch, builder-VM nix) allow-listed.
- [ ] Secrets module: `mlock` + `zeroize` + `subtle`; daemon-wide seccomp + landlock.
- [ ] CI lints: "exactly two shipped binaries + CLI", "no `Command` outside the allow-list".
- Gate: `ls` of the build outputs shows 1 host + 1 guest + `mvmctl`; lints green; secrets/seccomp tests pass.

**WS-NET — consolidated vsock networking + standardized protocol** (absorbs the old WS3; see §2.9) — the core auditability seam
First vertical slice (build in this order):

- [ ] `mvm-contract`: versioned frame codec (encode + incremental decoder) + handshake types; fuzz target for the decoder (never panic / OOM / OOB).
- [ ] `VmDuplexTransport` trait + an in-memory / process-UDS test backend (so CI needs no VMM).
- [x] Guest loopback/egress-client path and host `RealEndpointSpawner` enforce the admitted policy.
- [x] Supervisor L4 gate owns raw host/port forwarding and structured allow/deny audit.
- [x] SOCKS5 UDP Associate uses the same NIC-less vsock seam with shared UDP policy gating.
- [x] User-space egress evaluation, transparent rootless QEMU prototype, local TCP/UDP path benchmark, and non-root networking documentation are complete.

Then unify + retire the old paths:

- [x] Route Firecracker, HVF, and libkrun workload execution through the uniform vsock runner; fail-closed where the host cannot mediate.
- [x] Typed connectors use the broker/substitution seam with user-defined **`${NAME}`** named placeholders; host-side L7 inspection and data-governance witnesses cover all workload backends.
- [x] Delete the dead userspace network-gateway subsystem; collapse `NetworkingPreference`; drop `MVM_NETWORKING`/`MVM_GATEWAY_BIN`. Landed as plan 305, with `xtask check-no-gateway-names` keeping the names out. Enforce the mount no-shadow rule (`/mvm` in deny prefixes).
- [ ] Snapshot/restore/warm-start: fresh boot_id + nonce + handshake; stale flows closed; no live-vsock-survives-restore assumption.
- [x] Networking decision records why vsock is mandatory, why Model A was removed, and how typed connectors remain separate from raw admitted egress.
- Gate: protocol unit + fuzz green; process-level integration proves allow-passes / deny-drops / **stale-session-rejected**; `check_vsock_only_egress` passes on all workload backends; `machine run --image busybox --allow-host google.com` resolves DNS + connects (fixes `ping: bad address`); live smoke Mac (HVF) + Linux (libkrun + FC); no NIC bypass.

**WS9 — lifecycle correctness**

- [x] Confirm transient teardown (entrypoint exit + no healthcheck → VM stops) — already centralized; add tests. _Fixed: emit_launched_if no longer re-persists plan.json for transient runs, so teardown actually removes the VM state directory. Hermetic BDD 27/27; live BDD on Hetzner 36/37 (only Nix-flake network timeout remains, environment issue)._
- [ ] **Capture workload stdout/stderr + exit code over vsock** (reuse the `BuilderStatus`/`BuilderOutcome` pattern the builder VM already uses) so all workload output crosses the auditable seam and the transient exit code is sourced from it.
- [ ] Implement the missing **host-side healthcheck reaper** for persistent machines (probe the stored `health_check`; restart/mark-unhealthy on failure). Today it's persisted but never executed.
- Gate: transient exits propagate the vsock-sourced exit code + tear down; workload stdout/stderr captured over vsock; a persistent machine with a healthcheck is actively probed.

### Phase 3 — Quality: size, dead code, CLI, kernel/memory

**WS8 — file/function size + dead-code removal**

- [ ] Extract inline `#[cfg(test)]` modules from the 39 oversized files (cheap; drops many under 1500).
- [ ] Module-decompose the genuinely large bodies: `libkrun_builder`, `microvm`, `mvm-guest-agent`, `host-vm-init`, `doctor`, `unpack`, `image`, `vsock`.
- [ ] Split giant functions: `handle_client` (734 → per-verb handlers via a verb-handler trait), `run_inner`, `configure_flake_microvm_*`, `build_supervisor_config`, `unpack_layer` (per entry-type). Builders for multi-field config structs.
- [~] Delete dead/stub code: removed `crates/mvm-runtime/src/vm/egress_proxy.rs` (dead L7 stub), the `MVM_HVF_DUMP_DTB` debug gate, and the `HttpRegistry` SDK stub. **`storage/{pool,thin}.rs` dm-thin substrate is NOT dead** — it backs the live `mvmctl storage info`/`gc` verbs (`ThinPoolImpl`/`DeviceMapperBackend`), so it was kept. Still pending: gate `mock` backends behind `test-support`.
- [ ] Security fix: broker config currently parsed **unsigned** — verify signature before parse.
- [x] **Remove ssh-agent forwarding entirely — no SSH anywhere (core promise; ADR-001).** The tree carried a dev-tier ssh-agent-forwarding feature (host `$SSH_AUTH_SOCK` → vsock port 5301 → guest `/run/mvm/ssh-agent.sock`) that contradicted the "no SSH in microVMs, ever" promise and handed the guest the host's whole ssh-agent (bypassing bound-destination secret substitution). Deleted the whole surface: the `ssh_agent` spec field, manifest `[auth] ssh_agent`, `AuthMode::SshAgentSocket` + `AuthPolicy` (dropped the enum/struct entirely — `None` was the only variant left), the proxy (`mvm-cli::commands::ssh_agent_proxy`, `SSH_AGENT_PORT`, `run_ssh_agent_proxy_*`), the guest `SSH_AUTH_SOCK`/`/run/mvm/ssh-agent.sock` injection, tests, and CLI docs. **Strengthened ADR-001 to absolute** — deleted the "SSH-agent forwarding, when offered…" carve-out. Added `scripts/check-no-ssh.sh` (CI: `no-ssh-forwarding` in `security.yml`, beside `prod-agent-no-console`). The one dev interactive surface stays the builder-VM shell — nothing SSH.
- [x] **Eradicate the remaining SSH surface — no SSH in any guest, on any backend (ADR-001 follow-up).** A security audit found a full in-guest SSH server was still pervasive despite the ssh-agent-forwarding removal above: `image.rs`'s legacy Ubuntu-squashfs builder installed `openssh-server`, set `PermitRootLogin yes`/`PubkeyAuthentication yes`, generated an `*.id_rsa` keypair, and ordered workload units `After=… ssh.service`; `MvmState` (`base/config.rs`) carried a required `ssh_key` field that `microvm.rs`/`firecracker.rs` discovered/persisted as a boot-gate asset; the `refresh_builder_rootfs`/`download_builder_artifacts` builder-VM templates carried a dormant `inject_ssh` code path (always `"no"` in production, but live capability); five fully dead `*.tera` scripts (`builder_keygen`, `sync_local_flake`, `extract_artifacts_ssh`, `launch_firecracker_ssh`, `run_nix_build_ssh`) shelled real `ssh-keygen`/`scp`/`ssh`; the orchestrator accepted a legacy `"ssh"` alias for `BuilderMode::Vsock`; and a dead `tenant_ssh_key_path` helper lived in `mvm-core`. All removed — comms stays vsock-only on every backend (libkrun/HVF/Firecracker/qemu/mock), all confirmed SSH-token-free by source scan. Broadened `scripts/check-no-ssh.sh` from the ssh-agent-only pattern to every SSH-capability token (`sshd`/`openssh`/`ssh-keygen`/`authorized_keys`/`id_rsa`/`PermitRootLogin`/`sshd_config`/…), with an explicit, commented `ALLOWED_FILES` list for the pre-existing SSH _deny/detect_ code (`command_gate.rs`, `threat_classifier.rs`, the inbound SSH-banner network deny-scan, mkGuest's own build-time SSH-token ban) and no-SSH-assertion docs — verified the broadened gate fails on a planted `openssh-server`/`id_rsa` probe and passes clean on the real tree. Strengthened `no_backend_advertises_production_ssh` (`backend.rs`) to cover all 5 production `AnyBackend` variants.
- Gate: **0 non-test files > 1500 lines**; no `todo!`/`unimplemented!` on a production path; dead modules gone.

**WS7 — simple CLI**

- [x] Enforce one physical line per help item, strictly shorter than 80 columns,
      across every visible and hidden command's `--help`, `-h`, and
      `mvmctl help <path>` output. The shared renderer compacts long-help item
      blocks and caps overlong summaries at 79 columns with an ellipsis. The BDD
      suite discovers paths from the generated Clap tree, executes the real
      binary, and rejects both continuation lines and lines at or above 80
      columns, so new subcommands are covered automatically. Focused renderer
      tests, both exhaustive BDD scenarios, the serial full workspace suite,
      workspace check, formatting, and host workspace all-target Clippy pass.
- [ ] Redesign to a small, discoverable verb set; `env` shown in `--help`.
- [ ] Merge `setup`/`bootstrap` into one first-run `bootstrap`. Add the lifecycle verbs: **`upgrade`** (self-update `mvmctl`); **`uninstall`** (remove everything — the binary, `~/.mvm`, and installed host/guest artifacts); **`env cleanup`** (reclaim `~/.mvm` — caches + transient VM/build state, keeping config + keys); **`env reset`** (wipe `~/.mvm` back to a clean slate). These replace the fragmented `cache prune` / `pack prune` / `storage gc`. `env` becomes a visible top-level subcommand (today `hide = true`).
- [ ] Replace the 31-arm dispatch `match` with a `Command` trait (`fn run(&self, ctx: &Cli) -> Result<()>`); one module per command; every command calls `mvm-client`.
- [x] ~~`mvmctl serve` exposes the agent-facing server behind an `AgentProtocol` trait~~ — descoped. The MCP server was removed outright; no agent-protocol server surface remains.
- [ ] Remove hidden/duplicate/dead verbs.
- [ ] Slim the **Justfile** — collapse the recipe sprawl to a small set (`build`, `test`, `lint`, `ci`, `bdd`, `run`, `clean`).
- Gate: `mvmctl --help` lists the real surface; `tests/cli.rs` covers it; no command reaches past `mvm-client`; `just --list` is short.

**WS10 — tiny kernel + low memory + density**

- [x] **Fast machine substrate contract — issue #2279.** The kernel is now
  explicitly treated as one part of a prepared machine substrate spanning the
  kernel, initramfs, verified rootfs artifacts, runtime overlay, VMM shape,
  guest lifecycle, warmup, and pool identity. The ownership and measurement
  boundaries are documented in
  `specs/notes/2026-08-10-fast-machine-substrate.md`; issues #2280 and #2281
  own the kernel budget and filesystem-path experiments.
- [~] **Kernel boot-substrate ledger — issue #2280.** `cargo xtask perf
  footprint` now includes initramfs bytes and optionally enforces the resolved
  per-architecture built-in-symbol budget; cold-launch JSON reports carry the
  same artifact byte and kernel-config measurements beside their timings. The
  libkrun live probe now has bounded resident host-process capture after
  authenticated readiness, and the HVF guest-RAM seam now reports resident
  bytes with a direct untouched-versus-touched demand-fault witness plus
  monotonic private restore-mapping duration. The libkrun density report now
  also carries guest-agent RSS from the existing ResourceUsage RPC. The
  backend-neutral warm launch sample now records the whole VMM host process at
  authenticated readiness and after the first command: Linux reports RSS from
  `/proc/<pid>/statm` and
  minor/major fault deltas, while macOS reports physical footprint with fault
  counters explicitly unavailable. Warm-lane validation refuses missing
  evidence. The real-host Firecracker/HVF matrix, canonical budget table, and
  resulting native-host gates remain open. The report-level gate now requires
  20 measured samples after two warm-ups, revalidates every raw sample, applies
  the 200/250/300 ms prepared-cold percentile diagnostics and the independent
  30/50 ms warm target, and aggregates whole-VMM resident-memory/fault evidence
  without zero-filling unavailable counters. `mvmctl bench` now makes the
  release requirement explicit: every prepared dispatch must be `<200 ms`, a
  200.0 ms sample fails even below the publication floor, JSON schema v6 carries
  the maximum/verdict/remark, and the default output is an accessible timing
  table with PASS/FAIL words and phase remarks.
- [x] **Filesystem-path baseline — issue #2281.**
  `mvm_fs::rootfs::measure_ext4_pure` now records a stable JSON baseline for
  source identity, node composition, emitted ext4 size/digest, materializer
  version, and hash/walk/build timings; `cargo xtask perf filesystem --root
  <DIR> --json` exposes it to the benchmark workflow. Cold-launch evidence
  records the tier-selected `virtiofs_root` or `block_ext4` strategy, while
  the benchmark rejects missing or mixed strategies; candidate guest-local
  immutable paths still need equivalent first-access, working-set, density,
  and security evidence before an adopt/decline decision.

- [x] Kernel: minimal defconfig; stop boot-probing IPVS/btrfs/RAID-autodetect (#1283); bump the kernel pin (#1264). **Landed via #1786.**
- [x] Guest agent ≤ **8 MiB**: the static-musl Dev-profile agent measured
  1,372,160 bytes peak observed RSS (1,359,872 bytes steady idle). The
  capability-negotiated `ResourceUsage` RPC uses the existing `/proc` sampler,
  and `xtask perf footprint --guest-rss-bytes` enforces and reports the limit.
- [x] Complete sealed guest ≤ **50 MB**: the Nix-built rootfs, static runtime
  overlay, both dm-verity sidecars, and workload kernel total 33,917,960 bytes.
- [ ] Host daemon ≈ **64 MB**: minimal runtime, evaluate `mimalloc`, strip deps.
- [ ] **Density levers:** right-size the default `--memory` (64–96 MB, not 512); **demand-fault guest RAM** (MAP_ANON demand-zero instead of eager-dirty — the architectural fix for high VM density); share one **read-only kernel mmap** across VMs.
- [ ] Release profile: `lto = "thin"`, `codegen-units = 1`, `strip = true`, `panic = "abort"` for bins.
- [ ] Dep cut: dedupe ext4 (writer+reader), TLS (`reqwest`/`rustls`/`rcgen`), compression (`flate2`/`lzma-rs`/`tar`), net (`etherparse`/`rtnetlink`/`mio`), syscall (`nix`/`rustix`/`libc`); **reimplement trivially-used deps** where it removes an attack surface for little code.
- [ ] **Nix build speed:** local parallel/incremental build (nix-fast-build-style), no external cache providers (hermetic). **Narrowed (2026-07-31):** the initramfs left the Nix path entirely — it is now a deterministic cargo artifact (`build_initramfs_with_cargo`), so a cold cache costs one `cargo zigbuild` cross-compile, not a Nix evaluation. This item now covers only kernels, rootfs images, and overlays.
- Gate: guest RSS ≤ ~8 MB, host RSS ≤ ~64 MB idle; an idle guest configured at 512 MB resident-costs ~its working set (demand-fault proven); lockfile materially smaller.

**WS-DX — developer experience & performance** (the story #1637 promises)

- [ ] **Sub-second launch**, verified: a timed `mvmctl up` → PTY shell → `mvmctl down` e2e on Mac (HVF) and Linux (libkrun + FC), asserting sub-second boot + clean teardown.
- [~] **Warm start / warm pool** (pre-warmed standby VMs), **snapshot / fork / restore** (bake once, fork many via CoW, fast restore), **streaming exec**, **`expose_tcp`** (host↔guest port forward), **live host-directory mount** — the fast-local-runtime capabilities, exposed through `mvm-client` + the SDK.
      The transient `machine run --mount HOST:/GUEST:ro` path now uses a live
      read-only virtio-fs share on HVF instead of materializing an ext4 image;
      warm-start remains separately gated on a backend standby-pool capability.
      Phase timing now labels every launch `launch_mode=cold|warm` and reports
      `pool_wait_ms`, `claim_ms`, `warm_window_ms`, and `warm_slo=ok|over|na`;
      directory-share claims remain fail-closed until a
      backend can late-bind the host path after warm-child materialization.
      Plan 298 now breaks the implementation into eight owned issues: #2192
      defines the resident claim service and now has the typed warm/cold
      contract, service-owned lease registry, lease-origin reporting, and
      lease-safe cleanup; #2193 now has the content-addressed immutable
      artifact store, atomic publication, durable prewarm job states, restart
      recovery, worker-side support-artifact staging with compatibility-key
      digest checks, a resident worker adapter with retryable source failures,
      and validated host-path-free source descriptors persisted with jobs, plus
      a mandatory readiness-verifier publication gate and concrete
      OCI/template source resolver with worker factory wired into the resident
      service and a shared authenticated golden-VM verifier; backend-specific
      golden-VM factories remain before that issue closes; #2194 now has the
      process-local resident-parent reservation/quarantine substrate and
      signal-backed HVF pause/resume, while actual Apple Silicon memory,
      device-state, and vCPU-state restore/fork capability remains gated on a
      live backend primitive. The first state slice now provides a bounded
      snapshot-frame writer, exact-size guest-RAM copy/restore, and a fixed
      AArch64 HVF core-register codec with capture/restore adapters; device
      serialization now has a bounded versioned container plus deterministic
      PL011, virtio-blk, virtio-fs, and virtio-rng control-state codecs. Console
      transcripts, entropy bytes, backing handles, and active vsock sessions
      are rejected or omitted. The vsock codec now preserves only idle
      transport control state and fails closed on bound host endpoints,
      host-I/O descriptors, receive-credit sessions, pending packets,
      lifecycle transcripts, and exited workloads; live SLO validation
      remains open. The strict HVF bundle seam now combines RAM, AArch64 vCPU,
      device, and artifact sections and validates backend identity, required
      sections, duplicates, and exact RAM shape before restore; host-channel
      rebind and live capability admission remain open. HVF pause/resume now
      has a supervisor acknowledgement marker: pause returns only after the
      vCPU enters the hold, and resume returns only after the marker clears;
      child restore primitives now include exact-size private COW RAM remapping
      and explicit caller-authorized vsock host-channel rebinding. The HVF
      driver now wires fixed state-directory parent capture, private-RAM child
      restore, vCPU/device restoration, channel rebinding before execution,
      and the existing authenticated child-identity handshake. The prior real
      Apple Silicon restore failed because a fresh child supervisor created a
      new in-kernel GIC while the frame carried no distributor/redistributor
      state. The chosen fix keeps the paused parent as the HVF owner: a signed
      handoff request authorizes the child identity and channel mask, the
      listener retargets only claim-derived endpoints, and the parent resumes
      as the child. Focused protocol, path-safety, and channel-rebind tests
      pass. Real Darwin arm64 validation now proves the rootless signed
      resident handoff with the Hypervisor.framework entitlement. The fresh
      release-built Darwin arm64 matrix completed 1,000/1,000 warm claims
      below the strict 300ms ceiling, measuring p50=17.9ms, p95=22.1ms,
      p99=27.4ms, and max=33.3ms. The optimized path now omits the
      secret-free deny-all endpoint and defers broad orphan-state cleanup until
      after the guest command; consumed resident-parent payloads are reclaimed
      asynchronously after the measured handoff, keeping long-run state
      bounded. The earlier Linux x86_64 Firecracker/KVM 30/30 matrix measured
      only raw restore reachability. The source-matched authenticated witness
      completed 15/15 claims, with normal claims at 63–76ms but restore-start
      outliers at 513ms and 620ms; the identity RPC itself stayed at 24–35ms.
      The Firecracker path now pre-loads paused child VMMs during pool refill so
      restore/process-start variance is outside the measured launch window. The
      initially supplied baked guest image was stale and rejected clock
      resynchronization with `settimeofday: EPERM`; rebuilding the current
      `mvm-oci-init` and `mvm-guest-agent` into an isolated image copy fixed
      that contract. The source-matched authenticated FC witness now passes
      with claim=24ms, preload=41ms, resume=0ms, and identity=23ms; its
      11,356ms process bootstrap is outside the claim window. The full Linux
      claim matrix, Linux libkrun, and remaining backend/share-shape matrices
      remain open. The prior macOS host-vsock
      test hang was a parallel-test race caused by process-wide `MVM_HOME`
      mutation; UDS-channel tests now use explicit isolated roots, and the
      complete `mvm-hostd` package suite passes.
      A host-only Apple Silicon acceptance harness is now
      available as `just hvf-warm-restore`; it records the cold bootstrap
      separately and refuses any measured cold fallback or warm-SLO violation;
      the runtime now has an explicit trusted-snapshot backend contract for
      optional immutable background publication. Unsupported hosts perform no
      snapshot-service mutation and saved-state restores remain on the full
      verification path. The resident HVF claim path now uses a host-signed,
      user-owned bundle manifest as its O(1) publication witness, skips the
      growing audit-chain reload on that hot path, creates only the fresh child
      state directory, and hands the paused parent supervisor directly to the
      child identity; it never points the child at mutable checkpoint bytes.
      Saved-state claims retain full lineage verification. The root-only APFS
      helper remains optional for background publication and is not required by
      the rootless hot path. The 1,000-claim Darwin matrix passes the aggregate
      targets. On the FC host, the source-matched Linux build passes the runtime
      and guest-agent unit suites plus full workspace all-target clippy. The
      authenticated Firecracker witness now passes after rebuilding the current
      `mvm-oci-init` and `mvm-guest-agent` into an isolated image copy: claim is
      24ms, preload 41ms, resume 0ms, and identity 23ms. Production Linux
      standby admission, the full Linux claim matrix, and the remaining backend
      matrices remain open.
      After the latest `main` sync, including the backend crate/VMM-driver
      refactor, the exact merged source also passes 207 `mvm-vmm` unit tests,
      1,167 `mvm-runtime` unit tests (six ignored), macOS workspace all-target
      Clippy, and Linux workspace all-target Clippy. A fresh FC-host witness
      on that exact source reports spawn/bootstrap=11,154ms outside the SLO,
      claim=22ms, preload=42ms, resume=0ms, and authenticated identity=22ms;
      the measured warm claim is therefore below the strict 300ms requirement.
      #2195 adds fixed virtio-fs share slots; #2196 completes Linux
      Firecracker warm claims; #2197 hardens the VMM/share processes; #2198
      finalizes warm-required CLI semantics and timing; and #2199 adds the
      1,000-claim benchmark and CI gates. The execution plan is
      `specs/plans/298-warm-claim-service-and-hvf-pool.md`.
      The launch contract is now explicit in
      `specs/plans/297-sub-300ms-warm-launch-slo.md`: a warm claim must be
      strictly below 300ms from admission to authenticated guest readiness;
      cold boot and command/teardown time remain separately measured, with
      warm p50 ≤30ms and p99 ≤50ms as aggregate targets.
- [ ] `specs/plans/255-vsock-first-snapshot-egress-adoption.md` details the
      vsock-first snapshot/egress/warm-start adoption boundary (tracking issue:
      #1851). Phase 0 (spec) + Phase 1 (snapshot storage) merged to main (#1853);
      Phase 2 slice one — the runner-side warm-pool claim substrate
      (`specs/plans/255-phase2-warm-pool-substrate.md`) — landed on branch
      `feat/plan-255-phase2-warm-pool`, with the live FC warm pool + capability
      flip a follow-up slice. That follow-up
      (`specs/plans/255-live-fc-warm-claim.md`) built spawn/capture/fork/reseed
      and then **failed its live KVM validation**
      (`specs/notes/2026-07-28-plan-255-live-fc-warm-claim-validation.md`): the
      standby parent booted a bare rootfs and panicked for want of the runtime
      overlay that carries the guest agent. The parent's boot inputs now come
      from the launch's own `VmStartConfig` through the same mappers a workload
      boot uses, guarded by shape-equality tests, and a later live run on the
      same host confirms that half — the parent boots, reaches its guest agent,
      and the capture writes a `vm_full` checkpoint carrying a 512 MiB
      `memory.bin`, then releases the parent.
      Since then the recorded reductions have closed: a claimed child is wired
      the host channels a cold boot gets (#1917); an egress-allowing launch is
      **keyed** into the pool rather than excluded from it —
      `StandbyCompat::vsock_egress` (the launch's *effective* enablement: the
      policy allows egress **and** the admitted plan binds no secret) partitions
      the warm set, the parent boots that boolean and no destination, and the
      allow-list stays host-side on the claimed child's own egress endpoint; and
      the CLI no longer reserves a parent the runner is about to reserve (#1922),
      which had made every warm claim refuse with "parent is not in a claimable
      state" so the pool filled and never drained.
      The post-restore authority gap is also closed in code: after the final
      child identity is materialized, the host mints and validates the exact
      admitted `VerbGrant`, persists it only for that child, and delivers it
      with the generation token over PostRestore. The factory parent retains
      the boot-pinned host identity but receives no workload grant. A real
      host-key signature is verified in the hermetic warm-claim BDD, and a
      missing issuer or mismatched envelope refuses before fork with no orphan.
      `standby_pool` stays **`false`**: the **claim** half has still never
      completed live. Real Apple Silicon validation reached parent capture,
      child materialization, child channel binding, and child resume, then
      failed closed at the authenticated post-restore handshake: the guest
      produced no console progress because a fresh child process creates a new
      HVF GIC while the saved frame contains no distributor/redistributor state.
      The flip is gated on preserving the paused parent VM or proving a complete
      supported GIC state transfer, followed by timer, virtio-filesystem, and
      fresh-vsock continuity witnesses.
  - [x] Ordinary persistent-machine Firecracker teardown now fails closed
        (#2007): non-interactive or declined confirmation exits non-zero, state
        is retained unless process exit is verified, and a restart cannot
        overwrite the PID marker of a still-live process. Reconcile-on-entry
        also recognizes `fc.pid`, so it cannot delete a live Firecracker's
        state before the stop path attaches. The 2026-07-31 KVM recheck passed:
        refusal retained PID 4124113 and the exact process, then `--yes`
        removed the marker and process. Eleven regressions cover confirmation,
        marker ownership, exact-PID teardown, cleanup ordering, and
        reconciliation. The analogous warm-pool claim-refusal cleanup remains
        a separate open gate.
      Factory parents now receive an authority-free admitted plan and a signed
      `checkpoint.created` anchor before entering the pool (#1962). Live KVM
      validation proves a production-replenished parent is anchored and the
      next claim passes the former `ParentUnaudited` gate, restores a child, and
      reaches post-restore signaling. It then fails closed because the child's
      identity/grant re-pin does not complete; that handshake remains the hard
      blocker, with egress/broker/exit channel parity still behind it.
- [ ] A clean **external API** (`Image` / `Vm` / `Pool` / `ExecBuilder`-style) on `mvm-client`, so library and CLI share one surface.
- [ ] **Simple, fast install:** a one-line installer + `mvmctl upgrade`.
- Gate: the timed e2e proves sub-second launch on both hosts; warm-start + snapshot restore measured; the external API is documented and BDD-covered.

**WS-DX-COLD — prepared cold-launch performance**

- [x] **Trustworthy baseline (Plan 299 Phase 0) — COMPLETE.** A transient run
  writes a machine-readable launch sample; the backend records its own phases
  into a state-dir sidecar so a caller can see inside `VmBackend::start`; the
  benchmark invokes a built `mvmctl` directly, refuses a debug build, a
  contaminated lane, and a degraded launch, and reports raw samples with
  p50/p95/p99. Both native baselines measured (20 runs + 2 warm-ups, release):
  **HVF/aarch64 prepared cold 112.6 ms p50 / 116.6 ms p99** (warm claim 18.9 /
  20.0 ms) — inside budget; **Firecracker/x86_64 674.0 / 888.6 ms** — 3x over.
  The gap is the VMM boot itself (`driver_boot` 53.8 ms vs 623.6 ms on the same
  code path), so Phase 3 is now a Firecracker-path phase with HVF's number as
  its target. Foreground teardown is the other dominant cost (1086 ms of a
  1216 ms warm launch, from inline pool replenish), promoting Phase 6 ahead of
  Phase 3. **Phase 6 first change landed:** teardown no longer refills the warm
  pool, cutting a default `machine run` from 1366 ms to 353.8 ms p50 (3.9x) and
  leaving teardown as this VM's own cleanup only. **Phase 5 first change
  landed:** the readiness poll's flat 50 ms tick was a floor under every
  reported wait — adaptive backoff cut HVF dispatch from 117.2 ms to 81.4 ms
  p50, 2.5x inside the ≤200 ms budget. Two defects found and fixed on
  the way: a failed host-services
  registration slept 700 ms and lost `host.audit.v1` silently. Gates green:
  workspace Clippy, 10,648 nextest, doctests, hermetic BDD 153/153, Lint xtask
  gates, Linux cross-compile.
- [x] **Lifecycle-density benchmark harness (Plan 299).** Added an opt-in
  integration test that runs 1,000 prepared microVM start/stop operations,
  defaults to HVF, reports start and stop p50/p95/p99/max plus wall-clock
  throughput, and supports bounded batches across Firecracker, HVF, libkrun,
  QEMU, and Apple Container. It remains VM-free unless explicitly enabled with
  `MVM_LIFECYCLE_BENCH=1`.
- [x] **HVF stop-path diagnosis (Plan 299).** Added phase timing to the
  lifecycle harness. A 1,000-cycle run attributes 67.62 ms p50 / 74.97 ms p95
  / 77.01 ms p99 to supervisor PID disappearance after SIGTERM; attach,
  endpoint reaping, console cleanup, state-marker removal, and force-kill
  escalation do not account for the stop latency.
- [x] **Launch resolution without a launch (Plan 299 Phase 2, #2333).**
  `mvmctl pool warm` could spawn nothing on any backend: it passed no launch
  config, so the spawn built an image-less compat key and refused itself, and
  nothing could produce a launch shape without running a launch. The four things
  a claimable parent needs — rootfs plus verity sidecars, runtime overlay plus
  universal initramfs, cmdline tokens, and admission — existed only inline in
  the run path. They now compose into `crate::exec::resolve_launch`, which
  returns a bootable `VmStartConfig` without booting; `run_inner` calls it, and
  `pool warm --image/--cpus/--memory` resolves its parents' shape through the
  same function, so the recorded compat key is the one a claim searches for. The
  accepted-and-ignored `--rootfs` flag is removed. This is the resolution half
  of Phase 2 only — the prepared-artifact manifest is still open.
- [x] **Prepared cold launch:** with a local, verified kernel/initramfs/artifact
  set and a new guest identity, reach authenticated guest readiness and run
  `/bin/true` in strictly under 200 ms on every measured boot on Apple Silicon
  HVF and Linux Firecracker/KVM. This is a hard per-sample prepared-cold
  requirement, not a percentile, warm-pool, or snapshot-restore claim.
  - 2026-08-19 local HVF evidence: release schema-v6 run against cached Alpine,
    20 measured launches after 2 warm-ups, p50/p95/p99 76.9/86.0/99.3 ms,
    maximum 102.7 ms, zero degraded or hidden-work samples. The HVF no-mount
    half passes.
  - 2026-08-19 established Linux/KVM-host evidence: the baseline Firecracker
    run was clean but failed at 293.6/299.7/302.2 ms p50/p95/p99 and 302.8 ms
    maximum. After removing nested readiness retry, overlapping console setup,
    quieting successful pre-readiness serial output, providing unthrottled
    entropy, and removing redundant root privilege/socket work, the same
    schema-v6 20+2 protocol passed at 129.2/131.3/132.0 ms and **132.2 ms
    maximum**. It used the existing universal 4,310,016-byte kernel; a
    Firecracker-specific kernel candidate saved only about 3 ms and was
    rejected. All samples were cached, no-mount, non-degraded, and free of
    hidden launch work or leaked benchmark processes. The optimized report is
    `/root/mvm-bench-20260819/reports/prepared-cold-firecracker-alpine-optimized-2026-08-19.json`
    (SHA-256 `e12f30ae2bf43a32ced2d6fe585fbe5f40a80f89002f61775c6a7ccf7613360e`).
    Designated signed live jobs remain open.
  - The benchmark now also reports the parent-observed full CLI lifecycle in
    schema v7 and the accessible table. Repeated prepared runtime-overlay
    validation is guarded by a mutation-sensitive validation stamp, reducing a
    warmed attach to 0.42 ms while same-size rewrites, replacements, and corrupt
    stamps still fall back to full fail-closed verification. A fresh 20+2
    Firecracker run kept authenticated boot below the hard limit at
    138.1/148.2/174.6 ms p50/p95/p99 and **181.3 ms maximum**, but measured the
    full process lifecycle at 762.9/822.8/848.3 ms and **854.6 ms maximum**.
    Admission was 268.3 ms p50 and teardown 109.4 ms p50. The host is backed by
    rotational ext4-on-RAID1, where required durability flushes measured
    60-175 ms apiece; a full durable lifecycle below 200 ms therefore requires
    low-latency persistent storage and a fresh validation, not a specialized
    kernel or a weaker audit/cleanup boundary. Report SHA-256:
    `d224bacb3aa04b727a74c424ff20a2f93f8adf3196da0743e63bd1acea922c74`.
  - 2026-08-20 full-lifecycle follow-up: independent receipt, decision-cache,
    and authoritative audit-chain flushes now run concurrently at their shared
    pre-boot durability boundary; launch and command audit emission share one
    validated signer and terminal barrier. Failures and dropped batch scopes
    still synchronously retry every pending path, and receipt-head recovery
    handles a crash that leaves the head ahead of receipt files. On the same
    Firecracker host and universal kernel, a release 20+2 run cut admission p50
    from 268.3 to 160.5 ms and full CLI lifecycle p50 from 762.9 to 580.6 ms
    (23.9%). Authenticated boot remained inside the hard requirement at
    135.4/151.5/182.8 ms p50/p95/p99 and **190.6 ms maximum**, with no leaked
    benchmark process. Report SHA-256:
    `89aabed4403cdca9def18666cdd9af28f6ccc05cd856868f65e025a71d02f980`.
- [ ] **Separate the cold lanes:** report prepared cold, prepared cold with a
  mount-cache hit, mount-cache miss, artifact miss, and warm claim as distinct
  distributions. A first-use image pull, build, digest, or ext4 materialization
  may not be hidden inside the launch SLO.
- [ ] **Content-addressed mount cache:** fingerprint source content and mount
  policy, publish immutable images atomically under `MVM_HOME`, verify the
  manifest and image digest before attach, support read-only direct attach and
  writable copy-on-write, and remove obsolete internal add-directory naming.
- [ ] **Explicit artifact preparation:** move image, kernel, initramfs, and
  optional verity preparation out of the launch critical path. Prepared
  manifests must be local, digest-verified, and free of host-path or network
  dependencies when launch begins.
- [ ] **Backend cold path:** profile and reduce VMM creation, memory mapping,
  vCPU/device setup, and first-instruction latency for HVF, Firecracker/KVM,
  and libkrun where supported. Reuse immutable host mappings and a resident
  control plane only; every launch still gets a fresh guest identity and
  authenticated channel.
  - [x] Firecracker no-mount slice: reduce authenticated dispatch from a
    302.8 ms baseline maximum to 132.2 ms without a backend-specific kernel,
    warm parent, snapshot restore, or weakened identity/authentication checks.
- [ ] **Readiness and cleanup:** replace polling with event-driven authenticated
  readiness, preserve generation/key checks, and measure command completion and
  teardown separately. Foreground cleanup must remain bounded without weakening
  reaper, state-retention, egress, or crash-recovery guarantees.
- [ ] **Live evidence:** run release-built matrices on Apple Silicon/HVF and
  the Linux Firecracker host, attach signed timing evidence, add BDD and
  hermetic regression coverage, and fail CI on prepared-cold p99 regressions.
  The complete work is tracked in [Plan 299](plans/299-cold-launch-performance.md).

### Phase 4 — Docs, close-out, stretch

**WS12 — ADRs alive + website docs**

- [ ] Keep the consolidated ADRs authoritative; update `CLAUDE.md`/`AGENTS.md` to the new crate/binary/dir/feature/backend reality.
- [ ] Update the website docs (`public/src/content/docs/**`) — CLI reference, architecture diagram, backend list (drop QEMU and the retired macOS backend), single-dir, install/upgrade/clean.
- [ ] Sweep stale `specs/{claims,compliance,threat-models,references,contracts,runbooks}` path references out of `SECURITY.md`, `README.md`, `ops/`, other ADRs, and `public/src/content/docs/**` (flagged by WS0.2a — they now live in ADR-002/050/067/090).
- Gate: docs match the shipped CLI + architecture; no dangling `specs/` paths; `#1637` (one-command microVM) becomes accurate.

**WS13 — issue/PR close-out** (all but #1637 — see Appendix B)

- [ ] Fold each still-relevant intent into its WS; close the 8 issues + 4 PRs with a pointer to the superseding WS. Keep **#1637** open.
- Gate: only #1637 remains open.

**WS11 — wasm-container backend + `no_std` core (CORE goal; DESIGN LANDED — see `specs/refactor/11-wasm-backend.md` + §2.5)**

- [x] **DESIGN + scope decided** (`specs/refactor/11-wasm-backend.md`; ADR-024 → Accepted): `WasmBackend` = the **claim-free portability/demo/browser tier** (host `wasmtime`, opt-in, honest capability matrix, zero numbered claims — ADR-024's 3 constraints); **workload = user-supplied WASI module**; production-untrusted-wasm (engine-in-guest per ADR-024) DEFERRED. Open Qs resolved: no in-guest agent (agent responsibilities → host WASI-imports), browser slice = `no_std` OCI decoders only. `no_std` FOUNDATION already done (Increment 3 — mvm-contract builds on wasm32).
- [x] `mvm-contract` is `#![no_std] + alloc`, `unsafe_code = "forbid"`, `wasm32-unknown-unknown` CI build (Increment 1–3). _GAP → P1:_ tests running UNDER wasm (lib-build only today) + explicit no_std-boundary lint.
- [x] **P1 DONE** (`5b01e0f6b`): `wasm-no-std-boundary` CI job in `ci.yml` — builds `mvm-contract` on `wasm32-unknown-unknown` (the no_std boundary, was a LOCAL-only check, now CI-enforced) AND runs its tests under real wasm (`wasm32-wasip1` via `wasmtime`) — **339 tests pass under wasm**. Crate attr → `#![cfg_attr(all(not(feature="schema"), not(test)), no_std)]` (std-during-test so libtest links; wasm lib build stays no_std). chrono `clock` re-declared dev-only (kept off the wasm lib build → gate stays chrono-clock-free). The wasm32 _build itself_ IS the no_std lint (fails on any std/OS leak). Independently re-confirmed wasm build clean + nextest 6567/0.
- [x] **P2 DONE** (`0ecb04486`): `BackendKind::Wasm` (unconditional, no_std-safe) + `WasmBackend: VmBackend` in `mvm-runtime/src/wasm_backend.rs` runs a user-supplied WASI Preview 1 module under host `wasmtime`/`wasmtime-wasi` (pinned 46) behind opt-in `wasm-backend` feature (default tree = 0 wasmtime; 42 with feature). Honest: `capabilities()` reports no HW-virt/kernel/TAP/vsock/snapshot; `security_profile()` = every numbered claim `DoesNotHold` (claim-free, tested). Fail-closed typed `WasmBackendError` (KernelBoot/VerifiedBoot/Networking/Console/PauseResume-NotSupported + NotCompiledIn) — NO prod panic/unimplemented. Real exit-code tests (`.wat` fixtures: exit 0 + `proc_exit(7)`). Deviation (sound): type/AnyBackend/catalog wiring UNCONDITIONAL (side-effect-free ctor), only wasmtime internals cfg-gated in a private `engine` submod → zero CLI changes (--hypervisor is a String), NotCompiledIn error at first real use (mirrors existing "recognized-but-unavailable" pattern). Green: check/clippy (default + feature), nextest 6567/6567 + mvm-runtime 925/925(feature), wasm32 protocol still clean, check-no-string-backend-dispatch clean.
- [x] **P3 COMPLETE** (P3a + P3b.1 + P3b.2) — the governed egress seam, POC gate met. Design SIMPLIFIED (`bf3eac389`, doc 11): NO new transport — wasm egress is just a `WireRequest` client (`mvm_core::substitution_wire`) over the existing `Uds` to the SAME substitution endpoint the microVM backends use (faithful by construction). Reachability recon (`127b22e44`) flagged that governance lives in mvm-hostd, unreachable in-process from WasmBackend in mvm-runtime — **resolved** by homing the witness in mvm-hostd's own tests (it deps mvm-runtime for `WasmBackend` and owns `SubstitutionService`, so it drives the REAL governance in-process with no dependency inversion — cleaner than the recon's anticipated subprocess route).
  - [x] **P3a** (`5d834b606` + gate-fix `d84912885`): the `mvm:egress` wasmtime host-import on WasmBackend — reads a `WireRequest` from guest memory, relays via REUSED `mvm_agentd::substitution_client::relay` (no 2nd frame codec), writes `WireResponse` back; 10 typed fail-closed error codes (never traps host on guest input); endpoint UDS path = host state (`with_egress_endpoint`, default None). Proven by a stub-UDS + `.wat`-fixture round-trip test (`${API_KEY}` placeholder → `WireResponse::Ok{200,"pong"}`) + 2 fail-closed tests. Default build wasmtime-free; claim-free unchanged. (Also fixed a pre-existing P2 `check-no-spec-refs` fail: ADR-002 in a wasm_backend comment/test-string.)
  - [x] **P3b.1** (`45b1db3e6`): `WasmBackend::start()` spawns the substitution endpoint mirroring libkrun — `wasm_endpoint_plan` (skip iff no-secrets + deny-all) + `wasm_substitution_spawn_params` (`EndpointTransport::Uds` via shared `vm_substitution_endpoint_socket`, `terminator_listen`/`tls_intermediate` `None` [http-only POC], `network_policy: Some`, **`raw_egress: false`** — wasm is always wire-mode, the required deviation from libkrun) + thin `spawn_wasm_egress_endpoint_if_needed` reusing `spawn_substitution_endpoint`; wires the UDS into the P3a host-import + reaps after the synchronous run. Decision/params unit-tested (no subprocess), 26/26, all gates green. **KNOWN FOLLOW-UP**: P2's `reject_unsupported_start_config` still fails `--network-allow` closed (`NetworkingNotSupported`), so the governed-egress path is built + unit-tested but NOT reachable in production `start()` until P3b.2 proves the witness + relaxes that gate (correct fail-closed posture — don't enable governed egress until proven).
  - [x] **P3b.2 DONE** (`e669bcc5d` gate-relax + `4d709d196` allow + `8c270214d` deny) — the **data-governance witness** passes; POC gate met. Executed subagent-plan `specs/plans/13-ws11-wasm-egress-poc.md`. **Home deviation (improved on the plan):** the witness lands in **mvm-hostd** tests (`crates/mvm-hostd/tests/wasm_egress_witness.rs`), not mvm-runtime — mvm-hostd already deps mvm-runtime (`WasmBackend`) + owns `SubstitutionService`/`Recorder`/`verify_audit_chain`, so it drives the REAL governance types **in-process** with NO dependency inversion and NO subprocess. A mvm-hostd `wasm-backend` feature forwards to mvm-runtime's; the test is `#![cfg(feature = "wasm-backend")]` so a default build pulls no wasmtime. **Two tests, four properties each:** allow path — a `.wat` module drives the `mvm:egress` host-import, observes `WireResponse::Ok{200}` through the REAL claim-10 gate, the destination receives the real secret while the module only ever held the placeholder, and a chain-signed `secret.substituted` entry verifies (no secret in it, claim 13); deny path — a claim-12 bind-check drop (destination network-admitted but not in the secret's binding) yields a refusal, the destination is never contacted, and a chain-signed `secret.placeholder_dropped` entry verifies. **Hermetic concession (documented in-file):** the production forward leg refuses loopback (SSRF hardening), so the test swaps ONLY the outbound TCP dial for a `Forwarder` test double — the crate's own test seam — and decouples the policy destination (a public IP the gate admits; loopback is mandatory-denied regardless of allow-list) from the physical loopback dial. Task 1 relaxed P2's networking gate so an allow-egress `VmStartConfig` is no longer rejected by `reject_unsupported_start_config` (config-level unit test `start_config_with_egress_policy_is_now_allowed`; the dead `NetworkingNotSupported` variant then removed — final-review Minor). **Scope honesty (final-review Important):** the witness drives the governance seam directly via `WasmBackend::with_egress_endpoint` + an in-process `SubstitutionService`, so it proves substitution + audit but NOT the full `start()` → `spawn_wasm_egress_endpoint_if_needed` → real-subprocess wiring (both tests use `VmStartConfig::default()` = `deny_all`, so the relaxed gate never fires in them). That decision layer is unit-tested per P3b.1; an end-to-end spawn-path test is a **deferred follow-up** (§below — it hits the same SSRF-refuses-loopback wall). All gates green (workspace clippy, runtime+hostd wasm-backend clippy, 27 wasm_backend units + 2 witnesses, 0 wasmtime in non-dev graph, 4 xtask gates, wasm32 protocol build, fmt). (Full TLS-terminating substitution for HTTPS dests → P3c; browser → P4 — each its own subsequent plan.)
- [ ] **P4**: browser POC — `mvm-contract` + `no_std` OCI decoders run in the browser (image inspect/verify).
  - Plan 329 browser-tier shell demo (`/demo`) is E2E-green; OCI-decoder P4 work remains open.
- [ ] **REMAINING WS11 WORK — design of record is `specs/plans/301-wasm-backend-completion-and-browser-slice.md`** (plan landed, execution not started). Covers both open halves. **Part A (host tier):** A1 end-to-end `start()`→`spawn_wasm_egress_endpoint_if_needed`→real-subprocess coverage (the P3b.2 deferred follow-up; same SSRF-refuses-loopback wall); A2 = P3c TLS-terminating substitution (P3b.1 shipped http-only, `tls_intermediate`/`terminator_listen` both `None`, so https destinations must fail closed until it lands); A3 transparent WASI socket interception (Fork 1's eventual goal — the explicit `mvm:egress` host-import stays the supported path); A4 resolve the Preview 1 vs doc-11's "target Preview 2" divergence (amend one or the other, don't leave them disagreeing); A5 **ADR-024's Status paragraph is STALE** — it still says no implementation has landed and no `wasmtime` is in the workspace, both false since P2 (constraints untouched) + confirm the P2-assigned `deny.toml` review actually happened; A6 generalize the witness across all workload backends ("the same witness" was the whole argument for the subprocess route and is currently true only wasm-side). **Part B (P4 browser):** B1 = **the long pole** — the `no_std` OCI decoders P4 assumes DO NOT EXIST (`mvm-fs` is std-heavy: tokio/reqwest/rustls/rayon/libc/rustix/xattr/tar/flate2), so `oci/{manifest_types,manifest,reference,layer,archive}` must be cut decode-vs-fetch and the pure half relocated **verbatim** to `mvm-contract` by the Increment 3 method (leaf-first, byte-identical serde, green+wasm-clean each step); open question = gzip/tar under no_std (`flate2` defaults to a C backend) or scope to manifest-level inspection; B2 Worker + thin main-thread proxy (no verify work on the main thread — the current `web/audit-verify/index.html` jank-locks the tab); B3 OPFS content-addressed cache with **verify-on-read** eviction, `postcard` for the local unsigned record envelope ONLY (JCS stays the signing input — ADR-031 byte-identity with mvmd is untouchable); B4 `wasm-opt -Oz` + a gzipped-size budget in the existing wasm lane (`scripts/ci-linux-coverage.sh`) — Increment 3 moved the entire signed plan into the crate the bundle is built from and nobody is measuring it; B5 delete `web/audit-verify/` once B4 covers verify+Merkle, fix the stale `mvm-verify` crate refs in ADR-031, add `mvmctl audit pubkey` (without it the page can't be run against a user's own logs). Execution model for B2/B3/B4 is taken from ferrovec (in-browser Rust/wasm vector store; Worker + OPFS + ~33 KB gzipped) as prior art — not a dependency. ADR-024's three constraints bind throughout: **no numbered claim is added**.
- Gate: `mvm-contract` wasm build+tests green; no_std-boundary lint holds; `WasmBackend` runs a workload through the shared egress/audit seam (POC-gated) with the data-governance witness passing.

**Semantic address (UOR-ADDR) pilot — IMPLEMENTED (orthogonal to WS11; do NOT weave into P3)**

- [x] **DESIGN** (`specs/refactor/12-semantic-address-pilot.md`): additive `SemanticAddress` (`sha256(JCS(ir))` = UOR-ADDR JSON realization) for Workload IR, with a distinct newtype and no use in exact-byte, signature, nonce, or ephemeral-ID paths. The `uor-addr` crate remains deferred to the verification-gated WS11-P4/browser decision.
- [x] **EXECUTED** (`2f75f268b`, extended by this follow-up): `mvm-core/src/semantic_address.rs` validates schema first, NFC-normalizes JSON strings/object keys, then computes the UOR-ADDR label. The 12 published UOR-ADDR JSON fixtures pass; the Python/TypeScript SDK parity witness remains green. `ir_hash` is intentionally reported as a separate internal fingerprint because it does not perform UOR Unicode normalization.
- [x] **UOR FRAMEWORK EXPLORATION** (`specs/research/uor-framework-integration-exploration.md`, 2026-07-22): broader UOR Framework, Prism, and PrimeShield adoption is not recommended. The host-side UOR-ADDR conformance baseline is complete; `BuildProvenance` addressing and `uor-addr` crate adoption remain separate follow-ups.

**WS14 — mvmd contract (secondary)**

- [ ] Freeze the mvmd-facing surface (`mvm-contract` + `mvm-client` + `BuildEnvironment`/`ShellEnvironment` traits); document it; file the coordinated rename for the mvmd repo.
- Gate: the public surface is documented and stable; mvmd rename tracked as a follow-up.

---

## 4. Sequencing

```
Phase 0 (hygiene)  ─┐   parallel-safe, do first
Phase 1 (foundations: crates, single-dir, features, trait/hardcoding) ─┐  the spine
Phase 2 (binaries, egress invariant, lifecycle) ─┐  depends on Phase 1 crate boundaries
Phase 3 (size, dead-code, CLI, kernel/memory)    ─┐  depends on the new crates existing
Phase 4 (docs, close-out, wasm stretch, mvmd)     ─   last
```

WS4/WS5/WS6 can proceed in parallel with WS1 sub-steps. WS3 depends on `mvm-net` (1d). WS2 depends on the guest/host crate merges (1e/1h). WS10's de-tokio depends on WS2's single-binary shape.

### Workstream: universal initramfs + vsock-activated boot (Plan 270) — COMPLETE

Shipped in #1914 (core), #1931 (QEMU unified runner), #1933 (Docker dev-tier, subsequently removed by Plan 329), #1936 (Wasm activation), #1968 (Apple Container kernel on HVF), #1985 (activation agent-readiness retry), and #1996 (deterministic cargo initramfs, which replaced the Nix initramfs build described below). Tracked in `specs/plans/270-universal-initramfs-vsock-activated-boot.md`. This workstream replaces the per-rootfs init paths (`mvm-verity-init`, `mvm-oci-init`, busybox `/init`) with one content-addressed initramfs in which `mvm-agentd` is PID 1 and receives a signed `ActivateEnvironment` command over vsock.

**Prerequisites:** satisfied. `feat/vsock-control-conformance` and `feat/firecracker-vsock-only-final` are already merged to `main`; `feat/hvf-converge-vsock` cleanup is in PR #1905.

**Execution order:**
1. [x] Initramfs Nix derivation + content-addressed build. Created
   `nix/packages/mvm-guest-agent-static.nix`, `nix/images/initramfs/flake.nix`,
   and exposed `packages.<system>.initramfs` producing `initramfs.cpio.gz`,
   `initramfs.hash`, `initramfs.size`, and `VERSION`. **Replaced (#1996):**
   the Linux build path is now `build_initramfs_with_cargo` in
   `mvm-build/src/initramfs.rs` — the pinned agent source is cross-compiled
   via the shared `guest_agent_build::resolve_or_build_guest_binaries` cache
   and packed as an epoch-zero, stably-ordered newc cpio (same sidecar
   contract). The flake remains only as the optional publish-path build.
2. [x] PID-1 signal handling and zombie reaping in `mvm-agentd`. Added
   `init.rs` with PID-1 detection, early filesystem mounts, and a SIGCHLD
   reaper. Wired into `mvm-guest-agent.rs` before the vsock bind.
3. [x] `ActivateEnvironment` protocol types and boot state machine. Added
   `ActivateEnvironment`/`RootfsConfig`/`RuntimeOverlayConfig`/`VolumeConfig`
   to the vsock protocol, plus `ActivationState` in `AgentBootState` and a
   fail-closed dispatch gate that rejects everything except activation until
   activated.
4. [x] Guest-side mount library (dm-verity + overlayfs). Filled
   `guest_mount.rs` with real dm-verity ioctl setup, pivot_root/switch_root,
   overlayfs runtime overlay, and virtio-fs volume mounting ported from
   `mvm-verity-init.rs`. Includes policy guards (no shadowing of `/`, `/mvm`,
   `/mvm/runtime`, `/dev`, `/dev/vda`, `/dev/vdc`), privilege drop with
   supplementary-group clearance, and ext4 block-size probe. Focused tests and
   workspace clippy pass; `cargo test -p mvm-agentd` green.

5. [x] Host-side activation for the universal initramfs. Added
   `mvm-runtime/src/microvm/activation.rs`, which builds
   `ActivateEnvironment` from the admitted `VmStartConfig` (fixed virtio-blk
   slots `/dev/vda`..`/dev/vdd`, rootfs roothash from config or sidecar,
   runtime-overlay roothash, virtio-fs volume mapping, and verb-grant
   envelope) and sends it over `RunningVm::vsock_connect(GUEST_AGENT_PORT)`.
   `WorkloadRunner::start_workload` now activates after boot when both
   `initrd_path` and `roothash` are present. `MockGuestAgent` answers
   `ActivateEnvironment` with `ActivateEnvironmentAck` so hermetic tests stay
   green. `cargo nextest run -p mvm-runtime` (1091 passed) and
   `cargo nextest run -p mvm-agentd` (498 passed) confirm no regressions.

6. [x] VmmDriver cmdline shrink for universal initramfs. Removed the
   legacy `mvm.roothash`, `mvm.data`, `mvm.hash`, and runtime-overlay
   device tokens from `workload_cmdline` for verity/initramfs boots; they
   now travel over vsock via `ActivateEnvironment`. The driver base
   bootargs already emitted only console/panic for the `!has_disk`
   initramfs branch, so FC/libkrun/HVF/Mock drivers needed no signature
   change. Updated `workload_runner::cmdline` and runner tests to assert
   the new token-free cmdline shape. `cargo nextest run -p mvm-runtime`
   (1091 passed) and `cargo nextest run -p mvm-agentd` (498 passed).
   **Corrected — the shrink was unconditional and broke every host that
   cannot resolve the universal artifact.**
   `attach_universal_initramfs_if_cached` is non-fatal by design, and on
   macOS it always fails (no local build for a Linux initramfs on macOS, and
   the published `initramfs-<arch>.tar.gz` 404s), so the boot falls back to the
   legacy per-rootfs `rootfs.initrd` whose PID 1 is `mvm-verity-init` — which
   reads those exact tokens off the cmdline and is never sent
   `ActivateEnvironment`. Result on every macOS `machine run --image`:
   `mvm-verity-init: FATAL: no mvm.roothash= on kernel cmdline` → `Kernel
   panic - Attempted to kill init!` before userspace, no guest agent, and a
   host-side `Failed to read frame length` out of the first RPC.
   `workload_cmdline` now emits the tokens whenever
   `microvm::booted_with_universal_initramfs(config)` is false, so each boot
   protocol gets the channel its PID 1 actually reads. The unit tests and the
   `s4_verified_boot` feature that asserted the tokens were absent were
   themselves keyed to a legacy `rootfs.initrd` fixture, so they encoded the
   panic; each now carries a universal-flavour case (tokens absent) and a
   legacy-flavour case (tokens present).
8. [x] Guest-agent readiness proven on the wire. `wait_for_agent` /
   `wait_for_guest_agent` both documented "reachable means it speaks the
   protocol, not just that the socket is open", but reached that verdict
   through `negotiate_protocol`, which in a non-test build takes the
   `negotiate_protocol_authenticated` arm and never touches the stream — so
   in every shipped binary the probe degenerated to "did `connect()` succeed".
   The VMM binds the agent port before the guest kernel starts, so that
   succeeds throughout the guest's boot and equally for a guest that panicked
   before userspace; both callers then issued their real RPC into a dead
   socket and surfaced `Failed to read frame length` from the framing layer.
   Added `mvm_agentd::vsock::probe_agent_ready` — authenticated handshake plus
   one `Ping`, real I/O with no cfg-gated shortcut, any answer (including a
   refusal) counting as ready and only a transport failure as not-yet — and
   routed both waiters through it.
9. [x] Initramfs cache resolver/builder and CLI attachment. Added
   `mvm-fs/src/initramfs.rs` resolver, `mvm-build/src/initramfs.rs`
   builder + cache installer, and `attach_universal_initramfs_if_cached` in
   `mvm-cli/src/commands/vm/up/runtime_source.rs`, wired from `exec.rs` and
   `oci_persist.rs` and `checkpoint.rs` right after the runtime-overlay attachment. The resolver
   validates `initramfs.cpio.gz`, `initramfs.hash`, `initramfs.size`, and
   `VERSION`; the builder supports worktree-isolated caches by seeding from
   the default cache, falls back to a published-release download on non-Linux
   hosts, produces the artifact on Linux via the deterministic cargo build
   (`build_initramfs_with_cargo` — previously `nix build`, replaced in
   #1996), and installs
   atomically. `cargo fmt --all`, `cargo clippy --workspace --all-targets --
   -D warnings`, the spec-ref lint, targeted nextest for the modified crates
   (mvm-fs, mvm-build, mvm-runtime, mvm-agentd, mvm-cli initramfs tests),
   and the pre-commit hook all pass. Full workspace nextest on the Linux
   builder VM now passes (8136 passed, 12 skipped) after also fixing the
   runtime-overlay flake's `__pycache__` cleanup in the Nix sandbox. Full
   workspace nextest on macOS still shows four pre-existing mvm-build
   failures unrelated to Plan 270. The end-to-end Nix build of the initramfs
   flake succeeded on the Linux builder VM after removing the
   sandbox-incompatible `mknod` calls (device nodes are provided by devtmpfs
   at guest boot).  The `universal_initramfs_attach_tests` cold-cache
   assertion was relaxed so the test stays green on Linux, where the Nix build
   fallback can warm the cache automatically.  Added a BDD scenario for the
   cold-cache non-fatal fallback under `features/suites/s14_universal_initramfs`,
   and updated the verified-boot cmdline feature to assert that the legacy
   `mvm.roothash`/`mvm.data`/`mvm.hash` tokens are omitted from initramfs boots
   — narrowed by item 6's correction to *universal*-initramfs boots only.
10. [x] Retired the obsolete CLI workload-guest payload. `mvm-cli/build.rs`
    now embeds only the host and seed builder/bootstrap manifests; the six
    workload helpers are supplied by the universal initramfs and runtime
    overlay. Removed the dead skip-embedding environment switch and fast-test
    recipe, deleted the embedded-byte OCI plumbing, retained a content-keyed
    source fallback for legacy rootfs-only development, and added `xtask` plus
    integration assertions that prevent workload binaries from returning to
    the CLI payload. Focused tests, workspace clippy, formatting, and the full
    workspace test suite pass; the latter was run serially because unrelated
    tests mutate process-global environment variables under parallel execution.

Live witness for items 6 and 8 on macOS 26.5.2 / arm64, HVF backend, after the
corrections: `machine run --image alpine -- /bin/sh -c "echo TRANSIENT-OK; cat
/etc/alpine-release"` prints `TRANSIENT-OK` + `3.24.1` in 5.8s, and
`machine run --image alpine -it --allow-host google.com -- /bin/sh -c "ping -c 3
google.com"` attaches its PTY, resolves `google.com` to a real address, and runs
the command inside the guest. `ping` then fails with `can't create raw socket:
Address family not supported by protocol` — the vsock-only data plane offers no
raw IP by design, so ICMP is unreachable and a TCP client is the right probe.

TCP egress over vsock is live on the same path: `--allow-host example.com:80`
with `wget http://example.com`, and bare `--allow-host example.com` with
`wget https://example.com`, both return the real page body from inside the
guest.

One diagnosability note, now closed. A bare `--allow-host <host>` means
`<host>:443` (`parse_allow_host` defaults to the https port), so pairing it with
an `http://` URL is a port mismatch and the gate denies — correctly. What the
guest saw was `HTTP/1.1 403 Forbidden` with `Content-Length: 0` and no reason,
which reads as "egress is broken" rather than "port 80 was not admitted"; the
host knew exactly which `EgressVerdict::Deny` it took and discarded it. That cost
three rounds of misdiagnosis in this very session, including two wrong
attributions of the refusing component.

`EgressVerdict::Deny` now carries a typed `DenyReason` (no-egress / host not
admitted / port not admitted / address not admitted / resolution failed), so a
deny site cannot fail to say why — the compiler asks at each one.
`http_forward` renders it into the 403 body and logs it host-side; the raw-TCP
and SOCKS-UDP paths, whose wire formats have no room for a reason, log it rather
than dropping it. Live: `--allow-host example.com` with `http://example.com`
answers

```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

example.com:80 is not admitted; allowed: example.com:443
```

Remaining gap, deliberately not chased here: busybox `wget` prints only the
status line and discards the body, so a wget user still needs the host log
(`/tmp/mvm-substitution-endpoint-<vm>.log`). Surfacing a failed run's egress
denials through `mvmctl` itself is the follow-up.

### ICMP echo over vsock

`ping` could not work in a NIC-less guest: no route, no raw socket, so busybox
`ping` fails at `socket()` before a packet exists. The vsock egress path carries
TCP streams (`host:port` + ack + splice) and DNS (its own frame marker), and had
nothing for ICMP — not a misconfiguration, an absent transport.

The host now echoes on the guest's behalf behind an `MVM_ICMP/1` frame on the
shared egress stream, decided by the same claim-10 gate every other verb uses.
`EgressGate::decide_icmp_request` admits a host the allow-list named on *any*
port (ICMP has none), refuses one it did not, and keeps mandatory-deny above the
allow-list so a pinned loopback address cannot turn ping into a probe of the
host's own networks. The socket is the unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP`
ping socket, never `SOCK_RAW`: raw would need `CAP_NET_RAW` and would let this
code read every ICMP packet on the host.

Delivery is a **bind mount, not an image edit**. `mvm-ping` ships in the runtime
overlay and is mounted over the image's own `/bin/ping`, so the rootfs keeps
exactly the bytes the registry served (which is what the recorded OCI provenance
refers to), `/proc/mounts` records the substitution, and an absolute-path caller
still reaches the working tool. An earlier attempt copied over the image
instead; the mount is both more honest and materially smaller — `ping` leaves the
four OCI-injection lists entirely and lives only in the overlay.

Two findings the tests could not have produced:

- **Batched round trips measure the reader's buffer, not the network.** The
  first working run reported `seq=0 36.6ms, seq=1 0.1ms, seq=2 0.0ms`: later
  reply lines were already in memory. Each echo is now its own request, the way
  `ping` times each packet.
- **The audit emitted nothing while compiling cleanly.** `EventCategory::Flow`
  is mandatorily plan-bound and the per-VM egress endpoint holds no
  `ExecutionPlan`, so every entry was dropped with a warning only the endpoint's
  own log carried. ICMP now has its own category, as DNS does and for the same
  reason.

Live on macOS 26.5.2 / arm64 / HVF, `--allow-host google.com` with
`/bin/ping -c 2 google.com`:

```
PING google.com (56 bytes) via host
56 bytes from 142.251.218.174: seq=0 time=13.8 ms (host leg 8.9 ms)
2 sent, 2 received, 0% packet loss
```

with `icmp.admitted` in the chain-signed log carrying host, pinned IP and count.
An unadmitted host answers `example.com is not admitted; allowed: google.com`.

**Blocking, and not caused by this work:** once `~/.mvm/cache/initramfs/` is
seeded, boots take the universal-initramfs path and fail with `send
ActivateEnvironment to guest: Failed to read frame length`. Setting that cache
aside restores working boots, which isolates it: the universal-initramfs boot is
broken independently of ICMP, and anyone who seeds that cache gets a dead guest.
This is the other half of the legacy-cmdline story — the legacy path now works,
and the path meant to replace it does not.

### The universal-initramfs cache could not see source fixes

A boot that attached the universal initramfs died at its first RPC with
`send ActivateEnvironment to guest: Failed to read frame length`, and the guest
console said `rejecting control connection without a pinned host key` — the
symptom #1959 had already fixed.

It kept happening because the cache could not see that fix.
`<cache>/initramfs/<version>/<arch>/` is keyed on a version that only moves at
release, so an artifact built from older guest sources outlives every change to
them: the fix lands, the cache still serves the binary from before it, and the
fix looks inert. The runtime overlay and the verity initramfs both record a
`SOURCE_FINGERPRINT` for this reason; this one did not. It does now — a mismatch
**evicts** rather than ignores, so the next resolve rebuilds instead of
re-finding the same bytes, and an artifact with no fingerprint is treated as
unknown provenance rather than assumed fresh. Trusting those is what let the
stale one survive.

The activation race underneath — `activate_workload` sending before the agent
had bound its port — was fixed independently on main by #1985 while this was in
review, so only the cache work remains here.

Live on macOS: the stale artifact is discarded, the host falls back to the legacy
initramfs (macOS cannot build the universal one), and the workload runs. A
working universal-initramfs boot is **not** verified here — this host cannot
produce the artifact, so what is proven is the eviction and the fallback.

`initramfs::tests::resolve_returns_missing_when_cache_empty` is also fixed. Its
`HOME` isolation had made it genuinely hermetic, which exposed what that was
hiding: on Linux the empty-cache path falls through to a real build (then
`nix build`; since #1996 the deterministic cargo build), and
with a shell double that reports success without producing an artifact the call
never returns. It ran for 20,000+ seconds and took a CI job to its six-hour
limit. It had been passing on Linux only by finding an artifact it was supposed
to prove absent. It now exercises `resolve_or_seed_from_default_cache`, whose
contract is the one the name claims, and completes in milliseconds.

That a shell double reporting success can make the nix path hang rather than
error is worth closing separately: a build producing no artifact should fail,
not wait. For the initramfs this is now moot because the Nix build path was
removed entirely; the cargo build either produces the artifact or returns a
typed error.
HVF real rootfs bring-up remains the long pole tracked in Plan 255/265/214; Plan 270 designs for HVF but does not duplicate that work. Plan 268 (`specs/plans/268-backend-shim-removal.md`) stays a separate future workstream and is not absorbed here.

### Deferred: a dry run should not require a bootable backend

`machine run --dry-run` with egress enabled (`--allow-host` / `--net`) resolves an
*available* egress-capable backend before printing the plan, so it exits 1 on a
host with no usable VMM. That makes the command's outcome a fact about the host
rather than about the request, and it is why two otherwise-valuable hermetic
scenarios — that a bare `--allow-host <host>` resolves to `<host>:443`, and that
`--net` resolves to the dev preset — could not be gated: they pass on a developer
machine and fail on a CI runner, and the reverse assertion has the same problem
inverted.

Whether that check belongs in a dry run is a real question. A dry run exists to
show the resolved plan without booting, and needing a bootable backend defeats it
exactly where it is most useful — CI, a laptop without a VMM, planning a run
before provisioning. Against that, a plan you could never execute is arguably
worth refusing. Not decided here, and deliberately not changed inside a test
change.

## 5. Definition of done

- Both surfaces build; `cargo nextest run --workspace` + `cargo test --workspace --doc` + `cargo clippy --workspace --all-targets -- -D warnings` + `cargo fmt --all --check` green.
- **Binding Rust coding standard** (gist `c3161f55…`), enforced per-change, not just at the end: traits/enums over stringly dispatch (`name() == "…"` is banned — use a typed discriminant); **exhaustive matches, no wildcard `_ =>` on owned enums**; builder pattern for any type/fn with more than a couple of (esp. optional) fields; **functions ≤ ~500 lines**; borrowed params (`&str`/`&[T]`/`impl AsRef<Path>`); `with_capacity`/no needless `.clone()`; `thiserror` in libs; **clippy is fixed, never `#[allow]`-suppressed** (each surviving `#[allow]` scoped to the smallest item + justified).
- ~11 crates, 2 features, 1 host + 1 guest + 1 CLI binary, 1 base dir, 0 non-test files > 1500 lines, no `Command` outside the allow-list, no hardcoded IPs/ports, vsock-only egress on every workload backend with the data-governance witness passing.
- All security claims still witnessed; live egress + boot smoke on Mac (HVF) and Linux (libkrun + FC); **sub-second launch** proven by the timed e2e; guest RAM demand-faulted for density.
- **Wasm-container capable (core goal):** `mvm-contract` builds + tests on `wasm32-unknown-unknown` in CI with a CI-enforced `no_std` boundary; a `WasmBackend` runs a workload end-to-end through the same `VmBackend` + egress/audit/secret-substitution seam (POC-gated — the v1 bar is the seam proven, not full production parity).
- Workload stdout/stderr + exit code flow over vsock; the builder VM runs the same single guest binary.
- `just bdd` green; every security claim and top-level CLI verb has a passing Gherkin scenario; `just ci` runs the BDD suite.
- Root is ~8 dirs (§2.8); SDKs live under `crates/`.
- SDK usage (decorator + runtime) unchanged; ADRs consolidated but intact; website docs current; only #1637 open.

---

## Plan 330 — Decision provenance layer

Cross-sprint work tracked in `specs/plans/330-decision-provenance-layer.md`.

- [x] Phase 0 — RFC/plan drafted and opened as PR #2455.
- [x] Phase 1 — PROV-O export of existing audit events (`mvm-contract::provenance`, `mvm-core::provenance`, `mvmctl audit provenance export`). Implementation PR #2461.
- [x] Phase 2 — Enrich audit events with authorizer/rationale. Implementation PR #2461.
- [x] Phase 3 — `DecisionRecord` API and content-addressed store (PR #2461).
- [x] Phase 4 — Query API and causal chains: `trace`, `impact`, and `similar` queries over the cached decision store, exposed through `mvmctl trust audit decisions {trace,impact,similar}`.
- [ ] Phase 5 — Optional standards interoperability.

## Plan 335 — Merge-queue throughput

Cross-sprint work tracked in `specs/plans/2026-08-15-merge-queue-throughput.md`.

- [x] Consolidate automatic architecture and kernel validation into the main
      CI graph behind one shared scope job.
- [x] Preserve the required `Invariant` and per-architecture kernel check
      names while removing duplicate runner allocations and feature tests.
- [x] Add trusted default-branch Rust workspace and Nix cache warming.
- [x] Pass actionlint, shellcheck, formatting, workspace check, focused
      workflow tests, host all-target Clippy, and the affected crate's complete
      serial test suite.
- [ ] Land the workflow change, pass Linux all-target Clippy, and apply and
      verify the live merge-queue and required-check settings.

## Plan 338 — WebLinux browser backend, builder, workbench, and `mvmd` deployment client

Cross-sprint work tracked in `specs/plans/338-weblinux-browser-backend-builder-workbench-and-mvmd-deploy.md`.
Browser-hosted demo scoped in `specs/plans/2026-08-21-weblinux-browser-demo.md`.

- [x] 0.1 Add ADR-049 and Plan 338 with `Backing:`/`Validation:` headers.
- [x] 0.2 Update ADR-024 to reflect the browser-Linux implementation and link ADR-049.
- [x] 0.3 Update ADR-006 to allow `mvmctl deploy` as a client operation to `mvmd`.
- [x] 1.1 Add `BackendKind::WebLinux` and pure capability metadata.
- [x] 1.7 Define minimal portable lifecycle protocol skeleton.
- [x] 2.1 Pin and package a reproducible QEMU-Wasm engine through Nix.
      Pinned upstream revisions and added `nix/packages/qemu-wasm.nix`;
      build is queued for the Linux builder VM.
- [ ] 2.8 Boot an `mvm`-built x86_64 kernel under headless Chromium and record measurements.

Workstream 1 first slice (1.1, 1.7) and the WS-2 engine packaging
scaffolding landed in PR #2776.

## Appendix A — ADR consolidation clusters (~91 → ~15)

| Canonical ADR (theme)                       | Merge these                                                                            |
| ------------------------------------------- | -------------------------------------------------------------------------------------- |
| Security posture & trust boundary (SoT)     | 002, 032, 063, 070, 083, 088, 104, 108, 109, 111 + claims + compliance + threat-models |
| Networking / egress / vsock                 | 004, 006, 055, 064, 067, 078, 082, 085, 100, 101, 110                                  |
| Backends / hypervisor abstraction           | 014, 046, 056, 072, 076, 093, 094, 095, 098, 099, 102                                  |
| Builder VM / Stage 0 / seed                 | 005, 013, 054, 057, 065, 068, 071, 096, 106, 107                                       |
| Host services broker / daemon               | 059, 061, 062, 084, 089, 090                                                           |
| Signed/audited execution + claims substrate | 041, 044, 047, 048, 058, 079, 103                                                      |
| OCI / image / registry / verity             | 050, 052, 074, 097                                                                     |
| Secrets substitution                        | 049, 067                                                                               |
| Machine / CLI surface                       | 077, 091, 092, 105                                                                     |
| Function entrypoints / factories            | 007, 008, 010, 011, 039                                                                |
| Encryption                                  | 027, 042                                                                               |
| WASM path                                   | 069, 080, 081                                                                          |

## Appendix B — issue / PR close-out

| #        | Kind       | Disposition                                                         |
| -------- | ---------- | ------------------------------------------------------------------- |
| **1637** | PR (draft) | **KEEP OPEN** — one-command microVM docs/blog; WS12 makes it true   |
| 1701     | issue      | Fold → WS3 (finish vsock tunnel), then close                        |
| 1717     | PR         | Fold → WS3 (FC transparent net over vsock), then close              |
| 1601     | issue      | Fold → WS3 (HVF host-vsock-proxy), then close                       |
| 1674     | issue      | **Fixed by #1804** — prior-layer path tracking                      |
| 1654     | issue      | Fold → WS4 (runtime sockets under `~/.mvm/run`), then close         |
| 1462     | issue      | Fold → WS2 (verb-grant delivery), then close                        |
| 1366     | issue      | **Closed** — landed via #1791 (Sandbox.connect dev-only exec guard) |
| 1283     | issue      | **Closed** — landed via #1786 (boot-probe strip done)               |
| 1264     | issue      | **Closed** — #1786 documents upstream-blocked pin bump; no action   |
| 1716     | PR         | Superseded by this sprint — close                                   |
| 1718     | PR         | Folded (dev-builder rename subsumed by WS1) — close           |
| 1713     | PR         | Contradicts consolidation (splits SDK) — close                      |

## Appendix C — biggest confirmed removals

- Userspace network gateways — the whole guest-NIC gateway subsystem; replaced by the one vsock seam (WS-NET).
- `crates/mvm-runtime/src/vm/egress_proxy.rs` L7 stub — removed (WS8).
- `crates/mvm-runtime/src/storage/{pool,thin}.rs` dm-thin substrate — **NOT dead**: backs the live `mvmctl storage info`/`gc` verbs (`ThinPoolImpl`/`DeviceMapperBackend`), kept (WS8).
- QEMU backend (WS1e), retired-backend remnants, the Swift supervisor dir (WS0.4).
- 28 member features → 2 (WS5); ~24 `#[cfg]`-heavy gates collapse.

## 2026-08-18 — Assurance controller-service bridge

- [x] Carry optional generic typed-service proxy bindings in host-signed VM
      registration while preserving the canonical bytes of ordinary launches.
- [x] Keep authoritative assurance session/evidence state and audit signing
      keys in the admitting controller; route the resident broker over a
      bounded host-only UDS with exact signed descriptor and capability checks.
- [x] Derive live broker session identity from VM registration, refuse direct
      non-capability calls, and fail closed for mismatched identities,
      oversized frames, missing/controller failure, and unsigned bindings.
- [x] Stop a just-started VM when assurance session opening fails, preventing a
      workload from continuing under a weaker post-admission binding.
- [x] Pass the focused signed-control, controller-proxy, daemon, registry,
      admitted-boot rollback, real typed-probe round-trip, and all-target
      Clippy checks for the changed crates.
- [x] Persist terminal provider request/result identity before transport;
      replay completed responses exactly and refuse interrupted, failed, or
      conflicting retries without executing the admitted runner twice.
- [x] Pass the post-journal full macOS workspace format, check, test, and
      all-target Clippy gates plus the x86_64 Linux cross-target and BDD
      required-feature compilation gates.
- [x] Close the counterparty fact gap with a strict operator-session bundle:
      validate it against the Scout request in `mvm-security`, transfer it only
      through `OpenSession`, and require MVM's all-or-nothing identity join
      before durable claim or runner execution.
- [x] Build the sibling-owned signed `scoutd` extension pack. The sibling now
      emits a static x86_64-musl guest entrypoint, strict build recipe, SPDX
      SBOM, and independently signed generic pack. MVM's product-agnostic ext4
      materializer and verifier accept the actual artifact; tamper, expiry,
      revocation, wrong-signer, protocol, and artifact-budget failures are
      covered and fail closed.
- [x] Inject the real admitted boot configuration. `LifecycleAdmittedCampaignRunner` now
      fixes the join, already-open session binding, explicit-root durable
      dispatch, host observation, confirmed cleanup, and finalization sequence;
      positive and identity-mismatch mock-backend tests pass. The reusable
      `serve_provider` helper and dedicated `mvm-extension-provider` executable
      own the bounded MVEX process boundary. The checked-in executable now
      injects an operator-configured `AdmittedTrialBooter` that resolves,
      re-verifies, and promotes the exact signed pack before plan admission.
      A process-level conformance test covers the real executable's `Hello`,
      `OpenSession`, `Start`, and `Shutdown` sequence. Then run the admitted
      live microVM flow, tracked by
      `specs/plans/2026-08-18-certifying-assurance-campaign-closeout.md`. The
      sibling launcher now carries an explicit absolute
      `--provider-state-root` and global `--provider-mvm-home` while clearing
      the provider environment. It restores only the selected `MVM_HOME`; MVM
      requires an exact boot-config match, rejects relative/symlink replay
      roots, and uses no ambient or temporary fallback. The concrete-provider
      lifecycle fault/recovery matrix is now complete: deadline cancellation,
      stale and closed grants, replay/idempotency, controller recovery on both
      sides of terminal commit, guest failure, host reconstruction, partial
      observation, cleanup failure, and concurrent-run exhaustion all fail
      closed under focused tests. Current focused counts are 9 lifecycle-runner,
      9 provider-controller, 7 durable adapter, 4 guest cancellation-state,
      and 27 host assurance broker tests; the durable provider journal omits
      prompt, credential, and runner-diagnostic markers and remains size
      bounded. The sibling host package now disables implicit binary discovery,
      keeping `scoutd` exclusively behind its explicit MVM-API harness. The
      sibling passes 73 workspace tests, all-target check and Clippy, formatting,
      4 pack-producer tests, and 4 guest-harness tests. The sibling-owned `scoutd` now compiles against
      MVM's canonical guest assurance API, selects only declared destination
      labels within the admitted step budget, calls only `campaign_probe.v1`,
      and emits a verdict-free candidate. MVM validates every returned
      observation against the exact invocation before host observation,
      confirmed cleanup, and finalization. Focused contract, guest, broker,
      host-session, lifecycle-runner, and provider-process tests pass, as does
      touched-crate all-target Clippy. W5.3 now carries runtime attestation
      only through a host-selected verifier: a canonical challenge binds every
      admitted identity, grant nonce/expiry, backend, and opening receipt;
      provider, challenge, enrolled-root, freshness, and lifetime mismatches
      fail closed; and a successful join emits signed attestation audit and
      receipt evidence. Seven focused tests cover the positive and refusal
      paths. The concrete provider carries its operator-selected attestation
      mode into the signed plan, refuses a required request against `noop`,
      and rejects injected verification booleans; ordinary synthesis callers
      retain the closed `noop` default. Trusted hardware attestation, the real
      KVM canary, and the full Scout-linked admitted run remain open, so current evidence is non-certifying and
      `INCONCLUSIVE`. MVM's policy identity is now a shared contract rather than a host-private
      helper: `mvm-contract` publishes `sha256:nul-separated-policy-refs-v1`
      and a deterministic vector, and host admission uses the same function.
      The sibling planner still needs to adopt that vector before the trusted
      KVM flow can proceed. Assurance admission also now requires adjacent
      guest metadata at protocol version 2 or newer, refusing the legacy
      protocol-v0 OCI rootfs before Firecracker startup. The native libkrun builder now passes a source-current
      six-disk runtime probe. Corrected Stage 0 persistent-store preparation
      completed without ext4, data-loss, or capacity errors and promoted the
      new rootfs. Its static `/sbin/mvm-setpriv` launches the automatic agent
      as UID 990 with exactly `CAP_KILL|CAP_SYS_TIME` effective and ambient and
      `NoNewPrivs=1`; the strict live result recorded capability mask
      `0000000002000020` and exit code zero. Mutable XDG, Rustup, Cargo, target,
      and temporary state use explicit `/out` paths without changing `HOME`.
      Host x86_64 Linux all-target cross-check and BDD required-feature
      compilation now pass. The source-current native Linux lane also passes
      focused sparse-store, Stage 0 prepopulation/recovery, Stage 0 binary,
      VMM, and hostd assurance tests; workspace all-target/all-feature Clippy
      and check; and BDD required-feature compilation. Its eight durable gate
      markers under
      `/nix/var/mvm/assurance-gates/2026-08-20-admission-ai-assurance-final-current`
      close item 7; the fresh run includes all 559 Linux `mvm-vmm` tests and
      72 focused hostd assurance tests and exits zero. Its source-matched VM
      state is `mvm-builder-vm-1787217398177-7306`. Hardware probing found no
      KVM or TPM2/SNP/TDX device in that builder. Exact-current probe
      `mvm-builder-vm-1787214676670-12105` found
      absent `/dev/{tpmrm0,tpm0,sev-guest,tdx_guest,kvm}`, no TSM/TDX report
      path, and an empty `/sys/class/tpm`; seven all-feature provider tests
      prove only the fail-closed `NotYetImplemented` behavior. Item 6 stays
      open pending one real trusted device and its manufacturer verifier
      collateral. The existing
      Lima test VM has KVM but no admission-visible production-safe backend in
      this checkout. Production assurance admission now rejects the configured
      `qemu` and `mock` dev/test backends before artifact or pack work; its
      focused refusal test and `mvm-hostd` all-target/all-feature Clippy pass.
      This proves the negative admission boundary, not a live KVM campaign.
      The provider now binds operator-selected attestation mode into the
      signed plan and refuses required-attestation requests when configured as
      `noop`. QEMU/mock are production-refused and QEMU is admitted only in an
      explicit non-certifying dev/test tier. The attempted native aarch64
      canary build filled the shared 68.7 GiB Nix store while realizing the
      default-tenant image; no garbage collection or pre-existing state removal
      was performed, so the live lane remains open. A follow-up isolated retry
      with a fresh 96 GiB sparse store stopped before VM startup because Stage 0
      could not resolve `releases.nixos.org` to fetch the pinned
      `nix-2.34.7-aarch64-linux.tar.xz` seed.
      Host-available MVM checks additionally pass the clean complete workspace
      test run including doctests, 1,906 hostd library tests, 64 assurance
      contract tests, workspace all-target check and Clippy, six-key schema
      emission, formatting, plan-name validation, and sprint-append validation.
      The exact parallel workspace gate is stable after isolating xtask's
      nested Cargo target, guarding environment-dependent manifest/mock-agent
      fixtures, and using a Firecracker-compatible pack in the positive
      production-booter fixture while retaining explicit `qemu`/`mock`
      refusal tests.
      The reference Scout scan and plan produced run
      `scout-1787181844-1787181844602-371467bf57b4`; the only available fixture
      provider remained non-certifying and report correlation correctly ended
      globally `INCONCLUSIVE`. Real KVM, trusted attestation, and a
      trusted-provider run remain open.
## 2026-08-21 assurance closeout evidence

The supplied native x86_64 Linux/KVM host now runs the concrete assurance
provider through a real Firecracker guest. The run uses signed pack
`sha256:f72aeb04240d16ea6c0c8a4855f3d8443006e7eb3702429af005c3718946e59d`,
plan `sha256:18a220846c25a6cec1f0b4f36dd4bfbab764f4e50671394e6da32acfcbd7ef16`,
session `s-ebc20dc44ec9937f1acc4b7c85038c1b`, grant digest
`sha256:b0991c541656cac6ebd02c27389a8b3c299b7cbadd6d4477653a0219545acf34`,
Firecracker backend, observer and cleanup receipts, and exact terminal replay
without a second VM. The result is `INCONCLUSIVE` (`attestation_verified:false`,
`attempted_effect:false`): no TPM2/SEV-SNP/TDX device or manufacturer
collateral is available. The sibling now consumes MVM's published four-reference
`sha256:nul-separated-policy-refs-v1` digest over
`operator-network-v1`, `operator-egress-v1`, `operator-fs-v1`, and
`operator-tools-v1` and emits
`sha256:5dd0de53b6d211f764728599e291e93a9491dc34f87596e906365fb74c95e0ff`.
The full Scout-linked attempt reached signed-plan admission but failed closed
before guest-agent startup on `mvm-oci-init` user-volume path-policy denial;
the exact retry replayed without a second execution. Trusted hardware
attestation and a successful typed effect probe remain open.

## 2026-08-21 FlowMux public-surface stack-order repair

The public-surface slice now carries the ingress UDP observed-peer reply fix
required by its own regression test. Outbound transform and egress admission
remain mandatory for guest-introduced UDP destinations; replies to a peer
already observed by the bounded ingress relay use that peer table instead.
The focused regression passes five consecutive runs, including the path that
rejects a forged unseen peer.

## 2026-08-21 merge-queue actionlint download retry

The pinned actionlint download now retries connection resets and other
transient transfer failures with `curl --retry-all-errors`, while retaining a
three-attempt bound, a two-second retry delay, and checksum verification. This
repairs the infrastructure-only failure that ejected the otherwise-green
aarch64 vsock permission PR from the merge queue.

## 2026-08-21 claim-18 backend-alternative witness

The scheduled Security mutation lane found that capability negotiation's
WebLinux transport arm could be deleted while a wildcard silently selected the
wrong UDS alternative. Recovery and transport alternatives now match every
`BackendKind` exhaustively, and a focused WebLinux negotiation witness requires
the browser-channel route. A missing backend arm is therefore a compile error,
while the behavior-specific test catches a wrong explicit alternative.

## 2026-08-22 AArch64 before-build loop mount repair

The merge-group AArch64 QEMU witness completed its workload build but failed
the before-build lifecycle hook because bare `mount` resolved to BusyBox.
BusyBox forwarded `loop` to ext4 instead of allocating a loop device, so the
guest powered down without returning `rootfs.ext4`. The hook runner now calls
the builder image's explicit util-linux `/sbin/mount`, with a focused constant
regression pinning that executable contract. The live lane forces a refresh of
embedded host binaries so the guest always carries the checkout under test,
even when Cargo caches are restored.

## 2026-08-23 AArch64 builder rootfs journal sealing

The merge-group AArch64 QEMU witness then reached workload activation and
proved that a hook-mutated `rootfs.ext4` could be exported with a journal that
still required recovery. Workload disks are hypervisor-enforced read-only, so
the guest correctly refused to replay that journal. The builder hook boundary
now runs offline `e2fsck` after all writable mounts are dropped, accepting only
the clean and repaired exit codes; a still-mounted or damaged image fails the
build instead of being published. Every export route also flushes the copied
artifact before reporting completion, and the builder toolchain GC roots now
retain `e2fsck` alongside `mkfs.ext4`.

A follow-up merge-group witness proved that sealing only the writable temporary
image was insufficient: the final copied artifact could still reach the
read-only workload with recovery required. Every builder publication route now
checks the destination image after the final copy and before its durability
sync. The persistent-builder shell path also preserves the hook command's real
exit status instead of the status of a negated condition.

## 2026-08-22 guest hostname generated-protocol parity

The BDD code-generation drift gate caught that the optional post-restore
hostname field had not reached the generated protocol artifacts. The protocol
schema and Python and TypeScript bindings are now regenerated from the Rust
wire type, keeping all supported SDK surfaces in parity.

## 2026-08-22 scheduled mutation witness repair

Completed Security run 32552650847 exposed seven surviving authorization
mutants in extension verification, budget narrowing, attachment, and assurance
proxy collision handling. Focused boundary and one-field-at-a-time tests now
catch the exact fail-open changes. A bounded local mutation proof caught all
20 generated mutants across those predicates and the adjacent provenance
fields; one obsolete accepted miss is removed from the ratchet.

## 2026-08-22 capture all-features closure witness

The `mvm-capture` workspace addition raises the all-features closure by exactly
one first-party node, from 469 to 470, without adding a new third-party crate.
The feature-closure ratchet and delivery evidence now record that measured
change explicitly.

The AArch64 CI witness also proved that valid ELF metadata can live beyond the
bounded inspection prefix. Capture now preserves the header evidence, omits
unread segments with an explicit warning, and continues without executing or
fully loading the discovered binary.

The clean-checkout workspace lane exposed that the `.env` redaction witness
had depended on a locally present ignored fixture file. It now creates the
secret-bearing `.env` inside a temporary project, preserving the same negative
privacy assertions while making the test deterministic in CI.

## 2026-08-22 FlowMux deletion fuzz-lock repair

The deletion slice's standalone `mvm-agentd` fuzz lock had resolved `blake3`
1.8.7, bypassing the workspace-reviewed vendored `arrayref` patch and causing
the locked invariant lane to fail closed. The lock now pins `blake3` 1.8.6;
the patch is active and the standalone all-target fuzz check passes with
`--locked`.
## 2026-08-21 FlowMux permanent-gate harness repair

The host-binary manifest integration test now reuses Cargo's prebuilt `xtask`
binary instead of starting a nested workspace compilation. The full workspace
test run therefore retains the manifest synchronization assertion without
racing concurrent doctest compilation.
## 2026-08-21 FlowMux Firecracker and CI evidence

The approved Lima-KVM Firecracker tier now boots the FlowMux-only Alpine guest
and completes an admitted TCP/DNS fetch: `example.com:80` returns the Example
Domain body with exit code zero. The post-stack CI rerun found a stale
standalone SDK fuzz lockfile and an ingress UDP regression: the active session
path applied outbound deny-all to replies for already observed ingress peers.
The lockfile is regenerated, and only guest-introduced UDP destinations pass
through outbound admission; observed-peer ingress replies remain constrained
by the relay peer table. The focused ingress test passes five consecutive
runs, the locked fuzz check passes on Rust 1.91.1, and hostd all-target Clippy
passes with warnings denied. Performance, the wider backend behavior matrix,
and libkrun evidence remain open.

## 2026-08-21 FlowMux final-evidence validation follow-up

The closeout branch now passes the complete macOS host workspace test,
doc-test, check, and formatting chain after synchronizing the Python package
root with the deleted browser helpers. The standalone SDK fuzz lock also pins
`blake3` 1.8.6 so the workspace-reviewed vendored `arrayref` patch remains in
the resolved graph; the focused supply-chain pin test and locked fuzz check
pass. These are validation repairs only: the performance decision and wider
Firecracker/HVF/libkrun live matrix remain open, so the W8 tracker and issue
#2751 remain open.

## 2026-08-22 FlowMux SDK ingress compatibility repair

The final-evidence BDD lane exposed that its old SDK snapshot retired more than
dynamic forwarding: it also overwrote typed OCI sources, boot commands,
literal environment and egress lowering, and the pinned browser/readiness
surface. Python and TypeScript now preserve those APIs while declaring opaque
loopback TCP ingress on `machine run` before boot. Dynamic forwarding still
fails closed with migration guidance, and both SDK suites cover the combined
contract. The retired guest port-forward request has also been removed from
the generated Python protocol binding, restoring schema drift checks. The same
BDD rerun exposed outer nightly-only Cargo flags leaking
into the pinned stable nested cross-compiler; nested builds now clear every
outer toolchain, wrapper, and Rust flag variable, with a focused regression
test covering the boundary.

## 2026-08-22 scheduled security-lane dependency and scanner repair

The consolidated scheduled Security workflow exposed two latent failures.
`async-trait` 0.1.92 introduced `syn` 3 beside the workspace's existing
`syn` 2 graph, so the workspace now pins 0.1.89, the last compatible release,
and cargo-deny again reports advisories, bans, licenses, and sources green.
The no-SSH source gate now recognizes capture's private-key filename denylist
as detector data and prunes generated dependency/build trees from its scan.
A shell regression proves generated dependencies are ignored while a genuine
source SSH token is still rejected.

The same scheduled run measured new AI-policy and FlowMux mutants. Constructor
tests distinguish metered policy from the disabled default, while focused
FlowMux witnesses now pin ingress generation teardown, authentication-gated
readiness, the exact consecutive-accept failure ceiling, and Linux confinement
input refusal. Only the constructor replacement that is byte-for-byte
equivalent to `Default` is accepted with a recorded rationale.

Two later hostd shards showed that the generic `substitute` witness name was
mutating an entire 4,700-line proxy module. Its surface is now limited to the
claim-relevant substitution adapter and request-preparation boundary: three
mutants were measured, two caught and one unviable. Audit witnesses also pin a
zero-line checkpoint's genesis fallback and the exact accountable-prune entry
count; remaining equivalent or performance-only misses carry explicit reasons.
The final hostd shard's broker witness now asserts every teaching response up
to the configured ceiling and the first terse response immediately after it.

## 2026-08-24 transient start console diagnostic closeout

- [x] Emit the guest console diagnostic before transient startup cleanup removes
      the machine state directory.
- [x] Preserve cleanup and return the original backend startup error.
- [x] Record the delivered behavior in
      `specs/sprint/delivery/2819-transient-start-console-diagnostic.md`.

## 2026-08-24 stopped-machine log diagnostic closeout

- [x] Distinguish a missing machine state directory from other output-capture
      failures when `machine logs` has no readable source.
- [x] Name the inspected state directory and direct operators to `machine ls`
      instead of exposing the raw stream error.
- [x] Cover the missing-state path with focused CLI regression tests and record
      the delivery in `specs/sprint/delivery/2824-stopped-vm-logs-error.md`.

## 2026-08-24 retained-state log diagnostic closeout

- [x] Distinguish retained machine state with missing captures from a removed or
      never-booted machine.
- [x] Name each missing capture source and direct operators to `machine inspect`
      for the persisted machine.
- [x] Cover the retained-state path with a focused CLI regression test and record
      the delivery in `specs/sprint/delivery/2825-retained-state-logs-error.md`.

## 2026-08-24 missing-state recovery guidance closeout

- [x] Give the missing-state `machine logs` error a concrete `machine ls`
      recovery command.
- [x] Pin the recovery guidance in the focused CLI regression test.
- [x] Record the delivery in
      `specs/sprint/delivery/2826-missing-state-logs-recovery.md`.

## 2026-08-23 FlowMux forward-proxy identity repair

- [x] Move the secret-substitution forward proxy out of the workload-uid guest
      agent and into an init-owned helper that can read the root-only FlowMux
      signing key on both guest init paths.
- [x] Ship the helper in baked and runtime-overlay artifacts, fail overlay
      validation when it is missing, and preserve the shared-kernel Unix-socket
      endpoint path.
- [x] Log the privileged relay failure chain while returning only a stable,
      non-sensitive failure class to the workload.
- [ ] Capture the live secret-bearing `OpenHttp` substitution witness; the
      owning FlowMux plan keeps that hardware-backed acceptance item open.

## 2026-08-23 Nix guest FlowMux identity handoff

- [x] Move the Nix guest's identity-drive mount into a short root-owned Rust
      provisioning action before the long-lived egress process drops privilege.
- [x] Reserve service uid 989 for the 0400 signing key; refuse uid collisions
      with the workload, guest agent, or optional builder.
- [x] Keep the egress parser under `no_new_privs` with only
      `CAP_NET_BIND_SERVICE`; do not retain mount capability.
- [x] Cover the ordering and capability boundary structurally, plus valid and
      invalid provisioning command modes in unit tests.
- [x] Preserve networkless guest boot by making an absent identity optional
      only when vsock egress is not requested; unreadable and required
      identities remain fail-closed.

# Refactor status

Last updated: 2026-09-03

## In progress

- [ ] **Release-artifact authenticity and provenance.**
      `specs/plans/2026-09-03-release-artifact-authenticity-and-provenance.md`.
      WS-A registers the shipped signature chain as `MVM-SEC-20`, precisely
      distinguishing directly signed archives from raw blobs authenticated by
      signed checksum manifests and recording the weaker self-update posture.
      The generated conformance ledger and all 68 policy/model gates are green;
      provenance and checksum-policy decisions remain in WS-B and WS-C.

- [x] **Persistent host-directory snapshots.**
      `specs/plans/2026-09-02-retire-dirshare.md`.
      Ad-hoc `--host <directory>` registration now creates a private ext4
      snapshot on verified encrypted backing and registers it as a block
      volume. Focused materialization, validation, error-path, launch-lease,
      full workspace, and BDD tests are green; merged via #3151.

- [ ] **Workload output affordance — durable writable inline disks.**
      `specs/plans/2026-09-02-workload-output-affordance.md`.
      Foreground transient runs now flush writable disks through the existing
      authenticated guest-agent `SleepPrep` request before forced teardown.
      The OCI-safe handler uses `sync(2)` directly, shares that implementation
      with the detached exit reporter, treats a failed flush as a run failure,
      and holds caller-owned image locks through teardown. Sized writable disk
      mounts are admitted while directory snapshots remain read-only. A
      no-explicit-sync write survived a second fresh Alpine VM on macOS HVF;
      gated compilation, the full workspace nextest suite, doc tests, all-targets Clippy,
      policy checks, and BDD are green. Broader surface design and merge remain.

- [x] **Refresh host-directory snapshots at machine start.**
      `specs/plans/2026-09-03-refresh-host-snapshot-at-start.md`.
      Persistent `--host` and transient `--mount` share one verified,
      content-addressed ext4 image cache. Start-time source fingerprints cover
      emitted filesystem semantics, changed snapshots refresh before lease
      acquisition, missing sources refuse, and writable consumers receive
      private copies. The unbounded block-at-a-time writer verifies each file
      against its walked digest, and cache initialization separately verifies
      encrypted destination backing. The live README BDD fixture declares its
      encrypted-backing prerequisite without bypassing production probes.
      Workspace tests/check, host and Linux-native Clippy,
      gated compilation, and hermetic BDD are green. A live Firecracker
      restart observed changed bytes even when the source mtime was preserved.
- [x] **Cargo target-dir guard.**
      `specs/plans/2026-09-02-cargo-target-dir-guard.md`.
      Both cargo wrapper scripts reclaim a CARGO_TARGET_DIR pointing outside
      the current source tree — the compile-time sibling of the stale-helper
      bug, observed as an E0063 naming a field deleted by a merged PR, served
      from rlibs in a shared target dir inherited from unrelated work. Policy
      mirrors dev-env.sh: inside-tree values honored, outside-tree values
      reclaimed loudly, MVM_DEV_ENV_KEEP_INHERITED=1 keeps them anyway. Gate
      tests and CI shellcheck green; merged via #3135.
- [x] **Aux host-helper contract verification.**
      `specs/plans/2026-09-02-aux-helper-contract.md`.
      Host helpers answer a `--contract-version` probe and `mvmctl` verifies
      the answer before spawning: a stale helper in a source checkout is
      rebuilt in the running binary's profile, and any other stale pick is a
      hard error naming both contract versions and the rebuild command,
      replacing the recurring silent cross-profile fallback that surfaced as
      an "unknown field" spawn failure. A `HvfSupervisorConfig` shape pin
      forces the contract version to bump with the schema. A freshly rebuilt
      helper gets one retry only when its first bounded probe times out,
      covering the observed macOS first-launch transient without accepting a
      malformed or wrong-version helper. Focused
      regressions, affected crate suites, zero-warning Clippy, and Linux/BDD
      gated compilation are green; merged via #3132.

- [ ] **Supply-chain evidence carryover (WS1.1 + WS1.4 + WS2.1 + WS3.1).**
      `specs/plans/2026-09-02-supply-chain-evidence-carryover.md` on
      `feat/supply-chain-evidence`. Boot-liveness beacon recorded as a
      chain-signed `lifecycle.beacon_reported` entry; local deploy store
      gains its first read path (`mvmctl deployments ls`); sealed OCI
      rematerializes now write a JCS+Ed25519 provenance mark into the
      rootfs before verity hashing (`/mvm/provenance.json` + detached
      signature) and an in-toto/SLSA v1 DSSE sidecar (`rootfs.intoto.json`)
      beside the sealed image. Cross-repo items (mvmd registry/queries,
      studio pages, scout verification) remain open in the plan.

- [ ] **Signed caller commitment — issue #3070.**
      `specs/plans/2026-09-01-signed-caller-commitment.md`.
      Replaces reliance on overwriteable free-form audit labels with one typed,
      opaque 32-byte commitment covered by the plan identity/signature and
      copied into chain-signed audit entries. Workspace tests, zero-warning
      Clippy, Linux/BDD gated checks, frozen-wire compatibility, and the full
      non-live BDD suite are green; merge delivery remains.

- [x] **Contributor SDK-sidecar recovery guidance.**
      `specs/plans/2026-09-01-contributor-sidecar-recovery.md`.
      The source-checkout recovery path now distinguishes debug and release
      embedded binaries, repairs the pinned macOS rust-objcopy loader at the
      compiler boundary, reports actionable sidecar provenance only when a
      sidecar is actually selected, treats owned endpoint SIGTERM as teardown,
      builds the native HVF helper beside the same-profile embedded `mvmctl`,
      bounds and streams unfiltered directory snapshots, tolerates vanished
      live-tree entries, and versions host-side injection semantics directly
      in the cached OCI root tag so a still-valid guest-binary digest sidecar
      cannot leave Rust's Cargo environment stale. Host
      workspace validation and the release embed witness are green; no live VM
      command was run outside the builder VM.

- [ ] **Mounted PTY image environment.**
      `specs/plans/2026-09-01-mounted-pty-image-environment.md`.
      Mounted absolute PTY commands now reach the guest console directly, so
      an image login profile cannot erase the OCI-declared `PATH`. Focused,
      workspace, Clippy, gated-target, formatting, and non-live BDD checks are
      green; the live Rust directory-share witness and merge remain.

- [ ] **Extended CI residual regressions — issues #3051 and #3052.**
      `specs/plans/2026-08-28-extended-ci-red-repair.md`.
      Persistent launches clamp vCPUs before admission, authenticated frame
      reads preserve retryable I/O sources. Focused regressions are green;
      broad validation and merge delivery remain.

- [ ] **Warm claim authenticated readiness — issue #3039.**
      `specs/plans/2026-08-31-warm-claim-authenticated-readiness.md`.
      A restored child advances only after an authenticated Ping proves its
      guest agent is serving; accepted-but-silent transports stay in the bounded
      readiness loop. Explicit warm residency now fails closed on a rejected
      claim, while auto-detected warm residency may retain its cold fallback.
      Workspace tests, zero-warning Clippy, Linux/BDD gated compilation, and
      policy checks are green; merge delivery remains.

- [ ] **Flake workload exit-code propagation — issue #3041.**
      `specs/plans/2026-08-31-flake-exit-code-propagation.md`.
      Empty manifest argv now means the image owns execution: the run path
      waits for the backend's sealed workload result, preserves its nonzero
      exit code, and rejects a missing report. Focused regressions, the
      workspace suite, zero-warning Clippy, workspace check, and gated-target
      compilation are green; merge delivery remains.

- [ ] **Egress refusal status contract — issue #3040.**
      `specs/plans/2026-09-01-egress-refusal-status.md`.
      FlowMux now distinguishes a policy refusal (`403 Forbidden`) from an
      admitted target whose upstream connection failed (`502 Bad Gateway`) on
      the wire, with a behavior-revision bump and focused host/guest protocol
      regressions. Workspace tests, Clippy, formatting, gated-target checks,
      and documentation gates are green; merge delivery remains.

- [ ] **Published musl SDK sidecar — issue #3045.**
      `specs/plans/2026-08-31-publish-musl-sdk-sidecar.md`.
      SDK sidecar release names now bind architecture and libc; both release
      trains require, attach, sign, and consume glibc and musl artifacts for
      both architectures. Focused downloader, release-contract,
      workflow-syntax, consumer-example, workspace, Clippy, gated-target,
      formatting, and policy validation is green; merge delivery remains.

- [~] **Documented-example parse-tier promotion.**
      `specs/plans/2026-08-30-doc-example-parse-tier-promotion.md`.
      `machine diff` now reuses the authenticated control session and joins
      `machine proc start` in the live journey; both website commands moved to
      the covered ledger and the parse-tier pin fell from 65 to 63. The full
      hermetic BDD gate is green (241 passed, one capability skip). Merge
      delivery and the remaining five journey-batch A verbs remain.

- [ ] **Wasmtime security update — issues #3018 and #3020.**
      `specs/plans/2026-08-31-wasmtime-security-update.md`.
      The complete optional Wasmtime dependency family is locked to patched
      46.0.3, removing the two vulnerabilities reported by the scheduled
      Security lane. All 897 feature-enabled runtime tests, Clippy, and the 62
      policy gates are green; merge delivery and fresh scheduled Security and
      claim-freshness evidence remain.

- [ ] **Default-backend host-services broker witness — issue #2988.**
      `specs/plans/2026-08-28-default-backend-broker-witness.md`.
      The live SDK broker fixture is now a read-only ext4 disk instead of a
      virtio-fs directory share, and the refusal scenario names the broker's
      `not bound` result. A separate top-level mount/timeout scenario preserves
      the website-command coverage ratchet. Focused coverage, BDD compilation,
      workspace tests, zero-warning Clippy, formatting, and policy gates are
      green; live Firecracker/HVF evidence and merge delivery remain.

- [x] **Remove virtio-fs — `specs/plans/2026-08-31-remove-virtio-fs.md`.**
      Stage A: `--mount` is materialized into an ext4 image and attached as
      virtio-blk, the directory-share capability seam is gone, and the runtime
      `VmVolumeKind::DirShare` / local `Directory` variants are retired while
      signed plans retain `ShareKind::DirShare` for claim 1. Workspace, gated,
      and BDD checks plus a live Firecracker `machine run --mount` witness are
      green. Stage B: the
      dev-tier virtio-fs root is deleted end to end — the tier gate, the
      capability, the launch-config field, the driver bootargs arm, and the HVF
      device model's root channel including the `MVM_HVF_VIRTIOFS_ROOT` env hook
      that bypassed the gate. Stage D (`xtask check-no-virtio-fs`) landed early
      as a ratchet rather than last. Stage C was never blocked on how `out`
      returns artifacts — `builder_disk_transport` had already solved it as a
      raw tar on a disk, needing no host-side ext4 reader — and its QEMU half
      has landed: both one-shot QEMU builder sites carry job and artifacts over
      that transport, with the `virtiofsd` spawn loops, the shared memory
      backend and the `vhost-user-fs-pci` devices deleted. Widening the gate's
      pattern to the `add_virtio_fs` spelling and the `virtiofsd` spawn side
      took it from 23 pinned sites to 54. The QEMU *workload* driver's share arm
      then became a refusal mirroring Firecracker's, which left
      `crates/mvm-vmm/src/host/virtiofsd.rs` with no consumers: deleted, along
      with `mvm-vmm`'s `which` dependency and the `--sandbox none` flag that
      started the plan. `specs/plans/2026-08-31-virtiofsd-sandbox-parity.md` is
      superseded by that deletion.
      The persistent HVF builder has moved too: `persistent_builder_spec`
      declares no shares, readiness moved from a marker file inside the (now
      unshared) `/job` onto a dispatch round trip, and the host rewrites the
      input disk per `Run` and reads the output disk per `Result`. Live-validated
      on macOS 26.5.2 — two `nix build` dispatches into one session, both exit 0.
      A live persistent Firecracker BDD
      witness now pins the remaining unmaterialized-directory behavior: the
      registry is consumed, and the workload runner refuses before boot because
      it cannot express the directory grant. That settles reachability without
      pretending the managed-directory product decision is complete.
      The final libkrun work materializes Stage 0's `RootDir` as ext4, carries
      Stage 0 and one-shot inputs/artifacts as raw-tar block disks, moves the
      persistent builder and install output arm onto the same transport, and
      replaces libkrun's share mapping with a refusal. A forced Stage 0 rebuild
      and a real `machine build --builder libkrun` both completed on Apple
      Silicon with `root_dir: null` and `virtio_fs_mounts: []`. The exact stale-
      pin gate is now at its intended floor: 19 sites across 6 files (16 C-API
      declarations, the low-level share type, and the QEMU/Firecracker refusal
      tests).

- [ ] **Warm standby image claim repair — issue #3002.**
      `specs/plans/2026-08-28-warm-standby-image-claim.md`.
      Block and virtiofs roots were distinct standby compatibility shapes, so
      HVF's read-only OCI dev root could claim only a parent that booted the
      same device model. The virtiofs root has since been removed
      (`specs/plans/2026-08-31-remove-virtio-fs.md` Stage B); the compat key
      still compares the recorded strategy, because a parent warmed before that
      removal declares its own on disk. The cross-platform witness explicitly warms capacity in the
      artifact-warm home and checks request-state cleanup against a baseline.
      Workspace tests, all-target/all-feature Clippy, Linux- and BDD-gated
      checks, formatting, and policy gates are green. The required eBPF lane's
      signed-audit regression now verifies authenticated labels exactly; live
      CI witnesses and merge delivery remain.

- [ ] **Linux 6.12.107 synchronized kernel pin — issue #2971.**
      `specs/plans/2026-08-28-kernel-6-12-107.md`.
      Both kernel consumers use the kernel.org-verified archive and SRI hash;
      structural tests and workspace Clippy are green. Linux Nix builds and
      merge delivery remain.

- [ ] **Portable dev-VM socket resolver test — issue #2973.**
      `specs/plans/2026-08-28-portable-dev-vm-socket-test.md`.
      The test now asserts the canonical state-or-short socket namespace; the
      focused regression, all 598 `mvm-vmm` tests, workspace tests, and
      workspace Clippy are green. Merge delivery remains.

- [ ] **Worker restart identity barrier — issue #2976.**
      `specs/plans/2026-08-28-worker-restart-identity-barrier.md`.
      Recovery assertions now begin only after the old worker PID has been
      replaced by a live supervisor-published identity. The focused and
      workspace validation gates are green; merge delivery remains.

- [ ] **Wasm SDK host-service admission — issue #2977.**
      `specs/plans/2026-08-28-wasm-sdk-host-service-admission.md`.
      Wasm now refuses the native SDK-sidecar mechanism at the backend-aware
      admission seam instead of leaking a disk-volume backend error. Focused
      regressions, the gated BDD runner, workspace tests, isolated doctests,
      workspace Clippy, formatting, and policy gates are green. Merge delivery
      remains.

- [ ] **Security lane red repair — issues #2982 and #2986.**
      `specs/plans/2026-08-28-security-lane-red-repair.md`.
      The scheduled supply-chain failure is repaired with non-yanked
      `chacha20 0.10.2`; a lockfile regression pins it. Libkrun's vCPU ceiling
      now has a mutation witness, and eight stale baseline exemptions are
      removed. Focused tests, workspace tests, isolated doctests, workspace
      Clippy, formatting, `cargo deny`, and policy gates are green. A fresh
      Security run and merge delivery remain.

- [ ] **Extended CI red repair — issues #2979 and #3007.**
      `specs/plans/2026-08-28-extended-ci-red-repair.md`.
      Linux helper compilation is platform-scoped, clean runners install the
      SDK prerequisites and warm the source sidecar, installed bundle SHA-256
      values reach the shared slot-or-bundle dispatcher, and the live macOS
      witness targets an Intel runner with HVF access without pulling the
      arm64-only libkrun firmware path. The Linux witness also grants QEMU read
      access to the hosted kernel and initramfs and takes ownership of the
      vhost-vsock device before the Stage 0 sidecar build. QEMU extraction now
      copies the complete sidecar bundle without restoring guest ownership.
      The Intel witness installs QEMU and selects it for Stage 0 artifact
      construction, retaining HVF for workload execution and avoiding the
      unavailable libkrun host library.
      The newest Linux follow-on installs `virtiofsd`, grants unprivileged
      ICMP sockets to the runner group, and threads the documented service-plane
      ext4 fixture through transient launch resolution as a read-only block
      volume while retaining fail-closed directory-share capability checks.
      The latest rerun showed the warm-up reused an existing universal
      initramfs without validating its guest-source fingerprint. It now always
      enters launch resolution, evicting stale guest agents before the live
      suite. Firecracker declares its u8 vCPU wire ceiling, and the refusal
      witnesses now assert the actual child/status-channel contracts.
      Focused tests, workspace tests, isolated doctests, workspace Clippy,
      formatting, and policy gates are green. A fresh Extended CI run and merge
      delivery remain.

- [ ] **HVF machine restore dispatch — issue #2961.**
      `specs/plans/2026-08-27-hvf-machine-restore-dispatch.md`.
      The `machine` fork/restore surfaces now share the backend-origin
      dispatcher with `vm checkpoint fork`, preserving the machine surface's
      Firecracker opt-in without misrouting HVF checkpoints. Focused dispatch
      regressions are green, and a live two-to-one-vCPU mismatch refuses before
      restore-target construction. The successful live two-vCPU child witness
      and merge delivery remain.

- [ ] **Recorded-backend pause and resume — issue #2929.**
      `specs/plans/2026-08-27-recorded-backend-pause-resume.md`.
      Pause/resume now resolves the live machine's owner before dispatch while
      retaining Firecracker's sealed snapshot path and explicit marker-less
      backend fallback. Validation and merge-queue delivery remain.

- [ ] **Audit root-history classification repair — issue #2940.**
      `specs/plans/2026-08-27-audit-root-history-classification.md`.
      Signed Merkle-root history files are excluded from lifecycle-chain
      sweeps through one shared suffix; focused and workspace tests, doctests,
      check, and Clippy are green, and merge-queue delivery remains.

- [ ] **SDK sidecar source build — issue #2941.**
      `specs/plans/2026-08-27-sdk-sidecar-source-build.md`.
      Source checkouts can explicitly build the guest-facing glibc sidecar
      through the shared Stage 0 artifact runner and atomically bind it to the
      checkout fingerprint. An unembedded SDK-sidecar command now re-executes
      its complete build in the isolated source helper carrying the opt-in
      embedded Linux payload, and the documented-surface E2E suite exercises
      that cold-cache handoff. A live aarch64 cold run completed Stage 0/Nix
      and cached both libc variants through the HVF builder. Focused regressions
      plus workspace check/tests, formatting, and zero-warning Clippy are green;
      merge delivery remains.

- [ ] **Issue #2942 — warm-launch gate contract repair.**
      `specs/plans/2026-08-27-warm-launch-gate-contract.md`.
      The live warm-residency witness now consumes the CLI's strict sub-300 ms
      hard ceiling rather than a prepared-cold 200 ms literal. Focused boundary
      and BDD compilation checks, workspace tests, check, Clippy, formatting,
      and repository gates are green; merge-queue delivery remains.

- [ ] **Extended CI documented-surface repair — issues #2938 and #2979.**
      `specs/plans/2026-08-27-extended-ci-documented-surface.md`.
      Both scheduled platform witnesses now build signed-manifest verification
      through the standard link path, and the macOS HVF lane installs its
      embedded Linux cross toolchain. The explicit published-image choice now
      reaches builder bootstrap, macOS downloads its workload kernel, and the
      source-matched SDK-sidecar job runs inside that fetched image under HVF
      instead of ARM-only libkrun or Linux-host QEMU Stage 0. Focused tests and
      Clippy are green; the live rerun and merge delivery remain.

- [ ] **Cloudflare Pages cutover.**
      `specs/plans/2026-08-27-cloudflare-pages-cutover.md`.
      The existing Pages project and account now have a checked-in Wrangler configuration,
      reproducible local/CI deployment commands, an account/project preflight,
      a shared and tested complete-WebLinux-bundle gate, and a verified
      deployment.
      The production hostname still needs to be attached to the project.

- [ ] **Cold-boot guest wall clock — issue #2956.**
      `specs/plans/2026-08-27-cold-boot-wall-clock.md`.
      The active universal-initramfs PID 1 now consumes the host epoch before
      trust validation or workload activation. Strict shared parsing and the
      existing narrow clock-sync path have focused positive and refusal tests;
      workspace tests, gated targets, and zero-warning Clippy are green. Merge
      delivery remains.

- [ ] **SDK surface contract repairs — issues #2902 and #2906.**
      `specs/plans/2026-08-26-sdk-surface-contract-repairs.md`.
      The README's `mvm.local_path` decorator source and the builder-pack Cargo
      feature remediation are implemented and locally green; merge-queue
      delivery remains.

- [ ] **Flake-built slot resolution — issue #2967.**
      `specs/plans/2026-08-28-flake-slot-resolution.md`.
      Strict materialized slot addresses resolve through the existing registry;
      unknown and identity-mismatched records fail closed. Focused and workspace
      tests, gated-target compilation, and Clippy are green; merge delivery
      remains.

- [ ] **Receipt-attached resource utilization.**
      `specs/2026-08-28-receipt-attached-resource-utilization.md` /
      `specs/plans/2026-08-28-receipt-attached-resource-utilization-implementation.md`.
      Every backend's `plan.exited` receipt now carries measured CPU, memory,
      host-state, and wall-clock usage in `extensions["mvm.usage"]`, sourced
      from a `workload.usage` sidecar the libkrun supervisor, HVF vCPU threads,
      and the host's own exit report each populate. Firecracker and QEMU
      observe neither CPU nor memory (neither VMM is a process this host
      reaps). All ten tasks are implemented; see
      `specs/sprint/delivery/receipt-attached-resource-utilization.md` for the
      per-backend coverage table and stated limits. Full workspace gate green
      apart from the pre-existing macOS-only
      `dev_vm_connects_via_libkrun_per_port_socket` failure; merge-queue
      delivery remains.

## Completed

- [x] **Signed caller commitment — issue #3070, PR #3076.**
      `specs/plans/2026-09-01-signed-caller-commitment.md`.
      Replaces reliance on overwriteable free-form audit labels with one typed,
      opaque 32-byte commitment covered by the plan identity/signature and
      copied into chain-signed audit entries. Workspace tests, zero-warning
      Clippy, Linux/BDD gated checks, frozen-wire compatibility, and the full
      non-live BDD suite were green before merge. Landed on main as
      `8623950746`; issue #3070 is closed.

- [x] **SDK sidecar selection from the image's own libc — issue #2969, PR #3060.**
      `specs/sprint/delivery/sdk-sidecar-image-libc-selection.md`.
      Closes the half #3044 named as remaining: the variant is chosen from the
      libc the image recorded at materialization rather than from a catalogued
      runtime's declaration, so an arbitrary `--image` selects correctly instead
      of being refused as unknown. One resolution still feeds both the plan
      grant and the attached volume, now through `AdmitInputs`. The declaration
      keeps a job as a cross-check against the observed value, and the resolver
      proves a cached artifact's libc from its own `DT_NEEDED` rather than from
      the path it was filed under. Workspace tests, gated targets, Clippy and
      the live `host.kv.v1` witness were green before merge. Landed on main as
      `e79b366c98`.

- [x] **Kernel cache moved out of the Stage 0 blast radius — PR #3038.**
      `specs/sprint/delivery/kernel-cache-outside-stage0-blast-radius.md`.
      The workload kernel was cached inside `builder-vm/<arch>`, the directory
      Stage 0 `remove_dir_all`s on a source-fingerprint change, so promoting a
      new builder image destroyed a half-hour artifact and the next boot rebuilt
      it — blowing `just e2e-launch`'s 1800s cap. Entries now live at
      `<cache>/kernels/<arch>/<variant>/`; `resolve_kernel` adopts an entry left
      at the old path by renaming it. The layout was hand-rebuilt at nine call
      sites, all now routed through `kernel_cache_dir`/`cached_kernel_path`. The
      gate's builder cap is raised to 7200s, matching `ci-full.yml`. Merged
      after a live macOS 26 `e2e-launch` run confirmed the migration is a rename
      rather than a rebuild.

- [x] **machine diff handshake retry — issue #3024, PR #3028.**
      `specs/plans/2026-08-31-machine-diff-handshake-retry.md`.
      A typed pre-authentication peer hangup gets one fresh connection; an EOF
      after authentication is never replayed. Focused regressions cover both
      boundaries and the bounded retry budget.

- [x] **Fleet stream edge delivery handoff.** The edge pump now terminates in
      the bounded, exactly-once guest input route; close carries the scanner's
      withheld tail before EOF. `StreamPlane::subscribe` and
      `LaunchOutcome::admitted` provide the two narrow capabilities the
      external fleet supervisor needs without re-admission or guest
      addressing. mvmd PR #238 now drives those capabilities in a bounded
      production workflow, and the three fleet-only dormant declarations have
      been removed.

- [x] **Linux 6.12.106 synchronized kernel pin — issue #2931.**
      `specs/plans/2026-08-27-kernel-6-12-106.md`.
      Both kernel consumers use the kernel.org-verified archive and SRI hash;
      local and merge-queue gates passed, PR #2939 merged, and issue #2931
      closed through the PR link.

- [x] **Workload address public API rename.** The unused UOR-ADDR pilot is now
      exposed as `mvm_core::{WorkloadAddress, WorkloadAddressError,
      WorkloadAddressParseError, workload_address}` and the
      `mvm_core::workload_address` module. CLI and BDD vocabulary use workload
      address throughout; no deprecated semantic-name aliases remain.

- [x] **Site QEMU-WASM release artifact** —
      `specs/plans/2026-08-26-site-qemu-wasm-release-artifact.md`.
      The browser QEMU pack now builds on the `boot-image/v*` release cadence;
      Cloudflare Pages consumes the signed, checksummed release artifact while
      retaining the current revision's demo shell. Its oversized WASM module is
      staged as an explicitly decompressed gzip payload so it fits Cloudflare's
      per-file limit. GitHub CLI receives the semantic-version filter directly
      through `--jq` in both consuming workflows, with a regression contract
      against the unsupported standalone jq `-r` flag. Workflow contracts,
      actionlint, and Clippy are green.

- [x] **AI egress metering and token budgets** —
      `specs/plans/2026-08-21-ai-egress-metering-and-budget.md`.
      Provider-reported token counts (OpenAI + Anthropic) at the host
      substitution endpoint, per-VM Prometheus metrics, audit records, and an
      optional token budget that refuses further AI egress when exhausted.
      Phases 1–6 complete and green (`cargo check`, `cargo clippy`,
      `just check-gated`, unit/integration tests, and SDK tests). Builds on
      Plan 313's seam; does not cover streaming relay or compaction.

This is the cross-plan progress index. The owning plan remains authoritative
for detailed scope and acceptance criteria.

## Completed issue closeouts

- [x] **Issues #3051 and #3065 — a vCPU ceiling is the VMM's, not the wire
      format's.** The Firecracker and libkrun drivers both declared
      `max_vcpus: Some(u8::MAX)`, reasoning from the count being a byte on the
      wire. Neither VMM boots that many, so the clamp above the backends
      faithfully produced a count that would not run and `--cpus 9999` failed
      on both while passing on HVF, which asks the host for its ceiling instead
      of deriving one from a type. Each driver now declares what it actually
      boots — Firecracker 32, probed against the API; libkrun 64, measured,
      since `krun_get_max_vcpus()` forwards KVM's 4096 while libkrun aborts at
      65 — and holds the value handed to the VMM to that same constant. The
      reporting clamp stays a single call site above the backends.
      Live-witnessed on x86_64 Linux/KVM. See
      `specs/sprint/delivery/vcpu-ceilings-are-the-vmms-not-the-wires.md`.
      Followed by `xtask check-vcpu-ceilings`, which refuses a `max_vcpus`
      derived from an integer type's `MAX` so a fourth backend cannot reach the
      same wrong conclusion two authors already reached independently. Wired
      into `check-all`, so it runs on every PR. See
      `specs/sprint/delivery/vcpu-ceiling-gate-refuses-wire-type-limits.md`.
      Closed out by issue #3099, which asked the same question of the fourth
      backend and answered it the other way: QEMU declares no ceiling on
      purpose. Its limit belongs to the machine type (255 on the x86_64
      default, 288 reported for q35, 512 on aarch64 `virt`) and the driver
      names no machine on x86_64, so any constant is the distribution's to
      change; querying is worse, since `query-machines` reports a `cpu-max` for
      q35 that the same machine refuses to start; and no host-side ceiling is
      observable anyway, because the guest kernel's `CONFIG_NR_CPUS` binds
      first at 64. A clamp warning is truthful only where the declared ceiling
      is the binding one, which is true on Firecracker and libkrun and never on
      QEMU. See
      `specs/sprint/delivery/qemu-declares-no-vcpu-ceiling-on-purpose.md`.

- [x] **virtiofsd sandbox parity — issue #3022.**
      `specs/plans/2026-08-31-virtiofsd-sandbox-parity.md`.
      The shared QEMU helper selects the namespace sandbox explicitly for both
      Rust and C daemon flavours, and focused argv tests prevent either
      implementation from silently losing confinement. PR #3026 passed its
      merge-group gates and landed on 2026-08-31.

- [x] **Issue #2951 — ad-hoc exec honors the image environment.** Streaming
      exec now uses the shared workload resolver, so image-declared `PATH`,
      variables, and working directory reach `run -- <cmd>` while inherited
      agent variables and the writable workload `HOME` retain their established
      semantics. An unreadable image config degrades to the prior behavior. See
      `specs/sprint/delivery/2951-ad-hoc-exec-image-environment.md`.

- [x] **Issue #2930 — FlowMux HTTPS live-client repair.** The seven live HTTPS
      egress witnesses use the pinned multi-arch `curlimages/curl:8.21.0`
      client so HTTPS is carried through an HTTP `CONNECT` tunnel. The
      fail-closed refusal of plaintext HTTPS absolute-form requests is
      preserved and protected by a repository regression. See
      `specs/sprint/delivery/egress-https-absolute-uri-refusal.md`.

- [x] **Issue #2887 — guest RPC refusals and SDK live-profile propagation.**
      Filesystem and process unary calls now preserve universal policy
      refusals as typed errors. The live SDK carries an explicitly selected
      dev profile into its nested machine launch while an omitted profile
      remains standard, and Python/TypeScript share one generated environment
      name plus the same validated argv contract. See
      `specs/sprint/delivery/2887-guest-rpc-refusals.md`.

- [x] **Issue #2888 — HVF vCPU resource contract.** HVF implements SMP: the
      vCPU count reaches the process that creates them, the FDT describes N
      `cpu@N` nodes, PSCI `CPU_ON`/`AFFINITY_INFO` answer against the CPUs that
      exist, and each secondary runs on its own thread against a mutex-guarded
      device model. A request above the backend's declared ceiling
      (`VmCapabilities::max_vcpus`; HVF 4, libkrun 255, firecracker none) is
      clamped with a warning rather than refused, so a portable `--cpus` does
      not fail on one host and succeed on another. The ceiling of 4 is measured,
      not derived — tracked as #2927. Supersedes the earlier refusal contract in
      `specs/sprint/delivery/2888-hvf-vcpu-contract.md`; see
      `specs/sprint/delivery/hvf-smp-cpus-honoured.md`.

- [x] **Issue #2874 — scheduled Security peer-policy mutation witness.**
      `NetworkPolicy::peers()` now has a focused witness that distinguishes
      both policy variants carrying an admitted peer from the deny-all empty
      default. The exact surviving empty-slice mutant from Security run
      32931995875 is caught; the second generated replacement is unviable.
      Issue #2875 remains open as the scheduled-evidence tracker until the next
      scheduled Security run records the repaired lane. See
      `specs/sprint/delivery/2874-security-peer-policy-witness.md`.

- [x] **Issues #2841 and #2842 — scheduled security evidence is executable.**
      Sealed-production policy witnesses now follow the refactored agent
      modules and the `mvm-contract` source of truth. A contributor-checkout
      witness catches the runtime-overlay predicate mutation, obsolete
      accepted misses are removed, and the non-Linux confinement compatibility
      stub can no longer mask mutations of Linux fail-closed confinement. See
      `specs/sprint/delivery/2841-security-claim-witness-repair.md`.

- [x] **Missing-state log recovery guidance.** The lifecycle-aware
      `machine logs` failure now gives operators the concrete `machine ls`
      command for verifying whether the named machine still exists, with a
      focused assertion preventing the recovery step from regressing. See
      `specs/sprint/delivery/2826-missing-state-logs-recovery.md`.

- [x] **Retained-state log diagnostics.** When a machine state directory
      survives but every output capture is absent, `machine logs` now names
      the retained state, each missing source, and the likely interrupted-boot
      or manual-cleanup cause. Operators are directed to `machine inspect` for
      the persisted machine. See
      `specs/sprint/delivery/2825-retained-state-logs-error.md`.

- [x] **Stopped-machine log diagnostics.** `machine logs` now distinguishes a
      missing machine state directory from other capture-source failures,
      reports the path it inspected, and directs operators to `machine ls`
      instead of surfacing the raw stream error. Focused CLI tests preserve the
      missing-state behavior. See
      `specs/sprint/delivery/2824-stopped-vm-logs-error.md`.

- [x] **The guest resolves a bare `argv[0]`.** The README documents
      `commands.start(["python", …])` and `exec("uname", …)`, the SDK forwards
      argv verbatim, and the guest refused any non-absolute `argv[0]` — so the
      documented form could not run, while its sibling `exec` accepted it. A
      bare name now resolves against the image's declared `PATH` (the search
      `exec` already used), a relative path stays refused, and the request's own
      `PATH` is never consulted. #2887's grant half turned out to have been
      fixed already, so the scenario is `@live` and its README example is a real
      witness. See `specs/sprint/delivery/guest-resolves-bare-argv0.md`.

- [x] **Skipped scenarios fail a gating lane; website coverage ratcheted.**
      `MVM_BDD_STRICT_SKIPS` turns the skip tally into a gate with a per-lane
      allow-list, so a runner that quietly loses a capability reddens the lane
      instead of reporting a pass that proved less than the last one. Stable
      skip names cover the directory-share capability as well, so the mapping
      remains exhaustive as backend capabilities grow. The
      website's 461 documented commands across 86 files are ratcheted rather
      than adjudicated — coverage is computed by the README gate's own rule and
      checked in at 170 covered / 267 uncovered, and cannot decay or accept a
      new undeclared command. See
      `specs/sprint/delivery/readme-examples-gate-a-release.md`.

- [x] **Documented examples gate a release.** `release.yml` blocked only on the
      hermetic BDD lane, which boots no guest; the live documented-surface lanes
      ran nightly in `ci-full.yml` and gated nothing. Both moved into a reusable
      `e2e-docs.yml` that Extended CI and `release.yml` now share, so no tag is
      cut while a documented example is red on Linux/Firecracker or macOS/HVF.
      Coverage also moved from per command path to per example: all 38 README
      invocations carry a checked `@live` witness, a hermetic witness, or a
      reviewed exemption, and a witness must carry the example's flags rather
      than merely name its verb. First run surfaced a second broken README
      example (`run --mode live --profile dev`, the #2887 residual). See
      `specs/sprint/delivery/readme-examples-gate-a-release.md`.

- [x] **Guest devpts and `/dev/fd` provisioning.** The universal-initramfs boot
      path created `/dev/pts` and never mounted `devpts` onto it, so `openpty()`
      failed for every `ConsoleOpen` and no OCI image could serve
      `machine run -it` or `machine console`. PID 1 now mounts `devpts` and
      links the `/dev/fd` family between the pivot and the privilege drop,
      loudly but non-fatally, skipping a mount a container runtime already made.
      A PTY-driven `@live` scenario reaches the interactive path the suite's
      piped-stdin steps structurally could not. See
      `specs/sprint/delivery/guest-devpts-interactive-console.md`.

- [x] **Transient start console diagnostics.** A transient backend-start
      failure now prints the guest console diagnostic before deleting the
      machine state directory, preserving the guest-side cause while retaining
      cleanup and the original startup error. See
      `specs/sprint/delivery/2819-transient-start-console-diagnostic.md`.

- [x] **Nix guest FlowMux identity ownership.** The shell init now delegates
      identity-drive mounting to a short root-owned Rust action, assigns only
      the 0400 signing key to reserved service uid 989, and then starts the
      long-lived egress client under `no_new_privs` with only low-port bind
      capability. Workload, agent, and builder uid collisions fail at image
      evaluation, the network parser retains no mount privilege, and a
      networkless boot tolerates only an absent identity drive while required
      or unreadable identities still refuse. See
      `specs/sprint/delivery/2828-nix-flowmux-identity.md`.

- [x] **FlowMux forward-proxy identity ownership.** Secret-substitution HTTP
      relays now run in an init-owned helper that can read the root-only guest
      signing key, rather than in the workload-uid guest agent. Both baked and
      overlay runtime-source policies carry the helper, incomplete overlays
      fail closed, and relay diagnostics do not expose privileged causes to the
      workload. The live secret-bearing substitution witness remains tracked
      by the owning FlowMux plan.

- [x] **Scheduled Security dependency and no-SSH scanner repair.** The
      supply-chain lane pins the last `async-trait` release on `syn` 2,
      restoring the duplicate-version policy, while the no-SSH lane permits
      only the capture secret-filename denylist and excludes generated
      dependency/build trees. Positive and negative shell fixtures preserve
      the fail-closed source boundary. Newly measured AI-policy and FlowMux
      mutants are covered by focused constructor, ingress-generation,
      readiness, accept-ceiling, and pre-confinement refusal witnesses; only
      the provably identical disabled-policy constructor remains baselined.
      Claim-13 mutation scope now measures its actual substitution boundary
      (three mutants rather than the proxy module's unrelated transport
      internals), and audit witnesses pin checkpoint and prune-accounting
      behavior while equivalent/performance-only misses stay documented. The
      broker's teaching-refusal ceiling is also mutation-pinned at its exact
      transition.
- [x] **Artifact acquisition is explicit across source and release builds.**
      Official binaries download verified launch artifacts even when invoked
      from an mvm checkout; contributor binaries may build source-matched
      artifacts and name that cold-build phase. Bootstrap now prepares the
      kernel, initramfs, runtime overlay, and OCI guest shims. The release
      overlay carries all six shims, contract tests prevent producer/consumer
      drift, and worktree-stable Cargo targets reuse dependencies without
      weakening content-keyed final caches. Production OCI admission runs
      before artifact preparation, so a refused pull starts no build or
      download. The merge-queue aarch64 smoke preserves and executes a
      source-channel root CLI binary with user-facing manifest verification;
      a separate release-channel helper downloads only the published builder
      image because a pre-merge build cannot consume its not-yet-published
      runtime archive format. It installs `virtiofsd` plus the `ipxe-qemu`
      package that carries `efi-virtio.rom`, bootstraps source-matched runtime
      artifacts before the first builder-backed launch, grants the hosted
      runner's unprivileged QEMU process access to `/dev/vhost-vsock`, and
      passes that one device into the local Docker witness. It pins the
      dependency order that makes the overlay available before kernel
      preparation. Builder and workload QEMU launches share one architecture
      mapping, so AArch64 consistently selects the `virt` machine and PL011
      console; pre-daemonization failures retain a bounded QEMU-log tail.
      Authenticated host handshakes preserve typed session errors so a peer
      reset while the slow TCG guest becomes ready reaches the existing
      bounded activation retry; identity and protocol rejections still fail
      closed. Failed transient starts emit a redacted guest-console tail before
      cleanup. Hook-mutated ext4 images are checked and journal-replayed
      offline after the writable mount is dropped. Every destination is checked
      again after the final publication copy and before its durability sync;
      the persistent-builder path preserves the hook command's real exit
      status. A mounted or damaged image fails before publication, preserving
      the workload's hypervisor-enforced read-only rootfs contract. The same
      fail-closed check is emitted into one-shot and persistent job scripts so
      source-checkout behavior stays correct when release bootstrap deliberately
      boots a published builder image whose hook runner predates the repair.
      The tagged release workflow separately verifies the signed
      future-format overlay through the production downloader before publish.
      The standalone hostd fuzz lock is refreshed for the current dependency
      graph.
      The owning plan is
      `specs/plans/2026-08-20-artifact-acquisition-contract.md`.

- [x] **Issue #2792 — Security watcher delivery has an independent backstop.**
      The scheduled claim-witness reconciliation now inspects only scheduled
      runs and requires the latest one to be fresh, completed, and successful.
      A failed, cancelled, timed-out, or still-running nightly is therefore
      reported even if GitHub omits the event-driven watcher's `workflow_run`
      delivery; pull-request and dispatch runs cannot mask the evidence.

- [x] **Issue #2830 — Extended CI lanes restored.** Both macOS lanes trust
      the `slp/krun` Homebrew tap and install libkrun before compiling its
      consumers. The Linux builder-image smoke supplies all three binaries in
      the host-binary manifest, including `mvm-builderd`. Structural tests pin
      the two workflow contracts.

- [x] **Issue #2870 — Extended CI failures repaired.** The AArch64 no-KVM
      witness executes the sealed exit-code image's baked entrypoint instead of
      replacing it with `/bin/true`, and both macOS lanes use one trusted-tap
      installer that builds the checksum-pinned firmware formula from source
      instead of requesting an upstream bottle basename that does not exist.
      The Apple workspace lane also installs the pinned embedded-host Zig/Rust
      toolchain before mvm-cli's build script needs it. The release workflow
      reuses the same installer and bounded retries.

- [x] **Issue #2789 — guest hostname follows the machine name.** The shared
      workload cmdline carries one validated `mvm.hostname=` token for cold
      boots, while warm children receive their final name through the existing
      post-restore identity handshake. Privileged guest code re-validates and
      applies both before workload code starts. Missing legacy fields remain
      compatible; the protocol schema and generated Python and TypeScript
      bindings include the optional field; malformed values and syscall failures
      are covered explicitly.

- [x] **Issue #2657 — live BDD is visible and merge-gated.** Capability skips
      are reported instead of disappearing from the test summary, and a
      merge-queue/manual-only KVM lane runs one tagged Firecracker witness for
      the README persistent-machine lifecycle. The CI-only selector composes
      with the existing live and backend capability gates, so narrowing the
      suite cannot accidentally authorize a live boot. Structural tests pin
      the workflow trigger, recipe, selector, and exact public command
      sequence.

- [x] **Issue #2756 — Linux 6.12.104 kernel pin refresh.** The libkrunfw
      firmware build and custom workload/builder kernels consume the same
      kernel.org-verified source archive and SRI hash. Structural parity and
      freshness checks report both pins synchronized and current.

- [x] **Issue #2831 — Linux 6.12.105 kernel pin refresh.** The libkrunfw
      firmware build and custom workload/builder kernels consume the same
      kernel.org-verified source archive and SRI hash. Structural parity and
      freshness checks report both pins synchronized and current.

- [x] **Faster Rust compilation — nightly Cranelift development path.** The
      dated nightly compiler, eight frontend threads, and Cranelift cut a cold
      representative build from 172.14s to 66.48s (61.4%). Tests and release
      builds retain LLVM; Clippy retains stable 1.96 without suppressions.
      Embedded-host and runtime-overlay guest binaries remain reproducible on
      their Nix-aligned Rust 1.91.1 pin, isolated from outer nightly flags and
      host compiler wrappers. The contributor shell was realized successfully
      in the libkrun builder VM.

- [x] **Issue #2574 — the first publishable Linux/Firecracker launch lane.**
      The false `host_services` degradation was already removed; the remaining
      dispatch gap was a nested 100 ms reconnect cadence inside the driver's
      own readiness backoff. Firecracker now makes one strict CONNECT attempt
      per bounded probe, while ordinary RPC callers retain resilient retries.
      On the established rotational KVM host, the required 2 warm-ups + 20
      measured `prepared_cold` launches passed at **171.5 / 176.0 / 178.0 ms
      p50/p95/p99** against **200 / 250 / 300 ms** budgets. The public page
      carries the host, backend, storage class, report path, and digest.

- [x] **Issue #2634 — sealed guests have writable runtime state without a
      writable root.** The universal initramfs mounts `/run` and `/tmp` as
      restricted tmpfs filesystems and moves them across the workload-root
      pivot. Mediated tools can therefore build their `/run` overlay and
      `/tmp` is real scratch space while the verified image stays read-only.
      Optional home/passwd mutations are not attempted on a sealed root. The
      live lifecycle suite covers Alpine `/tmp` writes and retains the
      absolute `/bin/ping` mediated-tool proof. Together with PRs #2690,
      #2709, and #2720, this closes the NIC-less and read-only boot-noise issue.

- [x] **AArch64 sealed-workload witness and QEMU teardown.** The Raspberry Pi
      QEMU path now reaches the workload entrypoint with the correct console,
      uid transition, compressed module handling, and builder/runtime-overlay
      artifacts. Session teardown selects the backend recorded in machine
      state and reaps both QEMU and its vsock bridge. See
      `specs/sprint/delivery/2836-aarch64-sealed-workload-witness.md`.

- [x] **Issue #2684 — a sealed boot is reachable and proven before release.**
      The CLI release train publishes both universal-initramfs archives under
      the downloader's exact versioned names and refuses to publish when that
      build fails. The boot-image train exercises its staged x86_64 production
      image both plainly and with the complete initramfs + dm-verity triple
      before upload; the harness refuses partial or malformed integrity input.

- [x] **Plan 337 COMPLETE — the SDK surface is generated from Rust.** Sessions
      finished Tier C. Python's `contextvars` + `Token` has no
      `AsyncLocalStorage` equivalent, so the shape was a choice, not a
      translation: `session(id, body)` was taken over `using s = session(id)`
      because the latter lets concurrent sessions in different async tasks
      clobber one another — a correctness bug rather than an ergonomic one. A
      test runs two overlapping async bodies and checks each sees only its own
      id. The abandonment net is weaker than Python's by necessity
      (`FinalizationRegistry` may never run and is not run at exit), so the
      callback shape carries a `try/finally`, which is the stronger guard and
      another reason for the shape. `_remote.ts` now attaches `--session`;
      `workload_ref` opts out, since a session belongs to one workload. Last
      divergence name closed by renaming `current_recording_dict` to
      `current_recording` — the `_dict` suffix encoded a Python-only return
      type — and exporting the TypeScript counterpart. **Both directional
      backlogs are empty: python-only 30 -> 0, typescript-only 2 -> 0.** What
      remains in `surface_divergence.json` is difference, not debt: two names
      that cannot close (`derive_schema`, `SecretInArgWarning`) and the
      type-erased set. #2558 and #2559 were verified already fixed on main by
      other sessions.

- [x] **Plan 337 WS-6 increment 1 — Tier C transport and the error taxonomy,
      as a declared subset.** The eight Tier D error types and the code that
      raises them landed together on purpose: generating the classes while
      TypeScript had nothing to throw them would have exported eight dead types
      and cleared eight divergence entries while closing nothing.
      `_remote.ts` implements real-VM invocation, the stderr envelope scan, and
      `RemoteFunction` / `func` / `workload_ref` / `WorkloadRef` (a `Proxy`
      where Python uses `__getattr__`). `MVM_NO_VM=1` is *refused* with
      `NoVmIntrospectionError` naming the reason rather than falling through to
      a real VM — the caller asked for local dispatch and would otherwise have
      got a microVM. `RemoteError` needed one registry extension (structured
      fields plus a message format). Two language differences recorded rather
      than smoothed: `SecretInArgWarning` is permanently Python-only (no JS
      warning type), and `RemoteError.message` holds the composed string in
      JavaScript where Python exposes the raw one. Sessions deferred to their
      own change — they force the AsyncLocalStorage-versus-ergonomics choice.
      Divergence 16 -> 4; across the plan 30 -> 4, typescript-only still 0.

- [x] **Plan 337 WS-7 + WS-8 — Tier F decided, plan closed out except what
      Tier C gates.** Option 2 for `derive_schema` confirmed (callers pass
      `args_schema` / `return_schema`), but the plan's claim that it needed "no
      new machinery" was wrong: TypeScript's `entrypoint_function` accepted no
      schema arguments at all, so the recommended option was impossible rather
      than merely less ergonomic. The IR had carried both fields all along;
      only the constructor omitted them, and it now accepts them. Documented in
      the TypeScript README where someone reaching for `derive_schema` looks,
      with the reason (types are erased before the program runs) rather than
      the absence. `surface_divergence.json` gains a
      `python_only_permanent_by_design` bucket so a never-closing difference is
      not counted as backlog. WS-8.2/8.3/8.4 done — all seven generated
      artifacts drift-gated, each shown to fail on a hand-edit. **WS-8.1 is
      left open on purpose:** the divergence file still carries Tier C's
      machinery and the eight error types only Tier C raises, and those close
      with WS-6. Across the plan, python-only divergence went 30 -> 16 and
      typescript-only 2 -> 0. WS-6.2-6.6 remain, and want a scoping decision
      (declared subset) before implementation.

- [x] **Plan 337 WS-4 — Tier B, and the split is the finding.** `warm_process`
      generates cleanly (one registry extension: a nullable default), verified
      differentially before its hand-copy was deleted. `addon_use` deliberately
      does not: expressing it declaratively needs a cross-parameter XOR, a
      branching target, a derived string field and default-if-absent — four
      capabilities no other constructor uses, i.e. a mini-language for one
      function. It stays hand-written in both languages but pinned by the s27
      golden IR document, meeting the WS-1 standard that a copy is dangerous
      only when nothing checks it. Rust has no XOR at all —
      `addon_use_registry` / `addon_use_local` are two functions, so the
      invalid combination cannot be written, which is the WS-1 thesis a third
      time. **Two defects found by the new coverage:** WS-3's deletion of
      `node_deps` had also removed the module-level `_UNRESOLVED_SHA256`,
      leaving `addon_use` raising `NameError` while all 212 Python tests still
      passed — because none of them called it; `tests/test_ctors.py` now closes
      that gap and was confirmed to fail without the fix. And the first
      `_addon.ts` exported `UNRESOLVED_SHA256` where Python's is private,
      caught immediately by the two-way divergence gate. Divergence 19 -> 17;
      everything left is Tier C, its error taxonomy, or Tier F. WS-6.2-6.6,
      WS-7, WS-8 open.

- [x] **Plan 337 WS-3 — Tier A constructors generated from a declarative
      registry.** The workstream the WS-1 spike existed to enable, and the
      first real test of its decision: all eight constructors now come from
      `mvm-sdk/src/ctor_registry.rs` — parameters, defaults and *constraints* —
      rendered into both languages, with the Python hand-copies deleted and
      TypeScript gaining all eight for the first time. The constraint
      vocabulary needed is three cases, small enough to be worth the machinery
      and large enough that no parser could have inferred it. Generation also
      removed a fragility rather than relocating it: the hand-written Python
      named numbered variant classes (`_ir.NetworkDns3`) that
      `datamodel-codegen` renumbers along with their `KindN` enums, and the
      generated code resolves by discriminant so neither number exists
      anywhere. Byte-compatibility established differentially over 26 cases
      (every valid path, both alias spellings, the port boundaries, every
      refusal) with zero differences, then the Python suite passed unchanged.
      The new golden-IR scenario caught a real cross-language divergence on
      first run — Python's `{tool!r}` renders `'poetry'` where `JSON.stringify`
      rendered `"poetry"` — now fixed so both agree byte-for-byte.
      `python_only_absent_from_typescript`: 27 -> 19. WS-4, WS-6.2-6.6, WS-7,
      WS-8 open.

- [x] **Plan 337 WS-5 + WS-6.1 — error taxonomy generated; Tier C sized.**
      The host-services error hierarchy and its `MVM_HSVC_*` status codes were
      triplicated: Rust constants plus a hand mirror in each SDK, under a
      comment asking a human to keep them matching — and the prose had already
      drifted ("audit cap" vs "e.g. the 4 KiB audit cap"). Now one
      `macro_rules!` registry in `mvm-sdk/src/error_taxonomy.rs`, emitted and
      rendered into both languages, with both mirrors deleted and `STATUS_OK`
      generated so none of the mirror survives. `ErrorBase` models the
      hierarchy rather than per-language literals, and refuses to emit a
      Python-only `Warning` into TypeScript. **Scope correction:** Tier D's
      eight named types are *not* generated here — all eight are raised only by
      Tier C's `_remote.py`, so emitting them into TypeScript would export
      classes nothing can throw and clear eight divergence entries while
      closing nothing; they land with WS-6. **WS-6.1 sizing found Tier C is two
      dispatch paths, not one**: `MVM_NO_VM=1` derives argv from Python
      function introspection (`__module__`, `inspect.getfile`) and has no
      JavaScript equivalent at all; session scoping forces a choice between
      correct async isolation and Python-like ergonomics; and the
      `weakref.finalize` abandonment net degrades to a best-effort
      `FinalizationRegistry`. Recommendation recorded: ship TypeScript Tier C
      as a declared subset. Ten further env vars found unregistered.
      WS-3, WS-4, WS-6.2-6.6, WS-7, WS-8 open.

- [x] **Plan 337 WS-1 + WS-2 — SDK surface generated from Rust.** WS-1 spiked
      both mechanisms for extracting a constructor manifest from
      `mvm_sdk::ctor` and re-scoped the plan rather than stopping it: the
      attribute/`inventory` mechanism recovered *less* than the `syn` parse
      (an attribute sees one item, so it cannot resolve a default living in a
      sibling fn), and both failed identically on the facts that are simply
      absent from Rust — `port=53`, keyword-only calling, `1..=65535`, the
      `"pip-tools"` alias. Rust discharges those constraints statically, so
      extraction is the wrong direction; the manifest is authored
      declaratively and records *constraints*, with `syn` re-scoped to a
      coverage gate plus a golden-IR behavioural gate. Surfaced a live defect
      (#2559): Rust's `host_port` accepts port `0` where Python rejects it —
      fixed 2026-08-16 by moving the constraint to `mvm_contract::ir::validate`
      (`dns_resolver` had the wider version of it) behind a shared golden
      verdict corpus both languages are checked against, which is the first
      slice of that behavioural gate. WS-2 built
      the pipeline end-to-end on Tier E — a `macro_rules!` registry in
      `mvm-sdk/src/env.rs`, `emit_sdk_env`, and a hand-written xtask emitter
      (necessary: `json-schema-to-typescript` emits only `export type`, which
      `tsc` erases, so a generated constant would be invisible to the s27
      runtime surface check). `MVM_CLI_BIN` was quadruplicated and invisible to
      every gate because all four copies agreed. TypeScript-only divergence is
      now zero; the two `MVM_MACHINE_*` names were deliberately *not* emitted
      into TypeScript, since nothing there read them, and were recorded as a
      behaviour gap until #2558 supplied the behaviour — the wrapper now bounds
      its subprocess with both, so the registry exports them and the divergence
      file is down to the type-erased set plus the unported names. That work
      also found that neither SDK's unit suite ran in CI at all (212 pytest,
      138 vitest, no cargo target and no workflow step); `just sdk-test` on the
      BDD lane closes it. Also fixed a ~50% pre-existing flake in the s27
      TypeScript live fixture (unawaited `wait()` racing `spawnSync`): base
      9/20, now 30/30. WS-3–WS-5, WS-7, WS-8 open; WS-6 (Tier C) untouched.

- [x] **Plan 336 — runtime SDK parity + live-transport BDD.** The golden
      `tests/machine-fixtures` corpus was shadowed by an unanchored copy under
      `crates/`, which is what the Python and TypeScript suites resolved to;
      both were red on main and blind to `machine start --image`. Corpus
      collapsed to one, both languages repointed and given Rust-equivalent
      coverage tripwires, `xtask check-single-fixture-corpus` added. Fixed a
      packaging defect that made every host-side TypeScript entry point throw
      `ReferenceError: require is not defined` in the published ESM artifact —
      invisible to vitest, which supplies CJS interop. New
      `s27_sdk/runtime_live_transport.feature` drives the built artifacts in
      both languages against a shared recording CLI double, and the suite now
      gates a PR at all — it previously ran only from release-tag workflows.
      Cross-language surface divergence measured and mostly closed: TypeScript
      stopped exporting 7 internals, Python gained the 9 host-service errors a
      caller has to name, TS-only divergence 18 → 2, remainder pinned by a
      reviewed list. WS-G4 (porting the 27 absent names — the `@mvm.func`
      surface) deferred: a feature port needing product intent.

- [x] **Plan 325 — lowercase OCI image names.** Registry and repository
      capitalization is normalized before validation across every shared OCI
      pull and launch path, while case-sensitive tags and strict digest
      validation remain unchanged.
- [x] **Plan 269 — backend shim removal.** Inverted the driver/backend
      relationship: `FcDriver`, `HvfDriver`, `LibkrunDriver`, and `QemuDriver`
      now own their VMM mechanics, the legacy `FirecrackerBackend` /
      `HvfBackend` / `LibkrunBackend` / `QemuBackend` shells are deleted, and
      every selectable microVM backend reaches production through the blanket
      `impl VmBackend for WorkloadRunner<D: VmmDriver, ...>`. `WasmBackend` is
      the sole documented direct-`VmBackend` exemption. Workspace nextest,
      all-target Clippy, and `check-claim-catalog` are green; migration
      boundary recorded in `MIGRATION-269.md`.

- [x] **Plan 322 — persistent-machine README contract.** `machine create`
      accepts the optional machine name positionally, and real-binary coverage,
      all three SDKs, shared fixtures, BDD scenarios, recovery guidance, and
      website docs agree on that single public command shape. Host and Linux
      gates, including the complete workspace suite and doctests, pass.
- [x] **Issue #2365 / Plan 319 — audit-log rotation.** The chain-signed audit
      log now rotates into sequenced segments at 4 MiB instead of growing
      forever. Rotation is an authenticated handoff, not a truncation: each new
      segment opens with a signed record naming its predecessor and that
      predecessor's final chain hash, so a removed segment is reported by
      number rather than passing silently. Retention is keep-everything;
      deletion stays an explicit operator action. ADR-001 rows 8 and 14 amended
      to say what `verify_audit_chain` now attests.
- [x] **Plan 322 — HVF virtio-fs shared-memory sentinel.** The queue-backed
      virtio-fs transport returns the required all-one absent-region value from
      its shared-memory length and base registers, so Linux no longer rejects
      `uvol` devices as zero-length DAX windows. Unit coverage and the original
      native-HVF Alpine directory-share command pass.
- [x] **Plan 316 — merge-queue forward progress.** Reduced live speculative
      build concurrency from four to two, restored immediate single-entry
      progress, raised the check-response timeout from 90 to 240 minutes, and
      made timeout ejections terminal for automatic recovery at an unchanged
      commit. Required checks and exact merge-commit validation are unchanged.
- [x] **Foreground `machine run` port forwarding.** Repeatable
      `--port HOST:GUEST` promotes a run to a persistent machine, delegates to
      the existing forwarding lifecycle, binds loopback rather than socat's
      wildcard default, and refuses detached or competing attached ownership.
- [x] **CLI help layout invariant.** Every visible and hidden command emits one
      physical line per help item, strictly shorter than 80 columns, for
      `--help`, `-h`, and `mvmctl help <path>`. The shared renderer compacts
      long-help blocks and caps overlong summaries at 79 columns; generated-tree
      BDD coverage executes the real binary, rejects continuation lines and
      overlong output, and automatically includes future subcommands.
- [x] **Issue-closeout batch — #2165, #2321, and #2323.** #2165 closed as
      completed by PR #2330: the workload runner now emits read-only root
      bootargs for read-only root devices. #2321 and #2323 were previously
      closed; the batch is complete.
- [x] **Issue #2128 — kernel pin freshness.** The libkrunfw bundle and custom
      guest kernel now share the verified Linux 6.12.102 LTS source pin;
      structural parity coverage prevents the consumers from drifting apart.
- [x] **Issue #2293 — audit-chain durability boundaries.** PR #2302 removed
      the duplicate synthetic `plan.admitted` and bound OCI provenance to the
      plan that boots. PR #2317 made admission the pre-action sync barrier,
      deferred post-hoc records without changing chain content or ordering,
      retained fail-safe sync for unknown events, and preserved torn-tail
      detection. PR #2328 removed the redundant head fsync and added head recovery. PR #2465 records the record-vs-control decision, adds torn-head coverage, and closes the issue; the KVM `emit: receipt` re-measure showed p50 ~45.4 ms on a Linux/KVM host.
- [x] **Issue #2289 — kernel pin freshness follow-up.** Closed as completed
      by PR #2301. The libkrunfw and custom guest kernel inputs now
      synchronize on the verified Linux 6.12.103 LTS source pin, and
      structural parity coverage uses the upstream tarball's verified SRI
      hash.

## Fast machine substrate

- [~] **Obscura browser provider pilot.** An explicit experimental provider,
      typed SDK OCI source, honest live-option lowering, bounded CDP readiness,
      and pinned Nix guest example are implemented on an isolated feature
      branch. Chromium remains the default. Real-backend policy proof,
      compatibility, full Nix/workspace, and native Linux gates remain open in
      `specs/plans/2026-08-18-obscura-browser-provider.md`.

- [x] **Issue #2279 — define the fast machine substrate and canonical template
      contract.** The cross-plan note joins Plans 298, 299, 265, 270, and 292
      around one prepared template identity, explicit lifecycle phases, a
      system-level kernel budget, and a measured filesystem-path decision. It
      introduces no second cache or snapshot graph. Follow-up measurements and
      live backend work remain open under issues #2280, #2281, #2194, #2195,
      #2196, and #2199. Launch evidence now records the tier-selected root
      filesystem strategy and rejects missing or mixed strategies so
      filesystem comparisons cannot mix security tiers. The libkrun probe also
      exposes bounded resident host-process capture, and the HVF guest-RAM seam
      exposes resident bytes with a demand-fault witness and records private
      restore-mapping duration. The libkrun density report also carries the
      readiness-bound guest-agent RSS witness. Backend-neutral warm launch
      evidence now samples the whole VMM host process at authenticated
      readiness and after the first command, including Linux fault deltas and
      macOS physical footprint. The real-host Firecracker/HVF matrix,
      canonical budget table, and gates remain open.
- [x] **Plan 314 — event-driven process lifecycle and shutdown.** The shared
      macOS kqueue/Linux pidfd observer drives normal HVF, Firecracker,
      libkrun, and QEMU shutdown with bounded fallback, identity-safe final
      verification, and fail-closed escalation. Live HVF, Firecracker,
      libkrun, and QEMU repetition gates pass with no force-kill escalation in
      the 1,000-cycle HVF run and no leaked backend processes, PID markers, or
      owned sockets. Supervisor profiling found vCPU exit, not the 5 ms
      watchdog, dominates internal HVF shutdown, so no unnecessary control
      protocol was added. The foreground-wait audit, repository waiting-model
      rule, complete workspace tests, formatting, checks, and Linux all-target
      clippy are green. The post-completion HVF builder regression is also
      closed: work inputs now use the shared filtered staging seam before ext4
      packing, and a transport-boundary test proves source is retained while
      host `target/` scratch output is excluded. An authorized live sleeper
      build packed 57.1 MiB instead of 55.7 GB and returned builder exit code
      zero; the later workload boot stopped at a separate readiness timeout.

## In-flight plans

- [ ] **Static crates registry recovery**
      (`specs/plans/2026-08-26-static-crates-registry-fetch.md`, issue #2904).
      The pinned Nix crate fetcher is blocked by crates.io's curl user-agent
      policy. One shared cargo-deps helper is applied to every repository Rust
      derivation so checksum-verified downloads use the unaffected static CDN
      without redefining Cargo's built-in registry, and future derivations
      cannot silently restore the API endpoint.

- [ ] **Detached declared ingress**
      (`specs/plans/2026-08-26-detached-declared-ingress.md`, issue #2901).
      Persistent `machine run -d` launches can now carry signed `--port`
      declarations before boot, and the Obscura example uses that lifecycle
      instead of the retired dynamic-forwarding verb. Validation and merge are
      in progress.

- [ ] **Admission cache durability boundary**
      (`specs/plans/2026-08-26-admission-cache-durability.md`, issue #2900).
      The chain-signed admission event retains the one fail-closed durability
      barrier that gates boot. Receipt files, decision records, and per-machine
      `plan.json` remain atomically published, permission-restricted derived
      views, but no longer add independent stable-storage waits before launch.
      Focused recovery, rebuild, permissions, and barrier-count tests plus
      package Clippy are green; merge is pending.

- [x] **`.mvmev` offline verifiability**
      (`specs/plans/2026-08-25-mvmev-offline-verifiability.md`, issue #2863).
      The format-level gap is complete: schema version 1 now normatively names
      RFC 8785 JCS over integer-only, ASCII JSON; the public reference specifies
      parse/recanonicalize/verify order, member layout, SHA-256 address rules,
      and the three independent results. Frozen valid, invalid, archive-ID, and
      Ed25519 vectors gate cross-language compatibility. The remaining gap is
      the stream-plane transcript root, which is
      not chain-anchored: `emit_transcript_sealed` has one production caller,
      the opt-in forensic *network* capture path, so the transcript of what a
      workload actually printed sits beside the audit chain rather than inside
      it. The landed WS4 pieces anchor both live and adopted stream-plane seals;
      remaining WS4 work surfaces the root on the receipt and audits other seal
      paths. Adjacent to, and
      deliberately disjoint from, the qualification plan's WS1, which landed in
      #2855.

- [~] **Workload service plane**
      (`specs/plans/2026-08-25-workload-service-plane.md`). Three workstreams
      taken from a 2026-08-25 survey of a commercial enterprise
      application-platform vendor, scoped deliberately as depth on existing
      seams rather than new API surface -- the survey's main finding was that
      `mvmd` already carries 143 gateway route modules (~90k lines) of which
      only six touch provisioning at all. WS-A: workload-to-workload addressing
      by name, resolved host-side in front of the two existing
      `EgressGate::decide_request` call sites, so no guest NIC appears and
      claim 10 still covers east-west. WS-B: a key-value store as a broker
      handler beside `host_time_v1`, inheriting binding-gated dispatch and the
      no-raw-secret channel property. WS-C: catalog entries gain a bound
      workload shape and a run edge through the existing `synthesize_plan`
      admission path. Not started; WS-C task C-4 depends on WS-A and WS-B
      bindings. The `host.kv.v1` witness retains its sized, read-only ext4
      `--volume`: the transient parser accepts it, and an Apple Silicon live run
      reached the broker and returned `KV-OK`. The unbound live refusal still
      needs a fresh run. A repository-to-signed-workload generator is noted as an
      unscheduled follow-up in `specs/SPRINT.md`.

- [x] **Execution-receipt evidence archive**
      (`specs/plans/2026-08-22-execution-receipt-evidence-archive.md`,
      implementation plan `…-implementation.md`, ADR-110).
      `receipts export` dropped every audit entry with no receipt mapping --
      egress decisions, stream attach/input grants, sealed-transcript anchors
      -- and said nothing about having done so. Tasks 1-8 shipped: an exhaustive
      `EntryMapping` so nothing falls through, three self-locating receipt
      extensions, a signed `.mvmev` archive with one inclusion proof per leaf,
      and a verifier reporting integrity/inclusion/completeness separately with
      a 1/2/4 exit bitmask. Completeness is `attested` for a plan-scoped
      archive and `derivable` only under `--full-chain`; the two are never
      collapsed. Open: transcript chunk embedding, blocked on which transcript
      store is authoritative (ADR-110's open question). WS5 (mvmd blob store +
      index) is specced in mvmd and not started.

- [ ] **HVF builder state out of the workload VM namespace**
      (`specs/plans/2026-08-21-hvf-builder-state-out-of-the-workload-namespace.md`).
      The HVF builder family stages VM state under `~/.mvm/vms/` rather than
      the builder cache root libkrun uses, so `machine ls` listed a running
      `nix build` as a user machine and the orphan reaper never pruned a
      finished build's dir. Both reading ends are fixed by name via
      `mvm_core::naming::is_builder_owned_vm_name`; separating the two state
      roots so the filter stops being the mechanism is open.

- [~] **Plan 338 — WebLinux browser backend, builder, workbench, and `mvmd`
      deployment client**
      (`specs/plans/338-weblinux-browser-backend-builder-workbench-and-mvmd-deploy.md`).
      ADR-049 renumbered from ADR-043 to avoid collision with the existing
      ADR-043. ADR-024 updated to link ADR-049 while preserving the direct-WASI
      claim-free boundary. ADR-006 updated to allow `mvmctl deploy` as an
      authenticated `mvmd` client operation. Plan 338 registered in
      `specs/SPRINT.md` and this file. First slice landed in PR #2776:
      `BackendKind::WebLinux` with contract-level capability dimensions,
      native `AnyBackend::WebLinux` stub that fails closed,
      `BuilderBackendChoice::WebLinux` excluded from native auto-detect,
      minimal portable lifecycle DTOs (`BackendRequest`/`BackendResponse`,
      `ArtifactRef`/`ArtifactSetRef`), and matching tests. WS-2 engine
      feasibility is now pinned: `ktock/qemu-wasm` 5a65998d47, Emscripten
      3.1.50, zlib/libffi/pixman/glib/xterm-pty versions are recorded, and
      `nix/packages/qemu-wasm.nix` packages the engine through the Nix
      builder boundary. The demo terminal now forwards Ctrl+C/Ctrl+D as raw
      ETX/EOT bytes through the Worker to the serial PTY, with focused and
      live-browser coverage. Build verification is queued for the Linux
      builder.

- [~] **Security lane recovery — issue #2736.** The advisory finding is fixed,
      the release-artifact bootstrap source now compiles with warnings denied,
      and pull-request CI exercises that otherwise dormant feature directly.
      Focused mutation witnesses cover authenticated-session signal validity,
      live/dead endpoint readiness branches, redacted TLS material, builder
      projection, and endpoint identity configuration.
      Every dependency graph that contains `arrayref` resolves a byte-for-byte
      vendored copy of the reviewed 0.3.9 upstream revision. Pinned file hashes
      guard the vendored source, Git dependencies remain denied, and Nix image
      sources plus the host build fingerprint retain that path dependency.
      The exact Security rerun's capability-builder finding now has a direct
      all-fields witness; its only remaining constructor mutant is documented
      as the identical `Default::default()` expression rather than waived as
      an untested behavior. Completed run 32552650847 then exposed seven
      authorization survivors in extension verification and attachment;
      focused boundary and single-field witnesses catch all 20 generated
      mutants across those predicates, and the now-caught host-budget miss has
      been removed from the accepted baseline.
      Closure remains gated on a clean Security workflow run from current
      `main`, including every mutation shard and both reproducibility builds.

- [x] **Secret bindings for forked children** —
      `specs/plans/2026-08-18-fork-inherits-secret-bindings.md`, issue #2698.
      Option A (W0 and A1–A6) is complete: fork bindings are explicit,
      tenant-validated before clone/boot, carried by every booting entry point,
      and recorded as names plus allowed hosts without source or value data.
      Dropping a parent binding is refused unless the caller explicitly permits
      attenuation. Option B (implicit checkpoint inheritance) remains designed
      and deliberately deferred.

- [~] **Durable agent sessions** —
      `specs/plans/2026-08-18-durable-agent-sessions.md` (design) +
      `specs/plans/2026-08-18-durable-session-substrate.md` (implementation,
      Tasks 1–5 complete) +
      `specs/plans/2026-08-18-durable-session-park.md` (implementation,
      Tasks 1–5 complete) +
      `specs/plans/2026-08-18-session-approval-head.md` (implementation,
      Tasks 1–4 complete) +
      `specs/plans/2026-08-18-resume-session-orchestrator.md` (implementation,
      Tasks 1–3 complete) +
      `specs/plans/2026-08-18-session-retention.md` (implementation, Tasks 1–3
      complete). `CheckpointMeta` gains `Option<SessionBinding>`
      (`session_id`/`generation`/`journal_cursor`/`approval_head`), folded
      into `meta_digest` the same way `grants` already is; `approval_head` is
      a dedicated `ApprovalHead` newtype, not `CheckpointDigest` reused.
      `mvm_runtime::agent_session::AgentSessionStore` gives sessions a
      filesystem store (`AgentSessionRecord`, `SandboxResidency`) over
      `mvm_core::config::agent_sessions_dir()`, with `parent_checkpoint`
      typed as a `CheckpointDigest` content-address rather than a mutable
      `CheckpointId`. `fork_checkpoint`/`fork_vm_full` explicitly clear the
      binding on a forked child. The park slice adds crash-safe record
      writes through the shared `mvm_core::atomic_io::atomic_write` helper,
      `ParkReason`/`StorageTier`/`select_tier`, four new record fields
      (`journal_cursor`, `approval_head`, `storage_tier`, `park_reason`),
      `AgentSessionRecord::park`/`resume` transitions with
      `SessionTransitionError`, and store-level `park`/`resume` fenced on
      the caller's expected generation — a check-then-act refusal, not a
      compare-and-swap, so a second caller racing on the same generation is
      not yet serialized; the module has no call sites yet, so nothing races
      it in production today.
      `ApprovalLedger::head()` (`crates/mvm-contract/src/policy/approval.rs`)
      content-addresses the ledger's decision state — every record's
      approval id, its capability, and its terminal state, deliberately
      excluding wall-clock fields plus `resource_digest`, `policy_digest`,
      `admission_plan_digest`, and `authorized_operators` — and `ParkInput`
      lets a park commit the journal cursor and that head with the
      transition in one fenced write instead of two. `AgentSessionStore::
resume` takes a `current_head` and refuses when it differs from the
      head recorded at park.
      STILL OPEN: the quiesce sequence over the existing guest verbs is the
      rest of WS3 — `CheckpointIntegrations`/`Wake` have no host-side caller
      anywhere in the workspace, and while `GuestRequest::SleepPrep` does
      have one (the Firecracker stop-time filesystem flush at
      `crates/mvm-backends/src/driver/fc.rs`'s
      `prepare_guest_filesystems_for_stop`), nothing on a park path calls
      it. WS4 is DONE: the ledger-head comparison landed, `resume_session`
      (`crates/mvm-hostd/src/session_resume.rs`) loads the record, refuses
      anything but `Hibernated`, resolves the resume point, checks the
      record's stored `meta_digest` against a fresh `compute_meta_digest()`,
      runs `verify_content`, builds a `SynthesisInput` naming the session and
      the generation the resume opens, admits it through
      `mvm_hostd::plan_admission::admit_for_run`, and only then transitions
      the record. Still open: nothing calls `ApprovalLedger::head()` to
      produce the value either side of the step-2 comparison carries —
      `resume_session` reads its caller-supplied `current_approval_head`
      straight off the record; `PostRestore` fabric re-registration and
      credential minting are not implemented; the synthesized plan carries
      `grants: None`, so a resumed session re-arms neither a wall-clock bound
      nor a CPU share; a session parked with `approval_head: None` resumes
      with no ledger fence at all. WS5 is partial: retention classes, expiry,
      a scheduler that calls `demote`, and actual byte movement between tiers
      remain undelivered.

      WS6 and WS7 are DONE, both via
      `specs/plans/2026-08-19-session-cli-and-audit.md` and
      `specs/plans/2026-08-19-resume-boot.md`
      (`crates/mvm-cli/src/commands/agent_session.rs` and
      `crates/mvm-hostd/src/session_resume.rs`). `mvmctl agent-session`
      carries `open`, `ls`, `show`, `park` and `resume`, and `resume --boot`
      cold-boots a `Cold`-tier session through the shared post-admission tail,
      refusing `Parked` and `Resident` by name. `session.resumed` is emitted
      before the boot attempt so a failed boot leaves the chain consistent
      with the moved record. Known limitation: on x86 Firecracker the plan
      pins the source `vmlinux` digest, but the VMM loads an ELF sibling
      derived from it; the derived file is not itself pinned. WS8 BDD remains
      untouched.

- [~] **Admission-bound AI assurance sessions** —
      `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md`. W1–W4,
      W6/W7, W7b landed and W5 partial: the envelope, the authority
      intersection, the fail-closed outcome ladder, `host.assurance.v1`,
      resolvable audit/receipt citations, the workload-facing
      `AssuranceCampaign`, the boot-path session lifecycle, and
      `collect_evidence` — cleanup read through the admission budget's own
      liveness probe, disposability off the signed plan.
      `observer_verified` is deliberately only "MVM recorded a probe", not an
      independent observer, and a test pins that a real session still evaluates
      `INCONCLUSIVE` for `ObserverMissing`. Landing W7b exposed two bugs the
      fixtures had masked: the binding rejected every real `sha256:`-prefixed
      plan id, and the probe handler compared the guest's session identity
      against the supervisor's lookup key.
      STILL OPEN: trusted hardware attestation and the full Scout-linked
      certifying campaign. The supplied native x86_64 KVM host now proves the
      concrete provider reaches a real Firecracker guest agent, observer,
      exact cleanup, and host finalization; plan
      `sha256:18a220846c25a6cec1f0b4f36dd4bfbab764f4e50671394e6da32acfcbd7ef16`
      and grant digest
      `sha256:b0991c541656cac6ebd02c27389a8b3c299b7cbadd6d4477653a0219545acf34`
      are recorded. An identical retry replays the bounded terminal response
      without a second VM. The run is `INCONCLUSIVE` because no TPM2/SEV-SNP/TDX
      trust root is present and the probe reported no attempted effect. The
      sibling now consumes MVM's published four-reference
      `sha256:nul-separated-policy-refs-v1` vector over
      `operator-network-v1`, `operator-egress-v1`, `operator-fs-v1`, and
      `operator-tools-v1` and the exact digest
      `sha256:5dd0de53b6d211f764728599e291e93a9491dc34f87596e906365fb74c95e0ff`.
      A current Scout-linked attempt reached signed-plan admission but failed
      closed before guest-agent startup on `mvm-oci-init` path-policy denial;
      its identical retry replayed without a second execution.

- [~] **Embedded-binary content store** — `specs/plans/2026-08-17-embedded-binary-content-store.md`.
      Phases 1–2 landed: both nested legs of `crates/mvm-cli/build.rs` are keyed
      on their real dependency closure rather than on `PROFILE == "debug"` plus
      "the file exists", and the store lives outside `target/` so worktrees,
      profiles and target triples share it. Cold build **359s → 45.5s**; the
      build script within it **332.7s → 0.4s**; an `mvm-cli` edit no longer
      re-runs either leg. The dev profile keeps its stale-embedded-binary trade
      deliberately, but a miss now knows it is stale and says so via
      `cargo:warning=`. Supersedes the freshness half of
      `specs/plans/2026-08-15-aux-helper-binary-freshness.md`.
      The per-VM aux leg — the last unconditional rebuild, and by 2026-08-26
      **17.8s of a 20.9s** inner-loop rebuild (85%) — was first made cheap by
      `specs/plans/2026-08-26-aux-helper-staleness-gate.md` (reuse on a key
      miss, plus a spawn-time refusal of the marked binary; **20.9s → 8.5s**),
      and on 2026-08-28 **deleted outright** by
      `specs/plans/2026-08-28-build-script-drops-the-aux-helper-leg.md`. Those
      seven binaries are ordinary `mvm-hostd` `[[bin]]`s that a workspace
      `cargo build` already produces where `aux_bin::resolve` already looked, so
      the leg was a duplicate compile of `mvm-hostd`'s closure per worktree.
      Build script on a key miss **60.37s → 0.13s**, nested cargo invocations
      **7 → 0**, `rerun-if-changed` set **1013 → 648**, nested target dir
      **13.6 GB → 649 MB**. The `.mvm-stale` marker and `MVM_ALLOW_STALE_AUX`
      went with it — cargo owns freshness, so staleness is no longer
      representable rather than merely detected.
      The remaining musl leg then went opt-in behind `embed-host-bins` —
      `specs/plans/2026-08-28-embedded-host-binaries-are-opt-in.md` — so the
      script no longer runs on the inner loop **at all**: with the feature off
      it watches four files and writes an empty table, and a `mvm-core` edit
      produces zero build-script executions. `just embed` and the tag-push
      release workflow turn it on; an unembedded `mvmctl` refuses to bootstrap
      a builder VM with the recipe named.
      STILL OPEN: Phase 3 (phantom build.rs tests — the `MVM_LIBKRUN_HEADER`
      half is closed, its probe is deleted), Phase 4 (dead crate edges;
      `deps_audit` and the tree-sitter grammars off the serial path; the
      `mvm-hostd` audit cluster), Phase 5 (sccache 4.2% Rust hit rate, worktree
      hygiene). The pinned zig now follows the feature: eight of `ci.yml`'s nine
      `install-zigbuild` steps are gone, each job traced to what it runs first,
      and that trace caught `just bdd-live-ci` booting real microVMs without the
      payload. Still open: the missing `rerun-if-env-changed` on
      `MVM_EMBED_CACHE_MAX_BYTES` / `MVM_EMBED_CACHE_DIR`. An earlier revision
      of this entry also listed "the embed store sitting at 17 GB against its
      4 GiB ceiling" — that was wrong; `prune` holds, and the effective ceiling
      on that host is a deliberate 64 GiB `[env]` override in a global cargo
      config.

- [~] **Agent tool and memory planes**
      (`specs/plans/2026-08-18-agent-tool-and-memory-planes.md`). Opened
      2026-08-18; no workstream started. Design only: ADR-045 gained sections
      18-19 (an agent's tool surface is broker dispatch, and the catalog
      derives from `ExecutionPlan.services` rather than from anything the guest
      or its model says) and ADR-047 defines the memory plane. Sequenced behind
      `specs/plans/2026-08-18-durable-agent-sessions.md` WS1, which owns the
      session identity memory keys on and is itself unmerged.
  - [x] WS1 — catalog derivation from the signed admission (PR #2705)
  - [x] WS2 — per-capability argument policy inside the descriptor digest (#2705)
  - [~] WS3 — the guest-side-client gate landed; the host-side adapter has not
  - [x] WS4 — refusal names the surface, and repeated misses are rate-bounded (#2705)
  - [ ] WS5-WS9 — memory plane: store + record, `host.memory.v1`, write scan
        and ceilings, audit + retention, bounded recall
  - [ ] WS10 — `mvmctl memory` read-only surface, tests + BDD

- [~] **Launch path as declared stages**
      (`specs/plans/2026-08-15-launch-path-as-declared-stages.md`). Opened
      2026-08-15; no workstream started. Split out of the artifact-derived
      runtime identity work, which landed first so its cache-staleness class
      would not muddy these timing measurements.
  - [ ] WS1 — split the two `attach_*` calls into `lookup_*` + `attach_*`
  - [ ] WS2 — stage `resolve_launch`, parallel probes in stage 2
  - [ ] WS3 — `SubPhase` per stage + `every_launch_stage_is_timed`
  - [ ] WS4 — golden-compare `VmStartConfig`, record `dispatch_window_ms()`

- [~] **Plan 335 — merge-queue throughput.** Automatic architecture and kernel
      checks now share the main CI scope gate, required check names are
      preserved transitively, duplicate runner allocations are removed, and
      trusted default-branch Rust/Nix cache warming is added. Repository and
      host validation are green; landing, Linux CI, and verified live queue
      settings remain open.

- [~] Plan 330 — Decision provenance layer
  (`specs/plans/330-decision-provenance-layer.md`)
  - [ ] Phase 0 — RFC and ADR approved
  - [x] Phase 1 — PROV-O export of existing events
  - [x] Phase 2 — Enrich existing audit events with authorizer/rationale
  - [x] Phase 3 — DecisionRecord API and content-addressed store
  - [x] Phase 4 — Query API and causal chains
  - [x] Phase 5 — Optional standards interoperability (TIBET-JSON export; C2PA/in-toto/SPDX evaluated, not adopted)

- [~] Plan 325 — SDK sidecar reserved mount
  (`specs/plans/325-sdk-sidecar-reserved-mount.md`)
  - [x] Reserved SDK disk is excluded from generic user-volume activation
  - [x] Legacy and universal guest boot paths mount `mvm.sdk_dev` read-only at
        `/mvm/sdk`
  - [x] Explicit worktree binaries source guest artifacts from the same worktree
  - [x] Guest Cargo target graphs and artifact caches are source-isolated
  - [x] Sealed OCI roots carry the reserved `/mvm/sdk` mountpoint
  - [x] Agent timeouts preserve a redacted console diagnostic before cleanup
  - [x] The hermetic `/mnt/wheels` plus SDK-sidecar BDD regression passes, and
        host preflight refuses invalid `/wheels` mounts before VM boot
  - [x] Source builds include the host-agent helpers and exact admitted service
        bindings reach a real `host.time.v1` handler
  - [x] The framed broker/SDK BDD regression and native HVF Python-wheel command
        pass
  - [ ] Native libkrun Python host-time acceptance passes

- [x] Plan 323 — Concurrent builds through one builder VM
      (`specs/plans/323-concurrent-builds-one-builder-vm.md`)
  - [x] Phase 1 — a contended Nix-store image lock queues (naming the holding
        pid and command) instead of failing the second build outright;
        `MVM_BUILDER_LOCK_WAIT_SECS` bounds the wait and `0` restores
        fail-fast for CI
  - [x] Phase 2 — `HvfPersistentHostVm` uses the persistent-builder spec so the
        multiplexing path exists on the macOS 26+ default backend. It carried
        `work`/`mvm-bins`/`job`/`out` as virtio-fs shares until the remove-
        virtio-fs plan's Stage C moved it onto the disk transport
  - [x] Phase 3 — a contended store image adopts a live persistent session or
        auto-starts one (arbitrated by a start marker), so concurrent builds
        share one VM instead of queueing
  - [x] Phase 4 — troubleshooting and CLI-reference docs cover the contention
        message, the wait override, and the persistent-builder path

- [x] Plan 322 — Scope merge-group Rust CI to behavior-changing diffs
      (`specs/plans/322-merge-group-ci-scope.md`)
  - [x] Fail-closed path classification preserves required aggregates while
        prose/site-only diffs avoid six cold Rust jobs; validation is complete.
- [x] Plan 315 — Bootstrap means machine-ready
      (`specs/plans/315-bootstrap-machine-readiness.md`)
  - [x] Bootstrap acquires and verifies both builder image and workload kernel
  - [x] Downloaded/local kernel publication is staged and verified reads fail closed
  - [x] Local dm-verity capability uses resolved config, not raw-image strings
  - [x] Required ARM64 cross-backend console support is pinned to its measured
        959-symbol budget; the unaffected x86_64 ratchet remains 917
  - [x] Full serialized workspace tests and doctests, host all-target Clippy,
        the 461-test `xtask --features man` CI lane, and 172 BDD scenarios pass;
        KVM-backed ARM64 cold bootstrap, kernel publication, persistent Stage 0
        reuse, and two fully warm Alpine runs complete without a second Stage 0
  - [x] Persistent Stage 0 ext4 reuse requires clean filesystem state; cold
        repair and warm reuse pass live ARM64 builder runs without ext4 errors
  - [~] Workspace tests expose unrelated non-deterministic `mvm-hostd` failures;
        Linux all-target Clippy remains for CI or a supported builder entry point

- [x] Plan 316 — website and docs redesign (agent design review completed and maintainer sign-off received; merged via #2438)
      (`specs/plans/316-website-redesign.md`)
  - [x] Homepage sections, docs chrome, and shared primitives rebuilt onto
        token-driven surfaces; stale Apple Virtualization / Docker-fallback /
        nonexistent Nix service-builder claims and the third-party Google
        Fonts CDN fetch removed from `public/src/components/`
  - [x] Copy-to-clipboard install-command controls (Hero, Install) converted
        from non-focusable `<div onClick>` to real `<button type="button">`
        with an accessible name and a visible focus ring in both schemes
  - [x] `pnpm check:tokens`, `pnpm check:samples` (10/10), and `pnpm build`
        (131 pages) all clean; stale-claim grep sweep and doc-route/footer
        link resolution against `dist/` both confirmed empty/OK; no
        `public/src/content/` file touched on the branch
  - [x] Homepage restructured a second time after maintainer review: numbered
        eyebrows, card grids and the multi-bloom treatment removed (uniform
        application was what made the page read as generated); mono headings
        with Inter body; two inline-SVG diagrams (`HeroStackDiagram`,
        `ContainmentDiagram`) carry the visual identity
  - [x] Browser verification now measured rather than deferred: 57/57
        focusable elements show a focus indicator; 0 text nodes below WCAG AA
        on landing (dark + light) and docs; reduced-motion resolves to
        `animation-name: none`; no horizontal overflow at 390/768/1024;
        gutters 108/34/26 across every section and the header
  - [x] Maintainer design review — agent design review completed; see
        `specs/notes/316-design-review.md` for findings and the remaining
        maintainer options ( GlowCard use, Quickstart Result tab, install-tab
        duplication).
  - [x] PR #2359 merged to `main`
  - [x] Implementation plan reconciled against what shipped: five tasks named
        components that were never created, because the mid-flight review
        restructured the page, and two stated goals (the scroll-synced code
        walkthrough and the SDK/CLI tab block as its own section) were dropped
        by that review. Mapping recorded in the plan's status header; the step
        checkboxes were never ticked during execution and are not a record of
        what happened
  - [x] Docs security pages carried a "seven claims" framing predating most of
        ADR-001's ledger (#2398); `ci-claims.md` now mirrors the full table and
        `matryoshka.md` separates layer-defending from backend-independent
        claims

- [x] Plan 315 — HVF virtio-vsock transmit-credit regression
      (`specs/plans/315-hvf-vsock-credit-regression.md`)
  - [x] Restore bounded guest credit recording, fail-closed unknown-credit
        behavior, protocol counter wrapping, and complete state teardown
  - [x] Prove first-window stop/resume and byte-for-byte 32 MiB delivery;
        prove no lifetime quota over a simulated 4 GiB transfer; prove active
        download credit prevents request-side idle eviction after 60 seconds;
        add the live documented pandas-install scenario
  - [x] Pass all 503 `mvm-vmm` tests, the serial aggregate workspace suite,
        workspace check, macOS workspace all-target Clippy, and the focused
        x86_64 and aarch64 Linux cross-builds
  - [x] Run Linux-native workspace Clippy/tests — CI test-linux and
        lint-core passed on PR #2324; local x86_64 and aarch64 Linux
        cross-builds (`cargo zigbuild --target x86_64-unknown-linux-gnu`
        and `--target aarch64-unknown-linux-gnu -p mvm-vmm --lib
--all-features`) pass on current `main`. Local Linux-native
        builder-VM gates are tracked in Plan 316.

- [ ] Plan 316 — Local Linux builder-VM gates via `mvmctl __builder-shell-job`
      (`specs/plans/316-builder-vm-shell-job-runner.md`)
  - [ ] Add hidden `mvmctl __builder-shell-job` command and example scripts
  - [ ] Run `mvm-vmm` tests and crate-level Clippy inside the HVF/libkrun
        builder VM
  - [ ] Update Plan 315 and `specs/SPRINT.md` to reference this plan

- [x] Plan 318 — span-timing profiling
      (`specs/plans/318-span-timing-profiling.md`)
  - [x] Phase 1 — `SpanTimingLayer`, bounded log-scale histogram, self-time
        attribution, text/JSON reports, per-layer log filter so spans are
        constructed at the CLI's default `error` verbosity
  - [x] Phase 2 — instrument `mvm-fs` OCI/ext4 entry points and the four
        backend `boot` paths plus HVF restore, then the launch critical path
        in `mvm-cli` and the admission/audit/build/client entry points
  - [x] Phase 3 — labelled prometheus export, pure per-call profile diffing in
        `bench/span_profile.rs`, and a measured decision to keep the per-close
        mutex (12 ns/span disabled; throughput scales up, not down, under
        contention). Wiring the diff into a CI lane stays with Plan 311's
        large-image work; guest-side `mvm-agentd` needs a profile egress path
        first.
- [x] Plan 2167 — durable agent session and event contract
      (`specs/plans/2167-agent-session-contract.md`)
  - [x] Versioned public IDs, lifecycle commands, durable/ephemeral event
        envelopes, typed errors, and bounded retention/cursor semantics
  - [x] Idempotent prompt delivery, cancellation confirmation, restart replay,
        and committed transcript/audit output references
  - [x] Client/SDK re-exports, contract serialization/security tests, and
        three non-`@wip` BDD scenarios

- [x] Plan 2168 — unified runtime policy and human approval
      (`specs/plans/2168-runtime-approval.md`)
  - [x] Typed fail-closed policy evaluation requires signed admission and
        applies deterministic specificity/priority/effect precedence
  - [x] Approval requests, authorized first responses, expiry, cancellation,
        replay, and terminal-state refusal share the durable agent-session
        cursor
  - [x] Bounded digest-only metadata, audit action mappings, client/SDK
        re-exports, unit tests, and three non-`@wip` BDD scenarios

- [x] Plan 2170 — typed capability bindings
      (`specs/plans/2170-typed-capability-bindings.md`)
  - [x] Versioned per-verb descriptors, schema references, limits, and exact
        descriptor-digest bindings
  - [x] Host-signed admission allowlist and invocation-time fail-closed gates
  - [x] Timeout, cancellation, replay, bounded I/O, typed failures, and
        digest-only capability audit events
  - [x] Real broker UDS round trip, BDD scenarios, and validation gates

- [~] Security lane mutation-witness repair — **issue #2135**
  - [x] Add direct witnesses for the security-sensitive admission,
        verification, lease, and substitution cleanup invariants
  - [x] Fail closed when an accepted miss leaves the pinned mutation surface,
        migrate 26 libkrun identities to their current file, and remove 15
        obsolete misses without adding a waiver (83 accepted misses to 68)
  - [x] Catch the current actionable `mvm-vmm`, `mvm-hostd`, and `mvm-agentd`
        mutants in focused mutation proofs
  - [x] Add the six witnesses exposed by the first exact rerun and prove the
        complete contract shard plus the focused five-mutant hostd repair
  - [x] Pass workspace all-target Clippy, the isolated `mvm-cli` doctest rerun,
        formatting, and the static mutation surface gate; the workspace suite
        passed all repaired areas before one unrelated host-agent socket-bind
        timeout whose isolated integration rerun passed 4/4
  - [x] Pass every mutation and security job in exact run 31516221103 and add a
        bounded, directly witnessed retry for the repeated Linux `ETXTBSY`
        shutdown-hook fixture spawn that remained; workspace all-target Clippy
        passes, and the sole parallel CLI failure passed its exact isolated
        rerun
  - [x] Serialize the guest-console tests that share process-global session
        state after the next exact run exposed their race; join the completion
        thread and pass 20/20 parallel stress runs
  - [~] PR #2472 (`fix/2135-security-lane-mutants`) accepts the remaining
    backend/runtime survivors in the mutation-witness baseline; Security
    workflow run 31817896244 is the final verification gate before merge
    and issue closure
- [~] Issue #2101 — OCI workload privilege hardening
  - [x] `harden_init_process()` in `mvm-oci-init` narrows the bounding set to
        `RESTORE_AGENT_CAPABILITIES` and sets `no_new_privs` before the agent
        is spawned; `drop_workload_capability_bounding_set()` empties it in the
        entrypoint `pre_exec`; `drop_guest_agent_privilege_raw` matches, so the
        initramfs and OCI paths reach the same posture
  - [x] Fixed a real bug in the drop loop: it walks slots 0..=63 but tested the
        keep mask with `1u32 << cap`, panicking at slot 32 in debug and
        mis-answering every slot above 31. Mask arithmetic split out and tested
        on every host; reverting the widening turns two of three tests red
  - [x] Ordered `NoNewPrivs` before the bounding-set drop and made the
        workload drop tolerate `EPERM`. The drop needs `CAP_SETPCAP`, so an
        unprivileged spawn failed outright, and because it ran first the
        failure also skipped `NoNewPrivs` — the load-bearing control. The
        privileged init path still fails closed
  - [x] Issue #2522 — the `EPERM` tolerance above covered the workload spawn
        but not the agent's own drop, which ran the same bounding-set narrowing
        *after* `set_capabilities` had already removed `CAP_SETPCAP`. Every
        `machine run --image` failed: the errno left the `pre_exec` hook, the
        agent never started, and the host timed out waiting for it. The
        narrowing now runs before the identity change, while the caller still
        holds the capability the syscall needs, and both call sites share one
        helper. Bisected against the parent commit and witnessed live on HVF
  - [ ] Re-run the adversarial probe on HVF **and** Firecracker — the closure
        gate, not yet run; no Linux/KVM host available
  - [ ] Record the ADR-001 claims 1/2 scope decision (owner call; determines
        whether this is claim-bearing or defense-in-depth)
- [~] Plan 300 — open-issue reconciliation and closeout
  (`specs/plans/300-open-issue-closeout.md`)
  - [x] Inventory all 39 issues open at the 2026-08-13 snapshot against
        current `origin/main`, issue comments, owning plans, and workflow state
  - [x] Close eight issues on 2026-08-13: #2165, #2289, #2333, #2423 as
        completed by merged PRs; #2180, #2181, #2305, #2413 as not planned /
        superseded
  - [x] Close #2292, #2307, #2318 as completed by merged PRs
  - [x] Second reconciliation pass 2026-08-14 against `2bc7dc2bc`: re-read all
        28 and verified each against the tree. No issue was complete-but-stale.
        Closed five combinations — #2347→#2299, #2281→#2280, #2199→#2198,
        #2193→#2194/#2196, #2166→#2169 — each transferring its acceptance
        criteria to the surviving issue in the same action. Deliberately not
        combined: Plan 316's eight phases (the ordering is the safety property),
        the warm-pool workstreams #2194–#2197 (different live-validation
        surfaces), and #2135 (a generated tracker, closed by workflow state)
  - [x] Correct Plan 316's Phase 2 status: it was marked COMPLETE with six of
        seven boxes unchecked and two verifiably undone on `main`
  - [ ] Execute the remaining 23 closure paths in the plan's dependency order
  - [ ] Reconcile a fresh GitHub query after every phase and at final closeout
- [~] Runtime hardening for production — plan 303, branch
  `feat/plan-303-runtime-hardening`
  - [x] WS1 — `overflow-checks = true` in `[profile.release]`, a
        `release-witness` profile, and a CI lane running the untrusted-input
        crates under it (wired into the `test` aggregate and pinned by
        `check_workflow_paths`)
  - [x] WS2 — audit-chain appends land as one `write_all` + `sync_data`; a
        torn tail reports as truncation rather than tampering
        (`AuditError::TruncatedTail`, `VerifyError::TruncatedTail`,
        `AuditRefusalKind::Truncated`)
  - [x] WS3 — manifest body capped before buffering; decompressed-byte and
        entry-count caps on `UnpackOptions`
  - [x] WS5 — a panicking `payload_tap` observer kills the flow; telemetry
        observers keep today's isolation (scope corrected from the original
        write-up — see the plan)
  - [x] WS4 — redacting panic hook wired into seven daemon bins; observes and
        redacts only (exiting would break three `catch_unwind` isolation
        sites, and signing from a hook can deadlock or double-panic)
  - [~] WS6 — **not** "add Landlock": the jailer already implements it
    (`jailer/landlock.rs` + `LANDLOCK.md` + a live property test). Real
    gap is that `confine_self` is called by only two bins, leaving
    `mvm-host-signer`, `mvm-audit-signer`, `mvm-signer-helper` and
    `mvm-broker` unconfined. Blocked on per-role seccomp allowlists,
    which need live-Linux validation and should follow `feat/seccomp-audit`
  - [x] WS7 — Miri lane over `mvm-contract`, advisory (nightly + dispatch,
        `continue-on-error`). 511 tests, no UB, ~4m25s with `merkle::` skipped
        — those sweeps ran past 30 min under the interpreter. Widening to
        `mvm-core` crypto and the `mvm-fs` ext4 writer deferred
- [~] Delete the dead guest-NIC gateway stack — plan 305, branch
  `feat/305-delete-gateway-stack`
  - [x] WS2 — the deletion: ~15,600 lines net. The gateway `NetworkingMode`
        variants and net-attach FFI, `libkrun-sys`'s bridge + gateway spawn
        modules, `mvm-hostd`'s `gateway_bridge/`, the four `rvproxy_*`
        modules, the observer pipeline and registry, `firecracker_bridge/`,
        the `mvm-bridge` sidecar, the `fuzz-vmhost` crate, the supervisor's
        bridge route, and `NetworkingPreference` / `MVM_NETWORKING` /
        `MVM_GATEWAY_BIN`
  - [x] `xtask check-no-gateway-names` — tree-wide gate, wired into `ci.yml`'s
        lint lane; clean over 2,109 files
  - [x] Docs corrected: `CLAUDE.md` host-dependencies (told contributors to
        install a package the runtime no longer uses), `README.md`, ADR-028,
        ADR-036, the jailer's `LANDLOCK.md`/`SECCOMP.md`, public
        troubleshooting + CLI reference, kernel image notes, three workflows
  - [x] Jailer property tests re-pointed from the deleted sidecar's spec to
        `ConfinementSpec::substitution_endpoint`; verified on live Linux
        (kernel 6.8, Landlock enforcing) with no third-party binary installed
  - [ ] WS1 — the broken confinement CI lane fix + `cargo -p` gate (PR #2260)
  - [ ] Follow-up: `gateway_audit_socket` plumbing through `SupervisorConfig`
        / `mvm-vmm` / `mvm-backends` — a neutral name that reaches the
        warm-pool claim path; deliberately out of scope here
- [x] HVF save/restore for checkpoint and fork — **plan 304**, branch
      `feat/hvf-save-restore`
  - [x] Audit `HvfVmFullControl` against the whole `VmFullControl` surface and
        add the writable-disk capture refusal
  - [x] Restore entry point: the launch-config rewrite in `mvm-backends`, and
        the `ForkRestore` callback / `VmFullRestore` adapters in `mvm-runtime`
  - [x] Backend-neutral dispatch: `AnyBackend::vm_full_control`, one shared
        liveness marker list held to the backend catalog by test,
        `vm_full_origin` replacing the supervisor-config fork predicate,
        `fork_vm_full_fc` → `fork_vm_full`
  - [x] Flip `snapshot_capability` to `SaveRestore` and update the pinned tests
  - [x] Chain-anchor the restore path; keep `capture_fs_quick` and the verity
        binding untouched; fresh child identity on every fork
  - [x] BDD suite `s11_snapshot/hvf_save_restore.feature` + benchmark evidence

- [~] Plan 299 — Prepared cold-launch performance
  (`specs/plans/299-cold-launch-performance.md`), branch
  `plan/cold-launch-performance`
  - [x] Phase 0 — trustworthy baseline COMPLETE. Both native lanes measured
        from release binaries: HVF/aarch64 prepared cold 112.6 ms p50 /
        116.6 ms p99 (warm claim 18.9 / 20.0 ms), Firecracker/x86_64 674.0 /
        888.6 ms. The difference is the VMM boot (`driver_boot` 53.8 vs
        623.6 ms on identical code), retargeting Phase 3 at the Firecracker
        path. Foreground teardown is the other dominant cost, promoting
        Phase 6 ahead of Phase 3.
  - [x] Phase 1 — content-addressed `--mount` image cache. Persistent `--host`
        registrations use the same cache and refresh on source changes before
        start.
  - [~] Phase 2 — artifact preparation outside the launch path. The resolution
    half landed as the warm pool's hard prerequisite (**#2333**):
    `crate::exec::resolve_launch` yields a bootable `VmStartConfig` without
    starting a VM, `run_inner` calls it instead of inlining it, and
    `pool warm --image` uses it to spawn parents a matching launch claims.
    `pool warm` could previously spawn nothing on any backend. The
    prepared-artifact manifest and the acquire/prepare split are still open,
    so a cold cache is still populated inline.
  - [~] Phase 3 — reduce backend cold-start latency. Re-measured on KVM at
    `c866611af` as Phase 5 asked: `driver_boot` is 630.5 ms, unmoved from
    623.6 ms, so the cost is real rather than a poll artifact and can be
    decomposed. It is a shell `sleep 0.1` socket poll plus ~9 curl/sudo
    subprocesses (**#2292**, closed by PR #2463). On HVF there is little left — `vmm_create`
    11.6 ms, `driver_boot` 7.8 ms — the remaining cold cost there is guest
    boot at 58.6 ms.
  - [ ] Phase 4 — parallelize independent host work
  - [~] Phase 5 — event-driven guest readiness. The flat 50 ms readiness poll
    was quantizing every launch: adaptive backoff cut `guest_kernel_entry`
    from 53.8 ms to 18.0 ms p50 and HVF dispatch from 117.2 ms to 81.4 ms.
    Three further fixed 50 ms polls (driver PID-file wait, standby agent
    wait, teardown pid-exit) now share one backoff in
    `mvm_core::poll_backoff`: VM creation reads 4.6 ms rather than 53.8 ms
    of tick, and total is 310.1 ms p50. The authenticated readiness
    notification itself remains.
  - [~] Phase 6 — move cleanup off the foreground critical path. Teardown
    decomposed and the warm-pool refill removed from it: a default
    `machine run` went 1366 ms -> 353.8 ms p50. Remaining teardown is
    `stop_transient` 142.9 ms, which is real cleanup. The Plan 314 event
    path then completed a native macOS 26.5.2 / arm64 1,000-cycle HVF run
    in the Rust test profile with p50/p95/p99 stop times of
    703.48/1,151.28/1,865.07 ms and zero SIGKILL escalations. That run is
    a lifecycle stress baseline, not a replacement for the release
    prepared-cold numbers above: its stop tail is dominated by detached
    supervisor PID disappearance. Follow-up: give pool maintenance to the
    resident per-tenant daemon and continue reducing supervisor shutdown
    latency.
    The "real cleanup" remainder was then decomposed and was mostly not:
    `stop_console_cleanup` was the largest span in a transient teardown and
    57.0 ms of it was two more instances of the cadence bug — the stream
    accept loop polling a nonblocking listener on a 25 ms tick, and
    `DurableSink::seal` polling `is_finished()` every 20 ms for a writer that
    exits in microseconds. Backoff could not fix the first (it idles at the
    ceiling for the VM's whole life), so the listener now blocks and shutdown
    wakes it by connecting to its own socket, bounded and with a detach path;
    the second waits on a channel the writer thread's sender closes on exit.
    Measured on release, HVF/macOS, against an unchanged control span in the
    same runs: `stop_console_cleanup` 57.0 -> 7.0-7.7 ms while
    `stop_pid_disappearance` held at 33.4-35.5 ms against a 33.7 ms baseline.
    Foreground teardown 91.4 -> 41-45 ms. A fifth cadence site was then found
    inside the guest agent — `exec_stream` slept a flat 50 ms before rechecking
    a child that had already exited, a hard floor under every exec — taking
    `command` 52.5 -> 4.6-5.4 ms. Total 287.2 -> p50 191.2 ms over 9 samples
    (not the 20 a publishable lane needs; the host became too loaded to finish
    the set, so there is no p95/p99 yet).
    Admission's three pre-boot chain barriers now
    share one flush, closing #2293's open acceptance item without changing
    `sync_policy_for`'s fail-closed default, and the chain cursor reads a
    bounded tail instead of the whole 4 MiB segment on every append. **Two things are open
    and newly named.** The receipt write, not the chain, is the dominant admit
    cost at ~36 ms of ~45 ms — a structure the code calls a derived cache,
    doing an `F_FULLFSYNC` synchronously before boot. And
    `stop_pid_disappearance` is guest-RAM teardown: `shutdown-timing.json`
    accounts for only 2.9 ms of it, because the host waits on kqueue process
    exit while the record stops before the process exits. It is linear in guest
    memory at ~48 ms/GB (33 ms at 512M, 194 ms at 4G), so the watchdog
    self-pipe is not worth building and a large workload pays teardown no
    `alpine`-sized benchmark can see.
  - [ ] Phase 7 — live validation and regression gates
  - [x] Cross-plan fast-machine-substrate contract documented in
        `specs/notes/2026-08-10-fast-machine-substrate.md` (issue #2279)
  - [~] Kernel/boot-substrate budget and filesystem-path evaluation tracked by
    issues #2280 and #2281. The artifact-ledger slice of #2280 and the
    pure-Rust ext4 baseline report are landed. Whole-VMM warm-ready and
    first-command memory/fault instrumentation is also landed; its
    real-host matrix, canonical budget/gates, candidate filesystem
    comparison, and the adopt/decline decision remain open.

- [ ] Plan 311 — Launch critical-path waste on real-sized images
      (`specs/plans/311-launch-critical-path-waste.md`), branch
      `plan/311-launch-critical-path`. Sits beneath Plan 299's contract: its
      baseline runs `alpine` (9.9 MB rootfs), and three per-launch costs are
      invisible at that size. On `python:3.12` (1.1 GB, 116x) a debug profile
      shows ~557 ms re-hashing the cached rootfs for OCI provenance, ~67 ms in a
      `ps` subprocess reaping orphaned helpers, and ~28 ms scanning `vmlinux`
      for dm-verity markers with `windows().any()`. The Plan 299 lane gate
      cannot see any of it — a re-hash is not a pull, build, mount
      materialization, or warm claim.
  - [x] Phase A0 — release baseline on both images. `python:3.12` 1.15-1.57 s
        vs `alpine` 0.52 s wall clock on identical code and cache state, which
        is the finding restated as a measurement.
  - [x] Phase B — `sha256_file_cached` on the OCI admission path — **#2273**.
        The two kernel-digest sites stay uncached on purpose (an integrity pin
        must not read a mtime-keyed cache); `run.rs` already hashed the rootfs
        through the cache, so the OCI path was the outlier, not the precedent.
  - [x] Phase C — process-table sweep moved to the builder-VM spawn sites —
        **#2274**. A cache-hit resolve spawns no helper and now walks no
        process table.
  - [x] Phase D — `memmem` replaces `windows().any()` in the kernel verity
        probe — **#2275**. A verdict sidecar was considered and rejected:
        ~5 ms in release is not worth caching a safety check.
  - [x] Phase E — `artifact_bytes_hashed` + `process_table_scans` on the launch
        sample, both refused by the prepared lanes — **#2276**. Plan 299's
        contract table now names the image behind each percentile.
  - [~] Phase F — validated on both backends. HVF meets the contract at
    p50/p95/p99 on a 1.1 GB image (dispatch 77.3 / 79.7 / 90.1 ms against
    ≤200 / ≤250 / ≤300), and `alpine` and `python:3.12` now agree inside
    run-to-run noise where they used to differ by ~780 ms. claim-8 /
    claim-14 digests unchanged, chain still verifies. Firecracker/KVM
    repeated: the fixes hold there (both counters zero) but that backend
    misses the contract for reasons this plan does not own — residual
    Firecracker boot work (**#2299**; **#2292** is closed by PR #2463) and
    receipt durability on the admission path (**#2318** is closed by PR #2465).
    Audit-chain batching and duplicate
    admission are closed under #2293. Outstanding: the warm-lane
    comparison, blocked because no standby pool can be filled today.

- [~] eBPF vsock egress telemetry spike — **issue #2211**, branch
  `feat/ebpf-vsock-egress-telemetry`
  - [x] Remove the standalone `mvm-ebpf-egress` crate; fold the Aya loader
        and eBPF program into `mvm-hostd` and the observability target
        metadata into `mvm-runtime`
  - [x] Add `VmObservabilityTarget` sidecar in `mode.json` and wire
        `EbpfTelemetryManager` attach/detach hooks into
        `Supervisor::launch`/`stop`
  - [x] Add vsock egress counters to the global metrics snapshot and keep
        macOS/Windows builds on no-op stubs
  - [x] Host workspace `check`, `mvm-runtime`/`mvm-hostd` all-target Clippy,
        `cargo fmt`, and focused telemetry unit tests pass
  - [x] Build the real Aya eBPF object with nightly + `bpf-linker`
        (`just build-ebpf` builds `bpfel-unknown-none` on any host)
  - [x] End-to-end attach→detach integration test via `mode.json` sidecar
  - [x] Full workspace test run on the host (cargo nextest: 10134 passed,
        18 skipped; cargo test previously flaked on one netd test that
        passes in isolation)
  - [x] Full workspace test run in CI / Linux builder VM (PR #2214)
  - [x] Implement Linux Aya load/attach/ring-buffer read path
        (cross-compiles for x86_64-unknown-linux-gnu via cargo-zigbuild)
  - [x] Validate load/attach on a live Linux host (PR #2221)

- [~] Plan 287 — Userspace socket datapath
  (`specs/plans/287-userspace-socket-datapath.md`, ADR-037)
  Tracked end to end under epic #2111, which also carries plan 285's
  deferred set. Every workstream below has its own issue; the epic
  records the ordering and the two gates that are not preference.
  **Frozen by plan 316 Phase 0.** ADR-037 is superseded for production
  workload networking: this datapath forwarded raw IP packets for
  `l3-vsock`, which no longer boots. No feature work lands on its runtime
  path; deletion is plan 316 Phase 7 (#2376).
  - [x] Phase A (WS0) — fix the two platform-neutral defects in the shipped
        `mvm-netd` drive loop that blocked this work and affected Linux
        today: a pollable descriptor out of `GuestConnection`, a
        `DatapathHandle::readiness_fd` accessor, a real monotonic clock
        replacing the per-frame counter that made a 5-minute idle timeout
        mean 300,000 guest frames, and a `mio` poll loop that drains the
        guest channel and the datapath independently so host-to-guest
        traffic no longer stalls while the guest is quiet
  - [x] Phase B (WS1, #2112) — the smoltcp-backed `UserspaceSocketDatapath`
        itself, making `l3-vsock` work on hosts with no privileges. All 16
        tasks landed: the TCP path, the deferred handshake so the
        guest's `connect()` never reports ESTABLISHED for a destination
        that has not accepted, the destination-integrity assertion, bounded
        queues, deadlines on the two states where no host error can ever
        arrive, UDP associations, and backend selection — `host_datapath()`
        now hands back the userspace datapath on macOS and wherever the
        Linux TUN probe fails, carrying the reason for the substitution so
        a later capability refusal is not a bare `missing: ["icmp"]`.
        `MacosUserspaceGateway`, the placeholder whose whole behaviour was
        a refusal, is deleted. The blocker exposed under task 14 — nothing
        in production drove `UserspaceHandle::service`, so a fallback
        host's guest could not complete a connect — is fixed: the drive
        loop services the datapath it owns. Task 15 adds nine unprivileged
        end-to-end witnesses, six driven through the real `mvm-netd`
        process rather than a handle the test services itself. Task 16
        closes it out in the docs: the guide's platform matrix now splits
        by forwarding backend rather than by platform, ADR-036's
        present-tense `MacosUserspaceGateway` prose is corrected, and
        ADR-037's memory ceiling is re-derived from `limits.rs` — its
        `1024 × 32 KiB = 32 MiB` was wrong three ways over, against a real
        46,500,608 bytes (44.35 MiB). **Three defects were shipped and
        recorded rather than hidden**, in ADR-037 §"Known defects in what
        shipped" and in plan 287's own deferred set; **two are now
        closed**. Every host socket the datapath opens is registered on the
        set behind `readiness_fd`, so a resolved connect and an arriving
        byte wake the drive loop rather than waiting out its 50 ms tick —
        the registration lives with the socket, so it cannot go stale at any
        of the places one is dropped out of a table. `poll_inbound` is
        bounded by `MAX_INBOUND_PACKETS_PER_PASS` and reports
        `InboundDrain::Backlogged`, mirroring the guest-facing drain rather
        than inventing a second mechanism. The two further defects found
        while closing those are **also closed**: a flow's host-to-guest
        pump now reports that same backlog when its per-pass byte budget is
        what stopped it, so a peer's tail no longer waits out the tick, and
        the association fixture that aimed at a closed loopback port — where
        the ICMP unreachable surfaced on the next `send` as `ECONNREFUSED`,
        deterministically on Linux — now aims at a destination that exists
        and discards. The last of the three is closed for datagrams by WS2;
        declared **TCP** ingress on this backend stays unserved and is
        recorded as the remaining over-claim
  - [x] WS1b (#2113) — fuzz the datapath ingress, and correct claim 5's
        recorded witness surface. **Gates backend selection in WS1 and the
        IPv6 guard in WS3**: the smoltcp ingress parser is unreachable by
        any guest today, and selection is precisely what puts it on a
        guest-controlled input path, so it is fuzzed before it is exposed
        rather than after. `fuzz_datapath_ingress` drives admission, the
        datapath's re-read of an admitted packet, and the per-flow smoltcp
        stack; claim 5 now records it in `model/claims.toml` and ADR-001
  - [x] WS1c (#2114) — bounds audit. The `DEFAULT_MAX_HOST_SOCKETS` comment
        said "back under 44 MiB", which counted only the per-flow term
        (43.16 MiB) and omitted the three machine-level terms the constant
        itself sums; it now states 44.35 MiB and names both. The
        machine-wide device term gained an assertion of its own — losing it
        and losing the UDP term each move the total by the same 384,000
        bytes, so the total alone could not say which. Thirteen mutations
        drove every component constant and every term of the formula; all
        thirteen red. No bound was changed: `FD_RESERVE` is uncounted slack
        and `DEFAULT_MAX_HOST_SOCKETS` is an affordability ceiling rather
        than a demand figure, and both comments now say so instead of
        implying a derivation neither has
  - [x] WS2 (#2115) — UDP ingress: declared inbound datagram mappings,
        admitted explicitly rather than inferred from traffic. A UDP
        mapping is declarable end to end (plan, lease, netd config,
        `IngressTable`), `DatapathRequest` carries the declarations, and
        `DatagramIngress` binds one host listener per mapping on **exactly**
        the address declared — the bind address is the exposure decision,
        and no second per-source allow-list was invented because the plan
        carries none. The guest port comes from the declaration, never from
        the datagram's own destination port. Binding is not admitting: a
        synthesized packet goes back through `admit_inbound`, so a withdrawn
        declaration stops delivery while the socket is still bound
        (`an_inbound_datagram_reaches_the_guest_only_while_its_mapping_is_declared`,
        mutation-proved). A guest answer leaves a listener only toward a
        peer that has written to that mapping, since the listener's socket
        is unconnected and would otherwise be an egress route around the
        admitted-destination check. Bounded like the rest of the module —
        16 listeners, 32 peers each, both dropping the newcomer rather than
        evicting — and the memory ceiling moved with it: a fifth term,
        `UDP_INGRESS_BUFFER_BYTES`, and one shared per-poll divisor took the
        association batch from 4 datagrams to 3, so the ceiling is now
        46,673,216 bytes (44.51 MiB). `declared_ingress: true` is honest for
        datagrams; declared **TCP** ingress binds nothing here and stays
        recorded as an over-claim
  - [x] WS3 (#2116) — IPv6 as a first-class family (ADR-038). **Complete:
        admission, the guest kernel, in-guest configuration, and host-side
        v6 allocation have all landed. IPv6 is opt-in per plan.** The fuzz
        gate that blocked the admission change is closed, so the guard now
        admits v6. One `embedded_v4` extraction runs ahead of every other
        rule and hands its result to the entire existing v4 class check —
        v4-mapped, v4-compatible, NAT64 and 6to4 all reach
        `169.254.169.254`, and the canonical-form peer assertion collapses
        exactly the distinction such a bypass exploits, so that check is
        the only defence rather than a backstop. Mutating the extraction to
        return `None` reddens seven tests, one of them on the resolver
        path. Native v6 classes mirror their v4 analogues, link-local a
        mandatory deny because `fe80::/10` is where NDP neighbours live.
        The userspace backend carries v6 flows and still cannot emit an
        arbitrary v6 packet, so `ipv6_flows: true` with
        `arbitrary_ipv6: false`; `FULL_L3_V4` is renamed `FULL_L3`.
        `CONFIG_IPV6` landed in the workload kernel, measured at +200,704 B
        and carrying no IPsec — the v6-IPsec options that drag XFRM in are
        disabled explicitly, so `XFRM`/`XFRM_ALGO`/`XFRM_USER` stay in the
        required-disable set and their absence is proven every build. The
        guest agent then grew the v6 half of its bring-up: address, on-link
        peer, default route and resolver over rtnetlink — chosen over an
        `AF_INET6` ioctl mirror because `in6_rtmsg`'s fields are private in
        `libc`, so that road ends in hand-rolled structs anyway. The
        requests are built by a pure function, so their order and every
        field are asserted off Linux; skipping the address request, the
        agent's v6 mapping, or the peer in the default route each reddens a
        distinct test. It runs in the same privileged phase as the v4
        sequence, so `CAP_NET_ADMIN` is held no longer than before, and a
        v6-only CONFIG is refused rather than half-applied.
        **Host allocation closed.** `L3NetworkSpec.features` is the
        request: a plan setting `IPV6` is leased a unique-local `/126` at
        the same index as its `/30`, out of one index space so a single
        `release` frees both families. The pool is `fd00::/8`, never global
        and never documentation space, and an allocator configured outside
        `fc00::/7` is refused. The consequence that mattered — every
        guest's own address now sits in the range the class check closes —
        holds the right way round: a machine still cannot reach its
        neighbour's leased address, its neighbour's gateway, or unrelated
        ULA space under any policy including `unrestricted`, witnessed at
        the admitter and again end to end through the real guest agent, and
        mutation-proven against removing the ULA arm. `assign_config` sends
        the pair, `features::granted` is the intersection of what the guest
        offered and what the host leased, and `Config::decode` refuses a
        frame where the bit and the assignment disagree. A leased pair sets
        `required_capabilities.ipv6_flows`, so a backend without it refuses
        at open with a shortfall naming it — closing ADR-037's fourth known
        defect. A plan that does not ask is unchanged in every byte.
        **Both backends now carry the family.** The packet backend's v6
        half is the host-side mirror of the guest's: an `AF_INET6`
        `SIOCSIFADDR` puts the gateway's `/126` on the TUN, which is what
        creates the connected prefix the guest's address sits in, and the
        `inet` ruleset pins the v6 source beside the v4 one — so it
        declares plain `FULL_L3`, `arbitrary_ipv6` included, since a device
        that carries whole packets never cared which family they were in.
        Witnessed on real hardware in the privileged lane (11/11): the
        forward chain drops a v6 source the host never assigned while the
        assigned one passes, proven by broadening the source match (the
        spoof passes) and by deleting the rule (the control stops passing);
        and with two machines open — so a neighbour's `/126` really is a
        connected route — a guest still cannot reach the neighbour's
        address, its gateway, or unrelated ULA space, mutation-proven
        against the ULA arm. A v4-only lease loads a ruleset with no v6
        rule in it at all.
        **Still unwired above the plan:** no `mvmctl` surface populates an
        `L3NetworkSpec` at all — every `SynthesisInput` site passes
        `l3_network: None`, and the boot path also hardcodes
        `network_mode: Default` — so a CLI/IR knob for IPv6 alone would be
        inert on the path that boots a VM; the two belong together
  - [x] WS4 (#2117) — benchmarked 2026-08-04; **multi-queue rejected, no
        implementation code**, which is the intended outcome when the
        numbers do not support the work. Six `#[ignore]`d benchmarks extend
        the existing `userspace_datapath.rs` suite, reusing its `Translator`
        rather than standing up a second harness. Aggregate host→guest
        throughput **rises 3.2×** from 1 to 16 flows (6.6 → 20.9 Gb/s
        median, 8 runs), so a single serial service pass is not the ceiling
        multi-queue presumes. What limits _one_ flow is a fixed ~12.8 µs
        per-pass cost that is almost entirely one syscall: on macOS a
        zero-timeout `kevent` returning **no** events costs ~12,600 ns
        against 171–430 ns when it returns one, reproduced in pure C with
        none of this code in the picture, and `drain_for` only terminates on
        a zero return. **Since fixed**: the drain now stops on a _short_
        return, which a drained queue is already reporting, so the
        terminating empty call is gone. Re-measured on the same host —
        guest→host **2.9×** (1.9 → 5.5 Gb/s), host→guest 1.12× (7.0 → 7.8),
        round-trip p50 68 → 53 µs. The gain splits that way because the
        removed call is the _second_ one, and only ~37% of host→guest drains
        find anything to make a second call about. The remaining ~12 µs is
        the empty _first_ poll, and the obvious fix for it — skip the drain
        when readiness did not wake the pass — is measurably **unsound**: an
        outer kqueue is edge-triggered on the inner set going non-empty, so
        a set left dirty never wakes the drive loop again, and the
        unconditional drain is the only thing that repairs it. Recorded as a
        new deferred item with the probe results. On Linux, measured:
        `epoll_wait` costs the same either way (~480 vs ~610 ns), so the fix
        is harmless there and buys nothing.
        Per-byte capacity is ≈26 Gb/s on one core; latency p50 68–73 µs
        round trip, 78–130 µs connect→established. The guest→host figure
        (2.0 Gb/s) is a floor bounded by the benchmark's own send window,
        and says so. Also fixed in passing: `l3_linux_privileged.rs` had not
        compiled for Linux since the IPv6 field addition, because
        `just check-linux` is `--lib` and never builds Linux-gated test files
  - [ ] WS5 (#2118) — zero-copy / batched transfer, gated on the same
        measurement; must keep the memory ceiling assertable
  - [~] WS7 (#2119) — node-to-node transport for cross-host VM traffic.
    **Designed, deliberately not implemented: ADR-040.** Three of the
    four properties the hop must preserve cannot be preserved today,
    each for a reason outside the transport. No cross-node trust root
    exists and building one here would be a second one beside the
    plan-signing root (needs WS8); addresses are not unique across
    nodes, so a destination IP does not name a VM and a peer's address
    collides with a local machine's; the policy language cannot name a
    peer workload and `IngressTable::admits` takes no source, so
    admitting a peer means admitting the host network. The fourth
    blocker — no audit record for the hop to preserve — is now closed
    by the gateway audit path below. The ADR records the design, the
    rejected alternatives, and the four unblocking conditions
  - [~] WS8 (#2120) — mvmd-facing node-control API, mvm side only.
    **The mvm half is implemented** (`mvm_hostd::nodectl`, ADR-041,
    sequenced in `specs/plans/295-node-control-api.md`): ownership is
    a uid comparison against the connection's peer credential and
    never a field in the message, so a caller is refused a machine it
    does not own and a listing carries only its own. Forcing
    `CallerIdentity::owns` to `true` reddens five tests. Wire types
    are `deny_unknown_fields`, tables are bounded and drop rather
    than evict, and nothing here binds a listener. **The cross-node
    issuer is deliberately not built**: ADR-041 answers ADR-040's
    open question by placing the issuer with the control plane and
    the verification seam here, so this _half_-unblocks #2119 rather
    than unblocking it — a key scoped to a node pair would still be a
    second trust root. The fleet-orchestration half stays in mvmd
  - [x] Gateway audit (#2151) — the L3 gateway now writes chain-signed
        entries. `mvm_hostd::netd::audit::NetdAuditor` routes every
        `GatewayEvent` through the **existing** supervisor `Recorder`
        under a new `EventCategory::L3`, so there is one audit path
        rather than a second one. Twelve event names, one per variant.
        Decisions, never traffic: an entry per packet would be a write
        amplifier a guest drives at line rate, so repeats fold into two
        bounded dedup tables — one keyed on host-defined enumerations,
        one on guest-chosen values and capped. A decision that cannot get
        a guest-keyed bucket **degrades to its class key rather than going
        unrecorded**. The caps are the whole rate bound (768 entries per
        30s); a separate emission budget was considered and dropped,
        because above the caps it never fires and below them it makes the
        degrade path unreachable.
        Emission is fail-open and counted, because this process is the
        only way a workload reaches the network and a signer fault must
        not become a network outage; what never reached the chain is
        written to the chain at teardown. Mutating `fact_for` to drop
        `FlowDenied` reddens nine tests, including the end-to-end one
        against the shipping binary; stubbing `emit` reddens thirteen.
        Both dedup tables joined `MEMORY_CEILING_BYTES` and its
        residual-form assertion.
        **Six facts ADR-036 named are not emitted** — tunnel
        requested/connected/configured, flow closed, ingress
        opened/closed — because none has a call site; recorded as such in
        the ADR rather than claimed
  - [ ] WS9 (#2121) — WSL2 validation on a real runner; documented and
        scheduled rather than claimed, since no live Windows host is
        available
  - [x] WS6 (#2122) — **rejected 2026-08-03**: mvm adds no root-capable
        component. macOS raw IP would need a `utun`, which needs root and
        which no entitlement avoids. ICMP, raw IP and arbitrary IPv4/IPv6
        stay refused at admission on the userspace backend, honestly and
        for a stated reason. ADR-039 status Rejected; reopening requires a
        workload with a demonstrated need
- [x] Extract `mvm-backends` crate (`specs/plans/298-extract-mvm-backends-crate.md`)
  - [x] Driver seam (`VmmDriver`, `VmmSpec`, `RunningVm`, snapshot types) moved to `mvm-vmm`
  - [x] Host `virtiofsd` helper moved to `mvm-vmm`
  - [x] Shared host helpers (`host_agent_spawn`, `substitution_spawn`, `broker_services_spawn`, `netd_spawn`, `aux_bin`, `egress_shared`, `workload_wait`, `drive_file`, `process_liveness`) moved to `mvm-vmm::host`
  - [x] Microvm boot/cmdline helpers (`boot_config`, `egress_bridge`) moved to `mvm-vmm::host`
  - [x] Substrate helpers (`open_console_capture`, `runtime_meta`/`observability_target`, `ui`) moved to `mvm-vmm::host`
  - [x] `mvm-backends` crate scaffolded; `MockDriver` lives under `test-support`
  - [x] Host command execution (`shell`, `linux_env`) moved to `mvm-vmm::host`
  - [x] Move concrete drivers: all five (`FcDriver`, `HvfDriver`, `LibkrunDriver`, `QemuDriver`, `MockDriver`) now live in `mvm-backends`
- [x] Extract the Firecracker driver (`specs/plans/298-extract-firecracker-driver.md`)
  - [x] Snapshot seam (`SnapshotIO`, guarded load paths, device-model guard, the single `CannedIO` double) lifted into `mvm-vmm`
  - [x] `ForkVmFullRestorer` deleted — one method, one impl, one call site; now a callback
  - [x] FC mechanics moved to `mvm-backends::fc` (API client, VMM process, control, observe, guards, snapshot, fork namespace, `FirecrackerIO`, `FcVmFullControl`)
  - [x] `driver/fc.rs` and the legacy `FirecrackerBackend` moved; `mvm-runtime::driver` is re-exports only
  - [x] `base/config.rs` moved to `mvm-vmm::host` (dependency-free leaf that pinned the FC modules)
  - [x] Dead code removed: the retired raw flake launcher, the `require_linux_env` no-op, and the duplicate `bind_unix_listener`
  - [x] Move legacy `VmBackend` implementations (`FirecrackerBackend`, `HvfBackend`, `LibkrunBackend`, `QemuBackend`) into `mvm-backends`
  - [x] Wire `mvm-runtime` to depend on `mvm-backends` and re-export the driver surface; removed local HVF/libkrun/QEMU/Mock driver and legacy backend source files
- [ ] Plan 301 — Finish WS11: `WasmBackend` completion + the P4 browser slice
      (`specs/plans/301-wasm-backend-completion-and-browser-slice.md`) — plan
      landed, execution not started. Bound by ADR-024's three constraints;
      adds no numbered claim.
  - [ ] Part A (host tier): A1 end-to-end `start()`→endpoint-subprocess
        coverage; A2 = P3c TLS-terminating substitution (http-only today);
        A3 transparent WASI socket interception; A4 resolve the Preview 1 vs
        "target Preview 2" divergence; A5 ADR-024 Status is stale (claims no
        implementation has landed — false since P2) + `deny.toml` review;
        A6 run one governance witness across all workload backends
  - [ ] Part B (P4 browser): B1 extract the `no_std` OCI decoders — **the long
        pole; they do not exist today** (`mvm-fs` is std-heavy), via the
        Increment 3 verbatim-relocation method; B2 Worker + thin proxy;
        B3 OPFS content-addressed cache with verify-on-read; B4 `wasm-opt -Oz` + gzipped-size budget in the existing wasm lane; B5 delete
        `web/audit-verify/`, fix the stale `mvm-verify` refs in ADR-031, add
        `mvmctl audit pubkey`
- [x] Plan 320 — A live wasm sandbox demo on the website
      (`specs/plans/320-wasm-browser-demo.md`) — PR #2429 merged to `main`;
      hardening items closed in #2441. This follow-up fix (#2447) adds the
      wasm build to `.github/workflows/pages.yml` and corrects
      `web/mvm-demo/build.sh` to preserve the `pkg/` subdirectory when staging,
      so the live `/demo` route serves the bundle. Browser-engine sandbox at
      `/demo`, landing teaser, Web Worker ownership, curated `wasm32-wasip1`
      fixtures, Rust fixture-parity tests, and `wasm-opt -Oz` + gzipped size
      budget in the Linux wasm lane. Egress decision, placeholder substitution,
      and audit-entry construction/chain signing are relocated into
      `mvm-contract` so host and browser run
      identical code. Claim-free by ADR-024 §3; adds no claim-catalog witness.
  - [x] E2.1 — the placeholder leaf relocated as
        `mvm_contract::substitution`; the constant hard-renamed to
        `SECRET_PLACEHOLDER_PREFIX` to avoid colliding with
        `policy::secret_binding`'s then-existing
        `PLACEHOLDER_PREFIX` (`"mvm-managed:"`, since deleted with that
        module). Minting stays host-side to keep `getrandom` out
        of the browser bundle.
  - [x] E1 — `projection.rs` relocated to `mvm-contract` verbatim; the
        `mvm_core::policy::projection` module re-export kept all ~20 call sites
        unchanged and `wasm_egress_witness.rs` green **unmodified**. The
        `is_mandatory_deny`/`mandatory_deny_ranges`/`unmap_v4_mapped`
        predicates it decides with moved down with it (re-exported the same
        way); the iptables generators stayed in `mvm-core`. Side effect: the
        54 projection tests plus 10 mandatory-deny tests now run under
        `wasm32-wasip1` (651 → 715), closing plan 301 P1's "tests under wasm"
        gap for this module.
  - [x] E2 substitution core — complete. E2.1 relocated the placeholder
        leaf as `mvm_contract::substitution` with the hard-renamed
        `SECRET_PLACEHOLDER_PREFIX`. E2.2 de-duplicated the claim-12 bind
        check as `mvm_contract::ir::host_is_bound`. E2.3 moved the portable
        half of `SubstitutionRegistry` down as `PlaceholderMap`
        (insert/resolve/host_is_bound), leaving the OS-RNG `mint` in the
        host wrapper so the browser bundle does not pull `getrandom`. E2.4
        relocated the pure text replacement as
        `mvm_contract::substitution::substitute_into`; the host `Injector`
        wraps the result in `Zeroizing`. E2.5 extracted the pure header-walk
        core of `prepare_request` into
        `mvm_contract::substitution::prepare_request` over a
        `SubstitutionDriver` trait; the host `SubstitutionEndpoint` implements
        the trait and the existing `prepare_request` wrapper keeps all call
        sites and tests unchanged.
  - [x] E3 audit writer core — option A landed. E3.2 hard-renamed the host
        chain-signed entry to `PlanAuditEntry`; E3.3 de-duplicated
        `hash_line` and `signed_bytes_for` into `mvm-contract::verify`; E3.4
        moved `PlanAuditEntry` into `mvm-contract` as a generic type (host
        instantiates with `TenantId`/`PlanId`/`PolicyId`/`DateTime<Utc>`, the
        browser uses string defaults); E3.5 unified `SignedEnvelope` and
        retired `MirrorEntry`; E3.6 exposed the pure `seal()` helper and made
        `FileAuditSigner::write_signed` call it. The frozen audit-chain
        fixture still verifies unchanged and `wasm_egress_witness.rs` is
        green.
  - [x] Oracle for both: `wasm_egress_witness.rs` must stay green
        **unmodified**.
  - [x] `web/mvm-demo/` wasm-bindgen crate, workspace-excluded; Worker-owned
        UI + thin main-thread proxy; three curated WASI fixtures
        (allowed / denied / unbound) with `wasm-opt -Oz` and a gzipped-size
        budget; tamper button; Astro `/demo` route and landing teaser. The
        `build.sh` produces the deployable bundle and the `website.yml`
        workflow builds it before Astro. Crate exposes `decide_egress`,
        `substitute_placeholder`, `verify`, and `run_scenario` shims over
        `mvm-contract`; `seal()` is available in `mvm-contract` for the demo
        to sign real audit entries.
  - [ ] Does **not** retire `web/audit-verify/` (no Merkle inclusion) — B5 and
        `mvmctl audit pubkey` remain plan 301's
- [ ] Run-first CLI ergonomics
      (`specs/plans/329-run-first-cli-and-upstream-adoption.md` — note three
      plans share the number 329; refer to this one by path) — Phase A landed:
      ADR-027 amended so `run` is a first-class visible verb, the fifteen
      user-facing verb groups promoted out of `hide = true`, twelve missing
      reference rows written, and `xtask check-cli-help-matches-docs` added to
      the Lint job so `mvmctl --help` and the published CLI reference cannot
      drift apart again. Phase 5 (snapshot/fork DX) was already complete.
      Phase 1 then landed the shared argument core: the 26 shared execution
      flags are declared once in `RunArgs` and flattened into both verbs, with
      `run` adding the SDK transport and `machine run` the lifecycle flags. Both
      verbs now default to `--profile standard`. Phase 2 then landed runtime
      detection: `mvm_core::runtime_catalog` plus one shared resolver whose
      order is explicit source > `--runtime` > `mvm.toml` walk-up > argv[0] >
      project file > bundled default. Inference is `run`-only; `machine run`
      keeps its explicit-source contract. Phases 3–4 and 6–8 remain.
- [ ] Plan 329 — Browser-tier microVM demo (`specs/plans/329-browser-wasm-backend-demo.md`)
      — in progress on `feat/329-browser-wasm-backend`. Extends Plan 320 with a
      `wasm32-wasip1` guest that boots, provides a shell, and delegates `fetch`
      to a host `mvm:egress` import gated by `mvm-contract` `NetworkPolicy`.
      Audit entries (`vm.start`, `egress.allow`, `egress.deny`, `vm.stop`) are
      signed in the Worker and rendered live. E2E Playwright test passes; remote
      node bridge (Slice 5) remains open.
- [ ] Plan 321 — wasm as a workload format inside a real microVM
      (`specs/plans/321-wasm-in-microvm-workload-format.md`) — design, not
      started. ADR-024's sanctioned engine-in-guest path: a wasm workload
      inherits claims 3/10/13/15 from the microVM it runs inside, because the
      isolation boundary is the microVM and wasm is only the executable format.
      No new `BackendKind`.
  - [ ] WS1 Nix factory row (`interpreter = null` + wrapper-kind discriminator,
        per `nix/lib/factories/languages/default.nix:17-20`); WS2 end-to-end
        compute-only run on a real backend; WS3 egress is blocked on WASI
        Preview 1 having no sockets — deferred deliberately, not shipped
        half-governed; WS4 stale-reference cleanup + ADR-024 Status fix
  - [ ] Already present: `Language::Wasm` in `mvm-agentd/src/runner/config.rs`,
        `wasmtime run` in `mvm-runner.rs:154`, `wasm` in
        `mvm-contract/data/supported_languages.txt`. Only the image half is
        missing.
- [ ] Plan 298 — NANDA-style execution receipts and conformance badges
      (`specs/plans/298-nanda-receipts-and-conformance-badges.md`)
  - [x] WS1 RFC approved: `ExecutionReceipt` and `ConformanceBadge` envelopes,
        JCS canonicalization, Ed25519/`did:key` signing, chain semantics, and
        mapping to existing `AuditEntry` events defined
  - [x] WS2 Core types and canonicalization: `receipt.rs`,
        `conformance_badge.rs`, `did_key.rs`, unit tests, workspace clippy clean
  - [x] WS3 Read-only receipt exporter: `mvmctl trust audit receipts export`
        derives signed `ExecutionReceipt`s from verified chain-signed
        `AuditEntry` events; unit + integration tests pass
  - [x] WS4 Runtime emission of receipts: `AuditEmitter::with_receipts()`
        persists signed `ExecutionReceipt`s alongside chain-signed audit
        events; per-tenant receipt store with `prev_receipt_id` continuity
  - [ ] WS5 Conformance badge generator
  - [ ] WS6 Documentation and registry conventions

- [x] Plan 291 — Develop → build → deploy an attested workload image
      (`specs/plans/291-develop-build-deploy-attested.md`)
  - [x] WS1 `mvmctl deploy`: seal, BLAKE3 identity + SHA-256 interop, deploy
        record; retain the local sealed artifact and ship it to mvmd through
        the authenticated upload contract when a remote is configured
  - [x] WS2 `mvmctl watch`: rebuild on change, skip no-op rebuilds by address;
        long-running mode recovers from transient input/compile errors while
        `--once` remains fail-fast
  - [x] WS3 capture-from-sandbox via `reseal_volume`, converging on the
        declared-dependency path and keeping the lockfile hash pin; capture,
        `deps install`, and bounded `deps capture-live` implementation are
        present. PR #2132 passed branch and merge-group Test, Lint, and Nix
        gates and merged into main
  - [x] WS4 tier follows the attestation
    - [x] Agent-verb grant derives from admitted run shape, not image sidecar
    - [x] Bind the tier to an attested artifact and replace the interactive
          feature/symbol witnesses with conformance scenarios. Local
          `machine run --deployment` verifies and persists the signed record
          plus exact rootfs binding; remote extraction/boot are merged, and
          persistent-OCI console listeners now pre-open only for dev profiles
          (PR #2157). The universal agent is built once, while runtime profile
          and signed grant enforcement reject the complete DevOnly request set.

- [~] Plan 290 — Sensitive egress redaction
  (`specs/plans/290-sensitive-egress-redaction.md`)
  - [x] Validated byte detector and pinned, no-default-feature LeakGuard adapter
  - [x] Shared supplemental coverage for masking and reversible replacement
  - [x] Default secret/PII policy arms compressed and over-cap fail-closed gates
  - [~] Host workspace tests/check, workspace all-target Clippy and supply-chain
    gates pass; Linux builder-VM workspace all-target Clippy remains
  - [ ] Structured/streaming body coverage and split-boundary witnesses
  - [ ] Signed CLI policy lowering and admission posture reporting
  - [ ] Build-level claim promotion and adversarial backend witnesses

- [x] Plan 289 — Host-side machine logs
      (`specs/plans/289-host-side-machine-logs.md`)
  - [x] Read backend-captured logs from the isolated host VM state directory
  - [x] Preserve log flags without shell interpolation; follow mode honors the
        requested line count. Superseded by plan 295, which replaced the reader:
        `--lines`/`--follow`/`--hypervisor` and the explicit missing-log error
        survive, the pre-split `firecracker.log` substitution does not
  - [x] Cover host-only CLI behavior and log resolution with regression tests
  - [x] Keep isolated test state behind the canonical config resolver and home
        isolation gates
  - [x] Complete workspace tests, check, formatting, and all-target clippy

- [x] Plan 286 — Guest-kernel hardware floor
      (`specs/plans/286-kernel-floor.md`)
  - [x] Audit resolved x86_64/aarch64 configs and enforce required cuts
  - [x] Ratchet workload configs to 902 x86_64 / 936 aarch64 built-ins
  - [x] Shrink the x86_64 workload image by 46.8% and boot it on Firecracker
  - [x] Preserve, build and boot the 955-symbol builder-kernel contract
  - [x] Native 936-symbol aarch64 artifact built and booted to PID 1 on HVF
  - [x] Full validation, merge-queue readiness and rollup closeout

- [x] Plan 285 — HVF virtio-rng
      (`specs/plans/285-hvf-virtio-rng.md`, issue #2060)
  - [x] Portable bounded virtio-mmio entropy device and negative tests
  - [x] HVF FDT/run-loop wiring while retaining the early boot seed
  - [x] Live HVF guest binds `virtio_rng.0` and serves distinct entropy reads
  - [x] Full gates, merge, and issue closeout

- [x] Plan 284 — Zero-open-issue reconciliation
      (`specs/plans/284-zero-open-issue-reconciliation.md`)
  - [x] Classify and reconcile the original 19 open issues
  - [x] Land the queued fixes for #2007, #2028, and #2029
  - [x] Land the security, kernel-pin, installer-fixture, and cold-cache-test
        fixes for #1983, #1937, #1972, and #2035
  - [x] Repair newly filed #2039
  - [x] Repair newly filed #2042
  - [x] Repair newly filed #2048
  - [x] Resolve newly filed #2052 through the merged shared guest-bootstrap fix
  - [x] Revalidate and close newly filed #2054 on current main
  - [x] Execute the refiled volume epic #2040
  - [x] Verify the repository has zero open GitHub issues
  - [x] Repair the subsequent scheduled-security alert #2067 and retain a
        PR-time regression witness for its mutation-shard toolchain
  - [x] Add executable Linux mutation witnesses for the L3 privilege-drop path
        exposed by #2067's exact security rerun
  - [x] Pin libkrun's L3 refusal and classify its default-equivalent mutation
        exposed by #2067's exact security rerun
  - [x] Add a fail-closed bounding-set result classifier whose Linux mutation
        witness kills the final comparison survivor from the corrected-head run

- [x] Plan 283 — Production object-store volumes
      (`specs/plans/283-production-object-store-volumes.md`, issue #2040)
  - [x] Canonical mvm contract and dead S3-path removal
  - [x] Live local/block attachment through the admitted VM launch path
  - [x] mvmd OpenDAL → `object_store` migration with mandatory encryption
  - [x] Authenticated remote volume CLI/client lifecycle with typed failures
  - [x] Canonical worker handoff, Linux/KVM composition proof, and follow-up PR
        matrices are green
  - [x] MinIO integration plus Linux/KVM persistence and restore proof
  - [x] Reconcile rejected speculative clauses and close #2040 with evidence

- [~] Plan 295 — Workload stream plane
  (`specs/plans/295-workload-stream-plane.md`)
  - [x] T1–T3 — stream record DTOs + chain verify; transcript stream
        directions and per-chunk linkage; ring retention
  - [x] T4–T5b — guest pump emits as produced; fd-3 control records; the
        entrypoint RPC response streams
  - [x] T6–T6b — host broker ingest/redact/chain/fan-out; chunks batched into
        segments
  - [x] T7–T8 — console capture as a second broker source; the client reader
        trait, tracing bridge, and SDK surface
  - [x] T9 — `mvmctl logs` over the broker, the durable transcript, and the
        console capture (history splice + exited-VM path), `machine run`
        attaches unless `--detach`, and the builder-VM `tail -f` path is gone
  - [x] T9 fix round 1 — a capture the filter emptied reports as present rather
        than absent (`EmptyHistory`); a console-only read refuses a channel
        selection or resume point it cannot supply instead of ignoring it under
        a contradicting warning; and the hole between the sealed history and
        the live head is reported (`SpliceGap`) rather than rendering a partial
        log as a complete one
  - [x] T9b — the plane is constructed in production: `StreamPlane` stands a
        broker, its socket, its ring-retained transcript, and its console
        follower up on VM start and seals them on stop; `mvmctl` registers it
        at startup through the runtime's `ConsoleStreamer` hook, unconditional
        and never admission-gated
  - [x] T9c — the second source is wired: entrypoint `stdout`/`stderr`/fd-3
        frames are ingested as `StreamSource::Entrypoint` with their true
        channel, so `logs --stream stderr` returns what the workload wrote
        there. `mvmctl invoke` prints what the broker cleared rather than the
        raw frame, so it and `logs` show the same redacted, chained bytes and
        neither is a path around the redaction seam
  - [x] T9d — every workload shape seals: the durable writer mirrors each landed
        chunk into an append-only journal beside the segments, so a `stop` in a
        different process from the `start` rebuilds and seals that VM's
        transcript instead of leaving a directory of ciphertext no reader can
        open. A rebuilt seal is marked `adopted` (inside the sealed root) and
        reports as incomplete, because nothing on disk records what the
        departed process shed on its way out. Teardown also kills before
        releasing the capture, so a dying guest's last words reach the chain
  - [x] T10 — `ExecutionPlan.stream_retention` (`Persist` default / `Ephemeral`
        opt-out) is admitted, labelled on `plan.admitted`, and honoured by the
        plane: an ephemeral run gets the same broker, socket, redaction, chain
        and fan-out, creates no capture directory, and seals to no manifest
        rather than to an empty one that would assert the workload printed
        nothing. ADR-035 records the posture including the three limits found
        during execution (the console fallback is redacted on read, the follow half
        is open for detached workloads, a spliced read repeats its adopted
        prefix). Website guide `guides/workload-output-streaming.md` plus the
        stream surfaces in the CLI reference. `CLAUDE.md` corrected on the
        claims-ledger location, the `mvm-client` facade, and the fabricated
        claim-12/13 witness names
  - [x] T11–T15 — the input plane (Phase 2): frame DTOs and the plan grant;
        the grant/lease/secret-scan gate; agent-side delivery and EOF; the
        route from gate to guest sink; the sealed-tier refusal of the input
        grant for a shell-shaped entrypoint; and the claims ledger — claim 15
        reworded (it used to hold by _absence_, there being no host→guest byte
        path at all, and now holds by _policy_) and claim 17 added at status
        `Preview` with a limits note (T17 below closed two; plan 293 WS1 closed
        the third by giving the scan fingerprints, and its follow-on closed the
        blanket carry's stall with a content-independent idle release; the two
        that remain are permanent properties of hashing and of scanning)
  - [x] T16 — the input plane's documentation: a sibling guide
        `guides/workload-input.md` (grant, single-writer lease, secret scan,
        explicit EOF, the `--prod` shell refusal stated as the heuristic it is,
        and the four limits), the claim-15 trade recorded as a decision in
        ADR-035, and the reconciliation of every user-facing site that still
        asserted claim 15 in its old absence form — README ×3, the
        isolation-tiers reference, `specs/01-project.md` ×3, plus ADR-035's own
        security-posture section and the sealed-prod verb table in
        `reference/guest-agent.md`, which had drifted from the `ProdSafe`
        classification of `StreamInput`/`CloseStreamInput`. ADR-001's limit 3
        sharpened: `StreamPlane::open_input` is the only route into the gate and
        has no caller outside `tests/workload_input_plane.rs`, so _neither_ half
        of the input plane has run on a real VM — "proven end to end" described
        test fidelity, not liveness
  - [x] T17 — the operator surface, landed with a live entrypoint resolver in
        the same change as the plan required. `machine run --entrypoint --stdin
-` opens the route under the plan that boot was admitted under, pumps
        the caller's stdin through the gate in acceptance order on its own
        thread, refreshes the lease on a ticker while the writer is idle, and
        closes the workload's stdin on the caller's EOF. The grant is
        conditional on the request, so a call that did not ask carries no
        `host.stream.v1`. The entrypoint is resolved from the image's
        `mvm-meta.json` sidecar — a new `entrypointArgv` field written by both
        the `mkGuest` and OCI build paths, because the host cannot read inside a
        materialized ext4 — and admission **fails closed** when it cannot
        resolve one, so the shell refusal cannot go dormant again
  - [~] Residual after T9b/T9d: T9d closed the _seal_ half — a detached run's
    transcript is now sealed by whatever stops the VM. The _follow_ half
    remains: the console follower still dies with the starting process, so
    output a detached VM produces after that point reaches no capture at
    all until a resident host process owns the plane
  - [ ] Deferred to the broker task: state a follower's start sequence in the
        first batch, so the reader can close the accept-window gap between the
        transcript snapshot and the live subscription
  - [ ] Deferred to the broker task: re-seal the stream transcript periodically,
        so durable history exists for a _running_ VM and survives a kill
- [x] Plan 282 — Merge queue auto-requeue
      (`specs/plans/282-merge-queue-auto-requeue.md`)
  - [x] Refuse conflicts and bound retry attempts per PR
  - [x] Keep privileged execution on the trusted base ref with no checkout
  - [x] Complete repository validation and queue the PR

- [~] Plan 270 — Universal initramfs + vsock-activated boot
  (`specs/plans/270-universal-initramfs-vsock-activated-boot.md`)
  - [x] Core boot contract: `ActivateEnvironment` over the authenticated
        vsock session, `ActivationState` gate, PID-1 agent with mount
        library + uid-901 drop (#1914)
  - [x] Runner/driver adoption: QEMU unified runner (#1931), Docker
        dev-tier (#1933), Wasm activation (#1936), Apple Container kernel
        on HVF (#1968)
  - [x] Activation agent-readiness retry on the wire (#1985)
  - [x] Deterministic cargo initramfs replaces the Nix initramfs build
        (#1996); attestation stays the content hash + sidecar contract
  - [x] Retire the obsolete CLI workload-guest payload and dead
        skip-embedding switch; the universal initramfs/runtime overlay owns
        workload binaries (#2013)
  - [x] Pin `mvmctl` embedding to the builder/bootstrap host and seed
        manifests
  - [~] Deviations recorded at the unticked steps in the plan: capability-bit
    negotiation, chain-signed boot events, and vm_id/session binding were
    superseded by the path discriminator + session-key pinning; the
    guest-side activation idle timeout and focused zombie-reaping tests
    remain open
  - [~] Remaining rollout, snapshot, BDD, and live-smoke work stays in the
    plan

- [~] Plan 271 — Apple Container backend: Apple's container kernel on HVF
  (`specs/plans/271-apple-container-backend.md`)
  - [x] Stage 1 — fail-closed skeleton: kernel artifact resolution + thin
        HVF-runner delegation
  - [x] Stage 2 — live validation + claim review (2026-08-01): required
        `vmlinux.blake3` digest sidecar (fail-closed on absence/mismatch),
        sealed dm-verity boot proven on macOS HVF (gated e2e, 4.27s), CLI
        smoke via `machine run --hypervisor apple-container`, claims array
        stays a verbatim HVF-runner mirror (claim 3 stays DoesNotHold for
        the virtiofs-root path — owner decision)
  - [x] Admitted workload funnel un-barred (2026-08-01): `WorkloadBackend`
        implemented with the runner's `VsockUdsChannel` transport,
        `as_workload_backend` returns the backend, and
        `require_workload_backend` / `start_prepared` / the admitted
        persistent-OCI path accept `--hypervisor apple-container`
  - [ ] Container-mode closure (later stage)
- [x] Plan 281 — Merge queue latency audit
      (`specs/plans/281-merge-queue-latency.md`)
  - [x] Measure queue, merge-group, runner, execution, rebuild, and post-check
        latency from live GitHub metadata and logs
  - [x] Preserve required exact-commit validation while making merge-group
        triggering and cancellation behavior explicit
  - [x] Apply capacity-backed merge-queue settings in the repository ruleset

- [ ] Plan 279 — Build action identity and a real artifact manifest
      (`specs/plans/279-build-action-identity-and-artifact-manifest.md`)
  - [ ] WS1 — `ActionDigest` into the identity taxonomy (land after plan 276 WS6)
  - [ ] WS2 — `ArtifactManifest`: mode, xattrs, symlinks, hard links; one walk
        shared with the ext4 materializer
  - [ ] WS3 — Bind action → artifact, host-signed, into the chain-signed log
  - [ ] WS4 — Decision gate: measure, then decide the fetch/build network split
  - [x] Prerequisite, landed separately: narrow the nix workspace filter to an
        allow-list so a docs-only edit stops invalidating every guest binary
        (416 of 1872 files, 22%, stop being cache keys)

- [x] Plan 284 — CI lint and merge-queue latency
      (`specs/plans/284-ci-lint-latency.md`)
  - [x] Target only the packages that own `test-support` code
  - [x] Remove branch-local multi-gigabyte Cargo target caches
  - [x] Share nested `mvm-cli` builds across feature fingerprints
  - [x] Move man-page tests onto Test's warm compile graph
  - [x] Keep the removed MCP server and smoke lane out of CI
  - [x] Complete workspace and Linux clippy verification; the first live run
        passed and measured a 19–21 minute runner wait

- [x] Plan 297 — Parallel pull-request CI lanes
      (`specs/plans/297-ci-parallel-lanes.md`)
  - [x] Split independent lint and Linux-only test coverage into concurrent
        jobs without changing required check names
  - [x] Keep targeted feature coverage and Linux conformance coverage intact
  - [x] Complete workflow and repository verification
- [~] Plan 276 — Content-addressing conformance and defense
  (`specs/plans/276-content-addressing-conformance-and-defense.md`)
  - [x] WS0 — plan + recon note landed (#1964); axis/policy ratification open
  - [x] WS1 — pin the evidence each claim rests on: `witness_kinds` per claim
        in `model/claims.toml`, gated by `check-claim-catalog`. The original
        premise (two tier vocabularies over the same claims) was wrong — the
        registers share no key; the real gap was that a claim could be
        delisted from a whole kind of witness with every gate green
  - [x] WS2 — prose over-claim meta-gate, shipped as `xtask check-no-overclaim`
  - [~] WS3 — replay golden-vector corpus. `ir_hash`, `leaf_hash`,
    `interior_hash`, `merkle_root`, `compute_plan_id` and `bundle_sha256`
    now carry frozen addresses. The existing `ir_hash` tests were all
    _relational_, so a canonicalization change moving every address
    consistently passed all four — planted and confirmed. The audit `prev_hash`
    spine is closed by WS4's frozen signed corpus
  - [x] WS4 — one frozen signed audit chain both verifiers read. The existing
        parity test compared them over a randomly-keyed chain generated per
        run, which no verifier outside that process could ever see. riscv32 is
        a compile oracle, not an executing one — the executing pair is the host
        verifier and the no_std mirror, with wasm executing the mirror
  - [ ] WS5 — bind each witness to its recorded red-proof
  - [~] WS6 — **lead item**: content-address the caches, verify on read. The
    2026-08-01 recon revision reverses finding 2 — integrity-on-read is the
    one attestation property no surveyed system enforces, mvm included —
    which promoted this from tail to lead
    - [x] Dev-build artifact cache, shipped in #2053: `mvm_core::action` +
          `verify_artifacts_on_disk`, verify on read, fail closed to a cold
          miss, and eviction of **both** the record and the build directory —
          a record-only eviction would leave the poisoned tree under a name a
          later build re-adopts. Unblocks plan 279 WS1
    - [~] Workload/builder kernel cache: plan 288
      (`specs/plans/288-kernel-cache-verify-on-read.md`). WS1–WS3 + WS5
      landed — the fetch path verifies against the published checksum
      manifest and records a digest sidecar, the read path verifies against
      it and evicts the whole entry on failure, and
      `check-verified-kernel-reads` keeps new callers on the seam. WS1's
      `VerifiedKernel` initially reached only the arms that used it: the
      Firecracker/qemu arm and the CLI's kernel-less-image fallback still
      booted on presence until 2026-08-11. WS4 (shared sidecar helper with
      the BLAKE3 artifact path) is the remainder
    - [ ] Cold-tier background scrub (recon §7.9)
  - [~] WS7 — σ/κ separation: `mvm_core::at_rest` gives the protocol digest
    over plaintext and the storage address over bytes at rest as disjoint
    types, σ as a set, and the transform descriptor as an open enumeration.
    The plan's "everything is Identity today" premise was wrong — OCI
    layers are tar+gzip and transcripts store ciphertext — which
    strengthens the case. Remaining: adopt the types at those two sites
  - [x] Discharged elsewhere: sealed transcript root anchored into the audit
        chain (recon §7.6 → plan 280, #2017); post-restore child verb grant
        (recon §7.7 → #2019)

- [~] Plan 316 — Single flow-aware vsock networking path
  (`specs/plans/316-single-flow-vsock-networking.md`, ADR-042). The active
  remainder is issue #2751 and
  `specs/plans/2026-08-19-flowmux-single-path-closeout.md`; the original phase
  issues are closed historical records.
  - [x] Protocol, authenticated endpoint, production outbound cutover, and
        authenticated-session readiness. TCP, UDP, DNS, mediated ICMP, and
        typed HTTP use FlowMux on `GuestService::NetworkFlow`; the raw/Wire
        guest dispatcher is deleted and `check-one-guest-protocol` guards the
        transport boundary.
  - [x] Relayed-vsock host-first handshake (#2741). HVF and libkrun now open
        the endpoint relay on guest connect, retain the route needed for a
        host-first greeting, and reset immediately when no endpoint exists.
  - [x] Shared per-VM admitted limits. Signed `NetworkLimits` reach endpoint
        startup, where one RAII budget and rate limiter are shared across all
        sessions. Aggregate TCP/HTTP, UDP, DNS, ICMP, ingress-listener, and
        session ceilings survive session churn and return reservations on
        teardown; malformed admitted limits fail before the endpoint binds.
  - [x] FlowMux performance harness and labelled legacy/current baselines.
        Strict macOS arm64 and Linux x86_64 host-loopback reports are recorded;
        their 21/28 pre-deletion threshold misses remain explicit, with no
        approved exception, for the final closeout matrix to resolve.
        The first post-deletion macOS candidate batches TCP credits and improves
        the result to 20 misses (12/32 checks pass), but still fails the gate;
        its raw report and comparison are recorded with no implied exception.
  - [x] Bounded typed transformations and endpoint-owned connectors. Typed
        HTTP now streams incrementally with bounded cross-frame transforms,
        fail-closed cancellation and audit behavior; web fetch and search
        authorize in their brokers but resolve, connect, and execute through
        the per-VM network endpoint. The host performance probe enables only
        the FlowMux client surface, keeping guest-only vsock dependencies out
        of the host graph and the duplicate-major invariant clean.
  - [x] Declared ingress runtime. Signed transport-neutral mappings reach exact
      endpoint binds before readiness; TCP and bounded observed-peer UDP use
      host-initiated FlowMux streams and declared guest-loopback targets.
      HTTP/TLS transformations remain host-owned, TLS keys never enter the
      guest contract, and opaque TCP stays explicitly non-transforming. Python
      and TypeScript browser helpers declare their listener before boot and
      preserve the existing OCI, command, egress, and readiness surfaces;
      dynamic post-admission forwarding fails with migration guidance.
  - [x] Remove the rejected `raw_ip_stack`/`L3Vsock` public compatibility
        surface now that the migration release condition has passed. Public
        IR, SDK, schema, CLI, fixtures, and docs expose no raw-network mode;
        stale serialized input receives an explicit migration refusal, while
        supported loopback adapters and typed connectors remain on FlowMux.
  - [x] Delete frozen L3 contract, guest, host, VMM, dependency, packaging,
        kernel, CI, and test slices. More than 41,000 lines and every L3-only
        binary/dependency are gone; dependency, supply-chain, closure, full
        workspace, gated-target, formatting, and BDD validation pass. The
        standalone agent fuzz lock retains the reviewed vendored `arrayref`
        patch through its `blake3` 1.8.6 pin.
  - [x] Permanent single-path and socket-owner invariants replace the migration
        ratchets. Synthetic fixtures reject every forbidden endpoint, backend,
        channel, L3/NIC, and socket-owner shape, while projection tests prove
        every flow family shares one admitted policy, budget, identity, VM
        resource, and audit sink.
  - [ ] Final performance, Firecracker, HVF, libkrun, BDD, supply-chain, and
        documentation evidence matrix. A fresh macOS arm64 host-loopback
        comparison remains failing and is retained as raw evidence; no
        performance exception has been recorded. Firecracker now has a passing
        admitted TCP/DNS witness on the approved Lima-KVM test tier; the wider
        live matrix remains open.

- [x] Plan 285 — L3 TUN-over-vsock network mode
  (`specs/plans/285-l3-tun-over-vsock.md`, ADR-036)
  **Retired and deleted by plan 316.** ADR-036 is superseded for production
  workload networking. The completed workstreams below stand only as a
  historical record of the removed implementation.
  - [x] W1–W8 — canonical `NetworkMode::L3Vsock`, the shared fuzzable wire
        protocol, the pure policy core, the guest `mvm-net-agent`, the
        machine-scoped host gateway, audit kinds, docs, and the unprivileged
        end-to-end suite
  - [x] W9 — backend-neutral `GuestChannelProvider` + typed `GuestService`,
        host-owned `VmInstanceIdentity` per boot, the signed `NetworkLease`
        with a local standalone authority, capability-gated forwarding
        backends, and the launch-specification no-guest-NIC guard
  - [x] Privileged Linux lane executed on a Linux/KVM host: real host TUN,
        real nftables, one shared default-drop forward hook with isolated
        per-machine chains, live forwarding witnesses for two machines,
        verified-clean teardown (nine privileged tests)
  - [x] IPv6 host datapath and shared `inet mvmn` isolation are implemented;
        the 13-test Linux/KVM acceptance lane is green for dual-stack
        assignment, IPv6 anti-spoofing, and two-machine chain
        teardown/forwarding
  - [x] BDD suite `s25_l3_vsock` (23 hermetic scenarios)
  - [x] Workload `VmmSpec` mapping carries the typed L3 control/data channels;
        netd socket layout follows the selected backend
  - [x] `VmmSpec::vsock` uses `GuestService` identities for standing channels;
        numeric ports are derived only at the VMM boundary
  - [x] Removed builder-role policy from `VmmSpec`; all boots require the
        typed substitution channel and HVF fails closed when it is absent
  - [~] Historical remainder intentionally descoped with deletion: macOS and
        WSL2 forwarding validation, node-to-node transport, and the dormant
        node-control surface are not part of the FlowMux product path.

- [~] Plan 265 — Fast-start SLO, backend sequencing & competitive positioning
  (`specs/plans/265-fast-start-slo-sequencing-positioning.md`)
  - [x] WS1 — Finish the FC warm-restore story (no-NIC guard, real
        `FirecrackerIO`, un-bailed warm restore, teardown on refusal)
  - [x] WS2 — The ≤30 ms p50 SLO: native API client, `api_put_socket`
        privilege verdict, pooled/pre-staged FC saved-state claim, and live
        KVM-box measurements recorded in the plan. SLO not cleared; remaining
        ~5–6 ms gap is Firecracker process startup + snapshot resume.

- [x] Plan 273 — SDK sidecar release acquisition
      (`specs/plans/273-sdk-sidecar-release-acquisition.md`)
  - [x] Publish `sdk-sidecar-<arch>.tar.gz` per-arch release assets, with
        `tests/release_assets.rs` pinning the workflow's names to the Rust
        constructor that requests them
  - [x] `mvm_build::sdk_sidecar` fetch + integrity-verify + atomic install,
        reusing the runtime overlay's transport helpers and one generalized
        archive-entry validator
  - [x] Reach it from the launch path on the download-mode acquire path; a
        source checkout keeps the fail-closed refusal

- [x] Plan 277 — release-artifact signature verification
      (`specs/plans/277-release-artifact-signature-verification.md`)
  - [x] Sign the image tarballs with `--new-bundle-format`, the only shape the
        in-binary Rust verifier parses; binary tarballs stay legacy for the
        cosign-CLI consumers (`install.sh`, `mvmctl update`)
  - [x] `mvm_build::release_signature` — fetch the bundle, verify against the
        versioned release identity, fail closed with no digest-only downgrade
  - [x] Wire the rung into both download paths, before extraction
  - [x] Docs + rollup; closes plan 273's one deferred gap

- [x] Plan 266 — lightweight microVM guest
      (`specs/plans/266-lightweight-microvm-guest.md`)
  - [x] WS-1/WS-2: static-musl privilege drop via the in-house `mvm-setpriv`
  - [x] WS-3: static-musl runtime overlay with the glibc SDK FFI split out
  - [x] WS-3 follow-up: plan-driven automatic SDK-sidecar attachment, gated
        fail-closed on the shared admission path
  - [x] WS-4: capability-negotiated guest-agent RSS query + 8 MiB ceiling
  - [x] WS-5/WS-6: lean kernel-module metadata, re-minimized immutable ext4, and
        the unified footprint ledger against the literal 50,000,000-byte contract
        with the optional SDK sidecar reported separately

- [x] Plan 280 — transcript root audit binding
      (`specs/plans/280-transcript-root-audit-binding.md`)
  - [x] Version-2 manifest root over fixed metadata and ordered ciphertext
        chunk records, with deterministic and mutation coverage
  - [x] Ordered `gateway.transcript_sealed` emission after atomic manifest
        persistence, chain-signed through the existing per-VM signer
  - [x] Exact tenant audit-chain anchor required before transcript key unwrap
        and decryption, with hermetic operator-path BDD coverage
  - [x] Production operator `disarm` now emits that anchor from the VM's real
        persisted admitted plan, refuses missing or cross-tenant bindings, and
        does not duplicate the signed entry when retried

- [x] Backend crate separation + HVF DAX + QEMU virtio-fs
      (**PR #2220**, branch `feat/backend-crate-separation`)
  - [x] Consolidate HVF under `mvm-runtime/src/backends/hvf`
  - [x] Extract shared `mvm-vmm` crate for VMM primitives
  - [x] Backend-agnostic `VmmSpec` with typed `VirtioFsShare` entries
  - [x] HVF and libkrun DAX support through `virtiofs` share mapping
  - [x] QEMU virtio-fs (and DAX) via standalone `virtiofsd` spawn helper
  - [x] Guest kernel config enables `FS_DAX`/`FUSE_DAX`/hotplug/zone-device
  - [x] Linux cross-compile stubs for Hypervisor.framework symbols
  - [x] Console-streaming test isolated with temp `MVM_HOME`
  - [x] `cargo test -p mvm-runtime` green; `cargo clippy -p mvm-runtime
-p mvm-build -- -D warnings` clean on macOS and Linux builder VM
  - [x] Full workspace test run on x86_64 Linux builder VM —
        `cargo nextest run --workspace`: 10372 passed, 19 skipped (4 threads)

- [~] Plan 255 — vsock-first snapshot, egress, and warm-start adoption
  (`specs/plans/255-vsock-first-snapshot-egress-adoption.md`)
  - [x] Snapshot storage and lineage-protected clone primitives
  - [x] Template-scoped warm-parent reservation and memory bounds
  - [x] QEMU Stage 0 raw-egress proof on the FC host
  - [x] Linux regression coverage for concurrent raw-egress handlers
  - [x] Final-child verb grant issuance, validation, persistence, and
        PostRestore delivery without granting authority to the parent
  - [x] Persistent-machine Firecracker stop fails closed and preserves state
        until process exit is verified (#2007; live KVM recheck passed)
  - [~] Live warm-launch, fork-isolation, and restore-clock verification
    — parent audit anchoring is fixed and live-proven (#1962); native HVF
    now has a paused-parent handoff with child-owned channel wiring and
    post-restore identity/grant re-pin (#2174). Serialized fresh-VMM
    restore and live Apple Silicon witnesses remain open.
  - [ ] Typed-connector egress-policy enrichment
  - [ ] OCI-image template build path and CLI facade completion

- [~] Plan 302 — audit-chain write-path hardening
  (`specs/plans/302-audit-chain-write-path-hardening.md`)
  - [x] `ReceiptStore` links and signs under one lock — the head read was
        outside it, so two emitters could claim one parent
  - [x] Receipt lock switched from process-scoped `fcntl` to `flock`, which
        actually excludes two threads
  - [x] `audit_signer::Chain` takes a sole-writer lock, writes each line in
        one `write_all`, and re-seeds its head after a failed append
  - [x] Audit emission fails closed on the sealed tier — a run that cannot
        record its admission does not reach the backend

  - [x] An unverifiable chain reports as unverifiable, not as a missing audit
        entry (#2258) — anchor returns `Err` naming the chains, distinct
        `ClaimRefusal::LedgerUnverifiable`, and a `doctor` audit-chain line
  - [ ] Audit emission fails closed under `--prod` (currently advisory, so a
        missing entry leaves no gap to detect)
  - [x] The primary chain stores the bytes its signature covers; no verifier
        re-derives them, so the entry schema can change without invalidating
        history
  - [ ] Converge the primary chain on JCS canonical bytes so no verifier has
        to reproduce serde field order

- [ ] Plan 306 — declared backing, tier honesty, and the check-time law
      (`specs/plans/306-declared-backing-and-tier-honesty.md`)
  - [ ] Declared-backing header + admission gate on contributor prose, which
        `check-doc-claims` deliberately excludes
  - [ ] Derive the ADR-001 per-backend tier matrix from `capabilities()`
        instead of maintaining it by hand
  - [ ] Refuse where we currently degrade silently (transient egress on
        libkrun/HVF, `up --network-allow`), plus a fail-closed pre-run probe
  - [ ] State the check-time law in ADR-001 and classify each governed effect
  - [ ] Pin the egress predicate algebra; enumerate escalation as deny-loud
  - [ ] Replay vectors for the audit chain's canonical signed bytes
  - [ ] Double-key the stale-name relief valves

- [x] Plan 333 — dependency hygiene: four defects and a ratchet, not a cut
      (`specs/plans/333-dependency-hygiene.md`)
  - [x] Phase 5 — the four defects: `hickory-proto` declared unconditionally in
        `mvm-hostd` while every consumer is `cfg(target_os = "linux")` (−6 on
        macOS, retires the shipped duplicate `rand` major there; `rand_core`
        0.10 stays, reached via aes-gcm/crypto-common, a P309 non-goal); the dead
        `memchr` workspace entry and its false justification; 69 member-manifest
        version pins that bypass `[workspace.dependencies]`; four stale
        `deny.toml` skip entries `cargo deny` already warns on. Landed: macOS
        closure 238 -> 232, Linux unchanged at 243; 18 of 25 deny skips were
        stale, not 4; only 7 of the 69 pins were safely convertible (
        `mvm-contract`'s 9 no_std narrowings must stay local or `std` leaks
        into a wasm32 crate)
  - [x] Phase 5.5 — the gate for the class: `xtask
        check-workspace-dep-inheritance`, plus a second
        `check-closure-budget` target for `aarch64-apple-darwin` (currently
        ungated, which is why the `hickory-proto` edge survived). Each proven
        red: re-pinning `thiserror = "1"`, re-adding `memchr`, and re-declaring
        `hickory-proto` unconditionally all fail, the last on macOS while Linux
        stays green
  - Re-measured Plan 309 Phase 3 independently and reproduced it; its declines
    stand and are not re-opened

- [ ] Plan 309 — dependency reduction
      (`specs/plans/309-dependency-reduction.md`)
  - [x] Phase 0 — the three defects: `mvm-build`'s hardcoded `thiserror` 1,
        the dead `rtnetlink` workspace entry, and `mvm-sdk`'s unconditional
        `schemars` leaking through feature unification into every consumer
  - [x] Phase 1 — drop rcgen's `x509-parser` feature (the ASN.1 tower and the
        closure's last `nom` 7) and replace `rayon` with an order-preserving
        scoped-thread `par_map`; closure 286 → 263, budget ratcheted
  - [x] Phase 2 — `mvm-http` over rustls retires `reqwest`; measured −20, not
        the −27 the raw subtree suggested. Differential harness against reqwest
        landed first and stays as a dev-dep oracle. Closure 262 → 242
  - [ ] Phase 3 — the product decisions: `tracing-subscriber`, `toml`, and the
        deferred `serde_jcs`. tree-sitter grammar gating is **struck** — the
        grammars are the SDK-to-Nix translation, not a tradeable dependency
  - [x] Phase 4 — `check-feature-closure-budget` bounds the all-features
        closure at 468, so the ~62 `wasmtime`-family packages behind an
        off-by-default feature stay observed. Not a lockfile count: measured,
        that number does not move when a dependency is removed (~120 orphans)
  - [x] Sigstore 0.9→0.11 (`specs/plans/2026-08-17-sigstore-0-11-upgrade.md`):
        sigstore-verify stack bumped, rustls feature selected (ring backend,
        not aws-lc-rs), dead `VerificationResult.success` API usage removed.
        Stale `rand`/`rand_core` ALLOWLIST entries ratcheted down in both
        `xtask/src/check_duplicate_majors.rs` and `deny.toml` (workspace
        unified on rand 0.10 in a prior change; the allowlist never followed).

- [x] Plan 2026-08-31 — RustCrypto 0.11 migration B4/C1
      (`specs/plans/2026-08-31-rustcrypto-011-migration-b4c1.md`)
      Gates cleared 2026-08-31: aes-gcm 0.11.1 stable; ed25519-dalek 3.0.0
      stable. Workspace was already on the 0.11 line for all crypto crates;
      this plan bumps aes-gcm lockfile 0.11.0 → 0.11.1 and records that
      sha2 0.10.9 / aws-lc-rs remain only in the optional manifest-verify
      path (blocked on sigstore-crypto > 0.11.0 upstream; default closure
      is already clean). C1 (oci-client rustls-tls-no-provider) does not
      apply: no oci-client dep in workspace.

- [ ] Plan 313 — egress token accounting, streaming, and compaction
      (`specs/plans/313-egress-token-accounting-and-compaction.md`)
  - [x] Phase 0 — verified: the substitution path buffers the whole response
        (`resp.bytes()`), loses chunk framing, has no body cap, and kills any
        stream held past the 30s whole-request timeout. Streaming and secret
        substitution are today mutually exclusive
  - [ ] Phase 1 — incremental response relay with bounded per-connection
        buffering, keeping the `service_redact` seam correct across chunk
        boundaries via a bounded overlap window
  - [ ] Phase 2 — token accounting from provider-reported `usage` (both SSE
        shapes), attributed to the `EgressGate` binding; zero new dependencies,
        `unknown` rather than a wrong heuristic
  - [ ] Phase 3 — `plan.egress_usage` chain-signed, payload-free audit entry
  - [ ] Phase 4 — surface totals via a read-side verb over the existing chain
  - [ ] Phase 5 — opt-in structural compaction, gated on Phase 3, with each
        elision recorded as a digest and never as content
  - [ ] Phase 6 — fleet aggregation from the same chain entries, derivable on
        customer hardware with no call home

- [~] Plan 308 — workload grants: one declaration, per-backend enforcement
  (`specs/plans/308-workload-grants.md`)
  - [x] WS1 — `Grants` in `mvm-contract`; `deny_unknown_fields` and an explicit
        `Unbounded` (no magic zero). The precedence resolver is NOT built — it
        belongs with the surfaces (WS6), since nothing yet has sources to resolve
  - [x] WS1b — `GrantCeiling`: separate trust root, unreachable from the
        precedence chain, so a plan signer cannot grant itself the machine
  - [x] WS2 — single Grants→`NetworkPolicy` projection, derived and fail-closed
  - [x] WS3 — `resource_controls` on `VmCapabilities` + `apply_grants` on
        `VmBackend`, tier read back rather than assumed
  - [x] WS3b — the seams made load-bearing: the signed plan carries `grants`,
        the ceiling is resolved from host config and checked before the plan
        is signed, `Supervisor::launch` applies grants and records the tier
        that came back, and a sealed run refuses a grant no mechanism on that
        tier backs (dev warns). No backend implements a real control yet —
        every tier still answers `declared`, which is WS4/WS5
  - [x] WS4.0 — spike COMPLETE. `cpu` _is_ delegated and `cpu.max` _is_
        writable, but cgroup v2 **migration** needs write access to the common
        ancestor and a login session's `session-N.scope` is `Delegate=no`. So
        WS4 became a systemd transient scope: measured 1.4937 cores against a
        1.5 target, `nr_throttled` confirming live throttling
  - [~] WS4 — CPU quota via `systemd-run --user --scope` (born bounded for
    free: systemd registers the scope before exec'ing the payload). Per-boot
    unique unit name, recorded in the VM state dir so the read-back can
    still resolve it. Prod gate consults host mechanism availability, not
    just backend kind. STILL OPEN: `exec_secs` enforcement; and the live
    measurement predates the read-back landing, so a bounded boot's
    _reported tier_ is unwitnessed on hardware
  - [x] WS4b — the host admission budget: `HostBudget`/`MachineCharge` in
        `mvm-contract`, measured in `mvm-hostd/src/admission_budget.rs` and
        checked in `admit_for_run`. Counts only machines with a live pid marker
        (the fork path's own probe, so a crashed VM cannot lock the host out)
        and each machine's configured maximum rather than the balloon's current
        commitment. Operator keys `host_budget_memory_mib` /
        `host_budget_cpu_millicores`
  - [x] WS7 — the ADR-001 claim row: ledger row **18** at `Preview`, with a
        "Preview 18 limits" note stating that CPU is declared-only off Linux,
        that wall clock has **no mechanism at all** in this tree (so a
        `WallClockGrant` passes the `--prod` enforceability gate with nothing
        behind it), that wasm fuel/epoch is declared and unwired, and that a
        restored or warm-claimed child is admission-bounded without its
        host-side CPU control being re-armed. `MVM-SEC-18` in
        `model/claims.toml`; every cited witness verified to exist
  - [ ] WS5 — wasm fuel **and** epoch (fuel alone bounds nothing in a host
        call) + `StoreLimits`
  - [~] WS5b — grants across snapshot/fork/restore; child ⊆ parent, closing
    the restore-laundering path. `grants_are_subset` in mvm-contract (CPU
    and wall clock read absence as unbounded, egress as deny-all;
    mismatched CPU units refused, never converted), `CheckpointMeta.grants`
    inside the content-address so a tampered parent record cannot justify
    a wider child (skip-serialized when absent, so an older checkpoint
    reads as schema-stale rather than tampered). BOTH restore paths check,
    through one predicate `ensure_child_grants_within_parent`: the vm_full
    fork and the warm-pool claim.
    (a) LANDED: the cleared child grant rides `RestoredChild.cpu_grant` to
    the child's spawn, and each restorer binds it where its cold boot binds
    `VmmSpec.cpu_grant` — HVF wraps the supervisor spawn, FC prefixes its
    launch line, the warm claim threads `ChildForkRequest.cpu_grant`. A
    restored child's tier now reads back `Cgroup2CpuMax`. A same-identity
    restore and a preloaded child stay unbounded by construction: neither
    has an admitted plan at the moment its VMM starts.
    STILL OPEN: (b) a warm parent seals no grant — a factory parent holds no
    plan or `cpu_grant` by construction and one parent serves every claim,
    so bounding a claimed child's CPU/wall clock needs a pool-level grant on
    `StandbySpec`; its egress is already bounded (absent egress = deny-all).
    Assessed and deferred with reason: there is no pool configuration to
    plumb from — a pool's identity is _derived_ from the provisioning
    launch, so the grant needs a declaring surface and a compat-key
    decision before it can be plumbed anywhere
  - [~] WS6 — four surfaces: manifest `[grants]`, `--grants-file` JSON,
    `--cpu-limit` CLI flag (`--timeout` supplies the wall-clock dimension),
    and `grants` on the `MachineSpec` DTO + `LaunchRequest` builder,
    resolved per dimension by `mvm_core::grants_resolve` and wired into the
    real `mvmctl` admission — `admission.rs` no longer hardcodes
    `grants: None`. The projection now has production callers, so its
    `dormant-controls.toml` entry is deleted. STILL OPEN: the SDK parity
    fixture
  - [~] WS6b — doctor/inspect tier reporting, persisted-spec migration, docs.
    The CLI boot path now calls `apply_grants` (via
    `mvm_client::enforced_grants_after_start`), records the tier per-VM,
    emits `plan.grants_enforced` on the chain, warns when a requested bound
    did not happen, and surfaces the achieved tier in `machine inspect`.
    Two `dormant-controls.toml` entries keep it from going unreachable
    again. STILL OPEN: doctor reporting, persisted-spec migration, docs
    gate, BDD suite

# Plan 305 — Delete the dead guest-NIC gateway stack

**Status: WS1 + WS2 COMPLETE** (WS4 remains)
**Supersedes:** the confinement-first framing this plan opened with (see
"History" below)
**Related:** plan 303 WS6, ADR-003, ADR-001 claim 10, `xtask
check-vsock-only-egress`

## Why

Workload egress converged on vsock. Every workload backend boots with a
virtio-vsock device and no net device, and egress leaves the guest only over
the per-VM substitution endpoint. The guest-NIC gateway stack that predates
that convergence — passt, gvproxy, the native/rvproxy gateway, the `mvm-bridge`
sidecar, and the observer packet pipeline they feed — is still in the tree but
no longer reachable.

This is not an inference from the docs. It is what the code says:

- `crates/mvm-build/src/libkrun_builder.rs:154` — *"The active transport is now
  direct vsock on every backend. `MVM_NETWORKING` is retained only as a
  compatibility knob so stale shells produce a warning instead of silently
  reopening legacy guest-NIC code paths."* The env var is read only to log
  `"MVM_NETWORKING is ignored; libkrun networking is now direct-vsock only"`.
- `crates/mvm-hostd/src/bin/mvm-libkrun-supervisor.rs:470` — *"Historical
  native-gateway hook: this now stays inert because the active libkrun
  transport is direct-vsock only."*
- `should_use_bridge_route()` (same file, ~252) returns **false** for
  `Tsi | VsockDirect`, and those are the only modes anything produces.
- `ConfigBuilder::with_passt` has **zero** non-test callers. The only
  construction of `NetworkingMode::Passt` in the tree is inside a `#[test]`.
- `with_native_gateway_config` is called only from inside a block already
  guarded on `cfg.krun.networking` *being* `NativeGateway`, which nothing sets.
- `run_packet_pipeline`'s only non-test callers are `gateway_bridge/passt.rs`
  and `gateway_bridge/native_gateway.rs`.

So the whole subtree is unreachable, and it is not inert weight: it is a second
egress model sitting next to the real one, with its own policy surface, its own
audit path, and its own confinement spec. `xtask check-vsock-only-egress`
exists precisely to keep gateway tokens off workload paths — deleting the
gateway makes that gate trivially true instead of continuously defended.

## Two live findings this surfaced

1. **The only CI lane exercising Landlock + seccomp confinement cannot run.**
   `.github/workflows/ci-full.yml` invokes `cargo test -p mvm-jailer-lite`.
   That crate was absorbed into `mvm-hostd` and no longer exists as a
   workspace member, so the step fails to resolve its package. The lane is
   `workflow_dispatch`-only, which is why nobody noticed. The tests themselves
   are fine — run on a live Landlock kernel (6.8, `landlock` in
   `/sys/kernel/security/lsm`) both pass.
2. **`ConfinementSpec::firecracker_bridge` hard-requires `/usr/bin/passt` to
   exist**, because Landlock's `PathFd::new` opens every allowlisted path. On a
   box without passt the property tests fail with `landlock path missing`. That
   is a spec pinned to a binary the runtime no longer launches.

## Workstreams

### WS1 — Fix the broken confinement lane

Independent of the deletion and worth landing first: a gate that cannot run is
worse than no gate, because the row in the ledger says it is covered.

- [x] `-p mvm-jailer-lite` → `-p mvm-hostd` in `ci-full.yml`, and correct the
      stale `crates/mvm-jailer-lite/...` paths in the lane comments and job name
- [x] xtask gate: every `-p <pkg>` in a workflow names a real workspace member,
      so the next crate consolidation cannot silently orphan a lane. Live over
      121 `-p` references across 20 workflow files

Writing the gate turned up three more defects in the same file, all of the
same shape — `ci-full.yml` is `workflow_dispatch`-only, so nothing it says is
ever contradicted by a run:

- [x] **The Landlock probe skipped itself on working kernels.** It gated on
      `[ -d /sys/kernel/security/landlock ]`. That directory does not exist on
      the live 6.8 box, which nonetheless carries `landlock` in
      `/sys/kernel/security/lsm` and passes both property tests. Now probes the
      LSM list, which is the kernel's own answer.
- [x] **`cargo test -p mvm-host-vm-init`** in the Firecracker boot-smoke lane.
      That is a `[[bin]]` of `mvm-build`, not a package, so the lane could not
      resolve it either. Now `-p mvm-build --bin mvm-host-vm-init`.
- [x] **A paths filter on `crates/mvm-host-vm-init/**`**, a directory absorbed
      into `mvm-build`. A trigger that cannot match never fires, so edits to
      the builder VM's PID 1 silently stopped gating the builder-vm lane.

Verified on the live Linux box: with the corrected command, both property
tests pass under an enforcing Landlock (`landlock_denies_paths_outside_ruleset`,
`seccomp_allows_listed_denies_unlisted`).

One caveat found while doing it, feeding WS2: the tests only pass there because
`passt` was installed. `ConfinementSpec::firecracker_bridge` lists the passt
binary as a Landlock-readable path, and `PathFd::new` opens every path in the
ruleset — so the spec cannot be built on a host without a binary the runtime
never launches.

### WS2 — Delete the gateway stack — DONE

~15,600 lines net (`+692 / −15,670`). Compiler-driven: each stage deleted an
entry point, then let `rustc` and `clippy -D warnings` enumerate what that
orphaned.

- [x] The gateway `NetworkingMode` variants and their builder setters
- [x] `libkrun-sys`: `bridge.rs`, `run_supervisor_with_bridge`, the two gateway
      spawn modules, `child_lifecycle.rs`, `GatewayHandle`,
      `configure_with_gateway`, and the net-attach FFI
- [x] `mvm-hostd`: `supervisor/gateway_bridge/` entire, the four
      `supervisor/network/rvproxy_*` modules, the observer pipeline
      (`pipeline.rs`, `latency.rs`, `flow_count.rs`) and the registry in
      `network/mod.rs`, `firecracker_bridge/`, the `mvm-bridge` sidecar and
      `src/bridge/`, and the `fuzz-vmhost` crate whose only two targets fuzzed
      deleted parsers
- [x] `run_with_bridge` / `should_use_bridge_route`; dispatch has one route
- [x] `NetworkingPreference` (a single-variant enum by then),
      `resolve_networking_mode`, `apply_networking_mode`, and with them
      `MVM_NETWORKING` / `MVM_GATEWAY_BIN`
- [x] Release packaging: `release.yml` built the deleted sidecar as an artifact
      and `RELEASE_HOST_BINS` listed it for `mvmctl update` to download

`supervisor/network/` keeps what the vsock path uses: the packet parser,
`stages::Redacting*` (the live substitution seam), and `flow_byte_log` (swept
by `mvmctl cache prune`).

Three findings recorded rather than quietly fixed, because each was true
*before* the deletion and would otherwise have been lost with the code:

1. **The supervisor's in-process plan verification was already unreachable.**
   `verify_signed_plan` was called only from `run_with_bridge`, which
   `should_use_bridge_route` gated off for every workload. Claim-8 verification
   happens at admission in the CLI, where ADR-001 puts it. Its three tests were
   checked against ADR-001's witness table, `model/claims.toml`, and
   `mvm-core/src/plan/content_id.rs`, which covers the same rejection ladder.
2. **`ConfinementSpec::firecracker_bridge` pinned a binary the runtime never
   launched**, so the jailer property tests only ran where it was installed.
   They now build `ConfinementSpec::substitution_endpoint` — the live confined
   role. `BRIDGE_SYSCALLS` → `CONFINED_ROLE_SYSCALLS`, which is what the shared
   table always was.
3. **A re-export was gated more tightly than the item it exported.** `start`
   returns `NotYetWired` without the `libkrun-sys` feature and has a test
   asserting that, but its re-export was feature-gated — reachable from nothing
   in a featureless build, kept alive only by the gateway boot path.

### The gate

`xtask check-no-gateway-names` walks the tree and fails on a word-boundary
match for the removed names, wired into `ci.yml`'s lint lane beside
`check-vsock-only-egress`.

Word boundaries are load-bearing and tested: `passthru` (a Nix attribute) and
`passthrough` contain one of the names as a substring, and a substring match
produced ~200 false positives — enough to get the gate switched off.
Exemptions are narrow and asserted narrow by a test; live documentation is not
exempt. One span-precise context allowance covers an SSH key filename that
cannot be renamed from here, with a test proving it does not excuse a real
reference on the same line. The walker skips symlinks — `Path::is_dir()`
follows them, and a `nix build` `result` symlink would walk `/nix/store` while
a cycle would not terminate.

### WS3 — Correct the docs the deletion falsifies — DONE

- [x] `CLAUDE.md` "Host dependencies" instructed installing a third Homebrew
      package and documented an `MVM_NETWORKING` per-OS default table that
      `libkrun_builder.rs` directly contradicted
- [x] `README.md`, ADR-028, ADR-036, the jailer's `LANDLOCK.md`/`SECCOMP.md`,
      public troubleshooting + CLI reference, kernel image notes, three
      workflows, two baseline scripts
- [x] An orphaned doc comment in `mvm-hostd/src/lib.rs` described the deleted
      bridge module while sitting on `pub mod broker;`

### WS4 — Then confine the signer roles

The original plan-305 scope, deferred behind the deletion because it is a
smaller surface afterwards: `mvm-host-signer`, `mvm-audit-signer`,
`mvm-signer-helper`, `mvm-broker` still run unconfined while `mvm-bridge` —
about to be deleted — is one of only two bins that call `confine_self`.

Blocked on: `mvmctl seccomp-audit` traces only the main thread, and all four
roles build `tokio::runtime::Builder::new_multi_thread()`, so any allowlist it
produces today is incomplete by construction and the failure mode is SIGSYS
under load. Extend the tracer with `PTRACE_O_TRACECLONE` first.

- [ ] Extend `seccomp-audit` to follow clones/threads
- [ ] Derive the four allowlists on the live Linux box
- [ ] One PR per role

## History

This plan opened as "confine the four unconfined moat roles". That framing
survived until the gateway stack was examined and found inert: confining
`mvm-bridge`'s peers is worth less than deleting the model `mvm-bridge` exists
to serve. The confinement work is preserved as WS4 rather than dropped.

## Out of scope

`gateway_audit_socket` survives in `SupervisorConfig`, `mvm-vmm` and
`mvm-backends`. It is a neutral name on the audit substrate rather than a
gateway reference, and untangling it reaches the warm-pool claim path.

## Validation

The live Linux box (kernel 6.8, Landlock active, `/dev/kvm`) is the target for
anything kernel-dependent. Both confinement property tests already pass there.

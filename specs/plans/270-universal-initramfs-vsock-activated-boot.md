# Universal initramfs + vsock-activated boot

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the multiple per-rootfs init paths (`mvm-verity-init`, `mvm-oci-init`, busybox `/init`) with one generic, content-addressed initramfs. The initramfs boots a tiny Linux kernel, starts `mvm-agentd` as PID 1, and waits on vsock for a signed `ActivateEnvironment` command from the host. Only after receiving that command does the agent mount the workload rootfs and runtime overlay, drop privileges, and become ready for the workload. Nix-built and OCI-sourced rootfs images boot through the identical guest path.

**Architecture:** Today the guest boot path is driven by kernel command line and differs between Nix rootfs (`mvm-verity-init` + busybox `/init`) and OCI rootfs (`mvm-oci-init`). The runtime overlay is attached as a second block device. This plan inverts control: the initramfs is generic, the agent is PID 1, and the host tells the agent what to mount over a signed vsock channel. The initramfs hash becomes part of the attestation statement. Warm snapshot restore remains the fast path; the universal initramfs is the standardized cold-boot shape that warm parents are built from.

**Tech Stack:** Rust (`mvm-agentd`, `mvm-runtime`, `mvm-protocol`), Nix (initramfs build), `cargo nextest`, `cargo clippy --workspace --all-targets -- -D warnings`.

## Global Constraints

- Work in a dedicated worktree (e.g., `../.worktrees/mvm-universal-initramfs`) on branch `feat/universal-initramfs`; git via `git -C <wt-abs>`.
- **Security-preserving change:** every ADR-001 claim is preserved or strengthened; no workload-visible security weakening.
- No `Plan N` / `ADR-\d+` / `#NNNN` / `W\d.` tokens in code or code comments (CI `check-no-spec-refs`); reword to the concept. Spec docs may reference them.
- Rust: never `#[allow]` a clippy lint; `rustup run nightly cargo fmt --all` before push; `cargo nextest run --workspace` green before any task is marked done.
- No `Co-Authored-By: Claude` trailer and no AI-tool attribution in commits or PR body.
- The builder VM keeps its own boot path; do not change it.
- WASM backend is explicitly out of scope — it does not boot Linux.
- WHP is a future note only; it conflicts with ADR-009 and is not part of this workstream.

## Prerequisites

Do not begin implementation until these three workstreams have merged. Sequence the plan behind them and update `specs/SPRINT.md` to state the dependency.

| Branch | Why it must land first |
| --- | --- |
| `feat/vsock-control-conformance` | Provides the authenticated, encrypted vsock channel that `ActivateEnvironment` rides on. |
| `feat/firecracker-vsock-only-final` | Makes Firecracker vsock-only; a NIC fallback would create a second control path and break the model. |
| `feat/hvf-converge-vsock` | Makes HVF vsock-only and removes the smoltcp-L3 fallback. |

HVF real rootfs bring-up remains the long pole tracked in Plan 255/265/214. This plan designs for HVF but does not duplicate that rootfs work.

---

## Task 1: Define `ActivateEnvironment` and the boot state machine

**Files:**
- `crates/mvm-protocol/src/protocol/guest_request.rs` — add the new request variant.
- `crates/mvm-protocol/src/protocol/capability.rs` — advertise `ActivateEnvironment` support.
- `crates/mvm-agentd/src/agent/state.rs` — `BootState` enum and guarded transitions.
- `crates/mvm-agentd/src/agent/audit.rs` — boot-stage audit events.
- `crates/mvm-agentd/src/protocol/activate.rs` — payload type + validation.

**Interfaces:**
- Produces: a typed `ActivateEnvironment` command, a `BootState` state machine, and chain-signed audit events for every transition.
- Consumes: the existing authenticated vsock framing and `ProtocolHello` capability negotiation.

- [ ] **Step 1: Add `ActivateEnvironment` to the guest request enum**

  Define `ActivateEnvironment(ActivateEnvironmentPayload)` as a `GuestRequest` variant. The payload includes:
  - `vm_id: VmId` — the unique microVM identifier.
  - `session_id: SessionId` — the per-VM session nonce minted at creation.
  - `rootfs: BlockDeviceSpec` — device path (`/dev/vda`), dm-verity roothash, filesystem type.
  - `overlay: BlockDeviceSpec` — device path (`/dev/vdc`), dm-verity roothash, lowerdir/upperdir/workdir layout.
  - `cap_drop: CapabilitySet` — capabilities to drop after activation.
  - `uid: u32`, `gid: u32` — the unprivileged identity to assume after activation (default uid 901).

- [ ] **Step 2: Define `BootState` and guarded transitions**

  ```rust
  enum BootState {
      Init,
      AgentListening,
      Activating,
      PrivilegeDropped,
      Ready,
      WorkloadRunning,
      Draining,
      ShuttingDown,
  }
  ```

  Only these transitions are legal:
  - `Init → AgentListening` after vsock listener is bound.
  - `AgentListening → Activating` on receipt of `ActivateEnvironment`.
  - `Activating → PrivilegeDropped` after successful mount + privilege drop.
  - `PrivilegeDropped → Ready` after post-drop self-check.
  - `Ready → WorkloadRunning` on `RunEntrypoint`.
  - Any state → `ShuttingDown` on shutdown or fatal error.

  `ActivateEnvironment` received after `Ready` is a protocol error; return `BootError::ActivationAfterReady` and shut down.

- [ ] **Step 3: Add capability negotiation**

  Add `activate_environment: bool` to `ProtocolHello.capabilities`. The agent sets it to `true`. A host that does not see the capability must fall back to the legacy cmdline-driven boot path and must not silently skip activation.

- [ ] **Step 4: Emit chain-signed audit events**

  Every transition emits a `LocalAuditEvent`:
  - `boot.agent_started`
  - `boot.activation_received`
  - `boot.rootfs_verified`
  - `boot.overlay_verified`
  - `boot.privilege_dropped`
  - `boot.ready`
  - `boot.workload_spawned`
  - `boot.shutdown_requested`

- [ ] **Step 5: Bind activation to the VM instance**

  The guest verifies that `vm_id` and `session_id` in the command match its own before acting. The session id is derived from the `AuthenticatedFrame` session key. A valid frame replayed at another VM is rejected.

- [ ] **Step 6: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-protocol -p mvm-agentd
  cargo clippy -p mvm-protocol -p mvm-agentd -- -D warnings
  ```

- [ ] **Step 7: Commit**

  ```bash
  git -C <wt> commit -m "protocol(agentd): add ActivateEnvironment, boot state machine, and capability negotiation"
  ```

---

## Task 2: Build the generic `mvm-agentd` PID-1 initramfs

**Files:**
- `crates/mvm-agentd/src/init.rs` — PID-1 stub or `init` subcommand.
- `crates/mvm-agentd/src/mount.rs` — mount library.
- `crates/mvm-agentd/src/reaper.rs` — zombie reaping.
- `crates/mvm-agentd/src/privilege.rs` — privilege drop.
- `crates/mvm-agentd/src/main.rs` — dispatch.
- `nix/lib/mk-initramfs.nix` — initramfs derivation.

**Interfaces:**
- Produces: a static-musl `mvm-agentd` binary that can be `/init`, a mount library, and a content-addressed initramfs cpio.
- Consumes: `mvm-fs` for ext4/dm-verity helpers, the vsock transport, and the authenticated frame codec.

- [ ] **Step 1: Add a tiny `/init` entry point**

  Implement `mvm-agentd init` (or a separate 50-line static-musl stub) that:
  - mounts `/proc`, `/sys`, `/dev`, `/dev/pts`;
  - loads the vsock module if not built-in;
  - binds the vsock listener;
  - `exec`s the main agent loop as PID 1.

  The agent itself is identical to the one in the runtime overlay; only its argv[0] differs.

- [ ] **Step 2: Implement PID-1 signal handling**

  Install handlers for `SIGTERM`, `SIGINT`, and `SIGCHLD`. Linux ignores `SIGTERM`/`SIGINT` for PID 1 by default; the agent must handle them explicitly. Use a self-pipe or signalfd to keep handlers async-signal-safe.

- [ ] **Step 3: Implement zombie reaping**

  On `SIGCHLD`, loop with `waitpid(-1, WNOHANG)` until `ECHILD`. Reap orphaned workload children and intermediate processes. Add focused tests for signal flood and orphaned grandchildren.

- [ ] **Step 4: Implement the mount library**

  Move mount logic out of the vsock listener into `crates/mvm-agentd/src/mount.rs` (or `mvm-fs` if it can be made guest-suitable). The library must:
  - set up dm-verity for rootfs and overlay;
  - mount the rootfs read-only;
  - mount the runtime overlay as an overlayfs at `/mvm/runtime`;
  - pivot root or chroot into the combined tree;
  - never run network code.

- [ ] **Step 5: Implement privilege drop**

  After successful mount, drop from root to uid 901 / gid 901, clear supplementary groups, and set `PR_SET_NO_NEW_PRIVS`. `ActivateEnvironment` is the only verb accepted before the drop. Add tests proving no workload command is accepted pre-drop.

- [ ] **Step 6: Content-address the initramfs**

  Build the initramfs once per `(target_arch, agent_version, kernel_version)` tuple. The cache key is the hash of:
  - the `mvm-agentd` static-musl binary;
  - the kernel config;
  - the initramfs file list and permissions.

  Include the initramfs hash in the attestation statement. The initramfs contains no secrets except the host-signer public key.

- [ ] **Step 7: Nix derivation**

  Add or refactor `nix/lib/mk-initramfs.nix` to produce the cpio. Remove busybox `/init` and `mvm-verity-init`/`mvm-oci-init` from the initramfs closure. Target size <5–10 MiB.

- [ ] **Step 8: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-agentd
  cargo clippy -p mvm-agentd -- -D warnings
  ```

- [ ] **Step 9: Commit**

  ```bash
  git -C <wt> commit -m "feat(agentd): generic PID-1 initramfs with mount library and privilege drop"
  ```

---

## Task 3: Host-side activation and unified rootfs boot path

**Files:**
- `crates/mvm-runtime/src/runner/activation.rs` — host-side activation sender.
- `crates/mvm-hostd/src/vm/activate.rs` — hostd activation logic.
- `crates/mvm-client/src/activation.rs` — client helper.
- `crates/mvm-fs/src/oci_to_rootfs.rs` — OCI rootfs materialization (use PR #1804 prior-layer path replacement).
- `crates/mvm-build/src/rootfs.rs` — Nix rootfs materialization.

**Interfaces:**
- Produces: a host path that attaches rootfs + overlay, computes hashes, signs `ActivateEnvironment`, and sends it over vsock.
- Consumes: the signed `ExecutionPlan`, dm-verity hashes, and the vsock control channel.

- [ ] **Step 1: Unify rootfs attachment**

  Nix-built rootfs and OCI-sourced rootfs must both be presented to the guest as block devices with explicit dm-verity roothashes. The guest mount library handles both identically. PR #1804's `unpack_layer_with_prior_paths` and `UnpackReport::paths_written` are used to materialize the OCI rootfs before sealing it into a verity block device.

- [ ] **Step 2: Compute and verify roothashes**

  The host computes the dm-verity roothash for rootfs and overlay before sending `ActivateEnvironment`. The guest recomputes/verifies during mount. A mismatch is a fatal error with explicit attribution (`ActivationError::VerityMismatch`).

- [ ] **Step 3: Sign and send `ActivateEnvironment`**

  The host signs the activation payload with the host-signer key, wraps it in `AuthenticatedFrame`, and sends it after the guest reports `AgentListening`. The host must wait for the `ready` acknowledgement before issuing `RunEntrypoint`.

- [ ] **Step 4: Fail-closed behavior**

  If the host never sends activation, the guest times out and shuts down. If the host sends bad data (unknown device, bad hash, wrong `vm_id`), the guest rejects the command, emits an audit event, and shuts down. Never boot half-initialized.

- [ ] **Step 5: Boot-failure attribution**

  Define typed errors so operators can distinguish:
  - `HostCommandInvalid` — host sent malformed or out-of-order data.
  - `DeviceNotFound` — guest could not open the named block device.
  - `VerityMismatch` — content did not match the declared roothash.
  - `MountFailed` — kernel/filesystem error during mount.
  - `Timeout` — host never sent activation.

- [ ] **Step 6: No guest network during activation**

  The initramfs must not bring up a NIC or perform DNS resolution. All host↔guest traffic during boot is vsock. This is enforced by construction (no NIC in the initramfs) and a CI witness.

- [ ] **Step 7: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-runtime -p mvm-hostd -p mvm-fs
  cargo clippy -p mvm-runtime -p mvm-hostd -p mvm-fs -- -D warnings
  ```

- [ ] **Step 8: Commit**

  ```bash
  git -C <wt> commit -m "feat(runtime): host-side ActivateEnvironment and unified rootfs boot path"
  ```

---

## Task 4: Update every `VmmDriver`

**Files:**
- `crates/mvm-runtime/src/driver/fc.rs`
- `crates/mvm-runtime/src/driver/libkrun.rs`
- `crates/mvm-runtime/src/driver/hvf.rs`
- `crates/mvm-runtime/src/driver/mock.rs`
- `crates/mvm-runtime/src/driver/traits.rs`

**Interfaces:**
- Produces: all drivers attach initramfs + rootfs + overlay block devices, expose vsock, and shrink `workload_base_bootargs` to console/panic/vsock.
- Consumes: the existing `VmmSpec`, `RunningVm`, and vsock channel abstractions.

- [ ] **Step 1: Shrink `workload_base_bootargs`**

  The initramfs owns root/init selection. Each driver's `workload_base_bootargs` returns only:
  - `console=`
  - `panic=`
  - `mvm.vsock_cid=` or equivalent vsock parameter

  Remove rootfs/overlay/roothash parameters from the kernel command line.

- [ ] **Step 2: Attach the initramfs**

  Every driver selects the content-addressed initramfs by hash from the host cache and attaches it as the boot initramfs. The hash is recorded in the VM start metadata.

- [ ] **Step 3: Attach rootfs and overlay block devices**

  Maintain the stable device mapping:
  - `/dev/vda` = workload rootfs
  - `/dev/vdc` = runtime overlay

  Each `VmmDriver` guarantees this mapping. `ActivateEnvironment` references these paths explicitly.

- [ ] **Step 4: Update `MockDriver`**

  `MockDriver` must simulate vsock and `ActivateEnvironment`; otherwise warm-path and unit tests break. It does not need real block devices, but it must exercise the same state machine and emit the same audit events.

- [ ] **Step 5: HVF coordination**

  HVF support is non-negotiable but gated on the existing rootfs work in Plan 255/265/214. Coordinate with that workstream: once HVF can attach a rootfs block device and vsock, the universal initramfs boot path applies unchanged.

- [ ] **Step 6: Dev console/PTY over vsock**

  The agent as PID 1 still owns the console data port. Verify that the PTY-over-vsock path works with the new initramfs and does not rely on a separate `mvm-guest-agent` process.

- [ ] **Step 7: Run tests and clippy**

  ```bash
  cargo nextest run -p mvm-runtime
  cargo clippy -p mvm-runtime -- -D warnings
  ```

- [ ] **Step 8: Commit**

  ```bash
  git -C <wt> commit -m "feat(runtime): VmmDriver initramfs attachment and shrunk bootargs"
  ```

---

## Task 5: Rollout, snapshots, bundles, and `mvm-setpriv`

**Files:**
- `crates/mvm-runtime/src/runner/compat.rs` — boot protocol negotiation.
- `crates/mvm-hostd/src/snapshot/meta.rs` — snapshot initramfs hash.
- `crates/mvm-cli/src/commands/up.rs` — feature flag.
- `crates/mvm-core/src/bundle/manifest.rs` — compatibility range.
- `crates/mvm-agentd/src/privilege.rs` — `mvm-setpriv` interaction.

**Interfaces:**
- Produces: a feature-flagged rollout path, snapshot compatibility, bundle metadata, and a decision on `mvm-setpriv`.

- [ ] **Step 1: Feature flag the new boot path**

  Add `--boot=universal-initramfs` (opt-in) with the old path as default. Keep the legacy path until BDD + live smoke pass. Host negotiates boot protocol via `ProtocolHello.capabilities`.

- [ ] **Step 2: Snapshot compatibility**

  The snapshot format records the initramfs hash. Restore must keep working even when the host has a different default agent version, as long as the initramfs is still in cache or can be re-fetched. Version negotiation lets a host downgrade the agent for an existing snapshot.

- [ ] **Step 3: Warm snapshot restore**

  Sub-200 ms remains a warm-snapshot-restore target, not a cold-boot target. The warm parent is built from the universal initramfs and restored into memory. Do not optimize the cold initramfs path for sub-200 ms.

- [ ] **Step 4: Bundle metadata**

  The initramfs may not need to ship inside `.mvmpkg`. The bundle manifest records the compatible initramfs hash range. Admission rejects a bundle if the required initramfs is not available on the host.

- [ ] **Step 5: `mvm-setpriv` interaction**

  If light-guest WS5 lands a custom `mvm-setpriv`, decide whether to:
  - keep it in the initramfs as a fallback helper, or
  - fold the functionality into `mvm-agentd`'s privilege-drop path and delete the separate binary.

  The plan should default to folding it into the agent to keep the initramfs small.

- [ ] **Step 6: Run tests and clippy**

  ```bash
  cargo nextest run --workspace
  cargo clippy --workspace --all-targets -- -D warnings
  ```

- [ ] **Step 7: Commit**

  ```bash
  git -C <wt> commit -m "feat(runtime): rollout flags, snapshot initramfs hash, bundle compatibility"
  ```

---

## Task 6: Tests, BDD, and verification

**Files:**
- `features/suites/s4_verified_boot/universal_initramfs.feature` — new BDD scenarios.
- `crates/mvm-conformance/tests/steps/boot.rs` — step definitions.
- `crates/mvm-agentd/tests/pid1.rs` — PID-1 tests.
- `crates/mvm-agentd/tests/mount_policy.rs` — mount no-shadow tests.
- `xtask/src/check_claim_catalog.rs` — update witnesses.

**Interfaces:**
- Produces: BDD coverage, unit tests, and updated claim-catalog witnesses for the new boot path.

- [ ] **Step 1: PID-1 tests**

  Add tests for:
  - `SIGTERM` and `SIGINT` handling;
  - zombie reaping, including orphaned grandchildren;
  - privilege drop before `ready`;
  - no workload command accepted before `ready`.

- [ ] **Step 2: Mount policy tests**

  Verify the deny-prefix set: `/`, `/mvm`, `/mvm/runtime`, `/dev`, `/dev/vda`, `/dev/vdc`. Verify mount ordering: rootfs → overlay → custom volumes. Verify custom volumes cannot shadow rootfs/overlay.

- [ ] **Step 3: Activation failure tests**

  - Missing activation → timeout + shutdown.
  - Roothash mismatch → shutdown.
  - Wrong `vm_id`/`session_id` → shutdown.
  - `ActivateEnvironment` after `ready` → protocol error + shutdown.
  - OCI rootfs boot and Nix rootfs boot both succeed.

- [ ] **Step 4: BDD scenarios**

  Write Gherkin scenarios for:
  - cold boot of a Nix image through the universal initramfs;
  - cold boot of an OCI image through the universal initramfs;
  - activation failure with boot-failure attribution;
  - mount no-shadow policy;
  - warm snapshot restore preserves initramfs hash.

- [ ] **Step 5: Live smoke**

  Run live smoke on Linux (Firecracker + libkrun) and Mac (HVF when the rootfs prerequisite lands). Document any hardware-specific gaps.

- [ ] **Step 6: Update claim-catalog witnesses**

  Add or update witnesses for verified boot, PID-1 behavior, and activation audit events. Run `cargo xtask check-claim-catalog`.

- [ ] **Step 7: Commit**

  ```bash
  git -C <wt> commit -m "test(conformance): BDD + unit tests for universal initramfs boot"
  ```

---

## Acceptance gate

- `cargo nextest run --workspace` green.
- `cargo clippy --workspace --all-targets -- -D warnings` green.
- `cargo xtask check-claim-catalog` green.
- `just bdd` green (or the BDD runner in use) with scenarios for Nix rootfs, OCI rootfs, activation failure, and mount no-shadow.
- Live smoke on Linux (FC + libkrun) passes; HVF smoke is either passing or explicitly gated on the existing rootfs workstream.
- No secrets in the initramfs except the host-signer public key.
- No guest NIC during activation.
- `ActivateEnvironment` is the only verb accepted before privilege drop.
- Initramfs size <10 MiB.

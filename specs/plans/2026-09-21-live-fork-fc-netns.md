# Live-parent fork activation on Firecracker (vsock-only)

Backing: shipped-source
Validation: check-sprint-append

Issue: tinylabscom/mvm#3552 — fork a running machine: advertise live-memory
save/restore on Firecracker. Kickoff: `specs/prompts/2026-09-21-live-fork-fc-netns.md`
(main checkout). Worktree `../.worktrees/mvm-fork-activation`, branch
`feat/live-fork`. PR #3581 (docs row fix) already sits on this branch.

## Governing invariant

There is no network in the microVMs: no NIC, no TAP/TUN. All guest traffic
rides vsock (JSON-RPC control channel, FlowMux streams, per-VM host proxies
keyed by VM name). Verified on the tree: the Firecracker boot path contains no
`network-interfaces`/`tap` PUT anywhere (`crates/mvm-backends/src/fc/host.rs`,
`control.rs`, `driver/fc.rs`), `tap_networking: false` and
`no_routable_guest_nic: true` in the fc capabilities, and
`assert_vsock_only_device_model` guards every restore. Both earlier designs on
the issue (patch the vmstate bitcode; per-child netns + TAP) are withdrawn.

## Premise (verified against the tree)

- A vm_full snapshot from a current vsock-only Firecracker carries **no net
  device** in its restored device model (`RestoredDeviceModel.network_interfaces`
  is empty; `driver/fc.rs` never PUTs `/network-interfaces`). The old
  TAP/MAC collision rationale in the fork guard is stale.
- The resource the restored state *does* carry is the parent's **vsock device**
  (UDS path + CID). The existing fork remap step
  (`FcForkRestorer::prepare_fork_load` -> `remap_paths_for_fork`,
  `crates/mvm-backends/src/fc/fork_namespace.rs`) bind-mounts the child's state
  dir over the parent's state dir in the child's private mount namespace, so
  the recorded parent UDS path resolves inside the child's own state dir. The
  vsock CID is per-VMM state (each Firecracker owns its own vsock device), so
  identical CIDs across parent and children do not collide on the host.
- Per-child resources are therefore state-dir-keyed and already distinct:
  child state dir (unique per child VM name; `fork_vm_full` refuses
  child name == parent name), child vsock UDS (remapped), egress path
  (per-VM proxies keyed by child VM name through the normal admit path).

## Tasks

- [x] Read issue #3552 + all comments (two design corrections recorded above).
- [x] Verify premise: vsock-only snapshot contents, vsock UDS remap into the
      child's state dir, per-child resource model.
- [x] Drop `MVM_FORK_VMFULL_FC_EXPERIMENTAL` and the `MustBeStopped`
      live-parent refusal in the fc fork arm
      (`crates/mvm-cli/src/commands/vm/checkpoint/fork_vm_full.rs`); pass
      `ForkParentLiveness::MayBeRunning`; remove the now-dead
      `bypass_experimental_guard` param from both arm param structs and both
      callers (`vm/checkpoint.rs`, `machine/checkpoint.rs`).
- [x] Flip `snapshot_capability` from `Unsupported` to `LiveMemory` in
      `crates/mvm-backends/src/driver/fc.rs` with the surrounding comment
      updated to the vsock-only reality.
- [x] Doctor parity: update the capability-matrix assertions
      (`crates/mvm-runtime/src/backend.rs`), the fc warm_start test, and the
      doctor warm-start tier assertions
      (`crates/mvm-cli/src/doctor/warm_start.rs`).
- [x] Witness: `crates/mvm-runtime/tests/fc_fork_live.rs` — fork N children
      from one *running* parent; assert all N reach ready, each child has its
      own vsock endpoint and egress path, distinct generation tokens and
      post-restore randomness, parent still serving while children run.
      Gated like `fc_warm_pool_live.rs` (Linux + KVM + `#[ignore]`).
- [x] Docs: update the recovery-path row in
      `public/src/content/docs/reference/platform-support.md` (coordinate with
      the PR #3581 commit on this branch).
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean (Linux
      builder env); touched-crate tests green; `just check-gated` clean.
- [ ] Update `specs/SPRINT.md` + `specs/REFACTOR-STATUS.md`; tick these boxes.
- [x] Push `feat/live-fork`, PR open referencing #3552, acceptance list ticked (PR #3586;
the branch's earlier docs commit went out as #3581).

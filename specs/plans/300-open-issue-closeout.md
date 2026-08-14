# Plan 300 — Open issue reconciliation and closeout

Backing: shipped-source
Validation: none

**Status:** IN PROGRESS — tracker closed to zero 2026-08-14; the plans are now the ledger
**Snapshot date:** 2026-08-14, against `origin/main` `2bc7dc2bc`

## Objective

Reconcile every open issue against merged code, current product intent, tests,
live evidence, and the owning plans. Close work that is demonstrably complete,
combine issues that describe one piece of work, preserve active defects and
security gaps, and execute the remainder in dependency order until every issue
is either completed or deliberately declined with its remaining requirements
transferred to a named owner.

The count has moved 39 → 31 → 28 → 23. The remaining 23 all retain material
acceptance criteria; **none is complete-but-stale**. Closing an umbrella, a
research issue, or a partially implemented issue does not count as progress
unless its remaining criteria move to an explicit owner in the same change.

Three of the 23 are blocked on something outside this repository — two need a
Linux host with `/dev/kvm` and NVMe that does not exist yet, and one needs
`mvm-studio#18` to freeze a handshake. Those are stated per phase rather than
left to be rediscovered mid-execution.

## Closure rules

An issue closes only when all applicable conditions are met:

1. Its current acceptance criteria match the intended outcome. Mixed or stale
   issues are narrowed or split before closure.
2. The implementation is merged to `main`, not merely present in a branch,
   draft pull request, or merge queue.
3. Unit, integration, BDD, security, and failure-path tests are green. Backend,
   kernel, privilege, networking, and performance claims also have a live
   witness on every claimed platform.
4. The owning plan, `specs/SPRINT.md`, and `specs/REFACTOR-STATUS.md` agree.
5. The final issue comment names the merged pull requests, test or workflow
   evidence, live evidence, and any intentionally excluded scope.

Generated trackers close only after the generating workflow is green. An issue
is not closed because adjacent code exists, its title was superseded, or a plan
mentions it.

## Reconciliation history

### 2026-08-13 — first pass, 39 → 31

Eight issues closed: #2165, #2289, #2333, #2423 as completed by merged pull
requests; #2180, #2181, #2305, #2413 as not planned or superseded.

| Issue | Closed as   | Reason                                                                             |
| ----- | ----------- | ---------------------------------------------------------------------------------- |
| #2165 | completed   | PR #2330 merged; workload block-root bootargs agree with read-only root attachment |
| #2289 | completed   | Kernel/libkrunfw pins now at 6.12.103 via PR #2301                                 |
| #2333 | completed   | PR #2335 merged; `pool warm --image <ref>` fills the pool                          |
| #2423 | completed   | PR #2428 merged; RFC 6962 consistency proofs landed                                |
| #2180 | not planned | Superseded by Plan 316 L3 deletion                                                 |
| #2181 | not planned | Superseded by Plan 316 L3 deletion                                                 |
| #2305 | not planned | Superseded by Plan 313 egress token accounting                                     |
| #2413 | not planned | 0.10.4 bpf-linker pin stable; 0.11.0 not worth the system LLVM cost                |

### 2026-08-13/14 — interim, 31 → 28

| Issue | Closed as | Reason                                                                     |
| ----- | --------- | -------------------------------------------------------------------------- |
| #2292 | completed | PR #2463; `driver_boot` split, in-process API client, no sudo bash launch  |
| #2307 | completed | `xtask check-nextest-groups` implemented and wired into CI                 |
| #2318 | completed | PR #2465; receipt is a record not a control; KVM re-measure p50 ~45.4 ms   |

### 2026-08-14 — second reconciliation pass, 28 → 23

Every remaining issue was re-read and verified against `origin/main` `2bc7dc2bc`.
**No issue was found complete-but-stale.** The five closures below are all
combinations: in each case two issues described one piece of work, and holding
them apart was creating a risk the combination removes. Every acceptance
criterion was transferred to the surviving issue in the same action, and each
closure comment names what moved.

| Issue | Closed as   | Absorbed into | Why they are one piece of work                                                                                                                                        |
| ----- | ----------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| #2347 | not planned | #2299         | Both say the launch numbers are untrustworthy. #2347: the test host is 7200rpm, so ~350 ms is storage tax. #2299: `guest_kernel_entry_ms` is 0.038 ms, so its own headline comparison is not measured at the same boundaries on both backends. Optimising against either alone is the failure. |
| #2281 | not planned | #2280         | Same measurement harness, same 20-sample/two-warmup gate, same blocked-on-native-hosts prerequisite, same "publish one canonical table and record an adopt/decline decision in Plan 299" shape. Two axes of one substrate; running the matrix twice risks two decisions taken against different fixtures. |
| #2199 | not planned | #2198         | A contract and its enforcement gate. #2199 gates on fields #2198 defines, so it cannot land first; #2198's "never report warm after a cold fallback" is unfalsifiable without #2199's 1,000 claims. Neither should be able to merge alone. |
| #2193 | completed   | #2194, #2196  | The prewarm substrate is merged on `main`. The one residual — per-backend disposable-VM factories — is not independently testable; it can only be exercised through each backend's own live validation matrix, which both issues already gate on. |
| #2166 | completed   | #2169         | Pure umbrella. Workstreams #2167, #2168, #2170 and related #2163 are closed; #2169 and #2083 are separately tracked. Its one residual criterion (end-to-end session reconnect through shared contracts) moved to #2169. |

Deliberately **not** combined, and why:

- **Plan 316's eight phases (#2368, #2371–#2377).** The phase split is a
  designed sequence with per-phase invariants and acceptance gates, not
  accidental fragmentation. Collapsing it would discard the ordering that is
  the plan's main safety property.
- **The warm-pool workstreams (#2194–#2197).** Backend parents, share slots,
  and process hardening are genuinely different work with different reviewers
  and different live-validation surfaces.
- **#2135.** A generated tracker. It closes when the generating workflow is
  green, not by judgement.

## Findings from the 2026-08-14 pass

Two discrepancies surfaced that are worth recording because neither was
visible from issue state alone.

**Plan 316 Phase 2 is marked complete and is not.**
`specs/plans/316-single-flow-vsock-networking.md` carried
`**Status: COMPLETE**` on Phase 2 while six of that phase's seven checkboxes
were unchecked in the same document, and two are verifiably undone in the tree:
the `EndpointSpawner` → `NetworkEndpointSpawner` rename has not happened
(`crates/mvm-hostd/tests/workload_stream_plane.rs` still imports
`EndpointSpawner`; the new names appear nowhere in the workspace), and the
hand-maintained duplicate `EGRESS_VSOCK_PORT = 5253` survives in
`crates/mvm-agentd/src/bin/mvm-egress-client.rs:16` and
`crates/mvm-agentd/src/bin/mvm-addon-dns.rs:93`. The second has a real cause —
`mvm-agentd` does not depend on `mvm-net`, so the guest cannot reach the typed
service mapping — which makes it a design question the phase owes an answer
to rather than a completed box. The plan status is corrected here; the issue
stays open.

**Plan 316's phase ordering has already been broken.** Phase 3 (#2372) is six
of seven boxes merged, ahead of Phase 2's completion. This matters because the
strict ordering was the mechanism meant to catch Phase 2 residue, so that
residue will not be caught by any later phase gate and has to be closed
deliberately.

**FlowMux is not on the production path at all.** This is the more serious
finding and it was only visible by reading the call sites rather than the
checkboxes. The host-side acceptor (`mvm-hostd::supervisor::flowmux`) and the
guest-side client (`mvm-agentd::flowmux`, wired to the loopback adapters by
#2468) both exist and are unit-tested. Nothing connects them on a real launch:

- `RealNetworkEndpointSpawner::spawn` — the single production spawn — passes
  `flowmux_identity: None`, hard-coded.
- `EndpointSpawnRequest` has **no** `flowmux_identity` field, so no caller can
  ask for it.
- The only construction of `FlowMuxIdentitySpawnConfig` in the workspace is
  inside `#[cfg(test)] fn endpoint_config_json_emits_flowmux_identity()`.
- `claim.rs` still computes `let raw_egress = inputs.secrets.is_empty();` —
  the raw-vs-wire admission choice Phase 3 is supposed to delete is the live
  selector.

So every admitted workload today speaks `Wire` or `Raw`, and the converged path
is unreachable machinery. Two consequences that change the plan:

1. **Phase 3's last checkbox cannot be executed as written.** Deleting
   `EgressMode`, `raw_egress`, and the raw-vs-wire choice would remove the only
   modes production uses and break all egress. The real remaining work is
   *switch production onto FlowMux*, and only then delete the legacy modes.
2. **Phase 2's and Phase 3's remaining boxes are one piece of work.** Phase 2
   owes "a failed FlowMux session prevents workload readiness"; Phase 3 owes
   "every flow type reaches one pipeline". Neither is meaningful until the
   production spawn carries a FlowMux identity. They should land together.

That work changes the egress path for every workload on every backend, so it
needs a live witness before merge, not just unit tests. It belongs with the
hardware-blocked set rather than the free-running set.

## 2026-08-14 — the tracker becomes empty; the plans become the ledger

The tracker and the plans were carrying the same work twice. Most open issues
were phase-trackers for a plan that already held the same items as checkboxes,
so an issue closing meant nothing until the plan agreed, and a plan moving
meant nothing until someone remembered the issue. Two ledgers that must agree,
updated by different people, is a reconciliation cost with no matching benefit
— this plan is itself the third attempt at paying it.

**Decision: the plans are the ledger.** Every open issue closes, and every
requirement it carried moves to the plan named below, with its acceptance
criteria intact. Work that had no plan of its own moves to
`specs/plans/332-open-work-register.md`.

This is bookkeeping, not progress. **Closing an issue moved its requirements;
it did not satisfy them.** Two of the closures are genuinely complete work
(#2101's fix, #2371's rename); the rest are transfers. The ADRs are untouched:
no claim was widened, no witness was dropped, and ADR-001's ledger still gates
under `check-claim-catalog`.

### Where each issue went

| Issue | Now owned by |
|---|---|
| #2368, #2371–#2377 | `specs/plans/316-single-flow-vsock-networking.md` — all eight phases, with checkboxes and the FlowMux-not-on-the-production-path correction |
| #2194–#2198, #2336 | `specs/plans/298-warm-claim-service-and-hvf-pool.md` + Phase 4 below |
| #2280, #2299 | `specs/plans/299-cold-launch-performance.md` + Phase 3 below |
| #2256 | `specs/plans/306-declared-backing-and-tier-honesty.md` — seven workstreams; WS1, WS4, WS6 landed, WS5 partially |
| #2211 | Phase 2 below |
| #2169, #2083 | Phase 7 below |
| #2101 | Phase 1 below — fix merged (PR #2478); the live probe remains |
| #2135 | `specs/plans/332-open-work-register.md` section H — the four concrete survivors |
| #2482–#2486, #2494, #2497 | `specs/plans/332-open-work-register.md` sections A–G |

### What is genuinely done

- **#2101** — PR #2478. `no_new_privs` and a bounded capability set on the OCI
  workload path, plus a real bug in the drop loop (`1u32 << cap` panicking at
  slot 32). The adversarial probe on HVF and Firecracker remains, and is
  carried in Phase 1.
- **#2371** — PR #2481. The `NetworkEndpointSpawner` rename and one home for
  the FlowMux port. The fail-closed readiness witness remains, and is carried
  in Plan 316.
- **#2107** — PR #2475, with the two unwitnessed acceptance criteria added
  afterwards.

### The two things that actually gate reaching zero *work*

1. **A Linux host with `/dev/kvm` and NVMe.** Eleven of the closed issues'
   requirements cannot be satisfied without one: the performance evidence
   matrix, the whole warm-launch chain, #2101's live probe, and the FlowMux
   production-path cutover.
2. **`mvm-studio#18`** for the launcher handshake.

Neither is a code problem, and neither was ever going to be solved by the
tracker.

## Current disposition — 23 open

| Issue | Owning plan | Disposition                                                              | Phase |
| ----- | ----------- | ------------------------------------------------------------------------ | ----- |
| #2135 | —           | Security lane red; PR #2472 open, run 31817896244 pending                | 0     |
| #2101 | ADR-001     | Kernel defect fixed by #2102; OCI `NoNewPrivs` + capability bound remain | 1     |
| #2107 | —           | Audit tracing mirror absent from `main`                                  | 2     |
| #2211 | research    | eBPF spike on branch only; scope decision required                        | 2     |
| #2299 | 299         | Launch baseline not trustworthy; absorbs #2347                            | 3     |
| #2280 | 299         | Substrate evidence matrix; absorbs #2281; blocked by #2299                | 3     |
| #2336 | 298         | Firecracker post-restore handshake; blocks the whole warm chain           | 4     |
| #2194 | 298         | Apple Silicon parent contract; absorbs #2193 residual                     | 4     |
| #2196 | 298         | Firecracker warm backend; absorbs #2193 residual; blocked by #2336        | 4     |
| #2195 | 298         | Fixed read-only share slots                                               | 4     |
| #2197 | 298         | Resident-process hardening                                                | 4     |
| #2198 | 298         | Warm contract + 1,000-claim gate; absorbs #2199                           | 4     |
| #2256 | 306         | Plan 306 not started; seven workstreams                                   | 5     |
| #2368 | 316         | Umbrella; Phases 0–1 done, 2–8 open                                       | 6     |
| #2371 | 316         | Phase 2 — two verified gaps plus the fail-closed assertion                | 6     |
| #2372 | 316         | Phase 3 — 6 of 7 boxes merged                                             | 6     |
| #2373 | 316         | Phase 4 — typed transformations                                           | 6     |
| #2374 | 316         | Phase 5 — declared ingress                                                | 6     |
| #2375 | 316         | Phase 6 — compatibility boundary; gated on a release, not just on code    | 6     |
| #2376 | 316         | Phase 7 — delete L3                                                       | 6     |
| #2377 | 316         | Phase 8 — permanent gate; should land with #2376                          | 6     |
| #2169 | —           | Bounded inspector contract; absorbs #2166 residual                        | 7     |
| #2083 | —           | Studio launcher; external dependency on `mvm-studio#18`                   | 7     |

Three of the 23 are blocked on things this repository does not control: #2299
and #2280 need a Linux host with `/dev/kvm` **and** NVMe that does not exist
yet, and #2083 needs `mvm-studio#18` to freeze a handshake. Those are called
out per phase below rather than left to be rediscovered.

## Phase 0 — Restore evidence quality

While the Security lane is red, several numbered ADR-001 claims have no live
evidence behind them. Nothing else in this plan is worth more than that.

- [ ] **#2135 — restore the Security lane.** PR #2472 accepts the remaining
      backend and runtime mutation survivors in the pinned baseline with reasons
      pointing at live backend integration tests and BDD scenarios; the
      pin-only surface gate passes. The prior repair reduced the accepted
      baseline from 83 to 68 without adding a waiver, added direct witnesses for
      the contract's omitted resource-control default and for hostd's exact
      broker byte limit, admitted-digest equality, host CPU mechanism truth
      table, explicit deferred-audit flush and drop-time flush, and fixed three
      test-infrastructure races found by successive exact runs (Linux `ETXTBSY`
      on freshly published shutdown-hook fixtures, a parallel CLI test observing
      another test's host CPU ceiling, and guest-console tests sharing
      process-global session state). Merge gate: a clean exact Linux Security
      workflow run. Close gate: a subsequent **scheduled or release** run green.
      Do not close on a `workflow_dispatch` run.

## Phase 1 — Close the remaining privilege gap

- [ ] **#2101 — finish OCI privilege hardening.** The kernel-selection defect is
      fixed on `main` by PR #2102 (`343eccce1`): the workload path accepts only
      the dedicated workload kernel, a default-microVM kernel is no longer a
      fallback, and regression tests cover dev and prod cache layouts. What
      remains is the second finding, which was always independent of the kernel
      question and is unchanged by the correction:
      `crates/mvm-agentd/src/bin/mvm-oci-init.rs` contains no `no_new_privs` or
      bounding-set call, so the OCI workload process runs with `NoNewPrivs: 0`
      and a full `CapBnd` of `000001ffffffffff` on **both** priority backends.
      - [ ] Narrow the issue body to this remaining decision; the `NAMESPACES`
            and HVF-property claims in the original report are withdrawn and
            should not survive in the issue text.
      - [ ] Decide and record whether ADR-001 claims 1 and 2 scope to mkGuest
            *services* only, where W2.3 already applies, or extend to the OCI
            workload process. This is an owner call and blocks the fix shape.
      - [ ] Define the minimal capability set the authenticated activation and
            restore paths actually require, then apply `no_new_privs` and the
            bounding set before workload exec.
      - [ ] Test setuid binaries, file capabilities, user-namespace attempts,
            wrong kernels, and syscall failure paths.
      - [ ] Re-run the adversarial probe from
            `specs/research/no-root-workload-live-witness.md` on HVF **and**
            Firecracker before closure. The outcome today holds by circumstance
            — the image ships zero setuid binaries and the rootfs is read-only —
            not by the named mechanism, so a probe that merely reports the
            starting uid does not close this.

## Phase 2 — Observability, without coupling it to evidence

Both items must not be able to weaken the audit chain or the sealed guest.

- [ ] **#2107 — mirror audit appends into tracing.** Emit one sanitized event at
      a dedicated target after each **successful** signed append, carrying only
      the fields the verified reader would expose: event kind, tenant, machine,
      plan id, timestamp, sequence. Share the verified-reader projection so
      field selection cannot drift between the two. Prove exact event parity,
      the secret/env/credential/key/host-path/policy-payload exclusions,
      byte-identical chain output with the mirror enabled and disabled, and that
      a panicking or blocking subscriber cannot alter append success, ordering,
      or latency. mvm emits only; no subscriber machinery ships here.
- [ ] **#2211 — settle the eBPF spike's contract.** The spike is on
      `feat/ebpf-vsock-egress-telemetry` and **not on `main`**: there is no
      `crates/mvm-ebpf-egress` in the tree. Decide one of two outcomes and
      execute it rather than leaving the issue to accrete:
      - Narrow to the landed Linux connection-observation spike, merge that, and
        refile byte accounting, latency attribution, and IPv6 as separate work;
        **or**
      - complete the original `(plan_id, vm_id, destination, bytes, latency)`
        tuple, attributing bytes and latency to the same plan/VM/destination
        binding, validated against the real `mvm-network-endpoint` on Linux.

      Either way: declare the macOS and no-target behavior explicitly, keep
      `BPF_SYSCALL` disabled in sealed workload kernels, add no guest-NIC or
      eBPF data plane for egress, and note that the spike's own text still says
      `mvm-substitution-endpoint` — that role is renamed on `main` and the
      issue needs updating with it.

## Phase 3 — Make performance evidence trustworthy before optimising against it

**Externally blocked.** Both items need a Linux host with `/dev/kvm` and NVMe.
Provisioning that host is the first action in this phase and nothing else here
starts without it.

- [ ] **#2299 — establish one trustworthy launch baseline.** Absorbs #2347.
      Define a backend-neutral interval from vCPU start to authenticated agent
      readiness and instrument HVF and Firecracker at identical boundaries, so
      the two numbers are subtractable — today `guest_kernel_entry_ms` reads
      0.038 ms on every Firecracker sample, which means the guest was already
      serving when the first readiness poll ran. Provision the NVMe `/dev/kvm`
      host, re-run the baseline, and publish it beside the rotational numbers
      from the 7200rpm host. State in Plan 299 which storage class the ≤200 ms
      contract is defined against; an SLO without one is not checkable. Re-scope
      the fsync-bound work against the NVMe result. Then publish side-by-side
      kernel timestamps with initcall and agent-start attribution, name the
      dominant contributor with evidence rather than from a console gap, and
      either reach <150 ms guest boot on Firecracker or record the architectural
      reason the backends cannot converge plus the revised contract. Do not
      retry virtio-rng (0 ms delta) or the i8042 probes (~8 ms, inside noise)
      without new evidence.
- [ ] **#2280 — publish the substrate evidence matrix.** Absorbs #2281. Blocked
      by #2299 — measured before the baseline is trustworthy, this matrix
      inherits the same storage tax and the same non-subtractable boot interval.
      Run the landed 20-sample/two-warmup gate on native HVF and native
      Firecracker with no degraded host services, and publish **one** canonical
      table: artifact sizes raw and compressed, initramfs size, built-in driver
      and boot-probe set with symbol counts, time to first guest instruction,
      time to authenticated readiness, whole-VMM working set, first-command
      fault deltas, and cold plus warm-restore fault cost. Compare the existing
      ext4/overlay/verity path against one guest-local immutable lower-layer
      candidate on the same fixture and the same security tier, with
      negative-path tests for xattrs, whiteouts, verity failure, read-only
      enforcement, CoW cleanliness, and tenant isolation. Record both
      adopt/decline decisions in Plan 299; neither may introduce a second cache
      graph. Every removed kernel feature needs a boot/readiness witness and a
      security witness, and the table feeds the release performance gates.

## Phase 4 — Make the warm pool work, then prove it

Strict order. Each step's live validation is the next step's precondition.

```text
#2336 Firecracker post-restore identity handshake
    -> #2194 HVF parent  |  #2196 Firecracker parent   (parallel)
        -> #2195 fixed read-only shares
            -> #2197 resident-process hardening
                -> #2198 CLI contract + 1,000-claim release gate
```

- [ ] **#2336 — diagnose, then fix, the post-restore identity handshake.** The
      single point of failure blocking every Firecracker warm claim. **Diagnosis
      first — the recorded cause is known-wrong.** The console line
      `authenticated control handshake failed: Failed to read frame length` is a
      red herring: `probe_ready` in `crates/mvm-vmm/src/post_restore.rs` connects
      and drops without a handshake, and the guest speaks second, so every 50 ms
      readiness probe produces that line during any restore. It also proves the
      host key *did* reach the guest, because `handle_client` would otherwise
      have returned the earlier `rejecting control connection without a pinned
      host key`. Plan 255 BUG-2's diagnosis therefore does not describe this
      failure.
      - [ ] Re-run the claim capturing complete stderr (`2>&1 | tail -60`, no
            grep) to obtain the full `Caused by:` chain under
            `signaling post-restore`. `probe_ready` succeeded, so the failure is
            inside `signal.post_restore(vm_name)`.
      - [ ] Candidates once that is in hand: the host-side
            `AuthenticatedSession::host` handshake over a vsock connection whose
            state did not survive snapshot restore, or the child's vsock CID/port
            mapping after fork.
      - [ ] Check `factory_parent_config`'s standing caveat as part of the fix: a
            factory parent holds no plan, so it emits no `mvm.verb_grant=`,
            `mvm.require_grant=` or `mvm.host_signer_pub=` cmdline tokens, and a
            child inherits its parent's cmdline out of restored memory rather
            than deriving its own. That divergence reaches every child by
            construction whether or not it causes this failure.
      - [ ] Keep the fail-closed posture. Refusing a child that cannot prove it
            reseeded is correct — that is the twin-CSPRNG case the fresh-identity
            guarantee exists to prevent. The defect is that the handshake cannot
            succeed at all, not that it refuses.
      - [ ] Reproduce and verify on a KVM host: `mvmctl pool warm 1 --image
            alpine`, then `MVM_RESIDENCY=warm MVM_HVF_WARM_REQUIRE_CLAIM=1
            mvmctl machine run --image alpine -- /bin/true`. Publish the claimed
            launch against the cold baseline of 549.8 / 564.7 / 554.4 ms
            `backend_start`.
- [ ] **#2194 — finalize the Apple Silicon parent contract.** Decide and record
      whether the supported path is a signed paused-parent handoff or a true CoW
      child restore; the substrate for both is landed (snapshot frame encoder,
      AArch64 register codec, device-state container with PL011/virtio-blk/
      virtio-fs/virtio-rng codecs, vsock control-state codec that fails closed on
      bound host endpoints or live sessions, acknowledged pause boundary, exact-
      size private COW remap, `VsockHostBindings` rebind). Prove fresh identity,
      authority and channels, failure quarantine, restart recovery, and live
      readiness on a **release** Apple Silicon build. Wire the disposable-VM
      factory to the shared golden-VM readiness verifier (from #2193) and assert
      warm claims are lookup-only. Capability bits stay honest: do not advertise
      standby until in-kernel interrupt-controller state is proven safe across
      restore and a sub-300 ms measurement is recorded.
- [ ] **#2196 — finish Firecracker warm claims on KVM.** Blocked by #2336.
      Validate factory capture, paused-child materialization, identity and grant
      delivery, snapshot device/network restrictions, cleanup, quarantine, and
      restart recovery on the exact merged source. Wire the backend factory to
      the readiness verifier and assert lookup-only claims. Production admission
      refuses until the full live matrix passes; no claim may silently become
      cold. Directory-share warm eligibility stays separate — Firecracker has no
      equivalent of the macOS share solution.
- [ ] **#2195 — bind fixed read-only share slots at claim time.** Fixed
      share-slot topology in golden VMs; typed guest tag/path/read-only shape;
      claim-time validation and binding through **opened directory handles**
      rather than path re-resolution; child VMM built with an identical device
      layout and a newly bound directory. Reject symlink, race, non-directory,
      disappeared-directory, and writable-expansion cases fail-closed. Host paths
      and directory contents stay out of pool keys, compatibility records, and
      snapshots. A backend that cannot bind before resume refuses warm mode
      rather than reporting a cold launch as warm.
- [ ] **#2197 — harden the resident workers by platform.** Linux: seccomp,
      Landlock where applicable, namespaces and cgroups, no-new-privileges,
      dropped capabilities, resource limits, inherited-FD and socket allowlists.
      macOS: process separation, restrictive entitlements, handle-scoped
      directory access, no ambient unrelated host paths, explicit share-worker
      ownership and lifecycle. Document the two platforms' guarantees
      separately — they are not the same guarantee. Test unauthorized file,
      socket and signal access, privilege retention, inherited-resource cleanup,
      and the worker-compromise boundary. A granted share must not expand into
      arbitrary host access.
- [ ] **#2198 — make warm outcomes exact, then gate them.** Absorbs #2199.
      Surface `pool_wait_ms`, `claim_ms`, `share_bind_ms`, `backend_restore_ms`,
      `warm_window_ms` as stable fields; distinguish warm success, cold success,
      warm refusal and warm failure in text and JSON; add explicit `--cold` and
      warm-required behavior; separate launch readiness from command execution
      and teardown so neither can relabel the result; test the exact 300 ms
      boundary. Then run ≥1,000 claims per advertised backend/share/shape/cache
      combination with **no outliers discarded**, publish p50/p95/p99/max/refusal
      rate and the cold comparison, and fail CI on a mislabeled warm claim, on
      max reaching 300 ms, or on p50 >30 ms / p99 >50 ms per Plan 297. Keep the
      workload benchmark (e.g. Python dependency installation) separate.

## Phase 5 — Governance and tier honesty

- [ ] **#2256 — execute Plan 306 in its recorded order.** Seven workstreams;
      WS1 and WS3 first because WS1 closes a defect this repository has already
      been bitten by and WS3 converts two known silent degradations into loud
      refusals.
      - [ ] **WS1** — declared-backing headers on claim-bearing contributor
            prose. `check-doc-claims` scans only `public/` and the root README
            by design, which is exactly why fabricated witness names lived in
            `specs/`, `CLAUDE.md` and `AGENTS.md` for months. Add a
            `Backing:`/`Validation:` header with an enum, a one-way citation
            rule (a `shipped-source` file may not rest on a `preview` one), and
            a `--self-test` that seeds a violation and asserts nonzero exit.
      - [ ] **WS3** — refuse what cannot be enforced exactly. Transient-lifecycle
            egress resolves to `AllowAll` on libkrun and HVF, and
            `up --network-allow` on libkrun enforces nothing. Convert both to
            typed refusals and add a fail-closed probe **before** the workload
            runs; today the gate is asserted wired by construction but the
            running host is never asked whether it took.
      - [ ] **WS4** — state the check-time law in ADR-001: *an effect may be
            checked no later than its last undo point*, with a column
            classifying each governed effect as checked-before or
            checked-at-commit.
      - [ ] **WS2** — derive the ADR-001 per-backend tier matrix from
            `capabilities()` rather than maintaining it by hand. Unblocked:
            #2248 made it computable.
      - [ ] **WS5** — pin the egress predicate algebra: deny-wins within a
            grant, union across grants, default-deny absent any admitting grant,
            and an unrecognised operator raises rather than falling through to
            allow. Replaces the env-var escape hatch with a verdict that denies.
      - [ ] **WS6** — freeze JCS replay vectors for `CanonicalEntry`'s signed
            bytes, covering the three cases where independent implementations
            diverge and today's vectors cover none: non-ASCII, integers above
            2^53, and float rejection. `mvm-contract` is meant to reach the
            browser, so a second verifier is coming.
      - [ ] **WS7** — double-key the stale-name relief valves so an exemption
            needs both a marker and an enumerated reason, and the list is
            visibly shrinking.

      Not in scope, per the issue: the grant riding the function parameter does
      not transfer here — the grant must stay detached so a supervisor that
      never sees the source can sign and verify it.

## Phase 6 — Complete the single FlowMux networking path (Plan 316)

Ordering was the plan's main safety property and it has already slipped: Phase 3
is six of seven boxes merged while Phase 2 has verified gaps. Close Phase 2's
residue before starting anything after Phase 3.

```text
#2371 Phase 2 residue  ->  #2372 Phase 3 (finish)
    -> #2373 Phase 4 -> #2374 Phase 5 -> #2375 Phase 6 -> #2376+#2377 Phases 7+8
```

- [ ] **#2371 — Phase 2 residue (rename portion landed in PR #2481).**
      Rename `EndpointSpawner`/`RealEndpointSpawner`
      to `NetworkEndpointSpawner`/`RealNetworkEndpointSpawner` and confirm one
      production `spawn` in `WorkloadRunner`. Resolve the duplicate
      `EGRESS_VSOCK_PORT = 5253` in `mvm-egress-client.rs` and `mvm-addon-dns.rs`
      — either give the guest the typed service mapping or record why it is
      pinned twice and gate the two values equal. Then the three assertions this
      phase exists for: a workload whose signed plan grants networking **does not
      reach ready** when the FlowMux session fails to authenticate; the
      transition adapter holds no independent connect, bind, DNS, rate or audit
      implementation, proved by test rather than convention; and no lock guard
      crosses an `.await`. Tick each plan checkbox in the change that makes it
      true.
- [ ] **#2371 + #2372 — put FlowMux on the production path.** These are one
      piece of work; see the findings section. Do this before deleting anything.
      - [ ] Add `flowmux_identity` to `EndpointSpawnRequest` and populate it in
            `RealNetworkEndpointSpawner::spawn` from the admitted plan's
            session identity and verifying key. Today it is hard-coded `None`
            and the request type has no field for it, so the converged path is
            unreachable outside tests.
      - [ ] Make a failed or missing FlowMux session prevent workload readiness
            when the signed plan grants networking — fail closed, not degrade.
            This is invariant 4 and Phase 2's central acceptance criterion.
      - [ ] Only then delete `EgressMode` (the `mvm-hostd` one — the
            `mvm-contract` enum of the same name is the L3 enforcement layer and
            belongs to Phase 7), `raw_egress`, protocol sniffing, duplicate line
            markers, and the `let raw_egress = inputs.secrets.is_empty()`
            admission choice in `claim.rs`.
      - [ ] Add the endpoint crash/restart integration tests.
      - [ ] Live-witness on at least one backend before merge. This changes the
            egress path for every workload; unit tests do not cover a
            regression that only appears against a real guest.
- [ ] **#2373 — Phase 4: stream typed transformations.** Replace
      `WireRequest`/`WireResponse` whole-body JSON/base64 with `OpenHttp` plus
      bounded streaming head/body frames, folding in Plan 313 Phase 1 so long
      responses no longer buffer wholly or die at a 30-second total-request
      deadline. Route typed connector execution through the endpoint; broker
      dispatch must not be able to call `TcpStream::connect`, an HTTP client, or
      a resolver, asserted by test. Apply substitution only after final
      DNS/redirect admission and immediately before host TLS emission, and
      redaction before each chunk crosses to the guest. Carry transformation as
      an explicit admitted flow class and refuse an opaque flow when the plan
      requires substitution — never downgrade silently. Preserve a bounded
      overlap window at least as long as the longest configured fingerprint so a
      split-frame secret is still caught.
- [ ] **#2374 — Phase 5: declared ingress on FlowMux.** Move `L3IngressMapping`
      to a transport-neutral signed-plan type, moving Rust, Python and TypeScript
      fixtures and schemas together. Bind listeners only after admission and
      before reporting ready; refuse duplicate binds, unsigned wildcard binds,
      unsupported protocols and unavailable transform material. TCP ingress on
      even stream IDs with redacted peer metadata; UDP ingress with one bounded
      peer table per mapping, replies only to a peer that previously sent to that
      mapping. Host-owned HTTP/TLS termination resolving certificate keys by
      plan-bound secret reference **inside** the endpoint, never serialized to
      the guest — a dedicated non-disclosure test. Opaque TCP ingress supported
      but explicitly marked non-transforming, refused at admission whenever the
      mapping requires transformation. Remove `mvm_core::ingress_broker` and
      `ingress_handler`; exactly one listener owner survives and teardown
      releases every socket.
- [ ] **#2375 — Phase 6: compatibility boundary.** Keep the loopback HTTP proxy,
      SOCKS5h, SOCKS5 UDP, controlled DNS stub, mediated ping helper and typed
      SDK connectors as the supported surfaces, all terminating in the same
      FlowMux client. **Release-gated, not code-gated:** hold the Phase-0
      `raw_ip_stack=true` rejection through the migration release and only then
      remove the flag from the Rust IR, both SDKs, schemas, examples, docs and
      fixtures — never a silent reinterpretation. Close Plan 278 as rejected,
      recording that no compatibility concession sets `DUMPABLE=1`, adds
      `CAP_SYS_PTRACE`, reads workload memory, or installs seccomp
      user-notification. Document plainly that unsupported traffic shapes have
      **no route**, not a second stack. BDD: proxy-aware app works, typed
      connector transforms, non-cooperative direct socket fails closed.
- [ ] **#2376 + #2377 — Phases 7 and 8, landed together.** Phase 8 replaces the
      temporary Phase-0 ratchet (`xtask check-l3-expansion-freeze`) with the
      permanent `check-single-network-path`, and Phase 7 deletes the tree that
      ratchet watches. Merged separately they leave a window with no gate over
      the invariant, so land them as one change or land the permanent gate first
      in shadow mode.
      - Phase 7: delete `mvm-contract::l3`, `NetworkMode`, `L3NetworkSpec`,
        `L3IngressMapping`, `mvm-net/src/l3/`, `mvm-agentd/src/l3/`,
        `mvm-net-agent`, guest `mvm0` setup, `mvm-hostd/src/netd/`, the
        `mvm-netd` bin, host TUN/netns/nftables setup, the smoltcp datapath,
        `mvm-vmm::host::netd_spawn`, and smoltcp itself. Update `Cargo.lock`,
        `deny.toml`, closure-budget baselines, release packaging, Nix
        derivations, kernel configs (drop the `CONFIG_TUN` requirement), scripts
        and CI path filters. Rewrite protocol-independent security scenarios
        from `s25_l3_vsock` against FlowMux; delete only those whose asserted
        capability is intentionally unsupported. `cargo machete`, `cargo deny
        check`, `cargo audit`, the duplicate-major gate and the closure-budget
        gate must pass with no L3-only dependency or binary left.
      - Phase 8: `check-single-network-path` asserts exactly one production
        network endpoint bin, exactly one production spawn implementation, every
        workload backend binding `NetworkFlow`, and no forbidden
        raw-packet/NIC/gateway symbols outside historical specs. Add a
        socket-owner gate permitting outbound `connect` and workload listener
        `bind` only in the endpoint plus enumerated non-workload host
        infrastructure, testing a forbidden synthetic call and every exemption.
        Add a signed-plan projection test proving TCP, UDP, DNS, ingress and
        typed connectors reach the same policy object and audit sink. Run the
        final `xtask network-perf` matrix against the Phase-1 baselines: opaque
        TCP/UDP p50 and p95 may regress ≤5%, throughput ≥95%, peak RSS ≤+10%;
        typed transformed HTTP may regress ≤10% while gaining bounded streaming.
        Any exception needs a measured root cause and owner approval recorded in
        Plan 316 before merge. Live-witness Firecracker on Linux/KVM and HVF on
        macOS, and libkrun on every supported host OS, each covering deny-all,
        admitted TCP, DNS, UDP, typed substitution, declared ingress, endpoint
        crash, no guest NIC, and absence of L3 services.
- [ ] **#2368 — close the umbrella last**, once Phases 2–8 are complete and the
      definition of done holds: no production L3/raw-packet workload networking
      code and no second ingress or egress socket owner; an admitted workload has
      either no `NetworkFlow` capability or exactly one authenticated FlowMux
      endpoint with no transport selector; every shape shares one policy
      projection, resource budget, session identity, audit sink and endpoint
      lifecycle; claims 5, 8, 10, 12, 13 remain `Shipped` and preview claim 16
      retains positive, negative, split-frame, wrong-destination and audit-leak
      witnesses.

## Phase 7 — Agent and Studio surface

**Externally blocked** on `mvm-studio#18` for the handshake contract.

- [ ] **#2169 — expose the bounded inspector through shared contracts.** Live and
      history cursors with durable-event recovery; bounded, redacted output;
      process tree, output tails, exit state; posture-authorized filesystem and
      stop/kill actions; capability discovery and versioned negotiation so Studio
      renders only what the target backend and posture support; consistent local
      and gateway errors. Test reconnect, stale cursor, replay prevention, denied
      and failed mutations, audit emission, teardown, and secret exclusion.
      Inspector access never implies production shell or exec; a stale or
      disconnected inspector cannot silently repeat a destructive action; both
      backends fail closed when they cannot enforce the requested operation.
      Carries #2166's transferred criterion: an end-to-end agent session
      reconnects through these contracts without weakening admission, audit, or
      the production-shell restriction, and Studio adds no private API.
- [ ] **#2083 — the versioned Studio launcher.** Freeze the matching server
      handshake with `mvm-studio#18` first. Locate only a sibling artifact beside
      `mvmctl` or the managed artifact under `MVM_HOME/bin`; never a
      user-supplied path, never through a shell, never via PATH discovery.
      Reject symlinks and unsafe ownership or mode. Handshake before opening a
      browser; open only after Studio reports readiness over a private inherited
      channel. Keep credentials out of argv, logs, errors and persisted state.
      Refuse production, fleet, or unknown posture. Forward Ctrl-C, reap the
      child, surface typed startup failures. Tests: help, missing artifact,
      incompatible version, invalid permissions/symlink, readiness timeout, child
      failure, production refusal, clean shutdown, and an end-to-end dev launch
      reaching an authenticated loopback inventory page without orphaning the
      server. Document deterministic version-paired packaging.

## Final reconciliation gate

- [ ] Every issue from the 23-issue set has a final disposition with linked
      evidence.
- [ ] Every active requirement has exactly one issue and one owning plan. No
      acceptance criterion exists only in a comment or only in this rollup.
- [ ] Host workspace tests green; Linux-only Clippy, Nix, Firecracker, KVM,
      kernel and privilege witnesses run in the project builder VM.
- [ ] `specs/SPRINT.md`, this plan, and `specs/REFACTOR-STATUS.md` agree.
- [ ] A fresh GitHub query contains no completed or superseded open issue.

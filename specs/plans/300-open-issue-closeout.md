# Plan 300 — Open issue reconciliation and closeout

**Status:** IN PROGRESS — 2026-08-13 reconciliation executed; 8 issues closed, 31 remain
**Snapshot date:** 2026-08-13

## Objective

Reconcile the 31 issues currently open against merged code, current product
intent, tests, live evidence, and the owning plans. Close work that is
demonstrably complete, combine or supersede duplicates, preserve active defects
and security gaps, and execute the remainder in dependency order until every
issue is either completed or deliberately declined with its remaining
requirements transferred.

The snapshot contains one issue whose implementation is complete but whose
GitHub state is stale (#2293). The other 29 issues retain material acceptance
criteria. Closing an umbrella, research issue, or partially implemented issue
does not count as progress unless its remaining criteria move to an explicit
owner in the same change.

## Execution update — first concrete-fix batch

The first implementation batch addresses two user-visible correctness/security
defects before the larger dependency graphs: #2165 makes every workload-runner
root command line agree with the read-only root block, and #2321 bounds the
credential-bearing forward response before it can be accumulated. #2323 uses
the shared bounded poll backoff for Firecracker teardown. These changes stay
open until their PRs are merged and the required live witnesses are recorded.

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

## 2026-08-13 reconciliation update

**Current open issue count: 31.** Eight issues were closed on 2026-08-13:
#2165, #2289, #2333, #2423, #2180, #2181, #2305, and #2413.

### Closed on 2026-08-13

| Issue | Closed as | Reason |
|---|---|---|
| #2165 | completed | PR #2330 merged; workload block-root bootargs agree with read-only root attachment |
| #2289 | completed | Kernel/libkrunfw pins now at 6.12.103 via PR #2301 |
| #2333 | completed | PR #2335 merged; `pool warm --image <ref>` fills the pool |
| #2423 | completed | PR #2428 merged; RFC 6962 consistency proofs landed |
| #2180 | not planned | Superseded by Plan 316 L3 deletion |
| #2181 | not planned | Superseded by Plan 316 L3 deletion |
| #2305 | not planned | Superseded by Plan 313 egress token accounting |
| #2413 | not planned | 0.10.4 bpf-linker pin remains stable; 0.11.0 not worth system LLVM cost |

### Plan 316 note

- #2370 (Phase 1) is closed; #2368 umbrella should be updated to mark Phase 1
  complete and Phase 2 (#2371) actionable.

## Snapshot disposition

| Issue | Disposition at 2026-08-13 | Closure owner |
|---|---|---|
| #2083 | Open; Studio server contract external dependency | Agent/Studio phase |
| #2101 | Kernel defect fixed; OCI privilege posture remains | Security phase |
| #2107 | Open; audit mirror absent | Audit/observability phase |
| #2135 | Open; Security lane red | Evidence-repair phase |
| #2166 | Parent epic; #2169 and #2083 remain | Agent/Studio phase |
| #2169 | Open; bounded inspector contract/APIs remain | Agent/Studio phase |
| #2193 | Partial artifact-prewarm substrate; backend factories remain | Warm-launch phase |
| #2194 | Partial HVF paused-parent handoff; final live contract remains | Warm-launch phase |
| #2195 | Open; fixed read-only share binding remains | Warm-launch phase |
| #2196 | Partial Firecracker standby path; #2336 blocks KVM matrix | Warm-launch phase |
| #2197 | Open; resident-process hardening remains | Warm-launch phase |
| #2198 | Partial typed timing; refusal/cold contract remains | Warm-launch phase |
| #2199 | Partial benchmark substrate; 1,000-claim matrix remains | Warm-launch phase |
| #2211 | Partial eBPF spike; bytes/latency/scope decision remains | Observability phase |
| #2256 | Open; Plan 306 not started | Governance phase |
| #2280 | Partial measurement substrate; native host matrix remains | Performance phase |
| #2281 | Partial ext4 baseline; candidate comparison/decision remains | Performance phase |
| #2292 | Host-side overhead mostly fixed; percentile gate remains | Performance phase |
| #2299 | Open; cross-backend phase accounting not comparable | Performance phase |
| #2307 | Known filter fixed; fail-open configuration gate remains | CI phase |
| #2318 | Open; receipt durability and head recovery decision remains | Audit/performance phase |
| #2336 | Open; Firecracker post-restore handshake failure | Warm-launch phase |
| #2347 | Open; NVMe baseline for launch contract | Performance phase |
| #2368 | Plan 316 umbrella; Phase 1 complete, Phase 2+ open | Networking rewrite phase |
| #2371 | Plan 316 Phase 2 — authenticated endpoint | Networking rewrite phase |
| #2372 | Plan 316 Phase 3 — converge egress TCP/UDP/DNS | Networking rewrite phase |
| #2373 | Plan 316 Phase 4 — stream typed transformations | Networking rewrite phase |
| #2374 | Plan 316 Phase 5 — declared ingress on FlowMux | Networking rewrite phase |
| #2375 | Plan 316 Phase 6 — compatibility boundary | Networking rewrite phase |
| #2376 | Plan 316 Phase 7 — delete L3 completely | Networking rewrite phase |
| #2377 | Plan 316 Phase 8 — mechanically enforce one path | Networking rewrite phase |

## Phase 0 — Close completed work and restore evidence quality

- [x] **#2293 — close the completed audit-chain fsync issue.** PR #2302
      removed the duplicate synthetic `plan.admitted` and bound OCI provenance
      to the plan that boots. PR #2317 made `plan.admitted` the durability
      barrier, deferred post-hoc records, preserved ordering and torn-tail
      detection, and recorded KVM timings. Add the evidence comment, close as
      completed, and synchronize this plan, the sprint, and the rollup. Closed
      as completed on 2026-08-10 after posting the merged implementation and
      KVM evidence; receipt-store latency remains independently tracked by
      #2318.
- [ ] **#2135 — restore the Security lane.** Triage every current failure in
      run 31359464384 against `origin/main`; repair actionable mutation
      witnesses without weakening the baseline; run the affected shards and
      then the whole Security workflow. Let the watcher close the issue only
      after a clean scheduled or release run. The failed run is now reconciled:
      direct witnesses catch the actionable `mvm-vmm`, `mvm-hostd`, and
      `mvm-agentd` mutants; accepted misses fail closed when their files leave
      the pinned surface; moved libkrun identities now name their current file;
      and obsolete accepted misses were removed, reducing the baseline from 83
      to 68 without adding a waiver. The first exact rerun exposed one
      default-equivalent contract survivor and five hostd survivors; direct
      witnesses now cover omitted fail-closed resource controls, exact broker
      byte limits, admitted digest equality, the host CPU mechanism truth
      table, explicit deferred-audit flushing, and drop-time flushing. Focused
      mutation proofs, workspace all-target Clippy, formatting, and the static
      surface gate pass on the fix branch. The workspace suite passed every
      repaired area but hit one unrelated host-agent socket-bind timeout; its
      isolated integration rerun passed 4/4. Exact Security run 31516221103
      passed every mutation and security job, then twice exposed a Linux
      `ETXTBSY` race while spawning freshly published shutdown-hook fixtures.
      The lifecycle runner now retries that transient spawn error with a
      bounded delay, with success-after-retry and retry-exhaustion witnesses;
      workspace all-target Clippy passes. The workspace suite passed the
      repaired area but one parallel CLI test observed another test's temporary
      host CPU ceiling; its exact isolated rerun passed. The next exact run
      exposed the guest-console tests sharing process-global session state;
      those stateful tests now share one lock and join their completion thread,
      with 20/20 parallel stress passes. A clean exact Linux Security workflow
      and subsequent scheduled or release run remain the merge-and-close gates.
- [x] **#2289 — closed by PR #2301.** Kernel and libkrunfw pins are now at
      6.12.103; normal release artifact refresh follows.
- [ ] **#2292 — finish the Firecracker host-overhead closeout.** Retain #2298's
      in-process API client, backoff, and split spans. Remove or explicitly
      justify the two remaining privileged operations, then run
      `ColdLaunchBench` with 20 samples after two warmups for both `alpine` and
      `python:3.12` on KVM and publish p50/p95/p99. Close only after the issue's
      checklist reflects the residual #2299 guest-boot work.

## Phase 1 — Fix safety and boot-correctness defects

- [ ] **#2101 — finish OCI privilege hardening.** Narrow the issue body to the
      remaining `NoNewPrivs` and capability-bounding-set decision now that
      #2102 fixed kernel selection. Define the minimal capability set required
      for authenticated activation/restore, apply it before workload exec, and
      test setuid/file-capability attempts, user namespaces, wrong kernels,
      and syscall failures. Re-run the adversarial probe on HVF and
      Firecracker before closure.
- [ ] **#2318 — define receipt durability and remove the redundant sync.**
      Record whether an execution receipt is a control or a record. Make the
      receipt body the durable object, treat the head as a recoverable cache if
      that matches the decision, rebuild a missing/stale/torn head under the
      tenant lock, and prove concurrent append ordering. Re-measure the KVM
      `emit: receipt` span against 100.7 ms and require at most one durability
      barrier per append unless the written model proves two are necessary.
- [ ] **#2307 — gate nextest override filters.** Add
      `xtask check-nextest-groups` using `cargo nextest list -E` for each
      configured override, reject nonexistent workspace packages and empty
      filter matches, register it in xtask help/available commands and CI, and
      add a self-test that moves a module and observes a nonzero exit.

## Phase 2 — Audit mirror and host observability

- [ ] **#2107 — mirror audit appends into tracing without coupling.** Emit one
      sanitized event at a dedicated target only after a successful signed
      append. Share the verified-reader projection so field selection cannot
      drift. Prove exact event parity, secret/path/policy exclusion, signed-
      chain byte identity, and that absent or hostile subscribers cannot alter
      append success, ordering, or latency.
- [ ] **#2211 — choose and finish the eBPF spike contract.** Either narrow the
      issue to the landed Linux connection-observation spike and refile byte,
      latency, and IPv6 attribution, or complete the original tuple. For the
      latter, attribute bytes and latency to the same plan/VM/destination
      binding, validate the real substitution endpoint on Linux, declare the
      macOS/no-target behavior, and keep sealed guest kernels BPF-free.

## Phase 3 — Establish comparable performance evidence

- [ ] **#2299 — make guest-boot measurements comparable before optimizing.**
      Define a backend-neutral interval from vCPU start to authenticated agent
      readiness, instrument both HVF and Firecracker at the same boundaries,
      and publish side-by-side kernel timestamps and initcall/agent-start
      attribution. Name the dominant contributor with evidence; reach <150 ms
      on Firecracker or record the architectural reason and revised contract.
- [ ] **#2280 — finish the kernel/boot-substrate matrix.** Run the landed
      20-sample/two-warmup report gate on native HVF and Firecracker without
      degraded host services. Publish artifact sizes, kernel symbols, readiness,
      whole-VMM working set, first-command fault deltas, and warm-restore cost
      for matching shapes. Every removed feature needs boot and security
      witnesses, and the canonical table must feed Plan 299 release gates.
- [ ] **#2281 — make the filesystem adopt/decline decision.** Compare the
      existing ext4/overlay/verity path and one guest-local immutable lower
      candidate on the same fixture and security tier. Measure preparation,
      readiness, first access, working set, and multi-claim density; test
      xattrs, whiteouts, verity failure, read-only enforcement, CoW cleanliness,
      and tenant isolation. Record the decision without creating another cache
      graph.
- [ ] **#2347 — re-baseline the launch contract on NVMe.** Provision or identify
      a Linux `/dev/kvm` host with NVMe, re-run the launch baseline, publish it
      beside the current rotational numbers, and re-scope fsync-bound work
      against the NVMe baseline. Define the storage class for the ≤200 ms
      contract.

## Phase 4 — Make the warm pool usable, then prove it

The executable dependency order is:

```text
#2336 Firecracker post-restore identity handshake
    -> #2193 verified artifact prewarm
    -> #2194 HVF parent / #2196 Firecracker parent
    -> #2195 fixed read-only shares
    -> #2197 resident-process hardening
    -> #2198 CLI timing and refusal contract
    -> #2199 1,000-claim release matrix
```

- [ ] **#2336 — diagnose and fix the Firecracker post-restore identity
      handshake.** Capture the full `signal.post_restore` error chain, determine
      whether the failure is in the vsock connection state after snapshot
      restore, the child's CID/port mapping after fork, or the authenticated
      session itself, then fix it. This is the single point of failure blocking
      the whole Firecracker warm-claim chain.
- [ ] **#2193 — connect asynchronous prewarm to real factories.** Feed the
      bootless prepared shape through the existing content-addressed jobs and
      authenticated readiness verifier. Test hit, miss, corruption,
      invalidation, concurrency, restart recovery, and source mismatch before
      either backend advertises capacity.
- [ ] **#2194 — finalize the Apple Silicon parent contract.** Decide and record
      whether the supported path is signed paused-parent handoff or a true CoW
      child restore. Prove fresh identity/authority/channels, failure
      quarantine, restart recovery, live readiness, and honest capability bits
      on a release Apple Silicon build.
- [ ] **#2196 — finish Firecracker warm claims on KVM.** Validate factory
      capture, paused-child materialization, identity and grant delivery,
      device/network restrictions, cleanup, quarantine, and restart recovery
      on the exact merged source. Production admission must refuse until the
      full live matrix passes.
- [ ] **#2195 — bind fixed read-only share slots at claim time.** Use opened
      directory handles rather than path re-resolution, reject symlink/race/
      disappearance and writable expansion, keep host paths and contents out
      of pool keys and saved state, and make unsupported backends refuse warm
      mode rather than report a cold fallback as warm.
- [ ] **#2197 — harden resident workers by platform.** On Linux apply
      no-new-privileges, capability drop, seccomp/Landlock or the documented
      equivalent, resource limits, and inherited-FD allowlists. On macOS use
      process separation, restrictive entitlements, handle-scoped access, and
      explicit ownership. Test unauthorized file/socket/signal access,
      privilege retention, cleanup, and compromise boundaries.
- [ ] **#2198 — make warm outcomes user-visible and exact.** Surface stable
      pool-wait, claim, share-bind, restore, and warm-window fields; distinguish
      warm success, cold success, refusal, and failure in text and JSON; add
      explicit `--cold` and warm-required behavior; test exactly 300 ms and
      prove command/teardown time cannot relabel a cold run as warm.
- [ ] **#2199 — run and gate the 1,000-claim matrix.** Cover every advertised
      backend, representative CPU/memory and image shapes, no-share and
      supported read-only shares, cache state, and explicit cold comparison.
      Retain all outliers and publish p50/p95/p99/max/refusal rate; CI fails at
      `>=300 ms`, p50 >30 ms, p99 >50 ms, or any mislabeled fallback.

## Phase 5 — Governance and tier honesty

- [ ] **#2256 — execute Plan 306 in its recorded order.** Land declared-backing
      headers and a failing self-test; derive the ADR-001 backend matrix from
      `capabilities()`; refuse unfaithful egress and add the pre-run probe;
      state and classify the check-time law; pin deny-wins/default-deny
      predicate algebra and deny-loud escalation; freeze audit JCS replay
      vectors including non-ASCII, >2^53 integer, and float refusal; then
      double-key stale-name exemptions. Each workstream updates its plan box,
      sprint, and rollup only after its tests pass.

## Phase 6 — Complete the single FlowMux networking path (Plan 316)

Plan 316 Phases run strictly in order. Phase 0 (#2369) and Phase 1 (#2370) are
already complete. Update the umbrella issue #2368 to mark Phase 1 done and
Phase 2 actionable, then execute the remaining phases in order:

```text
#2368 umbrella
    -> #2371 Phase 2 — authenticated endpoint
        -> #2372 Phase 3 — converge egress TCP/UDP/DNS
            -> #2373 Phase 4 — stream typed transformations
                -> #2374 Phase 5 — declared ingress on FlowMux
                    -> #2375 Phase 6 — compatibility boundary
                        -> #2376 Phase 7 — delete L3 completely
                            -> #2377 Phase 8 — mechanically enforce one path
```

- [ ] **#2371 — Phase 2: introduce the one authenticated endpoint.** Rename the
      production role to `mvm-network-endpoint`, rename `GuestService::Substitution`
      to `NetworkFlow`, authenticate one long-lived FlowMux session before
      accepting frames, add bounded per-stream registries and graceful shutdown,
      and keep legacy dispatch behind a transition adapter that calls the new
      endpoint's canonical functions.
- [ ] **#2372 — Phase 3: converge egress TCP, UDP, and DNS.** Replace raw
      preludes with typed frames, move parsing/DNS/rate/audit into one pipeline,
      delete `EgressMode` and protocol sniffing, and add integration tests for
      deny-all, pinning, concurrent flows, and endpoint crash.
- [ ] **#2373 — Phase 4: stream typed transformations over the same path.**
      Replace whole-body JSON exchange with bounded streaming frames, route
      typed connectors through the endpoint, apply substitution/redaction as an
      explicit admitted flow class, and prove split-frame secret detection.
- [ ] **#2374 — Phase 5: implement declared ingress on FlowMux.** Move
      `L3IngressMapping` to a transport-neutral signed plan, bind listeners only
      after admission, implement TCP/UDP and HTTP/TLS ingress with host-owned
      certificates, and remove the second listener process/policy type.
- [ ] **#2375 — Phase 6: set the compatibility boundary.** Keep loopback proxy,
      SOCKS5h, SOCKS5 UDP, DNS stub, ping helper, and typed connectors as the
      supported surfaces; reject `raw_ip_stack` and close Plan 278; document that
      unsupported traffic has no route.
- [ ] **#2376 — Phase 7: delete L3 completely.** Remove `mvm-contract::l3`,
      `mvm-net/src/l3/`, `mvm-agentd/src/l3/`, `mvm-hostd/src/netd/`, smoltcp,
      `CONFIG_TUN`, and the L3-only tests and suites. This closes #2180 and
      #2181 by making them obsolete.
- [ ] **#2377 — Phase 8: make one path mechanically enforceable.** Replace the
      temporary Phase-0 ratchet with `check-single-network-path`, add a socket-
      owner gate, prove all network shapes reach the same policy/audit sink, run
      the final `xtask network-perf` matrix, and live-witness every backend.

## Phase 7 — Complete the agent and Studio surface

The durable session (#2167), runtime approval (#2168), typed bindings (#2170),
and SDK parity (#2163) are already closed. Remaining order:

```text
#2169 bounded inspector -> #2083 versioned launcher -> #2166 epic closeout
```

- [ ] **#2169 — expose the bounded inspector through shared contracts.** Add
      live/history cursors, bounded/redacted output, process state, capability
      discovery, posture-authorized filesystem and stop actions, and consistent
      local/gateway errors. Test reconnect, stale cursor, replay prevention,
      denied and failed mutations, audit emission, teardown, and secret
      exclusion.
- [ ] **#2083 — coordinate and implement the versioned Studio launcher.**
      Freeze the matching server handshake with `mvm-studio#18`; locate only a
      sibling or managed artifact; reject symlinks and unsafe ownership/mode;
      use a private inherited readiness channel; keep credentials out of argv,
      logs, errors, and state; refuse production/fleet/unknown posture; and
      prove version mismatch, timeout, child failure, Ctrl-C, reaping, package
      pairing, and an authenticated loopback inventory page.
- [ ] **#2166 — close the parent epic last.** Update its child ledger to show
      #2167, #2168, and #2170 complete, then close only after #2169 and #2083
      merge and an end-to-end agent session reconnects through the shared
      contracts without weakening admission, audit, or production-shell
      restrictions.

## Final reconciliation gate

- [ ] Every issue from the current 31-issue set has a final disposition and
      linked evidence.
- [ ] Every active requirement has exactly one issue and one owning plan; no
      acceptance criterion exists only in a comment or in this rollup.
- [ ] Host workspace tests are green; Linux-only clippy, Nix, Firecracker,
      KVM, kernel, and privilege witnesses ran in the project builder VM.
- [ ] `specs/SPRINT.md`, this plan, and `specs/REFACTOR-STATUS.md` agree.
- [ ] A fresh GitHub query contains no completed or superseded open issue.

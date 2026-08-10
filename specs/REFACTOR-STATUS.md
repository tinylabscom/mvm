# Refactor status

Last updated: 2026-08-08

This is the cross-plan progress index. The owning plan remains authoritative
for detailed scope and acceptance criteria.

## Completed issue closeouts
- [x] **Issue #2128 — kernel pin freshness.** The libkrunfw bundle and custom
      guest kernel now share the verified Linux 6.12.102 LTS source pin;
      structural parity coverage prevents the consumers from drifting apart.

## In-flight plans

- [~] Security lane mutation-witness repair — **issue #2135**
  - [x] Add direct witnesses for the security-sensitive admission,
        verification, lease, and substitution cleanup invariants
  - [x] Run focused mutation shards for `mvm-cli`, `mvm-core`, `mvm-agentd`,
        `mvm-hostd`, and `mvm-vmm`
  - [x] Pass workspace check, all-target Clippy, formatting, and the mutation
        surface gate on the dedicated fix branch
  - [ ] Merge the fix and rerun the exact Linux Security workflow before
        closing the issue
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
  - [ ] Phase 1 — content-addressed `--mount` image cache
  - [ ] Phase 2 — artifact preparation outside the launch path
  - [ ] Phase 3 — reduce backend cold-start latency
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
        `stop_transient` 142.9 ms, which is real cleanup. Follow-up: give pool
        maintenance to the resident per-tenant daemon.
  - [ ] Phase 7 — live validation and regression gates

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
        multi-queue presumes. What limits *one* flow is a fixed ~12.8 µs
        per-pass cost that is almost entirely one syscall: on macOS a
        zero-timeout `kevent` returning **no** events costs ~12,600 ns
        against 171–430 ns when it returns one, reproduced in pure C with
        none of this code in the picture, and `drain_for` only terminates on
        a zero return. **Since fixed**: the drain now stops on a *short*
        return, which a drained queue is already reporting, so the
        terminating empty call is gone. Re-measured on the same host —
        guest→host **2.9×** (1.9 → 5.5 Gb/s), host→guest 1.12× (7.0 → 7.8),
        round-trip p50 68 → 53 µs. The gain splits that way because the
        removed call is the *second* one, and only ~37% of host→guest drains
        find anything to make a second call about. The remaining ~12 µs is
        the empty *first* poll, and the obvious fix for it — skip the drain
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
        the verification seam here, so this *half*-unblocks #2119 rather
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
        B3 OPFS content-addressed cache with verify-on-read; B4 `wasm-opt -Oz`
        + gzipped-size budget in the existing wasm lane; B5 delete
        `web/audit-verify/`, fix the stale `mvm-verify` refs in ADR-031, add
        `mvmctl audit pubkey`
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
        reworded (it used to hold by *absence*, there being no host→guest byte
        path at all, and now holds by *policy*) and claim 17 added at status
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
        has no caller outside `tests/workload_input_plane.rs`, so *neither* half
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
  - [~] Residual after T9b/T9d: T9d closed the *seal* half — a detached run's
        transcript is now sealed by whatever stops the VM. The *follow* half
        remains: the console follower still dies with the starting process, so
        output a detached VM produces after that point reaches no capture at
        all until a resident host process owns the plane
  - [ ] Deferred to the broker task: state a follower's start sequence in the
        first batch, so the reader can close the accept-window gap between the
        transcript snapshot and the live subscription
  - [ ] Deferred to the broker task: re-seal the stream transcript periodically,
        so durable history exists for a *running* VM and survives a kill
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
        *relational*, so a canonicalization change moving every address
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
    - [ ] Workload/builder kernel cache: still path-trusting.
          `verify_fetched_kernel` exists with **no production caller** —
          neither the fetch nor the read path checks a kernel against its pin.
          Scoped as plan 288
          (`specs/plans/288-kernel-cache-verify-on-read.md`)
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

- [~] Plan 285 — L3 TUN-over-vsock network mode
  (`specs/plans/285-l3-tun-over-vsock.md`, ADR-036)
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
  - [ ] macOS forwarding backend — capability-declared and refusing; the
        userspace socket gateway is not implemented
  - [ ] WSL2 validation on a real runner; node-to-node transport; mvmd
        node-control RPC surface

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

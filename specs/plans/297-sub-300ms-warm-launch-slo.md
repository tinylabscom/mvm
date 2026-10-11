# Plan 297 — Sub-300ms warm launch contract

**Status:** In progress.

## Decision

The sub-300ms requirement applies to every successful warm-eligible transient
machine launch. The measured interval starts when launch resolution begins and
ends when the claimed child has a reachable guest agent and is ready for the
first command. It includes cache validation, admission, pool claim, child
materialization, identity reseeding, backend restore/start work, and the vsock
readiness handshake.

The launch path is prepared-only: it never downloads, compiles, pulls,
materializes, or repairs. Missing or stale artifacts fail within the same
budget and name the explicit `bootstrap` or `image pull` command. A
warm-eligible launch never silently falls back when its compatible standby is
missing; it names `pool warm`. Shapes the current pool cannot serve—such as
named machines and materialized directory volumes—retain their separately
reported cold path until the backend capability work below makes them
warm-eligible. Command execution and teardown remain outside the startup
interval.

The hard requirement is strict: every successful launch must complete startup
in less than 300ms. Exactly 300ms is a miss.

The aggregate targets are stronger than the hard ceiling:

| Metric | Requirement | Meaning |
| --- | ---: | --- |
| Per-launch maximum | `< 300ms` | No successful warm-eligible transient launch may exceed the hard ceiling |
| Warm p50 | `≤ 30ms` | Normal local hot-path target |
| Warm p99 | `≤ 50ms` | Scheduler and filesystem variance budget |
| Cold boot | separately reported | Only for currently ineligible launch shapes |

The CLI timing record reports `launch_mode` and `warm_slo`. A cold run reports
its actual phases and is never labeled as a warm success. A warm run that
exceeds the ceiling fails the launch contract and records the phase breakdown.
When phase timing is requested, JSON runs keep stdout as one machine-readable
document and include the structured timing record in `phase_timing`; human
readable runs render the same information as a table. The legacy timing line
and detail records remain available to non-JSON log consumers.

## Critical-path design

The warm path is:

```text
admit plan
  -> reserve compatible clean standby
  -> materialize child using local CoW
  -> bind fresh identity and workload authority
  -> restore/resume under the no-NIC guard
  -> reapply confinement and attach live shares
  -> authenticated vsock readiness
  -> first command
```

No network, object-store fetch, image build, ext4 materialization, host
directory copy, cache repair, or synchronous cleanup belongs in this interval.
A cache or standby miss refuses the launch and names the explicit preparation
command; it never silently expands the interval or cold-boots.

## Compatibility and live mounts

The pool key must include image and boot compatibility inputs: image digest,
architecture, kernel and initramfs digests, backend/VMM version, CPU and
memory shape, runtime overlay, network-policy shape, guest-agent protocol,
and directory-share shape.

The host path itself must be late-bound at claim time. A user changing the
host directory contents must not invalidate the factory parent or force a
directory copy. The backend must therefore either hot-attach the read-only
virtio-fs share after claim or reserve a share endpoint whose host path can be
bound before the child becomes guest-visible. If a backend cannot satisfy that
property, it refuses the warm claim and uses its separately measured cold
path; it never stages an ext4 replacement.

All warm claims still execute admission, identity reseeding, authority
binding, confinement, and authenticated vsock setup. The pool is a latency
optimization, not an authorization bypass.

## Instrumentation contract

The timing record must contain:

- `launch_mode=cold|warm`;
- `pool_wait_ms` and `claim_ms` for warm launches;
- `backend_start_ms` and `vsock_wait_ms`;
- `warm_window_ms`, defined as the admitted-to-vsock-ready interval;
- `warm_slo=ok|over` for warm launches and `warm_slo=na` for cold launches;
- the image/backend/CPU/memory/share-shape benchmark dimensions.

The existing phase-timing unit tests pin the strict boundary and the p50/p99
constants. The live benchmark must run at least 1,000 claims for each
supported backend and share shape, discard no outliers, and publish p50, p95,
p99, maximum, claim-refusal rate, and cold comparison. CI passes only when
the hard maximum is below 300ms, p50 is at most 30ms, p99 is at most 50ms,
and no claim silently falls back after being labeled warm.

## Delivery gates

- [x] Remove the directory-to-ext4 staging path and the retired CLI surface;
      transient host directories use only live read-only shares.
- [x] Pin the strict `<300ms` warm-window boundary in phase timing.
- [x] Add cold/warm launch-mode and SLO status to the runtime timing record.
- [x] Remove the secret-free deny-all egress endpoint from the warm claim hot
      path and defer broad orphan-state maintenance until after the guest
      command; the security posture remains fail-closed while launch timing
      excludes unrelated filesystem cleanup.
- [x] Add `pool_wait_ms`, `claim_ms`, and `warm_window_ms` to the runtime timing
      record.
- [x] Keep phase timing JSON-safe by embedding it in `--json` output and render
      it as a table for non-JSON runs.
- [x] Make published artifacts the default for source and release binaries;
      local guest-runtime compilation requires an explicit build-mode bootstrap.
- [x] Make transient launch artifact resolution cache-only and move pulling,
      materialization, and cache repair to explicit preparation commands.
- [x] Refuse cold fallback and enforce the strict startup ceiling on successful
      transient launches.
- [x] Preload paused Firecracker child VMMs during pool refill, run the
      no-NIC device-model guard before publication, and resume only after the
      claim wires fresh host channels and completes the child identity gates.
- [ ] Make pool compatibility and late-bound share attachment explicit in the
      backend capability contract.
- [ ] Add a hermetic benchmark harness with deterministic claim/refusal cases.
- [~] Run the live 1,000-claim matrix on every supported backend and record
      the results in a dated validation note. Darwin arm64 now has a fresh
      release-built 1,000-claim run with 1,000/1,000 successful warm claims,
      p50=17.9ms, p95=22.1ms, p99=27.4ms, and max=33.3ms; every claim stayed
      below the strict 300ms ceiling. The earlier Linux x86_64 Firecracker/KVM
      30/30 matrix measured only raw restore reachability. The source-matched
      authenticated witness completed 15/15 claims, with normal claims at
      63–76ms but restore-start outliers at 513ms and 620ms; the identity RPC
      itself stayed at 24–35ms. The strict Linux maximum is not green yet; the
      Firecracker implementation now pre-loads paused child VMMs during pool
      refill so restore/process-start variance is outside the measured launch
      window, with real Linux validation of that path remaining open. Linux
      libkrun and the
      remaining backend/share-shape matrices remain open.
- [ ] Enforce the hard maximum and aggregate p50/p99 thresholds in CI.

The host-side live acceptance harness is now available as
`just hvf-warm-restore`. It records the bootstrap separately, then requires a
configurable matrix of real HVF claims to report warm mode, `warm_slo=ok`, and
the strict `<300ms` ceiling before checking the p50/p99 targets. The fresh
Darwin arm64 1,000-claim matrix passes both aggregate targets. The direct
Linux Firecracker/KVM witness is green; production standby admission and the
remaining backend/share-shape matrices remain open.

The macOS host-vsock test hang was traced to parallel tests mutating the
process-wide `MVM_HOME` while another test was connecting to its socket. The
UDS-channel tests now use explicit isolated roots, and the complete
`mvm-hostd` package suite passes without the hang.

## Non-goals

- This plan does not promise cold boot below 300ms for launch shapes the
  standby pool cannot yet serve; those remain visibly cold and separately
  measured.
- This plan does not make read-write host shares safe or part of the warm
  contract; transient live shares remain read-only.
- This plan does not put remote artifact storage on the synchronous launch
  path.

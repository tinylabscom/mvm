# 2585 — a lane that never finishes is not a green lane

## What the issue said, and whether it reproduced

The tracking issue named one failing job on run 31927524890: `Claim
witnesses — mutation-tested (mvm-vmm)`, four survivors in
`EgressProxySpawnConfig::from_host_env`. All four were real witness gaps —
the function had no direct coverage at all — and all four were already
closed: #2578 landed six behavioural tests four minutes after the watcher
opened the issue. Verified against `origin/main`:

```
cargo mutants -p mvm-vmm --file crates/mvm-vmm/src/host/network_endpoint_spawn.rs --re from_host_env
Found 4 mutants to test
ok       Unmutated baseline in 26s build + 7s test
4 mutants tested in 74s: 4 caught
```

The fifth survivor in that log, `SubstitutionSpawnParams::builder ->
Default::default()`, is the provably-equivalent one #2540 baselined; still
correctly tolerated, and it shares an identity with nothing live.

So the named failure needed no fix. The lane was red anyway, for two
reasons the issue could not name — because the watcher could not see them.

## A job killed by its own timeout reports `cancelled`

`security-lane-watch.yml` selected jobs whose conclusion was `failure` or
`timed_out`. Actions does not use `timed_out` for a job killed by
`timeout-minutes`; it reports `cancelled`. Two jobs in that run were in
exactly that state and appear nowhere in the issue:

| job | ran for | budget |
|---|---|---|
| `Claim witnesses — mutation-tested (mvm-hostd/2of2)` | 5h30m26s | `timeout-minutes: 330` |
| `Fuzz — parsers (vsock + OCI)` | 6h00m16s | none, so the platform cap |

Missing them from a report is the small half. On a night where an
unfinished shard is the only casualty, the failing set is *empty* — and the
watcher reads an empty set as green and closes the tracking issue. A run
cancelled as a whole had the same hole from the other side.

`security.yml` had already written down the intent this defeated: a shard
under the cap "fails as itself". It does not; it is stopped as itself, and
reports as cancelled. Both the comment and the watcher now say so.

The shard imbalance that caused the mutation-side timeout was fixed
independently and first in #2584, which cut `mvm-hostd` four ways off the
same measurement. That PR noticed the `cancelled` conclusion and recorded
it; nothing acted on it, which is what this closes.

## The fuzz lane had never finished a cron run

`secs=1800` was chosen when the lane had four targets. It has seventeen.
Step timings from the run:

```
34.8 min  success   Fuzz GuestRequest
  ...               (nine more, all 30-32 min)
18.6 min  cancelled Fuzz gateway packet parse + rebuild (host-side)
 0.0 min  skipped   Fuzz userspace datapath ingress (fuzz_datapath_ingress)
 0.0 min  skipped   Fuzz runtime recording (SDK trace)
 0.0 min  skipped   Fuzz ext4 build_image (rootfs writer)
 0.0 min  skipped   Fuzz FUSE dispatch (virtio-fs request parser)
 0.0 min  skipped   Fuzz virtqueue geometry (virtio-vsock ring walk)
```

`fuzz_datapath_ingress` is named in ADR-001 as a claim-5 witness. It had
never executed on a nightly. The job reported `cancelled`, so nothing said
so. `specs/SPRINT.md` predicted this in July — "the lane should be expected
to time out rather than pass" — and the residual was never closed; it is
closed here and that note amended in place.

Budget is now 720s per target under `timeout-minutes: 300`: 17 × (720 +
120s build allowance) = 238 min, 62 minutes of headroom. The build
allowance is measured — the run's per-step times put a sanitizer build
between a few seconds and five minutes.

## Keeping the budget honest

A duration set in one place and a target list grown in another is how 4 ×
30 min became 17 × 30 min without either edit looking wrong. `xtask
check-workflow-paths` already enumerated the fuzz targets, so it now
multiplies them by the declared per-target seconds and refuses a product
that cannot fit. Target eighteen fails a PR rather than silently pushing
the lane back over its ceiling.

Proof it bites — reverting `FUZZ_SECS_SCHEDULE` to 1800:

```
Error: check-workflow-paths: 1 fuzz lane(s) cannot finish inside their timeout:
  security.yml: fuzz job budgets 17 target(s) × (1800s fuzzing + 120s build) = 544 min, past its own timeout-minutes: 300
```

and the unit witness with it:

```
thread 'check_workflow_paths::tests::the_fuzz_lane_fits_inside_its_own_timeout' panicked
17 targets × 1800s + build does not fit in 300 min
```

Restored: 627 passed, 0 failed in `xtask`.

## What is not fixed

The shape #2578 named is still open: the surface pin protects against a
*file* leaving mutation coverage, not against new uncovered code arriving
inside a file already on the surface. That is how `from_host_env` shipped
unwitnessed, and nothing here changes it.

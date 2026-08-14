# 2497 — release verification required a deleted binary

Plan 305 deleted the `mvm-bridge` sidecar and corrected the prose docs, but the
packaging and install layer kept naming it. `verify-release-assets.sh` listed
`mvm-bridge` as a required asset for every target while `release.yml` builds and
bundles only `mvmctl`, `mvm-network-endpoint`, and — on macOS — the two
supervisors. Since `release.yml` runs that verifier, the next tagged release
would have failed asset verification on every target.

The gate could not have caught this. `verify-release-assets.test.sh` carried its
own copy of the same stale list, and `build_valid_fixture` creates whatever that
copy names — so the fixture manufactured a `mvm-bridge` file and the check went
green. Both lists were stale in lockstep.

## Delivered

- Dropped `mvm-bridge` from the verifier's required-bin lists, the test's
  fixture list, the Homebrew formula, and `install.sh`'s install loop.
- Corrected the two live install docs, which additionally named
  `mvm-substitution-endpoint` — not the binary's name; it is
  `mvm-network-endpoint`.
- Corrected `CLAUDE.md`, which listed `mvm-bridge` as a per-VM supervisor bin
  and `supervisor/` as containing a `gateway_bridge/` module deleted with the
  gateway stack, plus two `Cargo.toml` comments describing the sidecar.
- Added a drift gate: the test now derives the shipped set from `release.yml`'s
  staging loop and asserts every bin the verifier requires is one the workflow
  actually bundles. Restoring `mvm-bridge` to the verifier turns it red with
  `verifier requires bin(s) release.yml never builds: mvm-bridge`.

`public/docs/investigations/binary-size-baseline.md` still names the binary and
is deliberately left alone — it records measurements taken at a point in time.

## Validation

`shellcheck` on all three scripts, and `verify-release-assets.test.sh` at
12 passed / 0 failed — both the lanes `ci.yml` runs for these files.

## Second instance of the same bug class

Generalizing the check — enumerate every real binary and crate from `cargo
metadata`, then scan packaging, CI, scripts, and docs for names that do not
exist — found one more live break. `-p mvm-vm-host`, a crate the Bar-A
consolidation absorbed into `mvm-hostd`, was still being built by
`scripts/check-hvf-oci-allow-host-smoke.sh` (wired into a `just` recipe) and
`scripts/measure-hvf-density.sh`. Both fail on that line:

```
error: package ID specification `mvm-vm-host` did not match any packages
```

In both scripts the preceding line already said `-p mvm-hostd`, so only the
supervisor's line was missed when the crate moved. A comment in `ci-full.yml`
named it too. Same root cause as the bridge: the rename updated the code and
not its callers.

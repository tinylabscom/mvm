# The Linux e2e lane's three real failures

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#3007](https://github.com/tinylabscom/mvm/issues/3007)

## Outcome

Two of the three scenario failures the documented-surface Linux lane reported
are fixed at their root cause, both verified on real KVM hardware. The third is
#3039 and is already gated.

## Why these were invisible

`Extended CI` had never been allowed to finish (fixed separately in #3178), so
nobody had read this lane's verdict in days. Underneath that, two of the three
failures could only ever have been seen there: the macOS/HVF documented-surface
job is **skipped** on hosted runners, so Linux/Firecracker is the only lane in
the repository that boots a guest at all.

Both bugs are host-architecture- or host-storage-dependent, which is exactly the
class a developer machine cannot see.

## 1. Every OCI image lost its own environment

`pull_core.rs`'s fresh-pull path built its `MaterializeCall` with
`entrypoint: None`, forty lines after computing `config_path` and never using
it. The sibling cache-hit path had always passed it.

The image's config blob is its declaration of `Env`, `WorkingDir` and
`Entrypoint`/`Cmd`. Dropping it means `/etc/mvm/image-runtime.json` is never
written into the rootfs, and the guest falls back to
`workload_env::DEFAULT_PATH` — so an image's own tools are off `PATH` even
though the binaries are right there in the rootfs.

Measured on the KVM box, `machine run --image rust -- /bin/bash -c 'command -v
cargo; echo PATH=$PATH'`:

    before  PATH=/run/mvm/bin:/usr/local/sbin:/usr/local/bin:...   (no cargo)
    after   PATH=/run/mvm/bin:/usr/local/cargo/bin:/usr/local/sbin:...
            /usr/local/cargo/bin/cargo

and `/etc/mvm/` in the materialized rootfs goes from `name variant` to
`entrypoint image-runtime.json name variant`.

The scenario that caught this was written for a *different* bug — a mounted PTY
run being routed through `/bin/sh -lc`. That fix (#3104) is intact; it was
failing underneath for this reason, which is why the mount and the terminal
looked implicated and were not. A plain-path scenario now states the defect as
it actually is.

## 2. A machine with no volumes was refused on an unencrypted disk

`refresh_registered_host_snapshots_*` constructed `MountImageCache` on entry,
and constructing it verifies that its directory sits on encrypted backing
storage. That check is about where a *mounted host directory's* bytes come to
rest, but charging it to every launch meant a named machine with no registered
volumes and no `--mount` at all was refused on any host without a dm-crypt/LUKS
mapping:

    mount image cache is not on encrypted backing storage
    /root/.mvm/cache/mount-images is backed by /dev/md2, which does NOT
    appear to sit on a dm-crypt/LUKS mapping

This is a production defect, not only a lane failure: it blocks `machine run -d`
for any user on an ordinary disk. The cache is now opened only once an
attachment carrying a host snapshot is found; `require_host_encryption` still
guards each snapshot's source separately, so enforcement is unchanged where it
applies.

It survived because `MountImageCache::new` is `#[cfg(test)]`-stubbed to skip the
very verification that fails, so under test eager and lazy construction were
indistinguishable. The constructor is now injected at that seam and the test
asserts *whether* it runs.

## 3. The SDK fixture pinned an architecture

`sandbox_script.py` pinned `alpine@sha256:e7a1a92a…`, which the registry reports
as a single-platform `linux/arm64/v8` manifest — not a multi-arch index. On
x86_64 the guest is handed aarch64 binaries and `uname` fails to exec:

    Guest proc error (SpawnFailed): Exec format error (os error 8)

It passes on Apple Silicon and cannot pass on the only lane that boots a guest.
Repinned to alpine:3.22's index digest, which carries amd64 and arm64 among
others. Still immutable and content-addressed, so claim 14's plan-mode refusal
of mutable references is unaffected — verified: plan mode still reports
`ADMITTED`.

A digest pin looks architecture-neutral and is not. Every other `@sha256:` image
pin under `features/`, `fixtures/` and `scripts/` was audited; this was the only
real one.

## 4. The failure that hid all of this

`SandboxLiveError` captured `mvmctl`'s stderr and rendered only its summary
line, so the CI log said `failed with exit code 1` and nothing else — for a
class whose whole diagnosis is in that stderr. Its own docstring promised
"exactly which verb refused and why". Fixed in both the Python and TypeScript
SDKs; the first run with it produced the encrypted-storage error above
immediately.

## Delivery checklist

- [x] Pass the image's declared runtime config through the fresh-pull path.
- [x] Open the mount-image cache only when a host snapshot needs it.
- [x] Repin the SDK fixture to a multi-arch index digest.
- [x] Render captured stderr in both SDKs' live errors.
- [x] Verify every fix on real KVM hardware, not only in unit tests.
- [x] State the image-environment defect as a plain-path scenario.
- [ ] Confirm on the first Extended CI run after this lands.
- [ ] Close #3007 once the lane reports clean.

## What is deliberately not fixed here

`pool warm` (#3039) is the third failure and is separately tracked; it is now
gated into the "did NOT run" tally rather than failing.

The wiring in fix 1 is witnessed by the live scenario, not by a hermetic test.
The pull path does network I/O before it reaches the materializer, so there is
no seam that proves the config reaches it without booting. That is honest about
what the guard is: the live lane.

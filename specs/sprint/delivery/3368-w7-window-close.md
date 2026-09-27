# W7 window close — signals, release train and rollback drill

Backing: shipped-source
Validation: cargo run -p xtask -- repin-image-lock

Issue #3368, plan `specs/plans/2026-09-24-image-cutover-and-deletion.md` W7.2
and W7.3. The plan's "W7 window close" section carries the full signal table;
this note records how each piece was obtained.

## The window

It ran from 2026-09-24T19:24:38Z to 2026-09-25T15:07:55Z and closed on its
recorded criteria without an extension. Every merge-group run in it booted the
pinned `mvm-images` set (`Guest image boots` 17 of 17; `Boot latency ceiling`
16 of 16 that were in scope). Download counts came from the releases API at
open and close: new CLIs read `image-set/v*` roots while `boot-image/v0.1.5`
and `v0.18.0-rc.1` kept serving the CLIs that predate the lock. No issue
reports a 404.

The CLI release train was `v0.18.0-rc.2` (run 36134611204). Its mirror step
verified the pinned `image-set/v0.1.1` — 29 artifacts under root
`abc06f5f…d554` — with the `mvmctl` it was about to ship, and gated each of the
mirrored files before signing. Its `verify-release`
job failed on checks outside the mirror — a per-archive checksum file the
release never uploads (the same failure as `v0.18.0-rc.1`), kernel manifests
signed under `kernel-build.yml`'s identity, and the attested builder pack
missing from the mirrored checksum file — and the plan records which of those
W8 removes and where the rest is fixed.

## The rollback drill

The drill moved the lock between two verified image-set releases in both
directions, with no CLI rebuild and no change to the merge queue's protected
state.

## Why not the `legacy` entry

The plan asked for a rollback to the explicit `legacy` lock entry. That is not
possible for a current CLI: `boot-image/v0.1.5` publishes no signed
`image-set.json`, so there is no root digest to pin, and every acquisition path
refuses at the manifest stage before requesting a member. The `legacy` entry is
a trust record for CLIs that predate the lock. The drill therefore used a second
image set, `image-set/v0.1.1`, published for the purpose
(`mvm-images` run 36079826208; root `abc06f5f…d554`, verified with
`cosign verify-blob` against
`release.yml@refs/tags/image-set/v0.1.1`).

## Forward: v0.1.0 → v0.1.1

`update-image-pin.yml` (run 36085954556) ran `xtask repin-image-lock` over the
v0.1.1 root and pushed a branch advancing every route of the lock — root tag and
digest, signing ref, boot tag, Stage 0 tag and both Stage 0 digests. The same
run could not open the pull request: the repository does not permit GitHub
Actions to create pull requests. The branch was opened by hand, unchanged, as
#3677, and merged through the queue. Its merge-group run (36089819238) booted
the new set: `Boot latency ceiling` passed in 5 minutes and
`Guest image boots (mvm-images)` in 31. No CLI release was involved — this is
also the first image-only change carried by a pin alone.

## Rollback: v0.1.1 → v0.1.0

On branch `drill/w7-rollback-to-image-set-v0.1.0`, `xtask repin-image-lock`
over the v0.1.0 root produced a lock byte-identical to the one `main` carried
before #3677. `ci.yml` was dispatched on that branch (run 36093777305); both
`Boot latency ceiling` and `Guest image boots (mvm-images)` passed against the
restored pin. The run's aggregate `Test` job failed on one input,
`Nix flake check (Linux eval)`, which stopped on a Nix store path that was not
valid.
Re-running that one job, with the lock still rolled back,
passed, and the run concluded green on its second attempt. `main` was never moved back, so nothing needed restoring
afterwards. The drill branch is deleted once this record lands.

## What it shows

Rollback in both directions is an `images.lock` edit to a verified existing
release, produced by the same tool the weekly pin proposal uses, and witnessed
by the same boot lanes. The one gap it found is outside the lock: automated pin
proposals need either Actions permission to open pull requests or a token that
has it.

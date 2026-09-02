# Extended CI's red has to mean a regression, not the standing macOS gap

Extended CI has been red since 2026-08-29 and is red on current main. Three
jobs fail, and one of them **cannot pass**: the documented-surface macOS lane
detects in 41 seconds that no GitHub-hosted macOS runner can boot an mvm guest
and fails on purpose, naming issue #3011.

That was a deliberate choice and the reasoning behind it is sound — a tag cut
without live macOS evidence is a tag with no evidence its own README works, and
`release.yml` lists `e2e-docs` in `needs:` precisely so that cannot happen. The
problem is that the same job serves a second caller with a different question.
Extended CI runs nightly. A nightly whose red never varies reports the same
colour for a missing runner as for a real regression, so nobody reads it — which
is exactly how the claim-bearing lanes went stale before, `app-deps-audit`
having been cited by ADR-001 for months while running zero times.

So the fix is not to stop blocking. It is to let one probe mean two things to
two callers.

## What changed

`e2e-docs.yml` gains a `workflow_call` input,
`macos_blocks_on_unusable_host`, defaulting to **true**. The arch preflight
moves out of the macOS job into its own `e2e-docs-macos-host-check` job, which
runs the same live `uname -m` and then either fails (blocking caller) or reports
`supported=false` and lets the lane skip (non-blocking caller). The macOS lane
itself becomes `needs:` that check, gated on `supported == 'true'`.

- `release.yml` passes `true` — stated at the call site rather than inherited,
  so the gate is visible where the decision matters. Release behaviour is
  **unchanged**: a hosted macOS host still fails the workflow and still blocks
  the tag.
- `ci-full.yml` passes `false` — the nightly skips the lane with a warning
  annotation that names #3011, and its red goes back to meaning a commit broke
  something.

The default is the safe one on purpose: a future caller that says nothing gets
blocking, so the opt-out cannot spread by omission.

## Why the probe stays a live `uname`

Resolving #3011 means pointing `runs-on` at a self-hosted Apple Silicon runner.
Keying the skip to the runner *label* would mean the lane kept skipping on
hardware that can run it, and the gap would close with the evidence silently
never coming back. Keying it to the host means the retarget is the whole change
— the lane starts running for both callers with nothing to remember to flip.

## Tests

Three, in `tests/github_actions_extended_e2e.rs`. Nothing previously pinned any
of this, so the release gate could have been turned off by editing one line
with every test still green.

- `releases_still_block_on_a_macos_host_that_cannot_boot_a_guest` — the safety
  property. Verified by mutation: flipping `release.yml` to `false` fails it.
- `the_macos_host_gate_defaults_to_blocking` — a `false` default would make
  every future caller non-blocking by omission.
- `the_macos_lane_runs_whenever_the_host_probe_says_the_host_can_boot` — pins
  the probe to `uname` and the lane to the check's output.

`actionlint` clean on all three workflows.

## Not addressed here

The other two Extended CI failures are real and stay red, which is now the
point:

- **Linux, Firecracker e2e** — `doctor found issues`, an entrypoint boot
  failure, and `control frame read failed` / `session i/o error: Resource
  temporarily unavailable (os error 11)`, the same EAGAIN signature as the
  closed #3052. The recipe was then terminated by signal 15 at 81 minutes.
- **Aarch64 no-KVM bundle smoke (QEMU TCG)** — SIGTERM 5m12s in with its output
  redirected to a file, so nothing was captured. The job's `timeout-minutes` is
  300, so that is not the cause.

Both need diagnosis on real hardware rather than log-reading. They are the work
this change makes visible.

The vCPU clamp failure that was in this lane is **gone** — it was the pre-fix
`u8::MAX` ceiling and the run reporting it predated the fix.

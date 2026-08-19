# Operator-declared campaigns on the client launch path

Plan: `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md` (W9)

## What landed

A campaign declaration is now loadable from a file and threads all the way to
the session open, so a library caller can run one against a real boot.

`deny_unknown_fields` on the declaration means a key this build does not
understand refuses the campaign rather than being dropped — a dropped
destination or a dropped approval is the quiet widening this contract exists to
prevent. Size is checked before parsing, and a declaration naming no
destination is refused at load rather than becoming a session that can probe
nothing.

**The probe sees the launch's own policy.** `build_campaign` derives the
`NetworkPolicy` from the launch's granted egress, not from the declaration —
which carries none. So a probe asks exactly the question the workload's own
traffic would, and an operator cannot widen what a campaign observes by writing
a different policy beside it.

**A remote backend refuses it.** The declaration path names a file on the
host's filesystem. A gateway backend resolving it against its own would run a
different campaign than the caller wrote, so `run_machine` refuses a spec
carrying one instead of dropping or mis-resolving it. Absent, the field is
skip-serialized, so an ordinary spec's bytes do not move.

## What this does not reach

`mvmctl machine run` boots through `AnyBackend` directly from
`commands/machine/lifecycle.rs`; it does not go through `admit_and_boot_local`.
So this thread serves the library/client path and **not** the CLI verb. An
`--assurance-campaign` flag needs that second seam opened first, which is W9b.

That was found by tracing rather than assumed — `LaunchRequest` turns out to
have no CLI caller at all, only client and test ones. Worth recording, because
"thread it to the boot path" reads like one path and is two.

## A testing note

`mvm-core`'s `client` module is behind a feature. `cargo test -p mvm-core --lib`
compiles none of it, so a new test there neither runs nor fails to compile — it
silently is not there. Use `--features client`.

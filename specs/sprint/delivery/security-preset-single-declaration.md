# The security presets, stated once

**Plan:** `specs/plans/329-run-first-cli-and-upstream-adoption.md` Phase 3 —
the last phase, and the one that closes the plan out.

## What was wrong

Phase 3 asked for presets that "do not create new privileged paths". They did
not create any. But the preset vocabulary was written down four times:

1. `validate_run_profile` — restrictive rejects `--env` and `--mount`,
   permissive needs the acknowledgement;
2. `profile_allows_writable_volume(profile: &str)` —
   `matches!(profile, "dev" | "permissive")`;
3. `profile_allows_dev_init(profile: &str)` — the same `matches!`;
4. the prose in the CLI reference.

Four declarations of one policy is four chances to disagree, and the copy a
reader checks is not necessarily the copy that runs. Two of the four were
stringly-typed, and one of those failed in a quiet direction: a machine spec
carrying an unrecognised profile string simply did not match `"dev" |
"permissive"`, so it was treated as not-dev by accident rather than refused.

## What shipped

`RunProfile::grants() -> ProfileGrants` is the single statement of what each
preset permits: `env`, `host_shares`, `writable_shares_when_persistent`,
`dev_guest`, `needs_acknowledgement`. The validator and both gates read it. The
stringly-typed pair are gone, and an unrecognised persisted profile now refuses
and names the value.

`writable_shares_when_persistent` is spelled that way deliberately. A transient
run's live share is read-only under *every* profile; only the persistent
machine-spec path honours `:rw`. Calling the field "writable shares" would have
re-created the same wrong belief that made `RunProfile::Dev`'s old doc comment
("Environment variables and writable host mounts") misleading.

`mvmctl doctor` now reports the default:

```
default run profile: OK (standard — env allowed; read-only host shares
(both `run` and `machine run`; override with --profile))
```

read off `RunArgs::default()` and `grants()` rather than restated. A doctor line
that repeats a policy in prose is one more copy to go stale, and this one would
go stale in the direction of claiming a tighter posture than the tool has. A
permissive default is a *finding*, not a description.

## Tests

The mapping is asserted as a table — that is what "preset-to-policy mapping"
means — plus a companion test that permissions only widen as the presets loosen,
so "stricter" stays a meaningful word in the help and the docs. Both
mutation-checked: widening `standard` and severing the validator from the table
each go red.

The receipt already carried `profile`; it now has a witness, because an artifact
that records what ran but not what it was permitted to do is missing the half an
auditor is reading it for.

## Plan status

Substantially complete, not complete. Four items stay open and are listed in the
plan's new "What is still open" section rather than ticked: the `MvmClient`
facade migration (never this plan's to close), two template items Plan 255
Phase 4 also owns, and the Homebrew tap left as a maintainer decision.

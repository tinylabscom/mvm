# No tag ships while a documented example is unproven

Three independent gaps let `mvmctl machine run --image rust -it -- /bin/bash`
reach users with a guest console that failed on every OCI image. Each of them
individually looked like coverage.

## 1. No live lane blocked a release

`release.yml`'s release job needed `[bdd, build, initramfs-image]`. `bdd` is the
hermetic lane: it drives `--help`, refusal paths, and cross-reads of in-tree
docs, and boots no guest. It cannot see a documented command that parses and
then fails at runtime, which is the entire failure mode.

The lanes that *do* boot guests on both backends already existed and already
passed — `e2e-docs-linux` (Firecracker/KVM) and `e2e-docs-macos` (HVF) — but
lived in `ci-full.yml`, which runs at 04:51 nightly and gates nothing. The
launch-modes lane (`just e2e-launch`) ran in no workflow at all.

Both documented-surface jobs moved into `.github/workflows/e2e-docs.yml` as a
reusable `workflow_call`. Extended CI calls it nightly; `release.yml` now calls
it too and the release job waits on it. Extracting rather than duplicating is
the point: two callers needing the same lane had been getting different ones.

Both backends, because the defect reproduced on HVF — the macOS default — and a
Linux-only gate would have shipped it.

## 2. Coverage was per command path, not per example

`tiers.toml` assigns a verification tier to each *command path*. `machine run`
was tier `live`, and one live `machine run --image alpine -- true` discharged
that obligation for all twelve `machine run` variants the README prints —
including `-it`. The tier was accurate and the coverage was not.

`features/suites/s8_readme_contract/readme_examples.toml` is per invocation. All
38 distinct README `mvmctl` commands carry exactly one of:

- `witness` — a `@live` scenario that boots a guest running this shape
- `hermetic_witness` + `reason` — a scenario that really executes it but boots
  no guest, because there is none to boot (`doctor`, `template list`)
- `exempt` — why it cannot be executed at all

The witness is checked, not trusted. It must resolve to the same verb *and*
carry at least the same flags, with short and long spellings reconciled against
the real clap arguments so `--out` and `-o` compare equal. Values may differ: a
scenario booting `--image alpine` legitimately stands in for a README line
booting `--image python:3.12`, and pinning the value would make the suite a
transcription of the README rather than a test of it.

Verified red-first, both ways that matter:

- a new README example with no entry → *"these README examples have no entry
  in ... so nothing proves they work"*
- the `-it` example pointed at the plain transient-run scenario → *"witness ...
  does not exercise README example ... naming the same verb is what let a broken
  `-it` ship while `machine run` looked covered"*

The second is the original bug expressed as a test failure.

## 3. A witness could prove the opposite of what it claimed

The first draft matched on shape alone, and the shapes it found were alarming:
`-it` matched *"machine run refuses an interactive PTY without a terminal"*, and
`bootstrap` matched *"--help lists the documented top-level verbs"*. Both name
the right verb with the right flags. Neither runs the command, and the first
asserts it does not work.

So `witness` must additionally be `@live`. Anything hermetic is either a
`hermetic_witness` — which has to say why a guest would prove nothing — or an
exemption.

## What the gate found

Nine documented shapes had no live witness. Five new scenarios:

- `--allow-host` and `--mount` on one launch — the README's headline "install a
  dependency at boot" example. The allow-host scenario had no mount and the
  mount scenario had no egress; the mount is set up by the same launch that
  installs the egress policy, so covering them separately covered neither.
- `--cpus`, `--memory` and `--allow-host` together
- `-vvv` on a launch that admits a host — verbosity changes what the launch path
  logs, and nothing had ever booted a guest with it set
- `machine reconfigure`, added to the documented lifecycle scenario. It is
  documented in the same README block as the verbs around it and was the only
  one of them nothing ran.
- `run --mode live --profile dev` — the existing scenario proves the same script
  is *refused without* the flag, which is the opposite claim from the documented
  form working
- `machine run --entrypoint --flake` — the last step of "from dev loop to
  attested image". `build compile` was covered, `machine build` was covered, and
  booting the result was not; the hermetic suite proves `--entrypoint` is refused
  against an OCI image, which says nothing about the flake form.

Recorded exemptions, each naming what does cover it: `bootstrap` (every live
lane runs it as setup, so a break fails the suite at the door), both `kernel
build` arms, the three `deps` commands, and `run --peer`.

One exemption records a limitation rather than a cost: `generate template` *is*
executed, by a scenario that drives it through a bespoke step rather than a
quoted command line. The structural check reads commands out of quoted step
text, so it cannot confirm the shape and is not asked to pretend. Spelling the
invocation in the step would promote it to a `hermetic_witness`.

## Scope

README only. The same machinery extends to `public/src/content/docs` — the
extractor already walks it for the tier gate — but that is 115 tiered paths and
a great many more exemptions to adjudicate, and it is worth doing once this
mechanism has proven itself on the smaller surface.

## Cost

A tag now waits on both live lanes. That is the slowest thing in `release.yml`,
and it is deliberate: a tag that cannot wait for it is a tag published without
evidence that its own README works.

## What the gate found on its first run: a second broken README example

`mvmctl run --mode live --profile dev ./script.py` is in the README and does not
work.

`--profile dev` clears the grant gate — the ProdSafe refusal does not fire — and
the script then dies on `mvmctl machine proc start` exit 1 against the guest it
has just booted. That is the residual named in the *title* of #2887, "fs/proc
verb refusals were reported as protocol mismatches; **dev-mode launches still
cannot grant DevOnly verbs**", which was closed on 2026-08-27 with the reporting
half fixed and this half not.

Nothing had ever run it. The existing live scenario drives the same fixture
*without* `--profile dev` and asserts it is refused, which is the opposite claim.
"The escape hatch is documented" and "the escape hatch functions" had never been
the same statement.

The new scenario is tagged `@wip`, not `@live`, so a pre-existing defect does not
red the release lane the moment that lane starts blocking releases — and because
it is not `@live` it cannot serve as a witness, so the manifest records this line
as unproven rather than covered. Retag it and delete the exemption when the verb
works.

This is one example of the class the gate exists to surface, found within minutes
of the gate existing.

---

# Follow-on: the two gaps this left open

## A skipped scenario no longer passes as a green lane

The suite prints a tally of what it declined to run and a line saying a green
suite is not full coverage while it is nonzero. That is advice, and advice is
not read at the moment it matters: a runner that quietly loses a capability
produces a green run that proved less than the one before it, and nothing says
so. In a lane that gates releases, that is the same failure shape as the tally
not existing.

`MVM_BDD_STRICT_SKIPS` makes the suite exit nonzero on any skip the lane did not
declare, naming the reason and pointing at the two ways to resolve it. The
allow-list is per lane, spelled with the stable `ScenarioGate` names:

The stable-name mapping is exhaustive over backend capabilities, including
`needs-dir-share`, so adding a capability cannot silently evade the release
lane's skip policy.

- **launch lane** — `pending,needs-perf-budget-host`. Verified against a real
  run: those are the only two it skips.
- **documented-surface lane** — additionally `needs-memory-snapshot` (Firecracker
  genuinely reports `unsupported`; the macOS job sets `MVM_BDD_SNAPSHOT` and does
  not skip these), `needs-bundle-fixture` and `needs-tls-tunnel-client`.

Deliberately absent from both: `needs-workload-kernel`, `needs-guest-bin-dir`,
`needs-firecracker`, `needs-live-opt-in`, `needs-sdk-sidecar`, `needs-node`. If
one of those fires, the lane did not boot what it claims to boot, and that has to
be a failure rather than a footnote. Unset, the variable changes nothing, so a
developer running the suite on a laptop still gets the tally and not a failure.

Verified across all three modes: strict with the reason disallowed exits 1,
strict with it allowed exits 0, and the default exits 0.

The Linux documented-surface lane has not run under this policy yet — it cannot
run on this host. If its allow-list is short an entry, its first run fails loudly
naming exactly which one, which is the intended way to find out.

## The website is ratcheted, not adjudicated

The README's 38 examples each carry a hand-written witness or exemption. The
website is **461 distinct commands across 86 files**, and hand-writing 400-odd
justifications would manufacture the appearance of review rather than perform
it. An exemption is a claim someone has to be able to disagree with, and nobody
can disagree with four hundred of them written in an afternoon.

So `features/suites/s29_doc_examples/docs_coverage.toml` is computed, not
authored. Coverage uses the same rule as the README gate — a scenario driving
the same verb with at least the same flags — and the partition is checked in.
Three properties hold from there:

- a command that is covered today may not become uncovered
- a newly documented command must be classified before it merges
- a command that becomes covered must be moved out of the debt list, so the
  number keeps meaning something

**Baseline: 170 covered, 267 uncovered.** That number is the honest state of
website-example coverage today, and it is now visible and monotonic rather than
unknown. Regenerate with `MVM_UPDATE_DOCS_COVERAGE=1`.

Both arms verified red-first: a covered command that loses its scenario fails
with *"were exercised by a scenario and no longer are"*, and a newly documented
command fails with *"newly documented and are not in the coverage ledger"*.

This is deliberately weaker than the README's gate. The README says every
example is proven or someone said why not; the website says coverage cannot
silently decay and new documentation cannot skip the decision. Closing the
267 is ordinary work that can now be done incrementally against a number that
does not drift.

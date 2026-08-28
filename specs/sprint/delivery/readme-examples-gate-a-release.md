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

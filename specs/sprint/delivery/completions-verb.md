# `mvmctl completions` — and two bullets that should not be ticked

**Plan:** `specs/plans/329-run-first-cli-and-upstream-adoption.md` Phase 8.

## The verb

The completion renderer has been in `commands/env/completions.rs` all along.
What it lacked was a name a user could type: it was reachable only through
`shell-init --emit-completions`, a flag deliberately hidden as "an
implementation detail of the eval block" — while the published CLI reference
documented that same hidden flag as the way to get completions.

Documented and unfindable at once is the pattern this surface has spent several
PRs shedding, so the flag became a verb and the eval block now calls the verb.
One name for one thing, and it is the discoverable one.

A test previously pinned `completions` as *removed* ("folded into
`shell-init`"). That decision is reversed, so the test was **replaced** rather
than deleted — it now pins the new contract in both directions: the verb parses,
the hidden flag is gone rather than shadowed, and the eval block calls the verb
and not the removed flag.

## `fish` is refused, not approximated

The renderer emits bash and zsh. Phase 8's bullet said "bash/zsh/fish", but
accepting `fish` and handing back a bash script would be worse than refusing:
the user would source it and get errors that look like a bug in their shell.
Clap refuses and lists what is supported. A fish renderer is real work and is
not in this phase.

## Two bullets that are not ticked

**The install.sh bullet is struck.** It asked to bootstrap a non-Nix host
"enough to run the dev-tier Docker backend" — and the Docker backend was
removed, so there is no such tier. The half that still had force, running `run`
without host Nix, is already true: the OCI path needs no host Nix and
`bootstrap` acquires the builder VM itself.

**The Homebrew tap stays open**, with the evaluation recorded. A tap is
outward-facing infrastructure: a public repository, a formula whose SHA needs
bumping every release, and a support surface for installs mvm did not build.
The release pipeline already ships signed, checksum-verified artifacts that
`install.sh` consumes and that claim 6 covers end to end. A tap adds a second
acquisition path with weaker provenance unless its formula verifies the same
checksums — which nobody has scoped. That is a maintainer's call, not something
to tick.

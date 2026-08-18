# Homebrew tap, without weakening provenance

**Status:** Proposed. Scoped out of the run-first CLI plan, whose Phase 8 asked
only that a tap be *evaluated*. The evaluation said a tap is worth having and
that the interesting part is not the formula.

Backing: shipped-source
Validation: `install.sh`'s existing hash + cosign path, which this must not
weaken — it adds no new security claim, and claim 6 (pre-built artifacts are
hash-verified) has to keep holding across both acquisition paths.

## Why this is not just a formula

`install.sh` already does the honest thing today:

- downloads the per-arch archive from the GitHub release;
- downloads `checksums-sha256.txt` and refuses on mismatch — `MVM_SKIP_HASH_VERIFY=1`
  is the documented emergency escape and is never set in CI;
- verifies the cosign bundle when `cosign` is present, and says so when it is not.

A Homebrew tap adds a **second acquisition path**. The risk is not that a
formula is hard to write — it is that Homebrew's own `sha256` field becomes the
only thing standing between a user and a substituted artifact, while the
release's checksum manifest and cosign bundle go unconsulted. That would leave
two paths with different assurance and one of them quietly weaker, which is
exactly the shape claim 6 exists to prevent.

So the deliverable is not "a tap". It is **a tap whose provenance is the same
provenance**, plus the machinery that keeps it that way across releases.

## Non-goals

- **A formula in homebrew-core.** Core has its own review cadence and would put
  a third party between the release and the user. A tap under the project's own
  org keeps the trust path short.
- **Building from source in the formula.** The release artifacts are what claim
  6 covers; a source build in a formula is a different artifact with different
  provenance and no checksum manifest to check against.
- **Bottles.** Same reason: a bottle is an artifact the release pipeline did not
  produce.

## Workstreams

### WS1 — The formula, verifying the release's own manifest

- [ ] Create the tap repository with a formula that installs the released
      archive for the host arch.
- [ ] The formula's `sha256` must equal the entry in that release's
      `checksums-sha256.txt`. Do not hand-copy it: generate the formula from
      the manifest so the two cannot diverge by typo.
- [ ] Record the release tag the formula points at, so a reader can tell which
      release a given formula revision installs without resolving a URL.

**Acceptance:** `brew install <tap>/mvmctl` produces a binary whose sha256
matches the release manifest entry for that tag.

### WS2 — Keep the tap and the release in step

- [ ] Extend the release workflow to open (or push) the formula update as part
      of publishing a release, sourced from the checksum manifest it just
      generated.
- [ ] A release that publishes artifacts but fails to update the formula must
      be visible — a tap silently pinned to an older release is the failure
      mode that makes "just use brew" wrong advice.

**Acceptance:** cutting a release updates the formula in the same run, or fails
loudly.

### WS3 — A gate that proves they agree

- [ ] Add a check that resolves the formula's `sha256` and version against the
      release manifest for the tag it names, and fails when they disagree.
- [ ] Decide where it runs. A tap in a second repository is outside this repo's
      CI, so this is either a scheduled check here that reads the tap, or a
      check in the tap that reads the release. Prefer the former: this repo
      already owns the release and the manifest.

**Acceptance:** a deliberately wrong `sha256` in the formula fails the gate.

### WS4 — Say which path a user is on

- [ ] Document the tap beside `install.sh`, with the provenance each path
      carries stated plainly rather than implied.
- [ ] `mvmctl doctor` already reports install state; consider reporting the
      acquisition path when it is determinable. Optional, and only if it can be
      determined honestly — a guess here is worse than silence.

## Open questions

- **Who owns the tap repository**, and does its release process get the same
  branch protection as this one? A tap with weaker write controls than the
  release it mirrors moves the weakest link rather than removing it.
- **Does the formula verify cosign?** Homebrew has no hook for it. The honest
  answer may be that the tap carries checksum provenance and `install.sh`
  remains the path that also verifies signatures — in which case say so in the
  docs instead of implying parity.

## Verification

```sh
just fmt-check
just check-gated
cargo nextest run --workspace
just clippy
```

Plus, on a clean macOS host: `brew install`, then compare the installed
binary's sha256 against the release manifest by hand once before trusting the
gate.

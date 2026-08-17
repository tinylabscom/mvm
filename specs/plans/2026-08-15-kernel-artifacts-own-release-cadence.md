# Kernel artifacts on their own release cadence

Backing: preview
Validation: none

**Status: DEFERRED — recorded so the tradeoff is not re-derived from scratch.**

## The question

Should the guest kernel build move out of this repository into its own, so it can
be patched on a CVE cadence independent of `mvmctl` releases?

**The premise this was written on has since moved, and it weakens the case
rather than strengthening it.** When this was recorded, the kernel was already a
separately *built* artifact but not a separately *versioned* one: a CVE fix
could only reach users bolted onto an `mvmctl` release tag. That was the whole
gain a repo split would have bought.

The image release train closed that without a split. Images now publish under
their own `boot-image/v*` tag namespace on their own semver counter, fired by
`.github/workflows/release-boot-image.yml`, while the flakes stay in
`nix/images/`. A kernel CVE fix can be cut as `boot-image/v0.3.0` without
touching the CLI version or waiting on a CLI release.

So the question is no longer "how do we decouple the cadence" — that is done.
What remains is only whether a *separate repository* adds anything on top of a
separate tag namespace, and the honest answer is: very little, against costs
that have not changed.

## The shape it would take

The pattern worth copying, if we do this, is the split — not the extraction:

- **Out:** build, sign, publish. A small repo holding the flake, the signer, and
  two workflows (build-on-PR, build-sign-publish-on-tag). Per-arch `vmlinux` +
  `.sha256` + signature as release assets.
- **In:** boot validation. It stays here, because the boot test needs the VMM,
  and the VMM is here. The consumer repo references the kernel flake and boots a
  guest on a KVM runner against it.

Getting that backwards — trying to boot-test in the kernel repo — is the failure
mode, since it would drag the whole VMM into a repo whose job is to produce one
ELF file.

## Why it is deferred

The gain was CVE cadence alone, and that is now already banked by the tag
namespace. What is left over is bought with real cost that the split does not
reduce:

- Every contributor build gains a cross-repo flake reference, against the
  standing invariant that a source checkout builds every image locally from
  in-repo flakes with no release-pipeline round-trip. A kernel that lives
  elsewhere is either vendored back in (defeating the point) or fetched
  (violating the invariant).
- Two repos to keep in lockstep for any change that touches both the kernel
  config and the code that boots it — which is most kernel changes we actually
  make.
- `check-kernel-config-budget` and `check-kernel-pin-freshness` currently gate
  the kernel in the same run as its consumer. Splitting means either duplicating
  them or letting the pin drift between repos.

And the cadence problem is no longer the argument: a kernel CVE that needs to
ship faster than the next CLI release is now shippable today, from this
repository, by tagging the image line.

## What would change the answer

- [ ] ~~A kernel CVE we need to ship out-of-band.~~ **Retired** — the
      `boot-image/v*` train ships one today without a split.
- [ ] The kernel gaining consumers outside this repository.
- [ ] Kernel build time becoming a large enough share of release wall-clock that
      decoupling pays for itself on that alone.

## Adjacent work that landed instead

The image release train (`boot-image/v*`) took the cadence argument off the
table, as described above. Separately, signing the checksum manifests closed the
more urgent half of the same supply-chain question: the artifacts were hash-pinned but the hash manifest
itself was unsigned, so whoever could swap an artifact could swap its checksum
file. That gap did not need a repo split to fix, and fixing it does not depend on
one.

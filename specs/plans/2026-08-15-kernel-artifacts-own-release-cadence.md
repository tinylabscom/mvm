# Kernel artifacts on their own release cadence

Backing: preview
Validation: none

**Status: DEFERRED — recorded so the tradeoff is not re-derived from scratch.**

## The question

Should the guest kernel build move out of this repository into its own, so it can
be patched on a CVE cadence independent of `mvmctl` releases?

Today `nix/images/kernel/flake.nix` is already a standalone publishable flake —
it emits per-arch `vmlinux`, `configfile`, `metrics`, `resolved-configs`, and an
`artifact-manifest` carrying `kernel_version` / `config_hash` / `artifact_hash` —
and `.github/workflows/kernel-build.yml` publishes it on `v*` tags. So the kernel
is *already* a separately-built artifact. What it is not is separately
*versioned*: a kernel CVE fix can only reach users attached to an `mvmctl`
release tag.

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

The gain is CVE cadence alone, and it is bought with real cost:

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

The cadence problem is also not yet biting: we have not had a kernel CVE that
needed to ship faster than the next release.

## What would change the answer

- [ ] A kernel CVE we need to ship out-of-band, i.e. the cadence cost becomes
      concrete rather than hypothetical.
- [ ] The kernel gaining consumers outside this repository.
- [ ] Kernel build time becoming a large enough share of release wall-clock that
      decoupling pays for itself on that alone.

## Adjacent work that landed instead

Signing the checksum manifests (this branch) closes the more urgent half of the
same supply-chain question: the artifacts were hash-pinned but the hash manifest
itself was unsigned, so whoever could swap an artifact could swap its checksum
file. That gap did not need a repo split to fix, and fixing it does not depend on
one.

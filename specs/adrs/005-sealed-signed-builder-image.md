# ADR 005: Sealed, Signed Builder Image

## Status

Proposed — 2026-04-30

## Context

Sprint 42's commit `688b7de` made the dev/builder VM the *only* build
environment for everything `mvmctl build` produces. The host no longer
runs `nix` or any Linux build tooling. The commit message is explicit:
*"any code path that runs on the host is outside the sandbox, and any
'we'll just bypass the VM here' shortcut chips away at the contract one
PR at a time."*

That promotion makes the dev/builder image **load-bearing** for the
security model: if a tampered image is silently swapped or modified,
every artifact mvmctl builds — including the production-bound
rootfs/kernel images that user flakes ship via `mvm-build`, and the
pool images mvmd will rebuild via plan 23 — inherits whatever the
tampered image injects.

Sprint 42's W5.1 closed part of this gap by SHA-256-verifying downloads
against a per-arch checksum manifest (`apple_container.rs:918-1048`),
with `MVM_SKIP_HASH_VERIFY=1` as the documented escape. The W5.1 code
itself flags the remaining gap at line 952: *"who can swap the artifact
can also swap the checksum file, so the checksum manifest is TLS-only
trust today, on the checksum file itself in a future iteration."*

This ADR records the architectural decisions for that future iteration.

## Decisions

### 1. The image is a signed release artifact

The dev/builder image (`nix/images/builder/flake.nix` outputs) becomes
a **signed release artifact** alongside the `mvmctl` CLI binary.
Cosign keyless signs a per-release manifest that records SHA-256 of
each artifact, the Nix store hash, the source git SHA, and the SHA-256
of every flake lockfile. Mvmctl verifies the signature on download and
on every cache reuse.

The manifest — not the artifacts individually — is the trust anchor.
One cosign verification step covers everything inside.

### 2. Two outputs from one flake — sibling `default` and `builder`

The single `nix/images/builder/flake.nix#default` output splits into:

- **`default`** — current behavior. Dev guest agent (Exec vsock handler
  compiled in for `mvmctl exec`/`console`). Writable `/dev/vdb`
  overlay. `verifiedBoot = false`. Used by `mvmctl dev up`. **No
  behavior change.**
- **`builder`** — new sibling output. Same package list. Prod guest
  agent (no Exec handler). No writable overlay (squashfs root +
  tmpfs overlay for `/tmp`, `/var/log`, `/nix/var`). `verifiedBoot
  = true`. Used by mvmd's pool-build pipeline (mvmd plan 23).

Plumbed through `mkGuest` as a `variant ∈ {"dev", "builder"}`
parameter, visible as `passthru.variant`. Reuses the prod/dev guest
agent split from commit `4e6c5fa` and the existing sibling flake at
`nix/dev/flake.nix`.

### 3. Cosign keyless via GitHub OIDC, identity-bound to release tags

The expected signing identity is
`https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/v*`.
The release pipeline is the only entity that can produce verifiable
artifacts; an unsigned-or-untagged build cannot accidentally claim
project authority.

Reuses the existing cosign keyless flow already used for the `mvmctl`
binary (Sprint 21 binary signing) and the SBOM (W5.4). One signing
infrastructure, three artifact families.

### 4. Verify on every startup, fail closed

Mvmctl runs the full verification pipeline on every `dev up`, including
cache hits (re-hash cached files against the cached manifest, no
network). Verification failure is a hard fail with no auto-retry,
pointing at the troubleshooting docs. Tampering must be loud.

`MVM_SKIP_HASH_VERIFY=1` keeps its W5.1 escape semantics — but only for
the SHA-256 check. A separate `MVM_SKIP_COSIGN_VERIFY=1` exists for
emergency cosign rotation. Both print non-suppressible warnings.

### 5. Reusable verification primitive in `mvm-security::image_verify`

The verification logic lives in `mvm-security::image_verify` as a
reusable primitive with a typed `VerifyError` enum (not `anyhow`).
mvmctl consumes it for the dev variant on `dev up`. mvmd (cross-repo,
plan 23) consumes the same functions for the builder variant on pool
rebuild and for pool images of its own. Same primitive, different
artifacts.

The typed-error contract lets mvmd's reconciliation loop pattern-match
outcomes — Revoked, Expired, DigestMismatch, etc. — and decide whether
to skip the bad image, alert, hold rollout, instead of crash-looping on
`anyhow::Error`.

### 6. Lifecycle: revocation list + manifest `not_after`

A signed image can be recalled. The release pipeline maintains a
cosign-signed `revoked-versions.json` published as the `revocations`
release tag's only asset. Mvmctl checks it at most once per 24h
(cached, fresh-window 7d). Manifests carry `not_after` (default 90d
post-release): mvmctl warns and proceeds; mvmd refuses (different risk
tolerances).

### 7. Air-gapped operators stay on the trusted path

A new `mvmctl dev import-image` (and `mvmd image import`) subcommand
runs the *same* verification logic against local files. Without this,
regulated/gov/air-gapped operators are pushed onto
`MVM_SKIP_HASH_VERIFY=1` — the unsafe escape becomes their default,
which is exactly the failure mode this ADR exists to prevent.

## Alternatives considered

- **Single image used for both mvmctl `dev up` and mvmd pool builds.**
  Reject: the dev variant bundles the dev guest agent's vsock Exec
  handler (RCE-by-design — that's how `mvmctl exec` and `console`
  work). Acceptable in mvmctl's local sandbox, unacceptable inside
  an mvmd coordinator's production builder VM. Two outputs from one
  flake gives single source of truth without shipping the Exec
  handler to production.
- **Distinct flakes for dev and builder.** Reject: lets the build
  sandbox tooling drift silently between dev and production —
  the "works on my machine" trap. One flake, two outputs.
- **Sign artifacts individually instead of a per-release manifest.**
  Reject: requires N verification steps per boot; no place to record
  cross-artifact metadata (Nix store hash, lockfile hashes, advisory
  list); manifest schema versioning is harder.
- **Project-internal Ed25519 signing root instead of cosign keyless.**
  Reject: requires key management + rotation infrastructure the
  project doesn't otherwise need. Cosign keyless reuses Sigstore's
  transparency log + GitHub OIDC, which the project is already
  publishing under for the CLI binary.
- **TLS-only trust on the checksum file (status quo post-W5).**
  Reject: the W5.1 code itself flags this as the gap to close. An
  attacker who can swap the artifact can swap the checksum.
- **Seal the dev image (current `default` output) instead of adding a
  builder sibling.** Reject: would break `mvmctl dev` for everyone.
  Users running `nix build` inside the dev VM expect outputs to
  persist in `/nix/store` across the session. The split preserves
  ergonomics for dev users while enabling production sealing.
- **Sign the user's microVM image (what `mvmctl build --flake ./myapp`
  produces).** Out of scope. Users have their own release identities
  and may not want their builds attached to mvm's. The signed builder
  produces *their* artifacts; what they do with them is theirs.

## Consequences

**Positive:**
- Trust chain bottoms out at a cryptographic identity bound to the
  source tree, not at "GitHub's TLS cert + release infrastructure."
- Production builders (mvmd plan 23) never carry the dev RCE primitive.
- One verification primitive serves both mvmctl users and mvmd's
  fleet pipeline. Single audit surface.
- Air-gapped operators have a sanctioned trusted path. The unsafe
  escape (`MVM_SKIP_HASH_VERIFY=1`) is no longer the *only* offline
  option.
- Builder image inherits sprint 42's W3 dm-verity protection. Tampering
  the on-disk rootfs panics the kernel before userspace.
- Verifiable answer to "which dev/builder image built this artifact?"
  via manifest digest recording (mvmd plan 23 records this in pool
  manifests).

**Negative:**
- mvmd takes a hard dependency on `mvm-security::image_verify` (git-dep
  until crates.io publish). Cross-repo coordination required.
- Hotfixes require cutting new tags. No re-signing existing tags in
  place. Same constraint that already applies to mvmctl binaries.
- `sigstore` Rust crate is heavy (TUF + transparency log + x509).
  Binary size impact may force a default-on Cargo feature gate.
- Reversal cost is medium: once a tag ships with the cosign-signed
  manifest, downgrading would require either impossible post-hoc
  re-signing or a period of unverified downloads.

**Neutral:**
- Manifest schema versioning needed from day one so older mvmctl/mvmd
  binaries fail closed on unknown versions.
- The dev variant continues to be verity-exempt per ADR-002 §W3.4.
  Only the builder variant gets verity protection.

## References

- Sprint 42 commit `688b7de` — "make dev VM the only build environment;
  delete HostBuildEnv"
- `specs/adrs/002-microvm-security-posture.md` — the seven-claim
  threat model that drove sprint 42
- `specs/plans/29-w5-supply-chain.md` — W5.1 SHA-256 verification this
  plan extends
- `specs/plans/36-sealed-signed-builder-image.md` — implementation plan
  derived from this ADR
- mvmd plan 23 + mvmd ADR 0001 (cross-repo) — rolling microVM rebuild
  pipeline that consumes the verification primitive

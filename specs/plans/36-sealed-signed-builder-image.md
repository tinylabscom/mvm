# Plan 36 — Sealed, signed builder image

> Status: ready to implement
> Owner: Ari
> Parent: extends [`plans/29-w5-supply-chain.md`](29-w5-supply-chain.md) (W5.1 SHA-256 → cosign signature on the manifest)
> ADR: [`adrs/005-sealed-signed-builder-image.md`](../adrs/005-sealed-signed-builder-image.md)
> mvmd counterpart: cross-repo plan 23 (rolling microVM rebuild) + ADR 0001 in mvmd
> Estimated effort: ~1 sprint (4 PRs, each independently mergeable)

## Why

Sprint 42's W5 (supply chain) shipped per-arch SHA-256 checksum manifests
for the dev-image and default-microvm downloads, with verification on
fetch in `crates/mvm-cli/src/commands/env/apple_container.rs:918-1048`
and `MVM_SKIP_HASH_VERIFY=1` as the documented escape. The code itself
flags the remaining gap at line 952:

> *"who can swap the artifact can also swap the checksum file, so the
> checksum manifest is **TLS-only trust today, on the checksum file
> itself in a future iteration**"*

That future iteration is this plan. The checksum file is fetched over
HTTPS but is not itself signed, so the trust chain bottoms out at
"GitHub's TLS cert + GitHub's release infrastructure," not at a
cryptographic identity bound to the source tree. A compromised release
asset (account takeover, CDN compromise, in-flight TLS interception with
a stolen CA) lets an attacker swap *both* the artifact and the checksum
in lockstep, and `mvmctl` accepts it as legitimate.

The downstream stakes: sprint 42's commit `688b7de` made the
dev/builder VM the *only* build environment — every artifact `mvmctl
build` produces, and (via the parallel mvmd plan 23) every pool image
mvmd rebuilds, inherits whatever that VM was when it ran. Tampering
the builder image taints everything built inside it. Closing the
"who-signed-the-checksum-file?" gap is the last mile of the W5 chain.

## What sprint 42 already shipped (do not redo)

| W5 / W6 item                                  | Code path                                                | Closes plan-36 layer    |
| --------------------------------------------- | -------------------------------------------------------- | ----------------------- |
| **W5.1** SHA-256 download verify              | `apple_container.rs:918-1048`, 5 regression tests        | Layer 3 (artifact integrity) ✅ |
| **W5.2** `cargo deny`                         | `deny.toml`, `ci.yml::deny` job                          | partial Layer 0 ✅      |
| **W5.3** mvmctl reproducibility               | `ci.yml::reproducibility` job                            | partial Layer 0 ✅      |
| **W5.4** SBOM + cosign                        | `release.yml:205-247`                                    | precedent for Layer 4 ✅ |
| **W6.2** Security model in CLAUDE.md          | `CLAUDE.md`                                              | doc surface ✅          |
| **W6.4** `mvmctl security status` probes      | `commands/security/status.rs`                            | extension point ✅      |
| **W3** dm-verity for prod microVMs            | `nix/flake.nix::verityArtifacts`                         | informs Layer 2 design  |

The dev/builder image is explicitly verity-exempted per ADR-002 §W3.4
and `nix/images/builder/flake.nix` (`verifiedBoot = false`): its
overlayfs upper layer mutates `/nix` at runtime, which can't compose
with dm-verity. Plan 36 splits the flake (Layer 1) so the new **builder
variant** can be sealed while the **dev variant** keeps overlay-mutable
behavior unchanged.

## Threat model

| Threat                                              | Today (post W5)                          | After plan 36       |
| --------------------------------------------------- | ---------------------------------------- | ------------------- |
| GitHub release asset replaced (CDN/acct compr.)     | checksum verify catches body-only swap   | catches checksum-and-body swap (sig fails) |
| TLS MITM on download                                | undetected if attacker swaps both        | sig verify fails    |
| Local cache tampering (`~/.cache/mvm/dev/*`)        | undetected after first download          | re-hash on every `dev up` against cached signed manifest |
| Drift between releases (non-reproducible build)     | mvmctl binary covered (W5.3); image NOT  | image reproducibility CI gate added |
| Lima Ubuntu base swapped out (Lima fallback path)   | undetected; out of mvmctl's control      | not in scope (Lima is deprecated path) |
| Compromise of release-time signing identity         | n/a (no signing today)                   | rotate via tag; revocation list |
| Known-bad signed image keeps running after recall   | n/a                                      | revocation list + manifest `not_after` |
| Production builder ships RCE-by-design Exec handler | no production builder yet (mvmd plan 23 pending) | builder variant strips Exec handler |
| Air-gapped operator forced off trusted path         | `MVM_SKIP_HASH_VERIFY=1` documented but loud | `mvmctl dev import-image` runs same verification on local files |

**Out of scope (named explicitly):**
- TPM / measured boot of the running builder VM. Neither Apple Container
  nor Lima exposes a vTPM today.
- Hardening Lima's own Ubuntu fetch. Lima is the legacy fallback for
  pre-macOS-26 / no-KVM hosts; documented as lower-trust.
- Signing the user's microVM image (what `mvmctl build --flake ./myapp`
  produces). User's responsibility.
- Default-microvm signing parity. Trivial extension once plan 36 lands;
  separate follow-up issue.

## Terminology: dev image vs builder image

The codebase converged on "builder image" — `nix/images/builder/` is
where the flake lives, `passthru.role = "builder"` is plumbed via
`mkGuest` (W7.3, W7.4). Plan 36 splits that single output into two
sibling outputs:

| Image                                 | Source                                  | Guest agent                  | Used by                  | Signed asset prefix            |
| ------------------------------------- | --------------------------------------- | ---------------------------- | ------------------------ | ------------------------------ |
| **Dev image** (`mvm-dev`)             | `nix/images/builder/flake.nix#default`  | Dev (Exec handler compiled in for `mvmctl exec`/`console`) | mvmctl on `dev up` | `dev-vmlinux-{arch}` / `dev-rootfs-{arch}.ext4` |
| **Builder image** (`mvm-builder-prod`)| `nix/images/builder/flake.nix#builder`  | Prod (no Exec handler)       | mvmd coordinator on pool build (mvmd plan 23) | `builder-vmlinux-{arch}` / `builder-rootfs-{arch}.squashfs` |

**Why two outputs from one flake**: identical build sandbox tooling, two
different agent variants. Reuses the prod/dev guest agent split from
commit `4e6c5fa` and the existing sibling flake at `nix/dev/flake.nix`.
The dev variant keeps `verifiedBoot = false` and the writable overlay
(no behavior change for `mvmctl dev up`); the builder variant drops the
overlay (production builds run in ephemeral builder VMs), goes
squashfs-RO root, and gets `verifiedBoot = true`.

**Why not separate flakes**: lets the build sandbox tooling drift
silently between dev and production — the "works on my machine" trap.
One flake, two outputs.

## Approach: minimize, seal builder, sign, verify

### Layer 0 — Provenance: pin every lockfile + image reproducibility

The dev/builder images depend on three flake lockfiles:

- `nix/flake.nix::flake.lock` — parent flake (production guest agent library).
- `nix/dev/flake.nix::flake.lock` — sibling flake (dev guest agent variant).
- `nix/images/builder/flake.lock` — image flake.

The release manifest carries the SHA-256 of each lockfile content (not
just paths) so the input closure is recoverable from the signed manifest
alone:

```json
"flake_locks": {
  "nix/flake.nix":                "sha256:...",
  "nix/dev/flake.lock":           "sha256:...",
  "nix/images/builder/flake.lock": "sha256:..."
}
```

CI gates:
- **Release-PR check**: `nix flake metadata --json` against each flake;
  assert lockfile committed, in sync, no `dirty` flag.
- **Tag-only reproducibility check** (extends W5.3 from mvmctl-binary to
  the dev/builder images): build each variant twice on different runners,
  assert identical Nix store hashes.

### Layer 1 — Minimize and split: builder variant has no Exec handler

Audit `nix/images/builder/flake.nix` package list and split the single
`default` output into:

- `default` — current behavior. Dev agent (Exec handler compiled in).
  Writable `/dev/vdb` overlay. `verifiedBoot = false`. Used by
  `mvmctl dev up`. **No behavior change.**
- `builder` — new sibling output. Same package list. Prod agent (no Exec
  handler). No writable overlay (squashfs root + tmpfs overlay for
  `/tmp`, `/var/log`, `/nix/var`; `/nix/store` read-only from squashfs).
  `verifiedBoot = true`. Used by mvmd's pool-build pipeline.

Plumbed through `mkGuest` as a `variant ∈ {"dev", "builder"}`
parameter, visible in `passthru.variant`. Reuses the existing prod/dev
guest agent split (`dev-shell` Cargo feature toggle, parent/sibling
flake override from commit `4e6c5fa`).

Audit each package entry's caller in a comment so future additions
require justification:

- **Definitely keep**: `nix`, `coreutils`, `bashInteractive`, `gnused`,
  `gnugrep`, `gawk`, `findutils`, `which`, `e2fsprogs`, `util-linux`.
- **Justify or drop in builder variant**: `gnumake`, `git`, `curl`,
  `iproute2`, `iptables`, `jq`, `less`, `procps`. `iptables`+`jq` are
  required by `mvm-runtime/src/vm/network.rs::bridge_ensure` only when
  the dev VM hosts transient microVMs (`mvmctl exec`); confirm whether
  the builder variant needs them or moves the bridge logic host-side.

### Layer 2 — Seal the builder variant

The builder variant becomes:

- Squashfs root, mounted read-only.
- Tmpfs overlays for `/tmp`, `/var/log`, `/nix/var`.
- `/nix/store` read-only from squashfs (already content-addressed; the
  RO mount makes immutability physical).
- `verifiedBoot = true` — dm-verity sidecar emitted by `mkGuest` as it
  does for production tenant images (W3.1).

The dev variant keeps the overlay model — users running `mvmctl dev`
expect `nix build` outputs to persist in `/nix/store` across the
session. Splitting the flake is what lets us keep that ergonomic without
dragging it into production.

### Layer 3 — Sign: cosign the manifest, not just the artifacts

W5.1 verifies SHA-256 against an unsigned checksum file. Plan 36
elevates the **manifest** to the trust anchor. Per `{arch} × {variant}`:

```
{variant}-vmlinux-{arch}                     ← already published (dev)
{variant}-rootfs-{arch}.{ext4,squashfs}      ← already published (dev), squashfs new for builder
{variant}-image-{arch}.manifest.json         ← NEW (replaces unsigned checksum file)
{variant}-image-{arch}.manifest.json.sig     ← NEW (cosign keyless sig)
{variant}-image-{arch}.manifest.json.pem     ← NEW (cosign keyless cert)
```

Manifest schema (v1):

```json
{
  "schema_version": 1,
  "version": "0.14.0",
  "arch": "aarch64",
  "variant": "dev" | "builder",
  "rootfs_format": "ext4" | "squashfs",
  "artifacts": [
    { "name": "dev-vmlinux-aarch64",        "sha256": "..." },
    { "name": "dev-rootfs-aarch64.ext4",    "sha256": "..." }
  ],
  "nix_store_hash": "abc123...",
  "source_git_sha": "...",
  "flake_locks": {
    "nix/flake.nix":                "sha256:...",
    "nix/dev/flake.lock":           "sha256:...",
    "nix/images/builder/flake.lock": "sha256:..."
  },
  "addressed_advisories": ["CVE-2026-1234", ...],
  "built_at": "2026-04-30T18:00:00Z",
  "not_after":  "2026-07-29T18:00:00Z"
}
```

`schema_version` from day one so older mvmctl/mvmd binaries fail closed
on unknown versions. `addressed_advisories` lets mvmd (plan 23) decide
"this image addresses the CVE we're patching against" — empty array on
v0.14.0, populated as mvmd's advisory ingest pipeline lands.
`built_by_image` lives on **pool image manifests** (mvmd-side), not the
builder image's own manifest, so it's not in this schema.

Sign the manifest, not each binary individually — one cosign keyless
verification step covers everything inside.

### Layer 4 — Verify on every builder-VM startup

Replace the unsigned-checksum path in `apple_container.rs:918-1048`
with a verification pipeline. The W5.1 SHA-256 code stays as the inner
check; plan 36 wraps it in cosign verification of the manifest.

1. Always download the manifest first.
2. Verify `manifest.json.sig` against `manifest.json.pem` and the
   expected OIDC identity
   (`https://github.com/auser/mvm/.github/workflows/release.yml@refs/tags/v*`)
   using the `sigstore` Rust crate's offline-bundle path.
3. Pin the version: `manifest.version == env!("CARGO_PKG_VERSION")`
   exactly. No "newer is fine."
4. **Revocation check** (best-effort, online-only): fetch
   `https://github.com/auser/mvm/releases/download/revocations/revoked-versions.json`
   at most once per 24h (cache + cosign-verify). If `manifest.version`
   is in the list, hard fail with the recall reason. Network failure is
   non-fatal only if the cached revocation file is fresh (<7d).
5. **Max-age check**: if `now > manifest.not_after`, mvmctl warns and
   proceeds; mvmd refuses (different risk tolerance).
6. Download artifacts, streaming SHA-256.
7. Reuse W5.1's `verify_hash` to compare against the manifest digests
   (don't reinvent the deletion-on-mismatch path).
8. Cache the verified manifest at `~/.cache/mvm/dev/v{version}/manifest.json`
   (version-namespaced — fixes cross-version cache-poisoning that
   today's `~/.cache/mvm/dev/` shares).
9. **Cache integrity check on subsequent boots**: re-hash cached files
   against the cached manifest. Network-free, sub-second.
10. **Telemetry** via `mvm-core::observability::metrics`:
    - `dev_image_verify_total{outcome ∈ {ok, sig_invalid, digest_mismatch, version_skew, revoked, expired, network}}`
    - `dev_image_verify_duration_ms` histogram
11. **`MVM_SKIP_HASH_VERIFY=1`** keeps its W5.1 semantics — but plan 36
    *narrows* it to skip only the SHA-256 check, **not** the cosign
    signature check. Add a separate `MVM_SKIP_COSIGN_VERIFY=1` for the
    rare emergency rotation. Both print loud warnings.

Failure mode: hard fail with no auto-retry, error pointing at
troubleshooting docs. Tampering must be loud.

### Layer 5 — Reusable primitive for mvmd consumption

New crate module `mvm-security::image_verify`:

```rust
pub struct SignedManifest {
  pub schema_version: u32,
  pub version: String,
  pub arch: String,
  pub variant: String,
  pub artifacts: Vec<ArtifactDigest>,
  pub flake_locks: BTreeMap<String, String>,
  pub addressed_advisories: Vec<String>,
  pub built_at: DateTime<Utc>,
  pub not_after: DateTime<Utc>,
  // ... other fields
}

pub enum VerifyError {
  SignatureInvalid { reason: String },
  DigestMismatch { name: String, expected: String, actual: String },
  VersionSkew { manifest: String, runtime: String },
  Revoked { reason: String, since: DateTime<Utc> },
  Expired { not_after: DateTime<Utc> },
  CertExpired,
  WrongIssuer { found: String, expected: String },
  Io(io::Error),
  // ...
}

pub fn verify_manifest(
  manifest_bytes: &[u8],
  signature: &[u8],
  certificate_pem: &[u8],
  expected_identity: &str,
  cosign_bundle: Option<&CosignBundle>,
) -> Result<SignedManifest, VerifyError>;

pub fn verify_artifact(path: &Path, expected: &ArtifactDigest)
  -> Result<(), VerifyError>;
```

mvmctl consumes this for the dev variant on `dev up`. mvmd (plan 23)
consumes the same functions for the builder variant on pool rebuild and
for pool images of its own. Same primitive, different artifacts. Typed
`VerifyError` lets mvmd's reconciliation loop pattern-match outcomes
instead of crash-looping on `anyhow::Error`.

`mvm-security` is workspace-internal today; publishing to crates.io is
tracked separately (bundle with the apple-container crate publishing
backlog item). Until publish, mvmd consumes via git-dep.

## Rebuild and distribution

**Trigger**: tag-driven, via the existing release workflow (which
already builds mvmctl, default-microvm artifacts, and SBOM per W5.4).
There is no rebuild-without-release path — cosign keyless's signing
identity is bound to `refs/tags/v*`.

```
just release  (or `git tag v0.14.0 && git push --tags`)
  │
  ▼
.github/workflows/release.yml — existing job set
  │
  ├─ matrix: { arch ∈ {aarch64, x86_64} } × { variant ∈ {dev, builder} }
  │
  ▼
new job: build-image (parameterized by variant)
  1. checkout @ tag
  2. nix build nix/images/builder#packages.${arch}-linux.${variant}
  3. extract vmlinux + rootfs.{ext4|squashfs} from store output
  4. compute sha256 of each + Nix store hash + flake.lock SHA-256s
  5. emit ${variant}-image-${arch}.manifest.json
  6. cosign sign-blob --yes (keyless, OIDC from GH Actions)
  7. gh release upload v${version} \
       ${variant}-vmlinux-${arch} \
       ${variant}-rootfs-${arch}.{ext4|squashfs} \
       ${variant}-image-${arch}.manifest.json{,.sig,.pem}
```

**Distribution**: GitHub Releases, same release as `mvmctl`. URLs are
deterministic from the mvmctl version — `apple_container.rs:918-921`
already constructs URLs this way.

**Republish / hotfix**: cut a new tag (`v0.14.1`). Never re-sign an
existing tag's artifacts in place.

**Air-gapped**: new `mvmctl dev import-image` (and `mvmd image import`)
subcommand runs the same verification logic against local files.

## Critical files to modify

### In-repo (mvm)

| File                                                                        | Change                                                                   |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `specs/SPRINT.md`                                                           | When sprint 44 closes, add Sprint 45 entry pointing at this plan         |
| `public/src/content/docs/guides/airgapped-bootstrap.md`                     | NEW — operator guide for `mvmctl dev import-image` workflow              |
| `public/src/content/docs/guides/troubleshooting.md`                         | New section: "Builder image signature verification failed"              |
| `public/src/content/docs/guides/verify-release.md`                          | Document image manifest verification alongside existing CLI binary verify steps |
| `nix/images/builder/flake.nix`                                              | Add `builder` sibling output: prod agent (no Exec handler), squashfs RO root with tmpfs overlay, `verifiedBoot = true`. Keep existing `default` output behavior unchanged. Audit and comment package list. |
| `nix/lib/minimal-init/default.nix`                                          | Confirm tmpfs overlays for `/tmp`, `/var/log`, `/nix/var` work on RO root for the builder variant. |
| `nix/flake.nix::mkGuestFn`                                                  | Add `variant ∈ {"dev", "builder"}` parameter, plumbed via `passthru.variant` |
| `crates/mvm-cli/src/commands/env/apple_container.rs:918-1048`               | Wrap existing W5.1 hash-verify with cosign manifest verification; rename internal `fetch_expected_hashes` → `fetch_signed_manifest`; namespace cache by version (`~/.cache/mvm/dev/v{version}/`). |
| `crates/mvm-cli/src/commands/env/dev.rs`                                    | New `mvmctl dev import-image` subcommand                                 |
| `crates/mvm-security/src/image_verify.rs`                                   | NEW module — `SignedManifest`, `VerifyError`, `verify_manifest`, `verify_artifact`. Reusable from mvmd. |
| `crates/mvm-security/Cargo.toml`                                            | Add `sigstore`, `sha2`, `serde_json`, `chrono` deps (gate behind feature if binary size matters) |
| `crates/mvm-core/src/observability/metrics.rs`                              | Add `dev_image_verify_total{outcome=…}` counter + `dev_image_verify_duration_ms` histogram |
| `crates/mvm-cli/src/commands/security/status.rs`                            | Extend probes to surface "image manifest cosign-verified?" alongside W6.4's existing checks |
| `.github/workflows/release.yml`                                             | New job `build-image` (matrix `arch × variant`): builds via Nix, generates + cosign-signs the manifest, uploads release assets. Adjacent to existing W5.4 SBOM job. |
| `.github/workflows/security.yml`                                            | New job `image-reproducibility`: builds each variant twice on different runners, asserts identical store hashes (extends W5.3 from mvmctl-binary to images, tag-only). |
| `.github/workflows/ci.yml`                                                  | New release-PR gate: `nix flake metadata --json` per flake, assert lockfiles committed + in sync + non-dirty |
| `revocations` release tag                                                   | NEW — stable release tag whose only assets are `revoked-versions.json` + `.sig` + `.pem`. Append-only updates each release; cosign-signed against the same release identity. |

### Cross-repo (mvmd)

- mvmd plan 23 — rolling microVM rebuild pipeline (consumes `mvm-security::image_verify`).
- mvmd ADR 0001 — rolling microVM rebuild as a first-class capability.
- These live in mvmd repo; references-only here.

## Phasing (4 PRs, each independently mergeable)

- **PR-A — Layer 5 + Layer 3 schema**: `mvm-security::image_verify`
  module + `SignedManifest` schema + tests. No callsite changes. The
  primitive ships first so mvmd plan 23's Phase 1 can pick it up early.
- **PR-B — Layer 0 + Layer 1**: split `nix/images/builder/flake.nix`
  into `default` + `builder` outputs; mkGuest `variant` parameter;
  reproducibility + lockfile-cleanliness CI gates. Keeps existing
  `default` behavior untouched; introduces the sealed `builder` output.
- **PR-C — Layer 3 release pipeline + Layer 4 verification**:
  `release.yml::build-image` job; mvmctl wraps W5.1 with cosign verify;
  version-namespaced cache; revocation list infrastructure.
- **PR-D — Telemetry, air-gapped path, ADR + docs**: metrics, `mvmctl
  dev import-image`, troubleshooting + airgapped-bootstrap docs.

## Verification

End-to-end test matrix — must all pass before sprint closes:

1. **Happy path, fresh download**: `rm -rf ~/.cache/mvm/dev && mvmctl dev up` → manifest + artifacts downloaded, cosign-verified, SHA-256 matches, VM boots.
2. **Cache hit, untampered**: second `mvmctl dev up` → reads cached manifest, recomputes SHAs, matches, sub-second.
3. **Tampered cached rootfs**: `dd ... seek=1000 conv=notrunc` then `mvmctl dev up` → hard fail on SHA-256 mismatch.
4. **Tampered cached manifest**: edit `~/.cache/mvm/dev/v{ver}/manifest.json` → cosign verification fails on next `dev up`.
5. **MITM simulated**: local server returns wrong rootfs but right manifest → SHA-256 mismatch hard fail.
6. **Version skew**: drop in manifest from a different `mvmctl` version → fail with "manifest version v0.14.1 does not match mvmctl v0.14.0".
7. **Offline (cache present, no network)**: succeeds via re-hashing cached files; revocation cache fresh.
8. **Offline (no cache, no network)**: hard fail with specific error pointing at offline-bootstrap docs.
9. **`MVM_SKIP_HASH_VERIFY=1`**: skips SHA-256 (existing W5.1 semantics) but **does NOT** skip cosign sig — separation-of-concerns regression test.
10. **`mvmctl dev import-image`**: imports valid local files → success; tampered local rootfs → hard fail.
11. **Builder variant boot test**: build the new `builder` output, attempt `touch /etc/breakme` inside it → fails with EROFS; `mount | grep ' / '` shows `squashfs` and `ro`. Verity cmdline arg present.
12. **Reproducibility CI gate**: build both variants twice on the same arch on different runners; assert byte-identical Nix store hashes.
13. **Lockfile-cleanliness CI gate**: PR with stale `flake.lock` → CI red.
14. **Tests**: `cargo test --workspace` clean. New tests in `mvm-security::image_verify` cover happy path, every `VerifyError` variant (mocked cert/issuer/expiry), revocation hit/miss, max-age boundary.
15. **Clippy clean**: `cargo clippy --workspace --all-targets -- -D warnings`.
16. **Live KVM smoke**: builder variant boots end-to-end on a real KVM host (folds into the existing `live-verity-boot` lane added in plan 35-sprint-44).

## Acceptance criteria

Sprint closes when:

1. ✅ Both `default` and `builder` outputs build deterministically from `nix/images/builder/flake.nix`.
2. ✅ The release pipeline emits cosign-signed manifests for both variants, attached to the GitHub Release.
3. ✅ `mvmctl dev up` requires (and verifies) the cosign-signed manifest in addition to W5.1's SHA-256 check.
4. ✅ `mvm-security::image_verify` exposes a stable, typed-error API that mvmd can consume.
5. ✅ The builder variant boots squashfs-RO with verity active; tampering the ext4 inside the squashfs panics the kernel before userspace.
6. ✅ Reproducibility + lockfile-cleanliness CI gates green.
7. ✅ Air-gapped `mvmctl dev import-image` works against local files.
8. ✅ ADR 005 merged; `airgapped-bootstrap.md` published.
9. ✅ `cargo test --workspace` all passing; `cargo clippy --workspace --all-targets -- -D warnings` clean.

## Reversal cost

Medium. Once a tag ships with the cosign-signed manifest, downgrading
to "checksum-file-only" trust would require either re-signing
checksums post-hoc (impossible — release identity is tag-bound) or
accepting a period of unverified downloads. Reversal would be a
deliberate design decision, not a code rollback.

## Open questions to confirm during PR-A

- **`sigstore` crate vs shelling to `cosign verify-blob`**: sigstore's
  Rust crate is heavy (TUF + transparency log + x509). Measure binary
  size impact; if >5 MB, gate behind a `manifest-verify` Cargo feature
  default-on for release builds, off for `cargo install
  --no-default-features`.
- **Default-microvm signing parity**: trivial to extend the new pipeline.
  In scope or follow-up issue?
- **Lockfile inventory**: confirm `nix/dev/flake.lock` exists alongside
  `nix/flake.nix::flake.lock` and `nix/images/builder/flake.lock`. Add
  any others surfaced by `find nix -name flake.lock`.

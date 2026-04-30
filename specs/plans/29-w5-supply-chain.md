# Plan 29 — W5: supply chain

> Status: ✅ shipped — 2026-04-30
> Owner: Ari
> Parent: `specs/plans/25-microvm-hardening.md` §W5
> ADR: `specs/adrs/002-microvm-security-posture.md`
> Estimated effort: 2 days
>
> ### Shipped artifacts
>
> - **W5.1** `download_dev_image` and `download_default_microvm_image`
>   in `crates/mvm-cli/src/commands/env/apple_container.rs` now fetch
>   the per-arch checksum manifest before downloading any artifact,
>   stream every byte through SHA-256, and refuse to use a file whose
>   digest doesn't match. `MVM_SKIP_HASH_VERIFY=1` is the documented
>   emergency-rotation escape hatch (logs a warning at WARN level).
>   Five regression tests in `hash_verify_tests`: matching accepts,
>   mismatch deletes-and-errors, env-var bypass, manifest parser,
>   missing-entry error path. Tests serialise via `ENV_LOCK` since
>   they touch the global env.
> - **W5.2** `deny.toml` at the workspace root with advisories +
>   licenses + bans + sources policies. CI gate
>   (`.github/workflows/ci.yml`'s `deny` job) runs `cargo deny check`;
>   `.githooks/pre-commit` runs the same locally if `cargo-deny` is
>   installed. `just deny` and `just supply-chain` recipes wrap the
>   command. Three transitive unmaintained advisories
>   (`fxhash`/RUSTSEC-2025-0057, `instant`/RUSTSEC-2024-0384,
>   `number_prefix`/RUSTSEC-2025-0119) are explicitly ignored with
>   reasons. The `rand` 0.8 → 0.8.6 bump (RUSTSEC-2026-0097, custom-
>   logger unsoundness) landed alongside the deny config.
> - **W5.3** `.github/workflows/ci.yml` gained a `reproducibility`
>   job that pins `SOURCE_DATE_EPOCH=1700000000`,
>   `CARGO_INCREMENTAL=0`, and `RUSTFLAGS=--remap-path-prefix`, then
>   builds `mvmctl` twice (clean between) and `diff`s the SHA-256s.
>   A mismatch fails the build and surfaces a `::error::` annotation.
> - **W5.4** Already shipped in `.github/workflows/release.yml` —
>   `cargo-cyclonedx` produces `sbom.cdx.json` at release time,
>   cosign-signs it, and the bundle is attached to the GitHub
>   release alongside the binaries.

## Why

The mvmctl binary trusts three things absolutely: the Cargo
dependency tree it compiles, the Nix binary cache it pulls store
paths from, and the GitHub release it downloads pre-built dev
images from when the user lacks a Linux builder. None of those
are signed-and-verified by us; only TLS protects the wire. A
typo-squatted Cargo dep, a malicious nixpkgs commit, or a one-off
GitHub account compromise lands code in a microVM with the same
authority any project-shipped code has.

W5 turns each into a verified-by-us link.

## Threat shape addressed

- A malicious Cargo dep introduced via typo-squatting or a
  legitimate dep's compromise produces a `cargo-audit`/`cargo-deny`
  failure that blocks the next merge.
- A GitHub release artifact tampered with after the fact is
  rejected by the SHA-256 mismatch in mvmctl's bundled hash.
- A non-deterministic build leak (which can mask injected code)
  fails the reproducibility check.
- Downstream consumers can audit *what* mvmctl ships against an
  emitted SBOM.

## Scope

In: changes to CI, release workflow, and a small piece of
`mvm-cli` that consults the bundled hash on download. New tools
land in CI; no runtime cost.

Out: nixpkgs trust. We inherit nixpkgs's signing model (the
`cache.nixos.org-1` key), and switching to a privately-signed
binary cache is a separate decision (named in ADR-002 as
"inherited assumption, documented but not changed").

## Sub-items

### W5.1 — Pre-built dev image SHA-256 verified against bundled hash

**What**

`crates/mvm-cli/src/commands/env/apple_container.rs::download_dev_image`
currently does `curl -fSL` and trusts the bytes. Replace with:

1. Release pipeline computes
   `sha256sum dev-vmlinux-{arch} dev-rootfs-{arch}.ext4` at
   release-build time.
2. Pipeline writes the hashes into a `const &[(name, hash)]`
   array in a generated source file:
   `crates/mvm-cli/src/release_hashes.rs` (or via `build.rs`).
3. `download_dev_image` consults the const for the running
   mvmctl version's expected hash, downloads the artifact,
   verifies before swapping into place.
4. Mismatch: delete the partial download, error to the user with
   a clear message ("artifact integrity check failed; refusing
   to use; please re-run release pipeline or report").

The same mechanism applies to `default-microvm` (W4 follow-up
already lands `default-microvm-{vmlinux,rootfs.ext4}` in
release artifacts; just add hashes).

**Files**

- `build.rs` at the workspace root (or in `mvm-cli`): consult
  an env-var the release workflow sets, generate the const file.
- `crates/mvm-cli/src/release_hashes.rs`: the generated module.
- `crates/mvm-cli/src/commands/env/apple_container.rs::download_file`:
  add `expected_sha256: Option<&str>` parameter, pipe the
  download through a streaming sha256 hasher (`sha2` crate
  already a transitive dep), compare on completion.
- `.github/workflows/release.yml`: write the four hashes into
  the env so build.rs picks them up.

**Tests**

- Unit test: `download_file` against a local-file mock with a
  known correct hash returns Ok.
- Unit test: same with a wrong hash returns the
  integrity-failure error.
- Integration test (gated on release CI): the release workflow
  builds mvmctl, then runs `mvmctl dev up` against a tampered
  artifact, asserts the failure path.

### W5.2 — `cargo-deny` and `cargo-audit` in CI

**What**

Two tools. Configure both, run both on every PR.

**`cargo-deny`** — `deny.toml` at the workspace root:

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-DFS-2016", "Unicode-3.0", "Zlib", "MPL-2.0", "CC0-1.0"]
copyleft = "deny"
default = "deny"

[bans]
multiple-versions = "deny"
deny = []
skip = []
skip-tree = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**`cargo-audit`** — runs against the lockfile, picks up RUSTSEC
advisories. No config file needed; just the binary.

**Pre-commit hook** — both tools also run locally via
`.githooks/pre-commit` (already exists; add to it).

**Files**

- `deny.toml` at workspace root.
- `.github/workflows/security.yml` (W6.3): add cargo-deny +
  cargo-audit steps.
- `.githooks/pre-commit`: add the same two commands so local
  pushes catch issues.

**Tests**

- Existing CI passing on a clean tree is the test. A test PR
  that adds a known-vulnerable dep version (e.g., an old
  `serde_json` with an advisory) gets blocked.

### W5.3 — mvmctl reproducibility check

**What**

Build mvmctl twice on different CI runners (or the same runner
twice with explicit timestamp/buildid resets). Hash the
resulting binaries. Mismatch fails the build.

This catches:

- Build-time non-determinism (timestamps, hashmaps with random
  iteration order, file-system order leaking).
- Code-path differences between runners (e.g., runner A has a
  different libc baked into a build script).
- Compromised CI that injects code on one runner but not
  another.

The hash check goes in `security.yml`. Implementation:

```yaml
- run: cargo build --release
- run: sha256sum target/release/mvmctl > /tmp/hash-a.txt
- run: cargo clean && cargo build --release
- run: sha256sum target/release/mvmctl > /tmp/hash-b.txt
- run: diff /tmp/hash-a.txt /tmp/hash-b.txt
```

A real-world reproducibility setup typically requires a few
flags (`SOURCE_DATE_EPOCH`, `--frozen`, `--locked`,
deterministic linker flags). We pin them in `Cargo.toml`'s
`[profile.release]` section as needed.

**Files**

- `Cargo.toml`: ensure `[profile.release]` has any
  determinism-relevant flags pinned.
- `.github/workflows/security.yml`: the double-build steps.

**Tests**

- The CI step itself.

### W5.4 — SBOM emission

**What**

`cargo-sbom` produces a CycloneDX-formatted SBOM from
Cargo.lock. Run it at release time, attach to the GitHub
release alongside the binary.

```yaml
- uses: anchore/sbom-action@v0
  with:
    path: ./
    format: cyclonedx-json
    output-file: mvmctl-sbom.cdx.json
- uses: actions/upload-release-asset@v1
  with:
    asset_path: ./mvmctl-sbom.cdx.json
```

(Or the explicit `cargo install cargo-sbom && cargo sbom` route
if the anchore action turns out to be heavyweight.)

**Files**

- `.github/workflows/release.yml`: SBOM step + upload.

**Tests**

- A release dry-run produces the SBOM, attaches it; user can
  download and grep.

## Sequencing

W5.2 (cargo-deny/audit) is the highest-priority and lowest-cost;
do it first. W5.1 (image hash) is medium and depends on the
release pipeline cooperating. W5.3 (reproducibility) is a CI-only
change. W5.4 (SBOM) is a release-only change. None depend on each
other.

PR sequence:

1. PR-A: W5.2 — `deny.toml` + workflow. Self-contained.
2. PR-B: W5.1 — hash-verify on download. Touches mvm-cli + build.rs.
3. PR-C: W5.3 + W5.4 — both CI-only. One PR.

## CI gates

All four items add gates to `.github/workflows/security.yml`
(W6.3).

## Rollback shape

- W5.2: `deny.toml` allowlists or `skip` entries handle false
  positives (a transitive dep with a stale advisory we've
  reviewed). Reversible per-entry.
- W5.1: a single env override (`MVM_SKIP_HASH_VERIFY=1`) makes
  the download trust TLS only — for debugging an
  emergency-rotation scenario.
- W5.3: turn off the double-build step. Cost: less detection,
  no breakage.
- W5.4: turn off the SBOM upload. Cost: downstream consumers
  can't audit; no breakage.

## Reversal cost

Low for all four. Configuration flips in CI; no runtime API
implications.

## Acceptance criteria

W5 ships when:

1. ✅ `cargo-deny check` green locally and in CI.
2. ✅ `cargo-audit` green.
3. ✅ A tampered dev-image artifact is rejected by mvmctl's
   download path (regression test).
4. ✅ The reproducibility build produces matching hashes on
   two CI runs.
5. ✅ A release dry-run emits a CycloneDX SBOM.
6. ✅ Plan 25 §W5 checkboxes flipped.

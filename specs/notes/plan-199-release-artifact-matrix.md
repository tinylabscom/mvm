# Plan 199 Workstream B2 — release artifact matrix + verification

**Date:** 2026-06-16 · **Owner:** mvm · Companion to
[`plans/199-host-runtime-packaging-and-crate-boundaries.md`](../plans/199-host-runtime-packaging-and-crate-boundaries.md)

The contract for what every `v*` tag publishes (`.github/workflows/release.yml`),
and the post-publish gate that enforces it
(`packaging/release/verify-release-assets.sh`, run by the `verify-release` job).

## The matrix

### Binary `mvmctl` (the default user download path — install.sh / `mvmctl update` / Homebrew)

| Target | Arch | OS | Status |
|---|---|---|---|
| `aarch64-apple-darwin` | arm64 | macOS | published (product baseline, macOS 26+) |
| `x86_64-unknown-linux-gnu` | x86_64 | Linux | published |
| `aarch64-unknown-linux-gnu` | arm64 | Linux | published |
| `x86_64-apple-darwin` | x86_64 | macOS | **deferred** — needs a native Intel runner (libkrun link); install.sh/Homebrew `on_intel` point at the absent asset |

Per published target: `mvmctl-<target>.tar.gz` + `.tar.gz.sha256` (per-file SHA256)
+ `.tar.gz.bundle` (cosign keyless OIDC signature: signature + Fulcio cert + Rekor
proof). Plus one combined `checksums-sha256.txt` across all targets, and a signed
SBOM `sbom.cdx.json` (+ `.bundle`).

### Image artifacts (best-effort — an image-build failure must not block the binary release)

Per arch (`aarch64`, `x86_64`), each with a `*-checksums-sha256.txt`:

- **builder-vm** — `builder-vm-vmlinux-<arch>`, `builder-vm-rootfs-<arch>.ext4`, optional `.cmdline.txt` / `.manifest.json`
- **runtime-overlay** — `runtime-overlay-<arch>.{ext4,verity,roothash,VERSION}`
- **default-microvm** (prod variant) — `default-microvm-vmlinux-<arch>`, `default-microvm-rootfs-<arch>.{ext4,verity,roothash}`, `default-microvm-meta-<arch>.json`

Image `*.manifest.json` files are cosign-signed (`.bundle`) per ADR-005 so
`mvm-security::image_verify` can consume them.

## Provenance

- **Signatures:** cosign keyless via GitHub OIDC (`id-token: write`). Identity =
  the `release.yml` workflow ref; issuer = `https://token.actions.githubusercontent.com`.
  No long-lived signing key.
- **SBOM:** CycloneDX (`cargo cyclonedx`) over the whole workspace, signed.
- **Reproducibility:** `security.yml` double-builds `mvmctl` and asserts a matching
  SHA256 across two clean builds (claim 7 / W5.3) — independent of this gate.

## The verification gate (B2 deliverable)

`packaging/release/verify-release-assets.sh --assets-dir DIR` is **fail-closed**:
for every published target it asserts the tarball, its `.sha256` (and that the
recorded hash matches the actual bytes), its `.bundle` signature, and an entry in
the combined `checksums-sha256.txt`; then that the signed SBOM is present. `--cosign`
additionally runs `cosign verify-blob` against each bundle (identity via
`COSIGN_IDENTITY_REGEXP`/`COSIGN_IDENTITY` + `COSIGN_OIDC_ISSUER`).

The `verify-release` job in `release.yml` (needs `release`) downloads the just-published
assets and runs it with `--cosign`, so a release that is missing a checksum, a
signature, or whose bytes don't match their recorded hash **fails the workflow**.

Self-tested (no tag needed) across happy-path + five tamper cases (bad checksum,
missing signature, missing tarball, not-in-manifest, missing SBOM signature) — all
behave as expected.

## Scope notes

- This gate proves the binary download path is **complete, checksummed, and signed**.
  It deliberately does not re-derive image provenance — image manifests carry their
  own cosign bundles consumed by `image_verify`.
- The deferred `x86_64-apple-darwin` target is intentionally absent from the verified
  set; restore the row here and in the script's default `--targets` when an Intel
  runner is available.

# Homebrew release channel

The formula installs the seven required Linux host executables (plus the HVF
supervisor on macOS) and native hostlib in `lib/mvmctl`. Public executables are
symlinks in `bin`; the library also has a discovery symlink in `lib`.
`share/mvmctl/package-managed` contains `homebrew`, so self-update defers to
Homebrew. No optional libkrun supervisor or old-macOS fallback is shipped.
The macOS baseline is Apple Silicon on macOS 26.

Installation copies the published bytes without ad-hoc signing. On macOS it
requires strict Developer ID signature verification of every Mach-O and
Gatekeeper assessment of the CLI and HVF supervisor. Homebrew never downloads
an unsigned guest runtime: the CLI's runtime resolver fetches and verifies the
matching signed `mvm-guest-bins-vVERSION.tar.gz` when needed.

## Validation

Host-only fixtures, requiring Python 3, Ruby and jq:

```sh
python3 nix/packaging/homebrew/test_homebrew.py
sh -n nix/packaging/homebrew/render-formula.sh
bash -n nix/packaging/homebrew/prepare-formula.sh
actionlint .github/workflows/homebrew-smoke.yml .github/workflows/update-homebrew-tap.yml
```

The fixture suite executes rendering, the real formula's install method against
a filesystem-backed Homebrew DSL, and the release preparation script with
mocked GitHub/cosign commands. It covers missing payloads, byte preservation,
symlinks, package-manager ownership, signature rejection, malformed versions,
duplicate/malformed checksums and unpromoted releases. This is **not** evidence
of a native Homebrew install or real cryptographic verification.

`homebrew-smoke.yml` is the postpublication native install/load/remove gate for
Linux x86_64, Linux aarch64 and macOS arm64. Runners without native Homebrew use
the commit-pinned official installer; setup failure is not a skipped target. It authenticates
the exact stable tag's manifest, runs mandatory style/audit/install/test checks,
loads hostlib through the shared installed-release smoke, and verifies removal.
The shared smoke's `--runtime-fetch` mode downloads the exact versioned runtime
archive, checksum and their signature bundles into private temporary storage,
checks the checksum, and invokes the installed CLI's `env verify-release` for
the archive and checksum with the exact release tag. It does not write into the
Homebrew prefix or fabricate an installed archive. This witnesses versioned
runtime acquisition and the installed verifier, not lazy-cache behavior or a
live VM launch. Native success requires an actual complete signed release;
fixtures do not establish readiness for any target.

## Release integration

`prepare-formula.sh TAG DIRECTORY` accepts only stable CLI tags whose GitHub
release is published, non-draft and non-prerelease. Before rendering it verifies
the checksum manifest's Sigstore bundle with the exact
`release.yml@refs/tags/TAG` identity and GitHub Actions OIDC issuer.

`update-homebrew-tap.yml` requires all three native smoke lanes and compares the
rendered formula against each lane's retained formula before publication.
No audit failure is masked. The tap credential is passed through Git askpass,
never a clone URL or credential-bearing Git config.

Releases promoted by `GITHUB_TOKEN` do not trigger release-event workflows.
After stable promotion, `release.yml` calls the tap updater as a reusable
workflow. Its install and publication result therefore belongs to the parent
release outcome, rather than only recording that a dispatch was accepted.

For an explicit later retry, the workflow remains manually dispatchable:

```sh
gh workflow run update-homebrew-tap.yml --repo tinylabscom/mvm --ref "$TAG_NAME" -f tag="$TAG_NAME"
```

Using the release tag selects the same reviewed formula and witness code.
A manual dispatch from `main` remains available for later formula fixes.

The tap updater needs the repository secret `HOMEBREW_TAP_TOKEN` with push
access to `tinylabscom/homebrew-mvm`. A manual dispatch is asynchronous: inspect
its completed smoke and push jobs before recording channel success. No workflow
or publication is invoked by the local fixture suite.

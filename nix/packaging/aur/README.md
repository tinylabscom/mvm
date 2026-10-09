# Binary distribution recipes

`render-packages.py` generates an AUR `PKGBUILD` and a standalone
`package.nix` from the **same authenticated release**. It requires Python 3.11+
and `cosign` on PATH. It never downloads or publishes anything.

The AUR recipe targets official Arch Linux's `x86_64` platform; the Nix
derivation also supports `aarch64-linux`. Unofficial Arch Linux ARM is not
advertised without a native installation witness.

Templates are not installable packages and contain no invented release hashes.
Do not substitute an older host archive or a runtime-overlay archive to make
generation succeed.

## Generate after signing

Put the release's downloaded/staged assets in `/tmp/mvm-release-assets`:

- `checksums-sha256.txt` and its `.bundle`
- both `mvmctl-x86_64-unknown-linux-gnu.tar.gz` and
  `mvmctl-aarch64-unknown-linux-gnu.tar.gz`, each with its `.bundle`
- `mvm-guest-bins-v0.23.1.tar.gz`, its `.sha256`, and its `.bundle`

Once v0.23.1 is actually signed and available:

```sh
python3 nix/packaging/aur/render-packages.py \
  --version 0.23.1 --assets-dir /tmp/mvm-release-assets \
  --out-dir /tmp/mvm-release-recipes
```

The generator invokes the same cosign exact release-workflow identity and
GitHub OIDC issuer policy as the installer. It verifies the combined checksum
manifest and all three archives, checks their digests against that signed
manifest, and checks the guest `.sha256` agrees. No verifier override or unsigned
mode exists. Recipe hashes for the archive, checksum, and bundle are hashes of
those verified local bytes. Authentication failure creates no recipes.

The broader release gate `nix/packaging/release/verify-release-assets.sh --cosign`
still owns release-set completeness; this generator intentionally does not
require unrelated macOS, deb/rpm, or SBOM assets.

## Install and validate

Run packaging and runtime smokes **inside the project builder VM**, not on the
host. On an Arch builder environment, review the generated PKGBUILD, then:

```sh
cd /tmp/mvm-release-recipes
makepkg --verifysource
makepkg --cleanbuild
makepkg --printsrcinfo > .SRCINFO
```

The release workflow publishes the signed generated recipes alongside the
archives. `release-recipes-smoke.yml` installs the published PKGBUILD with
`makepkg` and `pacman`, executes the installed CLI, loads hostlib, checks the
installed guest archive bytes, and removes the package before stable promotion.
The generation tests do not substitute for these installed-artifact checks or
the release's live guest boot gate. Record each actual run's results in its PR.

The package installs every Linux host helper and `libmvm_hostlib.so` beside the
real executable in `/usr/lib/mvmctl`, exposing binaries via `/usr/bin` symlinks.
The complete, unmodified signed guest archive (both guest architectures) and its
checksum/bundle live in `/usr/lib/mvmctl/guest-runtime`. The runtime resolves the
real executable, verifies that triplet, and populates its normal guest cache;
packaging does not create an unsigned pre-extracted cache.

Host-only hermetic generator checks:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s nix/packaging/aur -p 'test_*.py' -v
```

These use synthetic byte fixtures and mocked verifier subprocesses, explicitly
not a real signature-verification or package-install witness.

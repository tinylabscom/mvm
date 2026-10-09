# Standalone nixpkgs-style binary derivation

The [shared renderer](../aur/README.md) emits `package.nix` alongside the AUR
PKGBUILD. The result is a conventional `callPackage` function using only
`lib`, `stdenv`, `fetchurl`, and `autoPatchelfHook`; it has no private mvm flake
helpers, vendoring functions, toolchain inputs, or local source dependencies.
Every fetched asset is pinned to verified bytes under one release tag.

This is deliberately named **mvmctl-bin**, not a claim of upstream nixpkgs
acceptance. Building from source would require separately designing and
validating the embedded Rust toolchain and locked vendoring used by this
workspace. The binary recipe keeps that work out of this distribution channel.
It declares binary source provenance and patches host ELF interpreters/RPATHs
for Nix. The signed guest archive remains unmodified and is never auto-patched.

After generating from an actual signed release, run this only in the project
builder VM, using its approved nixpkgs:

```sh
nix-build -E 'let pkgs = import <nixpkgs> {}; in pkgs.callPackage /tmp/mvm-release-recipes/package.nix {}'
./result/bin/mvmctl --version
```

Test both `x86_64-linux` and `aarch64-linux` builders before publication. The
result exposes `$out/bin` symlinks, host helpers and hostlib in `$out/lib/mvmctl`,
and the complete signed guest archive triplet in
`$out/lib/mvmctl/guest-runtime`. `autoPatchelfHook` fails on unresolved host
dependencies instead of ignoring them; builder validation must establish any
additional release-specific dynamic dependencies.

`release-recipes-smoke.yml` builds this standalone derivation on both native
Linux architectures, installs it into an isolated Nix profile, runs the CLI and
loads hostlib, checks the installed guest archive, and removes the profile
package. Stable promotion requires those jobs. Recipe generation alone is not
evidence that installation or guest-runtime acquisition works.

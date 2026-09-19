# The Nix-built initramfs carries the workspace version

Backing: shipped-source
Validation: cargo run -p xtask -- check-runtime-overlay-version

The universal initramfs that `nix/images/initramfs/flake.nix` builds, and that
the release publishes, wrote `VERSION` `0.18.0` from a literal of its own while
the workspace was `0.18.0-rc.2`. `InitramfsResolver` refuses an initramfs whose
`VERSION` differs from the running mvmctl's, and a mismatch is not treated as a
miss, so a CLI built from the same commit could not boot with the initramfs
that commit publishes. The flake comment said the value was kept in lock-step
with the runtime overlay; nothing checked that, and `check-runtime-overlay-version`
read only the overlay flake.

## One pin, not three

The overlay and SDK sidecar already took their version from one literal,
`overlayVersion`, which the gate compared with Cargo.toml and `just release`
rewrote. That literal moved to `nix/images/version.nix`, and both the overlay
flake and the initramfs flake bind their version with `import ../version.nix`.
There is still exactly one hand-maintained copy of the workspace version under
`nix/images/`, and the release recipe rewrites that file instead of the overlay
flake.

The relative import keeps the mvm-images copies working without a rewrite:
`images/runtime-overlay/image.nix` and `images/initramfs/image.nix` sit one
directory below `images/`, so the pin is copied to `images/version.nix` beside
them.

## The gate

`check-runtime-overlay-version` now fails when:

- `nix/images/version.nix` differs from `[workspace.package].version`, or holds
  anything other than one quoted string;
- either image flake binds its version to anything other than the pin. A
  literal `initramfsVersion = "0.18.0";`, the shape that shipped, is refused
  with the file and binding named.

Unit tests cover each refusal against a scratch tree, and one test runs the gate
against the checked-in tree so `cargo nextest` fails on the same drift as
`check-all`.

## Evidence

`nix build ./nix/images/initramfs#packages.x86_64-linux.default` on the Hetzner
KVM host, from this branch:

```
/nix/store/6dl8azhh886gx3q57fyp7gx7i5pmrqzc-mvm-initramfs-x86_64-linux-6.12
VERSION: 0.18.0-rc.2
```

`nix eval` gives `0.18.0-rc.2` for both the initramfs and the runtime overlay
`version` passthru.

The initramfs bytes do not change: `VERSION` is written beside the cpio, not
into it. Its output path does change, because the string is part of the build
script.

# Builder-VM kernel

A slim custom Linux 6.12 kernel tailored for the libkrun builder
VM. Built via `pkgs.linuxManualConfig` from a `.config` generated
by `make defconfig` + the `enables` / `disables` lists in
[`builder.nix`](./builder.nix) + `make olddefconfig`. (Plan 92
landed `tinyconfig` first; `e663abf4` switched to `defconfig`
because tinyconfig stripped arch_timer / GIC / OF — see the
comment in `builder.nix`.)

Nothing is vendored under this directory. The source of truth is
the `enables` / `disables` lists in `builder.nix`.

## Why a slim, all-built-in kernel

Stock `pkgs.linuxPackages.kernel` ships hundreds of `=m` modules
the builder VM never loads, and the things it *does* load are
modules too (overlay, vsock, virtio-fs, iptables tables). Under
that shape, `mvm-host-vm-init` has to:

1. Ship a `/lib/modules/<kver>/` tree in the rootfs (closure-walked
   by `mkGuest`).
2. Modprobe each module at the right time (overlay before mount,
   vsock before `socket()`, fuse + virtiofs before mount).
3. Hope modprobe finds the module (silent failure modes on a
   missing closure entry).

That contract has multiple silent-failure surfaces and a closure-
walking abstraction in `mk-guest.nix` that broke during Plan 92
validation in five different ways.

Slim flips every feature we need to `=y` (built-in). modprobe
becomes a no-op. No module tree to ship. The whole class of
failure goes away. Plan 92 records the decision and tradeoffs.

## Tradeoff: first-boot kernel compile

Because the config is novel, `cache.nixos.org` doesn't have a
substitute. A contributor's first `dev up` compiles the kernel
once (3-5 min on Apple Silicon, ~10 min on slower hosts). After
that, the kernel's nix store hash is stable across runs and
contributors share it within the local nix store.

## Changing what's compiled in

Add a feature: drop its short Kconfig symbol (without the
`CONFIG_` prefix) into the `enables` list. `make olddefconfig`
will pull in transitive dependencies on the next build.

Remove a feature: add it to `disables`. If `olddefconfig` later
re-enables it because another `=y` symbol depends on it, that
parent symbol needs to come off too — disabling a leaf doesn't
override a hard dependency.

To introspect what `olddefconfig` produced, build the
`kernel-configfile` flake output (added in Plan 95 §W2):

```sh
nix build .#kernel-configfile -o /tmp/kconfig
grep '=y$' /tmp/kconfig | sort > /tmp/kconfig.y.txt
```

The output is a regular `.config` text file — diffable across
`disables` edits to confirm SoC platform clusters or other
unwanted symbols are gone.

## Why no TSI patches

Plan 87 / Plan 88 / ADR-055 moved builder-VM networking to passt
(Linux) / gvproxy (macOS) via virtio-net. The TSI syscall-hijack
path is no longer used in any builder VM. The vendored TSI patch
series (22 files) was removed by Plan 92.

## Maintenance contract

When the kernel needs a change:

1. **Add a built-in feature.** Append the short Kconfig symbol to
   `enables`. `make olddefconfig` handles transitive deps.
2. **Remove a feature.** Append to `disables`. If `olddefconfig`
   pulls it back in, the parent also needs to come off.
3. **Bump the kernel version.** Edit the `pkgs.linux_6_12`
   reference (or follow nixpkgs' rename if the LTS pin moves).
   `make olddefconfig` reconciles dropped / renamed / added
   symbols automatically.

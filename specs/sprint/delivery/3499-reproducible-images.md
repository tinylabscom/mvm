# Image filesystems are a function of their input tree

Backing: shipped-source
Validation: cargo run -p xtask -- check-image-reproducibility

Building one image derivation twice gave different bytes. The files inside were
identical; the metadata around them was drawn at random by the tools that wrote
it. Two producers of the same image could not be compared by digest, and the
published root hash of the default microVM could not be re-derived from source.

## What was random, and what pins it now

| Recipe | Random input | Fix |
|---|---|---|
| `nix/lib/mk-guest.nix` (every mkGuest rootfs: default microVM, builder VM) | ext4 directory hash seed. nixpkgs `make-ext4-fs.nix` pins the UUID only and takes no extra `mkfs` arguments. | It is handed an `e2fsprogs` whose `mkfs.ext4` always adds `-E hash_seed=00000000-0000-0000-0000-000000000002`, the Rust writer's `Mke2fsOptions` default. |
| `nix/images/runtime-overlay/flake.nix` (overlay, SDK sidecar) | ext4 hash seed. The pin was passed as `-E hash_seed=… -E no_copy_xattrs`, and `mke2fs` keeps only the last `-E`. | One `-E hash_seed=…,no_copy_xattrs`, the option set the Rust writer already uses. |
| runtime overlay and `nix/images/default-tenant/flake.nix` | dm-verity superblock UUID | `veritysetup format --uuid=00000000-0000-0000-0000-000000000003`, the Rust sealer's `MVM_VERITY_PINNED_UUID`. |
| `nix/images/initramfs/flake.nix` | cpio inode and device numbers | `cpio --reproducible`; input already sorted, mtimes already epoch. |
| `nix/packages/qemu-wasm-smoke-image.nix` | ext2 UUID and hash seed | `mkfs.ext2 -U … -E hash_seed=…` |

These change image bytes, and therefore the overlay and default-image root
hashes: that is the point. The file trees inside are unchanged.

## Regression checks

- `xtask check-image-reproducibility` (in `check-all`) reads every recipe under
  `nix/` and refuses an `mkfs.ext*` without `-U` or an effective `hash_seed`, an
  `mkfs` with more than one `-E`, a `veritysetup format` without `--uuid`, a
  `cpio -o` without `--reproducible`, and a `make-ext4-fs.nix` call not handed
  its own `e2fsprogs`. Unit tests cover each refusal, including the exact
  double-`-E` shape that shipped, and one runs the gate over the tree and
  requires it to see every kind of call so it cannot pass vacuously.
- The merge-queue `guest-image-boot` job now runs `nix build --rebuild` on the
  default microVM's final derivation, its two ext4 derivations, and the runtime
  overlay. Nix fails the step if a rebuild's bytes differ. `check-workflow-paths`
  asserts the step is present.

## Evidence (x86_64, Hetzner KVM host)

Built from `main` (`fd555b5ef9`) and from this branch, then every derivation
that writes filesystem bytes was rebuilt with `nix build --rebuild`. The branch
was also built a second time from nothing in a separate Nix store, so the two
branch hashes below come from independent builds.

On `main`, every rebuild failed with "may not be deterministic":

| Artifact | Differing bytes, build vs rebuild on `main` |
|---|---|
| mkGuest `ext4-fs.img` (default microVM) | 60 |
| default microVM `rootfs.verity` | 15 |
| `overlay.ext4` | 40 (`overlay.verity`, `overlay.roothash` follow) |
| `sdk.ext4` | 20 |
| initramfs cpio (uncompressed) | 12 (`initramfs.hash` follows) |
| QEMU-wasm smoke rootfs | 32 |

On the branch, every `--rebuild` passed, and the independent store gave the
same output paths and bytes:

| Artifact | Build 1 sha256 | Build 2 (separate store) sha256 |
|---|---|---|
| `initramfs.cpio.gz` | `3a0cfb35d6d8aac243a47afa82d88f263f7a6a304fd05cc5fe9a5051af1f914c` | same |
| `initramfs.hash` | `2c313b9c132ae08673b77156fe1233df5f430a3c958b46ed17e296c8e58d6cf1` | same |
| `overlay.ext4` | `a28edaab2613ae326b777032674918bd6b74c30ba17724076cfcac27a748c967` | same |
| `overlay.verity` | `1672922b04ca4a626f3d3d7a8bf5d91c98f6623845a34cdd3360ea17510a81e6` | same |
| `overlay.roothash` | `1e95fdef1855f77b4488246d09711e654c08895e40e712d39e74d766a73c0be3` | same |
| `sdk.ext4` (glibc) | `27a65174959bf88a1161890642e0f83adbabc58d517820465a09b96f5215fbfd` | same |
| mkGuest `ext4-fs.img` | `9acb6dbb3f8ccdf3de127f2001838dd24709061f08fc84784b38525c0cb3d577` | same |
| default `rootfs.ext4` | `88b617292f926c08c80eb10359661ce1669a36d267c0175c90eeb89b1cf7118c` | same |
| default `rootfs.verity` | `a6d3ffa7179c48a9f2c1badbcb85822db5163da8300ba89bd22364d471aacaae` | same |
| default `rootfs.roothash` | `ec32ca1749c34a7af9f05c2208f2a8526be326dcb4bbc74c834c343e2e679332` | same |
| QEMU-wasm smoke rootfs | `9a69efa3472f94f3d9e4c783acf128028df1f5e6f4f24c7f4020db3c95feb1bc` | same |

File trees, `main` against the branch (`debugfs rdump` for ext4, cpio
extraction for the initramfs; path, type, mode, owner, symlink target, content
sha256):

- overlay (48 entries), SDK sidecar (6), QEMU-wasm rootfs (415), initramfs
  (`/init`): identical. `dumpe2fs -h` differs only in `Directory Hash Seed`
  (now the pin) and the superblock checksum, plus `Filesystem UUID` for the
  QEMU-wasm image.
- default microVM: identical once `/nix/store/<hash>-` prefixes are normalized.
  The prefixes differ because the filtered workspace source includes `nix/`,
  `xtask/` and `.github/`, all edited here, so every derivation built from it
  gets a new store path; `nix-path-registration` differs only in those paths and
  the NAR hash of the rootfs tree that embeds them. The superblock differs in
  the hash seed and its checksum.

aarch64 was not built; the recipes take no architecture-specific branch in any
of these steps.

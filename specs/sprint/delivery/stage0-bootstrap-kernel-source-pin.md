# Stage 0 bootstrap kernel: a source pin, and the first live HVF bootstrap

The VMM-agnostic Stage 0 work fetched its bootstrap kernel through
`update::download_kernel`, which holds the bytes to the release's signed checksum
manifest at run time. That is correct, and it is also unusable on the build most
contributors run: authenticating the manifest needs the `manifest-verify`
feature, `just embed` does not enable it, and so the check refuses closed.

The first live run showed it in six seconds, before any VM existed:

```
refusing to parse an unauthenticated checksum manifest
(builder-vm-aarch64-checksums-sha256.txt) … manifest-verify feature is disabled
in this build
```

Before that work, an HVF bootstrap lowered onto libkrun and took libkrunfw's
kernel from the local dylib, so nothing was fetched and nothing needed signing.
Moving Stage 0 off libkrun moved that kernel onto a fetch, and the fetch onto a
feature the contributor build lacks. Every HVF bootstrap from `just embed` was
broken. No test could see it: every test injects its own fetcher.

## The fix is the design the module already claimed

`stage0_kernel`'s own docs call the kernel a **bootstrap seed**, "classified the
same way Stage 0 classifies its root filesystem". The Nix seed is a
`BootstrapAsset`: a URL and a SHA-256 pinned in source, fail-closed, no signature
at run time. The kernel was classified as a seed but verified like a release
artifact. Now it is pinned like a seed.

`BOOTSTRAP_KERNEL_AARCH64` and `BOOTSTRAP_KERNEL_X86_64` pin the
`builder-vm-vmlinux-<arch>` assets of `boot-image/v0.1.5`. The digests were
copied out of that release's checksum manifests only after both manifests passed
`cosign verify-blob` against
`release-boot-image.yml@refs/tags/boot-image/v0.1.5`, so the pin inherits exactly
that trust.

Two things did not change:

- **The transport is still injected, and still curl.** The pinned URL is a GitHub
  release asset: a `302` to `release-assets.githubusercontent.com`. `mvm-http`
  follows no redirects, by design. `mvm-cli` supplies `download_file` (curl), and
  all verification stays in `mvm-build` against the pin, so a transport that
  returns the wrong bytes is refused rather than trusted.
- **A cached kernel is held to the pin, not just its sidecar.** The digest
  sidecar vouches for whatever was last written, so a kernel from an older pin
  would otherwise survive a pin bump. `a_cached_kernel_from_an_older_pin_is_replaced`
  holds that.

## First live HVF bootstrap

macOS 26.6.2 arm64, libkrun installed but never touched, plain `just embed`, cold
isolated `MVM_HOME`, `mvmctl __builder-vm-bootstrap`: **exit 0 in about 11
minutes.** The guest console carries every leg the unit tests cannot reach:

| Leg | Console |
|---|---|
| clock seed | `wall clock set from host epoch 1789558517` |
| disk transport | `Stage 0 Nix store is /dev/vdb (label "mvm-nix-store")` |
| vsock egress | `copying path … from 'https://cache.nixos.org'` |
| the build | `building path:/work/nix/images/builder-vm#packages.aarch64-linux.default` |
| completion | `stage0-init: done; halting`, then `reboot: Power down` |

The cache then held `rootfs.ext4` (760 MiB), `vmlinux`, `manifest.json`,
`cmdline.txt` and provenance.

## Two traps, both hit on the way

- **The HVF supervisor came out of the build unsigned.** `codesign` showed no
  `com.apple.security.hypervisor` entitlement until `mvmctl env sign`. Unsigned,
  macOS SIGKILLs it and the failure reads like a Stage 0 regression.
- **`--features user` does not link locally.** The sigstore stack's `aws-lc`
  symbols come up undefined on this host. It does not matter for this path once
  the kernel is pinned, but a contributor who follows the old error's advice
  ("rebuild with `--features user`") hits it.

## Not done

- **Firecracker is not live-proven.** This host has no KVM.
- **`stage0-init` logs `backend = libkrun` under HVF.** Its detection is
  `is_qemu()`, and everything else takes the libkrun label. Cosmetic, but
  misleading now that HVF and Firecracker take that arm.
- **`--kernel-source download` still needs `manifest-verify`.** That flag fetches
  the builder *image's* kernel through `download_kernel`, a separate path this
  change deliberately leaves alone.

# Deployment Architecture

## Overview

`mvmctl` ships as a single binary that users install via a `curl | sh` install script. The install model prioritizes **speed**, **safety**, and **zero-dependency runtime** — users should be able to go from zero to running microVMs in under 30 seconds on a clean machine.

This document describes the reference deployment model and the decisions that shape it.

---

## Key Design Goals

### 1. One-Liner Install

Users install with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
```

No build from source required. No Nix needed on the host. No Docker.

### 2. Binary-First, Source-Optional

The primary distribution channel is prebuilt binaries published to GitHub Releases. Source builds exist for:

- Debugging / development
- Air-gapped installs (side-load a custom build)
- Contributors who want to iterate on the CLI itself

### 3. Platform Detection & Auto-Selection

The installer and runtime automatically detect the platform and select the best backend:

| Platform | Runtime Backend | Notes |
|----------|-----------------|-------|
| **Linux + KVM** | Firecracker | Native, sub-200ms boot, Tier 1 |
| **macOS 26+ Apple Silicon** | Vz | Bundled with OS, zero extra deps |
| **macOS 13–25 Apple Silicon** | libkrun | Homebrew-managed, in-process VMM |

### 4. Builder VM is Runtime-Transparent

Users **do not** run Nix on the host. On first workload build:

1. `mvmctl` bootstraps or reuses a Linux builder VM
2. Nix evaluation + `nix build` run **inside** the builder VM
3. Extracted rootfs is copied back to the host cache
4. Runtime backends boot **already-built** images

5. Security: build-time Nix runs in the builder VM; host touches only tarballs

### 5.契約 (Contract)

1. **Checksum verification**: Every release binary has a SHA-256 in `checksums-sha256.txt`. The installer verifies match before install.
2. **Signature verification**: Optional cosign bundle (`*.bundle`) is verified if `cosign` is available.
3. **macOS codesigning**: On macOS, the installer re-signs `mvmctl` with `com.apple.security.hypervisor` entitlement so Hypervisor.framework calls succeed.
4. **Perf**: On-disk size and runtime memory usage are explicit concerns

---

## Distribution Artifacts

### Release Tag Anatomy

Each release tag `vX.Y.Z` publishes:

```
release/
  mvmctl-<version>-aarch64-apple-darwin.tar.gz      # macOS Apple Silicon
  mvmctl-<version>-aarch64-apple-darwin.tar.gz.bundle  # cosign bundle
  mvmctl-<version>-aarch64-unknown-linux-gnu.tar.gz   # Linux arm64
  mvmctl-<version>-aarch64-unknown-linux-gnu.tar.gz.bundle
  mvmctl-<version>-x86_64-apple-darwin.tar.gz       # macOS Intel (future)
  mvmctl-<version>-x86_64-apple-darwin.tar.gz.bundle
  mvmctl-<version>-x86_64-unknown-linux-gnu.tar.gz   # Linux x86_64
  mvmctl-<version>-x86_64-unknown-linux-gnu.tar.gz.bundle
  checksums-sha256.txt                              # SHA-256 for each .tar.gz
```

### Archive Contents

Each `.tar.gz` contains:

```
mvmctl-<target>/
  mvmctl                         # main CLI binary
  mvm-bridge                     # per-VM Firecracker bridge (Linux)
  mvm-vz-supervisor              # per-VM Vz supervisor (macOS 26+)
  mvm-libkrun-supervisor        # per-VM libkrun supervisor (macOS 13-25)
  resources/
    mvmctl.entitlements         # macOS Hypervisor entitlements file
```

All per-VM host binaries are **installed beside `mvmctl`** so the backend's "adjacent-to-exe" resolver finds them at runtime.

---

## Installer Implementation

### Current State

See `install.sh` in the repo root. It:

1. Detects platform (macOS/Linux, arch)
2. Resolves version (latest or pinned via `MVM_VERSION`)
3. Downloads archive + checksums
4. Verifies SHA-256 (`shasum -a 256` / `sha256sum`)
5. Verifies cosign signature if available (non-fatal)
6. Extracts and installs to `~/.local/bin`
7. On macOS: re-signs with Hypervisor entitlement
8. **Prefetches builder image** via `mvmctl bootstrap` (opt-out via `MVM_SKIP_BUILDER_PREFETCH=1`)

### Environment Variables

| Var | Purpose |
|-----|--------|
| `MVM_VERSION` | Pin a specific release tag (e.g. `v0.16.0`) |
| `MVM_INSTALL_DIR` | Override install directory (default: `~/.local/bin`) |
| `MVM_SKIP_HASH_VERIFY` | Skip SHA-256 check (emergency only, **not recommended**) |
| `MVM_SKIP_CODESIGN` | Skip macOS codesign step |
| `MVM_SKIP_BUILDER_PREFETCH` | Skip builder image prefetch; defer to first `dev up` |
| `MVM_UPDATE_API_URL` | Override GitHub API base (testing) |
| `MVM_UPDATE_DOWNLOAD_URL` | Override GitHub download base (testing) |

---

TODO: What needs be done to make the build.rs generate a single binary

---

## Future Work

### Portable Artifacts (`.mvmpkg`)

We aim to support signed, single-file portable bundles that can be:

```bash
mvmctl machine run workload.mvmpkg -- ./app
```

This is in follow-up work; the current path is image-based (OCI image refs or `mvm.toml` → Nix builds).

### Platform-Specific Installers

#### Windows

Use [`rust-mingw`](https://github.com/nim-lang/cqueues/tree/master/cqueues-platform/src/platform/windows) for cross-compilation, then distribute via `.zip` (no `.tar.gz` — Windows expects zip for archives).

### Additional features

- **Uninstall**: add `MVM_UNINSTALL=1` to the installer to remove `mvmctl` and related files
- **Completions**: auto-generate and install shell completions (`bash`, `zsh`, `fish`) during install
- **Man pages**: optionally install generated man pages to `--prefix/share/man`
- **AppImage**: Linux portable format for environments without `.local/bin` in PATH
- **Flatpak/Snap**: For Linux distros that prefer sandboxed containerized installs

</content>
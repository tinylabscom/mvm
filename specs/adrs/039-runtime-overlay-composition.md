---
title: "ADR-039: Runtime overlay composition — transparent dev-rich vs prod-slim images"
status: Proposed
date: 2026-05-08
related: ADR-002 (security posture), ADR-005 (libkrun/libkrun pivot), plan 61-runtime-overlay-composition-and-billing
---

## Status

Proposed. Implementation sequenced in plan 61.

## Context

Two features need to coexist:

1. **A slim, secure production rootfs** — minimal attack surface, dm-verity-able, signed, hash-stable, suitable for the seven security claims of ADR-002.
2. **A fully-featured dev experience** — bash, coreutils, debugging tools (strace, tcpdump, gdb), interactive shell, the things a developer expects when they `mvmctl dev` into a microVM.

Post-Lima (ADR-005), `mvmctl dev` boots a real microVM via apple-container (macOS 26+) or libkrun (Linux). So whatever tools the developer uses live *inside* a microVM. The question is **how to put them there without compromising claim #1**.

User constraint, stated explicitly: "the tooling needs to be transparent to the user. This library/repo should be able to determine what needs to be in the binary in which what context the user is operating in." This rules out:

- A `debugTools = "basic" | "full"` knob on `mkGuest` — pushes the choice onto the user.
- A `.dev` flake output convention alongside `.default` — same problem.
- Per-purpose catalog entries (`foo`, `foo-dev`) — user-visible variant taxonomy.
- mvm rewriting / extending the user's flake at evaluation time — slow, brittle (Nix surprises), ties debug freshness to user `nix build`.

The "rootless vs busybox containers" framing the question began with is a category error: every mvm image is already rootless-by-construction (W2.1–W2.4) and busybox-based by default (`mkGuest`). The real axis is *what extra tools live in the rootfs at boot*, decided per invocation.

## Decision

**One canonical artifact (the workload). One mvm-shipped curated dev-tools overlay. Composition picked by command at runtime.**

### What the user writes

Exactly one thing in their flake — the workload:

```nix
packages.aarch64-darwin.default = mvm.lib.aarch64-darwin.mkGuest {
  entrypoint.command = "/usr/local/bin/myservice";
  packages = [ pkgs.myservice ];
};
```

No `.dev` output. No `devExtras`. No `debugTools` knob. No `dev=true`. The workload artifact is the prod artifact: signed, dm-verity-able, hash-stable.

### What mvm ships

A curated dev-tools overlay — a small versioned ext4 image (~30–50 MB), built by mvm CI per arch, fetched and hash-verified at runtime. Contents target the 80% debugging case:

- bash + bash-completion
- coreutils, util-linux, busybox-extras
- curl, wget, jq, less, vim-tiny
- strace, lsof, tcpdump, dig
- htop, procps
- git (small)

**Versioning**: pinned to mvmctl release. Cached at `~/.mvm/dev/overlay/v<mvmctl-version>/<arch>.ext4`. Hash-verified using the W5.1 verifier (cosign + SHA-256), reused from the prebuilt-image fetcher.

### Composition by command

| Command | Rootfs composition | Entrypoint behavior |
|---|---|---|
| `mvmctl run` | workload only | as declared (sealed) |
| `mvmctl run --debug` | workload + overlay | as declared, PTY console available |
| `mvmctl dev` | workload + overlay | drops into `/bin/bash` (overlay-provided) |
| `mvmctl dev --run-service` | workload + overlay | runs declared entrypoint + side-shell via `mvmctl console` |
| `mvmctl debug <vm>` | live-attach overlay to running VM | PTY console, no entrypoint change |

The user types `mvmctl dev` against any project — even one that only declared a sealed workload — and gets a usable shell with debugging tools. Zero opt-in. Zero parallel images.

### Mount mechanics

The overlay is attached as an additional virtio-blk disk (Apple Virtualization on macOS, libkrun on Linux). At boot, the workload's init script (`nix/lib/mk-guest.nix`'s embedded init) detects the overlay disk by label, mounts it RO at `/usr/dev`, and prepends `/usr/dev/bin` to `PATH`. Mode 0555. The workload's own paths and binaries are untouched.

For `mvmctl debug <vm>` (live attach), the runtime hot-attaches the overlay disk at the hypervisor level. Apple Virtualization supports virtio-blk hot-add; libkrun does not yet — first cut falls back to "stop, restart with overlay attached, restore state" with a clear warning.

`mvmctl dev` overrides the workload's declared entrypoint to `/bin/bash` via kernel cmdline (`mvm.entrypoint=/bin/bash`). The init script honors this when the overlay is mounted. `--run-service` omits the override.

## Consequences

**Positive:**
- **Transparent**: user declares a workload, types a command, gets the right thing. No flake-level dev/prod split, no knobs.
- **Honest about prod**: workload rootfs is byte-identical between `mvmctl run` and `mvmctl dev`. SHA-256 of workload artifact does not change.
- **Single security floor**: W2.x (rootless, RO `/etc`, setpriv, seccomp) applies regardless of overlay presence. Overlay can only add files, not grant privileges.
- **W3 verified boot preserved**: workload rootfs verifies under its own dm-verity roothash. Overlay has its own roothash. Separate block devices = no rootfs-hash drift.
- **W4.3 unaffected**: `prod-agent-no-exec` CI lane gates the guest *agent*; the overlay is rootfs-side.
- **CI surface bounded**: one workload artifact path through CI, plus one overlay artifact (per arch). No combinatorial dev/prod-flavored variants.

**Negative:**
- **Overlay update cadence pinned to mvmctl**: a CVE in (say) `curl` on the overlay ships its fix on the next mvmctl release. Acceptable for dev-only scope; if a critical CVE lands mid-cycle, users can `MVM_OVERLAY_VERSION=<patched>` to override.
- **libkrun live-attach is deferred**: `mvmctl debug <vm>` falls back to stop/restart on Linux until libkrun upstream supports virtio-blk hot-add.
- **No project-specific dev tools**: a Postgres workload that wants `psql` in the dev shell either adds it to `packages` (and accepts prod-bloat) or lives without it. If this friction is real, a future ADR can add a secondary per-project overlay.

**Neutral:**
- Catalog (`mvm-core::catalog::CatalogEntry`) stays purpose-agnostic. No dev/prod taxonomy in the catalog.
- The existing `dev-shell` cargo feature on the guest agent (gating `do_exec`, per W4.3) is unrelated and stays as-is.

## Alternatives considered

**`debugTools = "basic" | "full"` knob on `mkGuest`** — rejected. Violates the transparency constraint; user has to choose at flake-authoring time.

**`.dev` flake output convention** — rejected. Same problem; user has to declare both `default` and `dev` outputs and remember which `mvmctl` command builds which.

**Two pre-built variants per catalog entry** — rejected. Doubles CI surface, reopens W4.3 audit per variant, expands drift risk.

**mvm rewrites the user's flake at eval time to add packages** — rejected. Brittle (Nix evaluation surprises, cross-system targets, store path interactions); slower (per-user `nix build` for the dev variant); ties dev tooling freshness to the user's build cache rather than to mvm releases.

**OverlayFS instead of additional disk + RO mount** — considered. Overlay would need a writable upper layer (tmpfs is fine), which is fine for dev but adds an init-script complexity and slightly more boot cost. Pure RO secondary disk + `PATH` prepend is simpler and sufficient for the 80% case (developers don't typically write into `/usr/dev`).

## Threat model impact

- **No rootfs hash drift**: prod artifact is the same bytes whether or not the overlay is attached. The dm-verity check covers only the workload rootfs; the overlay is verified separately by its own roothash.
- **Capability containment**: the overlay can add binaries but not grant capabilities. setpriv `--bounding-set=-all --no-new-privs` (W2.3) is set per-service in init *after* the overlay mounts. A SUID binary in the overlay would be neutered by `--no-new-privs`.
- **Live-attach trust**: `mvmctl debug <vm>` requires host-side authority to invoke. The hypervisor enforces who can attach disks; the running VM cannot self-attach. No new vsock RPC for disk attach.
- **Audit**: every overlay attach emits a `DiskAttached { kind: Overlay }` usage event (per ADR-040), making the dev/debug path observable in the audit log.

## Compliance impact

- **SOC 2**: positive. The dev/prod boundary is enforced by a runtime-determined invariant (overlay never present in `mvmctl run`) rather than a build-time convention that can drift.
- **CIS**: neutral — adds no new privileged components.

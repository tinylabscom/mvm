# ADR-030: libkrun is the macOS execution and builder substrate; host Nix is never used

## Status

Accepted.

## Context

macOS exposes no `/dev/kvm`; running a Linux `nix build` or a Linux
workload from macOS needs some Linux execution substrate underneath it.
mvm does not shell out to a host `nix` binary and does not trust a
host-configured Nix daemon or remote builder for any of its own build or
run paths — every Nix evaluation happens inside a VM mvm itself
launched, so the same `mvmctl` binary produces the same artifacts
regardless of what the host happens to have installed.

## Decision

1. **libkrun is the macOS 13–25 default execution and builder backend**,
   and an available Linux backend. It drives Hypervisor.framework
   directly, giving a macOS host a native Linux guest with no
   intermediate general-purpose VM in the path. HVF is the macOS 26+
   Apple Silicon default; libkrun is its fallback and remains the
   pre-26 default (the full backend matrix and selection ladder are
   ADR-007's decision, not re-derived here).
2. **There is no intermediate Linux dev-VM hop on the macOS path.** A
   guest action goes `host → libkrun/HVF guest → workload`, never
   through a second general-purpose Linux VM in between.
3. **Host Nix is never used by `mvmctl`, even when present on the
   host.** `mvmctl` does not shell out to a host `nix` binary, does not
   consult a host-configured Nix remote-builder setting, and does not
   honor a `nix-daemon` URL in any code path. `xtask check-no-host-nix`
   enforces this mechanically in CI. Every Nix evaluation runs inside
   the builder VM (selected per ADR-007's `BuilderVm` ladder) that
   `mvmctl` itself launches.
4. **A source checkout never depends on a downloaded, mvm-published
   artifact for any image it builds.** Both the builder-VM image
   (`nix/images/builder-vm/`) and every user-facing image build locally
   from the in-repo flakes whenever `mvmctl` runs from a source
   checkout. The mvm-published GitHub-release prebuilts exist only for
   end-user, non-source-checkout installs.

## Consequences

Deterministic behavior across contributor machines: a contributor with
host Nix installed sees identical `mvmctl` behavior to one without, and
macOS has no extra VM hop to reason about beyond the one guest libkrun
or HVF already runs.

`mvmctl` owns its own Linux-builder bootstrap end to end rather than
delegating to any existing host-Nix remote-builder convention — that
bootstrap path is mvm's own maintenance burden, not an integration with
external tooling.

This ADR governs the execution substrate (libkrun/HVF, no host Nix, no
intermediate VM) and does not restate which specific backend runs a
given workload or build — that selection logic is ADR-007's decision.
It also does not restate how a user-supplied OCI image gets turned into
a bootable rootfs — that is ADR-017's decision and is unchanged by this
one.

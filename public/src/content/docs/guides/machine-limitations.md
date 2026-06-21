---
title: Machine Limitations & Scope
description: What the mvmctl machine surface does and does not do — network protocol scope, volumes, SSH-agent, macOS requirements, GPU, and architecture support.
---

`mvmctl machine` is a real microVM, not a container — so its boundaries are
different from what a Docker-shaped mental model expects. This page is the
explicit "what you do not get by default" list, kept beside the
[scenarios guide](/getting-started/machine-scenarios/) so you never have to
infer a stronger guarantee than mvm actually provides.

## No host Nix, ever

Beginner machine workflows never require host Nix, and `mvmctl` never shells out
to a host `nix` binary. OCI-backed machines (`--image`) don't touch Nix at all;
flake-backed builds run Nix **inside** the builder VM. If a doc or error implies
host Nix is a prerequisite for running a machine, that is a bug — file it.

## Network protocol scope

Default egress is **deny-all**. You opt in per run:

- `--net` enables dev-tier outbound networking.
- `--allow-host <host[:port]>` narrows egress to an explicit allow-list.

What rides that path:

- **TCP** egress to admitted destinations, and **DNS** (UDP/53) through the
  gateway's resolver.
- **Not raw ICMP.** `ping` does not work from inside the guest — the userspace
  gateway forwards TCP and DNS, not raw ICMP. A failed `ping` is not a
  networking fault; test reachability with a TCP client (`curl`, `nc`).
- **Never SSH.** `--allow-host <host:22>` is refused, and TCP/22 is denied even
  under broad egress. SSH into a microVM is banned by design (see
  [SSH-agent](#ssh-agent-dev-tier-only) for the one socket-forwarding exception).

Egress is enforced identically across backends — the policy and its
allow/deny effect are the same value whether the enforcer is Firecracker's
nftables or the libkrun/Vz gateway. See
[Network egress policy](/guides/network-egress-policy/) for the full model.

## Volume shapes

- Host directory shares: `--add-dir HOST:GUEST[:MODE]`. `MODE` defaults to
  `ro`; `rw` requires `--profile dev` (or `permissive`) — a sealed prod machine
  cannot be handed a writable host share by default.
- Persistent disk volumes are declared in an `mvm.toml` / `Mvmfile.toml`
  manifest, not as ad-hoc flags.
- Shares are explicit. There is no implicit host-filesystem visibility — a guest
  sees only the directories you name (security claim 1).

## SSH-agent (dev-tier only)

`ssh_agent` forwards **only** the host's `SSH_AUTH_SOCK` Unix socket into the
guest. Prerequisites and bounds:

- Dev-capable profile only — a sealed prod machine cannot enable it.
- `SSH_AUTH_SOCK` must be set on the host and point at a real Unix socket.
- It forwards the socket, nothing else. No private key files, `~/.ssh`,
  known-hosts material, or SSH config is ever copied or mounted.

## macOS requirements

- **macOS 26+ Apple Silicon** uses the Vz (Virtualization.framework) backend,
  which ships with the OS — no extra libraries. The per-VM supervisor binaries
  are code-signed at launch; an unsigned or entitlement-stripped build will be
  refused by the OS, so run a signed `mvmctl` (the release binary is signed).
- **macOS 13–25 Apple Silicon** uses libkrun and needs the Homebrew trio
  (`slp/krun/libkrun`, `libkrunfw`, `gvproxy`).

## GPU

No GPU. There is no GPU passthrough and no virtio-gpu in the default machine
surface — GPU acceleration is not available. Do not assume CUDA/Metal access
inside a machine.

## Architecture support

- **Host:** macOS Apple Silicon (arm64), or Linux x86_64 / aarch64 with
  `/dev/kvm`.
- **Guest:** the guest runs the host's architecture — there is no cross-arch
  emulation. An `arm64` host runs `arm64` guests; an `x86_64` host runs
  `x86_64` guests. An image built only for a foreign architecture will not boot.

## Portable artifacts are preview

`machine check-artifact` previews whether a portable `.mvm` artifact would be
admitted (signature / hash / format / host-arch checks) without booting. The
end-to-end `machine pack` and `machine run <artifact>` workflow is **not yet
shipped** — use the lower-level `mvmctl artifact` verbs until it lands.

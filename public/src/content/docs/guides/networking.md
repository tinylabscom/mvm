---
title: Networking
description: Network layout and connectivity in mvmctl microVMs.
---

## Network by Backend

Networking differs by backend:

| Backend | Network Type | Guest IP | Host Access |
|---------|-------------|----------|-------------|
| Firecracker (Linux native) | TAP device | 172.16.0.2/30 | Direct via TAP |
| Apple Container | vmnet | DHCP-assigned | Via vmnet bridge |
| libkrun (macOS) | TSI (transparent socket impl) | host-loopback | Via per-port vsock listeners |
| microvm.nix | TAP device | 172.16.0.2/30 | Direct via TAP |
| Docker | Docker bridge | Docker-assigned | Via Docker port mapping |

## Firecracker Network Layout

```
Firecracker microVM (172.16.0.2/30, eth0)
    | TAP interface (tap0)
Linux host (172.16.0.1/30, tap0)  --  iptables NAT  --  internet
```

On Linux with `/dev/kvm`, Firecracker boots directly on the host — no VM hop. The TAP device connects the microVM to the host network namespace and gets NAT'd to the internet. On macOS hosts, networking is backend-specific: Apple Container uses vmnet bridge mode; libkrun uses TSI (transparent socket impl) where outbound TCP/UDP appears as host-side socket calls.

## Port Forwarding

Forward guest ports to the host with `-p`:

```bash
mvmctl up --flake . -p 8080:8080
mvmctl up --flake . -p 3000:3000 -p 8080:8080   # multiple ports

# Or forward after boot
mvmctl forward my-vm -p 3000:3000
```

## vsock Communication

MicroVMs don't use networking for host communication -- they use **vsock**:

| Port | Protocol | Purpose |
|------|----------|---------|
| 5252 | Length-prefixed JSON | Guest agent (health checks, status, snapshot lifecycle) |

The host connects by writing `CONNECT 5252\n` to the vsock socket and reading `OK 5252\n`. All requests are request/response pairs. vsock is supported on Firecracker, Apple Container, and microvm.nix backends. Docker uses a unix socket instead.

For Firecracker, the host-side vsock UDS is scoped to the running VM directory:
`<vm-dir>/runtime/v.sock`. It is not a global or master socket. `mvmctl up`
reserves the VM name before launch and rejects duplicate active/reserved names,
because that name is the identity used to resolve the per-VM communication
channel.

## No SSH

MicroVMs have **no SSH access** by design. Communication is exclusively via vsock. This eliminates:

- SSH key management
- SSH daemon attack surface
- Network-based authentication bypasses

For debugging dev builds, use `mvmctl machine logs <name>` to view guest console output, or `mvmctl machine logs <name> -f` to follow in real time.

## Network Policies

By default, microVMs have unrestricted internet access via NAT. Use `--network-preset` or `--network-allow` to restrict outbound traffic:
For a deny-first review workflow, see [Network egress policy](/guides/network-egress-policy/).

```bash
# Built-in presets
mvmctl up --flake . --network-preset dev          # GitHub, npm, PyPI, crates.io, OpenAI, Anthropic
mvmctl up --flake . --network-preset registries    # Package registries only
mvmctl up --flake . --network-preset none          # No outbound (DNS only)

# Explicit allowlist
mvmctl up --flake . \
    --network-allow github.com:443 \
    --network-allow api.openai.com:443
```

Network policies are enforced via iptables FORWARD rules on the bridge interface (Firecracker backend on Linux). DNS (port 53) is always allowed so domain resolution works. Rules are automatically cleaned up when the VM stops. On macOS backends, policies are enforced at the host-side TSI/vmnet layer rather than via iptables.

**Built-in presets:**

| Preset | Allowed Domains |
|--------|----------------|
| `unrestricted` | All traffic (default) |
| `dev` | github.com, api.github.com, registry.npmjs.org, crates.io, static.crates.io, index.crates.io, pypi.org, files.pythonhosted.org, api.openai.com, api.anthropic.com |
| `registries` | registry.npmjs.org, crates.io, static.crates.io, index.crates.io, pypi.org, files.pythonhosted.org |
| `none` | No outbound traffic (DNS only) |

## Seccomp Profiles

Restrict the syscalls available inside the microVM with `--seccomp`:

```bash
mvmctl up --flake . --seccomp standard    # File ops + process control (no sockets)
mvmctl up --flake . --seccomp network     # Standard + socket syscalls
mvmctl up --flake . --seccomp minimal     # Signals, pipes, timers only
```

The seccomp manifest is written to the config drive as `seccomp.json` for the guest init to apply via `prctl(PR_SET_SECCOMP)`. Tiers are cumulative — each includes all syscalls from lower tiers.

The same tier is also copied into the signed `ExecutionPlan` admission profile. That profile is audit/provenance data: it binds the declared workload intent to the chosen seccomp tier, policy refs, secret-release posture, and audit labels. The actual syscall enforcement remains the guest seccomp manifest generated from `mvm-security`; the plan-side tier exists so `mvmctl audit verify` can prove which posture was admitted.

| Tier | Syscalls | Use Case |
|------|----------|----------|
| `essential` | ~40 | Process bootstrap only (linker, glibc init) |
| `minimal` | ~110 | + signals, pipes, timers, process control |
| `standard` | ~140 | + file manipulation, fs operations |
| `network` | ~160 | + sockets, connect, bind (for networked agents) |
| `unrestricted` | all | No restrictions (default) |

## DNS

The guest's `/etc/resolv.conf` is configured at build time to use the host's DNS resolver. Internet access works out of the box through the NAT chain (Firecracker), vmnet (Apple Container), or Docker bridge networking (Docker).

### Local addon DNS (opt-in)

When a guest declares one or more local development addons via the
`addon_dns_zone` config-disk field (see
`specs/contracts/local-addon-dns.md`), `/init` activates the baked
in-guest resolver `mvm-addon-dns`:

1. The pre-existing `/etc/resolv.conf` is snapshotted into
   `/run/mvm/upstream-resolv.conf` so the resolver has an explicit
   upstream chain. This must happen before the resolv.conf rewrite or
   the resolver would recurse into itself.
2. `/etc/resolv.conf` is bind-mounted from `/run/mvm/resolv.conf` and
   set to `nameserver 127.0.0.1` + `nameserver ::1`.
3. `mvm-addon-dns` is forked under `setpriv` to the agent uid with
   only `CAP_NET_BIND_SERVICE` as an ambient capability (no other
   privilege is granted). The supervisor itself rejects any non-loopback
   bind address and refuses upstreams that point back at its own
   listener.

The resolver answers exact configured addon hostnames authoritatively
and forwards every other name (including sibling names in the same
parent domain) to the upstream snapshot. SIGHUP reloads the zone file
without re-binding sockets; in-flight UDP queries are never dropped.

Guests that declare no addons skip the entire bootstrap, so
`/etc/resolv.conf` stays byte-for-byte the build-time default.

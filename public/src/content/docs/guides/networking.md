---
title: Networking
description: Network layout and connectivity in mvmctl microVMs.
---

## Network by Backend

Networking differs by backend:

| Backend | Network Type | Guest IP | Host Access |
|---------|-------------|----------|-------------|
| Firecracker (Linux native) | TAP device | 172.16.0.2/30 | Direct via TAP |
| HVF (macOS 26+, default) | vsock-only | — | Guest I/O over vsock; no guest NIC |
| Vz (macOS 26+, opt-in) | vmnet by default; vsock-only for OCI egress | DHCP-assigned when vmnet is present | Via vmnet bridge, or host-vsock proxy on the NIC-less OCI path |
| libkrun (macOS) | TSI (transparent socket impl) | host-loopback | Via per-port vsock listeners |
| microvm.nix | TAP device | 172.16.0.2/30 | Direct via TAP |

## Firecracker Network Layout

```
Firecracker microVM (172.16.0.2/30, eth0)
    | TAP interface (tap0)
Linux host (172.16.0.1/30, tap0)  --  iptables NAT  --  internet
```

On Linux with `/dev/kvm`, Firecracker boots directly on the host — no VM hop. The TAP device connects the microVM to the host network namespace and gets NAT'd to the internet. On macOS hosts, networking is backend-specific: the default HVF backend is vsock-only (guest I/O crosses vsock, no guest NIC); Vz (opt-in) uses vmnet bridge mode; libkrun uses TSI (transparent socket impl) where outbound TCP/UDP appears as host-side socket calls.

## Port Forwarding

`machine run` does not publish ports directly. Boot a named machine, then map
guest ports to the host with `machine forward`:

```bash
mvmctl machine run --flake . --name my-vm -d
mvmctl machine forward my-vm -p 8080:8080
mvmctl machine forward my-vm -p 3000:3000 -p 8080:8080   # multiple ports
```

## vsock Communication

MicroVMs don't use networking for host communication -- they use **vsock**:

| Port | Protocol | Purpose |
|------|----------|---------|
| 5252 | Length-prefixed JSON | Guest agent (health checks, status, snapshot lifecycle) |

The host connects by writing `CONNECT 5252\n` to the vsock socket and reading `OK 5252\n`. All requests are request/response pairs. vsock is supported on Firecracker, HVF, Vz, and microvm.nix backends.

For Firecracker, the host-side vsock UDS is scoped to the running VM directory:
`<vm-dir>/runtime/v.sock`. It is not a global or master socket. `mvmctl machine run`
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

By default, a workload gets **no outbound network** (deny-all egress). Opt in
with `--net` (broad dev egress) or narrow to specific hosts with `--allow-host
HOST[:PORT]` (repeatable; `--allow-host` wins over `--net`). For a deny-first
review workflow, see [Network egress policy](/guides/network-egress-policy/).

```bash
# Broad dev egress (DNS + general outbound)
mvmctl machine run --flake . --net

# Narrow allowlist — only these hosts (PORT defaults to 443)
mvmctl machine run --flake . \
    --allow-host github.com:443 \
    --allow-host api.openai.com:443
```

`--allow-host` is a **TCP host:port** policy, not a general-purpose network
grant. A bare host defaults to port `443`, so `--allow-host google.com` means
"allow TCP to `google.com:443`". On OCI-backed runs that request outbound
egress (`--net` or `--allow-host`) — both transient `machine run --image ...`
and persistent `machine run -d --image ...` / `machine start <name>` for an
image-backed machine — `mvmctl` now selects only backends that can keep the
guest **NIC-less** and proxy outbound traffic over the host-vsock egress
endpoint. The injected guest runtime starts `mvm-egress-client` and the runtime
sets standard proxy env vars to its loopback SOCKS listener automatically.
Today that contract is provided by `hvf`; if no available backend can provide
it, the start is refused up front instead of silently degrading to a
guest NIC. This enables tools such as `curl` and `wget`; it does **not** add
raw ICMP, so `ping google.com` is still expected to fail. Use an HTTP/TCP probe
as the smoke test instead.

Network policies are enforced via iptables FORWARD rules on the bridge interface (Firecracker backend on Linux). DNS (port 53) is always allowed so domain resolution works. Rules are automatically cleaned up when the VM stops. On macOS backends, policies are enforced at the host-side layer rather than via iptables.

## Security Profiles

Pick the guest's security posture with `--profile`. It governs env injection and
host-share permissions, and selects the seccomp posture applied inside the guest:

```bash
mvmctl machine run --flake . --profile restrictive   # no env injection, no host shares
mvmctl machine run --flake . --profile standard      # explicit env; read-only host shares (default)
mvmctl machine run --flake . --profile dev           # dev ergonomics: explicit env + writable host shares
```

The resolved profile is copied into the signed `ExecutionPlan` admission record — audit/provenance data binding the declared workload intent to the chosen posture, policy refs, secret-release posture, and audit labels — so `mvmctl trust audit verify` can prove which posture was admitted.

| Profile | Env injection | Host shares |
|---------|---------------|-------------|
| `restrictive` | none | none |
| `standard` (default) | explicit `-e KEY=VALUE` | read-only |
| `dev` | explicit `-e KEY=VALUE` | read-write allowed |
| `permissive` | explicit | read-write (requires `MVM_ACK_PERMISSIVE_RUN=1`) |

## DNS

The guest's `/etc/resolv.conf` is configured at build time to use the host's DNS resolver. Internet access works out of the box through the NAT chain (Firecracker), vmnet (Vz).

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

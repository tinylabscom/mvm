---
title: Networking
description: Network layout and connectivity in mvmctl microVMs.
---

## Network by Backend

Networking differs by backend:

| Backend | Network Type | Guest IP | Host Access |
|---------|-------------|----------|-------------|
| Firecracker (Linux native) | NIC-less vsock egress | — | Host endpoint; default-deny policy gate |
| HVF (macOS 26+, default) | NIC-less vsock egress | — | Host endpoint; default-deny policy gate |
| libkrun (macOS) | NIC-less vsock egress | — | Host endpoint; default-deny policy gate |
| QEMU (Linux dev/test) | Rootless user-mode virtio | 10.0.2.15/24 | QEMU user-mode network; outside production claims |

## Production Network Layout

```
MicroVM workload (no guest NIC)
    | loopback SOCKS5 TCP CONNECT / UDP ASSOCIATE
    | controlled DNS / mediated ping / typed connectors
    | authenticated FlowMux on vsock port 5253
Per-VM mvm-network-endpoint
    | signed policy + shared limits + host DNS + payload-free audit
    | opaque TCP/UDP or explicitly typed transformation
Internet or an admitted host-owned ingress listener
```

Firecracker, HVF, and libkrun production workloads do not expose a guest NIC.
Proxy-aware TCP applications use the injected loopback SOCKS5 listener; UDP
applications use SOCKS5 `UDP ASSOCIATE`. The host resolves names, applies the
signed allow/deny policy separately for TCP and UDP, and opens the external
socket only after admission. This keeps DNS and egress on the same auditable
host seam.

Raw ICMP and arbitrary non-proxy-aware sockets are intentionally not available
on this path. `ping` is therefore not a valid egress smoke test; use an HTTP,
TCP, or SOCKS5-aware UDP probe.

## Rootless QEMU transparent networking

Linux users who need ordinary guest TCP and UDP sockets without configuring a
host TAP device can opt into QEMU's dev/test backend:

```bash
mvmctl machine run --hypervisor qemu --image alpine --net -- \
  sh -c 'wget -qO- https://example.com'
```

QEMU uses the same NIC-less FlowMux path as every production backend. The
workload reaches admitted destinations through the guest loopback adapters;
the backend does not attach `virtio-net-pci`, SLIRP, TAP, or a host bridge.

## Port Forwarding

Declare ingress before boot so the exact host listener and guest-loopback
target are covered by the signed admission plan:

```bash
mvmctl machine run --flake . --name my-vm --port 8080:8080
mvmctl machine run --flake . --name my-vm -p 3000:3000 -p 8080:8080
```

`--port` makes the machine persistent and the per-VM FlowMux endpoint owns the
listener for the machine lifecycle. Dynamic forwarding after admission is
refused; update the machine declaration and restart when the mapping changes.

## vsock Communication

MicroVMs don't use networking for host communication -- they use **vsock**:

| Port | Protocol | Purpose |
|------|----------|---------|
| 5252 | Length-prefixed JSON | Guest agent (health checks, status, snapshot lifecycle) |
| 5253 | Authenticated FlowMux frames | TCP, UDP, DNS, mediated ping, typed connectors, declared ingress |

The host connects by writing `CONNECT 5252\n` to the vsock socket and reading `OK 5252\n`. All requests are request/response pairs. vsock is supported on Firecracker, HVF, and microvm.nix backends.

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
That contract is provided by Firecracker, HVF, and libkrun. If no available
backend can provide it, the start is refused up front instead of silently
degrading to a guest NIC. This enables tools such as `curl` and `wget` through
the loopback adapters. General raw ICMP remains unsupported; the injected
mediated ping helper is the only ICMP-shaped surface.

For a repeatable live proof on macOS Apple Silicon, run:

```bash
just hvf-oci-allow-host-smoke
```

That wrapper packages both the exact CLI path
`mvmctl machine run --hypervisor hvf --image alpine --allow-host google.com -- ps aux`
and a second admit/deny relay proof that demonstrates allowed traffic is
reachable while a non-admitted destination is refused, all without a guest NIC.

For production NIC-less backends, policies are enforced by the host endpoint
and the shared egress gate rather than guest firewall rules. QEMU's user-mode
network is a dev/test convenience and is not a substitute for that production
policy boundary.

## Measuring the paths

Run the opt-in local benchmark to compare direct kernel sockets with the
SOCKS5-framed relay overhead for TCP and UDP:

```bash
MVM_EGRESS_BENCH=1 cargo test --test egress_path_bench -- --nocapture
```

The benchmark measures local transport overhead only; it does not represent a
particular hypervisor, VPN, or Internet route.

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

Production guest DNS is backend-independent. The loopback DNS stub sends a
typed FlowMux request to the same per-VM endpoint used by TCP, UDP, ingress,
and connectors. The host resolver filters private, link-local, loopback,
metadata, and rebinding answers before pinning an admitted result and emitting
a payload-free audit record. A workload with no DNS grant has no fallback
resolver or guest NIC.

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

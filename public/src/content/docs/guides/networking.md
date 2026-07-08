---
title: Networking
description: Network layout and connectivity in mvmctl microVMs.
---

## Workload Egress Contract

For **workload** microVMs, networking is a backend capability contract, not a
backend-specific escape hatch:

- `--net` and `--allow-host` select **policy only**.
- A workload boot that carries network policy requires backend capabilities
  `vsock + no_guest_nic + host_vsock_proxy`.
- If the selected backend cannot satisfy that contract, `mvmctl` refuses the
  boot instead of silently enabling guest NIC, TAP, gvproxy, passt, vmnet, or
  any other backend-specific L2/L3 dataplane for workload traffic.

Current workload-backend status:

| Backend | Workload egress status |
|---------|------------------------|
| HVF (macOS 26+, default) | Supported. Guest I/O crosses the host vsock gate; no guest NIC. |
| Firecracker (Linux/KVM) | Supported. Workload egress is guest→vsock→host gate; no guest NIC or TAP dataplane. |
| libkrun (macOS 13-25 & Linux) | Supported. Workload egress is guest→vsock→host gate; no guest NIC or gvproxy/passt dataplane. |
| qemu | Dev/test only; not a workload backend. |

Builder-VM and other internal build networking are separate implementation
details. The contract above is specifically for **workload** microVM egress.

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

The host connects by writing `CONNECT 5252\n` to the vsock socket and reading `OK 5252\n`. All requests are request/response pairs. vsock is supported on Firecracker, HVF, libkrun, and qemu.

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
HOST[:PORT]` (repeatable; `--allow-host` wins over `--net`). These flags select
the admitted egress policy only; they do **not** enable guest networking on an
unsupported backend. For a deny-first review workflow, see
[Network egress policy](/guides/network-egress-policy/).

```bash
# Broad dev egress (DNS + general outbound)
mvmctl machine run --flake . --net

# Narrow allowlist — only these hosts (PORT defaults to 443)
mvmctl machine run --flake . \
    --allow-host github.com:443 \
    --allow-host api.openai.com:443
```

On supported workload backends, policy enforcement happens at the host-side
vsock gate. DNS is mediated by the same gate; no workload guest NIC is involved.

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

The guest's `/etc/resolv.conf` is configured at build time to use the host's
resolver chain. On supported workload backends, DNS egress crosses the same
host-side vsock gate as every other outbound flow.

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

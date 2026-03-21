---
title: Networking
description: Network layout and connectivity in mvmctl microVMs.
---

## Network by Backend

Networking differs by backend:

| Backend | Network Type | Guest IP | Host Access |
|---------|-------------|----------|-------------|
| Firecracker (Linux) | TAP device | 172.16.0.2/30 | Direct via TAP |
| Firecracker (Lima) | TAP in Lima VM | 172.16.0.2/30 | Via Lima NAT |
| Apple Container | vmnet | DHCP-assigned | Via vmnet bridge |
| microvm.nix | TAP device | 172.16.0.2/30 | Direct via TAP |
| Docker | Docker bridge | Docker-assigned | Via Docker port mapping |

## Firecracker Network Layout

```
Firecracker microVM (172.16.0.2/30, eth0)
    | TAP interface (tap0)
Lima VM (172.16.0.1/30, tap0)  --  iptables NAT  --  internet
    | Lima virtualization
Host (macOS / Linux)
```

The microVM has internet access via NAT through the Lima VM (or directly on native Linux). The TAP device connects the microVM to the host network namespace.

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
| 52 | Length-prefixed JSON | Guest agent (health checks, status, snapshot lifecycle) |

The host connects by writing `CONNECT 52\n` to the vsock socket and reading `OK 52\n`. All requests are request/response pairs. vsock is supported on Firecracker, Apple Container, and microvm.nix backends. Docker uses a unix socket instead.

## No SSH

MicroVMs have **no SSH access** by design. Communication is exclusively via vsock. This eliminates:

- SSH key management
- SSH daemon attack surface
- Network-based authentication bypasses

For debugging dev builds, use `mvmctl logs <name>` to view guest console output, or `mvmctl logs <name> -f` to follow in real time.

## DNS

The guest's `/etc/resolv.conf` is configured at build time to use the host's DNS resolver. Internet access works out of the box through the NAT chain (Firecracker), vmnet (Apple Container), or Docker bridge networking (Docker).

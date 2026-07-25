# Plan 259 — User-Space MicroVM Outbound Networking via SOCKS5 Mirroring

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Ref:** [#1830](https://github.com/tinylabscom/mvm/issues/1830)  
**Status:** Proposal / Draft

## Context & Inspiration

Currently, providing internet connectivity to MicroVMs (e.g., Firecracker, Cloud Hypervisor) typically requires host-level elevated privileges to configure TAP interfaces, bridges, and complex iptables/nftables NAT rules.

In peer-to-peer systems like BitTorrent, Trackers and Magnet links decouple endpoint discovery from network topology:
- Trackers/DHT resolve abstract resource hashes into active peer addresses (IP:Port) without requiring direct network intimacy.
- Peers communicate through lightweight connection brokers or proxies (SOCKS5/HTTP) to traverse NATs and restrictive networks seamlessly.

We can apply a similar pattern to MicroVM internet access: routing guest traffic through a host-side SOCKS5 proxy/mirror over a lightweight transport (like vsock or a simple user-space VirtIO network stack) to achieve zero-config, rootless networking.

## The Problem

- **Root Privileges Required:** Standard microVM networking requires root or `CAP_NET_ADMIN` on the host to create TAP devices and configure routing.
- **Brittle Host Rules:** Host IP forwarding and NAT rules can conflict with local firewall policies, VPNs, or container runtimes (Docker/Podman).
- **Complex Multitenancy:** Isolating microVM traffic safely at Layer 2/3 requires tedious subnet management on the host.

## Proposed Solution

Implement a user-space SOCKS5 networking proxy for microVM guests that mimics tracker/proxy routing:

1. **Guest Layer (Transparent Client/Forwarder):**
   - A lightweight user-space network daemon (e.g., slirp4netns, gVisor netstack, or custom vsock-to-SOCKS5 forwarder) runs inside or alongside the VM.
   - Outbound TCP/UDP traffic from the guest is intercepted and wrapped into standard SOCKS5 requests.

2. **Host Layer (SOCKS5 Mirror / Tracker Broker):**
   - The host runs a local SOCKS5 proxy server listening either on localhost or over a UNIX socket / vsock channel.
   - The host proxy handles external DNS resolution and outbound connections on behalf of the MicroVM—acting like a "tracker" that resolves target hosts and proxies the data stream back into the VM.

```
[ MicroVM Guest App ]
       │ (e.g., HTTP/TCP)
       ▼
[ Guest User-Space Stack ] ──(SOCKS5 via vsock / TUN)──► [ Host SOCKS5 Mirror ] ──► [ Internet ]
```

## Key Benefits

- **Rootless Operation:** No host bridge creation, TAP devices, or sudo required to give VMs internet access.
- **VPN/Host Aware:** Guest traffic naturally follows the host’s active routing table (including host-level VPNs and proxies).
- **Isolation by Default:** VMs cannot probe or scan the host's physical LAN unless explicitly permitted by the host SOCKS5 proxy rules.

## Implementation Tasks

- [ ] Evaluate existing user-space stacks (slirp4netns, gVisor/netstack, gost, or redsocks).
- [ ] Benchmark latency and throughput of standard TAP/NAT vs. vsock + SOCKS5 forwarding.
- [ ] Prototype transparent TCP and UDP (SOCKS5 UDP Associate) handling for guest workloads.
- [ ] Write integration docs for launching microVMs in non-root environments.

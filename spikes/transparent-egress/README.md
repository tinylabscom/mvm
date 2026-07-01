# Transparent egress over vsock — spike (ADR-100)

Proves that an **unmodified workload** doing an ordinary `connect()` (incl.
HTTP/HTTPS) — *no proxy env, no awareness* — reaches the network over **vsock** with
**no guest NIC**. The host side is the existing `EgressProxy` (claim-10 decide +
proxy), unchanged; everything here is the guest-side interception layer.

## How it works (mechanism (b) from ADR-100 — netfilter REDIRECT)

```
workload connect(realIP:port)               # unmodified app, no proxy env
  → default route via dummy0 (NIC-less; just gives connect() somewhere to route)
  → nat OUTPUT REDIRECT --to-ports 1080     # iptables, all TCP
  → tproxy on 127.0.0.1:1080
      getsockopt(SO_ORIGINAL_DST) = realIP:port   # the real target, transparently
      AF_VSOCK connect (host CID 2, EGRESS_PORT 5253)
      write "realIP:port\n"; splice both ways
  → host EgressProxy: claim-10 decide → open real TCP → proxy bytes
```

The kernel's own TCP stack terminates the workload's connection (so `tproxy` is
trivial + robust); `tproxy`'s upstream is AF_VSOCK, never TCP, so the REDIRECT rule
never catches its own egress. ADR-100 also describes mechanism (a), a TUN +
userspace netstack (smoltcp), which needs no netfilter; this spike uses (b) because
the kernel does the TCP.

## Components

- `tproxy.rs` — the transparent proxy (static musl): `SO_ORIGINAL_DST` → vsock.
- `tclient.rs` — an unmodified test workload: a plain `TcpStream::connect`, no proxy.
- `tinit.rs` — PID 1: brings up `lo` + a `dummy0` default route (NIC-less but
  routed), installs the nat REDIRECT, starts `tproxy`, runs `tclient`.
- `transparent-extras.fragment` — kernel config on top of
  `../kvm-x86-boot/microvm-x86_64.fragment`: the guest IP stack + netfilter REDIRECT
  + `CONFIG_FILE_LOCKING` (iptables locks `/run/xtables.lock`).

## Build + run (Linux x86_64 + /dev/kvm)

```sh
# kernel: thin microVM fragment + transparent extras
cd <linux-src> && make tinyconfig
./scripts/kconfig/merge_config.sh -m .config \
  microvm-x86_64.fragment transparent-extras.fragment
make olddefconfig && make -j"$(nproc)" bzImage

# guest binaries (static)
rustc --edition 2024 --target x86_64-unknown-linux-musl -O -o tinit  tinit.rs
rustc --edition 2024 --target x86_64-unknown-linux-musl -O -o tproxy tproxy.rs
rustc --edition 2024 --target x86_64-unknown-linux-musl -O -o tclient tclient.rs

# initramfs: /init=tinit, /tproxy, /tclient, /dev/{console,kmsg,null}, and the
# dynamic tools the guest execs — iproute2 `ip`, `iptables-legacy`, their ldd libs,
# and the xtables extension plugins (libxt_REDIRECT.so / libxt_tcp.so).
# Boot via the kvm-backend-egress example (host echo server + claim-10 gate).
```

Gotchas this spike pinned down (all real, all fixed above):
- cpio must include **directory entries** (`find . | cpio`), or the extractor skips
  files.
- userspace tty TX needs the serial IRQ (the VMM models a *polled* 16550), so the
  guest must log to `/dev/kmsg` (polled console), not a tty write (which blocks).
- virtio-mmio on x86 is discovered from the kernel cmdline (`virtio_mmio.device=`)
  only with `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y` (no DT/ACPI on x86).
- module params for a **loaded** module go to `finit_module`, not the kernel cmdline.
- the device IRQ must be **pulsed** on x86 IOAPIC (edge), or async replies are lost.
- iptables dlopens `libxt_REDIRECT.so` at runtime — ship the xtables plugin dir.
- iptables locks `/run/xtables.lock` → needs `CONFIG_FILE_LOCKING=y`.

## Status: live-proven

On a /dev/kvm box, a NIC-less guest's **plain `connect()`** round-tripped through the
vsock gateway: `tcp connected` + `reply: ping` in-guest, `egress allowed:
[<target>]` host-side. This is the prototype for ADR-100 migration step 4 (the
guest interception layer); productionizing means folding it into a guest helper
(and/or the TUN+netstack variant) + DNS-over-vsock + the UDP decision.

# Builder dependency installs leave through the vsock egress client (issue #3484)

`mvmctl deps install` ran its installer behind a guest-local allowlist proxy,
`mvm-egress-proxy`, which dialed upstream itself with `TcpStream::connect`.
The builder VM is NIC-less on every backend, so on libkrun that dial had no
route and installs could not fetch at all; any builder with a route would have
left past the host's egress gate. HVF and Firecracker refuse install jobs.

- The install arm of `mvm-host-vm-init` hands `uv` / `pnpm` the same proxy
  environment every flake build already gets (`VSOCK_EGRESS_PROXY_ENV`,
  `socks5h://127.0.0.1:1080`, the guest's vsock egress client), so an install
  reaches the network only over the `NetworkFlow` relay to the builder's host
  endpoint, whose `EgressGate` runs `trusted_build_egress()` plus the mandatory
  deny ranges. There is one builder egress path, not two.
- An install on a builder booted without `mvm.vsock_egress=1` is refused up
  front instead of reaching for a direct connection.
- In disk-transport mode the install arm now exports `/out` to the output
  device, as the flake arm already did; before, `result.json` died with the VM.
- Deleted as dead: the guest proxy lifecycles (`proxy.rs`), the iptables
  lockdown and per-job posture code (`network.rs`, inert with no NIC), the
  `vsock_proxy` CONNECT relay (it spoke a plaintext line protocol the FlowMux
  endpoint no longer serves), `iptables-legacy` in the builder image, and
  `mvm-egress-proxy` from both host-binary manifests, so it is neither embedded
  in `mvmctl` nor installed in a builder rootfs.
- `mvm-egress-proxy`'s source and cargo target stay for now: the image
  repository's host-binary script still compiles it by name, and its pinned
  `mvm` still lists it. It goes once that repository stops naming it.
- `check-single-network-path` gains a builder half: no builder code opens a TCP
  connection except the egress client's readiness probe or binds a listener,
  no host-binary manifest names the retired proxy, and the QEMU builder passes
  no NIC argument. `production_code` now blanks `#[cfg(test)]` items instead of
  truncating at the first one, so code after an inline test module is read.
  `check-mvm-host-binaries-sync` also holds `BUILDER_HOST_BINARIES` to the
  manifest.

Witnesses: `install_on_a_vsock_egress_builder_routes_through_the_egress_client`,
`install_on_a_builder_without_vsock_egress_is_refused`,
`installer_env_is_the_vsock_egress_env`,
`builder_egress_relays_an_admitted_flow_and_audits_a_refused_one` (real
`build_egress_gate(trusted_build_egress())` behind a real `FlowMuxAccept`: an
admitted flow is relayed and audited, cloud metadata is refused and audited, no
payload byte in the chain), and the new `check-single-network-path` unit tests.
Each was revert-checked: admitting an install without vsock egress, handing the
installer the old `http://127.0.0.1:8443` proxy, adding `-netdev` to the QEMU
builder, putting the retired proxy back in the manifest, and adding a
guest-local listener that dials upstream each turn the matching witness red.

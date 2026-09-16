# Firecracker serves builds (#3324)

Firecracker could bootstrap a builder image but not use it: `register_driver_builders`
returned `None` for it, so `--builder firecracker`, and so every Linux-with-KVM
host by auto-detect, refused ordinary builds by name.

## The resolver has nothing to bake

`fc_builder_image::resolve_fc_builder_image` returns
`builder_vm_cache_dir()/<arch>/{vmlinux, rootfs.ext4}` and the seeded closure
when present. The HVF resolver runs a patcher VM to inject `mvm-host-vm-init`;
Firecracker does not need to, because the builder-vm flake Stage 0 builds
already installs it at `/sbin/mvm-host-vm-init` — which is how libkrun has
always booted the same files. Kernel format stays `FcDriver`'s problem
(`ensure_fc_loadable_kernel`), the one place that knows what Firecracker loads.
A missing half refuses and says to run `mvmctl bootstrap`.

Builder shell jobs on Firecracker admit the current source image first, as
libkrun's do, so a stale image is rebuilt rather than run.

## What wiring it exposed

Reading the builder spec against `FcDriver` turned up three things that were
wrong on every driver-backed builder and invisible on HVF:

- **Egress direction.** The builder specs declared their `NetworkFlow` port
  `HostDials`. The guest dials. HVF ignores direction; Firecracker bridges only
  `GuestDials` ports (`wire_guest_dial_bridges`), so on Firecracker every
  substituter fetch would have found no listener. This also affected Firecracker
  Stage 0 on `main`. All three builder specs now share `builder_egress_port`.
- **Console.** `BUILDER_CMDLINE` hardcoded HVF's PL011 console. It is now
  `BUILDER_CMDLINE_TAIL` behind the driver's `workload_base_bootargs(false)`;
  on HVF the result is byte-identical to the old constant, which a test pins.
- **Agent port.** The one-shot builder declared a `MachineControl` port its
  guest never serves, which on Firecracker makes `FcDriver::boot` wait 60s for
  an agent that will not answer. It is gone; a test asserts no builder shape
  asks a driver to wait.

`DriverBuilderVm` also stopped calling itself HVF in its errors and VM names;
the name now comes from the driver, so HVF's `mvm-hvf-builder-*` is unchanged.

## Not done

- **Not live-proven.** No KVM host was reachable (the Hetzner box timed out on
  SSH, `rpi1.local` did not resolve). The proof is compositional: both boot
  contracts compose onto `FcDriver` with its own console, a bootable cmdline,
  no agent wait, and a `GuestDials` egress port.
- **The persistent builder** still refuses Firecracker by name.
- **The SDK sidecar build** still calls the HVF resolver directly.

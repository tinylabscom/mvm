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

## What the live run found

The first run on a KVM host hung, and not in anything above. Stage 0 finished
its build in 17 minutes, printed `stage0-init: done; halting`, and the kernel
answered `reboot: Power off not available: System halted instead`. The builder
kernel has no power-off method under Firecracker on x86_64. HVF and libkrun exit
on a halt; Firecracker keeps the halted guest alive, and the runner waited only
for the process, so it would have sat out its two-hour backstop.

- **The runner now watches for the halt.** `ConsoleHaltWatch` tails the console
  for the kernel's banner and the runner stops the VM when it appears. It ends
  the wait and nothing more: the on-disk result still decides success.
- **Firecracker could not kill an agentless guest.** `FcRunningVm::kill` asked
  the guest agent to flush first and returned the connect error before
  signalling anything. It now skips the flush when the boot spec served no
  agent, the condition boot already uses for its agent wait.

## Live validation

Ubuntu 24.04 x86_64 with `/dev/kvm`, Firecracker v1.14.1, `mvmctl` built with
`embed-host-bins` and without `user`, a cold `MVM_HOME`, nothing selected by
hand, and nothing killed by hand:

| Leg | Evidence |
|---|---|
| auto-detect | `builder backend: OK (firecracker — auto-detected …)` |
| bootstrap kernel pin | the x86_64 `boot-image/v0.1.5` kernel fetched and verified |
| Stage 0 | `builder guest halted; stopping its VMM`, then exit 0 after 17 minutes |
| builder shell job | exit 0; `/out` came back through the output disk |
| driver console | guest `/proc/cmdline` begins `console=ttyS0 quiet reboot=k panic=1` |
| guest egress | `curl https://cache.nixos.org/nix-cache-info` from the job returned the store's real `nix-cache-info` |
| ignored live test | `live_firecracker_builder_runs_a_shell_job` passed against the bootstrapped image in 11.5s |

The guest's egress client logs one `egress client connection failed … early
eof` at start-up. The fetch after it succeeds, so the channel works; what the
first dial hits is not chased here.

## Not done

- **The persistent builder** still refuses Firecracker by name.
- **The SDK sidecar build** still calls the HVF resolver directly.
- **The shell-job VM is still named `mvm-hvf-builder-shell-*`** on every
  backend. The prefix is what ephemeral-VM reaping keys on, so renaming it is
  its own change.
- **aarch64 Firecracker** is untested; this run was x86_64 only.

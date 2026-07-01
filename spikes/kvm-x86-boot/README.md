# x86_64 KVM boot spike

A standalone `kvm-ioctls` driver that boots a stock x86_64 Linux `bzImage` on
`/dev/kvm` straight to userspace (PID 1), via the 64-bit long-mode entry. This is
the proven recipe the `kvm::KvmVm` backend productionizes; it is **Linux-only**
and lives outside the cargo workspace (not built by `cargo build`).

Run on a Linux KVM host:

```sh
mkdir kvm-smoke && cd kvm-smoke && cargo init --bin
# add to Cargo.toml: kvm-ioctls, kvm-bindings, libc
cp /path/to/main.rs src/main.rs
MVM_INITRD=initramfs.cpio cargo run --release -- /boot/vmlinuz-x.y.z
```

The boot contract this pins down (every from-scratch KVM VMM needs it; same as
firecracker / cloud-hypervisor):

- 64-bit long-mode entry: PML4/PDPT/PD identity map (2 MiB pages), flat 64-bit
  GDT, `cr0=PE|PG`, `cr4=PAE`, `efer=LME|LMA`, kernel at 1 MiB, entry `+0x200`,
  `rsi=boot_params`.
- `KVM_SET_CPUID2` with the host-supported CPUID — without it the kernel reads a
  zeroed CPUID (phys-addr-bits=0) and its early page-table math faults.
- Two-entry e820 (0–640 KiB, then 1 MiB–end). A single entry makes the kernel
  fall back to legacy e801, see ~640 KiB, and panic in `alloc_low_pages`.
- In-kernel irqchip **and** `KVM_CREATE_PIT2`. Without the PIT the kernel hangs
  after APIC setup waiting for timer ticks.
- 16550 serial (PIO 0x3f8) for the console; polled TX is enough for kernel
  printk (userspace tty TX needs the serial IRQ, modeled in the backend).
- A `SIGALRM` watchdog interrupts a hung `KVM_RUN` so the run always terminates.

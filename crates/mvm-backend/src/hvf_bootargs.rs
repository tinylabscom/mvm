//! Cfg-free HVF workload boot-args helpers.
//!
//! The raw-HVF boot flow is macOS-only, but the workload cmdline choice is pure
//! string assembly and is shared by cfg-free backend glue that still compiles on
//! Linux CI. Keep that helper out of the macOS-only `crate::hvf` module.

use crate::vmm::fdt;

const UART_BASE: u64 = fdt::SERIAL_MMIO_BASE;

/// Cmdline used for block-rootfs workload boots.
pub(crate) fn default_bootargs(has_disk: bool) -> String {
    let mut args =
        format!("earlycon=pl011,0x{UART_BASE:x} console=ttyAMA0 panic=-1 nokaslr loglevel=8");
    if has_disk {
        args.push_str(" root=/dev/vda rw init=/init");
    }
    args
}

/// Cmdline used for virtiofs-root dev boots.
pub(crate) fn default_virtiofs_bootargs() -> String {
    format!(
        "earlycon=pl011,0x{UART_BASE:x} console=ttyAMA0 panic=-1 nokaslr loglevel=8 \
         rootfstype=virtiofs root=mvmroot rw init=/init"
    )
}

/// Default workload kernel cmdline for the chosen root strategy.
pub fn workload_bootargs(virtiofs_root: bool, has_disk: bool) -> String {
    if virtiofs_root {
        default_virtiofs_bootargs()
    } else {
        default_bootargs(has_disk)
    }
}

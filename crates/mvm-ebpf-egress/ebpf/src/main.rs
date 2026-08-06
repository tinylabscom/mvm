#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[kprobe]
pub fn mvm_egress_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_mvm_egress_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_mvm_egress_tcp_connect(ctx: ProbeContext) -> Result<u32, u32> {
    // Spike: log that the probe fired. Future iterations will extract
    // the destination from `struct sock *sk` (first argument) and emit
    // a ring-buffer event to userspace.
    info!(&ctx, "mvm egress tcp_connect probe fired");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

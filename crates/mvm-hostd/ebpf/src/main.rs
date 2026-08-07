#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, macros::map, maps::RingBuf, programs::ProbeContext};
use aya_log_ebpf::info;

/// Ring buffer used to notify userspace that the egress kprobe fired.
/// Each record is a single placeholder byte; future iterations will carry
/// the resolved destination address and port.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[kprobe]
pub fn mvm_hostd_egress_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_mvm_hostd_egress_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_mvm_hostd_egress_tcp_connect(ctx: ProbeContext) -> Result<u32, u32> {
    // Spike: log that the probe fired. Future iterations will extract
    // the destination from `struct sock *sk` (first argument) and emit
    // a ring-buffer event carrying the resolved address/port.
    info!(&ctx, "mvm hostd egress tcp_connect probe fired");

    if let Some(mut entry) = EVENTS.reserve::<u8>(0) {
        entry.write(1);
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

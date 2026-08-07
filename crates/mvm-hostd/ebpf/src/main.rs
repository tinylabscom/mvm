#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

/// Local layout mirror of `struct sock_common`.  The order and sizes match
/// the in-kernel layout on x86_64 so that reads resolve to the right offsets
/// when the object is loaded without BTF CO-RE relocations for these types.
#[repr(C)]
pub struct sock_common {
    pub skc_daddr: u32,
    pub skc_rcv_saddr: u32,
    pub skc_hash: u32,
    pub skc_dport: u16,
    pub skc_num: u16,
    pub skc_family: u16,
}

/// Local layout mirror of `struct sock`.  Only `__sk_common` is needed.
#[repr(C)]
pub struct sock {
    pub __sk_common: sock_common,
}

/// Network-byte-order record written to the ring buffer for every
/// `tcp_connect` kprobe hit. Userspace converts to host order.
#[repr(C)]
pub struct EgressEvent {
    pub family: u16,
    pub dport: u16,
    pub daddr: u32,
}

/// Ring buffer used to notify userspace that the egress kprobe fired.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[kprobe]
pub fn mvm_hostd_egress_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_mvm_hostd_egress_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

const AF_INET: u16 = 2;

fn try_mvm_hostd_egress_tcp_connect(ctx: ProbeContext) -> Result<u32, u32> {
    // `tcp_connect(struct sock *sk, ...)` — sk is the first argument.
    let sk: *mut sock = ctx.arg(0).ok_or(1u32)?;

    let family: u16 =
        unsafe { bpf_probe_read_kernel(&(*sk).__sk_common.skc_family) }.map_err(|_| 1u32)?;

    if family != AF_INET {
        // IPv6 and other families are out of scope for this spike.
        return Ok(0);
    }

    let daddr: u32 =
        unsafe { bpf_probe_read_kernel(&(*sk).__sk_common.skc_daddr) }.map_err(|_| 1u32)?;
    let dport: u16 =
        unsafe { bpf_probe_read_kernel(&(*sk).__sk_common.skc_dport) }.map_err(|_| 1u32)?;

    info!(
        &ctx,
        "mvm egress observed daddr=%u dport=%u",
        u32::from_be(daddr),
        u16::from_be(dport) as u32,
    );

    if let Some(mut entry) = EVENTS.reserve::<EgressEvent>(0) {
        entry.write(EgressEvent {
            family,
            dport,
            daddr,
        });
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
};

/// Prefix mirror of `struct sock_common`.  The order and sizes match the
/// in-kernel layout on x86_64 up to and including `skc_family`, which is
/// enough for the fields this probe reads.  The contract below locks the
/// prefix size and alignment to the kernel header.
#[repr(C)]
pub struct sock_common {
    pub skc_daddr: u32,
    pub skc_rcv_saddr: u32,
    pub skc_hash: u32,
    pub skc_dport: u16,
    pub skc_num: u16,
    pub skc_family: u16,
}

const _: () = {
    use core::mem::{align_of, size_of};
    // Prefix size/alignment derived from the kernel struct sock_common layout
    // (daddr 0, rcv_saddr 4, hash 8, dport 12, num 14, family 16).
    assert!(size_of::<sock_common>() == 20);
    assert!(align_of::<sock_common>() == 4);
};

/// Network-byte-order record written to the ring buffer for every
/// `tcp_connect` kprobe hit. Userspace converts to host order.
#[repr(C)]
pub struct EgressEvent {
    pub family: u16,
    pub dport: u16,
    pub daddr: u32,
}

const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<EgressEvent>() == 8);
    assert!(align_of::<EgressEvent>() == 4);
};

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
    // `tcp_connect(struct sock *sk, ...)` — the first member of `struct sock`
    // is `struct sock_common __sk_common`, so the argument pointer can be
    // treated as a `*mut sock_common` for the fields we read.
    let sk: *mut sock_common = ctx.arg(0).ok_or(1u32)?;

    let family: u16 = unsafe { bpf_probe_read_kernel(&(*sk).skc_family) }.map_err(|_| 1u32)?;

    if family != AF_INET {
        // IPv6 and other families are out of scope for this spike.
        return Ok(0);
    }

    let daddr: u32 = unsafe { bpf_probe_read_kernel(&(*sk).skc_daddr) }.map_err(|_| 1u32)?;
    let dport: u16 = unsafe { bpf_probe_read_kernel(&(*sk).skc_dport) }.map_err(|_| 1u32)?;

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

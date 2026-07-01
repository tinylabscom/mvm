// Transparent egress proxy (static musl): the guest kernel REDIRECTs all workload
// TCP here; we read the real destination via SO_ORIGINAL_DST and funnel the stream
// to the host vsock egress gateway (port 5253) using its "host:port\n" + stream
// protocol. No NIC: the upstream is AF_VSOCK, never TCP, so the REDIRECT rule never
// catches our own egress. The kernel's TCP stack terminates the workload's
// connection, so this proxy stays trivial. See README.md.
fn klog(s: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        use std::io::Write;
        let _ = f.write_all(s.as_bytes());
    }
}

use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::thread;

#[repr(C)]
struct SockaddrIn {
    fam: u16,
    port: [u8; 2],
    addr: [u8; 4],
    zero: [u8; 8],
}
#[repr(C)]
struct SockaddrVm {
    fam: u16,
    res1: u16,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}

unsafe extern "C" {
    fn getsockopt(fd: i32, lvl: i32, name: i32, val: *mut core::ffi::c_void, len: *mut u32) -> i32;
    fn socket(d: i32, t: i32, p: i32) -> i32;
    fn connect(fd: i32, a: *const core::ffi::c_void, l: u32) -> i32;
    fn read(fd: i32, b: *mut u8, n: usize) -> isize;
    fn write(fd: i32, b: *const u8, n: usize) -> isize;
    fn close(fd: i32) -> i32;
}

fn vsock(port: u32) -> i32 {
    unsafe {
        let s = socket(40, 1, 0); // AF_VSOCK, SOCK_STREAM
        if s < 0 {
            return -1;
        }
        let a = SockaddrVm { fam: 40, res1: 0, port, cid: 2, zero: [0; 4] };
        if connect(s, &a as *const _ as *const _, core::mem::size_of::<SockaddrVm>() as u32) != 0 {
            close(s);
            return -1;
        }
        s
    }
}

fn splice(a: i32, b: i32) {
    let mut buf = [0u8; 16384];
    loop {
        let n = unsafe { read(a, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        let mut o = 0isize;
        while o < n {
            let w = unsafe { write(b, buf.as_ptr().offset(o), (n - o) as usize) };
            if w <= 0 {
                return;
            }
            o += w;
        }
    }
}

fn main() {
    let l = TcpListener::bind("0.0.0.0:1080").expect("bind 1080");
    klog("MVMP: listening 1080\n");
    for c in l.incoming() {
        let c = match c {
            Ok(c) => c,
            Err(_) => continue,
        };
        thread::spawn(move || {
            let cfd = c.as_raw_fd();
            let mut sa: SockaddrIn = unsafe { core::mem::zeroed() };
            let mut len = core::mem::size_of::<SockaddrIn>() as u32;
            // SOL_IP=0, SO_ORIGINAL_DST=80 — the address the workload connected to.
            if unsafe { getsockopt(cfd, 0, 80, &mut sa as *mut _ as *mut _, &mut len) } != 0 {
                return;
            }
            let port = (u16::from(sa.port[0]) << 8) | u16::from(sa.port[1]);
            let target = format!(
                "{}.{}.{}.{}:{}\n",
                sa.addr[0], sa.addr[1], sa.addr[2], sa.addr[3], port
            );
            klog(&format!("MVMP: orig_dst {target}"));
            let v = vsock(5253);
            klog(&format!("MVMP: vsock={v}\n"));
            if v < 0 {
                return;
            }
            unsafe {
                write(v, target.as_ptr(), target.len());
            }
            let h = thread::spawn(move || splice(cfd, v));
            splice(v, cfd);
            let _ = h.join();
            unsafe {
                close(v);
            }
            drop(c);
        });
    }
}

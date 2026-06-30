// Unmodified workload (static musl): a PLAIN connect() to a real IP, NO proxy env.
// If transparent egress works, this rides vsock with zero awareness of it. Logs to
// /dev/kmsg (the polled console) because userspace tty TX would block on the
// unmodeled serial IRQ.
use std::io::{Read, Write};
use std::net::TcpStream;

fn klog(s: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = f.write_all(s.as_bytes());
    }
}

fn main() {
    klog("MVMT: client start (plain connect, NO proxy env)\n");
    match TcpStream::connect("88.99.197.234:9099") {
        Ok(mut s) => {
            klog("MVMT: tcp connected\n");
            let _ = s.write_all(b"ping");
            let mut b = [0u8; 64];
            match s.read(&mut b) {
                Ok(n) => klog(&format!("MVMT: reply ({n}): {}\n", String::from_utf8_lossy(&b[..n]))),
                Err(e) => klog(&format!("MVMT: read err {e}\n")),
            }
        }
        Err(e) => klog(&format!("MVMT: connect err {e}\n")),
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

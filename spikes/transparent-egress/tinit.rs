// Static PID 1: NIC-less but routed — bring up loopback + a dummy default route so
// connect() reaches the OUTPUT chain, install the nat REDIRECT that sends all TCP to
// the transparent proxy, start the proxy, then run an unmodified workload. The
// networking tools (iproute2 `ip`, `iptables-legacy`) are dynamic and shipped with
// their libs + xtables plugins; the proxy/client/init are static. See README.md.
use std::process::Command;

fn klog(s: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        use std::io::Write;
        let _ = f.write_all(s.as_bytes());
    }
}

fn run(c: &str, a: &[&str]) {
    match Command::new(c).args(a).output() {
        Ok(o) => klog(&format!(
            "MVMT: {c} {a:?} code={:?} err={}\n",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => klog(&format!("MVMT: {c} spawn-fail {e}\n")),
    }
}

fn main() {
    klog("MVMT: tinit start\n");
    run("/sbin/ip", &["link", "set", "lo", "up"]);
    // CONFIG_DUMMY=y auto-creates dummy0 at boot ("File exists" is harmless); it
    // just carries a default route so connect() routes into OUTPUT (no real NIC).
    run("/sbin/ip", &["link", "add", "dummy0", "type", "dummy"]);
    run("/sbin/ip", &["addr", "add", "10.0.0.1/24", "dev", "dummy0"]);
    run("/sbin/ip", &["link", "set", "dummy0", "up"]);
    run("/sbin/ip", &["route", "add", "default", "via", "10.0.0.2", "dev", "dummy0"]);
    run(
        "/sbin/iptables-legacy",
        &["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "1080"],
    );
    klog("MVMT: net + REDIRECT installed; starting proxy\n");
    let _ = Command::new("/tproxy").spawn();
    std::thread::sleep(std::time::Duration::from_millis(800));
    let _ = Command::new("/tclient").status();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

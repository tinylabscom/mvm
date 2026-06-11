use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Cap per scrape file at 1 MiB. A rogue or runaway supervisor writing a
/// multi-GB `.prom` file must not be able to DoS `/metrics` or burn host
/// RAM. The legitimate `flow-count-metrics` exposition is a few hundred
/// bytes; 1 MiB leaves three orders of magnitude of headroom for future
/// observers.
const MAX_SCRAPE_FILE_BYTES: usize = 1024 * 1024;

/// A minimal HTTP server that serves `GET /metrics` in a background thread.
///
/// Binds to `127.0.0.1:<port>` and returns the Prometheus exposition format
/// from the global metrics registry on every request. No external dependencies —
/// uses only `std::net::TcpListener`.
pub struct MetricsServer {
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MetricsServer {
    /// Bind to `127.0.0.1:<port>` and start serving in a background thread.
    pub fn start(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .with_context(|| format!("Failed to bind metrics server on port {}", port))?;
        // Non-blocking accept so the shutdown flag is checked promptly.
        listener
            .set_nonblocking(true)
            .context("Failed to set metrics listener to non-blocking")?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = std::thread::spawn(move || {
            serve_loop(listener, shutdown_clone);
        });

        tracing::info!("Metrics available at http://127.0.0.1:{}/metrics", port);

        Ok(Self {
            shutdown,
            handle: Some(handle),
        })
    }

    /// Signal the background thread to stop and wait for it to exit.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn serve_loop(listener: TcpListener, shutdown: Arc<AtomicBool>) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => handle_connection(stream),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }
}

fn handle_connection(mut stream: TcpStream) {
    // Read the request line — we don't need to parse it fully.
    let mut buf = [0u8; 512];
    let _ = stream.read(&mut buf);

    let mut body = mvm_core::observability::metrics::global().prometheus_exposition();
    append_per_vm_scrape_files(&mut body);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Concatenate per-VM Prometheus scrape files written by supervisor-side
/// observers (e.g. `FlowCountMetrics::write_scrape_file`) onto the global
/// metrics output. The supervisor and CLI run as the same user and share
/// `~/.mvm/audit/` (mode 0700), so the filesystem is the
/// cross-process surface — no new RPC, no new socket. File-name contract:
/// `metrics-<vm>-flow-count.prom`.
///
/// `var_os` is preferred over `var` so a non-UTF-8 `HOME` is treated as
/// unset rather than falling through `Err(NotUnicode)` into an
/// unintended path.
fn append_per_vm_scrape_files(out: &mut String) {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let dir = std::path::PathBuf::from(home).join(".mvm/audit");
    append_per_vm_scrape_files_from(out, &dir);
}

/// Mirrors the `ObserverAllowlist::load_from_path` hardening pattern in
/// `crates/mvm-supervisor/src/network/mod.rs`: `file_type()` skips
/// symlinks (and directories), then `O_NOFOLLOW` makes the open itself
/// fail closed on the TOCTOU window between `file_type()` and open.
/// `Read::take` caps each file at `MAX_SCRAPE_FILE_BYTES` so a runaway
/// or rogue scrape file can't DoS `/metrics`.
///
/// The file-uid check from `load_from_path` is intentionally omitted —
/// these files are written by sibling supervisor processes running as
/// the same user, not by potentially-untrusted policy authors; symlink
/// rejection and size capping cover the threat model here.
fn append_per_vm_scrape_files_from(out: &mut String, dir: &std::path::Path) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(d) => d,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // `is_file()` returns the raw file type, so symlinks (even when
        // they point at regular files) return `false`. Drop everything
        // that isn't a regular file outright.
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        // Discover ALL supervisor-written scrape files, not just
        // flow-count. New per-observer-latency files
        // (`metrics-<vm>-observer-latency.prom`) are picked up automatically.
        if !name.starts_with("metrics-") || !name.ends_with(".prom") {
            continue;
        }
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        else {
            continue;
        };
        let mut body = String::new();
        if file
            .take(MAX_SCRAPE_FILE_BYTES as u64)
            .read_to_string(&mut body)
            .is_ok()
        {
            out.push_str(&body);
            if !body.ends_with('\n') {
                out.push('\n');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_server_binds() {
        // Pick a port unlikely to be in use; retry once with a different port if needed.
        let server = MetricsServer::start(19091)
            .or_else(|_| MetricsServer::start(19092))
            .expect("metrics server should bind");
        server.stop();
    }

    #[test]
    fn test_metrics_server_responds() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpStream;

        let server = MetricsServer::start(19093)
            .or_else(|_| MetricsServer::start(19094))
            .expect("metrics server should bind");

        // Give the background thread a moment to start.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Determine which port actually bound by inspecting the local addr.
        // Since we can't easily query the bound port from MetricsServer,
        // try both candidate ports.
        let stream = TcpStream::connect("127.0.0.1:19093")
            .or_else(|_| TcpStream::connect("127.0.0.1:19094"))
            .expect("should connect to metrics server");

        let mut stream_clone = stream.try_clone().unwrap();
        stream_clone
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .unwrap();

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            response.push_str(&line);
        }

        assert!(
            response.contains("mvm_requests_total"),
            "response should contain prometheus metrics, got: {response}"
        );

        server.stop();
    }

    #[test]
    fn append_per_vm_scrape_files_from_filters_prefix_and_suffix() {
        let tmpdir = tempfile::tempdir().unwrap();
        let audit = tmpdir.path().join(".mvm/audit");
        std::fs::create_dir_all(&audit).unwrap();
        std::fs::write(
            audit.join("metrics-vm-a-flow-count.prom"),
            "mvm_flow_opened_total{tenant=\"a\"} 5\n",
        )
        .unwrap();
        std::fs::write(
            audit.join("metrics-vm-b-flow-count.prom"),
            "mvm_flow_opened_total{tenant=\"b\"} 9\n",
        )
        .unwrap();
        // Any `metrics-*.prom` is now discovered, including the
        // new per-observer-latency files.
        std::fs::write(
            audit.join("metrics-vm-d-observer-latency.prom"),
            "mvm_observer_latency_us_count{observer=\"r\",vm=\"d\",direction=\"egress\"} 3\n",
        )
        .unwrap();
        // Non-`metrics-` prefix or non-`.prom` suffix must NOT match.
        std::fs::write(audit.join("other-vm.prom"), "should_not_appear 1\n").unwrap();
        std::fs::write(audit.join("metrics-vm-c.txt"), "should_not_appear 2\n").unwrap();

        let mut out = String::new();
        append_per_vm_scrape_files_from(&mut out, &audit);
        assert!(out.contains("mvm_flow_opened_total{tenant=\"a\"} 5"));
        assert!(out.contains("mvm_flow_opened_total{tenant=\"b\"} 9"));
        assert!(out.contains("mvm_observer_latency_us_count"));
        assert!(!out.contains("should_not_appear"));
    }

    #[test]
    fn append_per_vm_scrape_files_from_skips_symlinks() {
        use std::os::unix::fs::symlink;
        let tmpdir = tempfile::tempdir().unwrap();
        let audit = tmpdir.path().join(".mvm/audit");
        std::fs::create_dir_all(&audit).unwrap();

        let real = audit.join("metrics-vm-real-flow-count.prom");
        std::fs::write(&real, "mvm_flow_opened_total{tenant=\"real\"} 1\n").unwrap();

        // Attacker-planted symlink pointing at sensitive content.
        let sensitive = tmpdir.path().join("sensitive.txt");
        std::fs::write(&sensitive, "ROOT_PASSWORD=hunter2\n").unwrap();
        let link = audit.join("metrics-vm-attacker-flow-count.prom");
        symlink(&sensitive, &link).unwrap();

        let mut out = String::new();
        append_per_vm_scrape_files_from(&mut out, &audit);
        assert!(out.contains("tenant=\"real\""));
        assert!(!out.contains("ROOT_PASSWORD"));
    }

    #[test]
    fn append_per_vm_scrape_files_from_caps_file_size() {
        let tmpdir = tempfile::tempdir().unwrap();
        let audit = tmpdir.path().join(".mvm/audit");
        std::fs::create_dir_all(&audit).unwrap();

        let big = audit.join("metrics-vm-big-flow-count.prom");
        let body = "x".repeat(MAX_SCRAPE_FILE_BYTES + 1024);
        std::fs::write(&big, &body).unwrap();

        let mut out = String::new();
        append_per_vm_scrape_files_from(&mut out, &audit);
        // The cap applies, so we don't read the extra 1 KiB past the
        // boundary. Small slack accounts for a possible trailing
        // newline appended when the body doesn't already end in '\n'.
        assert!(out.len() <= MAX_SCRAPE_FILE_BYTES + 16);
    }
}

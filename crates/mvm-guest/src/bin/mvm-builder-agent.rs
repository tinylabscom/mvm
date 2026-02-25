use std::io::{BufRead, BufReader, Write};
use std::mem::size_of;
use std::os::fd::{FromRawFd, RawFd};
use std::process::{Command, Stdio};

use mvm_guest::builder_agent::{BuilderRequest, BuilderResponse};

const AF_VSOCK: i32 = 40;
const SOCK_STREAM: i32 = 1;
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
const PORT: u32 = mvm_guest::builder_agent::BUILDER_AGENT_PORT;

#[repr(C)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

unsafe extern "C" {
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
    fn listen(sockfd: i32, backlog: i32) -> i32;
    fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
    fn close(fd: i32) -> i32;
}

fn handle_client(fd: RawFd) {
    // SAFETY: fd comes from accept and is a valid file descriptor owned by this function.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let line_trim = line.trim();
                if line_trim.is_empty() {
                    continue;
                }
                let req = match serde_json::from_str::<BuilderRequest>(line_trim) {
                    Ok(req) => req,
                    Err(e) => {
                        write_resp(
                            &mut reader,
                            BuilderResponse::Err {
                                message: format!("parse error: {}", e),
                            },
                        );
                        continue;
                    }
                };

                match req {
                    BuilderRequest::Ping => {
                        write_resp(&mut reader, BuilderResponse::Pong);
                    }
                    BuilderRequest::Build {
                        flake_ref,
                        attr,
                        timeout_secs,
                    } => {
                        let timeout = timeout_secs.unwrap_or(1800);
                        if let Err(e) = run_build(&mut reader, &flake_ref, &attr, timeout) {
                            write_resp(
                                &mut reader,
                                BuilderResponse::Err {
                                    message: format!("agent error: {}", e),
                                },
                            );
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
}

fn write_resp(reader: &mut BufReader<std::fs::File>, resp: BuilderResponse) {
    let writer = reader.get_mut();
    let _ = writeln!(
        writer,
        "{}",
        serde_json::to_string(&resp)
            .unwrap_or_else(|_| "{\"Err\":{\"message\":\"encode error\"}}".to_string())
    );
    let _ = writer.flush();
}

fn ensure_mount(
    reader: &mut BufReader<std::fs::File>,
    dev: &str,
    mountpoint: &str,
) -> anyhow::Result<()> {
    let cmd = format!(
        "mountpoint -q {mp} || (mkdir -p {mp} && mount {dev} {mp})",
        mp = mountpoint,
        dev = dev
    );
    let output = Command::new("sh").arg("-c").arg(&cmd).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = format!("mount {} -> {} failed: {}", dev, mountpoint, stderr);
        write_resp(reader, BuilderResponse::Log { line: msg.clone() });
        return Err(anyhow::anyhow!("{}", msg));
    }
    let msg = format!("mounted {} -> {}", dev, mountpoint);
    write_resp(reader, BuilderResponse::Log { line: msg });
    Ok(())
}

/// Find the nix binary, searching well-known install locations.
fn find_nix_bin() -> Option<String> {
    let candidates = [
        "/nix/var/nix/profiles/default/bin/nix",
        "/root/.nix-profile/bin/nix",
        "/nix/var/nix/profiles/per-user/root/profile/bin/nix",
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    // Fallback: search /nix/store for the nix binary.
    if let Ok(out) = Command::new("find")
        .args([
            "/nix/store",
            "-maxdepth",
            "3",
            "-name",
            "nix",
            "-type",
            "f",
            "-path",
            "*/bin/nix",
        ])
        .output()
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(line) = stdout.lines().next() {
            if !line.is_empty() {
                return Some(line.to_string());
            }
        }
    }
    None
}

/// Return PATH prefix that includes the directory containing nix.
fn nix_path_prefix() -> String {
    if let Some(nix_bin) = find_nix_bin() {
        if let Some(dir) = std::path::Path::new(&nix_bin).parent() {
            return dir.to_string_lossy().to_string();
        }
    }
    // Best-effort defaults covering both multi-user and single-user installs.
    "/nix/var/nix/profiles/default/bin:/root/.nix-profile/bin".to_string()
}

fn ensure_nix(reader: &mut BufReader<std::fs::File>) -> anyhow::Result<()> {
    // Check if nix is already available.
    if find_nix_bin().is_some() {
        ensure_nix_conf();
        return Ok(());
    }

    write_resp(
        reader,
        BuilderResponse::Log {
            line: "Nix not found, installing (single-user)...".to_string(),
        },
    );

    // Capture install output for diagnostics.
    let output = Command::new("sh")
        .arg("-c")
        .arg("curl --retry 3 --retry-delay 2 -L https://nixos.org/nix/install | sh -s -- --no-daemon 2>&1")
        .output()?;

    let install_log = String::from_utf8_lossy(&output.stdout);
    // Stream last 10 lines of install log.
    let lines: Vec<&str> = install_log.lines().collect();
    let start = lines.len().saturating_sub(10);
    for line in &lines[start..] {
        write_resp(
            reader,
            BuilderResponse::Log {
                line: format!("[nix-install] {}", line),
            },
        );
    }

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Nix installer failed (exit {}). Builder rootfs needs Nix pre-installed or network access.",
            output.status
        ));
    }

    ensure_nix_conf();

    // Verify nix is actually available after install.
    match find_nix_bin() {
        Some(path) => {
            let msg = format!("Nix installed at {}", path);
            write_resp(reader, BuilderResponse::Log { line: msg });
        }
        None => {
            // Log what we can find in /nix for diagnostics.
            let diag = Command::new("sh")
                .arg("-c")
                .arg("ls -la /nix/var/nix/profiles/ 2>&1; echo '---'; ls -la /root/.nix-profile/bin/ 2>&1; echo '---'; find /nix/store -maxdepth 3 -name nix -type f 2>/dev/null | head -5")
                .output()
                .ok();
            let info = diag
                .as_ref()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Nix installer exited 0 but nix binary not found. Diagnostics:\n{}",
                info
            ));
        }
    }
    Ok(())
}

fn ensure_nix_conf() {
    let conf = "experimental-features = nix-command flakes\n";
    let _ = std::fs::create_dir_all("/etc/nix");
    let _ = std::fs::write("/etc/nix/nix.conf", conf);
    let _ = std::fs::create_dir_all("/root/.config/nix");
    let _ = std::fs::write("/root/.config/nix/nix.conf", conf);
}

fn run_build(
    reader: &mut BufReader<std::fs::File>,
    flake_ref: &str,
    attr: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    // Disks are attached by the host as:
    // - /dev/vdb -> /build-out (rw)
    // - /dev/vdc -> /build-in (ro, optional local flake)
    ensure_mount(reader, "/dev/vdb", "/build-out")?;
    if flake_ref == "/build-in" {
        ensure_mount(reader, "/dev/vdc", "/build-in")?;
    }

    // Ensure Nix is available before attempting the build.
    ensure_nix(reader)?;

    let nix_path = nix_path_prefix();
    write_resp(
        reader,
        BuilderResponse::Log {
            line: format!("nix PATH: {}", nix_path),
        },
    );

    // Build with explicit PATH.
    let build_cmd = format!(
        "export PATH=\"{nix_path}:$PATH\"; \
         timeout {t} nix build {flake}#{attr} --no-link --print-out-paths 2>&1",
        nix_path = nix_path,
        t = timeout,
        flake = flake_ref,
        attr = attr
    );

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&build_cmd)
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture nix build stdout"))?;
    let mut out_reader = BufReader::new(stdout);
    let mut buf = String::new();
    let mut last_store_path: Option<String> = None;
    let mut log_lines: Vec<String> = Vec::new();

    loop {
        buf.clear();
        let n = out_reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        let line = buf.trim_end().to_string();
        if let Some(p) = line.strip_prefix("/nix/store/") {
            let _ = p; // marker only
            last_store_path = Some(line.clone());
        }
        log_lines.push(line.clone());
        write_resp(reader, BuilderResponse::Log { line });
    }

    let status = child.wait()?;
    if !status.success() {
        // Best-effort persist log in /build-out for host-side inspection.
        let _ = std::fs::write("/build-out/build.log", log_lines.join("\n"));
        return Err(anyhow::anyhow!(
            "nix build failed (exit {}): {}",
            status,
            build_cmd
        ));
    }

    let out_path = last_store_path
        .ok_or_else(|| anyhow::anyhow!("nix build produced no store path"))?
        .to_string();

    let copy_cmd = format!(
        "set -euo pipefail; \
         cp {p}/kernel /build-out/vmlinux 2>/dev/null || cp {p}/vmlinux /build-out/vmlinux; \
         cp {p}/rootfs /build-out/rootfs.ext4 2>/dev/null || cp {p}/rootfs.ext4 /build-out/rootfs.ext4; \
         echo '{{\"note\":\"Base fc config placeholder\"}}' > /build-out/fc-base.json",
        p = out_path
    );
    let status = Command::new("sh").arg("-c").arg(&copy_cmd).status()?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "failed to copy artifacts (exit {}): {}",
            status,
            copy_cmd
        ));
    }

    // Persist build log after success as well.
    let _ = std::fs::write("/build-out/build.log", log_lines.join("\n"));
    write_resp(reader, BuilderResponse::Ok { out_path });
    Ok(())
}

fn main() {
    // SAFETY: libc call, arguments are constant values.
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("failed to create vsock socket");
        std::process::exit(1);
    }

    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: PORT,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    // SAFETY: pointers are valid for the specified size.
    let bind_rc = unsafe {
        bind(
            fd,
            &addr as *const SockAddrVm as *const core::ffi::c_void,
            size_of::<SockAddrVm>() as u32,
        )
    };
    if bind_rc != 0 {
        eprintln!("failed to bind vsock socket");
        // SAFETY: fd is valid.
        unsafe {
            close(fd);
        }
        std::process::exit(1);
    }

    // SAFETY: fd is valid.
    if unsafe { listen(fd, 16) } != 0 {
        eprintln!("failed to listen on vsock socket");
        // SAFETY: fd is valid.
        unsafe {
            close(fd);
        }
        std::process::exit(1);
    }

    loop {
        // SAFETY: null addr pointers are allowed for accept when peer addr is not needed.
        let cfd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            continue;
        }
        handle_client(cfd);
    }
}

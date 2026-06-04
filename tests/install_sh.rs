//! Integration test for the repo-root install.sh. Serves fake release
//! assets over a loopback HTTP server and drives the script with its
//! documented env overrides.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

fn host_target() -> &'static str {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-unknown-linux-gnu"
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d: [u8; 32] = Sha256::digest(bytes).into();
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Build a gzipped tar containing `mvmctl-<target>/mvmctl` (+ a
/// resources dir) where mvmctl is a shell stub printing a version.
fn make_tarball(target: &str) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let dir = format!("mvmctl-{target}");
    let stub = b"#!/bin/sh\necho 'mvmctl 9.9.9'\n";
    let mut tar = tar::Builder::new(Vec::new());
    let mut hdr = tar::Header::new_gnu();
    hdr.set_size(stub.len() as u64);
    hdr.set_mode(0o755);
    hdr.set_cksum();
    tar.append_data(&mut hdr, format!("{dir}/mvmctl"), &stub[..])
        .unwrap();
    let ent = b"<plist></plist>\n";
    let mut h2 = tar::Header::new_gnu();
    h2.set_size(ent.len() as u64);
    h2.set_mode(0o644);
    h2.set_cksum();
    tar.append_data(
        &mut h2,
        format!("{dir}/resources/mvmctl.entitlements"),
        &ent[..],
    )
    .unwrap();
    let tar_bytes = tar.into_inner().unwrap();
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

/// Minimal loopback HTTP server. `routes` maps request-path → body.
/// Runs until the returned sender is dropped.
fn serve(routes: Vec<(String, Vec<u8>)>) -> (String, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (tx, rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        loop {
            if rx.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 2048];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let body = routes
                        .iter()
                        .find(|(p, _)| p == path)
                        .map(|(_, b)| b.clone());
                    match body {
                        Some(b) => {
                            let hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                b.len()
                            );
                            let _ = stream.write_all(hdr.as_bytes());
                            let _ = stream.write_all(&b);
                        }
                        None => {
                            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        }
                    }
                }
                Err(_) => thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    });
    (format!("http://{addr}"), tx)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn install_sh_downloads_verifies_and_installs() {
    let target = host_target();
    let tarball = make_tarball(target);
    let archive = format!("mvmctl-{target}.tar.gz");
    let checks = format!("{}  {}\n", sha256_hex(&tarball), archive);
    let routes = vec![
        (
            format!("/tinylabscom/mvm/releases/download/v9.9.9/{archive}"),
            tarball.clone(),
        ),
        (
            "/tinylabscom/mvm/releases/download/v9.9.9/checksums-sha256.txt".to_string(),
            checks.into_bytes(),
        ),
    ];
    let (base, _stop) = serve(routes);

    let install_dir = tempfile::tempdir().unwrap();
    let status = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .env("MVM_VERSION", "v9.9.9")
        .env("MVM_UPDATE_DOWNLOAD_URL", &base)
        .env("MVM_INSTALL_DIR", install_dir.path())
        .env("MVM_SKIP_CODESIGN", "1")
        .status()
        .unwrap();
    assert!(status.success(), "install.sh should succeed");
    assert!(
        install_dir.path().join("mvmctl").exists(),
        "binary installed"
    );
}

#[test]
fn install_sh_rejects_tampered_checksum() {
    let target = host_target();
    let tarball = make_tarball(target);
    let archive = format!("mvmctl-{target}.tar.gz");
    // Wrong checksum on purpose.
    let checks = format!("{}  {}\n", "0".repeat(64), archive);
    let routes = vec![
        (
            format!("/tinylabscom/mvm/releases/download/v9.9.9/{archive}"),
            tarball,
        ),
        (
            "/tinylabscom/mvm/releases/download/v9.9.9/checksums-sha256.txt".to_string(),
            checks.into_bytes(),
        ),
    ];
    let (base, _stop) = serve(routes);

    let install_dir = tempfile::tempdir().unwrap();
    let status = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .env("MVM_VERSION", "v9.9.9")
        .env("MVM_UPDATE_DOWNLOAD_URL", &base)
        .env("MVM_INSTALL_DIR", install_dir.path())
        .env("MVM_SKIP_CODESIGN", "1")
        .status()
        .unwrap();
    assert!(!status.success(), "tampered checksum must fail the install");
    assert!(
        !install_dir.path().join("mvmctl").exists(),
        "no binary on failure"
    );
}

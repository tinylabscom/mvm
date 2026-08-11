//! Integration test for the repo-root install.sh. Serves fake release
//! assets over a loopback HTTP server and drives the script with its
//! documented env overrides.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

const MAX_REQUEST_HEADER_BYTES: usize = 8 * 1024;

fn read_request_path(reader: &mut impl Read) -> std::io::Result<Option<String>> {
    let mut request = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if request.len().saturating_add(read) > MAX_REQUEST_HEADER_BYTES {
            return Ok(None);
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    if !request.windows(4).any(|window| window == b"\r\n\r\n") {
        return Ok(None);
    }

    let request = String::from_utf8_lossy(&request);
    let mut fields = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = fields.next();
    let path = fields.next();
    let version = fields.next();
    if method != Some("GET") || version.is_none() || fields.next().is_some() {
        return Ok(None);
    }
    Ok(path.map(str::to_owned))
}

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

/// Build a gzipped tar containing release-shaped VM binaries and assets where
/// mvmctl is a shell stub printing a version.
fn make_tarball(target: &str) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let dir = format!("mvmctl-{target}");
    // The stub records its argv to `$MVM_TEST_INVOCATION_LOG` (default
    // /dev/null, so tests that don't set it are unaffected) so a test can
    // assert whether install.sh invoked `mvmctl bootstrap`.
    let stub =
        b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${MVM_TEST_INVOCATION_LOG:-/dev/null}\"\necho 'mvmctl 9.9.9'\n";
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
        format!("{dir}/assets/mvmctl.entitlements"),
        &ent[..],
    )
    .unwrap();
    let supervisor_entitlements = b"<plist><key>com.apple.security.hypervisor</key></plist>\n";
    let mut h3 = tar::Header::new_gnu();
    h3.set_size(supervisor_entitlements.len() as u64);
    h3.set_mode(0o644);
    h3.set_cksum();
    tar.append_data(
        &mut h3,
        format!("{dir}/assets/mvm-supervisor.entitlements"),
        &supervisor_entitlements[..],
    )
    .unwrap();
    for hostbin in ["mvm-hvf-supervisor", "mvm-libkrun-supervisor"] {
        let bytes = hostbin.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, format!("{dir}/{hostbin}"), bytes)
            .unwrap();
    }
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
                    // The listener is non-blocking so the stop channel can be
                    // observed. Accepted sockets are request/response streams:
                    // make that contract explicit on every platform, then read
                    // through the header terminator instead of assuming one
                    // `read` contains the entire request line.
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let path = read_request_path(&mut stream).ok().flatten();
                    let body = routes
                        .iter()
                        .find(|(candidate, _)| Some(candidate.as_str()) == path.as_deref())
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

#[test]
fn request_reader_collects_fragmented_headers() {
    struct FragmentedReader<'a> {
        fragments: VecDeque<&'a [u8]>,
    }

    impl Read for FragmentedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(fragment) = self.fragments.pop_front() else {
                return Ok(0);
            };
            assert!(fragment.len() <= buf.len());
            buf[..fragment.len()].copy_from_slice(fragment);
            Ok(fragment.len())
        }
    }

    let mut reader = FragmentedReader {
        fragments: VecDeque::from([
            b"G".as_slice(),
            b"ET /artifact HTTP/1.1\r\nHo".as_slice(),
            b"st: 127.0.0.1\r\nConnection: close\r\n\r\n".as_slice(),
        ]),
    };

    assert_eq!(
        read_request_path(&mut reader).unwrap().as_deref(),
        Some("/artifact")
    );
}

#[test]
fn request_reader_rejects_incomplete_headers() {
    let mut reader = b"GET /artifact HTTP/1.1\r\nHost: localhost\r\n".as_slice();

    assert_eq!(read_request_path(&mut reader).unwrap(), None);
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
fn install_sh_runs_machine_readiness_bootstrap_by_default_and_honors_optout() {
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

    let run = |skip_env: Option<&str>| -> String {
        let install_dir = tempfile::tempdir().unwrap();
        let log = install_dir.path().join("invocations.log");
        let mut cmd = Command::new("sh");
        cmd.arg(repo_root().join("install.sh"))
            .env("MVM_VERSION", "v9.9.9")
            .env("MVM_UPDATE_DOWNLOAD_URL", &base)
            .env("MVM_INSTALL_DIR", install_dir.path())
            .env("MVM_SKIP_CODESIGN", "1")
            .env("MVM_TEST_INVOCATION_LOG", &log);
        if let Some(name) = skip_env {
            cmd.env(name, "1");
        }
        assert!(cmd.status().unwrap().success(), "install.sh should succeed");
        std::fs::read_to_string(&log).unwrap_or_default()
    };

    // Default: install.sh runs `mvmctl bootstrap`.
    assert!(
        run(None).contains("bootstrap"),
        "default install must prepare infrastructure via `mvmctl bootstrap`"
    );
    // Preferred opt-out suppresses the whole readiness bootstrap.
    assert!(
        !run(Some("MVM_SKIP_BOOTSTRAP")).contains("bootstrap"),
        "MVM_SKIP_BOOTSTRAP=1 must skip bootstrap"
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

#[cfg(target_os = "macos")]
#[test]
fn install_sh_codesigns_all_macos_vm_targets() {
    use std::os::unix::fs::PermissionsExt;

    let target = host_target();
    let tarball = make_tarball(target);
    let archive = format!("mvmctl-{target}.tar.gz");
    let checks = format!("{}  {}\n", sha256_hex(&tarball), archive);
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

    let root = tempfile::tempdir().unwrap();
    let fake_bin = root.path().join("bin");
    std::fs::create_dir_all(&fake_bin).unwrap();
    let log = root.path().join("codesign.log");
    let codesign = fake_bin.join("codesign");
    std::fs::write(
        &codesign,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&codesign, std::fs::Permissions::from_mode(0o755)).unwrap();

    let install_dir = root.path().join("install");
    let path = format!("{}:{}", fake_bin.display(), std::env::var("PATH").unwrap());
    let status = Command::new("sh")
        .arg(repo_root().join("install.sh"))
        .env("MVM_VERSION", "v9.9.9")
        .env("MVM_UPDATE_DOWNLOAD_URL", &base)
        .env("MVM_INSTALL_DIR", &install_dir)
        .env("MVM_SKIP_BUILDER_PREFETCH", "1")
        .env("PATH", path)
        .status()
        .unwrap();
    assert!(status.success(), "install.sh should sign the VM targets");

    let log = std::fs::read_to_string(log).unwrap();
    assert!(log.contains("mvmctl"), "mvmctl was not codesigned: {log}");
    assert!(
        log.contains("mvm-hvf-supervisor"),
        "HVF supervisor was not codesigned: {log}"
    );
    assert!(
        log.contains("mvm-libkrun-supervisor"),
        "libkrun supervisor was not codesigned: {log}"
    );
}

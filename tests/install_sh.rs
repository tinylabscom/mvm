//! Integration tests for the repo-root `install.sh` and `uninstall.sh`. Serves
//! fake release assets over a loopback HTTP server and drives the scripts with
//! their documented env overrides, always against a temporary install dir,
//! library dir, `HOME` and `MVM_HOME`.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn baked_version() -> String {
    std::fs::read_to_string(repo_root().join("install.sh"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("DEFAULT_VERSION=\"")?.strip_suffix('"'))
        .expect("install.sh must carry a DEFAULT_VERSION sentinel")
        .to_owned()
}

/// The host binaries `release.yml` requires in the archive for `target`, read
/// from the workflow itself so this list cannot drift from the release job.
///
/// The job assigns a base `REQUIRED_HOSTBINS="..."` and, inside an
/// `apple-darwin` conditional, appends to it with
/// `REQUIRED_HOSTBINS="${REQUIRED_HOSTBINS} ..."`.
fn required_hostbins(target: &str) -> Vec<String> {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/release.yml"))
        .expect("read release.yml");
    let lines: Vec<&str> = workflow.lines().collect();
    let mut base = Vec::new();
    let mut darwin = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(value) = line
            .trim()
            .strip_prefix("REQUIRED_HOSTBINS=\"")
            .and_then(|rest| rest.strip_suffix('"'))
        else {
            continue;
        };
        let names = value
            .split_whitespace()
            .filter(|word| *word != "${REQUIRED_HOSTBINS}")
            .map(str::to_owned);
        let appended = value.starts_with("${REQUIRED_HOSTBINS}");
        let under_darwin = index
            .checked_sub(1)
            .and_then(|previous| lines.get(previous))
            .is_some_and(|previous| previous.contains("apple-darwin"));
        match (appended, under_darwin) {
            (false, false) => base.extend(names),
            (true, true) => darwin.extend(names),
            _ => panic!("unrecognised REQUIRED_HOSTBINS assignment in release.yml: {line}"),
        }
    }
    assert!(
        base.len() >= 5,
        "release.yml's REQUIRED_HOSTBINS parsed to {base:?}; the parser no longer matches the workflow"
    );
    assert!(
        !darwin.is_empty(),
        "release.yml's darwin REQUIRED_HOSTBINS addition was not found"
    );
    if target.ends_with("apple-darwin") {
        base.extend(darwin);
    }
    base
}

/// A shell stub `mvmctl` that reports `version` and records its argv to
/// `$MVM_TEST_INVOCATION_LOG` (default /dev/null) so a test can assert which
/// commands install.sh ran.
fn stub_mvmctl(version: &str) -> String {
    format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"${{MVM_TEST_INVOCATION_LOG:-/dev/null}}\"\necho 'mvmctl {version}'\n"
    )
}

/// A release-shaped archive: `mvmctl`, host binaries and entitlement assets.
struct Release {
    version: String,
    mvmctl: String,
    hostbins: Vec<String>,
    entitlements: bool,
}

impl Release {
    fn new(version: &str) -> Self {
        Self {
            version: version.to_owned(),
            mvmctl: stub_mvmctl(version),
            hostbins: vec![
                "mvm-hvf-supervisor".to_owned(),
                "mvm-libkrun-supervisor".to_owned(),
            ],
            entitlements: true,
        }
    }

    /// Only signing reads the profiles, and only macOS signs.
    #[cfg(target_os = "macos")]
    fn without_entitlements(mut self) -> Self {
        self.entitlements = false;
        self
    }

    fn with_mvmctl(mut self, script: String) -> Self {
        self.mvmctl = script;
        self
    }

    fn with_hostbins(mut self, hostbins: Vec<String>) -> Self {
        self.hostbins = hostbins;
        self
    }

    fn archive_name() -> String {
        format!("mvmctl-{}.tar.gz", host_target())
    }

    fn tarball(&self) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let dir = format!("mvmctl-{}", host_target());
        let mut tar = tar::Builder::new(Vec::new());
        let mut append = |path: String, bytes: &[u8], mode: u32| {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            tar.append_data(&mut header, path, bytes).unwrap();
        };
        append(format!("{dir}/mvmctl"), self.mvmctl.as_bytes(), 0o755);
        if self.entitlements {
            append(
                format!("{dir}/assets/mvmctl.entitlements"),
                b"<plist><key>com.apple.security.virtualization</key></plist>\n",
                0o644,
            );
            append(
                format!("{dir}/assets/mvm-supervisor.entitlements"),
                b"<plist><key>com.apple.security.hypervisor</key></plist>\n",
                0o644,
            );
        } else {
            append(format!("{dir}/assets/NOTICE"), b"no profiles\n", 0o644);
        }
        append(format!("{dir}/README.md"), b"# mvmctl\n", 0o644);
        for hostbin in &self.hostbins {
            let body = format!("#!/bin/sh\necho '{hostbin} {}'\n", self.version);
            append(format!("{dir}/{hostbin}"), body.as_bytes(), 0o755);
        }
        let tar_bytes = tar.into_inner().unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    /// The archive and its checksum manifest, at the release download paths.
    fn routes(&self) -> Vec<(String, Vec<u8>)> {
        let tarball = self.tarball();
        let archive = Self::archive_name();
        let checks = format!("{}  {}\n", sha256_hex(&tarball), archive);
        let base = format!("/tinylabscom/mvm/releases/download/{}", self.version);
        vec![
            (format!("{base}/{archive}"), tarball),
            (format!("{base}/checksums-sha256.txt"), checks.into_bytes()),
        ]
    }
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

fn serve_releases(releases: &[&Release]) -> (String, mpsc::Sender<()>) {
    serve(
        releases
            .iter()
            .flat_map(|release| release.routes())
            .collect(),
    )
}

/// A throwaway host: install dir, library dir, `HOME` and `MVM_HOME`, all
/// under one temporary root.
struct Host {
    _tempdir: tempfile::TempDir,
    /// The temporary root with every link resolved, which is how the scripts
    /// write the paths they record.
    root: PathBuf,
}

impl Host {
    fn new() -> Self {
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let host = Self {
            _tempdir: tempdir,
            root,
        };
        std::fs::create_dir_all(host.home()).unwrap();
        host
    }

    fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }

    fn lib(&self) -> PathBuf {
        self.root.join("lib").join("mvm")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn mvm_home(&self) -> PathBuf {
        self.home()
            .join(mvm_core::config::DEFAULT_MVM_HOME_DIR_NAME)
    }

    fn keys_dir(&self) -> PathBuf {
        mvm_core::config::mvm_keys_dir_at(self.mvm_home())
    }

    fn config_path(&self) -> PathBuf {
        let config_dir = mvm_core::config::mvm_config_dir_at(self.mvm_home());
        config_dir.join("config.toml")
    }

    fn host_agent_dir(&self, tenant: &str) -> PathBuf {
        mvm_core::config::host_agent_dir_at(self.mvm_home(), tenant)
    }

    /// `sh <script>` with every path the scripts derive pinned inside the host.
    fn script(&self, script: &str) -> Command {
        let mut command = self.pinned(Command::new("sh"));
        command.arg(repo_root().join(script));
        command
    }

    /// The real `mvmctl` under test, with the same pinned environment.
    fn mvmctl(&self) -> Command {
        self.pinned(Command::new(env!("CARGO_BIN_EXE_mvmctl")))
    }

    fn pinned(&self, mut command: Command) -> Command {
        command
            .env("HOME", self.home())
            .env("MVM_HOME", self.mvm_home())
            .env("MVM_INSTALL_DIR", self.bin())
            .env_remove("MVM_INSTALL_LIB_DIR")
            .env_remove("MVM_UNINSTALL_CHECKER")
            .env_remove("MVM_HOST_AGENT_PATH")
            .env_remove("MVM_INSTALL_KEEP")
            .env_remove("MVM_VERSION")
            .env("MVM_UPDATE_API_URL", "http://127.0.0.1:1")
            .env("MVM_SKIP_CODESIGN", "1")
            .env("MVM_SKIP_BOOTSTRAP", "1")
            .env("MVM_SKIP_RECONCILE", "1")
            // System tools only: an mvmctl or cosign the developer has on PATH
            // must not stand in for the ones under test.
            // `INSTALL_SH_TEST_TOOLS` prepends a directory, to run the scripts
            // under another `sh` or another set of core utilities.
            .env("PATH", test_tool_path())
            .stdin(Stdio::null());
        command
    }

    fn installer(&self, base: &str, version: &str) -> Command {
        let mut command = self.script("install.sh");
        command
            .env("MVM_UPDATE_DOWNLOAD_URL", base)
            .env("MVM_VERSION", version);
        command
    }

    fn install(&self, base: &str, version: &str) -> Output {
        self.installer(base, version).output().unwrap()
    }

    fn install_ok(&self, base: &str, version: &str) {
        let output = self.install(base, version);
        assert!(
            output.status.success(),
            "install of {version} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// `mvmctl --version` through the entry on PATH.
    fn mvmctl_version(&self) -> String {
        let output = Command::new(self.bin().join("mvmctl"))
            .arg("--version")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "installed mvmctl does not run: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn release_dirs(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.lib())
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    /// Everything outside `HOME`: the install dir and the library dir.
    fn install_snapshot(&self) -> Vec<String> {
        let home = self.home().display().to_string();
        self.snapshot()
            .into_iter()
            .filter(|path| !path.starts_with(&home))
            .collect()
    }

    /// Everything under `HOME`, the mvm state directory included.
    fn state_snapshot(&self) -> Vec<String> {
        let home = self.home().display().to_string();
        self.snapshot()
            .into_iter()
            .filter(|path| path.starts_with(&home))
            .collect()
    }

    fn current_target(&self) -> PathBuf {
        std::fs::read_link(self.lib().join("current")).unwrap()
    }

    /// Every path under the host root with its kind and link target, for
    /// asserting that a refused operation changed nothing.
    fn snapshot(&self) -> Vec<String> {
        fn walk(dir: &Path, out: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let kind = entry.file_type().unwrap();
                if kind.is_symlink() {
                    let target = std::fs::read_link(&path).unwrap();
                    out.push(format!("{} -> {}", path.display(), target.display()));
                } else if kind.is_dir() {
                    out.push(format!("{}/", path.display()));
                    walk(&path, out);
                } else {
                    out.push(path.display().to_string());
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out.sort();
        out
    }
}

fn test_tool_path() -> String {
    const SYSTEM: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
    match std::env::var("INSTALL_SH_TEST_TOOLS") {
        Ok(prefix) if !prefix.is_empty() => format!("{prefix}:{SYSTEM}"),
        _ => SYSTEM.to_owned(),
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
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

#[test]
fn install_sh_uses_baked_version_without_calling_api() {
    let version = baked_version();
    let release = Release::new(&version);
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    let status = host
        .script("install.sh")
        .env("MVM_UPDATE_DOWNLOAD_URL", &base)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "baked install should succeed without reaching the API"
    );
    assert_eq!(host.mvmctl_version(), format!("mvmctl {version}"));
}

#[test]
fn install_sh_falls_back_to_api_after_baked_version_404() {
    let release = Release::new("v9.9.9");
    let mut routes = release.routes();
    routes.push((
        "/repos/tinylabscom/mvm/releases/latest".to_string(),
        br#"{"tag_name":"v9.9.9"}"#.to_vec(),
    ));
    let (base, _stop) = serve(routes);

    let host = Host::new();
    let status = host
        .script("install.sh")
        .env("MVM_UPDATE_API_URL", &base)
        .env("MVM_UPDATE_DOWNLOAD_URL", &base)
        .status()
        .unwrap();
    assert!(status.success(), "404 should fall back to the API release");
    assert_eq!(host.mvmctl_version(), "mvmctl v9.9.9");
}

#[test]
fn install_sh_honors_explicit_version_without_calling_api() {
    let release = Release::new("v9.9.9");
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    let output = host.install(&base, "v9.9.9");
    assert!(
        output.status.success(),
        "explicit version should succeed without reaching the API: {}",
        stderr(&output)
    );
}

#[test]
fn install_sh_runs_machine_readiness_bootstrap_by_default_and_honors_optout() {
    let release = Release::new("v9.9.9");
    let (base, _stop) = serve_releases(&[&release]);

    let run = |skip_bootstrap: bool| -> String {
        let host = Host::new();
        let log = host.root.join("invocations.log");
        let mut command = host.installer(&base, "v9.9.9");
        command.env("MVM_TEST_INVOCATION_LOG", &log);
        if !skip_bootstrap {
            command.env_remove("MVM_SKIP_BOOTSTRAP");
        }
        assert!(
            command.status().unwrap().success(),
            "install.sh should succeed"
        );
        std::fs::read_to_string(&log).unwrap_or_default()
    };

    // Default: install.sh runs `mvmctl bootstrap`.
    assert!(
        run(false).contains("bootstrap"),
        "default install must prepare infrastructure via `mvmctl bootstrap`"
    );
    // Preferred opt-out suppresses the whole readiness bootstrap.
    assert!(
        !run(true).contains("bootstrap"),
        "MVM_SKIP_BOOTSTRAP=1 must skip bootstrap"
    );
}

#[test]
fn install_sh_rejects_tampered_checksum() {
    let release = Release::new("v9.9.9");
    let mut routes = release.routes();
    // Wrong checksum on purpose.
    routes[1].1 = format!("{}  {}\n", "0".repeat(64), Release::archive_name()).into_bytes();
    let (base, _stop) = serve(routes);

    let host = Host::new();
    let output = host.install(&base, "v9.9.9");
    assert!(
        !output.status.success(),
        "tampered checksum must fail the install"
    );
    assert!(!host.bin().join("mvmctl").exists(), "no binary on failure");
    assert!(!host.lib().exists(), "no release directory on failure");
}

#[test]
fn install_sh_installs_every_host_binary_the_release_job_requires() {
    let target = host_target();
    let hostbins = required_hostbins(target);
    let release = Release::new("v9.9.9").with_hostbins(hostbins.clone());
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    host.install_ok(&base, "v9.9.9");

    for hostbin in &hostbins {
        let beside_mvmctl = host.bin().join(hostbin);
        assert!(
            beside_mvmctl.is_file(),
            "{hostbin} is required by release.yml for {target} but is not beside {}",
            host.bin().join("mvmctl").display()
        );
        assert_eq!(
            std::fs::read_link(&beside_mvmctl).unwrap(),
            host.lib().join("current").join(hostbin),
            "{hostbin} must resolve through the current release"
        );
        // Linux resolves mvmctl's own path through every link, so the release
        // directory must hold the full set as well.
        assert!(
            host.current_target().join(hostbin).is_file(),
            "{hostbin} missing from the release directory"
        );
    }
    assert!(
        host.bin()
            .join("assets")
            .join("mvmctl.entitlements")
            .is_file()
    );
    assert!(
        !host.bin().join("README.md").exists(),
        "only executables and assets belong on PATH"
    );
}

#[test]
fn install_sh_leaves_out_the_optional_libkrun_supervisor() {
    let release = Release::new("v9.9.9");
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    host.install_ok(&base, "v9.9.9");

    assert!(host.bin().join("mvm-hvf-supervisor").is_file());
    assert!(!host.bin().join("mvm-libkrun-supervisor").exists());
    assert!(
        !host
            .current_target()
            .join("mvm-libkrun-supervisor")
            .exists()
    );
}

#[test]
fn install_sh_upgrade_swaps_the_whole_set_and_keeps_a_bounded_history() {
    let releases: Vec<Release> = ["v1.0.0", "v2.0.0", "v3.0.0", "v4.0.0"]
        .iter()
        .map(|version| Release::new(version))
        .collect();
    let (base, _stop) = serve_releases(&releases.iter().collect::<Vec<_>>());

    let host = Host::new();
    for release in &releases {
        let output = host
            .installer(&base, &release.version)
            .env("MVM_INSTALL_KEEP", "2")
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert_eq!(host.mvmctl_version(), format!("mvmctl {}", release.version));
    }

    assert_eq!(host.release_dirs(), vec!["3-v3.0.0", "4-v4.0.0"]);
    assert_eq!(host.current_target(), host.lib().join("4-v4.0.0"));
    // Every PATH entry reaches the release through the one `current` link, so
    // renaming that link is the whole swap.
    for name in ["mvmctl", "mvm-hvf-supervisor", "assets"] {
        assert_eq!(
            std::fs::read_link(host.bin().join(name)).unwrap(),
            host.lib().join("current").join(name),
            "{name} does not point through current"
        );
    }
    let supervisor = Command::new(host.bin().join("mvm-hvf-supervisor"))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&supervisor.stdout).trim(),
        "mvm-hvf-supervisor v4.0.0"
    );
    let leftovers: Vec<String> = host
        .snapshot()
        .into_iter()
        .filter(|path| path.contains(".mvm-new.") || path.contains(".install.lock"))
        .collect();
    assert!(leftovers.is_empty(), "staging debris: {leftovers:?}");
}

#[test]
fn install_sh_verifies_the_new_mvmctl_before_switching_to_it() {
    let log_dir = tempfile::tempdir().unwrap();
    let log = log_dir.path().join("invocations.log");
    // Records the path it was run through, then fails.
    let broken = Release::new("v2.0.0").with_mvmctl(
        "#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$MVM_TEST_INVOCATION_LOG\"\nexit 3\n".to_owned(),
    );
    let good = Release::new("v1.0.0");
    let (base, _stop) = serve_releases(&[&good, &broken]);

    let host = Host::new();
    host.install_ok(&base, "v1.0.0");
    let before = host.snapshot();

    let output = host
        .installer(&base, "v2.0.0")
        .env("MVM_TEST_INVOCATION_LOG", &log)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a broken release must not install"
    );
    assert_eq!(host.mvmctl_version(), "mvmctl v1.0.0");
    assert_eq!(host.snapshot(), before, "a refused upgrade changes nothing");
    let invocations = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !invocations.is_empty() && invocations.lines().all(|path| path.contains("/lib/mvm/")),
        "the broken mvmctl must be caught from its release directory, before any PATH \
         entry reaches it: {invocations}"
    );
}

#[test]
fn install_sh_rolls_back_when_the_switched_release_fails_through_path() {
    // Runs from its release directory but fails when reached through the PATH
    // entry, so the failure surfaces only after `current` has been switched.
    let fails_through_path =
        "#!/bin/sh\ncase \"$0\" in\n  */lib/mvm/*) echo 'mvmctl v2.0.0' ;;\n  *) exit 4 ;;\nesac\n";
    let good = Release::new("v1.0.0").with_hostbins(vec!["mvm-hvf-supervisor".to_owned()]);
    let failing = Release::new("v2.0.0")
        .with_mvmctl(fails_through_path.to_owned())
        .with_hostbins(vec![
            "mvm-hvf-supervisor".to_owned(),
            "mvm-broker".to_owned(),
            "mvm-audit-signer".to_owned(),
        ]);
    let (base, _stop) = serve_releases(&[&good, &failing]);

    let host = Host::new();
    host.install_ok(&base, "v1.0.0");
    // A link of the user's own that the new release's entry replaces.
    std::os::unix::fs::symlink("/opt/elsewhere/mvm-broker", host.bin().join("mvm-broker")).unwrap();
    let before = host.snapshot();

    let output = host.install(&base, "v2.0.0");
    assert!(
        !output.status.success(),
        "a release that fails after the switch must not install"
    );
    assert!(
        stderr(&output).contains("previous release"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.mvmctl_version(), "mvmctl v1.0.0");
    assert_eq!(
        host.snapshot(),
        before,
        "rollback restores current and the replaced link, and drops the new release \
         and its new PATH entries"
    );
}

#[test]
fn install_sh_adopts_an_unversioned_install_so_its_upgrade_can_roll_back() {
    use std::os::unix::fs::PermissionsExt;
    let broken = Release::new("v2.0.0").with_mvmctl("#!/bin/sh\nexit 3\n".to_owned());
    let good = Release::new("v3.0.0");
    let (base, _stop) = serve_releases(&[&broken, &good]);

    let host = Host::new();
    std::fs::create_dir_all(host.bin().join("assets")).unwrap();
    std::fs::write(host.bin().join("assets/mvmctl.entitlements"), "<plist/>").unwrap();
    for (name, body) in [
        ("mvmctl", stub_mvmctl("v1.0.0")),
        ("mvm-hvf-supervisor", "#!/bin/sh\n".to_owned()),
        ("mvm-libkrun-supervisor", "#!/bin/sh\n".to_owned()),
        ("unrelated-tool", "#!/bin/sh\n".to_owned()),
    ] {
        let path = host.bin().join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let output = host.install(&base, "v2.0.0");
    assert!(!output.status.success());
    assert_eq!(host.mvmctl_version(), "mvmctl v1.0.0");
    assert_eq!(host.current_target(), host.lib().join("1-unversioned"));

    // A second attempt reuses the preserved install rather than refusing the
    // files it already carried.
    host.install_ok(&base, "v3.0.0");
    assert_eq!(host.mvmctl_version(), "mvmctl v3.0.0");
    assert_eq!(host.release_dirs(), vec!["1-unversioned", "2-v3.0.0"]);
    assert!(
        !host.bin().join("mvm-libkrun-supervisor").exists(),
        "an old payload the release leaves out is moved off PATH"
    );
    assert!(
        host.lib()
            .join("1-unversioned/mvm-libkrun-supervisor")
            .is_file(),
        "and kept with the preserved install"
    );
    assert!(
        !std::fs::symlink_metadata(host.bin().join("unrelated-tool"))
            .unwrap()
            .is_symlink(),
        "a file the old installer never made is not mvm's to move"
    );
}

#[test]
fn install_sh_refuses_to_replace_an_entry_it_did_not_create() {
    let release = Release::new("v1.0.0");
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    std::fs::create_dir_all(host.bin().join("assets")).unwrap();
    std::fs::write(host.bin().join("assets/thesis.tex"), "chapter one").unwrap();

    let output = host.install(&base, "v1.0.0");
    assert!(!output.status.success(), "a foreign directory must refuse");
    assert!(
        stderr(&output).contains("did not create"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        std::fs::read_to_string(host.bin().join("assets/thesis.tex")).unwrap(),
        "chapter one"
    );
    assert!(!host.bin().join("mvmctl").exists());
    assert!(
        !host.lib().exists(),
        "a failed first install leaves no library"
    );
}

/// A library directory holding someone's numbered directories.
fn populate_unrelated_numbered_dirs(dir: &Path) {
    for (name, file) in [("2024-photos", "beach.jpg"), ("1-intro", "notes.md")] {
        std::fs::create_dir_all(dir.join(name)).unwrap();
        std::fs::write(dir.join(name).join(file), "keep me").unwrap();
    }
}

#[test]
fn install_and_uninstall_refuse_an_unmarked_library_directory() {
    let release = Release::new("v1.0.0");
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    std::fs::create_dir_all(host.bin()).unwrap();
    populate_unrelated_numbered_dirs(&host.lib());
    let before = host.snapshot();

    let output = host.install(&base, "v1.0.0");
    assert!(!output.status.success(), "an unmarked library must refuse");
    assert!(
        stderr(&output).contains("was not created by install.sh"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.snapshot(), before);

    let output = host
        .script("uninstall.sh")
        .env("MVM_INSTALL_LIB_DIR", host.lib())
        .arg("--purge")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "finding nothing to remove is not success"
    );
    assert!(
        stderr(&output).contains("leaving it untouched"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.snapshot(), before);
}

#[test]
fn install_and_uninstall_leave_unmarked_numbered_dirs_in_their_library_alone() {
    let releases: Vec<Release> = ["v1.0.0", "v2.0.0", "v3.0.0"]
        .iter()
        .map(|version| Release::new(version))
        .collect();
    let (base, _stop) = serve_releases(&releases.iter().collect::<Vec<_>>());

    let host = Host::new();
    let install_keeping_two = |version: &str| {
        let output = host
            .installer(&base, version)
            .env("MVM_INSTALL_KEEP", "2")
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
    };
    install_keeping_two("v1.0.0");
    populate_unrelated_numbered_dirs(&host.lib());
    install_keeping_two("v2.0.0");
    // A release a crashed run never finished: marked, but still staging, and
    // newer than the complete release that must survive the next prune.
    std::fs::create_dir_all(host.lib().join("3-v0.9.0")).unwrap();
    std::fs::write(host.lib().join("3-v0.9.0/.mvm-release"), "staging\n").unwrap();
    install_keeping_two("v3.0.0");
    assert_eq!(
        host.release_dirs(),
        vec!["1-intro", "2-v2.0.0", "2024-photos", "4-v3.0.0"],
        "only marked releases are numbered from, counted and pruned; the staging one \
         is removed without taking a complete release's place"
    );

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(host.release_dirs(), vec!["1-intro", "2024-photos"]);
    for (name, file) in [("2024-photos", "beach.jpg"), ("1-intro", "notes.md")] {
        assert_eq!(
            std::fs::read_to_string(host.lib().join(name).join(file)).unwrap(),
            "keep me"
        );
    }
    assert!(!host.bin().join("mvmctl").exists());
}

#[test]
fn install_sh_refuses_a_current_that_is_not_a_link() {
    let release = Release::new("v1.0.0");
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    std::fs::create_dir_all(host.bin()).unwrap();
    std::fs::create_dir_all(host.lib().join("current")).unwrap();
    std::fs::write(host.lib().join(".mvm-lib"), "").unwrap();
    let before = host.snapshot();

    let output = host.install(&base, "v1.0.0");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not a link"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.snapshot(), before);
}

#[test]
fn install_sh_clears_temporary_links_a_crashed_run_left() {
    let (base, _stop) = serve_releases(&[&Release::new("v1.0.0"), &Release::new("v2.0.0")]);

    let host = Host::new();
    host.install_ok(&base, "v1.0.0");
    std::os::unix::fs::symlink("/nowhere", host.bin().join("mvmctl.mvm-new.4242")).unwrap();
    std::os::unix::fs::symlink("/nowhere", host.lib().join("current.mvm-new.4242")).unwrap();
    std::fs::write(host.bin().join("notes.mvm-new.txt"), "mine").unwrap();

    host.install_ok(&base, "v2.0.0");
    assert!(
        std::fs::symlink_metadata(host.bin().join("mvmctl.mvm-new.4242")).is_err()
            && std::fs::symlink_metadata(host.lib().join("current.mvm-new.4242")).is_err(),
        "stale temporary links must be removed"
    );
    assert!(host.bin().join("notes.mvm-new.txt").is_file());
}

#[test]
fn install_and_uninstall_refuse_while_another_run_holds_the_lock() {
    let (base, _stop) = serve_releases(&[&Release::new("v1.0.0"), &Release::new("v2.0.0")]);

    let host = Host::new();
    host.install_ok(&base, "v1.0.0");
    std::fs::create_dir(host.lib().join(".install.lock")).unwrap();
    let before = host.snapshot();

    let output = host.install(&base, "v2.0.0");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("in progress"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.snapshot(), before);

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("in progress"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.snapshot(), before);
}

#[cfg(target_os = "macos")]
fn fake_codesign(host: &Host) -> (String, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let fake_bin = host.root.join("fake-bin");
    std::fs::create_dir_all(&fake_bin).unwrap();
    let log = host.root.join("codesign.log");
    let codesign = fake_bin.join("codesign");
    std::fs::write(
        &codesign,
        format!(
            "#!/bin/sh\n[ -z \"${{FAKE_CODESIGN_FAIL:-}}\" ] || {{ echo 'signing refused' >&2; exit 1; }}\nprintf '%s\\n' \"$*\" >> \"{}\"\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&codesign, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin:/usr/sbin:/sbin", fake_bin.display());
    (path, log)
}

#[cfg(target_os = "macos")]
#[test]
fn install_sh_codesigns_each_binary_with_its_role_profile() {
    let mut hostbins = required_hostbins(host_target());
    hostbins.push("mvm-libkrun-supervisor".to_owned());
    let release = Release::new("v9.9.9").with_hostbins(hostbins.clone());
    let (base, _stop) = serve_releases(&[&release]);

    let host = Host::new();
    let (path, log) = fake_codesign(&host);
    let output = host
        .installer(&base, "v9.9.9")
        .env_remove("MVM_SKIP_CODESIGN")
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "install.sh should sign the VM targets: {}",
        stderr(&output)
    );

    let log = std::fs::read_to_string(log).unwrap();
    let profile_for = |binary: &str| -> Option<String> {
        log.lines().find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let (target, rest) = fields.split_last()?;
            let profile = rest.last()?;
            (Path::new(target).file_name()? == binary).then(|| (*profile).to_owned())
        })
    };
    assert!(
        profile_for("mvmctl").is_some_and(|p| p.ends_with("/assets/mvmctl.entitlements")),
        "mvmctl must carry the virtualization profile: {log}"
    );
    assert!(
        profile_for("mvm-hvf-supervisor")
            .is_some_and(|p| p.ends_with("/assets/mvm-supervisor.entitlements")),
        "the HVF supervisor must carry the hypervisor profile: {log}"
    );
    for hostbin in hostbins
        .iter()
        .filter(|name| name.as_str() != "mvm-hvf-supervisor")
    {
        assert!(
            profile_for(hostbin).is_none(),
            "{hostbin} needs no entitlement and must keep its own signature: {log}"
        );
    }
    assert!(
        !host.bin().join("mvm-libkrun-supervisor").exists(),
        "the standard installer must not install the optional libkrun supervisor"
    );
}

#[cfg(target_os = "macos")]
fn install_with_codesign(host: &Host, base: &str, version: &str, fail_signing: bool) -> Output {
    let (path, _log) = fake_codesign(host);
    let mut command = host.installer(base, version);
    command.env_remove("MVM_SKIP_CODESIGN").env("PATH", &path);
    if fail_signing {
        command.env("FAKE_CODESIGN_FAIL", "1");
    }
    command.output().unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn install_sh_keeps_the_previous_release_when_codesign_fails() {
    let (base, _stop) = serve_releases(&[&Release::new("v1.0.0"), &Release::new("v2.0.0")]);

    let host = Host::new();
    let output = install_with_codesign(&host, &base, "v1.0.0", false);
    assert!(output.status.success(), "{}", stderr(&output));
    let before = host.snapshot();

    let output = install_with_codesign(&host, &base, "v2.0.0", true);
    assert!(
        !output.status.success(),
        "a signing failure must fail the install"
    );
    assert!(
        stderr(&output).contains("codesign failed"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.mvmctl_version(), "mvmctl v1.0.0");
    assert_eq!(host.snapshot(), before);
}

#[cfg(target_os = "macos")]
#[test]
fn install_sh_keeps_the_previous_release_when_a_required_profile_is_missing() {
    let (base, _stop) = serve_releases(&[
        &Release::new("v1.0.0"),
        &Release::new("v2.0.0").without_entitlements(),
    ]);

    let host = Host::new();
    let output = install_with_codesign(&host, &base, "v1.0.0", false);
    assert!(output.status.success(), "{}", stderr(&output));
    let before = host.snapshot();

    let output = install_with_codesign(&host, &base, "v2.0.0", false);
    assert!(
        !output.status.success(),
        "an unsignable mvmctl must fail the install"
    );
    assert!(
        stderr(&output).contains("missing entitlement profile"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.mvmctl_version(), "mvmctl v1.0.0");
    assert_eq!(host.snapshot(), before);
}

// ---- uninstall.sh ----

/// A release whose `mvmctl` hands every command to the real binary under test,
/// so the uninstaller's running-machine and daemon checks run the shipped code.
fn release_running_real_mvmctl(version: &str) -> Release {
    let real = env!("CARGO_BIN_EXE_mvmctl");
    Release::new(version)
        .with_mvmctl(format!("#!/bin/sh\nexec '{real}' \"$@\"\n"))
        .with_hostbins(vec![
            "mvm-hvf-supervisor".to_owned(),
            "mvm-network-endpoint".to_owned(),
        ])
}

/// An mvmctl from before `env uninstall --quiesce`: clap rejects the flag and
/// exits 2.
const PRE_QUIESCE_MVMCTL: &str = "#!/bin/sh\ncase \"$1\" in\n  env) echo \"error: unexpected argument '--quiesce' found\" >&2; exit 2 ;;\nesac\necho 'mvmctl v0.17.0'\n";

/// A child process killed and reaped when the test ends, however it ends.
struct Spawned(Option<Child>);

impl Spawned {
    fn sleep_as(program: &Path) -> Self {
        Self(Some(Command::new(program).arg("60").spawn().unwrap()))
    }

    fn pid(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    fn is_running(&mut self) -> bool {
        self.0.as_mut().unwrap().try_wait().unwrap().is_none()
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn sleep_binary() -> PathBuf {
    ["/bin/sleep", "/usr/bin/sleep"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .expect("a sleep binary")
}

/// A copy of `sleep` at `path`, runnable under its new name.
fn copy_sleep_to(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::copy(sleep_binary(), path).unwrap();
    // macOS kills a copied platform binary at exec; an ad-hoc signature lets
    // the copy run under its new name.
    if cfg!(target_os = "macos") {
        let signed = Command::new("/usr/bin/codesign")
            .args(["--sign", "-", "--force"])
            .arg(path)
            .output()
            .unwrap();
        assert!(signed.status.success(), "{}", stderr(&signed));
    }
}

/// Install a release that runs the real mvmctl, plus a populated state dir and
/// an unrelated file in the install dir that no uninstall may touch.
fn installed_host() -> (Host, mpsc::Sender<()>) {
    let release = release_running_real_mvmctl("v1.0.0");
    let (base, stop) = serve_releases(&[&release]);
    let host = Host::new();
    host.install_ok(&base, "v1.0.0");
    std::fs::write(host.bin().join("unrelated-tool"), "#!/bin/sh\n").unwrap();
    std::fs::create_dir_all(host.keys_dir()).unwrap();
    let config_path = host.config_path();
    std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    std::fs::write(config_path, "").unwrap();
    (host, stop)
}

fn record_daemon_pid(host: &Host, pid: u32) {
    let tenant = host.host_agent_dir("acme");
    std::fs::create_dir_all(&tenant).unwrap();
    std::fs::write(tenant.join("daemon.pid"), pid.to_string()).unwrap();
}

#[test]
fn uninstall_sh_refuses_while_a_machine_is_running_and_changes_nothing() {
    let (host, _stop) = installed_host();
    let mut supervisor = Spawned::sleep_as(&sleep_binary());
    let vm = mvm_core::config::vm_state_dir_at(host.mvm_home(), "web");
    std::fs::create_dir_all(&vm).unwrap();
    std::fs::write(vm.join("hvf.pid"), supervisor.pid().to_string()).unwrap();
    let before = host.snapshot();

    let output = host.script("uninstall.sh").arg("--purge").output().unwrap();

    assert!(!output.status.success(), "a running machine must refuse");
    assert!(stderr(&output).contains("web"), "{}", stderr(&output));
    assert_eq!(host.snapshot(), before);
    assert!(supervisor.is_running(), "the machine must not be touched");
}

#[test]
fn uninstall_sh_removes_exactly_the_install_set_and_keeps_state_without_purge() {
    let (host, _stop) = installed_host();
    let stopped = mvm_core::config::vm_state_dir_at(host.mvm_home(), "old");
    std::fs::create_dir_all(&stopped).unwrap();
    std::fs::write(stopped.join("hvf.pid"), "2147483646").unwrap();
    let state_before = host.state_snapshot();

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));

    let root = host.root.display().to_string();
    assert_eq!(
        host.install_snapshot(),
        vec![
            format!("{root}/bin/"),
            format!("{root}/bin/unrelated-tool"),
            format!("{root}/lib/"),
        ],
        "only the install set may be removed"
    );
    assert_eq!(
        host.state_snapshot(),
        state_before,
        "state is untouched without --purge"
    );
}

#[test]
fn uninstall_creates_no_state_directory_where_there_was_none() {
    for through_mvmctl in [false, true] {
        let (host, _stop) = installed_host();
        std::fs::remove_dir_all(host.mvm_home()).unwrap();

        let output = if through_mvmctl {
            host.mvmctl()
                .args(["env", "uninstall"])
                .env("MVM_INSTALL_LIB_DIR", host.lib())
                .output()
                .unwrap()
        } else {
            host.script("uninstall.sh").output().unwrap()
        };
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(
            !host.mvm_home().exists(),
            "uninstalling must not create the state directory (through mvmctl: {through_mvmctl})"
        );
        assert!(!host.lib().exists());
    }
}

#[test]
fn uninstall_dry_run_leaves_no_trace() {
    let (host, _stop) = installed_host();
    let before = host.snapshot();

    let output = host
        .script("uninstall.sh")
        .args(["--purge", "--dry-run"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Would remove"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Removed"));
    assert_eq!(host.snapshot(), before, "uninstall.sh --dry-run");

    let output = host
        .mvmctl()
        .args(["env", "uninstall", "--purge", "--dry-run"])
        .env("MVM_INSTALL_LIB_DIR", host.lib())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(host.snapshot(), before, "mvmctl env uninstall --dry-run");
}

#[test]
fn uninstall_sh_purge_removes_the_state_directory() {
    let (host, _stop) = installed_host();

    let output = host.script("uninstall.sh").arg("--purge").output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!host.mvm_home().exists(), "--purge removes MVM_HOME");
    assert!(!host.lib().exists());
    assert!(!host.bin().join("mvmctl").exists());
    assert!(
        host.home().is_dir(),
        "only the state directory goes, not HOME"
    );
}

/// Plant the file that marks a directory as mvm state: the host signing key.
fn plant_signing_key(dir: &Path) {
    std::fs::create_dir_all(dir.join("keys")).unwrap();
    std::fs::write(dir.join("keys/host-signer.ed25519"), "key").unwrap();
}

/// Run `uninstall.sh --purge` with `MVM_HOME` (and optionally `HOME`) set, and
/// assert it refuses without changing anything.
fn assert_purge_refused(host: &Host, what: &str, mvm_home: &Path, home: Option<&str>) {
    let before = host.snapshot();
    let mut command = host.script("uninstall.sh");
    command.arg("--purge");
    match home {
        Some(home) => command.env("HOME", home),
        None => command.env("HOME", host.home()),
    };
    let output = command.env("MVM_HOME", mvm_home).output().unwrap();
    assert!(!output.status.success(), "--purge must refuse {what}");
    assert!(
        stderr(&output).contains("refusing --purge"),
        "{what}: {}",
        stderr(&output)
    );
    assert_eq!(
        host.snapshot(),
        before,
        "{what}: the refusal comes before anything is removed"
    );
}

#[test]
fn uninstall_sh_purge_refuses_home_and_its_ancestors_even_holding_mvm_files() {
    let (host, _stop) = installed_host();
    // Both hold the signing key, so only the rule about HOME and its ancestors
    // can refuse them.
    plant_signing_key(&host.root);
    plant_signing_key(&host.home());
    assert_purge_refused(&host, "an ancestor of HOME", &host.root, None);
    assert_purge_refused(&host, "HOME itself", &host.home(), None);
}

#[test]
fn uninstall_sh_purge_refuses_a_directory_without_mvm_files() {
    let (host, _stop) = installed_host();
    let photos = host.root.join("photos");
    std::fs::create_dir_all(photos.join("keys")).unwrap();
    std::fs::write(photos.join("beach.jpg"), "keep me").unwrap();
    assert_purge_refused(
        &host,
        "a sibling of HOME holding only a keys/ folder",
        &photos,
        None,
    );

    let notes = host.root.join("notes");
    std::fs::create_dir_all(notes.join("audit")).unwrap();
    std::fs::write(notes.join("audit/2024.txt"), "keep me").unwrap();
    assert_purge_refused(
        &host,
        "a directory holding an audit/ folder with no chain",
        &notes,
        None,
    );
}

#[test]
fn uninstall_sh_purge_refuses_with_an_empty_home() {
    let (host, _stop) = installed_host();
    assert_purge_refused(
        &host,
        "state under an empty HOME",
        &host.mvm_home(),
        Some(""),
    );
}

#[test]
fn uninstall_sh_purge_never_follows_a_symlinked_state_directory() {
    // `.mvm` is a link to a directory that is not mvm state. Written with or
    // without a trailing slash, the link's name must not vouch for its target.
    for written in ["", "/"] {
        let (host, _stop) = installed_host();
        let victim = host.root.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("thesis.tex"), "chapter one").unwrap();
        let config = host.root.join("cfg");
        std::fs::create_dir_all(&config).unwrap();
        std::os::unix::fs::symlink(
            &victim,
            config.join(mvm_core::config::DEFAULT_MVM_HOME_DIR_NAME),
        )
        .unwrap();
        let mvm_home = PathBuf::from(format!(
            "{}{written}",
            config
                .join(mvm_core::config::DEFAULT_MVM_HOME_DIR_NAME)
                .display()
        ));

        assert_purge_refused(
            &host,
            &format!("a state-directory link to other data ({mvm_home:?})"),
            &mvm_home,
            None,
        );
        assert_eq!(
            std::fs::read_to_string(victim.join("thesis.tex")).unwrap(),
            "chapter one"
        );
    }

    // A link to real mvm state is unlinked, never emptied through the slash.
    for written in ["", "/"] {
        let (host, _stop) = installed_host();
        let state = host.root.join("real-state");
        plant_signing_key(&state);
        let link = host
            .root
            .join("cfg")
            .join(mvm_core::config::DEFAULT_MVM_HOME_DIR_NAME);
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&state, &link).unwrap();

        let output = host
            .script("uninstall.sh")
            .arg("--purge")
            .env("HOME", host.home())
            .env("MVM_HOME", format!("{}{written}", link.display()))
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "the link is removed ({written:?})"
        );
        assert!(
            state.join("keys/host-signer.ed25519").is_file(),
            "the directory it points at is left in place ({written:?})"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("Removed the link"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn install_sh_adopts_only_what_it_can_vouch_for_as_an_older_install() {
    use std::os::unix::fs::PermissionsExt;
    let release = Release::new("v2.0.0");
    let (base, _stop) = serve_releases(&[&release]);

    let not_mvmctl = "#!/bin/sh\necho 'not really mvmctl'\n".to_owned();
    for (what, mvmctl, foreign_asset) in [
        (
            "an mvmctl that is not mvmctl, beside a thesis in assets/",
            not_mvmctl.clone(),
            true,
        ),
        ("an mvmctl that is not mvmctl", not_mvmctl, false),
        (
            "a real older mvmctl beside a thesis in assets/",
            stub_mvmctl("v1.0.0"),
            true,
        ),
    ] {
        let host = Host::new();
        // The library's parent exists, as `~/.local/lib` usually does, so the
        // snapshot shows only what the install itself made.
        std::fs::create_dir_all(host.lib().parent().unwrap()).unwrap();
        std::fs::create_dir_all(host.bin().join("assets")).unwrap();
        std::fs::write(host.bin().join("assets/mvmctl.entitlements"), "<plist/>").unwrap();
        if foreign_asset {
            std::fs::write(host.bin().join("assets/thesis.tex"), "chapter one").unwrap();
        }
        let path = host.bin().join("mvmctl");
        std::fs::write(&path, mvmctl).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let before = host.snapshot();

        let output = host
            .installer(&base, "v2.0.0")
            .env("MVM_INSTALL_KEEP", "1")
            .output()
            .unwrap();
        assert!(!output.status.success(), "{what}: the install must refuse");
        assert!(
            stderr(&output).contains("refusing to replace"),
            "{what}: {}",
            stderr(&output)
        );
        assert_eq!(
            host.snapshot(),
            before,
            "{what}: nothing is adopted, staged or removed"
        );
    }
}

#[test]
fn install_sh_never_writes_a_marker_through_a_symlink() {
    let (base, _stop) = serve_releases(&[&Release::new("v1.0.0"), &Release::new("v2.0.0")]);
    let host = Host::new();
    host.install_ok(&base, "v1.0.0");
    let elsewhere = host.root.join("elsewhere.txt");
    std::fs::write(&elsewhere, "keep me").unwrap();
    std::fs::remove_file(host.lib().join(".mvm-lib")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, host.lib().join(".mvm-lib")).unwrap();

    host.install_ok(&base, "v2.0.0");
    assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "keep me");
    assert!(
        !std::fs::symlink_metadata(host.lib().join(".mvm-lib"))
            .unwrap()
            .is_symlink(),
        "the marker is rewritten as a regular file"
    );
}

#[test]
fn install_and_uninstall_share_one_rule_for_an_older_install() {
    let function = |script: &str| -> String {
        let text = std::fs::read_to_string(repo_root().join(script)).unwrap();
        let start = text
            .find("unversioned_install_entries() {")
            .unwrap_or_else(|| panic!("{script} lost unversioned_install_entries"));
        let end = start + text[start..].find("\n}\n").expect("function end");
        text[start..end].to_owned()
    };
    assert_eq!(
        function("install.sh"),
        function("uninstall.sh"),
        "install.sh adopts and uninstall.sh removes by the same rule"
    );
}

#[test]
fn uninstall_sh_refuses_to_signal_a_pid_that_is_not_the_daemon() {
    let (host, _stop) = installed_host();
    let mut unrelated = Spawned::sleep_as(&sleep_binary());
    record_daemon_pid(&host, unrelated.pid());
    let before = host.snapshot();

    let output = host.script("uninstall.sh").arg("--purge").output().unwrap();

    assert!(!output.status.success(), "an ambiguous PID must abort");
    assert!(
        stderr(&output).contains("may not be the host-agent daemon"),
        "{}",
        stderr(&output)
    );
    assert!(
        unrelated.is_running(),
        "the unrelated process must not be signalled"
    );
    assert_eq!(host.snapshot(), before);
}

#[test]
fn uninstall_sh_refuses_a_daemon_named_binary_outside_the_install() {
    let (host, _stop) = installed_host();
    let impostor = host.root.join("elsewhere").join("mvm-host-agent");
    copy_sleep_to(&impostor);
    let mut process = Spawned::sleep_as(&impostor);
    record_daemon_pid(&host, process.pid());
    let before = host.snapshot();

    let output = host.script("uninstall.sh").output().unwrap();

    assert!(!output.status.success(), "a name alone is not an identity");
    assert!(
        stderr(&output).contains("may not be the host-agent daemon"),
        "{}",
        stderr(&output)
    );
    assert!(process.is_running());
    assert_eq!(host.snapshot(), before);
}

#[test]
fn uninstall_sh_stops_an_installed_daemon_before_removing_the_install() {
    let (host, _stop) = installed_host();
    let daemon_bin = host.current_target().join("mvm-host-agent");
    copy_sleep_to(&daemon_bin);
    let mut daemon = Command::new(&daemon_bin).arg("60").spawn().unwrap();
    assert!(
        daemon.try_wait().unwrap().is_none(),
        "the stand-in daemon must be running before the uninstall"
    );
    let pid = daemon.id();
    // Reap the daemon the moment it exits, as init would for a real detached
    // daemon; an unreaped zombie still answers kill(pid, 0) on Linux.
    let reaper = thread::spawn(move || daemon.wait().unwrap());
    record_daemon_pid(&host, pid);

    let output = host.script("uninstall.sh").output().unwrap();

    // Whatever the uninstall did, do not leave the stand-in running. SIGKILL,
    // so a daemon the uninstall failed to stop cannot pass as one it stopped.
    if !reaper.is_finished() {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .stderr(Stdio::null())
            .status();
    }
    let status = reaper.join().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(15),
        "the uninstall must stop the daemon with SIGTERM, got {status:?}"
    );
    assert!(!host.bin().join("mvmctl").exists());
}

#[test]
fn uninstall_sh_names_force_when_the_installed_mvmctl_predates_the_check() {
    let release = Release::new("v0.17.0").with_mvmctl(PRE_QUIESCE_MVMCTL.to_owned());
    let (base, _stop) = serve_releases(&[&release]);
    let host = Host::new();
    host.install_ok(&base, "v0.17.0");
    std::fs::create_dir_all(host.keys_dir()).unwrap();
    let before = host.snapshot();

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("predates") && stderr(&output).contains("--force"),
        "{}",
        stderr(&output)
    );
    assert_eq!(host.snapshot(), before);

    let output = host.script("uninstall.sh").arg("--force").output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!host.lib().exists());
    assert!(host.keys_dir().is_dir());
}

#[test]
fn uninstall_sh_asks_no_mvmctl_when_there_is_no_state_directory() {
    // Machines and daemon PIDs are recorded under the state directory, so an
    // install that never ran one needs no check — not even from an mvmctl that
    // cannot perform it.
    let release = Release::new("v0.17.0").with_mvmctl(PRE_QUIESCE_MVMCTL.to_owned());
    let (base, _stop) = serve_releases(&[&release]);
    let host = Host::new();
    host.install_ok(&base, "v0.17.0");

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!host.lib().exists());
    assert!(!host.mvm_home().exists());
}

/// The layout the installer before release directories left: binaries and
/// assets copied straight into the install dir, beside a user's own files.
fn unversioned_host(mvmctl: &str) -> Host {
    use std::os::unix::fs::PermissionsExt;
    let host = Host::new();
    std::fs::create_dir_all(host.bin().join("assets")).unwrap();
    std::fs::write(host.bin().join("assets/mvmctl.entitlements"), "<plist/>").unwrap();
    std::fs::write(
        host.bin().join("assets/mvm-supervisor.entitlements"),
        "<plist/>",
    )
    .unwrap();
    for (name, body) in [
        ("mvmctl", mvmctl),
        ("mvm-hvf-supervisor", "#!/bin/sh\n"),
        ("mvm-network-endpoint", "#!/bin/sh\n"),
        ("mvm-broker", "#!/bin/sh\n"),
        ("unrelated-tool", "#!/bin/sh\n"),
    ] {
        let path = host.bin().join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    host
}

#[test]
fn uninstall_sh_removes_an_unversioned_install_by_its_known_names() {
    let host = unversioned_host(PRE_QUIESCE_MVMCTL);

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let root = host.root.display().to_string();
    assert_eq!(
        host.install_snapshot(),
        vec![
            format!("{root}/bin/"),
            format!("{root}/bin/mvm-broker"),
            format!("{root}/bin/unrelated-tool"),
        ],
        "only the files the old installer copied are removed"
    );
}

#[test]
fn uninstall_sh_on_an_unversioned_install_with_state_needs_force_from_an_old_mvmctl() {
    let host = unversioned_host(PRE_QUIESCE_MVMCTL);
    std::fs::create_dir_all(host.keys_dir()).unwrap();
    let before = host.snapshot();

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--force"), "{}", stderr(&output));
    assert_eq!(host.snapshot(), before);

    let output = host.script("uninstall.sh").arg("--force").output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!host.bin().join("mvmctl").exists());
    assert!(!host.bin().join("assets").exists());
}

#[test]
fn uninstall_sh_refuses_an_unversioned_mvmctl_that_is_not_mvmctl() {
    let host = unversioned_host("#!/bin/sh\necho 'something else 1.0'\n");
    let before = host.snapshot();

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(!output.status.success());
    assert_eq!(host.snapshot(), before);
}

#[test]
fn uninstall_sh_finding_nothing_is_not_success() {
    let host = Host::new();
    std::fs::create_dir_all(host.bin()).unwrap();

    let output = host.script("uninstall.sh").output().unwrap();
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("no mvmctl installation found"),
        "{}",
        stderr(&output)
    );
}

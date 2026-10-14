use runmvm_client::{DiscoveryOptions, Error, Hostlib};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    time::Duration,
};
use wait_timeout::ChildExt;

struct Scratch {
    path: PathBuf,
    _directory: tempfile::TempDir,
}
impl Scratch {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("runmvm-client-")
            .tempdir()
            .unwrap();
        Self {
            path: directory.path().to_path_buf(),
            _directory: directory,
        }
    }
}
fn build(dir: &Path, variant: &str) -> PathBuf {
    let output = dir.join(format!("{variant}.{}", std::env::consts::DLL_EXTENSION));
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixture.rs");
    let mut command = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
    command.args([
        "--edition=2024",
        "--crate-type=cdylib",
        "--crate-name=hostlib_fixture",
    ]);
    if variant != "good" {
        command.args(["--cfg", variant]);
    }
    let child = command.arg(source).arg("-o").arg(&output).spawn().unwrap();
    assert!(bounded_wait(child, Duration::from_secs(60)).success());
    output
}

fn bounded_wait(mut child: Child, timeout: Duration) -> ExitStatus {
    match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        outcome => {
            // A concurrent exit can make kill fail. Always attempt reaping,
            // even when termination itself reports an error.
            let killed = child.kill();
            let reaped = child.wait();
            panic!("test subprocess did not finish: {outcome:?}; kill={killed:?}; reap={reaped:?}");
        }
    }
}

#[test]
fn relative_paths_in_isolated_process() {
    let scratch = Scratch::new();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "relative_paths_child", "--nocapture"])
        .env("RUNMVM_CLIENT_RELATIVE_TEST", "1")
        .current_dir(&scratch.path)
        .spawn()
        .unwrap();
    // Let the child's shorter rustc deadline kill and reap its own compiler.
    assert!(bounded_wait(child, Duration::from_secs(120)).success());
}

#[test]
fn relative_paths_child() {
    if std::env::var_os("RUNMVM_CLIENT_RELATIVE_TEST").is_none() {
        return;
    }
    let good = build(Path::new("."), "good");
    let bare = good.file_name().unwrap();
    let absolute = good.canonicalize().unwrap();
    let options = DiscoveryOptions {
        hostlib_path: Some(PathBuf::from(bare)),
        path: None,
    };
    assert_eq!(options.resolve().unwrap(), absolute);
    // SAFETY: this child compiled the fixture and owns its isolated directory.
    let host = unsafe { Hostlib::load(Path::new(bare)) }.unwrap();
    assert_eq!(
        host.call_value("none", None).unwrap(),
        serde_json::Value::Null
    );
    let name = if cfg!(target_os = "macos") {
        "libmvm_hostlib.dylib"
    } else if cfg!(windows) {
        "mvm_hostlib.dll"
    } else {
        "libmvm_hostlib.so"
    };
    std::fs::copy(&good, name).unwrap();
    let executable = if cfg!(windows) {
        "mvmctl.exe"
    } else {
        "mvmctl"
    };
    std::fs::write(executable, b"must not execute").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let options = DiscoveryOptions {
        hostlib_path: None,
        path: Some(std::env::join_paths([Path::new("")]).unwrap()),
    };
    assert_eq!(
        options.resolve().unwrap(),
        Path::new(name).canonicalize().unwrap()
    );
    // SAFETY: discovery selects the fixture copied within this isolated directory.
    let host = unsafe { Hostlib::discover(options) }.unwrap();
    assert_eq!(host.abi_version(), (1 << 16) | 7);
}

#[test]
fn native_ownership_negotiation_and_errors() {
    let scratch = Scratch::new();
    let good = build(&scratch.path, "good");
    // SAFETY: this test owns and compiles the exact fixture ABI.
    let monitor = unsafe { libloading::Library::new(&good) }.unwrap();
    // SAFETY: fixture exports this exact signature, monitor remains live.
    let frees =
        unsafe { monitor.get::<unsafe extern "C" fn() -> usize>(b"fixture_frees\0") }.unwrap();
    let count = || unsafe { frees() };
    let host = unsafe { Hostlib::load(&good) }.unwrap();
    assert_eq!(host.abi_version(), (1 << 16) | 7);
    assert_eq!(
        host.call_json_bytes("echo", Some(b"{\"x\":\"a\\u0000b\"}"))
            .unwrap(),
        b"{\"x\":\"a\\u0000b\"}"
    );
    assert_eq!(count(), 1);
    assert_eq!(
        host.call_value("none", None).unwrap(),
        serde_json::Value::Null
    );
    assert_eq!(count(), 2);
    assert!(matches!(
        host.call_value("error", None),
        Err(Error::Native { status: 913, .. })
    ));
    assert_eq!(count(), 3);
    assert!(matches!(
        host.call_value("parse", None),
        Err(Error::Json { status: 0 })
    ));
    assert_eq!(count(), 4);
    for method in ["null", "oversize"] {
        assert!(matches!(host.call_value(method, None), Err(Error::Buffer)));
    }
    assert_eq!(count(), 6);
    assert!(matches!(
        unsafe { Hostlib::load(build(&scratch.path, "bad_abi")) },
        Err(Error::Abi { .. })
    ));
    assert!(matches!(
        unsafe { Hostlib::load(build(&scratch.path, "missing_free")) },
        Err(Error::Load)
    ));
}

#[test]
fn injected_discovery_does_not_execute_cli() {
    let scratch = Scratch::new();
    let executable = scratch.path.join(if cfg!(windows) {
        "mvmctl.exe"
    } else {
        "mvmctl"
    });
    std::fs::write(&executable, b"must not execute").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let name = if cfg!(target_os = "macos") {
        "libmvm_hostlib.dylib"
    } else if cfg!(windows) {
        "mvm_hostlib.dll"
    } else {
        "libmvm_hostlib.so"
    };
    let library = scratch.path.join(name);
    std::fs::write(&library, b"discovery only").unwrap();
    let options = DiscoveryOptions {
        hostlib_path: None,
        path: Some(std::env::join_paths([&scratch.path]).unwrap()),
    };
    assert_eq!(options.resolve().unwrap(), library.canonicalize().unwrap());
    let options = DiscoveryOptions {
        hostlib_path: Some(scratch.path.join("missing")),
        ..options
    };
    assert!(matches!(options.resolve(), Err(Error::ExplicitPath)));
}

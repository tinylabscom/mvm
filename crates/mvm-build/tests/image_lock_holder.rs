//! Regression test: store-image sidecar lock survives the starter process.
//!
//! Proves that the store-image sidecar lock survives the process that started
//! the holder. This is the invariant the store-lock ownership fix enforces: a
//! persistent-builder supervisor holds the lock for the VM's lifetime, even
//! after the `mvmctl persistent-builder start` CLI exits.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Locate the helper binary that this test drives.
///
/// Cargo sets `CARGO_BIN_EXE_<name>` when running integration tests so tests
/// can find binaries declared in the same crate. Nextest uses the same binary
/// layout but sets `NEXTEST_BIN_EXE_<name>` instead, and a plain `cargo test`
/// run from an IDE may set neither, so every layout the CI matrix exercises is
/// covered.
fn helper_path() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_mvm-test-image-lock-holder") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("NEXTEST_BIN_EXE_mvm-test-image-lock-holder") {
        return PathBuf::from(path);
    }
    // Fallback for harnesses that do not set the cargo env: the helper lives in
    // the same profile directory as the test binary (e.g. target/debug).
    let test_bin = std::env::current_exe().expect("current test binary path");
    test_bin
        .parent()
        .and_then(|deps| deps.parent())
        .map(|profile| profile.join("mvm-test-image-lock-holder"))
        .filter(|path| path.exists())
        .expect("mvm-test-image-lock-holder helper not found next to test binary")
}

/// Append `.lock` to an image path, matching `image_lock::sidecar_lock_path`.
fn sidecar_lock_path(image: &Path) -> PathBuf {
    let mut s = image.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

/// Try to acquire an exclusive non-blocking `flock` on `path`.
///
/// Returns `true` if the lock was acquired, `false` if it is already held by
/// another process. Any other error panics.
fn try_lock(path: &Path) -> bool {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .expect("open sidecar for try-lock");
    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        // Release immediately; we only wanted to test contention.
        let _ = unsafe { libc::flock(fd, libc::LOCK_UN) };
        true
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EAGAIN) || err.raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            false
        } else {
            panic!("unexpected flock error: {err}");
        }
    }
}

/// Spawn the helper, wait for its READY signal, and return the child handle.
///
/// If the helper exits before signaling READY or the deadline expires, the
/// child is reaped so the test does not leave a zombie.
fn spawn_holder(lock_path: &Path) -> Child {
    let mut child = Command::new(helper_path())
        .arg(lock_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn image-lock holder");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        if Instant::now() > deadline {
            break Err("timed out waiting for READY from helper".to_string());
        }
        match reader.read_line(&mut line) {
            Ok(0) => break Err("helper exited before READY".to_string()),
            Ok(_) if line.trim() == "READY" => break Ok(()),
            Ok(_) => {
                line.clear();
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => break Err(format!("read helper stdout: {e}")),
        }
    };

    if ready.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    ready.expect("helper did not become READY");
    child
}

#[test]
fn store_image_lock_survives_holder_starter_exit() {
    // Create a store image and its sidecar lock file. We use the public API
    // to create the image, drop the lock, then hand the sidecar to the helper
    // so it can play the supervisor role.
    let scratch = tempfile::TempDir::new().expect("tempdir");
    let cache = scratch.path().join("builder-vm");
    let lock = mvm_build::builder_vm_runtime::acquire_nix_store_image_lock(&cache, "aarch64", 64)
        .expect("create store image and sidecar");
    let image_path = lock.path().to_path_buf();
    let lock_path = sidecar_lock_path(&image_path);
    drop(lock);

    // Sanity: the lock is free after we dropped it.
    assert!(
        try_lock(&lock_path),
        "sidecar must be unlocked before helper starts"
    );

    // Start the helper. It plays the supervisor: it acquires the lock and
    // keeps it alive. The test process plays the starter: it does not hold
    // the lock itself and could exit at this point.
    let mut helper = spawn_holder(&lock_path);

    // The starter (this process) no longer holds the lock. Assert that the
    // sidecar is still exclusively locked from a separate process context.
    assert!(
        !try_lock(&lock_path),
        "sidecar must remain locked while helper holds it"
    );

    // Terminate the helper and confirm the lock is released.
    helper.kill().expect("kill helper");
    let status = helper.wait().expect("wait for helper");
    // The helper may exit with a signal; that is fine for this test.
    let _ = status;

    assert!(
        try_lock(&lock_path),
        "sidecar must be unlocked after helper exits"
    );
}

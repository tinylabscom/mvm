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

#[test]
fn a_waiter_reclaims_the_lock_when_its_holder_dies() {
    // The holder is a separate process that never releases the lock on its
    // own. Killing it is the crash case: the waiter must pick the lock up by
    // itself, with no lock file for anyone to delete.
    let scratch = tempfile::TempDir::new().expect("tempdir");
    let lock_path = scratch.path().join("stage0.lock");
    std::fs::write(&lock_path, b"").expect("create lock file");
    let mut holder = spawn_holder(&lock_path);
    assert!(!try_lock(&lock_path), "the helper must hold the lock");

    let killer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        holder.kill().expect("kill the holder");
        holder.wait().expect("reap the holder");
    });

    let subject = mvm_build::builder_vm_runtime::LockSubject {
        what: "the test lock",
        remedy: "or give up",
    };
    let started = Instant::now();
    let acquired = mvm_build::builder_vm_runtime::acquire_lock_waiting(
        &lock_path,
        &subject,
        mvm_build::builder_vm_runtime::LockWait::of(Duration::from_secs(30)),
    )
    .expect("a dead holder's lock must be reclaimed by the waiter");
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "the waiter must have queued behind the live holder first"
    );
    killer.join().expect("killer thread");
    drop(acquired);
}

/// Set on the child process [`lock_wait_status_goes_to_stderr_and_stdout_stays_clean`]
/// spawns, naming the lock the child should wait on.
const WAIT_CHILD_ENV: &str = "MVM_TEST_LOCK_WAIT_CHILD";

/// The waiting half of the stdout/stderr split test, run in a child process
/// so its output streams can be captured. A no-op in an ordinary test run.
#[test]
fn lock_wait_child_waits_on_the_named_lock() {
    let Some(lock_path) = std::env::var_os(WAIT_CHILD_ENV) else {
        return;
    };
    let subject = mvm_build::builder_vm_runtime::LockSubject {
        what: "the test lock",
        remedy: "or give up",
    };
    let held = mvm_build::builder_vm_runtime::acquire_lock_waiting(
        Path::new(&lock_path),
        &subject,
        mvm_build::builder_vm_runtime::LockWait::of(Duration::from_secs(30)),
    )
    .expect("the child must get the lock once its holder dies");
    drop(held);
}

#[test]
fn lock_wait_status_goes_to_stderr_and_stdout_stays_clean() {
    // A command that prints JSON on stdout can block on a lock; the waiting
    // line must not end up inside the JSON a caller parses.
    let scratch = tempfile::TempDir::new().expect("tempdir");
    let lock_path = scratch.path().join("stage0.lock");
    std::fs::write(&lock_path, b"").expect("create lock file");
    let mut holder = spawn_holder(&lock_path);

    let child = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "lock_wait_child_waits_on_the_named_lock",
            "--nocapture",
        ])
        .env(WAIT_CHILD_ENV, &lock_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the waiting child");

    // Long enough for the wait to be announced, which happens at two seconds.
    std::thread::sleep(Duration::from_millis(3500));
    holder.kill().expect("kill the holder");
    holder.wait().expect("reap the holder");

    let output = child.wait_with_output().expect("wait for the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "child failed: {stderr}");
    assert!(
        stderr.contains("[mvm] waiting for the test lock — held by"),
        "the wait must be announced on stderr: {stderr}"
    );
    assert!(
        stderr.contains("— done in"),
        "an announced wait ends with a done line: {stderr}"
    );
    assert!(
        !stdout.contains("[mvm]") && !stdout.contains("waiting for"),
        "status must never reach stdout: {stdout}"
    );
}

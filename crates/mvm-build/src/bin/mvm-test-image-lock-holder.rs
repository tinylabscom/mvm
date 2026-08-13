//! Test fixture: hold an exclusive `flock` on a sidecar lock file.
//!
//! Used by `crates/mvm-build/tests/image_lock_holder.rs` to prove that the
//! store-image lock survives the process that started the holder. The binary
//! acquires the lock, prints `READY` to stdout, then blocks until it receives
//! EOF on stdin or is killed.
//!
//! This is intentionally not a user-facing tool; it exists only to exercise
//! cross-process locking invariants that unit tests inside one process cannot
//! reach.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

fn main() {
    let lock_path = std::env::args()
        .nth(1)
        .expect("usage: mvm-test-image-lock-holder <lock-path>");
    let lock_path = PathBuf::from(lock_path);

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(&lock_path)
        .expect("open lock file");

    // Acquire an exclusive lock and hold it until the process exits.
    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
    assert_eq!(rc, 0, "acquire exclusive flock");

    let mut stdout = std::io::stdout();
    stdout.write_all(b"READY\n").expect("write ready signal");
    stdout.flush().expect("flush ready signal");

    // Block until stdin closes or the process is terminated.
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
}

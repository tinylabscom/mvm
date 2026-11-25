//! How a thread following a file idles between reads.
//!
//! Two followers share this: the console capture's and the audit chain's.
//!
//! On Linux the follower blocks on inotify: a watch on the file (writes,
//! truncation, rename, unlink) and one on its directory (the file appearing,
//! or a new file renamed over it), plus an eventfd that a stop writes to. A
//! file nobody writes to costs the follower no wakeup at all, which is what an
//! idle workload's console and an idle unit's audit chain are.
//!
//! Every other host, and a Linux host that refuses inotify, re-checks the file
//! on a fixed interval. Watches only decide when the follower looks; the read
//! path is the same either way, so the two cannot disagree on what is read.

use std::path::Path;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

/// How often the timed fallback re-checks the file.
pub(crate) const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// What the follower blocks on between reads.
pub trait FileWait: Send + Sync {
    /// Start noticing changes to `path`. Called before every read, so a write
    /// that lands between the read and [`wait`](Self::wait) still ends the
    /// wait instead of being missed.
    fn arm(&self, path: &Path);

    /// Block until the file may have changed or [`interrupt`](Self::interrupt)
    /// was called. A spurious return is allowed; a missed change is not.
    fn wait(&self);

    /// End the current wait and every later one at once.
    fn interrupt(&self);
}

/// The quietest waiter this host supports.
pub fn for_file() -> Box<dyn FileWait> {
    #[cfg(target_os = "linux")]
    {
        match inotify::FileEvents::new() {
            Ok(events) => return Box::new(events),
            Err(error) => {
                tracing::debug!(%error, "inotify unavailable; file followers poll");
            }
        }
    }
    Box::new(Timed::default())
}

/// Re-check every [`POLL_INTERVAL`], returning at once after an interrupt.
#[derive(Default)]
struct Timed {
    interrupted: Mutex<bool>,
    wake: Condvar,
}

impl FileWait for Timed {
    fn arm(&self, _path: &Path) {}

    fn wait(&self) {
        let interrupted = self
            .interrupted
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *interrupted {
            return;
        }
        let _ = self.wake.wait_timeout(interrupted, POLL_INTERVAL);
    }

    fn interrupt(&self) {
        *self
            .interrupted
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
}

#[cfg(target_os = "linux")]
mod inotify {
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::Path;
    use std::sync::{Mutex, PoisonError};

    use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, eventfd, poll};
    use rustix::fs::inotify::{self, CreateFlags, WatchFlags};

    use super::{FileWait, POLL_INTERVAL};

    /// Changes to the followed file's own inode.
    const FILE_EVENTS: WatchFlags = WatchFlags::MODIFY
        .union(WatchFlags::ATTRIB)
        .union(WatchFlags::CLOSE_WRITE)
        .union(WatchFlags::MOVE_SELF)
        .union(WatchFlags::DELETE_SELF);

    /// A name appearing in the directory: the file created late, or rotated in.
    const DIRECTORY_EVENTS: WatchFlags = WatchFlags::CREATE
        .union(WatchFlags::MOVED_TO)
        .union(WatchFlags::ONLYDIR);

    pub(super) struct FileEvents {
        inotify: OwnedFd,
        interrupt: OwnedFd,
        watches: Mutex<Watches>,
    }

    #[derive(Default)]
    struct Watches {
        directory: Option<i32>,
        file: Option<i32>,
    }

    impl FileEvents {
        pub(super) fn new() -> io::Result<Self> {
            Ok(Self {
                inotify: inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)?,
                interrupt: eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?,
                watches: Mutex::default(),
            })
        }

        fn watches(&self) -> std::sync::MutexGuard<'_, Watches> {
            self.watches.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// The queued events only say "look again", so they are read and dropped.
        fn discard_events(&self) {
            let mut buf = [0u8; 4096];
            while matches!(rustix::io::read(&self.inotify, &mut buf), Ok(n) if n > 0) {}
        }
    }

    impl FileWait for FileEvents {
        fn arm(&self, path: &Path) {
            let mut watches = self.watches();
            if watches.directory.is_none() {
                watches.directory = path
                    .parent()
                    .and_then(|dir| inotify::add_watch(&self.inotify, dir, DIRECTORY_EVENTS).ok());
            }
            // Re-adding a watch on the same inode returns its existing
            // descriptor. A different one means the path now names a new file,
            // so the old file's watch would only report writes nobody reads.
            let file = inotify::add_watch(&self.inotify, path, FILE_EVENTS).ok();
            if let Some(old) = watches.file.filter(|old| Some(*old) != file) {
                let _ = inotify::remove_watch(&self.inotify, old);
            }
            watches.file = file;
        }

        fn wait(&self) {
            // Without the directory watch a late or rotated file would go
            // unnoticed, so fall back to the timed re-check.
            let timeout = match self.watches().directory {
                Some(_) => None,
                None => Timespec::try_from(POLL_INTERVAL).ok(),
            };
            let mut fds = [
                PollFd::new(&self.inotify, PollFlags::IN),
                PollFd::new(&self.interrupt, PollFlags::IN),
            ];
            match poll(&mut fds, timeout.as_ref()) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                // Never spin on a poll that keeps failing.
                Err(_) => std::thread::sleep(POLL_INTERVAL),
            }
            self.discard_events();
        }

        fn interrupt(&self) {
            // Never read back, so the eventfd stays readable and every later
            // wait returns at once too.
            let _ = rustix::io::write(&self.interrupt, &1u64.to_ne_bytes());
        }
    }
}

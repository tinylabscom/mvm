//! The one writer for host-side notices a foreground command prints over its
//! workload's output: egress refusals today, runtime approval prompts next.
//!
//! Every notice goes to stderr, whole, under one process-wide lock. A notice
//! written from a watcher thread therefore never lands in the middle of
//! another, and a caller that needs the terminal to itself for a moment — an
//! approval prompt waiting on an answer — takes [`hold`] and every notice
//! queues behind it until the guard drops.
//!
//! The sink is a trait so a test can read exactly what a user would see, and
//! so a renderer that keeps a live status line can take over: it only has to
//! clear its line before writing and redraw it after.

use std::io::Write as _;
use std::sync::{Mutex, MutexGuard};

static WRITER: Mutex<()> = Mutex::new(());

/// Keep every other notice off the terminal until the guard drops.
pub(in crate::commands) fn hold() -> MutexGuard<'static, ()> {
    WRITER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Where notices go.
pub(in crate::commands) trait NoticeSink: Send + Sync {
    /// Write `lines` as one block nothing else interleaves with.
    fn block(&self, lines: &[String]);

    /// Write one whole notice line.
    fn line(&self, text: &str) {
        self.block(&[text.to_string()]);
    }
}

/// The process's stderr, `[mvm]`-prefixed like the rest of the host's chrome.
pub(in crate::commands) struct Stderr;

impl NoticeSink for Stderr {
    fn block(&self, lines: &[String]) {
        let _writer = hold();
        let mut err = std::io::stderr().lock();
        for text in lines {
            let _ = writeln!(err, "[mvm] {text}");
        }
        let _ = err.flush();
    }
}

/// A sink that keeps what it was given, for tests.
#[cfg(test)]
#[derive(Default)]
pub(in crate::commands) struct Captured(pub Mutex<Vec<String>>);

#[cfg(test)]
impl NoticeSink for Captured {
    fn block(&self, lines: &[String]) {
        let _writer = hold();
        self.0.lock().unwrap().extend_from_slice(lines);
    }
}

#[cfg(test)]
impl Captured {
    pub(in crate::commands) fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A notice written while something holds the terminal waits for it,
    /// rather than landing in the middle of a prompt.
    #[test]
    fn a_held_terminal_queues_notices_until_it_is_released() {
        let sink = Arc::new(Captured::default());
        let guard = hold();
        let written = Arc::new(AtomicBool::new(false));
        let writer = {
            let sink = Arc::clone(&sink);
            let written = Arc::clone(&written);
            std::thread::spawn(move || {
                sink.line("egress blocked: a:443");
                written.store(true, Ordering::SeqCst);
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!written.load(Ordering::SeqCst), "the notice waited");
        drop(guard);
        writer.join().unwrap();
        assert_eq!(sink.lines(), ["egress blocked: a:443"]);
    }
}

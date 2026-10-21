//! Capture a dispatched job's stderr until its direct child exits.
//!
//! A detached descendant can retain the pipe's writer after the direct child
//! exits. The direct child's exit is therefore authoritative: drain output
//! already available at that point, then return without waiting for pipe EOF.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read};

/// Max stderr lines retained in the final `/job/result` tail.
pub(crate) const STDERR_TAIL_LINES: usize = 20;

/// Read `stderr` line by line until the direct child has exited and all output
/// available at that point is drained, returning `(exit_code, tail)`.
///
/// Exit is sampled before each read: output the child wrote ahead of exiting is
/// already in the pipe once the exit is visible, so a read that then finds
/// nothing means the available pipe contents are drained. Sampling after the
/// read lets a write-then-exit land between the two and drops the output.
pub(crate) fn capture_stderr_until_exit<R: Read, F: FnMut(&str)>(
    stderr: &mut R,
    mut try_exit: impl FnMut() -> std::io::Result<Option<i32>>,
    mut on_line: F,
) -> (i32, String) {
    let mut tail: VecDeque<String> = VecDeque::with_capacity(STDERR_TAIL_LINES);
    let mut pending = Vec::new();
    let mut read_buf = [0u8; 4096];
    let exit_code = loop {
        let exited = match try_exit() {
            Ok(exit) => exit,
            Err(_) => break -1,
        };
        let mut pipe_drained = false;
        match stderr.read(&mut read_buf) {
            Ok(0) => pipe_drained = true,
            Ok(n) => {
                pending.extend_from_slice(&read_buf[..n]);
                while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                    let mut bytes = pending.drain(..=newline).collect::<Vec<_>>();
                    bytes.pop();
                    if bytes.last() == Some(&b'\r') {
                        bytes.pop();
                    }
                    let Ok(line) = String::from_utf8(bytes) else {
                        pipe_drained = true;
                        break;
                    };
                    on_line(&line);
                    if tail.len() == STDERR_TAIL_LINES {
                        tail.pop_front();
                    }
                    tail.push_back(line);
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::WouldBlock => pipe_drained = true,
            Err(_) => pipe_drained = true,
        }

        if let Some(code) = exited
            && pipe_drained
        {
            if !pending.is_empty()
                && let Ok(mut line) = String::from_utf8(std::mem::take(&mut pending))
            {
                if line.ends_with('\r') {
                    line.pop();
                }
                on_line(&line);
                if tail.len() == STDERR_TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
            break code;
        }

        if pipe_drained {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    let tail_joined = tail.into_iter().collect::<Vec<_>>().join("\n");
    (exit_code, tail_joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A child that writes and exits between the reader's empty read and the
    /// exit check must not lose that output.
    #[test]
    fn capture_keeps_output_written_just_before_exit() {
        struct LateWriter<'a> {
            exited: &'a Cell<bool>,
            delivered: bool,
        }

        impl Read for LateWriter<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.exited.get() || self.delivered {
                    return Err(ErrorKind::WouldBlock.into());
                }
                self.delivered = true;
                buf[..3].copy_from_slice(b"hi\n");
                Ok(3)
            }
        }

        let exited = Cell::new(false);
        let mut reader = LateWriter {
            exited: &exited,
            delivered: false,
        };
        let (code, tail) = capture_stderr_until_exit(
            &mut reader,
            || {
                exited.set(true);
                Ok(Some(0))
            },
            |_| {},
        );

        assert_eq!((code, tail.as_str()), (0, "hi"));
    }
}

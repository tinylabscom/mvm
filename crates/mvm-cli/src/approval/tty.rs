//! The terminal approval backend.
//!
//! It asks on the controlling terminal of the `mvmctl` process that owns the
//! run — `/dev/tty`, opened fresh — and never on standard input, which may be
//! the workload's. The rules, in the order they apply:
//!
//! 1. No controlling terminal: deny (`no_tty`).
//! 2. An interactive (`-it`) run is already reading this terminal for the
//!    workload: deny (`tty_busy`) rather than race it for keystrokes.
//! 3. The question is drawn with every guest-derived field passed through
//!    [`display_safe`], so a request path cannot redraw the prompt or hide
//!    what it asks.
//! 4. Anything typed before the prompt, or during a short arming window after
//!    it is drawn, is discarded: a key already on its way cannot answer a
//!    question it was not typed for.
//! 5. `y` approves this request, `s` approves it for the session; anything
//!    else — including an empty line, and no answer before the deadline — is a
//!    denial.

use std::time::{Duration, Instant};

use mvm_client::approval_broker::{
    ApprovalAnswer, ApprovalBackend, ApprovalPrompt, ApprovalScope, ApprovalSubject, display_safe,
};

/// How long input is discarded after the prompt is drawn.
pub const ARMING_WINDOW: Duration = Duration::from_millis(750);
/// Longest answer line read.
const MAX_ANSWER_BYTES: usize = 64;
/// Longest guest-derived field shown.
const MAX_SHOWN_CHARS: usize = 200;

/// A terminal the backend can talk to. The real one is `/dev/tty`; tests
/// substitute a script.
pub trait Terminal {
    /// Draw `text`.
    fn write(&mut self, text: &str) -> std::io::Result<()>;
    /// Throw away everything typed so far.
    fn discard_input(&mut self) -> std::io::Result<()>;
    /// Read one line, or `None` if none arrives before `deadline`.
    fn read_line(&mut self, deadline: Instant, max_bytes: usize)
    -> std::io::Result<Option<String>>;
    /// Wait out `duration` (the arming window).
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Where the prompt is drawn, and how it interleaves with the run's own
/// output. The default frames it on its own lines on the terminal. The
/// live-denial lines (PS-04) are expected to share this seam so a prompt and
/// a denial never tear each other.
pub trait PromptRenderer: Send + Sync {
    fn render(&self, prompt: &ApprovalPrompt) -> String;
}

/// The default rendering: a framed block, every guest field made safe.
#[derive(Debug, Default, Clone, Copy)]
pub struct FramedRenderer;

impl PromptRenderer for FramedRenderer {
    fn render(&self, prompt: &ApprovalPrompt) -> String {
        let safe = |s: &str| display_safe(s, MAX_SHOWN_CHARS);
        let what = match &prompt.subject {
            ApprovalSubject::Egress {
                route_id,
                rule,
                destination,
                method,
                path,
            } => format!(
                "  request   {} {}{}\n  route     {} ({})",
                safe(method),
                safe(destination),
                safe(path),
                safe(route_id),
                safe(rule),
            ),
            ApprovalSubject::SecretUse {
                secret,
                destination,
            } => format!(
                "  secret    {}\n  going to  {}",
                safe(secret),
                safe(destination)
            ),
            ApprovalSubject::ToolCall { tool } => format!("  tool      {}", safe(tool)),
        };
        format!(
            "\r\n\u{2500}\u{2500} mvm: approval needed ({}) \u{2500}\u{2500}\r\n{}\r\n  expires   in {}s\r\nAllow? [y] once, [s] this session, [N] no: ",
            prompt.subject.kind_label(),
            what.replace('\n', "\r\n"),
            prompt.expires_in_ms / 1000,
        )
    }
}

/// Asks on the controlling terminal.
pub struct TerminalBackend<T> {
    open: Box<dyn Fn() -> std::io::Result<T> + Send + Sync>,
    renderer: Box<dyn PromptRenderer>,
    busy: bool,
    arming: Duration,
}

impl TerminalBackend<ControllingTty> {
    /// The backend for this process's controlling terminal. `interactive_run`
    /// is whether the run itself reads the terminal (`-it`).
    #[must_use]
    pub fn controlling(interactive_run: bool) -> Self {
        Self::with_terminal(ControllingTty::open, interactive_run)
    }
}

impl<T: Terminal> TerminalBackend<T> {
    /// A backend over whatever `open` returns.
    #[must_use]
    pub fn with_terminal(
        open: impl Fn() -> std::io::Result<T> + Send + Sync + 'static,
        interactive_run: bool,
    ) -> Self {
        Self {
            open: Box::new(open),
            renderer: Box::new(FramedRenderer),
            busy: interactive_run,
            arming: ARMING_WINDOW,
        }
    }

    /// Draw prompts with `renderer`.
    #[must_use]
    pub fn renderer(mut self, renderer: impl PromptRenderer + 'static) -> Self {
        self.renderer = Box::new(renderer);
        self
    }

    fn ask(&self, prompt: &ApprovalPrompt) -> Result<ApprovalAnswer, &'static str> {
        if self.busy {
            return Err("tty_busy");
        }
        let mut tty = (self.open)().map_err(|_| "no_tty")?;
        // Leave a margin so the answer reaches the endpoint before it gives up.
        let budget =
            Duration::from_millis(prompt.expires_in_ms).saturating_sub(Duration::from_secs(1));
        let deadline = Instant::now() + budget;
        tty.discard_input().map_err(|_| "no_tty")?;
        tty.write(&self.renderer.render(prompt))
            .map_err(|_| "no_tty")?;
        tty.pause(self.arming);
        tty.discard_input().map_err(|_| "no_tty")?;
        let line = tty
            .read_line(deadline, MAX_ANSWER_BYTES)
            .map_err(|_| "no_tty")?;
        let Some(line) = line else {
            let _ = tty.write("\r\n(no answer — denied)\r\n");
            return Err("tty_no_answer");
        };
        let answer = match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Some(ApprovalScope::Once),
            "s" | "session" => Some(ApprovalScope::Session),
            _ => None,
        };
        match answer {
            Some(scope) => {
                let _ = tty.write(&format!("(approved: {})\r\n", scope.label()));
                Ok(ApprovalAnswer::approved(
                    prompt.request_id.clone(),
                    scope,
                    "tty",
                ))
            }
            None => {
                let _ = tty.write("(denied)\r\n");
                Err("tty_denied")
            }
        }
    }
}

impl<T: Terminal + 'static> ApprovalBackend for TerminalBackend<T> {
    fn decide(&self, prompt: &ApprovalPrompt) -> ApprovalAnswer {
        self.ask(prompt)
            .unwrap_or_else(|reason| ApprovalAnswer::denied(prompt.request_id.clone(), reason))
    }
}

/// `/dev/tty`, opened read-write without becoming the controlling terminal.
pub struct ControllingTty {
    file: std::fs::File,
}

impl ControllingTty {
    fn open() -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
            .open("/dev/tty")?;
        Ok(Self { file })
    }

    fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.file.as_raw_fd()
    }
}

impl Terminal for ControllingTty {
    fn write(&mut self, text: &str) -> std::io::Result<()> {
        use std::io::Write;
        self.file.write_all(text.as_bytes())?;
        self.file.flush()
    }

    fn discard_input(&mut self) -> std::io::Result<()> {
        // SAFETY: `fd` is an open descriptor owned by `self.file` for the
        // duration of this call; tcflush reads no memory from us.
        let rc = unsafe { libc::tcflush(self.fd(), libc::TCIFLUSH) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn read_line(
        &mut self,
        deadline: Instant,
        max_bytes: usize,
    ) -> std::io::Result<Option<String>> {
        use std::io::Read;
        let mut line = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let mut poll = libc::pollfd {
                fd: self.fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            // SAFETY: one valid pollfd for the duration of the call.
            let ready = unsafe { libc::poll(&mut poll, 1, timeout) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                return Ok(None);
            }
            let mut byte = [0u8; 1];
            if self.file.read(&mut byte)? == 0 {
                return Ok(None);
            }
            if matches!(byte[0], b'\n' | b'\r') {
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if line.len() < max_bytes {
                line.push(byte[0]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::policy::approval::{ApprovalOutcome, ApprovalRequestId};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// A scripted terminal. `typed_ahead` is what the operator (or anything
    /// else) typed before input was last discarded; `answers` arrive after.
    #[derive(Default)]
    struct Script {
        typed_ahead: VecDeque<String>,
        during_arming: VecDeque<String>,
        answers: VecDeque<String>,
        drawn: String,
        discards: usize,
        armed: bool,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<Script>>);

    impl Terminal for Fake {
        fn write(&mut self, text: &str) -> std::io::Result<()> {
            self.0.lock().unwrap().drawn.push_str(text);
            Ok(())
        }
        fn discard_input(&mut self) -> std::io::Result<()> {
            let mut s = self.0.lock().unwrap();
            s.typed_ahead.clear();
            s.during_arming.clear();
            s.discards += 1;
            Ok(())
        }
        fn read_line(&mut self, _deadline: Instant, max: usize) -> std::io::Result<Option<String>> {
            let mut s = self.0.lock().unwrap();
            let line = s
                .typed_ahead
                .pop_front()
                .or_else(|| s.during_arming.pop_front())
                .or_else(|| s.answers.pop_front());
            Ok(line.map(|l| l.chars().take(max).collect()))
        }
        fn pause(&mut self, _duration: Duration) {
            self.0.lock().unwrap().armed = true;
        }
    }

    fn prompt(path: &str) -> ApprovalPrompt {
        ApprovalPrompt {
            request_id: ApprovalRequestId::parse("appr-1").unwrap(),
            subject: ApprovalSubject::Egress {
                route_id: "github".into(),
                rule: "rule-2".into(),
                destination: "api.github.com:443".into(),
                method: "POST".into(),
                path: path.into(),
            },
            expires_in_ms: 60_000,
        }
    }

    fn backend(fake: &Fake, busy: bool) -> TerminalBackend<Fake> {
        let fake = fake.clone();
        TerminalBackend::with_terminal(move || Ok(fake.clone()), busy)
    }

    #[test]
    fn y_approves_once_and_s_for_the_session() {
        for (typed, scope) in [("y", ApprovalScope::Once), ("S\n", ApprovalScope::Session)] {
            let fake = Fake::default();
            fake.0.lock().unwrap().answers.push_back(typed.into());
            let answer = backend(&fake, false).decide(&prompt("/x"));
            assert_eq!(answer.outcome, ApprovalOutcome::Approved, "{typed:?}");
            assert_eq!(answer.scope, scope);
        }
    }

    #[test]
    fn empty_input_anything_else_or_silence_is_a_denial() {
        for typed in ["", "   ", "n", "yolo", "yes please"] {
            let fake = Fake::default();
            fake.0.lock().unwrap().answers.push_back(typed.into());
            let answer = backend(&fake, false).decide(&prompt("/x"));
            assert_eq!(answer.outcome, ApprovalOutcome::Denied, "{typed:?}");
        }
        let silent = Fake::default();
        let answer = backend(&silent, false).decide(&prompt("/x"));
        assert_eq!(answer.reason_label(), "tty_no_answer");
    }

    #[test]
    fn type_ahead_and_keys_pressed_during_the_arming_window_are_discarded() {
        let fake = Fake::default();
        {
            let mut s = fake.0.lock().unwrap();
            s.typed_ahead.push_back("y".into());
            s.during_arming.push_back("s".into());
            s.answers.push_back("n".into());
        }
        let answer = backend(&fake, false).decide(&prompt("/x"));
        assert_eq!(
            answer.outcome,
            ApprovalOutcome::Denied,
            "only the answer typed after arming counts"
        );
        let s = fake.0.lock().unwrap();
        assert!(s.armed, "the arming window was waited out");
        assert_eq!(s.discards, 2, "before drawing and after arming");
    }

    #[test]
    fn no_terminal_or_a_busy_one_is_a_denial() {
        let none: TerminalBackend<Fake> = TerminalBackend::with_terminal(
            || Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no tty")),
            false,
        );
        assert_eq!(none.decide(&prompt("/x")).reason_label(), "no_tty");

        let fake = Fake::default();
        fake.0.lock().unwrap().answers.push_back("y".into());
        assert_eq!(
            backend(&fake, true).decide(&prompt("/x")).reason_label(),
            "tty_busy"
        );
        assert!(fake.0.lock().unwrap().drawn.is_empty(), "nothing was drawn");
    }

    #[test]
    fn a_hostile_path_cannot_redraw_or_disguise_the_prompt() {
        let fake = Fake::default();
        fake.0.lock().unwrap().answers.push_back("n".into());
        let hostile = "/ok\u{1b}[2K\u{1b}[1A\rAllow? [y] once: y\u{1b}]0;title\u{07}\u{202e}";
        backend(&fake, false).decide(&prompt(hostile));
        let drawn = fake.0.lock().unwrap().drawn.clone();
        assert!(!drawn.contains('\u{1b}'), "{drawn:?}");
        assert!(!drawn.contains('\u{202e}'), "{drawn:?}");
        assert!(!drawn.contains('\u{07}'), "{drawn:?}");
        // The carriage return that would have moved the cursor back is shown
        // as `?`, inline, so the forged prompt text sits visibly inside the
        // path instead of over the real question.
        assert!(
            drawn.contains("POST api.github.com:443/ok?Allow"),
            "{drawn:?}"
        );
    }
}

use std::io::{self, BufRead, IsTerminal as _, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Verbosity
// ---------------------------------------------------------------------------

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable opt-in `[mvm]` chatter (info/success/step/progress). The
/// chrome is off by default — like every other tracing/`RUST_LOG`
/// consumer — and only narrates when the user opts in. Errors,
/// warnings, banners, status tables, and interactive prompts always
/// print regardless. Called once at CLI startup based on
/// `--verbose`/`--debug` or the presence of `RUST_LOG`.
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

/// Whether `[mvm]` chatter is currently enabled.
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// When set, `info` / `success` / `warn` / `step` / `progress` route
/// to stderr instead of stdout. Errors already go to stderr
/// unconditionally. The toggle exists so verbs that emit a final
/// structured-JSON envelope on stdout (`mvmctl up --up-json`,
/// Followup H-live) can suppress chrome from the parsed channel
/// without rewriting every call site.
static CHROME_TO_STDERR: AtomicBool = AtomicBool::new(false);

/// Route `[mvm]` chatter to stderr instead of stdout. Used by verbs
/// that emit a machine-readable envelope on stdout. Idempotent; the
/// flag is process-global, so callers reset it when they're done.
pub fn set_chrome_to_stderr(on: bool) {
    CHROME_TO_STDERR.store(on, Ordering::Relaxed);
}

/// Whether chrome is currently routed to stderr. Public so that
/// the parallel `mvm-cli::ui` mirror module can honor the same
/// flag without each crate maintaining its own atomic.
pub fn is_chrome_routed_to_stderr() -> bool {
    CHROME_TO_STDERR.load(Ordering::Relaxed)
}

/// Internal alias used by the in-module print helpers.
fn chrome_to_stderr() -> bool {
    is_chrome_routed_to_stderr()
}

/// Whether opt-in `[mvm]` chatter (`info` / `success` / `step` /
/// `progress`) should print. Keyed off the same verbosity toggle as
/// tracing's `RUST_LOG`, so the chrome is off by default and follows
/// the user's logging choice rather than being always-on. Errors,
/// warnings, banners, status tables, and interactive prompts are not
/// chatter and print regardless.
fn chatter_enabled() -> bool {
    is_verbose()
}

// ---------------------------------------------------------------------------
// Styled message helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy)]
enum Style {
    Bold,
    Cyan,
    Green,
    Red,
    Yellow,
    Dim,
}

fn style_codes(styles: &[Style]) -> &'static str {
    match styles {
        [Style::Bold] => "1",
        [Style::Cyan] => "36",
        [Style::Green] => "32",
        [Style::Red] => "31",
        [Style::Yellow] => "33",
        [Style::Dim] => "2",
        [Style::Bold, Style::Cyan] => "1;36",
        [Style::Bold, Style::Red] => "1;31",
        [Style::Bold, Style::Yellow] => "1;33",
        [Style::Bold, Style::Green] => "1;32",
        _ => "",
    }
}

fn stream_supports_color(stream: Stream) -> bool {
    match stream {
        Stream::Stdout => io::stdout().is_terminal(),
        Stream::Stderr => io::stderr().is_terminal(),
    }
}

fn style_text(stream: Stream, text: &str, styles: &[Style]) -> String {
    render_styled_text(text, styles, stream_supports_color(stream))
}

fn render_styled_text(text: &str, styles: &[Style], enabled: bool) -> String {
    let codes = style_codes(styles);
    if codes.is_empty() || !enabled {
        return text.to_string();
    }
    format!("\x1b[{codes}m{text}\x1b[0m")
}

fn prefix(stream: Stream) -> String {
    style_text(stream, "[mvm]", &[Style::Bold, Style::Cyan])
}

/// Print an informational message: `[mvm]` message. Opt-in chatter —
/// suppressed unless `--verbose`/`--debug` or `RUST_LOG` is set.
pub fn info(msg: &str) {
    if !chatter_enabled() {
        return;
    }
    if chrome_to_stderr() {
        eprintln!("{} {}", prefix(Stream::Stderr), msg);
    } else {
        println!("{} {}", prefix(Stream::Stdout), msg);
    }
}

/// Print a success message: `[mvm]` message (in green). Opt-in chatter —
/// suppressed unless `--verbose`/`--debug` or `RUST_LOG` is set.
pub fn success(msg: &str) {
    if !chatter_enabled() {
        return;
    }
    if chrome_to_stderr() {
        eprintln!(
            "{} {}",
            prefix(Stream::Stderr),
            style_text(Stream::Stderr, msg, &[Style::Green])
        );
    } else {
        println!(
            "{} {}",
            prefix(Stream::Stdout),
            style_text(Stream::Stdout, msg, &[Style::Green])
        );
    }
}

/// Print an error message: `[mvm]` ERROR: message (in red).
pub fn error(msg: &str) {
    eprintln!(
        "{} {}",
        style_text(Stream::Stderr, "[mvm]", &[Style::Bold, Style::Red]),
        style_text(Stream::Stderr, msg, &[Style::Red])
    );
}

/// Print a warning message: `[mvm]` message (in yellow)
pub fn warn(msg: &str) {
    if chrome_to_stderr() {
        eprintln!(
            "{} {}",
            prefix(Stream::Stderr),
            style_text(Stream::Stderr, msg, &[Style::Yellow])
        );
    } else {
        println!(
            "{} {}",
            prefix(Stream::Stdout),
            style_text(Stream::Stdout, msg, &[Style::Yellow])
        );
    }
}

/// Print an always-on liveness/notice line: `[mvm]` message. Unlike the opt-in
/// chatter helpers, this prints regardless of verbosity — reserved for the
/// case where a periodic line is the *only* feedback that a long, silent
/// blocking step is alive (e.g. the Stage 0 builder-image build's heartbeat),
/// which must remain visible in the default quiet mode.
pub fn notice(msg: &str) {
    if chrome_to_stderr() {
        eprintln!("{} {}", prefix(Stream::Stderr), msg);
    } else {
        println!("{} {}", prefix(Stream::Stdout), msg);
    }
}

/// Print a numbered step: `[mvm]` Step n/total: message. Opt-in chatter —
/// suppressed unless `--verbose`/`--debug` or `RUST_LOG` is set.
pub fn step(n: u32, total: u32, msg: &str) {
    if !chatter_enabled() {
        return;
    }
    let stream = if chrome_to_stderr() {
        Stream::Stderr
    } else {
        Stream::Stdout
    };
    let formatted = format!(
        "\n{} {} {}",
        prefix(stream),
        style_text(
            stream,
            &format!("Step {}/{}:", n, total),
            &[Style::Bold, Style::Yellow]
        ),
        msg,
    );
    if chrome_to_stderr() {
        eprintln!("{formatted}");
    } else {
        println!("{formatted}");
    }
}

/// Print a progress / chatter message that's only useful when
/// troubleshooting (e.g. "auto-starting dev VM…"). Suppressed by default;
/// shown when `--verbose`/`--debug` is passed or `RUST_LOG` is set.
pub fn progress(msg: &str) {
    if !chatter_enabled() {
        return;
    }
    if chrome_to_stderr() {
        eprintln!("{} {}", prefix(Stream::Stderr), msg);
    } else {
        println!("{} {}", prefix(Stream::Stdout), msg);
    }
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/// Print a green bold banner box.
pub fn banner(lines: &[&str]) {
    let width = lines.iter().map(|l| l.len()).max().unwrap_or(0) + 4;
    let rule = "=".repeat(width);
    let stream = if chrome_to_stderr() {
        Stream::Stderr
    } else {
        Stream::Stdout
    };

    let print_line = |line: &str| {
        if chrome_to_stderr() {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };
    print_line("");
    print_line(&style_text(stream, &rule, &[Style::Bold, Style::Green]));
    for line in lines {
        let pad = width - line.len() - 4;
        print_line(&style_text(
            stream,
            &format!("  {}{}  ", line, " ".repeat(pad)),
            &[Style::Bold, Style::Green],
        ));
    }
    print_line(&style_text(stream, &rule, &[Style::Bold, Style::Green]));
    print_line("");
}

// ---------------------------------------------------------------------------
// Status table
// ---------------------------------------------------------------------------

/// Print the status header.
pub fn status_header() {
    println!(
        "{}",
        style_text(Stream::Stdout, "mvmctl status", &[Style::Bold])
    );
    println!(
        "{}",
        style_text(Stream::Stdout, "-------------", &[Style::Dim])
    );
}

/// Print a status line with a bold label and a colored value.
/// Recognized values: "Running", "Stopped", "Not running", etc.
pub fn status_line(label: &str, value: &str) {
    let colored_value = if value.starts_with("Running") {
        style_text(Stream::Stdout, value, &[Style::Green])
    } else if value == "Stopped" {
        style_text(Stream::Stdout, value, &[Style::Yellow])
    } else if value.starts_with("Not ") || value == "-" {
        style_text(Stream::Stdout, value, &[Style::Dim])
    } else if value.starts_with("Starting") {
        style_text(Stream::Stdout, value, &[Style::Yellow])
    } else {
        value.to_string()
    };

    println!(
        "{} {}",
        style_text(Stream::Stdout, &format!("{:<14}", label), &[Style::Bold]),
        colored_value
    );
}

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

/// Show an interactive confirmation prompt. Returns true if confirmed.
pub fn confirm(msg: &str) -> bool {
    prompt_text(msg)
        .map(|answer| matches_confirm(&answer))
        .unwrap_or(false)
}

/// Show an interactive free-form prompt and return the entered line.
pub fn prompt_text(msg: &str) -> io::Result<String> {
    let mut stdout = io::stdout();
    write_prompt(&mut stdout, msg)?;
    read_line_from(io::stdin().lock())
}

/// Show an interactive secret prompt with terminal echo disabled while the
/// user types.
pub fn prompt_secret(msg: &str) -> io::Result<String> {
    let mut stdout = io::stdout();
    write_prompt(&mut stdout, msg)?;
    #[cfg(unix)]
    {
        let stdin = io::stdin();
        let guard = EchoGuard::disable(libc::STDIN_FILENO)?;
        let line = read_line_from(stdin.lock());
        drop(guard);
        writeln!(stdout)?;
        line
    }
    #[cfg(not(unix))]
    {
        read_line_from(io::stdin().lock())
    }
}

fn write_prompt(mut out: impl Write, msg: &str) -> io::Result<()> {
    write!(out, "{msg} ")?;
    out.flush()
}

fn read_line_from(mut reader: impl BufRead) -> io::Result<String> {
    let mut buf = String::new();
    reader.read_line(&mut buf)?;
    Ok(trim_single_trailing_newline(buf))
}

fn trim_single_trailing_newline(mut buf: String) -> String {
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    buf
}

fn matches_confirm(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(unix)]
struct EchoGuard {
    fd: libc::c_int,
    original: libc::termios,
}

#[cfg(unix)]
impl EchoGuard {
    fn disable(fd: libc::c_int) -> io::Result<Self> {
        if !io::stdin().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret prompt requires a terminal",
            ));
        }
        // SAFETY: tcgetattr/tcsetattr operate on the calling process's stdin fd,
        // and Drop restores the captured terminal settings before returning.
        unsafe {
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut original) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut hidden = original;
            hidden.c_lflag &= !libc::ECHO;
            if libc::tcsetattr(fd, libc::TCSANOW, &hidden) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd, original })
        }
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // SAFETY: restore the previously captured terminal settings for stdin.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

// ---------------------------------------------------------------------------
// Spinners
// ---------------------------------------------------------------------------

struct SpinnerInner {
    message: Mutex<String>,
    stop: AtomicBool,
    handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    active: bool,
}

#[derive(Clone)]
pub struct Spinner {
    inner: Arc<SpinnerInner>,
}

impl Spinner {
    pub fn set_message(&self, msg: impl Into<String>) {
        if let Ok(mut current) = self.inner.message.lock() {
            *current = msg.into();
        }
    }

    pub fn finish_and_clear(&self) {
        self.inner.stop.store(true, Ordering::Relaxed);
        if let Ok(mut handle) = self.inner.handle.lock()
            && let Some(join) = handle.take()
        {
            let _ = join.join();
        }
        if self.inner.active {
            let _ = clear_spinner_line();
        }
    }
}

fn clear_spinner_line() -> io::Result<()> {
    let mut stderr = io::stderr().lock();
    write!(stderr, "\r\x1b[2K")?;
    stderr.flush()
}

/// Create and start a spinner with the given message.
/// Call `.finish_with_message()` or `.finish_and_clear()` when done.
pub fn spinner(msg: &str) -> Spinner {
    let active = io::stderr().is_terminal();
    let inner = Arc::new(SpinnerInner {
        message: Mutex::new(msg.to_string()),
        stop: AtomicBool::new(false),
        handle: Mutex::new(None),
        active,
    });
    if active {
        let thread_inner = Arc::clone(&inner);
        let handle = std::thread::spawn(move || {
            const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut frame = 0usize;
            while !thread_inner.stop.load(Ordering::Relaxed) {
                let msg = thread_inner
                    .message
                    .lock()
                    .map(|s| s.clone())
                    .unwrap_or_default();
                let glyph =
                    style_text(Stream::Stderr, FRAMES[frame % FRAMES.len()], &[Style::Cyan]);
                let mut stderr = io::stderr().lock();
                if write!(stderr, "\r\x1b[2K{glyph} {msg}").is_err() {
                    break;
                }
                if stderr.flush().is_err() {
                    break;
                }
                frame += 1;
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        });
        if let Ok(mut slot) = inner.handle.lock() {
            *slot = Some(handle);
        }
    }
    Spinner { inner }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `VERBOSE` is a process-global atomic; serialize the toggle tests
    // so they don't race each other under nextest's process-parallel
    // runner sharing this address space.
    static GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn chatter_follows_verbose_toggle() {
        let _g = GUARD.lock().unwrap();
        let prev = is_verbose();

        set_verbose(false);
        assert!(!chatter_enabled(), "chatter is off by default");

        set_verbose(true);
        assert!(chatter_enabled(), "chatter opts in with verbose/RUST_LOG");

        set_verbose(prev);
    }

    #[test]
    fn trim_single_trailing_newline_strips_once() {
        assert_eq!(trim_single_trailing_newline("hello\n".into()), "hello");
        assert_eq!(trim_single_trailing_newline("hello\r\n".into()), "hello");
        assert_eq!(trim_single_trailing_newline("hello".into()), "hello");
        assert_eq!(trim_single_trailing_newline("hello\n\n".into()), "hello\n");
    }

    #[test]
    fn matches_confirm_accepts_only_yes_values() {
        assert!(matches_confirm("y"));
        assert!(matches_confirm("YES"));
        assert!(matches_confirm(" yes "));
        assert!(!matches_confirm(""));
        assert!(!matches_confirm("n"));
        assert!(!matches_confirm("delete-everything"));
    }

    #[test]
    fn style_text_is_plain_when_color_disabled() {
        assert_eq!(
            render_styled_text("plain", &[Style::Bold, Style::Green], false),
            "plain"
        );
    }

    #[test]
    fn style_text_wraps_ansi_codes_when_enabled() {
        assert_eq!(
            render_styled_text("ok", &[Style::Bold, Style::Green], true),
            "\u{1b}[1;32mok\u{1b}[0m"
        );
    }

    #[test]
    fn spinner_set_message_and_finish_are_safe_without_active_tty() {
        let spinner = Spinner {
            inner: Arc::new(SpinnerInner {
                message: Mutex::new("start".to_string()),
                stop: AtomicBool::new(false),
                handle: Mutex::new(None),
                active: false,
            }),
        };
        spinner.set_message("next");
        assert_eq!(spinner.inner.message.lock().unwrap().as_str(), "next");
        spinner.finish_and_clear();
        assert!(spinner.inner.stop.load(Ordering::Relaxed));
    }
}

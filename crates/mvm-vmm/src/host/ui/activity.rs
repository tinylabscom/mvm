//! Live status for long phases the user is waiting on.
//!
//! A phase that can outlast a couple of seconds — pulling an image, building
//! the builder image, waiting for another process's lock — registers an
//! [`Activity`] for its duration. On a terminal the innermost activity keeps
//! one line redrawn in place with a spinner, its elapsed time, and whatever
//! detail the phase last reported. A phase still running after two seconds
//! also prints a `[mvm] <phase>…` line, and a `done in …` line when it ends;
//! one that finishes sooner leaves no trace. Off a terminal (a pipe, CI, a
//! log capture) there is no live line; the announced phase instead prints a
//! heartbeat line at a fixed cadence, so a captured log still shows the
//! process was alive.
//!
//! Everything here writes to stderr. Stdout stays the channel for command
//! results and machine-readable envelopes, and the activity lines are not
//! chatter: they are the only feedback during a long block, so they print at
//! the default verbosity.
//!
//! The terminal has one bottom line, so there is one board per process. Nested
//! activities stack; the innermost is drawn, and finishing it redraws its
//! parent. Lines printed through [`println_above`] clear the live line first
//! and redraw it after, so interleaved raw output never lands on top of it.

use std::io::{self, IsTerminal as _, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{Stream, Style, format_elapsed, render_styled_text, stream_supports_color};

/// How often the terminal line is redrawn. Fast enough for the spinner to read
/// as motion, slow enough to cost nothing.
const TTY_REDRAW_INTERVAL: Duration = Duration::from_millis(100);

/// Cadence of the heartbeat line off a terminal. A captured log gains a line
/// every this-often per live activity rather than one per detail update, so a
/// multi-minute build stays readable.
pub const PLAIN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// A phase announces itself with a `[mvm] <phase>…` line once it has run this
/// long, and only then. Most runs pass through most phases in milliseconds
/// (a cached kernel, a reused image), and a line per trivial phase would bury
/// the ones that matter; a phase still going at this point is one the user is
/// actually waiting on. An announced phase also leaves a `done in …` line.
const ANNOUNCE_AFTER: Duration = Duration::from_secs(2);

/// Terminal width assumed when the real one cannot be read.
const FALLBACK_WIDTH: usize = 100;

const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// How the board renders: redrawn in place, or appended as plain lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Tty { color: bool },
    Plain,
}

/// Whether an activity is shown off a terminal. A spinner has nothing to say
/// in a log beyond what its caller already prints, so it stays terminal-only;
/// a phase activity announces itself and heartbeats everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Visibility {
    Everywhere,
    TerminalOnly,
}

/// A detail computed at render time, for progress that advances without its
/// owner calling back — a byte counter a download loop bumps, say.
struct LiveDetail(Box<dyn Fn() -> String + Send>);

impl std::fmt::Debug for LiveDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LiveDetail")
    }
}

#[derive(Debug)]
struct Entry {
    id: u64,
    label: String,
    detail: Option<String>,
    live: Option<LiveDetail>,
    started: Instant,
    last_emitted: Instant,
    visibility: Visibility,
    /// Whether the `[mvm] <label>…` line has been printed.
    announced: bool,
}

impl Entry {
    /// The live source if one is attached, else the last detail set.
    fn current_detail(&self) -> Option<String> {
        match &self.live {
            Some(live) => Some((live.0)()),
            None => self.detail.clone(),
        }
    }
}

/// The rendering state machine, separated from the process-wide stderr sink so
/// the TTY and plain renderings are testable against a buffer and a supplied
/// clock.
#[derive(Debug)]
pub(crate) struct Board {
    mode: Mode,
    width: usize,
    entries: Vec<Entry>,
    next_id: u64,
    frame: usize,
    /// Whether the live line is currently on screen (TTY only), so a clear is
    /// only written when there is something to clear.
    drawn: bool,
}

impl Board {
    pub(crate) fn new(mode: Mode, width: usize) -> Self {
        Self {
            mode,
            width: width.max(20),
            entries: Vec::new(),
            next_id: 1,
            frame: 0,
            drawn: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn push(
        &mut self,
        out: &mut dyn Write,
        label: String,
        visibility: Visibility,
        now: Instant,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(Entry {
            id,
            label,
            detail: None,
            live: None,
            started: now,
            last_emitted: now,
            visibility,
            announced: false,
        });
        self.redraw(out, now);
        id
    }

    /// Remove `id`. With `report_done`, an activity that ran long enough to be
    /// noticed leaves a `done in …` line behind in place of the live line.
    fn pop(&mut self, out: &mut dyn Write, id: u64, report_done: bool, now: Instant) {
        let Some(index) = self.entries.iter().position(|e| e.id == id) else {
            return;
        };
        let entry = self.entries.remove(index);
        let elapsed = now.saturating_duration_since(entry.started);
        let shows_done = report_done && entry.announced;
        self.clear(out);
        if shows_done {
            let _ = writeln!(
                out,
                "[mvm] {} — done in {}",
                entry.label,
                format_elapsed(elapsed)
            );
        }
        self.redraw(out, now);
    }

    fn set_detail(&mut self, id: Option<u64>, detail: Option<String>) {
        let entry = match id {
            Some(id) => self.entries.iter_mut().find(|e| e.id == id),
            None => self.entries.last_mut(),
        };
        if let Some(entry) = entry {
            entry.detail = detail;
        }
    }

    fn set_live(&mut self, id: u64, live: LiveDetail) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.live = Some(live);
        }
    }

    fn set_label(&mut self, id: u64, label: String) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.label = label;
        }
    }

    /// Advance time: announce every phase that has now run long enough, then
    /// redraw the terminal line or emit the heartbeats that have come due.
    fn tick(&mut self, out: &mut dyn Write, now: Instant) {
        self.announce_due(out, now);
        match self.mode {
            Mode::Tty { .. } => {
                self.frame = self.frame.wrapping_add(1);
                self.redraw(out, now);
            }
            Mode::Plain => {
                for entry in &mut self.entries {
                    if !entry.announced
                        || now.saturating_duration_since(entry.last_emitted)
                            < PLAIN_HEARTBEAT_INTERVAL
                    {
                        continue;
                    }
                    let _ = writeln!(out, "[mvm] {}", plain_heartbeat(entry, now));
                    entry.last_emitted = now;
                }
            }
        }
    }

    /// Print the `[mvm] <label>…` line of every phase past [`ANNOUNCE_AFTER`],
    /// outermost first. On a terminal this leaves the phase in the scrollback:
    /// a nested phase takes over the live line, and without the record the
    /// outer one would vanish from view.
    fn announce_due(&mut self, out: &mut dyn Write, now: Instant) {
        let due = |entry: &Entry| {
            !entry.announced
                && entry.visibility == Visibility::Everywhere
                && now.saturating_duration_since(entry.started) >= ANNOUNCE_AFTER
        };
        if !self.entries.iter().any(due) {
            return;
        }
        self.clear(out);
        for entry in &mut self.entries {
            if due(entry) {
                let _ = writeln!(out, "[mvm] {}…", entry.label);
                entry.announced = true;
                entry.last_emitted = now;
            }
        }
    }

    /// Print `line` as ordinary output without disturbing the live line.
    fn passthrough(&mut self, out: &mut dyn Write, line: &str, now: Instant) {
        self.clear(out);
        let _ = writeln!(out, "{line}");
        self.redraw(out, now);
    }

    fn clear(&mut self, out: &mut dyn Write) {
        if self.drawn {
            let _ = write!(out, "\r\x1b[2K");
            self.drawn = false;
        }
        let _ = out.flush();
    }

    fn redraw(&mut self, out: &mut dyn Write, now: Instant) {
        let Mode::Tty { color } = self.mode else {
            let _ = out.flush();
            return;
        };
        let Some(entry) = self.entries.last() else {
            self.clear(out);
            return;
        };
        let text = truncate_to_width(&tty_status_text(entry, now), self.width.saturating_sub(3));
        let glyph = SPINNER_FRAMES[self.frame % SPINNER_FRAMES.len()];
        let glyph = render_styled_text(glyph, &[Style::Cyan], color);
        let _ = write!(out, "\r\x1b[2K{glyph} {text}");
        let _ = out.flush();
        self.drawn = true;
    }
}

/// `label — 1m04s · detail`: the text of the live terminal line, before the
/// spinner glyph and truncation.
fn tty_status_text(entry: &Entry, now: Instant) -> String {
    let elapsed = format_elapsed(now.saturating_duration_since(entry.started));
    match &entry.current_detail() {
        Some(detail) => format!("{} — {elapsed} · {detail}", entry.label),
        None => format!("{} — {elapsed}", entry.label),
    }
}

/// `label — still running, 1m04s — detail`: one heartbeat line off a terminal.
fn plain_heartbeat(entry: &Entry, now: Instant) -> String {
    let elapsed = format_elapsed(now.saturating_duration_since(entry.started));
    match &entry.current_detail() {
        Some(detail) => format!("{} — still running, {elapsed} — {detail}", entry.label),
        None => format!("{} — still running, {elapsed}", entry.label),
    }
}

/// Cut `text` to at most `max` characters, marking the cut. A live line that
/// wraps cannot be cleared with a single carriage return, so it must fit.
fn truncate_to_width(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// The process-wide board plus whether its ticker thread is running.
struct Shared {
    board: Board,
    ticker_running: bool,
}

static SHARED: Mutex<Option<Shared>> = Mutex::new(None);

/// Run `f` against the process board, creating it on first use from the real
/// stderr's terminal-ness and width.
fn with_board<R>(f: impl FnOnce(&mut Shared, &mut dyn Write) -> R) -> R {
    let mut guard = SHARED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let shared = guard.get_or_insert_with(|| Shared {
        board: Board::new(detect_mode(), terminal_width()),
        ticker_running: false,
    });
    let mut stderr = io::stderr().lock();
    f(shared, &mut stderr)
}

fn detect_mode() -> Mode {
    if io::stderr().is_terminal() {
        Mode::Tty {
            color: stream_supports_color(Stream::Stderr),
        }
    } else {
        Mode::Plain
    }
}

/// Columns of the terminal behind stderr, or [`FALLBACK_WIDTH`].
fn terminal_width() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ only writes the `winsize` struct passed to it; a
        // non-terminal fd makes the call fail, which falls through below.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut size) };
        if rc == 0 && size.ws_col > 0 {
            return usize::from(size.ws_col);
        }
    }
    FALLBACK_WIDTH
}

/// Start the ticker thread if none is running. It exits on its own once the
/// board is empty, so an idle process carries no thread.
fn ensure_ticker(shared: &mut Shared) {
    if shared.ticker_running {
        return;
    }
    shared.ticker_running = true;
    let interval = match shared.board.mode {
        Mode::Tty { .. } => TTY_REDRAW_INTERVAL,
        Mode::Plain => Duration::from_millis(250),
    };
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            let keep_going = with_board(|shared, out| {
                if shared.board.is_empty() {
                    shared.ticker_running = false;
                    return false;
                }
                shared.board.tick(out, Instant::now());
                true
            });
            if !keep_going {
                break;
            }
        }
    });
}

/// A live phase. Dropping it removes the line; [`Activity::finish`] also
/// leaves a `done in …` line when the phase ran long enough to be noticed.
#[derive(Debug)]
#[must_use = "an activity is shown only while the handle is alive"]
pub struct Activity {
    id: u64,
    finished: bool,
}

impl Activity {
    /// Replace the detail shown after the elapsed time.
    pub fn set_detail(&self, detail: impl Into<String>) {
        let detail = detail.into();
        with_board(|shared, _| shared.board.set_detail(Some(self.id), Some(detail)));
    }

    /// Compute the detail from `source` each time the line is drawn, instead
    /// of from the last [`set_detail`](Self::set_detail). For progress that
    /// moves without a caller to report it, like a shared byte counter.
    /// `source` runs with the board locked, so it must not touch this module.
    pub fn track(&self, source: impl Fn() -> String + Send + 'static) {
        let live = LiveDetail(Box::new(source));
        with_board(|shared, _| shared.board.set_live(self.id, live));
    }

    /// Replace the label, for a phase whose name only becomes known part way.
    pub fn set_label(&self, label: impl Into<String>) {
        let label = label.into();
        with_board(|shared, _| shared.board.set_label(self.id, label));
    }

    /// End the phase successfully.
    pub fn finish(mut self) {
        self.end(true);
    }

    fn end(&mut self, report_done: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        with_board(|shared, out| shared.board.pop(out, self.id, report_done, Instant::now()));
    }
}

impl Drop for Activity {
    fn drop(&mut self) {
        self.end(false);
    }
}

fn start_with(label: String, visibility: Visibility) -> Activity {
    let id = with_board(|shared, out| {
        let id = shared.board.push(out, label, visibility, Instant::now());
        ensure_ticker(shared);
        id
    });
    Activity {
        id,
        finished: false,
    }
}

/// Start a phase that is shown at every verbosity, on a terminal and off it.
pub fn start(label: impl Into<String>) -> Activity {
    start_with(label.into(), Visibility::Everywhere)
}

/// Start a terminal-only spinner line. Off a terminal it prints nothing.
pub(crate) fn start_terminal_only(label: impl Into<String>) -> Activity {
    start_with(label.into(), Visibility::TerminalOnly)
}

/// Set the detail of the innermost live activity, for code that reports
/// progress without holding the handle of the phase it runs inside. A no-op
/// when nothing is live.
pub fn set_current_detail(detail: impl Into<String>) {
    let detail = detail.into();
    with_board(|shared, _| shared.board.set_detail(None, Some(detail)));
}

/// Print one line of ordinary output to stderr without tearing the live line.
pub fn println_above(line: &str) {
    with_board(|shared, out| shared.board.passthrough(out, line, Instant::now()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(out: &[u8]) -> String {
        String::from_utf8(out.to_vec()).expect("utf-8")
    }

    fn tty() -> Board {
        Board::new(Mode::Tty { color: false }, 80)
    }

    fn plain() -> Board {
        Board::new(Mode::Plain, 80)
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_quick_phase_leaves_no_trace_off_a_terminal() {
        let mut board = plain();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let id = board.push(&mut out, "Resolving".into(), Visibility::Everywhere, t0);
        board.tick(&mut out, t0 + Duration::from_millis(900));
        board.pop(&mut out, id, true, t0 + Duration::from_millis(1500));
        assert!(out.is_empty(), "{:?}", render(&out));
    }

    #[test]
    fn a_plain_phase_announces_after_two_seconds_then_heartbeats_on_cadence() {
        let mut board = plain();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let id = board.push(&mut out, "Pulling rust".into(), Visibility::Everywhere, t0);
        assert!(out.is_empty(), "nothing before the phase has lasted");

        board.tick(&mut out, t0 + ANNOUNCE_AFTER);
        assert_eq!(render(&out), "[mvm] Pulling rust…\n");

        out.clear();
        board.set_detail(Some(id), Some("12.0 MiB of 40.0 MiB (30%)".into()));
        board.tick(&mut out, t0 + ANNOUNCE_AFTER + secs(5));
        assert!(out.is_empty(), "no heartbeat before the cadence");

        board.tick(&mut out, t0 + ANNOUNCE_AFTER + PLAIN_HEARTBEAT_INTERVAL);
        assert_eq!(
            render(&out),
            "[mvm] Pulling rust — still running, 17s — 12.0 MiB of 40.0 MiB (30%)\n"
        );

        out.clear();
        board.pop(&mut out, id, true, t0 + secs(62));
        assert_eq!(render(&out), "[mvm] Pulling rust — done in 1m02s\n");
    }

    #[test]
    fn a_plain_board_writes_no_terminal_control_sequences() {
        let mut board = plain();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let id = board.push(&mut out, "Booting".into(), Visibility::Everywhere, t0);
        board.tick(&mut out, t0 + secs(60));
        board.passthrough(&mut out, "raw line", t0 + secs(61));
        board.pop(&mut out, id, true, t0 + secs(62));
        let text = render(&out);
        assert!(!text.contains('\r') && !text.contains('\x1b'), "{text:?}");
        assert!(
            text.ends_with("[mvm] Booting — done in 1m02s\n"),
            "{text:?}"
        );
    }

    #[test]
    fn a_terminal_only_activity_is_silent_off_a_terminal() {
        let mut board = plain();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let id = board.push(&mut out, "spin".into(), Visibility::TerminalOnly, t0);
        board.tick(&mut out, t0 + secs(120));
        board.pop(&mut out, id, true, t0 + secs(121));
        assert!(out.is_empty(), "{:?}", render(&out));
    }

    #[test]
    fn the_terminal_line_is_live_at_once_and_redrawn_in_place() {
        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let id = board.push(
            &mut out,
            "Building the builder image".into(),
            Visibility::Everywhere,
            t0,
        );
        assert_eq!(render(&out), "\r\x1b[2K⠋ Building the builder image — 0s");

        out.clear();
        board.set_detail(Some(id), Some("building linux-6.12 (3/42)".into()));
        board.tick(&mut out, t0 + Duration::from_millis(1500));
        assert_eq!(
            render(&out),
            "\r\x1b[2K⠙ Building the builder image — 1s · building linux-6.12 (3/42)"
        );

        out.clear();
        board.tick(&mut out, t0 + secs(64));
        assert_eq!(
            render(&out),
            "\r\x1b[2K[mvm] Building the builder image…\n\
             \r\x1b[2K⠹ Building the builder image — 1m04s · building linux-6.12 (3/42)"
        );
    }

    #[test]
    fn raw_lines_clear_the_live_line_and_redraw_it_after() {
        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        board.push(&mut out, "Stage 0".into(), Visibility::Everywhere, t0);
        out.clear();
        board.passthrough(&mut out, "building '/nix/store/x.drv'", t0);
        assert_eq!(
            render(&out),
            "\r\x1b[2Kbuilding '/nix/store/x.drv'\n\r\x1b[2K⠋ Stage 0 — 0s"
        );
    }

    #[test]
    fn finishing_the_inner_activity_redraws_its_parent() {
        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let _outer = board.push(&mut out, "outer".into(), Visibility::Everywhere, t0);
        let inner = board.push(&mut out, "inner".into(), Visibility::Everywhere, t0);
        board.tick(&mut out, t0 + secs(3));
        out.clear();
        board.pop(&mut out, inner, true, t0 + secs(3));
        assert_eq!(
            render(&out),
            "\r\x1b[2K[mvm] inner — done in 3s\n\r\x1b[2K⠙ outer — 3s"
        );
    }

    #[test]
    fn a_nested_phase_leaves_its_parent_named_in_the_scrollback() {
        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        board.push(&mut out, "outer".into(), Visibility::Everywhere, t0);
        board.push(
            &mut out,
            "inner".into(),
            Visibility::Everywhere,
            t0 + secs(1),
        );
        out.clear();
        board.tick(&mut out, t0 + secs(3));
        assert_eq!(
            render(&out),
            "\r\x1b[2K[mvm] outer…\n[mvm] inner…\n\r\x1b[2K⠙ inner — 2s"
        );
    }

    #[test]
    fn a_terminal_only_spinner_is_never_announced() {
        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let id = board.push(&mut out, "spin".into(), Visibility::TerminalOnly, t0);
        board.tick(&mut out, t0 + secs(30));
        board.pop(&mut out, id, true, t0 + secs(31));
        let text = render(&out);
        assert!(!text.contains("[mvm]"), "{text:?}");
    }

    #[test]
    fn an_abandoned_phase_is_not_reported_done() {
        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let failed = board.push(&mut out, "failed".into(), Visibility::Everywhere, t0);
        board.tick(&mut out, t0 + secs(5));
        out.clear();
        board.pop(&mut out, failed, false, t0 + secs(90));
        assert_eq!(
            render(&out),
            "\r\x1b[2K",
            "a dropped activity is not `done`"
        );
    }

    #[test]
    fn a_tracked_source_is_read_at_each_redraw() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let id = board.push(&mut out, "Pulling".into(), Visibility::Everywhere, t0);
        let bytes = Arc::new(AtomicU64::new(0));
        let source = Arc::clone(&bytes);
        board.set_live(
            id,
            LiveDetail(Box::new(move || {
                format!("{} bytes", source.load(Ordering::Relaxed))
            })),
        );

        bytes.store(512, Ordering::Relaxed);
        out.clear();
        board.tick(&mut out, t0 + secs(1));
        assert!(
            render(&out).ends_with("Pulling — 1s · 512 bytes"),
            "{:?}",
            render(&out)
        );
    }

    #[test]
    fn an_unknown_id_is_ignored() {
        let mut board = tty();
        let mut out = Vec::new();
        board.pop(&mut out, 42, true, Instant::now());
        board.set_detail(Some(42), Some("x".into()));
        assert!(out.is_empty());
    }

    #[test]
    fn the_live_line_never_exceeds_the_terminal_width() {
        let mut board = Board::new(Mode::Tty { color: false }, 30);
        let mut out = Vec::new();
        board.push(
            &mut out,
            "a label far longer than thirty columns of terminal".into(),
            Visibility::Everywhere,
            Instant::now(),
        );
        let text = render(&out);
        let visible = text
            .rsplit("\r\x1b[2K")
            .next()
            .expect("a live line was drawn");
        assert!(visible.chars().count() <= 30, "{visible:?}");
        assert!(visible.ends_with('…'), "{visible:?}");
    }

    #[test]
    fn set_current_detail_targets_the_innermost_activity() {
        let mut board = tty();
        let mut out = Vec::new();
        let t0 = Instant::now();
        let outer = board.push(&mut out, "outer".into(), Visibility::Everywhere, t0);
        let inner = board.push(&mut out, "inner".into(), Visibility::Everywhere, t0);
        board.set_detail(None, Some("detail".into()));
        let detail_of = |board: &Board, id| {
            board
                .entries
                .iter()
                .find(|e| e.id == id)
                .and_then(|e| e.detail.clone())
        };
        assert_eq!(detail_of(&board, inner).as_deref(), Some("detail"));
        assert_eq!(detail_of(&board, outer), None);
    }
}

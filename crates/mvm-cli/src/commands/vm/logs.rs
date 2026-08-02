//! `mvmctl logs` — read a microVM's captured stdout/stderr, live or after it
//! exited.
//!
//! Three sources, resolved by `mvm_core::stream_client`: the host-side broker
//! while the VM runs, its durable transcript once the broker is gone, and —
//! only when neither answers — the console capture every backend writes. None
//! is reached through the guest and none needs the builder VM; the path this
//! replaced shelled `tail -f` at that same console file through an
//! environment abstraction that was a no-op on two host tiers and a dead end
//! on the third.
//!
//! **An incomplete or degraded capture says so.** A truncated transcript, a
//! follower that fell behind the broker's ring, and a console-only read (no
//! channel separation, no hash chain) are all rendered as notices on stderr.
//! Showing a partial log as if it were the whole thing is the failure this
//! command exists to prevent, so silence is not an option in any of them.
//!
//! **A verification failure exits nonzero**, mirroring `mvmctl trust audit
//! verify`. A pruned window is not a failure — it is the ring doing its job,
//! and it surfaces as a gap notice, not as tampering.

use std::io::Write;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, ValueEnum};

use mvm_core::config;
use mvm_core::naming::validate_vm_name;
use mvm_core::stream_client::{
    KindFilter, OutputRecord, OutputRequest, StreamAvailability, StreamOpts, Truncation,
    VmOutputStream, open_vm_output,
};
use mvm_core::transcript::GapMarker;
use mvm_core::user_config::MvmConfig;
use mvm_protocol::stream::StreamKind;

use super::Cli;
use super::shared::clap_vm_name;

/// Which output channels to show.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[value(rename_all = "lower")]
pub(in crate::commands) enum StreamSelector {
    /// Everything the workload produced.
    #[default]
    All,
    /// Standard output only.
    Stdout,
    /// Standard error only.
    Stderr,
    /// Structured fd-3 control records only.
    Trace,
}

impl StreamSelector {
    fn filter(self) -> KindFilter {
        match self {
            Self::All => KindFilter::all(),
            Self::Stdout => KindFilter::only(StreamKind::Stdout),
            Self::Stderr => KindFilter::only(StreamKind::Stderr),
            Self::Trace => KindFilter::only(StreamKind::Trace),
        }
    }
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Follow log output (like tail -f)
    #[arg(long, short = 'f')]
    pub follow: bool,
    /// Number of recorded output records to replay before following. A record
    /// is one captured write, not one line
    #[arg(long, short = 'n', default_value = "50")]
    pub lines: u32,
    /// Which output channel to show
    #[arg(long, value_enum, default_value_t = StreamSelector::All)]
    pub stream: StreamSelector,
    /// Show the hypervisor's own diagnostic log instead of workload output
    #[arg(long)]
    pub hypervisor: bool,
}

/// Roughly how many bytes one recorded record is worth, for turning `-n` into
/// the console fallback's byte-based tail. The console has no record
/// boundaries to count, so the flag can only be approximated there — generous
/// on purpose, since showing a little more than asked beats cutting a run off
/// mid-sentence.
const CONSOLE_BYTES_PER_RECORD: u64 = 512;

impl Args {
    /// What the stream layer is being asked for.
    fn request(&self) -> OutputRequest {
        OutputRequest {
            opts: StreamOpts::builder()
                .follow(self.follow)
                .kinds(self.stream.filter())
                .build(),
            history_tail: Some(self.lines as usize),
            console_tail_bytes: Some(u64::from(self.lines) * CONSOLE_BYTES_PER_RECORD),
        }
    }
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    execute(args)
}

/// The command proper. Split from [`run`] so a test drives it without
/// assembling a whole parsed `Cli` for two parameters neither arm reads.
fn execute(args: Args) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    if args.hypervisor {
        return show_hypervisor_log(&args);
    }
    let stream = open_vm_output(&args.name, args.request())
        .with_context(|| format!("Reading output for microVM {:?}", args.name))?;
    show(&args, stream)
}

/// How many recorded records `machine run`'s attach replays before it starts
/// following. Nonzero because a `run` against an already-running machine would
/// otherwise open on silence and look broken; a freshly-booted one has no
/// history to replay, so the value only shows up in the case that needs it.
const ATTACH_REPLAY_LINES: u32 = 50;

/// What an attach found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::commands) enum AttachOutcome {
    /// The stream was followed to its end.
    Followed,
    /// The machine has no capture to attach to.
    NoCapture,
}

/// Follow a machine's output, for `machine run` without `--detach`.
///
/// A machine with no capture is reported through [`AttachOutcome::NoCapture`]
/// rather than as an error: the boot succeeded, and failing the command over
/// an absent observability channel would make `machine run` less reliable than
/// `machine run -d`. Every *other* failure — a chain break above all — still
/// propagates, because those mean the output that did arrive cannot be
/// trusted.
pub(in crate::commands) fn attach(name: &str) -> Result<AttachOutcome> {
    let args = attach_args(name);
    let stream = match open_vm_output(name, args.request()) {
        Ok(stream) => stream,
        Err(mvm_core::stream_client::StreamError::NoCapture { .. }) => {
            return Ok(AttachOutcome::NoCapture);
        }
        Err(err) => {
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("Attaching to output for microVM {name:?}"));
        }
    };
    show(&args, stream)?;
    Ok(AttachOutcome::Followed)
}

/// What [`attach`] asks for: every channel, replay then follow.
fn attach_args(name: &str) -> Args {
    Args {
        name: name.to_string(),
        follow: true,
        lines: ATTACH_REPLAY_LINES,
        stream: StreamSelector::All,
        hypervisor: false,
    }
}

/// Announce what was found, then drain it.
fn show(args: &Args, mut stream: VmOutputStream) -> Result<()> {
    announce(args, &stream);
    pump(&mut stream, &mut Sinks::inherited())
        .with_context(|| format!("Reading output for microVM {:?}", args.name))
}

/// Where each channel's bytes go.
///
/// stdout to stdout and stderr to stderr, the way a shell pipeline expects, so
/// `mvmctl logs vm | grep` filters the workload's stdout rather than a merged
/// transcript of both. Held behind a struct so a test drives the rendering
/// against buffers instead of the process's real fds.
struct Sinks<'a> {
    out: Box<dyn Write + 'a>,
    err: Box<dyn Write + 'a>,
}

impl Sinks<'static> {
    fn inherited() -> Self {
        Self {
            out: Box::new(std::io::stdout()),
            err: Box::new(std::io::stderr()),
        }
    }
}

/// Drain the stream into the sinks until it ends or a verification error stops
/// it.
///
/// The gap is polled **inside** the loop, not once at the end. A marker
/// arrives with the batch that reports it, and the normal way out of `logs -f`
/// is the user interrupting — so a report deferred to the end is a report the
/// follow case never makes.
fn pump(stream: &mut VmOutputStream, sinks: &mut Sinks<'_>) -> Result<()> {
    let mut reported_gap: Option<GapMarker> = None;
    while let Some(record) = stream.next_output()? {
        if render(&record, sinks)? == Rendered::ConsumerGone {
            return Ok(());
        }
        report_new_gap(stream.gap(), &mut reported_gap, sinks);
    }
    report_new_gap(stream.gap(), &mut reported_gap, sinks);
    let _ = sinks.out.flush();
    let _ = sinks.err.flush();
    Ok(())
}

/// Whether the consumer on the other end is still reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rendered {
    Written,
    /// The pipe closed — `mvmctl logs vm | head`. Not an error.
    ConsumerGone,
}

/// Write one record verbatim.
///
/// Verbatim matters: the bytes are hash-chained, so re-framing them into lines
/// would render something the chain does not cover. A `Trace` record is the
/// exception — it is a structured control message rather than workload stdio,
/// so it is labelled with a prefix the workload's own output cannot forge.
///
/// A closed pipe ends the read cleanly rather than raising. `mvmctl logs vm |
/// head -1` is an ordinary thing to type, and Rust does not restore the
/// default `SIGPIPE`, so the write returns `EPIPE` instead of killing the
/// process; treating that as a failure would print an error and exit nonzero
/// for a command that did exactly what was asked.
fn render(record: &OutputRecord, sinks: &mut Sinks<'_>) -> Result<Rendered> {
    let wrote = match record.kind {
        StreamKind::Stdout => write_out(&mut sinks.out, &record.payload),
        StreamKind::Stderr => write_out(&mut sinks.err, &record.payload),
        StreamKind::Trace => {
            let labelled = format!(
                "[mvmctl-trace] {}\n",
                String::from_utf8_lossy(&record.payload)
            );
            write_out(&mut sinks.err, labelled.as_bytes())
        }
    };
    match wrote {
        Ok(()) => Ok(Rendered::Written),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(Rendered::ConsumerGone),
        Err(err) => Err(err.into()),
    }
}

/// Write and push, so a piped consumer sees output while the workload runs
/// rather than when this process exits.
fn write_out(sink: &mut Box<dyn Write + '_>, bytes: &[u8]) -> std::io::Result<()> {
    sink.write_all(bytes)?;
    sink.flush()
}

/// Say what was found, before any of it is printed.
///
/// Silence here is what turns a partial capture into a log that reads as
/// complete, so every degraded shape gets a line: a follow with nothing left
/// to follow, and a transcript that lost either end.
fn announce(args: &Args, stream: &VmOutputStream) {
    match stream.availability() {
        StreamAvailability::LiveAndHistory => {}
        StreamAvailability::LiveOnly => eprintln!(
            "note: microVM {:?} has no recorded output yet; showing live output only",
            args.name
        ),
        StreamAvailability::HistoryOnly if args.follow => eprintln!(
            "note: microVM {:?} has no live output stream; showing its recorded output and exiting",
            args.name
        ),
        StreamAvailability::HistoryOnly => {}
        StreamAvailability::ConsoleOnly => announce_console_only(args),
    }
    if let Some(truncation) = stream.truncation() {
        eprintln!("warning: {}", describe_truncation(truncation));
    }
}

/// The console fallback cannot do two things the broker can, and a user who is
/// not told will read its output as if it could.
fn announce_console_only(args: &Args) {
    eprintln!(
        "note: microVM {:?} has no output capture; showing its console log, which merges \
         stdout and stderr and is not hash-chained",
        args.name
    );
    if args.stream != StreamSelector::All && args.stream != StreamSelector::Stdout {
        eprintln!(
            "warning: --stream {:?} cannot be honoured on a console log — it carries no channel \
             labels, so nothing will match",
            args.stream
        );
    }
}

/// One line naming what the capture lost and from which end.
fn describe_truncation(truncation: Truncation) -> String {
    let mut parts = Vec::new();
    if truncation.evicted_chunks > 0 {
        parts.push(format!(
            "{} oldest record(s) ({} bytes) were dropped to make room",
            truncation.evicted_chunks, truncation.evicted_bytes
        ));
    }
    if truncation.refused_chunks > 0 {
        parts.push(format!(
            "{} record(s) ({} bytes) never reached the store",
            truncation.refused_chunks, truncation.refused_bytes
        ));
    }
    format!(
        "recorded output is incomplete: {} — what follows is a window, not the whole run",
        parts.join("; ")
    )
}

/// Report loss the follower has newly noticed, once per advance.
///
/// A pruned window is normal operation, not tampering, so this is a notice
/// rather than a failure — but an unreported one leaves a hole the reader
/// cannot distinguish from the workload having been quiet. The marker is
/// cumulative, so only an advance is news.
fn report_new_gap(gap: Option<GapMarker>, reported: &mut Option<GapMarker>, sinks: &mut Sinks<'_>) {
    let Some(gap) = gap else {
        return;
    };
    if reported.is_some_and(|seen| seen.after_seq >= gap.after_seq) {
        return;
    }
    *reported = Some(gap);
    let _ = writeln!(
        sinks.err,
        "warning: {} live record(s) ({} bytes) after seq {} were dropped before this reader \
         could take them",
        gap.dropped_chunks, gap.dropped_bytes, gap.after_seq
    );
    let _ = sinks.err.flush();
}

/// Print the VMM's own diagnostic log.
///
/// A different artifact from workload output — hypervisor-side, written by the
/// VMM, and absent on backends that do not keep one. A plain file tail rather
/// than a stream subscription, because nothing chains or redacts it.
fn show_hypervisor_log(args: &Args) -> Result<()> {
    let path = config::vm_hypervisor_log(&args.name);
    let contents = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "No hypervisor log for microVM {:?} at {} (only the Firecracker backend writes one)",
            args.name,
            path.display()
        )
    })?;
    let mut out = std::io::stdout();
    for line in tail_lines(&contents, args.lines as usize) {
        writeln!(out, "{line}")?;
    }
    out.flush()?;
    if args.follow {
        return follow_file(&path, contents.len() as u64, &mut out);
    }
    Ok(())
}

/// How often a followed file is re-checked for appended bytes.
const HYPERVISOR_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// Keep printing whatever is appended to `path` past `offset`.
///
/// Ends when the consumer hangs up; otherwise runs until interrupted, the way
/// `tail -f` does.
fn follow_file(path: &std::path::Path, mut offset: u64, out: &mut impl Write) -> Result<()> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut file =
        std::fs::File::open(path).with_context(|| format!("Following {}", path.display()))?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        file.seek(SeekFrom::Start(offset))?;
        let read = file.read(&mut buf)?;
        if read == 0 {
            std::thread::sleep(HYPERVISOR_POLL);
            continue;
        }
        offset = offset.saturating_add(read as u64);
        match out.write_all(&buf[..read]).and_then(|()| out.flush()) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    }
}

/// The last `count` lines of `text`, oldest first. `count == 0` yields
/// nothing, the same reading `-n 0` gets on the stream path — one meaning for
/// the flag rather than two.
fn tail_lines(text: &str, count: usize) -> Vec<&str> {
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.len() <= count {
        return lines;
    }
    lines.split_off(lines.len() - count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use mvm_core::stream_client::{OutputRecord, RecordOrigin};

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        args: Args,
    }

    fn parse(argv: &[&str]) -> Result<Args, clap::Error> {
        let mut full = vec!["logs"];
        full.extend_from_slice(argv);
        TestCli::try_parse_from(full).map(|cli| cli.args)
    }

    fn record(seq: u64, kind: StreamKind, payload: &str) -> OutputRecord {
        OutputRecord {
            seq,
            kind,
            origin: RecordOrigin::Durable,
            payload: payload.as_bytes().to_vec(),
        }
    }

    struct Captured {
        out: Vec<u8>,
        err: Vec<u8>,
    }

    fn render_all(records: &[OutputRecord]) -> Captured {
        let mut out = Vec::new();
        let mut err = Vec::new();
        {
            let mut sinks = Sinks {
                out: Box::new(&mut out),
                err: Box::new(&mut err),
            };
            for record in records {
                render(record, &mut sinks).expect("render");
            }
        }
        Captured { out, err }
    }

    #[test]
    fn stream_defaults_to_every_channel() {
        let args = parse(&["vm"]).expect("parse");
        assert_eq!(args.stream, StreamSelector::All);
        assert_eq!(args.request().opts.kinds, KindFilter::all());
    }

    #[test]
    fn stream_stderr_parses_and_narrows_the_filter() {
        let args = parse(&["vm", "--stream", "stderr"]).expect("parse");
        assert_eq!(args.stream, StreamSelector::Stderr);
        let kinds = args.request().opts.kinds;
        assert!(kinds.matches(StreamKind::Stderr));
        assert!(!kinds.matches(StreamKind::Stdout));
        assert!(!kinds.matches(StreamKind::Trace));
    }

    #[test]
    fn every_stream_selector_parses() {
        for (flag, want) in [
            ("all", StreamSelector::All),
            ("stdout", StreamSelector::Stdout),
            ("stderr", StreamSelector::Stderr),
            ("trace", StreamSelector::Trace),
        ] {
            let args = parse(&["vm", "--stream", flag]).expect("parse");
            assert_eq!(args.stream, want, "--stream {flag}");
        }
    }

    #[test]
    fn an_unknown_stream_selector_is_refused() {
        assert!(parse(&["vm", "--stream", "syslog"]).is_err());
    }

    #[test]
    fn follow_and_lines_reach_the_request() {
        let args = parse(&["vm", "-f", "-n", "7"]).expect("parse");
        let request = args.request();
        assert!(request.opts.follow);
        assert_eq!(request.history_tail, Some(7));
    }

    #[test]
    fn each_channel_goes_to_its_own_fd() {
        // `mvmctl logs vm | grep` must filter the workload's stdout, not a
        // merge of both channels.
        let captured = render_all(&[
            record(0, StreamKind::Stdout, "to-stdout"),
            record(1, StreamKind::Stderr, "to-stderr"),
        ]);
        assert_eq!(captured.out, b"to-stdout");
        assert_eq!(captured.err, b"to-stderr");
    }

    #[test]
    fn stdio_bytes_are_written_verbatim_not_line_framed() {
        // The bytes are hash-chained, so re-framing renders something the
        // chain does not cover: no added newline, no lossy conversion.
        let captured = render_all(&[
            record(0, StreamKind::Stdout, "no-newline"),
            record(1, StreamKind::Stdout, "\rprogress"),
        ]);
        assert_eq!(captured.out, b"no-newline\rprogress");
    }

    #[test]
    fn a_trace_record_is_labelled_so_the_workload_cannot_forge_it() {
        let captured = render_all(&[record(0, StreamKind::Trace, r#"{"level":"info"}"#)]);
        assert!(captured.out.is_empty());
        let err = String::from_utf8(captured.err).expect("utf8");
        assert!(err.starts_with("[mvmctl-trace] "), "{err}");
        assert!(err.contains(r#"{"level":"info"}"#), "{err}");
    }

    #[test]
    fn truncation_names_both_ends_it_can_lose() {
        let described = describe_truncation(Truncation {
            refused_chunks: 3,
            refused_bytes: 30,
            evicted_chunks: 2,
            evicted_bytes: 20,
        });
        assert!(
            described.contains("2 oldest record(s) (20 bytes)"),
            "{described}"
        );
        assert!(described.contains("3 record(s) (30 bytes)"), "{described}");
        assert!(
            described.contains("a window, not the whole run"),
            "{described}"
        );
    }

    #[test]
    fn truncation_at_one_end_does_not_claim_the_other() {
        let described = describe_truncation(Truncation {
            refused_chunks: 0,
            refused_bytes: 0,
            evicted_chunks: 4,
            evicted_bytes: 40,
        });
        assert!(described.contains("4 oldest record(s)"), "{described}");
        assert!(
            !described.contains("never reached the store"),
            "{described}"
        );
    }

    #[test]
    fn the_tail_keeps_the_newest_lines() {
        let text = "one\ntwo\nthree\nfour\n";
        assert_eq!(tail_lines(text, 2), vec!["three", "four"]);
        assert_eq!(tail_lines(text, 99), vec!["one", "two", "three", "four"]);
        assert!(tail_lines(text, 0).is_empty(), "-n 0 means zero lines");
    }

    #[test]
    fn an_attach_replays_recorded_output_before_following() {
        // A `run` against an already-running machine opens on whatever it has
        // said so far; opening on silence would look like a broken attach.
        let request = attach_args("m").request();
        assert!(request.opts.follow, "an attach follows");
        assert_eq!(request.opts.kinds, KindFilter::all());
        assert!(
            request.history_tail.is_some_and(|tail| tail > 0),
            "an attach replays some history: {:?}",
            request.history_tail
        );
    }

    #[test]
    fn a_vm_with_no_capture_at_all_fails_rather_than_printing_nothing() {
        // An empty exit-zero here is the worst outcome available: it reads as
        // "the workload printed nothing" when the truth is "nobody looked".
        let _home = isolated_home();
        let err = execute(parse(&["ghost-vm", "-f"]).expect("parse"))
            .expect_err("a VM with no capture must not read as empty output");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("ghost-vm"), "{rendered}");
        assert!(rendered.contains("no output capture"), "{rendered}");
    }

    #[test]
    fn attaching_to_a_vm_with_no_capture_is_reported_not_fatal() {
        // The boot succeeded; failing `machine run` over an absent
        // observability channel would make it less reliable than `run -d`.
        let _home = isolated_home();
        assert_eq!(
            attach("ghost-vm").expect("attach must not fail on an absent capture"),
            AttachOutcome::NoCapture
        );
    }

    #[test]
    fn the_hypervisor_log_names_the_path_it_looked_in() {
        let _home = isolated_home();
        let err = execute(parse(&["ghost-vm", "--hypervisor"]).expect("parse"))
            .expect_err("no hypervisor log exists for this VM");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("firecracker.log"), "{rendered}");
    }

    /// A sink whose writes fail the way a closed pipe does.
    struct ClosedPipe;

    impl Write for ClosedPipe {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn a_closed_pipe_ends_the_read_cleanly() {
        // `mvmctl logs vm | head -1` is ordinary. Rust does not restore the
        // default SIGPIPE, so an unhandled EPIPE would print an error and exit
        // nonzero for a command that did exactly what was asked.
        let mut err = Vec::new();
        let mut sinks = Sinks {
            out: Box::new(ClosedPipe),
            err: Box::new(&mut err),
        };
        let outcome = render(&record(0, StreamKind::Stdout, "into the void"), &mut sinks)
            .expect("a closed pipe is not a failure");
        assert_eq!(outcome, Rendered::ConsumerGone);
    }

    #[test]
    fn a_write_failure_that_is_not_a_closed_pipe_still_propagates() {
        struct Wedged;
        impl Write for Wedged {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut err = Vec::new();
        let mut sinks = Sinks {
            out: Box::new(Wedged),
            err: Box::new(&mut err),
        };
        assert!(render(&record(0, StreamKind::Stdout, "x"), &mut sinks).is_err());
    }

    fn gap(after_seq: u64) -> GapMarker {
        GapMarker {
            after_seq,
            dropped_chunks: 3,
            dropped_bytes: 30,
        }
    }

    #[test]
    fn a_new_gap_is_reported_once_and_an_advance_is_reported_again() {
        // Under `--follow` the marker arrives mid-stream and the reader may
        // never return, so reporting has to happen as it advances — but a
        // cumulative marker repeated on every batch must not spam.
        let mut err = Vec::new();
        let mut reported = None;
        {
            let mut out = Vec::new();
            let mut sinks = Sinks {
                out: Box::new(&mut out),
                err: Box::new(&mut err),
            };
            report_new_gap(Some(gap(4)), &mut reported, &mut sinks);
            report_new_gap(Some(gap(4)), &mut reported, &mut sinks);
            report_new_gap(Some(gap(9)), &mut reported, &mut sinks);
        }
        let rendered = String::from_utf8(err).expect("utf8");
        assert_eq!(rendered.lines().count(), 2, "{rendered}");
        assert!(rendered.contains("after seq 4"), "{rendered}");
        assert!(rendered.contains("after seq 9"), "{rendered}");
    }

    #[test]
    fn no_gap_reports_nothing() {
        let mut err = Vec::new();
        let mut reported = None;
        {
            let mut out = Vec::new();
            let mut sinks = Sinks {
                out: Box::new(&mut out),
                err: Box::new(&mut err),
            };
            report_new_gap(None, &mut reported, &mut sinks);
        }
        assert!(err.is_empty());
        assert_eq!(reported, None);
    }

    #[test]
    fn a_console_only_vm_reads_its_console_log() {
        // Until a broker or transcript exists this is the only source a real
        // VM has; refusing here would leave `logs` showing nothing anywhere.
        let (_env, tmp) = isolated_home();
        let state = mvm_core::config::vm_state_dir("console-vm");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::write(state.join("console.log"), b"hello from the console\n")
            .expect("console capture");
        assert!(tmp.path().exists());

        execute(parse(&["console-vm"]).expect("parse")).expect("a console capture is readable");
    }

    /// An `MVM_HOME` of its own, so a stray real capture on the developer's
    /// machine cannot make these pass for the wrong reason.
    fn isolated_home() -> (mvm_core::util::test_env::TestEnv, tempfile::TempDir) {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", tmp.path());
        (env, tmp)
    }
}

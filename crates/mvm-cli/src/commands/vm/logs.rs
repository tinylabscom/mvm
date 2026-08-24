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

use mvm_contract::stream::StreamKind;
use mvm_core::config;
use mvm_core::naming::validate_vm_name;
use mvm_core::stream_client::{
    EmptyHistory, KindFilter, OutputRecord, OutputRequest, SpliceGap, StreamAvailability,
    StreamError, StreamOpts, Truncation, VmOutputStream, open_vm_output,
};
use mvm_core::transcript::GapMarker;
use mvm_core::user_config::MvmConfig;

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

    /// What to call this selection back to the person who typed it.
    fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Trace => "trace",
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
            // The byte figure stays as the coarse read-window hint; the line
            // count is what bounds the console fallback, because `-n` is a
            // line request and an estimate answers it only approximately —
            // short lines under-trim and return more than was asked for.
            console_tail_bytes: Some(u64::from(self.lines) * CONSOLE_BYTES_PER_RECORD),
            console_tail_lines: Some(self.lines as usize),
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
    let stream = match open_vm_output(&args.name, args.request()) {
        Ok(stream) => stream,
        Err(StreamError::NoCapture {
            vm,
            socket,
            transcript,
            console,
        }) => {
            // Check if the VM has a state directory at all
            let state_dir = config::vm_state_dir(&vm);
            if !state_dir.exists() {
                anyhow::bail!(
                    "microVM {:?} has no state directory at {}; it may have been removed \
                     or never booted",
                    vm,
                    state_dir.display()
                );
            }
            // State survived, so distinguish a missing capture from a machine
            // that was removed or never booted.
            anyhow::bail!(
                "microVM {:?} has a state directory at {} but no output capture:\n\
                 - no live broker at {}\n\
                 - no transcript at {}\n\
                 - no console capture at {}\n\
                 \n\
                 The retained state can indicate an interrupted boot or manual capture cleanup.\n\
                 Run `machine inspect {}` to inspect the persisted machine, or `machine ls` to verify it still exists.",
                vm,
                state_dir.display(),
                socket.display(),
                transcript.display(),
                console.display(),
                vm
            );
        }
        Err(err) => {
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("Reading output for microVM {:?}", args.name));
        }
    };
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
    show_into(args, &mut stream, &mut Sinks::inherited())
}

/// [`show`] against explicit sinks, so a test reads exactly what an operator
/// would rather than asserting on the pieces separately.
fn show_into(args: &Args, stream: &mut VmOutputStream, sinks: &mut Sinks<'_>) -> Result<()> {
    announce(args, stream, sinks);
    pump(stream, sinks).with_context(|| format!("Reading output for microVM {:?}", args.name))
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
/// Both kinds of loss are polled **inside** the loop, before the record they
/// precede is rendered. A ring marker arrives with the batch that reports it
/// and a splice hole is measured on the first live record, so a notice
/// deferred to the end is a notice `logs -f` never prints — the normal way out
/// of a follow is the user interrupting. Printing before the record also puts
/// the notice on the side of the hole it describes.
fn pump(stream: &mut VmOutputStream, sinks: &mut Sinks<'_>) -> Result<()> {
    let mut reported_gap: Option<GapMarker> = None;
    let mut reported_splice = false;
    while let Some(record) = stream.next_output()? {
        report_new_gap(stream.gap(), &mut reported_gap, sinks);
        report_splice_gap(stream.splice_gap(), &mut reported_splice, sinks);
        if render(&record, sinks)? == Rendered::ConsumerGone {
            return Ok(());
        }
    }
    report_new_gap(stream.gap(), &mut reported_gap, sinks);
    report_splice_gap(stream.splice_gap(), &mut reported_splice, sinks);
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
/// to follow, a transcript that lost either end, and a replay that came back
/// empty for a reason the operator did not choose.
fn announce(args: &Args, stream: &VmOutputStream, sinks: &mut Sinks<'_>) {
    match stream.availability() {
        StreamAvailability::LiveAndHistory => {}
        StreamAvailability::LiveOnly => notice(
            sinks,
            &format!(
                "note: microVM {:?} has no recorded output yet; showing live output only",
                args.name
            ),
        ),
        StreamAvailability::HistoryOnly if args.follow => notice(
            sinks,
            &format!(
                "note: microVM {:?} has no live output stream; showing its recorded output and \
                 exiting",
                args.name
            ),
        ),
        StreamAvailability::HistoryOnly => {}
        StreamAvailability::HistoryAndConsole => {
            let line = describe_history_and_console(args);
            notice(sinks, &line);
        }
        StreamAvailability::ConsoleOnly => announce_console_only(args, sinks),
    }
    if let Some(line) = describe_console_merge(args) {
        notice(sinks, &line);
    }
    if let Some(line) = stream.empty_history().and_then(|e| describe_empty(e, args)) {
        notice(sinks, &line);
    }
    if let Some(truncation) = stream.truncation() {
        notice(
            sinks,
            &format!("warning: {}", describe_truncation(truncation)),
        );
    }
}

/// Why a replay came back empty, or `None` when the operator asked for that.
///
/// A capture that matched nothing is the case worth naming: it looks exactly
/// like a workload that printed nothing, and the transcript proving otherwise
/// is right there.
fn describe_empty(empty: EmptyHistory, args: &Args) -> Option<String> {
    match empty {
        EmptyHistory::CaptureEmpty => Some(format!(
            "note: microVM {:?} has an output capture and it is empty",
            args.name
        )),
        EmptyHistory::FilteredOut => Some(format!(
            "note: microVM {:?} has recorded output, but none of it is on the {} channel",
            args.name,
            args.stream.label()
        )),
        EmptyHistory::NotRequested => None,
    }
}

/// What the console merge does to a channel selection — which is not the same
/// thing on every channel.
///
/// A capture has two sources and only one of them can name a channel. The
/// entrypoint frames arrive tagged `Stdout` or `Stderr` the way the guest sent
/// them; the console capture is one merged byte stream, so every record it
/// contributes is recorded as `Stdout` whichever fd wrote it. That covers
/// everything outside the entrypoint call — boot, and whatever the guest says
/// after the agent is gone.
///
/// So the merge *withholds* that output from a `stderr` or `trace` read and
/// *adds* it to a `stdout` one. Telling a `stdout` reader that something is
/// hidden from them would be a plain contradiction — nothing is.
///
/// Only said when a channel was selected: on an unnarrowed read every record
/// is shown regardless of its tag, so the merge changes nothing. A
/// console-only VM needs no note here — the resolver refuses a channel
/// selection outright rather than reaching this point.
fn describe_console_merge(args: &Args) -> Option<String> {
    let effect = match args.stream {
        StreamSelector::All => return None,
        StreamSelector::Stdout => format!(
            "so a {} read carries the console's output as well as the entrypoint's — boot \
             output, and anything written once the guest agent is gone, shows up here whichever \
             fd produced it",
            args.stream.label()
        ),
        StreamSelector::Stderr | StreamSelector::Trace => format!(
            "so a {} read shows only what the entrypoint call separated — boot output, and \
             anything written once the guest agent is gone, is on the stdout channel whichever \
             fd produced it",
            args.stream.label()
        ),
    };
    Some(format!(
        "note: microVM {:?} records console output as stdout, {effect}",
        args.name
    ))
}

/// The console fallback cannot do four things the broker can, and a user who
/// is not told will read its output as if it could. Redaction leads: the other
/// three cost the reader accuracy, that one shows them raw guest bytes.
///
/// A channel selection is not among them: the resolver refuses that outright
/// rather than leaving this note to carry a warning about a filter nothing
/// applied.
fn announce_console_only(args: &Args, sinks: &mut Sinks<'_>) {
    notice(
        sinks,
        &format!(
            "note: microVM {:?} has no output capture; showing its console log, which \
             merges stdout and stderr, is not hash-chained, and has no record boundaries \
             — so -n is approximated in bytes, and a value split across a 64 KiB read is \
             not redacted",
            args.name
        ),
    );
}

/// Two sources, read one after the other, and the reader has to be told where
/// the seam is.
///
/// The recorded half was sealed by a process that did not capture it, so it
/// stops where *that* process exited — for a detached start, seconds into the
/// run. Everything after it comes off the console log: redacted like the
/// recorded half, but with none of the chain's guarantees. Saying so is what
/// stops the unchained remainder being read as if the chain covered it, and
/// what explains the repeated lines where the two halves overlap.
fn describe_history_and_console(args: &Args) -> String {
    format!(
        "note: microVM {:?} was recorded by a process that exited before the run did; what the \
         recording covers is shown first, then the console log covering the rest — which \
         merges stdout and stderr, is not hash-chained, and repeats the part the recording \
         already showed",
        args.name
    )
}

/// Write one operator notice on stderr, degrading rather than raising.
///
/// `eprintln!` panics when the write fails, and `mvmctl logs vm 2>&-` is an
/// ordinary thing for a script to do — a diagnostic must not be the thing that
/// kills the command it is diagnosing. Routed through the sinks so a test
/// reads what an operator would.
fn notice(sinks: &mut Sinks<'_>, line: &str) {
    let _ = writeln!(sinks.err, "{line}");
    let _ = sinks.err.flush();
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
    if truncation.adopted {
        // The counts above came from a manifest rebuilt after the capturing
        // process was gone, so they are a floor. Saying "0 records lost"
        // would be the one reading this capture cannot support.
        parts.push(
            "the capture was sealed after the process recording it exited, so anything it \
             dropped on the way out is uncounted"
                .to_string(),
        );
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
    notice(
        sinks,
        &format!(
            "warning: {} live record(s) ({} bytes) after seq {} were dropped before this reader \
             could take them",
            gap.dropped_chunks, gap.dropped_bytes, gap.after_seq
        ),
    );
}

/// Report a hole where the recorded half meets the live one, once.
///
/// Not a failure and not tampering: a manifest is only written when a capture
/// seals, so a long-running VM's recorded half can stop well before the point
/// a follower attaches, leaving a run of records in neither source. Silence
/// there is the worst outcome available — the two halves render adjacently and
/// a partial log reads as the whole run.
fn report_splice_gap(gap: Option<SpliceGap>, reported: &mut bool, sinks: &mut Sinks<'_>) {
    let Some(gap) = gap else {
        return;
    };
    if std::mem::replace(reported, true) {
        return;
    }
    notice(
        sinks,
        &format!(
            "warning: {} record(s) between recorded seq {} and live seq {} are in neither the \
             recorded capture nor the live stream — what follows resumes after a hole",
            gap.missing(),
            gap.after_seq,
            gap.before_seq
        ),
    );
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
            adopted: false,
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
            adopted: false,
        });
        assert!(described.contains("4 oldest record(s)"), "{described}");
        assert!(
            !described.contains("never reached the store"),
            "{described}"
        );
    }

    #[test]
    fn a_capture_sealed_after_its_recorder_exited_says_its_counts_are_a_floor() {
        // Every count is zero and the capture is still not whole: a run
        // stopped by a later invocation cannot know what the process that
        // recorded it dropped on its way out.
        let described = describe_truncation(Truncation {
            refused_chunks: 0,
            refused_bytes: 0,
            evicted_chunks: 0,
            evicted_bytes: 0,
            adopted: true,
        });
        assert!(
            described.contains("sealed after the process"),
            "{described}"
        );
        assert!(described.contains("uncounted"), "{described}");
    }

    #[test]
    fn a_spliced_read_names_the_seam_and_the_overlap() {
        // Two sources shown back to back. A reader not told where the chained
        // half stops reads the console remainder as if the chain covered it,
        // and reads the repeated prefix as the workload having said it twice.
        let described = describe_history_and_console(&parse(&["m"]).expect("parse"));
        assert!(
            described.contains("exited before the run did"),
            "{described}"
        );
        assert!(described.contains("console log"), "{described}");
        assert!(described.contains("not hash-chained"), "{described}");
        assert!(described.contains("repeats"), "{described}");
        // The spliced-in half is raw guest bytes. Losing the chain costs
        // accuracy; losing redaction is the one with a safety consequence, so
        // it is named rather than left to the guide.
        assert!(
            !described.contains("which is not redacted"),
            "the console half is redacted now; the notice must not still deny it: {described}"
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
        assert!(rendered.contains("no state directory"), "{rendered}");
    }

    #[test]
    fn a_stopped_vm_with_no_state_directory_shows_helpful_error() {
        // Regression guard for the scenario in the bug report:
        // `machine logs <vm>` on a stopped VM that was removed or never booted
        // should give a helpful error message rather than the raw StreamError.
        let _home = isolated_home();
        let err = execute(parse(&["calm-koala-f97a"]).expect("parse"))
            .expect_err("a VM with no state directory must not read as empty");
        let rendered = format!("{err:#}");
        // Verify the error mentions the VM name
        assert!(rendered.contains("calm-koala-f97a"), "{rendered}");
        // Verify the error mentions the lack of state directory
        assert!(rendered.contains("no state directory"), "{rendered}");
        // Verify it suggests the VM may have been removed
        assert!(rendered.contains("removed"), "{rendered}");
    }

    #[test]
    fn retained_state_without_a_capture_is_diagnosed_separately() {
        let (_env, _home) = isolated_home();
        let state_dir = config::vm_state_dir("quiet-vm");
        std::fs::create_dir_all(&state_dir).expect("state directory");

        let err = execute(parse(&["quiet-vm"]).expect("parse"))
            .expect_err("retained state without a capture must not read as empty output");
        let rendered = format!("{err:#}");

        assert!(
            rendered.contains(&state_dir.display().to_string()),
            "{rendered}"
        );
        assert!(rendered.contains("no live broker"), "{rendered}");
        assert!(rendered.contains("no transcript"), "{rendered}");
        assert!(rendered.contains("no console capture"), "{rendered}");
        assert!(rendered.contains("interrupted boot"), "{rendered}");
        assert!(rendered.contains("machine inspect quiet-vm"), "{rendered}");
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

    #[test]
    fn a_running_capture_is_read_from_the_broker_and_not_the_console_beside_it() {
        // The degraded path has to be the exception, not the default. A VM
        // whose stream plane is up must resolve to the broker even though its
        // console log sits right there and would have answered — and the
        // notices must not describe a console-only read, because that is what
        // tells an operator the bytes are unchained and channel-merged.
        let (_env, _tmp) = isolated_home();
        let state = mvm_core::config::vm_state_dir("planed-vm");
        std::fs::create_dir_all(&state).expect("state dir");
        let console = state.join("console.log");
        std::fs::write(&console, b"merged out and err\n").expect("console capture");

        let plane = mvm_hostd::stream::StreamPlane::new();
        let redaction = mvm_core::policy::RedactionPolicy::default();
        plane
            .attach(&mvm_runtime::workload_runner::ConsoleCapture {
                vm_name: "planed-vm",
                console_log: &console,
                redaction: &redaction,
                retention: mvm_core::plan::StreamRetention::Persist,
            })
            .expect("attach a plane");

        let args = parse(&["planed-vm"]).expect("parse");
        let stream = open_vm_output("planed-vm", args.request()).expect("the stream opens");
        assert_eq!(
            stream.availability(),
            StreamAvailability::LiveOnly,
            "a running plane must serve this read, not the console fallback"
        );

        let mut out = Vec::new();
        let mut err = Vec::new();
        {
            let mut sinks = Sinks {
                out: Box::new(&mut out),
                err: Box::new(&mut err),
            };
            announce(&args, &stream, &mut sinks);
        }
        let notices = String::from_utf8(err).expect("utf8");
        assert!(
            !notices.contains("no output capture"),
            "a VM with a live broker has a capture: {notices}"
        );
        assert!(
            !notices.contains("merges stdout and stderr"),
            "the console-only warning must not fire on a broker read: {notices}"
        );
        assert!(notices.contains("no recorded output yet"), "{notices}");

        drop(stream);
        plane.release("planed-vm");
    }

    /// An `MVM_HOME` of its own, so a stray real capture on the developer's
    /// machine cannot make these pass for the wrong reason.
    fn isolated_home() -> (mvm_core::util::test_env::TestEnv, tempfile::TempDir) {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.set("MVM_HOME", tmp.path());
        (env, tmp)
    }

    mod operator_view {
        //! What the command actually prints, driven end to end over a real
        //! sealed transcript and a real broker socket.
        //!
        //! The notices are the product here: every one of them exists because
        //! its absence renders a partial log as a complete one. Asserting on
        //! the pieces separately would let the wiring rot — a notice computed
        //! and never written reads exactly like a notice that had nothing to
        //! say.

        use super::*;
        use mvm_contract::stream::{StreamRecord, StreamSource};
        use mvm_core::crypto::aead;
        use mvm_core::stream_client::{
            OutputLocator, SpliceGap, StreamBatch, open_vm_output_at, write_batch,
        };
        use mvm_core::transcript::{
            self, CaptureBinding, CaptureBounds, Direction, MANIFEST_FILENAME, RetentionPolicy,
            TranscriptWriter, TranscriptWriterConfig,
        };
        use std::path::Path;

        /// A real sealed transcript, written the way the broker will: chunks
        /// encrypted through the real writer under a real KEK and sealed to a
        /// manifest on disk. Nothing here is a stand-in, so a verification
        /// regression in the read path fails these tests too.
        fn seal_history(root: &Path, lines: &[&str]) -> OutputLocator {
            let keys_dir = root.join("keys");
            let dir = root.join("stream");
            std::fs::create_dir_all(&keys_dir).expect("keys dir");
            std::fs::create_dir_all(&dir).expect("capture dir");

            let kek = transcript::load_or_init_kek(&keys_dir).expect("kek");
            let data_key = aead::Key::from_bytes([0x33; 32]);
            let wrapped = transcript::wrap_data_key(&kek, &data_key);
            let mut writer = TranscriptWriter::new(
                &dir,
                data_key,
                TranscriptWriterConfig {
                    capture_id: "capture-vm".to_string(),
                    binding: CaptureBinding {
                        tenant_id: "local".to_string(),
                        vm_name: "vm".to_string(),
                        session_id: None,
                    },
                    bounds: CaptureBounds {
                        max_duration_secs: u64::MAX,
                        max_bytes: 8 << 20,
                        max_chunks: 4096,
                    },
                    retention: RetentionPolicy::Ring,
                    created_unix_secs: 0,
                    recipient: "transcript-kek".to_string(),
                    wrapped_data_key_b64: wrapped,
                },
            );
            for line in lines {
                writer
                    .push(Direction::Stdout, line.as_bytes())
                    .expect("push");
            }
            let manifest = writer.seal();
            std::fs::write(
                dir.join(MANIFEST_FILENAME),
                serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
            )
            .expect("write manifest");

            OutputLocator {
                vm: "vm".to_string(),
                socket: root.join("absent.sock"),
                transcript_dir: dir,
                console_log: root.join("absent-console.log"),
                keys_dir,
            }
        }

        /// A real listening socket that hands one follower `frames` and hangs
        /// up, so the live half is resolved through the production dial.
        struct FakeBroker {
            thread: Option<std::thread::JoinHandle<()>>,
        }

        impl FakeBroker {
            fn serve(path: &Path, frames: Vec<u8>) -> Self {
                let listener = std::os::unix::net::UnixListener::bind(path).expect("bind");
                let thread = std::thread::spawn(move || {
                    if let Ok((mut socket, _)) = listener.accept() {
                        let _ = socket.write_all(&frames);
                        let _ = socket.flush();
                    }
                });
                Self {
                    thread: Some(thread),
                }
            }
        }

        impl Drop for FakeBroker {
            fn drop(&mut self) {
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
        }

        /// A live chain of `count` records starting at `from`, framed the way
        /// a broker sends them.
        fn framed_live(from: u64, count: u64) -> Vec<u8> {
            let mut prev = [0u8; 32];
            let mut records = Vec::new();
            for seq in 0..from + count {
                let record = StreamRecord {
                    seq,
                    source: StreamSource::Entrypoint,
                    kind: StreamKind::Stdout,
                    host_unix_nanos: 1_000 + seq,
                    prev_hash: prev,
                    payload: format!("live-{seq}").into_bytes(),
                };
                prev = record.hash();
                records.push(record);
            }
            let anchor = if from == 0 {
                [0u8; 32]
            } else {
                records[(from - 1) as usize].hash()
            };
            let mut buf = Vec::new();
            write_batch(
                &mut buf,
                &StreamBatch {
                    anchor,
                    records: records.split_off(from as usize),
                    gap: None,
                    caught_up: true,
                },
            )
            .expect("frame");
            buf
        }

        /// Serve `frames` at a socket the locator then points at.
        fn with_broker(root: &Path, locator: &mut OutputLocator, frames: Vec<u8>) -> FakeBroker {
            let socket = root.join("s.sock");
            let broker = FakeBroker::serve(&socket, frames);
            locator.socket = socket;
            broker
        }

        /// Run one whole read: notices to stderr, workload bytes to stdout.
        fn read_all(args: &Args, locator: &OutputLocator) -> Captured {
            let mut stream =
                open_vm_output_at(locator, args.request()).expect("the fixture must open");
            let mut out = Vec::new();
            let mut err = Vec::new();
            {
                let mut sinks = Sinks {
                    out: Box::new(&mut out),
                    err: Box::new(&mut err),
                };
                show_into(args, &mut stream, &mut sinks).expect("read");
            }
            Captured { out, err }
        }

        fn notices(captured: Captured) -> String {
            String::from_utf8(captured.err).expect("notices are utf8")
        }

        #[test]
        fn a_hole_between_the_recorded_and_live_halves_is_reported() {
            // The manifest is only written at seal, so a running VM's
            // recorded half stops well before a follower attaches. Printing
            // seq 0..2 straight into seq 7 shows a partial log as the whole
            // run — the failure this command exists to prevent.
            let root = tempfile::tempdir().expect("tempdir");
            let mut locator = seal_history(root.path(), &["h-0", "h-1", "h-2"]);
            let _broker = with_broker(root.path(), &mut locator, framed_live(7, 2));

            let captured = read_all(&parse(&["vm"]).expect("parse"), &locator);
            assert_eq!(captured.out, b"h-0h-1h-2live-7live-8");
            let rendered = notices(captured);
            assert!(
                rendered.contains("in neither the recorded capture nor the live stream"),
                "{rendered}"
            );
            assert!(rendered.contains("4 record(s)"), "{rendered}");
            assert!(rendered.contains("recorded seq 2"), "{rendered}");
            assert!(rendered.contains("live seq 7"), "{rendered}");
        }

        #[test]
        fn two_halves_that_meet_are_reported_as_nothing_at_all() {
            let root = tempfile::tempdir().expect("tempdir");
            let mut locator = seal_history(root.path(), &["h-0", "h-1", "h-2"]);
            let _broker = with_broker(root.path(), &mut locator, framed_live(3, 2));

            let captured = read_all(&parse(&["vm"]).expect("parse"), &locator);
            assert_eq!(captured.out, b"h-0h-1h-2live-3live-4");
            assert_eq!(notices(captured), "", "an unbroken splice says nothing");
        }

        #[test]
        fn a_channel_selection_names_the_half_of_the_capture_that_cannot_honour_it() {
            // The correction this replaces a lie with: before the entrypoint
            // source was wired, a live read said nothing at all and
            // `--stream stderr` came back empty forever. It can honour the
            // request now — for the entrypoint's own frames. The console half
            // is still one merged stream, and silence about that reads as
            // "the workload wrote nothing to stderr".
            let root = tempfile::tempdir().expect("tempdir");
            let locator = seal_history(root.path(), &["only-stdout"]);

            let rendered = notices(read_all(
                &parse(&["vm", "--stream", "stderr"]).expect("parse"),
                &locator,
            ));
            assert!(
                rendered.contains("records console output as stdout"),
                "{rendered}"
            );
            assert!(rendered.contains("a stderr read"), "{rendered}");
            assert!(
                rendered.contains("shows only what the entrypoint call separated"),
                "{rendered}"
            );
        }

        #[test]
        fn a_stdout_read_is_told_what_the_merge_adds_rather_than_what_it_hides() {
            // The merge withholds console output from a stderr read and *adds*
            // it to a stdout one. Telling a stdout reader that something is
            // hidden from them is a plain contradiction — nothing is, and a
            // notice that contradicts what the operator can see teaches them
            // to ignore the next one.
            let root = tempfile::tempdir().expect("tempdir");
            let locator = seal_history(root.path(), &["only-stdout"]);

            let rendered = notices(read_all(
                &parse(&["vm", "--stream", "stdout"]).expect("parse"),
                &locator,
            ));
            assert!(
                rendered.contains("records console output as stdout"),
                "{rendered}"
            );
            assert!(
                rendered.contains("a stdout read carries the console's output"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("shows only what the entrypoint call separated"),
                "nothing is withheld from a stdout read: {rendered}"
            );
        }

        #[test]
        fn an_unnarrowed_read_is_not_told_about_a_merge_that_hides_nothing_from_it() {
            // Every record is shown whatever its tag, so the caveat would be
            // noise on the default read — and noise is how a notice that
            // matters stops being read.
            let root = tempfile::tempdir().expect("tempdir");
            let locator = seal_history(root.path(), &["one", "two"]);

            let rendered = notices(read_all(&parse(&["vm"]).expect("parse"), &locator));
            assert!(
                !rendered.contains("records console output as stdout"),
                "{rendered}"
            );
        }

        #[test]
        fn a_capture_that_matched_no_channel_says_so_rather_than_claiming_none_exists() {
            // A stdout-only run read as stderr has a healthy, verified
            // transcript and nothing to show from it. "No output capture" is
            // the one thing that is not true.
            let root = tempfile::tempdir().expect("tempdir");
            let locator = seal_history(root.path(), &["only-stdout"]);

            let captured = read_all(
                &parse(&["vm", "--stream", "stderr"]).expect("parse"),
                &locator,
            );
            assert!(captured.out.is_empty());
            let rendered = notices(captured);
            assert!(
                rendered.contains("has recorded output, but none of it is on the stderr channel"),
                "{rendered}"
            );
            assert!(!rendered.contains("no output capture"), "{rendered}");
        }

        #[test]
        fn an_empty_capture_is_announced_as_empty() {
            let root = tempfile::tempdir().expect("tempdir");
            let locator = seal_history(root.path(), &[]);

            let captured = read_all(&parse(&["vm"]).expect("parse"), &locator);
            assert!(captured.out.is_empty());
            assert!(
                notices(captured).contains("has an output capture and it is empty"),
                "an empty capture is not the same as an absent one"
            );
        }

        #[test]
        fn asking_for_no_replay_is_announced_as_nothing() {
            let root = tempfile::tempdir().expect("tempdir");
            let locator = seal_history(root.path(), &["one", "two"]);

            let captured = read_all(&parse(&["vm", "-n", "0"]).expect("parse"), &locator);
            assert!(captured.out.is_empty());
            assert_eq!(
                notices(captured),
                "",
                "an operator who asked for no replay does not need telling"
            );
        }

        #[test]
        fn a_console_only_read_states_what_that_source_cannot_do() {
            let root = tempfile::tempdir().expect("tempdir");
            let mut locator = seal_history(root.path(), &[]);
            // Point past the capture entirely: console is the only source.
            locator.transcript_dir = root.path().join("no-capture");
            locator.console_log = root.path().join("console.log");
            std::fs::write(&locator.console_log, b"merged out and err\n").expect("capture");

            let captured = read_all(&parse(&["vm"]).expect("parse"), &locator);
            assert_eq!(captured.out, b"merged out and err\n");
            let rendered = notices(captured);
            assert!(rendered.contains("merges stdout and stderr"), "{rendered}");
            assert!(rendered.contains("not hash-chained"), "{rendered}");
            // The console is redacted now, so the notice must not claim
            // otherwise — an operator who reads "not redacted" and goes
            // hunting for a rawer source is being sent somewhere that does
            // not exist. What stays named is what is still true: merged
            // channels, no chain, and the read-boundary limit.
            assert!(!rendered.contains("which is not redacted"), "{rendered}");
            assert!(
                rendered.contains("-n is approximated in bytes"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("nothing will match"),
                "no warning about a filter that is never applied: {rendered}"
            );
        }

        #[test]
        fn a_channel_selection_on_a_console_only_vm_is_refused_not_quietly_ignored() {
            // Showing the whole merged console under `--stream stderr` puts
            // the correction on stderr, where a script reading stdout never
            // sees it. Refusing is the only answer that cannot mislead.
            let _home = isolated_home();
            let state = mvm_core::config::vm_state_dir("console-vm");
            std::fs::create_dir_all(&state).expect("state dir");
            std::fs::write(state.join("console.log"), b"merged out and err\n").expect("capture");

            let err = execute(parse(&["console-vm", "--stream", "stderr"]).expect("parse"))
                .expect_err("a console log cannot separate channels");
            let rendered = format!("{err:#}");
            assert!(rendered.contains("merging stdout and stderr"), "{rendered}");
            assert!(rendered.contains("a channel selection"), "{rendered}");
        }

        fn splice(after_seq: u64, before_seq: u64) -> SpliceGap {
            SpliceGap {
                after_seq,
                before_seq,
            }
        }

        #[test]
        fn a_splice_hole_is_reported_once_however_many_records_follow_it() {
            let mut err = Vec::new();
            let mut reported = false;
            {
                let mut out = Vec::new();
                let mut sinks = Sinks {
                    out: Box::new(&mut out),
                    err: Box::new(&mut err),
                };
                report_splice_gap(Some(splice(2, 7)), &mut reported, &mut sinks);
                report_splice_gap(Some(splice(2, 7)), &mut reported, &mut sinks);
                report_splice_gap(None, &mut reported, &mut sinks);
            }
            let rendered = String::from_utf8(err).expect("utf8");
            assert_eq!(rendered.lines().count(), 1, "{rendered}");
        }

        #[test]
        fn a_notice_to_a_closed_stderr_degrades_rather_than_raising() {
            // `eprintln!` panics on a failed write, and `mvmctl logs vm 2>&-`
            // is an ordinary thing for a script to do. A diagnostic must not
            // be what kills the command it is diagnosing.
            let mut out = Vec::new();
            let mut sinks = Sinks {
                out: Box::new(&mut out),
                err: Box::new(ClosedPipe),
            };
            let mut reported = false;
            notice(&mut sinks, "note: nobody is listening");
            report_splice_gap(Some(splice(1, 9)), &mut reported, &mut sinks);
            assert!(reported, "a swallowed write still counts as reported");
        }
    }
}

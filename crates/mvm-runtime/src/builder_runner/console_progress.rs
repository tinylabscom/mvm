//! Show a builder guest's progress on the host terminal while it runs.
//!
//! A builder VM is headless: its only output is the console log the VMM
//! captures, and a Stage 0 bootstrap or a cold kernel build spends many minutes
//! in `nix build` there. The runner already tails that log to notice a halted
//! guest; this reads the same lines and turns them into the detail of one live
//! status line, so the wait says which derivation is building and how far
//! through the plan it is. At `-v` the raw lines are echoed too.

use mvm_build::nix::build_log::NixBuildProgress;

use crate::ui::activity::{self, Activity};

/// Where condensed progress goes. The terminal in production; a recorder in
/// tests, so the condensing is checkable without a global stderr board.
pub(super) trait ProgressSink {
    fn detail(&mut self, detail: &str);
    fn raw_line(&mut self, line: &str);
}

/// The live status line.
pub(super) struct TerminalSink {
    activity: Activity,
}

impl ProgressSink for TerminalSink {
    fn detail(&mut self, detail: &str) {
        self.activity.set_detail(detail);
    }

    fn raw_line(&mut self, line: &str) {
        activity::println_above(line);
    }
}

/// Condenses console lines into a status detail and hands both to a sink.
pub(super) struct BuildConsoleProgress<S: ProgressSink> {
    sink: S,
    progress: NixBuildProgress,
    echo_raw: bool,
    shown: Option<String>,
}

impl BuildConsoleProgress<TerminalSink> {
    /// Start a live status line labelled `label`. `echo_raw` also prints every
    /// console line, for `-v`.
    pub(super) fn start(label: &str, echo_raw: bool) -> Self {
        Self::with_sink(
            TerminalSink {
                activity: activity::start(label),
            },
            echo_raw,
        )
    }

    /// End the line, leaving a `done in …` record behind.
    pub(super) fn finish(self) {
        self.sink.activity.finish();
    }
}

impl<S: ProgressSink> BuildConsoleProgress<S> {
    pub(super) fn with_sink(sink: S, echo_raw: bool) -> Self {
        Self {
            sink,
            progress: NixBuildProgress::default(),
            echo_raw,
            shown: None,
        }
    }

    /// Report a host-side step (staging inputs, booting) until the guest has
    /// something of its own to say.
    pub(super) fn host_step(&mut self, step: &str) {
        self.show(step.to_string());
    }

    /// Fold in the lines one console poll returned.
    pub(super) fn observe(&mut self, lines: &[String]) {
        let mut changed = false;
        for line in lines {
            if self.echo_raw {
                self.sink.raw_line(line);
            }
            changed |= self.progress.observe(line);
        }
        if changed && let Some(summary) = self.progress.summary() {
            self.show(summary);
        }
    }

    fn show(&mut self, detail: String) {
        if self.shown.as_deref() == Some(detail.as_str()) {
            return;
        }
        self.sink.detail(&detail);
        self.shown = Some(detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        details: Vec<String>,
        raw: Vec<String>,
    }

    impl ProgressSink for &mut Recorder {
        fn detail(&mut self, detail: &str) {
            self.details.push(detail.to_string());
        }
        fn raw_line(&mut self, line: &str) {
            self.raw.push(line.to_string());
        }
    }

    fn lines(text: &[&str]) -> Vec<String> {
        text.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn console_lines_become_one_condensed_detail_per_change() {
        let mut recorder = Recorder::default();
        {
            let mut progress = BuildConsoleProgress::with_sink(&mut recorder, false);
            progress.host_step("booting the builder VM");
            progress.observe(&lines(&[
                "[    0.1] Booting Linux",
                "these 2 derivations will be built:",
                "building '/nix/store/aaaa-busybox-1.36.drv'...",
                "busybox> CC applets.o",
            ]));
            progress.observe(&lines(&["busybox> CC more.o"]));
            progress.observe(&lines(&["building '/nix/store/bbbb-linux-6.12.drv'..."]));
        }
        assert_eq!(
            recorder.details,
            vec![
                "booting the builder VM",
                "building busybox-1.36 (1/2)",
                "building linux-6.12 (2/2)",
            ]
        );
        assert!(recorder.raw.is_empty(), "raw lines are for -v only");
    }

    #[test]
    fn verbose_echoes_every_raw_line_in_order() {
        let mut recorder = Recorder::default();
        {
            let mut progress = BuildConsoleProgress::with_sink(&mut recorder, true);
            progress.observe(&lines(&[
                "kernel noise",
                "building '/nix/store/aaaa-x.drv'...",
            ]));
        }
        assert_eq!(
            recorder.raw,
            vec!["kernel noise", "building '/nix/store/aaaa-x.drv'..."]
        );
    }
}

//! Egress refusals, shown to the person who started the workload.
//!
//! The reading, classifying and counting live in `mvm_client::egress_denials`;
//! this module points them at the local tenant's chain and at stderr:
//!
//! - live, while a foreground run or a followed machine's output is on
//!   screen: [`PendingWatch`] / [`watch_machine`];
//! - at exit: [`print_summary`], one block with counts and the flags to
//!   allow what can be allowed;
//! - after the fact: `mvmctl explain`, through `mvm_client::explain`.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

pub(in crate::commands) use mvm_client::egress_denials::{
    DenialTally, DenialWatch, DeniedDestination, Live, WatchTarget, latest_admission,
    print_summary, verify_local_chain,
};

use super::denial_review::{ReviewOffer, ReviewSource};
use super::host_notices::{NoticeSink, Stderr};

/// Start watching `vm_name`'s refusals in the local tenant's chain. `None`
/// when there is no home to read a chain from; the command runs regardless.
pub(in crate::commands) fn watch_machine(vm_name: &str, live: Live) -> Option<DenialWatch> {
    Some(DenialWatch::start(WatchTarget {
        chain: mvm_client::egress_denials::local_chain()?,
        vm_name: vm_name.to_string(),
        live,
        sink: Arc::new(Stderr) as Arc<dyn NoticeSink>,
    }))
}

/// Finish a watch, if one was running, print its exit summary, and offer its
/// grantable refusals for review — in place when `review` names the project
/// manifest the run was admitted under and there is a terminal, otherwise as
/// the `mvmctl explain` command that reviews them later. Returns what it saw.
pub(in crate::commands) fn finish_and_summarize(
    watch: Option<DenialWatch>,
    review: &ReviewOffer,
) -> DenialTally {
    let tally = watch.map(DenialWatch::finish).unwrap_or_default();
    super::denial_review::summarize_and_offer(&tally, review);
    tally
}

/// A watch that starts once the machine's name exists.
///
/// A transient run names its machine inside the boot path, immediately before
/// the admission that precedes the endpoint's spawn. The watch is armed there,
/// so its starting point in the chain precedes anything the endpoint writes.
pub(in crate::commands) struct PendingWatch {
    live: Live,
    running: RefCell<Option<DenialWatch>>,
    /// The name the watch was last armed with, kept after it finishes so the
    /// refusals can be offered for review under it.
    armed: RefCell<Option<String>>,
}

impl PendingWatch {
    pub(in crate::commands) fn new(live: Live) -> Self {
        Self {
            live,
            running: RefCell::new(None),
            armed: RefCell::new(None),
        }
    }

    /// The watch a transient run arms from its admission. Refusals print as
    /// they happen, except where a stray line would corrupt the session (a
    /// raw-mode PTY) or the caller asked for one JSON document.
    pub(in crate::commands) fn for_run(json: bool, pty: bool) -> Rc<Self> {
        Rc::new(Self::new(if json || pty {
            Live::Quiet
        } else {
            Live::Notices
        }))
    }

    /// Start watching `vm_name`. A second call — a retried boot under a new
    /// name — replaces the first watch.
    pub(in crate::commands) fn arm(&self, vm_name: &str) {
        self.armed.replace(Some(vm_name.to_string()));
        let watch = watch_machine(vm_name, self.live);
        if let Some(previous) = self.running.replace(watch) {
            drop(previous.finish());
        }
    }

    /// Stop watching and return what was seen: empty when the run never got
    /// as far as naming a machine.
    pub(in crate::commands) fn finish(&self) -> DenialTally {
        self.running
            .borrow_mut()
            .take()
            .map(DenialWatch::finish)
            .unwrap_or_default()
    }

    /// How the refusals are offered for review: under the machine's name,
    /// against `source`. `None` when the run never named a machine.
    pub(in crate::commands) fn review_offer(&self, source: &ReviewSource) -> Option<ReviewOffer> {
        self.armed
            .borrow()
            .as_ref()
            .map(|vm_name| ReviewOffer::new(vm_name.as_str(), source.clone()))
    }

    /// [`Self::finish`], printing the exit summary unless `print` is false.
    ///
    /// Called as soon as the workload returns — before its outputs are
    /// collected and before a nonzero exit ends the process — so the summary
    /// is the last thing the run says about egress.
    pub(in crate::commands) fn finish_and_summarize(&self, print: bool) -> DenialTally {
        let tally = self.finish();
        if print {
            print_summary(&tally, &Stderr);
        }
        tally
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transient run's refusals are offered under the name its machine was
    /// given at admission, which is the name `mvmctl explain` finds it by.
    #[test]
    fn an_armed_watch_offers_its_review_under_the_machines_name() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let watch = PendingWatch::new(Live::Quiet);
        let source = ReviewSource::Manifest("/project/mvm.toml".into());

        assert_eq!(watch.review_offer(&source), None);
        watch.arm("vm-first");
        watch.arm("vm-retried");
        drop(watch.finish());

        assert_eq!(
            watch.review_offer(&source),
            Some(ReviewOffer::new("vm-retried", source))
        );
    }

    #[test]
    fn an_unarmed_watch_finishes_empty() {
        assert!(PendingWatch::new(Live::Quiet).finish().is_empty());
    }

    #[test]
    fn a_json_or_pty_run_watches_quietly() {
        assert_eq!(PendingWatch::for_run(true, false).live, Live::Quiet);
        assert_eq!(PendingWatch::for_run(false, true).live, Live::Quiet);
        assert_eq!(PendingWatch::for_run(false, false).live, Live::Notices);
    }
}

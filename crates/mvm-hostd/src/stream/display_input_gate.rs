//! The gate on host-to-guest display input.
//!
//! Display frames flow guest to host and need only the view grant. Input is
//! the other direction: pointer, keys, text and paste that change what the
//! workload does. This gate is the only way an input frame becomes something
//! a caller may deliver, and it holds five properties:
//!
//! - **Default-deny, separately from view.** [`DisplayInputGate::open`] refuses
//!   unless the admitted plan carries `grants.display_input`. The view token
//!   grants nothing here.
//! - **Attended on the sealed tier.** A workload built sealed refuses display
//!   input unless the signed grant marks the run attended.
//! - **One writer, ordered, with a lifetime.** The lease, its expiry and its
//!   refresh-by-writing are the stdin gate's own, taken on a separate channel
//!   of the same table, and a frame whose `seq` does not advance is refused
//!   rather than reordered.
//! - **No secret scan.** The stdin plane refuses secret-shaped bytes; display
//!   input carries human-typed credentials on purpose, so scanning it would
//!   refuse the one flow it exists for.
//! - **Audited by kind and count.** `display.granted`, `display.refused` and
//!   `display.input_event` reach the chain-signed log before anything is
//!   handed back for delivery, and carry event kinds and counts only.
//!
//! A frame that opens a credential entry also marks the run as carrying a
//! human credential, which refuses checkpoint and fork for the rest of the
//! run, and pauses frame recording until the entry ends.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use mvm_contract::grants::display::{
    DisplayGrantViolation, DisplayInputGrant, DisplayTier, authorize_display_input,
};
use mvm_contract::stream::{DisplayInputEvent, DisplayInputFrame, DisplayInputFrameError};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;
use crate::plan_admission::AdmittedPlan;
use crate::stream::input_gate::{
    InputRefusal, LeaseChannel, bound_lease_ttl, claim_lease, release_lease, renew_lease,
};

/// Why the gate would not admit a display input writer or frame.
///
/// Every variant is a refusal: nothing from a refused frame is delivered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisplayInputRefusal {
    /// The admitted plan carries no display input grant.
    #[error("no admitted display input grant for this workload")]
    NotGranted,
    /// A sealed workload's grant is not marked attended.
    #[error("display input on a sealed workload requires an attended grant in the signed plan")]
    SealedWithoutAttendedGrant,
    /// The decision could not be written to the chain-signed log.
    #[error("the display input decision could not be recorded in the audit chain")]
    Unauditable,
    /// Another writer holds the display input lease.
    #[error("another writer holds the display input lease ({holder})")]
    LeaseHeld { holder: String },
    /// This session's lease lapsed.
    #[error("the display input lease expired")]
    LeaseExpired,
    /// The frame's `seq` does not advance past what was already accepted.
    #[error("display input frame seq {seq} does not advance past the accepted {after}")]
    OutOfOrder { seq: u64, after: u64 },
    /// The frame breaks the contract's shape or bounds.
    #[error("display input frame is malformed: {0}")]
    Malformed(DisplayInputFrameError),
    /// A paste arrived without a clipboard grant.
    #[error("paste needs a clipboard grant in the signed plan")]
    PasteNotGranted,
    /// A paste exceeds the clipboard grant's bound.
    #[error("paste of {len} bytes exceeds the granted {limit}")]
    PasteTooLarge { len: usize, limit: u32 },
    /// A credential entry began without a human-credential grant.
    #[error("credential entry needs a human_credential grant in the signed plan")]
    CredentialEntryNotGranted,
    /// A credential entry began while one was open, or ended while none was.
    #[error("credential entry markers must alternate, beginning with begin")]
    CredentialEntryOutOfTurn,
    /// The run could not be marked as carrying a human credential, so checkpoint
    /// and fork could not be refused for it.
    #[error("the human-credential marker could not be recorded: {0}")]
    CredentialUnrecorded(String),
}

impl DisplayInputRefusal {
    /// Wire-stable reason word for the audit chain.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotGranted => "not-granted",
            Self::SealedWithoutAttendedGrant => "sealed-without-attended-grant",
            Self::Unauditable => "unauditable",
            Self::LeaseHeld { .. } => "lease-held",
            Self::LeaseExpired => "lease-expired",
            Self::OutOfOrder { .. } => "out-of-order",
            Self::Malformed(error) => error.reason(),
            Self::PasteNotGranted => "paste-not-granted",
            Self::PasteTooLarge { .. } => "paste-too-large",
            Self::CredentialEntryNotGranted => "credential-entry-not-granted",
            Self::CredentialEntryOutOfTurn => "credential-entry-out-of-turn",
            Self::CredentialUnrecorded(_) => "credential-unrecorded",
        }
    }
}

impl From<DisplayGrantViolation> for DisplayInputRefusal {
    fn from(violation: DisplayGrantViolation) -> Self {
        match violation {
            DisplayGrantViolation::SealedWithoutAttendedGrant => Self::SealedWithoutAttendedGrant,
            DisplayGrantViolation::NotGranted
            | DisplayGrantViolation::ClipboardBoundTooLarge { .. }
            | DisplayGrantViolation::EgressOutsideCredentialDestinations(_) => Self::NotGranted,
        }
    }
}

/// Keeps [`DisplayAuditSink`] closed: a sink that answered `Ok(())` without
/// writing would leave display input unaudited while the gate believed it was.
mod sealed {
    pub trait Sealed {}
}

/// Where the gate records its decisions.
pub trait DisplayAuditSink: sealed::Sealed + Send + Sync {
    fn record_granted(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        holder: &str,
        attended: bool,
    ) -> anyhow::Result<()>;
    fn record_refused(&self, plan: &ExecutionPlan, vm: &str, reason: &str) -> anyhow::Result<()>;
    fn record_events(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        holder: &str,
        seq: u64,
        kinds: &BTreeMap<&'static str, u32>,
    ) -> anyhow::Result<()>;
    fn record_credential_entry(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        holder: &str,
        began: bool,
    ) -> anyhow::Result<()>;
}

/// The production sink: the host's chain-signed audit log.
pub struct DisplayAudit {
    emitter: Arc<AuditEmitter>,
}

impl DisplayAudit {
    #[must_use]
    pub fn new(emitter: Arc<AuditEmitter>) -> Self {
        Self { emitter }
    }
}

impl sealed::Sealed for DisplayAudit {}

impl DisplayAuditSink for DisplayAudit {
    fn record_granted(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        holder: &str,
        attended: bool,
    ) -> anyhow::Result<()> {
        self.emitter
            .emit_display_granted(plan, vm, holder, attended)
    }

    fn record_refused(&self, plan: &ExecutionPlan, vm: &str, reason: &str) -> anyhow::Result<()> {
        self.emitter.emit_display_refused(plan, vm, reason)
    }

    fn record_events(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        holder: &str,
        seq: u64,
        kinds: &BTreeMap<&'static str, u32>,
    ) -> anyhow::Result<()> {
        self.emitter
            .emit_display_input_events(plan, vm, holder, seq, kinds)
    }

    fn record_credential_entry(
        &self,
        plan: &ExecutionPlan,
        vm: &str,
        holder: &str,
        began: bool,
    ) -> anyhow::Result<()> {
        self.emitter
            .emit_display_credential_entry(plan, vm, holder, began)
    }
}

/// Where the gate marks a run as carrying a human credential.
///
/// A seam rather than a direct call so the refusal path is testable without a
/// VM state directory; production uses [`RunMarkers`].
pub(crate) trait CredentialMarkers: Send + Sync {
    fn begin_entry(&self, vm: &str) -> anyhow::Result<()>;
    fn end_entry(&self, vm: &str) -> anyhow::Result<()>;
}

/// The per-run markers in the VM's state directory.
pub(crate) struct RunMarkers;

impl CredentialMarkers for RunMarkers {
    fn begin_entry(&self, vm: &str) -> anyhow::Result<()> {
        mvm_runtime::vm::human_credential::begin_entry(vm)
    }

    fn end_entry(&self, vm: &str) -> anyhow::Result<()> {
        mvm_runtime::vm::human_credential::end_entry(vm)
    }
}

/// Everything one open needs besides the plan.
struct OpenParams {
    vm: String,
    tier: DisplayTier,
    audit: Arc<dyn DisplayAuditSink>,
    markers: Arc<dyn CredentialMarkers>,
    lease_ttl: Duration,
}

/// The gate: reached by name, holding no state of its own beyond the shared
/// lease table.
pub struct DisplayInputGate;

impl DisplayInputGate {
    /// Take the display input lease on `vm` under `admitted`.
    ///
    /// `tier` is whether the workload's image was built sealed. It comes from
    /// the host's record of the running VM, never from the plan, because the
    /// plan's author is the party the sealed-tier rule constrains.
    ///
    /// # Errors
    /// Every [`DisplayInputRefusal`] an open can produce; each is recorded.
    pub fn open(
        vm: &str,
        admitted: &AdmittedPlan,
        tier: DisplayTier,
        audit: DisplayAudit,
    ) -> Result<DisplayInputSession, DisplayInputRefusal> {
        Self::open_authorized(
            admitted.plan(),
            OpenParams {
                vm: vm.to_string(),
                tier,
                audit: Arc::new(audit),
                markers: Arc::new(RunMarkers),
                lease_ttl: bound_lease_ttl(vm),
            },
        )
    }

    fn open_authorized(
        plan: &ExecutionPlan,
        params: OpenParams,
    ) -> Result<DisplayInputSession, DisplayInputRefusal> {
        let OpenParams {
            vm,
            tier,
            audit,
            markers,
            lease_ttl,
        } = params;
        let grant = match authorize_display_input(plan.grants.as_ref(), tier) {
            Ok(grant) => grant.clone(),
            Err(violation) => {
                let refusal = DisplayInputRefusal::from(violation);
                record_refusal(audit.as_ref(), plan, &vm, &refusal);
                return Err(refusal);
            }
        };

        let holder = match claim_lease(LeaseChannel::Display, &vm, plan, lease_ttl) {
            Ok(holder) => holder,
            Err(refusal) => {
                let refusal = match refusal {
                    InputRefusal::LeaseHeld { holder } => DisplayInputRefusal::LeaseHeld { holder },
                    _ => DisplayInputRefusal::LeaseExpired,
                };
                record_refusal(audit.as_ref(), plan, &vm, &refusal);
                return Err(refusal);
            }
        };

        if let Err(error) = audit.record_granted(plan, &vm, &holder, grant.attended) {
            release_lease(LeaseChannel::Display, &vm, &holder);
            tracing::warn!(vm = %vm, error = %error, "display input refused: grant not recorded");
            record_refusal(audit.as_ref(), plan, &vm, &DisplayInputRefusal::Unauditable);
            return Err(DisplayInputRefusal::Unauditable);
        }

        Ok(DisplayInputSession {
            vm,
            plan: plan.clone(),
            grant,
            holder,
            audit,
            markers,
            lease_ttl,
            highest_accepted_seq: None,
            entry_open: false,
            refused: None,
        })
    }
}

/// One leased writer's channel into a workload's display.
pub struct DisplayInputSession {
    vm: String,
    plan: ExecutionPlan,
    grant: DisplayInputGrant,
    holder: String,
    audit: Arc<dyn DisplayAuditSink>,
    markers: Arc<dyn CredentialMarkers>,
    lease_ttl: Duration,
    highest_accepted_seq: Option<u64>,
    entry_open: bool,
    /// A session that refused a frame for anything other than ordering stays
    /// refused, as the stdin session does.
    refused: Option<DisplayInputRefusal>,
}

impl DisplayInputSession {
    /// The lease holder id this session was minted.
    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    /// Whether a credential entry is open on this session.
    #[must_use]
    pub fn credential_entry_open(&self) -> bool {
        self.entry_open
    }

    /// Offer one frame. On `Ok` the frame is what the caller delivers, in
    /// order, and its kinds and counts are already in the chain.
    ///
    /// # Errors
    /// The refusal, which has been recorded.
    pub fn write(
        &mut self,
        frame: DisplayInputFrame,
    ) -> Result<DisplayInputFrame, DisplayInputRefusal> {
        self.check_live()?;
        if let Some(after) = self.highest_accepted_seq
            && frame.seq <= after
        {
            let refusal = DisplayInputRefusal::OutOfOrder {
                seq: frame.seq,
                after,
            };
            record_refusal(self.audit.as_ref(), &self.plan, &self.vm, &refusal);
            return Err(refusal);
        }
        if let Err(refusal) = self.authorize(&frame) {
            return Err(self.latch(refusal));
        }
        if let Err(error) = self.audit.record_events(
            &self.plan,
            &self.vm,
            &self.holder,
            frame.seq,
            &frame.kind_counts(),
        ) {
            tracing::warn!(vm = %self.vm, error = %error, "display input refused: events not recorded");
            return Err(self.latch(DisplayInputRefusal::Unauditable));
        }
        self.apply_credential_markers(&frame)?;
        self.highest_accepted_seq = Some(frame.seq);
        Ok(frame)
    }

    /// Extend the lease without sending input.
    ///
    /// # Errors
    /// The lease lapsed, or the session already refused.
    pub fn refresh(&mut self) -> Result<(), DisplayInputRefusal> {
        self.check_live()
    }

    /// End the session: close any open credential entry and release the lease.
    pub fn close(self) {
        drop(self);
    }

    /// Check every event against the grant before anything has an effect, so a
    /// refused frame changes nothing.
    fn authorize(&self, frame: &DisplayInputFrame) -> Result<(), DisplayInputRefusal> {
        frame.validate().map_err(DisplayInputRefusal::Malformed)?;
        let mut entry_open = self.entry_open;
        for event in &frame.events {
            match event {
                DisplayInputEvent::Paste { text } => {
                    let clipboard = self
                        .grant
                        .clipboard
                        .ok_or(DisplayInputRefusal::PasteNotGranted)?;
                    let limit = clipboard.max_paste_bytes.get();
                    if u32::try_from(text.len()).map_or(true, |len| len > limit) {
                        return Err(DisplayInputRefusal::PasteTooLarge {
                            len: text.len(),
                            limit,
                        });
                    }
                }
                DisplayInputEvent::CredentialEntryBegin => {
                    if self.grant.human_credential.is_none() {
                        return Err(DisplayInputRefusal::CredentialEntryNotGranted);
                    }
                    if entry_open {
                        return Err(DisplayInputRefusal::CredentialEntryOutOfTurn);
                    }
                    entry_open = true;
                }
                DisplayInputEvent::CredentialEntryEnd => {
                    if !entry_open {
                        return Err(DisplayInputRefusal::CredentialEntryOutOfTurn);
                    }
                    entry_open = false;
                }
                DisplayInputEvent::PointerMove { .. }
                | DisplayInputEvent::PointerButton { .. }
                | DisplayInputEvent::Wheel { .. }
                | DisplayInputEvent::Key { .. }
                | DisplayInputEvent::Text { .. } => {}
            }
        }
        Ok(())
    }

    /// Mark the run and record the window for every credential marker in the
    /// frame, in order. A begin that cannot be marked refuses the frame: an
    /// unmarked run could be forked with the credential inside it.
    fn apply_credential_markers(
        &mut self,
        frame: &DisplayInputFrame,
    ) -> Result<(), DisplayInputRefusal> {
        for event in &frame.events {
            match event {
                DisplayInputEvent::CredentialEntryBegin => {
                    if let Err(error) = self.markers.begin_entry(&self.vm) {
                        return Err(self.latch(DisplayInputRefusal::CredentialUnrecorded(
                            format!("{error:#}"),
                        )));
                    }
                    self.entry_open = true;
                    if let Err(error) =
                        self.audit
                            .record_credential_entry(&self.plan, &self.vm, &self.holder, true)
                    {
                        return Err(self.latch(DisplayInputRefusal::CredentialUnrecorded(
                            format!("{error:#}"),
                        )));
                    }
                }
                DisplayInputEvent::CredentialEntryEnd => self.end_entry(),
                _ => {}
            }
        }
        Ok(())
    }

    /// Close the recording pause, best effort: the run stays marked whatever
    /// happens here, so a failure costs recording, not the fork refusal.
    fn end_entry(&mut self) {
        if !self.entry_open {
            return;
        }
        self.entry_open = false;
        if let Err(error) = self.markers.end_entry(&self.vm) {
            tracing::warn!(vm = %self.vm, error = %error, "credential entry window not closed");
        }
        if let Err(error) =
            self.audit
                .record_credential_entry(&self.plan, &self.vm, &self.holder, false)
        {
            tracing::warn!(vm = %self.vm, error = %error, "credential entry end not recorded");
        }
    }

    fn check_live(&mut self) -> Result<(), DisplayInputRefusal> {
        if let Some(refusal) = &self.refused {
            return Err(refusal.clone());
        }
        if renew_lease(
            LeaseChannel::Display,
            &self.vm,
            &self.holder,
            self.lease_ttl,
        ) {
            Ok(())
        } else {
            Err(self.latch(DisplayInputRefusal::LeaseExpired))
        }
    }

    fn latch(&mut self, refusal: DisplayInputRefusal) -> DisplayInputRefusal {
        record_refusal(self.audit.as_ref(), &self.plan, &self.vm, &refusal);
        self.refused = Some(refusal.clone());
        refusal
    }
}

impl Drop for DisplayInputSession {
    /// A session that ends with a credential entry open closes it, so a writer
    /// that went away does not leave recording paused for the rest of the run.
    fn drop(&mut self) {
        self.end_entry();
        release_lease(LeaseChannel::Display, &self.vm, &self.holder);
    }
}

/// Record a refusal, best effort: the refusal stands whether or not it lands.
fn record_refusal(
    sink: &dyn DisplayAuditSink,
    plan: &ExecutionPlan,
    vm: &str,
    refusal: &DisplayInputRefusal,
) {
    if let Err(error) = sink.record_refused(plan, vm, refusal.reason()) {
        tracing::warn!(
            vm = %vm,
            reason = refusal.reason(),
            error = %error,
            "display input refusal not recorded in the audit chain"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use mvm_contract::grants::{DisplayClipboardGrant, Grants, HumanCredentialGrant};
    use mvm_contract::policy::network_policy::HostPort;
    use mvm_contract::protocol::broker::ServiceId;
    use mvm_contract::stream::{DISPLAY_VIEW_GRANT_SERVICE, PointerButton};
    use mvm_core::plan::test_support::PlanFixture;

    use super::*;

    /// Everything a sink was asked to record, as `(event, detail)` pairs.
    #[derive(Default)]
    struct RecordingSink {
        entries: Mutex<Vec<(String, String)>>,
        fail_events: bool,
    }

    impl RecordingSink {
        fn push(&self, event: &str, detail: String) {
            self.entries
                .lock()
                .unwrap()
                .push((event.to_string(), detail));
        }

        fn entries(&self) -> Vec<(String, String)> {
            self.entries.lock().unwrap().clone()
        }
    }

    impl sealed::Sealed for RecordingSink {}

    impl DisplayAuditSink for RecordingSink {
        fn record_granted(
            &self,
            _: &ExecutionPlan,
            _: &str,
            _: &str,
            attended: bool,
        ) -> anyhow::Result<()> {
            self.push("display.granted", format!("attended={attended}"));
            Ok(())
        }

        fn record_refused(&self, _: &ExecutionPlan, _: &str, reason: &str) -> anyhow::Result<()> {
            self.push("display.refused", reason.to_string());
            Ok(())
        }

        fn record_events(
            &self,
            _: &ExecutionPlan,
            _: &str,
            _: &str,
            _: u64,
            kinds: &BTreeMap<&'static str, u32>,
        ) -> anyhow::Result<()> {
            if self.fail_events {
                anyhow::bail!("the chain is unreachable");
            }
            self.push("display.input_event", format!("{kinds:?}"));
            Ok(())
        }

        fn record_credential_entry(
            &self,
            _: &ExecutionPlan,
            _: &str,
            _: &str,
            began: bool,
        ) -> anyhow::Result<()> {
            self.push("display.credential_entry", format!("began={began}"));
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemoryMarkers {
        log: Mutex<Vec<&'static str>>,
        fail: bool,
    }

    impl CredentialMarkers for MemoryMarkers {
        fn begin_entry(&self, _: &str) -> anyhow::Result<()> {
            if self.fail {
                anyhow::bail!("no state directory");
            }
            self.log.lock().unwrap().push("begin");
            Ok(())
        }

        fn end_entry(&self, _: &str) -> anyhow::Result<()> {
            self.log.lock().unwrap().push("end");
            Ok(())
        }
    }

    fn unique_vm(prefix: &str) -> String {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
    }

    fn plan_with(display_input: Option<DisplayInputGrant>) -> ExecutionPlan {
        PlanFixture::new()
            .services(vec![
                ServiceId::parse(DISPLAY_VIEW_GRANT_SERVICE).expect("view token parses"),
            ])
            .grants(Some(Grants {
                display_input,
                ..Grants::default()
            }))
            .build()
    }

    fn credential_grant() -> DisplayInputGrant {
        DisplayInputGrant {
            attended: true,
            clipboard: Some(DisplayClipboardGrant {
                max_paste_bytes: NonZeroU32::new(8).unwrap(),
            }),
            human_credential: Some(HumanCredentialGrant {
                destinations: vec![HostPort::new("login.example", 443)],
            }),
        }
    }

    struct Opened {
        result: Result<DisplayInputSession, DisplayInputRefusal>,
        sink: Arc<RecordingSink>,
        markers: Arc<MemoryMarkers>,
    }

    fn open(plan: &ExecutionPlan, vm: &str, tier: DisplayTier) -> Opened {
        open_with(
            plan,
            vm,
            tier,
            RecordingSink::default(),
            MemoryMarkers::default(),
        )
    }

    fn open_with(
        plan: &ExecutionPlan,
        vm: &str,
        tier: DisplayTier,
        sink: RecordingSink,
        markers: MemoryMarkers,
    ) -> Opened {
        let sink = Arc::new(sink);
        let markers = Arc::new(markers);
        let result = DisplayInputGate::open_authorized(
            plan,
            OpenParams {
                vm: vm.to_string(),
                tier,
                audit: sink.clone(),
                markers: markers.clone(),
                lease_ttl: Duration::from_secs(30),
            },
        );
        Opened {
            result,
            sink,
            markers,
        }
    }

    fn frame(seq: u64, events: Vec<DisplayInputEvent>) -> DisplayInputFrame {
        DisplayInputFrame { seq, events }
    }

    fn click(seq: u64) -> DisplayInputFrame {
        frame(
            seq,
            vec![DisplayInputEvent::PointerButton {
                x: 4,
                y: 4,
                button: PointerButton::Left,
                pressed: true,
            }],
        )
    }

    /// A view-only plan grants frames and nothing toward the guest: no session
    /// exists to write through, and the refusal is in the chain.
    #[test]
    fn display_input_refused_without_grant() {
        let vm = unique_vm("no-input-grant");
        for tier in [DisplayTier::Accessible, DisplayTier::Sealed] {
            let opened = open(&plan_with(None), &vm, tier);
            assert!(matches!(
                opened.result,
                Err(DisplayInputRefusal::NotGranted)
            ));
            assert_eq!(
                opened.sink.entries(),
                vec![("display.refused".to_string(), "not-granted".to_string())]
            );
        }
    }

    #[test]
    fn display_refused_on_sealed_tier_without_attended_grant() {
        let vm = unique_vm("sealed");
        let unattended = plan_with(Some(DisplayInputGrant::default()));
        let opened = open(&unattended, &vm, DisplayTier::Sealed);
        assert!(matches!(
            opened.result,
            Err(DisplayInputRefusal::SealedWithoutAttendedGrant)
        ));
        assert_eq!(
            opened.sink.entries(),
            vec![(
                "display.refused".to_string(),
                "sealed-without-attended-grant".to_string()
            )]
        );

        // The same unattended grant is enough on an accessible image, and an
        // attended one is enough on a sealed image.
        let accessible = open(&unattended, &vm, DisplayTier::Accessible);
        assert!(accessible.result.is_ok());
        drop(accessible);
        let attended = plan_with(Some(DisplayInputGrant {
            attended: true,
            ..DisplayInputGrant::default()
        }));
        let opened = open(&attended, &vm, DisplayTier::Sealed);
        assert!(opened.result.is_ok());
        assert_eq!(
            opened.sink.entries(),
            vec![("display.granted".to_string(), "attended=true".to_string())]
        );
    }

    #[test]
    fn one_writer_holds_the_display_lease_and_stdin_is_a_separate_channel() {
        let vm = unique_vm("lease");
        let plan = plan_with(Some(DisplayInputGrant::default()));
        let first = open(&plan, &vm, DisplayTier::Accessible);
        let holder = first.result.as_ref().unwrap().holder().to_string();
        let second = open(&plan, &vm, DisplayTier::Accessible);
        assert_eq!(
            second.result.err(),
            Some(DisplayInputRefusal::LeaseHeld { holder })
        );
        assert_eq!(
            crate::stream::input_gate::InputGate::lease_holder(&vm),
            None,
            "a display lease must not occupy the VM's stdin lease"
        );
        drop(first);
        assert!(open(&plan, &vm, DisplayTier::Accessible).result.is_ok());
    }

    #[test]
    fn frames_are_audited_by_kind_and_refused_out_of_order() {
        let vm = unique_vm("order");
        let plan = plan_with(Some(DisplayInputGrant::default()));
        let mut opened = open(&plan, &vm, DisplayTier::Accessible);
        let session = opened.result.as_mut().unwrap();
        let sent = frame(
            3,
            vec![
                DisplayInputEvent::Text {
                    text: "hunter2".into(),
                },
                DisplayInputEvent::Key {
                    key: "Enter".into(),
                    pressed: true,
                },
            ],
        );
        assert_eq!(session.write(sent.clone()).unwrap(), sent);
        assert_eq!(
            session.write(click(3)).err(),
            Some(DisplayInputRefusal::OutOfOrder { seq: 3, after: 3 })
        );
        assert!(
            session.write(click(4)).is_ok(),
            "an out-of-order frame does not latch the session"
        );

        let entries = opened.sink.entries();
        assert!(
            entries
                .iter()
                .all(|(_, detail)| !detail.contains("hunter2") && !detail.contains("Enter"))
        );
        assert_eq!(
            entries[1],
            (
                "display.input_event".to_string(),
                r#"{"key": 1, "text": 1}"#.to_string()
            )
        );
    }

    #[test]
    fn display_input_is_not_secret_scanned() {
        // A credential is exactly what attended input carries. Bind a
        // fingerprint for it on the stdin gate and the display gate must still
        // deliver it.
        let vm = unique_vm("unscanned");
        crate::stream::input_gate::InputGate::bind_fingerprints(
            &vm,
            vec![
                mvm_contract::stream::SecretFingerprint::of(
                    b"correct horse battery",
                    mvm_contract::stream::SecretCategory::HostSecret,
                )
                .unwrap(),
            ],
        );
        let plan = plan_with(Some(DisplayInputGrant::default()));
        let mut opened = open(&plan, &vm, DisplayTier::Accessible);
        let typed = frame(
            0,
            vec![DisplayInputEvent::Text {
                text: "correct horse battery".into(),
            }],
        );
        assert!(opened.result.as_mut().unwrap().write(typed).is_ok());
        crate::stream::input_gate::InputGate::unbind(&vm);
    }

    #[test]
    fn paste_needs_the_clipboard_grant_and_its_bound() {
        let vm = unique_vm("paste");
        let no_clipboard = plan_with(Some(DisplayInputGrant::default()));
        let mut opened = open(&no_clipboard, &vm, DisplayTier::Accessible);
        let paste = |seq, text: &str| {
            frame(
                seq,
                vec![DisplayInputEvent::Paste {
                    text: text.to_string(),
                }],
            )
        };
        assert_eq!(
            opened.result.as_mut().unwrap().write(paste(0, "abc")).err(),
            Some(DisplayInputRefusal::PasteNotGranted)
        );
        assert_eq!(
            opened.result.as_mut().unwrap().write(click(1)).err(),
            Some(DisplayInputRefusal::PasteNotGranted),
            "a session that refused a paste stays refused"
        );
        drop(opened);

        let granted = plan_with(Some(credential_grant()));
        let mut opened = open(&granted, &vm, DisplayTier::Sealed);
        let session = opened.result.as_mut().unwrap();
        assert!(session.write(paste(0, "12345678")).is_ok());
        assert_eq!(
            session.write(paste(1, "123456789")).err(),
            Some(DisplayInputRefusal::PasteTooLarge { len: 9, limit: 8 })
        );
    }

    #[test]
    fn a_credential_entry_marks_the_run_and_brackets_the_recording_pause() {
        let vm = unique_vm("credential");
        let plan = plan_with(Some(credential_grant()));
        let mut opened = open(&plan, &vm, DisplayTier::Sealed);
        let session = opened.result.as_mut().unwrap();
        session
            .write(frame(
                0,
                vec![
                    DisplayInputEvent::CredentialEntryBegin,
                    DisplayInputEvent::Text {
                        text: "p4ss".into(),
                    },
                ],
            ))
            .unwrap();
        assert!(session.credential_entry_open());
        session
            .write(frame(1, vec![DisplayInputEvent::CredentialEntryEnd]))
            .unwrap();
        assert!(!session.credential_entry_open());
        assert_eq!(*opened.markers.log.lock().unwrap(), vec!["begin", "end"]);
        let kinds: Vec<_> = opened
            .sink
            .entries()
            .into_iter()
            .map(|(event, detail)| format!("{event} {detail}"))
            .collect();
        assert!(kinds.contains(&"display.credential_entry began=true".to_string()));
        assert!(kinds.contains(&"display.credential_entry began=false".to_string()));
    }

    #[test]
    fn a_credential_entry_needs_its_grant_and_alternates() {
        let vm = unique_vm("credential-order");
        let no_credential = plan_with(Some(DisplayInputGrant {
            attended: true,
            ..DisplayInputGrant::default()
        }));
        let mut opened = open(&no_credential, &vm, DisplayTier::Sealed);
        assert_eq!(
            opened
                .result
                .as_mut()
                .unwrap()
                .write(frame(0, vec![DisplayInputEvent::CredentialEntryBegin]))
                .err(),
            Some(DisplayInputRefusal::CredentialEntryNotGranted)
        );
        assert!(opened.markers.log.lock().unwrap().is_empty());
        drop(opened);

        let plan = plan_with(Some(credential_grant()));
        let mut opened = open(&plan, &vm, DisplayTier::Sealed);
        assert_eq!(
            opened
                .result
                .as_mut()
                .unwrap()
                .write(frame(0, vec![DisplayInputEvent::CredentialEntryEnd]))
                .err(),
            Some(DisplayInputRefusal::CredentialEntryOutOfTurn)
        );
    }

    #[test]
    fn a_begin_that_cannot_mark_the_run_is_refused() {
        let vm = unique_vm("unmarked");
        let plan = plan_with(Some(credential_grant()));
        let mut opened = open_with(
            &plan,
            &vm,
            DisplayTier::Sealed,
            RecordingSink::default(),
            MemoryMarkers {
                fail: true,
                ..MemoryMarkers::default()
            },
        );
        let refusal = opened
            .result
            .as_mut()
            .unwrap()
            .write(frame(0, vec![DisplayInputEvent::CredentialEntryBegin]))
            .unwrap_err();
        assert_eq!(refusal.reason(), "credential-unrecorded");
    }

    #[test]
    fn a_session_dropped_mid_entry_resumes_recording() {
        let vm = unique_vm("dropped");
        let plan = plan_with(Some(credential_grant()));
        let mut opened = open(&plan, &vm, DisplayTier::Sealed);
        opened
            .result
            .as_mut()
            .unwrap()
            .write(frame(0, vec![DisplayInputEvent::CredentialEntryBegin]))
            .unwrap();
        let markers = Arc::clone(&opened.markers);
        drop(opened);
        assert_eq!(*markers.log.lock().unwrap(), vec!["begin", "end"]);
    }

    #[test]
    fn input_that_cannot_be_audited_is_not_delivered() {
        let vm = unique_vm("unaudited");
        let plan = plan_with(Some(DisplayInputGrant::default()));
        let mut opened = open_with(
            &plan,
            &vm,
            DisplayTier::Accessible,
            RecordingSink {
                fail_events: true,
                ..RecordingSink::default()
            },
            MemoryMarkers::default(),
        );
        assert_eq!(
            opened.result.as_mut().unwrap().write(click(0)).err(),
            Some(DisplayInputRefusal::Unauditable)
        );
    }
}

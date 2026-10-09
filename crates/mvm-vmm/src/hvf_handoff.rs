//! Authenticated request used when a paused first-party VMM becomes a claimed child.

use serde::{Deserialize, Serialize};

/// Host request that authorizes a paused parent to become a claimed child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HvfHandoffRequest {
    /// Registry-safe child VM name; all channel paths are derived from it.
    pub child_vm_name: String,
    /// PID of the paused parent supervisor, bound into the authorization.
    pub parent_pid: u32,
    /// Presence bits for authorized child channels; paths remain supervisor-derived.
    pub channel_mask: u8,
    /// The signed `ExecutionPlan` the child was admitted under, as the claim
    /// carried it. The parent booted with no plan, so this is how the process
    /// that now owns the child learns the bounds it has to enforce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_plan: Option<String>,
    /// Ed25519 signature over the protocol domain, parent PID, channel mask,
    /// child name and admitted plan.
    pub signature: String,
}

/// What a parent learned from a handoff it accepted: who it now is, and the
/// plan that child was admitted under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedHandoff {
    /// The child the parent became.
    pub child_vm_name: String,
    /// The child's admitted plan, when the claim carried one.
    pub admitted_plan: Option<String>,
}

/// Where a parent publishes the handoff it accepted, for the supervisor that
/// owns it. Sent at most once: a parent becomes one child.
pub type HandoffAcceptedSender = std::sync::mpsc::Sender<AcceptedHandoff>;

/// Bounded owner-control requests; no payload bytes travel over this channel.
pub enum CaptureControl {
    Prepare(CapturePreparation),
    Finish(std::sync::mpsc::SyncSender<bool>),
}

pub type CaptureControlSender = std::sync::mpsc::SyncSender<CaptureControl>;

/// Sent only after transport authentication and child-path validation.
pub struct CapturePreparation {
    pub child: AcceptedHandoff,
    pub prepared: std::sync::mpsc::SyncSender<Result<Box<dyn std::io::Write + Send>, String>>,
    pub detached: std::sync::mpsc::Receiver<bool>,
    pub sealed: std::sync::mpsc::SyncSender<bool>,
}

/// End-to-end bound on the pre-ACK transfer, including owner retirement.
pub const CAPTURE_HANDOFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A one-shot pre-ACK hold, independent of the caller's pause signal.
///
/// Each CPU acknowledges from its pause hook, after leaving guest execution
/// and preparing devices. A requested pause alone is never evidence of this.
/// Failure deliberately leaves the hold engaged until the machine is stopped.
pub struct HandoffFence {
    state: std::sync::Mutex<FenceState>,
}

struct FenceState {
    used: bool,
    held: bool,
    parked: Vec<bool>,
    offline: Vec<bool>,
}

impl HandoffFence {
    pub fn new(vcpus: usize) -> Self {
        assert!(vcpus > 0);
        Self {
            state: std::sync::Mutex::new(FenceState {
                used: false,
                held: false,
                parked: vec![false; vcpus],
                offline: vec![false; vcpus],
            }),
        }
    }

    /// Start only after request authentication. This fence cannot be reused.
    pub fn begin(&self) -> std::io::Result<()> {
        let mut state = self.state.lock().expect("handoff fence poisoned");
        if state.used {
            return Err(std::io::Error::other("handoff fence already consumed"));
        }
        state.used = true;
        state.held = true;
        state.parked = state.offline.clone();
        Ok(())
    }

    /// A secondary that has never entered the guest is already quiescent.
    /// Its owning thread must call `leave_offline` before its first entry.
    pub fn enter_offline(&self, cpu: usize) {
        let mut state = self.state.lock().expect("handoff fence poisoned");
        state.offline[cpu] = true;
        if state.held {
            state.parked[cpu] = true;
        }
    }

    /// Atomically exclude first guest entry while a transfer holds this CPU.
    pub fn leave_offline(&self, cpu: usize) -> bool {
        let mut state = self.state.lock().expect("handoff fence poisoned");
        if state.held {
            return false;
        }
        state.offline[cpu] = false;
        true
    }

    pub fn held(&self) -> bool {
        self.state.lock().expect("handoff fence poisoned").held
    }

    /// Called only on the owning vCPU thread, inside its prepared pause hold.
    pub fn acknowledge(&self, cpu: usize) {
        let mut state = self.state.lock().expect("handoff fence poisoned");
        if state.held {
            state.parked[cpu] = true;
        }
    }

    pub fn all_parked(&self) -> bool {
        let state = self.state.lock().expect("handoff fence poisoned");
        state.held && state.parked.iter().all(|parked| *parked)
    }

    /// Release only after channel ownership, capture sealing and ACK succeeded.
    pub fn release_after_ack(&self) -> std::io::Result<()> {
        let mut state = self.state.lock().expect("handoff fence poisoned");
        if !state.held || !state.parked.iter().all(|parked| *parked) {
            return Err(std::io::Error::other("handoff CPUs not quiesced"));
        }
        state.held = false;
        Ok(())
    }
}

/// Domain separator for the host-authorized live handoff signature.
pub const HVF_HANDOFF_PROTOCOL_DOMAIN: &[u8] = b"mvm-hvf-live-handoff-v1";

/// The parent's reply to a handoff that took: exactly this line.
pub const HANDOFF_ACCEPTED: &[u8] = b"OK\n";

/// Dedicated telemetry authorization bit in a signed handoff channel mask.
pub const HANDOFF_TELEMETRY: u8 = 1 << 4;
/// Channel-mask bit for the guest-to-host view-only display relay.
pub const HANDOFF_DISPLAY: u8 = 1 << 5;
/// The GPU remoting channel survives a live handoff (HVF fork).
pub const HANDOFF_GPU: u8 = 1 << 6;

/// Longest reply line either side of the handoff socket will handle, newline
/// included. The parent writes within it and the host reads no further, so an
/// unterminated reply cannot hold a claim open.
pub const HANDOFF_RESPONSE_MAX_BYTES: usize = 512;

const REFUSAL_PREFIX: &str = "ERR ";
const RETRY_PREFIX: &str = "RETRY ";

/// The parent's reply to a handoff it refused: `ERR <reason>`, on one line.
///
/// The reason is the whole point. The parent is a paused process nobody can
/// attach to, and this line is the only account of what it refused — a bare
/// `ERR` left a failed claim reading `rejected live handoff: ERR` and nothing
/// more. Control characters are flattened so the reason cannot end the line
/// early, and it is cut on a character boundary to fit the bound.
pub fn refusal_line(reason: &str) -> Vec<u8> {
    reply_line(REFUSAL_PREFIX, reason)
}

/// The parent's reply when no complete request reached it: `RETRY <reason>`.
///
/// A refusal is final — the parent judged a request and stops. This says the
/// opposite: the parent judged nothing and changed nothing, so it is still
/// paused and claimable and the host may ask again.
pub fn retry_line(reason: &str) -> Vec<u8> {
    reply_line(RETRY_PREFIX, reason)
}

fn reply_line(prefix: &str, reason: &str) -> Vec<u8> {
    let budget = HANDOFF_RESPONSE_MAX_BYTES - prefix.len() - 1;
    let mut line = String::with_capacity(HANDOFF_RESPONSE_MAX_BYTES);
    line.push_str(prefix);
    for ch in reason.chars().map(|c| if c.is_control() { ' ' } else { c }) {
        if line.len() - prefix.len() + ch.len_utf8() > budget {
            break;
        }
        line.push(ch);
    }
    line.push('\n');
    line.into_bytes()
}

/// What the host makes of the parent's reply line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffReply {
    /// Exactly [`HANDOFF_ACCEPTED`]: the parent is now the child.
    Accepted,
    /// A complete [`retry_line`]: the parent is untouched and still claimable.
    Retry(String),
    /// Anything else, refusal or not, as the parent sent it.
    Refused(String),
}

impl HandoffReply {
    /// Classify one reply line read off the handoff socket.
    pub fn parse(line: &[u8]) -> Self {
        if line == HANDOFF_ACCEPTED {
            return Self::Accepted;
        }
        let text = String::from_utf8_lossy(line);
        match text
            .strip_suffix('\n')
            .and_then(|line| line.strip_prefix(RETRY_PREFIX))
        {
            Some(reason) => Self::Retry(reason.to_string()),
            None => Self::Refused(text.trim().to_string()),
        }
    }
}

impl HvfHandoffRequest {
    /// Build the canonical bytes signed by the host identity for one claim.
    ///
    /// The admitted plan is bound when present, so a request cannot carry a
    /// plan the host did not authorize for this child. A request without one
    /// signs exactly the bytes it did before plans were carried.
    pub fn signing_message(
        parent_pid: u32,
        child_vm_name: &str,
        channel_mask: u8,
        admitted_plan: Option<&str>,
    ) -> Vec<u8> {
        let name = child_vm_name.as_bytes();
        let name_len = u32::try_from(name.len()).expect("VM name fits protocol length");
        let plan = admitted_plan.map(str::as_bytes).unwrap_or_default();
        let mut message = Vec::with_capacity(
            HVF_HANDOFF_PROTOCOL_DOMAIN.len() + 4 + 4 + 1 + name.len() + 8 + plan.len(),
        );
        message.extend_from_slice(HVF_HANDOFF_PROTOCOL_DOMAIN);
        message.extend_from_slice(&parent_pid.to_be_bytes());
        message.push(channel_mask);
        message.extend_from_slice(&name_len.to_be_bytes());
        message.extend_from_slice(name);
        if admitted_plan.is_some() {
            message.extend_from_slice(&(plan.len() as u64).to_be_bytes());
            message.extend_from_slice(plan);
        }
        message
    }

    /// The bytes this request's signature has to cover.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        Self::signing_message(
            self.parent_pid,
            &self.child_vm_name,
            self.channel_mask,
            self.admitted_plan.as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_requires_fresh_acknowledgement_from_every_cpu() {
        let fence = HandoffFence::new(4);
        for cpu in 0..4 {
            fence.acknowledge(cpu);
        }
        fence.begin().unwrap();
        assert!(
            !fence.all_parked(),
            "pre-request acknowledgements are stale"
        );
        for cpu in 0..3 {
            fence.acknowledge(cpu);
            assert!(!fence.all_parked());
            assert!(fence.release_after_ack().is_err());
            assert!(fence.held(), "failure must not release guest execution");
        }
        fence.acknowledge(3);
        assert!(fence.all_parked());
        fence.release_after_ack().unwrap();
        assert!(!fence.held());
        assert!(
            fence.begin().is_err(),
            "a transferred standby is never reused"
        );
    }

    #[test]
    fn handoff_holds_an_offline_cpu_before_its_first_guest_entry() {
        let fence = HandoffFence::new(2);
        fence.enter_offline(1);
        fence.begin().unwrap();
        assert!(!fence.leave_offline(1));
        assert!(!fence.all_parked());
        fence.acknowledge(0);
        assert!(fence.all_parked());
        fence.release_after_ack().unwrap();
        assert!(fence.leave_offline(1));
    }

    #[test]
    fn the_signature_binds_the_admitted_plan_and_a_planless_request_is_unchanged() {
        let planless = HvfHandoffRequest::signing_message(42, "child", 0b0011, None);
        let with_plan = HvfHandoffRequest::signing_message(42, "child", 0b0011, Some("{}"));
        let other_plan = HvfHandoffRequest::signing_message(42, "child", 0b0011, Some("{ }"));
        let empty_plan = HvfHandoffRequest::signing_message(42, "child", 0b0011, Some(""));
        assert_ne!(planless, with_plan);
        assert_ne!(with_plan, other_plan);
        assert_ne!(planless, empty_plan, "an empty plan is still a plan");
        assert!(
            planless.ends_with(b"child"),
            "a request without a plan signs what it always did"
        );
    }

    #[test]
    fn a_planless_request_keeps_its_wire_shape() {
        let request = HvfHandoffRequest {
            child_vm_name: "child".into(),
            parent_pid: 42,
            channel_mask: 0,
            admitted_plan: None,
            signature: "00".into(),
        };
        let wire = serde_json::to_string(&request).unwrap();
        assert!(!wire.contains("admitted_plan"), "{wire}");
        assert_eq!(
            serde_json::from_str::<HvfHandoffRequest>(&wire).unwrap(),
            request
        );
        assert_eq!(
            request.message(),
            HvfHandoffRequest::signing_message(42, "child", 0, None)
        );
    }

    #[test]
    fn a_refusal_carries_its_reason_on_one_line() {
        assert_eq!(
            refusal_line("handoff signature rejected"),
            b"ERR handoff signature rejected\n"
        );
    }

    #[test]
    fn a_reason_containing_a_newline_cannot_end_the_line_early() {
        let line = refusal_line("first\nsecond\r");
        assert_eq!(line, b"ERR first second \n");
        assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn a_long_reason_is_cut_to_the_bound_on_a_character_boundary() {
        let line = refusal_line(&"é".repeat(HANDOFF_RESPONSE_MAX_BYTES));
        assert!(line.len() <= HANDOFF_RESPONSE_MAX_BYTES);
        assert_eq!(line.last(), Some(&b'\n'));
        assert!(std::str::from_utf8(&line).is_ok(), "cut mid-character");
    }

    #[test]
    fn a_refusal_is_never_mistaken_for_acceptance() {
        assert_ne!(refusal_line(""), HANDOFF_ACCEPTED);
        assert_ne!(refusal_line("OK"), HANDOFF_ACCEPTED);
    }

    #[test]
    fn each_reply_line_parses_back_to_what_the_parent_meant() {
        assert_eq!(
            HandoffReply::parse(HANDOFF_ACCEPTED),
            HandoffReply::Accepted
        );
        assert_eq!(
            HandoffReply::parse(&retry_line("no request arrived")),
            HandoffReply::Retry("no request arrived".to_string())
        );
        assert_eq!(
            HandoffReply::parse(&refusal_line("handoff signature rejected")),
            HandoffReply::Refused("ERR handoff signature rejected".to_string())
        );
    }

    #[test]
    fn a_retry_reason_is_flattened_and_bounded_like_a_refusal() {
        let line = retry_line(&format!("a\nb{}", "é".repeat(HANDOFF_RESPONSE_MAX_BYTES)));
        assert!(line.starts_with(b"RETRY a b"));
        assert!(line.len() <= HANDOFF_RESPONSE_MAX_BYTES);
        assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn only_a_complete_retry_line_permits_another_attempt() {
        // A reply cut off before its newline, an acceptance missing its
        // newline, and a refusal whose reason mentions retrying are not
        // invitations to ask again.
        for line in [
            &b"RETRY no request arrived"[..],
            b"OK",
            b"",
            b"ERR RETRY \n",
            b"RETRY\n",
        ] {
            assert!(
                matches!(HandoffReply::parse(line), HandoffReply::Refused(_)),
                "{:?} must not parse as accepted or retryable",
                String::from_utf8_lossy(line)
            );
        }
    }
}

//! Chain-signed records for host-to-guest display input.
//!
//! Payload-free by construction: an input event is recorded as its kind and a
//! count, never the key, the text, or the coordinates. A human typing a
//! password through an attended display is the case this plane exists for, so
//! the chain must be unable to hold one.

use std::collections::BTreeMap;

use super::AuditEmitter;
use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

/// A writer was admitted to a workload's display input.
pub const GRANTED_EVENT: &str = "display.granted";
/// A display input writer or frame was turned away.
pub const REFUSED_EVENT: &str = "display.refused";
/// A batch of display input events was admitted for delivery to the guest.
pub const INPUT_EVENT: &str = "display.input_event";
/// A human began typing a credential; recording pauses from here.
pub const CREDENTIAL_ENTRY_BEGIN_EVENT: &str = "display.credential_entry_begin";
/// The credential entry ended; recording resumes.
pub const CREDENTIAL_ENTRY_END_EVENT: &str = "display.credential_entry_end";
/// Label: the VM whose display was driven.
pub const LABEL_VM_NAME: &str = "vm_name";
/// Label: the display input lease holder.
pub const LABEL_HOLDER: &str = "display_input_holder";
/// Label: why the gate refused, as a wire-stable reason word.
pub const LABEL_REASON: &str = "display_input_reason";
/// Label: the writer's frame sequence number.
pub const LABEL_SEQ: &str = "display_input_seq";
/// Label: total events in the delivered batch.
pub const LABEL_EVENT_COUNT: &str = "display_input_events";
/// Label: per-kind counts, `kind=count` joined by commas in kind order.
pub const LABEL_EVENT_KINDS: &str = "display_input_kinds";
/// Label: whether the run was admitted as attended.
pub const LABEL_ATTENDED: &str = "display_input_attended";

impl AuditEmitter {
    /// Emit `display.granted`: a writer took a VM's display input lease.
    pub fn emit_display_granted(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        holder: &str,
        attended: bool,
    ) -> Result<()> {
        self.emit(
            plan,
            GRANTED_EVENT,
            [
                (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (LABEL_HOLDER.to_string(), holder.to_string()),
                (LABEL_ATTENDED.to_string(), attended.to_string()),
            ],
        )
    }

    /// Emit `display.refused`: the binding and the reason word, nothing about
    /// the events that were refused.
    pub fn emit_display_refused(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        reason: &str,
    ) -> Result<()> {
        self.emit(
            plan,
            REFUSED_EVENT,
            [
                (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (LABEL_REASON.to_string(), reason.to_string()),
            ],
        )
    }

    /// Emit `display.input_event` for one admitted batch: how many events of
    /// each kind, never what they carried.
    pub fn emit_display_input_events(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        holder: &str,
        seq: u64,
        kinds: &BTreeMap<&'static str, u32>,
    ) -> Result<()> {
        let total: u64 = kinds.values().map(|count| u64::from(*count)).sum();
        let rendered = kinds
            .iter()
            .map(|(kind, count)| format!("{kind}={count}"))
            .collect::<Vec<_>>()
            .join(",");
        self.emit(
            plan,
            INPUT_EVENT,
            [
                (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (LABEL_HOLDER.to_string(), holder.to_string()),
                (LABEL_SEQ.to_string(), seq.to_string()),
                (LABEL_EVENT_COUNT.to_string(), total.to_string()),
                (LABEL_EVENT_KINDS.to_string(), rendered),
            ],
        )
    }

    /// Emit the start or end of a credential entry window.
    pub fn emit_display_credential_entry(
        &self,
        plan: &ExecutionPlan,
        vm_name: &str,
        holder: &str,
        began: bool,
    ) -> Result<()> {
        let event = if began {
            CREDENTIAL_ENTRY_BEGIN_EVENT
        } else {
            CREDENTIAL_ENTRY_END_EVENT
        };
        self.emit(
            plan,
            event,
            [
                (LABEL_VM_NAME.to_string(), vm_name.to_string()),
                (LABEL_HOLDER.to_string(), holder.to_string()),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::stream::{DisplayInputEvent, DisplayInputFrame};
    use mvm_core::plan::test_support::PlanFixture;

    #[test]
    fn an_input_event_entry_carries_kinds_and_counts_and_nothing_typed() {
        let dir = tempfile::tempdir().unwrap();
        let emitter =
            AuditEmitter::with_dir(ed25519_dalek::SigningKey::from_bytes(&[3; 32]), dir.path())
                .unwrap();
        let frame = DisplayInputFrame {
            seq: 7,
            events: vec![
                DisplayInputEvent::Text {
                    text: "hunter2".into(),
                },
                DisplayInputEvent::Key {
                    key: "Enter".into(),
                    pressed: true,
                },
                DisplayInputEvent::Key {
                    key: "Enter".into(),
                    pressed: false,
                },
            ],
        };
        emitter
            .emit_display_input_events(
                &PlanFixture::new().build(),
                "attended-vm",
                "holder#1",
                frame.seq,
                &frame.kind_counts(),
            )
            .unwrap();

        let mut chain = String::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "jsonl") {
                chain.push_str(&std::fs::read_to_string(path).unwrap());
            }
        }
        assert!(chain.contains(INPUT_EVENT), "{chain}");
        assert!(chain.contains("key=2,text=1"), "{chain}");
        assert!(
            !chain.contains("hunter2") && !chain.contains("Enter"),
            "{chain}"
        );
    }
}

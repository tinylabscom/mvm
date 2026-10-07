//! Wire-stable event names and label keys for the workload output-stream audit.
//!
//! Shared by the emitter and readers so the strings cannot drift. One entry is
//! signed per attach, never per record: output bytes stay in the transcript.

/// Emitted when a follower attaches to a VM's output stream.
pub const SUBSCRIBED_EVENT: &str = "stream.subscribed";
/// Label: the VM whose stream was attached to.
pub const LABEL_VM_NAME: &str = "vm_name";
/// Label: the broker-assigned reader id, unique within one broker.
pub const LABEL_READER_ID: &str = "stream_reader_id";
/// Label: the stream sequence number the reader starts at. Records
/// before it were produced before the attach and are not delivered.
pub const LABEL_FROM_SEQ: &str = "stream_from_seq";
/// Label on `plan.admitted`: the retention mode the plan was admitted
/// under, so a later reader can tell a run that kept no transcript from a
/// run whose transcript went missing.
pub const LABEL_RETENTION: &str = "stream_retention";

/// Emitted when a writer is admitted to a workload's stdin.
///
/// Output capture needs no authorization and so audits only the attach;
/// input is the direction that changes what the workload does, so the
/// admission itself is the fact worth signing. Without it the chain would
/// record every writer that was turned away and nothing about the one that
/// got in.
pub const INPUT_GRANTED_EVENT: &str = "stream.input_granted";
/// Emitted whenever the input gate turns a writer away.
pub const INPUT_REFUSED_EVENT: &str = "stream.input_refused";
/// Label: which writer holds — or was refused because somebody else holds
/// — the single-writer input lease.
pub const LABEL_HOLDER: &str = "stream_input_holder";
/// Label: why the gate refused, as a wire-stable reason word.
pub const LABEL_REASON: &str = "stream_input_reason";
/// Label: which category of known secret was recognised in the refused
/// bytes. The category name, never the matched value — a refusal that
/// quoted the secret to explain itself would ship exactly what it stopped.
pub const LABEL_SECRET_CATEGORY: &str = "stream_input_secret_category";
/// Label: the `seq` an out-of-order frame carried. A position, not a
/// payload — it says which frame the writer sent out of turn and nothing
/// about what was in it.
pub const LABEL_SEQ: &str = "stream_input_seq";
/// Label: the highest `seq` the session had already accepted when the
/// out-of-order frame arrived.
pub const LABEL_AFTER_SEQ: &str = "stream_input_after_seq";

//! Chain-signed audit for the L3 tunnel gateway.
//!
//! The gateway is where default-deny is enforced for `l3-vsock`, and a
//! refusal nobody recorded is a decision nobody can afterwards prove was
//! made. This module puts the gateway's decisions on the same tamper-evident
//! chain plan admission and the broker already write to — one audit path,
//! reached through the same [`Recorder`] every other plan-less per-machine
//! process uses.
//!
//! ## Decisions, never traffic
//!
//! [`GatewayEvent`] is produced per *packet*. An entry per packet would hand
//! a guest a write amplifier into the host's audit log at line rate, which is
//! a denial of service it controls. So what lands on the chain is the
//! decision *class* and the first destination that provoked it; repeats fold
//! into that entry and are counted. Volume lives in the gateway's counters,
//! where it costs nothing.
//!
//! Two dedup tables, because the two key spaces have different owners:
//!
//! - **Classes.** Keys built only from host-defined enumerations — a deny
//!   reason, a direction. Finite and small, so it cannot be crowded out.
//! - **Destinations.** Keys carrying guest-chosen values. Capped at
//!   [`DESTINATION_BUCKETS`]; a fact that cannot get a bucket there falls
//!   back to its class key rather than going unrecorded. **Granularity
//!   degrades under pressure; the record does not disappear.**
//!
//! Those two caps are the whole rate bound: a bucket emits at most once per
//! window, so what a guest can cause to be written is
//! [`MAX_ENTRIES_PER_WINDOW`] and nothing else is needed to hold it there. A
//! separate emission budget was considered and dropped — set above the caps
//! it can never bind, set below them it fires first and the degrade-to-class
//! path becomes unreachable, so it is a knob that either does nothing or
//! silently loses refusals.
//!
//! What the tables *do* fold is counted, and the count is written to the
//! chain when the tunnel tears down, so the log states how much of itself is
//! a summary rather than lying by omission.
//!
//! ## Never recorded
//!
//! Packet payloads, DNS answer data, and anything a guest sends as content.
//! DNS names are the one guest-chosen string that lands here, as the
//! normalized metadata the policy decision was actually made against, and
//! every guest-derived label is clamped to [`MAX_LABEL_BYTES`].

use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::supervisor::audit_recorder::{EventCategory, Recorder};
use crate::supervisor::{Decision, DedupKey, RetryStormSuppressor};
use mvm_core::plan::PlanId;

use super::gateway::{Direction, GatewayEvent};

/// How long repeats of one decision fold into its first entry.
///
/// Long enough that an ordinary retry burst is one line, short enough that a
/// condition still happening minutes later shows up again rather than once at
/// the start. It is also half of the rate bound: widen it and
/// [`MAX_ENTRIES_PER_WINDOW`] buys more time.
pub const DEDUP_WINDOW: Duration = Duration::from_secs(30);

/// Buckets the guest-keyed dedup table will open.
///
/// A ceiling on memory a guest drives by picking destinations, not a figure
/// about demand. Past it a fact degrades to its class key, which lives in the
/// host-keyed table and is always available.
pub const DESTINATION_BUCKETS: usize = 256;

/// Buckets the host-keyed dedup table will open.
///
/// Sits at roughly twice the key space it can actually hold — 66 keys, the
/// two deny-reason enumerations dominating — so it never binds. That is the
/// point: the table a refusal falls back to must not be one a guest can fill.
/// `the_class_key_space_fits_the_table_that_must_never_be_full` counts the
/// real key set, so a new event class has to confront this number.
pub const CLASS_BUCKETS: usize = 128;

/// Entries a guest can cause to be written in one [`DEDUP_WINDOW`].
///
/// Derived, not chosen, which is why there is no budget beside it. A bucket
/// emits at most once per window, so the live tables bound the rate — and the
/// factor of two is the one subtlety: buckets already open when a window
/// begins can age out inside it, freeing their slots for that many new keys.
///
/// At the caps above this is 768 entries per 30 seconds, roughly 26 a second,
/// and only a guest that never repeats a destination reaches it. That is a
/// real cost stated plainly rather than a bound that pretends otherwise;
/// lowering it means widening the window or shrinking the tables, and both
/// are visible here.
pub const MAX_ENTRIES_PER_WINDOW: usize = 2 * (DESTINATION_BUCKETS + CLASS_BUCKETS);

/// Longest guest-derived label value that reaches the chain.
///
/// Bounds both the entry and the dedup key built from it. A DNS name past
/// this is pathological; truncating one costs an operator nothing and keeps a
/// guest from using a label as a channel.
pub const MAX_LABEL_BYTES: usize = 128;

/// Bytes one dedup bucket is charged.
///
/// The key's three strings — a plan digest, an event name, and a bucket
/// clamped to [`MAX_LABEL_BYTES`] — with their allocations, plus the state
/// beside them and the map's own slot. Rounded up rather than measured: this
/// is a ceiling, and a figure that has to be re-measured whenever a string
/// grows is not one.
pub const BUCKET_BYTES: usize = 512;

/// Worst-case bytes both dedup tables hold at their caps.
pub const DEDUP_TABLE_BYTES: usize = (DESTINATION_BUCKETS + CLASS_BUCKETS) * BUCKET_BYTES;

/// Host-owned identity every entry the gateway writes is bound to.
///
/// All of it is assigned by the launch path from the signed plan. Nothing
/// here is guest-supplied, which is what makes an entry attributable.
#[derive(Debug, Clone)]
pub struct NetdAuditContext {
    pub tenant: String,
    pub machine_id: String,
    pub plan_digest: String,
    pub session: String,
    pub policy_epoch: u64,
}

/// What the auditor could not put on the chain, and why.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditDrops {
    /// Decisions folded into an earlier entry for the same bucket.
    pub deduplicated: u64,
    /// Entries the signer refused to write.
    pub emit_failed: u64,
}

/// The gateway's chain-signed audit surface.
pub struct NetdAuditor {
    recorder: Option<Recorder>,
    runtime: Option<tokio::runtime::Runtime>,
    context: NetdAuditContext,
    classes: RetryStormSuppressor,
    destinations: RetryStormSuppressor,
    drops: AuditDrops,
    /// Set once the first emit failure has been reported, so a wedged signer
    /// cannot turn one fault into a line per decision on stderr.
    reported_emit_failure: bool,
}

impl NetdAuditor {
    /// Attach to the host's chain if the signer key is where it belongs.
    ///
    /// Absent key ⇒ the gateway serves un-audited rather than refusing to
    /// serve, matching the substitution endpoint's posture at the same seam.
    pub fn open(context: NetdAuditContext) -> Self {
        let recorder =
            crate::supervisor::substitution_endpoint::build_audit_recorder(&context.tenant.clone());
        Self::with_recorder(recorder, context)
    }

    /// Explicit recorder. The test seam, and the constructor [`Self::open`]
    /// funnels into.
    pub fn with_recorder(recorder: Option<Recorder>, context: NetdAuditContext) -> Self {
        // One runtime for the process rather than one per emit: the gateway
        // emits from its drive loop, where per-entry runtime construction
        // would be paid on the datapath's own thread.
        let runtime = recorder.as_ref().and_then(|_| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    eprintln!(
                        "mvm-netd: no runtime for audit emission, serving un-audited: {error}"
                    )
                })
                .ok()
        });
        Self {
            recorder: runtime.is_some().then_some(recorder).flatten(),
            runtime,
            context,
            classes: RetryStormSuppressor::new(DEDUP_WINDOW),
            destinations: RetryStormSuppressor::new(DEDUP_WINDOW),
            drops: AuditDrops::default(),
            reported_emit_failure: false,
        }
    }

    /// Whether anything this auditor is told will reach the chain.
    pub fn is_recording(&self) -> bool {
        self.recorder.is_some()
    }

    /// What has not reached the chain so far.
    pub fn drops(&self) -> AuditDrops {
        self.drops
    }

    /// Buckets currently held across both dedup tables.
    pub fn tracked_buckets(&self) -> usize {
        self.classes.len() + self.destinations.len()
    }

    /// Record one gateway decision.
    ///
    /// Cheap when the decision is a repeat and free when no recorder
    /// attached, so the drive loop can call it on every event.
    pub fn observe(&mut self, event: &GatewayEvent) {
        if self.recorder.is_none() {
            return;
        }
        let Some(fact) = fact_for(event) else {
            return;
        };
        let now = Utc::now();
        let Some(granularity) = self.admit(&fact, now) else {
            return;
        };
        let mut labels = self.base_labels();
        labels.push(("bucket_granularity".to_string(), granularity.to_string()));
        labels.extend(fact.labels);
        self.emit(fact.event, labels);
    }

    /// Close the audit surface: reap what the dedup tables were still
    /// holding and record, on the chain itself, what never reached it.
    ///
    /// The teardown entry is the one place the log states its own
    /// completeness. Without it a reader cannot distinguish "the guest made
    /// four decisions" from "the guest made forty thousand and the dedup
    /// tables folded the rest into four".
    pub fn finish(&mut self) {
        if self.recorder.is_none() {
            return;
        }
        let now = Utc::now();
        self.reap(now);
        let drops = self.drops;
        let mut labels = self.base_labels();
        labels.extend([
            ("deduplicated".to_string(), drops.deduplicated.to_string()),
            ("emit_failed".to_string(), drops.emit_failed.to_string()),
        ]);
        self.emit(TUNNEL_DISCONNECTED, labels);
    }

    /// Which table took the fact's bucket, or `None` when this decision folds
    /// into an entry already on the chain.
    fn admit(&mut self, fact: &AuditFact, now: DateTime<Utc>) -> Option<&'static str> {
        let class_key = self.key(fact.event, &fact.class);
        let Some(guest) = &fact.guest else {
            return self.fold(Table::Class, class_key, now).then_some("class");
        };
        let guest_key = self.key(fact.event, guest);
        if self.destinations.contains(&guest_key) {
            return self
                .fold(Table::Destination, guest_key, now)
                .then_some("destination");
        }
        if self.destinations.len() >= DESTINATION_BUCKETS {
            // Reap first — a table full of buckets whose windows have all
            // passed is not under pressure, it is unswept.
            self.reap(now);
        }
        if self.destinations.len() < DESTINATION_BUCKETS {
            return self
                .fold(Table::Destination, guest_key, now)
                .then_some("destination");
        }
        // Full of live buckets. The class key is in the table a guest cannot
        // fill, so the decision is still recorded — with the destination in
        // its labels and a coarser bucket behind it.
        self.fold(Table::Class, class_key, now).then_some("class")
    }

    /// Whether this observation opens an entry, or folds into an open one.
    fn fold(&mut self, table: Table, key: DedupKey, now: DateTime<Utc>) -> bool {
        let suppressor = match table {
            Table::Class => &mut self.classes,
            Table::Destination => &mut self.destinations,
        };
        match suppressor.observe(key, now) {
            Decision::Emit => true,
            Decision::Suppress => {
                self.drops.deduplicated += 1;
                false
            }
        }
    }

    /// Drain both tables of buckets whose windows have passed. The fold count
    /// is kept by `fold` as it happens, so the summaries are not needed here.
    fn reap(&mut self, now: DateTime<Utc>) {
        drop(self.classes.flush(now));
        drop(self.destinations.flush(now));
        // The class table is bounded by its key space rather than by a cap,
        // but a bound nothing enforces is a bound that moves when a variant
        // is added. Refuse to grow past the stated one.
        debug_assert!(self.classes.len() <= CLASS_BUCKETS);
    }

    fn key(&self, event: &str, bucket: &str) -> DedupKey {
        DedupKey {
            plan_id: PlanId(self.context.plan_digest.clone()),
            event: event.to_string(),
            bucket: clamp(bucket),
        }
    }

    /// The binding every entry carries: which machine, which boot, under
    /// which plan and policy, speaking which version of the wire protocol.
    fn base_labels(&self) -> Vec<(String, String)> {
        vec![
            ("machine_id".to_string(), self.context.machine_id.clone()),
            ("session".to_string(), self.context.session.clone()),
            ("plan_digest".to_string(), self.context.plan_digest.clone()),
            (
                "policy_epoch".to_string(),
                self.context.policy_epoch.to_string(),
            ),
            (
                "protocol_version".to_string(),
                mvm_contract::l3::limits::PROTOCOL_VERSION.to_string(),
            ),
        ]
    }

    /// Write one entry.
    ///
    /// **Fail-open, counted.** A signer that cannot write must not be able to
    /// stop the datapath: this process is the only way a workload reaches the
    /// network, so failing closed here would turn a full disk into a
    /// network outage for every machine on the host, and the decision the
    /// entry describes has already been enforced whether or not it was
    /// recorded. What the failure must not do is vanish — it is counted, and
    /// the count goes on the chain at teardown.
    fn emit(&mut self, event: &'static str, labels: Vec<(String, String)>) {
        let (Some(recorder), Some(runtime)) = (&self.recorder, &self.runtime) else {
            return;
        };
        let result = runtime.block_on(recorder.record_unbound(EventCategory::L3, event, labels));
        if let Err(error) = result {
            self.drops.emit_failed += 1;
            if !self.reported_emit_failure {
                self.reported_emit_failure = true;
                eprintln!("mvm-netd: audit emission failed, serving on regardless: {error}");
            }
        }
    }
}

/// Which dedup table a fact's bucket belongs in.
#[derive(Clone, Copy)]
enum Table {
    Class,
    Destination,
}

pub const TUNNEL_READY: &str = "l3.tunnel_ready";
pub const TUNNEL_DISCONNECTED: &str = "l3.tunnel_disconnected";
pub const FLOW_ADMITTED: &str = "l3.flow_admitted";
pub const FLOW_DENIED: &str = "l3.flow_denied";
pub const INGRESS_DELIVERED: &str = "l3.ingress_delivered";
pub const INGRESS_DENIED: &str = "l3.ingress_denied";
pub const DNS_ADMITTED: &str = "l3.dns_admitted";
pub const DNS_DENIED: &str = "l3.dns_denied";
pub const MALFORMED_FRAME: &str = "l3.malformed_frame";
pub const STALE_SESSION: &str = "l3.stale_session";
pub const QUEUE_OVERFLOW: &str = "l3.queue_overflow";
pub const RATE_LIMITED: &str = "l3.rate_limited";

/// One decision, ready to be deduplicated and written.
struct AuditFact {
    event: &'static str,
    /// Bucket built only from host-defined enumerations.
    class: String,
    /// Bucket carrying guest-chosen values, when the decision has one worth
    /// distinguishing. `None` means the class *is* the decision.
    guest: Option<String>,
    labels: Vec<(String, String)>,
}

/// What, if anything, this event says that belongs on the chain.
///
/// `InboundDelivered` is the one traffic-shaped event here, and it is kept
/// because admitting a remote's first packet back to a guest is a decision
/// the return-flow rules made. Bucketed on the source, it is one entry per
/// remote per window, not one per packet.
fn fact_for(event: &GatewayEvent) -> Option<AuditFact> {
    let fact = match event {
        GatewayEvent::TunnelReady { session } => AuditFact {
            event: TUNNEL_READY,
            class: "ready".to_string(),
            guest: None,
            labels: vec![("tunnel_session".to_string(), session.to_string())],
        },
        // Teardown is recorded by `finish`, which knows what the tables were
        // still holding. Recording it here too would double the entry.
        GatewayEvent::CleanedUp { .. } => return None,
        GatewayEvent::FlowAdmitted {
            src,
            dst,
            dst_port,
            protocol,
        } => AuditFact {
            event: FLOW_ADMITTED,
            // Not the protocol byte: that comes off the guest's IP header,
            // and a class key must come from a set the host defines or the
            // table a refusal falls back to is one a guest can fill.
            class: "admitted".to_string(),
            guest: Some(format!("{protocol}|{dst}|{dst_port}")),
            labels: vec![
                ("src".to_string(), src.to_string()),
                ("dst".to_string(), dst.to_string()),
                ("dst_port".to_string(), dst_port.to_string()),
                ("protocol".to_string(), protocol.to_string()),
                (
                    "direction".to_string(),
                    Direction::Egress.as_str().to_string(),
                ),
                ("verdict".to_string(), "admitted".to_string()),
            ],
        },
        GatewayEvent::FlowDenied {
            reason,
            dst,
            dst_port,
        } => {
            let dst = dst
                .map(|d| d.to_string())
                .unwrap_or_else(|| UNPARSED.to_string());
            let port = dst_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| UNPARSED.to_string());
            AuditFact {
                event: FLOW_DENIED,
                class: reason.as_str().to_string(),
                guest: Some(format!("{}|{dst}|{port}", reason.as_str())),
                labels: vec![
                    ("reason".to_string(), reason.as_str().to_string()),
                    ("dst".to_string(), dst),
                    ("dst_port".to_string(), port),
                    (
                        "direction".to_string(),
                        Direction::Egress.as_str().to_string(),
                    ),
                    ("verdict".to_string(), "denied".to_string()),
                ],
            }
        }
        GatewayEvent::InboundDelivered { src, .. } => AuditFact {
            event: INGRESS_DELIVERED,
            class: "delivered".to_string(),
            guest: Some(src.to_string()),
            labels: vec![
                ("src".to_string(), src.to_string()),
                (
                    "direction".to_string(),
                    Direction::Ingress.as_str().to_string(),
                ),
                ("verdict".to_string(), "delivered".to_string()),
            ],
        },
        GatewayEvent::InboundDenied { reason } => AuditFact {
            event: INGRESS_DENIED,
            class: reason.as_str().to_string(),
            guest: None,
            labels: vec![
                ("reason".to_string(), reason.as_str().to_string()),
                (
                    "direction".to_string(),
                    Direction::Ingress.as_str().to_string(),
                ),
                ("verdict".to_string(), "denied".to_string()),
            ],
        },
        GatewayEvent::DnsAdmitted { name, answers } => AuditFact {
            event: DNS_ADMITTED,
            class: "admitted".to_string(),
            guest: Some(name.clone()),
            labels: vec![
                ("name".to_string(), clamp(name)),
                // The count, never the addresses: how many answers a
                // question got is metadata, what they were is the reply.
                ("answers".to_string(), answers.to_string()),
                ("verdict".to_string(), "admitted".to_string()),
            ],
        },
        GatewayEvent::DnsDenied { name, reason } => AuditFact {
            event: DNS_DENIED,
            class: (*reason).to_string(),
            guest: Some(format!("{reason}|{name}")),
            labels: vec![
                ("name".to_string(), clamp(name)),
                ("reason".to_string(), (*reason).to_string()),
                ("verdict".to_string(), "denied".to_string()),
            ],
        },
        GatewayEvent::MalformedFrame { detail } => AuditFact {
            event: MALFORMED_FRAME,
            class: "malformed".to_string(),
            guest: None,
            // The decoder's own message: lengths, versions, and a message
            // type. It carries no bytes off the wire, and it is clamped
            // regardless.
            labels: vec![("detail".to_string(), clamp(detail))],
        },
        GatewayEvent::StaleSession => AuditFact {
            event: STALE_SESSION,
            class: "stale_session".to_string(),
            guest: None,
            labels: Vec::new(),
        },
        GatewayEvent::QueueOverflow { direction } => AuditFact {
            event: QUEUE_OVERFLOW,
            class: direction.as_str().to_string(),
            guest: None,
            labels: vec![("direction".to_string(), direction.as_str().to_string())],
        },
        GatewayEvent::RateLimited => AuditFact {
            event: RATE_LIMITED,
            class: "dns".to_string(),
            guest: None,
            labels: vec![("limit".to_string(), "dns_qps".to_string())],
        },
    };
    Some(fact)
}

/// Stand-in for an address or port the packet was too malformed to carry.
const UNPARSED: &str = "unparsed";

/// Clamp a guest-derived string to [`MAX_LABEL_BYTES`], on a character
/// boundary.
fn clamp(value: &str) -> String {
    if value.len() <= MAX_LABEL_BYTES {
        return value.to_string();
    }
    let mut end = MAX_LABEL_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::Path;

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use mvm_core::plan::TenantId;
    use mvm_net::l3::{DenyCode, SessionId};

    use super::*;
    use crate::supervisor::audit::AuditEntry;
    use crate::supervisor::{FileAuditSigner, verify_audit_chain_entries};

    const TENANT: &str = "local";

    fn context() -> NetdAuditContext {
        NetdAuditContext {
            tenant: TENANT.to_string(),
            machine_id: "machine-a".to_string(),
            plan_digest: "sha256:plan-a".to_string(),
            session: SessionId(0x1234_5678_9abc_def0).to_string(),
            policy_epoch: 7,
        }
    }

    /// An auditor writing into a chain rooted at `dir`, plus the key the
    /// chain must verify under.
    fn auditor_in(dir: &Path) -> (NetdAuditor, VerifyingKey) {
        let key = {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
            SigningKey::from_bytes(&seed)
        };
        let verifying = key.verifying_key();
        let signer = FileAuditSigner::open(key, dir).expect("open the chain");
        let recorder = Recorder::new(std::sync::Arc::new(signer), TenantId(TENANT.to_string()));
        (
            NetdAuditor::with_recorder(Some(recorder), context()),
            verifying,
        )
    }

    /// Every entry on the tenant's chain, verified rather than parsed: an
    /// assertion over an unverified log would pass on a log a tamper had
    /// already broken.
    fn chain(dir: &Path, key: &VerifyingKey) -> Vec<AuditEntry> {
        let path = dir.join(format!("{TENANT}.jsonl"));
        if !path.exists() {
            return Vec::new();
        }
        verify_audit_chain_entries(&path, key).expect("the chain must verify")
    }

    fn events(entries: &[AuditEntry], event: &str) -> Vec<AuditEntry> {
        entries
            .iter()
            .filter(|e| e.event == event)
            .cloned()
            .collect()
    }

    fn denied(dst: &str, port: u16) -> GatewayEvent {
        GatewayEvent::FlowDenied {
            reason: DenyCode::DestinationNotAdmitted,
            dst: Some(dst.parse::<IpAddr>().unwrap()),
            dst_port: Some(port),
        }
    }

    fn admitted(dst: &str, port: u16) -> GatewayEvent {
        GatewayEvent::FlowAdmitted {
            src: "10.201.0.6".parse().unwrap(),
            dst: dst.parse::<IpAddr>().unwrap(),
            dst_port: port,
            protocol: 6,
        }
    }

    /// **The witness this module exists for.** A refusal that leaves no
    /// entry is a decision nobody can afterwards prove was made, which is
    /// exactly what default-deny at this seam is worth nothing without.
    #[test]
    fn a_denied_flow_lands_on_the_chain_with_its_reason_and_destination() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        auditor.observe(&denied("93.184.216.34", 443));

        let entries = chain(dir.path(), &key);
        let denials = events(&entries, FLOW_DENIED);
        assert_eq!(denials.len(), 1, "a refusal must produce exactly one entry");
        let labels = &denials[0].labels;
        assert_eq!(
            labels.get("reason").map(String::as_str),
            Some("destination_not_admitted"),
            "an entry that does not say why cannot answer the question a reader has"
        );
        assert_eq!(labels.get("dst").map(String::as_str), Some("93.184.216.34"));
        assert_eq!(labels.get("dst_port").map(String::as_str), Some("443"));
        assert_eq!(labels.get("verdict").map(String::as_str), Some("denied"));
        assert_eq!(
            labels.get("machine_id").map(String::as_str),
            Some("machine-a")
        );
        assert_eq!(
            labels.get("plan_digest").map(String::as_str),
            Some("sha256:plan-a")
        );
        assert_eq!(labels.get("policy_epoch").map(String::as_str), Some("7"));
    }

    /// A refusal that names a different destination is a different decision.
    #[test]
    fn a_refusal_to_a_new_destination_is_its_own_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        auditor.observe(&denied("93.184.216.34", 443));
        auditor.observe(&denied("198.51.100.7", 443));

        assert_eq!(events(&chain(dir.path(), &key), FLOW_DENIED).len(), 2);
    }

    /// An entry per packet would hand the guest a write amplifier into the
    /// host's audit log, at whatever rate it can send.
    #[test]
    fn a_retried_refusal_does_not_write_a_line_per_packet() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        for _ in 0..2_000 {
            auditor.observe(&denied("93.184.216.34", 443));
        }

        assert_eq!(
            events(&chain(dir.path(), &key), FLOW_DENIED).len(),
            1,
            "two thousand identical refusals are one decision"
        );
        assert_eq!(auditor.drops().deduplicated, 1_999);
    }

    /// The first packet of a flow is a decision; the rest of it is traffic.
    #[test]
    fn an_admitted_flow_is_recorded_once_and_not_per_packet() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        for _ in 0..500 {
            auditor.observe(&admitted("93.184.216.34", 443));
        }

        let admissions = events(&chain(dir.path(), &key), FLOW_ADMITTED);
        assert_eq!(admissions.len(), 1);
        assert_eq!(
            admissions[0].labels.get("dst").map(String::as_str),
            Some("93.184.216.34")
        );
    }

    /// The destination table is a ceiling on memory a guest drives. It must
    /// hold, and holding it must not cost a refusal its entry — under
    /// pressure the bucket coarsens and the record survives.
    #[test]
    fn a_refusal_survives_a_destination_table_a_guest_has_filled() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        // Fill the guest-keyed table with admitted destinations, well past
        // its cap.
        for i in 0..(DESTINATION_BUCKETS as u32 * 3) {
            let octets = std::net::Ipv4Addr::from(0x0b00_0000 + i);
            auditor.observe(&admitted(&octets.to_string(), 443));
        }
        assert!(
            auditor.tracked_buckets() <= DESTINATION_BUCKETS + CLASS_BUCKETS,
            "the dedup tables grew past their caps: {} buckets",
            auditor.tracked_buckets()
        );

        auditor.observe(&denied("203.0.113.9", 443));

        let denials = events(&chain(dir.path(), &key), FLOW_DENIED);
        assert_eq!(
            denials.len(),
            1,
            "a refusal must reach the chain even when the guest has filled the destination table"
        );
        assert_eq!(
            denials[0].labels.get("dst").map(String::as_str),
            Some("203.0.113.9"),
            "the entry still names the destination even when the bucket is coarse"
        );
    }

    /// The bounded tables *are* the rate bound. A guest cycling destinations
    /// it never repeats is the worst case, and it must still land under
    /// [`MAX_ENTRIES_PER_WINDOW`] with no separate budget helping.
    #[test]
    fn the_dedup_tables_bound_how_much_chain_a_guest_can_cause() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        for i in 0..(MAX_ENTRIES_PER_WINDOW as u32 * 8) {
            let octets = std::net::Ipv4Addr::from(0x0b00_0000 + i);
            auditor.observe(&denied(&octets.to_string(), 443));
        }

        let written = chain(dir.path(), &key).len();
        assert!(
            written <= MAX_ENTRIES_PER_WINDOW,
            "{written} entries from {} novel destinations, against a ceiling of \
             {MAX_ENTRIES_PER_WINDOW}",
            MAX_ENTRIES_PER_WINDOW * 8
        );
        assert!(
            auditor.drops().deduplicated > 0,
            "what the tables folded must be counted, not forgotten"
        );
        assert!(
            auditor.tracked_buckets() <= DESTINATION_BUCKETS + CLASS_BUCKETS,
            "the tables grew past their caps: {} buckets",
            auditor.tracked_buckets()
        );
    }

    /// A budget below the destination cap would fire before the table could
    /// fill, making the degrade-to-class path unreachable — which is why
    /// there is no budget. Pin the derivation so a later one cannot be added
    /// without confronting that.
    #[test]
    fn the_rate_ceiling_is_the_tables_and_nothing_else() {
        const {
            assert!(
                MAX_ENTRIES_PER_WINDOW == 2 * (DESTINATION_BUCKETS + CLASS_BUCKETS),
                "the ceiling is the live buckets plus the ones that can age out inside a window"
            );
            assert!(
                CLASS_BUCKETS < DESTINATION_BUCKETS,
                "the host-keyed table is the small one: its key space is fixed, \
                 while the guest-keyed table exists to absorb variety"
            );
        };
        // 768 entries per 30 seconds. Restated as a literal so a change to
        // either cap has to be argued for here.
        assert_eq!(MAX_ENTRIES_PER_WINDOW, 768);
        assert_eq!(DEDUP_WINDOW, Duration::from_secs(30));
    }

    /// A log that does not say how much of itself is missing is a log that
    /// lies by omission.
    #[test]
    fn teardown_records_what_never_reached_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        for _ in 0..10 {
            auditor.observe(&denied("93.184.216.34", 443));
        }
        auditor.finish();

        let entries = chain(dir.path(), &key);
        let teardown = events(&entries, TUNNEL_DISCONNECTED);
        assert_eq!(teardown.len(), 1);
        assert_eq!(
            teardown[0].labels.get("deduplicated").map(String::as_str),
            Some("9"),
            "the teardown entry must state how many decisions folded"
        );
        assert_eq!(
            teardown[0].labels.get("emit_failed").map(String::as_str),
            Some("0")
        );
    }

    /// The chain records that a question was asked and what the policy said
    /// about it. It does not record the answer's contents.
    #[test]
    fn a_dns_verdict_carries_the_name_and_the_answer_count_only() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        auditor.observe(&GatewayEvent::DnsAdmitted {
            name: "example.com".to_string(),
            answers: 2,
        });
        auditor.observe(&GatewayEvent::DnsDenied {
            name: "evil.test".to_string(),
            reason: "not admitted by policy",
        });

        let entries = chain(dir.path(), &key);
        let admitted = events(&entries, DNS_ADMITTED);
        assert_eq!(admitted.len(), 1);
        assert_eq!(
            admitted[0].labels.get("name").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            admitted[0].labels.get("answers").map(String::as_str),
            Some("2")
        );

        let refused = events(&entries, DNS_DENIED);
        assert_eq!(refused.len(), 1);
        assert_eq!(
            refused[0].labels.get("reason").map(String::as_str),
            Some("not admitted by policy")
        );
    }

    /// A guest that puts bytes in a name must not be able to put them on the
    /// chain unbounded — the label is metadata, not a channel.
    #[test]
    fn a_guest_chosen_label_is_clamped() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());

        auditor.observe(&GatewayEvent::DnsDenied {
            name: "a".repeat(4_000),
            reason: "not admitted by policy",
        });

        let entries = chain(dir.path(), &key);
        let name = entries[0].labels.get("name").cloned().unwrap_or_default();
        assert!(
            name.len() <= MAX_LABEL_BYTES + 4,
            "a {}-byte label reached the chain",
            name.len()
        );
    }

    /// Drive one of every event class, so the two tests below measure the
    /// whole label surface rather than a corner of it.
    fn drive_every_event_class(auditor: &mut NetdAuditor, dns_name: &str) {
        auditor.observe(&GatewayEvent::TunnelReady {
            session: SessionId(9),
        });
        auditor.observe(&admitted("93.184.216.34", 443));
        auditor.observe(&denied("198.51.100.7", 80));
        auditor.observe(&GatewayEvent::InboundDelivered {
            src: "93.184.216.34".parse().unwrap(),
            bytes: 1_400,
        });
        auditor.observe(&GatewayEvent::InboundDenied {
            reason: DenyCode::UnsolicitedInbound,
        });
        auditor.observe(&GatewayEvent::DnsAdmitted {
            name: dns_name.to_string(),
            answers: 1,
        });
        auditor.observe(&GatewayEvent::DnsDenied {
            name: dns_name.to_string(),
            reason: "name_not_admitted",
        });
        auditor.observe(&GatewayEvent::MalformedFrame {
            detail: "frame length 9 is below the 16-byte header".to_string(),
        });
        auditor.observe(&GatewayEvent::StaleSession);
        auditor.observe(&GatewayEvent::QueueOverflow {
            direction: Direction::Ingress,
        });
        auditor.observe(&GatewayEvent::RateLimited);
        auditor.finish();
    }

    /// **The negative.** The chain records decisions, so the set of labels it
    /// can carry is closed. A label key outside this list means a field
    /// arrived without anybody deciding it belonged on a tamper-evident
    /// record — which is exactly how payload gets into an audit log.
    ///
    /// Written as an allow-list rather than a scan for known-bad bytes,
    /// because a scan only catches the payload you thought of.
    #[test]
    fn the_chain_carries_only_the_labels_this_module_declares() {
        const ALLOWED: &[&str] = &[
            // The binding every entry carries.
            "machine_id",
            "session",
            "plan_digest",
            "policy_epoch",
            "protocol_version",
            "bucket_granularity",
            // Decision detail.
            "src",
            "dst",
            "dst_port",
            "protocol",
            "direction",
            "verdict",
            "reason",
            "name",
            "answers",
            "detail",
            "limit",
            "tunnel_session",
            // Teardown completeness.
            "deduplicated",
            "emit_failed",
            // Added by the recorder itself for every category.
            "category",
        ];
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());
        drive_every_event_class(&mut auditor, "example.com");

        let entries = chain(dir.path(), &key);
        assert!(
            entries.len() >= 10,
            "only {} entries written",
            entries.len()
        );
        for entry in &entries {
            for label in entry.labels.keys() {
                assert!(
                    ALLOWED.contains(&label.as_str()),
                    "{:?} carries an undeclared label {label:?}; if it belongs on a \
                     tamper-evident record, add it here and say why",
                    entry.event
                );
            }
        }
    }

    /// A guest-chosen string reaches the chain in exactly one place: the DNS
    /// name the policy decision was made against, kept because it *is* the
    /// normalized metadata. Everywhere else a guest byte would have to come
    /// from a packet body — and no `GatewayEvent` carries one, which is why
    /// this holds by construction rather than by filtering.
    ///
    /// The marker is placed in every guest-influenced position at once, so a
    /// future field that started carrying guest content would surface here.
    #[test]
    fn the_only_guest_chosen_value_on_the_chain_is_the_name_a_decision_was_made_against() {
        const MARKER: &str = "GUESTCHOSENMARKER";
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, key) = auditor_in(dir.path());
        drive_every_event_class(&mut auditor, &format!("{MARKER}.example.com"));

        let entries = chain(dir.path(), &key);
        let carrying: Vec<&str> = entries
            .iter()
            .filter(|e| e.labels.values().any(|v| v.contains(MARKER)))
            .map(|e| e.event.as_str())
            .collect();
        assert_eq!(
            carrying,
            vec!["l3.dns_admitted", "l3.dns_denied"],
            "a guest-chosen string reached the chain outside the DNS name"
        );
        for entry in &entries {
            for (label, value) in &entry.labels {
                if value.contains(MARKER) {
                    assert_eq!(
                        label, "name",
                        "{:?} put a guest-chosen string in {label:?}",
                        entry.event
                    );
                }
            }
        }
    }

    /// The gateway is the only way a workload reaches the network. An audit
    /// path that can wedge it converts a full disk into a network outage, so
    /// emission fails open — and the failure is counted rather than lost.
    #[test]
    fn an_emit_failure_does_not_stop_the_gateway_and_is_counted() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, _key) = auditor_in(dir.path());

        // Replace the chain directory with a regular file: every subsequent
        // append fails at the filesystem.
        let chain_path = dir.path().join(format!("{TENANT}.jsonl"));
        std::fs::create_dir_all(&chain_path).expect("a directory where the chain file goes");

        auditor.observe(&denied("93.184.216.34", 443));
        auditor.observe(&denied("198.51.100.7", 443));

        assert_eq!(
            auditor.drops().emit_failed,
            2,
            "a signer that cannot write must be counted, not silently tolerated"
        );
    }

    /// No signer key on the host means the gateway serves un-audited rather
    /// than refusing to serve. The same posture the substitution endpoint
    /// takes at the same seam.
    #[test]
    fn an_auditor_without_a_recorder_is_inert() {
        let mut auditor = NetdAuditor::with_recorder(None, context());
        assert!(!auditor.is_recording());
        for _ in 0..100 {
            auditor.observe(&denied("93.184.216.34", 443));
        }
        auditor.finish();
        assert_eq!(auditor.drops(), AuditDrops::default());
        assert_eq!(auditor.tracked_buckets(), 0);
    }

    /// The table a refusal falls back to must not be one a guest can fill,
    /// so its whole key space has to be host-defined and has to *fit*.
    ///
    /// The guest-keyed table is filled first, so every fact takes its class
    /// key and the count that comes out is the real worst case rather than
    /// the handful of classes an unpressured gateway opens. A new event
    /// class, or a new deny reason, moves that number and fails here — which
    /// is the point: the cap is a claim about a key set, and a claim about a
    /// key set has to be recounted when the set changes.
    #[test]
    fn the_class_key_space_fits_the_table_that_must_never_be_full() {
        let dir = tempfile::tempdir().unwrap();
        let (mut auditor, _key) = auditor_in(dir.path());

        for i in 0..(DESTINATION_BUCKETS as u32) {
            let octets = std::net::Ipv4Addr::from(0x0b00_0000 + i);
            auditor.observe(&admitted(&octets.to_string(), 443));
        }
        assert_eq!(
            auditor.destinations.len(),
            DESTINATION_BUCKETS,
            "the guest-keyed table must be full, or this measures nothing"
        );

        for code in DENY_CODES {
            auditor.observe(&GatewayEvent::FlowDenied {
                reason: *code,
                dst: None,
                dst_port: None,
            });
            auditor.observe(&GatewayEvent::InboundDenied { reason: *code });
        }
        for reason in DNS_DENY_REASONS {
            auditor.observe(&GatewayEvent::DnsDenied {
                name: "x.example.com".into(),
                reason,
            });
        }
        auditor.observe(&GatewayEvent::TunnelReady {
            session: SessionId(1),
        });
        auditor.observe(&admitted("203.0.113.9", 443));
        auditor.observe(&GatewayEvent::InboundDelivered {
            src: "203.0.113.9".parse().unwrap(),
            bytes: 40,
        });
        auditor.observe(&GatewayEvent::DnsAdmitted {
            name: "x.example.com".into(),
            answers: 1,
        });
        auditor.observe(&GatewayEvent::MalformedFrame {
            detail: "x".to_string(),
        });
        auditor.observe(&GatewayEvent::StaleSession);
        auditor.observe(&GatewayEvent::QueueOverflow {
            direction: Direction::Ingress,
        });
        auditor.observe(&GatewayEvent::QueueOverflow {
            direction: Direction::Egress,
        });
        auditor.observe(&GatewayEvent::RateLimited);

        // 23 deny codes on egress + 23 on ingress + 11 DNS refusal reasons +
        // 2 queue directions + one apiece for tunnel-ready, flow-admitted,
        // ingress-delivered, dns-admitted, malformed-frame, stale-session and
        // rate-limited.
        assert_eq!(
            auditor.classes.len(),
            23 + 23 + 11 + 2 + 7,
            "the class key space changed; recount it against CLASS_BUCKETS"
        );
        assert!(
            auditor.classes.len() * 3 / 2 <= CLASS_BUCKETS,
            "the class table must keep half again as much room as its key space \
             needs: {} keys against a cap of {CLASS_BUCKETS}",
            auditor.classes.len()
        );
        assert!(
            auditor.tracked_buckets() <= DESTINATION_BUCKETS + CLASS_BUCKETS,
            "the tables grew past their caps under the worst case"
        );
    }

    /// Every deny reason, so the test above measures the real key space
    /// rather than a sample of it. A new variant that is not added here
    /// fails the exhaustive match below at compile time.
    const DENY_CODES: &[DenyCode] = &[
        DenyCode::MalformedPacket,
        DenyCode::SpoofedSource,
        DenyCode::FragmentRefused,
        DenyCode::OversizedPacket,
        DenyCode::AddressFamilyUnassigned,
        DenyCode::MulticastDenied,
        DenyCode::BroadcastDenied,
        DenyCode::ReservedRangeDenied,
        DenyCode::MandatoryDeny,
        DenyCode::PrivateRangeDenied,
        DenyCode::LoopbackDenied,
        DenyCode::LinkLocalDenied,
        DenyCode::ProtocolDenied,
        DenyCode::DestinationNotAdmitted,
        DenyCode::PortNotAdmitted,
        DenyCode::IcmpDenied,
        DenyCode::GatewayServiceDenied,
        DenyCode::FlowTableFull,
        DenyCode::HostSocketUnavailable,
        DenyCode::UnsolicitedInbound,
        DenyCode::WrongDestination,
        DenyCode::PeerDestinationMismatch,
        DenyCode::SessionNotReady,
    ];

    /// Every DNS refusal reason the gateway can produce, from its own literals
    /// and from `deny_label`. Unlike [`DENY_CODES`] these are `&'static str`
    /// rather than an enum, so nothing pins them at compile time — the count
    /// assertion above is what catches an addition.
    const DNS_DENY_REASONS: [&str; 11] = [
        "tcp_dns_unsupported",
        "malformed_datagram",
        "malformed_query",
        "resolution_failed",
        "name_not_admitted",
        "rebinding",
        "no_admissible_answer",
        "binding_table_full",
        "name_table_full",
        "alias_chain_too_deep",
        "malformed_name",
    ];

    /// Pins [`DENY_CODES`] to the enumeration: a new variant makes this
    /// match non-exhaustive and the build fails here rather than silently
    /// leaving the class-table bound measured against a stale list.
    #[test]
    fn every_deny_reason_is_in_the_class_key_space() {
        for code in DENY_CODES {
            match code {
                DenyCode::MalformedPacket
                | DenyCode::SpoofedSource
                | DenyCode::FragmentRefused
                | DenyCode::OversizedPacket
                | DenyCode::AddressFamilyUnassigned
                | DenyCode::MulticastDenied
                | DenyCode::BroadcastDenied
                | DenyCode::ReservedRangeDenied
                | DenyCode::MandatoryDeny
                | DenyCode::PrivateRangeDenied
                | DenyCode::LoopbackDenied
                | DenyCode::LinkLocalDenied
                | DenyCode::ProtocolDenied
                | DenyCode::DestinationNotAdmitted
                | DenyCode::PortNotAdmitted
                | DenyCode::IcmpDenied
                | DenyCode::GatewayServiceDenied
                | DenyCode::FlowTableFull
                | DenyCode::HostSocketUnavailable
                | DenyCode::UnsolicitedInbound
                | DenyCode::WrongDestination
                | DenyCode::PeerDestinationMismatch
                | DenyCode::SessionNotReady => {}
            }
        }
        assert_eq!(DENY_CODES.len(), 23);
    }

    /// Every entry the gateway writes must pass the category's prefix check,
    /// or `record_unbound` refuses it at run time and the decision is lost.
    #[test]
    fn every_event_name_carries_the_categorys_prefix() {
        for name in [
            TUNNEL_READY,
            TUNNEL_DISCONNECTED,
            FLOW_ADMITTED,
            FLOW_DENIED,
            INGRESS_DELIVERED,
            INGRESS_DENIED,
            DNS_ADMITTED,
            DNS_DENIED,
            MALFORMED_FRAME,
            STALE_SESSION,
            QUEUE_OVERFLOW,
            RATE_LIMITED,
        ] {
            assert!(
                name.starts_with(&format!("{}.", EventCategory::L3.as_str())),
                "{name} would be refused by the recorder's prefix check"
            );
        }
    }
}

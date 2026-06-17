//! Re-feed rvproxy's exported flow events into mvm's chain-signed audit.
//!
//! When the gateway runs as a native `rvproxy run --config` subprocess, rvproxy
//! emits flow lifecycle events to its dataplane-audit export stream (JSONL file
//! or UDS). Each line is a `DataplaneAuditEvent` tagged by kind; the `flow`
//! records carry rvproxy's `FlowEvent`. This module parses those records and maps
//! them into mvm's [`FlowEvent`], which the per-VM `signer_task` chain-signs — so
//! the claim-10 audit stays mvm's source of truth even though rvproxy is the
//! event *source*.
//!
//! Only `flow` records are consumed; rvproxy's other dataplane-audit records
//! (`forward-flow` / `guest-egress` / `packet`) are ignored here. In mvm's
//! deployment the byte scans (placeholder-leak + undeclared redaction) stay in
//! the splice, so rvproxy only ever emits `opened`, policy-`denied`, and normal
//! `closed` flow events — which is why the verdict→reason mapping below is total.
//!
//! Unlike the splice's coarse per-VM-direction `flow_id` (`<vm>-egress`), the
//! native path is per-connection: each rvproxy flow carries its 5-tuple, so the
//! re-emitted `flow_id` is `<vm>-egress-<proto>-<src>-<dst>` (strictly more
//! granular audit).

use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::supervisor::audit::{FlowCloseReason, FlowDirection};
use crate::supervisor::gateway_bridge::{FlowEvent, FlowEventKind};

/// rvproxy's exported `FlowEvent` (mirror of
/// `rvproxy-transport::FlowEvent` / `FlowEndpoints`). mvm consumes rvproxy as a
/// subprocess and does not depend on its crates, so the wire shape is mirrored
/// here; the field names and enum spellings match rvproxy's serde exactly.
#[derive(Debug, Deserialize)]
struct RvproxyFlowEvent {
    kind: RvproxyFlowKind,
    protocol: String,
    endpoints: RvproxyFlowEndpoints,
    verdict: RvproxyFlowVerdict,
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    bytes_to_remote: u64,
    #[serde(default)]
    #[allow(dead_code)]
    bytes_to_guest: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RvproxyFlowKind {
    Opened,
    Closed,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RvproxyFlowVerdict {
    Allowed,
    Denied,
}

#[derive(Debug, Deserialize)]
struct RvproxyFlowEndpoints {
    source_ip: Ipv4Addr,
    source_port: u16,
    destination_ip: Ipv4Addr,
    destination_port: u16,
}

/// Extract the rvproxy `FlowEvent` from one exported dataplane-audit line, or
/// `None` if the line is not a `flow` record (or is unparseable). The outer
/// envelope is `{"kind":"<type>","event":{...}}`; only `kind == "flow"` carries
/// a `FlowEvent`, so other record kinds are skipped without erroring.
fn parse_flow_record(line: &str) -> Option<RvproxyFlowEvent> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    if value.get("kind")?.as_str()? != "flow" {
        return None;
    }
    serde_json::from_value(value.get("event")?.clone()).ok()
}

/// Map an rvproxy flow event onto mvm's audit [`FlowEvent`]. rvproxy flow events
/// are guest-egress flows, so the direction is always `Egress`. A `denied`
/// verdict is a policy drop (claim-10); a normal `closed` flow maps to `Eof`.
fn to_mvm_flow_event(vm_name: &str, event: &RvproxyFlowEvent) -> FlowEvent {
    let ep = &event.endpoints;
    let flow_id = format!(
        "{vm_name}-egress-{}-{}:{}-{}:{}",
        event.protocol, ep.source_ip, ep.source_port, ep.destination_ip, ep.destination_port
    );
    let kind = match (&event.kind, &event.verdict) {
        (RvproxyFlowKind::Opened, _) => FlowEventKind::Opened,
        (RvproxyFlowKind::Closed, RvproxyFlowVerdict::Denied) => FlowEventKind::Closed {
            reason: FlowCloseReason::PolicyDropped,
        },
        (RvproxyFlowKind::Closed, RvproxyFlowVerdict::Allowed) => FlowEventKind::Closed {
            reason: FlowCloseReason::Eof,
        },
    };
    FlowEvent {
        flow_id,
        direction: FlowDirection::Egress,
        kind,
    }
}

/// Read rvproxy's exported dataplane-audit stream line by line, mapping each
/// `flow` record into an mvm [`FlowEvent`] handed to `sink`. The real caller
/// passes a sink that forwards into `signer_task`'s mpsc channel (so the events
/// are chain-signed); `reader` is the JSONL file or UDS connection. Non-flow and
/// blank/garbage lines are skipped. Returns when the stream ends or on read
/// error.
pub fn pump_flow_audit<R: BufRead>(
    reader: R,
    vm_name: &str,
    mut sink: impl FnMut(FlowEvent),
) -> std::io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if let Some(event) = parse_flow_record(line.trim()) {
            sink(to_mvm_flow_event(vm_name, &event));
        }
    }
    Ok(())
}

/// How long [`follow_flow_audit`] waits for rvproxy to create the export file
/// before giving up, and how long it idles between EOF polls once attached.
const FOLLOW_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Tail rvproxy's growing flow-audit JSONL export (the native-gateway audit
/// source), mapping each new `flow` record into mvm's [`FlowEvent`] and handing
/// it to `sink`. Unlike [`pump_flow_audit`] (read-to-EOF), this follows the file
/// as rvproxy appends over the VM's lifetime: on EOF it idles `FOLLOW_POLL_INTERVAL`
/// and resumes. `sink` returns `false` to stop the loop — the production caller
/// returns `false` once `signer_task`'s channel is closed (the supervisor is
/// tearing down), so the thread exits instead of spinning.
///
/// The file is opened append-follow style; rvproxy creates it at gateway start,
/// but to avoid a startup race we poll up to `FOLLOW_OPEN_TIMEOUT` for it to
/// appear. rvproxy's default 128 MiB rotation threshold is far above a per-VM
/// flow volume, so a held read position does not miss events to rotation in
/// practice. Returns when `sink` stops, on the open timeout, or on read error.
pub fn follow_flow_audit(
    path: &Path,
    vm_name: &str,
    mut sink: impl FnMut(FlowEvent) -> bool,
) -> std::io::Result<()> {
    let mut waited = Duration::ZERO;
    let file = loop {
        match std::fs::File::open(path) {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if waited >= FOLLOW_OPEN_TIMEOUT {
                    return Err(e);
                }
                std::thread::sleep(FOLLOW_POLL_INTERVAL);
                waited += FOLLOW_POLL_INTERVAL;
            }
            Err(e) => return Err(e),
        }
    };

    let mut reader = BufReader::new(file);
    // `line` accumulates across reads: a partial append (no trailing newline)
    // is kept and completed on a later read rather than parsed truncated. It is
    // cleared only after a whole line is consumed.
    let mut line = String::new();
    loop {
        let n = reader.read_line(&mut line)?;
        if n == 0 || !line.ends_with('\n') {
            // EOF, or a partial line not yet terminated: idle, then resume —
            // the buffered partial survives for the next read to complete.
            std::thread::sleep(FOLLOW_POLL_INTERVAL);
            continue;
        }
        if let Some(event) = parse_flow_record(line.trim())
            && !sink(to_mvm_flow_event(vm_name, &event))
        {
            return Ok(());
        }
        line.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn flow_line(kind: &str, verdict: &str, reason: &str, dst: &str, dport: u16) -> String {
        format!(
            r#"{{"kind":"flow","event":{{"kind":"{kind}","protocol":"tcp","endpoints":{{"source_ip":"192.168.127.2","source_port":41000,"destination_ip":"{dst}","destination_port":{dport}}},"verdict":"{verdict}","reason":{reason},"bytes_to_remote":12,"bytes_to_guest":34}}}}"#
        )
    }

    #[test]
    fn parses_opened_flow_record() {
        let line = flow_line("opened", "allowed", "null", "93.184.216.34", 443);
        let ev = parse_flow_record(&line).expect("flow record parses");
        let mapped = to_mvm_flow_event("vm-demo", &ev);
        assert!(matches!(mapped.kind, FlowEventKind::Opened));
        assert!(matches!(mapped.direction, FlowDirection::Egress));
        assert_eq!(
            mapped.flow_id,
            "vm-demo-egress-tcp-192.168.127.2:41000-93.184.216.34:443"
        );
    }

    #[test]
    fn denied_close_maps_to_policy_dropped() {
        let line = flow_line("closed", "denied", "\"deny-by-default\"", "8.8.8.8", 443);
        let ev = parse_flow_record(&line).unwrap();
        let mapped = to_mvm_flow_event("vm-demo", &ev);
        assert!(matches!(
            mapped.kind,
            FlowEventKind::Closed {
                reason: FlowCloseReason::PolicyDropped
            }
        ));
    }

    #[test]
    fn allowed_close_maps_to_eof() {
        let line = flow_line("closed", "allowed", "\"guest_fin\"", "93.184.216.34", 443);
        let ev = parse_flow_record(&line).unwrap();
        let mapped = to_mvm_flow_event("vm-demo", &ev);
        assert!(matches!(
            mapped.kind,
            FlowEventKind::Closed {
                reason: FlowCloseReason::Eof
            }
        ));
    }

    #[test]
    fn non_flow_and_garbage_records_are_skipped() {
        // Other dataplane-audit record kinds carry a different `event` shape.
        let guest_egress = r#"{"kind":"guest-egress","event":{"event_type":"allowed","protocol":"tcp","source_ip":"192.168.127.2","source_port":41000,"destination_ip":"8.8.8.8","destination_port":443,"message":null}}"#;
        let packet = r#"{"kind":"packet","event":{"event_type":"invalid-frame","message":"x"}}"#;
        assert!(parse_flow_record(guest_egress).is_none());
        assert!(parse_flow_record(packet).is_none());
        assert!(parse_flow_record("not json").is_none());
        assert!(parse_flow_record("").is_none());
    }

    #[test]
    fn pump_maps_only_flow_records_in_order() {
        let stream = [
            flow_line("opened", "allowed", "null", "93.184.216.34", 443),
            r#"{"kind":"packet","event":{"event_type":"invalid-frame","message":"x"}}"#.to_string(),
            String::new(), // blank line
            flow_line("closed", "denied", "\"l4_allowlist_miss\"", "8.8.8.8", 80),
            "garbage".to_string(),
            flow_line(
                "closed",
                "allowed",
                "\"idle_timeout\"",
                "93.184.216.34",
                443,
            ),
        ]
        .join("\n");

        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink_collected = collected.clone();
        pump_flow_audit(stream.as_bytes(), "vm-demo", move |ev| {
            sink_collected.lock().unwrap().push(ev);
        })
        .unwrap();

        let events = collected.lock().unwrap();
        assert_eq!(events.len(), 3, "only the 3 flow records map");
        assert!(matches!(events[0].kind, FlowEventKind::Opened));
        assert!(matches!(
            events[1].kind,
            FlowEventKind::Closed {
                reason: FlowCloseReason::PolicyDropped
            }
        ));
        assert!(matches!(
            events[2].kind,
            FlowEventKind::Closed {
                reason: FlowCloseReason::Eof
            }
        ));
    }

    #[test]
    fn follow_reads_appended_records_and_stops_on_sink_false() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("flow-audit.jsonl");
        // Pre-populate: an opened + a denied-close record, plus a garbage line
        // the follower must skip without counting.
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "{}",
            flow_line("opened", "allowed", "null", "93.184.216.34", 443)
        )
        .unwrap();
        writeln!(f, "garbage not json").unwrap();
        writeln!(
            f,
            "{}",
            flow_line("closed", "denied", "\"deny-by-default\"", "8.8.8.8", 443)
        )
        .unwrap();
        f.flush().unwrap();

        // Sink collects and stops (returns false) once both flow records arrive,
        // so the follow loop exits instead of polling forever.
        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink_collected = collected.clone();
        follow_flow_audit(&path, "vm-demo", move |ev| {
            let mut v = sink_collected.lock().unwrap();
            v.push(ev);
            v.len() < 2
        })
        .unwrap();

        let events = collected.lock().unwrap();
        assert_eq!(
            events.len(),
            2,
            "two flow records followed; garbage skipped"
        );
        assert!(matches!(events[0].kind, FlowEventKind::Opened));
        assert!(matches!(
            events[1].kind,
            FlowEventKind::Closed {
                reason: FlowCloseReason::PolicyDropped
            }
        ));
    }
}

//! Plan 89 W2 part 3 — hand-rolled JSON for the
//! `HostVmResponse::Result` wire frame builder-init sends right
//! before reboot.
//!
//! ## Why hand-roll
//!
//! `mvm-host-vm-init` keeps a ≤ 1.5 MiB rootfs size budget
//! (Plan 72 §W3) and deliberately does not pull `serde_json`
//! (`Cargo.toml` comment at the deps section). The host-side
//! consumer (`mvm_build::builder_protocol::HostVmResponse::Result`)
//! is a typed serde enum; this module mirrors its wire shape
//! exactly so the host's `serde_json::from_slice::<HostVmResponse>`
//! parses what we emit. The `builder_response_matches_typed_serde`
//! test below uses `mvm-build` as a dev-dep to pin the two sides
//! together — if anyone tweaks either struct, that test breaks
//! and points at the resync.
//!
//! ## Single-shot caveats
//!
//! `HostVmResponse::Result` carries a `job_id: JobId(Uuid)` and a
//! `job_timings: JobTimings { dispatch_ms, build_ms, teardown_ms }`.
//! In single-shot mode there is no incoming dispatch with an id and
//! no remote-dispatch round-trip to time, so:
//!
//! - `job_id` is the nil UUID
//!   (`00000000-0000-0000-0000-000000000000`). The host's
//!   single-shot caller knows to ignore it; persistent dispatch
//!   (W3) will populate it from the `HostVmRequest::Run` it
//!   correlates against.
//! - `dispatch_ms` and `teardown_ms` are `0`. Only `build_ms`
//!   carries a meaningful value, measured by the caller as
//!   `job_end_ms - job_start_ms`.

use crate::boot_timings::BootTimings;

/// The nil UUID used by the single-shot path when no incoming
/// dispatch supplied a `job_id`. Persistent-dispatch callers
/// (Plan 89 W3 part 3) echo back the request's id instead.
pub(crate) const NIL_JOB_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Owned snapshot of the data needed to hand-roll a
/// `HostVmResponse::Result` JSON frame. The producer (the linux
/// module's `run` path for single-shot, or the W3 dispatch loop)
/// gathers these fields after the inner build returns.
#[derive(Debug, Clone)]
pub(crate) struct DispatchResponse {
    /// UUID-string echoed from the incoming `HostVmRequest::Run`.
    /// Single-shot callers pass [`NIL_JOB_ID`]; persistent
    /// dispatch echoes the host-generated id from
    /// `HostVmRequest::Run::job_id`.
    pub job_id: String,
    pub exit_code: i32,
    pub stderr_tail: String,
    /// Cold-boot phase timings. `Some` on the first response a
    /// persistent VM emits (matches the host-side
    /// `HostVmResponse::Result::boot_timings: Option<...>`
    /// semantics); `None` on subsequent dispatches in the same
    /// session — there's no second cold boot to time. Single-shot
    /// always passes `Some`.
    pub boot_timings: Option<BootTimings>,
    pub build_ms: u64,
}

impl DispatchResponse {
    /// Render as the exact wire JSON `mvm_build::builder_protocol::HostVmResponse::Result`
    /// deserializes from. Field order matches the serde-derived
    /// internally-tagged enum encoding (`"kind"` first, then the
    /// variant's struct fields in declaration order).
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(r#"{"kind":"result","job_id":""#);
        push_json_string(&mut out, &self.job_id);
        out.push_str(r#"","exit_code":"#);
        out.push_str(&self.exit_code.to_string());
        out.push_str(r#","stderr_tail":""#);
        push_json_string(&mut out, &self.stderr_tail);
        out.push_str(r#"","boot_timings":"#);
        match &self.boot_timings {
            Some(bt) => out.push_str(&bt.to_json()),
            None => out.push_str("null"),
        }
        out.push_str(r#","job_timings":{"dispatch_ms":0,"build_ms":"#);
        out.push_str(&self.build_ms.to_string());
        out.push_str(r#","teardown_ms":0}}"#);
        out
    }
}

/// Plan 89 W3 part 3 — wire JSON for `HostVmResponse::Bye`,
/// the dispatch loop's acknowledgement of `HostVmRequest::Shutdown`.
/// Static body; no fields to escape.
pub(crate) fn bye_json() -> &'static str {
    r#"{"kind":"bye"}"#
}

/// Plan 89 W3 part 9 — wire JSON for `HostVmResponse::StderrChunk`,
/// one frame per stderr line the dispatch loop streams back to the
/// host while a build is running. Matches the serde-derived shape in
/// `mvm_build::builder_protocol::HostVmResponse::StderrChunk`
/// (`{"kind":"stderr_chunk","job_id":"...","line":"..."}`); the
/// cross-validation test below pins it.
///
/// `line` must already have its trailing `\n` stripped — the host's
/// `mvm_build::builder_protocol::HostVmResponse::StderrChunk` docs
/// commit to that.
pub(crate) fn stderr_chunk_json(job_id: &str, line: &str) -> String {
    let mut out = String::with_capacity(64 + job_id.len() + line.len());
    out.push_str(r#"{"kind":"stderr_chunk","job_id":""#);
    push_json_string(&mut out, job_id);
    out.push_str(r#"","line":""#);
    push_json_string(&mut out, line);
    out.push_str(r#""}"#);
    out
}

/// Plan 107 A2.2 — wire JSON for `HostVmResponse::WorkloadStarted`
/// (`{"kind":"workload_started","workload_id":"...","pid":N}`).
/// Mirrors the serde-derived field order; the cross-validation test
/// below pins it against the typed enum.
pub(crate) fn workload_started_json(workload_id: &str, pid: u32) -> String {
    let mut out = String::with_capacity(80 + workload_id.len());
    out.push_str(r#"{"kind":"workload_started","workload_id":""#);
    push_json_string(&mut out, workload_id);
    out.push_str(r#"","pid":"#);
    out.push_str(&pid.to_string());
    out.push('}');
    out
}

/// Plan 107 A2.2 — wire JSON for `HostVmResponse::WorkloadStopped`.
pub(crate) fn workload_stopped_json(workload_id: &str) -> String {
    let mut out = String::with_capacity(64 + workload_id.len());
    out.push_str(r#"{"kind":"workload_stopped","workload_id":""#);
    push_json_string(&mut out, workload_id);
    out.push_str(r#""}"#);
    out
}

/// Plan 107 A2.2 — wire JSON for
/// `HostVmResponse::WorkloadStatusReport`.
pub(crate) fn workload_status_report_json(workload_id: &str, status: &str) -> String {
    let mut out = String::with_capacity(80 + workload_id.len() + status.len());
    out.push_str(r#"{"kind":"workload_status_report","workload_id":""#);
    push_json_string(&mut out, workload_id);
    out.push_str(r#"","status":""#);
    push_json_string(&mut out, status);
    out.push_str(r#""}"#);
    out
}

/// Plan 107 A2.2 — wire JSON for `HostVmResponse::WorkloadFailed`,
/// the fail-closed negative path (spawn / collision / parse error).
pub(crate) fn workload_failed_json(workload_id: &str, error: &str) -> String {
    let mut out = String::with_capacity(80 + workload_id.len() + error.len());
    out.push_str(r#"{"kind":"workload_failed","workload_id":""#);
    push_json_string(&mut out, workload_id);
    out.push_str(r#"","error":""#);
    push_json_string(&mut out, error);
    out.push_str(r#""}"#);
    out
}

/// JSON string-escape per RFC 8259 §7. Inlined rather than calling
/// the existing `json_escape` in `main.rs` because that one is
/// `#[cfg(target_os = "linux")]`-gated under the linux module —
/// this module is cross-platform so `cargo test` on macOS hosts
/// can exercise the roundtrip. `pub(crate)` so [`crate::workload`]
/// reuses the same escaper for the Firecracker config JSON.
pub(crate) fn push_json_string(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_timings() -> BootTimings {
        let (mut t, _anchor) = BootTimings::new(std::time::Instant::now());
        t.pseudofs_ready_ms = Some(12);
        t.nix_device_ready_ms = Some(18);
        t.nix_seeded_ms = None;
        t.nix_mounted_ms = Some(220);
        t.modules_ready_ms = Some(35);
        t.virtiofs_ready_ms = Some(48);
        t.network_ready_ms = Some(250);
        t.job_start_ms = Some(260);
        t.job_end_ms = Some(8400);
        t.poweroff_start_ms = Some(8410);
        t
    }

    #[test]
    fn dispatch_response_emits_valid_json() {
        let resp = DispatchResponse {
            job_id: NIL_JOB_ID.to_string(),
            exit_code: 0,
            stderr_tail: "warning: foo\nwarning: bar".to_string(),
            boot_timings: Some(sample_timings()),
            build_ms: 8140,
        };
        let json = resp.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(parsed["kind"], "result");
        assert_eq!(parsed["job_id"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(parsed["exit_code"], 0);
        assert_eq!(parsed["stderr_tail"], "warning: foo\nwarning: bar");
        assert_eq!(parsed["job_timings"]["dispatch_ms"], 0);
        assert_eq!(parsed["job_timings"]["build_ms"], 8140);
        assert_eq!(parsed["job_timings"]["teardown_ms"], 0);
        assert_eq!(parsed["boot_timings"]["init_start_ms"], 0);
        assert_eq!(
            parsed["boot_timings"]["nix_seeded_ms"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn dispatch_response_escapes_control_chars_in_stderr_tail() {
        let resp = DispatchResponse {
            job_id: NIL_JOB_ID.to_string(),
            exit_code: 1,
            stderr_tail: "line1\n\"quoted\"\tand\\back\x01slash".to_string(),
            boot_timings: Some(sample_timings()),
            build_ms: 0,
        };
        let json = resp.to_json();
        // Must round-trip through a real JSON parser.
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(
            parsed["stderr_tail"],
            "line1\n\"quoted\"\tand\\back\x01slash"
        );
    }

    #[test]
    fn dispatch_response_handles_empty_stderr_tail() {
        let resp = DispatchResponse {
            job_id: NIL_JOB_ID.to_string(),
            exit_code: 0,
            stderr_tail: String::new(),
            boot_timings: Some(sample_timings()),
            build_ms: 100,
        };
        let json = resp.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(parsed["stderr_tail"], "");
    }

    /// Plan 89 W3 part 3 — `boot_timings: None` produces a JSON
    /// `null` rather than an object. Mirrors the persistent VM's
    /// second-and-subsequent dispatches.
    #[test]
    fn dispatch_response_emits_null_boot_timings_when_none() {
        let resp = DispatchResponse {
            job_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            exit_code: 0,
            stderr_tail: String::new(),
            boot_timings: None,
            build_ms: 42,
        };
        let json = resp.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(parsed["boot_timings"], serde_json::Value::Null);
        assert_eq!(parsed["job_id"], "01234567-89ab-cdef-0123-456789abcdef");
    }

    #[test]
    fn bye_json_matches_typed_builder_response_bye() {
        let typed: mvm_build::builder_protocol::HostVmResponse =
            serde_json::from_str(bye_json()).expect("parse");
        assert!(matches!(
            typed,
            mvm_build::builder_protocol::HostVmResponse::Bye {}
        ));
    }

    /// Plan 89 W3 part 9 — hand-rolled `StderrChunk` must
    /// deserialize as the typed enum variant with the same field
    /// values. Bumps either shape and this test breaks.
    #[test]
    fn stderr_chunk_json_matches_typed_builder_response() {
        let job_id = "01234567-89ab-cdef-0123-456789abcdef";
        let line = "[mvm] nix build: 12/47 derivations";
        let json = stderr_chunk_json(job_id, line);
        let typed: mvm_build::builder_protocol::HostVmResponse =
            serde_json::from_str(&json).expect("must parse as typed HostVmResponse");
        match typed {
            mvm_build::builder_protocol::HostVmResponse::StderrChunk {
                job_id: got_id,
                line: got_line,
            } => {
                assert_eq!(got_id.to_string(), job_id);
                assert_eq!(got_line, line);
            }
            other => panic!("expected StderrChunk variant, got {other:?}"),
        }
    }

    #[test]
    fn stderr_chunk_json_escapes_control_chars_in_line() {
        let json = stderr_chunk_json(NIL_JOB_ID, "warn: \"q\"\tand\\back\x01slash");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(parsed["kind"], "stderr_chunk");
        assert_eq!(parsed["line"], "warn: \"q\"\tand\\back\x01slash");
    }

    #[test]
    fn stderr_chunk_json_handles_empty_line() {
        let json = stderr_chunk_json(NIL_JOB_ID, "");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(parsed["line"], "");
    }

    /// **The cross-validation test.** Hand-rolled JSON must
    /// deserialize as `mvm_build::builder_protocol::HostVmResponse`
    /// with `Result` variant carrying the expected fields. Bumps
    /// either struct's shape (renames, additions, type changes)
    /// trip this test, which is the signal to re-sync.
    #[test]
    fn dispatch_response_parses_as_typed_builder_response() {
        let resp = DispatchResponse {
            job_id: NIL_JOB_ID.to_string(),
            exit_code: 7,
            stderr_tail: "uh oh".to_string(),
            boot_timings: Some(sample_timings()),
            build_ms: 1234,
        };
        let json = resp.to_json();
        let typed: mvm_build::builder_protocol::HostVmResponse =
            serde_json::from_str(&json).expect("must parse as typed HostVmResponse");
        match typed {
            mvm_build::builder_protocol::HostVmResponse::Result {
                job_id,
                exit_code,
                stderr_tail,
                boot_timings,
                job_timings,
            } => {
                assert_eq!(job_id.to_string(), "00000000-0000-0000-0000-000000000000");
                assert_eq!(exit_code, 7);
                assert_eq!(stderr_tail, "uh oh");
                assert_eq!(job_timings.dispatch_ms, 0);
                assert_eq!(job_timings.build_ms, 1234);
                assert_eq!(job_timings.teardown_ms, 0);
                let bt = boot_timings.expect("boot_timings present");
                assert_eq!(bt.init_start_ms, Some(0));
                assert_eq!(bt.nix_seeded_ms, None);
                assert_eq!(bt.network_ready_ms, Some(250));
            }
            other => panic!("expected Result variant, got {other:?}"),
        }
    }

    /// Plan 107 A2.2 — every workload-lifecycle emitter must
    /// deserialize as the typed `HostVmResponse` variant with the
    /// expected fields. Drift on either side trips this.
    #[test]
    fn workload_emitters_parse_as_typed_builder_response() {
        use mvm_build::builder_protocol::{HostVmResponse, WorkloadId};

        let id = "00000000-0000-0000-0000-000000000000";

        match serde_json::from_str(&workload_started_json(id, 4242)).unwrap() {
            HostVmResponse::WorkloadStarted { workload_id, pid } => {
                assert_eq!(workload_id, WorkloadId(uuid::Uuid::nil()));
                assert_eq!(pid, 4242);
            }
            other => panic!("expected WorkloadStarted, got {other:?}"),
        }

        match serde_json::from_str(&workload_stopped_json(id)).unwrap() {
            HostVmResponse::WorkloadStopped { workload_id } => {
                assert_eq!(workload_id, WorkloadId(uuid::Uuid::nil()));
            }
            other => panic!("expected WorkloadStopped, got {other:?}"),
        }

        match serde_json::from_str(&workload_status_report_json(id, "running")).unwrap() {
            HostVmResponse::WorkloadStatusReport {
                workload_id,
                status,
            } => {
                assert_eq!(workload_id, WorkloadId(uuid::Uuid::nil()));
                assert_eq!(status, "running");
            }
            other => panic!("expected WorkloadStatusReport, got {other:?}"),
        }

        match serde_json::from_str(&workload_failed_json(id, "spawn failed: ENOENT")).unwrap() {
            HostVmResponse::WorkloadFailed { workload_id, error } => {
                assert_eq!(workload_id, WorkloadId(uuid::Uuid::nil()));
                assert_eq!(error, "spawn failed: ENOENT");
            }
            other => panic!("expected WorkloadFailed, got {other:?}"),
        }
    }

    #[test]
    fn workload_failed_escapes_control_chars_in_error() {
        let json = workload_failed_json(NIL_JOB_ID, "oops:\n\"quoted\"\tbad");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must parse");
        assert_eq!(parsed["kind"], "workload_failed");
        assert_eq!(parsed["error"], "oops:\n\"quoted\"\tbad");
    }
}

//! Plan 89 W3 part 2 — hand-rolled parser for `HostVmRequest`
//! JSON, the wire-format the persistent builder VM's dispatch loop
//! reads off vsock.
//!
//! Mirror of `mvm_build::builder_protocol::HostVmRequest` on the
//! host side. Cross-platform on purpose — the parser sees coverage
//! from `cargo test` on every developer host so the wire shape
//! stays in lock-step with the host's serde-derived encoding
//! without depending on a Linux cross-compile.
//!
//! ## Why hand-roll
//!
//! Same rationale as [`crate::install_spec`] and
//! [`crate::dispatch_response`]: the Plan 72 §W3 size budget caps
//! the static-linked init at ≤ 1.5 MiB, so we don't pull
//! `serde_json` for the handful of wire shapes the dispatch loop
//! reads. The wire shape is closed (two variants, three optional
//! field clusters) and the
//! `parses_what_mvm_build_serializes_with_serde` test pins our
//! parser against the host's typed `serde_json::to_vec` output.
//!
//! ## Wire shape
//!
//! Internally-tagged enum encoding (`#[serde(tag = "kind", rename_all
//! = "snake_case")]`) on the host side. Two variants:
//!
//! ```json
//! {
//!   "kind": "run",
//!   "job_id": "00000000-0000-0000-0000-000000000000",
//!   "job": { "Flake": { "flake_ref": "...", "attr_path": "..." } },
//!   "job_dir_relpath": "..."
//! }
//! ```
//!
//! …or with the install variant:
//!
//! ```json
//! { "kind": "run", "job_id": "...",
//!   "job": { "Install": { "spec_path": "..." } },
//!   "job_dir_relpath": "..." }
//! ```
//!
//! …or:
//!
//! ```json
//! { "kind": "shutdown" }
//! ```
//!
//! `BuilderJob` uses serde's default external tagging on the host
//! side (no `#[serde(tag = "...")]`), which yields the
//! `{"Flake": {...}}` / `{"Install": {...}}` nesting above. This
//! parser walks that exact shape.

use std::fmt;

/// In-guest mirror of `mvm_build::builder_vm::BuilderJob`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderJob {
    Flake {
        flake_ref: String,
        attr_path: String,
    },
    Install {
        spec_path: String,
    },
}

/// In-guest mirror of `mvm_build::builder_protocol::HostVmRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostVmRequest {
    Run {
        job_id: String,
        job: BuilderJob,
        job_dir_relpath: String,
    },
    Shutdown,
    /// Plan 107 W6 / A2.2 — start a workload microVM inside the host
    /// VM. Carries the spawn config the `WorkloadVmm` backend
    /// (Firecracker today) needs. Fields mirror
    /// `mvm_build::builder_protocol::HostVmRequest::WorkloadStart`.
    WorkloadStart {
        workload_id: String,
        kernel_path: String,
        rootfs_path: String,
        vsock_socket_dir: String,
        vcpus: u32,
        memory_mib: u32,
        kernel_cmdline_extras: String,
    },
    /// Plan 107 W6 / A2.2 — stop a running workload microVM.
    WorkloadStop {
        workload_id: String,
    },
    /// Plan 107 W6 / A2.2 — query a workload microVM's status.
    WorkloadStatus {
        workload_id: String,
    },
}

#[derive(Debug)]
pub enum ParseError {
    /// Body wasn't valid UTF-8.
    NotUtf8(std::str::Utf8Error),
    /// Couldn't find the `"kind"` discriminator.
    MissingKind,
    /// `"kind"` was present but neither `"run"` nor `"shutdown"`.
    UnknownKind(String),
    /// `HostVmRequest::Run` was missing a required field.
    MissingRunField(&'static str),
    /// `Run.job` had neither `"Flake"` nor `"Install"`.
    UnknownJobVariant,
    /// `Run.job.<variant>` was missing a required field.
    MissingJobField(&'static str),
    /// A workload request was missing a required field.
    MissingWorkloadField(&'static str),
    /// A numeric workload field (`vcpus` / `memory_mib`) was absent
    /// or not a base-10 integer.
    BadNumber(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8(e) => write!(f, "HostVmRequest body not UTF-8: {e}"),
            Self::MissingKind => write!(f, "HostVmRequest missing `kind` discriminator"),
            Self::UnknownKind(k) => write!(f, "HostVmRequest unknown kind `{k}`"),
            Self::MissingRunField(name) => write!(f, "HostVmRequest::Run missing `{name}`"),
            Self::UnknownJobVariant => {
                write!(f, "HostVmRequest::Run job is neither Flake nor Install")
            }
            Self::MissingJobField(name) => write!(f, "BuilderJob missing `{name}`"),
            Self::MissingWorkloadField(name) => {
                write!(f, "HostVmRequest workload missing `{name}`")
            }
            Self::BadNumber(name) => {
                write!(f, "HostVmRequest workload field `{name}` is not an integer")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a JSON-encoded `HostVmRequest` body (no length prefix —
/// the caller has already framed). Tolerant of insignificant
/// whitespace between JSON tokens because serde's writer may emit
/// either compact or pretty output (we test against compact, but
/// don't want to fail closed on pretty just to be safe).
pub fn parse(bytes: &[u8]) -> Result<HostVmRequest, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(ParseError::NotUtf8)?;
    let kind = find_string_value(text, "kind").ok_or(ParseError::MissingKind)?;
    match kind.as_str() {
        "shutdown" => Ok(HostVmRequest::Shutdown),
        "run" => parse_run(text),
        "workload_start" => parse_workload_start(text),
        "workload_stop" => parse_workload(text, |workload_id| HostVmRequest::WorkloadStop {
            workload_id,
        }),
        "workload_status" => parse_workload(text, |workload_id| HostVmRequest::WorkloadStatus {
            workload_id,
        }),
        other => Err(ParseError::UnknownKind(other.to_string())),
    }
}

/// Parse the id-only workload variants (`workload_stop` /
/// `workload_status`).
fn parse_workload(
    text: &str,
    ctor: impl FnOnce(String) -> HostVmRequest,
) -> Result<HostVmRequest, ParseError> {
    let workload_id = find_string_value(text, "workload_id")
        .ok_or(ParseError::MissingWorkloadField("workload_id"))?;
    Ok(ctor(workload_id))
}

/// Parse `workload_start`, which carries the full spawn config.
/// Mirrors `mvm_build::builder_protocol::HostVmRequest::WorkloadStart`.
fn parse_workload_start(text: &str) -> Result<HostVmRequest, ParseError> {
    let workload_id = find_string_value(text, "workload_id")
        .ok_or(ParseError::MissingWorkloadField("workload_id"))?;
    let kernel_path = find_string_value(text, "kernel_path")
        .ok_or(ParseError::MissingWorkloadField("kernel_path"))?;
    let rootfs_path = find_string_value(text, "rootfs_path")
        .ok_or(ParseError::MissingWorkloadField("rootfs_path"))?;
    let vsock_socket_dir = find_string_value(text, "vsock_socket_dir")
        .ok_or(ParseError::MissingWorkloadField("vsock_socket_dir"))?;
    let vcpus = find_u32_value(text, "vcpus").ok_or(ParseError::BadNumber("vcpus"))?;
    let memory_mib =
        find_u32_value(text, "memory_mib").ok_or(ParseError::BadNumber("memory_mib"))?;
    // `kernel_cmdline_extras` may legitimately be empty, so an empty
    // string is fine; only a *missing* key is an error.
    let kernel_cmdline_extras = find_string_value(text, "kernel_cmdline_extras")
        .ok_or(ParseError::MissingWorkloadField("kernel_cmdline_extras"))?;
    Ok(HostVmRequest::WorkloadStart {
        workload_id,
        kernel_path,
        rootfs_path,
        vsock_socket_dir,
        vcpus,
        memory_mib,
        kernel_cmdline_extras,
    })
}

fn parse_run(text: &str) -> Result<HostVmRequest, ParseError> {
    let job_id = find_string_value(text, "job_id").ok_or(ParseError::MissingRunField("job_id"))?;
    let job_dir_relpath = find_string_value(text, "job_dir_relpath")
        .ok_or(ParseError::MissingRunField("job_dir_relpath"))?;
    let job = parse_job(text)?;
    Ok(HostVmRequest::Run {
        job_id,
        job,
        job_dir_relpath,
    })
}

fn parse_job(text: &str) -> Result<BuilderJob, ParseError> {
    // Externally-tagged enum: look for `"Flake":` or `"Install":`
    // marker inside the `"job":` object. Use marker-bracketed
    // searches rather than full JSON parsing; the wire is closed
    // and the marker can't appear in a string value because of
    // JSON's escape rules (`"` inside a string is `\"`, never bare).
    if contains_object_marker(text, "Flake") {
        let flake_ref =
            find_string_value(text, "flake_ref").ok_or(ParseError::MissingJobField("flake_ref"))?;
        let attr_path =
            find_string_value(text, "attr_path").ok_or(ParseError::MissingJobField("attr_path"))?;
        Ok(BuilderJob::Flake {
            flake_ref,
            attr_path,
        })
    } else if contains_object_marker(text, "Install") {
        let spec_path =
            find_string_value(text, "spec_path").ok_or(ParseError::MissingJobField("spec_path"))?;
        Ok(BuilderJob::Install { spec_path })
    } else {
        Err(ParseError::UnknownJobVariant)
    }
}

/// Locate a marker like `"Flake":` or `"Install":` in the text.
/// Allows for optional whitespace between the colon and the
/// following `{`. The marker can only appear at object-key
/// position because the surrounding `"` chars would otherwise be
/// escaped (JSON strings can't contain unescaped `"`).
fn contains_object_marker(text: &str, key: &str) -> bool {
    let marker = format!("\"{key}\":");
    text.contains(&marker)
}

/// Find a JSON string value for the given key in `text`. Returns
/// the decoded value (with `\"`, `\\`, `\n`, `\r`, `\t`, `\b`,
/// `\f`, and `\u{XXXX}` escapes processed) or `None` if the key
/// isn't present at any object position.
///
/// Only handles top-level-style keys: scans for `"key":` followed
/// by optional whitespace and a `"..."`-delimited string. Doesn't
/// walk the JSON tree, so if `"key"` appears twice at different
/// nesting levels the first match wins. Sufficient for the closed
/// `HostVmRequest` shape: each key (`kind`, `job_id`,
/// `job_dir_relpath`, `flake_ref`, `attr_path`, `spec_path`) only
/// appears once in any valid request.
fn find_string_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let mut search_from = 0;
    while let Some(idx) = text[search_from..].find(&needle) {
        let after = search_from + idx + needle.len();
        let rest = text[after..].trim_start();
        // Must be followed by an opening quote — otherwise the value
        // isn't a string (could be a number, object, etc.) and we
        // don't handle it here.
        if let Some(stripped) = rest.strip_prefix('"') {
            return Some(decode_json_string(stripped));
        }
        search_from = after;
    }
    None
}

/// Find a JSON unsigned-integer value for the given key. Scans for
/// `"key":`, skips whitespace, and parses the leading run of ASCII
/// digits as a `u32`. Returns `None` if the key is absent, the
/// value isn't a bare number, or it overflows `u32`. Sufficient for
/// the closed workload payload (`vcpus`, `memory_mib`), which serde
/// emits as bare JSON numbers.
fn find_u32_value(text: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{key}\":");
    let mut search_from = 0;
    while let Some(idx) = text[search_from..].find(&needle) {
        let after = search_from + idx + needle.len();
        let rest = text[after..].trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return digits.parse::<u32>().ok();
        }
        search_from = after;
    }
    None
}

/// Decode a JSON string starting at the byte after the opening
/// `"`. Returns the decoded contents up to (but excluding) the
/// matching closing `"`. Unknown escape sequences are passed
/// through literally — better to surface a bad input than to
/// silently drop a byte the host meant to send.
fn decode_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\x08'),
                Some('f') => out.push('\x0c'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16)
                        && let Some(ch) = char::from_u32(code)
                    {
                        out.push(ch);
                    }
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => break,
            },
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_FLAKE_RUN: &str = r#"{"kind":"run","job_id":"00000000-0000-0000-0000-000000000001","job":{"Flake":{"flake_ref":"path:/work","attr_path":"packages.aarch64-linux.default"}},"job_dir_relpath":"jobs/abc"}"#;

    const SAMPLE_INSTALL_RUN: &str = r#"{"kind":"run","job_id":"00000000-0000-0000-0000-000000000002","job":{"Install":{"spec_path":"/job/install_spec.json"}},"job_dir_relpath":"jobs/def"}"#;

    const SAMPLE_SHUTDOWN: &str = r#"{"kind":"shutdown"}"#;

    #[test]
    fn parses_shutdown() {
        assert_eq!(
            parse(SAMPLE_SHUTDOWN.as_bytes()).unwrap(),
            HostVmRequest::Shutdown
        );
    }

    #[test]
    fn parses_flake_run() {
        let parsed = parse(SAMPLE_FLAKE_RUN.as_bytes()).unwrap();
        match parsed {
            HostVmRequest::Run {
                job_id,
                job,
                job_dir_relpath,
            } => {
                assert_eq!(job_id, "00000000-0000-0000-0000-000000000001");
                assert_eq!(job_dir_relpath, "jobs/abc");
                match job {
                    BuilderJob::Flake {
                        flake_ref,
                        attr_path,
                    } => {
                        assert_eq!(flake_ref, "path:/work");
                        assert_eq!(attr_path, "packages.aarch64-linux.default");
                    }
                    other => panic!("expected Flake, got {other:?}"),
                }
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parses_install_run() {
        let parsed = parse(SAMPLE_INSTALL_RUN.as_bytes()).unwrap();
        match parsed {
            HostVmRequest::Run { job_id, job, .. } => {
                assert_eq!(job_id, "00000000-0000-0000-0000-000000000002");
                match job {
                    BuilderJob::Install { spec_path } => {
                        assert_eq!(spec_path, "/job/install_spec.json");
                    }
                    other => panic!("expected Install, got {other:?}"),
                }
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn decodes_escapes_in_string_values() {
        let json = r#"{"kind":"run","job_id":"x","job":{"Flake":{"flake_ref":"line1\nline2\\back\"quote","attr_path":"y"}},"job_dir_relpath":"z"}"#;
        let parsed = parse(json.as_bytes()).unwrap();
        if let HostVmRequest::Run {
            job: BuilderJob::Flake { flake_ref, .. },
            ..
        } = parsed
        {
            assert_eq!(flake_ref, "line1\nline2\\back\"quote");
        } else {
            panic!("expected Flake run");
        }
    }

    #[test]
    fn rejects_unknown_kind() {
        let json = r#"{"kind":"hello"}"#;
        match parse(json.as_bytes()).unwrap_err() {
            ParseError::UnknownKind(k) => assert_eq!(k, "hello"),
            other => panic!("expected UnknownKind, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_kind() {
        let json = r#"{"job_id":"x"}"#;
        assert!(matches!(
            parse(json.as_bytes()).unwrap_err(),
            ParseError::MissingKind
        ));
    }

    #[test]
    fn rejects_missing_run_field() {
        let json =
            r#"{"kind":"run","job_id":"x","job":{"Flake":{"flake_ref":"a","attr_path":"b"}}}"#;
        match parse(json.as_bytes()).unwrap_err() {
            ParseError::MissingRunField("job_dir_relpath") => {}
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_job_variant() {
        let json = r#"{"kind":"run","job_id":"x","job":{"Bogus":{"flake_ref":"a","attr_path":"b"}},"job_dir_relpath":"z"}"#;
        assert!(matches!(
            parse(json.as_bytes()).unwrap_err(),
            ParseError::UnknownJobVariant
        ));
    }

    /// **The cross-validation test.** What the host's serde-derived
    /// writer (`mvm_build::builder_protocol::HostVmRequest` →
    /// `mvm_guest::vsock::write_frame`) emits must parse cleanly
    /// via this hand-rolled parser. Any schema drift on either side
    /// trips this test and that's the signal to resync.
    #[test]
    fn parses_what_mvm_build_serializes_with_serde() {
        use mvm_build::builder_protocol::{HostVmRequest as HostReq, JobId};
        use mvm_build::builder_vm::BuilderJob as HostJob;

        // Flake run
        let req = HostReq::Run {
            job_id: JobId(uuid::Uuid::nil()),
            job: HostJob::Flake {
                flake_ref: "path:/work".to_string(),
                attr_path: "packages.aarch64-linux.default".to_string(),
            },
            job_dir_relpath: "abc".to_string(),
        };
        let json = serde_json::to_vec(&req).expect("serialize");
        let parsed = parse(&json).expect("parse");
        match parsed {
            HostVmRequest::Run {
                job_id,
                job,
                job_dir_relpath,
            } => {
                assert_eq!(job_id, "00000000-0000-0000-0000-000000000000");
                assert_eq!(job_dir_relpath, "abc");
                match job {
                    BuilderJob::Flake {
                        flake_ref,
                        attr_path,
                    } => {
                        assert_eq!(flake_ref, "path:/work");
                        assert_eq!(attr_path, "packages.aarch64-linux.default");
                    }
                    other => panic!("got {other:?}"),
                }
            }
            other => panic!("got {other:?}"),
        }

        // Install run
        let req = HostReq::Run {
            job_id: JobId::new(),
            job: HostJob::Install {
                spec_path: "/job/spec.json".into(),
            },
            job_dir_relpath: "deadbeef".to_string(),
        };
        let json = serde_json::to_vec(&req).expect("serialize");
        let parsed = parse(&json).expect("parse");
        if let HostVmRequest::Run {
            job: BuilderJob::Install { spec_path },
            ..
        } = parsed
        {
            assert_eq!(spec_path, "/job/spec.json");
        } else {
            panic!("expected Install");
        }

        // Shutdown
        let req = HostReq::Shutdown {};
        let json = serde_json::to_vec(&req).expect("serialize");
        let parsed = parse(&json).expect("parse");
        assert_eq!(parsed, HostVmRequest::Shutdown);
    }

    const SAMPLE_WORKLOAD_START: &str = r#"{"kind":"workload_start","workload_id":"00000000-0000-0000-0000-000000000009","kernel_path":"/job/workload/vmlinux","rootfs_path":"/job/workload/rootfs.ext4","vsock_socket_dir":"/var/lib/mvm/workloads","vcpus":2,"memory_mib":1024,"kernel_cmdline_extras":"root=/dev/vda ro init=/init"}"#;

    #[test]
    fn parses_workload_start_full_payload() {
        match parse(SAMPLE_WORKLOAD_START.as_bytes()).unwrap() {
            HostVmRequest::WorkloadStart {
                workload_id,
                kernel_path,
                rootfs_path,
                vsock_socket_dir,
                vcpus,
                memory_mib,
                kernel_cmdline_extras,
            } => {
                assert_eq!(workload_id, "00000000-0000-0000-0000-000000000009");
                assert_eq!(kernel_path, "/job/workload/vmlinux");
                assert_eq!(rootfs_path, "/job/workload/rootfs.ext4");
                assert_eq!(vsock_socket_dir, "/var/lib/mvm/workloads");
                assert_eq!(vcpus, 2);
                assert_eq!(memory_mib, 1024);
                assert_eq!(kernel_cmdline_extras, "root=/dev/vda ro init=/init");
            }
            other => panic!("expected WorkloadStart, got {other:?}"),
        }
    }

    #[test]
    fn parses_workload_stop_and_status() {
        let stop = r#"{"kind":"workload_stop","workload_id":"abc"}"#;
        assert_eq!(
            parse(stop.as_bytes()).unwrap(),
            HostVmRequest::WorkloadStop {
                workload_id: "abc".to_string()
            }
        );
        let status = r#"{"kind":"workload_status","workload_id":"abc"}"#;
        assert_eq!(
            parse(status.as_bytes()).unwrap(),
            HostVmRequest::WorkloadStatus {
                workload_id: "abc".to_string()
            }
        );
    }

    #[test]
    fn rejects_workload_start_missing_field() {
        // Drop `rootfs_path`.
        let json = r#"{"kind":"workload_start","workload_id":"x","kernel_path":"/k","vsock_socket_dir":"/d","vcpus":1,"memory_mib":64,"kernel_cmdline_extras":""}"#;
        match parse(json.as_bytes()).unwrap_err() {
            ParseError::MissingWorkloadField("rootfs_path") => {}
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn rejects_workload_start_non_numeric_vcpus() {
        // `vcpus` is a string, not a bare number.
        let json = r#"{"kind":"workload_start","workload_id":"x","kernel_path":"/k","rootfs_path":"/r","vsock_socket_dir":"/d","vcpus":"two","memory_mib":64,"kernel_cmdline_extras":""}"#;
        match parse(json.as_bytes()).unwrap_err() {
            ParseError::BadNumber("vcpus") => {}
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn workload_start_accepts_empty_cmdline_extras() {
        let json = r#"{"kind":"workload_start","workload_id":"x","kernel_path":"/k","rootfs_path":"/r","vsock_socket_dir":"/d","vcpus":1,"memory_mib":64,"kernel_cmdline_extras":""}"#;
        match parse(json.as_bytes()).unwrap() {
            HostVmRequest::WorkloadStart {
                kernel_cmdline_extras,
                ..
            } => assert_eq!(kernel_cmdline_extras, ""),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn find_u32_value_handles_present_absent_and_overflow() {
        assert_eq!(find_u32_value(r#"{"vcpus": 4}"#, "vcpus"), Some(4));
        assert_eq!(find_u32_value(r#"{"vcpus":0}"#, "vcpus"), Some(0));
        assert_eq!(find_u32_value(r#"{"other":4}"#, "vcpus"), None);
        // > u32::MAX
        assert_eq!(find_u32_value(r#"{"vcpus":4294967296}"#, "vcpus"), None);
    }

    /// Cross-validation for the workload variants — what the host's
    /// serde writer emits must parse via this hand-rolled parser.
    #[test]
    fn parses_workload_start_serialized_by_mvm_build() {
        use mvm_build::builder_protocol::{HostVmRequest as HostReq, WorkloadId};

        let req = HostReq::WorkloadStart {
            workload_id: WorkloadId(uuid::Uuid::nil()),
            kernel_path: "/job/workload/vmlinux".to_string(),
            rootfs_path: "/job/workload/rootfs.ext4".to_string(),
            vsock_socket_dir: "/var/lib/mvm/workloads".to_string(),
            vcpus: 4,
            memory_mib: 2048,
            kernel_cmdline_extras: "root=/dev/vda ro".to_string(),
        };
        let json = serde_json::to_vec(&req).expect("serialize");
        match parse(&json).expect("parse") {
            HostVmRequest::WorkloadStart {
                workload_id,
                kernel_path,
                rootfs_path,
                vsock_socket_dir,
                vcpus,
                memory_mib,
                kernel_cmdline_extras,
            } => {
                assert_eq!(workload_id, "00000000-0000-0000-0000-000000000000");
                assert_eq!(kernel_path, "/job/workload/vmlinux");
                assert_eq!(rootfs_path, "/job/workload/rootfs.ext4");
                assert_eq!(vsock_socket_dir, "/var/lib/mvm/workloads");
                assert_eq!(vcpus, 4);
                assert_eq!(memory_mib, 2048);
                assert_eq!(kernel_cmdline_extras, "root=/dev/vda ro");
            }
            other => panic!("got {other:?}"),
        }

        // Stop + status round-trip through serde too.
        let stop = HostReq::WorkloadStop {
            workload_id: WorkloadId(uuid::Uuid::nil()),
        };
        let json = serde_json::to_vec(&stop).expect("serialize");
        assert_eq!(
            parse(&json).expect("parse"),
            HostVmRequest::WorkloadStop {
                workload_id: "00000000-0000-0000-0000-000000000000".to_string()
            }
        );
    }
}

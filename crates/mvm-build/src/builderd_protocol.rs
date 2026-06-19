//! Typed wire protocol for the resident builder-VM control plane
//! (`mvm-builderd`).
//!
//! This is the long-term replacement for the controlled-shell-job
//! channel in [`crate::builder_protocol`]
//! ([`crate::builder_protocol::HostVmRequest::Run`] carries a
//! [`crate::builder_vm::BuilderJob`]). The host keeps `mvmctl` as the
//! single control plane and drives Nix / Linux-only build work by
//! sending typed [`BuilderRequest`]s over vsock to a resident
//! `mvm-builderd` inside the builder VM, which streams structured
//! [`BuilderResponse`]s back.
//!
//! The protocol is **allowlisted, not a generic remote shell**: every
//! request names an explicit operation kind with explicit inputs and
//! outputs, so the security boundary and cache/provenance behaviour stay
//! reviewable. There is deliberately no "run this command" variant — a
//! raw shell escape, if it ever exists, lives in the legacy
//! [`crate::builder_protocol`] adapter, gated and logged, never here.
//!
//! ## Wire conventions
//!
//! Both enums are externally-tagged on `kind` with snake_case tags and
//! `#[serde(deny_unknown_fields)]` on every variant, mirroring
//! [`crate::builder_protocol`]: a newer peer shipping an extra field
//! against an older peer fails closed rather than silently dropping it.
//! Empty struct variants (`{}`) are used instead of unit variants so
//! `deny_unknown_fields` actually fires.
//!
//! ## Framing and size cap
//!
//! This protocol reuses [`mvm_guest::vsock::read_frame`] /
//! [`mvm_guest::vsock::write_frame`], inheriting their 256 KiB
//! pre-deserialize `MAX_FRAME_SIZE` (`crates/mvm-guest/src/vsock.rs`).
//! That bound rejects an adversarial length prefix before allocation,
//! and is amply sufficient for these messages — the inputs are paths,
//! flake references, and small fingerprints, never bulk artifact bytes
//! (artifacts are written to mounted output paths, and the response
//! only names them).
//!
//! ## Version negotiation
//!
//! [`Handshake`] carries [`PROTOCOL_VERSION`]. The daemon answers a
//! handshake by [`negotiate`]-ing the caller's version against its own
//! supported set; an unsupported version is refused fail-closed with a
//! [`BuilderResponse::Failed`] carrying [`FailureCategory::Version`],
//! never by guessing a wire shape.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema version of this protocol. Bumped on any
/// backwards-incompatible change to [`BuilderRequest`] /
/// [`BuilderResponse`]. The host stamps it into every [`Handshake`];
/// the daemon refuses versions it does not support.
pub const PROTOCOL_VERSION: u32 = 1;

/// Per-operation identifier the host stamps before sending a
/// [`BuilderRequest`]. The daemon echoes it in every
/// [`BuilderResponse`] for that operation so progress, logs, the
/// terminal result, and cancellation all correlate to one operation.
///
/// `Uuid` v4 because the host mints these; the daemon only validates
/// that a response id matches an outstanding request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationId(pub Uuid);

impl OperationId {
    /// Mint a fresh operation id. Used by the host's dispatch path.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for OperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Inbound message sent host → `mvm-builderd` over the builder VM's
/// resident control vsock port.
///
/// Every non-handshake variant carries an [`OperationId`] so the
/// daemon can stream progress/log/result frames back correlated to the
/// originating request and the host can cancel an in-flight operation
/// by id. The set of variants is the *stable allowlist* — adding a new
/// build/eval capability means adding a variant here, not widening a
/// shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BuilderRequest {
    /// First message on a fresh connection. Establishes the protocol
    /// version both sides will speak. The daemon replies with
    /// [`BuilderResponse::Accepted`] on a supported version or
    /// [`BuilderResponse::Failed`] / [`FailureCategory::Version`] on an
    /// unsupported one.
    Handshake {
        /// The host's [`PROTOCOL_VERSION`].
        protocol_version: u32,
    },

    /// Liveness / readiness probe. The daemon answers with a
    /// [`BuilderResponse::Accepted`] for the same operation id. Used by
    /// `mvmctl doctor` and the host client's readiness wait.
    Probe {
        /// Host-minted id echoed in the matching response.
        op: OperationId,
    },

    /// Evaluate `nix flake check` against a flake the host has staged
    /// into a mounted source share inside the builder VM.
    FlakeCheck {
        /// Host-minted id echoed in every response for this operation.
        op: OperationId,
        /// Path, *inside the builder VM*, to the flake directory the
        /// host staged into a mounted source share.
        flake_path: String,
    },

    /// Build a microVM guest image from a flake attribute.
    BuildGuestImage {
        /// Host-minted id echoed in every response for this operation.
        op: OperationId,
        /// Flake reference resolved by the host (e.g.
        /// `git+file:///work?dir=.`).
        flake_ref: String,
        /// Attribute path under the flake, system-resolved by the host
        /// (e.g. `packages.aarch64-linux.default`).
        attr_path: String,
        /// Optional cache-key/fingerprint input the host computed for
        /// this image so the daemon can short-circuit to a warm store
        /// path. `None` disables the short-circuit.
        fingerprint: Option<String>,
    },

    /// Build a source-built host tool package (e.g. the embedded
    /// builder-VM binaries) from a flake attribute. Same shape as
    /// [`Self::BuildGuestImage`] but a distinct variant so the daemon
    /// and audit trail keep guest-image and host-tool builds separate.
    BuildHostTool {
        /// Host-minted id echoed in every response for this operation.
        op: OperationId,
        /// Flake reference resolved by the host.
        flake_ref: String,
        /// Attribute path under the flake, system-resolved by the host.
        attr_path: String,
        /// Optional cache-key/fingerprint input. See
        /// [`Self::BuildGuestImage::fingerprint`].
        fingerprint: Option<String>,
    },

    /// Prefetch a source into the builder Nix store so a later build
    /// does not have to fetch it. Removes ad hoc host-side probing.
    PrefetchSource {
        /// Host-minted id echoed in every response for this operation.
        op: OperationId,
        /// Source reference to prefetch (flake/url/store input the host
        /// resolved).
        source_ref: String,
    },

    /// Query whether a store path is already present in the builder Nix
    /// store, so the host can decide whether a build is needed without
    /// shelling out.
    QueryStorePath {
        /// Host-minted id echoed in the matching response.
        op: OperationId,
        /// The `/nix/store/...` path to look up.
        store_path: String,
    },

    /// Cancel an in-flight operation by id. The daemon stops the
    /// operation and replies with [`BuilderResponse::Cancelled`] for
    /// `target`. Cancelling an unknown/finished id is a no-op the
    /// daemon still acknowledges.
    CancelJob {
        /// Id of the operation to cancel (a previously-sent `op`).
        target: OperationId,
    },
}

/// Outbound message sent `mvm-builderd` → host over the same vsock
/// connection. Every variant carries the [`OperationId`] it belongs to
/// so the host can demultiplex concurrent operations.
///
/// A given operation produces zero-or-more [`Self::Progress`] /
/// [`Self::LogChunk`] frames, then exactly one terminal frame:
/// [`Self::ArtifactReady`], [`Self::StorePathReady`], [`Self::Failed`],
/// or [`Self::Cancelled`]. [`Self::Accepted`] is the immediate
/// acknowledgement for [`BuilderRequest::Handshake`] and
/// [`BuilderRequest::Probe`].
///
/// No `Eq`: [`Self::Progress`] carries an `f32` fraction. `PartialEq`
/// is enough for the wire roundtrip tests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BuilderResponse {
    /// Request accepted. For a [`BuilderRequest::Handshake`] this also
    /// reports the version the daemon agreed to speak; for a
    /// [`BuilderRequest::Probe`] it is the readiness acknowledgement.
    Accepted {
        /// The operation this acknowledges. The handshake reply uses
        /// the nil id (the handshake has no operation id of its own);
        /// a probe reply echoes the probe's id.
        op: OperationId,
        /// Protocol version the daemon will speak for this connection.
        protocol_version: u32,
    },

    /// Structured progress for an in-flight operation. Carries a
    /// machine-readable fraction and a short human label rather than
    /// free-form stderr, so the host renders a uniform progress UI.
    Progress {
        /// The operation this progress belongs to.
        op: OperationId,
        /// Completion in `[0.0, 1.0]`, best-effort. The daemon may send
        /// monotonically increasing values; the host treats a missing
        /// or out-of-range value as indeterminate.
        fraction: f32,
        /// Short human-readable phase label (e.g. `"evaluating"`,
        /// `"building 12/47"`).
        label: String,
    },

    /// A bounded chunk of build log output for an operation. Distinct
    /// from [`Self::Progress`] so the host can route raw logs to a file
    /// while rendering progress separately. Redaction posture is the
    /// daemon's responsibility before the chunk is sent.
    LogChunk {
        /// The operation this log belongs to.
        op: OperationId,
        /// A slice of log text (no framing guarantees about line
        /// boundaries; the host concatenates).
        text: String,
    },

    /// Terminal success: the operation produced an artifact at a
    /// mounted output path the host can read.
    ArtifactReady {
        /// The operation that produced this artifact.
        op: OperationId,
        /// Path, *inside the builder VM's mounted output share*, to the
        /// produced artifact. The host resolves it to its host-side
        /// mount.
        artifact_path: String,
        /// Resolved `/nix/store/...` path backing the artifact, when
        /// applicable, for provenance. `None` for non-store outputs.
        store_path: Option<String>,
    },

    /// Terminal success for an operation whose result is a store path
    /// rather than a copied artifact (e.g.
    /// [`BuilderRequest::PrefetchSource`] /
    /// [`BuilderRequest::QueryStorePath`]).
    StorePathReady {
        /// The operation this resolves.
        op: OperationId,
        /// The resolved `/nix/store/...` path.
        store_path: String,
        /// Whether the path was already present in the store
        /// (`true`) or had to be built/fetched (`false`). Lets a
        /// [`BuilderRequest::QueryStorePath`] report presence without a
        /// separate variant.
        already_present: bool,
    },

    /// Terminal failure. Carries a *stable* [`FailureCategory`] so the
    /// host shows actionable messages without parsing arbitrary stderr,
    /// plus a human-readable detail and a retryability hint.
    Failed {
        /// The operation that failed. The handshake-version refusal
        /// uses the nil id.
        op: OperationId,
        /// Stable machine-readable failure class.
        category: FailureCategory,
        /// Human-readable detail for logs / surfacing.
        message: String,
        /// Whether the host may retry the same request unchanged.
        retryable: bool,
    },

    /// Terminal success for an operation that produces neither an
    /// artifact nor a store path — it either passed or failed, and it
    /// passed (e.g. [`BuilderRequest::FlakeCheck`]). A `Failed` is the
    /// negative counterpart.
    Completed {
        /// The operation that completed successfully.
        op: OperationId,
    },

    /// Terminal acknowledgement that an operation was cancelled in
    /// response to a [`BuilderRequest::CancelJob`].
    Cancelled {
        /// The operation that was cancelled.
        op: OperationId,
    },
}

/// Stable failure classification carried by [`BuilderResponse::Failed`].
///
/// The string tags are part of the wire contract: the host matches on
/// the category to choose a message and a retry posture, so renaming a
/// variant tag is a breaking change. `Unknown` is the catch-all the
/// daemon uses when no narrower category applies; the host treats it as
/// non-retryable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    /// The caller's [`PROTOCOL_VERSION`] is not supported by the
    /// daemon. Fail-closed; not retryable without a client change.
    Version,
    /// The request named an input the daemon rejected before running
    /// (missing/invalid path, malformed reference, disallowed shape).
    InvalidRequest,
    /// A Nix evaluation failed (flake check / attribute resolution).
    NixEval,
    /// A Nix build failed after a successful evaluation.
    NixBuild,
    /// Fetching a source/input failed (network, missing input).
    Fetch,
    /// The operation exceeded its time budget.
    Timeout,
    /// An internal daemon error not attributable to the request.
    Internal,
    /// The operation kind is recognized and well-formed, but this
    /// daemon build does not implement it (skeleton stage or a request
    /// from a newer host). Distinct from [`Self::Version`]: the
    /// protocol version matched, only this one operation is missing.
    /// Non-retryable against the same daemon.
    Unsupported,
    /// Catch-all when no narrower category applies. Non-retryable.
    Unknown,
}

/// Negotiate the protocol version a [`BuilderRequest::Handshake`]
/// proposes against this build's [`PROTOCOL_VERSION`].
///
/// Returns the agreed version on success. Returns the *requested*
/// version on refusal (`Err`) so the caller can report it. The policy
/// is exact-match for v1 — there is no backwards range yet, so any
/// version other than [`PROTOCOL_VERSION`] is refused fail-closed.
/// Widening to a supported range is a deliberate future change with its
/// own tests, not a silent accept.
pub fn negotiate(requested: u32) -> Result<u32, u32> {
    if requested == PROTOCOL_VERSION {
        Ok(PROTOCOL_VERSION)
    } else {
        Err(requested)
    }
}

/// Build the daemon's reply to a [`BuilderRequest::Handshake`] carrying
/// `requested`: an [`BuilderResponse::Accepted`] on a supported version
/// or a fail-closed [`BuilderResponse::Failed`] /
/// [`FailureCategory::Version`] otherwise.
///
/// The handshake has no operation id of its own, so both replies use
/// the nil [`OperationId`].
pub fn handshake_reply(requested: u32) -> BuilderResponse {
    match negotiate(requested) {
        Ok(version) => BuilderResponse::Accepted {
            op: OperationId(Uuid::nil()),
            protocol_version: version,
        },
        Err(bad) => BuilderResponse::Failed {
            op: OperationId(Uuid::nil()),
            category: FailureCategory::Version,
            message: format!(
                "unsupported builder protocol version {bad}; this daemon speaks {PROTOCOL_VERSION}"
            ),
            retryable: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T) -> T
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let bytes = serde_json::to_vec(value).expect("serialize");
        let back: T = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(value, &back, "wire roundtrip mismatch");
        back
    }

    fn op() -> OperationId {
        OperationId(Uuid::nil())
    }

    // ---- request roundtrips --------------------------------------------

    #[test]
    fn handshake_roundtrips() {
        roundtrip(&BuilderRequest::Handshake {
            protocol_version: PROTOCOL_VERSION,
        });
    }

    #[test]
    fn probe_roundtrips() {
        roundtrip(&BuilderRequest::Probe { op: op() });
    }

    #[test]
    fn flake_check_roundtrips() {
        roundtrip(&BuilderRequest::FlakeCheck {
            op: op(),
            flake_path: "/work/nix".to_string(),
        });
    }

    #[test]
    fn build_guest_image_roundtrips() {
        roundtrip(&BuilderRequest::BuildGuestImage {
            op: op(),
            flake_ref: "git+file:///work?dir=.".to_string(),
            attr_path: "packages.aarch64-linux.default".to_string(),
            fingerprint: Some("blake3:abcd".to_string()),
        });
        // None branch of the optional fingerprint.
        roundtrip(&BuilderRequest::BuildGuestImage {
            op: op(),
            flake_ref: "path:.".to_string(),
            attr_path: "packages.x86_64-linux.worker".to_string(),
            fingerprint: None,
        });
    }

    #[test]
    fn build_host_tool_roundtrips() {
        roundtrip(&BuilderRequest::BuildHostTool {
            op: op(),
            flake_ref: "path:.".to_string(),
            attr_path: "packages.aarch64-linux.mvm-host-vm-init".to_string(),
            fingerprint: None,
        });
    }

    #[test]
    fn prefetch_source_roundtrips() {
        roundtrip(&BuilderRequest::PrefetchSource {
            op: op(),
            source_ref: "github:nixos/nixpkgs/nixos-unstable".to_string(),
        });
    }

    #[test]
    fn query_store_path_roundtrips() {
        roundtrip(&BuilderRequest::QueryStorePath {
            op: op(),
            store_path: "/nix/store/aaaa-foo".to_string(),
        });
    }

    #[test]
    fn cancel_job_roundtrips() {
        roundtrip(&BuilderRequest::CancelJob { target: op() });
    }

    // ---- response roundtrips -------------------------------------------

    #[test]
    fn accepted_roundtrips() {
        roundtrip(&BuilderResponse::Accepted {
            op: op(),
            protocol_version: PROTOCOL_VERSION,
        });
    }

    #[test]
    fn progress_roundtrips() {
        roundtrip(&BuilderResponse::Progress {
            op: op(),
            fraction: 0.42,
            label: "building 12/47".to_string(),
        });
    }

    #[test]
    fn log_chunk_roundtrips() {
        roundtrip(&BuilderResponse::LogChunk {
            op: op(),
            text: "warning: dirty tree\n".to_string(),
        });
    }

    #[test]
    fn artifact_ready_roundtrips() {
        roundtrip(&BuilderResponse::ArtifactReady {
            op: op(),
            artifact_path: "/out/rootfs.ext4".to_string(),
            store_path: Some("/nix/store/bbbb-image".to_string()),
        });
        roundtrip(&BuilderResponse::ArtifactReady {
            op: op(),
            artifact_path: "/out/kernel".to_string(),
            store_path: None,
        });
    }

    #[test]
    fn store_path_ready_roundtrips() {
        roundtrip(&BuilderResponse::StorePathReady {
            op: op(),
            store_path: "/nix/store/cccc-src".to_string(),
            already_present: true,
        });
    }

    #[test]
    fn failed_roundtrips_every_category() {
        for category in [
            FailureCategory::Version,
            FailureCategory::InvalidRequest,
            FailureCategory::NixEval,
            FailureCategory::NixBuild,
            FailureCategory::Fetch,
            FailureCategory::Timeout,
            FailureCategory::Internal,
            FailureCategory::Unsupported,
            FailureCategory::Unknown,
        ] {
            roundtrip(&BuilderResponse::Failed {
                op: op(),
                category,
                message: "boom".to_string(),
                retryable: false,
            });
        }
    }

    #[test]
    fn completed_roundtrips() {
        roundtrip(&BuilderResponse::Completed { op: op() });
    }

    #[test]
    fn cancelled_roundtrips() {
        roundtrip(&BuilderResponse::Cancelled { op: op() });
    }

    // ---- wire-tag stability --------------------------------------------

    #[test]
    fn request_kind_tags_are_stable_snake_case() {
        let cases = [
            (
                serde_json::to_value(BuilderRequest::Handshake {
                    protocol_version: 1,
                })
                .unwrap(),
                "handshake",
            ),
            (
                serde_json::to_value(BuilderRequest::Probe { op: op() }).unwrap(),
                "probe",
            ),
            (
                serde_json::to_value(BuilderRequest::FlakeCheck {
                    op: op(),
                    flake_path: "x".to_string(),
                })
                .unwrap(),
                "flake_check",
            ),
            (
                serde_json::to_value(BuilderRequest::BuildGuestImage {
                    op: op(),
                    flake_ref: "x".to_string(),
                    attr_path: "y".to_string(),
                    fingerprint: None,
                })
                .unwrap(),
                "build_guest_image",
            ),
            (
                serde_json::to_value(BuilderRequest::BuildHostTool {
                    op: op(),
                    flake_ref: "x".to_string(),
                    attr_path: "y".to_string(),
                    fingerprint: None,
                })
                .unwrap(),
                "build_host_tool",
            ),
            (
                serde_json::to_value(BuilderRequest::PrefetchSource {
                    op: op(),
                    source_ref: "x".to_string(),
                })
                .unwrap(),
                "prefetch_source",
            ),
            (
                serde_json::to_value(BuilderRequest::QueryStorePath {
                    op: op(),
                    store_path: "x".to_string(),
                })
                .unwrap(),
                "query_store_path",
            ),
            (
                serde_json::to_value(BuilderRequest::CancelJob { target: op() }).unwrap(),
                "cancel_job",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(value["kind"], expected, "request tag drift: {value}");
        }
    }

    #[test]
    fn response_kind_tags_are_stable_snake_case() {
        let cases = [
            (
                serde_json::to_value(BuilderResponse::Accepted {
                    op: op(),
                    protocol_version: 1,
                })
                .unwrap(),
                "accepted",
            ),
            (
                serde_json::to_value(BuilderResponse::Progress {
                    op: op(),
                    fraction: 0.0,
                    label: "x".to_string(),
                })
                .unwrap(),
                "progress",
            ),
            (
                serde_json::to_value(BuilderResponse::LogChunk {
                    op: op(),
                    text: "x".to_string(),
                })
                .unwrap(),
                "log_chunk",
            ),
            (
                serde_json::to_value(BuilderResponse::ArtifactReady {
                    op: op(),
                    artifact_path: "x".to_string(),
                    store_path: None,
                })
                .unwrap(),
                "artifact_ready",
            ),
            (
                serde_json::to_value(BuilderResponse::StorePathReady {
                    op: op(),
                    store_path: "x".to_string(),
                    already_present: false,
                })
                .unwrap(),
                "store_path_ready",
            ),
            (
                serde_json::to_value(BuilderResponse::Failed {
                    op: op(),
                    category: FailureCategory::Unknown,
                    message: "x".to_string(),
                    retryable: false,
                })
                .unwrap(),
                "failed",
            ),
            (
                serde_json::to_value(BuilderResponse::Completed { op: op() }).unwrap(),
                "completed",
            ),
            (
                serde_json::to_value(BuilderResponse::Cancelled { op: op() }).unwrap(),
                "cancelled",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(value["kind"], expected, "response tag drift: {value}");
        }
    }

    #[test]
    fn failure_category_tags_are_stable_snake_case() {
        let cases = [
            (FailureCategory::Version, "version"),
            (FailureCategory::InvalidRequest, "invalid_request"),
            (FailureCategory::NixEval, "nix_eval"),
            (FailureCategory::NixBuild, "nix_build"),
            (FailureCategory::Fetch, "fetch"),
            (FailureCategory::Timeout, "timeout"),
            (FailureCategory::Internal, "internal"),
            (FailureCategory::Unsupported, "unsupported"),
            (FailureCategory::Unknown, "unknown"),
        ];
        for (category, expected) in cases {
            assert_eq!(serde_json::to_value(category).unwrap(), expected);
        }
    }

    #[test]
    fn operation_id_serializes_as_bare_uuid_string() {
        let json = serde_json::to_string(&OperationId(Uuid::nil())).expect("serialize");
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
    }

    // ---- deny_unknown_fields fail-closed -------------------------------

    #[test]
    fn deny_unknown_fields_rejects_extra_request_field() {
        let bad = serde_json::json!({
            "kind": "flake_check",
            "op": "00000000-0000-0000-0000-000000000000",
            "flake_path": "/work/nix",
            "future_field": 42,
        });
        let res: Result<BuilderRequest, _> = serde_json::from_value(bad);
        assert!(res.is_err(), "must reject future_field, got {res:?}");
    }

    #[test]
    fn deny_unknown_fields_rejects_extra_response_field() {
        let bad = serde_json::json!({
            "kind": "accepted",
            "op": "00000000-0000-0000-0000-000000000000",
            "protocol_version": 1,
            "future_field": "rogue",
        });
        let res: Result<BuilderResponse, _> = serde_json::from_value(bad);
        assert!(res.is_err(), "must reject future_field, got {res:?}");
    }

    #[test]
    fn unknown_request_kind_is_rejected() {
        // A future request variant against an older daemon fails
        // closed rather than being silently ignored.
        let bad = serde_json::json!({
            "kind": "exec_shell",
            "op": "00000000-0000-0000-0000-000000000000",
            "cmd": "rm -rf /",
        });
        let res: Result<BuilderRequest, _> = serde_json::from_value(bad);
        assert!(res.is_err(), "unknown kind must be rejected, got {res:?}");
    }

    // ---- version negotiation -------------------------------------------

    #[test]
    fn negotiate_accepts_current_version() {
        assert_eq!(negotiate(PROTOCOL_VERSION), Ok(PROTOCOL_VERSION));
    }

    #[test]
    fn negotiate_refuses_other_versions_fail_closed() {
        assert_eq!(negotiate(0), Err(0));
        assert_eq!(negotiate(PROTOCOL_VERSION + 1), Err(PROTOCOL_VERSION + 1));
        assert_eq!(negotiate(9999), Err(9999));
    }

    #[test]
    fn handshake_reply_accepts_supported_version() {
        match handshake_reply(PROTOCOL_VERSION) {
            BuilderResponse::Accepted {
                op,
                protocol_version,
            } => {
                assert_eq!(op, OperationId(Uuid::nil()));
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn handshake_reply_refuses_unsupported_version_with_version_category() {
        match handshake_reply(PROTOCOL_VERSION + 1) {
            BuilderResponse::Failed {
                op,
                category,
                retryable,
                ..
            } => {
                assert_eq!(op, OperationId(Uuid::nil()));
                assert_eq!(category, FailureCategory::Version);
                assert!(!retryable, "a version mismatch is not retryable as-is");
            }
            other => panic!("expected Failed/Version, got {other:?}"),
        }
    }
}

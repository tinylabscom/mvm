// `anyhow` is used only by the hostd-transport async fns below.
#[cfg(feature = "hostd-transport")]
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::instance::VolumeAttach;
use crate::tenant::TenantNet;

/// Default Unix domain socket path for hostd.
pub const HOSTD_SOCKET_PATH: &str = "/run/mvm/hostd.sock";

/// Maximum frame size for hostd IPC (1 MiB).
#[cfg(feature = "hostd-transport")]
const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Wire-protocol version for hostd IPC (mvmd ↔ mvm-hostd Unix-socket
/// control channel).
///
/// **Bump policy.** Increment when ANY of the following change in a
/// way that's not backward-compatible with a peer at the previous
/// version:
///
/// - A new `HostdRequest` or `HostdResponse` variant is added that
///   older peers can't downgrade or ignore gracefully (most variant
///   additions are forward-compat because serde rejects unknown
///   variants on the receive side — so adding usually requires a
///   bump unless deliberately gated by feature negotiation).
/// - A field is added to an existing variant in a position that
///   shifts wire layout (serde JSON is name-keyed so this is rare).
/// - A field's semantic meaning changes (same name, different
///   semantics — e.g., `timeout_secs` previously meant total but
///   now means per-attempt).
/// - The frame encoding shifts (e.g., switching from
///   length-prefixed JSON to CBOR).
///
/// **Don't bump for:** new fields with `#[serde(default)]`, new
/// variants that older clients refuse cleanly with a typed error,
/// or comments / docstrings / internal helpers.
///
/// The mvmd repo's `tests/mvmd_compat.rs` pins this against
/// frozen-byte fixtures for `AgentRequest::Reconcile`,
/// `HostdRequest::Start`, and `HostdResponse::Started`, so a PR
/// that shifts the wire format without bumping this constant fails
/// CI on the mvmd side. The fixtures live next to the test;
/// regenerate them in the same commit that bumps the version.
///
/// **History:**
/// - `1`: initial shape.
/// - `2`: workspace-volume attach — `workspace_id` threaded through
///   every instance-scoped `HostdRequest` variant and `volumes:
///   Vec<VolumeAttach>` added to `StartInstance`. All new fields are
///   `#[serde(default)]` so old payloads still deserialize; the bump
///   forces mvmd-side fixture refresh because byte output changes
///   when defaults are present (JSON keys appear with default values).
pub const PROTOCOL_VERSION: u32 = 2;

// ============================================================================
// Request/Response types
// ============================================================================

/// Request from agentd to hostd (privileged executor).
///
/// Each variant maps to exactly one privileged operation. The agentd
/// (unprivileged) decides WHAT to do; hostd (privileged) decides HOW.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostdRequest {
    /// Start an existing instance (TAP, cgroup, jailer, FC launch).
    StartInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        /// Workspace owning the instance (PROTOCOL_VERSION 2+).
        /// `None` for legacy sandbox-class instances created before
        /// workspace identity was threaded through.
        #[serde(default)]
        workspace_id: Option<String>,
        /// Workspace-scoped volumes to attach at start
        /// (PROTOCOL_VERSION 2+). Wiring into the Firecracker config
        /// happens mvmd-side in `mvmd_runtime::vm::workspace::*`.
        #[serde(default)]
        volumes: Vec<VolumeAttach>,
    },
    /// Stop a running instance (kill FC, teardown cgroup, TAP).
    StopInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        /// Workspace owning the instance (PROTOCOL_VERSION 2+).
        #[serde(default)]
        workspace_id: Option<String>,
    },
    /// Snapshot and suspend an instance.
    SleepInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        force: bool,
        #[serde(default)]
        drain_timeout_secs: Option<u64>,
        /// Workspace owning the instance (PROTOCOL_VERSION 2+).
        #[serde(default)]
        workspace_id: Option<String>,
    },
    /// Restore an instance from snapshot.
    WakeInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        /// Workspace owning the instance (PROTOCOL_VERSION 2+).
        #[serde(default)]
        workspace_id: Option<String>,
    },
    /// Destroy an instance and optionally wipe volumes.
    DestroyInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        wipe_volumes: bool,
        /// Workspace owning the instance (PROTOCOL_VERSION 2+).
        #[serde(default)]
        workspace_id: Option<String>,
    },
    /// Create per-tenant bridge and NAT rules.
    SetupNetwork { tenant_id: String, net: TenantNet },
    /// Tear down per-tenant bridge and NAT rules.
    TeardownNetwork { tenant_id: String, net: TenantNet },
    /// Health check.
    Ping,
}

/// Response from hostd to agentd.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostdResponse {
    /// Operation succeeded.
    Ok,
    /// Error with description.
    Error { message: String },
    /// Pong response to Ping.
    Pong,
}

// ============================================================================
// Frame protocol (length-prefixed JSON over Unix socket)
//
// The hostd IPC async transport. Gated behind
// `hostd-transport` so the default `mvm-core` build carries no tokio; the
// `HostdRequest`/`HostdResponse` types above stay unconditional. mvmd
// consumes these via the `mvmctl::core::protocol` facade.
// ============================================================================

/// Read a length-prefixed JSON frame from a tokio AsyncRead.
#[cfg(feature = "hostd-transport")]
pub async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .with_context(|| "Failed to read frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE {
        anyhow::bail!("Frame too large: {} bytes (max {})", len, MAX_FRAME_SIZE);
    }

    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .with_context(|| "Failed to read frame body")?;

    Ok(buf)
}

/// Write a length-prefixed JSON frame to a tokio AsyncWrite.
#[cfg(feature = "hostd-transport")]
pub async fn write_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    writer
        .write_all(&len)
        .await
        .with_context(|| "Failed to write frame length")?;
    writer
        .write_all(data)
        .await
        .with_context(|| "Failed to write frame body")?;
    writer
        .flush()
        .await
        .with_context(|| "Failed to flush frame")?;
    Ok(())
}

/// Serialize and send a request.
#[cfg(feature = "hostd-transport")]
pub async fn send_request<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &HostdRequest,
) -> Result<()> {
    let data = serde_json::to_vec(req).with_context(|| "Failed to serialize request")?;
    write_frame(writer, &data).await
}

/// Read and deserialize a request.
#[cfg(feature = "hostd-transport")]
pub async fn recv_request<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<HostdRequest> {
    let data = read_frame(reader).await?;
    serde_json::from_slice(&data).with_context(|| "Failed to deserialize request")
}

/// Serialize and send a response.
#[cfg(feature = "hostd-transport")]
pub async fn send_response<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &HostdResponse,
) -> Result<()> {
    let data = serde_json::to_vec(resp).with_context(|| "Failed to serialize response")?;
    write_frame(writer, &data).await
}

/// Read and deserialize a response.
#[cfg(feature = "hostd-transport")]
pub async fn recv_response<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<HostdResponse> {
    let data = read_frame(reader).await?;
    serde_json::from_slice(&data).with_context(|| "Failed to deserialize response")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::TenantNet;

    /// Pin the protocol version constant. mvmd's
    /// `tests/mvmd_compat.rs` reads `PROTOCOL_VERSION` and compares
    /// against its own frozen-byte fixtures; if this binary
    /// disagrees with the mvmd snapshot, the fixture-set has
    /// drifted and one side needs a refresh. Locking the value
    /// here means a PR can't silently bump the const without also
    /// updating this test (and prompting the fixture re-gen).
    #[test]
    fn protocol_version_is_two() {
        // Bumped from 1 to 2 in the workspace-volume attach change.
        assert_eq!(PROTOCOL_VERSION, 2);
    }

    #[test]
    fn protocol_version_is_u32() {
        // Compile-check the declared type. mvmd's wire-format test
        // serialises `PROTOCOL_VERSION` as a 4-byte little-endian
        // value; if this ever became u8 or u64, mvmd's pin would
        // break in a confusing way. Pin the type here so the
        // breakage is obvious.
        let _: u32 = PROTOCOL_VERSION;
    }

    #[test]
    fn test_hostd_request_start_roundtrip() {
        let req = HostdRequest::StartInstance {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            instance_id: "i-abc123".to_string(),
            workspace_id: None,
            volumes: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::StartInstance {
                tenant_id,
                pool_id,
                instance_id,
                workspace_id,
                volumes,
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(pool_id, "workers");
                assert_eq!(instance_id, "i-abc123");
                assert_eq!(workspace_id, None);
                assert!(volumes.is_empty());
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_hostd_request_start_with_workspace_volumes_roundtrip() {
        use crate::instance::{VolumeAttach, VolumeMode};
        let req = HostdRequest::StartInstance {
            tenant_id: "acme".to_string(),
            pool_id: "memory-svc".to_string(),
            instance_id: "i-mem".to_string(),
            workspace_id: Some("ws-prod".to_string()),
            volumes: vec![VolumeAttach {
                workspace_id: "ws-prod".to_string(),
                name: "memory".to_string(),
                mount_path: "/var/lib/memory".to_string(),
                mode: VolumeMode::ReadWrite,
            }],
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::StartInstance {
                workspace_id,
                volumes,
                ..
            } => {
                assert_eq!(workspace_id.as_deref(), Some("ws-prod"));
                assert_eq!(volumes.len(), 1);
                assert_eq!(volumes[0].mount_path, "/var/lib/memory");
                assert_eq!(volumes[0].mode, VolumeMode::ReadWrite);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_hostd_request_stop_roundtrip() {
        let req = HostdRequest::StopInstance {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            instance_id: "i-abc123".to_string(),
            workspace_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HostdRequest::StopInstance { .. }));
    }

    #[test]
    fn test_hostd_request_sleep_roundtrip() {
        let req = HostdRequest::SleepInstance {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            instance_id: "i-abc123".to_string(),
            force: true,
            drain_timeout_secs: Some(30),
            workspace_id: Some("ws-prod".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::SleepInstance {
                force,
                drain_timeout_secs,
                workspace_id,
                ..
            } => {
                assert!(force);
                assert_eq!(drain_timeout_secs, Some(30));
                assert_eq!(workspace_id.as_deref(), Some("ws-prod"));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_hostd_request_wake_roundtrip() {
        let req = HostdRequest::WakeInstance {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            instance_id: "i-abc123".to_string(),
            workspace_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HostdRequest::WakeInstance { .. }));
    }

    #[test]
    fn test_hostd_request_destroy_roundtrip() {
        let req = HostdRequest::DestroyInstance {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            instance_id: "i-abc123".to_string(),
            wipe_volumes: true,
            workspace_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::DestroyInstance { wipe_volumes, .. } => assert!(wipe_volumes),
            _ => panic!("Wrong variant"),
        }
    }

    /// PROTOCOL_VERSION 1 wire format — payload predates workspace_id
    /// and volumes. Must still deserialize so an mvmd-agent pinned to
    /// v1 can still talk to a v2 mvm-hostd while the cross-repo bump
    /// rolls out.
    #[test]
    fn test_hostd_request_start_v1_backward_compat() {
        let v1_json = r#"{
            "StartInstance": {
                "tenant_id": "acme",
                "pool_id": "workers",
                "instance_id": "i-legacy"
            }
        }"#;
        let parsed: HostdRequest = serde_json::from_str(v1_json).unwrap();
        match parsed {
            HostdRequest::StartInstance {
                tenant_id,
                workspace_id,
                volumes,
                ..
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(workspace_id, None);
                assert!(volumes.is_empty());
            }
            _ => panic!("Wrong variant"),
        }
    }

    /// Same v1-compat check for the other instance-scoped variants —
    /// the workspace_id field must be optional everywhere it landed.
    #[test]
    fn test_hostd_request_instance_variants_v1_backward_compat() {
        let cases = [
            r#"{"StopInstance":{"tenant_id":"t","pool_id":"p","instance_id":"i"}}"#,
            r#"{"SleepInstance":{"tenant_id":"t","pool_id":"p","instance_id":"i","force":false}}"#,
            r#"{"WakeInstance":{"tenant_id":"t","pool_id":"p","instance_id":"i"}}"#,
            r#"{"DestroyInstance":{"tenant_id":"t","pool_id":"p","instance_id":"i","wipe_volumes":false}}"#,
        ];
        for json in cases {
            let parsed: HostdRequest = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("v1 payload {json:?} should parse: {e}"));
            // Each instance variant carries workspace_id; assert it
            // defaults to None when the v1 payload omits it.
            let ws = match &parsed {
                HostdRequest::StopInstance { workspace_id, .. } => workspace_id,
                HostdRequest::SleepInstance { workspace_id, .. } => workspace_id,
                HostdRequest::WakeInstance { workspace_id, .. } => workspace_id,
                HostdRequest::DestroyInstance { workspace_id, .. } => workspace_id,
                _ => panic!("unexpected variant for {json:?}"),
            };
            assert_eq!(
                ws, &None,
                "v1 payload {json:?} should default workspace_id to None"
            );
        }
    }

    /// PROTOCOL_VERSION 2 canonical fixture for StartInstance with the
    /// new fields populated. mvmd-side `tests/mvmd_compat.rs` mirrors
    /// this shape; if the serialized bytes drift, both sides need a
    /// refresh in the same commit.
    #[test]
    fn test_hostd_request_start_v2_fixture() {
        use crate::instance::{VolumeAttach, VolumeMode};
        let req = HostdRequest::StartInstance {
            tenant_id: "acme".to_string(),
            pool_id: "memory-svc".to_string(),
            instance_id: "i-mem-001".to_string(),
            workspace_id: Some("ws-prod".to_string()),
            volumes: vec![VolumeAttach {
                workspace_id: "ws-prod".to_string(),
                name: "memory".to_string(),
                mount_path: "/var/lib/memory".to_string(),
                mode: VolumeMode::ReadWrite,
            }],
        };
        let actual = serde_json::to_string(&req).unwrap();
        let expected = concat!(
            r#"{"StartInstance":{"#,
            r#""tenant_id":"acme","#,
            r#""pool_id":"memory-svc","#,
            r#""instance_id":"i-mem-001","#,
            r#""workspace_id":"ws-prod","#,
            r#""volumes":[{"#,
            r#""workspace_id":"ws-prod","#,
            r#""name":"memory","#,
            r#""mount_path":"/var/lib/memory","#,
            r#""mode":"read_write""#,
            r#"}]"#,
            r#"}}"#,
        );
        assert_eq!(actual, expected);
        // Round-trip the fixture to make sure parsing matches construction.
        let parsed: HostdRequest = serde_json::from_str(expected).unwrap();
        assert!(matches!(parsed, HostdRequest::StartInstance { .. }));
    }

    #[test]
    fn test_hostd_request_setup_network_roundtrip() {
        let net = TenantNet::new(3, "10.240.3.0/24", "10.240.3.1");
        let req = HostdRequest::SetupNetwork {
            tenant_id: "acme".to_string(),
            net: net.clone(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::SetupNetwork { tenant_id, net: n } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(n.tenant_net_id, 3);
                assert_eq!(n.ipv4_subnet, "10.240.3.0/24");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_hostd_request_teardown_network_roundtrip() {
        let net = TenantNet::new(3, "10.240.3.0/24", "10.240.3.1");
        let req = HostdRequest::TeardownNetwork {
            tenant_id: "acme".to_string(),
            net,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HostdRequest::TeardownNetwork { .. }));
    }

    #[test]
    fn test_hostd_request_ping_roundtrip() {
        let req = HostdRequest::Ping;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HostdRequest::Ping));
    }

    #[test]
    fn test_hostd_response_ok_roundtrip() {
        let resp = HostdResponse::Ok;
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HostdResponse = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HostdResponse::Ok));
    }

    #[test]
    fn test_hostd_response_error_roundtrip() {
        let resp = HostdResponse::Error {
            message: "instance not found".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HostdResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdResponse::Error { message } => assert_eq!(message, "instance not found"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_hostd_response_pong_roundtrip() {
        let resp = HostdResponse::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: HostdResponse = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, HostdResponse::Pong));
    }

    #[test]
    fn test_all_request_variants_serialize() {
        let net = TenantNet::new(1, "10.240.1.0/24", "10.240.1.1");
        let variants: Vec<HostdRequest> = vec![
            HostdRequest::StartInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
                workspace_id: None,
                volumes: vec![],
            },
            HostdRequest::StopInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
                workspace_id: None,
            },
            HostdRequest::SleepInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
                force: false,
                drain_timeout_secs: None,
                workspace_id: None,
            },
            HostdRequest::WakeInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
                workspace_id: None,
            },
            HostdRequest::DestroyInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
                wipe_volumes: false,
                workspace_id: None,
            },
            HostdRequest::SetupNetwork {
                tenant_id: "t".to_string(),
                net: net.clone(),
            },
            HostdRequest::TeardownNetwork {
                tenant_id: "t".to_string(),
                net,
            },
            HostdRequest::Ping,
        ];

        for req in &variants {
            let json = serde_json::to_string(req).unwrap();
            let _: HostdRequest = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_all_response_variants_serialize() {
        let variants: Vec<HostdResponse> = vec![
            HostdResponse::Ok,
            HostdResponse::Error {
                message: "err".to_string(),
            },
            HostdResponse::Pong,
        ];

        for resp in &variants {
            let json = serde_json::to_string(resp).unwrap();
            let _: HostdResponse = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_socket_path_constant() {
        assert_eq!(HOSTD_SOCKET_PATH, "/run/mvm/hostd.sock");
    }

    #[cfg(feature = "hostd-transport")]
    #[tokio::test]
    async fn test_frame_roundtrip() {
        let data = b"hello hostd";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let read_back = read_frame(&mut cursor).await.unwrap();
        assert_eq!(read_back, data);
    }

    #[cfg(feature = "hostd-transport")]
    #[tokio::test]
    async fn test_request_send_recv_roundtrip() {
        let req = HostdRequest::Ping;
        let mut buf = Vec::new();
        send_request(&mut buf, &req).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let parsed = recv_request(&mut cursor).await.unwrap();
        assert!(matches!(parsed, HostdRequest::Ping));
    }

    #[cfg(feature = "hostd-transport")]
    #[tokio::test]
    async fn test_response_send_recv_roundtrip() {
        let resp = HostdResponse::Ok;
        let mut buf = Vec::new();
        send_response(&mut buf, &resp).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let parsed = recv_response(&mut cursor).await.unwrap();
        assert!(matches!(parsed, HostdResponse::Ok));
    }
}

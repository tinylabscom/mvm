use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::tenant::TenantNet;

/// Default Unix domain socket path for hostd.
pub const HOSTD_SOCKET_PATH: &str = "/run/mvm/hostd.sock";

/// Maximum frame size for hostd IPC (1 MiB).
const MAX_FRAME_SIZE: usize = 1024 * 1024;

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
    },
    /// Stop a running instance (kill FC, teardown cgroup, TAP).
    StopInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
    },
    /// Snapshot and suspend an instance.
    SleepInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        force: bool,
        #[serde(default)]
        drain_timeout_secs: Option<u64>,
    },
    /// Restore an instance from snapshot.
    WakeInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
    },
    /// Destroy an instance and optionally wipe volumes.
    DestroyInstance {
        tenant_id: String,
        pool_id: String,
        instance_id: String,
        wipe_volumes: bool,
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
// ============================================================================

/// Read a length-prefixed JSON frame from a tokio AsyncRead.
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
pub async fn send_request<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    req: &HostdRequest,
) -> Result<()> {
    let data = serde_json::to_vec(req).with_context(|| "Failed to serialize request")?;
    write_frame(writer, &data).await
}

/// Read and deserialize a request.
pub async fn recv_request<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<HostdRequest> {
    let data = read_frame(reader).await?;
    serde_json::from_slice(&data).with_context(|| "Failed to deserialize request")
}

/// Serialize and send a response.
pub async fn send_response<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &HostdResponse,
) -> Result<()> {
    let data = serde_json::to_vec(resp).with_context(|| "Failed to serialize response")?;
    write_frame(writer, &data).await
}

/// Read and deserialize a response.
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

    #[test]
    fn test_hostd_request_start_roundtrip() {
        let req = HostdRequest::StartInstance {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            instance_id: "i-abc123".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::StartInstance {
                tenant_id,
                pool_id,
                instance_id,
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(pool_id, "workers");
                assert_eq!(instance_id, "i-abc123");
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
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::SleepInstance {
                force,
                drain_timeout_secs,
                ..
            } => {
                assert!(force);
                assert_eq!(drain_timeout_secs, Some(30));
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
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: HostdRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            HostdRequest::DestroyInstance { wipe_volumes, .. } => assert!(wipe_volumes),
            _ => panic!("Wrong variant"),
        }
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
            },
            HostdRequest::StopInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
            },
            HostdRequest::SleepInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
                force: false,
                drain_timeout_secs: None,
            },
            HostdRequest::WakeInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
            },
            HostdRequest::DestroyInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
                wipe_volumes: false,
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

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let data = b"hello hostd";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let read_back = read_frame(&mut cursor).await.unwrap();
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn test_request_send_recv_roundtrip() {
        let req = HostdRequest::Ping;
        let mut buf = Vec::new();
        send_request(&mut buf, &req).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let parsed = recv_request(&mut cursor).await.unwrap();
        assert!(matches!(parsed, HostdRequest::Ping));
    }

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

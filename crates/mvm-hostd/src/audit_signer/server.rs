//! UDS server loop — accepts [`AppendEntryRequest`] envelopes, dispatches
//! to [`Chain`], writes back [`AppendEntryResponse`].
//!
//! Single-threaded chain access — all appends go through one
//! `Arc<Mutex<Chain>>` so the in-memory head stays consistent with the
//! `O_APPEND` FD's view. Tokio mutex (not std) so the lock doesn't
//! block other connections' protocol parsing.

use std::sync::Arc;

use anyhow::{Context, Result};
use mvm_core::protocol::audit_signer::{
    AppendEntryRequest, AppendEntryResponse, AuditSignerErrorCode,
};
use mvm_core::security::SIG_ALG_ED25519;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::audit_signer::canonical::CanonicalEntry;
use crate::audit_signer::chain::Chain;

const DEFAULT_MAX_FRAME_BYTES: usize = 65_536;

pub type SharedChain = Arc<Mutex<Chain>>;

/// Accept loop.
pub async fn serve(
    listener: UnixListener,
    chain: SharedChain,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    info!(
        workload_id = %workload_id,
        max_frame_bytes,
        "mvm-audit-signer accept loop started"
    );
    loop {
        let (stream, _addr) = listener
            .accept()
            .await
            .context("mvm-audit-signer UDS accept failed")?;
        let chain = chain.clone();
        let workload_id = workload_id.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, chain, workload_id, max_frame_bytes).await {
                warn!(error = %e, "mvm-audit-signer connection terminated with error");
            }
        });
    }
}

pub async fn serve_on_listener(
    listener: UnixListener,
    chain: SharedChain,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    serve(listener, chain, workload_id, max_frame_bytes).await
}

async fn handle_connection(
    mut stream: UnixStream,
    chain: SharedChain,
    workload_id: String,
    max_frame_bytes: usize,
) -> Result<()> {
    let req = read_frame::<AppendEntryRequest>(&mut stream, max_frame_bytes).await?;
    debug!(
        workload_id = %workload_id,
        request_id = %req.request_id(),
        "mvm-audit-signer received request"
    );

    let response = dispatch(req, &chain).await;
    write_frame(&mut stream, &response).await?;
    stream
        .shutdown()
        .await
        .context("mvm-audit-signer UDS shutdown failed")?;
    Ok(())
}

async fn dispatch(req: AppendEntryRequest, chain: &SharedChain) -> AppendEntryResponse {
    let request_id = req.request_id().to_string();
    match req {
        AppendEntryRequest::Probe { request_id } => AppendEntryResponse::Pong { request_id },
        AppendEntryRequest::AppendEntry {
            request_id: _,
            category,
            ts,
            workload_id,
            tenant_id,
            session_id,
            correlation_id,
            fields,
        } => {
            let mut chain = chain.lock().await;
            let entry = CanonicalEntry {
                category,
                correlation_id,
                fields,
                prev_hash: chain.head().to_string(),
                session_id,
                tenant_id,
                ts,
                workload_id,
            };
            match chain.append(entry) {
                Ok(new_head) => AppendEntryResponse::Ok {
                    request_id,
                    chain_head: new_head.clone(),
                    entry_hash: new_head,
                    sig_alg: SIG_ALG_ED25519,
                },
                Err(code) => AppendEntryResponse::Err {
                    request_id,
                    code,
                    message: format_code_message(code),
                },
            }
        }
    }
}

fn format_code_message(code: AuditSignerErrorCode) -> String {
    match code {
        AuditSignerErrorCode::NotReady => "audit-signer not ready".into(),
        AuditSignerErrorCode::InvalidRequest => "invalid request shape".into(),
        AuditSignerErrorCode::FsyncFailed => "audit JSONL fsync failed".into(),
        AuditSignerErrorCode::ChainDriftDetected => {
            "chain drift detected: caller prev_hash mismatch".into()
        }
        AuditSignerErrorCode::InternalError => "audit-signer internal error".into(),
    }
}

// Length-prefixed JSON framing lives in `crate::framing` (was
// `mvm_core::framing`); these wrappers keep the audit-signer error
// context on the shared transport. The cap-before-alloc gate is enforced
// there.
async fn read_frame<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<T> {
    crate::framing::read_json_frame(stream, max_frame_bytes)
        .await
        .context("mvm-audit-signer frame read failed")
}

async fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    crate::framing::write_json_frame(stream, value)
        .await
        .context("mvm-audit-signer frame write failed")
}

pub fn default_max_frame_bytes() -> usize {
    DEFAULT_MAX_FRAME_BYTES
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::tempdir;
    use tokio::net::UnixStream as ClientStream;

    use super::*;
    use tokio::io::AsyncReadExt;

    async fn write_req(stream: &mut ClientStream, req: &AppendEntryRequest) -> Result<()> {
        let body = serde_json::to_vec(req).unwrap();
        let len: u32 = body.len().try_into().unwrap();
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&body).await?;
        Ok(())
    }

    async fn read_resp(stream: &mut ClientStream) -> Result<AppendEntryResponse> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    fn uds_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("audit-signer.sock")
    }

    fn sample_append(req_id: &str) -> AppendEntryRequest {
        AppendEntryRequest::AppendEntry {
            request_id: req_id.into(),
            category: "plan".into(),
            ts: "2026-05-27T22:30:00Z".into(),
            workload_id: "wl-001".into(),
            tenant_id: "t-001".into(),
            session_id: "sess-001".into(),
            correlation_id: "01HCORR0000000000000000".into(),
            fields: serde_json::json!({"verb": "now"}),
        }
    }

    async fn boot(dir: &tempfile::TempDir) -> (PathBuf, SharedChain, tokio::task::JoinHandle<()>) {
        let path = uds_path(dir);
        let listener = UnixListener::bind(&path).unwrap();
        let jsonl = dir.path().join("audit.jsonl");
        let head = dir.path().join("HEAD");
        let chain = Arc::new(Mutex::new(Chain::open(&jsonl, &head, None).unwrap()));
        let task = tokio::spawn({
            let chain = chain.clone();
            async move {
                let _ = serve_on_listener(listener, chain, "wl-test".into(), 65_536).await;
            }
        });
        tokio::task::yield_now().await;
        (path, chain, task)
    }

    #[tokio::test]
    async fn probe_returns_pong_with_echoed_request_id() {
        let dir = tempdir().unwrap();
        let (path, _chain, task) = boot(&dir).await;
        let mut client = ClientStream::connect(&path).await.unwrap();
        let req = AppendEntryRequest::Probe {
            request_id: "probe-1".into(),
        };
        write_req(&mut client, &req).await.unwrap();
        let resp = read_resp(&mut client).await.unwrap();
        match resp {
            AppendEntryResponse::Pong { request_id } => assert_eq!(request_id, "probe-1"),
            other => panic!("expected Pong, got {:?}", other),
        }
        task.abort();
    }

    #[tokio::test]
    async fn append_advances_chain_head_and_persists() {
        let dir = tempdir().unwrap();
        let (path, chain, task) = boot(&dir).await;
        let mut client = ClientStream::connect(&path).await.unwrap();
        let req = sample_append("req-1");
        write_req(&mut client, &req).await.unwrap();
        let resp = read_resp(&mut client).await.unwrap();
        match resp {
            AppendEntryResponse::Ok {
                request_id,
                chain_head,
                entry_hash,
                sig_alg,
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(chain_head, entry_hash);
                assert_eq!(sig_alg, SIG_ALG_ED25519);
                let in_memory_head = chain.lock().await.head().to_string();
                assert_eq!(in_memory_head, chain_head);
                let secondary = std::fs::read_to_string(dir.path().join("HEAD")).unwrap();
                assert_eq!(secondary, chain_head);
            }
            other => panic!("expected Ok, got {:?}", other),
        }
        task.abort();
    }

    #[tokio::test]
    async fn rejects_unknown_envelope_fields_with_internal_error() {
        // The envelope's deny_unknown_fields means an extra field
        // fails the read_frame parse — the connection drops rather
        // than returning a typed error. We assert the connection
        // closes; the supervisor's proxy treats it as Unavailable.
        let dir = tempdir().unwrap();
        let (path, _chain, task) = boot(&dir).await;
        let mut client = ClientStream::connect(&path).await.unwrap();
        let bad_body = serde_json::to_vec(&serde_json::json!({
            "verb": "append_entry",
            "request_id": "bad",
            "category": "plan",
            "ts": "2026-05-27T00:00:00Z",
            "workload_id": "wl",
            "tenant_id": "t",
            "session_id": "s",
            "correlation_id": "c",
            "fields": {},
            "extra": "field",
        }))
        .unwrap();
        let len: u32 = bad_body.len().try_into().unwrap();
        client.write_all(&len.to_be_bytes()).await.unwrap();
        client.write_all(&bad_body).await.unwrap();
        let mut buf = [0u8; 4];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "server must drop connection on bad envelope");
        task.abort();
    }
}

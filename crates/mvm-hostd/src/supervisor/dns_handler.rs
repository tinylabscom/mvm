//! Policy-gated DNS-over-vsock request handling.

use std::future::Future;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use mvm_core::protocol::dns::{
    DnsQuestion, DnsRcode, MAX_DNS_MESSAGE, decode_query, encode_response,
};
use mvm_core::rate_limit::TokenBucket;
use mvm_runtime::vmm::egress_gate::{DnsVerdict, EgressGate};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::supervisor::audit_recorder::Recorder;
use crate::supervisor::{dns_audit, raw_egress};

/// First-line marker that selects DNS framing on the shared egress stream.
pub const FRAME_LINE: &str = mvm_core::guest_netd::DNS_FRAME_LINE;
/// Default DNS query rate for one workload endpoint.
pub const DEFAULT_DNS_QUERIES_PER_SEC: u32 = 100;
/// Default number of simultaneous DNS queries for one workload endpoint.
pub const DEFAULT_DNS_MAX_INFLIGHT: usize = 32;

/// Shared per-workload DNS admission guard.
pub struct DnsRateGuard {
    bucket: Mutex<TokenBucket>,
    inflight: Semaphore,
}

impl DnsRateGuard {
    /// Build a guard with an explicit sustained rate and concurrency cap.
    pub fn new(queries_per_sec: u32, max_inflight: usize) -> Self {
        Self {
            bucket: Mutex::new(TokenBucket::new(queries_per_sec)),
            inflight: Semaphore::new(max_inflight),
        }
    }

    /// Admit one query, or return `None` without waiting when either limit is full.
    pub async fn admit(&self) -> Option<SemaphorePermit<'_>> {
        self.try_admit()
    }

    fn try_admit(&self) -> Option<SemaphorePermit<'_>> {
        let permit = self.inflight.try_acquire().ok()?;
        let Ok(mut bucket) = self.bucket.lock() else {
            return None;
        };
        bucket.try_take().then_some(permit)
    }
}

impl Default for DnsRateGuard {
    fn default() -> Self {
        Self::new(DEFAULT_DNS_QUERIES_PER_SEC, DEFAULT_DNS_MAX_INFLIGHT)
    }
}

/// Serve one length-prefixed DNS query over an asynchronous guest stream.
///
/// The query and response are DNS-over-TCP framed. Oversized frames are
/// rejected before allocation, and policy refusal never performs an upstream
/// lookup.
pub async fn serve_dns<S>(
    guest: S,
    gate: &EgressGate,
    recorder: Option<&Recorder>,
    rate_guard: &DnsRateGuard,
    timeout: Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve_dns_with_resolver(
        guest,
        gate,
        recorder,
        rate_guard,
        timeout,
        raw_egress::resolve_hostname_ips_pure,
    )
    .await
}

async fn serve_dns_with_resolver<S, F>(
    mut guest: S,
    gate: &EgressGate,
    recorder: Option<&Recorder>,
    rate_guard: &DnsRateGuard,
    timeout: Duration,
    resolve: F,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(&str, Duration) -> std::io::Result<Vec<IpAddr>> + Send + 'static,
{
    let query = read_frame_async(&mut guest, timeout).await?;
    let response = match decode_query(&query) {
        Ok(question) => match rate_guard.admit().await {
            Some(permit) => {
                let gate = gate.clone();
                let (question, verdict) = tokio::task::spawn_blocking(move || {
                    let verdict = gate.dns_verdict(&question.name, question.qtype, |name| {
                        resolve(name, timeout)
                    });
                    (question, verdict)
                })
                .await
                .map_err(std::io::Error::other)?;
                if let Some(recorder) = recorder {
                    dns_audit::emit_dns_query(recorder, &question.name, question.qtype, &verdict)
                        .await;
                }
                let response = encode_verdict(&question, verdict);
                drop(permit);
                response
            }
            None => {
                if let Some(recorder) = recorder {
                    dns_audit::emit_dns_rate_limited(recorder, &question.name, question.qtype)
                        .await;
                }
                encode_response(&question, DnsRcode::Refused, &[])
            }
        },
        Err(_) => encode_malformed_refusal(&query),
    };
    write_frame_async(&mut guest, &response, timeout).await
}

async fn read_frame_async<S>(guest: &mut S, timeout: Duration) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0_u8; 2];
    with_timeout(timeout, guest.read_exact(&mut length)).await?;
    let length = usize::from(u16::from_be_bytes(length));
    validate_frame_length(length)?;
    let mut query = vec![0_u8; length];
    with_timeout(timeout, guest.read_exact(&mut query)).await?;
    Ok(query)
}

async fn write_frame_async<S>(
    guest: &mut S,
    response: &[u8],
    timeout: Duration,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let length = u16::try_from(response.len()).map_err(|_| invalid_frame_length())?;
    with_timeout(timeout, guest.write_all(&length.to_be_bytes())).await?;
    with_timeout(timeout, guest.write_all(response)).await?;
    with_timeout(timeout, guest.flush()).await
}

async fn with_timeout<T>(
    timeout: Duration,
    operation: impl Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS stream timed out"))?
}

fn validate_frame_length(length: usize) -> std::io::Result<()> {
    if length > MAX_DNS_MESSAGE {
        Err(invalid_frame_length())
    } else {
        Ok(())
    }
}

fn invalid_frame_length() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "DNS frame exceeds the configured message limit",
    )
}

fn encode_verdict(question: &DnsQuestion, verdict: DnsVerdict) -> Vec<u8> {
    match verdict {
        DnsVerdict::Resolved(ips) => encode_response(question, DnsRcode::NoError, &ips),
        DnsVerdict::Refused => encode_response(question, DnsRcode::Refused, &[]),
    }
}

fn encode_malformed_refusal(query: &[u8]) -> Vec<u8> {
    let id = query
        .get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .unwrap_or(0);
    encode_response(
        &DnsQuestion {
            name: String::new(),
            qtype: mvm_core::protocol::dns::DnsRecordType::A,
            id,
        },
        DnsRcode::Refused,
        &[],
    )
}

/// Serve one length-prefixed DNS query over a blocking guest vsock file.
#[cfg(target_os = "linux")]
pub fn serve_dns_blocking(
    mut guest: std::fs::File,
    gate: &EgressGate,
    recorder: Option<&Recorder>,
    rate_guard: &DnsRateGuard,
    timeout: Duration,
) -> std::io::Result<()> {
    use std::io::{Read, Write};

    let mut length = [0_u8; 2];
    guest.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    validate_frame_length(length)?;
    let mut query = vec![0_u8; length];
    guest.read_exact(&mut query)?;
    let response = match decode_query(&query) {
        Ok(question) => match rate_guard.try_admit() {
            Some(permit) => {
                let verdict = gate.dns_verdict(&question.name, question.qtype, |name| {
                    raw_egress::resolve_hostname_ips_pure(name, timeout)
                });
                if let Some(recorder) = recorder {
                    dns_audit::emit_dns_query_blocking(
                        recorder,
                        &question.name,
                        question.qtype,
                        &verdict,
                    );
                }
                let response = encode_verdict(&question, verdict);
                drop(permit);
                response
            }
            None => {
                if let Some(recorder) = recorder {
                    dns_audit::emit_dns_rate_limited_blocking(
                        recorder,
                        &question.name,
                        question.qtype,
                    );
                }
                encode_response(&question, DnsRcode::Refused, &[])
            }
        },
        Err(_) => encode_malformed_refusal(&query),
    };
    let length = u16::try_from(response.len()).map_err(|_| invalid_frame_length())?;
    guest.write_all(&length.to_be_bytes())?;
    guest.write_all(&response)?;
    guest.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::supervisor::audit::CapturingAuditSigner;
    use mvm_core::plan::TenantId;
    use mvm_runtime::vmm::egress_gate::EgressGate;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn build_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
        let mut query = Vec::from(id.to_be_bytes());
        query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            query.push(u8::try_from(label.len()).expect("test label length fits in u8"));
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }

    async fn exchange_query(client: &mut tokio::io::DuplexStream, query: &[u8]) -> Vec<u8> {
        client
            .write_all(
                &u16::try_from(query.len())
                    .expect("test query length fits in u16")
                    .to_be_bytes(),
            )
            .await
            .unwrap();
        client.write_all(query).await.unwrap();
        let mut length = [0_u8; 2];
        client.read_exact(&mut length).await.unwrap();
        let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        client.read_exact(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn refuses_an_unadmitted_name() {
        let gate = EgressGate::default_deny();
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = tokio::spawn(async move {
            serve_dns(
                server,
                &gate,
                None,
                &DnsRateGuard::default(),
                Duration::from_secs(1),
            )
            .await
        });

        let response = exchange_query(&mut client, &build_query("blocked.test", 1, 0x2222)).await;
        assert_eq!(&response[..2], &[0x22, 0x22]);
        assert_eq!(response[3] & 0x0f, 5);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn audits_one_policy_decision_for_a_valid_query() {
        let gate = EgressGate::default_deny();
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(signer.clone(), TenantId("local".to_string())));
        let (mut client, server) = tokio::io::duplex(4096);
        let handler_recorder = Arc::clone(&recorder);
        let handler = tokio::spawn(async move {
            serve_dns(
                server,
                &gate,
                Some(&handler_recorder),
                &DnsRateGuard::default(),
                Duration::from_secs(1),
            )
            .await
        });

        let response = exchange_query(&mut client, &build_query("blocked.test", 1, 0x2222)).await;
        assert_eq!(response[3] & 0x0f, 5);
        handler.await.unwrap().unwrap();

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].event, "dns.refused");
        assert_eq!(
            entries[0].labels.get("qname").map(String::as_str),
            Some("blocked.test")
        );
    }

    #[tokio::test]
    async fn unrestricted_lookup_returns_filtered_answer() {
        let gate = EgressGate::new(mvm_core::policy::projection::CanonicalEgress::Unrestricted);
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = tokio::spawn(async move {
            serve_dns_with_resolver(
                server,
                &gate,
                None,
                &DnsRateGuard::default(),
                Duration::from_secs(1),
                |_name, _timeout| {
                    Ok(vec![
                        "93.184.216.34".parse::<IpAddr>().unwrap(),
                        "10.0.0.8".parse::<IpAddr>().unwrap(),
                    ])
                },
            )
            .await
        });

        let response = exchange_query(&mut client, &build_query("allowed.test", 1, 0x1234)).await;
        assert_eq!(response[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
        assert_eq!(&response[response.len() - 4..], &[93, 184, 216, 34]);
        handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_payload_read() {
        let gate = EgressGate::default_deny();
        let (mut client, server) = tokio::io::duplex(16);
        let handler = tokio::spawn(async move {
            serve_dns(
                server,
                &gate,
                None,
                &DnsRateGuard::default(),
                Duration::from_secs(1),
            )
            .await
        });
        client.write_all(&4097_u16.to_be_bytes()).await.unwrap();

        let error = handler.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rate_guard_denies_when_bucket_is_empty() {
        let guard = DnsRateGuard::new(0, 1);
        assert!(guard.admit().await.is_none());
    }

    #[tokio::test]
    async fn rate_guard_caps_concurrent_queries() {
        let guard = DnsRateGuard::new(10, 1);
        let first = guard.admit().await.expect("first query is admitted");
        assert!(guard.admit().await.is_none());
        drop(first);
        assert!(guard.admit().await.is_some());
    }

    #[tokio::test]
    async fn rate_limited_query_is_refused_and_audited_without_lookup() {
        let gate = EgressGate::new(mvm_core::policy::projection::CanonicalEgress::Unrestricted);
        let signer = Arc::new(CapturingAuditSigner::new());
        let recorder = Arc::new(Recorder::new(signer.clone(), TenantId("local".to_string())));
        let lookups = Arc::new(AtomicUsize::new(0));
        let handler_lookups = Arc::clone(&lookups);
        let (mut client, server) = tokio::io::duplex(4096);
        let handler = tokio::spawn(async move {
            serve_dns_with_resolver(
                server,
                &gate,
                Some(&recorder),
                &DnsRateGuard::new(0, 1),
                Duration::from_secs(1),
                move |_name, _timeout| {
                    handler_lookups.fetch_add(1, Ordering::Relaxed);
                    Ok(vec!["93.184.216.34".parse::<IpAddr>().unwrap()])
                },
            )
            .await
        });

        let response = exchange_query(&mut client, &build_query("busy.test", 1, 0x4444)).await;
        assert_eq!(response[3] & 0x0f, 5);
        handler.await.unwrap().unwrap();
        assert_eq!(lookups.load(Ordering::Relaxed), 0);

        let entries = signer.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].labels.get("verdict").map(String::as_str),
            Some("rate_limited")
        );
    }
}

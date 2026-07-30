//! Opt-in live probe for measuring the resident guest agent over its real
//! authenticated vsock control channel.

use std::os::unix::net::UnixStream;

use mvm_agentd::vsock::{GuestRequest, GuestResponse, send_request};

#[test]
fn live_resource_usage_reports_nonzero_rss() {
    if std::env::var("MVM_LIVE_SMOKE").as_deref() != Ok("1") {
        eprintln!("MVM_LIVE_SMOKE != 1; skipping live guest-agent RSS probe");
        return;
    }

    let rss_bytes = match std::env::var("MVM_AGENT_DIRECT_VSOCK_UDS") {
        Ok(vsock_path) => query_resource_usage_direct(&vsock_path),
        Err(_) => {
            let vsock_path =
                std::env::var("MVM_AGENT_VSOCK_UDS").expect("a guest-agent UDS is required");
            mvm_agentd::vsock::query_resource_usage_at(&vsock_path).expect("query guest-agent RSS")
        }
    };

    println!("guest_agent_rss_bytes={rss_bytes}");
    assert!(rss_bytes > 0, "the live guest-agent RSS must be nonzero");
}

fn query_resource_usage_direct(vsock_path: &str) -> u64 {
    let mut stream = UnixStream::connect(vsock_path).expect("connect to direct guest-agent UDS");
    match send_request(&mut stream, &GuestRequest::ResourceUsage)
        .expect("query guest-agent RSS over direct UDS")
    {
        GuestResponse::ResourceUsageReport { rss_bytes } => rss_bytes,
        GuestResponse::Error { message } => panic!("guest resource usage error: {message}"),
        response => panic!("unexpected response to ResourceUsage: {response:?}"),
    }
}

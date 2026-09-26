//! The webhook backend: POST the question, read the answer.
//!
//! The request body is the [`ApprovalPrompt`] as JSON. The reply must be a
//! 2xx with a JSON body `{"outcome": "approved" | "denied", "scope": "once" |
//! "session"}` (`scope` optional, default `once`). Everything else is a
//! denial:
//!
//! - a URL that is not `https://`, unless its host is loopback;
//! - a redirect — the client never follows one, so a 3xx is just a non-2xx;
//! - a reply over [`MAX_WEBHOOK_REPLY_BYTES`];
//! - no reply within the timeout (the prompt's own deadline or the
//!   backend's, whichever is sooner);
//! - a body that does not parse.

use std::io::Read;
use std::time::Duration;

use mvm_contract::policy::approval::ApprovalOutcome;
use mvm_contract::policy::approval_prompt::{ApprovalAnswer, ApprovalPrompt, ApprovalScope};
use serde::Deserialize;

use super::ApprovalBackend;

/// Largest reply read from a webhook.
pub const MAX_WEBHOOK_REPLY_BYTES: u64 = 4 * 1024;
/// Default wait for a webhook reply.
pub const DEFAULT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a webhook URL is refused at configuration.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("approval webhook URL {0:?} does not parse")]
    BadUrl(String),
    #[error(
        "approval webhook URL {0:?} must be https:// (http:// is allowed only to a loopback host)"
    )]
    NotHttps(String),
}

/// POSTs each prompt to a URL.
#[derive(Debug, Clone)]
pub struct WebhookBackend {
    url: String,
    timeout: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    outcome: ApprovalOutcome,
    #[serde(default)]
    scope: ApprovalScope,
}

impl WebhookBackend {
    /// A webhook at `url`.
    ///
    /// # Errors
    ///
    /// A URL that does not parse, or that is not `https://` to a
    /// non-loopback host.
    pub fn new(url: &str) -> Result<Self, WebhookError> {
        let parsed =
            mvm_http::Url::parse(url).map_err(|_| WebhookError::BadUrl(url.to_string()))?;
        let ok = match parsed.scheme() {
            "https" => parsed.host_str().is_some(),
            "http" => mvm_http::is_loopback_host(&parsed),
            _ => false,
        };
        if !ok {
            return Err(WebhookError::NotHttps(url.to_string()));
        }
        Ok(Self {
            url: url.to_string(),
            timeout: DEFAULT_WEBHOOK_TIMEOUT,
        })
    }

    /// Wait at most `timeout` for a reply.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn ask(&self, prompt: &ApprovalPrompt) -> Result<ApprovalAnswer, &'static str> {
        let deadline = Duration::from_millis(prompt.expires_in_ms).min(self.timeout);
        let client = mvm_http::blocking::Client::builder()
            .timeout(deadline)
            .max_response_bytes(MAX_WEBHOOK_REPLY_BYTES)
            .build()
            .map_err(|_| "webhook_error")?;
        let response = client
            .post(&self.url)
            .json(prompt)
            .send()
            .map_err(|_| "webhook_unreachable")?;
        if !response.status().is_success() {
            return Err("webhook_refused");
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_WEBHOOK_REPLY_BYTES)
        {
            return Err("webhook_reply_too_large");
        }
        let mut body = Vec::new();
        response
            .take(MAX_WEBHOOK_REPLY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| "webhook_reply_too_large")?;
        if body.len() as u64 > MAX_WEBHOOK_REPLY_BYTES {
            return Err("webhook_reply_too_large");
        }
        let reply: Reply = serde_json::from_slice(&body).map_err(|_| "webhook_malformed")?;
        Ok(match reply.outcome {
            ApprovalOutcome::Approved => {
                ApprovalAnswer::approved(prompt.request_id.clone(), reply.scope, "webhook")
            }
            ApprovalOutcome::Denied => ApprovalAnswer::denied(prompt.request_id.clone(), "webhook"),
        })
    }
}

impl ApprovalBackend for WebhookBackend {
    fn decide(&self, prompt: &ApprovalPrompt) -> ApprovalAnswer {
        self.ask(prompt)
            .unwrap_or_else(|reason| ApprovalAnswer::denied(prompt.request_id.clone(), reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::policy::approval::ApprovalRequestId;
    use mvm_contract::policy::approval_prompt::ApprovalSubject;
    use std::io::Write;
    use std::net::TcpListener;

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt {
            request_id: ApprovalRequestId::parse("appr-1").unwrap(),
            subject: ApprovalSubject::Egress {
                route_id: "r".into(),
                rule: "rule-1".into(),
                destination: "api.example.com:443".into(),
                method: "POST".into(),
                path: "/x".into(),
            },
            expires_in_ms: 10_000,
        }
    }

    /// A one-shot loopback HTTP server that replies with `reply` verbatim and
    /// hands back the request it received.
    fn serve_once(reply: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://127.0.0.1:{}/approve",
            listener.local_addr().unwrap().port()
        );
        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = socket.read(&mut buf) {
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
                if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if seen.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let _ = socket.write_all(&reply);
            String::from_utf8_lossy(&seen).into_owned()
        });
        (url, handle)
    }

    fn http(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn an_approving_reply_approves_with_its_scope_and_the_prompt_is_posted() {
        let (url, server) = serve_once(http(
            "200 OK",
            r#"{"outcome":"approved","scope":"session"}"#,
        ));
        let answer = WebhookBackend::new(&url).unwrap().decide(&prompt());
        let request = server.join().unwrap();
        assert_eq!(answer.outcome, ApprovalOutcome::Approved);
        assert_eq!(answer.scope, ApprovalScope::Session);
        assert!(request.starts_with("POST /approve"), "{request}");
        assert!(request.contains("\"request_id\":\"appr-1\""), "{request}");
    }

    #[test]
    fn a_redirect_is_refused_not_followed() {
        let (url, server) = serve_once(
            b"HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/elsewhere\r\ncontent-length: 0\r\n\r\n"
                .to_vec(),
        );
        let answer = WebhookBackend::new(&url).unwrap().decide(&prompt());
        server.join().unwrap();
        assert_eq!(answer.outcome, ApprovalOutcome::Denied);
        assert_eq!(answer.reason_label(), "webhook_refused");
    }

    #[test]
    fn an_oversized_reply_is_refused() {
        let big = format!(
            "{{\"outcome\":\"approved\",\"pad\":\"{}\"}}",
            "x".repeat(MAX_WEBHOOK_REPLY_BYTES as usize)
        );
        let (url, server) = serve_once(http("200 OK", &big));
        let answer = WebhookBackend::new(&url).unwrap().decide(&prompt());
        server.join().unwrap();
        assert_eq!(answer.outcome, ApprovalOutcome::Denied);
    }

    #[test]
    fn a_malformed_or_non_2xx_reply_is_a_denial() {
        let (url, server) = serve_once(http("200 OK", r#"{"outcome":"sure"}"#));
        assert_eq!(
            WebhookBackend::new(&url)
                .unwrap()
                .decide(&prompt())
                .reason_label(),
            "webhook_malformed"
        );
        server.join().unwrap();
        let (url, server) = serve_once(http("500 Internal Server Error", "{}"));
        assert_eq!(
            WebhookBackend::new(&url).unwrap().decide(&prompt()).outcome,
            ApprovalOutcome::Denied
        );
        server.join().unwrap();
    }

    #[test]
    fn a_silent_webhook_times_out_as_a_denial() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        );
        let started = std::time::Instant::now();
        let answer = WebhookBackend::new(&url)
            .unwrap()
            .timeout(Duration::from_millis(300))
            .decide(&prompt());
        assert_eq!(answer.outcome, ApprovalOutcome::Denied);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(listener);
    }

    #[test]
    fn only_https_or_loopback_http_is_accepted() {
        assert!(WebhookBackend::new("https://approvals.example.com/hook").is_ok());
        assert!(WebhookBackend::new("http://127.0.0.1:8080/hook").is_ok());
        assert!(WebhookBackend::new("http://[::1]:8080/hook").is_ok());
        assert!(WebhookBackend::new("http://localhost/hook").is_ok());
        for bad in [
            "http://approvals.example.com/hook",
            "http://10.0.0.5/hook",
            "ftp://example.com/",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(WebhookBackend::new(bad).is_err(), "{bad}");
        }
    }
}

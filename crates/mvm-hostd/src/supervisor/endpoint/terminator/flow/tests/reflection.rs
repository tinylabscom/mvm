//! A destination that sends a substituted credential back does not deliver it
//! to the guest.
//!
//! The forward leg here is an echo: it answers with the credential it was
//! actually handed, in a header and in a body streamed in small chunks, so a
//! value is split across chunk boundaries the way a real upstream splits it.
//! What the guest reads has to carry the placeholder in each place, the chain
//! has to say how many times each binding's value came back, and never what
//! the value was.

use super::*;

/// Size of each body chunk the echo sends. Smaller than any value, so every
/// value in the body straddles at least one boundary.
const ECHO_CHUNK: usize = 5;

/// Echoes the credential it was handed.
struct EchoForwarder {
    /// Text appended to the echoed body, for a destination that returns a
    /// value it received earlier.
    extra: String,
    /// `Content-Encoding` to declare on the response, if any.
    encoding: Option<&'static str>,
    /// The `Accept-Encoding` values the forward leg was handed.
    accept_encoding: Mutex<Vec<String>>,
}

impl EchoForwarder {
    fn new() -> Arc<Self> {
        Self::with(String::new(), None)
    }

    fn with(extra: String, encoding: Option<&'static str>) -> Arc<Self> {
        Arc::new(Self {
            extra,
            encoding,
            accept_encoding: Mutex::new(Vec::new()),
        })
    }

    fn echoed(req: &PreparedRequest) -> String {
        req.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl Forwarder for EchoForwarder {
    async fn forward(&self, req: PreparedRequest) -> Result<ForwardResponse, ForwardError> {
        let stream = self.forward_stream(req).await?;
        let mut body = Vec::new();
        let mut receiver = stream.body;
        while let Some(chunk) = receiver.recv().await {
            body.extend(chunk?);
        }
        Ok(ForwardResponse {
            status: stream.status,
            headers: stream.headers,
            body,
        })
    }

    async fn forward_stream(
        &self,
        req: PreparedRequest,
    ) -> Result<ForwardStreamResponse, ForwardError> {
        self.accept_encoding.lock().expect("echo lock").extend(
            req.headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
                .map(|(_, value)| value.clone()),
        );
        let echoed = Self::echoed(&req);
        let body = format!(
            "{{\"headers\":{{\"authorization\":\"{echoed}\"}},\"extra\":\"{}\"}}",
            self.extra
        )
        .into_bytes();
        let mut headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-echo-authorization".to_string(), echoed),
        ];
        if let Some(encoding) = self.encoding {
            headers.push(("content-encoding".to_string(), encoding.to_string()));
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(body.len());
        for chunk in body.chunks(ECHO_CHUNK) {
            sender
                .try_send(Ok(chunk.to_vec()))
                .expect("the channel holds every chunk");
        }
        Ok(ForwardStreamResponse {
            status: 200,
            headers,
            body_len: Some(body.len() as u64),
            body: receiver,
        })
    }
}

fn one_binding(forwarder: Arc<dyn Forwarder>) -> Assembled {
    assemble(
        &[Bound {
            secret: "model-api",
            pattern: BOUND_HOST,
        }],
        &[BOUND_HOST],
        forwarder,
    )
}

fn over_flow_to(vm: &Assembled, host: &str, request: &[u8]) -> Vec<u8> {
    exchange_with(vm, host, &vm.intermediate_pem, request)
        .expect("the guest's tls client completes its handshake")
}

fn head_of(response: &[u8]) -> String {
    let end = super::super::super::find_subslice(response, b"\r\n\r\n").expect("a response head");
    String::from_utf8_lossy(&response[..end]).into_owned()
}

#[test]
fn a_value_echoed_in_a_header_and_a_split_body_reaches_the_guest_as_its_placeholder() {
    let echo = EchoForwarder::new();
    let vm = one_binding(echo.clone());
    let placeholder = vm.placeholders[0].clone();

    let response = over_flow_to(
        &vm,
        BOUND_HOST,
        &request_with_placeholder(&placeholder, BOUND_HOST),
    );
    assert!(
        status_line(&response).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    let text = String::from_utf8_lossy(&response);
    assert!(
        !text.contains(REAL_SECRET),
        "the value reached the guest: {text}"
    );
    assert!(
        head_of(&response).contains(&format!("x-echo-authorization: Bearer {placeholder}")),
        "the echoed header carries the placeholder: {text}"
    );
    let body = String::from_utf8(dechunk(&response)).expect("utf-8 body");
    assert!(
        body.contains(&format!("\"authorization\":\"Bearer {placeholder}\"")),
        "the echoed body carries the placeholder: {body}"
    );

    let chain = vm.audit_chain();
    let line = chain
        .lines()
        .find(|line| line.contains("secret.reflection_scrubbed"))
        .unwrap_or_else(|| panic!("no reflection entry: {chain}"));
    assert!(line.contains("model-api"), "{line}");
    assert!(line.contains(BOUND_HOST), "{line}");
    assert!(line.contains("\"count\":\"2\""), "header and body: {line}");
    assert!(!chain.contains(REAL_SECRET), "no value in the chain");
}

#[test]
fn a_value_returned_later_by_another_destination_is_scrubbed_too() {
    // The second destination returns the first secret's value, which it could
    // only have had from somewhere else. Both values share a prefix — the
    // second is the first plus a suffix — so the longer must win the match.
    let echo = EchoForwarder::with(REAL_SECRET.to_string(), None);
    let vm = assemble(
        &[
            Bound {
                secret: "model-api",
                pattern: BOUND_HOST,
            },
            Bound {
                secret: "ci-token",
                pattern: OTHER_HOST,
            },
        ],
        &[BOUND_HOST, OTHER_HOST],
        echo,
    );
    let first = over_flow_to(
        &vm,
        BOUND_HOST,
        &request_with_placeholder(&vm.placeholders[0], BOUND_HOST),
    );
    assert!(status_line(&first).starts_with("HTTP/1.1 200"));
    let second = over_flow_to(
        &vm,
        OTHER_HOST,
        &request_with_placeholder(&vm.placeholders[1], OTHER_HOST),
    );
    assert!(status_line(&second).starts_with("HTTP/1.1 200"));

    let body = String::from_utf8(dechunk(&second)).expect("utf-8 body");
    assert!(!body.contains(REAL_SECRET), "{body}");
    assert!(
        body.contains(&format!("Bearer {}", vm.placeholders[1])),
        "its own value becomes its own placeholder: {body}"
    );
    assert!(
        body.contains(&format!("\"extra\":\"{}\"", vm.placeholders[0])),
        "the earlier value becomes the earlier placeholder: {body}"
    );
    let chain = vm.audit_chain();
    assert!(chain.contains("ci-token"), "{chain}");
    assert!(!chain.contains(REAL_SECRET), "{chain}");
}

#[test]
fn a_response_without_the_value_is_relayed_unchanged_and_records_nothing() {
    let harness = harness(BOUND_HOST, b"{\"ok\":true}");
    let response = exchange(
        &harness,
        &request_with_placeholder(&harness.placeholder, BOUND_HOST),
    );
    assert!(status_line(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(dechunk(&response), b"{\"ok\":true}");
    assert!(
        !harness.audit_chain().contains("secret.reflection_scrubbed"),
        "nothing came back, so nothing is recorded"
    );
}

#[test]
fn the_upstream_is_asked_for_an_unencoded_response() {
    let echo = EchoForwarder::new();
    let vm = one_binding(echo.clone());
    let request = format!(
        "GET /v1/models HTTP/1.1\r\nhost: {BOUND_HOST}\r\nauthorization: Bearer {}\r\naccept-encoding: gzip, br\r\n\r\n",
        vm.placeholders[0]
    );
    let response = over_flow_to(&vm, BOUND_HOST, request.as_bytes());
    assert!(status_line(&response).starts_with("HTTP/1.1 200"));
    assert_eq!(
        *echo.accept_encoding.lock().expect("echo lock"),
        ["identity"],
        "the guest's accept-encoding is replaced, not forwarded"
    );
}

#[test]
fn an_encoded_response_is_refused_rather_than_relayed_unread() {
    let echo = EchoForwarder::with(String::new(), Some("gzip"));
    let vm = one_binding(echo);
    let response = over_flow_to(
        &vm,
        BOUND_HOST,
        &request_with_placeholder(&vm.placeholders[0], BOUND_HOST),
    );
    assert!(
        status_line(&response).starts_with("HTTP/1.1 502"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    assert!(!String::from_utf8_lossy(&response).contains(REAL_SECRET));
    let chain = vm.audit_chain();
    assert!(chain.contains("response_encoded_unscannable"), "{chain}");
    assert!(chain.contains("response_refused"), "{chain}");
}

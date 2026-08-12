use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
const MAX_HEADER_BYTES: usize = 16 * 1024;

pub struct TestHttpServer {
    addr: SocketAddr,
    routes: Arc<Mutex<Vec<Route>>>,
    task: JoinHandle<()>,
}

impl TestHttpServer {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP server");
        let addr = listener.local_addr().expect("read test HTTP server addr");
        let routes = Arc::new(Mutex::new(Vec::new()));
        let accept_routes = Arc::clone(&routes);
        let task = tokio::spawn(async move {
            run_accept_loop(listener, accept_routes).await;
        });
        Self { addr, routes, task }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn register(&self, route: Route) {
        self.routes.lock().expect("lock test routes").push(route);
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct Route {
    method: String,
    path: String,
    expected_auth: Option<String>,
    responder: Responder,
}

impl Route {
    pub fn exact(method: impl Into<String>, path: impl Into<String>, responder: Responder) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            expected_auth: None,
            responder,
        }
    }

    pub fn with_bearer_auth(mut self, token: impl Into<String>) -> Self {
        self.expected_auth = Some(format!("Bearer {}", token.into()));
        self
    }

    pub fn with_authorization(mut self, authorization: impl Into<String>) -> Self {
        self.expected_auth = Some(authorization.into());
        self
    }

    fn matches(&self, request: &ParsedRequest) -> bool {
        self.method == request.method
            && self.path == request.path
            && self.expected_auth.as_deref() == request.authorization.as_deref()
    }
}

pub enum Responder {
    Static(TestResponse),
    Flaky(FlakyResponder),
}

impl Responder {
    fn respond(&self) -> TestResponse {
        match self {
            Self::Static(response) => response.clone(),
            Self::Flaky(responder) => responder.respond(),
        }
    }
}

pub struct FlakyResponder {
    calls: Arc<AtomicU32>,
    fail_first: u32,
    success: TestResponse,
}

impl FlakyResponder {
    pub fn new(fail_first: u32, success: TestResponse) -> Self {
        Self {
            calls: Arc::new(AtomicU32::new(0)),
            fail_first,
            success,
        }
    }

    fn respond(&self) -> TestResponse {
        let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
        if attempt < self.fail_first {
            TestResponse::builder(503)
                .header("Content-Type", "text/plain")
                .body_string("Service Unavailable")
                .build()
        } else {
            self.success.clone()
        }
    }
}

#[derive(Clone)]
pub struct TestResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl TestResponse {
    pub fn builder(status: u16) -> TestResponseBuilder {
        TestResponseBuilder {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

pub struct TestResponseBuilder {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl TestResponseBuilder {
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body_bytes(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    pub fn body_string(self, body: impl Into<String>) -> Self {
        self.body_bytes(body.into().into_bytes())
    }

    pub fn build(self) -> TestResponse {
        TestResponse {
            status: self.status,
            headers: self.headers,
            body: self.body,
        }
    }
}

struct ParsedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
}

async fn run_accept_loop(listener: TcpListener, routes: Arc<Mutex<Vec<Route>>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let connection_routes = Arc::clone(&routes);
        tokio::spawn(async move {
            let _ = handle_connection(stream, connection_routes).await;
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    routes: Arc<Mutex<Vec<Route>>>,
) -> std::io::Result<()> {
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(_) => {
            write_response(
                &mut stream,
                &TestResponse::builder(400)
                    .header("Content-Type", "text/plain")
                    .body_string("bad request")
                    .build(),
            )
            .await?;
            return Ok(());
        }
    };

    let response = routes
        .lock()
        .expect("lock test routes")
        .iter()
        .find(|route| route.matches(&request))
        .map(|route| route.responder.respond())
        .unwrap_or_else(not_found_response);

    write_response(&mut stream, &response).await
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<ParsedRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer
            .windows(HEADER_TERMINATOR.len())
            .any(|window| window == HEADER_TERMINATOR)
        {
            break;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test request headers too large",
            ));
        }
    }
    parse_request(&buffer)
}

fn parse_request(bytes: &[u8]) -> std::io::Result<ParsedRequest> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "request not utf-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing request line")
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing method"))?;
    let path = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing path"))?;
    let authorization = lines.find_map(parse_authorization_header);
    Ok(ParsedRequest {
        method: method.to_string(),
        path: path.to_string(),
        authorization,
    })
}

fn parse_authorization_header(line: &str) -> Option<String> {
    let (name, value) = line.split_once(':')?;
    if !name.eq_ignore_ascii_case("authorization") {
        return None;
    }
    Some(value.trim().to_string())
}

async fn write_response(stream: &mut TcpStream, response: &TestResponse) -> std::io::Result<()> {
    let mut bytes = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason_phrase(response.status)
    )
    .into_bytes();
    let has_content_length = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    for (name, value) in &response.headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    if !has_content_length {
        bytes.extend_from_slice(format!("Content-Length: {}\r\n", response.body.len()).as_bytes());
    }
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    bytes.extend_from_slice(&response.body);
    stream.write_all(&bytes).await?;
    stream.flush().await
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

fn not_found_response() -> TestResponse {
    TestResponse::builder(404)
        .header("Content-Type", "text/plain")
        .body_string("not found")
        .build()
}

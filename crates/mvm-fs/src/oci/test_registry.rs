//! A small image registry that runs in-process, for tests that push and pull.
//!
//! It speaks the part of the distribution API a single-layer artifact needs —
//! blob `HEAD`/`GET`, the two-request upload, and manifest `PUT`/`GET` — and
//! records every request so a test can assert that none were made. It checks
//! uploaded blob digests the way a real registry does, and offers hooks to
//! serve bytes that do not match what was stored, which is how the client's
//! own re-hashing is exercised.
//!
//! The server runs on its own thread with its own runtime, so synchronous
//! callers (the CLI's blocking entry points) and async tests use it the same
//! way. Test-only: compiled for this crate's tests and behind `test-support`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use sha2::{Digest, Sha256};

const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// One request as the registry saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
}

#[derive(Default)]
struct State {
    blobs: HashMap<String, Vec<u8>>,
    // (repository, tag-or-digest) -> (media type, bytes)
    manifests: HashMap<(String, String), (String, Vec<u8>)>,
    served_blob_override: HashMap<String, Vec<u8>>,
    served_manifest_override: HashMap<(String, String), Vec<u8>>,
    advertised_digest_override: HashMap<(String, String), String>,
    omit_digest_header: bool,
    upload_location_origin: Option<String>,
    required_token: Option<String>,
    requests: Vec<RecordedRequest>,
}

/// A running registry. Dropping it stops the server.
pub struct MemoryRegistry {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
}

impl MemoryRegistry {
    /// Bind to an ephemeral loopback port and start serving.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test registry");
        let addr = listener.local_addr().expect("test registry address");
        let state = Arc::new(Mutex::new(State::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let upload_ids = Arc::new(AtomicU64::new(0));
        let (thread_state, thread_stop) = (Arc::clone(&state), Arc::clone(&stop));
        thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (state, ids) = (Arc::clone(&thread_state), Arc::clone(&upload_ids));
                thread::spawn(move || {
                    let _ = serve(stream, addr, &state, &ids);
                });
            }
        });
        Self { addr, state, stop }
    }

    /// `host:port`, usable as the registry part of a reference.
    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.lock().requests.clone()
    }

    /// Stored blob bytes, if the registry holds that digest.
    pub fn blob(&self, digest: &str) -> Option<Vec<u8>> {
        self.lock().blobs.get(digest).cloned()
    }

    /// Stored manifest bytes at a tag or digest.
    pub fn manifest(&self, repository: &str, reference: &str) -> Option<Vec<u8>> {
        self.lock()
            .manifests
            .get(&(repository.to_string(), reference.to_string()))
            .map(|(_, bytes)| bytes.clone())
    }

    /// Store a manifest directly, bypassing the upload path, under `reference`
    /// and under the digest of `bytes`.
    pub fn insert_manifest(
        &self,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
    ) {
        let digest = sha256_digest(bytes);
        let mut state = self.lock();
        for key in [reference.to_string(), digest] {
            state.manifests.insert(
                (repository.to_string(), key),
                (media_type.to_string(), bytes.to_vec()),
            );
        }
    }

    /// Store a blob directly, bypassing the upload path.
    pub fn insert_blob(&self, bytes: &[u8]) -> String {
        let digest = sha256_digest(bytes);
        self.lock().blobs.insert(digest.clone(), bytes.to_vec());
        digest
    }

    /// Serve `bytes` for `digest` from now on, whatever was uploaded.
    pub fn serve_blob_as(&self, digest: &str, bytes: &[u8]) {
        self.lock()
            .served_blob_override
            .insert(digest.to_string(), bytes.to_vec());
    }

    /// Serve `bytes` for a manifest reference from now on.
    pub fn serve_manifest_as(&self, repository: &str, reference: &str, bytes: &[u8]) {
        self.lock().served_manifest_override.insert(
            (repository.to_string(), reference.to_string()),
            bytes.to_vec(),
        );
    }

    /// Advertise `digest` in `Docker-Content-Digest` for a manifest reference.
    pub fn advertise_manifest_digest(&self, repository: &str, reference: &str, digest: &str) {
        self.lock().advertised_digest_override.insert(
            (repository.to_string(), reference.to_string()),
            digest.to_string(),
        );
    }

    /// Stop sending `Docker-Content-Digest` on manifest responses.
    pub fn omit_digest_header(&self) {
        self.lock().omit_digest_header = true;
    }

    /// Hand out upload locations on another origin.
    pub fn upload_locations_on(&self, origin: &str) {
        self.lock().upload_location_origin = Some(origin.to_string());
    }

    /// Refuse every `/v2/` request that lacks `Bearer <token>`, answering
    /// with a challenge whose token endpoint issues exactly that token.
    pub fn require_token(&self, token: &str) {
        self.lock().required_token = Some(token.to_string());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("test registry state")
    }
}

impl Drop for MemoryRegistry {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it observes the flag.
        let _ = TcpStream::connect(self.addr);
    }
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

struct Request {
    method: String,
    target: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    head_only: bool,
}

impl Response {
    fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            head_only: false,
        }
    }

    fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
}

fn serve(
    mut stream: TcpStream,
    addr: SocketAddr,
    state: &Mutex<State>,
    upload_ids: &AtomicU64,
) -> std::io::Result<()> {
    let Some(request) = read_request(&mut stream)? else {
        return Ok(());
    };
    let response = route(&request, addr, state, upload_ids);
    write_response(&mut stream, &response)
}

fn route(
    request: &Request,
    addr: SocketAddr,
    state: &Mutex<State>,
    upload_ids: &AtomicU64,
) -> Response {
    let (path, query) = request
        .target
        .split_once('?')
        .unwrap_or((request.target.as_str(), ""));
    let mut state = state.lock().expect("test registry state");
    state.requests.push(RecordedRequest {
        method: request.method.clone(),
        path: path.to_string(),
    });

    if path == "/token" {
        return match &state.required_token {
            Some(token) => Response::new(200)
                .header("Content-Type", "application/json")
                .body(format!("{{\"token\":\"{token}\"}}").into_bytes()),
            None => Response::new(404),
        };
    }
    if let Some(token) = &state.required_token {
        if request.authorization.as_deref() != Some(&format!("Bearer {token}")) {
            return Response::new(401).header(
                "WWW-Authenticate",
                format!(
                    "Bearer realm=\"http://{addr}/token\",service=\"test-registry\",scope=\"repository:any:pull,push\""
                ),
            );
        }
    }

    let Some(rest) = path.strip_prefix("/v2/") else {
        return Response::new(404);
    };
    if let Some((repository, id)) = rest.split_once("/blobs/uploads/") {
        return upload(&mut state, request, repository, id, query, addr, upload_ids);
    }
    if let Some((_, digest)) = rest.rsplit_once("/blobs/") {
        return blob(&state, request, digest);
    }
    if let Some((repository, reference)) = rest.rsplit_once("/manifests/") {
        return manifest(&mut state, request, repository, reference);
    }
    Response::new(404)
}

fn blob(state: &State, request: &Request, digest: &str) -> Response {
    let Some(stored) = state.blobs.get(digest) else {
        return Response::new(404);
    };
    let served = state
        .served_blob_override
        .get(digest)
        .unwrap_or(stored)
        .clone();
    match request.method.as_str() {
        "HEAD" => {
            let mut response =
                Response::new(200).header("Content-Length", served.len().to_string());
            response.head_only = true;
            response
        }
        "GET" => Response::new(200)
            .header("Content-Type", "application/octet-stream")
            .body(served),
        _ => Response::new(405),
    }
}

fn upload(
    state: &mut State,
    request: &Request,
    repository: &str,
    id: &str,
    query: &str,
    addr: SocketAddr,
    upload_ids: &AtomicU64,
) -> Response {
    match (request.method.as_str(), id) {
        ("POST", "") => {
            let next = upload_ids.fetch_add(1, Ordering::SeqCst);
            let origin = state
                .upload_location_origin
                .clone()
                .unwrap_or_else(|| format!("http://{addr}"));
            Response::new(202).header(
                "Location",
                format!("{origin}/v2/{repository}/blobs/uploads/{next}?session=s{next}"),
            )
        }
        ("PUT", id) if !id.is_empty() => {
            let Some(digest) = query
                .split('&')
                .find_map(|pair| pair.strip_prefix("digest="))
                .map(|d| d.replace("%3A", ":"))
            else {
                return Response::new(400);
            };
            if sha256_digest(&request.body) != digest {
                return Response::new(400).body(b"DIGEST_INVALID".to_vec());
            }
            state.blobs.insert(digest.clone(), request.body.clone());
            Response::new(201)
                .header("Location", format!("/v2/{repository}/blobs/{digest}"))
                .header("Docker-Content-Digest", digest)
        }
        _ => Response::new(405),
    }
}

fn manifest(state: &mut State, request: &Request, repository: &str, reference: &str) -> Response {
    let key = (repository.to_string(), reference.to_string());
    match request.method.as_str() {
        "PUT" => {
            let digest = sha256_digest(&request.body);
            for stored_under in [reference.to_string(), digest.clone()] {
                state.manifests.insert(
                    (repository.to_string(), stored_under),
                    (
                        "application/vnd.oci.image.manifest.v1+json".to_string(),
                        request.body.clone(),
                    ),
                );
            }
            Response::new(201).header("Docker-Content-Digest", digest)
        }
        "GET" => {
            let Some((media_type, stored)) = state.manifests.get(&key) else {
                return Response::new(404);
            };
            let served = state
                .served_manifest_override
                .get(&key)
                .unwrap_or(stored)
                .clone();
            let mut response = Response::new(200).header("Content-Type", media_type.clone());
            if !state.omit_digest_header {
                let advertised = state
                    .advertised_digest_override
                    .get(&key)
                    .cloned()
                    .unwrap_or_else(|| sha256_digest(&served));
                response = response.header("Docker-Content-Digest", advertised);
            }
            response.body(served)
        }
        _ => Response::new(405),
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = buffer
            .windows(HEADER_TERMINATOR.len())
            .position(|window| window == HEADER_TERMINATOR)
        {
            break pos;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(std::io::Error::other("test request headers too large"));
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let target = request_line.next().unwrap_or_default().to_string();
    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.trim().to_string());
        }
    }
    let mut body = buffer[header_end + HEADER_TERMINATOR.len()..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(Some(Request {
        method,
        target,
        authorization,
        body,
    }))
}

fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {} Test\r\n", response.status).into_bytes();
    for (name, value) in &response.headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !response.head_only {
        out.extend_from_slice(format!("Content-Length: {}\r\n", response.body.len()).as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    if !response.head_only {
        out.extend_from_slice(&response.body);
    }
    stream.write_all(&out)?;
    stream.flush()
}

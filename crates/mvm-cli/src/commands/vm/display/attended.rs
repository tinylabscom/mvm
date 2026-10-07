//! The attended half of `mvmctl machine display`: the same loopback viewer,
//! plus a page that sends a human's pointer, keys and text back through the
//! display input gate.
//!
//! The token authorizes a session rather than one request, because the page
//! needs three paths: itself, the frame stream, and the input endpoint. It is
//! still random, still bound to `127.0.0.1` only, and printed once. An input
//! request whose `Origin` names any other origin is refused, so a page served
//! from elsewhere cannot post into the session even if it guessed the token.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use mvm_client::display::{
    DisplayAuthority, DisplayInputRoute, DisplayInputRouteError, on_interrupt,
};
use mvm_contract::stream::{DisplayInputEvent, DisplayInputFrame};
use rand::Rng as _;
use serde::Deserialize;

use super::{REQUEST_TIMEOUT, bind_loopback, open_frames, serve_frames};

const HEADER_LIMIT: usize = 8 * 1024;
const BODY_LIMIT: usize = 512 * 1024;
/// Half the lease lifetime, so a human who pauses never loses the session.
const REFRESH_EVERY: Duration = Duration::from_secs(10);

type SharedRoute = Arc<Mutex<Option<DisplayInputRoute>>>;

/// Serve frames and accept attended input for `name` until the page ends the
/// session or the process is interrupted.
pub(super) fn serve(name: &str, authority: &DisplayAuthority) -> Result<()> {
    // Opened once here so a machine with no frame stream fails before any
    // input authority is taken; the viewer's frame request reopens it on its
    // own thread.
    drop(open_frames(name)?);
    let route = authority
        .open_input()
        .with_context(|| format!("open attended display input on {name:?}"))?;
    let route: SharedRoute = Arc::new(Mutex::new(Some(route)));
    // An interrupt skips destructors. Closing the route here is what ends an
    // open credential entry, so recording resumes and the chain records it.
    let interrupt_route = Arc::clone(&route);
    let _cleanup = on_interrupt("display input session", move || {
        close_route(&interrupt_route);
    });
    let stop = Arc::new(AtomicBool::new(false));
    spawn_refresher(Arc::clone(&route), Arc::clone(&stop));

    let listener = bind_loopback().context("bind the local display viewer")?;
    let address = listener.local_addr().context("read the viewer address")?;
    let session = Session::new(address);
    println!(
        "Open {} to view and drive {name:?}. The URL is private: anyone with it can send input until you end the session.",
        session.url()
    );
    if authority.attended() {
        println!("This run is attended: its signed plan says a human is driving it.");
    }
    let result = session.accept_loop(&listener, &route, name);
    stop.store(true, Ordering::Release);
    close_route(&route);
    result
}

fn spawn_refresher(route: SharedRoute, stop: Arc<AtomicBool>) {
    let spawned = std::thread::Builder::new()
        .name("mvm-display-refresh".into())
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(REFRESH_EVERY);
                let mut held = route.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(route) = held.as_mut()
                    && let Err(refusal) = route.refresh()
                {
                    eprintln!("display input session ended: {refusal}");
                    return;
                }
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(error = %error, "display input lease will not be refreshed while idle");
    }
}

fn close_route(route: &SharedRoute) {
    if let Some(route) = route.lock().unwrap_or_else(PoisonError::into_inner).take() {
        route.close();
    }
}

/// The body the page posts: a batch of events, numbered by the viewer.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputBatch {
    events: Vec<DisplayInputEvent>,
}

struct Session {
    address: SocketAddr,
    token: String,
    nonce: String,
    next_seq: u64,
}

/// What one request asks the session for.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Page,
    Frames,
    Input,
    Close,
}

impl Session {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            token: random_hex(),
            nonce: random_hex(),
            next_seq: 0,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/{}", self.address, self.token)
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn accept_loop(
        mut self,
        listener: &TcpListener,
        route: &SharedRoute,
        name: &str,
    ) -> Result<()> {
        let mut frames_open = false;
        loop {
            let (mut client, peer) = listener.accept().context("accept local viewer")?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let Ok(request) = read_request(&mut client) else {
                respond(&mut client, "400 Bad Request", "text/plain", b"");
                continue;
            };
            match self.classify(&request) {
                Some(Route::Page) => {
                    let page = page(&self.token, &self.nonce);
                    respond_page(&mut client, &self.nonce, page.as_bytes());
                }
                Some(Route::Frames) if frames_open => {
                    respond(
                        &mut client,
                        "409 Conflict",
                        "text/plain",
                        b"frames already open",
                    );
                }
                Some(Route::Frames) => {
                    frames_open = true;
                    let name = name.to_string();
                    std::thread::spawn(move || {
                        let served = open_frames(&name)
                            .and_then(|mut stream| serve_frames(&mut client, &mut stream));
                        if let Err(error) = served {
                            tracing::debug!(error = %error, "display frame viewer closed");
                        }
                    });
                }
                Some(Route::Input) => self.input(&mut client, route, &request.body),
                Some(Route::Close) => {
                    respond(&mut client, "204 No Content", "text/plain", b"");
                    return Ok(());
                }
                None => respond(&mut client, "403 Forbidden", "text/plain", b""),
            }
        }
    }

    fn classify(&self, request: &Request) -> Option<Route> {
        let rest = request
            .path
            .strip_prefix('/')?
            .strip_prefix(self.token.as_str())?;
        let posting = request.method == "POST";
        if posting
            && request
                .origin
                .as_deref()
                .is_some_and(|origin| origin != self.origin())
        {
            return None;
        }
        match (request.method.as_str(), rest) {
            ("GET", "") => Some(Route::Page),
            ("GET", "/frames") => Some(Route::Frames),
            ("POST", "/input") => Some(Route::Input),
            ("POST", "/close") => Some(Route::Close),
            _ => None,
        }
    }

    fn input(&mut self, client: &mut TcpStream, route: &SharedRoute, body: &[u8]) {
        let batch: InputBatch = match serde_json::from_slice(body) {
            Ok(batch) => batch,
            Err(error) => {
                respond(
                    client,
                    "400 Bad Request",
                    "text/plain",
                    error.to_string().as_bytes(),
                );
                return;
            }
        };
        let frame = DisplayInputFrame {
            seq: self.next_seq,
            events: batch.events,
        };
        self.next_seq = self.next_seq.saturating_add(1);
        let mut held = route.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(route) = held.as_mut() else {
            respond(
                client,
                "410 Gone",
                "text/plain",
                b"the input session has ended",
            );
            return;
        };
        match route.write(frame) {
            Ok(()) => respond(client, "204 No Content", "text/plain", b""),
            Err(error @ DisplayInputRouteError::Refused(_)) => {
                respond(
                    client,
                    "403 Forbidden",
                    "text/plain",
                    error.to_string().as_bytes(),
                );
            }
            Err(error @ DisplayInputRouteError::Undelivered(_)) => {
                respond(
                    client,
                    "502 Bad Gateway",
                    "text/plain",
                    error.to_string().as_bytes(),
                );
            }
        }
    }
}

fn random_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    origin: Option<String>,
    content_length: usize,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        if buffer.len() >= HEADER_LIMIT {
            return Err(invalid("request headers are too large"));
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(invalid("request ended before its headers"));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let mut request = parse_head(&buffer[..header_end])?;
    let length = request.content_length;
    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(invalid("request ended before its body"));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    request.body = body;
    Ok(request)
}

/// Parse the request line and the two headers the session reads. The body is
/// read afterwards, up to the declared length.
fn parse_head(head: &[u8]) -> std::io::Result<Request> {
    let head = std::str::from_utf8(head).map_err(|_| invalid("request is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(path), Some("HTTP/1.1")) = (first.next(), first.next(), first.next())
    else {
        return Err(invalid("malformed request line"));
    };
    let mut origin = None;
    let mut length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("origin") {
            origin = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            length = value
                .parse()
                .map_err(|_| invalid("invalid content length"))?;
        }
    }
    if length > BODY_LIMIT {
        return Err(invalid("request body is too large"));
    }
    Ok(Request {
        method: method.to_string(),
        path: path.to_string(),
        origin,
        content_length: length,
        body: Vec::new(),
    })
}

fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn respond(client: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = client.write_all(head.as_bytes());
    let _ = client.write_all(body);
}

fn respond_page(client: &mut TcpStream, nonce: &str, page: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        page.len()
    );
    let _ = client.write_all(head.as_bytes());
    let _ = client.write_all(page);
}

/// The viewer page. It holds no state the host does not: every event is sent
/// as it happens, in order, one request at a time.
fn page(token: &str, nonce: &str) -> String {
    format!(
        r#"<!doctype html>
<meta charset="utf-8">
<title>Attended display</title>
<style nonce="{nonce}">
body {{ margin: 0; background: #111; color: #ddd; font: 14px sans-serif; }}
#bar {{ padding: 6px; }}
#screen {{ max-width: 100%; cursor: crosshair; outline: none; }}
</style>
<div id="bar">
<button id="begin">Begin credential entry</button>
<button id="end">End credential entry</button>
<button id="close">End session</button>
<span id="status"></span>
</div>
<img id="screen" tabindex="0" alt="workload display" src="/{token}/frames">
<script nonce="{nonce}">
const base = "/{token}";
const screen = document.getElementById("screen");
const status = document.getElementById("status");
const buttons = ["left", "middle", "right"];
let queue = [];
let sending = false;
function push(event) {{ queue.push(event); flush(); }}
async function flush() {{
  if (sending || queue.length === 0) return;
  sending = true;
  const events = queue.splice(0, 256);
  try {{
    const reply = await fetch(base + "/input", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{ events }}),
    }});
    status.textContent = reply.ok ? "" : await reply.text();
  }} catch (error) {{
    status.textContent = String(error);
  }}
  sending = false;
  flush();
}}
function at(event) {{
  const box = screen.getBoundingClientRect();
  return {{
    x: Math.max(0, Math.round((event.clientX - box.left) * screen.naturalWidth / box.width)),
    y: Math.max(0, Math.round((event.clientY - box.top) * screen.naturalHeight / box.height)),
  }};
}}
function button(event) {{ return buttons[event.button] || "left"; }}
screen.addEventListener("mousedown", (event) => {{
  event.preventDefault();
  screen.focus();
  push({{ kind: "pointer-button", ...at(event), button: button(event), pressed: true }});
}});
screen.addEventListener("mouseup", (event) => {{
  push({{ kind: "pointer-button", ...at(event), button: button(event), pressed: false }});
}});
let lastMove = 0;
screen.addEventListener("mousemove", (event) => {{
  const now = Date.now();
  if (now - lastMove < 50) return;
  lastMove = now;
  push({{ kind: "pointer-move", ...at(event) }});
}});
screen.addEventListener("wheel", (event) => {{
  event.preventDefault();
  push({{ kind: "wheel", ...at(event), delta_x: Math.round(event.deltaX), delta_y: Math.round(event.deltaY) }});
}}, {{ passive: false }});
screen.addEventListener("keydown", (event) => {{
  event.preventDefault();
  push({{ kind: "key", key: event.key, pressed: true }});
}});
screen.addEventListener("keyup", (event) => {{
  event.preventDefault();
  push({{ kind: "key", key: event.key, pressed: false }});
}});
document.addEventListener("paste", (event) => {{
  event.preventDefault();
  const text = event.clipboardData.getData("text");
  if (text) push({{ kind: "paste", text }});
}});
screen.addEventListener("dragstart", (event) => event.preventDefault());
screen.addEventListener("contextmenu", (event) => event.preventDefault());
document.getElementById("begin").onclick = () => push({{ kind: "credential-entry-begin" }});
document.getElementById("end").onclick = () => push({{ kind: "credential-entry-end" }});
document.getElementById("close").onclick = () => fetch(base + "/close", {{ method: "POST" }});
</script>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session {
            address: "127.0.0.1:4100".parse().unwrap(),
            token: "t0k".into(),
            nonce: "n0nce".into(),
            next_seq: 0,
        }
    }

    fn request(method: &str, path: &str, origin: Option<&str>) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            origin: origin.map(str::to_string),
            content_length: 0,
            body: Vec::new(),
        }
    }

    #[test]
    fn the_token_scopes_every_path_and_nothing_else() {
        let session = session();
        assert_eq!(
            session.classify(&request("GET", "/t0k", None)),
            Some(Route::Page)
        );
        assert_eq!(
            session.classify(&request("GET", "/t0k/frames", None)),
            Some(Route::Frames)
        );
        assert_eq!(
            session.classify(&request("POST", "/t0k/input", None)),
            Some(Route::Input)
        );
        assert_eq!(session.classify(&request("GET", "/t0k/input", None)), None);
        assert_eq!(
            session.classify(&request("POST", "/other/input", None)),
            None
        );
        assert_eq!(session.classify(&request("GET", "/t0kX", None)), None);
    }

    #[test]
    fn input_from_another_origin_is_refused() {
        let session = session();
        assert_eq!(
            session.classify(&request(
                "POST",
                "/t0k/input",
                Some("http://127.0.0.1:4100")
            )),
            Some(Route::Input)
        );
        assert_eq!(
            session.classify(&request("POST", "/t0k/input", Some("https://evil.example"))),
            None
        );
        assert_eq!(
            session.classify(&request("POST", "/t0k/close", Some("null"))),
            None
        );
    }

    #[test]
    fn a_batch_carries_only_contract_events() {
        let batch: InputBatch = serde_json::from_str(
            r#"{"events":[{"kind":"pointer-move","x":1,"y":2},{"kind":"credential-entry-begin"}]}"#,
        )
        .unwrap();
        assert_eq!(batch.events.len(), 2);
        assert!(serde_json::from_str::<InputBatch>(r#"{"events":[],"seq":9}"#).is_err());
        assert!(serde_json::from_str::<InputBatch>(r#"{"events":[{"kind":"evaluate"}]}"#).is_err());
    }

    #[test]
    fn request_heads_are_bounded_and_parsed() {
        let head = b"POST /t0k/input HTTP/1.1\r\nOrigin: http://127.0.0.1:4100\r\nContent-Length: 12\r\n\r\n";
        let request = parse_head(head).unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.origin.as_deref(), Some("http://127.0.0.1:4100"));
        assert_eq!(request.content_length, 12);
        let huge = format!(
            "POST /t0k/input HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            BODY_LIMIT + 1
        );
        assert!(parse_head(huge.as_bytes()).is_err());
        assert!(parse_head(b"GET /t0k HTTP/1.0\r\n\r\n").is_err());
    }

    #[test]
    fn the_page_scripts_run_only_under_the_session_nonce() {
        let page = page("t0k", "n0nce");
        assert!(page.contains(r#"<script nonce="n0nce">"#));
        assert!(page.contains(r#"src="/t0k/frames""#));
        assert!(!page.contains("<script>"));
    }
}

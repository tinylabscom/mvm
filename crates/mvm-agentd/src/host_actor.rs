//! Guest lifecycle calls with no plaintext broker fallback.

use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use mvm_contract::protocol::workload_actor::{ActorRequest, ActorResponse};
use mvm_core::net::actor_session::{
    ACTOR_BINDING_FILE, ACTOR_GUEST_KEY_FILE, ACTOR_ROUTE_PREFACE, ActorDeadlineStream,
    ActorSession, ActorSessionBinding, MAX_ACTOR_BINDING_BYTES,
};
use zeroize::Zeroizing;

/// Call the admitted host lifecycle endpoint once, with a bounded total deadline.
///
/// Missing identity, wrong boot, failed authentication and malformed replies all
/// fail closed. A transport error after sending is an unknown outcome; callers
/// must retain their operation's idempotency key rather than invent a new one.
pub fn call(request: &ActorRequest, timeout: Duration) -> Result<ActorResponse> {
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(300),
        "invalid actor deadline"
    );
    let binding_bytes = read_bounded(
        &Path::new(crate::flowmux_drive::RUN_MVM_DIR).join(ACTOR_BINDING_FILE),
        MAX_ACTOR_BINDING_BYTES,
    )?;
    let binding: ActorSessionBinding =
        serde_json::from_slice(&binding_bytes).context("actor binding unavailable")?;
    binding.session_id()?;
    let seed = read_bounded(
        &Path::new(crate::flowmux_drive::RUN_MVM_DIR).join(ACTOR_GUEST_KEY_FILE),
        32,
    )?;
    let key = SigningKey::from_bytes(seed.as_slice().try_into().context("invalid actor key")?);
    ensure!(
        key.verifying_key().to_bytes() == binding.guest_public_key,
        "actor identity mismatch"
    );
    let deadline = Instant::now() + timeout;
    let stream =
        crate::vsock::connect_host_vsock(crate::vsock::BROKER_PORT, timeout.as_secs().max(1))?;
    let mut stream = ActorDeadlineStream::new(stream, deadline)?;
    stream.write_all(&ACTOR_ROUTE_PREFACE)?;
    let mut session = ActorSession::guest(&mut stream, &binding, key)?;
    session.send_request(&mut stream, request)?;
    session
        .receive_response(&mut stream)
        .context("actor response unavailable")
}

fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = std::fs::File::open(path).context("actor identity unavailable")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "actor identity exceeds bound");
    Ok(bytes)
}

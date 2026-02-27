# Sprint 17: Wire Authenticated Vsock Protocol

## Context

The Ed25519 vsock authentication infrastructure is fully implemented but unused:
- **Types:** `AuthenticatedFrame`, `SessionHello`/`SessionHelloAck`, `SecurityPolicy`, `AccessPolicy`, `RateLimitPolicy`, `SessionPolicy` in `mvm-core/src/security.rs`
- **Wire functions:** `write_authenticated_frame`, `read_authenticated_frame`, `handshake_as_host`, `handshake_as_guest` in `mvm-guest/src/vsock.rs`
- **Signing:** `SignedPayload` in `mvm-core/src/signing.rs`, Ed25519 via `ed25519-dalek`

The production vsock path (`connect_to` -> `send_request`) still uses unauthenticated length-prefixed JSON. The guest agent (`mvm-guest-agent`) reads/writes raw frames with no session or signing.

This sprint wires the existing primitives into the production code paths with backward-compatible version negotiation.

---

## Deliverables

### 1. Host-side key provisioning

Before VM boot, generate per-session Ed25519 keypair and write it to the secrets drive.

**Files:**
- MODIFY: `crates/mvm-runtime/src/vm/instance/lifecycle.rs` — after creating the secrets drive image, write session keys
- NEW: `crates/mvm-runtime/src/vm/session_keys.rs` — generate keypair, serialize PEM/raw, write to drive

**Key paths on secrets drive:**
```
/mnt/secrets/vsock/session_key     (guest signing key, 32-byte seed)
/mnt/secrets/vsock/host_pubkey     (host public key, 32 bytes)
```

**Host retains:**
- `host_signing_key` in memory (for signing host->guest frames)
- `host_pubkey` written to secrets drive (for guest to verify host frames)
- After handshake: `guest_verifying_key` (from SessionHelloAck)

### 2. Guest agent: authenticated session support

After vsock accept + CONNECT/OK, attempt authenticated handshake. Fall back to legacy if keys are absent.

**File:** MODIFY `crates/mvm-guest/src/bin/mvm-guest-agent.rs`

**Flow per connection:**
1. Accept vsock connection, complete CONNECT/OK
2. Try to read session key from `/mnt/secrets/vsock/session_key`
3. **If key found:** read host pubkey, call `handshake_as_guest()`, then use `read_authenticated_frame` / `write_authenticated_frame` for all subsequent frames
4. **If key missing:** log warning, fall back to legacy `read_frame` / `write_frame` (current behavior)
5. Track `session_id` and `sequence` counter per connection

**New helper in guest agent:**
```rust
struct SessionState {
    authenticated: bool,
    session_id: String,
    sequence: u64,
    guest_signing_key: Option<SigningKey>,
    host_verifying_key: Option<VerifyingKey>,
}
```

### 3. Host-side: authenticated send/receive

The high-level API functions (`query_worker_status_at`, `ping_at`, etc.) currently call `connect_to` + `send_request` (unauthenticated). Add an authenticated path.

**File:** MODIFY `crates/mvm-guest/src/vsock.rs`

**Changes:**
- Add `connect_authenticated(uds_path, timeout_secs, host_signing_key) -> Result<(UnixStream, SessionState)>` — calls `connect_to` then `handshake_as_host`
- Add `send_request_authenticated(stream, req, session_state) -> Result<GuestResponse>` — uses `write_authenticated_frame` / `read_authenticated_frame`
- Add `_authenticated` variants of the high-level API or add an `auth: Option<&HostSessionKeys>` parameter to existing functions
- `connect_to` and `send_request` remain for backward compatibility (legacy unauthenticated path)

### 4. SecurityPolicy loading

The host reads `SecurityPolicy` from the config drive to decide whether auth is required.

**File:** MODIFY `crates/mvm-runtime/src/vm/instance/lifecycle.rs`

**Logic:**
- Load `SecurityPolicy` from config drive (or use default if absent)
- If `require_auth: true` and handshake fails -> refuse to communicate with VM
- If `require_auth: false` (default) -> attempt auth, fall back to legacy on failure

### 5. CLI integration

`mvmctl vm status/ping/exec` need to load host keys when auth is available.

**File:** MODIFY `crates/mvm-cli/src/commands.rs`

**Changes:**
- `cmd_vm_status`, `cmd_vm_ping`, `cmd_vm_exec`: look for host signing key in the VM's runtime directory
- If key found: use authenticated path. If not: use legacy path (current behavior)
- Host key path: `<vm_dir>/host_session_key` (written during VM boot)

### 6. Version negotiation

Support mixed environments where some guests have keys and some don't.

**Protocol:**
1. After CONNECT/OK, host sends `SessionHello` as a length-prefixed JSON frame
2. Guest reads the frame. If it's a valid `SessionHello` -> respond with `SessionHelloAck` (authenticated session)
3. If guest doesn't have keys, it reads the `SessionHello` frame but responds with a `GuestResponse::Error { message: "auth_unsupported" }` -> host falls back to legacy mode and re-sends the original request as unauthenticated
4. If `require_auth: true` in SecurityPolicy, host rejects the fallback and returns error

---

## Existing code to reuse

| What | Location | Status |
|------|----------|--------|
| `AuthenticatedFrame` type | `mvm-core/src/security.rs:21` | Done |
| `SessionHello` / `SessionHelloAck` | `mvm-core/src/security.rs:40-62` | Done |
| `SecurityPolicy` + sub-types | `mvm-core/src/security.rs:72-163` | Done |
| `write_authenticated_frame` | `mvm-guest/src/vsock.rs:196` | Done |
| `read_authenticated_frame` | `mvm-guest/src/vsock.rs:229` | Done |
| `handshake_as_host` | `mvm-guest/src/vsock.rs:298` | Done |
| `handshake_as_guest` | `mvm-guest/src/vsock.rs:369` | Done |
| `write_frame` / `read_frame` | `mvm-guest/src/vsock.rs` | Done |
| `SignedPayload` | `mvm-core/src/signing.rs` | Done |
| Ed25519 dependency | `mvm-guest/Cargo.toml` | Done |
| Handshake + auth frame tests | `mvm-guest/src/vsock.rs` (tests module) | Done |

---

## New code needed

| What | Location |
|------|----------|
| Session key generation + disk write | `mvm-runtime/src/vm/session_keys.rs` (NEW) |
| Pre-boot key provisioning hook | `mvm-runtime/src/vm/instance/lifecycle.rs` |
| Guest agent session state + auth read/write loop | `mvm-guest/src/bin/mvm-guest-agent.rs` |
| `connect_authenticated` + `send_request_authenticated` | `mvm-guest/src/vsock.rs` |
| Host key loading in CLI commands | `mvm-cli/src/commands.rs` |
| SecurityPolicy loading from config drive | `mvm-runtime/src/vm/instance/lifecycle.rs` |

---

## Task breakdown

### Phase A: Key provisioning (host side)

1. Create `session_keys.rs` in mvm-runtime:
   - `generate_session_keypair() -> (SigningKey, VerifyingKey)`
   - `write_session_keys(secrets_dir: &str, host_signing_key: &SigningKey) -> Result<()>`
   - `load_host_signing_key(vm_dir: &str) -> Result<Option<SigningKey>>`
2. Hook into VM boot in lifecycle.rs: after secrets drive is created, generate keys and write them
3. Save host signing key to `<vm_dir>/host_session_key` for later CLI use
4. Tests: key generation, write/read roundtrip, missing key returns None

### Phase B: Guest agent auth support

1. Add `SessionState` struct to guest agent
2. On connection accept: try to load `/mnt/secrets/vsock/session_key` and `/mnt/secrets/vsock/host_pubkey`
3. If keys present: call `handshake_as_guest`, switch to authenticated read/write
4. If keys absent: log once, use legacy protocol
5. Track sequence counter per connection, increment on each frame
6. Tests: guest agent handles both auth and legacy connections (mock vsock via UnixStream::pair)

### Phase C: Host-side auth send/receive

1. Add `HostAuth` struct holding signing key, guest verifying key, session ID, sequence counter
2. Add `connect_authenticated` that does CONNECT/OK + handshake
3. Add `send_request_authenticated` that wraps request in AuthenticatedFrame
4. Modify high-level API functions to accept optional auth context
5. Tests: authenticated request/response roundtrip via UnixStream::pair

### Phase D: CLI + policy wiring

1. In CLI vm commands: attempt to load host key from VM directory
2. If key found: use authenticated path. If not: use legacy
3. Load SecurityPolicy from config drive (if available)
4. If `require_auth: true` and auth fails: return clear error
5. Add `--require-vsock-auth` flag to `mvmctl run` / `mvmctl start`

---

## Backward compatibility

- Default `require_auth: false` — existing VMs and guest images work unchanged
- Version negotiation ensures graceful fallback when guest doesn't have keys
- No changes to CONNECT/OK wire format — auth handshake is an additional step after
- CLI auto-detects: if host key file exists, use auth; otherwise legacy
- Old guest agent (without auth support) will receive SessionHello as an unknown frame and respond with an error — host catches this and falls back

## Verification

```bash
cargo test --workspace                    # all tests pass
cargo clippy --workspace -- -D warnings   # zero warnings
```

Integration test:
1. Boot a VM without session keys -> legacy protocol works as before
2. Boot a VM with `--require-vsock-auth` -> keys provisioned, `vm status` uses authenticated frames
3. Verify `vm status` output is identical in both modes (auth is transparent to the user)
4. Tamper with a key file -> handshake fails, clear error message
5. `require_auth: true` with no keys -> VM refuses to communicate, error explains why

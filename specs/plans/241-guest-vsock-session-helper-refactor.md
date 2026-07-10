# Plan 241 — Guest Vsock Session Helper Refactor

> **For agentic workers:** keep the checkboxes current. The last unchecked item is the current blocker.

**Status:** COMPLETE

**Goal:** Refactor the guest-side addon bridge and SOCKS5 egress client so they share one small host-vsock session abstraction for "dial host vsock, write initial metadata, then splice bytes," while preserving the exact wire behavior and leaving host-side claim-10 policy enforcement explicit and unchanged.

**Architecture:** The shared helper owns only the repeated guest transport lifecycle: connect to a host AF_VSOCK port, write an already-decided initial byte prelude, and splice bytes bidirectionally. The addon bridge continues to frame a length-prefixed JSON peer header exactly as it does today. The SOCKS5 egress client continues to negotiate locally, send the newline-terminated `"host:port\n"` target line exactly as the host egress server expects, and leaves the host `EgressGate` decision path untouched.

**Files:**
- `crates/mvm-guest-helpers/src/addon_vsock_bridge.rs`
- `crates/mvm-guest-helpers/src/egress_client.rs`
- `crates/mvm-guest-helpers/src/guest_vsock_session.rs`
- `crates/mvm-guest-helpers/src/lib.rs`
- `crates/mvm-hostd/src/supervisor/http_forward.rs`
- `crates/mvm-hostd/src/supervisor/raw_egress.rs`
- `crates/mvm-hostd/src/supervisor/mod.rs`
- `specs/plans/241-guest-vsock-session-helper-refactor.md`
- `specs/SPRINT.md`
- `specs/REFACTOR-STATUS.md`

## Tasks

- [x] Add a shared guest-side host-vsock session helper that owns dial + initial-byte write + splice, without moving any host policy logic into the guest.
- [x] Refactor the addon bridge to use the shared helper while preserving the exact peer-header framing and byte order.
- [x] Refactor the SOCKS5 egress client to use the shared helper while preserving greeting/CONNECT negotiation, target-line framing, and reply timing.
- [x] Add or update tests for the shared helper plus both guest-side call paths.
- [x] Run validation for this slice:
  `cargo fmt --all --check`
  `MVM_DATA_DIR="$PWD/.mvm-test" CARGO_TARGET_DIR="$PWD/.mvm-test/target" CARGO_HOME="$PWD/.mvm-test/cargo" cargo test -p mvm-guest-helpers`
  `MVM_DATA_DIR="$PWD/.mvm-test" CARGO_TARGET_DIR="$PWD/.mvm-test/target" CARGO_HOME="$PWD/.mvm-test/cargo" cargo clippy -p mvm-guest-helpers --all-targets -- -D warnings`
  `MVM_DATA_DIR="$PWD/.mvm-test" CARGO_TARGET_DIR="$PWD/.mvm-test/target" CARGO_HOME="$PWD/.mvm-test/cargo" cargo check --workspace`
  `MVM_DATA_DIR="$PWD/.mvm-test" CARGO_TARGET_DIR="$PWD/.mvm-test/target" CARGO_HOME="$PWD/.mvm-test/cargo" cargo test --workspace`
  `MVM_DATA_DIR="$PWD/.mvm-test" CARGO_TARGET_DIR="$PWD/.mvm-test/target" CARGO_HOME="$PWD/.mvm-test/cargo" cargo clippy --workspace --all-targets -- -D warnings`
- [x] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` in the same change with the completed slice and validation state.

## Outcome

The guest-side addon bridge and SOCKS5 egress client now share
`guest_vsock_session::HostVsockSession`, a small helper that owns only the
repeated guest transport lifecycle: dial host vsock, write already-framed
initial bytes, then splice traffic bidirectionally. The addon peer header stays
byte-for-byte identical, the SOCKS5 negotiation and newline-terminated target
line framing stay identical, and host-side claim-10 enforcement remains
explicit and unchanged in the host crates. The same guest helper now also
recognizes absolute-form HTTP proxy requests and sends a reserved first frame so
hostd's raw-egress entry point can dispatch them into a host-side forward-proxy
path while leaving TLS, HTTP parsing, and policy checks on the host side.

## Validation Notes

- 2026-07-09 rebase refresh: the branch was rebased onto current `origin/main`
  before re-running validation. Focused guest and host checks stayed green,
  along with `cargo check --workspace`, `cargo test --workspace`, and
  `cargo clippy --workspace --all-targets -- -D warnings`.
- 2026-07-09 local runtime proof: a signed local `mvmctl` binary was required
  before HVF admission would succeed (`mvmctl env sign` on macOS). The initial
  worktree-local `MVM_DATA_DIR=.mvm-test` runtime smoke then failed before guest
  boot because the per-VM substitution-endpoint UDS path exceeded the Unix
  socket length limit under the long worktree path; rerunning with a short
  `/tmp` `MVM_DATA_DIR` fixed that environment issue.
- 2026-07-09 BusyBox HTTPS smoke closeout: plain admitted egress now injects
  `http://127.0.0.1:1080`, the guest loopback proxy accepts both CONNECT and
  absolute-form HTTP proxy requests, and the host raw-egress entry point
  dispatches a reserved frame into a host-side forward-proxy path. After
  rebuilding/signing the local binaries and reusing the short `/tmp`
  `MVM_DATA_DIR`, the required HVF smoke passed:
  `mvmctl machine run --image busybox --allow-host google.com --allow-host www.google.com -- /bin/sh -lc 'wget -qO- https://google.com >/dev/null; echo exit:$?'`
  → `exit:0`.

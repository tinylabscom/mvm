# Plan 129 Stage 1b/2 — Transparent egress terminator (SDK-free substitution) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make egress substitution mvm's job, not the SDK's — a generic client in the guest (`curl http://api…`, no `import mvm`) gets its placeholder swapped for the real credential by a host-side terminator the gateway transparently redirects to, with the guest only ever holding `mvm-secret-<hex>` and the substitution chain-audited.

**Architecture:** mvm spawns passt under a dedicated per-VM uid; a host nft `nat OUTPUT REDIRECT` rule (scoped by `meta skuid` to that uid — so only guest egress, never the host's own) steers the guest's outbound HTTP to a **host-side transparent terminator**. The terminator recovers the original destination via `SO_ORIGINAL_DST`, reads the request, and reuses the already-built `prepare_request()` / `SubstitutionEndpoint` to swap the placeholder (or sign), then forwards to the real destination. Stage 1b does this for `http` (no CA). Stage 2 adds TLS termination via a per-VM name-constrained CA for `https`. Everything host-side (registry, resolver, injector, signer, audit) is reused; the in-guest forward proxy and `HTTP_PROXY` env stop being required.

**Tech Stack:** Rust, `libc` (getsockopt SO_ORIGINAL_DST), nftables (`nft`), `url`, the existing `mvm-hostd` substitution stack; Stage 2 adds `rcgen` (new dep) + `rustls`.

**Design context (decisions already settled — see memory `project_plan_129_sdk_free_egress_decision`):**
- Substitution requires the host to see+modify the request. `https` ⇒ host-side TLS termination with a guest-trusted cert ⇒ **name-constrained MITM scoped to bound hosts only** (ADR-006). This adds *zero* host visibility over what the injector already needs (host sees bound-host plaintext either way). ADR-067 to be amended to make proxy-native primary, SDK optional.
- **Placeholder-marker** for bearer/basic (swap `mvm-secret-<hex>`, site-agnostic); **transparent signing** for sigv4/hmac. The guest reads the placeholder from an env var with plain `os.environ` — SDK-free.
- Feasibility proven: nft `nat OUTPUT REDIRECT` + `SO_ORIGINAL_DST` catches passt's host-netns outbound (PoC green, memory `reference_passt_outbound_nft_redirectable`). The real design point is **uid/cgroup scoping** so we don't redirect the host's own egress.

**Prereqs / baseline:** branch `feat/plan-129-egress-terminator` off `origin/main` (#724). The SDK authoring (`secret()` `type`/`hosts`), the jailed `mvm-substitution-endpoint`, and `invoke.rs::substitution_env` already landed (#717/#722/#723). This plan is additive — no changes to those.

**Scope:** Stage 1b is the complete, demoable increment (`http`, Linux/passt). Stage 2 (`https` + CA) is the follow-on. **macOS/gvproxy is out of scope** (no nft; needs pf or gvproxy's forwarding API — a later port). The box demo is Linux/passt.

---

## Resume state (2026-06-08) — START HERE next session

**Done (on `feat/plan-129-egress-terminator`, ahead of `origin/main` #724, pushed — draft PR #735):**
- Task 1 — `8039120d` `terminator/orig_dst.rs`: `original_dst()` (Linux `SO_ORIGINAL_DST`, cfg-gated) + portable `sockaddr_in_to_v4`.
- Task 2 — `3f68e3e8` `terminator/request.rs`: `proxy_request_from_origin_form(raw, orig_dst) -> ProxyRequest`.
- Task 3 — `45557b69` `terminator/handler.rs` + `read.rs`: the host-testable substitution core + bounded reader; `8ed2a584` deduped `find_subslice` into `mod.rs`. Reviewed (fail-closed claim-12 property structurally enforced + tested: `forward` is never called for an unbound dest / unknown placeholder).
- `mvm-hostd` builds + unit-tests on macOS; 795/795 pass, fmt+clippy clean.

**Design refinement that changes Task 4 (already applied in code):** the plan's original `handle(stream, …)` (which called the Linux-only `original_dst` inline, making it un-testable off-Linux) was split. The testable core is now `handler::handle_request(raw: &[u8], orig_dst: SocketAddr, endpoint, forward)`. **Task 4's Linux-gated listener** is the glue that does, per accepted connection: `original_dst(&stream)` → `read::read_http_request(&mut stream)` → `handle_request(&raw, orig_dst, &endpoint, forward)` → write the returned bytes back. Use that shape, not the original `handle`.

**Status (2026-06-09):** Task 0 ✅, Task 4 ✅ (PR #735, **merged**), Task 5 ✅ (PR #744, **merged** — FC TAP `nft prerouting iifname` redirect + endpoint/terminator wiring). **Task 6 (live box e2e) DEFERRED** to a dedicated bringup/debug session — kickoff prompt at `specs/prompts/129-fc-bringup-debug.md`. The FC microVM now boots on the box, but the live SDK-free e2e is gated on: the published default x86_64 kernel being a bzImage not an ELF vmlinux (issue **#746**), FC guest-agent reachability, and the local secret-launch glue (`specs/prompts/129-local-admission-launch.md`). Then Stage 2 (CA/`https`, ADR-006).

**✅ RESOLVED (2026-06-09) — Option 2 (Firecracker), with a mechanism correction.** The premise gap (substitution endpoint wired only on QEMU/slirp; `skuid` needs a passt-uid) was resolved by targeting **Firecracker** — but FC's egress is **TAP + nft NAT**, NOT passt, so the redirect mechanism changed from `meta skuid` (OUTPUT) to **`nat prerouting iifname "<tap>"`** (naturally guest-scoped; no passt, no uid). Re-validated on the box (PASS — see Task 5). No `passt.rs`/`--runas` change. Box is nft-only. See Task 5 for the corrected design; `[[project_plan_129_terminator_backend_gap]]`.

**Box phase setup (Tasks 0/6 + Linux integration):** the box is `root@88.99.197.234`; `/root/mvm-129` does NOT exist — clone off `origin/main` and `cargo build -p mvm-cli -p mvm-libkrun-supervisor --features libkrun-sys`. Isolate from any parallel session with a dedicated `MVM_CACHE_DIR=/root/.cache/mvm-129` + `MVM_DATA_DIR=/root/.mvm-129`. Boot via `mvmctl up --hypervisor qemu --builder qemu`. Known gotchas (see memory): cold-cache Stage 0 can panic (#576) — warm the cache; a workload `/init` may exit ~5s on input-less console — verify with a long-lived workload + `examples/agent_ping`, and read `<vm_state_dir>/console.log`. Feasibility + the nft scoping mechanism are proven (memory `reference_passt_outbound_nft_redirectable`): scope the redirect to passt's uid via `meta skuid` so only guest egress is intercepted, never the host's own.

---

### Task 0: Full-fidelity box confirm (passt-under-uid + nft redirect, real VM)

Confirms the integration the synthetic PoC couldn't (production passt, not pasta) before we build. Validation only — no code.

**Box:** `root@88.99.197.234`, worktree `/root/mvm-129` (create off `origin/main`).

- [x] **Step 1: Stand up the worktree + build on the box** (Tier A needs no mvmctl build — validated the mechanism directly)

```bash
ssh root@88.99.197.234 'git -C /root clone --no-checkout file:///root/mvm-mirror mvm-129 2>/dev/null; \
  cd /root/mvm-129 && git fetch origin && git checkout -B feat/plan-129-egress-terminator origin/main && \
  cargo build -p mvm-cli -p mvm-libkrun-supervisor --features libkrun-sys'
```

(If no local mirror, clone from the GitHub remote. Use a dedicated `MVM_CACHE_DIR=/root/.cache/mvm-129` / `MVM_DATA_DIR=/root/.mvm-129` to isolate from any parallel session per memory `project_dev_host_runs_builder_via_vz`.)

- [x] **Step 2: Manually reproduce the production interception, end to end** (Tier A stub-listener variant — see RESULT below)

Run a long-lived guest workload (so passt stays up), find passt's pid/uid, install the scoped redirect to a stub `SO_ORIGINAL_DST` listener (the `/tmp/passt-redirect-poc.sh` listener), and `mvmctl exec`/console a `curl http://<bound-host>/` from the guest:

```bash
# host: dedicate passt's uid by launching the VM with the terminator-uid env (Task 5 wires this;
# for Task 0, run passt manually under a known uid OR match passt's current uid from `ps`)
PASST_UID=$(ps -o uid= -C passt | tr -d ' ')
nft add table ip poc0; nft 'add chain ip poc0 output { type nat hook output priority -100 ; }'
nft add rule ip poc0 output meta skuid $PASST_UID tcp dport 80 redirect to :9999
# guest: curl http to any bound host; observe the listener captures ORIGINAL_DST
```

Expected: the stub listener logs `ORIGINAL_DST=<host-ip>:80` from the guest's curl, and the host's own `curl http://example.com` is NOT captured (skuid scoping holds).

- [x] **Step 3: Record the result** in this file (PASS/FAIL + the captured line). If skuid scoping doesn't isolate guest-from-host, fall back to a cgroup match (`socket cgroupv2 level N "mvm-passt-<vm>"`) and note it — that becomes Task 5's mechanism instead.

**RESULT (2026-06-08) — PASS (Tier A, decisive).** On `root@88.99.197.234`: a low-priv uid `mvmpasst` (uid 1002), an `ip poc0` table with `chain output { type nat hook output priority -100 }` and `meta skuid 1002 tcp dport 80 redirect to :9999`, and a stub `SO_ORIGINAL_DST` listener. `sudo -u mvmpasst curl http://1.1.1.1/` → listener logged `ORIGINAL_DST=1.1.1.1:80` (pre-REDIRECT dest recovered). Root's own `curl http://8.8.8.8/` was **NOT** captured (no second log line) — **skuid scoping isolates guest-uid egress from the host's own**. `meta skuid` is confirmed as Task 5's mechanism; no cgroup fallback needed. Box left clean (table deleted, uid removed, listener killed). Tier B (real passt under `--runas` carrying guest traffic) folds into Task 6's full VM e2e rather than a separate manual run.

---

### Task 1: `original_dst()` — recover the pre-REDIRECT destination

**Files:**
- Create: `crates/mvm-hostd/src/supervisor/terminator/mod.rs` (+ `pub mod terminator;` in `supervisor/mod.rs`)
- Create: `crates/mvm-hostd/src/supervisor/terminator/orig_dst.rs`
- Test: in-file `#[cfg(test)]`

- [ ] **Step 1: Write the failing test** (parsing is the unit-testable core; the syscall is covered by Task 6 e2e)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_network_order_sockaddr_in() {
        // 203.0.113.7:443, network byte order in the struct.
        let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        a.sin_port = 443u16.to_be();
        a.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(203, 0, 113, 7)).to_be();
        let v4 = sockaddr_in_to_v4(&a);
        assert_eq!(v4, std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(203,0,113,7), 443));
    }
}
```

- [ ] **Step 2: Run it (fails — `sockaddr_in_to_v4` undefined)**

Run: `cargo nextest run -p mvm-hostd parses_network_order_sockaddr_in`
Expected: FAIL (unresolved).

- [ ] **Step 3: Implement**

```rust
//! Recover the original destination of a connection the host nft `nat` chain
//! REDIRECTed to the terminator. Linux-only — the terminator runs on the passt
//! path. See memory `reference_passt_outbound_nft_redirectable`.
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::fd::AsRawFd;

const SO_ORIGINAL_DST: libc::c_int = 80;

pub fn original_dst(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: getsockopt writes a sockaddr_in into `addr` and the written
    // length into `len`; both out-params are valid for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(SocketAddr::V4(sockaddr_in_to_v4(&addr)))
}

fn sockaddr_in_to_v4(a: &libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)), u16::from_be(a.sin_port))
}
```

- [ ] **Step 4: Run it (passes)** — `cargo nextest run -p mvm-hostd parses_network_order_sockaddr_in` → PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(terminator): SO_ORIGINAL_DST recovery (plan 129 stage 1b)"`

---

### Task 2: origin-form request → `ProxyRequest`

**Files:** Create `crates/mvm-hostd/src/supervisor/terminator/request.rs`; Test in-file.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn builds_proxy_request_url_from_host_header() {
        let raw = b"GET /v1/x HTTP/1.1\r\nhost: api.openai.com\r\nauthorization: Bearer mvm-secret-abc\r\n\r\n";
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203,0,113,7), 80));
        let req = proxy_request_from_origin_form(raw, dst).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "http://api.openai.com/v1/x"); // bind-check keys on this host
        assert_eq!(req.headers[1], ("authorization".into(), "Bearer mvm-secret-abc".into()));
    }

    #[test]
    fn rejects_absolute_form_target() {
        // The terminator sees origin-form (path). Absolute-form would mean a
        // proxy-configured client, which isn't our path.
        let raw = b"GET http://x/ HTTP/1.1\r\nhost: x\r\n\r\n";
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203,0,113,7), 80));
        assert!(proxy_request_from_origin_form(raw, dst).is_err());
    }
}
```

- [ ] **Step 2: Run it (fails)** — `cargo nextest run -p mvm-hostd proxy_request_from_origin_form` → FAIL.

- [ ] **Step 3: Implement**

```rust
//! Reconstruct a `ProxyRequest` (the substitution stack's input) from a raw
//! origin-form HTTP/1.1 request the terminator read off a redirected socket.
use anyhow::{Context, Result, bail};
use crate::supervisor::substitution_proxy::ProxyRequest;
use std::net::SocketAddr;

pub fn proxy_request_from_origin_form(raw: &[u8], orig_dst: SocketAddr) -> Result<ProxyRequest> {
    let split = find_subslice(raw, b"\r\n\r\n").context("request has no header terminator")?;
    let head = std::str::from_utf8(&raw[..split]).context("request head not UTF-8")?;
    let body = raw[split + 4..].to_vec();

    let mut lines = head.split("\r\n");
    let request_line = lines.next().context("empty request")?;
    let mut parts = request_line.split(' ');
    let method = parts.next().filter(|m| !m.is_empty()).context("no method")?;
    let target = parts.next().context("no request target")?;
    let version = parts.next().context("no HTTP version")?;
    if !version.starts_with("HTTP/") {
        bail!("malformed request line: {request_line:?}");
    }
    // Origin-form (`/path`) is the transparent path; absolute-form means a
    // proxy-configured client, not ours.
    if !target.starts_with('/') {
        bail!("expected origin-form target, got {target:?}");
    }

    let mut headers = Vec::new();
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .with_context(|| format!("malformed header: {line:?}"))?;
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("host") {
            host = Some(value.to_string());
        }
        headers.push((name.to_string(), value.to_string()));
    }

    // The Host header is the name the guest dialed — the claim-12 bind-check in
    // `prepare_request` keys on it. Fall back to the original-dst IP (HTTP/1.0).
    let host = host.unwrap_or_else(|| orig_dst.ip().to_string());
    let host_no_port = host.split(':').next().unwrap_or(&host);
    let url = format!("http://{host_no_port}{target}");
    Ok(ProxyRequest { method: method.to_string(), url, headers, body })
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
```

- [ ] **Step 4: Run it (passes)**; **Step 5: Commit** — `"feat(terminator): origin-form request → ProxyRequest (plan 129 stage 1b)"`

---

### Task 3: terminator connection handler (reuse `prepare_request` + forward)

**Files:** Create `crates/mvm-hostd/src/supervisor/terminator/handler.rs`; Test in-file.

- [ ] **Step 1: Write the failing test** (inject a fake endpoint + forwarder; assert the placeholder-bearing request is substituted and forwarded to the original-dst)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Build a SubstitutionEndpoint over an in-memory registry binding
    // `mvm-secret-abc` → a bearer secret for `api.openai.com` (reuse the
    // helpers in keyholder::substitution tests), then drive one connection
    // through `handle` with a mock forwarder that records what it received.
    #[test]
    fn substitutes_placeholder_then_forwards_to_original_dst() {
        // ... assemble endpoint (see keyholder::substitution::tests for the
        // registry+resolver builder) ...
        // raw request carries `authorization: Bearer mvm-secret-abc`
        // assert: forwarder saw `Bearer <real-value>` and dialed the orig dst.
    }
}
```

(Use the existing `keyholder::substitution` test helpers to mint a registry; assert the forwarder closure observed the substituted header. Keep the assertion on the *forwarded* `PreparedRequest`, not on internal calls.)

- [ ] **Step 2: Run it (fails)**

- [ ] **Step 3: Implement**

```rust
//! One redirected connection: recover the real dest, read the request, reuse
//! the substitution stack, forward to the dest, stream the response back.
use anyhow::{Result, anyhow};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};

use crate::keyholder::substitution::SubstitutionEndpoint;
use crate::supervisor::substitution_proxy::{PreparedRequest, prepare_request};
use super::orig_dst::original_dst;
use super::request::proxy_request_from_origin_form;

/// Drive one redirected client connection. `forward` dials `orig_dst` (http for
/// Stage 1b), sends the substituted request, and returns the raw response.
/// Production passes a closure over the existing forwarder; tests pass a mock.
pub fn handle<F>(mut client: TcpStream, endpoint: &SubstitutionEndpoint<'_>, forward: F) -> Result<()>
where
    F: Fn(&PreparedRequest, SocketAddr) -> Result<Vec<u8>>,
{
    let orig_dst = original_dst(&client)?;
    let raw = super::read::read_http_request(&mut client)?; // bounded; Task 3b
    let req = proxy_request_from_origin_form(&raw, orig_dst)?;
    // `prepare_request` carries the claim-12 bind-check: an unbound destination
    // or unknown placeholder errors here, before anything is forwarded.
    let prepared = prepare_request(endpoint, req).map_err(|e| anyhow!("substitution refused: {e}"))?;
    let resp = forward(&prepared, orig_dst)?;
    client.write_all(&resp)?;
    client.flush().ok();
    Ok(())
}
```

- [ ] **Step 3b:** Add `terminator/read.rs` with a `read_http_request(&mut TcpStream) -> Result<Vec<u8>>` that reads headers to `\r\n\r\n` then the `Content-Length` body, bounded by 16 MiB — port the identical loop from `crates/mvm-guest/src/forward_proxy.rs::read_http_request` (it's already proven; copy it, with a test mirroring `forward_proxy`'s).

- [ ] **Step 4: Run it (passes)**; **Step 5: Commit** — `"feat(terminator): connection handler reusing prepare_request (plan 129 stage 1b)"`

---

### Task 4: terminator listener + wire into the endpoint

**Files:** Create `crates/mvm-hostd/src/supervisor/terminator/listener.rs`; Modify `crates/mvm-hostd/src/supervisor/substitution_endpoint.rs` (`EndpointConfig` gains `terminator_listen: Option<SocketAddr>`; `assemble` spawns the terminator listener when set, alongside the existing vsock one).

- [x] **Step 1: Write the failing test** — `EndpointConfig` round-trips the new optional field; `assemble` with `terminator_listen: Some(127.0.0.1:0)` returns a service that binds a TCP listener (assert it accepts a connection). Default `None` preserves today's behaviour.

- [x] **Step 2: Run it (fails)**

- [x] **Step 3: Implement** the listener (accept loop → `handle(stream, &endpoint, real_forward)` per connection, errors logged not fatal — same shape as `forward_proxy::serve`), and thread `terminator_listen` through `EndpointConfig`/`parse`/`assemble`. The real forwarder dials `orig_dst` over http and reads the response (reuse the existing forwarder type if it exposes a host:port dial; otherwise a thin `std::net::TcpStream` write/read for Stage 1b).

- [x] **Step 4: Run it (passes)**; **Step 5: Commit** — `"feat(terminator): TCP listener wired into the substitution endpoint (plan 129 stage 1b)"`

**DONE (2026-06-08, commits `3201006c` + review-fix `53f5b2b1`):** `serve_terminator(self: Arc<Self>, listener, timeout)` on `SubstitutionService` (Linux-gated); `terminator/listener.rs` with `forward_http_raw` (thin raw-TCP splice, configured timeout, 16 MiB-bounded read-to-EOF) + `prepared_to_origin_form_bytes` (origin-form, forces `Connection: close`, rejects CR/LF header injection); `EndpointConfig.terminator_listen: Option<SocketAddr>`; bin runs the terminator concurrently with the primary transport. Spec + code-quality reviewed (gating DoS fix: read/write timeouts on the untrusted guest socket; configured `forward_timeout_secs` threaded through). 805 mvm-hostd tests green; Linux cross-clippy clean.

---

### Task 5: per-VM nft REDIRECT on the guest TAP + endpoint/terminator wiring (Firecracker)

**MECHANISM CORRECTION (2026-06-09 — supersedes the original passt/skuid design).** Investigation of the actual backends found: the **Firecracker** egress path is **TAP + nft/iptables NAT** (`crates/mvm-backend/src/network_provider.rs:8-10` — "this one only owns the iptables-on-TAP egress mechanism"; gvproxy/passt is the *libkrun* path). There is **no passt-under-a-uid** on Firecracker, so `meta skuid` (what Task 0 validated) does **not** apply. The guest's egress arrives on the per-VM **TAP interface** and is routed/NAT'd (FORWARD/POSTROUTING) — so the transparent redirect must match the **incoming TAP interface** in `nat prerouting`, which is naturally guest-scoped (the host's own egress never enters via the tap). No dedicated uid, no `passt --runas`, no `passt.rs` change. **The box is nft-only (no iptables).**

**Re-validated on the box (2026-06-09 — PASS):** a netns+veth standing in for a TAP-fed guest behind the bridge MASQUERADE; rule `nft add rule ip <t> prerouting iifname "<iface>" tcp dport 80 redirect to :<port>` (chain `type nat hook prerouting priority -100`). Guest curl → captured `ORIGINAL_DST=1.1.1.1:80`; host's own egress (not via the iface) NOT captured. The terminator listener bound `0.0.0.0:<port>` receives the REDIRECTed forwarded connection (PREROUTING REDIRECT lands the packet on the host).

**Files:** Create `crates/mvm-hostd/src/supervisor/egress_redirect.rs` (`EgressRedirect::install(vm, tap_iface, term_port)` / `Drop` teardown + a pure `nft_rule_argv(table, iface, port)` for unit tests). Wire into the **Firecracker parent context** (`crates/mvm-backend/src/microvm.rs` `run_from_build` + `stop_vm` — the bridge child is Landlock-confined and can't run `nft`, so install in the unconfined parent), gated on `mvm_core::plan::secrets_from_signed_json(plan_json)` being non-empty (`plan_json` is already read at `spawn_fc_bridge`/available; the tap name comes from the slot/network provision). Replicate `qemu.rs::spawn_substitution_endpoint` for FC but set `terminator_listen: Some(0.0.0.0:<per-VM port>)` (per-VM port = a base + `slot.index` to avoid host-wide collisions) and record the endpoint PID + write `substitution-env.json` (consumed by `mvmctl invoke`'s `substitution_env`, the existing guest env-injection path).

- [x] **Step 1: Write the failing test** — `EgressRedirect::nft_rule_argv("mvm_egress_x", "tap-x", 18080)` produces the exact tokens for `add rule ip mvm_egress_x prerouting iifname "tap-x" tcp dport 80 redirect to :18080`. Pure-function test; the live `nft` call + the FC wiring are covered by Task 6.

- [ ] **Step 2: Run it (fails)**

- [ ] **Step 3: Implement** `egress_redirect.rs`: per-VM table `mvm_egress_<sanitized-vm>`, a `nat prerouting` chain (priority -100), and the iifname-scoped REDIRECT rule built from `nft_rule_argv`; `install` runs the `nft` calls, `Drop`/explicit `teardown` runs `nft delete table ip <table>`. Then wire FC `run_from_build`/`stop_vm`: when the plan carries secrets, spawn the substitution endpoint (vsock transport + `terminator_listen: Some(0.0.0.0:<port>)`), then `EgressRedirect::install(vm, tap, port)`; on stop, reap the endpoint PID, drop the redirect table, remove `substitution-env.json`. Gate everything on secrets; fail closed (roll back the FC boot if the endpoint/redirect can't come up, mirroring qemu.rs).

- [x] **Step 4: Run it (passes)**; **Step 5: Commit** — landed as PR #744 (5A `EgressRedirect` + 5B FC wiring + review fix), merged squash `8c3a327b`.

(Original passt/skuid `egress_redirect` sketch removed — it targeted the libkrun passt path; Firecracker uses TAP. A future libkrun-on-Linux terminator could add the skuid variant Task 0 validated, but that is out of scope for the FC slice.)

---

### Task 6: Box e2e — generic `http` client, SDK-free, audited

**Files:** none (validation). Append the result to this file. **Backend: Firecracker on the box** (the box is `rvproxy-firecracker`; `/dev/kvm` present → `auto_select` lands on Firecracker). The redirect is the validated TAP/`iifname` mechanism, NOT skuid.

- [ ] **Step 1:** On the box, store + bind a secret to a bound host, boot a secret-bearing FC workload, then `mvmctl invoke <vm> ...` (its `substitution_env` injects the `(var → placeholder)` pairs the endpoint wrote at boot) with a guest entrypoint doing `curl -s http://<bound-host>/ -H "Authorization: Bearer $TOKEN"` where `$TOKEN` holds the placeholder. The endpoint's `terminator_listen` + the per-VM `nat prerouting iifname "<tap>"` REDIRECT steer the guest's :80 egress to the terminator.
- [ ] **Step 2:** Assert the destination received `Authorization: Bearer <real value>`, not the placeholder; the guest holds only `mvm-secret-…`; `mvmctl audit verify` exits 0 and a `secret.substituted` entry exists with no secret bytes.
- [ ] **Step 3:** Assert the host's own egress is untouched (a host-side `curl http://<bound-host>/` is NOT intercepted — the `iifname` match only catches traffic arriving on the guest tap).
- [ ] **Step 4:** Record PASS/FAIL + log paths here.

---

## Stage 2 — name-constrained CA + `https` (follow-on; task outline)

Builds directly on Stage 1b's terminator. Full TDD plan authored after 1b lands (its shapes pin Stage 2's details). Outline:

- **2.1 Add `rcgen` (new workspace dep) + a CA module** (`crates/mvm-core/src/crypto/egress_ca.rs`): mint a long-lived host CA (`~/.mvm/egress/ca.{crt,key}`, key 0400) and, per VM-boot, a **name-constrained** intermediate (CA:TRUE, pathlen:0, `nameConstraints` permitted = the plan's bound hosts). Negative test: the CA refuses to vouch for an unbound host. Confirm the chosen `rcgen` version exposes `name_constraints` (≥0.13).
- **2.2 Per-run cert delivery to the guest** — only the per-VM intermediate *cert* (never the host CA, never the key) reaches the guest, via the existing per-run material path (the same channel `invoke.rs::substitution_env` / boot config uses). Trace that path on main; add the cert file to it.
- **2.3 Guest trust install** (`nix/lib/mk-guest.nix`) — a boot step copies the per-VM cert to `/etc/ssl/certs/` before the entrypoint. Honest caveat: Python `ssl`/older Node don't enforce `nameConstraints` client-side, so the **host-side allowlist check remains the real claim-12 boundary** (defense-in-depth).
- **2.4 TLS termination in the terminator** — `rustls` server using the per-VM intermediate to mint on-the-fly leaves per SNI; redirect rule extends to `tcp dport 443`; **bound SNI → terminate + substitute; unbound SNI → splice passthrough** (no termination, end-to-end TLS preserved). Re-originate real TLS upstream (validate the destination cert against the system store).
- **2.5 ADR-067 amendment + ADR-006 status** — make proxy-native primary / SDK optional; record that scoped name-constrained termination ≠ the rejected blanket MITM (zero added visibility argument).
- **2.6 Box e2e** — generic `curl https://api.openai.com/...` SDK-free: real credential reaches the destination, guest holds only the placeholder, `secret.substituted` audited. The headline acceptance goal.

## Re-home note

The fuller design rationale lives in `specs/notes/plan-129-egress-substitution-sdk-free-design.md`, drafted against the stale #693 checkout. Re-home it onto this worktree and reconcile its file anchors (jailed `mvm-substitution-endpoint`; `rcgen` is a *new* dep, not an upgrade; the spike's `substitution_proxy.rs`/`certs.rs` anchors were stale) in the same commit that starts Stage 1b.

## Self-review

- **Spec coverage:** transparent terminator (the design's Stage 1b) ✓; nft scoping = the PoC's identified design point ✓; reuse of `prepare_request`/`SubstitutionEndpoint` ✓ (real signatures verified `substitution_proxy.rs:81`, `keyholder/substitution.rs:142`); Stage 2 CA/https outlined, not faked ✓.
- **Type consistency:** `ProxyRequest`/`PreparedRequest`/`prepare_request` and `SubstitutionEndpoint::{new,substitute}` match current main exactly; `original_dst` returns `SocketAddr`, consumed by `proxy_request_from_origin_form` and `handle`.
- **No placeholders:** Tasks 1–2 and 5's pure functions carry full real code; Tasks 3–4 carry real code with the test bodies deferring to the existing `keyholder::substitution` test helpers (named, not invented); Stage 2 is an explicit outline, not bite-sized fiction.

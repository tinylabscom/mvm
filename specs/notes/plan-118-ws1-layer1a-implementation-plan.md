# Plan 118 WS-1 Layer 1a — Prelaunched libkrun Supervisor: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (only if dispatched agents can run Bash/build/test/commit in this environment) or
> superpowers:executing-plans (inline) to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.
>
> **Authoritative design:** `specs/notes/plan-118-ws1-layer1a-prelaunched-supervisor-design.md`
> and `specs/plans/118-supervisor-standby-pool-and-live-bench.md` §PR-10b.

**Goal:** Add a *prelaunched* mode to `mvm-libkrun-supervisor` that does the
workload-independent setup at spawn, blocks on a control UDS holding no rootfs/plan,
and on a verified `attach` message re-verifies the signed `ExecutionPlan` and only
then boots — the security-critical primitive a 1b warm pool is built from.

**Architecture:** Split `SupervisorConfig` into a workload-independent
`SupervisorBaseConfig` (spawned with) and a workload-specific `SupervisorAttachConfig`
(arrives over the control UDS). A pure `verify_and_merge_attach` function performs the
binding-nonce echo check, field merge, and the load-bearing plan re-verify
(Ed25519 signature + G4 window + nonce-replay) — reusing `mvm_core::plan::{verify_plan,
check_window, NonceStore}` verbatim, never forking a second verifier. The cold/legacy
path (bare `SupervisorConfig` on stdin, no control UDS) is byte-for-byte unchanged.

**Tech Stack:** Rust, `libkrun-sys` (FFI feature-gated), `mvm-core::plan` (signing +
validity), `mvm-hostd::framing` (length-prefixed JSON), `ed25519-dalek`, `cargo-fuzz`.

---

## Why the security crux matters (read before coding)

The cold path (`mvm-libkrun-supervisor.rs:204-217`) *deliberately skips* plan re-verify:
the host admitted the plan and stdin is a private parent→child pipe, trusted under
ADR-002 — it **extracts**, it does not verify. The warm path's control UDS is
**same-uid-reachable**, so it is NOT a trusted private channel. The supervisor MUST
independently re-verify before `start_enter`. This is the one new security invariant
1a adds. Cross-standby replay is closed by a **per-spawn binding nonce** that the attach
must echo (a standby with a different nonce rejects), combined with **one-shot attach**
(accept exactly one connection, then boot-or-die) and the plan's G4 window. Within-standby
replay is closed by the `NonceStore`.

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `crates/mvm-hostd/src/framing.rs` | Add sync `read_json_frame_sync`/`write_json_frame_sync` sharing `FrameError` + cap logic (the prelaunch accept path is sync — no tokio runtime before `start_enter`). | Modify |
| `crates/deps/libkrun-sys/src/lib.rs` | `SupervisorBaseConfig`, `SupervisorAttachConfig`, `AttachMergeError`, `SupervisorConfig::from_base_and_attach`. No `mvm-core` dep (stays a leaf). | Modify (near `:1293`) |
| `crates/mvm-vm-host/src/prelaunch.rs` | Pure `verify_and_merge_attach(base, attach_bytes, now, &mut NonceStore) -> Result<SupervisorConfig, AttachVerifyError>` — the unit-testable verify+merge (a–e rejection ladder, no VM). | Create |
| `crates/mvm-vm-host/src/lib.rs` | `pub mod prelaunch;` | Modify |
| `crates/mvm-vm-host/Cargo.toml` | Add `chrono`, `thiserror` deps. | Modify |
| `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs` | `PrelaunchEnvelope` stdin dispatch; `run_prelaunched`; control-socket bind/accept/read; extract `dispatch_config` tail shared with the legacy path. | Modify |
| `crates/deps/libkrun-sys/fuzz/fuzz_targets/fuzz_attach_message.rs` | Fuzz the `SupervisorAttachConfig` decoder (only attacker-reachable-post-spawn surface). | Create |
| `crates/deps/libkrun-sys/fuzz/Cargo.toml` | Register the new `[[bin]]`. | Modify |
| `crates/mvm-vm-host/tests/prelaunch_live.rs` | `libkrun-live`-gated integration: prelaunch → valid attach boots + agent reachable; wrong-nonce attach refused, no boot. | Create |
| `specs/REFACTOR-STATUS.md`, `specs/plans/118-...md`, design note | Tick the 1a boxes. | Modify |

## Build/test commands (this repo's gotchas)

- The supervisor bin is feature-gated and **not** rebuilt by plain `cargo build`/`test`.
  Build it explicitly, with the rustup toolchain prepended to PATH (Homebrew rustc
  shadows it → libkrun-sys bindgen E0514):
  ```bash
  PATH="$HOME/.rustup/toolchains/$(rustup show active-toolchain | awk '{print $1}')/bin:$PATH" \
    cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys
  ```
- Unit tests (no libkrun FFI needed for Tasks 1–3, 5):
  ```bash
  cargo nextest run -p mvm-hostd -p libkrun-sys -p mvm-vm-host -E 'not package(mvm-backend)'
  ```
- Gates before any commit that closes a task: `cargo fmt --all -- --check`,
  `cargo clippy --workspace -- -D warnings`, `cargo test --workspace --doc`.

---

## Task 1: Sync length-prefixed framing helpers

The prelaunch accept loop is synchronous (the supervisor has no tokio runtime running
before `start_enter`). Reuse the existing wire format by adding sync siblings to the
async framing — single source of truth for the 4-byte BE length prefix + cap check.

**Files:**
- Modify: `crates/mvm-hostd/src/framing.rs`
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing tests**

Add to `crates/mvm-hostd/src/framing.rs` `mod tests`:

```rust
    #[test]
    fn sync_round_trips_a_json_frame() {
        let msg = Msg { kind: "ping".into(), n: 7 };
        let mut buf = Vec::new();
        write_json_frame_sync(&mut buf, &msg).unwrap();
        let body_len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(body_len, buf.len() - FRAME_LEN_BYTES);
        let mut cursor = std::io::Cursor::new(buf);
        let got: Msg = read_json_frame_sync(&mut cursor, DEFAULT_MAX_FRAME_BYTES).unwrap();
        assert_eq!(got, msg);
    }

    #[test]
    fn sync_rejects_oversize_length_prefix_before_alloc() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_json_frame_sync::<_, Msg>(&mut cursor, DEFAULT_MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge { size, cap: DEFAULT_MAX_FRAME_BYTES } if size == u32::MAX as usize
        ));
    }

    #[test]
    fn sync_truncated_body_is_an_io_error() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&16u32.to_be_bytes());
        framed.extend_from_slice(b"abcd");
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_json_frame_sync::<_, Msg>(&mut cursor, DEFAULT_MAX_FRAME_BYTES).unwrap_err();
        assert!(matches!(err, FrameError::Io(_)));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-hostd framing::tests::sync_`
Expected: FAIL — `write_json_frame_sync`/`read_json_frame_sync` not found.

- [ ] **Step 3: Add the sync helpers**

Insert after `read_json_frame` (before `#[cfg(test)]`) in `crates/mvm-hostd/src/framing.rs`:

```rust
/// Synchronous sibling of [`write_json_frame`] for the same-uid UDS
/// control channels that run *without* a tokio runtime (the libkrun
/// supervisor's prelaunch accept path runs before `start_enter`, so it
/// can't park a runtime). Same wire format — 4-byte BE length + JSON body.
pub fn write_json_frame_sync<W, T>(stream: &mut W, value: &T) -> Result<(), FrameError>
where
    W: std::io::Write + ?Sized,
    T: serde::Serialize,
{
    let body = serde_json::to_vec(value).map_err(FrameError::Encode)?;
    let len: u32 = body.len().try_into().map_err(|_| FrameError::LengthOverflow)?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

/// Synchronous sibling of [`read_json_frame`]. Enforces `max_frame_bytes`
/// on the length prefix **before** allocating the body — same gate-1
/// invariant as the async path.
pub fn read_json_frame_sync<R, T>(stream: &mut R, max_frame_bytes: usize) -> Result<T, FrameError>
where
    R: std::io::Read + ?Sized,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_frame_bytes {
        return Err(FrameError::TooLarge { size: len, cap: max_frame_bytes });
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(FrameError::Decode)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-hostd framing::tests::sync_`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/framing.rs
git commit -m "feat(framing): sync length-prefixed JSON frame helpers for the supervisor prelaunch path"
```

---

## Task 2: Config split + `from_base_and_attach` (libkrun-sys)

Split the workload-independent vs workload-specific fields. `libkrun-sys` stays a leaf
(no `mvm-core` dep) — so the *merge + nonce echo* live here, but the *plan re-verify*
lives in Task 3 (which can depend on `mvm-core::plan`).

**Files:**
- Modify: `crates/deps/libkrun-sys/src/lib.rs` (add after `SupervisorConfig`'s `impl`,
  near `:1293`)
- Test: same file, in the existing `#[cfg(test)] mod tests` (or a new one if absent)

- [ ] **Step 1: Write the failing tests**

Add a test module near the `SupervisorConfig` definition (use a fresh
`#[cfg(test)] mod base_attach_tests`):

```rust
#[cfg(test)]
mod base_attach_tests {
    use super::*;

    fn base() -> SupervisorBaseConfig {
        // Kernel-only base: a standby carries NO workload rootfs. Build a
        // KrunContext then null the rootfs the new() constructor sets.
        let mut krun = KrunContext::new("standby-0", "/k/vmlinux", "/placeholder");
        krun.rootfs_path = None;
        SupervisorBaseConfig {
            krun,
            vm_state_dir: "/run/mvm/standby-0".into(),
            pid_file_name: None,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "aa".repeat(32),
            control_socket_path: "/run/mvm/standby-0/control-aa.sock".into(),
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
        }
    }

    fn attach(nonce: &str) -> SupervisorAttachConfig {
        SupervisorAttachConfig {
            binding_nonce: nonce.to_string(),
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/gateway-standby-0.sock".into(),
            gateway_events_socket: None,
            plan: serde_json::json!({"envelope": "stub"}),
            bundle: None,
        }
    }

    #[test]
    fn merge_happy_path_sets_rootfs_and_workload_fields() {
        let cfg = SupervisorConfig::from_base_and_attach(base(), attach(&"aa".repeat(32))).unwrap();
        assert_eq!(cfg.krun.rootfs_path.as_deref(), Some("/vol/rootfs.ext4"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(cfg.signing_key_path.as_deref().and_then(|p| p.to_str()), Some("/keys/host-signer.ed25519"));
        assert_eq!(cfg.vm_state_dir, "/run/mvm/standby-0");
        assert!(cfg.plan.is_some());
    }

    #[test]
    fn merge_rejects_binding_nonce_mismatch() {
        let err = SupervisorConfig::from_base_and_attach(base(), attach("bb".repeat(32).as_str())).unwrap_err();
        assert!(matches!(err, AttachMergeError::BindingNonceMismatch));
    }

    #[test]
    fn merge_rejects_base_that_already_carries_a_rootfs() {
        let mut b = base();
        b.krun.rootfs_path = Some("/leftover.ext4".into());
        let err = SupervisorConfig::from_base_and_attach(b, attach(&"aa".repeat(32))).unwrap_err();
        assert!(matches!(err, AttachMergeError::BaseHasRootfs));
    }

    #[test]
    fn attach_config_denies_unknown_fields() {
        let json = serde_json::json!({
            "binding_nonce": "aa", "rootfs_path": "/r", "tenant_id": "t",
            "audit_dir": "/a", "gateway_audit_socket": "/a/g.sock",
            "plan": {}, "surprise": true
        });
        assert!(serde_json::from_value::<SupervisorAttachConfig>(json).is_err());
    }

    #[test]
    fn base_and_whole_configs_are_serde_disjoint() {
        // A bare (legacy) SupervisorConfig JSON must NOT parse as a base
        // (missing binding_nonce/control_socket_path/signing_key_path/signer_id),
        // so the bin's wrapper-key dispatch can never misroute legacy callers.
        let whole = serde_json::json!({
            "krun": serde_json::to_value(KrunContext::new("n","/k","/r")).unwrap(),
            "vm_state_dir": "/s"
        });
        assert!(serde_json::from_value::<SupervisorBaseConfig>(whole).is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p libkrun-sys base_attach_tests`
Expected: FAIL — `SupervisorBaseConfig` / `SupervisorAttachConfig` / `AttachMergeError` /
`from_base_and_attach` not found.

- [ ] **Step 3: Add the types + merge**

Insert immediately after the `impl SupervisorConfig { ... }` block (after
`validate_audit_substrate`, near `:1420`) in `crates/deps/libkrun-sys/src/lib.rs`:

```rust
/// Workload-**independent** supervisor config — everything a prelaunched
/// standby (Plan 118 WS-1 1a) sets up before it knows which workload it
/// will run. Carries no rootfs and no plan; those arrive in the
/// [`SupervisorAttachConfig`] over the control UDS. `krun.rootfs_path`
/// MUST be `None` — [`SupervisorConfig::from_base_and_attach`] rejects a
/// base that already carries one (it would shadow the workload rootfs).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorBaseConfig {
    /// Workload-independent guest config: kernel, vcpus/ram, vsock wiring,
    /// console, host_listen_ports. `rootfs_path` must be `None`.
    pub krun: KrunContext,
    pub vm_state_dir: String,
    #[serde(default)]
    pub pid_file_name: Option<String>,
    /// `~/.mvm/keys/host-signer.ed25519` — host signing key. Source of the
    /// **public** key the attach-time plan re-verify checks against (claim 8;
    /// no new key). Carried in base because it is host identity, not workload.
    pub signing_key_path: std::path::PathBuf,
    /// Expected envelope `signer_id` (`host:{hostname}`). The attach plan must
    /// be signed by this id, else `verify_plan` reports `UnknownSigner`.
    pub signer_id: String,
    /// Per-spawn binding nonce (hex of 32 random bytes). The attach must echo
    /// it; a standby with a different nonce rejects (cross-standby replay).
    pub binding_nonce: String,
    /// Control UDS the standby binds and blocks on. Mode `0700`, in a `0700`
    /// dir, with the binding nonce embedded in the path.
    pub control_socket_path: std::path::PathBuf,
    #[serde(default)]
    pub bridge_restart_policy: BridgeRestartPolicy,
}

/// Workload-**specific** supervisor config — the bytes that arrive over the
/// control UDS at attach. The only attacker-reachable-post-spawn surface
/// (fuzzed by `fuzz_attach_message`). The plan re-verify in
/// `mvm_vm_host::prelaunch` is what makes accepting these bytes safe.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorAttachConfig {
    /// Echoed binding nonce — must equal `base.binding_nonce`.
    pub binding_nonce: String,
    /// Workload rootfs ext4 (`krun add_disk "root"`).
    pub rootfs_path: String,
    pub tenant_id: String,
    pub audit_dir: std::path::PathBuf,
    pub gateway_audit_socket: std::path::PathBuf,
    #[serde(default)]
    pub gateway_events_socket: Option<std::path::PathBuf>,
    /// JSON-encoded `SignedExecutionPlan` envelope — same carrier shape as
    /// `SupervisorConfig.plan`. Required (the warm path always carries a plan).
    pub plan: serde_json::Value,
    #[serde(default)]
    pub bundle: Option<serde_json::Value>,
}

/// Failure modes of [`SupervisorConfig::from_base_and_attach`]. The plan
/// re-verify failures live in `mvm_vm_host::prelaunch::AttachVerifyError` —
/// this leaf crate can't depend on `mvm-core::plan`.
#[derive(Debug, PartialEq, Eq)]
pub enum AttachMergeError {
    /// The attach's echoed binding nonce != the base's binding nonce.
    BindingNonceMismatch,
    /// The base already carried a rootfs — it would shadow the workload's.
    BaseHasRootfs,
}

impl std::fmt::Display for AttachMergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindingNonceMismatch => f.write_str("attach binding nonce does not match the standby's"),
            Self::BaseHasRootfs => f.write_str("base config already carries a rootfs (would shadow the workload)"),
        }
    }
}
impl std::error::Error for AttachMergeError {}

impl SupervisorConfig {
    /// Merge a prelaunched standby's [`SupervisorBaseConfig`] with the
    /// [`SupervisorAttachConfig`] received over the control UDS, validating
    /// the echoed binding nonce, into a whole `SupervisorConfig` the existing
    /// `run_with_bridge` path consumes verbatim. Does **not** verify the plan
    /// signature — that is `mvm_vm_host::prelaunch::verify_and_merge_attach`'s
    /// job (this crate is a leaf with no `mvm-core` dep).
    pub fn from_base_and_attach(
        base: SupervisorBaseConfig,
        attach: SupervisorAttachConfig,
    ) -> Result<SupervisorConfig, AttachMergeError> {
        if attach.binding_nonce != base.binding_nonce {
            return Err(AttachMergeError::BindingNonceMismatch);
        }
        if base.krun.rootfs_path.is_some() {
            return Err(AttachMergeError::BaseHasRootfs);
        }
        let mut krun = base.krun;
        krun.rootfs_path = Some(attach.rootfs_path);
        Ok(SupervisorConfig {
            krun,
            vm_state_dir: base.vm_state_dir,
            pid_file_name: base.pid_file_name,
            tenant_id: Some(attach.tenant_id),
            audit_dir: Some(attach.audit_dir),
            gateway_audit_socket: Some(attach.gateway_audit_socket),
            gateway_events_socket: attach.gateway_events_socket,
            signing_key_path: Some(base.signing_key_path),
            plan: Some(attach.plan),
            bundle: attach.bundle,
            bridge_restart_policy: base.bridge_restart_policy,
        })
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p libkrun-sys base_attach_tests`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/deps/libkrun-sys/src/lib.rs
git commit -m "feat(libkrun-sys): SupervisorBaseConfig/AttachConfig split + from_base_and_attach merge"
```

---

## Task 3: Pure `verify_and_merge_attach` (the security crux)

The unit-testable heart: parse attach bytes → merge (nonce echo) → re-verify the signed
plan (signature against the on-disk host key, G4 window, nonce-replay) — **never boots**.
Lives in `mvm-vm-host` because it needs both `libkrun-sys` (for the merge) and
`mvm-core::plan` (for verify). Reuses `verify_plan` + `check_window` + `NonceStore`.

**Files:**
- Modify: `crates/mvm-vm-host/Cargo.toml` (add `chrono`, `thiserror`)
- Create: `crates/mvm-vm-host/src/prelaunch.rs`
- Modify: `crates/mvm-vm-host/src/lib.rs` (`pub mod prelaunch;`)
- Test: in `prelaunch.rs` `#[cfg(test)] mod tests`

- [ ] **Step 1: Add deps + module declaration**

In `crates/mvm-vm-host/Cargo.toml` `[dependencies]` add:

```toml
chrono = { workspace = true }
thiserror = "1"
```

In `crates/mvm-vm-host/src/lib.rs`, add after `pub mod firecracker_bridge;`:

```rust
/// Plan 118 WS-1 1a — the prelaunched-supervisor attach verify+merge. Pure
/// (no VM, no `start_enter`) so the rejection ladder is unit-testable.
pub mod prelaunch;
```

- [ ] **Step 2: Write the failing tests**

Create `crates/mvm-vm-host/src/prelaunch.rs` with ONLY the test module first (the impl
in Step 4 makes them compile + pass). Test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use libkrun_sys::{BridgeRestartPolicy, KrunContext, SupervisorAttachConfig, SupervisorBaseConfig};
    use mvm_core::plan::{sign_plan, ExecutionPlan, NonceStore};
    use std::io::Write;

    const NONCE: &str = "aa_aa_aa_aa_aa_aa_aa_aa_aa_aa_aa_aa"; // any stable hex-ish string

    // A 32-byte ed25519 secret written to a tempfile; returns (path, signing key).
    fn write_key(dir: &std::path::Path) -> (std::path::PathBuf, SigningKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let path = dir.join("host-signer.ed25519");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(key.to_bytes().as_slice()).unwrap();
        (path, key)
    }

    fn sample_plan(now: chrono::DateTime<Utc>) -> ExecutionPlan {
        // Reuse the canonical sample then pin a window around `now`.
        let mut p = mvm_core::plan::signing::test_support::sample_plan();
        p.valid_from = now - Duration::minutes(5);
        p.valid_until = now + Duration::minutes(5);
        p
    }

    fn base(key_path: std::path::PathBuf, signer_id: &str) -> SupervisorBaseConfig {
        let mut krun = KrunContext::new("standby-0", "/k/vmlinux", "/placeholder");
        krun.rootfs_path = None;
        SupervisorBaseConfig {
            krun,
            vm_state_dir: "/run/mvm/standby-0".into(),
            pid_file_name: None,
            signing_key_path: key_path,
            signer_id: signer_id.into(),
            binding_nonce: NONCE.into(),
            control_socket_path: "/run/mvm/standby-0/control.sock".into(),
            bridge_restart_policy: BridgeRestartPolicy::HardFail,
        }
    }

    fn attach_bytes(nonce: &str, plan_envelope: serde_json::Value) -> Vec<u8> {
        let attach = SupervisorAttachConfig {
            binding_nonce: nonce.into(),
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/g.sock".into(),
            gateway_events_socket: None,
            plan: plan_envelope,
            bundle: None,
        };
        serde_json::to_vec(&attach).unwrap()
    }

    fn signed_envelope(plan: &ExecutionPlan, key: &SigningKey, signer_id: &str) -> serde_json::Value {
        serde_json::to_value(sign_plan(plan, key, signer_id)).unwrap()
    }

    #[test]
    fn happy_path_returns_admitted_config() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let plan = sample_plan(now);
        let bytes = attach_bytes(NONCE, signed_envelope(&plan, &key, "host:test"));
        let mut store = NonceStore::new();
        let cfg = verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap();
        assert_eq!(cfg.krun.rootfs_path.as_deref(), Some("/vol/rootfs.ext4"));
        assert_eq!(cfg.tenant_id.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn rejects_wrong_binding_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let bytes = attach_bytes("WRONG", signed_envelope(&sample_plan(now), &key, "host:test"));
        let mut store = NonceStore::new();
        let err = verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::Merge(_)));
    }

    #[test]
    fn rejects_unsigned_plan_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, _real) = write_key(dir.path());
        let attacker = SigningKey::from_bytes(&[9u8; 32]); // not the on-disk key
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let bytes = attach_bytes(NONCE, signed_envelope(&sample_plan(now), &attacker, "host:test"));
        let mut store = NonceStore::new();
        let err = verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::PlanVerify(_)));
    }

    #[test]
    fn rejects_out_of_window_plan() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let plan_now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let plan = sample_plan(plan_now);
        let bytes = attach_bytes(NONCE, signed_envelope(&plan, &key, "host:test"));
        // Verify an hour after the window closed.
        let later = plan_now + Duration::hours(1);
        let mut store = NonceStore::new();
        let err = verify_and_merge_attach(base(kp, "host:test"), &bytes, later, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::Validity(_)));
    }

    #[test]
    fn rejects_replayed_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let (kp, key) = write_key(dir.path());
        let now = Utc.with_ymd_and_hms(2026, 6, 9, 12, 0, 0).unwrap();
        let plan = sample_plan(now);
        let bytes = attach_bytes(NONCE, signed_envelope(&plan, &key, "host:test"));
        let mut store = NonceStore::new();
        // First admit succeeds; second (same store, same plan) is a replay.
        verify_and_merge_attach(base(kp.clone(), "host:test"), &bytes, now, &mut store).unwrap();
        let err = verify_and_merge_attach(base(kp, "host:test"), &bytes, now, &mut store).unwrap_err();
        assert!(matches!(err, AttachVerifyError::Validity(_)));
    }
}
```

> **Note on `test_support::sample_plan`:** `mvm-core`'s sample plan currently lives in
> `signing.rs`'s `#[cfg(test)]` module, which is not reachable cross-crate. Step 3 below
> promotes it to a `pub` test-support helper so this crate can build valid plans without
> duplicating the ~40-line literal.

- [ ] **Step 3: Expose a cross-crate sample-plan helper in mvm-core**

In `crates/mvm-core/src/plan/signing.rs`, move the `sample_plan()` body out of
`#[cfg(test)] mod tests` into a always-compiled, test-only-gated public helper. Add near
the top of the file (after imports):

```rust
/// Test-support fixtures shared across crates. Gated so it never ships in a
/// non-test build but is reachable from other crates' `#[cfg(test)]` code.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use crate::plan::types::*;
    use chrono::{TimeZone, Utc};
    use std::collections::BTreeMap;

    /// A minimal valid `ExecutionPlan` with a wide validity window. Callers
    /// override `valid_from`/`valid_until`/`nonce` as their scenario needs.
    pub fn sample_plan() -> ExecutionPlan {
        // ... move the EXACT body currently in `mod tests::sample_plan()` here ...
    }
}
```

Then in `signing.rs`'s `mod tests`, replace the local `sample_plan` with
`use super::test_support::sample_plan;`. Add the `test-support` feature to
`crates/mvm-core/Cargo.toml` `[features]` (`test-support = []`) and, in
`crates/mvm-vm-host/Cargo.toml` `[dev-dependencies]`, depend on it:

```toml
mvm-core = { workspace = true, features = ["test-support"] }
```

(If a `[dev-dependencies] mvm-core` line is absent, add it; the non-dev dep stays
feature-free so production builds never compile the fixtures.)

- [ ] **Step 4: Run tests to verify they fail (compile error / not-found)**

Run: `cargo nextest run -p mvm-vm-host prelaunch::tests`
Expected: FAIL — `verify_and_merge_attach` / `AttachVerifyError` not defined.

- [ ] **Step 5: Write the implementation**

Prepend to `crates/mvm-vm-host/src/prelaunch.rs` (above the test module):

```rust
//! Plan 118 WS-1 Layer 1a — prelaunched-supervisor attach verify+merge.
//!
//! The cold/legacy supervisor path extracts the admitted plan without
//! re-verifying (host-trusted private stdin pipe, ADR-002). The warm path's
//! control UDS is **same-uid-reachable**, so it is NOT a trusted private
//! channel — this module re-verifies the signed `ExecutionPlan` (Ed25519
//! signature + G4 window + nonce-replay) before the caller may `start_enter`.
//! Reuses `mvm_core::plan::{verify_plan, check_window, NonceStore}`; no fork.

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use libkrun_sys::{SupervisorAttachConfig, SupervisorBaseConfig, SupervisorConfig};
use mvm_core::plan::{check_window, verify_plan, NonceStore, SignedExecutionPlan};

/// Why an attach was refused. Every variant means the caller must NOT
/// `start_enter` — the standby exits non-zero.
#[derive(Debug, thiserror::Error)]
pub enum AttachVerifyError {
    #[error("decode attach config: {0}")]
    Decode(String),
    #[error("merge base+attach: {0}")]
    Merge(#[from] libkrun_sys::AttachMergeError),
    #[error("read host signing key {0}: {1}")]
    ReadKey(String, String),
    #[error("host signing key is {0} bytes, expected 32")]
    KeyLen(usize),
    #[error("decode SignedExecutionPlan envelope: {0}")]
    Envelope(String),
    #[error("plan signature verify failed: {0}")]
    PlanVerify(String),
    #[error("plan validity (window/nonce): {0}")]
    Validity(String),
}

/// Verify a control-UDS `attach` against a prelaunched standby's `base` and,
/// on success, return the whole `SupervisorConfig` the caller hands to the
/// existing `run_with_bridge` path. **Never boots.** The caller calls
/// `start_enter` only on `Ok`.
///
/// Order mirrors `mvm_hostd::supervisor::aggregate::launch`:
/// merge (binding-nonce echo) → signature → G4 window → nonce-replay.
pub fn verify_and_merge_attach(
    base: SupervisorBaseConfig,
    attach_bytes: &[u8],
    now: DateTime<Utc>,
    nonce_store: &mut NonceStore,
) -> Result<SupervisorConfig, AttachVerifyError> {
    // Pull the bits we still need after `base`/`attach` are moved into the merge.
    let signer_id = base.signer_id.clone();
    let key_path = base.signing_key_path.clone();

    let attach: SupervisorAttachConfig = serde_json::from_slice(attach_bytes)
        .map_err(|e| AttachVerifyError::Decode(e.to_string()))?;
    let plan_value = attach.plan.clone();

    // Binding-nonce echo + field merge (also rejects a base carrying a rootfs).
    let cfg = SupervisorConfig::from_base_and_attach(base, attach)?;

    // Derive the host-signer PUBLIC key from the on-disk secret. The key is
    // host-trusted state (claim 8); the secret never leaves this process. Same
    // 32-byte read the cold path's audit signer performs.
    let key_bytes = std::fs::read(&key_path)
        .map_err(|e| AttachVerifyError::ReadKey(key_path.display().to_string(), e.to_string()))?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AttachVerifyError::KeyLen(key_bytes.len()))?;
    let vk: VerifyingKey = SigningKey::from_bytes(&key_arr).verifying_key();

    // Re-verify the signature — the load-bearing warm-path invariant.
    let signed: SignedExecutionPlan = serde_json::from_value(plan_value)
        .map_err(|e| AttachVerifyError::Envelope(e.to_string()))?;
    let plan = verify_plan(&signed, &[(signer_id.as_str(), &vk)])
        .map_err(|e| AttachVerifyError::PlanVerify(e.to_string()))?;

    // G4 validity window + per-signer nonce-replay.
    check_window(&plan, now).map_err(|e| AttachVerifyError::Validity(e.to_string()))?;
    nonce_store
        .check_and_insert(&signed.0.signer_id, &plan)
        .map_err(|e| AttachVerifyError::Validity(e.to_string()))?;

    Ok(cfg)
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-vm-host prelaunch::tests`
Expected: PASS (5 tests). Also run `cargo nextest run -p mvm-core signing::` to confirm
the `test_support` move didn't break mvm-core's own tests.

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-vm-host/Cargo.toml crates/mvm-vm-host/src/lib.rs \
        crates/mvm-vm-host/src/prelaunch.rs crates/mvm-core/Cargo.toml \
        crates/mvm-core/src/plan/signing.rs
git commit -m "feat(supervisor): attach verify+merge with mandatory plan re-verify (Plan 118 WS-1 1a security crux)"
```

---

## Task 4: Bin wiring — prelaunch dispatch + control socket

Wire the pure function into the `mvm-libkrun-supervisor` bin: dispatch a `prelaunch_base`
stdin envelope to the new path, bind the control UDS one-shot, read the attach frame,
verify+merge, and hand off to the **existing** `run_with_bridge`. The legacy path stays
byte-for-byte unchanged.

**Files:**
- Modify: `crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs`

This bin only builds under `--features libkrun-sys`; verify with the explicit build
command (Build/test section). No new unit test here — the verify logic is Task 3's pure
function (already covered); the socket dance is covered by Task 6's live test.

- [ ] **Step 1: Add imports + the stdin dispatch envelope**

At the top of `main()`'s use-block region, add to the `libkrun_sys` import:
`SupervisorBaseConfig`. Add `use std::os::unix::fs::PermissionsExt;`,
`use std::time::{Duration, Instant};`, `use std::os::unix::net::{UnixListener, UnixStream};`,
`use chrono::Utc;`, `use mvm_core::plan::NonceStore;`.

Add above `fn main`:

```rust
/// Per-connection attach timeout. An abandoned connect must not wedge the
/// standby (1a; pool-size bounds the blast radius in 1b).
const ATTACH_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on the attach frame — workload config is small; reject hostile prefixes.
const MAX_ATTACH_BYTES: usize = 1 << 20; // 1 MiB

/// Stdin dispatch (Plan 118 WS-1 1a). The prelaunched producer wraps the base
/// config under a unique `prelaunch_base` key; legacy callers emit a bare
/// `SupervisorConfig` (no wrapper) and are byte-for-byte unchanged. Probed
/// wrapper-first: a legacy config has no such key, so it falls through to the
/// unchanged whole-config path. `deny_unknown_fields` + the disjoint required
/// fields (`base_and_whole_configs_are_serde_disjoint` test) make this
/// unambiguous — a botched prelaunch can never silently boot via the legacy arm.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrelaunchEnvelope {
    prelaunch_base: SupervisorBaseConfig,
}
```

- [ ] **Step 2: Branch in `main()` after reading stdin**

Replace the block from the `let cfg: SupervisorConfig = match serde_json::from_str(&json)`
(lines ~106-112) **and** the exit-capture + routing tail (lines ~114-159) with a dispatch
that routes prelaunch vs legacy, then shares a single `dispatch_config` tail:

```rust
    // Prelaunch (warm-pool standby) vs legacy/cold (bare SupervisorConfig).
    if let Ok(env) = serde_json::from_str::<PrelaunchEnvelope>(&json) {
        return run_prelaunched(env.prelaunch_base);
    }
    let cfg: SupervisorConfig = match serde_json::from_str(&json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: parse SupervisorConfig JSON: {e}");
            return ExitCode::from(2);
        }
    };
    dispatch_config(cfg)
}

/// Shared tail: given a finalized `SupervisorConfig` (from the legacy stdin
/// decode OR a verified prelaunch attach), bind the workload-exit control
/// listener and route to the bridge/legacy boot path. Extracted so both
/// entrypoints run identical post-config logic.
fn dispatch_config(cfg: SupervisorConfig) -> ExitCode {
    // Plan 152 WS-A: bind the workload-exit control listener before run dispatch.
    if cfg
        .krun
        .host_listen_ports
        .contains(&mvm_guest::vsock::WORKLOAD_EXIT_PORT)
    {
        let state_dir = std::path::PathBuf::from(&cfg.vm_state_dir);
        let control_sock = cfg.krun.vsock_socket_path(mvm_guest::vsock::WORKLOAD_EXIT_PORT);
        let _ = std::fs::remove_file(&control_sock);
        match std::os::unix::net::UnixListener::bind(&control_sock) {
            Ok(listener) => {
                std::thread::spawn(move || {
                    if let Err(e) = mvm_vm_host::exit_capture::capture_once(&listener, &state_dir) {
                        eprintln!("mvm-libkrun-supervisor: exit capture: {e}");
                    }
                });
            }
            Err(e) => eprintln!("mvm-libkrun-supervisor: bind control socket: {e}"),
        }
    }

    let outcome = if cfg.tenant_id.is_some() {
        run_with_bridge(cfg)
    } else {
        run_legacy(&cfg)
    };
    match outcome {
        Err(e) => {
            eprintln!("supervisor failed: {e}");
            ExitCode::from(1)
        }
    }
}
```

(The `ensure_signed()` + `MVM_KRUN_LOG` setup at the top of `main()` stays as-is — it
runs for both paths before the dispatch.)

- [ ] **Step 3: Add `run_prelaunched` + socket helpers**

Append to the bin:

```rust
/// Prelaunched-standby flow (Plan 118 WS-1 1a). `ensure_signed()` + the libkrun
/// dylib are already warm (done in `main`). Bind the control UDS, accept ONE
/// connection (per-conn timeout), read the attach frame, re-verify+merge, then
/// hand the whole config to the existing bridge path. One-shot: any failure or
/// timeout exits non-zero WITHOUT `start_enter`.
fn run_prelaunched(base: SupervisorBaseConfig) -> ExitCode {
    let sock_path = base.control_socket_path.clone();
    let listener = match bind_control_socket(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("prelaunch: bind control socket {}: {e}", sock_path.display());
            return ExitCode::from(3);
        }
    };
    let mut stream = match accept_one_with_timeout(&listener, ATTACH_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("prelaunch: attach accept failed: {e}");
            return ExitCode::from(4);
        }
    };
    // Best-effort cleanup of the control socket — the workload-exit socket the
    // bridge path binds is a different path under the state dir.
    let _ = std::fs::remove_file(&sock_path);

    let attach_bytes: Vec<u8> =
        match mvm_hostd::framing::read_json_frame_sync::<_, serde_json::Value>(&mut stream, MAX_ATTACH_BYTES) {
            // Re-encode to bytes for the pure verifier (it owns the deny_unknown_fields decode).
            Ok(v) => match serde_json::to_vec(&v) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("prelaunch: re-encode attach: {e}");
                    return ExitCode::from(5);
                }
            },
            Err(e) => {
                eprintln!("prelaunch: read attach frame: {e}");
                return ExitCode::from(5);
            }
        };

    let mut nonce_store = NonceStore::new();
    let cfg = match mvm_vm_host::prelaunch::verify_and_merge_attach(
        base,
        &attach_bytes,
        Utc::now(),
        &mut nonce_store,
    ) {
        Ok(c) => c,
        Err(e) => {
            // SECURITY: refused — never start_enter.
            eprintln!("prelaunch: attach refused: {e}");
            return ExitCode::from(6);
        }
    };
    dispatch_config(cfg)
}

/// Bind the control UDS at `path` with mode 0700, inside a 0700 parent dir.
/// Mirrors the W1.2 vsock-proxy posture: same-uid only.
fn bind_control_socket(path: &std::path::Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let _ = std::fs::remove_file(path); // clear a stale socket
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(listener)
}

/// Accept exactly one connection within `timeout`, else error. Sets a read
/// timeout on the accepted stream too, so a connected-but-silent peer can't
/// wedge the standby.
fn accept_one_with_timeout(listener: &UnixListener, timeout: Duration) -> std::io::Result<UnixStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))?;
                return Ok(stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "attach timeout"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
}
```

- [ ] **Step 4: Build the feature-gated bin**

Run:
```bash
PATH="$HOME/.rustup/toolchains/$(rustup show active-toolchain | awk '{print $1}')/bin:$PATH" \
  cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys
```
Expected: builds clean. Then `cargo clippy -p mvm-vm-host --features libkrun-sys -- -D warnings`.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-vm-host/src/bin/mvm-libkrun-supervisor.rs
git commit -m "feat(supervisor): prelaunched control-UDS attach path in mvm-libkrun-supervisor (Plan 118 WS-1 1a)"
```

---

## Task 5: Fuzz the attach decoder

The `SupervisorAttachConfig` decode is the only attacker-reachable-post-spawn surface.
Sibling harness to `fuzz_supervisor_config`; goal "never panic on any input".

**Files:**
- Create: `crates/deps/libkrun-sys/fuzz/fuzz_targets/fuzz_attach_message.rs`
- Modify: `crates/deps/libkrun-sys/fuzz/Cargo.toml`

- [ ] **Step 1: Write the harness**

Create `crates/deps/libkrun-sys/fuzz/fuzz_targets/fuzz_attach_message.rs`:

```rust
// Plan 118 WS-1 1a / ADR-055 §"New untrusted-input surfaces" — fuzz the
// host-side `SupervisorAttachConfig` JSON parser.
//
// The prelaunched `mvm-libkrun-supervisor` reads this struct off a same-uid
// control UDS — the only attacker-reachable surface after spawn. Any panic
// here is a hard process death before `start_enter`. Sibling of
// `fuzz_supervisor_config`; the harness goal is "never panic on any input"
// (`serde_json::Error` is the expected outcome for malformed bytes).

#![no_main]

use libfuzzer_sys::fuzz_target;
use libkrun_sys::SupervisorAttachConfig;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SupervisorAttachConfig>(data);
});
```

- [ ] **Step 2: Register the bin**

Append to `crates/deps/libkrun-sys/fuzz/Cargo.toml`:

```toml
[[bin]]
name = "fuzz_attach_message"
path = "fuzz_targets/fuzz_attach_message.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 3: Verify it compiles under cargo-fuzz**

Run (from the fuzz dir; `cargo-fuzz` must be installed — skip the run, just check build):
```bash
cargo +nightly fuzz build fuzz_attach_message --fuzz-dir crates/deps/libkrun-sys/fuzz 2>&1 | tail -5 || \
  echo "cargo-fuzz not installed locally — harness compiles in CI's security.yml fuzz job"
```
Expected: builds, or the documented skip (the `security.yml` fuzz job covers it).

- [ ] **Step 4: Commit**

```bash
git add crates/deps/libkrun-sys/fuzz/
git commit -m "test(fuzz): fuzz_attach_message — the prelaunch attach decode surface (Plan 118 WS-1 1a)"
```

---

## Task 6: `libkrun-live`-gated integration test

A real boot on a dev host: prelaunch a supervisor, send a valid attach for an admitted
plan, assert the guest boots + agent reachable; assert a wrong-nonce attach is refused
with no boot. Gated behind the `libkrun-live` feature so it never runs in the
no-FFI/no-VM CI lanes.

**Files:**
- Create: `crates/mvm-vm-host/tests/prelaunch_live.rs`
- Modify: `crates/mvm-vm-host/Cargo.toml` (add a `libkrun-live` feature + test deps)

> **Authoring note:** This test must reuse existing harness scaffolding — do **not**
> hand-roll a KrunContext/plan from scratch. Before writing, grep for an existing
> live-boot helper to model on (the agent-ping example + any `#[cfg(feature =
> "libkrun-live")]` test in `mvm-backend`/`mvm-vm-host`):
> `rg -l 'libkrun-live|agent_ping|examples/agent' crates tests examples`. Build the
> `BaseConfig` (kernel only, `rootfs_path = None`, `host_listen_ports` incl. the agent
> port), spawn `mvm-libkrun-supervisor` with `{"prelaunch_base": <base>}` on stdin, then
> connect to `base.control_socket_path` and `write_json_frame_sync` a
> `SupervisorAttachConfig` whose `plan` is a freshly-signed admitted envelope (sign with
> the same on-disk host key the base points at). Assert the agent answers a ping; in the
> wrong-nonce case assert the supervisor exits non-zero and no agent socket appears.

- [ ] **Step 1: Add the feature + test scaffolding**

In `crates/mvm-vm-host/Cargo.toml` `[features]`:

```toml
# Live-boot integration tests (dev host with libkrun). Never in CI's no-VM lanes.
libkrun-live = ["libkrun-sys"]
```

Create `crates/mvm-vm-host/tests/prelaunch_live.rs` guarded by
`#![cfg(feature = "libkrun-live")]`, implementing the two scenarios per the authoring
note above (model the boot/agent-ping on the helper found by the grep).

- [ ] **Step 2: Run on the dev host (Vz/libkrun available)**

Run (uses an isolated cache to avoid racing parallel sessions — see the
`MVM_CACHE_DIR/MVM_DATA_DIR` isolation note):
```bash
MVM_CACHE_DIR=$(mktemp -d) MVM_DATA_DIR=$(mktemp -d) \
PATH="$HOME/.rustup/toolchains/$(rustup show active-toolchain | awk '{print $1}')/bin:$PATH" \
  cargo test -p mvm-vm-host --features libkrun-live --test prelaunch_live -- --nocapture
```
Expected: both scenarios pass — valid attach boots + agent reachable; wrong-nonce attach
refused, supervisor exits non-zero, no boot.

> If the live boot can't be exercised on the dev host (the libkrun supervisor needs the
> Homebrew krun trio; this Mac defaults to the Vz builder), mark the test `#[ignore]`
> with a comment pointing at the gating note and lean on the Task 3 unit ladder + Task 5
> fuzz for the merge-able CI signal. Do NOT delete the test — leave it runnable for a
> libkrun-capable host.

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-vm-host/Cargo.toml crates/mvm-vm-host/tests/prelaunch_live.rs
git commit -m "test(supervisor): libkrun-live prelaunch boot + wrong-nonce-refused integration (Plan 118 WS-1 1a)"
```

---

## Task 7: Tracking-doc updates

**Files:**
- Modify: `specs/plans/118-supervisor-standby-pool-and-live-bench.md`
- Modify: `specs/REFACTOR-STATUS.md`
- Modify: `specs/notes/plan-118-ws1-layer1a-prelaunched-supervisor-design.md`

- [ ] **Step 1: Tick the boxes**

In Plan 118 §PR-10b (the supervisor primitive), check the boxes this PR lands (config
split, prelaunched flow, attach re-verify, fuzz, unit ladder, live test). Add a one-line
"1a landed in PR #<n>" note. In `specs/REFACTOR-STATUS.md`, tick the matching Plan 118
WS-1 1a row and bump "Last updated" to today's date. In the design note, change the
status banner to "Implemented (1a) — PR #<n>; 1b (pool) remains."

- [ ] **Step 2: Commit**

```bash
git add specs/plans/118-supervisor-standby-pool-and-live-bench.md \
        specs/REFACTOR-STATUS.md specs/notes/plan-118-ws1-layer1a-prelaunched-supervisor-design.md
git commit -m "docs(plan-118): record WS-1 1a prelaunched supervisor primitive landed"
```

---

## Final verification (before opening the PR)

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace -- -D warnings` (and `-p mvm-vm-host --features libkrun-sys`)
- [ ] `cargo nextest run --workspace -E 'not package(mvm-backend)'`
- [ ] `cargo test --workspace --doc`
- [ ] `cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys` (rustup PATH)
- [ ] Open the PR from `feat/plan-118-ws1-layer1a` — **no `Co-Authored-By: Claude` trailer**,
      no Claude attribution in the body.

## Out of scope (1b — separate PR)

`warm_pool_size` / `--warm-pool-size`; `SupervisorStandbyPool` under `~/.mvm/pool/<id>/`;
`up` claim + cold-boot fallback; base-compat (kernel match); reaper + `cache prune` TTL;
replenish-on-use; the bench delta.

---
title: "ADR-041: Signed, audited `ExecutionPlan` — the contract behind every `mvmctl up`"
status: Accepted
date: 2026-05-11
related: ADR-002 (microVM security posture); ADR-005 (libkrun + libkrun pivot); plan 60 (libkrun migration); plan 64 (supervisor wiring)
---

## Status

Accepted. Implementation shipped in plan 64 W1–W6 (`specs/plans/64-supervisor-wiring.md`, commits ae81767 W1, a71e60a W2, 2671f5f + bc91d77 W3, 587a33e W4, 7184b9a W6, and the W5 commit that adds `crates/mvm-cli/src/commands/vm/policy_resolver.rs`). With W5 landed, plan 64 closes; the remaining `*Ref → real-impl` work (TOML policy bundle format, mvm-hostd consumer lift) is plan 60 Phase 3 / Phase 6 hardware attestation.

The plan-60 §"Security model" claim 8 — *every workload runs from a signed, audited `ExecutionPlan`* — went from "proposed" to user-observably true with the W3 callsite + W4 audit chain landing together. CLAUDE.md updated 2026-05-11.

## Context

Through plan-60 the supervisor and plan crates (`mvm-plan`, `mvm-supervisor`) shipped extensive substrate — 28 plan tests, 228 supervisor tests, fail-closed Noop slots for every component (inspector, egress proxy, tool gate, keystore releaser, artifact collector), and a chain-signed audit signer. None of it ran in production: `mvmctl up` parsed args into `VmStartConfig`, called `backend.start()`, and never touched `ExecutionPlan` or `Supervisor::launch`.

That meant claim 8 from plan 60's security model — every workload runs from a signed, audited plan — was *substrate-true*: the types existed, the verifier worked, the chain signer worked, but no live caller produced or consumed any of it on a real boot.

Plan 64 closed that gap: every `mvmctl up` invocation now synthesizes an `ExecutionPlan` from CLI args, signs it under a host-local Ed25519 keypair, verifies it, checks the validity window and nonce replay-store, then emits a chain-signed audit trail bound to the resulting plan_id. Tampering with the audit log breaks `verify_audit_chain`, surfaced via `mvmctl audit verify`.

## Decision

### Lifecycle: plan synthesis → signing → admission → audit → boot

```
mvmctl up <flake|template|default>
  │
  ├── build/resolve rootfs                              [mvm-build dev_build / template loader]
  │     produces: rootfs.ext4 (PathBuf), vmlinux, initrd
  │
  ├── admit_plan_for_boot(...)                         [crates/mvm-cli/src/commands/vm/up.rs]
  │     │
  │     ├── sha256_file(rootfs.ext4)                    [mvm-security::image_verify]
  │     │
  │     ├── synthesize_plan(SynthesisInput { ... })    [W1 — crates/mvm-cli/src/commands/vm/plan_builder.rs]
  │     │     fresh UUIDv4 plan_id, 128-bit nonce, 10-min validity window
  │     │
  │     ├── host_signer::load_or_init_at(~/.mvm/keys/) [W2 — crates/mvm-cli/src/commands/vm/host_signer.rs]
  │     │     mode-0600 secret half, refuses loose perms
  │     │
  │     ├── admit_for_run(input, &SystemClock,         [W3 — crates/mvm-cli/src/commands/vm/plan_admission.rs]
  │     │                 &InMemoryNonceLedger, ...)
  │     │     ├── sign_plan + verify_plan (roundtrip)
  │     │     ├── check_window (G4 validity)
  │     │     └── nonce_store.check_and_insert (G4 replay)
  │     │
  │     └── AuditEmitter::emit_admitted(...)            [W4 — crates/mvm-cli/src/commands/vm/audit_chain.rs]
  │           appends signed envelope to ~/.mvm/audit/<tenant>.jsonl
  │
  ├── backend.start(&start_config)                      [mvm-backend::AnyBackend]
  │
  ├── if Ok(_):  emit_launched_if(ctx, backend_name)
  ├── if Err(e): emit_failed_if(ctx, "backend-start", &e); return Err(e)
  │
  └── ... rest of cmd_run (port forwarding, ctrl-c loop, etc.)
```

### Who builds, who signs, who consumes

| Role | Today | Phase 3 (plan 60 §Phase 3 / plan 63 W3) |
|---|---|---|
| **Plan builder** | `mvmctl` (`synthesize_plan` from CLI args) | mvmd remote-launch path + mvmforge IR-derived plans |
| **Plan signer** | host-local Ed25519 key at `~/.mvm/keys/host-signer.ed25519` (mode 0600) | mvmd's tenant key + on-host attestation key |
| **Plan verifier** | `mvm_plan::verify_plan` against the host's own pubkey + G4 window/nonce checks | supervisor's trusted-keys list (mvmd-issued, host-attested) |
| **Audit signer** | same host key (`AuditEmitter` wraps `FileAuditSigner`) | separate audit-signer key (split from plan-signer per plan 60 §Phase 3) |
| **Audit verifier** | `mvm_supervisor::verify_audit_chain` via `mvmctl audit verify` | same, plus mvmd-side aggregation + cold-stream replication |

### `*Ref` semantics — today vs. eventual

Each `Ref`-typed field of `ExecutionPlan` is a placeholder that resolves to a concrete component or policy at admission. Today most resolve to fail-closed Noops; W5 + Phase 3 give them real impls.

| Field | Today | Eventual resolver | Eventual home |
|---|---|---|---|
| `plan_id` | fresh UUIDv4 per invocation | same | — |
| `plan_version` | always `1` | mvmd revisions get monotonic versions | mvmd |
| `tenant` | `--tenant` flag, default `"local"` | mvmd-issued `TenantId` (cryptographic, not name) | mvmd |
| `workload` | VM name (post-validation) | image-baked workload manifest | mvm-build |
| `runtime_profile` | backend name (`firecracker` / `libkrun` / `apple-container`) | flake `passthru.mvm.profile` | mvm-build |
| `image` | `{ name: vm_name, sha256: <rootfs-hash>, cosign_bundle: None }` | `mvm-security::image_verify` signed-manifest path with cosign bundle | mvm-security |
| `admission_profile` | intent-bound binding of `intent`, selected seccomp tier, policy refs, secret-release posture, and audit taxonomy; direct `mvmctl up` defaults to `intent = "vm:boot"` | mvmd / SDK intent resolver picks named profiles such as `code:execute`, `agent:web-research`, `deploy:publish`, then refuses inconsistent requested powers | mvm-plan + mvmd policy resolver |
| `network_policy` / `fs_policy` / `egress_policy` / `tool_policy` | `"local-default"` → Noops, OR `"<tenant>:<workload>"` → loads `~/.mvm/policies/<tenant>/<workload>.toml` (still returns Noops; no live consumer yet) | real `EgressProxy` / `ToolGate` / `KeystoreReleaser` / `ArtifactCollector` impls reading the parsed bundle | plan 60 Phase 3 (proxies) + mvm-hostd lift |
| `secrets` | empty | mvmd-resolved `SecretGrant` set | mvmd + plan 63 W3 keyring |
| `artifact_policy` | `{ capture_paths: [], retention_days: 0 }` | per-policy bundle | W5 |
| `audit_labels` | empty | inherited from policy bundle + tags | W5 |
| `key_rotation` | `{ interval_days: 0 }` | plan 63 W3 rotation schedule | plan 63 |
| `attestation` | `AttestationRequirement { mode: Noop }` | TPM2 / SEV-SNP / TDX | plan 60 Phase 3 |
| `release_pin` | `None` | optional digest pin from policy | W5 |
| `post_run` | `{ destroy_on_exit: true, snapshot_on_idle: false, idle_secs: 0 }` | per-policy | W5 |
| `valid_from` / `valid_until` | `now` .. `now + 10 min` | unchanged (G4 invariant) | — |
| `nonce` | 128 random bits from `OsRng` | unchanged | — |

The validity window is deliberately short. Long enough for boot + signature verification + state machine walk; short enough that a captured plan can't be replayed hours later. G4 (`mvm_plan::check_window` + `NonceStore`) catches both directions.

### Audit chain shape

Each entry is one line of `~/.mvm/audit/<tenant>.jsonl` carrying a JSON-serialized `mvm_supervisor::SignedEnvelope`:

```json
{
  "entry": {
    "timestamp": "2026-05-11T18:34:21.043Z",
    "tenant": "local",
    "plan_id": "9f7c…",
    "plan_version": 1,
    "image_name": "vm-clever-koala",
    "image_sha256": "8c1f…",
    "event": "plan.launched",
    "labels": { "backend": "firecracker" }
  },
  "prev_hash": "<base64 url-safe-no-pad of SHA-256 of previous envelope>",
  "signature": "<base64 url-safe-no-pad of Ed25519 over `entry || prev_hash`>"
}
```

The chain seed (genesis `prev_hash`) is 32 zero bytes. `FileAuditSigner` restores its in-memory cursor from disk on construction so a process restart resumes without gaps.

Three event types today:

- `plan.admitted` — fires right after `admit_for_run` returns Ok; labels carry `signer_id`.
- `plan.launched` — fires after `backend.start()` Ok (or after `restore_from_template_snapshot` Ok on the snapshot path, or after `install_launchd_direct` Ok on the apple-container detach path); labels carry `backend`.
- `plan.failed` — fires on any error path between admission and successful boot; labels carry `error_class` (`backend-start` / `snapshot-restore` / `launchd-install`) and `error_message` (the rendered anyhow chain).

Audit emission failures `tracing::warn` and continue — a flaky audit fs cannot block a VM that already booted. W6's follow-up tightens this to "audit failure fails the boot" once the chain is reliably reachable on every supported host.

**Backend symmetry (Plan 98).** The `labels.backend` field accepts either `libkrun` or `vz` (and `firecracker` on Linux) — the chain itself is hypervisor-agnostic. `mvmctl up --prod` driven by `MVM_BUILDER_BACKEND=vz` emits the same `plan.admitted` / `plan.launched` / `plan.failed` sequence as the libkrun path, and `mvmctl audit verify` round-trips cleanly across both. Plan 98 §2.S3 ships the cross-backend audit-chain integrity test.

### Operator-facing surface

- `mvmctl up` (existing, instrumented): every invocation admits + audits. `--no-supervisor` is a one-release escape hatch that prints a deprecation warning and skips both.
- `mvmctl audit verify [--tenant <name>]` (new): runs `mvm_supervisor::verify_audit_chain` against `~/.mvm/audit/<tenant>.jsonl` using the host signer's verifying key. Nonzero exit on detected drift. Meant for scripting.
- `mvmctl audit show <plan_id> [--tenant <name>]` (new): filters the chain to entries for a specific `plan_id`.
- `mvmctl audit tail --chain [--tenant <name>] [-f]` (new): tails the plan-64 chain. The unflagged `mvmctl audit tail` still reads the legacy `~/.mvm/log/audit.jsonl` LocalAudit stream (no backward-compat break).

The CLI surface intentionally stops short of `mvmctl plan create / sign / verify`. Synthesis is internal-only for v0; the user-facing plan CLI is a follow-up after W5 lands and policy resolution gives plans meaningful surface area to inspect.

## Consequences

### Positive

- **Claim 8 is true on every host.** A `cargo test --workspace` run exercises the rejection paths on every PR; no special CI job needed because the workspace suite is the gate.
- **Forensic operability.** `mvmctl audit show <plan_id>` answers "what did this VM see at admission?" in O(file-scan) — no log re-derivation, no separate observability stack.
- **Tamper evidence is detection, not prevention.** A compromised host can still delete the audit file or rotate the host key. Plan 60 Phase 3's split-signer model (audit-signer ≠ plan-signer) and cold-stream replication change this.
- **The eventual `mvm-hostd` lift is a one-line change.** `AdmissionContext { admitted, emitter }` is exactly the shape `Supervisor::launch` consumes; the inline `admit + backend.start` body becomes `supervisor.launch(&signed, &trusted_keys).await` once the supervisor is in-process.

### Negative / honest deferrals

- **No `BackendLauncher` adapter yet.** Plan 64 W3 was originally scoped to replace the three inline `backend.start()` callsites with `Supervisor::launch` via a `BackendLauncher` adapter. Investigating `up.rs` (1084 LOC at the start of the session) showed that a faithful refactor was multi-day work that didn't fit cleanly into one slice. The substrate landed; the supervisor lift waits for `mvm-hostd`.
- **Audit signer = plan signer.** v0 uses the host's single Ed25519 key for both. A compromised host can mint a fresh chain. Splitting these keys is plan 60 Phase 3.
- **No trusted clock.** `SystemClock` reads the host wall-clock. A host can wind the clock back to admit a replayed plan within an expired window. `HostBoundRequest::QueryHostTime` (vsock-level) is plan 60 Phase 3.
- **No attestation.** `AttestationRequirement { mode: Noop }` is honored but ignored. Real TPM2 / SEV-SNP / TDX integration is plan 60 Phase 3.
- **PolicyRef slots all Noop.** `network_policy`, `fs_policy`, `egress_policy`, `tool_policy` all resolve to `"local-default"`, which W5's `policy_resolver::resolve_supervisor_components` maps to fail-closed Noops (`NoopEgressProxy` / `NoopToolGate` / `NoopKeystoreReleaser` / `NoopArtifactCollector`). For `"<tenant>:<workload>"` refs, the resolver loads `~/.mvm/policies/<tenant>/<workload>.toml` via `mvm_policy::toml_loader` — operators can stage the bundle file *now*, but the returned slots remain Noops because no live consumer (L4/L7 proxies, real ToolGate) exists yet to read the parsed bundle. Phase 3 builds those consumers. The W5 substrate has no live consumer yet — `up.rs::admit_plan_for_boot` ships `admit + backend.start()` rather than `Supervisor::launch`, so the resolver's `Box<dyn Trait>` slots are not yet handed to a supervisor builder. That happens with the mvm-hostd lift.

### Out of scope (named in plan 64's non-goals)

- Real policy file format (W5 / Phase 3)
- Multi-signer audit chain (Phase 3)
- Trusted clock via vsock (Phase 3)
- Attestation (Phase 3)
- Plan-bound key release (plan 63 W3 keyring)
- `mvmctl plan create / sign / verify` user-facing CLI (post-W5 follow-up)

## References

- `specs/plans/64-supervisor-wiring.md` — full sprint plan for plan 64.
- `specs/plans/60-mvm-libkrun-migration.md` Phase 6 — the cornerstone this ADR documents the shipping of.
- ADR-002 (`specs/adrs/002-microvm-security-posture.md`) — the seven claims this ADR's claim 8 joins.
- `crates/mvm-plan/src/` — `ExecutionPlan`, `SignedExecutionPlan`, `sign_plan`, `verify_plan`, `check_window`, `NonceStore`.
- `crates/mvm-supervisor/src/audit.rs` + `audit_file.rs` — `AuditEntry`, `AuditSigner`, `FileAuditSigner`, `verify_audit_chain`.
- `crates/mvm-cli/src/commands/vm/plan_builder.rs` — W1 synthesis.
- `crates/mvm-cli/src/commands/vm/host_signer.rs` — W2 keystore.
- `crates/mvm-cli/src/commands/vm/plan_admission.rs` — W3 admission pipeline substrate.
- `crates/mvm-cli/src/commands/vm/up.rs::admit_plan_for_boot` — W3 callsite.
- `crates/mvm-cli/src/commands/vm/audit_chain.rs` — W4 audit emitter.
- `crates/mvm-cli/src/commands/ops/audit.rs` — `mvmctl audit verify / show / tail --chain` CLI surface.
- `crates/mvm-cli/src/commands/vm/policy_resolver.rs` — W5 `PolicyRef → ResolvedSlots` resolver substrate.


## Consolidated from ADR-044 — `audit_emit!` macro is the canonical audit emit surface

## Status

Accepted. Macro shipped in PR #106 along with the `LocalAuditBuilder` API, the `xtask check-audit-positional` lint, and the migration of 37 positional emit call sites. The lint is wired into the CI Test/Lint job after `check-no-display-on-secret-types`; new positional `emit(…)` / `event(…).….emit()` calls fail CI until they get the macro treatment or an `// allow(audit-positional): <reason>` annotation.

`tests/audit_emissions_live.rs` carries 40 live drive-and-assert tests as of PR #108 — every positive Emits row in `AUDIT_POSTURE` (`tests/audit_total_coverage.rs`) that can be exercised hermetically has at least one matching live pin, plus 15 negative pins on the ReadOnly leaves.

## Context

Plan 60 Phase 4 calls for "every state-changing CLI verb emits one audit record per attempt, even on no-op" (plan 37 §6). The original emit surface was positional:

```rust
mvm_core::audit::emit(
    mvm_core::audit::LocalAuditKind::ManifestTagAdd,
    None,
    Some(&format!("template={template} tag={tag}")),
);
```

Three problems compounded:

1. **Readability.** The positional `(None, Some(&format!(…)))` form was hard to scan at a glance, especially in multi-line invocations. Reviewers regularly missed which argument was the vm_name versus the detail.

2. **Forward-compatibility.** Plan 60's roadmap calls for an `outcome` field on every emit and (eventually) a `trace_id` for cross-stream correlation. Adding either to the positional signature would have churned ~40 call sites for a one-method change.

3. **Drift.** Two emit destinations coexisted: the canonical `audit::emit` writes to `<state>/log/audit.jsonl` (XDG state path); a handful of sites — notably `storage gc` — built their own `LocalAuditLog::open` against `<data_dir>/audit.log` (singular, `.log`, no `/log/` subdir). The bypass meant `mvmctl audit tail` couldn't see those entries and the live test suite couldn't observe them without per-verb fixture work.

The substrate scaffold (`tests/audit_total_coverage.rs`) caught classification gaps — every CLI subcommand at every level must have an `AuditPosture` declaration — but didn't catch *behavioral* drift. A verb classified `Emits("X")` could ship without an actual emit, or emit to the wrong file, and the static scaffold wouldn't flag it.

## Decision

### Three-layer surface, one canonical entry point

```
audit_emit!(Kind, …)              ← four-arm macro (callers use this)
  │ desugars to
  ▼
audit::event(Kind).….emit()       ← builder API (open-ended composition)
  │ writes through
  ▼
LocalAuditLog::open(default_audit_log()).append(…)
  │ which lands at
  ▼
~/.local/state/mvm/log/audit.jsonl
```

#### Layer 1: `audit_emit!` macro (preferred)

Four arms collapse the common shapes to one line each:

```rust
audit_emit!(CachePrune);                                    // bare
audit_emit!(StorageGc, "count={count}");                    // format-string detail
audit_emit!(SlotRemove, vm: hash);                          // vm_name only
audit_emit!(SlotRemove, vm: hash, "path={p}", p = "x");     // both, named args
```

The format-string arm accepts the full `format!` syntax — positional args, named args, named captures — because the macro passes the literal token stream through to `format!()` verbatim. That means a call site can capture local variables inline (`"k={v}"`) without an explicit binding.

#### Layer 2: `LocalAuditBuilder` (for unusual compositions)

Chained-builder for the cases that don't fit the four arms (e.g. conditional fields, runtime-resolved kinds):

```rust
let mut b = audit::event(kind);
if include_vm { b = b.vm_name(name); }
if let Some(d) = detail { b = b.detail(d); }
b.emit();
```

`LocalAuditBuilder` is marked `#[must_use]` so a dropped chain (forgot `.emit()`) is a compile warning.

#### Layer 3: legacy `emit(kind, vm_name, detail)` shims

`audit::emit` and `audit::emit_to` survive as thin wrappers over the builder. They exist for two reasons: (a) one-line backward-compat for external crates that import the function, and (b) the `emit_to` variant lets tests redirect to an explicit path without `XDG_STATE_HOME` juggling.

New code uses Layer 1 or 2. The xtask lint enforces this.

### Guardrails

**`xtask check-audit-positional`** walks `crates/*/src/**/*.rs` and flags any call to `mvm_core::audit::emit(...)`, `audit::emit_to(...)`, or chained `audit::event(...).….emit()`. Opt-out via `// allow(audit-positional): <reason>` directly above the call (matches the `secret-debug` lint's annotation shape so contributors learn one convention).

The lint runs in CI's Test/Lint job. The audit module itself (`crates/mvm-core/src/policy/audit.rs`) is exempt — the shims and the builder API live there by definition.

**`tests/audit_emissions_live.rs`** is the behavioral suite. For every Emits row in `AUDIT_POSTURE`, a live test spawns the real `mvmctl` binary via `assert_cmd` against a `tempfile::tempdir()` HOME and asserts the audit log carries the expected entry. The substrate (`AuditSandbox`, `read_audit_log`, `count_entries_with_kind`) is shared infrastructure; per-row test bodies are typically 20–30 lines each.

**`tests/audit_total_coverage.rs`** stays as the classification scaffold. It recursively walks `mvm_cli::commands::cli_command()` and asserts every clap subcommand has a declared `AuditPosture`. The live and static layers complement each other: classification catches "did you forget to classify this verb?", behavior catches "did you forget to actually emit?".

### Migration tooling

`scripts/migrate-audit-emit.sh` is a Perl one-shot for the four common positional shapes (bare, with format-detail, with vm, with both). It's idempotent — running twice is a no-op — and handles single- and multi-line forms. The xtask lint catches anything the script skipped; the human reviews and migrates manually.

## Consequences

### Positive

- **One-line call sites.** The most common emit shape collapses from a 4-line positional invocation to a single-line macro call. Readers don't have to mentally parse `None, Some(&format!(…))`.
- **Future fields are free.** Adding `outcome` or `trace_id` to `LocalAuditEvent` becomes a one-method change on the builder; the macro grows new arms; the existing call sites stay untouched.
- **One canonical destination.** Every state-changing verb lands in `<state>/log/audit.jsonl`. `mvmctl audit tail` sees everything. The live test suite reads one file.
- **CI-enforced drift protection.** A new positional emit fails CI before it lands. The bypass requires a written-out reason that surfaces in lint output.

### Negative

- **One more thing to learn.** New contributors see `audit_emit!(...)` and have to look up its arms before they can extend it. The trade is reasonable because the macro's arms cover the 90% case explicitly (see the module-level docs in `crates/mvm-core/src/policy/audit.rs`).
- **`jump-to-def` lands on the macro.** Rust analyzer expands `audit_emit!(StorageGc, ...)` and shows the macro body, not the underlying `event(...)` call. A reader who wants to read the production path needs one extra hop. Acceptable cost.
- **`format!` syntax leaks through.** Misuse (`audit_emit!(K, "{undefined}")`) becomes a `format!` compile error, not a macro error. The message still points at the macro call site, so debugging is fine.

### Bounded

- **The macro doesn't cover the supervisor's chain-signed audit stream.** Plan 64's `~/.mvm/audit/<tenant>.jsonl` chain emits via `AuditEmitter` middleware. That's a different stream with different semantics (chain hashing, plan-bound entries). The `audit_emit!` macro is specifically for the `LocalAudit` stream used by single-host operator-facing verbs.
- **Negative complement tests are still per-verb.** The `xtask check-audit-positional` lint catches *positional* call sites; it doesn't catch a verb that *should* emit but doesn't. That's what the live test suite is for — adding a `Emits("X")` classification to `AUDIT_POSTURE` and a matching live test together is the contract.

## References

- **PR #106** — macro + builder + lint + 19 positional migrations
- **PR #107** — cleanup-host-fallback refactor + 5 ReadOnly negative pins
- **PR #108** — MockBackend substrate + VM-lifecycle live tests (VmStart, VmStop, VmTtlSet)
- **Plan 37 §6** — "no unaudited control-plane mutation" invariant
- **Plan 60 Phase 4** — Persistent observability (audit chain + emission)
- **ADR-041** — Signed, audited `ExecutionPlan` (the chain-signed audit stream this complements)


## Consolidated from ADR-047 — Application Dependency Audit Pipeline (Security Claim 9)

**Status**: Accepted (Phase 9 primitives landed; full pipeline ships post-Plan-71)
**Date**: 2026-05-13
**Cross-refs**: ADR-002 (microvm security posture, claims 1–8), ADR-014 (builder VM via libkrun), SDK port plan §"Auditing the dep volume"

## Context

mvm's existing security claims (ADR-002 claims 1–8) cover the
host↔guest boundary, the verified-boot path, the audited
ExecutionPlan, and a hardened guest agent. They do **not** cover
the *application-dependency* surface — every Python `pip`, Node
`pnpm`, and `npm` install pulls bytes from a public registry that
the rootfs verity hash does not sign.

When the SDK port plan added app-deps volumes (the "Application
deps install inside a builder microVM into a hash-tagged volume"
decision), it opened a new dimension of attack:

- A poisoned pypi mirror can ship a transitive dep whose hash
  matches but whose source is malicious.
- An outdated lockfile may pin a package whose `setup.py` runs
  arbitrary code at install time.
- A successful build inside the builder VM can produce a volume
  the host accepts without ever asking "did pip-audit have
  anything to say about this?"

Hash-pinning (already enforced by `E_UNPINNED_DEPS` in the IR)
is necessary but insufficient: an attacker who controls the
upstream package version field can still ship a hashed-but-poisoned
artifact. The verity claim (claim 3) protects the rootfs; the
*app-deps volume* is a second artifact layer that mounts at
runtime and was not previously audited.

## Decision

Every application-dependency volume the builder VM produces ships
with four sealed artifacts beside its installed contents, plus a
manifest that hashes all four:

```text
~/.mvm/volumes/deps/<volume_hash>/
├── content/                  # /app/.venv or /app/node_modules
├── sbom.cdx.json             # CycloneDX 1.5 SBOM
├── fetch.log                 # every URL the installer dialed
├── cve.json                  # pip-audit / pnpm-audit output
└── meta.json                 # schema_version + sha256s + timestamps
```

The `volume_hash` is computed as:

```text
volume_hash = sha256(content_sha256 || "\n" || canonical_json(meta))
```

where `canonical_json(meta)` is serde-canonical JSON of the
`VolumeManifest` struct (struct-field-order, `BTreeMap`-keyed
annotations). Any tamper to the content, the SBOM, the fetch log,
the CVE result, or the manifest itself invalidates the hash.

### Lifecycle gates

**Build-time (inside the builder VM):**

1. **Hash-pinning** — installer refuses lockfile entries lacking
   a `sha256` (existing `E_UNPINNED_DEPS` gate; re-affirmed here).
2. **Registry allowlist** — builder VM egress permits only
   `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`,
   `objects.githubusercontent.com`. Anything else fails closed at
   the network layer.
3. **Attestation verify** — under `--prod`, the installer rejects
   packages without PEP 740 (Python) or `npm --provenance` (Node)
   signatures. Under `--dev`, missing attestations warn and
   continue.
4. **CVE scan** — `pip-audit` (Python) / `pnpm audit --json`
   (Node) runs against the installed set. Under `--prod`, high or
   critical findings fail closed; under `--dev`, they warn and
   continue.
5. **SBOM emission** — `cyclonedx-py` / `pnpm sbom` produces a
   CycloneDX 1.5 document.
6. **Fetch log** — generated by intercepting the installer's HTTP
   client inside the builder VM.

**Seal:** The builder VM hashes content + sbom + fetch.log +
cve.json into `meta.json`, then computes the volume hash. The
volume directory is renamed to its hash.

**Admission-time (in `mvm_supervisor`):**

The `ExecutionPlan` carries the volume's `volume_hash` and the
`manifest.sha256`. `mvm-supervisor`'s admission verifier runs
[`verify_sealed_volume`](../../crates/mvm-sdk/src/compile/deps_audit.rs)
before launching the workload: the manifest schema version is
checked, every artifact's hash is recomputed from disk, and the
derived volume hash is compared against the plan's recorded value.

A `plan.admitted` audit-chain entry records the pair. A subsequent
tamper to the volume directory invalidates the chain via
`mvmctl audit verify`.

**Re-audit:** `mvmctl deps audit [--all | <hash>]` re-runs the
CVE scan against the current feed, rewrites `cve.json` (which
updates `cve_sha256` → `meta.json` → `volume_hash`), and reseals.
A scheduled re-audit (cron, off by default) keeps long-lived
deployments honest against new CVE disclosures.

**Inspection:** `mvmctl deps inspect <hash>` pretty-prints the
SBOM, fetch log, and CVE result for human review.

### CI gate

`.github/workflows/security.yml` grows an `app-deps-audit` job
mirroring the existing `cargo-deny` / `cargo-audit` gates: it
builds the project's examples, asserts the four sealed artifacts
emit cleanly, and that no example's CVE scan returns high or
critical findings.

### Claim 9 (new, additive to ADR-002)

> Every application-dependency volume is hash-locked,
> attestation-checked, CVE-scanned, SBOM-enumerated, and bound to
> the workload's audit chain. A tampered volume — content, SBOM,
> fetch log, CVE result, or manifest — fails admission closed.

### Backend symmetry (Plan 98)

The Install pipeline above is backend-agnostic on the host side and
entirely guest-side internal. The blanket `InstallDriver` impl over
any `BuilderVm` (`crates/mvm-build/src/app_deps.rs:304-321`) means
the same sealed volume — same `content/`, `sbom.cdx.json`,
`fetch.log`, `cve.json`, hash-chained `meta.json` — flows out of
both libkrun-driven and Vz-driven Install jobs. Cross-backend
parity is enforced by Plan 98 §2.S2 (sealed volume content
byte-equivalence on the same Install input) + §2.S10 (`meta.json`
hash-chain backend-neutrality — identical content yields identical
volume_hash regardless of which VMM booted the builder). Full
backend-parity discussion lives in **ADR-014 §"Vz as a second
builder backend (Plan 98)" → "Security claim parity"**.

## Status of the implementation

| Component | State |
|-----------|-------|
| `VolumeManifest` + `seal_volume` + `verify_sealed_volume` (pure-Rust primitives) | Landed in `crates/mvm-sdk/src/compile/deps_audit.rs` |
| Tamper-detection tests (content, sbom, cve, fetch_log, missing meta, schema mismatch) | Landed |
| Builder VM install path (`mvm-build::install_app_deps`) | **Blocked on Plan 72 W4/W5** — needs working libkrun builder VM |
| `mvmctl deps audit` / `mvmctl deps inspect` CLI verbs | Blocked on the builder VM (no volumes to inspect yet) |
| Supervisor admission verifier wiring | Blocked on the builder VM |
| `.github/workflows/security.yml::app-deps-audit` CI job | Blocked on the builder VM |
| `CLAUDE.md` claim 9 entry | To land alongside the CI gate |

The primitives ship now so:
- The wire format is frozen for the builder VM to target.
- Tamper-detection has unit-test coverage that doesn't need a VM.
- The admission verifier has a stable type to call into when the
  rest of the pipeline lands.

## Consequences

**Positive.**

- Closes the largest gap left by ADR-002 claims 1–8 — app deps
  were the only runtime-mutable input not bound to an audit chain.
- Re-audit is incremental: rewriting `cve.json` updates the volume
  hash without rebuilding `content/`. CI can cheaply rerun the
  scan against a fresh CVE feed.
- The wire shape uses `deny_unknown_fields` so a future
  builder-VM that emits a new field can't be silently accepted by
  an older host.

**Costs.**

- Every install on a fresh lockfile pays for SBOM emission + CVE
  scan. `cyclonedx-py` and `pip-audit` add ~5–10s wall-clock on a
  typical install; under `--dev` we trade strictness for speed.
- The manifest schema version bumps require coordinated host /
  builder VM release; a stale host against a newer builder VM
  produces `VolumeError::SchemaMismatch` rather than silent drift,
  which is the right failure mode.

**Out of scope.**

- Native binary deps (numpy on a custom CPython, sharp's libvips):
  these run inside the builder VM's full toolchain like any other
  install; the audit gates apply uniformly.
- Editable installs (`pip install -e`): break the "volume is a
  frozen artifact" model; deferred to a follow-up.
- Cross-tenant volume sharing: every volume is per-tenant in v1.

## Migration

Existing workloads (those built before this ADR shipped) have no
sealed volumes. The supervisor admission path is gated behind a
flag: if the plan carries no `volume_hash`, the admission verifier
is a no-op. New workloads built after the builder VM cutover
populate the hash, and admission enforces it. This lets the gate
roll in without breaking existing builds.

## References

- ADR-002 — `specs/adrs/002-microvm-security-posture.md` (claims
  1–8)
- ADR-014 — `specs/adrs/014-vmbackend-single-trait.md` (the host
  for the install path)
- Plan 72 (W4/W5) — `specs/plans/72-builder-vm-via-libkrun.md`
  (cutover that unblocks the install + admission wiring)
- SDK port plan §"Auditing the dep volume" — proposed claim 9
  text adopted here
- `crates/mvm-sdk/src/compile/deps_audit.rs` — the primitives


## Consolidated from ADR-048 — Claim-safe sandbox parity roadmap

- Status: Proposed
- Date: 2026-05-14
- Owner: MVM Project
- Related: ADR-004 (egress policy), ADR-031 (cross-platform strategy), ADR-041 (signed audited execution plans), ADR-047 (app dependency audit pipeline), mvmd ADR-0020 (OCI images as microVM workloads)

## Context

The earlier external sandbox runtime's public positioning has sharpened the product bar for local and fleet-managed code sandboxes (external project referred to obliquely per [[feedback_no_competitor_names_anywhere]]; trait key in auto-memory `reference_external_sandbox_control_plane_oblique_key`):

- sub-100ms cold start
- embedded, no-root, no-daemon SDK-owned runtime
- cross-platform native operation
- arbitrary OCI image input
- secrets that do not enter the guest
- programmable DNS/TLS-aware network policy
- extensible filesystem backends
- snapshot/fork/restore workflows
- in-perimeter and air-gapped deployment

`mvm` already has stronger operator/security primitives in several areas: Nix-built rootfs artifacts, signed plans, audit chains, dm-verity posture, Firecracker as the Tier-1 backend, vsock-only guest communication, and multi-backend architecture. The gap is that several developer-facing claims are not yet defensible as shipped behavior.

This ADR records the claims we want to make and the runtime primitives `mvm` must own before those claims are allowed in public docs, landing pages, or release notes.

## Decision

`mvm` will pursue claim-safe parity for seven claims, but each claim is gated by implementation and tests. Marketing language must use the claim status taxonomy below until the gate is green.

### Claim status taxonomy

| Status | Meaning |
|---|---|
| Shipped | Implemented, documented, tested, and wired through at least one production-capable backend. |
| Preview | Implemented behind an explicit flag or limited backend matrix; docs must name limitations. |
| Planned | ADR/plan exists; not available to users. |
| Not claimed | Deliberately absent or rejected. |

### The seven target claims

1. **Claims hygiene:** public docs clearly distinguish Shipped, Preview, Planned, and Not claimed.
2. **OCI ingest:** users can run digest-pinned OCI images in microVMs without Docker as the runtime.
3. **Programmable network policy:** deny-by-default egress with DNS pinning, SNI/Host enforcement, metadata endpoint protection, and audit.
4. **Secrets do not enter guests by default:** workloads receive opaque placeholders; real secret values are released only by trusted host-side policy for approved destinations, and only on host-mediated outbound surfaces. Guest HTTPS CONNECT egress is not a request-time substitution path.
5. **SDK-owned lifecycle:** Python/TypeScript/Rust SDKs can create, exec, inspect, snapshot, and stop sandboxes with cleanup bound to the parent process.
6. **Measured cold-start story:** published latency numbers are produced by a reproducible harness and split by fresh boot, guest-agent-ready, snapshot restore, and warm-pool claim.
7. **Extensible filesystem backends:** local, encrypted, object-store-backed, and in-memory filesystem substrates share one contract and state which backends are mountable versus API-only.

## Runtime Ownership

`mvm` owns the local primitives:

- OCI distribution, verification, unpacking, whiteout handling, rootfs materialization, template registration, and launch.
- Local egress enforcement surfaces: L3 rules, DNS pinning resolver, L7 proxy, SNI/Host policy, and audit emission.
- Host-side secret placeholder registry, policy-bound substitution, grant revocation, and redaction at all boundaries.
- SDK process-owned lifecycle over local `mvm` primitives.
- Performance harnesses and budgets for local backends.
- Storage and filesystem backend contracts.

`mvmd` owns fleet/product policy:

- Tenant image policy, registry allow rules, cache isolation, route exposure, and API admission.
- Fleet egress policy, tenant DNS policy, quota, and audit aggregation.
- Tenant secret providers, per-tenant grant policy, and cross-node revocation.
- Warm pools, placement, wake-on-demand, public API, generated SDKs, and web console claims.

If a primitive is missing in `mvm`, `mvmd` must not implement a parallel runtime path. The primitive is added to `mvm` first, then consumed by `mvmd`.

## Claim Gates

### OCI ingest

Public claim allowed only when:

- `mvmctl image pull <ref>` resolves an immutable digest and records requested ref plus launched digest.
- Production profile rejects mutable tags unless an explicit local/dev policy allows them.
- Layer unpacking handles whiteouts, symlinks, hardlinks, ownership, permissions, entrypoint, env, workdir, and exposed ports.
- Rootfs artifacts are tenant/cache scoped correctly.
- Tests cover digest pinning, mutable-tag rejection, private registry auth, whiteout behavior, and secret/cache non-leakage.

### Programmable network policy

Public claim allowed only when:

- `deny` is a first-class default policy.
- DNS answers for allowed names are pinned for the workload lifetime.
- HTTP Host and HTTPS SNI are verified against policy.
- Direct metadata endpoint access is blocked by default.
- Policy decisions emit audit records for allow, deny, DNS pin, DNS reject, and proxy failure.
- Integration tests prove DNS rebinding, raw-IP bypass, wrong-SNI, and metadata access are blocked.

### Secret non-leakage

Public claim allowed only when:

- Default SDK/CLI secret flow gives the guest only an opaque placeholder or a scoped, non-reusable grant.
- Real secret values never appear in guest env, guest files, guest argv, logs, audit detail, plan JSON, cache keys, route labels, error messages, or panic output.
- Substitution is bound to destination policy and transport identity.
- Grant revocation runs on stop, crash, timeout, and parent-process death.
- Tests cover hostile guest exfiltration attempts, destination mismatch, redirect chains, wrong SNI, plaintext HTTP, audit redaction, and crash cleanup.

### SDK lifecycle

Public claim allowed only when:

- Python, TypeScript, and Rust SDKs expose the same core lifecycle surface.
- SDK-created sandboxes are owned by the SDK process unless explicitly detached.
- Parent death triggers sandbox cleanup or documented lease expiry.
- The lifecycle surface works without importing or executing untrusted user code during static compilation.
- Tests cover create, exec, filesystem read/write/list, logs, snapshot, stop, parent cleanup, and error redaction.

### Cold-start

Public claim allowed only when:

- The harness records host, backend, kernel/rootfs digest, CPU model, memory, vCPU count, storage mode, and readiness signal.
- Numbers are published as p50/p95/p99/max and identify the readiness boundary.
- Fresh boot, guest-agent-ready boot, snapshot restore, and warm-pool claim are reported separately.
- CI enforces regression budgets for representative artifacts.

### Filesystem backends

Public claim allowed only when:

- The `VolumeBackend`/filesystem contract has conformance tests reused by every backend.
- Docs distinguish mountable backends from API-only backends.
- Encrypted backends encrypt content and names where promised.
- Object-store backends define consistency, rename, partial-write, and health semantics.
- Tests cover path traversal, symlink escape, concurrent writes, large files, deletion, rename, and audit.

## Consequences

### Positive

- The project can make stronger developer-facing claims without weakening the existing operator/security story.
- `mvmd` can expose product capabilities without forking runtime behavior.
- Docs gain a safe vocabulary for features that are planned but not yet shipped.

### Negative

- OCI ingest and secret substitution increase attack surface and test burden.
- The SDK lifecycle surface forces `mvm` to become more than a CLI.
- Secret substitution requires a trusted egress path; it cannot be bolted onto unrestricted networking.

## Non-goals

- Docker or a Docker daemon as the production runtime.
- Kubernetes or Compose compatibility.
- Claiming sub-100ms cold boot before measured data supports it.
- Claiming "secrets cannot leak" for legacy env/file injection flows.
- Bypassing signed plans, audit, or verified artifact checks for developer ergonomics.

## Implementation Plan

Tracked in [`specs/plans/74-claim-safe-sandbox-parity.md`](../plans/74-claim-safe-sandbox-parity.md).


## Consolidated from ADR-058 — Claim 10: bytes leaving the trust boundary are encrypted, attested, and audited

**Status:** Proposed
**Sprint:** 56 (W2, W3, W4)
**Plan:** [Plan 101](../plans/101-in-guest-volume-encryption-and-gateway-audit.md)

## Context

ADR-002 §"Out of scope" today carves out *a malicious host* — "mvmctl trusts the host with the hypervisor and private build keys." That carve-out is correct as stated, but the current implementation is too permissive: it grants the host more capability than the threat model requires.

Specifically:

- **RW tenant volumes are plaintext.** `mvmctl volume create` produces an AES-256-GCM archive (`crates/mvm-security/src/secret_store.rs`) that protects the volume's host-side file at rest *when locked*. But once a volume is opened and mounted into a guest, the backing storage on the host is decrypted ext4 / virtiofs. A host process with read access to the volume directory can read every byte the workload is writing or reading.
- **Gateway flows are not in the audit chain.** `crates/mvm-core/src/policy/audit.rs` (`LocalAuditKind` enum) has plan/admission events and Stage 0 boot events, but no flow events. gvproxy (macOS) and passt (Linux) handle all guest network I/O at the host level; neither emits attested flow metadata. A compromised host can route, log, or exfil any traffic with no record landing in the chain.
- **App-deps volumes have integrity, not confidentiality.** dm-verity-sealed deps volumes (claim 9, [Plan 73](../plans/73-app-deps-audit-pipeline.md) / ADR-041 §"Consolidated from ADR-047") prove "what's on disk hasn't been tampered with." They don't hide what's on disk. Different property.

Result: a host whose userland (not kernel — that's a different threat tier) has been compromised can read tenant data and silently exfil network traffic, and nothing in the audit chain notices.

## Threat model

This ADR narrows ADR-002's "out of scope: a malicious host" carve-out. The new posture:

- **Still trusted:** the hypervisor binary, the host kernel, the host signer's private key. Compromise of any of these defeats mvmctl's isolation by definition; out of scope here as in ADR-002.
- **No longer trusted (this ADR):** the host userland's *passive* read access. A user-space process on the host should not be able to (a) read tenant volume bytes at rest, or (b) exfil tenant network traffic, *without that fact being attested in the audit chain.*

Adversary capability assumed: read access to host filesystem and host network namespace. Not assumed: kernel module load, hypervisor hijack, signer key exfiltration (those are ADR-002's still-out-of-scope tier).

**Adjacent surface — not addressed here, named so readers don't expect it:** inbound TLS termination is mvmd's concern, not mvm's. mvmd manages tenant certs at its multi-tenant edge and is the natural place to terminate inbound TLS. Workload-level TLS (the user's own HTTPS listener inside the microVM) stays encrypted end-to-end. This ADR's threat model is *outbound exfil from the workload*, not *inbound eavesdrop or auth* — different threat model, different ADR if/when it gets one.


## Decision

Add claim 10 to ADR-002's CI-enforced security claims, in three legs.

### Leg 1 — Volume confidentiality

Every RW tenant volume is dm-crypt / LUKS-2 inside the guest. The host's view of the volume backing store is ciphertext at all times, even while the workload is running.

Key delivery: the signed `ExecutionPlan` carries a `Vec<EncryptedVolumeKey>` — per-volume symmetric keys, each wrapped under the tenant's pubkey. The mvm-supervisor never sees plaintext key material; it materializes the wrapped keys to an in-VM ramfs (never to host disk) and hands the ramfs path to the guest initramfs via kernel cmdline. The guest unwraps inside the VM using the tenant private key, escrowed by mvmd (cross-repo dep).

### Leg 2 — Network traffic audit

gvproxy (macOS) and passt (Linux) are wrapped with a control-socket listener that streams per-flow events to `mvm-supervisor`. Events: `flow_opened`, `flow_closed`, aggregated `flow_bytes` (every N seconds or on close), and `flow_policy_decision` (every deny / allow). All events land in the chained `~/.mvm/audit/<tenant>.jsonl`. The existing `mvm_supervisor::verify_audit_chain` mechanism extends to flow events with no schema break beyond the new enum variants.

No L7 inspection. No TLS termination. Only connection metadata and byte counts.

#### W6.A amendment (2026-05-26 — [Plan 102](../plans/102-gateway-audit-substrate-impl.md) / [Plan 103](../plans/103-w6a-implementation-tracker.md))

**No-bypass invariant.** TSI mode is removed entirely
(`NetworkingPreference::Tsi` deleted; `MVM_NETWORKING=tsi` rejected
with a clear warning + per-OS fallback). Every libkrun-backed VM
boots through `passt` (Linux) or `gvproxy` (macOS); every Vz-backed
VM boots through `gvproxy` via `VZFileHandleNetworkDeviceAttachment`.
No env-var, JSON-config field, or fallback lets a workload skip the
auditable bridge. `mvmctl doctor` flips the gateway probe from
`ok: true` (with a TSI escape note) to `ok: false` when the
gateway binary is missing — there is no escape hatch left.

**Coverage vs. capture.** W6.A commits to **coverage** — every byte
that crosses the trust boundary traverses an auditable bridge.
**Capture** (per-byte content into the chain) is opt-in via a future
`network_audit.mode = full_pcap` field, not the default. Aggregated
`FlowBytes` counters land in W8; full pcap is a forensic-only mode.

**Mediable substrate.** The bridge exposes a `FlowPolicy` hook
([`mvm_supervisor::gateway_bridge::FlowPolicy`]). W6.A ships the
`AllowAll` default; Plan 74's enforcer plugs in later for L4
decisions, and a future SNI inspector + Plan 34 Phase 2 (TLS MITM
in `L7EgressProxy` with workload-CA trust) plug in for hostname /
URL allowlist semantics — all without re-architecting the
bridge. The forward-compat seam is `FlowDecisionCtx`'s optional
`sni_hostname` / `url_path` fields.

**Cross-process chain integrity.** `FileAuditSigner::sign_and_emit`
now takes an `flock(LOCK_EX)` on the tenant chain file across the
read-cursor / sign / append critical section. Without this, two
`mvm-libkrun-supervisor` processes for the same tenant could both
restore the same `prev_hash` and break `verify_audit_chain`. The
flock is the precursor that made claim-10 per-VM emission safe.

**Scope (W6 impl):** gateway egress only — **north-south** through
passt/gvproxy. East-west microVM ↔ microVM lateral flows traverse
the tenant bridge below the gateway and are out of W6 scope;
deferred to W11 as a distinct capture plane. The same substrate
covers all three backends (libkrun+passt, libkrun+gvproxy,
Vz+gvproxy) through a single per-VM `signer_task`.

**Cross-tenant isolation invariant.** The W6.A substrate
introduces no cross-tenant coupling: per-VM gateway, per-tenant
chain file (flock-serialized within tenant only), per-VM mpsc /
broadcast (no shared queues), per-VM subscriber socket. The mvmd
cross-repo `mvmd-network-manager` plan (`tinylabscom/mvmd/specs/plans/50-network-manager.md`)
covers cross-tenant network management (per-tenant gateway pool,
egress quotas, tenant-level audit rollup, cross-tenant traffic
isolation) — out of mvm's scope by design.

### Leg 3 — Crypto state attestability

Every key fingerprint, key rotation, and key-unwrap-failure event lands in the audit chain. `mvmctl audit verify` covers volume-key events alongside flow events alongside the existing plan events. A new CI lane `claim-10-audit-tamper` exercises tamper detection: emit a known sequence, byte-flip one entry, assert `mvmctl audit verify` exits non-zero.

## Out of scope (named, like ADR-002)

- **Host filesystem encryption (FDE).** That's the user's concern — full-disk encryption protects host backups; this ADR protects per-volume at-rest exposure during active workload runs.
- **Per-byte traffic audit.** Aggregated `flow_bytes` only ([Plan 101](../plans/101-in-guest-volume-encryption-and-gateway-audit.md) W8); coverage of every byte through the bridge is structural (W6.A amendment above), capture is opt-in future mode ([Plan 203](../plans/203-forensic-network-transcript-capture.md)).
- **Audit metadata at rest.** The chain itself (5-tuples, byte counts, key fingerprints) is plaintext on host disk under `~/.mvm/audit/<tenant>.jsonl`. Tenant *data* is encrypted; tenant *behavior metadata* is not. Future claim 10.1 candidate; not in this sprint.

### Added by W6.A amendment

- **East-west microVM ↔ microVM lateral flows.** Different capture mechanism (`tc mirred` / eBPF / per-TAP libpcap), different policy surface. W11 candidate; named here so readers don't expect it from W6.
- **L7 URL inspection (path-level allowlist).** Composes via `L7EgressProxy` Phase 2 (TLS MITM with workload-trusted host CA per [ADR-004](004-hypervisor-egress-policy.md)); substrate exists, not yet finalized. Separate plan from W6.
- **DNS-over-HTTPS bypass mitigation.** Workloads using DoH (e.g., 1.1.1.1:443) hide queries inside encrypted HTTPS to a public resolver, evading admission-time DNS pinning. Separate Plan 74 follow-up: mandatory-deny well-known DoH endpoints.
- **SNI hostname allowlist.** Cleartext SNI extraction from TLS ClientHello → `FlowPolicy::evaluate` with `sni_hostname` populated. Substrate seam exists in W6.A's `FlowDecisionCtx`; inspector implementation is a separate plan.
- **Side-channel information leakage via flow timing.** Inherent to any flow audit; accepted.
- **Multi-user shared host with same UID.** Same-UID local attacker can read the gateway subscriber socket. Mode 0700 mitigates cross-UID; cross-UID-same-user is documented as accepted (they can already read the chain file directly).
- **Cross-tenant network management.** Per-tenant gateway pool, egress quotas, tenant-level rollup, cross-tenant traffic isolation — owned by mvmd via [`mvmd-network-manager`](https://github.com/tinylabscom/mvmd/blob/main/specs/plans/50-network-manager.md).

## Consequences

- `ExecutionPlan` grows: `volume_keys: Vec<EncryptedVolumeKey>` and `network_audit: NetworkAuditConfig` fields. PROTOCOL_VERSION bump in `crates/mvm-core/src/protocol/protocol.rs`.
- mvmd cross-repo work: tenant root key, key derivation, rotation policy. Tracked as Plan 101 W5.
- `mvmctl doctor` gains a `claim_10` row reporting LUKS-in-guest active + gateway audit emitting + audit chain valid.
- New CI lane: `claim-10-audit-tamper` byte-flip test gates every PR.
- Performance: dm-crypt overhead measurable on hot-path volume reads. Plan 101 W14 validates within threshold; backs out if pathological.

## References

- [ADR-002](002-microvm-security-posture.md) — microVM security posture (claim list extends to 10)
- ADR-041 (this document) — claim 8, signed ExecutionPlans (volume keys ride this signing path)
- ADR-041 §"Consolidated from ADR-047" — claim 9, app-deps audit (analogous structure for the audit chain extension)
- [ADR-004](004-hypervisor-egress-policy.md) — gvproxy / passt gateway choice
- [Plan 101](../plans/101-in-guest-volume-encryption-and-gateway-audit.md) — implementation rollout


## Consolidated from ADR-079 — App-builder product surface: adopt the ergonomics, reject the isolation model

**Status:** Accepted 2026-06-10. Implemented by
[`specs/plans/181-app-builder-product-surface.md`](../plans/181-app-builder-product-surface.md).
**Extends** [ADR-002](002-microvm-security-posture.md) (consolidated from ADR-070) (the
mvm-primitive ↔ mvmd-transport boundary), and builds on
[ADR-004](004-hypervisor-egress-policy.md) / Plan 179 (the first-party gateway
seam preview ingress publishes through) and the network-provider seam in
ADR-004. **Cross-refs:** ADR-002 (security posture — claims 1/2/10 are the lines
this ADR refuses to cross), ADR-041 (signed/audited execution plans — where
published ports get signed), Plan 33 (hosted transport — mvmd owns it),
Plan 170 (the same primitive↔product split applied to density), Plan 118 /
Plan 123 C4 / Plan 175 (warm pool + warm-start, the wake-on-access machinery),
Plan 169 / Plan 172 (agent-RPC + streamed exec, the task/files transport).
**Input:** a comparison against a sibling self-hosted AI-app-builder backend.

## Context

A sibling self-hosted AI-app-builder backend delivers a DX mvm does not yet
match: a single request creates an isolated environment, runs a coding agent in
it, and returns a **live, shareable preview URL**; instances `stop` to free RAM
and **wake on access**; a tasks API streams agent progress and a files API edits
the workspace; one command installs the whole stack and prints runnable next
steps; uninstall is graduated and workspace-preserving by default.

It buys that DX cheaply by discarding exactly the properties mvm exists to
provide. Its isolation is Docker containers; its control plane and edge router
run with the **Docker daemon socket mounted** (root-equivalent on the host) and
**symmetric host-path bind mounts** so sandboxes reach files by host path; its
API auth is **off by default** and its containers carry **no resource caps by
default**. Each of those is a direct contradiction of an mvm claim — claim 1
(no host-fs access beyond explicit shares), claim 2 (no guest elevation to
uid 0), claim 10 (no untrusted egress without policy), and the jailer/cgroup
posture.

mvm has the inverse profile: a much stronger engine (microVM isolation,
signed/audited execution plans, default-deny egress, secret substitution —
claims 1–15) behind a CLI-first surface that does not deliver the product loop.
The question this ADR settles is **which half of the sibling's design we take.**

The ergonomics do not depend on the isolation. The preview loop rides the
gateway seam we already own (ADR-004); wake-on-access rides warm-start
(Plan 123 C4 / Plan 175); the task/files surface rides agent-RPC + streamed
exec (Plan 169 / Plan 172); the lifecycle verbs and install/uninstall are CLI
plumbing on the `vm`/`env` groups. None of it requires relaxing a claim. The
weak isolation is not load-bearing for the DX — it is just the cheapest engine
the sibling had to hand.

## Decision

1. **Adopt the product-surface ergonomics; reject the isolation model.** mvm
   grows the create→agent→preview-URL loop, the instance-vs-workspace lifecycle
   split, a streamable task/files protocol, and one-command install/uninstall.
   mvm does **not** adopt container isolation, a daemon-socket-mounted control
   plane, host-path mounts into a workload, auth-off/caps-off defaults, or
   baked-in coding agents. These rejections are normative non-goals, recorded so
   they are not relitigated when the DX gap is felt again.

2. **Split every capability into an mvm-side primitive and an mvmd-side product
   leg, per ADR-002 (consolidated from ADR-070).** mvm ships the bridgeable primitives — a signed
   published-ports model, a per-port routing label at the gateway seam, a
   wake-on-access `VmBackend` hook, the task/files vsock protocol with an
   SSE-ready event shape, and the idle-TTL/keepalive contract. mvm does **not**
   grow a multi-tenant HTTP listener or tenant auth; that transport + auth +
   wildcard-DNS/TLS surface is mvmd's (Plan 33 / ADR-002 §"Consolidated from ADR-070" §5). This is the same
   boundary Plan 170 drew for density.

3. **One exception: a local, single-machine dev ingress lives in mvm.** So
   `mvmctl up`/`run` can hand a contributor a working
   `http://s-<id>-<port>.preview.localhost` URL on one box, mvm carries a tiny
   first-party reverse proxy bound to `localhost` only — no auth, no TLS, no
   wildcard DNS. This occupies the same single-host, no-tenant scope `mvmctl
   dev` already does, so it crosses no new trust boundary; `*.localhost`
   resolves to loopback in browsers with no DNS setup.

4. **Preview routing is L4 publication, not an HTTP proxy, and only published
   ports are routable.** The gateway exposes explicitly published guest ports
   under a stable id-derived key (`s-<vm>-<port>`); it does not parse HTTP. The
   published set is signed into the `ExecutionPlan` (audited, not ambient), so
   default-deny egress (claim 10) and the gateway mediation seam are unchanged —
   exposing a preview port is an admitted, recorded act, not a hole.

5. **The substrate stays agent-agnostic.** The task protocol carries an opaque
   runner/entrypoint reference; no coding-agent binary is baked into any rootfs.
   Agent tooling is a workload/SDK concern.

## Consequences

- mvm gains the product loop that makes app-builder backends feel magical, on
  top of an engine the sibling cannot match (strong enough to run *untrusted*
  code) — a combination neither the sibling (too weak to trust) nor mvm's
  current CLI-first surface delivers.
- mvmd gets a clean set of primitives to wrap: published-ports + routing label +
  wake hook → fleet preview URLs; the task/files vsock protocol + SSE shape →
  its HTTP API; the keepalive/idle-TTL contract → its density loop (already
  Plan 170 WS-D).
- No claim regresses. Preview ports are signed and audited; the wake hook reuses
  warm-start; the local ingress is loopback-only. `xtask check-claim-catalog`
  stays green.
- A small, owned local reverse proxy enters the tree (reusing the
  rvproxy/hyper surface), and a workspace-data lifecycle becomes a named concept
  in `mvm_core::config` distinct from instance lifecycle.

### Follow-ups

- [ ] Plan 181 WS-A–WS-D implementation (preview ingress, lifecycle verbs,
  task/files protocol, install DX).
- [ ] Decide L4-only-now vs. a fuller local HTTP router (Plan 181 WS-A open
  decision); recommendation is L4 + loopback proxy first.
- [ ] If/when a hosted (non-localhost) preview surface is wanted, it is an mvmd
  effort (Plan 33), not mvm — same disposition as ADR-002 §"Consolidated from ADR-070"'s hosted console.

## Alternatives considered

- **Take the sibling's stack wholesale (containers + socket + host mounts).**
  Rejected: it discards claims 1/2/10 and mvm's reason to exist. The DX does not
  require it.
- **Build the full multi-tenant preview/ingress + auth in mvm.** Rejected:
  violates the ADR-002 (consolidated from ADR-070) / Plan 33 boundary that reserves transport + tenant auth
  for mvmd. mvm ships primitives + a single-machine dev ingress only.
- **Ambient (unsigned) port exposure for convenience.** Rejected: it would make
  egress reachability an unrecorded side effect, weakening claim 10. Published
  ports are signed into the plan and audited.
- **Bake specific coding-agent binaries into the base image like the sibling.**
  Rejected: couples the substrate to specific agent tooling; the runner stays
  opaque.
- **Do nothing (keep the CLI-first surface).** Rejected: the product loop is the
  difference between an engine and a product, and it is achievable with zero
  claim cost.


## Consolidated from ADR-103 — Plan-bound agent verb capabilities

- Status: Proposed
- Note: Landed in two stages — the signed-type + guest-enforcement core (Plan 215 Tasks 1–5a) first; the out-of-band host-signer-key provisioning + wire delivery (5b–5d) as a follow-on, since the key separation becomes an active boundary only under the ADR-059 decomposition.
- Date: 2026-06-30
- Owner: MVM Project
- Related: ADR-002 (microVM security posture — claim 4 `do_exec`, claim 15 sealed interactivity), ADR-041 (signed audited execution plans — claim 8), ADR-067 (secret substitution — time/destination-bound signed credentials), ADR-059 / ADR-059 (host services broker — claim 12 binding-gated dispatch), ADR-059 (resident daemon trust gradient)
- Sequenced by: [Plan 215](../plans/215-plan-bound-agent-verb-capabilities.md)

## Context

The guest agent's control channel (vsock port 5252, `GUEST_AGENT_PORT`) carries every
host→guest control verb — ~75 `GuestRequest` variants multiplexed over one
`AuthenticatedFrame`-signed connection (`crates/mvm-guest/src/vsock.rs`). The agent is
the server; the host is the client.

Today the verb surface is gated exactly once, coarsely, by *class × profile*:

- Each variant classifies as `ProdSafe`, `DevOnly`, or `BuilderOnly`
  (`GuestRequest::class`, `crates/mvm-guest/src/vsock.rs:819`; a compile-fail test at
  `:5418` forces every new variant to be classified).
- Before dispatch the agent runs `req.allowed_in(active_profile)`
  (`crates/mvm-guest/src/bin/mvm-guest-agent.rs:2055`, logic at `vsock.rs:884`) and
  returns `GuestResponse::UnsupportedInProfile` for anything the boot profile
  (`SealedProd` / `Dev` / `Builder`) doesn't permit. A sealed-prod agent already
  refuses `Exec` / `FsWrite` / `ConsoleOpen`.

This class gate is a hard *outer* bound, but it is not per-workload. Every `ProdSafe`
verb is available to every sealed-prod workload — `RunEntrypoint`, `Ping`,
`MountVolume`, `UpdateIdleTimeout`, the status/probe family — regardless of whether a
given workload's admitted plan needs them. There is no way for a plan to say "this
workload receives `RunEntrypoint` and `Ping` and *nothing else*."

Two forces make that gap worth closing:

1. **Least privilege per workload.** The signed `ExecutionPlan` is the authority for
   what a workload may do (claim 8). It already binds host-side *services* (claim 12,
   `ExecutionPlan.services` → broker dispatch gate). The agent verb surface is the
   symmetric guest-side capability and is currently unbound.

2. **The host is decomposing.** Under the ADR-059 trust gradient the plan is signed by
   the host-signer moat at admission, but the component holding the 5252 client may be
   a less-trusted control process. A guest-side, plan-bound verb check is only
   meaningful when the *signing authority is separated from the calling authority* — so
   the grant must be bound to the plan's signature, not merely asserted by whoever is
   calling.

## Decision

Add an optional per-workload **verb grant** to the signed `ExecutionPlan`. The guest
agent, at handshake, receives a host-signer-signed capability token derived from that
grant, pins it for the session, and intersects every subsequent request against it —
*after* the existing class/profile gate. The grant is strictly **subtractive**: it can
only narrow what the profile already allows; it can never widen a `SealedProd` agent to
accept a `DevOnly` verb.

Enforcement is **guest-side** (the agent is the load-bearing last line, and it already
owns the `allowed_in` seam). This ADR does not require, but explicitly leaves room for,
a complementary host-side check at the daemon (closing the `services_bindings: vec![]`
gap at `crates/mvm-backend/src/host_agent_spawn.rs:208`) as a cheap outer layer.

### Why a handshake-delivered token, not a boot-time file

The grant must reach the agent *per claim*, not per boot. Warm pools (Plan 118
auto-claim, Plan 175 warm-start, Plan 211 sub-second `machine run`) pre-boot an agent
before its workload's plan exists, then claim it later. A boot-time artifact
(`/etc/mvm/agent-caps.json` read once at PID 1) is fixed at the wrong moment — it cannot
attenuate a VM that is claimed for a plan minted after boot. Each claim redoes
`ProtocolHello`, so the handshake is the one delivery point that re-pins per workload.

This mirrors the shape ADR-067 / claim 13 already ship for secrets: a **time-bound,
context-bound, signed credential** rather than a static blob.

### The grant

A new optional field on `ExecutionPlan` (additive, `#[serde(default)]` — no schema-bump
ceremony; `SCHEMA_VERSION` stays as-is):

```rust
/// Per-workload agent verb allow-list. `None`/absent → class-gate-only
/// (current behavior, preserves dev flows). `Some(set)` → the agent
/// accepts a control verb only if it passes the class gate AND its
/// `kind_name()` is in `set` (or is baseline). Strictly subtractive.
pub agent_verbs: Option<Vec<VerbId>>,
```

`VerbId` is the stable `GuestRequest::kind_name()` string (`vsock.rs:555`) — the kebab-case identifier used in `UnsupportedInProfile` responses and validated at parse time by `kind_name_strings_are_kebab_case`. Wire-stable by construction.

At admission the supervisor mints a session token and signs it with the host-signer key:

```rust
#[serde(deny_unknown_fields)]
pub struct VerbGrant {
    pub session_id: String,   // binds to THIS 5252 session
    pub plan_nonce: Nonce,    // binds to the admitted plan (claim 8 replay ledger)
    pub not_after: DateTime<Utc>, // ≤ plan.valid_until
    pub verbs: Vec<VerbId>,
    // Ed25519 signature by the host-signer authority, over the JCS bytes
    // of the fields above. NOT the per-session frame key.
}
```

### Baseline verbs (always allowed, need not be listed)

The handshake/liveness verbs are implicitly granted, mirroring claim 12's implicit
`host.audit.v1`: `ProtocolHello` (it *is* the handshake, and runs before any grant is
pinned), `Ping`, and `ReadinessStatus`. A grant listing only workload verbs never has to
enumerate these, and an empty `verbs: []` still yields a live, answerable agent.

### Enforcement order

```
read_authenticated_frame            (integrity + replay — unchanged)
  → allowed_in(active_profile)      (class/profile gate — unchanged, HARD outer bound)
    → grant.permits(verb)           (NEW: baseline OR in pinned set; skipped if no grant)
      → dispatch
```

The grant check is skipped entirely when the plan carries no `agent_verbs`, so opting
out is the default and dev/interactive flows are unaffected.

### Trust: the key separation is the whole point

The guest already obtains a host `VerifyingKey` + `session_id` at `ProtocolHello`
(`vsock.rs:2290`). The `VerbGrant` signature MUST chain to the **plan-admission
(host-signer) authority**, which under ADR-059 is distinct from the 5252 caller. If the
grant were signed by (or forgeable by) the caller, a compromised caller would simply mint
the verb it wants and the check would buy nothing. The Plan must therefore provision the
guest with the host-signer verifying key (or a delegation chain to it) and verify the
grant against it — separately from the per-session frame-signing key. This invariant is
load-bearing; a Plan that collapses the two keys silently defeats the ADR.

**Delivered status (Plan 219 — honest limitation).** The follow-on delivers the grant to
the guest over the kernel cmdline (`mvm.verb_grant=`), and the host-signer public key
rides *in the same envelope* as the grant. This means the delivered mechanism does **not**
yet provide cryptographic key separation: the Ed25519 signature is an integrity check over
a launcher-provisioned blob, and its trust root is entirely the kernel-cmdline provenance
(only the trusted launcher sets the cmdline `/init` decodes into `/run/mvm/`). This is
sound against the in-scope adversaries — an untrusted workload and a separate 5252 caller
cannot forge the cmdline — but it is *trusted-channel provisioning*, not verification
against an independent anchor. The obstacle is structural: the host-signer key is per-host
and minted at admission, so no independent pre-provisioned anchor exists to check against.
Achieving real key separation requires provisioning a trust anchor the grant-issuer cannot
swap (e.g. a signing key baked into the verity-sealed image at build time) — tracked as a
follow-up; until then, this ADR's "key separation" is an aspiration the delivered code does
not meet, and the claim must not be promoted to the ADR-002 ledger on the strength of the
cmdline mechanism alone.

### Denials are audited (claim-12 parity)

A grant refusal returns a new wire-stable `GuestResponse::VerbNotAuthorized { verb }`
(sibling to `UnsupportedInProfile`; must be registered in the `response_contract()` /
`ResponseVariant` machinery at `vsock.rs:1108`). On receiving it the host caller emits an
`agent.verb_denied` entry to the chain-signed audit log, so refusals are observable and
tamper-evident via `verify_audit_chain` — the same posture claim 12 gives service-call
denials.

## Alternatives considered

- **Boot-time signed grant file.** Rejected: cannot attenuate per-claim under warm-pool
  reuse (see "Why a handshake-delivered token").
- **Host-side only (close the `services_bindings: vec![]` gap, no guest change).** A real
  and complementary gap, but it is self-policing in the single-trusted-host case (the
  caller checks itself) and does not defend the guest as the last line. Kept explicitly
  in scope as an *optional outer layer*, not the primary mechanism.
- **Widen the class taxonomy instead (finer `RequestClass`).** Rejected: classes are a
  static property of a verb, not a per-workload one. No number of classes expresses "this
  particular workload needs this particular subset."
- **Encrypt the channel.** Out of scope and unrelated: vsock has one host endpoint and
  one guest endpoint inside the TCB; ADR-002 puts a malicious host out of scope. The need
  here is attenuation and authenticity, not confidentiality.

## Threat model

- **In scope:** a less-trusted host-side 5252 caller (ADR-059 gradient) invoking a
  `ProdSafe` verb the workload's admitted plan did not authorize; replay of a broader
  grant captured from an earlier plan (defended by `plan_nonce` + `not_after` riding the
  claim-8 validity/replay machinery); a grant forged by the caller (defended by the
  host-signer key separation).
- **Out of scope (unchanged from ADR-002):** a malicious host holding the hypervisor and
  the host-signer private key; confidentiality of vsock bytes; a guest that is already
  compromised attempting verbs — that is the class gate's and claim 4/15's job, which
  this ADR strengthens but does not replace.

## Consequences

- Strengthens the claim 4 / claim 15 family (interactive/exec surface minimization) with
  a per-workload dimension. Whether this becomes a numbered or `Preview` claim in the
  ADR-002 ledger is a maintainer decision and is deliberately **not** asserted here
  (cf. claim 16's pending promotion).
- New signed field on `ExecutionPlan`; synthesis populates `agent_verbs` from workload
  requirements, admission mints + signs the `VerbGrant`.
- New wire-stable `GuestResponse::VerbNotAuthorized` + `agent.verb_denied` audit verb.
- Zero behavior change for plans that omit `agent_verbs` — dev, interactive, and existing
  prod flows are unaffected until a plan opts in.

## Testing

- `agent_verb_grant_denies_unlisted_verb` — sealed-prod agent with a grant refuses a
  `ProdSafe` verb outside the set; returns `VerbNotAuthorized`.
- `agent_verb_grant_is_subtractive` — a grant listing a `DevOnly` verb does NOT make a
  `SealedProd` agent accept it (class gate still wins).
- `agent_verb_grant_baseline_always_allowed` — `ProtocolHello` / `Ping` / `ReadinessStatus`
  answer under an empty grant.
- `agent_verb_grant_forged_by_non_signer_rejected` — a grant not signed by the host-signer
  authority is refused at handshake.
- `agent_verb_grant_replay_across_session_rejected` — a grant bound to session A / nonce A
  is refused on session B.
- `agent_verb_grant_expired_rejected` — `not_after` in the past → refused.
- `no_grant_is_class_gate_only` — plan without `agent_verbs` behaves exactly as today.
- Audit: `audit_chain_contains_verb_denied_entries` — a refusal appears in the chain and
  survives `verify_audit_chain`; a tamper breaks it.

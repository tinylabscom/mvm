# Plan 129 Stage 1 — SDK-free secret authoring (`mvmctl run --secret`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a workload bind a secret for egress substitution with no SDK — `mvmctl run/up --secret NAME:HOST` adds the binding to the synthesized `ExecutionPlan` and asserts the claim-12 destination, reusing the already-built host substitution pipeline.

**Architecture:** `--secret NAME:HOST` parses to a CLI value, merges into `lowered_plan_secrets.secrets` as a `mvm_core::plan::SecretBinding { name: NAME, source: Keystore { address: NAME } }` (mirroring `lower_env_map`), and is validated against the host binding store (`FileBindingStore`) so a run can't reference an unbound secret or assert a host outside the stored `allowed_hosts`. Value + auth-type + allowed-hosts come from `mvmctl secret set` (already built); `--secret` is a pure reference + claim-12 assertion. No new substitution machinery — admission's `assemble_registry` already mints + injects the placeholder.

**Tech Stack:** Rust, clap, `mvm_core::plan`, `mvm_hostd::keyholder` (`FileBindingStore`/`SecretBindingMeta`), nextest.

**Sequencing:** Branch off latest `origin/main` after #721 lands (the inject leg). This plan is independent of the transparent-terminator work (Stage 1b/2) and is testable on its own against the existing in-guest forward-proxy path.

**Scope note — what this plan is NOT:** It does not build the transparent gateway terminator or the name-constrained CA (Stages 1b/2 in `specs/notes/plan-129-egress-substitution-sdk-free-design.md`). Those have no existing code (Plan 141 gives packet observe/drop, not TCP termination; no `rcgen` name-constraint path exists) and require a spike first — they are separate follow-on plans. This plan delivers SDK-free *authoring* + validates the full substitution loop over `http` with a generic client through the existing path.

---

### Task 1: `CliSecret` parse helper

**Files:**
- Create: `crates/mvm-cli/src/commands/vm/cli_secret.rs`
- Modify: `crates/mvm-cli/src/commands/vm/mod.rs` (add `mod cli_secret;`)
- Test: in-file `#[cfg(test)]` in `cli_secret.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_and_host() {
        let s = CliSecret::parse("openai:api.openai.com").unwrap();
        assert_eq!(s.name, "openai");
        assert_eq!(s.host, "api.openai.com");
    }

    #[test]
    fn rejects_missing_colon() {
        assert!(CliSecret::parse("openai").is_err());
    }

    #[test]
    fn rejects_empty_name_or_host() {
        assert!(CliSecret::parse(":api.openai.com").is_err());
        assert!(CliSecret::parse("openai:").is_err());
    }

    #[test]
    fn rejects_extra_segments() {
        // Stage 1 syntax is exactly NAME:HOST. Reject `NAME:HOST:extra`
        // so we don't silently ignore an auth-type/header the user meant.
        assert!(CliSecret::parse("openai:api.openai.com:bearer").is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli cli_secret`
Expected: FAIL — `CliSecret` not found.

- [ ] **Step 3: Write minimal implementation**

```rust
//! Plan 129 Stage 1 — the `--secret NAME:HOST` CLI authoring value.
//!
//! A run-time reference to a secret established by `mvmctl secret set`. The
//! `:HOST` is a claim-12 assertion checked against the stored binding, not a
//! place to (re)declare policy — `secret set` owns auth-type + allowed-hosts.

/// One `--secret NAME:HOST` occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct CliSecret {
    /// Keystore secret name (also the guest-facing env var). Resolves to
    /// `SecretSource::Keystore { address: name }`.
    pub name: String,
    /// Destination the run asserts this secret may reach. Verified against
    /// the stored `SecretBindingMeta.allowed_hosts` at merge time.
    pub host: String,
}

impl CliSecret {
    pub(in crate::commands) fn parse(s: &str) -> Result<Self, String> {
        let mut parts = s.splitn(2, ':');
        let name = parts.next().unwrap_or("");
        let host = parts.next().unwrap_or("");
        if name.is_empty() || host.is_empty() || host.contains(':') {
            return Err(format!(
                "--secret expects NAME:HOST (e.g. openai:api.openai.com), got {s:?}"
            ));
        }
        Ok(Self {
            name: name.to_string(),
            host: host.to_string(),
        })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-cli cli_secret`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/cli_secret.rs crates/mvm-cli/src/commands/vm/mod.rs
git commit -m "feat(cli): --secret NAME:HOST parse helper (plan 129 stage 1)"
```

---

### Task 2: `--secret` clap arg on `up`/`run`

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/up.rs` (the `Args` struct, near the `--env` field ~line 787)
- Test: `crates/mvm-cli/tests/cli.rs` (arg parsing/help)

- [ ] **Step 1: Write the failing test**

Add to `crates/mvm-cli/tests/cli.rs`:

```rust
#[test]
fn up_accepts_repeatable_secret_flag() {
    use clap::Parser;
    let cli = crate::Cli::try_parse_from([
        "mvmctl", "up",
        "--secret", "openai:api.openai.com",
        "--secret", "stripe:api.stripe.com",
    ])
    .expect("parses --secret pairs");
    // Reach the up Args and assert the raw strings round-tripped.
    let secrets = cli.up_secrets_for_test();
    assert_eq!(secrets, vec![
        "openai:api.openai.com".to_string(),
        "stripe:api.stripe.com".to_string(),
    ]);
}
```

(If `cli.rs` has no existing accessor pattern, assert on `try_parse_from` succeeding and that an empty invocation yields an empty `--secret` vec instead; the accessor is a convenience — match whatever the neighbouring `--env`/`--port` tests in `cli.rs` already do.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli up_accepts_repeatable_secret_flag`
Expected: FAIL — unknown argument `--secret`.

- [ ] **Step 3: Write minimal implementation**

In `up.rs` `Args`, immediately after the `pub env: Vec<String>` field:

```rust
    /// Bind a secret for egress substitution (format: NAME:HOST). NAME must
    /// already be stored via `mvmctl secret set NAME --host HOST --type ...`;
    /// HOST is asserted against that binding's allowed_hosts (claim 12). The
    /// guest only ever sees an opaque placeholder. Repeatable.
    #[arg(long = "secret")]
    pub secret: Vec<String>,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-cli up_accepts_repeatable_secret_flag`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/up.rs crates/mvm-cli/tests/cli.rs
git commit -m "feat(cli): up/run --secret NAME:HOST arg (plan 129 stage 1)"
```

---

### Task 3: Merge `--secret` into the plan with a claim-12 binding check

**Files:**
- Create: `crates/mvm-cli/src/commands/vm/cli_secret.rs` (extend — add `merge_cli_secrets`)
- Modify: `crates/mvm-cli/src/commands/vm/up.rs` (call site between tenant resolve ~line 1071 and `plan_secrets:` assembly ~line 1095)
- Test: in-file `#[cfg(test)]` in `cli_secret.rs`

- [ ] **Step 1: Write the failing test**

Add to `cli_secret.rs` tests:

```rust
use mvm_core::plan::{SecretBinding, SecretSource};
use mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta};
use mvm_sdk::ir::AuthType;
use tempfile::tempdir;

fn store_with(dir: &std::path::Path, name: &str, hosts: &[&str]) -> FileBindingStore {
    let store = FileBindingStore::with_dir(dir);
    store
        .put("local", name, &SecretBindingMeta {
            auth_type: AuthType::Bearer,
            allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
        })
        .unwrap();
    store
}

#[test]
fn merges_secret_as_keystore_binding() {
    let dir = tempdir().unwrap();
    let store = store_with(dir.path(), "openai", &["api.openai.com"]);
    let mut secrets: Vec<SecretBinding> = Vec::new();
    merge_cli_secrets(&["openai:api.openai.com".to_string()], "local", &store, &mut secrets)
        .unwrap();
    assert_eq!(secrets, vec![SecretBinding {
        name: "openai".into(),
        source: SecretSource::Keystore { address: "openai".into() },
    }]);
}

#[test]
fn refuses_unbound_secret_with_actionable_error() {
    let dir = tempdir().unwrap();
    let store = FileBindingStore::with_dir(dir.path()); // nothing stored
    let mut secrets = Vec::new();
    let err = merge_cli_secrets(&["openai:api.openai.com".into()], "local", &store, &mut secrets)
        .unwrap_err();
    assert!(err.contains("mvmctl secret set openai"), "got: {err}");
}

#[test]
fn refuses_host_outside_allowed_hosts() {
    let dir = tempdir().unwrap();
    let store = store_with(dir.path(), "openai", &["api.openai.com"]);
    let mut secrets = Vec::new();
    let err = merge_cli_secrets(&["openai:evil.example.com".into()], "local", &store, &mut secrets)
        .unwrap_err();
    assert!(err.contains("allowed_hosts"), "got: {err}");
}

#[test]
fn accepts_wildcard_allowed_host() {
    let dir = tempdir().unwrap();
    let store = store_with(dir.path(), "corp", &["*.internal.corp"]);
    let mut secrets = Vec::new();
    merge_cli_secrets(&["corp:db.internal.corp".into()], "local", &store, &mut secrets).unwrap();
    assert_eq!(secrets.len(), 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli merge_cli_secrets`
Expected: FAIL — `merge_cli_secrets` not found.

- [ ] **Step 3: Write minimal implementation**

Add to `cli_secret.rs` (note: reuses `mvm_sdk::ir::host_matches`, the exact wildcard rule the validator + injector use, so CLI and host agree):

```rust
use mvm_core::plan::{SecretBinding, SecretSource};
use mvm_hostd::keyholder::BindingStore;
use mvm_sdk::ir::host_matches;

/// Parse each `--secret NAME:HOST`, assert NAME is bound and HOST is within
/// its stored `allowed_hosts` (claim 12), and append the plan binding.
/// Dedupes by name (a repeated NAME is idempotent). Fails closed: an unbound
/// secret or an out-of-policy host is a hard error, not a silent skip.
pub(in crate::commands) fn merge_cli_secrets(
    raw: &[String],
    tenant: &str,
    bindings: &dyn BindingStore,
    out: &mut Vec<SecretBinding>,
) -> Result<(), String> {
    for item in raw {
        let parsed = CliSecret::parse(item)?;
        let meta = bindings
            .get(tenant, &parsed.name)
            .map_err(|e| format!("reading binding for {:?}: {e}", parsed.name))?
            .ok_or_else(|| {
                format!(
                    "secret {:?} is not bound. Run `mvmctl secret set {} --host {} --type bearer` first.",
                    parsed.name, parsed.name, parsed.host
                )
            })?;
        if !meta.allowed_hosts.iter().any(|p| host_matches(p, &parsed.host)) {
            return Err(format!(
                "secret {:?} is not allowed to reach {:?}; stored allowed_hosts = {:?} (claim 12). \
                 Re-run `mvmctl secret set` with the right --host, or fix --secret.",
                parsed.name, parsed.host, meta.allowed_hosts
            ));
        }
        if out.iter().any(|b| b.name == parsed.name) {
            continue; // idempotent: already bound this run
        }
        out.push(SecretBinding {
            name: parsed.name.clone(),
            source: SecretSource::Keystore { address: parsed.name },
        });
    }
    Ok(())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-cli merge_cli_secrets`
Expected: PASS (4 tests).

- [ ] **Step 5: Wire the call site in `up.rs`**

After `let resolved_tenant = ...` (~line 1071) and before the struct literal that sets `plan_secrets: lowered_plan_secrets.secrets` (~line 1095):

```rust
    // Plan 129 Stage 1 — merge SDK-free `--secret NAME:HOST` bindings into the
    // plan, asserting each against the host binding store (claim 12) before we
    // synthesize + sign the plan.
    let mut plan_secrets = lowered_plan_secrets.secrets;
    if !args.secret.is_empty() {
        let bindings = mvm_hostd::keyholder::FileBindingStore::default_location()
            .context("opening the secret binding store for --secret")?;
        super::cli_secret::merge_cli_secrets(
            &args.secret,
            &resolved_tenant,
            &bindings,
            &mut plan_secrets,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
    }
```

Then change the struct field from `plan_secrets: lowered_plan_secrets.secrets,` to `plan_secrets,`.

- [ ] **Step 6: Run the full crate test + clippy + fmt**

Run: `cargo nextest run -p mvm-cli && cargo clippy -p mvm-cli -- -D warnings && cargo fmt --all -- --check`
Expected: PASS, zero warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/cli_secret.rs crates/mvm-cli/src/commands/vm/up.rs
git commit -m "feat(cli): merge --secret into plan with claim-12 binding check (plan 129 stage 1)"
```

---

### Task 4: Reference doc for the SDK-free authoring flow

**Files:**
- Modify: `public/src/content/docs/reference/cli-commands.md` (the `up`/`run` + `secret` sections)

- [ ] **Step 1: Document the two-step flow**

Add under the secrets section, prose matching the existing doc voice:

```markdown
### Binding a secret for egress (no SDK)

1. Store the value + policy once:

   ```sh
   printf '%s' "$OPENAI_KEY" | mvmctl secret set openai --host api.openai.com --type bearer --value -
   ```

2. Bind it into a run; the guest only ever sees an opaque placeholder, and the
   real credential is substituted host-side at the egress boundary:

   ```sh
   mvmctl run --flake . --secret openai:api.openai.com
   ```

`--secret NAME:HOST` asserts the destination against the stored binding's
`allowed_hosts` (claim 12) before the plan is signed. An unbound secret or a
host outside the policy is refused.
```

- [ ] **Step 2: Commit**

```bash
git add public/src/content/docs/reference/cli-commands.md
git commit -m "docs(cli): SDK-free secret binding flow (plan 129 stage 1)"
```

---

### Task 5: Box validation — full `http` substitution loop, SDK-free

**Files:** none (validation only). Box: `root@88.99.197.234`, worktree `/root/mvm-129`, warm root QEMU cache.

- [ ] **Step 1: Build + store a test secret + bind it**

```bash
# on the box, in /root/mvm-129 (branch off origin/main after #721 lands)
cargo build -p mvm-cli -p mvm-libkrun-supervisor --features libkrun-sys
printf '%s' "real-token-123" | ./target/debug/mvmctl secret set demo --host 127.0.0.1 --type bearer --value -
```

- [ ] **Step 2: Run a workload that echoes its outbound request to a bound `http` host**

Use a workload whose entrypoint does `curl -s http://127.0.0.1:<echo>/ -H "Authorization: Bearer $demo"` where `$demo` is the placeholder env (admission-injected). Launch with `--secret`:

```bash
./target/debug/mvmctl run --flake ./examples/agent_ping --hypervisor qemu --builder qemu \
  --secret demo:127.0.0.1 2>&1 | tee /tmp/mvm-129-stage1.log
```

Expected: the echo destination receives `Authorization: Bearer real-token-123` (the real value), NOT the placeholder.

- [ ] **Step 3: Assert the guest only held the placeholder**

```bash
grep -a "mvm-secret-" <vm_state_dir>/console.log    # placeholder present in guest
# and confirm the real token never appears guest-side:
! grep -a "real-token-123" <vm_state_dir>/console.log
```

Expected: placeholder present guest-side; `real-token-123` absent guest-side.

- [ ] **Step 4: Assert the audit chain records the substitution with no secret bytes**

```bash
./target/debug/mvmctl audit verify
grep -a "secret.substituted" ~/.mvm/audit/local.jsonl
! grep -a "real-token-123" ~/.mvm/audit/local.jsonl
```

Expected: `audit verify` exits 0; a `secret.substituted` entry exists carrying `{name, destination, auth_type}`; the raw value is absent from the chain.

- [ ] **Step 5: Record the result in the design note**

Append a short "Stage 1 box validation: PASS/FAIL + log path" line to `specs/notes/plan-129-egress-substitution-sdk-free-design.md` and commit.

---

## Follow-on (separate plans, spike-gated — NOT in this plan)

- **Stage 1b — transparent `http` terminator.** Replace the in-guest forward proxy with a host-side transparent terminator on the gateway (the `MitmdumpSupervisor`/ADR-006 lane). Spike first: how a terminating L7 proxy integrates with gvproxy/passt (Plan 141 gives observe/drop only — `pipeline.rs::run_packet_pipeline`, no TCP termination). No existing code; do not write tasks until the spike lands.
- **Stage 2 — name-constrained CA + `https` termination.** Per-VM CA issuance (extend the `rcgen` usage in `crates/mvm/src/security/certs.rs`, which today mints only *unconstrained* certs) with `NameConstraints` scoped to the binding allow-list; bake the CA cert into the guest trust store via `nix/lib/mk-guest.nix`; terminate TLS only for bound hosts, passthrough otherwise. Negative test required: the CA refuses to vouch for an unbound host. This is the box demo's real leg.
- **Stage 3 — optional SDK sugar + ADR-049 retirement.** `mvm.secret()` `auth_type`/`allowed_hosts` (Python then TS) + runtime accessor over `os.environ`; retire `crates/mvm-sdk/src/runtime_substitution.rs`, `sdks/python/mvm/_runtime.py`, `sdks/typescript/src/runtime.ts`, and (after a cross-repo check that mvmd doesn't consume it) the dead `mvm_core::policy::secret_binding` module.

## Self-review notes

- **Spec coverage:** authoring leg of the design's Stage 1 ✓; box validation of the loop ✓; terminator/CA explicitly deferred with rationale ✓.
- **Type consistency:** uses the live `mvm_core::plan::SecretBinding { name, source: SecretSource::Keystore { address } }` throughout (verified `plan/types.rs:277`); reuses `mvm_sdk::ir::host_matches` + `mvm_hostd::keyholder::{BindingStore, FileBindingStore, SecretBindingMeta, AuthType}` (verified `binding.rs:22`). The `:HOST` segment is a claim-12 assertion against the stored binding, not a second policy source.
- **No placeholders:** every code step is real; the one conditional (`cli.rs` accessor) defers to the neighbouring `--env`/`--port` test idiom rather than inventing one.

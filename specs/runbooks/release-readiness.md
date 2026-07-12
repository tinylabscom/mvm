# Runbook — release-readiness gates

**Audience:** the engineer cutting a release tag, plus the
auditor verifying the published artifacts ship the claims they
say they ship.

**Status:** This walks the macOS-host-runnable gates an operator
clears before `git tag v<X>.<Y>.<Z>`. The Linux/KVM-only gates
(live boot benchmark, verified-boot tamper regression, builder-
image reproducibility, and the native-Linux builder contract)
run in CI or on the approved real KVM host; this runbook focuses
on what the operator can attest locally before pushing the tag.

The gates correspond 1:1 to the plan-60 §"Checkpoint review
process" exit checklist and the eight security claims in
`CLAUDE.md::Security model`.

---

## Gate 1 — Workspace builds + tests + lints are green

The bedrock check. Every PR runs this in CI; the operator
re-runs locally before tagging so the local working tree
matches what's about to ship.

```bash
$ cargo test --workspace
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo fmt --check
```

All three must exit 0. Failures block the tag — no exceptions.

## Gate 2 — Performance budgets are pinned

`cargo xtask perf budgets` is the single-source-of-truth
inventory of every documented performance budget across plan-60
Phase 9, plan-65, and plan-7a. Each budget is pinned to a
constant in `xtask/src/perf.rs` (or referenced from the source
module) by a unit test, so a PR that drifts a budget without
updating the spec link fails `cargo test -p xtask`.

```bash
$ cargo xtask perf budgets
cargo xtask perf budgets — 11 budget(s) tracked

  rootfs_size                20971520 bytes (20 MiB)
                               └─ Minimal-template ext4 rootfs size (plan-60 Phase 9 + ADR-013)
  firecracker_cold_boot      500 ms
                               └─ Firecracker cold-boot wall-clock (1 vCPU / 256 MiB) (ADR-013 §"Per-backend boot budgets")
  ...
```

For monitoring/release pipelines that want machine-readable
output:

```bash
$ cargo xtask perf budgets --json > release-perf-budgets.json
```

Archive `release-perf-budgets.json` alongside the release
artifacts. An auditor checking historical drift can `diff` two
releases' inventories to see exactly what changed.

## Gate 3 — Security posture self-test passes

`mvmctl audit posture` is a read-only check on the **live host
config** that backs claims 5–8 in `CLAUDE.md::Security model`:
host signer present + mode 0600, audit chain verifiable, tool
staging dir mode 0700, allowlists populated, TLS minimum
pinned. (Claims 1–4 — seccomp / no-uid0 / verified-boot /
prod-agent-no-exec — are enforced by build-time symbol gates
and CI lanes, not runtime introspection.)

```bash
$ mvmctl audit posture
mvmctl audit posture — security self-test (… ok / … warn / … fail)
  ✓ host_signer: present at ~/.mvm/keys/host-signer.ed25519 (mode 0600)
  ✓ audit_chain: 1247 entries verified, head=8a3f2c91…
  ✓ tool_staging_dir: ~/.mvm/tool-staging mode 0700
  ! web_fetch_allowlist: $MVM_WEB_FETCH_ALLOWLIST unset — fail-closed
  ! web_search_allowlist: $MVM_WEB_SEARCH_ALLOWLIST unset — fail-closed
  ✓ overlay_root: ~/.mvm/overlays mode 0700
  ! secret_store: ~/.mvm/secrets does not exist (no secrets stored)
  ✓ tls_minimum: pinned to TLS 1.3 (plan 65 W7)
```

Markers:

- `✓` — claim is enforced and live. No action.
- `!` — soft warning. Often the right state for a release that
  hasn't been configured for production yet (e.g., allowlists
  unset means tools are fail-closed — secure default). The
  operator confirms each `!` matches the deployed target.
- `✗` — hard failure. Blocks the release until investigated.
  Common causes: `host_signer` mode drifted off 0600, audit
  chain has a torn write, tool staging dir was created with
  default umask.

`mvmctl audit posture` exits non-zero on any `✗` finding. The
`--json` mode emits one object per check for programmatic
release gates.

## Gate 4 — Runtime-overlay release contract is still true

Every release now ships a shared readonly guest-runtime overlay,
and the release operator must verify that the release surface still
matches the product contract before tagging.

Release artifacts that must exist per architecture:

- `runtime-overlay-<arch>.ext4`
- `runtime-overlay-<arch>.verity`
- `runtime-overlay-<arch>.roothash`
- `runtime-overlay-<arch>.VERSION`
- `runtime-overlay-<arch>-checksums-sha256.txt`

The operator confirms:

1. the docs still say the overlay is cached under
   `~/.cache/mvm/runtime-overlay/<version>/<arch>/`
2. only **guest-executed** runtime binaries belong in the overlay
3. admitted backends mount it read-only
4. running VMs do not hot-remount
5. stopped VMs adopt a new version-matched overlay only on restart
6. unsupported Linux rootfs-backed libkrun builder use is fail-closed

The release workflow itself publishes the overlay assets, but the
operator still verifies the contract by checking the docs and
release surface together:

```bash
$ rg -n "runtime-overlay/<version>|hot-remount|stopped VMs|guest-executed" \
    public/src/content/docs/reference/releases.md \
    public/src/content/docs/reference/filesystem.md \
    public/src/content/docs/reference/guest-agent.md \
    public/src/content/docs/reference/cli-commands.md
```

For the full rollout/update/rollback procedure, see
`specs/runbooks/runtime-overlay-production-rollout.md`.

## Gate 5 — Audit chain integrity is verifiable

The audit chain at `~/.mvm/audit/<tenant>.jsonl` is the
operator-attested record of every `mvmctl` invocation. Before
tagging a release the operator confirms the chain links are
intact:

```bash
$ mvmctl audit verify --tenant local
audit chain '~/.mvm/audit/local.jsonl' verifies clean: 1247 entries
```

Non-zero exit indicates a broken chain (signature or hash-link
mismatch). Treat as a security incident — the chain shouldn't
break under normal operation, so a failure means either
tampering or a regression in the chain-emit path.

## Gate 6 — Destruction certificate verifier round-trip

The hosted-cloud tenant deprovisioning workflow belongs to `mvmd`.
`mvm` still owns the overlay erasure substrate and the independent
certificate verifier. The end-to-end substrate path is covered by
`tests/tenant_destroy_e2e.rs`, which `cargo test --workspace` in
Gate 1 already exercised.

The operator's manual gate for this repo is to verify a certificate
bundle produced by the control plane or a fixture:

```bash
$ mvmctl audit verify-cert /tmp/release-test-certs.json \
      --pubkey ~/.mvm/keys/host-signer.pub \
      --chain ~/.mvm/audit/local.jsonl
mvmctl audit verify-cert: 1 certificate(s) verified
  ✓ release-smoke-.../smoke: 1 file(s), 9 byte(s) wiped at 2026-05-11T18:00:00Z [chain ✓]
```

The `[chain ✓]` marker is the tripwire: it asserts the chain path
contains a matching destruction event with the `cert_fingerprint`
label. See `specs/runbooks/overlay-erasure.md` for the full
three-axis documentation.

## Gate 7 — Linux/KVM-only gates have passed in CI or on the approved host

These can't run on a macOS host; the operator reads them off
the CI status panel or the approved KVM host evidence rather than
running them locally:

| Gate | Workflow | What it asserts |
|------|----------|-----------------|
| Verified-boot artifact gate | `security.yml::verified-boot-artifacts` | Production microVM Nix build emits `rootfs.{verity,roothash}` |
| Seccomp tier functional denial | `security.yml::seccomp-functional` | `standard` tier blocks `socket(AF_INET)` at runtime |
| Reproducibility | `security.yml::reproducibility` | Two clean builds of `mvmctl` are byte-identical |
| Builder image reproducibility | `security.yml::builder-image-reproducibility` | Sealed builder image reproduces byte-for-byte |
| Cargo deny + audit | `security.yml::cargo-{deny,audit}` | Supply chain advisory + license clean |
| Fuzz | `security.yml::fuzz` | vsock frame parser fuzz lanes pass for 5 min (30 min on cron) |
| Flake lock cleanliness | `security.yml::flake-locks-clean` | Every `flake.lock` is committed + in sync |
| Native Linux builder overlay contract | approved KVM host `88.99.197.234` | Linux auto-detect picks qemu and rootfs-backed libkrun builder remains fail-closed |

A red status on any of these blocks the release. The CI lane
descriptions point to the ADR section that motivates them.

## What this runbook does NOT cover

- **Live boot benchmark.** `cargo xtask perf boot --runs N` is
  the Linux/KVM-gated p50/p95/max measurement; substrate exists,
  the N-run benchmark loop is a Phase 9 follow-up. Until it
  ships, the operator relies on the constant-pin `Backend::budget()`
  + the `verified-boot-artifacts` rootfs-size lane.
- **Snapshot pool warm-clone budget.** Phase 9 follow-up; the
  budgets inventory tracks the targeted ≤ 30 ms cold-clone, but
  the implementing path doesn't ship yet.
- **LUKS keyslot revocation for overlays.** Phase 7a Slice B;
  needs Linux + `cryptsetup`. Until shipped, destruction
  certificates carry the Slice A caveat ("zero-fill at FS
  layer; SSD wear-leveling means disk hardware retention is
  out-of-scope").
- **Hosted-cloud multi-host certificates.** Today the cert
  signs a single host's view of destruction. Multi-replica
  attestation is a roadmap item — track in
  `specs/runbooks/overlay-erasure.md`.

## Sign-off

After every gate above is green, the operator records a sign-
off line in the release commit message:

```text
release-readiness: all 7 local gates + CI/KVM gates green
  perf budgets: 11 tracked, no drift
  posture: host_signer + audit_chain + tls_minimum + overlay_root ✓
  runtime overlay: release assets + restart-only rollout contract ✓
  audit chain: 1247 entries verify clean
  destruction cert round-trip: smoke ✓
```

The auditor receiving the release artifacts replays Gates 2-6
against the published binaries; mismatch is a signal to dig
into the operator's chain before trusting the artifacts.

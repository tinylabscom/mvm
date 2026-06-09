# Plan 129 — local secret-workload launch via the admission flow (boot-e2e gate)

> Session kickoff prompt. Paste as the opening message of the next session.

## Context

Plan 129 egress-secret substitution (ADR-067) is **mechanism-complete and
box-validated**: the per-VM `mvm-substitution-endpoint` moat resolves
placeholders over real AF_VSOCK against the real encrypted secret store
(placeholder mint → substitute → claim-12 refuse), proven on the dev-kvm box
`root@88.99.197.234` (QEMU runtime). The guest only ever holds an opaque
`mvm-secret-<hex>` placeholder; the real credential never enters the guest.

Merged: #710/#711/#713/#715/#717/#718 (the loop — transport, `RunEntrypoint.env`,
endpoint moat, QEMU spawn, invoke env + guest forward proxy), #722/#723 (Python +
TS `mvm.secret(type=, hosts=)` egress surface; the old in-guest substitution
models retired across Rust/Python/TS), #724 (`examples/python/secret-egress/` +
the finding below), **#733 (Phase E — undeclared-secret/PII egress redact-to-`XXX`
wired always-on into the gateway bridge; the second tier of the invariant).**

**Both tiers of the no-secret invariant are now landed** (substitution +
redaction). What remains is purely the **user-facing local launch glue** — there
is no code path for a user to boot a secret-declaring workload locally. That is
the whole of this session's work.

## Security invariant — the whole point (verify, do not assume)

**A raw secret must NEVER land on the microVM — with or without the SDK.** Two
distinct mechanisms, and they are not interchangeable:

- **Substitution (declared secrets) = "never ON the guest."** The guest receives
  only an opaque `mvm-secret-<hex>` placeholder; the real value lives solely in
  the host `mvm-substitution-endpoint`, which injects/signs it on egress. This is
  the *only* mechanism that achieves "no secret on the microVM." It is **SDK-
  independent** — it is driven by the *admitted plan's* `.secrets` (placeholder
  env injection), not the SDK. mvm must hand a workload a placeholder, never a
  raw value. **Built + box-validated.**
- **Redaction/detection on egress = "never LEAVES the guest" (a backstop, not the
  guarantee).** If a secret is redacted on the way out, it *was already on the
  guest*. This only catches secrets that landed by some other path (baked into
  the image, hardcoded, fetched). It does **not** give "never on the microVM" —
  substitution does. **Shipped in #733** as `RedactingSubstitution` (a
  `SubstitutionStage`), wired always-on into the gateway-bridge `ObserverWiring`:
  it runs `SecretsScanner.redact()` + `PiiRedactor.redact()` over each egress
  payload, masks any undeclared secret-shaped / PII match to `XXX` in place
  (mask-and-continue, not a whole-request drop), and `tracing::warn!`s the
  destination + fired-rule categories (never the value).

**Both mechanisms are now live and verified.** The egress scan
(`build_egress_scan`) keeps `MandatoryDenyEgressScan` + `PlaceholderLeakScan` +
L4/DNS for the fail-closed *placeholder-leak* drop, and the separate always-on
`RedactingSubstitution` stage handles the mask-and-continue case for *undeclared
secret-shaped* content. So: declared secret → never on the guest (substitution);
undeclared secret that somehow landed → never leaves (`XXX`). **No invariant work
remains in this session** — the only open item is the user-facing local launch
glue below.

> Verify-don't-assume: before touching launch glue, confirm on the box that a
> declared secret reaches the guest only as a placeholder (env/fs hold
> `mvm-secret-<hex>`, never the value) for **both** an SDK workload and a non-SDK
> plan-declared `.secrets`. That confirmation is the boot-e2e gate below.

## The gap (from on-box validation, 2026-06-08)

`mvmctl compile` (which emits **local** boot artifacts with no admission)
**refuses managed secret refs**: *"managed secret refs are not supported by
`mvmctl compile` local boot artifacts yet … Use deploy/plan flows for managed
refs."* And `mvmctl up` takes `--flake`/`--manifest`, not an app+secrets. So
there is **no user-facing local path to launch a secret-declaring workload**,
even though:

- the admission machinery exists — `up.rs` (`lower_workload_secrets`,
  `admit_plan_for_boot`, `admit_for_run`) and `run_plan.rs` (admits each app via
  `admit_for_run`);
- the QEMU backend already spawns the substitution endpoint from the admitted
  plan's `.secrets` and fails closed (#717).

The missing piece is the user-facing glue from a secret-declaring app → an
admitted plan → `up` on QEMU → endpoint spawn.

## First: settle the scope decision

Is launching a secret-bearing workload **locally** in mvm's scope (dev/test on a
`/dev/kvm` box), or strictly **mvmd's** deploy/tenant domain? (Per the ADRs,
deploy / tenant lifecycle / the `--prod` gate live in mvmd, not mvmctl.)

- **If local-in-scope:** wire the route — secret-declaring workload → lowered
  `plan.secrets` → `admit_for_run`/`admit_plan_for_boot` → `up` on QEMU →
  endpoint (the spawn is done). Likely either relax the `compile` refusal to
  route managed refs through admission for a local boot, or add an `up` /
  `run --mode plan` path that accepts the secret-declaring app.
- **If mvmd-only:** document it, move the boot-e2e gate to mvmd integration
  tests, and close the mvm-side item.

## Then: boot-validate end to end on the box

Per `specs/plans/129-secrets-subsystem.md` §"Boot e2e runbook":

1. `printf '%s' "$KEY" | mvmctl secret set echo-key --host postman-echo.com --type bearer --value -`
2. Launch `examples/python/secret-egress` through the (decided) admission path on QEMU.
3. Assert: the destination saw the **real** credential (substitution), 
   `~/.mvm/vms/<vm>/substitution.pid` lived for the run and is gone after `stop`,
   and a request to an **unbound** host is refused (claim 12).

This closes the live guest→host leg (a real QEMU guest dialing host CID 2:5253);
the endpoint + store + substitution + forward are already box-proven over
loopback.

## Files

- `crates/mvm-cli/src/commands/vm/{up.rs, run_plan.rs, managed_secrets.rs, plan_admission.rs}`
- the `compile` managed-ref refusal site (in the compile command / `mvm-sdk` compile)
- `crates/mvm-backend/src/qemu.rs` — endpoint spawn (`spawn_substitution_endpoint`, done #717)
- `examples/python/secret-egress/`

## Constraints / gotchas

- **mvmd owns** deploy / tenant / `--prod` policy — don't build prod-gate logic in mvm.
- **SigV4 forward path stays deferred** (user decision); bearer/basic is the shipped path.
- Box: `pkill -f mvm-substitution-endpoint` **self-kills the launching shell**
  (its argv contains the binary path) — use `pkill -x mvm-substitutio`.
- Merges: repo requires **squash**; main branch protection requires 1 approving
  review (`aneyzberg`) and has `enforce_admins=true`, so a self-merge needs a
  brief `enforce_admins` toggle + restore, or aneyzberg's approval.

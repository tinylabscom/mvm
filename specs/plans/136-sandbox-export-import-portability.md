# Plan 136 — Sandbox export/import symmetry + Linux-guest caveat

## Context

A sibling libkrun-based agent-sandbox CLI — authored by the libkrun maintainer —
covers the same ground as mvm's dev mode (libkrun microVMs, gvproxy/passt networking,
a `~/work` host mount, per-VM state dirs). Reviewing it surfaced two small, concrete
gaps worth closing in mvm, plus one larger idea that is deliberately deferred.

The central finding: **mvm already has the hard part of sandbox export/import** —
signed, content-addressed `.mvmpkg` bundles (`mvmctl bundle export`/`fetch`/`install`,
`crates/mvm-plan/src/bundle.rs`) and the signed `ExecutionPlan`
(`crates/mvm-plan/src/plan.rs`), which is itself a portable sandbox descriptor pinning
image + deps-volume + resources + every policy. This plan therefore **reuses existing
machinery**; it does not design new artifact formats. The gap is narrow: verb
symmetry/discoverability and one deferred wiring loop. Plus a one-paragraph docs
caveat that the comparison tool documents and mvm does not.

## Scope

1. **Caveat doc** — guest is Linux even on a macOS host.
2. **Export/import verb symmetry** — add `mvmctl bundle import` over the existing
   fetch+install path.
3. **Close the bundle→ExecutionPlan loop** — populate `ExecutionPlan.bundle` during
   CLI plan synthesis (the piece deferred in Sprint 52 W2).
4. **Deferred (no code): host port exposure** — reasoning recorded; needs an ADR-002
   amendment + cross-repo (mvmd) policy work first.

Out of scope unless separately approved: a whole-sandbox descriptor (image + deps
volume + config as one archive) — see §"Optional".

---

## 1. Linux-guest caveat doc

mvm's docs explain *why* a builder VM exists but never warn agent authors that the
guest is Linux regardless of host OS. Add a Starlight `:::caution` callout.

- [ ] Add callout to `public/src/content/docs/guides/dev-image.md` (right after the
  intro; the file already says "sandboxed Linux shell").
- [ ] (Optional) Mirror in `public/src/content/docs/guides/troubleshooting.md`
  "Builder VM and Dev Shell Issues".

Callout text (matches the existing `:::note` / `:::tip[label]` convention):

```markdown
:::caution[The guest is always Linux]
Even on a macOS host, the mvm dev microVM and every workload guest run Linux.
macOS-native binaries, Homebrew packages, and OS-specific operations won't work
inside the guest. Agents driving the sandbox should target Linux.
:::
```

Docs only — no tests; verify via the `public/` Astro build.

---

## 2. `mvmctl bundle import` (verb symmetry)

We have `bundle export` but the re-import side is `fetch`/`install`; there is no
`import`, so the round-trip isn't an obvious pair. Add a thin `import` wrapper over the
existing verified install path — no new format, no new trust logic.

Reuses:
- `crates/mvm-cli/src/commands/bundle/export.rs` — existing `bundle export` (seal + sign).
- existing `bundle fetch` / `bundle install` — verify against
  `~/.mvm/trusted-publishers/<key_id>.pub`, install to `~/.mvm/bundles/<sha256>.mvmpkg`.
- `crates/mvm-plan/src/bundle.rs` — `BundleManifest`, `read_and_verify_bundle`,
  `verify_plan_bundle`, and the existing rejection-ladder tests.

- [ ] Add `crates/mvm-cli/src/commands/bundle/import.rs` implementing `bundle import
  <source>` as verify + install (delegating to the existing fetch/install code path).
- [ ] Register the subcommand in the bundle command module (mirror `export.rs` wiring).
- [ ] Test: export a built template to a temp `.mvmpkg`, import it, assert it lands in
  the bundle store and verifies.
- [ ] Test: `import` refuses a tampered archive / unknown key / key_id mismatch
  (extend the existing `bundle.rs` rejection-ladder coverage at the `import` level).

---

## 3. Close the bundle→ExecutionPlan loop

`ExecutionPlan.bundle: Option<PlanArtifact>` exists; the supervisor admit path already
re-verifies it when present. Only the CLI synthesis that *populates* it was deferred
(Sprint 52 W2). Wire it so an installed bundle can drive `mvmctl up`/`run`.

- [ ] In the plan-synthesis call site under `crates/mvm-cli/src/commands/vm/`, set
  `bundle: Some(PlanArtifact { bundle_sha256, manifest_sig_base64, key_id })` from the
  resolved/installed bundle.
- [ ] Test: synthesize a plan from an installed bundle; assert `bundle` is populated
  and that `verify_plan` + admit-time re-verify accept it.
- [ ] Test: a `bundle_sha256` / signature mismatch is refused (extends the existing
  claim-9 admit tests).

---

## 4. Host port exposure — DEFERRED (decision, no code)

The comparison tool forwards host ports to in-guest services trivially because it has
no threat model. In mvm this is not a flag:

- **Mechanism vs. policy / repo boundary.** The forwarding mechanism belongs in mvm —
  we own `GvproxyHandle`/`PasstHandle` (`crates/mvm-libkrun/src/`) and both gateways do
  TCP forwarding natively (a `ProxyConfig`/supervisor-config field). But *whether* a
  workload may expose a port is admission policy, which lives in **mvmd, not mvm**.
- **Threat-model gap.** Claim 10 covers *egress* only; *ingress* exposure (host/net →
  guest service) is undefined. It needs an **ADR-002 amendment** defining the ingress
  posture (default-deny, explicit opt-in, loopback-vs-all-interfaces), an
  `ExecutionPlan` field, and a `plan.port_exposed` audit entry (claims 8/12 lineage).

**Decision:** defer to a dedicated cross-repo plan that starts with the ADR. If a
near-term need appears, a *dev-mode, loopback-only* exposure is cheap and claim-free —
but the prod ingress path is not built here.

- [ ] (Deferred) File the ingress-posture ADR amendment + cross-repo plan when prioritised.

---

## Optional — whole-sandbox descriptor (needs explicit approval)

`bundle export` captures image artifacts only — not the sealed deps volume
(`~/.mvm/volumes/deps/<hash>/`, `DepsVolumeBinding`) or resource/policy config. The
mvm-native "export a whole sandbox" is: serialize + sign the `ExecutionPlan` (which
already pins all of that) together with its `.mvmpkg` and the referenced deps volume.
This is real new surface (multi-artifact archive + verbs) and overlaps heavily with the
ExecutionPlan we already have. **Recommendation: skip unless there is a concrete
"share a fully-configured sandbox including deps" need.**

---

## Verification

- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`,
  `cargo test --workspace` (use `just ci`).
- [ ] Round-trip: build a template → `mvmctl bundle export … --out /tmp/x.mvmpkg` →
  `mvmctl bundle import /tmp/x.mvmpkg` → `mvmctl up`/`run` against the installed bundle;
  confirm the synthesized plan carries the `bundle` pin and admits.
- [ ] Docs: build the `public/` Astro site; confirm the callout renders.

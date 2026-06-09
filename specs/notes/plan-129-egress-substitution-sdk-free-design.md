# Plan 129 — SDK-free egress substitution (design)

**Date:** 2026-06-08. **Status:** design, pending review.
**Amends:** ADR-067 §1 + Consequences + Alternatives (proxy-native becomes primary; SDK optional).
**Builds on:** ADR-006 (name-constrained egress CA), ADR-067 (egress substitution), the host substitution pipeline already shipped under Plan 129 Phases B–E.

## The correction that drove this

Earlier scoping treated the SDK as the substitution client: a workload would `import mvm`,
call `mvm.secret(...)`, and route through an SDK HTTP client that speaks absolute-form to the
guest forward proxy. **That is backwards.** Egress is mvm's responsibility, enforced at the
proxy the platform owns — it must not require a workload library. A workload that writes plain
`requests.get("https://api.openai.com", headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"})`
must get substitution with no mvm import. The SDK is ergonomic sugar, never a prerequisite.

ADR-067 §1 already hedged "configured by the **SDK / proxy env**," and ADR-006 exists precisely
for "hypervisor-level L7 egress interception." So this is a re-prioritization of the written
architecture, not a new direction: the proxy-native path becomes primary.

## We control all egress — what that does and doesn't buy

Every guest packet crosses gvproxy (macOS) / passt (Linux), and Plan 141's `on_packet`/`Verdict`
pipeline already gives inspect-and-drop at L3/L4. That is real and load-bearing — it is why the
leak-scan works, and it means interception can be **transparent**: no client proxy config, no
in-guest forward proxy, works for any client/language including ones that ignore `HTTP_PROXY`.

What controlling the wire does **not** buy us: reading or modifying **TLS**. For `https` the
packets carry ciphertext; without the session keys we cannot find the placeholder, let alone swap
it. That is TLS working as designed, not a gap we can close by owning the network harder.

## The one hard constraint

Substitution requires the gateway to **see and modify** the secret-bearing request.

- `http://` — the gateway reads the plaintext request directly. Substitutable with no SDK and no
  client proxy config. Caveat: the real secret differs in length from the fixed `mvm-secret-<hex>`
  placeholder, so an in-stream byte rewrite is TCP surgery (reseq every later packet, recompute
  checksums, fix `Content-Length`/framing). In practice the gateway **terminates and
  re-originates** — a *transparent* proxy. "No proxy" means no *client-configured* proxy, not no
  termination.
- `https://` — the gateway sees ciphertext. To substitute it must **terminate the guest's TLS**
  with a cert the guest trusts and re-originate the real TLS upstream — i.e. MITM.

There is no third option for a generic `https` client. Non-MITM `https` substitution requires the
client to speak absolute-form, which only a cooperating SDK does. Since the SDK is ruled out as a
*requirement*, **name-constrained MITM is mandatory for `https`.**

**Termination is host-side.** The guest is untrusted, so the CA private key and the
TLS-termination point live host-side (the gateway / ADR-006 L7 lane); only the CA *certificate*
(public, for trust) is baked into the guest image. The host already does the real upstream TLS;
the new piece is terminating the guest's leg.

### Why this does not break ADR-067's blast-radius pitch

ADR-067 rejected "TLS MITM of **all** guest egress." This is different: **name-constrained,
scoped to bound destinations only.** The per-VM CA (ADR-006) can vouch for *nothing* except the
hosts the user bound a secret to. For every other destination the proxy blind-tunnels `CONNECT`
end-to-end — no termination, no visibility.

The load-bearing observation: **the host already sees the bound-host request in plaintext** — the
injector/signer must, to inject or sign. Whether the guest delivers that request as
plaintext-absolute-form (SDK) or as TLS-to-mvm's-name-constrained-CA (generic client), the host's
plaintext visibility is **identical: bound destinations only.** Going SDK-free via scoped
termination widens the blast radius by zero bytes. That is the sentence the ADR-067 amendment must
carry.

## Mechanism

### Where the credential goes: placeholder-marker + transparent signing

- **Injected creds (`bearer`, `basic`)** — placeholder-marker. The workload puts the opaque
  placeholder where the credential goes (`Authorization: Bearer <ph>`, `X-API-Key: <ph>`, a query
  param — anywhere); the proxy find-replaces `mvm-secret-<hex>` in the outbound request. This is
  injection-site-agnostic and **already built** (`keyholder/injector.rs`, `find_placeholder` in
  `keyholder/substitution.rs`). SDK-free: the placeholder is an env var the workload reads with
  plain `os.environ` — admission already hands `(var → placeholder)` to guest env
  (`keyholder/admission.rs::assemble_registry`).
- **Signed auth (`sigv4`, `hmac`)** — transparent. There is no token to swap; the signer
  canonicalizes the whole request and adds the signature, keyed off `auth_type`. Already built
  (`keyholder/signer.rs`, `keyholder/sigv4.rs`). The workload makes an unsigned request to the
  bound host; the proxy signs on the way out.

Transparent header-injection for bearer was considered and rejected: it forces the *binding* to
encode the injection site (which header / scheme / query), which is more config and more brittle
than letting the workload mark the spot with the placeholder it already has in env.

### Transparent host-side gateway termination

The substitution point is a **host-side transparent terminator** on the gateway path (the
`MitmdumpSupervisor` lane ADR-006/plan-79 reserved), not an in-guest proxy and not a
client-configured one. It gains:

1. **Selective interception keyed on the binding allow-list.** A flow to a bound host is
   terminated and run through the existing substitute/sign path against the host substitution
   endpoint, then re-originated as real TLS upstream. A flow to any other host is passed through
   untouched (blind `CONNECT` tunnel for TLS / plain forward for clear). Fail *closed* toward
   termination only for bound hosts; fail *open* (passthrough) for the rest.
2. **Per-VM name-constrained CA** (`https` only), issued host-side at admission, name-constrained
   to the union of every bound secret's `allowed_hosts` for that VM. The CA *private key* and the
   termination point stay host-side; only the CA *certificate* is baked into the guest rootfs
   trust store via `nix/lib/mk-guest.nix` (mvm owns the image — not an adversarial CA). The
   name-constraint extension is the security boundary: it must refuse to vouch for any unbound
   host.
3. **Leak-scan unchanged.** The always-on `PlaceholderLeakScan` still drops a placeholder that
   escapes toward an unbound destination, audited as today.

Everything host-side is **reused**: substitution endpoint, `SubstitutionRegistry`, injector,
signer, sigv4 builder, binding store, `secret.substituted` / `secret.placeholder_dropped` audit.
What is new is the transparent terminator on the gateway + CA issuance + guest-trust wiring +
selective, binding-keyed interception. The in-guest forward proxy (#721) is no longer on the
critical path — it becomes the optional SDK-cooperative transport (Stage 3) or is retired with the
other ADR-049 leftovers.

## Authoring without the SDK

The plan needs a `SecretBinding` so admission mints + injects a placeholder. Two SDK-free routes,
both feeding the same synthesized plan + the same host binding store:

1. **Value + binding metadata:** `mvmctl secret set openai --host api.openai.com --type bearer`
   (built — `crates/mvm-cli/src/commands/ops/secret.rs` + `keyholder/binding.rs`).
2. **Plan binding:** `mvmctl run --secret openai:api.openai.com` adds the `SecretBinding` to the
   synthesized plan with no SDK — this is **Plan 125 Task E2** (`--secret NAME:host`, currently
   `[ ]`), parsing to `{name, allowed_hosts:[host], auth_type:bearer-default}`. `mvmctl up`
   already loads plan secrets from workload IR (`up.rs::load_workload_ir`); `--secret` is the
   CLI-native sibling that needs no manifest or SDK.

A declarative `[secrets]` table in `mvm.toml` is the natural third surface but reverses Plan 38's
"no secrets in the manifest" decision — out of scope here, captured as a follow-up that needs its
own ADR note. The SDK `secret()` gaining `auth_type`/`allowed_hosts` (the original blocker #1) is
retained as **optional** SDK-user ergonomics, not critical path.

## Staged delivery

Staged so each step builds the reusable core and adds one capability, rather than big-bang. The
transparent terminator is the through-line: Stage 1 builds it for clear traffic (no crypto),
Stage 2 adds the TLS-termination leg.

**Stage 1 — transparent terminator, `http`, no CA.** Host-side gateway terminates a guest `http`
flow to a *bound* host, runs substitute/sign against the host endpoint, re-originates, audits
`secret.substituted`. No SDK, no proxy env, no CA — a generic `curl http://<bound-host>/...` with
the placeholder env var just works. New work: the transparent terminator core + the SDK-free
authoring path (`--secret`, Plan 125 E2) + box validation. Proves the whole chain except the TLS
leg, and the terminator is reused verbatim by Stage 2. Acceptance: `mvmctl audit verify` shows
`secret.substituted`; the destination receives the real credential; guest env holds only
`mvm-secret-<hex>`.

**Stage 2 — add TLS termination (name-constrained CA) → `https` (the real demo).** Per-VM
name-constrained CA issuance (ADR-006), guest trust-store wiring, and the same terminator now
terminating TLS for bound hosts (passthrough for the rest). Generic
`curl https://api.openai.com/...` works SDK-free and hits the headline acceptance goal. `http`
can't demo a real API (all https), so Stage 2 is non-negotiable — Stage 1 de-risks it to "just the
TLS leg on a terminator that already works."

**Stage 3 (optional) — SDK sugar.** `mvm.secret()` authoring (`auth_type`/`allowed_hosts`) +
runtime accessor over `os.environ`, Python then TS; optionally keep the in-guest forward proxy as
an SDK-cooperative transport. Built last; not required for acceptance.

## What gets retired

The superseded ADR-049 in-guest resolution path: `crates/mvm-sdk/src/runtime_substitution.rs`,
`sdks/python/mvm/_runtime.py`, `sdks/typescript/src/runtime.ts`. They materialize credentials
*inside the guest* — the thing ADR-067 eliminates. Delete (no shim, per the no-backcompat rule);
the Plan 129 Phase D "deferred" list already names this.

## ADR-067 amendment

- §1: proxy-native (any client via proxy env) is **primary**; SDK is one optional client.
- New paragraph distinguishing **scoped name-constrained MITM (bound hosts)** from the rejected
  "MITM of all egress," with the zero-added-visibility argument above.
- Alternatives: the existing "TLS MITM of all guest egress — Rejected" entry stays, with a
  pointer that the *scoped* variant is the accepted `https` mechanism, not the blanket one.
- Consequences: replace "requires the workload to use the mvm SDK" with "`http` works through any
  proxy-env client; `https` through any client trusting the per-VM name-constrained CA; the SDK is
  optional ergonomics."

## Box validation

`root@88.99.197.234`, worktree `/root/mvm-129`, warm root QEMU cache,
`mvmctl up --hypervisor qemu --builder qemu`. Stage 1 validated with a plain
`curl http://<bound-host>/...` (no `--proxy` — transparent); Stage 2 with a real `https` API (or a
local TLS echo with a bound host). Branch off latest `origin/main` after #721 lands.

## Open risks

- **CA issuance + name-constraint enforcement** must be exact — a CA that vouches beyond
  `allowed_hosts` would be the blanket-MITM ADR-067 rejected. The name-constraint extension is the
  security boundary; it needs a negative test (CA refuses an unbound host).
- **Selective interception** must fail *closed* toward termination only for bound hosts and *open*
  (passthrough) for the rest — a bug that terminates an unbound flow is a visibility regression and
  a trust violation.
- **The transparent terminator is new** (Stage 1) — Plan 141 gives packet observe/drop, not TCP
  termination + L7 reassembly. Building it is the bulk of Stage 1; Stage 2 only adds the TLS leg on
  top. This is the deferred plan-79 §2.6.5 lane, real work, not a veneer.

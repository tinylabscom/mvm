# Dependency baseline (plan 126 Task A1)

Measured 2026-06-05 on `main` @ `bb1cbcbe` (post plan-126 B5). This is the
canonical measurement method + the live numbers every later plan-126 task
records its delta against. Plan 127's dep-count dashboard reads from here.

## Method (the canonical commands)

Two different numbers, measured two different ways — don't conflate them:

```sh
# (1) Default binary closure — what actually compiles into a default
#     `mvmctl` build. This is the number the B-tasks move.
cargo tree --workspace -e no-dev --prefix none | sed 's/ (.*)//' | sort -u | wc -l

# (2) Full lockfile — every package resolved across all features, targets,
#     and dev-deps. A coarser supply-chain-surface proxy.
grep -c '^name = ' Cargo.lock

# Per-target closure (how many crates a target drags):
cargo tree -p <crate> -e no-dev --prefix none | sed 's/ (.*)//' | sort -u | wc -l
# Who pulls a target:
cargo tree -i <crate> -e no-dev
# Feature-on closure (a gated feature's added cost):
cargo tree -p mvmctl --no-default-features --features <feat> -e no-dev --prefix none | sed 's/ (.*)//' | sort -u | wc -l
```

## Baseline numbers

| Metric | Value |
|---|---|
| Default binary closure (method 1) | **407** unique packages |
| Full lockfile (method 2) | **722** packages |
| `mvmctl` + `manifest-verify` closure | 469 (sigstore adds ~62) |
| `mvm` + `template-registry-s3` closure | 355 (opendal) |

Lockfile drifted 739 (2026-06-03) → **722** now — B5 + the intervening
merges + the 0.16.0 version bump. The brief's "723"/"735" earlier counts
were the lockfile metric at other points in time.

## The four B-task targets — corrected findings

The plan's Phase-B target list was written on assumptions that the live
tree contradicts. What's actually true:

| Target | In **default** closure? | Closure | Reality |
|---|---|---|---|
| `sigstore` | **No** — gated behind `manifest-verify` (off by default) | ~62 added when on | B1's *default-build* benefit is **already realized**. Only a `manifest-verify` build pays for it. B1 is now purely the cross-repo "relocate cosign-verify to mvmd" decision (the prod/admit gate lives in mvmd), not a default-closure cut. |
| `opendal` | **No** — gated behind `template-registry-s3` (off by default) | part of the 355 | Same as sigstore: B2's default benefit is **already realized**. B2 (→`object_store`) only helps the `template-registry-s3` build, and is coordinated with plan 123. |
| `pgp` (rpgp 0.17) | **Yes** — unconditional dep of `mvm-build` | **168** | **B3's premise is wrong.** `pgp` is **not** our release signing. It verifies the **Alpine minirootfs tarball's upstream PGP signature** against an embedded Alpine release key in Stage 0 (`crates/mvm-build/src/stage0.rs::verify_alpine_pgp_signature`). It **cannot** move to minisign — Alpine dictates the format. See below. |
| `aws-lc-rs` 1.16 | **Yes** | **16** + a C/cmake build | **B4 is entangled with C1, not a standalone cut** — see below. |

### The only two default-closure targets are `pgp` (168) and `aws-lc-rs` (16).

`sigstore` and `opendal` are already out of the default binary — their
cuts only shrink the respective *feature-on* builds.

## B4 re-scope: aws-lc-rs comes from the `oci-client` / reqwest-0.13 chain (= C1)

Traced where aws-lc-rs actually enters:

- **mvm's own `reqwest 0.12`** is **already aws-lc-free**: reqwest 0.12.28
  declares `rustls = { default-features = false }` and its `rustls-tls`
  feature enables `__rustls-ring` (the `ring` provider). So mvm's direct
  HTTP path uses ring today.
- **aws-lc-rs enters only via `oci-client 0.16 → reqwest 0.13.3 →
  rustls-platform-verifier 0.7`** (mvm-oci's registry client). The
  platform-verifier path pulls aws-lc.

So there are **two reqwest majors** in the tree (0.12 direct, 0.13 via
oci-client) — that's **Task C1** — and the aws-lc-rs the plan wants gone
(B4) is dragged in by the 0.13/oci-client/platform-verifier chain. **B4
and C1 are the same problem.** Removing aws-lc means getting oci-client's
TLS onto ring + webpki roots (no platform-verifier), which in practice
means unifying on one reqwest major and pinning that stack to ring.

This is a real TLS-stack-unification task (needs a runtime TLS smoke —
provider-pinning can compile-green yet fail at connect), **not** the
"~6 crates, mechanical" the plan estimated. mvmd is unaffected either way
(it already pins ring via `mvmd-proxy`/`certs.rs` + installs it, and keeps
its own aws-lc transitively through `iroh → hickory → rustls`).

### Blocker: `oci-client` hardcodes aws-lc-rs (no ring path in any version)

Drilled into the fix and hit a wall. `oci-client` **0.16.1** and **0.17.0**
both wire their only rustls option to aws-lc, via **two** hardcoded paths:

```toml
# oci-client 0.16/0.17 [features]
rustls-tls = ["reqwest/rustls", "jsonwebtoken/aws_lc_rs"]
# reqwest 0.13 [features]
rustls = ["__rustls-aws-lc-rs", "dep:rustls-platform-verifier", "__rustls"]
```

There is **no ring/webpki feature** — the only alternative oci-client
offers is `native-tls` (OpenSSL, a system dep — worse). Cargo feature
unification is additive, so a workspace-level rustls/ring pin **cannot
remove** the aws-lc that oci-client's features force on. So B4 is **not
achievable by configuration**. Removing aws-lc requires one of:

1. **Fork/patch `oci-client`** (bounded vendor) to add a ring path:
   `reqwest`'s webpki-roots-ring feature + `jsonwebtoken`'s `rust_crypto`
   provider. Plus unify the reqwest major. Moderate effort + a runtime
   TLS smoke. (Allowed per "vendoring as a bounded bridge is OK".)
2. **Replace `oci-client`** with a registry client that supports ring (or
   a minimal in-repo client). Large.
3. **Upstream a `rustls-tls-ring` feature to `oci-client`**, then bump.
   Slow (depends on maintainers).
4. **Defer B4** — accept aws-lc while we use `oci-client`.

### Decision (2026-06-20): option 3 — upstream the feature, rehome to roadmap

Picked **upstream + rehome** over a fork-now (option 1). The fix lives on
`oci-client` itself (its only rustls option hardcodes aws-lc via both
`reqwest/rustls` and `jsonwebtoken/aws_lc_rs`), so the durable form is an
upstream feature, now filed as **[oras-project/rust-oci-client#274][pr274]**:
`rustls-tls-no-provider = ["reqwest/rustls-no-provider", "jsonwebtoken/rust_crypto"]`,
mirroring reqwest's own `rustls-no-provider` (consumer installs the ring
provider). **Validated locally against upstream `main`:** with that feature
`cargo tree --no-default-features --features rustls-tls-no-provider -i aws-lc-rs`
is **empty** and the crate builds — correcting an earlier worry in this doc,
`rustls-platform-verifier` is provider-agnostic and does **not** re-drag aws-lc.

So the bounded fork *would* work; we rehome rather than carry one because a
one-line upstream feature is cleaner than a maintained `[patch.crates-io]`. Once
#274 lands it is a plain `oci-client` bump + feature flip + ring-provider install
(and that collapses the `reqwest` 0.12/0.13 split too); a `[patch.crates-io]`
bridge to the proven branch is available if we want aws-lc gone sooner. Until
then the D1 forbidden-dep gate + D2 duplicate-major ratchet keep the regression
closed and the `reqwest` split is a recorded D2 baseline entry, not an open cut.
B4 + C1 are tracked on the dependency roadmap, not as refactor-close blockers.

[pr274]: https://github.com/oras-project/rust-oci-client/pull/274

**Net conclusion for Phase B:** there are **no quick mechanical cuts
left**. The real reductions are (a) **B3** `pgp` −168 (a *security
decision* — drop/gate the Alpine PGP verify), and (b) **B4** −16 + the C
build (an *upstream fork/replace* of `oci-client`). Everything else is
already feature-gated out of the default binary.

## B3 re-scope: `pgp` is Alpine-tarball verification, not release signing

`mvm-build/src/stage0.rs` fetches Alpine's official minirootfs and verifies
it **two ways**: a source-pinned **SHA-256** (`verify_sha256` against
`ALPINE_MINIROOTFS_{AARCH64,X86_64}`) **and** a detached **PGP** signature
against the embedded `ALPINE_RELEASE_KEY_ASC` (fingerprint also pinned).
The doc comment calls PGP the layer that "catches a malicious upstream
mirror that signs with the wrong key."

But the tarball is **already byte-pinned by SHA-256** for the pinned
`ALPINE_VERSION`. For a pinned version the hash is the binding integrity
check; the PGP verify is **defense-in-depth** whose distinct value is
mainly at *version-bump* time (verify a new tarball's signature before
trusting its not-yet-pinned bytes).

So reducing the 168-crate `pgp` closure is **not** a minisign swap. The
options, each a real decision (not mechanical):

1. **Drop the PGP verify, keep the SHA-256 pin** (−168 crates). Removes a
   defense-in-depth layer; needs security-owner sign-off + an ADR-002
   note, and a documented version-bump procedure (verify the new tarball's
   PGP signature out-of-band before pinning its hash).
2. **Keep PGP, find a lighter verifier.** rpgp *is* the lean option for
   OpenPGP detached-signature verification; sequoia is heavier. No obvious
   smaller crate exists for RSA-OpenPGP verify. Low expected payoff.
3. **Gate it behind a feature** so only the contributor Stage-0 build pays
   for it (the published binary doesn't run Stage 0 the same way). Needs a
   look at whether any default path reaches `verify_alpine_pgp_signature`.

Recommendation: pursue option 1 (biggest win) **as a security decision**,
or option 3 if a feature boundary is clean — but not as a silent swap.

## Suggested task order (revised)

The plan's "quick mechanical cuts" mostly don't exist as written. The real
remaining work, honestly scoped:

1. **B4+C1 together (`aws-lc-rs` + the reqwest-major split)** — the only
   *mechanical-ish* default cut, but it's a TLS-stack-unification effort:
   collapse reqwest 0.12/0.13 to one major and steer `oci-client` onto
   ring + webpki (drop `rustls-platform-verifier`). −16 crates + the C
   build + one reqwest major. **Needs a real TLS-connect smoke**, and an
   `oci-client` feature/version that avoids platform-verifier (verify
   first — may need an oci-client bump or a fork-of-features).
2. **B3 (`pgp`, −168)** — biggest number, but a **security decision**:
   drop or feature-gate the Alpine-tarball PGP verify (defense-in-depth
   over the existing SHA-256 pin). Needs owner sign-off + an ADR-002 note.
3. **B1/B2** — no default-build benefit left (already feature-gated);
   pursue only for feature-on builds / the cross-repo sigstore relocation,
   sequenced with 123.
4. **D1** — the forbidden-dep gate (sibling of `check-core-runtime-free`
   from B5).

## Final measure (plan 126 Phase D close-out)

Re-measured 2026-06-13 on `main`, with the **same canonical commands** as
the A1 baseline above (apples-to-apples):

| Metric | A1 (`bb1cbcbe`) | Now | Delta |
|---|---|---|---|
| Default binary closure (method 1) | 407 | **347** | **−60** (~15%) |
| Full lockfile (method 2) | 722 | **683** | **−39** |

Per-target final state in the default closure:

| Target | A1 | Now | What happened |
|---|---|---|---|
| `sigstore` | out (feature-gated) | **out** | unchanged — only a `manifest-verify` build pays for it (that build's closure is 442). |
| `opendal` | out (feature-gated) | **out** | unchanged — only a `template-registry-s3` build pays. |
| `pgp` (rpgp) | **in** (168-crate subtree) | **out** | removed not via this plan's B3 options but by **plan 160** — the Stage-0 seed moved off the Alpine minirootfs (busybox tarball, no upstream-PGP-signed artifact), so `verify_alpine_pgp_signature` and its rpgp closure are gone. This is the bulk of the −60. |
| `aws-lc-rs` | **in** (16 + a C build) | **in** | still the sole heavy default-closure target — **B4 remains blocked** (`oci-client` hardcodes aws-lc in its only rustls option; needs a fork/replace + reqwest-major unify + a TLS smoke, not a config change). |

The −60 is **not** all plan 126: the dominant contributor is plan 160's
Alpine→busybox Stage-0 seed (pgp), with the duplicate-major dedup (D2)
and the confirmed-stable `sigstore`/`opendal` gating accounting for the
rest. Honestly attributed rather than claimed.

### What now keeps it cut (the ratchets)

The reduction is held by four CI-runnable gates, so a regression fails
rather than silently creeping back:

- **`check-forbidden-deps`** (D1) — `sea-*`/`mysql` banned from
  `Cargo.lock`, and `sigstore`/`opendal`/`pgp` banned from `mvmctl`'s
  default-feature closure (closure-based, since they legitimately remain
  in the lock behind off-by-default features). `aws-lc-rs` is
  deliberately *not* banned while B4 is blocked.
- **`check-core-runtime-free`** (B5) — `tokio` stays out of `mvm-core`'s
  default closure.
- **cargo-deny `multiple-versions = deny`** (D2) — the duplicate-major set
  is frozen behind an audited skip baseline.
- **cargo-deny / cargo-audit** (D2) — advisory + license drift.

### Remaining work (unchanged, decision-gated)

- **B4 + C1** (`aws-lc-rs`, −16 + a C build): blocked upstream by
  `oci-client`; needs the reqwest-major unify + a fork/feature that avoids
  `rustls-platform-verifier`, plus a TLS-connect smoke.
- **B1 / B2**: no default-build benefit left; only the cross-repo sigstore
  relocation + the `opendal`→`object_store` feature-build swap remain,
  sequenced with plan 123.

# Plan 309: Dependency reduction — cut the shipped closure

## Status

**Phases 0, 1, and 2 COMPLETE** (2026-08-10). `reqwest` is retired; the
shipping closure is **242**, down from 286 — a **15% cut**. Phase 3 (product
decisions) and Phase 4 (the lockfile ratchet) remain.

Earlier status, kept for the record: Phases 0 and 1 complete (2026-08-09). Shipping closure **286 → 263**
on `x86_64-unknown-linux-gnu`; macOS `aarch64-apple-darwin` 281 → 258.
`CLOSURE_BUDGET` ratcheted 286 → 263. Phase 2 (`mvm-http`) and Phase 3
(product decisions) are not started.

## Why

Every crate in `mvmctl`'s default closure is a supply-chain unit, an attack
surface unit, and a compile unit. `xtask check-closure-budget` already ratchets
the count, but the ratchet is **at its ceiling**: 286 of 286. There is no
headroom, which means the next genuinely-needed dependency forces a budget bump
rather than a trade.

This plan trades. It is a measured, staged reduction of the shipped closure with
the risky items isolated behind their own gates.

## Measured baseline (2026-08-09, `5cd52bc69`)

| Surface | Count | How measured |
|---|---|---|
| `mvmctl` default closure, `x86_64-unknown-linux-gnu` | **286** | `cargo tree -p mvmctl -e no-dev --target x86_64-unknown-linux-gnu` (the budget gate's own command) |
| `mvmctl` default closure, `aarch64-apple-darwin` | 281 | same, macOS target |
| `mvm-agentd` (sealed guest), `aarch64-unknown-linux-musl` | 116 | same, guest target |
| `Cargo.lock` packages | 672 | `grep -c '^name = ' Cargo.lock` |

Of the 672 lockfile packages, ~62 are the `wasmtime`/`cranelift`/`wit` family
reachable only through the off-by-default `wasm-backend` feature.

**Unique ownership** — crates that leave the shipped closure if the dep goes
(computed by re-reaching the tree with that node banned):

| Dep | Unique crates | Source usage |
|---|---|---|
| `reqwest` | 27 | 6 crates, ~98 refs |
| `rcgen` | 20 (11 from its `x509-parser` feature alone) | 1 module, `mvm-core/src/crypto/egress_ca.rs` |
| `aes-gcm` | 10 | 2 files |
| `tracing-subscriber` | 7 | 12 files |
| `tree-sitter` + 4 grammars | 7 | `mvm-sdk` compile/decorator — **keep**, see non-goals |
| `toml` | 6 | 10 crates |
| `clap` | 6 | pervasive |
| `rayon` | 5 | 5 files |
| `rand` 0.8 | 5 | pervasive |
| `flate2` | 5 | OCI layers |
| `schemars` | 4 | derive-only |
| `hickory-proto` | 3 | 2 files |
| `serde_jcs` | 2 | 12 files |
| `thiserror` 1.0 | 2 | **zero** — see Phase 0 |

## Non-goals — deliberately kept

Ruthless is not reckless. These are *not* cut, and the reasons are load-bearing:

- **`aes-gcm` / `x25519-dalek` (10 + 1 crates).** The obvious move is
  `ring::aead` — `ring` is already in the host closure via `rustls`. It does not
  work: the sealed guest agent (`mvm-agentd`, 116 crates, static musl) carries
  `aes-gcm` and `x25519-dalek` and has **no `ring` and no `rustls`**. Removing
  them from the host would not remove them from the shipped closure, because
  `mvmctl` depends on `mvm-agentd`. Cutting them for real means hand-rolling
  AEAD and X25519 in the sealed tier. Not doing that.
- **`clap`, `chrono`, `serde`, `serde_json`, `flate2`, `rand`.** Pervasive, and
  the closure cost is small relative to what re-implementing them would cost in
  correctness.
- **`tree-sitter` + its four grammars (7 crates).** Measured and then ruled
  out (maintainer call, 2026-08-10). These are the only C-compiling crates in
  the closure besides `ring`/`blake3`, so gating the JS/TS grammars behind an
  `sdk-node` feature looked attractive on build time. It is not available: the
  grammars *are* the SDK-to-Nix translation. `decorator/{python,typescript}.rs`
  parse the decorators, `compile/reachability.rs` and `compile/func_describe.rs`
  scope a function entrypoint to reachable code, `compile/strip_framework.rs`
  rewrites the source, and `addon/validator.rs` validates the Nix bodies with
  `tree-sitter-nix`. Gating them would make a default `mvmctl` unable to compile
  the workloads it exists to compile. Not a dependency to trade.

- **`smoltcp` / `mio` / `socket2` (6 crates).** A whole userspace forwarding
  backend; on macOS it is the only one.
- **`ring`, `rustls`, `ed25519-dalek`, `sha2`, `blake3`, `leakguard`,
  `seccompiler`, `landlock`, `nix`.** Security primitives with audited
  implementations. Not a place to save crates.

---

## Phase 0 — corrections (no behaviour change)

Three defects, not trade-offs. Land these first; they cost nothing.

- [x] **`thiserror = "1"` in `crates/mvm-build/Cargo.toml:107`.** A hardcoded
      major-1 pin while the workspace is on `thiserror` 2. Compiles a second
      copy of `thiserror` + `thiserror-impl` — a whole extra proc-macro build —
      into the shipped binary. Switch to `thiserror.workspace = true`.
      **−2 crates**, and it retires a duplicate major.
- [x] **`rtnetlink` is a dead `[workspace.dependencies]` entry.** No crate
      declares it; zero source references. It was deliberately removed from the
      guest (replaced with synchronous raw netlink) and
      `xtask check-guest-agent-runtime-free` *bans it by name*. Leaving the
      workspace entry live is a loaded gun pointed at that gate. Delete it.
      **0 crates, real risk removed.**
- [x] **`schemars` leaks into the default closure.**
      `crates/mvm-sdk/Cargo.toml:50` declares `schemars` non-optional, and
      line 29 sets `mvm-contract = { features = ["schema"] }`. Cargo unifies
      features workspace-wide, so this turns on `schemars` inside
      `mvm-contract` for *every* consumer — defeating the deliberate `schema`
      gating in `mvm-core`, `mvm-contract`, and `mvm-agentd`. The in-file
      comment ("adds no new default-build weight") is wrong at the workspace
      level. Give `mvm-sdk` its own optional `schema` feature.
      **−4 crates** plus a `schemars_derive` proc-macro build.

**Phase 0 exit: 286 → 280 — measured, as predicted.**

---

## Phase 1 — feature narrowing (no hand-written replacements)

- [x] **Drop `rcgen`'s `x509-parser` feature.** This is the best
      risk-adjusted cut in the plan: **−11 crates for a ~20-line refactor and
      zero new crypto code.**

      The feature exists solely for `Issuer::from_ca_cert_pem`, called from two
      `issuer()` methods in `crates/mvm-core/src/crypto/egress_ca.rs` (lines
      ~125 and ~194). Both do the same thing: serialize the in-memory `KeyPair`
      to PEM, then re-parse the certificate PEM to rebuild an `Issuer` that was
      fully determined at mint time. Retain the `CertificateParams` (or
      reconstruct them) and build the `Issuer` directly instead.

      Removes the entire ASN.1 tower: `x509-parser`, `asn1-rs`,
      `asn1-rs-derive`, `asn1-rs-impl`, `synstructure`, `der-parser`,
      `oid-registry`, `rusticata-macros`, `data-encoding`, `num-bigint`,
      `num-integer`, `lazy_static`, `minimal-lexical`, and **`nom` 7** — which
      is the last `nom` 7 in the shipped closure, retiring another duplicate
      major (`check_duplicate_majors.rs:46` documents that pin; update it).
      Three of those are proc-macro crates, so the build-time saving is larger
      than the count suggests.

      Verification: the existing `egress_ca` tests already assert the minted
      intermediate carries the right `nameConstraints`; they must stay green
      unchanged.

- [x] **Replace `rayon` with `std::thread::scope`.** **−5 crates** (`rayon`,
      `rayon-core`, `crossbeam-deque`, `crossbeam-epoch`, `crossbeam-utils`).

      Five call sites, all `par_iter().map(...)` over an owned `Vec` with no
      nested parallelism, no work-stealing requirement, and no rayon-specific
      combinators: `mvm-fs/src/rootfs.rs`, `mvm-fs/src/ext4/verity.rs`,
      `mvm-fs/src/ext4/mod.rs`, `mvm-build/src/runtime_overlay.rs`,
      `mvm-build/src/initramfs.rs`.

      Add one `par_map` helper — chunk the slice across
      `std::thread::available_parallelism()` scoped threads, collect in index
      order. This is the "small in-house library" option applied where it is
      genuinely low-risk: the semantics needed are a fraction of what rayon
      provides, and determinism of output order is something we want to own
      anyway (`rootfs.rs` already re-sorts by guest path to get it back).

      Guard with a benchmark on the dm-verity hash tree and the ext4 block
      emission — those are the two that motivated adopting rayon. If the
      scoped-thread version regresses measurably on a large image, keep rayon
      and say so in the plan.

**Phase 1 exit: 280 → 263 — measured** (the plan projected 262 by also
counting `serde_jcs`, which was deferred; the two structural cuts landed at
their predicted sizes). `CLOSURE_BUDGET` ratcheted to 263.

---

## Phase 2 — `mvm-http`, the in-house HTTP client

**Stage A (crate + proof) landed. Stage B (migration) not started.**

### The number is −20, not −27

The −27 in the baseline table is reqwest's raw subtree, and it was wrong as a
saving. `mvm-http` legitimately keeps `http`, `httparse`, `tokio-rustls`, and
`rustls-platform-verifier` (which brings `rustls-native-certs` and
`openssl-probe`), and is itself a crate. Measured projection:

| | crates |
|---|---|
| current | 262 |
| minus the reqwest subtree | 235 |
| union with `mvm-http`'s own closure | **242** |

So the migration is worth **−20**, still the largest remaining item by 3×.

### Stage A — the crate, with no callers (landed)

Built standalone and *not* wired into `mvmctl`, so the closure stays 262 and
the budget gate stays green while the client is proven. What it reuses is the
design decision that matters:

- `http` for header types — `HeaderName`/`HeaderValue` reject at construction
  the control characters behind response splitting.
- `httparse` for the response head — the parser hyper uses, zero deps, fuzzed
  upstream.
- `url` for URLs — a bespoke parser that disagreed with the SSRF guard about
  what the host is would *be* the SSRF bug.

What the crate does own is the framing decision, which it resolves once from
the head and **fails closed** on every ambiguity that enables request
smuggling: `Content-Length` together with `Transfer-Encoding` is refused rather
than resolved by precedence; disagreeing duplicate `Content-Length` values are
refused; non-decimal lengths and non-hex chunk sizes (`0x5`, `+5`, ` 5`) are
refused rather than coerced; `204`/`304`/`1xx`/HEAD are treated as bodyless
before framing headers are consulted; head size, header count and chunk-line
length are all bounded.

Two deliberate deviations from a general client, both narrowing:

- **Redirects are never followed, and there is no policy knob.** Every caller
  already set `Policy::none()`, and a redirect is the cheapest way to walk a
  validated request to an unvalidated host.
- **The body cap belongs to the reader, not the call site.** The reqwest code
  had six hand-rolled `while let Some(chunk)` accumulator loops; the cap is now
  enforced before a chunk is handed back.

The resolver is a trait, and the client dials **only** addresses it returns —
that is what makes it the SSRF chokepoint rather than an advisory check, and it
closes the check-then-connect rebinding window.

TLS floor is 1.2 by default, matching reqwest, so migration is not a silent
policy change; the hardened tool paths keep pinning 1.3 explicitly.

Coverage: 56 tests (19 parser units, 8 resolver/serialisation units, 22
end-to-end over real loopback sockets driving malformed and ambiguous framing),
plus a `cargo-fuzz` target on `parse_head`/`next_chunk` wired into
`security.yml`, asserting never-panic plus two span invariants an out-of-range
chunk would break.

### Stage B — migration (COMPLETE)

`reqwest` is gone from the product graph. Closure **262 → 242**, the projection
hit exactly.

- [x] A blocking face (`mvm_http::blocking`), holding **no runtime**. An
      earlier shape cached one per client, which made the client un-droppable
      inside an async context — tokio panics on that, far from the cause. Each
      `send` builds and discards a current-thread runtime after refusing
      outright if called from within one.
- [x] `mvm-cli`, `mvm-build`, `mvm-sdk`, `mvm-fs`, `mvm-core`.
- [x] `mvm-hostd` — `http_hardening`, `web_fetch`, `web_search`,
      `http_forward`, `substitution_proxy`, `terminator/tls`.
- [x] Differential harness against `reqwest`, run before the hostd cut over.
- [x] `reqwest` dropped from every manifest; `CLOSURE_BUDGET` ratcheted to 242.

**What the differential measured.** Twelve well-formed cases agree exactly.
Five ambiguous ones are refused here; only **two** are behavioural divergences,
and both are cases where reqwest *resolves* a framing ambiguity:

| case | reqwest | mvm-http |
|---|---|---|
| `0x`-prefixed chunk size | refuses | refuses |
| `+`-prefixed Content-Length | refuses | refuses |
| disagreeing duplicate Content-Length | refuses | refuses |
| **Content-Length + Transfer-Encoding** | **accepts**, prefers TE | refuses |
| **`Transfer-Encoding: gzip, chunked`** | **accepts** | refuses |

The first is the textbook smuggling primitive. Resolving an ambiguity is what
lets two hops disagree, so failing closed is the point rather than a
regression. The harness keeps `reqwest` as a **dev-dependency** deliberately —
it is the standing evidence, not scaffolding.

**A reqwest workaround deleted, not ported.** `http_hardening` documented that
reqwest connects on the *resolver's* port rather than the URL's and never hands
the resolver the port — so the SSRF-filtering resolver hardcoded 443, and any
caller forwarding elsewhere needed a second resolver-less builder plus a manual
resolve-filter-and-pin. `mvm_http::Resolve` receives `(host, port)`, so
`hardened_client_builder_no_dns` and `resolve_ssrf_safe_ips` are **gone**,
`substitution_proxy`'s per-request dance collapses to one builder call, and
`web_fetch`'s hand-rolled `PinnedDnsResolver` becomes the built-in
`PinnedResolver`. `http_forward` also loses five
`no_proxy`/`no_gzip`/`no_brotli`/`no_zstd`/`no_deflate` calls: mvm-http supports
neither proxies nor compression, so explicit disabling became absence.

**Witnesses.** 167 SSRF / egress / substitution / forward tests pass, including
the loopback, RFC1918, and IMDS refusals and the unbound-destination leak gate.

**Phase 2 exit: 262 → 242. Achieved.**

---

## Phase 2 preflight: measured, before writing any client

Feature narrowing is what made the rcgen cut cheap, so the same question was
asked of `reqwest` first. **It does not apply.** Measured against the shipped
closure:

| Change | Δ | Verdict |
|---|---|---|
| drop `blocking` | 0 | `futures-channel`/`futures-util` are `hyper-util`'s anyway |
| drop `json` | 0 | `serde_json` is already in the closure |
| drop `rustls-no-provider` | −5 | drops TLS entirely — not viable |

There is no public reqwest feature that yields rustls without
`rustls-platform-verifier` (`__rustls` is private), and swapping the platform
trust store for bundled `webpki-roots` would be a *downgrade* — it stops
honouring enterprise CA policy and root revocation. So the 27 crates are the
irreducible hyper/tower/http stack, and only a replacement wins them.

That makes Phase 2 a genuine ~2000-line HTTP/1.1 client, on the path that
carries OCI registry fetch, egress re-origination, and the `web_fetch` SSRF
guard. The reqwest surface it must reproduce is not just request/response: the
`reqwest::dns::Resolve` seam behind `SsrfFilteringResolver`, `min_tls_version`
pinned to TLS 1.3, `redirect::Policy::none`, streaming `.chunk()` under exact
byte caps, plus blocking and async faces. That is the whole cost, stated
before starting rather than discovered halfway.

## Phase 3 — measured and declined

Not a backlog. Every candidate below was measured, and each is **declined** for
the reason given. The rule this plan follows is: remove or reimplement a
dependency only where it can actually be cut. A dependency that is load-bearing,
or whose removal buys a single-digit crate count in exchange for behaviour users
rely on, is not a saving — it is a regression with a smaller lockfile.

Re-open one only with a new argument, not a re-reading of the same numbers.

| candidate | Δ | declined because |
|---|---|---|
| `tree-sitter` + 4 grammars | −7 | They *are* the SDK-to-Nix translation. See non-goals. |
| `toml` | −6 | User-facing config format. 0.8 → 0.9 measured as a wash (`toml_edit` swaps for `toml_parser` + `toml_writer`), so there is no free version bump either. |
| `tracing-subscriber` | −4 | `EnvFilter::try_from_default_env` backs `RUST_LOG`, and `.json()` backs the signer and substitution-endpoint logs. Taking it means owning env-filter directive semantics forever and regressing a `RUST_LOG` contract. |
| `hickory-proto` | −3 | DNS protocol code. Not a place for bespoke parsing. |
| `which` | −3 | 37 call sites for a PATH walk; the churn exceeds the gain. |
| `serde_jcs` | −2 | Audit-chain signing path — a canonicalization difference breaks signature verification silently rather than loudly. |
| `url` | −2 | Feeds the SSRF guard's host comparison. A second opinion about what the host is *is* the bug. |
| the −1 tail | −1 each | `keyring`, `ext4-view`, `xattr`, `bs58`, `aho-corasick`, `hex`, `ipnet`, `uuid`, `lzma-rs`, `etherparse`, `sysinfo`, `leakguard`. `keyring` is only −1 even on macOS: `security-framework` and the `core-foundation`/`objc2` set are shared with `rustls-platform-verifier`. |

One item here is worth doing for a reason other than crate count: the lockfile
carries `toml` at both 0.8 and 0.9, and consolidating retires a duplicate major.
That is hygiene for `check-duplicate-majors`, not a closure saving.

---

## Phase 4 — hold the line (COMPLETE)

The ratchet only works if it moves, and if it measures the right thing.

- [x] `CLOSURE_BUDGET` ratcheted at every phase exit: 286 → 280 → 263 → 262 →
      **242**.
- [x] **`xtask check-feature-closure-budget`** (new): bounds the workspace's
      all-features, no-dev closure at **468**, wired into the `Lint policy` job.
      The default-closure gate cannot see an off-by-default feature, so
      `wasm-backend`'s ~62-crate `wasmtime`/`cranelift` family was growing
      unobserved — not shipped, but compiled by `--all-features` lanes and
      scanned by `cargo deny` and `cargo audit`. A compile-time assertion pins
      the feature budget above the default one, since the two measure nested
      sets and an edit inverting them should not build. Both the runtime gate
      and the const assertion were verified to fail when violated.
- [ ] Moving `wasm-backend` to its own workspace member so the main `Cargo.lock`
      stops carrying the `cranelift` family. Still open; evaluate against
      Plan 301 before acting.

### Why the gate is not a `Cargo.lock` count

The original sketch here was "ratchet total lockfile packages". Measured, that
does not work: Cargo retains entries for packages unreachable from any target,
feature, or dev-dependency. This workspace's lockfile holds **672** while only
**552** are reachable with every feature *and* all dev-dependencies enabled —
about 120 orphans. Removing a real dependency can leave the count unchanged,
which was confirmed by dropping one and re-resolving: 672 before, 672 after. A
ratchet on that number would give false comfort in both directions.

The resolved-graph counts do respond, and they nest cleanly:

| metric | count | gate |
|---|---|---|
| default `mvmctl`, no-dev | 242 | `check-closure-budget` |
| workspace, no-dev, all-features | 468 | `check-feature-closure-budget` |
| workspace, with-dev, all-features | 552 | ungated (test-only tooling) |
| `Cargo.lock` raw | 672 | **not a metric** — ~120 orphans |

## Expected outcome

| Milestone | Closure | Δ from baseline | State |
|---|---|---|---|
| Baseline | 286 | — | — |
| Phase 0 | 280 | −6 | **landed** |
| Phase 1 | 263 | −23 | **landed** |
| `fs2` → std locking | 262 | −24 | **landed** |
| Phase 2 stage A (crate only) | 262 | −24 | **landed** |
| Phase 2 stage B (all callers) | **242** | **−44** | **landed** |
| Phase 3 | 242 | — | measured and **declined** |
| Phase 4 | 242 | — | **landed** (a second ratchet, not a cut) |

## What landed (2026-08-09)

23 crates left the shipped binary, and nothing entered it. The 23:
`asn1-rs`, `asn1-rs-derive`, `asn1-rs-impl`, `crossbeam-deque`,
`crossbeam-epoch`, `crossbeam-utils`, `der-parser`, `dyn-clone`,
`minimal-lexical`, `nom` 7, `num-bigint`, `num-integer`, `oid-registry`,
`rayon`, `rayon-core`, `rusticata-macros`, `schemars`, `schemars_derive`,
`serde_derive_internals`, `thiserror` 1.0, `thiserror-impl` 1.0,
`time-macros`, `x509-parser`. Six are proc-macro or derive crates, so the
compile-time saving is larger than 23/286 suggests.

Verification performed:

- Full workspace: `cargo build --all-targets`, `cargo clippy --all-targets
  -- -D warnings`, `cargo nextest run --workspace` (10,628 pass), doctests,
  nightly `cargo fmt --all --check`.
- All 41 `xtask check-*` policy gates pass, including `check-closure-budget`
  at its new 263 and `check-stubs`, which confirms the schemars gating
  changed no generated schema byte.
- Both egress-CA legs got a test proven to go **red** under a deliberate
  mint/rebuild DN divergence — the webpki path check for the leaf leg, and a
  new `intermediate_issuer_dn_matches_the_host_ca_subject_dn` for the root
  leg, which had no coverage before.
- `par_map` carries its own suite, including ragged-chunk coverage over
  every length 1..=97 and a worker-panic propagation test.
- Benchmark: `build_ext4_pure_100_files_64k` went 3.12 ms (rayon) → 2.71 ms
  (scoped threads). No regression; rayon's pool spin-up dominates a
  workload this size.
- Linux cross-build (`cargo zigbuild x86_64-unknown-linux-gnu`) clean for
  every touched crate.

### Also landed: `fs2` → std file locking (−1)

`fs2` was in the closure for `FileExt` alone — advisory `flock` across four
sites. std stabilized `File::lock`/`try_lock`/`unlock` in 1.89 and the
toolchain is pinned at 1.96, so the dep bought nothing. std additionally
splits contention out of the error type (`TryLockError::WouldBlock` vs
`TryLockError::Error`), so "another process holds it" no longer rides on an
errno comparison. The test-only spurious-`WouldBlock` retry wrappers were
*kept*: nothing in this change proves the platform `flock` was innocent, so
their comments were reworded rather than deleted.

### Deferred out of Phase 1

- **`serde_jcs` (−2).** Phase 1 originally counted it. It sits on the
  audit-chain signing path, where a canonicalization difference silently
  breaks signature verification rather than failing loudly. Two crates does
  not buy that risk without a differential corpus; moved to Phase 3.

### Found, not fixed (pre-existing, out of scope)

- `cargo check -p mvm-sdk --all-features` fails on `main` — `SubprocessBackend`
  in `mvm-sdk/src/facade.rs` does not implement `MvmClient::backend_capabilities`.
  The `client-facade` feature does not compile, which is why no lane caught it.
- `check-duplicate-majors` reports nine stale `windows-*` allowlist entries on
  `main`. (The two this work made stale, `thiserror` and `thiserror-impl`, were
  removed from the allowlist here.)

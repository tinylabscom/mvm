# Plan 309: Dependency reduction — cut the shipped closure

## Status

**Phases 0 and 1 COMPLETE** (2026-08-09). Shipping closure **286 → 263**
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
| `tree-sitter` + 4 grammars | 7 | `mvm-sdk` compile/decorator |
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

**−27 crates. The single largest item, and the highest risk.** Own phase, own
feature flag, own differential test suite.

`reqwest` pulls `hyper`, `h2`, `tower`, `http-body`, and their transitive set.
The API surface actually used is narrow and mundane:

- `Client` / `ClientBuilder` (18 + 7 refs), `blocking::Client` (5 files)
- `Response`, `StatusCode`, `header::HeaderMap`, `Method::from_bytes`, `Url`
- `redirect::Policy::none` (8 refs — every client disables redirects)
- `tls::Version::TLS_*` pinning
- `.chunk().await` streaming reads with size caps (7 sites)
- `reqwest::dns` custom resolver hook (2 refs)

No HTTP/2 requirement is visible in the call sites; no multipart, no cookies, no
proxy chaining, no connection-pool tuning.

- [ ] Write `crates/mvm-http`: HTTP/1.1 over `rustls` (already a direct
      dependency, already on `ring`, which is already in the closure), blocking
      and async surfaces, explicit `Content-Length`/chunked decoding, a
      hard response-size cap as a first-class constructor argument rather than
      a caller-side `.chunk()` loop, no redirect following at all (matching how
      every existing caller configures it), and a pluggable resolver.
- [ ] Migrate callers in dependency order, easiest first:
      `mvm-cli/src/http.rs` and `mvm-build/src/stage0.rs` (blocking artifact
      downloads, hash-verified — a wrong byte fails closed) →
      `mvm-cli/src/template_registry.rs` → `mvm-fs/src/oci/{registry,manifest,layer}.rs`
      → `mvm-hostd/src/supervisor/{http_forward,tools/*}.rs` **last**.
- [ ] Keep `reqwest` behind a `legacy-http` feature until every caller has
      migrated and the differential suite is green, then delete it.

**Risk, stated plainly.** The last group is the egress re-origination path and
the `web_fetch` SSRF hardening — i.e. ADR-023 substitution and the claim 13 /
Preview-claim-16 boundary. A homegrown HTTP client on that path can reintroduce
request smuggling, header injection, redirect-based SSRF, or an unbounded read.
Preconditions for merging Phase 2:

- [ ] Differential tests running the same request corpus through `reqwest` and
      `mvm-http`, asserting identical status/headers/body and identical
      *refusals*.
- [ ] A fuzz target on the response parser (status line, header block, chunked
      body), added to the `fuzz` job in `.github/workflows/security.yml`
      alongside the existing harnesses.
- [ ] The `http_hardening_loopback` and `wasm_egress_witness` tests green
      unchanged.

If the differential or fuzz work does not converge, **stop after Phase 1** —
`-24` banked with no security exposure is a better outcome than a rushed HTTP
stack on the egress path.

**Phase 2 exit: 262 → 235.**

---

## Phase 3 — candidates requiring a product decision

Not scheduled. Each needs a call that is not the implementer's to make.

- [ ] **`tree-sitter` + 4 grammars (−7 crates).** These and `ring`/`blake3` are
      the only C-compiling crates in the closure, so they cost build time out of
      proportion to their count. All four grammars are genuinely used: Python
      (decorator parse, reachability, `func_describe`, `strip_framework`),
      TypeScript/TSX + JavaScript (reachability, `func_describe`), Nix (addon
      body validator). Gating JS/TS behind an `sdk-node` feature would cut C
      compilation for the common Python case — but a default `mvmctl` would then
      refuse to compile Node workloads. **Product decision.**
- [ ] **`tracing-subscriber` (−7).** Used in 12 files, mostly `init`. A minimal
      in-house `Subscriber` is maybe 200 lines, but it means owning
      `env-filter` semantics forever. Poor ratio; listed for completeness.
- [ ] **`toml` (−6).** Investigated: bumping 0.8 → 0.9 is roughly a wash
      (`toml_edit` is replaced by `toml_parser` + `toml_writer`), *not* a free
      win. The lockfile currently carries both 0.8 and 0.9 — consolidating on
      one retires a duplicate major, which is worth doing on its own. Replacing
      TOML wholesale is a user-facing config-format change. **Product decision.**
- [ ] **`hickory-proto` (−3), `keyring` (−1).** Small; not worth bespoke code.

---

## Phase 4 — hold the line

The ratchet only works if it moves. Every phase above must land its
`CLOSURE_BUDGET` reduction *in the same PR* as the cut.

- [ ] Ratchet `CLOSURE_BUDGET` down at each phase exit (280 → 262 → 235).
- [ ] Add `xtask check-lockfile-budget`: a second ratchet on total `Cargo.lock`
      package count. The closure budget cannot see the ~62 `wasmtime` packages
      that an off-by-default feature drags into `cargo audit` / `cargo deny`
      scope and into `--all-features` CI builds. `wasm-backend` has an active
      design (Plan 301) and is **not** a deletion candidate — but its cost
      should be visible and bounded.
- [ ] Consider moving `wasm-backend` to its own workspace member with its own
      lockfile, so the main `Cargo.lock` stops carrying the `cranelift` family.
      Evaluate against Plan 301's Part A before acting.

## Expected outcome

| Milestone | Closure | Δ from baseline | State |
|---|---|---|---|
| Baseline | 286 | — | — |
| Phase 0 | 280 | −6 | **landed** |
| Phase 1 | 263 | −23 | **landed** |
| Phase 2 | ~236 | ~−50 | not started |

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

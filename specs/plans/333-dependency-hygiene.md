# Plan 333: Dependency hygiene — four defects and a ratchet, not a cut

## Status

**Phase 5 and Phase 5.5 COMPLETE** (2026-08-14). macOS closure **238 → 232**;
Linux unchanged at 243. Two gates added, each proven red. Successor to [Plan 309](309-dependency-reduction.md), whose
Phases 0–2 and 4 landed and whose Phase 3 measured and declined the remaining
candidates.

## The finding that matters

**The aggressive cutting is already done, and re-doing it would be a
regression.** Plan 309 took `mvmctl`'s shipped closure from **286 → 242**
(−15%) by retiring `reqwest`, `rayon`, `schemars`, `x509-parser` and
`thiserror` 1.0. It then measured every remaining candidate and *declined* them
in Phase 3 — `hickory-proto`, `which`, `toml`, `tracing-subscriber`,
`serde_jcs`, `url`, `tree-sitter`, and a −1 tail of twelve.

This plan re-measured the graph independently (2026-08-14, `37c38b93c`) and
**reproduces Phase 3's numbers**. Its declines stand. Cutting `which` is still
20+ call sites for −3; cutting `url` or `serde_jcs` still trades an SSRF guard
or a signature canonicalization for two crates apiece. Plan 309's rule holds:
*re-open one only with a new argument, not a re-reading of the same numbers.*

So this plan does not propose cuts. It proposes the four **defects** the
re-measurement turned up — items that are wrong rather than expensive — and the
gate that stops the class from recurring. Total closure effect: **−5 crates on
macOS, 0 on Linux.** The value is correctness and a hole closed in the ratchet,
not the crate count.

## Measured baseline (2026-08-14, `37c38b93c`)

| Surface | Count | How measured |
|---|---|---|
| `mvmctl` default closure, `x86_64-unknown-linux-gnu` | **243** | `cargo tree -p mvmctl -e no-dev --target x86_64-unknown-linux-gnu` |
| `mvmctl` default closure, `aarch64-apple-darwin` | 238 | same, macOS target |
| `Cargo.lock` packages | 681 | not a metric — see Plan 309 Phase 4 |
| `cargo deny check bans` | **ok** | 4 stale-skip warnings, no failures |

`CLOSURE_BUDGET` is at 243 and the gate is green, so the ratchet is once again
**at its ceiling** — the condition Plan 309 was written to relieve. The four
items below buy no Linux headroom; Phase 5.5 addresses the ceiling directly.

### Unique ownership, re-measured (macOS default closure, version-qualified)

Counting by `name`+`version` rather than name alone, which is what exposes a
duplicated major:

| Dep | Uniquely owns | Production usage |
|---|---|---|
| `tracing-subscriber` | 8 | `RUST_LOG` + JSON signer logs — declined, P309 |
| `tree-sitter` + 4 grammars | 7 | *is* the SDK-to-Nix translation — declined, P309 |
| `hickory-proto` | 4 (`rand` 0.10, `chacha20`, `data-encoding`) | **3 files, all `cfg(linux)` — see 5.1** |
| `rustls-platform-verifier` | 4 | platform trust store — swapping for `webpki-roots` is a downgrade |
| `which` | 3 | 20 sites of PATH walk — declined, P309 |
| `globset` | 2 | 1 file, SDK source bundling |
| `keyring`, `sysinfo`, `lzma-rs`, `bs58`, `unicode-normalization` | 1 each | the −1 tail — declined, P309 |

---

## Phase 5 — the four defects

Each is a correction with no behaviour change, in the same class as Plan 309's
Phase 0 (`rtnetlink`, `schemars`, `thiserror = "1"`).

- [x] **5.1 — `hickory-proto` is unconditional but every consumer is
      `cfg(target_os = "linux")`.** `crates/mvm-hostd/Cargo.toml:138` declares
      `hickory-proto.workspace = true` in the plain `[dependencies]` table. Its
      only host consumer is `supervisor/raw_egress.rs`, where **all four
      imports (lines 25–31) and all five consuming functions
      (`build_dns_query`, `encode_dns_message`, `decode_dns_message`,
      `parse_dns_response`, `query_upstreams`) carry
      `#[cfg(target_os = "linux")]`**. The `#[cfg(not(target_os = "linux"))]`
      arm at line 661 uses none of it, and `supervisor/hickory_dns.rs` (the
      `hickory-resolver` consumer) is already `#[cfg(feature = "custom-dns")]`.
      `mvm-agentd` already gates its own copy behind `addons`.

      So a macOS `mvmctl` compiles and links `hickory-proto` with **zero
      consumers**, and with it `rand` 0.10, `rand_core` 0.10, `chacha20`, and
      `data-encoding`.

      Fix: move the declaration into
      `[target.'cfg(target_os = "linux")'.dependencies]`, beside the
      `seccompiler`/`landlock` entries that already model this correctly.

      **Measured −6 on macOS (238 → 232); 0 on Linux.** It retires the shipped
      duplicate `rand` major on macOS along with `chacha20` and
      `data-encoding`.

      Narrower than this plan first claimed: `rand_core` 0.10 **stays** on
      macOS, reached through `aes-gcm` → `aead` → `crypto-common`. That is the
      RustCrypto 0.11 stack the sealed guest agent needs, which Plan 309's
      non-goals protect explicitly. So the duplicate `rand` is gone; the
      duplicate `rand_core` is not, and is not this plan's to remove.

      This does **not** re-open Plan 309 Phase 3's decline of `hickory-proto`.
      That decline was against *replacing* it with bespoke DNS parsing, which
      this does not do. The parser stays, on the platform that uses it.

      Verification: `cargo tree -p mvmctl -e no-dev --target
      aarch64-apple-darwin` loses exactly those five; `cargo zigbuild
      --target x86_64-unknown-linux-gnu` stays green; the `raw_egress` DNS
      tests are Linux-gated already and must stay green there.

- [x] **5.2 — `memchr` is a dead `[workspace.dependencies]` entry.**
      `Cargo.toml` declares it with a justification that is **factually
      false**: *"Already compiled into every host binary via globset ->
      aho-corasick, so a direct edge adds an import and no build cost. Used
      where a scan runs over a whole multi-megabyte artifact on the launch
      path."* No crate inherits it (`rg '^memchr' crates/*/Cargo.toml` → no
      matches) and there is not one `memchr::` reference in the tree. The
      quadratic-scan it claims to fix does not exist.

      This is the `rtnetlink` defect from Plan 309 Phase 0 exactly: a live
      workspace entry any crate can pick up by accident, carrying a comment
      that would survive review. Delete the entry and its comment.

      **0 crates** (`memchr` stays in the closure transitively via
      `aho-corasick`), one false claim removed.

- [x] **5.3 — 69 dependency declarations bypass `[workspace.dependencies]`.**
      Hardcoded versions across the member manifests, including three that
      duplicate a workspace-table entry verbatim (`async-trait = "0.1"` in
      `mvm-hostd`, `mvm-fs`, `mvm-runtime`; `rand = "0.8"` in `mvm-build`) and
      four `nix = "0.29"` copies.

      They agree with the table *today*, so nothing is duplicated right now.
      That is the whole problem: nothing holds them in agreement. This is the
      precise mechanism that produced Plan 309 Phase 0's `thiserror = "1"`
      bug — a member manifest pinned a major behind the workspace's back and
      compiled a second proc-macro into the shipped binary until someone
      noticed by hand.

      **Scope corrected during implementation — the original wording here was
      wrong and would have been destructive.** It said "convert every
      declaration that has a workspace-table counterpart". Only 17 of the 69
      have one, and **9 of those 17 are deliberate narrowings in
      `mvm-contract`**, which is `#![no_std]` + alloc and builds on
      `wasm32-unknown-unknown`. It declares `serde`, `serde_json`, `chrono`,
      `ipnet`, `base64`, `ed25519-dalek`, `sha2` and `thiserror` with
      `default-features = false` and `alloc` where the workspace table asks for
      `std`. Converting those to `.workspace = true` would enable `std` in a
      `no_std` crate and break the wasm target — and, through Cargo's
      workspace-wide feature unification, could leak `std` into `mvm-contract`
      for every consumer. `mvm-core`'s `rustls` entry is a narrowing too.

      Converted: only the **7 pins whose spec is byte-identical** to the table
      — `rand` (mvm-build), `async-trait` (mvm-fs, mvm-hostd, mvm-runtime),
      `tar` (mvm-cli, mvm-core), `tracing` (libkrun-sys). Pure redundancy, no
      resolution change.

      Left alone: the 9 `mvm-contract` narrowings, `mvm-core`'s `rustls`, and
      the 52 genuinely single-consumer deps (`virtio-queue`, `vm-memory`,
      `am-fs-ext4`, `wasmtime`, the four `nix` pins — the table has no `nix`
      entry at all), since hoisting a one-crate dep into the shared table is
      its own smell.

      The gate in 5.5 encodes exactly this rule: a differing **version
      requirement** is the bug; narrowing **features** at the same version is
      the intended escape hatch.

- [x] **5.4 — four stale entries in `deny.toml`'s `skip` list.**
      `cargo deny check bans` warns on `thiserror`, `thiserror-impl` (now
      single-version — Plan 309's write-up says it removed these; it did not),
      `which` (single-version), and `unicode-width` (not in the graph at all).
      Plan 309 additionally recorded nine stale `windows-*` entries as
      "found, not fixed".

      A stale skip is a hole, not clutter: it silently pre-authorizes a future
      duplicate of that exact crate.

      **Measured worse than the warnings first suggested: 18 of the 25 entries
      were stale.** Beyond the four warned at the time, the whole per-arch
      Windows shim family (`windows-targets` and nine `windows_<arch>_<abi>`
      crates) and the host-syscall group (`linux-raw-sys`, `mio`, `nix`,
      `redox_syscall`, `rustix`) had all converged to single versions. Seven
      entries survive and are real: `windows-core`, `windows-sys`, `bitflags`,
      `getrandom`, `rand`, `rand_core`, `vmm-sys-util`. `cargo deny check bans`
      is now warning-free.

**Phase 5 exit — achieved.** Linux closure unchanged at 243; macOS **238 → 232**
(one better than the projected 233). `cargo deny check bans` warning-free.

---

## Phase 5.5 — the gate that stops the class

The four defects above are three instances of one failure: **a dependency edge
that no gate can see.** A target-gated consumer with an unconditional manifest
edge (5.1), a workspace entry with no consumer (5.2), and a member pin that
shadows the workspace table (5.3) are all invisible to
`check-closure-budget`, which measures one target with default features and
therefore cannot observe any of them.

- [x] **`xtask check-workspace-dep-inheritance`** (new). Fails when a member
      manifest hardcodes a version for a crate that `[workspace.dependencies]`
      already names, and when a `[workspace.dependencies]` entry has no
      inheritor. Catches 5.2 and 5.3 permanently, and would have caught the
      `thiserror = "1"` bug at the commit that introduced it.

- [x] **Extend `check-closure-budget` to a second target.** The gate measures
      only `x86_64-unknown-linux-gnu`, which is why 5.1 survived: macOS is the
      primary contributor and HVF-workload platform, and its closure is
      currently ungated. Add an `aarch64-apple-darwin` budget alongside the
      existing one, ratcheted to the post-5.1 number.

      This is the item with the most durable value in the plan. Every
      macOS-only dependency regression to date has been unobservable.

- [x] **Verify each gate goes red.** Per the repo's standing rule, a gate that
      has not been proven to fail is not a gate: introduce the defect, confirm
      the failure, revert.

**Phase 5.5 exit — achieved.** Both gates run in `ci.yml`'s lint job, and all
three failure paths were demonstrated red and then restored:

| proof | gate | observed |
|---|---|---|
| `mvm-build` re-pins `thiserror = "1"` | inheritance | names the file, both requirements, and the fix |
| `memchr` re-added to the table | inheritance | reports it has no inheritor |
| `hickory-proto` re-declared unconditionally | closure budget | **macOS 238 over budget 232, while Linux stayed green at 243** |

The third proof is the plan's own thesis, executed: the defect is invisible to
the Linux budget and caught by the macOS one.

Writing the gate also surfaced a defect in itself. Its first run reported
`predicates` as a dead table entry; the root `Cargo.toml` is both the workspace
root *and* the `mvmctl` package, and its own `[dev-dependencies]` are the only
inheritors of several entries. Scanning members but not the root reported those
as dead. Fixed, with a regression test.

---

## Non-goals — deliberately not touched

Plan 309's non-goals carry over unchanged (`aes-gcm`/`x25519-dalek` in the
sealed guest, `clap`/`chrono`/`serde`/`flate2`/`rand`, `tree-sitter`,
`smoltcp`/`mio`/`socket2`, and the audited security primitives). Added here:

- **The Phase 3 decline table in Plan 309.** Independently re-measured and
  reproduced. Not re-opened.
- **`sysinfo`.** Worth one honest note that is *not* a crate-count argument:
  `crates/mvm-hostd/Cargo.toml:122` pins `sysinfo = "0.30"`, roughly three
  majors stale, for exactly two numbers (`refresh_memory` → total/available) in
  `supervisor/balloon.rs`. It is the oldest pinned dep in the graph. Cutting it
  is −1 and was declined; **upgrading** it is a maintenance question that
  belongs to whoever next touches the balloon, not to a dependency plan.
- **`Cargo.lock`'s 681 packages.** The raw count includes ~120 unreachable
  orphans and does not respond to real removals. Plan 309 Phase 4 proved this
  by dropping a dependency and re-resolving: 672 before, 672 after. It is not
  a metric and this plan does not report progress against it.

## Expected outcome

| Milestone | Linux | macOS | State |
|---|---|---|---|
| Baseline (Plan 309 exit) | 243 | 238 | — |
| Phase 5 | 243 | **232** | **landed** |
| Phase 5.5 | 243 | 232 | **landed** — two gates, no cut |

The honest summary: **−6 crates, on one platform.** The reason this plan was
worth landing is not the six. It is that three dependency edges and eighteen
stale duplicate-authorisations were invisible to every gate in the repo, and
after Phase 5.5 they are not.

The plan's own 5.3 is the cautionary note. As first written it would have
converted `mvm-contract`'s nine deliberate `no_std` narrowings to workspace
inheritance, enabling `std` in a `no_std` crate and breaking the wasm target —
a "hygiene" cleanup that would have been a genuine regression. Dependency
hygiene work fails in exactly this way: the mechanical rule is easy and the
exceptions are load-bearing.

# Plan 333: Dependency hygiene — four defects and a ratchet, not a cut

## Status

**Not started.** Successor to [Plan 309](309-dependency-reduction.md), whose
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

- [ ] **5.1 — `hickory-proto` is unconditional but every consumer is
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

      **−5 crates on macOS; 0 on Linux.** It also retires the shipped duplicate
      `rand` major on macOS — a second CSPRNG and a second `getrandom` shim
      compiled into a security product for nothing.

      This does **not** re-open Plan 309 Phase 3's decline of `hickory-proto`.
      That decline was against *replacing* it with bespoke DNS parsing, which
      this does not do. The parser stays, on the platform that uses it.

      Verification: `cargo tree -p mvmctl -e no-dev --target
      aarch64-apple-darwin` loses exactly those five; `cargo zigbuild
      --target x86_64-unknown-linux-gnu` stays green; the `raw_egress` DNS
      tests are Linux-gated already and must stay green there.

- [ ] **5.2 — `memchr` is a dead `[workspace.dependencies]` entry.**
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

- [ ] **5.3 — 69 dependency declarations bypass `[workspace.dependencies]`.**
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

      Fix: convert every declaration that has a workspace-table counterpart to
      `.workspace = true`; leave genuinely single-consumer deps
      (`virtio-queue`, `vm-memory`, `am-fs-ext4`, `wasmtime`) local, since
      hoisting a one-crate dep into the shared table is its own smell.

- [ ] **5.4 — four stale entries in `deny.toml`'s `skip` list.**
      `cargo deny check bans` warns on `thiserror`, `thiserror-impl` (now
      single-version — Plan 309's write-up says it removed these; it did not),
      `which` (single-version), and `unicode-width` (not in the graph at all).
      Plan 309 additionally recorded nine stale `windows-*` entries as
      "found, not fixed".

      A stale skip is a hole, not clutter: it silently pre-authorizes a future
      duplicate of that exact crate. Remove the four warned entries, re-check
      the nine `windows-*` ones, and prune whatever is stale.

**Phase 5 exit:** Linux closure unchanged at 243; macOS 238 → 233. `cargo deny
check bans` warning-free.

---

## Phase 5.5 — the gate that stops the class

The four defects above are three instances of one failure: **a dependency edge
that no gate can see.** A target-gated consumer with an unconditional manifest
edge (5.1), a workspace entry with no consumer (5.2), and a member pin that
shadows the workspace table (5.3) are all invisible to
`check-closure-budget`, which measures one target with default features and
therefore cannot observe any of them.

- [ ] **`xtask check-workspace-dep-inheritance`** (new). Fails when a member
      manifest hardcodes a version for a crate that `[workspace.dependencies]`
      already names, and when a `[workspace.dependencies]` entry has no
      inheritor. Catches 5.2 and 5.3 permanently, and would have caught the
      `thiserror = "1"` bug at the commit that introduced it.

- [ ] **Extend `check-closure-budget` to a second target.** The gate measures
      only `x86_64-unknown-linux-gnu`, which is why 5.1 survived: macOS is the
      primary contributor and HVF-workload platform, and its closure is
      currently ungated. Add an `aarch64-apple-darwin` budget alongside the
      existing one, ratcheted to the post-5.1 number.

      This is the item with the most durable value in the plan. Every
      macOS-only dependency regression to date has been unobservable.

- [ ] **Verify each gate goes red.** Per the repo's standing rule, a gate that
      has not been proven to fail is not a gate: introduce the defect, confirm
      the failure, revert.

**Phase 5.5 exit:** two new gates in the `Lint policy` job, each demonstrated
red.

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
| Phase 5 | 243 | **233** | planned |
| Phase 5.5 | 243 | 233 | two gates, no cut |

The honest summary: **−5 crates, on one platform.** The reason this plan is
worth landing is not the five. It is that three separate dependency edges were
invisible to every gate in the repo, and after Phase 5.5 they are not.

# Versioned Pack Cache + Lifecycle Facade + CLI (SP1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give the content-addressed pack cache a deterministic *active version* per pack class, plus `download`/`update`/`rollback`/`list`/`prune` operations exposed through the `mvmctl::core::pack_cache` facade and an `mvmctl pack` CLI group — so a new release is fetched+verified alongside the current one, promotion/rollback just move a pointer, and nothing is destructively overwritten.

**Architecture:** The cache already stores one dir per pack keyed by `pack_hash` and multiple versions coexist fine; the gap is that `resolve_pack` returns whichever `read_dir` hits first. SP1 adds a cache-side JSON **index** (`<cache>/packs/index.json`) recording each promoted pack's provenance (pack_hash, kind, arch, backend, channel, release version, promoted-at) plus an **active pointer** per `(kind, arch, backend)`. `resolve_pack` prefers the active pointer, falling back to today's scan. Version labels come from the *download context* (the release version in the asset URL), never a manifest change. This is Plan 213 SP1; design: `specs/notes/instant-first-use-pack-design.md`.

**Tech Stack:** Rust (edition 2024), `mvm-core` (`pack_cache`, `packs`), `mvm-cli` (clap commands).

## Global Constraints

- Edition **2024**. No `#[allow(clippy::too_many_arguments)]` in hand-written code — use a params struct/builder.
- No spec/plan/PR/ADR references in code comments (CI-gated: `Plan N`, `ADR-\d+`, `#NNNN`, `W\d.`).
- No `Co-Authored-By: Claude` trailer.
- **Never bypass verification**: an active pointer only ever resolves to a pack that re-verifies through the existing `PackVerifyCtx`; rollback only activates an already-cached, verified pack.
- **No manifest schema change** — version/provenance lives in the cache-side index, not `PackManifest`.
- `mvm-core` must stay runtime-free (no new `tokio`); the index is sync `std::fs` + `serde_json` (already a dep).
- Verification gate before "done": `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run -p mvm-core -p mvm-cli`, `cargo test --workspace --doc`.
- Work in worktree `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-pack-lifecycle` (branch `feat/plan-213-pack-lifecycle`).

## Scope

IN: the versioned-index + active-pointer primitive; `resolve_pack` preferring the active pointer; lifecycle facade (`record`/`set_active`/`list`/`version-aware prune`); the `mvmctl pack` CLI group; `download`/`update` wired for the **builder pack** (which already has release-fetch via `bootstrap.rs`), `list`/`rollback`/`prune` generic across all cached classes.

OUT (later sub-projects / follow-on): `download`/`update` for runtime + dev-image classes (their release-fetch isn't wired yet — `list`/`rollback` still cover them once present); the prepare phase + install.sh (SP2); the seed closure (SP3); the benchmark (SP4).

## File Structure

- `crates/mvm-core/src/pack_cache.rs` — **modify**: add the index types + read/write, extend `promote` to record provenance, add `set_active`/`get_active`/`list_versions`/`prune_versions`, make `resolve_pack` prefer the active pointer.
- `crates/mvm-core/src/pack_cache/index.rs` — **new** (child module): the `PackIndex` struct + pure load/mutate/save logic, unit-tested in isolation.
- `crates/mvm-cli/src/commands/pack/mod.rs` — **new**: `Args` + `PackAction` (Download/Update/Rollback/List/Prune) + `run()`.
- `crates/mvm-cli/src/commands/pack/{download,update,rollback,list,prune}.rs` — **new**: thin verb impls over the facade (mirrors `commands/image/`).
- `crates/mvm-cli/src/commands/mod.rs` — **modify**: add `Pack(pack::Args)` to `Commands`.
- `crates/mvm-cli/src/commands/dispatch.rs` — **modify**: add the `Commands::Pack(a) => pack::run(...)` arm.
- `crates/mvm-cli/src/commands/env/dev_vz/bootstrap.rs` — **modify**: `promote_staged_builder_pack` records the downloaded release version into the index.
- `crates/mvm-cli/src/commands/ops/cache.rs` — **modify**: add version-aware `prune_versions` to the `Prune` arm.

---

## Task 1: PackIndex primitive (types + pure load/mutate/save)

**Files:**
- Create: `crates/mvm-core/src/pack_cache/index.rs`
- Modify: `crates/mvm-core/src/pack_cache.rs` (add `mod index; pub use index::*;`)
- Test: inline `#[cfg(test)]` in `index.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct PackKey { pub kind: PackKind, pub arch: GuestArch, pub backend: PackBackend }
  pub struct PackEntry {
      pub pack_hash: Sha256Hex,
      pub key: PackKey,
      pub channel: String,          // trust.channel_identity
      pub release_version: String,  // from the download context (e.g. "v0.17.0")
      pub promoted_at_unix: u64,     // recency ordering
  }
  pub struct PackIndex { entries: Vec<PackEntry>, active: Vec<(PackKey, Sha256Hex)> }
  impl PackIndex {
      pub fn record(&mut self, e: PackEntry);                 // upsert by pack_hash; first record for a key sets active
      pub fn set_active(&mut self, key: &PackKey, hash: &Sha256Hex) -> bool; // false if hash not present for key
      pub fn active_for(&self, key: &PackKey) -> Option<&Sha256Hex>;
      pub fn versions_for(&self, key: &PackKey) -> Vec<&PackEntry>;   // newest promoted_at first
      pub fn remove(&mut self, hash: &Sha256Hex);            // drops entry + any active ref
      pub fn prunable(&self, keep_recent: usize) -> Vec<Sha256Hex>;   // per key: all but active + newest `keep_recent`
  }
  ```
  `PackKey`/`PackEntry`/`PackIndex` derive `Serialize, Deserialize, Clone, PartialEq, Debug` with `#[serde(deny_unknown_fields)]` on the wire types.

- [ ] **Step 1: Write the failing tests** — in `crates/mvm-core/src/pack_cache/index.rs`, define the types (above) and:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::GuestArch;
    use crate::packs::{PackBackend, PackKind};

    fn key() -> PackKey {
        PackKey { kind: PackKind::Builder, arch: GuestArch::Aarch64, backend: PackBackend::Any }
    }
    fn entry(hash: &str, ver: &str, at: u64) -> PackEntry {
        PackEntry { pack_hash: Sha256Hex::from_hex(hash).unwrap(), key: key(),
            channel: "stable".into(), release_version: ver.into(), promoted_at_unix: at }
    }

    #[test]
    fn first_record_becomes_active() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        assert_eq!(ix.active_for(&key()), Some(&Sha256Hex::from_hex(&"a".repeat(64)).unwrap()));
    }

    #[test]
    fn record_second_does_not_change_active_but_lists_both_newest_first() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        ix.record(entry(&"b".repeat(64), "v0.18.0", 20));
        assert_eq!(ix.active_for(&key()), Some(&Sha256Hex::from_hex(&"a".repeat(64)).unwrap()));
        let v = ix.versions_for(&key());
        assert_eq!(v[0].release_version, "v0.18.0"); // newest first
        assert_eq!(v[1].release_version, "v0.17.0");
    }

    #[test]
    fn set_active_rejects_unknown_hash() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        assert!(!ix.set_active(&key(), &Sha256Hex::from_hex(&"c".repeat(64)).unwrap()));
        assert!(ix.set_active(&key(), &Sha256Hex::from_hex(&"a".repeat(64)).unwrap()));
    }

    #[test]
    fn remove_drops_entry_and_active_ref() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        ix.remove(&Sha256Hex::from_hex(&"a".repeat(64)).unwrap());
        assert_eq!(ix.active_for(&key()), None);
        assert!(ix.versions_for(&key()).is_empty());
    }

    #[test]
    fn prunable_keeps_active_and_newest_n() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10)); // active
        ix.record(entry(&"b".repeat(64), "v0.18.0", 20));
        ix.record(entry(&"c".repeat(64), "v0.19.0", 30));
        // keep active (a) + newest 1 (c) -> b is prunable
        let p = ix.prunable(1);
        assert_eq!(p, vec![Sha256Hex::from_hex(&"b".repeat(64)).unwrap()]);
    }

    #[test]
    fn json_roundtrip_denies_unknown_fields() {
        let mut ix = PackIndex::default();
        ix.record(entry(&"a".repeat(64), "v0.17.0", 10));
        let s = serde_json::to_string(&ix).unwrap();
        let back: PackIndex = serde_json::from_str(&s).unwrap();
        assert_eq!(ix, back);
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p mvm-core --lib pack_cache::index 2>&1 | tail -15`
Expected: compile errors — types/methods not defined.

- [ ] **Step 3: Implement the types + methods** in `index.rs`. `record` upserts by `pack_hash` and, if the key has no active entry yet, sets it active. `versions_for` sorts by `promoted_at_unix` desc. `prunable` returns, per key, every hash except the active one and the newest `keep_recent` by `promoted_at_unix`. Use `Sha256Hex` and the `PackKind`/`PackBackend`/`GuestArch` enums from `crate::packs`/`crate::ids` (confirm exact paths first with `rg`). Add `mod index; pub use index::{PackIndex, PackEntry, PackKey};` to `pack_cache.rs`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p mvm-core --lib pack_cache::index 2>&1 | tail -15`
Expected: all 6 PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-pack-lifecycle
git add crates/mvm-core/src/pack_cache/index.rs crates/mvm-core/src/pack_cache.rs
git commit -m "feat(pack-cache): add versioned index + active-pointer primitive"
```

---

## Task 2: Persist the index + make resolve_pack prefer the active pointer

**Files:**
- Modify: `crates/mvm-core/src/pack_cache.rs`
- Test: inline `#[cfg(test)]` in `pack_cache.rs`

**Interfaces:**
- Consumes: Task 1's `PackIndex`.
- Produces:
  ```rust
  fn index_path(cache_root: &Path) -> PathBuf;                 // <cache>/packs/index.json
  fn load_index(cache_root: &Path) -> PackIndex;               // missing/corrupt -> default (fail-open)
  fn save_index(cache_root: &Path, ix: &PackIndex) -> Result<(), PackCacheError>; // temp+rename atomic
  ```
  `resolve_pack` gains active-pointer preference; signature unchanged.

- [ ] **Step 1: Write failing tests** (append to `pack_cache.rs` tests): promote two builder packs, `save_index` with `b` active, assert `resolve_pack` returns `b` (not scan-order `a`); then a test that with no index present `resolve_pack` still returns a compatible pack (fallback); then a test that if the active pack dir is corrupt, `resolve_pack` falls back to another verified entry.

```rust
    #[test]
    fn resolve_prefers_active_pointer_over_scan_order() {
        let tmp = tempfile::tempdir().unwrap();
        // promote two compatible builder packs (reuse the existing test helper
        // that builds+promotes a pack; see resolve_pack_returns_compatible_promoted_pack)
        let (a, b) = promote_two_builder_packs(tmp.path());
        let mut ix = load_index(tmp.path());
        ix.record(entry_for(&a)); ix.record(entry_for(&b));
        assert!(ix.set_active(&key_for(&b), &b.pack_hash()));
        save_index(tmp.path(), &ix).unwrap();
        let got = resolve_pack(PackKind::Builder, arch, backend, &ctx(tmp.path())).unwrap().unwrap();
        assert_eq!(got.pack_hash(), b.pack_hash());
    }

    #[test]
    fn resolve_falls_back_to_scan_when_no_index() { /* no save_index; assert Some(compatible) */ }

    #[test]
    fn resolve_falls_back_when_active_pack_is_corrupt() { /* corrupt b's sidecar, active=b; assert returns a */ }
```
(Use/extend the existing promote-a-pack test scaffolding already in `pack_cache.rs` — do not invent a second harness.)

- [ ] **Step 2: Run to verify fail** — `cargo test -p mvm-core --lib pack_cache 2>&1 | tail -20` → the new tests fail (active preference not implemented).

- [ ] **Step 3: Implement.** Add `index_path`/`load_index` (missing or `serde_json` error → `PackIndex::default()`, log nothing/fail-open)/`save_index` (write to `index.json.tmp`, `rename`). In `resolve_pack`, before the scan: `let ix = load_index(&cache_root); if let Some(h) = ix.active_for(&PackKey{kind,arch,backend}) { if let Some(dir) = verified_pack_dir_for_hash(h, ...) { return Ok(Some(dir)); } }` then fall through to the existing scan. Factor the "verify one pack dir by hash" step out of the existing scan loop so both paths share it (DRY).

- [ ] **Step 4: Run to verify pass** — all `pack_cache` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/pack_cache.rs
git commit -m "feat(pack-cache): persist index; resolve_pack prefers the active version"
```

---

## Task 3: Lifecycle facade (record on promote, set_active, list, version-aware prune)

**Files:**
- Modify: `crates/mvm-core/src/pack_cache.rs`
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces (public facade, reachable as `mvmctl::core::pack_cache::*`):
  ```rust
  pub struct PackProvenanceInput { pub channel: String, pub release_version: String, pub promoted_at_unix: u64 }
  /// Promote (verify+place) AND record into the index. Wraps `promote`.
  pub fn promote_and_record(staged_root: &Path, manifest: &PackManifest, prov: &PackProvenanceInput, ctx: &PackVerifyCtx) -> Result<VerifiedPackDir, PackCacheError>;
  pub fn set_active_version(cache_root: &Path, key: &PackKey, hash: &Sha256Hex) -> Result<(), PackCacheError>; // err if hash not in index for key
  pub fn list_versions(cache_root: &Path, filter: Option<PackKind>) -> Result<Vec<PackEntry>, PackCacheError>; // active-flagged via a returned wrapper or side map
  pub fn prune_versions(cache_root: &Path, keep_recent: usize, dry_run: bool) -> Result<Vec<Sha256Hex>, PackCacheError>; // never removes an active hash; deletes pack dir + index entry
  ```
- [ ] **Step 1: Write failing tests** — `promote_and_record` makes the pack resolvable AND appears in `list_versions`; `set_active_version` errors on an unknown hash and switches resolution when valid; `prune_versions(keep_recent=1)` removes the oldest non-active pack dir + its index entry but never the active one, and `dry_run=true` removes nothing.

- [ ] **Step 2: Run to verify fail** — methods undefined.

- [ ] **Step 3: Implement** by composing Task 1/2 primitives with the existing `promote`/`pack_dir`/`remove_pack_dir` helpers. `prune_versions` computes `load_index(...).prunable(keep_recent)`, and for each hash (unless `dry_run`) removes the pack dir and the index entry, then `save_index`. Reuse the existing dir-removal helper the current `prune_expired_packs` uses — do not duplicate it.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/pack_cache.rs
git commit -m "feat(pack-cache): lifecycle facade — record/set_active/list/prune_versions"
```

---

## Task 4: `mvmctl pack` CLI group (list/rollback/prune + builder download/update)

**Files:**
- Create: `crates/mvm-cli/src/commands/pack/mod.rs` + `{list,rollback,prune,download,update}.rs`
- Modify: `crates/mvm-cli/src/commands/mod.rs` (add `Pack(pack::Args)` to `Commands`, with a `display_order`), `crates/mvm-cli/src/commands/dispatch.rs` (add the arm)
- Test: `crates/mvm-cli/tests/cli.rs` (help/arg-parse smoke, following existing patterns)

**Interfaces:**
- Consumes: Task 3 facade.
- Produces the clap group (mirror `commands/image/mod.rs`):
  ```rust
  #[derive(clap::Args)] pub struct Args { #[command(subcommand)] pub action: PackAction }
  #[derive(clap::Subcommand)] pub enum PackAction {
      List  { #[arg(long)] kind: Option<PackKindArg>, #[arg(long)] json: bool },
      Rollback { kind: PackKindArg, #[arg(long)] to: Option<String> }, // to = release_version or pack_hash prefix
      Prune { #[arg(long, default_value_t = 2)] keep_recent: usize, #[arg(long)] dry_run: bool, #[arg(long)] json: bool },
      Download { kind: PackKindArg, #[arg(long)] version: Option<String> },
      Update { kind: PackKindArg },
  }
  pub fn run(cli: &Cli, args: Args, cfg: &UserConfig) -> Result<()>;
  ```
  `PackKindArg` is a clap `ValueEnum` (`builder`/`runtime`/`dev-image`) mapping to `PackKind`.

- [ ] **Step 1: Write the failing CLI test** in `tests/cli.rs`: assert `mvmctl pack --help` lists `list`/`rollback`/`prune`/`download`/`update`, and `mvmctl pack list --json` parses (following the existing `image --help` test pattern in that file).

- [ ] **Step 2: Run to verify fail** — `cargo test -p mvm-cli --test cli pack 2>&1 | tail` → command unknown.

- [ ] **Step 3: Implement** the module (mirror `commands/image/`): `mod.rs` declares `Args`/`PackAction`/`run` dispatching to the five submodules. `list` calls `pack_cache::list_versions` + renders a table/JSON (model on `ops/cache.rs::cache status`, which already formats `PackCacheEntry`), marking the active version. `rollback` resolves `--to` (a `release_version` or `pack_hash` prefix) against `list_versions`, then `set_active_version`. `prune` calls `prune_versions`. `download`/`update`: for `kind=builder`, reuse the existing `bootstrap.rs` release fetch (`fetch_release_builder_pack_staging` + `promote_and_record`); for `runtime`/`dev-image`, return a clear "not yet fetchable — <class> release-fetch is not wired" error (do NOT stub silently). Add `Pack(pack::Args)` to `Commands` (with `display_order`) and the `dispatch.rs` arm.

- [ ] **Step 4: Run to verify pass** — `cargo test -p mvm-cli --test cli pack` PASS; `cargo run -- pack --help` shows the group.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/pack crates/mvm-cli/src/commands/mod.rs crates/mvm-cli/src/commands/dispatch.rs crates/mvm-cli/tests/cli.rs
git commit -m "feat(cli): mvmctl pack — list/rollback/prune/download/update"
```

---

## Task 5: Record versions on the builder-pack download path + version-aware cache prune

**Files:**
- Modify: `crates/mvm-cli/src/commands/env/dev_vz/bootstrap.rs` (`promote_staged_builder_pack`)
- Modify: `crates/mvm-cli/src/commands/ops/cache.rs` (the `Prune` arm)
- Test: inline where feasible + a `pack_cache` integration test

**Interfaces:**
- Consumes: Task 3 facade.

- [ ] **Step 1: Write the failing test** — a `pack_cache` test asserting that after `promote_and_record` for a builder pack labelled `v0.17.0`, `list_versions(Some(Builder))` reports that version and it is active; and a `cache.rs`-level assertion (unit, on the pure retention decision) that `prune_versions(keep_recent=2)` is invoked by the prune path (extract the retention call so it's unit-testable, per the repo's "small testable units" rule).

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** In `promote_staged_builder_pack`, replace the bare `pack_cache::promote(...)` with `promote_and_record(..., &PackProvenanceInput { channel: manifest.trust.channel_identity.clone(), release_version: <the version used to build the fetch URL>, promoted_at_unix: <now, passed in — do not call Date::now() in mvm-core; compute at the mvm-cli call site> }, ...)`. In `ops/cache.rs::Prune`, after the existing `prune_expired_packs` call, add `pack_cache::prune_versions(&cache_root, keep_recent, dry_run)?`, honoring the arm's `dry_run`/`--deep` conventions and emitting the same `audit_emit!(CachePrune, ...)` shape.

- [ ] **Step 4: Run to verify pass** — `cargo nextest run -p mvm-core -p mvm-cli -E 'test(pack)'`.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/env/dev_vz/bootstrap.rs crates/mvm-cli/src/commands/ops/cache.rs
git commit -m "feat: record builder-pack version on download; version-aware cache prune"
```

---

## Self-Review

- **Spec coverage:** versioned index + active pointer → T1/T2; resolve prefers active → T2; lifecycle facade (record/set_active/list/prune) → T3; CLI group → T4; builder download/update wired + version-aware prune + provenance recording → T4/T5; runtime/dev-image download explicitly errors (not stubbed) → T4; verification never bypassed (active resolves only through `PackVerifyCtx`, fallback on corrupt) → T2; no manifest change (index-side versions) → T1/T5.
- **Type consistency:** `PackKey`/`PackEntry`/`PackIndex` names identical across T1–T5; `promote_and_record`/`set_active_version`/`list_versions`/`prune_versions` signatures fixed in T3 and consumed unchanged in T4/T5; `promoted_at_unix` computed at the mvm-cli call site (mvm-core stays clock-free).
- **No placeholders:** runtime/dev-image download returns an explicit error, not a silent stub.

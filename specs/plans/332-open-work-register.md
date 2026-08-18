# Plan 332 — Open work register

Backing: preview
Validation: none

**Status:** OPEN — opened 2026-08-14
**Supersedes as tracker:** the GitHub issue tracker, which is now empty by decision

## Why this exists

The issue tracker and the plans were carrying the same work twice. Most open
issues were phase-trackers for a plan that already had the same items as
checkboxes, so an issue closing meant nothing until the plan agreed, and the
plan moving meant nothing until someone remembered the issue. Two ledgers that
must agree and are updated by different people is a reconciliation cost with no
corresponding benefit.

The decision is that **the plans are the ledger**. This register carries the
work that had no plan of its own; everything else already lives in the plan
named beside it in `specs/plans/300-open-issue-closeout.md`.

Nothing here is complete. Closing an issue moved its requirements; it did not
satisfy them. Every item below is open work with its acceptance criteria intact,
carried verbatim from the issue it came from so the closure loses nothing.

## Ordering

**A first, and soon.** It is a confirmed production defect on the credential
path, it is small, and the codebase already contains the correct shape at two
other call sites to copy. **B is release-blocking** the moment a tag is cut.
The rest are unordered.

---

## A — Production egress accept loops exit permanently on transient errors

*From #2485. Confirmed by audit 2026-08-14.*

Five production accept loops on the egress path give up permanently on any
`accept(2)` error — each is `Err(e) => { warn!(...); return; }`:

| Location | Loop |
|---|---|
| `mvm-hostd/src/supervisor/network_endpoint_proxy.rs:791` | UDS substitution (Firecracker / libkrun) |
| `mvm-hostd/src/supervisor/network_endpoint_proxy.rs:812` | vsock substitution (QEMU) |
| `mvm-hostd/src/supervisor/network_endpoint_proxy.rs:863` | transparent egress terminator |
| `mvm-hostd/src/supervisor/raw_egress.rs:77` | raw egress UDS |
| `mvm-hostd/src/supervisor/raw_egress.rs:279` | raw egress vsock |

`accept(2)` fails transiently in normal operation — `ECONNABORTED` (peer went
away between SYN and accept), `EMFILE`/`ENFILE` (fd pressure), `EINTR`,
`ENOBUFS`. Any one ends that VM's accept loop for the life of the VM. The
endpoint process stays up, so nothing crashes and nothing is audited: **the
workload silently stops reaching the network.** On the two substitution loops
that is the credential path.

`mvm-hostd/src/stream/serve.rs:182` and `supervisor/gateway_audit.rs:121`
already log, back off, and continue. These five are the divergence.

- [ ] One shared accept-error classifier plus bounded backoff, applied to all
      five loops rather than five separate edits.
- [ ] Transient (`ECONNABORTED`, `EINTR`, `EMFILE`, `ENFILE`, `ENOBUFS`,
      `WouldBlock`) → warn, back off, continue.
- [ ] Fatal (`EBADF`, `ENOTSOCK`, `EINVAL` — the listener itself is broken, so
      retrying is an infinite hot spin) → warn and return, as today.
- [ ] Give up after N consecutive transient failures and make **that** the
      observable outcome, so "this VM's egress is gone" cannot be silent.
- [ ] Unit-test the classifier against the error table.
- [ ] Regression test: an injected `ECONNABORTED` does not end the loop; the
      next connection is still accepted.

Note for whoever takes this: `raw_egress.rs` is slated for deletion by Plan 316
Phase 3. It is live today, so it gets the fix; the fix dies with the file.

## B — Release verification requires `mvm-bridge`, a binary Plan 305 deleted

*From #2497. Release-blocking.*

`nix/packaging/release/verify-release-assets.sh` lists `mvm-bridge` as a
**required** asset for every target, but no `[[bin]]` declares it anywhere in
the workspace and the release workflow's build and staging steps do not produce
it. **The next tagged release fails asset verification on every target.**

CI never caught it because `verify-release-assets.test.sh` carries its own
stale copy of the same list, and `build_valid_fixture` manufactures whatever
that names — so the fixture creates an `mvm-bridge` file and the gate passes.
Both lists were stale in lockstep; no amount of fixture testing could catch it.

- [ ] Remove `mvm-bridge` from `verify-release-assets.sh` for every target.
- [ ] Remove it from `verify-release-assets.test.sh`'s `bins_for()` — and make
      the two lists derive from one source, or the same lockstep staleness
      recurs.
- [ ] `install.sh` — codesign/install loop and its comment.
- [ ] `nix/packaging/homebrew/mvmctl.rb.tmpl` — the formula installs it.
- [ ] `public/src/content/docs/install/{macos,linux}.md` — `--bin mvm-bridge`
      instructions. These also name `mvm-substitution-endpoint`, which is not
      the binary's name either; it is `mvm-network-endpoint`.
- [ ] `CLAUDE.md` — lists `mvm-bridge` as a per-VM supervisor bin, and
      `supervisor/` as containing a `gateway_bridge/` module deleted with the
      gateway stack.
- [ ] `Cargo.toml` — two comments describing the deleted sidecar.

`public/docs/investigations/binary-size-baseline.md` also names it and is left
alone: it is a dated measurement record, and rewriting history is not the fix.

## C — Per-share path exclusion on virtio-fs shares

*From #2483. Belongs with Plan 298's share-slot work, not after it.*

`VirtioFsShare` carries no way to exclude paths inside a share. The moment a
user shares a project directory into an agent workload — the central use case
for share slots — `.env`, `.git/config`, `.aws/credentials`, `.npmrc` and
`id_rsa` go with it. `read_only` does not help, because **reading is the
attack**: the workload never needs to write those files, it needs to not see
them.

Claim 1 holds as written — the share is explicit — but the granularity is wrong
for how shares actually get used, and it undercuts what ADR-023 exists to
guarantee: we go to real lengths to keep a raw secret out of the guest on the
egress path, then hand over `.env` through a bind mount.

- [ ] Land **with** the fixed share slots (Plan 298 / former #2195), not after.
      Retrofitting an exclusion list onto a shipped slot model is materially
      worse: the deny set has to be part of what claim-time binding *binds*, or
      a slot can be re-bound later with a weaker set.
- [ ] Deny at the FUSE server, not in the guest.
- [ ] `do_lookup` returns `ENOENT` for a denied name — the guest must not learn
      the path exists.
- [ ] `readdir`/`readdirplus` filter denied entries out of the snapshot.
- [ ] create/rename/link return `EACCES`; rename checks **both** source and
      target, so a denied file cannot be moved out of the denied set.
- [ ] Pure component patterns (`.env`) fast-path on the name; patterns
      containing `/` need the parent-inode chain walked to reconstruct the
      relative path.

## D — Upstream/intercepting proxy on the host egress leg

*From #2482.*

On a host that force-tunnels outbound traffic through a corporate proxy, every
workload's egress fails and there is no knob. A locally-trusted interception CA
already works, because the forward leg builds its root store from
`rustls-native-certs`. An *upstream proxy* does not: `mvm-http` has no proxy
support and nothing reads `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY`.

Safe to add because the proxy sits **upstream of** the host-side decision
point, not between guest and host. The guest still has no NIC, egress still
leaves over vsock, and the shared `EgressGate` is still the sole claim-10
decision point.

- [ ] Read the proxy env vars on the host egress leg, with an explicit config
      override that wins over env.
- [ ] HTTP `CONNECT` upstream support in `mvm-http`.
- [ ] SOCKS5 upstream (SOCKS4 only if a concrete need appears).
- [ ] Audit records the true destination **plus** that a proxy was traversed —
      a proxied connection must not look like a direct one in the chain.
- [ ] `mvmctl doctor` reports the resolved proxy configuration.
- [ ] Tests: the policy decision precedes proxy selection; `NO_PROXY` cannot
      widen the allow-list; a denied destination stays denied with a proxy
      configured. **`NO_PROXY` must not become a second, weaker way to pick a
      destination.**

## E — Route the pure ext4 build to the builder VM on host-memory pressure

*From #2494.*

`materialize_ext4_pure` builds the whole rootfs in memory. The fallback to the
builder VM is gated on **structural** limits only — `TooLarge` is the ext4
ceiling of 16 TiB. Host RAM is nowhere in the decision, so a large but
structurally valid image builds entirely in memory and the failure mode is an
OOM kill or swap thrash rather than a clean route out of process.

Measured peak RSS (release, macOS, `ru_maxrss`), after #2490 removed a second
full copy: 256 MiB tree → 683 MiB; 512 MiB → 1,349 MiB; 1 GiB → 2,522 MiB.
Linear at ~2.5×, which is close to the floor for an in-memory build — so the
fix is to stop entering the path when it will not fit, not to shrink it.

- [ ] Estimate tree size before building; refuse into the existing fallback
      when the estimate does not fit comfortably in available host memory.
- [ ] Reuse the existing seam — return the capacity-limit classification
      callers already route on (`RootfsError::is_pure_capacity_limit`) — so
      `mvmctl` behaviour is unchanged apart from which builds go out of process.
- [ ] Decide where "available memory" comes from per platform. A fixed fraction
      of total RAM is more predictable than a live availability probe, which
      races other processes.
- [ ] Check `oci_to_rootfs::ext4`'s existing estimation machinery
      (`estimate_grows_with_file_count`) before writing new code.
- [ ] Re-measure the multiplier rather than hardcoding 2.5 from the issue; it
      drifts as the writer changes.

## F — Bound snapshot content-hashing cost without weakening verify-on-read

*From #2486.*

`SnapshotStore` hashes a whole directory as a deterministic manifest per
operation: O(full tree), and it does not shrink as a CoW chain grows. A child
differing from its parent by a handful of blocks pays the parent's full bill.
Fine at today's test sizes; not fine on the warm-claim path, where the whole
point is a p50 in the tens of milliseconds.

**Explicit anti-goal: do not resolve this by making payload integrity opt-in.**
Verify-on-read is claim-bearing — it is what makes `verify_content` +
`verify_lineage` a real gate rather than a label, and what makes a fork from a
tampered parent fail closed. A comparable open-source sandbox runtime hit this
same regression and has an open PR resolving it exactly that way. Read their
measurement; reject their resolution.

- [ ] Measure first — hashing cost as a function of tree size and chain depth,
      on the KVM box, before designing anything.
- [ ] Incremental/chunked manifest so an unchanged subtree is not rehashed.
- [ ] Hash reuse across a CoW chain: a child's manifest derives from the
      parent's plus its own delta, without re-walking shared content.
- [ ] Preserve determinism — the same tree must produce the same id regardless
      of which path computed it, or lineage verification breaks.
- [ ] Preserve fail-closed: a tampered parent still refuses the fork, with the
      coverage it has now.
- [ ] Confirm the claim path's hashing cost fits the warm-restore p50 SLO, or
      say plainly that it does not.

## G — Gate PRs on a cold-boot latency ceiling

*From #2484.*

No per-PR guard on launch latency, so regressions are found by hand months
late. The machinery exists and is unused by CI: `bench/regression.rs` has
`compare_to_baseline`, and it already returns `Incomparable` when the schema
version or the host descriptor differs, so a baseline from a different kernel
cannot produce a fake green or a fake red. Grepping the workflows for `bench`
turns up only `runtime_boot_bench` inside `ci-full.yml`, which is
`workflow_dispatch`-only.

Complementary to the warm-launch release gate (Plan 298): different cadence,
different path, both needed.

- [ ] A CI lane running the cold-launch bench on the KVM runner, calling
      `compare_to_baseline` against a checked-in baseline.
- [ ] Baseline per host descriptor; an `Incomparable` verdict **fails loudly**
      rather than passing silently — a skipped comparison must never read as a
      pass.
- [ ] Tolerance picked from observed run-to-run variance on the runner, not
      guessed; record the measurement that justified the number.
- [ ] A documented, reviewable re-baselining path after an intentional change,
      so the gate does not become something people route around.
- [ ] Wire into the PR-gating workflow, not `ci-full.yml`.

Nail down variance before choosing a threshold. **A gate that flakes gets
disabled, and a disabled gate is worse than none because it reads as covered.**
The runner is rotational-disk-backed — a known source of multi-hundred-ms
swings on fsync-heavy paths — so that must be inside the measured variance or
excluded from the measured span.

## H — Security lane mutation survivors

*From #2135, a generated tracker. The lane is red; these are the concrete
survivors from run 31817896244.*

- [ ] `mvm-cli` `commands/image/pull_core.rs:206:13` — replace `&&` with `||`
      in `pull_image_with_trust`. Claim-14 adjacent: this is the OCI trust
      path.
- [ ] `mvm-cli` `commands/shared/resolve.rs:12:8` — delete `!` in
      `resolve_running_vm`.
- [ ] `mvm-cli` `commands/shared/resolve.rs:97:9` — replace `||` with `&&` in
      `resolve_manifest_arg`.
- [ ] `mvm-core` `cpu_scope.rs:407:34` — replace `==` with `!=` in
      `enforced_grants_for_vm`.

The tracker is generated per failing run, so it re-files itself if the lane
stays red. Closing the stale one loses nothing; these four survivors are what
it actually contained.

## What this register does not carry

Everything already owned by a plan. See
`specs/plans/300-open-issue-closeout.md` for the mapping — Plan 316's phases,
Plan 298's warm-launch chain, Plan 299's performance evidence, Plan 306's
governance workstreams, and the agent/Studio surface all keep their existing
homes and their existing checkboxes.

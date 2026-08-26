//! `xtask check-closure-budget`
//!
//! Assert the **default** `mvmctl` binary closure stays within a committed
//! crate budget (a ratchet). Dependency weight is a first-class DX/security
//! goal: every crate in the default no-dev closure is code that ships in the
//! binary and is a supply-chain + attack-surface unit. This gate makes a *new*
//! default dependency a deliberate, reviewed choice rather than a silent
//! accretion.
//!
//! The closure is platform-sensitive (macOS pulls libkrun/objc2; Linux pulls
//! firecracker), so the gate pins explicit targets for a deterministic count
//! regardless of the host running it — `cargo tree --target` resolves without
//! building.
//!
//! **Both** shipped targets are budgeted. Measuring only Linux left the macOS
//! closure unobserved, and that is not a hypothetical gap: `mvm-hostd`
//! declared `hickory-proto` unconditionally while every consumer in
//! `supervisor/raw_egress.rs` was `cfg(target_os = "linux")`, so a macOS
//! `mvmctl` linked it — plus `rand` 0.10, `chacha20` and `data-encoding` —
//! with no consumer at all. A Linux-only gate cannot see that class of defect,
//! and macOS is the primary contributor and HVF-workload platform.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;

/// One budgeted target: the triple `cargo tree` resolves against, and the max
/// distinct crates allowed in `mvmctl`'s default no-dev closure there.
struct ClosureBudget {
    target: &'static str,
    max: usize,
}

/// Both shipped targets. Lower a budget freely as deps drop; raising one must
/// be justified in the change that does.
const BUDGETS: &[ClosureBudget] = &[
    ClosureBudget {
        target: "x86_64-unknown-linux-gnu",
        max: CLOSURE_BUDGET,
    },
    ClosureBudget {
        target: "aarch64-apple-darwin",
        max: MACOS_CLOSURE_BUDGET,
    },
];

/// Max distinct crates in the default no-dev closure on
/// `aarch64-apple-darwin`. Baseline measured 2026-08-14 after target-gating
/// `hickory-proto` to Linux, which took the macOS closure 238 -> 232 by
/// dropping `hickory-proto`, `rand` 0.10, `rand_core` 0.10's `rand` edge,
/// `chacha20` and `data-encoding`.
///
/// Lower than the Linux budget because the Firecracker/KVM stack
/// (`kvm-bindings`, `kvm-ioctls`, `vmm-sys-util`, `landlock`, `seccompiler`,
/// the netlink family) does not enter the macOS graph.
///
/// 233 (was 232): `mvm-observability`, the same +1 the Linux budget took —
/// a workspace crate holding subscriber assembly that `mvm-core` used to
/// own, carrying no new third-party code on either target.
///
/// 227 (was 233): deleting the superseded L3 stack removes seven crates from
/// this graph; the first-party `mvm-mcp` adapter adds one and no third-party
/// crates.
///
/// 228 (was 227): `mvm-capture`, the project-environment capture frontend. It
/// adds one first-party crate and no new third-party crate to mvmctl's closure.
///
/// 229 (was 228): the same compile-time `syn` 3 transition recorded for the
/// Linux closure below.
const MACOS_CLOSURE_BUDGET: usize = 229;

/// Max distinct crates allowed in `mvmctl`'s default no-dev closure on
/// `x86_64-unknown-linux-gnu`. Baseline measured 2026-06-17 against the audited default
/// closure. The Linux KVM backend adds one audited ioctl-wrapper crate to the
/// default Linux release path. Lower it freely as deps drop; raising it must be
/// justified in the change that does.
///
/// 271 (was 267): remeasured 2026-07-09 after the production-readiness
/// closeout branch; the vsock-only builder/runtime path now ships a slightly
/// larger audited default closure. Lower it freely as deps drop; raising it
/// must be justified in the change that does.
///
/// 263 (was 270): deleting the obsolete L3 egress stack removed seven crates
/// from the default closure.
///
/// 266 (was 263): the mandatory authenticated control session uses
/// `x25519-dalek` for ephemeral host↔guest key agreement; the three-crate
/// increase is the measured cost of keeping that security boundary in the
/// default control path.
///
/// 267 (was 266): consolidating the guest's three hand-rolled AF_VSOCK sites
/// onto one `nix::sys::socket` leaf enables nix's `socket` feature, whose lone
/// build-time transitive (`memoffset`, an `offset_of!` helper with no further
/// deps) enters the default Linux closure. That one crate is the cost of
/// deleting the hand-rolled `sockaddr_vm` + raw-`libc`
/// socket/connect/bind/listen/accept boilerplate — nix exposes no AF_VSOCK API
/// without the `socket` feature. Lower it freely as deps drop.
///
/// 268 (was 267): adopting the audited `vm-memory` crate behind the in-house
/// VMM's `GuestMem` seam (the accepted rust-vmm primitives migration). Only
/// `vm-memory` itself is new on the default closure — its `libc`/`thiserror`
/// tree is already present — so the measured delta is +1. Lower it freely as
/// deps drop.
///
/// 271 (was 268): adopting the audited `virtio-queue` crate for the in-house
/// VMM's virtio-vsock TX ring walk. The measured delta is +3 — `virtio-queue`,
/// its `virtio-bindings` binding crate, and `vmm-sys-util` 0.15 (the KVM path's
/// `vmm-sys-util` 0.12.1 stays, so the closure target counts both) — while
/// `vm-memory`/`log` are already present. Lower it freely as deps drop.
///
/// 270 (was 279): the Apple Container backend's pivot to kernel-on-HVF
/// removed the vminitd gRPC client (`prost`/`prost-types`/`h2`/`http`) and
/// their exclusive transitive set from the default closure. Lower it freely
/// as deps drop.
///
/// 273 (was 270): the Apple Container kernel digest-pin contract uses BLAKE3
/// for streamed multi-hundred-megabyte kernel verification. Its `blake3`
/// package and three small support crates are part of the default host binary.
///
/// 274 (was 273): the canonical `mvm-volume-contract` leaf is now the single
/// volume contract consumed by both mvm and fleet orchestrators; the leaf
/// itself is the only new crate in the default closure.
///
/// 275 (was 274): the exact-pinned, zero-dependency `leakguard` detector adds
/// one crate to enforce default-on credential masking on protected egress.
///
/// 274 (was 275): consolidating the protocol and volume contracts into the
/// feature-gated `mvm-contract` package removes one package from the default
/// closure while preserving the protocol-only default feature set.
///
/// 279 (was 274): adopting `rayon` for parallel file walks, copies, ext4
/// directory/symlink block emission, and dm-verity hash-tree computation;
/// measured delta +5 crates (rayon, rayon-core, crossbeam-deque,
/// crossbeam-epoch, crossbeam-utils).
///
/// 284 (was 283): the `did:key` codec for receipt/conformance identity uses
/// the audited `bs58` crate; it is zero-dependency and the only new crate in
/// the default closure.
///
/// 286 (was 285): splitting the concrete VMM backends out of `mvm-runtime`
/// into `mvm-backends`. Measured delta +1, and the new crate is our own
/// workspace member, not a third-party dependency — the same code, one crate
/// boundary further out.
///
/// 263 (was 286): the dependency-reduction pass, in five cuts and no product
/// change. Three were defects: `mvm-build` pinned `thiserror` at 1 while the
/// workspace was on 2 (a second copy plus its proc-macro), `rtnetlink` sat in
/// `[workspace.dependencies]` with no consumer and a CI gate banning it, and
/// `mvm-sdk` enabled `schemars` unconditionally — which, through workspace
/// feature unification, switched it on inside `mvm-contract` for every consumer
/// and defeated the `schema` gating in three crates. The other two were trades:
/// dropping rcgen's `x509-parser` feature (it existed only to re-parse a PEM we
/// had just serialized, and carried the whole ASN.1 stack including the
/// closure's last `nom` 7), and replacing `rayon` with an order-preserving
/// scoped-thread `par_map` in `mvm-fs`, which is all five call sites needed.
///
/// 262 (was 263): `fs2` existed only for `FileExt`'s advisory file locking,
/// which std stabilized in 1.89 — well under the pinned 1.97 toolchain. std
/// also splits contention out of the error type (`TryLockError::WouldBlock`
/// vs `::Error`), so "another process holds it" stops riding on an errno
/// comparison.
///
/// 242 (was 262): `reqwest` is gone. Its last caller was `mvm-hostd`'s egress
/// and SSRF-guarded fetch paths; with those on the in-house `mvm-http`, the
/// whole hyper/tower stack leaves — `hyper`, `hyper-util`, `hyper-rustls`,
/// `tower`, `tower-http`, `tower-service`, `http-body`, `http-body-util`, the
/// `futures-*` set, `sync_wrapper`, `want`, `try-lock`, `atomic-waker`, and
/// `slab`. `http`, `httparse`, `url`, `tokio-rustls`, and
/// `rustls-platform-verifier` stay, because `mvm-http` uses them rather than
/// hand-rolling header validation, head parsing, URL parsing, or trust-store
/// handling. Measured net −20.
///
/// 243 (was 242): `uuid`'s `v5` feature, for the TIBET decision-record export
/// reachable from `mvmctl ops audit --format tibet`. UUIDv5 is defined over
/// SHA-1, so it cannot reuse the workspace's `sha2`; the feature pulls exactly
/// one crate, `sha1_smol`, which is a leaf with no dependencies of its own.
/// Measured net +1.
/// 244 (was 243): the new first-party `mvm-observability` crate, which takes
/// the subscriber-assembly half of `mvm-core::observability` (`logging` +
/// the span-timing `Layer`). It carries no new third-party code —
/// `tracing-subscriber` was already in this closure via `mvm-core`, and is
/// now reached via `mvm-observability` instead. The point of the split is
/// the crates that do NOT install a subscriber: `mvm-core` 110 -> 101, and
/// the sealed guest agent `mvm-agentd` 111 -> 102 (its `tracing-subscriber`
/// is now gated behind `addons`, since only the helper bins install one).
/// Measured +1 here, -9 on the guest agent and the embedded musl bins.
///
/// 236 (was 239): deleting the superseded L3 stack removes its retired graph;
/// `mvm-mcp` contributes one first-party crate and no new third-party crate.
///
/// 237 (was 236): `mvm-capture`, the project-environment capture frontend. It
/// adds one first-party crate and no new third-party crate to mvmctl's closure.
///
/// 238 (was 237): `async-trait` 0.1.92 removes a generated attribute rejected
/// by current nightly Clippy and moves its compile-time parser to `syn` 3.
pub(crate) const CLOSURE_BUDGET: usize = 238;

pub fn run(workspace: &Path) -> Result<()> {
    for budget in BUDGETS {
        check_one(workspace, budget)?;
    }
    Ok(())
}

fn check_one(workspace: &Path, budget: &ClosureBudget) -> Result<()> {
    let ClosureBudget { target, max } = *budget;
    let count = default_closure_crate_count(workspace, target)?;
    if count > max {
        bail!(
            "check-closure-budget: mvmctl's default {target} closure is {count} crates, \
             over the budget of {max} — a new dependency entered the default binary. \
             Drop it, gate it behind an off-by-default feature (or a \
             `[target.'cfg(...)'.dependencies]` table if it is platform-specific), or, if it \
             is genuinely required, bump the budget in xtask/src/check_closure_budget.rs with \
             a one-line justification in the PR."
        );
    }
    if count < max {
        eprintln!(
            "check-closure-budget: {target} {count} crates (budget {max}); deps dropped — \
             ratchet the budget down to {count}."
        );
    } else {
        eprintln!("check-closure-budget: {target} {count} crates (at budget {max})");
    }
    Ok(())
}

fn default_closure_crate_count(workspace: &Path, target: &str) -> Result<usize> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(&cargo)
        .current_dir(workspace)
        .args([
            "tree", "-p", "mvmctl", "-e", "no-dev", "--prefix", "none", "--locked", "--target",
            target,
        ])
        .output()
        .context("running `cargo tree -p mvmctl -e no-dev --target ...`")?;
    if !output.status.success() {
        bail!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(unique_crate_count(&String::from_utf8_lossy(&output.stdout)))
}

/// Count distinct crates in `cargo tree --prefix none` output. Each non-empty
/// line begins with `name vX.Y.Z`; a crate recurs across the tree (and a
/// repeated subtree is marked `(*)`), so dedup by `(name, version)` to count
/// each compiled crate once. Two majors of the same crate count as two — they
/// are two compilations in the binary.
fn unique_crate_count(tree: &str) -> usize {
    let mut crates: Vec<(&str, &str)> = tree
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let name = it.next()?;
            let version = it.next().unwrap_or("");
            Some((name, version))
        })
        .collect();
    crates.sort_unstable();
    crates.dedup();
    crates.len()
}

#[cfg(test)]
mod tests {
    use super::unique_crate_count;

    #[test]
    fn counts_distinct_name_version_pairs() {
        let tree = "mvmctl v0.16.1\nserde v1.0.0\nanyhow v1.0.99\nserde v1.0.0\n";
        // serde appears twice but is one crate.
        assert_eq!(unique_crate_count(tree), 3);
    }

    #[test]
    fn two_majors_count_as_two() {
        let tree = "mvmctl v0.16.1\nbitflags v1.3.2\nbitflags v2.6.0\n";
        assert_eq!(unique_crate_count(tree), 3);
    }

    #[test]
    fn repeated_subtree_marker_is_ignored() {
        // `cargo tree` marks a repeated subtree with a trailing `(*)`.
        let tree = "mvmctl v0.16.1\nserde v1.0.0\nserde v1.0.0 (*)\n";
        assert_eq!(unique_crate_count(tree), 2);
    }

    #[test]
    fn blank_lines_are_skipped() {
        let tree = "mvmctl v0.16.1\n\nserde v1.0.0\n\n";
        assert_eq!(unique_crate_count(tree), 2);
    }
}

//! `check-declared-backing` — claim-bearing prose must declare what backs it.
//!
//! # Why this exists
//!
//! `check-doc-claims` scans only `public/` and the root `README.md`, by
//! design: those are user-facing. `specs/`, `CLAUDE.md`, and `AGENTS.md` are
//! contributor-facing and were deliberately excluded — and that exclusion is
//! the hole several fabricated witness names lived in for months. Nothing
//! asked those files what backed them.
//!
//! The fix is not to point a phrase lint at contributor prose. It is to make
//! each claim-bearing file declare its own evidence class, so a reader can
//! tell a shipped guarantee from a design sketch without reading the code.
//!
//! # The four rules
//!
//! 1. The header block is present, and both values parse.
//! 2. A `Validation:` naming a witness resolves to something that exists.
//!    This reuses the citation resolver rather than growing a second one —
//!    two resolvers drift, and the drift is invisible until one of them is
//!    wrong.
//! 3. **One-way citation.** A `shipped-source` file may not rest on a
//!    `preview` one. This is the rule that stops a preview claim laundering
//!    itself into a shipped guarantee by being cited from a stronger file.
//! 4. A `preview` file may not use the assertive vocabulary `check-honesty`
//!    already enumerates. "Proves" and "guarantees" are not available to a
//!    document whose own header says it is a preview.
//!
//! # The shrinking backlog
//!
//! Annotating every file at once would mean judging ~150 documents in one
//! pass, and the cheap way to do that is to stamp them all `shipped-source`.
//! That is precisely the dishonesty this gate exists to prevent, so instead
//! un-annotated files are enumerated in [`PENDING`] with the intended end
//! state stated: **the list only shrinks**. A file removed from it must carry
//! a real header, and nothing may be added.

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Evidence classes, weakest to strongest in the sense rule 3 cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Backing {
    /// A record of something that was true once; not a current claim.
    Historical,
    /// A design or proposal. Not yet enforced by anything.
    Preview,
    /// Generated from another artifact; correct if the generator is.
    Generated,
    /// Backed by an example that is executed in CI.
    CheckedExample,
    /// Backed by shipped source with a named witness.
    ShippedSource,
}

impl Backing {
    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "historical" => Some(Self::Historical),
            "preview" => Some(Self::Preview),
            "generated" => Some(Self::Generated),
            "checked-example" => Some(Self::CheckedExample),
            "shipped-source" => Some(Self::ShippedSource),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Historical => "historical",
            Self::Preview => "preview",
            Self::Generated => "generated",
            Self::CheckedExample => "checked-example",
            Self::ShippedSource => "shipped-source",
        }
    }
}

/// The assertive vocabulary a `preview` file may not use. Mirrors
/// `check_honesty::ASSERTIVE`; kept as its own list because that one is
/// private and because widening this one is a separate decision.
const ASSERTIVE: &[&str] = &[
    "proves",
    "proven",
    "proof that",
    "guarantees",
    "establishes",
    "demonstrates that",
    "shows that",
    "confirms",
];

/// Files that must carry a header today. Everything under the scanned roots
/// that is not here and not in [`PENDING`] is an error, so a *new* file
/// cannot quietly skip the rule.
const SCANNED_ROOTS: &[&str] = &["specs/adrs", "specs/plans"];

/// Root-level files in scope.
const SCANNED_FILES: &[&str] = &["CLAUDE.md", "AGENTS.md"];

/// **This list only shrinks.**
///
/// Every entry is a file that predates the gate and has not been assessed. A
/// file leaves by gaining a real header; nothing may be added. The gate fails
/// if an entry names a file that no longer exists, so the list cannot rot into
/// a set of stale names that quietly permits nothing.
const PENDING: &[&str] = &[
    "specs/adrs/002-local-mcp-server.md",
    "specs/adrs/003-hypervisor-egress-policy.md",
    "specs/adrs/004-sealed-signed-builder-image.md",
    "specs/adrs/005-function-call-entrypoints.md",
    "specs/adrs/006-mvm-provider-cli-contract.md",
    "specs/adrs/007-vmbackend-single-trait.md",
    "specs/adrs/008-iroh-aware-encryption-layering.md",
    "specs/adrs/009-cross-platform-strategy.md",
    "specs/adrs/010-code-quality-enforcement.md",
    "specs/adrs/011-feature-flag-taxonomy.md",
    "specs/adrs/012-ci-execution-policy.md",
    "specs/adrs/013-usage-billing-model.md",
    "specs/adrs/014-signed-audited-execution-plans.md",
    "specs/adrs/015-hostd-protocol-versioning.md",
    "specs/adrs/016-hermetic-vm-lifecycle-testing.md",
    "specs/adrs/017-oci-image-verity-posture.md",
    "specs/adrs/018-mvm-runtime-overlay-disk.md",
    "specs/adrs/019-guest-protocol-versioning-and-readiness.md",
    "specs/adrs/020-host-services-broker.md",
    "specs/adrs/021-pid0-portability-boundary.md",
    "specs/adrs/022-target-architecture.md",
    "specs/adrs/023-secrets-subsystem-egress-substitution.md",
    "specs/adrs/024-wasm-sandbox-backend.md",
    "specs/adrs/025-warm-snapshot-prior-art-adoption-boundary.md",
    "specs/adrs/026-rootless-guest-runtime.md",
    "specs/adrs/027-cli-surface-consolidation.md",
    "specs/adrs/028-relocatable-dependency-free-host-bundle.md",
    "specs/adrs/029-gpu-posture.md",
    "specs/adrs/030-libkrun-pivot.md",
    "specs/adrs/031-serialization-crypto-storage-selection.md",
    "specs/adrs/032-egress-connect-completion-and-in-seam-dns.md",
    "specs/adrs/033-rust-vmm-virtio-primitives.md",
    "specs/adrs/034-docker-dev-tier-backend.md",
    "specs/adrs/035-workload-stream-plane.md",
    "specs/adrs/036-l3-tun-over-vsock.md",
    "specs/adrs/037-mvmd-only-production-launch.md",
    "specs/adrs/052-userspace-socket-datapath.md",
    "specs/adrs/038-ipv6-support.md",
    "specs/adrs/039-macos-network-helper.md",
    "specs/adrs/040-node-to-node-transport.md",
    "specs/adrs/041-node-control-api.md",
    "specs/adrs/042-single-flow-vsock-networking.md",
    "specs/plans/13-ws11-wasm-egress-poc.md",
    "specs/plans/2167-agent-session-contract.md",
    "specs/plans/2168-runtime-approval.md",
    "specs/plans/2170-typed-capability-bindings.md",
    "specs/plans/253-sdk-split-and-selective-release.md",
    "specs/plans/254-admitted-egress-connect-completion.md",
    "specs/plans/254-control-data-plane-hardening.md",
    "specs/plans/255-live-fc-warm-claim.md",
    "specs/plans/255-phase2-warm-pool-substrate.md",
    "specs/plans/255-vsock-first-snapshot-egress-adoption.md",
    "specs/plans/256-admitted-egress-connect-completion.md",
    "specs/plans/257-in-seam-dns-resolver.md",
    "specs/plans/258-uniform-vsock-egress-convergence.md",
    "specs/plans/259-userspace-socks5-udp-vsock.md",
    "specs/plans/261-faithful-flake-image-revert.md",
    "specs/plans/262-kernel-pin-bump.md",
    "specs/plans/264-workload-lifetime-firewall-key.md",
    "specs/plans/265-fast-start-slo-sequencing-positioning.md",
    "specs/plans/266-lightweight-microvm-guest.md",
    "specs/plans/266-vsock-overload-hardening.md",
    "specs/plans/267-instant-loop-interaction-latency-gate.md",
    "specs/plans/268-nonnested-aarch64-machine-run-witness.md",
    "specs/plans/269-backend-shim-removal-prompt.md",
    "specs/plans/269-backend-shim-removal.md",
    "specs/plans/270-universal-initramfs-vsock-activated-boot.md",
    "specs/plans/271-apple-container-backend.md",
    "specs/plans/272-mutation-tested-claim-witnesses.md",
    "specs/plans/273-sdk-sidecar-release-acquisition.md",
    "specs/plans/274-witness-rigor.md",
    "specs/plans/276-content-addressing-conformance-and-defense.md",
    "specs/plans/277-release-artifact-signature-verification.md",
    "specs/plans/278-transparent-connect-interception.md",
    "specs/plans/279-build-action-identity-and-artifact-manifest.md",
    "specs/plans/280-transcript-root-audit-binding.md",
    "specs/plans/281-merge-queue-latency.md",
    "specs/plans/282-merge-queue-auto-requeue.md",
    "specs/plans/283-production-object-store-volumes.md",
    "specs/plans/284-ci-lint-latency.md",
    "specs/plans/284-zero-open-issue-reconciliation.md",
    "specs/plans/285-hvf-virtio-rng.md",
    "specs/plans/285-l3-tun-over-vsock.md",
    "specs/plans/286-kernel-floor.md",
    "specs/plans/287-userspace-socket-datapath.md",
    "specs/plans/288-kernel-cache-verify-on-read.md",
    "specs/plans/289-host-side-machine-logs.md",
    "specs/plans/290-sensitive-egress-redaction.md",
    "specs/plans/291-develop-build-deploy-attested.md",
    "specs/plans/292-tiered-artifact-storage-and-warm-start.md",
    "specs/plans/293-stream-plane-followups.md",
    "specs/plans/294-stream-plane-completion.md",
    "specs/plans/295-node-control-api.md",
    "specs/plans/295-workload-stream-plane.md",
    "specs/plans/296-fleet-stream-fan-out.md",
    "specs/plans/297-ci-parallel-lanes.md",
    "specs/plans/297-sub-300ms-warm-launch-slo.md",
    "specs/plans/298-extract-firecracker-driver.md",
    "specs/plans/298-extract-mvm-backends-crate.md",
    "specs/plans/298-nanda-receipts-and-conformance-badges.md",
    "specs/plans/298-warm-claim-service-and-hvf-pool.md",
    "specs/plans/299-cold-launch-performance.md",
    "specs/plans/301-wasm-backend-completion-and-browser-slice.md",
    "specs/plans/302-audit-chain-write-path-hardening.md",
    "specs/plans/303-runtime-hardening.md",
    "specs/plans/304-hvf-save-restore-bench.md",
    "specs/plans/304-hvf-save-restore.md",
    "specs/plans/305-delete-dead-gateway-stack.md",
    "specs/plans/306-declared-backing-and-tier-honesty.md",
    "specs/plans/307-merge-queue-latency.md",
    "specs/plans/308-cgroup-delegation-findings.md",
    "specs/plans/308-workload-grants-implementation.md",
    "specs/plans/308-workload-grants.md",
    "specs/plans/309-dependency-reduction.md",
    "specs/plans/311-launch-critical-path-waste.md",
    "specs/plans/312-automatic-macos-entitlement-signing.md",
    "specs/plans/313-egress-token-accounting-and-compaction.md",
    "specs/plans/314-event-driven-lifecycle-shutdown.md",
    "specs/plans/315-bootstrap-machine-readiness.md",
    "specs/plans/315-hvf-vsock-credit-regression.md",
    "specs/plans/316-builder-vm-shell-job-runner.md",
    "specs/plans/316-merge-queue-forward-progress.md",
    "specs/plans/316-single-flow-vsock-networking.md",
    "specs/plans/316-website-redesign-implementation.md",
    "specs/plans/316-website-redesign.md",
    "specs/plans/318-span-timing-profiling.md",
    "specs/plans/319-audit-log-rotation.md",
    "specs/plans/320-wasm-browser-demo.md",
    "specs/plans/321-wasm-in-microvm-workload-format.md",
    "specs/plans/322-hvf-virtiofs-shared-memory-sentinel.md",
    "specs/plans/322-merge-group-ci-scope.md",
    "specs/plans/322-persistent-machine-readme-contract.md",
    "specs/plans/323-concurrent-builds-one-builder-vm.md",
    "specs/plans/324-builder-store-lock-ownership.md",
    "specs/plans/325-lowercase-oci-image-names.md",
    "specs/plans/325-sdk-sidecar-reserved-mount.md",
    "specs/plans/326-accountable-audit-prune.md",
    "specs/plans/326-builder-store-durability.md",
    "specs/plans/327-hvf-quota-implementation.md",
    "specs/plans/327-hvf-quota-spike-findings.md",
    "specs/plans/327-hvf-vcpu-quota.md",
    "specs/plans/328-merkle-consistency-proofs.md",
    "specs/plans/329-browser-wasm-backend-demo.md",
    "specs/plans/329-remove-docker-backend.md",
    "specs/plans/329-run-first-cli-and-upstream-adoption.md",
    "specs/plans/330-decision-provenance-layer.md",
    "specs/plans/recovery-open-work-2026-08-12.md",
];

#[derive(Debug)]
struct Declared {
    backing: Backing,
    validation: String,
}

/// Parse the header block out of the first 40 lines.
///
/// Bounded deliberately: a `Backing:` line buried on page nine is not a
/// declaration a reader will see, so it does not count as one.
fn parse_header(text: &str) -> Option<Declared> {
    let mut backing = None;
    let mut validation = None;
    for line in text.lines().take(40) {
        let trimmed = line.trim().trim_start_matches(['*', '-', '>', ' ']);
        if let Some(rest) = trimmed.strip_prefix("Backing:") {
            backing = Backing::parse(rest.trim().trim_matches('`'));
        } else if let Some(rest) = trimmed.strip_prefix("Validation:") {
            validation = Some(rest.trim().trim_matches('`').to_string());
        }
    }
    Some(Declared {
        backing: backing?,
        validation: validation?,
    })
}

/// Files in scope, relative to the workspace root.
fn scoped_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for f in SCANNED_FILES {
        if root.join(f).is_file() {
            out.push(PathBuf::from(f));
        }
    }
    for dir in SCANNED_ROOTS {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "md"))
            .filter_map(|p| p.strip_prefix(root).ok().map(Path::to_path_buf))
            .collect();
        found.sort();
        out.extend(found);
    }
    out
}

/// Substring search that will not match inside a longer word.
///
/// `contains` alone reads "provenance" as the assertive "proven", which is a
/// word this repo uses constantly and truthfully. A hit only counts when both
/// sides of it are a boundary, so multi-word entries like "proof that" still
/// match as written.
pub(crate) fn contains_word(haystack: &str, needle: &str) -> bool {
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let start = from + rel;
        let end = start + needle.len();
        let before_ok = haystack[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word(c));
        let after_ok = haystack[end..].chars().next().is_none_or(|c| !is_word(c));
        if before_ok && after_ok {
            return true;
        }
        from = start + needle.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Which files each file cites, for the one-way citation rule. Only intra-repo
/// markdown links into the scanned scope count; an external URL is not a claim
/// about our own evidence.
fn cited_files(text: &str, scope: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    for candidate in scope {
        // Cheap containment rather than a link parser: a path that appears at
        // all is a reference for this purpose, and a false positive here costs
        // a maintainer one honest look at their own citation.
        if text.contains(candidate.as_str()) {
            out.push(candidate.clone());
        }
    }
    out
}

/// Everything a `Validation:` value could name: our Rust sources and our
/// workflow definitions. Built once per run.
///
/// Deliberately the same two corpora `check-witness-citations` resolves
/// against. A second, subtly different corpus is how two resolvers start
/// disagreeing about whether a name exists.
fn resolvable_corpus(root: &Path) -> String {
    let mut out = String::new();
    for (dirs, exts) in [
        (["crates", "xtask", "src"].as_slice(), ["rs"].as_slice()),
        ([".github"].as_slice(), ["yml", "yaml"].as_slice()),
    ] {
        for dir in dirs {
            collect_into(&mut out, &root.join(dir), exts);
        }
    }
    out
}

fn collect_into(out: &mut String, dir: &Path, exts: &[&str]) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_into(out, &path, exts);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| exts.contains(&e))
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push_str(&text);
        }
    }
}

/// Whether a `Validation:` value is a name we can resolve, as opposed to prose
/// or the explicit `none`.
///
/// Only kebab gate names and snake_case test names are checked. Anything else
/// is a sentence describing validation, which this gate does not try to parse
/// — over-reaching here would produce false failures on honest prose.
fn is_resolvable_name(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("none") {
        return false;
    }
    if v.contains(char::is_whitespace) {
        return false;
    }
    let kebab = v.len() >= 6
        && v.contains('-')
        && v.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let snake = v.len() >= 12
        && v.contains('_')
        && v.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    kebab || snake
}

pub fn run(root: &Path) -> Result<()> {
    run_with(root, PENDING)
}

/// The gate proper, with the backlog as a parameter.
///
/// Split out so [`self_test`] can run every rule against a synthetic tree
/// carrying its own (empty) backlog. Sharing the real `PENDING` there would
/// make the stale-entry rule fire on 147 files that legitimately do not exist
/// in a scratch directory — a correct rule applied to the wrong tree.
pub fn run_with(root: &Path, pending_list: &[&str]) -> Result<()> {
    let pending: BTreeSet<&str> = pending_list.iter().copied().collect();
    let corpus = resolvable_corpus(root);
    let files = scoped_files(root);
    let scope: BTreeSet<String> = files
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    let mut errors: Vec<String> = Vec::new();
    let mut declared: std::collections::BTreeMap<String, Declared> = Default::default();

    // A stale allowlist entry is itself an error: otherwise the list rots into
    // names that permit nothing and the "it only shrinks" property is unowned.
    for entry in &pending {
        if !root.join(entry).is_file() {
            errors.push(format!(
                "PENDING names `{entry}`, which no longer exists. Remove the entry — a \
                 relief valve for a file that is gone permits nothing and hides the \
                 list's real size."
            ));
        }
    }

    for rel in &files {
        let rel_s = rel.to_string_lossy().to_string();
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        let Some(header) = parse_header(&text) else {
            if !pending.contains(rel_s.as_str()) {
                errors.push(format!(
                    "{rel_s}: no `Backing:` / `Validation:` header in the first 40 lines. \
                     Claim-bearing prose declares what backs it, or says `preview` and \
                     drops the assertive vocabulary."
                ));
            }
            continue;
        };

        // Rule 2: a Validation naming a witness must name one that exists.
        // An unresolvable name reads as enforcement that is not there, which
        // is the exact failure this whole gate was built for.
        if is_resolvable_name(&header.validation) && !corpus.contains(header.validation.trim()) {
            errors.push(format!(
                "{rel_s}: declares `Validation: {}`, which appears in no source or \
                 workflow. A validation that resolves to nothing reads as enforcement \
                 that is not there.",
                header.validation.trim()
            ));
        }

        // Rule 4: a preview may not assert.
        if header.backing == Backing::Preview {
            let lower = text.to_lowercase();
            for word in ASSERTIVE {
                if contains_word(&lower, word) {
                    errors.push(format!(
                        "{rel_s}: declares `preview` but uses \"{word}\". A document whose \
                         own header says it is a preview does not get the assertive \
                         vocabulary."
                    ));
                    break;
                }
            }
        }
        declared.insert(rel_s, header);
    }

    // Rule 3: one-way citation. Done after the first pass so every file's own
    // declaration is known before any file is judged against what it cites.
    for (rel_s, header) in &declared {
        if header.backing != Backing::ShippedSource {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(root.join(rel_s)) else {
            continue;
        };
        for cited in cited_files(&text, &scope) {
            if cited == *rel_s {
                continue;
            }
            if let Some(other) = declared.get(&cited)
                && other.backing == Backing::Preview
            {
                errors.push(format!(
                    "{rel_s} declares `{}` but cites {cited}, which declares `{}`. \
                     Evidence flows one way: a shipped claim may not rest on a preview, \
                     or the preview launders itself into a guarantee.",
                    header.backing.as_str(),
                    other.backing.as_str()
                ));
            }
        }
    }

    if !errors.is_empty() {
        for err in &errors {
            eprintln!("[error] {err}");
        }
        bail!(
            "check-declared-backing: {} file(s) do not declare what backs them",
            errors.len()
        );
    }

    println!(
        "check-declared-backing: clean ({} file(s) declared, {} pending assessment)",
        declared.len(),
        pending.len()
    );
    Ok(())
}

/// Seed each rule's violation into a scratch copy and assert the gate rejects
/// it.
///
/// A gate nobody has watched fail is a gate nobody knows works. This runs the
/// real [`run`] against a synthetic tree rather than testing the helpers in
/// isolation, so a rule that is implemented but never reached still fails
/// here.
pub fn self_test() -> Result<()> {
    let tmp = std::env::temp_dir().join(format!("mvm-declared-backing-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("specs/adrs"))?;
    std::fs::create_dir_all(tmp.join("specs/plans"))?;

    let cases: &[(&str, &str, &str)] = &[
        (
            "a missing header",
            "specs/adrs/900-no-header.md",
            "# No header\n\nThis file declares nothing.\n",
        ),
        (
            "an unparseable Backing value",
            "specs/adrs/901-bad-enum.md",
            "# Bad\n\nBacking: vibes\nValidation: none\n",
        ),
        (
            "a preview using assertive vocabulary",
            "specs/adrs/902-preview-asserts.md",
            "# Preview\n\nBacking: preview\nValidation: none\n\nThis proves the property.\n",
        ),
    ];

    for (name, rel, body) in cases {
        let _ = std::fs::remove_file(tmp.join("specs/adrs/900-no-header.md"));
        let _ = std::fs::remove_file(tmp.join("specs/adrs/901-bad-enum.md"));
        let _ = std::fs::remove_file(tmp.join("specs/adrs/902-preview-asserts.md"));
        std::fs::write(tmp.join(rel), body)?;
        if run_with(&tmp, &[]).is_ok() {
            std::fs::remove_dir_all(&tmp).ok();
            bail!("self-test: the gate accepted {name} ({rel})");
        }
    }

    // Rule 2 needs a corpus to resolve against; an empty scratch tree has
    // none, so any resolvable name is unresolvable there.
    std::fs::write(
        tmp.join("specs/adrs/906-bad-validation.md"),
        "# Bad\n\nBacking: shipped-source\nValidation: check-no-such-gate-exists\n",
    )?;
    if run_with(&tmp, &[]).is_ok() {
        std::fs::remove_dir_all(&tmp).ok();
        bail!("self-test: the gate accepted a Validation that resolves to nothing");
    }
    std::fs::remove_file(tmp.join("specs/adrs/906-bad-validation.md"))?;

    // The one-way citation rule needs two files that both parse.
    let _ = std::fs::remove_file(tmp.join("specs/adrs/902-preview-asserts.md"));
    std::fs::write(
        tmp.join("specs/plans/903-preview.md"),
        "# Preview\n\nBacking: preview\nValidation: none\n",
    )?;
    std::fs::write(
        tmp.join("specs/adrs/904-shipped.md"),
        "# Shipped\n\nBacking: shipped-source\nValidation: none\n\n\
         Evidence: specs/plans/903-preview.md\n",
    )?;
    if run_with(&tmp, &[]).is_ok() {
        std::fs::remove_dir_all(&tmp).ok();
        bail!("self-test: the gate accepted a shipped-source file citing a preview");
    }

    // And a clean tree must pass, or the gate rejects everything and proves
    // nothing.
    std::fs::remove_dir_all(&tmp)?;
    std::fs::create_dir_all(tmp.join("specs/adrs"))?;
    std::fs::write(
        tmp.join("specs/adrs/905-ok.md"),
        "# Fine\n\nBacking: shipped-source\nValidation: none\n",
    )?;
    run_with(&tmp, &[])?;

    std::fs::remove_dir_all(&tmp).ok();
    println!("check-declared-backing --self-test: every rule rejected its violation");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::contains_word;

    /// The regression this exists for. "provenance" contains "proven", and a
    /// substring match refused every preview document that used the word —
    /// which in this repo is most of them, and truthfully.
    #[test]
    fn an_assertive_word_does_not_match_inside_a_longer_word() {
        assert!(!contains_word("image provenance fields", "proven"));
        assert!(!contains_word("the prover ran", "proven"));
        assert!(!contains_word("disproven by the run", "proven"));
    }

    /// The other half: the rule still has to fire on the real thing, or the
    /// fix above would be indistinguishable from deleting the rule.
    #[test]
    fn an_assertive_word_still_matches_when_it_stands_alone() {
        assert!(contains_word("this proven mechanism", "proven"));
        assert!(contains_word("proven.", "proven"));
        assert!(contains_word("(proven)", "proven"));
        assert!(contains_word("it is proven", "proven"));
    }

    /// Multi-word entries carry an interior space, so the boundary test has to
    /// look at the ends of the phrase rather than each word.
    #[test]
    fn a_multi_word_phrase_matches_as_written() {
        assert!(contains_word("that is proof that it works", "proof that"));
        assert!(!contains_word("bulletproof thatch", "proof that"));
    }

    use super::*;

    #[test]
    fn every_enum_value_round_trips() {
        for b in [
            Backing::Historical,
            Backing::Preview,
            Backing::Generated,
            Backing::CheckedExample,
            Backing::ShippedSource,
        ] {
            assert_eq!(Backing::parse(b.as_str()), Some(b));
        }
        assert_eq!(Backing::parse("vibes"), None);
    }

    /// A declaration on page nine is not one a reader sees.
    #[test]
    fn a_header_past_the_bound_does_not_count() {
        let padded = format!(
            "{}\nBacking: shipped-source\nValidation: none\n",
            "x\n".repeat(60)
        );
        assert!(parse_header(&padded).is_none());
    }

    #[test]
    fn a_partial_header_is_not_a_header() {
        assert!(parse_header("Backing: preview\n").is_none());
        assert!(parse_header("Validation: none\n").is_none());
        assert!(parse_header("Backing: preview\nValidation: none\n").is_some());
    }

    /// The backlog's own integrity rule. Without this, the list rots into
    /// names that permit nothing while still reading as 147 outstanding items.
    #[test]
    fn a_pending_entry_naming_a_deleted_file_is_rejected() {
        let tmp = std::env::temp_dir().join(format!("mvm-db-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("specs/adrs")).unwrap();

        let err = run_with(&tmp, &["specs/adrs/gone.md"]).unwrap_err();
        assert!(
            err.to_string().contains("do not declare what backs them"),
            "a stale backlog entry must fail the gate: {err}"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// The gate ships with its own self-test green, so the rules are known to
    /// reject rather than merely known to exist.
    #[test]
    fn the_self_test_passes() {
        self_test().expect("every rule must reject its seeded violation");
    }
}

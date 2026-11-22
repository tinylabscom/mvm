//! `xtask check-epoch-gate`
//!
//! One gate decides whether an execution epoch may act for its unit
//! (`mvm_core::host_interface::epoch_gate`), and one method decides whether an
//! epoch is inside a capability grant's bounds
//! (`MailboxCapabilityGrant::admits_epoch`). A host service that compares
//! epochs itself can drift from that rule without any test noticing.
//!
//! This gate finds every comparison of an execution epoch in production
//! host-service code and fails unless its enclosing function is listed:
//!
//! - `GATE`: the gate's own rule.
//! - `AGREEMENT`: a check that two stored, signed or derived records name the
//!   same epoch, or a bound on allocating a new epoch. Neither decides whether
//!   an epoch is current; the reason says which it is.
//!
//! Each entry pins how many comparisons its function holds, so a comparison
//! added to a listed function fails too, and an entry whose function no longer
//! compares fails as stale. Policy epochs and wall-clock epochs are different
//! concepts and are not matched.

use anyhow::{Result, bail};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use crate::check_bundle_trust_sites::{is_production_source, production_part};

/// Production host-service code: the mailbox service and every other hostd
/// service, the core mailbox and host interface, and the mailbox contract.
const SCOPE: &[&str] = &[
    "crates/mvm-hostd/src",
    "crates/mvm-core/src/mailbox",
    "crates/mvm-core/src/mailbox.rs",
    "crates/mvm-core/src/host_interface",
    "crates/mvm-contract/src/protocol/mailbox",
    "crates/mvm-contract/src/protocol/mailbox.rs",
];

/// (file, enclosing function, comparisons, reason)
type Entry = (&'static str, &'static str, usize, &'static str);

const GATE: &[Entry] = &[
    (
        "crates/mvm-core/src/host_interface/epoch_gate.rs",
        "admit_at",
        2,
        "the gate's rule",
    ),
    (
        "crates/mvm-contract/src/protocol/mailbox.rs",
        "admits_epoch",
        1,
        "a grant's epoch bounds; the contract cannot depend on the gate and runs in the guest",
    ),
];

const AGREEMENT: &[Entry] = &[
    (
        "crates/mvm-contract/src/protocol/mailbox.rs",
        "validate_bounds",
        1,
        "a grant's minimum is not above its maximum",
    ),
    (
        "crates/mvm-contract/src/protocol/mailbox.rs",
        "check_scope",
        2,
        "an enrollment and a lease name the plan's epoch",
    ),
    (
        "crates/mvm-hostd/src/hvf_owner_signer.rs",
        "new",
        2,
        "binds the holder: refuses the uncommissioned sentinel epoch and requires the derived provider identity to name the grants store's recorded epoch",
    ),
    (
        "crates/mvm-core/src/host_interface/offline.rs",
        "check_epoch",
        1,
        "allocation bound of a new restart epoch under signed offline authority",
    ),
    (
        "crates/mvm-core/src/host_interface/recovery.rs",
        "new",
        1,
        "history is self-consistent: its original epoch is under its high-water mark",
    ),
    (
        "crates/mvm-core/src/host_interface/recovery.rs",
        "request",
        1,
        "allocation: a proposed epoch is above every epoch already used",
    ),
    (
        "crates/mvm-core/src/mailbox/conversation.rs",
        "drop_epoch",
        1,
        "selects the pending calls of one epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/journal.rs",
        "verify_recovered_lease",
        1,
        "a recovered lease names its journal entry's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/transport.rs",
        "resolve",
        1,
        "a route's claims name the queried epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/transport.rs",
        "authorize_outbound",
        1,
        "route claims name the header's epoch; currency is decided by the gate above it",
    ),
    (
        "crates/mvm-core/src/mailbox/frame.rs",
        "send_expected_receipt",
        1,
        "a receipt names the sent header's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/frame.rs",
        "send_local_outbox_message",
        1,
        "a receipt names the sender's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/reader.rs",
        "check_plan",
        1,
        "a reader boot binding names its plan's grant epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/reader.rs",
        "mint_guest_receive_capability",
        3,
        "a reader binding and send grant name the mailbox grant's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/reader.rs",
        "verify_delivery_lease",
        1,
        "a lease names its header's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/reader.rs",
        "verify_delivery_ack",
        1,
        "an enrollment names its plan's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/journal/checkpoint.rs",
        "restore_checkpoint",
        1,
        "a checkpointed receipt names its entry's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/journal/recovery.rs",
        "open_with_recovery",
        2,
        "a recovered receipt and lease name their entry's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/journal/receipt.rs",
        "verify_admission",
        1,
        "the history key is bound to the admitted context's epoch",
    ),
    (
        "crates/mvm-core/src/mailbox/journal/receipt.rs",
        "decode_retained_receipt",
        1,
        "a retained receipt names its entry's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_custody.rs",
        "open_existing",
        2,
        "a signed custody manifest names the identity's epoch",
    ),
    (
        "crates/mvm-hostd/src/actor_bootstrap.rs",
        "validate",
        1,
        "a controller grant names its plan's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_launch.rs",
        "with_retained",
        1,
        "retained keys name the template header's epoch",
    ),
    (
        "crates/mvm-hostd/src/actor_authority.rs",
        "validate_mailbox",
        4,
        "child and parent grants and capabilities name their plans' epochs",
    ),
    (
        "crates/mvm-hostd/src/policy_generation/workload_store.rs",
        "commit",
        1,
        "compare-and-swap precondition of the record's own write",
    ),
    (
        "crates/mvm-hostd/src/policy_generation/workload_store.rs",
        "enroll_destination",
        1,
        "an existing enrollment names the same binding",
    ),
    (
        "crates/mvm-hostd/src/policy_generation/workload_store.rs",
        "commit_destination",
        1,
        "a prepared head names its enrollment's epoch",
    ),
    (
        "crates/mvm-hostd/src/actor_lifecycle/lifecycle.rs",
        "launch_reserved",
        1,
        "a derived child mailbox starts at the first epoch",
    ),
    (
        "crates/mvm-hostd/src/actor_lifecycle/local_mailboxes.rs",
        "install_controller",
        1,
        "a controller grant names its plan's epoch",
    ),
    (
        "crates/mvm-hostd/src/actor_lifecycle/local_mailboxes.rs",
        "child_endpoint",
        2,
        "a fresh child starts at the first epoch, as its parent endpoint does",
    ),
    (
        "crates/mvm-hostd/src/actor_lifecycle/activation.rs",
        "activate",
        2,
        "a controller session and plan name the signed grant's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_launch/actor_template.rs",
        "verify_plan",
        2,
        "a grant names its plan's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_launch/actor_template.rs",
        "install_pair",
        1,
        "both endpoints of a pair name one epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_launch/actor_template.rs",
        "reap_attempt",
        1,
        "a peer record names the child grant's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_process/reader.rs",
        "load_or_enroll",
        1,
        "a persisted reader binding names the grant's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_service/conversation.rs",
        "enqueue_call",
        1,
        "the opened header names the conversation's epoch; the context was admitted by the gate",
    ),
    (
        "crates/mvm-hostd/src/mailbox_service/conversation.rs",
        "check_context",
        1,
        "the caller's context names the conversation's epoch; the gate admitted it",
    ),
    (
        "crates/mvm-hostd/src/mailbox_service/peer_transport.rs",
        "send_on",
        1,
        "a peer's receipt names the peer's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_service/durable.rs",
        "verify_bound_reader",
        1,
        "a conversation binding names the reader grant's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_service/durable.rs",
        "reader_context",
        1,
        "the reader's context names the policy's epoch; the gate admitted the policy",
    ),
    (
        "crates/mvm-hostd/src/mailbox_service/actor_operations.rs",
        "record_dispatch_receipt",
        1,
        "a receipt names its header's epoch",
    ),
    (
        "crates/mvm-hostd/src/mailbox_service/actor_operations.rs",
        "accept_call",
        2,
        "a reply grant is scoped to exactly the peer's epoch",
    ),
];

/// A comparison operator, or a method that compares its receiver with its
/// argument.
static COMPARISON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r" (?:==|!=|<=|>=|<|>) |\.(?:partial_cmp|cmp|contains)\(").expect("static regex")
});
/// A line rustfmt broke before a comparison operator continues the previous one.
static CONTINUATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:==|!=|<=|>=) ").expect("static regex"));
static FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").expect("static regex"));
static STRING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(?:\\.|[^"\\])*""#).expect("static regex"));
static IDENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z_][A-Za-z0-9_]*").expect("static regex"));

#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    file: String,
    function: String,
    line: usize,
    text: String,
}

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let files = scoped_files(workspace)?;
    let found = sites(&files);
    let problems = problems(&found, GATE, AGREEMENT);
    if !problems.is_empty() {
        bail!(
            "check-epoch-gate: {} problem(s):\n  {}\n\
             Decide whether an epoch may act with mvm_core::host_interface::epoch_gate \
             (CommandGate::admit or admit_at), or a grant's bounds with admits_epoch. If the \
             comparison only checks that two records name the same epoch, list its function in \
             AGREEMENT in xtask/src/check_epoch_gate.rs with the reason.",
            problems.len(),
            problems.join("\n  ")
        );
    }
    eprintln!(
        "check-epoch-gate: clean ({} comparison(s): {} in the gate, the rest record agreement)",
        found.len(),
        GATE.iter().map(|e| e.2).sum::<usize>()
    );
    Ok(())
}

fn scoped_files(workspace: &Path) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    for root in SCOPE {
        let path = workspace.join(root);
        let mut push = |p: &Path, text: &str| {
            let rel = p
                .strip_prefix(workspace)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/");
            if is_production_source(&rel) {
                files.push((rel, text.to_owned()));
            }
        };
        if path.is_file() {
            push(&path, &std::fs::read_to_string(&path)?);
        } else {
            crate::fs_walk::for_each_file(&path, Some("rs"), &mut push)?;
        }
    }
    Ok(files)
}

/// Every execution-epoch comparison in the production part of `files`.
fn sites(files: &[(String, String)]) -> Vec<Site> {
    let mut out = Vec::new();
    for (file, text) in files {
        let lines: Vec<String> = production_part(text).lines().map(code_of).collect();
        let mut function = String::new();
        let mut i = 0;
        while i < lines.len() {
            let start = i;
            let mut code = lines[i].clone();
            while lines.get(i + 1).is_some_and(|l| CONTINUATION.is_match(l)) {
                i += 1;
                code.push(' ');
                code.push_str(lines[i].trim_start());
            }
            if let Some(name) = FUNCTION.captures(&code) {
                function = name[1].to_owned();
            }
            if compares_an_epoch(&code) {
                out.push(Site {
                    file: file.clone(),
                    function: function.clone(),
                    line: start + 1,
                    text: code.trim().to_owned(),
                });
            }
            i += 1;
        }
    }
    out
}

/// The line with string literals emptied and any line comment removed.
fn code_of(line: &str) -> String {
    let line = STRING.replace_all(line, "\"\"");
    line.split("//").next().unwrap_or_default().to_owned()
}

fn compares_an_epoch(code: &str) -> bool {
    COMPARISON.find_iter(code).any(|m| {
        let operand = |c: char| c.is_ascii_alphanumeric() || "_.()&*[]:".contains(c);
        let before = &code[..m.start()];
        let left = &before[before
            .char_indices()
            .rev()
            .find(|(_, c)| !operand(*c))
            .map_or(0, |(i, c)| i + c.len_utf8())..];
        let after = &code[m.end()..];
        let right = &after[..after.find(|c| !operand(c)).unwrap_or(after.len())];
        names_an_execution_epoch(left) || names_an_execution_epoch(right)
    })
}

fn names_an_execution_epoch(operand: &str) -> bool {
    IDENT.find_iter(operand).any(|ident| {
        let ident = ident.as_str().to_ascii_lowercase();
        ident.contains("epoch") && !ident.contains("policy_epoch") && ident != "unix_epoch"
    })
}

fn problems(found: &[Site], gate: &[Entry], agreement: &[Entry]) -> Vec<String> {
    let mut by_function: BTreeMap<(&str, &str), Vec<&Site>> = BTreeMap::new();
    for site in found {
        by_function
            .entry((&site.file, &site.function))
            .or_default()
            .push(site);
    }
    let listed = |file: &str, function: &str| {
        gate.iter()
            .chain(agreement)
            .find(|e| e.0 == file && e.1 == function)
    };
    let mut out = Vec::new();
    for ((file, function), sites) in &by_function {
        match listed(file, function) {
            None => out.extend(sites.iter().map(|s| {
                format!(
                    "{}:{} in `{}` compares an execution epoch outside the gate: {}",
                    s.file, s.line, s.function, s.text
                )
            })),
            Some(entry) if entry.2 != sites.len() => out.push(format!(
                "{file}: `{function}` is listed with {} comparison(s) but has {}; classify the \
                 change and update the count",
                entry.2,
                sites.len()
            )),
            Some(_) => {}
        }
    }
    for entry in gate.iter().chain(agreement) {
        if !by_function.contains_key(&(entry.0, entry.1)) {
            out.push(format!(
                "{}: `{}` is listed but no longer compares an execution epoch",
                entry.0, entry.1
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "crates/mvm-hostd/src/service.rs";

    fn found(text: &str) -> Vec<Site> {
        sites(&[(FILE.to_owned(), text.to_owned())])
    }

    #[test]
    fn this_workspace_passes() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let found = sites(&scoped_files(workspace).unwrap());
        assert_eq!(problems(&found, GATE, AGREEMENT), Vec::<String>::new());
    }

    #[test]
    fn an_ungated_comparison_fails() {
        let text = "fn serve(grant: &Grant, current: ExecutionEpoch) {\n    if grant.epoch < current {}\n}\n";
        let problems = problems(&found(text), &[], &[]);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("service.rs:2 in `serve`"));
    }

    #[test]
    fn a_listed_agreement_passes_and_a_new_comparison_beside_it_fails() {
        let one =
            "fn check(a: &R, b: &R) -> bool {\n    a.execution_epoch == b.execution_epoch\n}\n";
        let entry = [(FILE, "check", 1, "two records agree")];
        assert!(problems(&found(one), &[], &entry).is_empty());
        let two = "fn check(a: &R, b: &R) -> bool {\n    a.execution_epoch == b.execution_epoch\n        && a.epoch <= b.epoch\n}\n";
        assert_eq!(problems(&found(two), &[], &entry).len(), 1);
    }

    #[test]
    fn a_stale_entry_fails() {
        let entry = [(FILE, "gone", 1, "two records agree")];
        let problems = problems(&found("fn other() {}\n"), &[], &entry);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("no longer compares"));
    }

    #[test]
    fn a_comparison_broken_across_lines_is_one_site() {
        let text = "fn f() {\n    if x\n        != current_epoch {}\n}\n";
        let found = found(text);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].line, 2);
    }

    #[test]
    fn range_and_ordering_methods_count() {
        assert_eq!(found("fn f() { (lo..=hi_epoch).contains(&e); }").len(), 1);
        assert_eq!(found("fn f() { epoch.cmp(&other); }").len(), 1);
    }

    #[test]
    fn other_epochs_comments_strings_and_tests_are_not_comparisons() {
        let text = "fn f() {\n    a.policy_epoch != b.policy_epoch;\n    t.duration_since(UNIX_EPOCH) > x;\n    // a.epoch == b.epoch\n    let s = \"epoch == 1\";\n    let v: Option<ExecutionEpoch> = None;\n    key == derive(&dir, grant.epoch)?;\n}\n#[cfg(test)]\nmod tests { fn t() { assert!(a.epoch == b.epoch); } }\n";
        assert_eq!(found(text), Vec::<Site>::new());
    }
}

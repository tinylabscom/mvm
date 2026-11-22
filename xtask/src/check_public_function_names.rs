//! Reject public `f` / `f_with_*` siblings within the same Rust owner scope.

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;
use syn::{ImplItem, Item, TraitItem, Visibility};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SiblingPair {
    path: String,
    owner: String,
    base: String,
    extended: String,
}

// The journal deliberately distinguishes volatile opening/admission from
// externally anchored and retained-key custody variants. Conflating their
// names would hide the authority boundary at call sites.
//
// The actor launch entrypoints keep their `_with_*` siblings because each
// variant names an additional custody boundary the base form does not hold:
// the reservation store's `open_with_host_budget` re-attaches to a live
// reservation only when the persisted budget matches the admitted one;
// admission's `admit_plan_for_run_with_host_permit` admits against a host
// hold the caller already acquired, never reserving the same launch twice;
// the owned-actor starts' `_with_bootstrap` variants provision the per-boot
// holder before activation instead of launching holderless; and the owned
// broker's `spawn_broker_with_actor_routes` wires the admitted actor
// conversation routes into the same single broker path. Conflating any of
// these names would hide the extra authority or custody each variant pins.
//
// The launch/admission entrypoints keep their `_with_verified_*` siblings
// because those variants thread the launch-verified runtime set through
// admission and start: the retained audit evidence must match the runtime
// that was actually verified, and conflating the names would hide that
// verification boundary at call sites. The CLI admission owner keeps its
// `new_for_rootfs_with_runtime` sibling for the same reason: cold dispatch
// must retain the exact launch-owned verified set the admission ran against.
//
// The warm-claim path keeps its `try_warm_claim_with_admission` sibling
// because that variant threads the CLI admission owner through the claim so
// the unified dispatch admits exactly once; the bare name is the
// admission-free convenience for callers that never carry one, and dropping
// the distinction would let a caller silently claim outside the admission
// it owes.
const EXCEPTIONS: &[(&str, &str, &str, &str)] = &[
    (
        "crates/mvm-cli/src/commands/pool.rs",
        "module",
        "try_warm_claim",
        "try_warm_claim_with_admission",
    ),
    (
        "crates/mvm-client/src/admission/cli_dispatch.rs",
        "impl CliAdmission",
        "new_for_rootfs",
        "new_for_rootfs_with_runtime",
    ),
    (
        "crates/mvm-core/src/mailbox/journal.rs",
        "impl MailboxJournal",
        "admit",
        "admit_with_anchor",
    ),
    (
        "crates/mvm-core/src/mailbox/journal.rs",
        "impl MailboxJournal",
        "open",
        "open_with_anchor",
    ),
    (
        "crates/mvm-core/src/mailbox/journal.rs",
        "impl MailboxJournal",
        "open",
        "open_with_custody",
    ),
    (
        "crates/mvm-build/src/release_signature.rs",
        "module",
        "verify_release_archive_bytes",
        "verify_release_archive_bytes_with_signer",
    ),
    (
        "crates/mvm-client/src/admission/mod.rs",
        "module",
        "admit_plan_for_boot",
        "admit_plan_for_boot_with_verified_retained",
    ),
    (
        "crates/mvm-client/src/admission/mod.rs",
        "module",
        "admit_plan_for_boot",
        "admit_plan_for_boot_with_verified_runtime",
    ),
    (
        "crates/mvm-client/src/admission/mod.rs",
        "module",
        "admit_plan_for_boot_configured_ingress",
        "admit_plan_for_boot_configured_ingress_with_verified_runtime",
    ),
    (
        "crates/mvm-client/src/boot.rs",
        "module",
        "start_prepared_custodied",
        "start_prepared_custodied_with_verified_runtime",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/start.rs",
        "module",
        "admit_and_start",
        "admit_and_start_with_verified_release",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/start.rs",
        "module",
        "start_admitted",
        "start_admitted_with_verified_release",
    ),
    (
        "crates/mvm-hostd/src/actor_reservations.rs",
        "impl ActorReservations",
        "open",
        "open_with_host_budget",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/admit.rs",
        "module",
        "admit_plan_for_run",
        "admit_plan_for_run_with_host_permit",
    ),
    (
        "crates/mvm-hostd/src/plan_admission/start.rs",
        "module",
        "start_admitted_owned_actor",
        "start_admitted_owned_actor_with_bootstrap",
    ),
    (
        "crates/mvm-runtime/src/actor_teardown.rs",
        "impl AnyBackend",
        "start_owned_actor",
        "start_owned_actor_with_bootstrap",
    ),
    (
        "crates/mvm-vmm/src/host/broker_services_spawn.rs",
        "module",
        "spawn_broker",
        "spawn_broker_with_actor_routes",
    ),
    (
        "crates/mvm-runtime/src/backend.rs",
        "impl AnyBackend",
        "prepare_owned_launch",
        "prepare_owned_launch_with_verified_runtime",
    ),
    (
        "crates/mvm-runtime/src/backend.rs",
        "impl AnyBackend",
        "start",
        "start_with_verified_runtime",
    ),
    // The hermetic OCI registry fixture keeps its `_with_status` sibling
    // because the base form pins the 307 hop production always answered,
    // while the variant names the exact redirect status (301, 302 or 303)
    // a test needs the blob GET to return; conflating the names would hide
    // which redirect class a test actually exercises.
    (
        "crates/mvm-fs/tests/common/mod.rs",
        "impl HermeticRegistry",
        "register_redirected_bearer_blob",
        "register_redirected_bearer_blob_with_status",
    ),
];
const EXPECTED_UNEXPLAINED_PAIRS: usize = 0;

pub(crate) fn run(workspace: &Path) -> Result<()> {
    let pairs = sibling_pairs(workspace)?;
    validate(&pairs, EXCEPTIONS, EXPECTED_UNEXPLAINED_PAIRS)?;
    eprintln!(
        "check-public-function-names: {} explained sibling pairs; zero unexplained",
        pairs.len()
    );
    Ok(())
}

fn public(vis: &Visibility) -> bool {
    !matches!(vis, Visibility::Inherited)
}

fn names_in_items(items: &[Item], path: &str, owner: &str, out: &mut Vec<SiblingPair>) {
    let mut names = BTreeSet::new();
    for item in items {
        if let Item::Fn(function) = item
            && public(&function.vis)
        {
            names.insert(function.sig.ident.to_string());
        }
    }
    add_pairs(path, owner, &names, out);
    for item in items {
        match item {
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    names_in_items(items, path, &format!("mod {}", module.ident), out);
                }
            }
            Item::Impl(block) => {
                let mut names = BTreeSet::new();
                for item in &block.items {
                    if let ImplItem::Fn(function) = item
                        && public(&function.vis)
                    {
                        names.insert(function.sig.ident.to_string());
                    }
                }
                let owner = format!("impl {}", quote_owner(&block.self_ty));
                add_pairs(path, &owner, &names, out);
            }
            Item::Trait(trait_) => {
                let names = trait_
                    .items
                    .iter()
                    .filter_map(|item| match item {
                        TraitItem::Fn(f) => Some(f.sig.ident.to_string()),
                        _ => None,
                    })
                    .collect();
                add_pairs(path, &format!("trait {}", trait_.ident), &names, out);
            }
            _ => {}
        }
    }
}

fn quote_owner(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_else(|| "?".into()),
        _ => "?".into(),
    }
}

fn add_pairs(path: &str, owner: &str, names: &BTreeSet<String>, out: &mut Vec<SiblingPair>) {
    for extended in names {
        if let Some((base, _)) = extended.split_once("_with_")
            && names.contains(base)
        {
            out.push(SiblingPair {
                path: path.into(),
                owner: owner.into(),
                base: base.into(),
                extended: extended.clone(),
            });
        }
    }
}

fn sibling_pairs(workspace: &Path) -> Result<Vec<SiblingPair>> {
    let mut pairs = Vec::new();
    crate::fs_walk::for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, contents| {
            let Ok(relative) = path.strip_prefix(workspace) else {
                return;
            };
            let relative = relative.to_string_lossy();
            if let Ok(file) = syn::parse_file(contents) {
                names_in_items(&file.items, &relative, "module", &mut pairs);
            }
        },
    )?;
    pairs.sort();
    Ok(pairs)
}

fn validate(
    pairs: &[SiblingPair],
    exceptions: &[(&str, &str, &str, &str)],
    expected_unexplained: usize,
) -> Result<()> {
    let actual: BTreeSet<_> = pairs
        .iter()
        .map(|p| {
            (
                p.path.as_str(),
                p.owner.as_str(),
                p.base.as_str(),
                p.extended.as_str(),
            )
        })
        .collect();
    let allowed: BTreeSet<_> = exceptions.iter().copied().collect();
    let stale: Vec<_> = allowed.difference(&actual).collect();
    if !stale.is_empty() {
        bail!("stale public-function-name exceptions: {stale:?}");
    }
    let unexplained: Vec<_> = actual.difference(&allowed).collect();
    if unexplained.len() != expected_unexplained {
        bail!(
            "expected {expected_unexplained} unexplained public sibling pairs, found {}: {unexplained:?}",
            unexplained.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scan(source: &str) -> Vec<SiblingPair> {
        let file = syn::parse_file(source).unwrap();
        let mut out = Vec::new();
        names_in_items(&file.items, "x.rs", "module", &mut out);
        out
    }
    #[test]
    fn detects_siblings_in_one_module_scope() {
        assert_eq!(
            scan("pub fn open(){} pub fn open_with_policy(){} ").len(),
            1
        );
    }
    #[test]
    fn separates_module_and_impl_owners() {
        assert!(
            scan("pub fn open(){} struct X; impl X { pub fn open_with_policy(){} }").is_empty()
        );
    }
    #[test]
    fn separates_individual_impl_owners() {
        assert!(scan("struct A; struct B; impl A { pub fn open(){} } impl B { pub fn open_with_policy(){} }").is_empty());
    }
    #[test]
    fn detects_siblings_inside_one_impl() {
        let pairs = scan("struct A; impl A { pub fn open(){} pub fn open_with_policy(){} }");
        assert_eq!(pairs[0].owner, "impl A");
    }
    #[test]
    fn rejects_unexpected_pairs() {
        let p = SiblingPair {
            path: "x".into(),
            owner: "module".into(),
            base: "a".into(),
            extended: "a_with_b".into(),
        };
        assert!(
            validate(&[p], &[], 0)
                .unwrap_err()
                .to_string()
                .contains("unexplained")
        );
    }
    #[test]
    fn rejects_stale_exceptions() {
        assert!(
            validate(&[], &[("x", "module", "a", "a_with_b")], 0)
                .unwrap_err()
                .to_string()
                .contains("stale")
        );
    }
}

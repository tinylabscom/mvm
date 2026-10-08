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

const EXCEPTIONS: &[(&str, &str, &str, &str)] = &[];

const EXPECTED_UNEXPLAINED_PAIRS: usize = 0;

pub fn run(workspace: &Path) -> Result<()> {
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

//! `mvmctl pack rollback`.

use anyhow::{Result, bail};

use mvm_core::pack_cache::{PackListEntry, set_active_version};

use crate::ui;

use super::PackKindArg;

pub(in crate::commands) fn run(kind: PackKindArg, to: Option<String>) -> Result<()> {
    let pack_kind = kind.to_pack_kind();
    let versions = mvm_core::pack_cache::list_versions(Some(pack_kind))?;
    if versions.is_empty() {
        bail!(
            "no recorded pack versions for kind '{}'; nothing to roll back",
            kind.label()
        );
    }

    let target = match &to {
        Some(to) => resolve_by_target(&versions, to)?,
        None => resolve_previous(&versions, kind)?,
    };

    set_active_version(&target.key, &target.pack_hash)?;
    ui::success(&format!(
        "Rolled back {} pack to version {} ({}).",
        kind.label(),
        target.release_version,
        short_hash(target.pack_hash.as_str()),
    ));
    Ok(())
}

/// Resolve `--to` against the recorded versions: a match on `release_version`
/// exactly, or a `pack_hash` prefix. Ambiguous (more than one match) or
/// no-match are both refused rather than guessed.
fn resolve_by_target<'a>(versions: &'a [PackListEntry], to: &str) -> Result<&'a PackListEntry> {
    let matches: Vec<&PackListEntry> = versions
        .iter()
        .filter(|entry| entry.release_version == to || entry.pack_hash.as_str().starts_with(to))
        .collect();
    match matches.as_slice() {
        [] => bail!("no cached pack version matches '{to}'"),
        [only] => Ok(only),
        many => bail!(
            "'{to}' matches {} cached pack versions ambiguously: {}",
            many.len(),
            many.iter()
                .map(|entry| format!(
                    "{} ({})",
                    entry.release_version,
                    short_hash(entry.pack_hash.as_str())
                ))
                .collect::<Vec<_>>()
                .join(", "),
        ),
    }
}

/// Resolve the implicit rollback target (no `--to`): the second-newest
/// version for this kind's single key. Refuses when the kind spans more than
/// one `(arch, backend)` key — pick `--to` explicitly in that case — or when
/// there is no older version to fall back to.
fn resolve_previous(versions: &[PackListEntry], kind: PackKindArg) -> Result<&PackListEntry> {
    let mut distinct_keys: Vec<&mvm_core::pack_cache::PackKey> = Vec::new();
    for entry in versions {
        if !distinct_keys.iter().any(|k| **k == entry.key) {
            distinct_keys.push(&entry.key);
        }
    }
    if distinct_keys.len() > 1 {
        bail!(
            "'{}' has {} recorded (arch, backend) targets; pass --to to disambiguate",
            kind.label(),
            distinct_keys.len(),
        );
    }

    let mut by_recency: Vec<&PackListEntry> = versions.iter().collect();
    by_recency.sort_by_key(|entry| std::cmp::Reverse(entry.promoted_at_unix));
    by_recency.into_iter().nth(1).ok_or_else(|| {
        anyhow::anyhow!(
            "only one version of '{}' is cached; nothing older to roll back to",
            kind.label()
        )
    })
}

fn short_hash(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

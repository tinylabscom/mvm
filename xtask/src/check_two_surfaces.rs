//! `xtask check-two-surfaces`
//!
//! The project ships exactly two things: what the **host machine runs** to host
//! sandboxes (`host`), and what a **user runs** to drive them (`user`). Those are
//! the only two consumer-facing product surfaces.
//!
//! This lint parses the workspace-root `[features]` table and fails if:
//!   * `host` or `user` is missing, or
//!   * a top-level feature exists that is neither a product surface (`host` /
//!     `user`) nor on the maintained internal allowlist below.
//!
//! Adding a new root feature therefore forces a decision: fold it into `host` or
//! `user` (it is product behaviour), or add it to `INTERNAL` with a reason (it is
//! a platform/dev/build sub-feature, not a third product surface). A third
//! consumer-facing product knob is a design error — "that's it, just two".

use anyhow::{Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

/// The two — and only two — consumer-facing product surfaces.
const SURFACES: [&str; 2] = ["host", "user"];

/// The only non-surface root features: unavoidable knobs that cannot be
/// unconditional. Every capability flag folds into `host`/`user`/`dev` (their
/// forwards are inlined in the root Cargo.toml); what remains here is `default`
/// plus platform/storage opt-ins that genuinely cannot always be on. Keep this
/// list tiny — a new entry is a conscious "this cannot live in a surface".
const INTERNAL: [&str; 9] = [
    "default",
    // Platform: link the libkrun C VMM (absent on a macOS-26 HVF host).
    "libkrun-sys",
    "libkrun-live",
    // Platform: link the Linux TPM2 TSS provider when a host exposes a TPM.
    "attestation-tpm2",
    // Optional heavy S3 storage backend for the template registry (fleet-only).
    "template-registry-s3",
    // Lean library knob: mvm-core's gated hostd IPC transport, flipped through
    // the facade by a downstream host-side daemon without pulling all of `host`.
    "hostd-transport",
    // Platform/dev-only: live Apple Silicon warm-handoff validation and the
    // opt-in immutable APFS snapshot provider. Neither adds a product surface.
    "hvf-live-validation",
    "trusted-apfs",
    // Dev/test-only: the hermetic in-memory mock VM backend. Never part of a
    // shipped binary; only this workspace's own test suite turns it on.
    "test-support",
];

/// A couple of release/build-only flags are allowed but explicitly *not* part of
/// either product surface (they gate acquisition mechanics, not behaviour).
/// `dev` is the local-development meta-feature (the `host` + `user` union that
/// runs every documented example) — a convenience, not a third product surface.
const BUILD_ONLY: [&str; 4] = [
    "release-artifact-bootstrap",
    "release-channel",
    "dev",
    // Whether the Linux host binaries are cross-compiled into the artifact.
    // Both settings expose the same verbs, so this gates acquisition, not
    // behaviour — it belongs here rather than in `host` or `user`.
    "embed-host-bins",
];

/// `dev` must aggregate both surfaces so a contributor can run every README /
/// docs example from one build. Asserted structurally below.
const DEV_META: &str = "dev";

pub fn run(workspace: &Path) -> Result<()> {
    let manifest = std::fs::read_to_string(workspace.join("Cargo.toml"))?;
    let features = feature_names(&manifest);

    if features.is_empty() {
        bail!("check-two-surfaces: no [features] table found in the root Cargo.toml");
    }

    for surface in SURFACES {
        if !features.contains(surface) {
            bail!(
                "check-two-surfaces: the `{surface}` product surface is missing from the root \
                 [features]. The project ships exactly two surfaces: `host` and `user`."
            );
        }
    }

    // `dev` must be the host+user union so `cargo build --features dev` runs every
    // README / docs example. If it stops aggregating a surface, examples for that
    // surface silently stop building under `dev`.
    if features.contains(DEV_META) {
        let deps = feature_deps(&manifest, DEV_META);
        for surface in SURFACES {
            if !deps.contains(surface) {
                bail!(
                    "check-two-surfaces: the `dev` meta-feature must include `{surface}` so it can \
                     run every documented example (it is the host+user union). Add `{surface}` to \
                     `dev = [...]` in the root Cargo.toml."
                );
            }
        }
    }

    let allowed: BTreeSet<&str> = SURFACES
        .iter()
        .chain(INTERNAL.iter())
        .chain(BUILD_ONLY.iter())
        .copied()
        .collect();

    let unclassified: Vec<&str> = features
        .iter()
        .map(String::as_str)
        .filter(|f| !allowed.contains(f))
        .collect();

    if !unclassified.is_empty() {
        bail!(
            "check-two-surfaces: root feature(s) {:?} are neither a product surface (`host`/`user`) \
             nor on the internal allowlist. The project ships exactly two surfaces — fold this into \
             `host` or `user` if it is product behaviour, or add it to `INTERNAL` in \
             xtask/src/check_two_surfaces.rs if it is a platform/dev/build sub-feature.",
            unclassified
        );
    }

    let runtime_manifest = std::fs::read_to_string(
        workspace
            .join("crates")
            .join("mvm-runtime")
            .join("Cargo.toml"),
    )?;
    validate_runtime_storage_features(&runtime_manifest)?;

    eprintln!(
        "check-two-surfaces: clean (exactly two product surfaces: host, user; \
         {} internal sub-features)",
        features.len() - SURFACES.len()
    );
    Ok(())
}

/// The local runtime may use `object_store` for the fleet-operated template
/// registry, but production tenant volume providers are constructed by the
/// fleet orchestrator. A member-only volume feature would bypass the two
/// shipped surfaces and put provider credentials on the local runtime.
fn validate_runtime_storage_features(manifest: &str) -> Result<()> {
    const TEMPLATE_REGISTRY_FEATURE: &str = "template-registry-s3";
    const REMOVED_VOLUME_FEATURE: &str = "storage-s3";

    let features = feature_names(manifest);
    if features.contains(REMOVED_VOLUME_FEATURE) {
        bail!(
            "check-two-surfaces: mvm-runtime feature `{REMOVED_VOLUME_FEATURE}` bypasses the \
             host/user product surfaces and crosses the fleet storage boundary; production \
             object-store volume providers belong in the fleet orchestrator"
        );
    }

    let object_store_features: Vec<&str> = features
        .iter()
        .map(String::as_str)
        .filter(|feature| feature_deps(manifest, feature).contains("dep:object_store"))
        .collect();
    if object_store_features != [TEMPLATE_REGISTRY_FEATURE] {
        bail!(
            "check-two-surfaces: mvm-runtime may activate `object_store` only through \
             `{TEMPLATE_REGISTRY_FEATURE}`, found {:?}",
            object_store_features
        );
    }
    Ok(())
}

/// Extract the feature names declared in the `[features]` table of a manifest.
/// A feature line is `name = ...` at the top of the table entry; continuation
/// lines of a multi-line array value are skipped by requiring the `=` to sit
/// before the first `[` / `"`.
fn feature_names(manifest: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut in_features = false;
    for line in manifest.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_features = trimmed.starts_with("[features]");
            continue;
        }
        if !in_features {
            continue;
        }
        let Some((lhs, _rhs)) = line.split_once('=') else {
            continue;
        };
        let name = lhs.trim();
        // A feature name is a bare identifier at column 0 (not an array element
        // continuation, which is indented and has no `=` before the bracket).
        if !name.is_empty()
            && !line.starts_with([' ', '\t'])
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            names.insert(name.to_string());
        }
    }
    names
}

/// Return the feature names listed in `feature`'s value array in the `[features]`
/// table (e.g. `dev = ["host", "user"]` → {host, user}). Handles single-line and
/// multi-line arrays. Empty if the feature isn't found.
fn feature_deps(manifest: &str, feature: &str) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let mut in_features = false;
    let mut collecting = false;
    for line in manifest.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') {
            in_features = trimmed.starts_with("[features]");
            collecting = false;
            continue;
        }
        if !in_features {
            continue;
        }
        if !collecting {
            if let Some((lhs, rhs)) = line.split_once('=')
                && lhs.trim() == feature
                && !line.starts_with([' ', '\t'])
            {
                for tok in rhs.split('"').skip(1).step_by(2) {
                    deps.insert(tok.to_string());
                }
                // A single-line `name = ["a", "b"]` closes on the same line.
                collecting = !rhs.contains(']');
            }
            continue;
        }
        // Multi-line continuation of the target feature's array.
        for tok in line.split('"').skip(1).step_by(2) {
            deps.insert(tok.to_string());
        }
        if line.contains(']') {
            collecting = false;
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_feature_names_ignoring_array_continuations() {
        let manifest = r#"
[package]
name = "x"

[features]
default = ["a"]
host = [
    "builder-vm",
    "pure-mkfs",
]
user = ["manifest-verify"]

[dependencies]
serde = "1"
"#;
        let names = feature_names(manifest);
        assert!(names.contains("default"));
        assert!(names.contains("host"));
        assert!(names.contains("user"));
        // indented array elements are not feature names
        assert!(!names.contains("builder-vm"));
        // dependency lines outside [features] are excluded
        assert!(!names.contains("serde"));
    }

    #[test]
    fn feature_deps_reads_the_dev_union() {
        let manifest = r#"
[features]
host = ["builder-vm"]
user = ["manifest-verify"]
dev = ["host", "user", "dev-watch"]
"#;
        let deps = feature_deps(manifest, "dev");
        assert!(deps.contains("host") && deps.contains("user") && deps.contains("dev-watch"));
        // a single-line array is fully captured
        assert_eq!(
            feature_deps(manifest, "host"),
            ["builder-vm".to_string()].into()
        );
    }

    #[test]
    fn every_current_root_feature_is_classified() {
        // Mirrors the real root feature set: nothing outside SURFACES ∪ INTERNAL
        // ∪ BUILD_ONLY. If this fails, a new root feature needs classifying.
        let allowed: BTreeSet<&str> = SURFACES
            .iter()
            .chain(INTERNAL.iter())
            .chain(BUILD_ONLY.iter())
            .copied()
            .collect();
        for f in [
            "host",
            "user",
            "default",
            "dev",
            "libkrun-sys",
            "attestation-tpm2",
            "template-registry-s3",
            "hostd-transport",
            "release-artifact-bootstrap",
            "release-channel",
            "test-support",
        ] {
            assert!(allowed.contains(f), "{f} must be classified");
        }
    }

    #[test]
    fn runtime_rejects_a_member_only_object_store_volume_feature() {
        let manifest = r#"
[features]
template-registry-s3 = ["dep:object_store"]
storage-s3 = ["dep:object_store", "dep:futures"]
"#;
        let err = validate_runtime_storage_features(manifest).unwrap_err();
        assert!(err.to_string().contains("storage-s3"));
    }

    #[test]
    fn runtime_allows_object_store_only_for_the_template_registry() {
        let manifest = r#"
[features]
default = []
template-registry-s3 = ["dep:object_store"]
wasm-backend = ["dep:wasmtime"]
"#;
        validate_runtime_storage_features(manifest).unwrap();
    }
}

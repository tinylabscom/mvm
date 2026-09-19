//! Environment-aware resolution helpers (running VMs, flake refs, network policy).

use anyhow::{Context, Result};

/// One of the two built workload sources accepted by `--manifest`: a
/// manifest path that resolves to a slot hash, or a manifest selecting a
/// pre-built wasm module.
///
/// `mvmctl up` / `mvmctl exec` accept either form via their
/// `--manifest` flag. A manifest is addressed by its path; the slot hash is
/// derived from that path.
///
/// Callers that need the persisted manifest re-read it via
/// `mvm_runtime::vm::template::lifecycle::template_load_slot(slot_hash)`
/// — keeping the enum lean here avoids the `clippy::large_enum_variant`
/// warning (`PersistedManifest` is ~350 bytes).
#[derive(Debug, Clone)]
pub enum ManifestArgRef {
    /// Manifest-keyed slot.
    Slot { slot_hash: String },
    /// Manifest selects a pre-built wasm module; no Nix/OCI build or slot.
    WasmModule {
        manifest_path: std::path::PathBuf,
        module_path: std::path::PathBuf,
    },
}

/// Resolve a `--manifest` argument to the manifest it names.
///
/// User-supplied arguments are paths — a manifest file or the directory
/// containing one. The machine-run flake path also threads the strict
/// 64-character address returned by `build_flake_to_slot` through this helper;
/// that internal shape resolves directly against the slot registry. Every
/// other non-existent bare argument remains a missing-path error: name-keyed
/// template slots are gone.
pub fn resolve_manifest_arg(arg: &str) -> Result<ManifestArgRef> {
    use mvm_core::manifest::{canonical_key_for_path, resolve_manifest_config_path};

    // `<template>@<alias>` form. Aliases live in the
    // template-tags catalog; we resolve them up front so a typo
    // surfaces as "alias not found" rather than booting the
    // current revision silently. Today we validate the alias and
    // log the revision_hash; piping the resolved hash through to
    // skip `current` and boot the aliased revision is a follow-up
    // chunk that needs lifecycle.rs plumbing.
    if let Some((template_id, alias)) = mvm_core::domain::template_tags::split_aliased_ref(arg) {
        match mvm_core::domain::template_tags::resolve_alias(template_id, alias) {
            Some(revision_hash) => {
                tracing::info!(
                    template = template_id,
                    alias,
                    revision_hash,
                    "manifest alias resolved",
                );
                // The alias resolves, but pinning the boot to
                // `revision_hash` needs lifecycle plumbing that does not
                // exist. With no name-keyed slot to fall back to there is
                // nothing to boot, so say so rather than silently booting
                // `current` under an alias the caller asked to pin.
                anyhow::bail!(
                    "manifest alias {alias:?} for template {template_id:?} resolves to \
                     revision {revision_hash}, but booting a pinned revision is not \
                     implemented; pass the manifest path instead"
                );
            }
            None => {
                anyhow::bail!(
                    "manifest alias {alias:?} for template {template_id:?} not found \
                     (run `mvmctl manifest alias ls {template_id}` to see available aliases)"
                );
            }
        }
    }

    let path = std::path::Path::new(arg);
    if !path.exists() {
        if mvm_core::manifest::is_slot_hash_dirname(arg) {
            let spec = mvm_runtime::vm::template::lifecycle::template_load_dispatched(arg)
                .with_context(|| {
                    format!(
                        "Built slot or installed bundle {arg} is not present in the local registry"
                    )
                })?;
            if spec.template_id != arg {
                anyhow::bail!(
                    "Built slot or installed bundle {arg} records mismatched identity {}",
                    spec.template_id
                );
            }
            return Ok(ManifestArgRef::Slot {
                slot_hash: arg.to_string(),
            });
        }
        anyhow::bail!(
            "Manifest path '{}' does not exist (expected a manifest file or its directory)",
            arg
        );
    }

    let manifest_path = resolve_manifest_config_path(path)
        .with_context(|| format!("Resolving --manifest {arg:?}"))?;
    let canonical = std::fs::canonicalize(&manifest_path).with_context(|| {
        format!(
            "Failed to canonicalize manifest path {}",
            manifest_path.display()
        )
    })?;

    // A manifest that selects a wasm module bypasses the build/slot system
    // entirely: the module exists at the declared path and is run directly.
    //
    // Neither half of that is re-derived here. `read_file` resolves a relative
    // `wasm` against the manifest's own directory before it returns, and
    // `canonical` is absolute, so what arrives is always an absolute path;
    // and its `validate` refuses a manifest whose module is not an existing
    // file, on that same resolved path. A second copy of either rule would be
    // free to drift from the one that ran.
    let manifest = mvm_core::domain::manifest::Manifest::read_file(&canonical)
        .with_context(|| format!("Reading manifest {} for wasm source", canonical.display()))?;
    if let Some(wasm) = manifest.wasm.as_deref() {
        return Ok(ManifestArgRef::WasmModule {
            manifest_path: canonical,
            module_path: std::path::PathBuf::from(wasm),
        });
    }

    let slot_hash = canonical_key_for_path(&canonical)?;

    // Verify the slot exists; surface a clear error otherwise so
    // `mvmctl up` doesn't proceed against a manifest that's never
    // been built. The slot's persisted record is dropped here —
    // callers that need it re-read via `template_load_slot`.
    mvm_runtime::vm::template::lifecycle::template_load_slot(&slot_hash).with_context(|| {
        format!(
            "Manifest at {} has no built slot — run `mvmctl build {}` first",
            canonical.display(),
            canonical.display()
        )
    })?;

    Ok(ManifestArgRef::Slot { slot_hash })
}

/// Resolve a flake reference: relative/absolute paths are canonicalized,
/// remote refs (containing `:`) pass through unchanged.
pub fn resolve_flake_ref(flake_ref: &str) -> Result<String> {
    if flake_ref.contains(':') {
        // Remote ref like "github:user/repo" — pass through
        return Ok(flake_ref.to_string());
    }

    // Local path — canonicalize to absolute
    let path = std::path::Path::new(flake_ref);
    let canonical = path
        .canonicalize()
        .with_context(|| format!("Flake path '{}' does not exist", flake_ref))?;

    Ok(canonical.to_string_lossy().to_string())
}

/// How faithfully the resolved `backend` enforces `policy` on the transient
/// (no-signed-bundle) run path. Recorded in the signed receipt **alongside**
/// the requested `network_posture` so a verifier never mistakes a requested
/// `host:port` allow-list for port-level enforcement on a backend that only
/// gates the host name.
///
/// - **deny-all** → `flow-drop` and **unrestricted** → `open`: enforced
///   identically on every backend (the flow-open gate / no gate), so the tier
///   is backend-independent.
/// - An **allow-list / preset** is host **and** port enforced on every
///   claim-bearing backend: the per-VM network endpoint's `EgressGate` decides each
///   destination against the admission-time DNS pins (a direct-IP dial to an
///   unlisted address is refused, not just an unlisted name). The tier is
///   uniformly `<backend>:l4-host-port`; the backend is still named so the
///   receipt records which backend ran the workload.
pub fn egress_enforcement_label(
    backend: &str,
    policy: &mvm_core::network_policy::NetworkPolicy,
) -> String {
    if policy.is_unrestricted() {
        return "open".to_string();
    }
    match policy.resolve_rules() {
        // Some(empty) = deny-all: every egress flow dropped at the gate, uniform.
        Some(rules) if rules.is_empty() => "flow-drop".to_string(),
        // Allow-list / preset with rules: host:port L4-enforced on every backend.
        _ => format!("{backend}:l4-host-port"),
    }
}

// `resolve_optional_network_policy` was used by a since-removed
// template-create flag to bake a default policy into the TemplateSpec.
// With that namespace gone and `[network]` removed from `mvm.toml`,
// runtime policy now lives entirely in `machine run --net` /
// `--allow-host`, the user-global config, and mvmd tenant config.
// Function deleted; the `resolve_network_policy` form (always returns
// Some) is the only remaining helper.

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::manifest::{MANIFEST_SCHEMA_VERSION, PersistedManifest, Provenance};
    use mvm_core::network_policy::{HostPort, NetworkPolicy};
    use mvm_core::util::test_env::TestEnv;

    fn persist_flake_slot(slot_hash: &str) {
        let now = mvm_core::time::utc_now();
        let persisted = PersistedManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            manifest_path: "<flake-slot>/fixture".to_string(),
            manifest_hash: slot_hash.to_string(),
            flake_ref: "/tmp/fixture-flake".to_string(),
            profile: "default".to_string(),
            vcpus: 2,
            mem_mib: 512,
            mem_initial_mib: None,
            data_disk_mib: 0,
            name: None,
            backend: "mock".to_string(),
            provenance: Provenance::current(),
            created_at: now.clone(),
            updated_at: now,
        };
        mvm_runtime::vm::template::lifecycle::template_persist_slot(&persisted)
            .expect("persist flake slot");
    }

    fn persist_installed_bundle(bundle_sha: &str) {
        let bundle_dir = mvm_core::config::bundles_dir().join(bundle_sha);
        std::fs::create_dir_all(bundle_dir.join("artifacts")).expect("create bundle artifacts");
        std::fs::write(bundle_dir.join("artifacts/vmlinux"), b"kernel")
            .expect("write bundle kernel");
        std::fs::write(bundle_dir.join("artifacts/rootfs.ext4"), b"rootfs")
            .expect("write bundle rootfs");
        let manifest = serde_json::json!({
            "schema_version": mvm_core::plan::bundle::BUNDLE_SCHEMA_VERSION,
            "publisher": "resolver-test",
            "key_id": "0123456789abcdef0123456789abcdef",
            "arch": mvm_core::arch::GuestArch::host().to_string(),
            "created_at": "2026-08-28T00:00:00Z",
            "artifacts": [
                {
                    "name": "kernel",
                    "role": "kernel",
                    "path": "artifacts/vmlinux",
                    "sha256": "0".repeat(64),
                    "size_bytes": 6
                },
                {
                    "name": "rootfs",
                    "role": "rootfs",
                    "path": "artifacts/rootfs.ext4",
                    "sha256": "1".repeat(64),
                    "size_bytes": 6
                }
            ]
        });
        std::fs::write(
            bundle_dir.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("encode bundle manifest"),
        )
        .expect("write bundle manifest");
    }

    #[test]
    fn a_materialized_flake_slot_hash_resolves_through_the_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let slot_hash = "a".repeat(64);
        persist_flake_slot(&slot_hash);

        let resolved = resolve_manifest_arg(&slot_hash).expect("built slot must resolve");

        assert!(matches!(resolved, ManifestArgRef::Slot { slot_hash: got } if got == slot_hash));
    }

    #[test]
    fn an_installed_bundle_hash_resolves_through_the_bundle_registry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let bundle_sha = "e".repeat(64);
        persist_installed_bundle(&bundle_sha);

        let resolved = resolve_manifest_arg(&bundle_sha).expect("installed bundle must resolve");

        assert!(matches!(resolved, ManifestArgRef::Slot { slot_hash } if slot_hash == bundle_sha));
    }

    #[test]
    fn an_unknown_slot_hash_fails_closed_as_a_registry_lookup() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let slot_hash = "b".repeat(64);

        let err = resolve_manifest_arg(&slot_hash).expect_err("unknown slot must fail");

        assert!(
            format!("{err:#}").contains("not present in the local registry"),
            "the refusal must identify a missing registry slot: {err:#}"
        );
    }

    #[test]
    fn a_slot_record_with_a_mismatched_identity_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(tmp.path());
        let requested = "c".repeat(64);
        let recorded = "d".repeat(64);
        let now = mvm_core::time::utc_now();
        let persisted = PersistedManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            manifest_path: "<flake-slot>/fixture".to_string(),
            manifest_hash: recorded.clone(),
            flake_ref: "/tmp/fixture-flake".to_string(),
            profile: "default".to_string(),
            vcpus: 2,
            mem_mib: 512,
            mem_initial_mib: None,
            data_disk_mib: 0,
            name: None,
            backend: "mock".to_string(),
            provenance: Provenance::current(),
            created_at: now.clone(),
            updated_at: now,
        };
        let slot_dir = mvm_core::manifest::slot_dir(&requested);
        persisted
            .write_to_slot(std::path::Path::new(&slot_dir))
            .expect("persist mismatched slot record");

        let err = resolve_manifest_arg(&requested).expect_err("mismatch must fail");

        assert!(
            format!("{err:#}").contains(&format!("mismatched identity {recorded}")),
            "the refusal must identify the recorded identity: {err:#}"
        );
    }

    /// A bare directory name is a manifest *path*, not a registry name.
    ///
    /// `looks_like_path` is a chain of `||`s ending in `path.is_dir()`.
    /// Replacing that last `||` with `&&` binds tighter, collapsing the tail to
    /// `path.is_file() && path.is_dir()` — which no path satisfies. A bare name
    /// that is really a directory then gets misread as a legacy registry name,
    /// and every earlier operand misses it: no `/`, no leading `.`, no `.toml`.
    ///
    /// Changes the process working directory, which is safe here because the
    /// named test gate is nextest and nextest runs one process per test.
    #[test]
    fn a_bare_directory_name_is_treated_as_a_path_not_a_registry_name() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // No slash, no leading dot, no .toml — only `is_dir` can classify it.
        let bare = "manifestdir";
        std::fs::create_dir(tmp.path().join(bare)).expect("create dir");

        let previous = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(tmp.path()).expect("chdir");
        let resolved = resolve_manifest_arg(bare);
        std::env::set_current_dir(previous).expect("restore cwd");

        // It resolves as a path — which fails, because the directory holds no
        // manifest. Every argument is a path now, so the only outcome a bare
        // directory can have is a manifest-not-found error.
        assert!(
            resolved.is_err(),
            "a directory with no manifest must fail rather than resolve"
        );
    }

    /// A relative wasm module resolves against the manifest's own directory.
    ///
    /// `Manifest::read_file` is what does that, before this function sees the
    /// path. The `if !module_path.is_absolute()` join that used to sit here
    /// re-derived the same rule and could not change the outcome either way,
    /// which is why deleting its `!` left every test passing; it is gone, and
    /// this asserts the resolution the caller actually depends on.
    #[test]
    fn a_relative_wasm_module_resolves_against_the_manifest_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("mvm.toml");
        std::fs::write(dir.path().join("app.wasm"), b"\0asm").expect("write module");
        std::fs::write(&manifest, "wasm = \"app.wasm\"\n").expect("write manifest");

        let resolved = resolve_manifest_arg(manifest.to_str().expect("utf8 path"))
            .expect("a manifest naming a module beside it must resolve");
        match resolved {
            ManifestArgRef::WasmModule { module_path, .. } => assert_eq!(
                module_path.canonicalize().ok(),
                dir.path().join("app.wasm").canonicalize().ok(),
                "the module must resolve beside the manifest, not against the cwd"
            ),
            other => panic!("expected a WasmModule, got {other:?}"),
        }
    }

    #[test]
    fn enforcement_tier_uniform_for_deny_all_and_unrestricted() {
        // deny-all and unrestricted are enforced the same way on every backend,
        // so the receipt records a backend-independent tier.
        for backend in ["firecracker", "libkrun"] {
            assert_eq!(
                egress_enforcement_label(backend, &NetworkPolicy::deny_all()),
                "flow-drop"
            );
            assert_eq!(
                egress_enforcement_label(backend, &NetworkPolicy::unrestricted()),
                "open"
            );
        }
    }

    #[test]
    fn enforcement_tier_allow_list_is_uniform_l4_host_port() {
        // host:port is now L4-enforced on every backend (Firecracker nftables;
        // libkrun via the admission-time DNS pin → L4 scan), so the receipt
        // records `<backend>:l4-host-port` uniformly — no more `dns-name-only`.
        let p = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        assert_eq!(
            egress_enforcement_label("firecracker", &p),
            "firecracker:l4-host-port"
        );
        assert_eq!(
            egress_enforcement_label("libkrun", &p),
            "libkrun:l4-host-port"
        );
    }

    /// The module path handed on is absolute either way the manifest names it,
    /// and the manifest may be given as its directory rather than its file.
    ///
    /// The absolute form is the arm the deleted `is_absolute` join used to
    /// skip, so nothing covered it; the relative form re-confirms through the
    /// directory entry point that `Manifest::read_file` is doing the
    /// resolution. Absoluteness is asserted because callers hand this straight
    /// to the wasm backend, which never sees the manifest's directory.
    #[test]
    fn a_wasm_manifest_resolves_to_the_absolute_module_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let module = tmp.path().join("app.wasm");
        std::fs::write(&module, b"\0asm").expect("write module");
        let canonical_module = std::fs::canonicalize(&module).expect("canonicalize module");

        // The relative form: resolved against the manifest's directory.
        let relative_dir = tmp.path().join("relative");
        std::fs::create_dir(&relative_dir).expect("create dir");
        std::fs::write(
            relative_dir.join("mvm.toml"),
            b"name = \"wasm-app\"\nwasm = \"../app.wasm\"\n",
        )
        .expect("write manifest");

        // The absolute form: taken as written.
        let absolute_dir = tmp.path().join("absolute");
        std::fs::create_dir(&absolute_dir).expect("create dir");
        std::fs::write(
            absolute_dir.join("mvm.toml"),
            format!("name = \"wasm-app\"\nwasm = \"{}\"\n", module.display()).as_bytes(),
        )
        .expect("write manifest");

        for dir in [&relative_dir, &absolute_dir] {
            match resolve_manifest_arg(&dir.to_string_lossy()).unwrap_or_else(|e| {
                panic!("a wasm manifest in {} must resolve: {e}", dir.display())
            }) {
                ManifestArgRef::WasmModule { module_path, .. } => {
                    assert!(
                        module_path.is_absolute(),
                        "the module path handed on must be absolute: {}",
                        module_path.display()
                    );
                    assert_eq!(
                        std::fs::canonicalize(&module_path).expect("canonicalize resolved module"),
                        canonical_module,
                        "resolved to a different module than the manifest named"
                    );
                }
                other => panic!("a wasm manifest must resolve to WasmModule, got {other:?}"),
            }
        }
    }

    /// A manifest whose wasm module is missing is refused, not booted.
    #[test]
    fn a_wasm_manifest_naming_a_missing_module_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("mvm.toml"),
            b"name = \"wasm-app\"\nwasm = \"absent.wasm\"\n",
        )
        .expect("write manifest");

        let err = resolve_manifest_arg(&tmp.path().to_string_lossy())
            .expect_err("a manifest naming a module that is not there must not resolve");
        // The refusal comes from the manifest read, which validates the module
        // exists before this function sees the path -- the reason there is no
        // second existence check here.
        assert!(
            format!("{err:#}").contains("existing file"),
            "refusal must name the missing module; got: {err:#}"
        );
    }

    /// `looks_like_path` is a five-way disjunction deciding whether a
    /// `--manifest` argument is a path or a legacy slot name. Four of its
    /// five disjuncts could be turned into conjunctions and both of the
    /// surrounding negations deleted without any test noticing, so each
    /// disjunct needs a case that *only* it satisfies.
    #[test]
    fn a_manifest_argument_is_a_path_on_any_one_signal_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");

        // A bare name is no longer a slot lookup: name-keyed slots are gone,
        // so it is just a path that does not exist.
        assert!(
            resolve_manifest_arg("openclaw").is_err(),
            "a bare name must fail as a missing path, not resolve to a slot"
        );

        // Each signal alone is enough to be treated as a path. None of
        // these exist, so the attempt must fail as a *missing path*
        // rather than fall through to a slot name.
        for arg in ["has/slash", ".leading-dot", "trailing.toml"] {
            let err = resolve_manifest_arg(arg)
                .expect_err("a path-shaped argument that does not exist must fail");
            assert!(
                err.to_string().contains("does not exist"),
                "{arg} must be treated as a path, got: {err}"
            );
        }

        // The two filesystem signals, isolated: a name with no slash, no
        // leading dot and no .toml suffix, that exists as a file, and one
        // that exists as a directory. Both must be paths.
        let file = tmp.path().join("plainfile");
        std::fs::write(&file, b"x").unwrap();
        let dir = tmp.path().join("plaindir");
        std::fs::create_dir_all(&dir).unwrap();
        // Use the absolute paths (they contain a slash, so also exercise
        // the happy path through to the existence check).
        for p in [&file, &dir] {
            let got = resolve_manifest_arg(&p.to_string_lossy());
            assert!(
                got.is_ok() || format!("{:?}", got).contains("manifest"),
                "an existing path must not be rejected as a missing one: {got:?}"
            );
        }
    }
}

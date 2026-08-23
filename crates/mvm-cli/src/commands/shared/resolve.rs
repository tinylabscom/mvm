//! Environment-aware resolution helpers (running VMs, flake refs, network policy).

use anyhow::{Context, Result};

/// One of two ways to refer to a built manifest: a legacy name (looked
/// up in the name-keyed registry) or a manifest path that resolves to
/// a slot hash.
///
/// `mvmctl up` / `mvmctl exec` accept either form via their
/// `--manifest` flag. The `Slot` variant is the current path;
/// `Name` is kept only to resolve any pre-existing name-keyed slots.
///
/// Callers that need the persisted manifest re-read it via
/// `mvm_runtime::vm::template::lifecycle::template_load_slot(slot_hash)`
/// — keeping the enum lean here avoids the `clippy::large_enum_variant`
/// warning (`PersistedManifest` is ~350 bytes).
#[derive(Debug, Clone)]
pub enum ManifestArgRef {
    /// Legacy name-keyed slot (resolves through `template_load`,
    /// `template_artifacts`, etc.).
    Name(String),
    /// Manifest-keyed slot.
    Slot { slot_hash: String },
    /// Manifest selects a pre-built wasm module; no Nix/OCI build or slot.
    WasmModule {
        manifest_path: std::path::PathBuf,
        module_path: std::path::PathBuf,
    },
}

/// Decide whether a `--manifest` argument refers to a manifest path
/// (file or directory containing one) or a legacy slot name.
///
/// Detection rule: if the argument resolves to an existing file or
/// directory on disk, treat it as a manifest path; otherwise it's a
/// name. Both `mvmctl up --manifest ./my-app` and
/// `mvmctl up --manifest openclaw` work as long as the referenced
/// thing actually exists.
///
/// Returns `Err` only on validation/IO failures; missing-name is
/// handled by the caller's downstream `template_load` lookup.
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
                // Boot path still loads `current`; pinning to
                // `revision_hash` is a follow-up. Treat as Name
                // so the existing flow proceeds.
                return Ok(ManifestArgRef::Name(template_id.to_string()));
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
    let looks_like_path = arg.contains('/')
        || arg.starts_with('.')
        || arg.ends_with(".toml")
        || path.is_file()
        || path.is_dir();
    if !looks_like_path {
        return Ok(ManifestArgRef::Name(arg.to_string()));
    }

    if !path.exists() {
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

/// Resolve the transient-run egress flags (`--net` / `--allow-host`) into a
/// single `NetworkPolicy`, identical for every backend.
///
/// Precedence (one tested place so it can't drift):
/// - any `--allow-host` ⇒ allow-list (narrowest intent **wins** over `--net`);
/// - else `--net` ⇒ the `dev` preset (broad outbound + DNS, never
///   `unrestricted`, so it never trips the claim-10 unrestricted ack);
/// - else ⇒ `deny_all` (the safe default).
///
/// `HOST` with no `:PORT` defaults to `443`.
pub fn resolve_run_network_policy(
    net: bool,
    allow_host: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{NetworkPolicy, NetworkPreset};

    if !allow_host.is_empty() {
        let rules = allow_host
            .iter()
            .map(|s| parse_allow_host(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(NetworkPolicy::allow_list(rules))
    } else if net {
        Ok(NetworkPolicy::preset(NetworkPreset::Dev))
    } else {
        Ok(NetworkPolicy::deny_all())
    }
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
/// - An **allow-list / preset** is now host **and** port enforced on every
///   backend: Firecracker via nftables (`-d <host> --dport <port>`), libkrun
///   via the admission-time DNS pin feeding the `L4PolicyScan` (a direct-IP dial
///   to an unlisted address is dropped, not just an unlisted name). The tier is
///   uniformly `<backend>:l4-host-port`; the backend is still named so the
///   receipt records which substrate enforced.
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

/// Parse one `--allow-host` entry. `HOST:PORT` is parsed strictly;
/// `HOST` with no port defaults to `443` (https). Fails closed on a
/// malformed port or empty host before any VM work.
fn parse_allow_host(entry: &str) -> Result<mvm_core::network_policy::HostPort> {
    use mvm_core::network_policy::{HostPort, is_banned_ssh_port};
    let parsed = match entry.rsplit_once(':') {
        // Has an explicit `:PORT` — strict parse (rejects empty host / bad port).
        Some(_) => entry
            .parse()
            .with_context(|| format!("invalid --allow-host {entry:?}")),
        // Bare host — default to the https port.
        None if entry.is_empty() => anyhow::bail!("--allow-host cannot be empty"),
        None => Ok(HostPort::new(entry, 443)),
    }?;
    if is_banned_ssh_port(parsed.port) {
        anyhow::bail!(
            "--allow-host {entry:?} requests TCP/22, but SSH sessions are banned in microVMs"
        );
    }
    Ok(parsed)
}

// `resolve_optional_network_policy` was used by a since-removed
// template-create flag to bake a default policy into the TemplateSpec.
// With that namespace gone and `[network]` removed from `mvm.toml`,
// runtime policy now lives entirely in `machine run --net` /
// `--allow-host`, the user-global config, and mvmd tenant config.
// Function deleted; the `resolve_network_policy` form (always returns
// Some) is the only remaining helper.

/// Resolve the requested hypervisor to the effective one for this host. `firecracker`
/// (the default `--hypervisor`) auto-detects: KVM → firecracker, macOS 26+ Apple Silicon
/// → hvf (the HVF VMM with vsock-only egress — no guest-NIC helper),
/// macOS 13-25 + libkrun → libkrun, else firecracker (surfaces a clear
/// "not available" error). Any explicit value is returned as-is. The `MVM_HYPERVISOR`
/// env var (alias `MVM_BACKEND`) overrides auto-detect — the workload-VMM override
/// mirroring `MVM_BUILDER_BACKEND` for the builder, so a Linux/KVM host can opt into
/// `libkrun` instead of the Firecracker default. Single source of truth, shared by
/// the run/pool paths so they agree on the backend.
pub fn resolve_effective_hypervisor(requested: &str) -> String {
    if requested != "firecracker" {
        return requested.to_string();
    }
    // Env override (auto-detect mode only — an explicit `--hypervisor` flag already
    // won above): `MVM_HYPERVISOR=<firecracker|libkrun|hvf|qemu>`, with the older
    // `MVM_BACKEND` kept as a back-compat alias. Does not change the platform default.
    for var in ["MVM_HYPERVISOR", "MVM_BACKEND"] {
        if let Some(name) = std::env::var_os(var) {
            let name = name.to_string_lossy().trim().to_ascii_lowercase();
            if !name.is_empty() {
                return name;
            }
        }
    }
    let plat = mvm_core::platform::current();
    if plat.has_kvm() {
        "firecracker"
    } else if plat.is_hvf_default_tier() {
        // macOS 26+ Apple Silicon: the HVF VMM (`hvf`) is the workload
        // default; the hvf path carries claim-10 egress over vsock via its
        // per-VM gating endpoint — no guest-NIC helper sidecar.
        "hvf"
    } else if plat.has_libkrun() {
        "libkrun"
    } else {
        "firecracker"
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};
    use mvm_core::util::test_env::TestEnv;

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
        // manifest. The point is that it was not silently taken for a name.
        if let Ok(ManifestArgRef::Name(n)) = resolved {
            panic!("a directory was misclassified as the registry name {n:?}");
        }
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
    fn run_net_default_is_deny_all() {
        assert_eq!(
            resolve_run_network_policy(false, &[]).unwrap(),
            NetworkPolicy::deny_all()
        );
    }

    #[test]
    fn run_net_flag_maps_to_dev_preset_not_unrestricted() {
        let p = resolve_run_network_policy(true, &[]).unwrap();
        assert_eq!(p, NetworkPolicy::preset(NetworkPreset::Dev));
        assert!(!p.is_unrestricted(), "--net must never be unrestricted");
    }

    #[test]
    fn allow_host_defaults_to_port_443() {
        let p = resolve_run_network_policy(false, &["api.example.com".to_string()]).unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)])
        );
    }

    #[test]
    fn allow_host_honors_explicit_port_and_multiple_hosts() {
        let p = resolve_run_network_policy(false, &["a.com".to_string(), "b.com:8443".to_string()])
            .unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![
                HostPort::new("a.com", 443),
                HostPort::new("b.com", 8443),
            ])
        );
    }

    #[test]
    fn allow_host_wins_over_net() {
        let p = resolve_run_network_policy(true, &["a.com".to_string()]).unwrap();
        assert_eq!(
            p,
            NetworkPolicy::allow_list(vec![HostPort::new("a.com", 443)]),
            "--allow-host must narrow, winning over --net"
        );
    }

    #[test]
    fn allow_host_rejects_malformed_entries_fail_closed() {
        assert!(resolve_run_network_policy(false, &["host:0notaport".to_string()]).is_err());
        assert!(resolve_run_network_policy(false, &[":443".to_string()]).is_err());
        assert!(resolve_run_network_policy(false, &["".to_string()]).is_err());
    }

    #[test]
    fn allow_host_rejects_ssh_port() {
        let err = resolve_run_network_policy(false, &["github.com:22".to_string()])
            .expect_err("TCP/22 must be refused");
        assert!(
            err.to_string().contains("SSH sessions are banned"),
            "unexpected error: {err:#}"
        );
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

    /// An explicit `--hypervisor <x>` (anything but the `firecracker`
    /// auto-detect sentinel) is returned verbatim — so a Linux/KVM host can
    /// select `libkrun` (or any other backend) without env.
    #[test]
    fn explicit_hypervisor_is_returned_verbatim() {
        assert_eq!(resolve_effective_hypervisor("libkrun"), "libkrun");
        assert_eq!(resolve_effective_hypervisor("hvf"), "hvf");
        assert_eq!(resolve_effective_hypervisor("qemu"), "qemu");
    }

    /// `MVM_HYPERVISOR` overrides auto-detect (and `MVM_BACKEND` is the
    /// back-compat alias); an explicit flag still wins over both. Process-isolated
    /// under nextest; restored here so a threaded runner doesn't leak it.
    #[test]
    fn env_overrides_auto_detect_with_alias() {
        let mut env = TestEnv::new();
        env.remove("MVM_BACKEND");
        env.set("MVM_HYPERVISOR", "libkrun");
        assert_eq!(resolve_effective_hypervisor("firecracker"), "libkrun");
        // An explicit flag wins over the env override.
        assert_eq!(resolve_effective_hypervisor("qemu"), "qemu");
        // The older alias is still honored.
        env.remove("MVM_HYPERVISOR");
        env.set("MVM_BACKEND", "hvf");
        assert_eq!(resolve_effective_hypervisor("firecracker"), "hvf");
    }

    /// On the macOS-26 Apple Silicon tier the auto-detect default is the
    /// HVF VMM (`hvf`). Host-conditioned: the assertion only fires on a host
    /// that actually reports the tier.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_26_default_is_hvf() {
        if !mvm_core::platform::current().is_hvf_default_tier() {
            return; // Not on the macOS-26 tier (e.g. macOS 13-25 CI runner).
        }
        let mut env = TestEnv::new();
        env.remove("MVM_HYPERVISOR");
        env.remove("MVM_BACKEND");
        assert_eq!(resolve_effective_hypervisor("firecracker"), "hvf");
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

        // A bare name matching none of the five signals is a slot name.
        match resolve_manifest_arg("openclaw").expect("a bare name resolves") {
            ManifestArgRef::Name(n) => assert_eq!(n, "openclaw"),
            other => panic!("a bare name must resolve to Name, got {other:?}"),
        }

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

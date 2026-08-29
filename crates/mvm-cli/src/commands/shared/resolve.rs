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
    resolve_run_network_policy_with_peers(net, allow_host, &[])
}

/// As [`resolve_run_network_policy`], plus the `--peer` routes.
///
/// Peers are orthogonal to the egress arms above: a workload may dial a peer
/// while admitting no outbound egress at all, which is the common shape for a
/// service that only talks to its own database. So the peer set is attached to
/// whichever policy the egress precedence selected rather than being an arm of
/// it.
pub fn resolve_run_network_policy_with_peers(
    net: bool,
    allow_host: &[String],
    peer: &[String],
) -> Result<mvm_core::network_policy::NetworkPolicy> {
    use mvm_core::network_policy::{NetworkPolicy, NetworkPreset};

    let base = if !allow_host.is_empty() {
        let rules = allow_host
            .iter()
            .map(|s| parse_allow_host(s))
            .collect::<Result<Vec<_>>>()?;
        NetworkPolicy::allow_list(rules)
    } else if net {
        NetworkPolicy::preset(NetworkPreset::Dev)
    } else {
        NetworkPolicy::deny_all()
    };

    if peer.is_empty() {
        return Ok(base);
    }
    let peers = peer
        .iter()
        .map(|s| parse_peer_binding(s))
        .collect::<Result<Vec<_>>>()?;
    Ok(base.with_peers(peers))
}

/// Parse `--peer NAME:PORT=ADDR:PORT` into a validated binding.
///
/// Both halves are required and neither is inferred. The left is what the
/// guest dials; the right is the peer's admitted ingress address. Refusing
/// here rather than at the gate keeps a malformed route out of the signed
/// plan, where it would read as an admitted destination that never resolves.
pub fn parse_peer_binding(raw: &str) -> Result<mvm_contract::peer::PeerBinding> {
    let (dialed, target) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid --peer '{raw}': expected NAME:PORT=ADDR:PORT"))?;
    let (name, port) = dialed
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid --peer '{raw}': the dialed side needs a :PORT"))?;
    let (host_addr, host_port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid --peer '{raw}': the target side needs a :PORT"))?;

    let binding = mvm_contract::peer::PeerBinding {
        name: mvm_contract::peer::PeerName::parse(name)
            .map_err(|e| anyhow::anyhow!("invalid --peer '{raw}': {e}"))?,
        port: port
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid --peer '{raw}': '{port}' is not a port"))?,
        host_addr: host_addr.to_string(),
        host_port: host_port
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid --peer '{raw}': '{host_port}' is not a port"))?,
    };
    binding
        .validate()
        .map_err(|e| anyhow::anyhow!("invalid --peer '{raw}': {e}"))?;
    Ok(binding)
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
    use mvm_core::manifest::{MANIFEST_SCHEMA_VERSION, PersistedManifest, Provenance};
    use mvm_core::network_policy::{HostPort, NetworkPolicy, NetworkPreset};
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
        let bundle_dir = std::path::PathBuf::from(mvm_core::config::mvm_home())
            .join("bundles")
            .join(bundle_sha);
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

#[cfg(test)]
mod peer_flag_tests {
    use super::*;

    #[test]
    fn a_well_formed_peer_parses_into_a_binding() {
        let b = parse_peer_binding("db.mvm.peer:5432=127.0.0.1:34567").expect("parses");
        assert_eq!(b.name.as_str(), "db.mvm.peer");
        assert_eq!(b.port, 5432);
        assert_eq!(b.host_addr, "127.0.0.1");
        assert_eq!(b.host_port, 34567);
    }

    /// Refused at the CLI rather than at the gate, so a malformed route never
    /// reaches the signed plan, where it would read as an admitted
    /// destination that happens never to resolve.
    #[test]
    fn a_malformed_peer_is_refused_at_the_boundary() {
        for bad in [
            "db.mvm.peer:5432",                 // no target
            "db.mvm.peer=127.0.0.1:34567",      // no dialed port
            "db.mvm.peer:5432=127.0.0.1",       // no target port
            "api.example.com:443=127.0.0.1:80", // not a peer name
            "db.mvm.peer:0=127.0.0.1:34567",    // zero port
            "db.mvm.peer:5432=db.internal:80",  // target is not a literal ip
            "db.mvm.peer:x=127.0.0.1:34567",    // port is not a number
        ] {
            assert!(
                parse_peer_binding(bad).is_err(),
                "expected `{bad}` to be refused"
            );
        }
    }

    /// Peers are orthogonal to the egress arms: the common shape is a service
    /// that talks only to its own database and admits no outbound egress.
    #[test]
    fn peers_attach_to_whichever_egress_arm_was_selected() {
        let peer = vec!["db.mvm.peer:5432=127.0.0.1:34567".to_string()];

        let denied = resolve_run_network_policy_with_peers(false, &[], &peer).expect("resolves");
        assert_eq!(denied.peers().len(), 1, "deny-all still carries its peers");

        let dev = resolve_run_network_policy_with_peers(true, &[], &peer).expect("resolves");
        assert_eq!(dev.peers().len(), 1);

        let allow = resolve_run_network_policy_with_peers(false, &["a.com".to_string()], &peer)
            .expect("resolves");
        assert_eq!(allow.peers().len(), 1);
    }

    #[test]
    fn no_peer_flag_leaves_the_policy_unchanged() {
        let p = resolve_run_network_policy_with_peers(false, &[], &[]).expect("resolves");
        assert!(p.peers().is_empty());
        assert_eq!(p, resolve_run_network_policy(false, &[]).expect("resolves"));
    }
}

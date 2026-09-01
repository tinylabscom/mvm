#[cfg(feature = "builder-vm")]
use super::kernel::{
    KernelSource, download_builder_kernel, resolve_kernel_source,
    run_stage0_rootfs_with_external_kernel,
};
#[cfg(feature = "builder-vm")]
use super::stage0_cache::write_builder_vm_cache_sidecars;
#[cfg(feature = "builder-vm")]
use super::stage0_cache::{
    acquire_stage0_lock, promote_builder_vm_stage0_cache, stage0_failure_reason_summary,
    stage0_fingerprint_prefix, unique_builder_vm_stage0_staging_dir,
};
use super::stage0_cache::{
    builder_vm_source_cache_status, builder_vm_source_fingerprint,
    validate_builder_vm_stage0_artifacts,
};
use super::*;
#[cfg(test)]
use serde::Deserialize;
#[cfg(test)]
use std::collections::HashMap;

#[cfg(test)]
pub(super) fn first_nameserver_from_resolv_conf(body: &str) -> Option<String> {
    mvm_agentd::guest_net::first_nameserver_from_resolv_conf(body)
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Stage0InputOverride {
    pub input_path: String,
    pub guest_path: String,
}

#[cfg(test)]
pub(super) fn stage0_build_conf_contents(
    build_attr: &str,
    output_mode: &str,
    resolver: Option<&str>,
    workspace_archive: Option<&str>,
    offline: bool,
    input_overrides: &[Stage0InputOverride],
) -> String {
    let mut out =
        format!("MVM_STAGE0_BUILD_ATTR={build_attr}\nMVM_STAGE0_OUTPUT_MODE={output_mode}\n");
    if let Some(resolver) = resolver {
        out.push_str(&format!("MVM_STAGE0_RESOLVER={resolver}\n"));
    }
    if let Some(workspace_archive) = workspace_archive {
        out.push_str(&format!(
            "MVM_STAGE0_WORKSPACE_ARCHIVE={workspace_archive}\n"
        ));
    }
    if offline {
        out.push_str("MVM_STAGE0_OFFLINE=1\n");
    }
    for (idx, override_) in input_overrides.iter().enumerate() {
        out.push_str(&format!(
            "MVM_STAGE0_OVERRIDE_INPUT_{idx}={}={}\n",
            override_.input_path, override_.guest_path
        ));
    }
    out
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct Stage0FlakeLock {
    nodes: HashMap<String, Stage0FlakeLockNode>,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct Stage0FlakeLockNode {
    locked: Option<Stage0FlakeLockSource>,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
struct Stage0FlakeLockSource {
    #[serde(rename = "type")]
    kind: String,
    owner: Option<String>,
    repo: Option<String>,
    rev: Option<String>,
    url: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Stage0RemoteInput {
    Github {
        owner: String,
        repo: String,
        rev: String,
    },
    Git {
        url: String,
        rev: String,
    },
}

#[cfg(test)]
pub(super) fn stage0_locked_input_sources(
    builder_flake_dir: &str,
) -> Result<Vec<(&'static str, &'static str, Stage0RemoteInput)>> {
    let lock_path = std::path::Path::new(builder_flake_dir).join("flake.lock");
    let body = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let lock: Stage0FlakeLock =
        serde_json::from_str(&body).with_context(|| format!("parsing {}", lock_path.display()))?;
    let mut out = Vec::new();
    for (node_name, input_path, guest_name) in [
        ("nixpkgs", "nixpkgs", "nixpkgs"),
        ("microvm", "microvm", "microvm"),
        ("spectrum", "microvm/spectrum", "spectrum"),
    ] {
        let node = lock
            .nodes
            .get(node_name)
            .ok_or_else(|| anyhow::anyhow!("flake.lock missing node {node_name}"))?;
        let locked = node
            .locked
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("flake.lock node {node_name} has no locked source"))?;
        let source =
            match locked.kind.as_str() {
                "github" => Stage0RemoteInput::Github {
                    owner: locked.owner.clone().ok_or_else(|| {
                        anyhow::anyhow!("flake.lock node {node_name} missing owner")
                    })?,
                    repo: locked.repo.clone().ok_or_else(|| {
                        anyhow::anyhow!("flake.lock node {node_name} missing repo")
                    })?,
                    rev: locked.rev.clone().ok_or_else(|| {
                        anyhow::anyhow!("flake.lock node {node_name} missing rev")
                    })?,
                },
                "git" => Stage0RemoteInput::Git {
                    url: locked.url.clone().ok_or_else(|| {
                        anyhow::anyhow!("flake.lock node {node_name} missing url")
                    })?,
                    rev: locked.rev.clone().ok_or_else(|| {
                        anyhow::anyhow!("flake.lock node {node_name} missing rev")
                    })?,
                },
                other => {
                    anyhow::bail!("unsupported flake.lock source type {other} for node {node_name}")
                }
            };
        out.push((input_path, guest_name, source));
    }
    Ok(out)
}

pub(in crate::commands) fn bootstrap_builder_vm_image() -> Result<()> {
    let arch = builder_vm_host_arch();
    let out_dir = format!("{}/builder-vm/{arch}", mvm_core::config::mvm_cache_dir());
    let out_dir_path = std::path::Path::new(&out_dir);
    let builder_flake = find_builder_vm_flake();
    let acquisition = mvm_build::boot_image_select::resolve(None, builder_flake.is_ok()).choice;
    let source_fingerprint = match acquisition {
        mvm_build::boot_image_select::BootImageAcquisition::Build => builder_flake
            .as_ref()
            .ok()
            .map(|flake_dir| builder_vm_source_fingerprint(flake_dir))
            .transpose()?,
        mvm_build::boot_image_select::BootImageAcquisition::Fetch => None,
    };
    let cache_ready = match source_fingerprint.as_deref() {
        Some(fingerprint) => {
            let status = builder_vm_source_cache_status(out_dir_path, fingerprint);
            ui::progress(&format!(
                "Builder VM source cache decision: {}",
                status.reason_code()
            ));
            status.is_ready()
        }
        None => validate_builder_vm_stage0_artifacts(out_dir_path).is_ok(),
    };

    match resolve_builder_vm_bootstrap_action(builder_flake, cache_ready, acquisition)? {
        BuilderVmBootstrapAction::UseCached => {
            ui::info(&format!("Builder VM image already cached at {out_dir}."));
            Ok(())
        }
        BuilderVmBootstrapAction::BuildFromSource { flake_dir } => {
            #[cfg(feature = "builder-vm")]
            let source_fingerprint = source_fingerprint.ok_or_else(|| {
                anyhow::anyhow!("builder VM source fingerprint was not computed for {flake_dir}")
            })?;
            ui::info(&format!(
                "Builder VM image not in cache; building locally from {flake_dir}..."
            ));

            // The nix-seed root-dir Stage 0 is the only bootstrap
            // path. The dev-image Stage 0 path
            // (bootstrap_builder_vm_image_via_dev_image_stage0) has been
            // removed; `nix/images/builder/flake.nix` is deleted.
            #[cfg(feature = "builder-vm")]
            {
                // `-v`/`RUST_LOG` streams the in-guest nix `--print-build-logs`
                // output live to the terminal. In that mode the streamed lines
                // are the progress signal, so the spinner/heartbeat stays off (it
                // would fight the scrolling output). Quiet mode keeps the spinner:
                // the Stage 0 build is otherwise silent for minutes and would read
                // as a hang.
                let verbose = mvm_runtime::ui::is_verbose();
                let _heartbeat = (!verbose)
                    .then(|| BuildHeartbeat::start("Preparing the builder VM (one-time setup)"));
                bootstrap_builder_vm_image_via_root_dir_stage0(
                    &flake_dir,
                    &out_dir,
                    &source_fingerprint,
                    verbose,
                )
                .context("building the source-checkout builder VM image via root-dir Stage 0")
            }

            #[cfg(not(feature = "builder-vm"))]
            {
                let _ = (&flake_dir, &out_dir, &source_fingerprint, arch);
                anyhow::bail!(
                    "Stage 0 needs the `builder-vm` cargo feature to be enabled \
                     for this `mvmctl` build."
                )
            }
        }
        BuilderVmBootstrapAction::DownloadPublished => {
            perform_builder_vm_download_published(arch, &out_dir)
        }
    }
}

pub(super) fn builder_vm_host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// Cadence of [`BuildHeartbeat`] liveness lines. ~20s keeps a multi-minute
/// Stage 0 build under ~20 lines while never leaving the user wondering for long.
#[cfg(feature = "builder-vm")]
const BUILD_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);

/// RAII liveness ticker for a long, silent blocking step. While alive, a thread
/// emits a periodic [`ui::format_heartbeat`] line so the operation can't be
/// mistaken for a hang — the Stage 0 builder-image build runs `nix` inside the
/// guest with no host-visible output until it completes. Stops + joins on drop,
/// so the build's own return is the natural end of the heartbeat.
#[cfg(feature = "builder-vm")]
pub(super) struct BuildHeartbeat {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    // `Some` on a TTY: an animated spinner whose message is refreshed with the
    // elapsed time. `None` when piped/redirected — there the text path emits a
    // periodic line instead (a spinner draws nothing off a terminal).
    spinner: Option<crate::ui::Spinner>,
}

#[cfg(feature = "builder-vm")]
impl BuildHeartbeat {
    fn start(activity: &'static str) -> Self {
        // On a TTY the animated spinner is the liveness signal and reads far
        // better than a wall of repeating text lines. Off a TTY (pipe, CI, log
        // capture) a spinner renders nothing, so fall back to the periodic text
        // line — routed through `notice`, not `info`, so it survives the default
        // quiet mode where `info` chatter is suppressed.
        if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            Self::start_spinner(activity)
        } else {
            Self::start_with(activity, BUILD_HEARTBEAT_INTERVAL, ui::notice)
        }
    }

    /// TTY path: an `indicatif` spinner refreshed with elapsed time. The spinner
    /// self-animates via its steady tick; this thread only updates the message.
    fn start_spinner(activity: &'static str) -> Self {
        use std::sync::atomic::Ordering;
        let pb = ui::spinner(&ui::format_build_progress(
            activity,
            std::time::Duration::ZERO,
        ));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        let pb_thread = pb.clone();
        let handle = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !thread_stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(250));
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                pb_thread.set_message(ui::format_build_progress(activity, start.elapsed()));
            }
        });
        Self {
            stop,
            handle: Some(handle),
            spinner: Some(pb),
        }
    }

    /// Injectable text core: `interval` and `emit` are parameters so a test can
    /// drive a tight cadence into a counter instead of stdout. Also the non-TTY
    /// runtime path.
    pub(super) fn start_with(
        activity: &'static str,
        interval: std::time::Duration,
        emit: impl Fn(&str) + Send + 'static,
    ) -> Self {
        use std::sync::atomic::Ordering;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = std::sync::Arc::clone(&stop);
        // Poll finely so `drop` is responsive; emit only once per `interval`.
        let poll = interval.min(std::time::Duration::from_millis(250));
        let handle = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut next = interval;
            while !thread_stop.load(Ordering::Relaxed) {
                std::thread::sleep(poll);
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                if start.elapsed() >= next {
                    emit(&ui::format_heartbeat(activity, start.elapsed()));
                    next += interval;
                }
            }
        });
        Self {
            stop,
            handle: Some(handle),
            spinner: None,
        }
    }
}

#[cfg(feature = "builder-vm")]
impl Drop for BuildHeartbeat {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Clear the spinner line so the build's own next output starts clean.
        if let Some(pb) = self.spinner.take() {
            pb.finish_and_clear();
        }
    }
}

/// The only call site that can invoke the published-prebuilt
/// download path. Gated behind `release-artifact-bootstrap`. Contributor
/// builds (the default) hit the `cfg(not(...))` arm and bail structurally
/// — even if the resolver routed here, the function refuses to touch the
/// network. End-user-binary release builds opt in at compile time.
///
/// Extracted from [`bootstrap_builder_vm_image`] specifically so the
/// fail-closed shape is unit-testable.
pub(super) fn perform_builder_vm_download_published(arch: &str, out_dir: &str) -> Result<()> {
    #[cfg(feature = "release-artifact-bootstrap")]
    {
        // Prefer a signed, content-addressed builder pack over the plain
        // checksum download when opted in. The pack is an accelerator, never a
        // hard dependency: no compatible verified pack (or any error placing
        // one) falls through to the download below.
        #[cfg(feature = "builder-vm")]
        if attested_builder_pack::attested_builder_pack_selected() {
            match attested_builder_pack::attempt_attested_builder_pack(arch, out_dir, true) {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => ui::warn(&format!(
                    "Attested builder pack unavailable ({error:#}); falling back to download."
                )),
            }
        }
        ui::info(&format!(
            "Builder VM image not in cache; downloading published prebuilt for v{}...",
            env!("CARGO_PKG_VERSION")
        ));
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("creating builder-vm cache dir {out_dir}"))?;
        download_builder_vm_image(arch, out_dir).context("downloading the builder VM image")
    }
    #[cfg(not(feature = "release-artifact-bootstrap"))]
    {
        let _ = (arch, out_dir);
        // Report which of the two situations this actually is. The message
        // used to assert the in-repo flake was missing without ever looking
        // for one, so a checkout that *had* the flake — and had simply been
        // routed here by `MVM_BOOT_IMAGE=fetch` — sent the reader hunting for
        // a file sitting in front of them. Two Linux baseline runs were lost
        // to that before anyone checked whether the file existed.
        if let Ok(flake_dir) = super::find_builder_vm_flake() {
            anyhow::bail!(
                "Builder VM image is missing and a fetch was requested, but this \
                 `mvmctl` was built without the `release-artifact-bootstrap` \
                 feature, so it cannot pull a published prebuilt. The in-repo \
                 builder VM flake IS present at {flake_dir} — unset \
                 `MVM_BOOT_IMAGE` (or set it to `build`) to build from it, \
                 which is what a source checkout is expected to do."
            );
        }
        anyhow::bail!(
            "Builder VM image is missing and no in-repo builder VM flake \
             was found. This `mvmctl` binary was built without the \
             `release-artifact-bootstrap` feature, so it cannot pull a \
             published prebuilt from GitHub releases (per Plan 77 W4 and \
             the AGENTS.md / CLAUDE.md invariant). \
             Run from a source checkout that has \
             `nix/images/builder-vm/flake.nix`, or rebuild `mvmctl` with \
             `--features release-artifact-bootstrap` (release-cut binaries only)."
        );
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum BuilderVmBootstrapAction {
    UseCached,
    BuildFromSource { flake_dir: String },
    DownloadPublished,
}

pub(super) fn resolve_builder_vm_bootstrap_action(
    builder_flake: Result<String>,
    cache_ready: bool,
    acquisition: mvm_build::boot_image_select::BootImageAcquisition,
) -> Result<BuilderVmBootstrapAction> {
    if cache_ready {
        return Ok(BuilderVmBootstrapAction::UseCached);
    }

    match acquisition {
        mvm_build::boot_image_select::BootImageAcquisition::Fetch => {
            Ok(BuilderVmBootstrapAction::DownloadPublished)
        }
        mvm_build::boot_image_select::BootImageAcquisition::Build => builder_flake
            .map(|flake_dir| BuilderVmBootstrapAction::BuildFromSource { flake_dir })
            .context("a local builder VM image build requires the in-repo builder VM flake"),
    }
}

/// Attested builder-image pack materializer: given a locally-verified builder
/// pack, place its `vmlinux` + `rootfs.ext4` (+ `cmdline.txt`) into the cache
/// dir the `DownloadPublished` path writes and stamp the readiness sidecars so
/// the next resolve takes `UseCached` with no Stage 0 and no network. The plain
/// checksum download pins bytes but carries no signature; this closes that gap
/// while staying a pure accelerator — anything short of a fully verified,
/// compatible pack falls through to the download untouched.
///
/// Placement reuses the Stage 0 promotion machinery verbatim: stage the files in
/// a same-filesystem sibling dir, write the identical sidecar set the readiness
/// check reads back, then let [`promote_builder_vm_stage0_cache`] do the atomic
/// rename + final readiness assertion — so the markers can never drift from the
/// predicate that gates them.
///
/// Gated on `all(release-artifact-bootstrap, builder-vm)` (plus `test`): the only
/// caller is the published-download arm, and it also needs the `builder-vm`
/// sidecar writers. A source checkout never reaches here.
#[cfg(any(
    all(feature = "release-artifact-bootstrap", feature = "builder-vm"),
    test
))]
pub(in crate::commands) mod attested_builder_pack {
    use std::collections::BTreeSet;
    use std::path::Path;

    use anyhow::{Context, Result};

    use mvm_core::arch::GuestArch;
    use mvm_core::config::mvm_keys_dir;
    #[cfg(feature = "manifest-verify")]
    use mvm_core::pack_cache::{PackProvenanceInput, promote_and_record};
    use mvm_core::pack_cache::{PackVerifyCtx, VerifiedPackDir, resolve_pack};
    use mvm_core::pack_trust::{PackTrustConfig, load_pack_trust_config};
    #[cfg(feature = "manifest-verify")]
    use mvm_core::packs::{COSIGN_BUNDLE_FILE_NAME, PackManifest};
    use mvm_core::packs::{
        HostCapability, LocalPackPolicy, PackBackend, PackKind, host_pack_policy_hash,
    };

    #[cfg(feature = "manifest-verify")]
    use super::{builder_vm_artifact_names, download_file};
    use super::{
        promote_builder_vm_stage0_cache, unique_builder_vm_stage0_staging_dir,
        write_builder_vm_cache_sidecars,
    };
    use crate::ui;

    const SYNTHESIZED_BUILDER_VM_CMDLINE: &str = "console=hvc0 root=/dev/vda ro rootfstype=ext4 rootwait panic=-1 \
         loglevel=8 init=/init mvm.chain_init=/sbin/mvm-host-vm-init\n";
    const SYNTHESIZED_BUILDER_VM_CACHE_MANIFEST: &str =
        r#"{"cache_contract_version":3,"runtime_overlay_ready":true,"vsock_egress_ready":true}"#;

    /// Truthy-parse for [`MVM_BUILDER_PACK`](super::MVM_BUILDER_PACK_ENV): `1`,
    /// `true`, `yes`, `on` (case-insensitive, trimmed). Everything else —
    /// including `0`, `false`, the empty string, and a missing value — is `false`.
    /// Lifted out so both arms are unit-testable without touching process env.
    pub(in crate::commands) fn builder_pack_requested_for(raw: Option<&str>) -> bool {
        matches!(
            raw.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
            Some("1" | "true" | "yes" | "on"),
        )
    }

    fn builder_pack_requested() -> bool {
        builder_pack_requested_for(std::env::var(super::MVM_BUILDER_PACK_ENV).ok().as_deref())
    }

    /// Whether the attested-pack path should be attempted ahead of the plain
    /// download. Requires the opt-in flag AND an installed binary: a source
    /// checkout (`find_builder_vm_flake().is_ok()`) always builds the builder
    /// image locally and must never take a published-artifact shortcut.
    pub(in crate::commands) fn attested_builder_pack_selected() -> bool {
        builder_pack_requested() && super::find_builder_vm_flake().is_err()
    }

    /// Local verification context for host builder packs. `trust` is the
    /// operator's on-disk [`PackTrustConfig`] (loaded from `pack-trust.json` in
    /// the keys dir); it answers both "is this signer trusted?" and "is it
    /// revoked?". An empty config (no publishers) trusts no key and allows no
    /// channel, so every promoted pack fails verification and the caller falls
    /// back to the download — fail-open on availability, never on trust.
    pub(in crate::commands) struct HostPackVerifyInputs {
        pub(in crate::commands) policy: LocalPackPolicy,
        pub(in crate::commands) trust: PackTrustConfig,
    }

    /// Load the on-disk trust config, folding both the absent and the malformed
    /// case into the inert empty config. A missing file is the expected default;
    /// a broken file must never brick the builder VM bootstrap, so we warn and stay inert — the
    /// pack path then trusts nothing and falls through to the plain download. It
    /// can never trust an unverified pack, so failing open here is safe.
    fn load_host_pack_trust() -> PackTrustConfig {
        match load_pack_trust_config(&mvm_keys_dir().join("pack-trust.json")) {
            Ok(Some(config)) => config,
            Ok(None) => PackTrustConfig::default(),
            Err(error) => {
                ui::warn(&format!(
                    "Ignoring malformed pack trust config ({error}); attested builder \
                     packs stay inert and the builder VM bootstrap falls back to the download."
                ));
                PackTrustConfig::default()
            }
        }
    }

    pub(in crate::commands) fn host_pack_verify_inputs(arch: GuestArch) -> HostPackVerifyInputs {
        let trust = load_host_pack_trust();
        HostPackVerifyInputs {
            policy: LocalPackPolicy {
                host_arch: arch,
                backend: PackBackend::Hvf,
                host_capabilities: BTreeSet::from([HostCapability("vsock".to_string())]),
                policy_hash: host_pack_policy_hash(arch),
                allowed_channels: trust.allowed_channels(),
                now: chrono::Utc::now(),
            },
            trust,
        }
    }

    /// The local policy a keyless-signed release pack must satisfy: identical
    /// to the operator's on-disk policy, but with the compiled-in release
    /// channels unioned into the allowed set. A release pack always declares
    /// one of [`mvm_core::release_trust::release_channels`], and that trust is
    /// carried by the embedded identity template, not by anything the operator
    /// configures — so it must be allowed independent of `pack-trust.json`.
    #[cfg(feature = "manifest-verify")]
    pub(in crate::commands) fn keyless_release_policy(base: &LocalPackPolicy) -> LocalPackPolicy {
        let mut policy = base.clone();
        policy
            .allowed_channels
            .extend(mvm_core::release_trust::release_channels());
        policy
    }

    /// Parse a staged release pack's manifest and verify+promote it into the
    /// local pack cache. `Ok(Some(_))` means the pack now exists in the cache
    /// (freshly promoted, or already there) and the caller's next resolve will
    /// find it. A verification failure is `Ok(None)` — fail-open on
    /// availability, so the caller falls through to the plain checksum
    /// download — but the rejection is logged so an operator can see why the
    /// acceleration path was skipped. A missing or unparsable staged manifest
    /// is a genuine error: the fetch step is expected to have already placed
    /// valid bytes there, so this signals a caller bug rather than an
    /// untrusted-publisher condition.
    #[cfg(feature = "manifest-verify")]
    pub(in crate::commands) fn promote_staged_builder_pack(
        staging: &Path,
        ctx: &PackVerifyCtx<'_>,
    ) -> Result<Option<VerifiedPackDir>> {
        let manifest_path = staging.join("pack-manifest.json");
        let manifest_bytes = std::fs::read(&manifest_path).with_context(|| {
            format!(
                "reading staged builder pack manifest at {}",
                manifest_path.display()
            )
        })?;
        let manifest: PackManifest =
            serde_json::from_slice(&manifest_bytes).with_context(|| {
                format!(
                    "parsing staged builder pack manifest at {}",
                    manifest_path.display()
                )
            })?;
        // `v{version}` matches the release tag `fetch_release_builder_pack_staging`
        // builds its download base URL from, so the recorded version always
        // names the exact release this pack came from.
        let release_version = format!("v{}", env!("CARGO_PKG_VERSION"));
        let prov = PackProvenanceInput {
            channel: manifest.trust.channel_identity.clone(),
            release_version,
            promoted_at_unix: chrono::Utc::now().timestamp() as u64,
        };
        match promote_and_record(staging, &manifest, &prov, ctx) {
            Ok(dir) => Ok(Some(dir)),
            Err(error) => {
                ui::warn(&format!(
                    "Published builder pack failed verification ({error}); \
                     falling back to the checksum download."
                ));
                Ok(None)
            }
        }
    }

    /// Download the release channel's published builder pack — manifest,
    /// detached cosign bundle, and artifacts — into a fresh staging dir laid
    /// out exactly as [`promote_staged_builder_pack`] expects:
    /// `pack-manifest.json`, [`COSIGN_BUNDLE_FILE_NAME`], `vmlinux`,
    /// `rootfs.ext4`, and a best-effort `cmdline.txt`. Asset basenames mirror
    /// [`super::download_builder_vm_image`]'s naming exactly, so the two
    /// download paths can never drift apart. The staging dir is a
    /// process-local tempdir; `promote` only ever copies out of it (never
    /// renames it), so it need not share a filesystem with the pack cache,
    /// and its `Drop` cleans it up on any early return here.
    #[cfg(feature = "manifest-verify")]
    pub(in crate::commands) fn fetch_release_builder_pack_staging(
        arch: &str,
    ) -> Result<tempfile::TempDir> {
        let staging = tempfile::Builder::new()
            .prefix("mvm-builder-pack-")
            .tempdir()
            .context("creating builder pack staging dir")?;
        let names = builder_vm_artifact_names(arch);
        let manifest_name = format!("builder-vm-{arch}.pack-manifest.json");
        let bundle_name = format!("{manifest_name}.bundle");
        let version = env!("CARGO_PKG_VERSION");
        let base_url = format!("https://github.com/tinylabscom/mvm/releases/download/v{version}");

        let manifest_dest = staging
            .path()
            .join("pack-manifest.json")
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{manifest_name}"), &manifest_dest)
            .with_context(|| format!("downloading builder pack manifest {manifest_name}"))?;

        let bundle_dest = staging
            .path()
            .join(COSIGN_BUNDLE_FILE_NAME)
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{bundle_name}"), &bundle_dest)
            .with_context(|| format!("downloading builder pack cosign bundle {bundle_name}"))?;

        let kernel_dest = staging
            .path()
            .join("vmlinux")
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{}", names.kernel), &kernel_dest)
            .context("downloading builder pack vmlinux artifact")?;

        let rootfs_dest = staging
            .path()
            .join("rootfs.ext4")
            .to_string_lossy()
            .into_owned();
        download_file(&format!("{base_url}/{}", names.rootfs), &rootfs_dest)
            .context("downloading builder pack rootfs artifact")?;

        // Best-effort: a missing cmdline.txt sidecar has a documented
        // fallback at the materializer, so a 404 here is not fatal.
        let cmdline_dest = staging
            .path()
            .join("cmdline.txt")
            .to_string_lossy()
            .into_owned();
        let _ = download_file(&format!("{base_url}/{}", names.cmdline), &cmdline_dest);

        Ok(staging)
    }

    /// Fetch the release channel's published builder pack and promote it into
    /// the local cache when it verifies. Both the fetch and the promote step
    /// are fail-open: any error is logged and swallowed here, never
    /// propagated, so [`attempt_attested_builder_pack`] always falls
    /// back to the plain checksum download rather than hard-failing the
    /// builder VM bootstrap on a network hiccup or a broken publish.
    #[cfg(feature = "manifest-verify")]
    fn fetch_and_promote_release_builder_pack(arch: &str, ctx: &PackVerifyCtx<'_>) {
        let staging = match fetch_release_builder_pack_staging(arch) {
            Ok(staging) => staging,
            Err(error) => {
                ui::warn(&format!(
                    "Fetching the published builder pack failed ({error:#}); \
                     falling back to the checksum download."
                ));
                return;
            }
        };
        if let Err(error) = promote_staged_builder_pack(staging.path(), ctx) {
            ui::warn(&format!(
                "Published builder pack was malformed ({error:#}); falling back \
                 to the checksum download."
            ));
        }
    }

    /// Entry point for the download arm: build the host verification context,
    /// resolve a compatible verified builder pack, and place it. `Ok(true)` when
    /// a pack was materialized (caller skips the download); `Ok(false)` when none
    /// is available. Errors are placement failures the caller logs before falling
    /// back — resolution finding nothing is `Ok(false)`, never an error.
    ///
    /// Two authorities are tried in order: the embedded keyless root (a stock
    /// binary's own release packs, no operator config needed) first, then the
    /// operator's ed25519 `pack-trust.json` (fleet/self-built packs). Both
    /// resolve against the same on-disk cache and fail open to the caller's
    /// plain download when neither yields a pack.
    ///
    /// `fetch_on_miss` gates the release-channel network fetch that runs when
    /// the embedded keyless root finds nothing locally cached: the production
    /// call site always passes `true`; a test passes `false` to exercise the
    /// local-cache-only resolve/materialize behavior without touching the
    /// network.
    pub(in crate::commands) fn attempt_attested_builder_pack(
        arch: &str,
        out_dir: &str,
        fetch_on_miss: bool,
    ) -> Result<bool> {
        let target_arch: GuestArch = arch
            .parse()
            .with_context(|| format!("unsupported builder pack arch {arch}"))?;
        let inputs = host_pack_verify_inputs(target_arch);
        let out_dir = Path::new(out_dir);
        let _ = fetch_on_miss;

        #[cfg(feature = "manifest-verify")]
        {
            let keyless = mvm_core::release_trust::release_keyless_trust(env!("CARGO_PKG_VERSION"));
            let policy = keyless_release_policy(&inputs.policy);
            let ctx = PackVerifyCtx::keyless(&policy, &keyless, &inputs.trust);
            if resolve_and_materialize_builder_pack(target_arch, out_dir, &ctx)? {
                return Ok(true);
            }
            if fetch_on_miss {
                fetch_and_promote_release_builder_pack(arch, &ctx);
                if resolve_and_materialize_builder_pack(target_arch, out_dir, &ctx)? {
                    return Ok(true);
                }
            }
        }

        // The config answers both trust and revocation queries, so it is passed
        // as the trust store and the revocation checker.
        let ctx = PackVerifyCtx::ed25519(&inputs.policy, &inputs.trust, &inputs.trust);
        resolve_and_materialize_builder_pack(target_arch, out_dir, &ctx)
    }

    /// Resolve a compatible verified builder pack against `ctx` and materialize
    /// it into `out_dir`. Split from [`attempt_attested_builder_pack`] so a test
    /// can inject a context whose trust store actually accepts a locally-minted
    /// pack (the production context trusts no keys yet).
    fn resolve_and_materialize_builder_pack(
        arch: GuestArch,
        out_dir: &Path,
        ctx: &PackVerifyCtx<'_>,
    ) -> Result<bool> {
        match resolve_pack(PackKind::Builder, arch, PackBackend::Hvf, ctx)
            .context("resolving attested builder pack from the local cache")?
        {
            Some(verified) => {
                let fingerprint = materialize_builder_pack(&verified, out_dir)?;
                ui::success(&format!(
                    "Placed attested builder VM image from verified pack {}.",
                    short_hash(&fingerprint)
                ));
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn short_hash(hash: &str) -> &str {
        &hash[..hash.len().min(12)]
    }

    /// Place the verified pack's builder-image files into `out_dir` atomically and
    /// stamp the readiness sidecars, returning the fingerprint the sidecars were
    /// keyed on (the pack's content-addressed hash). On any failure the staging
    /// dir is removed and `out_dir` is left untouched — a partial placement never
    /// publishes a dir that falsely reads ready.
    pub(in crate::commands) fn materialize_builder_pack(
        verified: &VerifiedPackDir,
        out_dir: &Path,
    ) -> Result<String> {
        // The pack's content-addressed hash is a stable, attested fingerprint: it
        // re-derives identically on every resolve, so the readiness sidecars pin
        // this exact pack's identity into the cache dir.
        let fingerprint = verified.verified.pack_hash.as_str().to_string();
        let staging = unique_builder_vm_stage0_staging_dir(out_dir)?;
        // A recycled pid could leave a prior crashed run's dir at this path; start
        // clean so no un-attested extra files ride the rename into the cache.
        let _ = std::fs::remove_dir_all(&staging);
        let outcome =
            place_and_promote_builder_pack(&verified.root, &staging, out_dir, &fingerprint);
        if outcome.is_err() {
            let _ = std::fs::remove_dir_all(&staging);
        }
        outcome.map(|()| fingerprint)
    }

    fn place_and_promote_builder_pack(
        pack_root: &Path,
        staging: &Path,
        out_dir: &Path,
        fingerprint: &str,
    ) -> Result<()> {
        std::fs::create_dir_all(staging)
            .with_context(|| format!("creating builder pack staging dir {}", staging.display()))?;
        copy_builder_pack_artifacts(pack_root, staging)?;
        // Reuses the shared sidecar writer so the markers can never drift from the
        // readiness predicate that reads them. That writer stamps a provenance
        // "kind" describing the local-build origin; here the origin is instead a
        // verified download, so the recorded kind is imprecise. Correcting it means
        // threading a distinct kind through the shared readiness predicate that the
        // local-build path also depends on, so it is left for a focused follow-up.
        write_builder_vm_cache_sidecars(staging, fingerprint)?;
        // The atomic rename + final readiness assertion; also the idempotency and
        // poisoned-final replacement the reuse path already handles.
        promote_builder_vm_stage0_cache(staging, out_dir, fingerprint)
            .context("promoting the materialized builder pack into the cache")
    }

    /// Copy the readiness-relevant builder-image files out of the verified pack.
    /// `vmlinux` + `rootfs.ext4` are required (a builder pack that omits them is
    /// malformed). `cmdline.txt` and the seeded closure NAR
    /// (`mvm_build::builder_pack::CLOSURE_FILE`) are optional and copied when
    /// present. When the pack omits `cmdline.txt`, this synthesizes the current
    /// canonical builder-vm cmdline. The closure NAR sits alongside the
    /// readiness-gated files here so the HVF/libkrun boot paths — which resolve
    /// it from this exact cache dir — pick it up without a separate lookup; it
    /// plays no part in the readiness check itself. The cache's `manifest.json`
    /// is always synthesized here because the pack envelope manifest
    /// (`pack-manifest.json`) is a different contract from the runtime cache
    /// manifest the builder loader validates.
    fn copy_builder_pack_artifacts(pack_root: &Path, dest: &Path) -> Result<()> {
        for name in ["vmlinux", "rootfs.ext4"] {
            let src = pack_root.join(name);
            if !src.exists() {
                anyhow::bail!(
                    "attested builder pack at {} is missing required artifact {name}",
                    pack_root.display()
                );
            }
            std::fs::copy(&src, dest.join(name))
                .with_context(|| format!("copying builder pack artifact {name}"))?;
        }
        let cmdline = pack_root.join("cmdline.txt");
        if cmdline.exists() {
            std::fs::copy(&cmdline, dest.join("cmdline.txt"))
                .context("copying builder pack cmdline.txt")?;
        } else {
            std::fs::write(dest.join("cmdline.txt"), SYNTHESIZED_BUILDER_VM_CMDLINE)
                .context("writing synthesized builder pack cmdline.txt")?;
        }
        let name = mvm_build::builder_pack::CLOSURE_FILE;
        let src = pack_root.join(name);
        if src.exists() {
            std::fs::copy(&src, dest.join(name))
                .with_context(|| format!("copying builder pack artifact {name}"))?;
        }
        std::fs::write(
            dest.join("manifest.json"),
            SYNTHESIZED_BUILDER_VM_CACHE_MANIFEST,
        )
        .context("writing synthesized builder pack manifest.json")?;
        Ok(())
    }
}
#[cfg(feature = "builder-vm")]
fn bootstrap_builder_vm_image_via_root_dir_stage0(
    builder_flake_dir: &str,
    out_dir: &str,
    source_fingerprint: &str,
    verbose: bool,
) -> Result<()> {
    let _stage0_guard = acquire_stage0_lock(out_dir)?;
    let removed = sweep_stage0_staging_siblings(std::path::Path::new(out_dir))?;
    if removed > 0 {
        ui::info(&format!(
            "Removed {removed} incomplete Stage 0 builder-image director{} from an earlier interruption.",
            if removed == 1 { "y" } else { "ies" }
        ));
    }

    // Time each host-visible Stage 0 step and print a one-line
    // `[mvm] <step> … <secs>s` so perceived speed matches the actual
    // per-step wall-clock.
    // The seed is the official Nix release tarball + the embedded
    // `stage0-init` PID 1 — one userland (busybox), no Alpine/apk/pgp.
    let fetch_started = std::time::Instant::now();
    let stage0_assets = mvm_build::stage0::assets_for_host_arch();
    let vendor_reports = mvm_build::stage0::prepare_assets(stage0_assets)
        .context("preparing Stage 0 bootstrap assets")?;
    ui::timed_step("Fetching Stage 0 bootstrap assets", fetch_started.elapsed());
    // One VendorBlobFetched audit entry per vendored blob (covers both
    // fresh fetch and cache revalidation), so every supply-chain trust
    // decision in the no-prebuilt-download path is auditable. The emit
    // lives here (the host caller) so `mvm-build` stays audit-free.
    for report in &vendor_reports {
        mvm_core::policy::audit::emit(
            mvm_core::policy::audit::LocalAuditKind::VendorBlobFetched,
            None,
            Some(&report.audit_detail()),
        );
    }

    // Workspace root = three dirs above the flake.nix
    // (nix/images/builder-vm/flake.nix → repo root).
    let workspace_root = std::path::Path::new(builder_flake_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("Cannot derive workspace root from {builder_flake_dir}"))?
        .to_path_buf();

    // Materialize the guest root tree under a stable per-host location.
    // libkrun mounts this directory as the guest root via virtiofs.
    let root_dir = mvm_build::stage0::stage0_cache_dir().join("root");
    let materialize_started = std::time::Instant::now();
    let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
    let boot_binaries = crate::host_binaries::extract::ensure_boot_host_binaries(
        std::path::Path::new(&host_bins_cache),
    )?;
    mvm_build::stage0::materialize_root_dir(&root_dir, &boot_binaries.stage0_init)
        .with_context(|| format!("materializing Stage 0 root at {}", root_dir.display()))?;
    ui::timed_step(
        "Materializing Stage 0 root dir",
        materialize_started.elapsed(),
    );

    let out_dir_path = std::path::Path::new(out_dir);
    let staging_dir = unique_builder_vm_stage0_staging_dir(out_dir_path)?;
    std::fs::create_dir_all(&staging_dir)
        .with_context(|| format!("creating Stage 0 staging dir {}", staging_dir.display()))?;

    let started = std::time::Instant::now();
    let fingerprint_prefix = stage0_fingerprint_prefix(source_fingerprint);
    mvm_core::audit_emit!(
        Stage0Boot,
        "seed=root-dir fingerprint_prefix={fingerprint_prefix} flavor={flavor}",
        flavor = STAGE0_FLAVOR_CURRENT,
    );

    // Extract the embedded host-vm binaries so the Stage 0 nix build
    // can install them from /mvm-bins instead of building them with
    // the guest's nix. Same cache dir the steady-state job path uses.
    // Kernel acquisition override (MVM_KERNEL_SOURCE / --kernel-source).
    // `download` (and `auto` when a publish exists) boots the builder VM
    // on a published, hash-verified kernel — build only the rootfs and
    // pair the kernel in, skipping the in-image kernel compile. Unset or
    // `compile` → the normal `default` build (kernel compiled in-image;
    // also the cheaper single-boot path, so `mvmctl bootstrap --kernel-source
    // compile` deliberately stays on it).
    let external_kernel: Option<std::path::PathBuf> = match resolve_kernel_source() {
        Some(KernelSource::Download) => {
            ui::info("Kernel source: download — fetching the published builder kernel.");
            Some(download_builder_kernel(builder_vm_host_arch())?)
        }
        Some(KernelSource::Auto) => match download_builder_kernel(builder_vm_host_arch()) {
            Ok(p) => {
                ui::info("Kernel source: auto — using the published builder kernel.");
                Some(p)
            }
            Err(e) => {
                ui::warn(&format!(
                    "no published builder kernel ({e}); compiling it in-image"
                ));
                None
            }
        },
        Some(KernelSource::Compile) | None => None,
    };

    let result = if let Some(kernel) = &external_kernel {
        run_stage0_rootfs_with_external_kernel(
            &staging_dir,
            &workspace_root,
            &root_dir,
            &boot_binaries.dir,
            kernel,
            source_fingerprint,
            verbose,
        )
    } else {
        run_stage0_root_dir(
            &staging_dir,
            &workspace_root,
            &root_dir,
            "/init",
            &boot_binaries.dir,
            source_fingerprint,
            verbose,
        )
    };
    let duration_ms = started.elapsed().as_millis() as u64;

    match result {
        Ok(()) => {
            promote_builder_vm_stage0_cache(&staging_dir, out_dir_path, source_fingerprint)
                .context("promoting Stage 0 artifacts into the builder VM cache")?;
            mvm_core::audit_emit!(
                Stage0CachePromoted,
                "cache={cache} fingerprint_prefix={fingerprint_prefix} duration_ms={duration_ms} flavor={flavor}",
                cache = out_dir_path.display(),
                flavor = STAGE0_FLAVOR_CURRENT,
            );
            Ok(())
        }
        Err((stage, e)) => {
            let _ = std::fs::remove_dir_all(&staging_dir);
            let reason = stage0_failure_reason_summary(&e);
            mvm_core::audit_emit!(
                Stage0Failed,
                "stage={stage} duration_ms={duration_ms} reason={reason}"
            );
            Err(e)
        }
    }
}

/// Boot the Stage 0 VM with the supplied `RootDir` image, mounting
/// `workspace_root` as `/work` and `staging_dir` as `/out`. On
/// clean exit, write the cache-validation sidecars next to the
/// emitted artifacts so the outer caller can promote them into the
/// per-arch builder VM cache.
#[cfg(feature = "builder-vm")]
#[cfg(feature = "builder-vm")]
fn run_stage0_root_dir(
    staging_dir: &std::path::Path,
    workspace_root: &std::path::Path,
    guest_root_dir: &std::path::Path,
    entry_path: &str,
    host_bin_dir: &std::path::Path,
    source_fingerprint: &str,
    verbose: bool,
) -> std::result::Result<(), (Stage0FailureStage, anyhow::Error)> {
    use mvm_build::builder_backend_select as bbs;

    // Dispatch Stage 0 through the `BuilderVm` trait. QEMU when explicitly
    // chosen (`MVM_BUILDER_BACKEND=qemu`) and **libkrun otherwise** — including
    // the HVF auto-detect default on macOS-26+, since HVF Stage 0 is still a gap.
    // That preserves the "Stage 0 is libkrun even on HVF-default hosts"
    // invariant. `verbose` forwards the in-guest nix `--print-build-logs`
    // output to host stderr.
    //
    // Auto-fallback: an auto-detected libkrun that fails to create its Stage 0
    // VM on Linux (rc -22 / `KVM_SET_USER_MEMORY_REGION`) transparently retries
    // on qemu; a genuine build error surfaces unchanged. Explicit
    // `--builder`/`MVM_BUILDER_BACKEND` opts out.
    let selected = bbs::resolve_choice();
    let explicit = bbs::resolve_env_override().is_some();
    bbs::run_with_builder_fallback(selected, explicit, |choice| {
        bbs::resolve_stage0_backend_for_choice(choice, verbose).run_stage0(
            guest_root_dir,
            entry_path,
            workspace_root,
            staging_dir,
            host_bin_dir,
        )
    })
    .map_err(|e| {
        (
            Stage0FailureStage::Build,
            anyhow::anyhow!("Stage 0 root-dir build: {e}"),
        )
    })?;

    // Refuse to promote a rootfs the steady-state VM can't boot: walk the
    // freshly-built ext4 and confirm the `init=` target is present.
    verify_stage0_rootfs_has_init(&staging_dir.join("rootfs.ext4"))
        .map_err(|e| (Stage0FailureStage::Validate, e))?;

    write_builder_vm_cache_sidecars(staging_dir, source_fingerprint)
        .map_err(|e| (Stage0FailureStage::Validate, e))?;

    Ok(())
}

/// Which Stage 0 bootstrap variant this build runs.
///
/// The `flavor=` field on `Stage0Boot` / `Stage0CachePromoted` audit
/// detail strings carries this value so a future per-variant identifier
/// (e.g. an experimental seed image alongside the nix-tarball seed) only
/// needs to flip this single constant — not every emit site. Today
/// there is one variant, so the value is the literal `"current"`.
#[cfg(feature = "builder-vm")]
pub(super) const STAGE0_FLAVOR_CURRENT: &str = "current";

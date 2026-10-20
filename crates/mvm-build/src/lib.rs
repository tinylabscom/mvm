//! Image identity and production primitives, with Unix-only VM orchestration.
//!
//! Non-Unix hosts can observe repositories and produce/verify local manifests.
//! They do not expose a VM launcher or a fallback implementation of one.

pub mod artifact_acquisition;
pub mod base_image_contract;
pub mod build_cache;
pub mod builder_boot;
pub mod builder_contract;
pub use mvm_builder_guest::builder_guest_paths;
pub mod builder_image_inputs;
pub mod cache_install;
pub mod embed_toolchain;
pub use mvm_builder_guest::host_payload_manifest;
pub mod image_protocol;
pub mod image_source;
pub mod source_closure;
mod source_copy;
pub mod workspace_graph;

/// Portable image-contract verification; acquisition requires a Unix host.
#[cfg(not(unix))]
pub mod published_image_set {
    pub use crate::base_image_contract::verify_base_image_contract;
}

use mvm_core::env_hygiene::helper_command;

// Each declaration below is Unix-only; the cfg sits on the item (not behind
// `include!`) so cargo-mutants can see the modules.
#[cfg(unix)]
pub mod app_deps;
#[cfg(unix)]
pub mod app_deps_gate;
#[cfg(unix)]
pub mod backend;
/// Production admission gate over the base-image sidecar pair: missing
/// scan, foreign shape, digest mismatch, or a high/critical finding
/// refuse `--prod`; dev warns and admits.
#[cfg(unix)]
pub mod base_image_gate;
/// Base-image CVE scan: correlate an `mvm_fs::os_inventory::OsInventory`
/// against OSV over `mvm_http::blocking` and render the app-deps-shaped
/// `cve.json` + CycloneDX SBOM sidecar pair.
#[cfg(unix)]
pub mod base_image_scan;
/// Synthetic boot archives shared by offline admission tests.
#[cfg(any(test, feature = "test-support"))]
#[cfg(unix)]
pub mod boot_asset_fixture;
/// Disk-only job/artifact transport for the hvf-VMM builder (tar-over-raw-
/// disk, so the host never formats or reads a guest filesystem).
#[cfg(unix)]
pub mod boot_image_select;
/// The uid a builder guest runs its guest agent under, chosen from the
/// identities the booted image names.
#[cfg(unix)]
pub use mvm_builder_guest::builder_agent_uid;
#[cfg(unix)]
pub mod builder_cmdline;
#[cfg(unix)]
pub use mvm_builder_guest::builder_disk_transport;
#[cfg(unix)]
mod builder_egress_process;
#[cfg(unix)]
mod builder_host_binaries;
/// What a staged builder job directory means to the guest, and the versioned
/// outcome the guest writes back.
#[cfg(unix)]
pub use mvm_builder_guest::builder_job_contract;
/// One flake build through a builder VM, as a request and a result, for a
/// caller that wants the artifacts where it asked for them.
#[cfg(unix)]
pub mod builder_orchestrator;
/// What the host checks in a builder VM's output before it uses or signs it.
#[cfg(unix)]
pub mod builder_output;
/// Reusable producer that turns real builder artifacts (`vmlinux` + `rootfs.ext4`)
/// into a signed, cache-promotable Builder pack — the produce half of the
/// attested-builder-pack path whose verify/materialize half lives in
/// `mvm_core::packs`.
#[cfg(unix)]
pub mod builder_pack;
/// Vsock dispatch wire types for the persistent builder VM.
#[cfg(unix)]
pub use mvm_builder_guest::builder_protocol;
#[cfg(unix)]
pub mod builder_route;
#[cfg(unix)]
pub mod builder_vm;
/// Builder image cache discovery and Stage 0 store preparation shared by all
/// VMM backends.
#[cfg(unix)]
pub mod builder_vm_image;
/// Hypervisor-agnostic builder-VM orchestration helper that wraps a
/// `VmBackendForBuilder` implementation (libkrun and HVF).
#[cfg(unix)]
pub mod builder_vm_runtime;
/// Builder disk transport, runtime-overlay, and egress helpers shared by all
/// one-shot VMM backends.
#[cfg(unix)]
pub mod builder_vm_transport;
/// Request-handling core of the resident `mvm-builderd` builder-VM
/// daemon: stateless request dispatch + the framed connection serve
/// loop. The bin entrypoint and AF_VSOCK listener land with boot wiring.
#[cfg(unix)]
pub use mvm_builder_guest::builderd;
/// Host-side client for the resident `mvm-builderd` daemon: connect +
/// handshake, run one typed operation per connection, stream
/// progress/log events, and surface a typed terminal outcome.
#[cfg(unix)]
pub mod builderd_client;
/// Typed allowlisted control-plane protocol for the resident
/// `mvm-builderd` builder-VM service (the long-term replacement for the
/// controlled-shell-job channel in `builder_protocol`).
#[cfg(unix)]
pub use mvm_builder_guest::builderd_protocol;
#[cfg(unix)]
pub mod cache;
/// The lib half of the retired `mvm-egress-proxy` bin, which no builder VM
/// installs or runs any more; see the module docs.
#[cfg(unix)]
pub mod egress_proxy;
#[cfg(unix)]
pub use mvm_builder_guest::egress_readiness;
/// Extract an FC-loadable ELF `vmlinux` from a published x86_64 bzImage.
#[cfg(unix)]
pub mod guest_elf;
/// Which libc a materialized guest rootfs carries, observed while the tree is
/// still a directory the host can read.
#[cfg(unix)]
pub mod guest_libc;
/// Config contract for the `mvm-hvf-supervisor` per-VM host process (raw HVF
/// macOS backend, raw HVF backend). Shared by `mvm_runtime::backends::hvf` (writer) + the bin.
/// Universal initramfs build + cache resolution.
#[cfg(unix)]
pub mod initramfs;
#[cfg(unix)]
pub mod intoto;
/// Content identity for fetched kernel artifacts.
#[cfg(unix)]
pub mod kernel_artifact;
/// Hash-verify a fetched kernel image against its [`kernel_artifact::KernelArtifactId`].
#[cfg(unix)]
pub mod kernel_fetch;
/// Host-side scaffold for the persistent builder VM's dispatch
/// supervisor. This module owns the dispatch wire over the socket
/// libkrun creates; spawning the libkrun VM itself lives in
/// `LibkrunPersistentHostVm`.
#[cfg(unix)]
pub mod persistent_builder;
/// Whether a live persistent builder session is kept, stopped, or reused.
#[cfg(unix)]
pub mod persistent_builder_policy;
#[cfg(unix)]
pub mod persistent_builder_transport;
/// Build-provenance recorder: content-addresses produced artifacts into the
/// signed plan's `BuildProvenance`.
#[cfg(unix)]
pub mod provenance;
#[cfg(unix)]
pub mod provenance_mark;
/// Acquire the signed image set this build pins and deliver its members, each
/// held to the digest the verified root declares.
#[cfg(unix)]
pub mod published_image_set;
/// OCI-unpacked tree to ext4 rootfs image. The host only allocates the
/// sparse file; formatting and copying happen inside the builder VM.
#[cfg(unix)]
pub mod rootfs;
/// In-process newc cpio writer for host-assembled initramfs archives.
#[cfg(unix)]
pub use mvm_builder_guest::rootfs_inject;
/// Shared run-path rootfs orchestration (inject runtime + materialize ext4),
/// used by the CLI's `run --image` and the `mvm-client` local backend.
#[cfg(unix)]
pub mod run_image;
#[cfg(unix)]
pub mod runtime_identity;
#[cfg(unix)]
pub use mvm_builder_guest::seed_store_entries;
#[cfg(unix)]
pub mod stage0;
/// Host-side Stage 0 pieces that belong to no particular VMM.
///
/// It materializes the seed root through the pure ext4 writer and re-exports
/// the persistent-store helpers formerly housed in `libkrun_builder`.
#[cfg(unix)]
pub mod stage0_host;
/// The one kernel Stage 0 can neither build nor resolve by the ordinary policy.
#[cfg(unix)]
pub mod stage0_kernel;
/// Whether a builder guest may fall back to a tmpfs Nix store, or must stop.
#[cfg(unix)]
pub use mvm_builder_guest::store_readiness;
#[cfg(unix)]
pub mod template_reuse;
/// Persistent ext4 image materialization for user-attached block volumes.
#[cfg(unix)]
pub mod volume_image;

/// Acquiring and running the builder-VM bootstrap helper.
#[cfg(unix)]
pub mod builder_vm_bootstrap;
/// Libkrun-backed builder VM. Native FFI linkage remains separately opt-in.
#[cfg(feature = "builder-libkrun")]
#[cfg(unix)]
pub mod libkrun_builder;

/// The libkrun `NetworkProvider` impl.
/// Gated with `libkrun_builder`: it wraps that module's gateway selection.
#[cfg(feature = "builder-libkrun")]
#[cfg(unix)]
pub mod libkrun_network_provider;

/// QEMU-backed builder VM (the Linux dev/builder substrate). Boots the
/// nix-tarball Stage 0 seed on the stock distro kernel + initramfs with
/// ext4 disks + vsock-only egress. Linux-only at runtime; compiles
/// everywhere (the selection only picks it on Linux).
/// Shared in-guest static-IP helpers: `configure_static` (gated
/// `cfg(linux)`) plus pure address-parsing/encoding utilities tested
/// on every host. Consumed by both `stage0-init` and `mvm-host-vm-init`.
#[cfg(unix)]
pub mod guest_net;

#[cfg(unix)]
pub mod qemu_builder;

/// Builder-runtime selection. `MVM_BUILDER_BACKEND` picks among the
/// available builder backends; the platform default is hvf on supported
/// Apple Silicon macOS and qemu elsewhere. libkrun remains an explicit
/// contributor-only override. The caller receives a `Box<dyn BuilderVm>` so
/// the dispatch site doesn't depend on which concrete driver the env-var
/// resolved to.
#[cfg(unix)]
pub mod builder_backend_select;
/// Per-host builder-VM health cache (skip a libkrun backend that can't create
/// its VM here).
#[cfg(unix)]
pub mod builder_health;

/// Host-side cross-compile + cache of the guest agent/netinit binaries
/// baked into an OCI rootfs by [`oci_runtime_inject`].
#[cfg(unix)]
pub mod guest_agent_build;
/// The `mvm-guest-bins` archive: every guest artifact mvm owns, for both guest
/// architectures, with a manifest pinning their bytes, the producing commit,
/// and its source fingerprints. The guest runtime `mvmctl` is to ship with each
/// release and assemble its overlay, initramfs and SDK sidecar from.
/// Compiled through [`guest_agent_build`]'s toolchain and caches.
#[cfg(unix)]
pub mod guest_bins;
/// One digest-keyed guest-runtime tree shared by the host-side assemblers.
#[cfg(unix)]
pub mod guest_runtime;
#[cfg(unix)]
pub mod nix;
/// Inject the mvm guest runtime (agent, netinit, `/init`, `/mvm/runtime`
/// mount point) into an OCI-unpacked rootfs so `run --image` has a vsock
/// control plane. Host-side filesystem I/O against the staging tree.
#[cfg(unix)]
pub mod oci_runtime_inject;
#[cfg(unix)]
pub mod pipeline;
/// Process-lifetime memo for answers every call site of one command shares.
#[cfg(unix)]
mod process_memo;
/// Cosign-verify a downloaded release archive against the release workflow's
/// keyless signing identity before anything reads it. Shared by every
/// release-artifact downloader.
#[cfg(unix)]
pub mod release_signature;
/// Host-side resolver for the mvm runtime overlay disk. Picks the right
/// ext4 + verity sidecar + roothash for the host arch: the pinned image set's
/// member from `~/.mvm/cache/image-set/<root>/runtime-overlay/`, or a source
/// build from `~/.mvm/cache/runtime-overlay/<version>/<arch>/`.
#[cfg(unix)]
pub mod runtime_overlay;
/// The overlay, initramfs and SDK sidecars assembled from one guest runtime,
/// and the archive digest each records as its origin.
#[cfg(unix)]
pub mod runtime_pieces;
/// Acquire the published SDK-sidecar disk for hosts that cannot build one.
/// Fetches the per-arch, per-libc member of the signed image set, proves it
/// against the verified root and its own manifest, and installs it under
/// `~/.mvm/cache/image-set/<root>/sdk-sidecar/<member-version>/<arch>/<libc>/`
/// for [`mvm_fs::sdk_sidecar::SdkSidecarResolver`] to pick up.
#[cfg(unix)]
pub mod sdk_sidecar;
/// Cross-process reuse of guest-source fingerprints and object
/// verifications, keyed on the exact filesystem state they describe.
#[cfg(unix)]
mod source_stamp;

// Legacy re-exports — preserve `mvm_build::build::*`, `mvm_build::scripts::*`, etc.
#[cfg(unix)]
pub use nix::manifest as nix_manifest;
#[cfg(unix)]
pub use nix::scripts;
#[cfg(unix)]
pub use pipeline::{build, dev_build, orchestrator, vsock_builder};

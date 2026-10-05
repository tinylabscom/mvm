pub mod app_deps;
pub mod app_deps_gate;
/// Compiled distribution channel and the default build-vs-download contract
/// shared by every launch-critical artifact resolver.
pub mod artifact_acquisition;
pub mod backend;
/// Production admission gate over the base-image sidecar pair: missing
/// scan, foreign shape, digest mismatch, or a high/critical finding
/// refuse `--prod`; dev warns and admits.
pub mod base_image_gate;
/// Base-image CVE scan: correlate an `mvm_fs::os_inventory::OsInventory`
/// against OSV over `mvm_http::blocking` and render the app-deps-shaped
/// `cve.json` + CycloneDX SBOM sidecar pair.
pub mod base_image_scan;
/// Disk-only job/artifact transport for the hvf-VMM builder (tar-over-raw-
/// disk, so the host never formats or reads a guest filesystem).
pub mod boot_image_select;
/// The builder boot contract: the payload of mvm's own builder binaries every
/// builder boot carries beside its image, the image's boot ABI, and the one
/// kernel command line every builder backend boots with.
pub mod builder_boot;
pub mod builder_cmdline;
pub mod builder_disk_transport;
mod builder_egress_process;
/// Where a running builder guest finds mvm's own builder binaries.
pub mod builder_guest_paths;
mod builder_host_binaries;
/// The mvm sources a builder image's evaluation reads, shared by the Stage 0
/// fingerprint and the local image cache key.
pub mod builder_image_inputs;
/// One flake build through a builder VM, as a request and a result, for a
/// caller that wants the artifacts where it asked for them.
pub mod builder_orchestrator;
/// Reusable producer that turns real builder artifacts (`vmlinux` + `rootfs.ext4`)
/// into a signed, cache-promotable Builder pack — the produce half of the
/// attested-builder-pack path whose verify/materialize half lives in
/// `mvm_core::packs`.
pub mod builder_pack;
/// Vsock dispatch wire types for the persistent builder VM.
pub mod builder_protocol;
pub mod builder_route;
pub mod builder_vm;
/// Builder image cache discovery and Stage 0 store preparation shared by all
/// VMM backends.
pub mod builder_vm_image;
/// Hypervisor-agnostic builder-VM orchestration helper that wraps a
/// `VmBackendForBuilder` implementation (libkrun and HVF).
pub mod builder_vm_runtime;
/// Builder disk transport, runtime-overlay, and egress helpers shared by all
/// one-shot VMM backends.
pub mod builder_vm_transport;
/// Request-handling core of the resident `mvm-builderd` builder-VM
/// daemon: stateless request dispatch + the framed connection serve
/// loop. The bin entrypoint and AF_VSOCK listener land with boot wiring.
pub mod builderd;
/// Host-side client for the resident `mvm-builderd` daemon: connect +
/// handshake, run one typed operation per connection, stream
/// progress/log events, and surface a typed terminal outcome.
pub mod builderd_client;
/// Typed allowlisted control-plane protocol for the resident
/// `mvm-builderd` builder-VM service (the long-term replacement for the
/// controlled-shell-job channel in `builder_protocol`).
pub mod builderd_protocol;
pub mod cache;
/// Shared conventions for admitting an artifact into a cache root: the
/// cross-root seed from the host's shared cache, the staging-directory dance
/// every install uses, and the digest-manifest check that gates admission.
pub mod cache_install;
/// The lib half of the retired `mvm-egress-proxy` bin, which no builder VM
/// installs or runs any more; see the module docs.
pub mod egress_proxy;
pub mod egress_readiness;
/// The pinned zig + Rust cross-compile toolchain that produces `mvmctl`'s Linux
/// host payload. Shared with `crates/mvm-cli/build.rs`, which `#[path]`-includes
/// it.
pub mod embed_toolchain;
/// Extract an FC-loadable ELF `vmlinux` from a published x86_64 bzImage.
pub mod guest_elf;
/// Which libc a materialized guest rootfs carries, observed while the tree is
/// still a directory the host can read.
pub mod guest_libc;
/// Which of this crate's binaries `mvmctl` embeds as its Linux host payload.
pub mod host_payload_manifest;
pub mod image_source;
/// Config contract for the `mvm-hvf-supervisor` per-VM host process (raw HVF
/// macOS backend, raw HVF backend). Shared by `mvm_runtime::backends::hvf` (writer) + the bin.
/// Universal initramfs build + cache resolution.
pub mod initramfs;
pub mod intoto;
/// Content identity for fetched kernel artifacts.
pub mod kernel_artifact;
/// Hash-verify a fetched kernel image against its [`kernel_artifact::KernelArtifactId`].
pub mod kernel_fetch;
/// Portable signed `.mvm` artifacts. A tar.gz wrapper around kernel +
/// rootfs + verity sidecars + cmdline, with an Ed25519-signed manifest
/// that hashes every payload.
pub mod packed_artifact;
/// Host-side scaffold for the persistent builder VM's dispatch
/// supervisor. This module owns the dispatch wire over the socket
/// libkrun creates; spawning the libkrun VM itself lives in
/// `LibkrunPersistentHostVm`.
pub mod persistent_builder;
/// Whether a live persistent builder session is kept, stopped, or reused.
pub mod persistent_builder_policy;
pub mod persistent_builder_transport;
/// Build-provenance recorder: content-addresses produced artifacts into the
/// signed plan's `BuildProvenance`.
pub mod provenance;
pub mod provenance_mark;
/// Acquire the signed image set this build pins and deliver its members, each
/// held to the digest the verified root declares.
pub mod published_image_set;
/// OCI-unpacked tree to ext4 rootfs image. The host only allocates the
/// sparse file; formatting and copying happen inside the builder VM.
pub mod rootfs;
/// In-process newc cpio writer for host-assembled initramfs archives.
pub mod rootfs_inject;
/// Shared run-path rootfs orchestration (inject runtime + materialize ext4),
/// used by the CLI's `run --image` and the `mvm-client` local backend.
pub mod run_image;
pub mod runtime_identity;
pub mod seed_store_entries;
/// The identity of a Rust binary an image compiles from workspace source.
pub mod source_closure;
pub mod stage0;
/// Host-side Stage 0 pieces that belong to no particular VMM.
///
/// It materializes the seed root through the pure ext4 writer and re-exports
/// the persistent-store helpers formerly housed in `libkrun_builder`.
pub mod stage0_host;
/// The one kernel Stage 0 can neither build nor resolve by the ordinary policy.
pub mod stage0_kernel;
/// Whether a builder guest may fall back to a tmpfs Nix store, or must stop.
pub mod store_readiness;
pub mod template_reuse;
/// Persistent ext4 image materialization for user-attached block volumes.
pub mod volume_image;
/// The workspace crate graph and source hashes, shared with `mvm-cli`'s build
/// script by `#[path]` include.
pub mod workspace_graph;

/// Acquiring and running the builder-VM bootstrap helper.
pub mod builder_vm_bootstrap;
/// Libkrun-backed builder VM. Native FFI linkage remains separately opt-in.
#[cfg(feature = "builder-libkrun")]
pub mod libkrun_builder;

/// The libkrun `NetworkProvider` impl.
/// Gated with `libkrun_builder`: it wraps that module's gateway selection.
#[cfg(feature = "builder-libkrun")]
pub mod libkrun_network_provider;

/// QEMU-backed builder VM (the Linux dev/builder substrate). Boots the
/// nix-tarball Stage 0 seed on the stock distro kernel + initramfs with
/// ext4 disks + vsock-only egress. Linux-only at runtime; compiles
/// everywhere (the selection only picks it on Linux).
/// Shared in-guest static-IP helpers: `configure_static` (gated
/// `cfg(linux)`) plus pure address-parsing/encoding utilities tested
/// on every host. Consumed by both `stage0-init` and `mvm-host-vm-init`.
pub mod guest_net;

pub mod qemu_builder;

/// Builder-runtime selection. `MVM_BUILDER_BACKEND` picks among the
/// available builder backends; the platform default is hvf on supported
/// Apple Silicon macOS and qemu elsewhere. libkrun remains an explicit
/// contributor-only override. The caller receives a `Box<dyn BuilderVm>` so
/// the dispatch site doesn't depend on which concrete driver the env-var
/// resolved to.
pub mod builder_backend_select;
/// Per-host builder-VM health cache (skip a libkrun backend that can't create
/// its VM here).
pub mod builder_health;

/// Which arm prepares an image that is otherwise pair-built from an image
/// checkout: adopt the pinned set's verified members (when they were built
/// from this tree, or unconditionally on request), or build locally.
pub mod fetch_unchanged;
/// Host-side cross-compile + cache of the guest agent/netinit binaries
/// baked into an OCI rootfs by [`oci_runtime_inject`].
pub mod guest_agent_build;
pub mod nix;
/// Inject the mvm guest runtime (agent, netinit, `/init`, `/mvm/runtime`
/// mount point) into an OCI-unpacked rootfs so `run --image` has a vsock
/// control plane. Host-side filesystem I/O against the staging tree.
pub mod oci_runtime_inject;
pub mod pipeline;
/// Cosign-verify a downloaded release archive against the release workflow's
/// keyless signing identity before anything reads it. Shared by every
/// release-artifact downloader.
pub mod release_signature;
/// Host-side resolver for the mvm runtime overlay disk. Picks the right
/// ext4 + verity sidecar + roothash for the host arch: the pinned image set's
/// member from `~/.mvm/cache/image-set/<root>/runtime-overlay/`, or a source
/// build from `~/.mvm/cache/runtime-overlay/<version>/<arch>/`.
pub mod runtime_overlay;
/// Acquire the published SDK-sidecar disk for hosts that cannot build one.
/// Fetches the per-arch, per-libc member of the signed image set, proves it
/// against the verified root and its own manifest, and installs it under
/// `~/.mvm/cache/image-set/<root>/sdk-sidecar/<member-version>/<arch>/<libc>/`
/// for [`mvm_fs::sdk_sidecar::SdkSidecarResolver`] to pick up.
pub mod sdk_sidecar;

// Legacy re-exports — preserve `mvm_build::build::*`, `mvm_build::scripts::*`, etc.
pub use nix::manifest as nix_manifest;
pub use nix::scripts;
pub use pipeline::{build, dev_build, orchestrator, vsock_builder};

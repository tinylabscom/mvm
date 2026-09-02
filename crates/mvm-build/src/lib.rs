pub mod app_deps;
pub mod app_deps_gate;
/// Compiled distribution channel and the default build-vs-download contract
/// shared by every launch-critical artifact resolver.
pub mod artifact_acquisition;
pub mod artifacts;
pub mod backend;
/// Disk-only job/artifact transport for the hvf-VMM builder (tar-over-raw-
/// disk, so the host never formats or reads a guest filesystem).
pub mod boot_image_select;
pub mod builder_cmdline;
pub mod builder_disk_transport;
/// Reusable producer that turns real builder artifacts (`vmlinux` + `rootfs.ext4`)
/// into a signed, cache-promotable Builder pack — the produce half of the
/// attested-builder-pack path whose verify/materialize half lives in
/// `mvm_core::packs`.
pub mod builder_pack;
/// Vsock dispatch wire types for the persistent builder VM.
pub mod builder_protocol;
pub mod builder_route;
pub mod builder_vm;
/// Hypervisor-agnostic builder-VM orchestration helper that wraps a
/// `VmBackendForBuilder` implementation (libkrun and HVF).
pub mod builder_vm_runtime;
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
/// Builder-VM egress allowlist proxy — the lib half of the
/// `mvm-egress-proxy` bin. Kept as a lib module (not bin-inlined) so
/// its pub API is dead-code-clean on non-Linux and its tests run
/// cross-platform.
pub mod egress_proxy;
pub mod egress_readiness;
/// The pinned zig + Rust cross-compile toolchain behind `embed-host-bins`.
/// Shared with `crates/mvm-cli/build.rs`, which `#[path]`-includes it.
pub mod embed_toolchain;
/// Extract an FC-loadable ELF `vmlinux` from a published x86_64 bzImage.
pub mod firecracker;
pub mod guest_elf;
/// Which libc a materialized guest rootfs carries, observed while the tree is
/// still a directory the host can read.
pub mod guest_libc;
/// Config contract for the `mvm-hvf-supervisor` per-VM host process (raw HVF
/// macOS backend, raw HVF backend). Shared by `mvm_runtime::backends::hvf` (writer) + the bin.
/// Universal initramfs build + cache resolution.
pub mod initramfs;
/// Hash-verify a fetched kernel image against its [`mvm_core::kernel_artifact::KernelArtifactId`].
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
pub mod persistent_builder_transport;
/// Build-provenance recorder: content-addresses produced artifacts into the
/// signed plan's `BuildProvenance`.
pub mod provenance;
/// OCI-unpacked tree to ext4 rootfs image. The host only allocates the
/// sparse file; formatting and copying happen inside the builder VM.
pub mod rootfs;
/// Self-hosting builder-rootfs bootstrap: inject freshly built mvm host binaries
/// into a rootfs via an initramfs patcher on the hvf VMM (no legacy builder).
pub mod rootfs_inject;
/// Shared run-path rootfs orchestration (inject runtime + materialize ext4),
/// used by the CLI's `run --image` and the `mvm-client` local backend.
pub mod run_image;
pub mod runtime_identity;
pub mod stage0;
/// Whether a builder guest may fall back to a tmpfs Nix store, or must stop.
pub mod store_readiness;
pub mod template_reuse;
/// Persistent ext4 image materialization for user-attached block volumes.
pub mod volume_image;

/// Acquiring and running the builder-VM bootstrap helper (gated by
/// `builder-vm`). See module-level docs.
#[cfg(feature = "builder-vm")]
pub mod builder_vm_bootstrap;
/// libkrun-backed builder VM (gated by `builder-vm`). See module-level
/// docs.
#[cfg(feature = "builder-vm")]
pub mod libkrun_builder;

/// The libkrun `NetworkProvider` impl.
/// Gated with `libkrun_builder`: it wraps that module's gateway selection.
#[cfg(feature = "builder-vm")]
pub mod libkrun_network_provider;

/// QEMU-backed builder VM (the Linux dev/builder substrate). Boots the
/// nix-tarball Stage 0 seed on the stock distro kernel + initramfs with
/// ext4 disks + vsock-only egress. Linux-only at runtime; compiles
/// everywhere (the selection only picks it on Linux).
/// Shared in-guest static-IP helpers: `configure_static` (gated
/// `cfg(linux)`) plus pure address-parsing/encoding utilities tested
/// on every host. Consumed by both `stage0-init` and `mvm-host-vm-init`.
pub mod guest_net;

pub use mvm_vmm::host::virtiofsd;

pub mod qemu_builder;

/// Builder-runtime selection. `MVM_BUILDER_BACKEND` picks among the
/// available builder backends; the platform default is hvf on macOS 26+
/// Apple Silicon, qemu on Linux native, and libkrun elsewhere. The caller
/// receives a `Box<dyn BuilderVm>` so the dispatch site doesn't depend on
/// which concrete driver the env-var resolved to.
#[cfg(feature = "builder-vm")]
pub mod builder_backend_select;
/// Per-host builder-VM health cache (skip a libkrun backend that can't create
/// its VM here). Gated with `builder_backend_select` — its only consumers are
/// the builder-selection paths behind `builder-vm`.
#[cfg(feature = "builder-vm")]
pub mod builder_health;

/// Host-side cross-compile + cache of the guest agent/netinit binaries
/// baked into an OCI rootfs by [`oci_runtime_inject`].
pub mod guest_agent_build;
pub mod nix;
/// Inject the mvm guest runtime (agent, netinit, `/init`, `/mvm/runtime`
/// mount point) into an OCI-unpacked rootfs so `run --image` has a vsock
/// control plane. Host-side filesystem I/O against the staging tree.
pub mod oci_runtime_inject;
pub mod pipeline;
/// Host-side resolver for the mvm runtime overlay disk. Picks the right
/// ext4 + verity sidecar + roothash for the running mvmctl version and
/// host arch from `~/.mvm/cache/runtime-overlay/<version>/<arch>/`.
/// Cosign-verify a downloaded release archive against the release workflow's
/// keyless signing identity before anything reads it. Shared by every
/// release-artifact downloader.
pub mod release_signature;
pub mod runtime_overlay;
/// Acquire the published SDK-sidecar disk for hosts that cannot build one.
/// Fetches the per-arch release tarball, proves it against the release's
/// checksum and its own manifest, and installs it under
/// `~/.mvm/cache/sdk-sidecar/<version>/<arch>/` for
/// [`mvm_fs::sdk_sidecar::SdkSidecarResolver`] to pick up.
pub mod sdk_sidecar;

// Legacy re-exports — preserve `mvm_build::build::*`, `mvm_build::scripts::*`, etc.
pub use nix::manifest as nix_manifest;
pub use nix::scripts;
pub use pipeline::{build, dev_build, orchestrator, vsock_builder};

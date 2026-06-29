pub mod app_deps;
pub mod app_deps_gate;
pub mod artifacts;
pub mod backend;
/// Vsock dispatch wire types for the persistent builder VM.
pub mod builder_protocol;
pub mod builder_route;
pub mod builder_vm;
/// Hypervisor-agnostic builder-VM orchestration helper that wraps a
/// `VmBackendForBuilder` implementation (libkrun and Vz).
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
/// Builder-VM egress allowlist proxy — the lib half of the
/// `mvm-egress-proxy` bin. Kept as a lib module (not bin-inlined) so
/// its pub API is dead-code-clean on non-Linux and its tests run
/// cross-platform.
pub mod egress_proxy;
/// Extract an FC-loadable ELF `vmlinux` from a published x86_64 bzImage.
pub mod fc_kernel;
pub mod firecracker;
/// Config contract for the `mvm-hvf-supervisor` per-VM host process (raw HVF
/// macOS backend, Plan 214). Shared by `mvm_backend::hvf` (writer) + the bin.
pub mod hvf_supervisor;
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
/// OCI-unpacked tree to ext4 rootfs image. The host only allocates the
/// sparse file; formatting and copying happen inside the builder VM.
pub mod rootfs;
pub mod stage0;
pub mod template_reuse;
/// Type-safe interface to the `mvm-vz-supervisor` binary —
/// `SupervisorConfig` + on-disk path helpers. It lives in mvm-build
/// (not mvm-backend) because mvm-build's `vz_builder` consumes it and
/// sits below mvm-backend, which would cycle. mvm-backend's `VzBackend`
/// reaches it via `mvm_build::vz`.
pub mod vz;

/// Host-side gvproxy lifecycle (detached spawn + PID-sidecar
/// tear-down). Lives here (not mvm-backend) so the Vz *builder*
/// (`vz_builder`) can reach it for cold-`nix build` egress;
/// mvm-backend's `VzBackend` consumes it via `mvm_build::host_gvproxy`.
/// Gated by `builder-vm` because it links `libkrun_sys::gvproxy` for
/// the binary locator + free-port reservation.
#[cfg(feature = "builder-vm")]
pub mod host_gvproxy;

/// libkrun-backed builder VM (gated by `builder-vm`). See module-level
/// docs.
#[cfg(feature = "builder-vm")]
pub mod libkrun_builder;

/// The libkrun gvproxy/passt `NetworkProvider` impl.
/// Gated with `libkrun_builder`: it wraps that module's gateway selection.
#[cfg(feature = "builder-vm")]
pub mod libkrun_network_provider;

/// QEMU-backed builder VM (the Linux dev/builder substrate). Boots the
/// nix-tarball Stage 0 seed on the stock distro kernel + initramfs with
/// ext4 disks + slirp networking. Linux-only at runtime; compiles
/// everywhere (the selection only picks it on Linux).
/// Shared in-guest static-IP helpers: `configure_static` (gated
/// `cfg(linux)`) plus pure address-parsing/encoding utilities tested
/// on every host. Consumed by both `stage0-init` and `mvm-host-vm-init`.
pub mod guest_net;

pub mod qemu_builder;

/// Vz-backed builder VM (gated by `builder-vm` for symmetry with
/// `libkrun_builder`). Implements the second
/// [`builder_vm::VmBackendForBuilder`] impl alongside
/// `LibkrunBuilderBackend`; both feed the same hypervisor-agnostic
/// `BuilderVmRuntime` orchestration on top.
#[cfg(feature = "builder-vm")]
pub mod vz_builder;

/// Builder-runtime selection. `MVM_BUILDER_BACKEND` picks between
/// `libkrun` (default) and `vz`; the caller receives a
/// `Box<dyn BuilderVm>` so the dispatch site doesn't depend on which
/// concrete driver the env-var resolved to.
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
/// OCI layer unpack to a staging rootfs directory. Handles whiteouts,
/// symlinks, hardlinks, ownership, permissions, path traversal, the
/// `/mvm` reserved-path collision check, and per-entry + per-layer
/// size caps (decompression-bomb mitigation). ext4 generation
/// (`mke2fs -d` against the staging dir) runs inside the builder VM.
pub mod oci_to_rootfs;
pub mod pipeline;
/// Host-side resolver for the mvm runtime overlay disk. Picks the right
/// ext4 + verity sidecar + roothash for the running mvmctl version and
/// host arch from `~/.cache/mvm/runtime-overlay/<version>/<arch>/`.
pub mod runtime_overlay;

// Legacy re-exports — preserve `mvm_build::build::*`, `mvm_build::scripts::*`, etc.
pub use nix::manifest as nix_manifest;
pub use nix::scripts;
pub use pipeline::{build, dev_build, orchestrator, vsock_builder};

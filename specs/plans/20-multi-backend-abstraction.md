# Multi-Backend VM Abstraction: Apple Containers (macOS) + Docker (Windows) for Dev

## Context

mvm currently requires Lima + Firecracker (KVM) to run microVMs on macOS. Lima bootstraps a full Ubuntu VM just to provide `/dev/kvm` — this adds startup latency and complexity. The goal:

- **macOS 26+ dev**: Apple Containers (sub-second startup, no Lima for runtime, native vsock)
- **Windows dev**: Docker (via WSL2)
- **Linux dev**: Lima + Firecracker (existing, kept as-is)
- **Production (all platforms)**: Firecracker on Linux with KVM (unchanged)

Lima + Firecracker remains the fallback on macOS <26.

Nix is still used for all backends — it builds the rootfs/image; only the packaging and runtime differ.

## Why Apple Containers Are Ideal for macOS Dev

| Feature | Firecracker | Apple Containers |
|---------|------------|-----------------|
| Model | Lightweight VM per workload | Lightweight VM per container |
| Guest IPC | **vsock** | **vsock** (vminitd gRPC on port 1024) |
| Startup | ~125ms | ~700ms — still sub-second |
| Filesystem | ext4/squashfs rootfs | ext4 (Swift userspace impl) |
| Image format | Custom rootfs from Nix | Direct ext4 mount (same rootfs) |
| Isolation | Hardware (KVM) | Hardware (Virtualization.framework) |
| Networking | TAP + bridge (172.16.0.0/24) | vmnet (192.168.64.0/24) |
| Snapshots | Full memory + state | Not supported |

**Key**: Both use vsock — `mvm-guest` transport layer is shared.

---

## Identified Gaps and Solutions

### Gap 1: Backend Interface Is Not Truly Unified

**Problem**: The `VmBackend` trait uses associated `type Config`. Callers must call `backend.start_firecracker(&FirecrackerConfig { ... })` — the "abstraction" leaks the backend type. Adding Apple Containers and Docker would add more `start_*()` methods.

**Solution: Unified `VmStartConfig`**

```rust
/// What the caller wants — backend figures out the how.
pub struct VmStartConfig {
    pub name: String,
    pub rootfs_path: PathBuf,         // Nix-built ext4 rootfs (all backends)
    pub kernel_path: Option<PathBuf>, // Firecracker needs; Apple Container ignores
    pub initrd_path: Option<PathBuf>, // Firecracker needs; others ignore
    pub cpus: u32,
    pub memory_mib: u32,
    pub profile: Option<String>,
    pub flake_ref: Option<String>,
    pub revision_hash: Option<String>,
    pub ports: Vec<PortMapping>,
    pub volumes: Vec<Volume>,         // backend translates to drives/mounts/bind-mounts
    pub config_files: Vec<ConfigFile>,
    pub secret_files: Vec<SecretFile>,
}
```

`AnyBackend::start(&VmStartConfig)` dispatches to each backend, which internally converts to its own config type. `FlakeRunConfig` stays as Firecracker's internal type — it just gains `From<&VmStartConfig>`.

### Gap 2: Nix Builds Still Need Linux

**Problem**: Lima provides the Linux environment for `nix build` (needs `mkfs.ext4`, `mount`, etc.). Eliminating Lima entirely creates a chicken-and-egg problem.

**Solution: Keep Lima for builds, Apple Containers for runtime**

- Lima stays as the build environment on macOS (lazy-bootstrapped only when a build is needed)
- Apple Containers replace Lima + Firecracker only for the **runtime** (start/stop/dev)
- The build step (`mvmctl build`, `mvmctl template build`) still runs `nix build` inside Lima
- `mvmctl dev` on macOS 26+ skips Lima for the shell but Lima auto-starts if you run a build

This means Lima is still a dependency on macOS, but it's no longer in the hot path for `start`/`stop`/`dev shell`. Future optimization: replace Lima with a "builder" Apple Container (Nix pre-installed) to eliminate Lima entirely.

### Gap 3: `dev` Mode Needs Backend Awareness

**Problem**: `cmd_dev()` currently = bootstrap Lima + drop into Lima shell. On macOS 26+ with Apple Containers, there's no Lima VM to shell into for dev work.

**Solution: Backend-aware dev mode with user choice**

- `mvmctl dev` → defaults to Apple Container shell on macOS 26+ (boots a dev container, exec via vminitd)
- `mvmctl dev --lima` → falls back to Lima shell (existing behavior, always available)
- `mvmctl dev` on macOS <26 → Lima shell (unchanged)
- On Apple Container: use `vminitd.createProcess()` gRPC to exec an interactive shell
- Dev container image: pre-built OCI with Nix, build tools, mvm guest agent

### Gap 4: Template System Is Snapshot-Dependent

**Problem**: `mvmctl template build` creates Firecracker memory snapshots for fast warm-start. Apple Containers don't support snapshots. Templates become a different concept per backend.

**Solution: Templates have two tiers**

- **Image template** (all backends): pre-built OCI/rootfs image, cold-boot only. Template stores the built artifact path, config (cpus, memory, ports), and profile metadata.
- **Snapshot template** (Firecracker only): existing behavior — image + memory snapshot for warm-start.

The `Template` struct gains a `kind` field:
```rust
pub enum TemplateKind {
    Image,              // OCI/rootfs only — all backends
    Snapshot(SnapInfo), // + memory snapshot — Firecracker only
}
```

`mvmctl template build` checks backend capabilities:
- If `capabilities().snapshots` → full snapshot template
- Otherwise → image-only template

`mvmctl template run` on Apple Container → cold-boot from image (no snapshot restore).

### Gap 5: Guest Channel Abstraction (vsock vs unix socket)

**Problem**: Firecracker and Apple Containers use vsock; Docker uses unix sockets. The guest agent communication is currently vsock-only in `mvm-guest`.

**Solution: `GuestChannel` trait designed upfront, implemented incrementally**

```rust
/// Backend-agnostic guest communication channel.
pub trait GuestChannel: Send + Sync {
    /// Connect to the guest agent.
    fn connect(&self) -> Result<Box<dyn AsyncReadWrite>>;
    /// Channel type for capability checking.
    fn channel_type(&self) -> ChannelType;
}

pub enum ChannelType {
    Vsock { cid: u32, port: u32 },
    UnixSocket { path: PathBuf },
}
```

- Phase 0: define the trait in `mvm-guest`
- Phase 1-2: vsock impl (Firecracker + Apple Container)
- Phase 3: unix socket impl (Docker)

The `VmBackend` trait gains `fn guest_channel(&self, id: &VmId) -> Result<Box<dyn GuestChannel>>` so the caller gets the right channel without knowing the backend.

### Gap 6: Cross-Platform Compilation

**Problem**: `mvm-apple-container` uses Containerization.framework — macOS only. The workspace must build on Linux (CI, production) and potentially Windows.

**Solution: Cargo feature gating + conditional compilation**

```toml
# Cargo.toml (workspace)
[features]
apple-container = ["mvm-apple-container"]
docker = []  # pure Rust, no platform restriction

# mvm-runtime/Cargo.toml
[target.'cfg(target_os = "macos")'.dependencies]
mvm-apple-container = { path = "../mvm-apple-container", optional = true }
```

- `AnyBackend` enum uses `#[cfg(target_os = "macos")]` for `AppleContainer` variant
- CI builds with `--features docker` (no Apple Container on Linux)
- macOS builds with `--features apple-container,docker`
- `VmBackend` trait and `VmStartConfig` are platform-agnostic (in `mvm-core`)

### Gap 7: Network Abstraction

**Problem**: Guest IPs are hardcoded: `172.16.0.2` for Firecracker TAP, `192.168.64.x` for vmnet. Port forwarding, health checks, and service discovery reference these directly.

**Solution: Backend provides network info**

`VmInfo` already has `guest_ip: Option<String>`. Extend with:
```rust
pub struct VmNetworkInfo {
    pub guest_ip: IpAddr,
    pub gateway_ip: IpAddr,      // for routing
    pub subnet: IpNetwork,       // e.g., 172.16.0.0/24 or 192.168.64.0/24
    pub port_mappings: Vec<PortMapping>,
}
```

Each backend populates this from its own networking model:
- Firecracker: TAP interface, `172.16.0.0/24`, host is `.1`, guest is `.2`
- Apple Container: vmnet, `192.168.64.0/24`, dynamic IP assigned
- Docker: Docker bridge, `172.17.0.0/16`, dynamic IP

Port forwarding logic reads from `VmNetworkInfo` instead of hardcoded IPs.

---

## Swift Interop Strategy (Not CLI Shelling)

Use `swift-bridge` crate for Rust↔Swift FFI to call Apple's Containerization framework directly.

### Architecture

```
mvm-runtime (Rust)
  └── AppleContainerBackend
        └── swift-bridge FFI
              └── mvm-apple-container (Swift package)
                    └── imports Containerization framework
                          └── LinuxContainer, VZVirtualMachineManager, etc.
```

### New Crate: `mvm-apple-container`

A thin Swift wrapper package bridged into Rust via `swift-bridge`. Exposes:

```rust
// Rust-side bridge (generated by swift-bridge)
mod ffi {
    fn create_container(id: &str, rootfs_path: &str, cpus: u32, memory_mb: u64) -> ContainerHandle;
    fn start_container(handle: &ContainerHandle) -> Result<VsockPort, String>;
    fn stop_container(handle: &ContainerHandle) -> Result<(), String>;
    fn container_status(handle: &ContainerHandle) -> ContainerState;
    fn list_containers() -> Vec<ContainerInfo>;
    fn container_logs(handle: &ContainerHandle, lines: u32) -> String;
    fn is_available() -> bool;
    fn exec_shell(handle: &ContainerHandle, cmd: &[&str]) -> Result<ExecHandle, String>;
}
```

The Swift side wraps `LinuxContainer` lifecycle:
- `create()` → configure VM with rootfs mount, CPUs, memory, vmnet networking
- `start()` → boot VM, vminitd comes up on vsock:1024, return vsock port
- `stop()` → graceful shutdown
- `exec_shell()` → `createProcess` via vminitd gRPC for `mvmctl dev` interactive shell
- State tracking via `LinuxContainer` state machine (initialized → created → started → stopped)

### Guest Communication

**Use vminitd as process launcher, mvm guest agent as application**
- vminitd is PID 1 in Apple Container, manages VM lifecycle via gRPC/vsock:1024
- mvm guest agent runs as a process launched by vminitd (`createProcess` gRPC call)
- mvm guest agent listens on its own vsock port (e.g., 52) for health checks / integration probes
- Host-side: Rust gRPC client talks to vminitd for lifecycle, `GuestChannel` (vsock) to guest agent for app-level stuff

## Nix Integration

Nix is still used for all backends. The build pipeline is **identical** — all backends consume the same ext4 rootfs:

```
Nix flake → mkGuest → ext4 rootfs (existing, runs in Lima on macOS)
                          ↓
            ┌─────────────┼──────────────┐
            ↓             ↓              ↓
    Firecracker      Apple Container    Docker
    (direct ext4     (direct ext4       (OCI wrap or
     block device)    via VZ block       volume mount)
                      attachment)
```

- **Firecracker**: uses ext4 rootfs as drive attachment (unchanged)
- **Apple Containers**: mounts ext4 rootfs directly via `VZDiskImageStorageDeviceAttachment` — no OCI conversion, no slow import, sub-second startup
- **Docker**: volume-mounts the rootfs directory or OCI wraps (Phase 3, details TBD)

No new `oci.rs` module needed for Apple Containers — the same ext4 rootfs works directly.

---

## Implementation Plan

### Phase 0 — Unify the Backend Interface (~0.5 sprint)

**This is the prerequisite.** Without it, every new backend adds more leaky `start_*()` methods.

**0.1 Create `VmStartConfig` in mvm-core**
- File: `crates/mvm-core/src/vm_backend.rs`
- Backend-agnostic struct describing what to run (name, rootfs, cpus, memory, ports, volumes, config/secret files)
- Replace associated `type Config` on `VmBackend` trait with `VmStartConfig`

**0.2 Add `GuestChannel` trait to mvm-core**
- File: `crates/mvm-core/src/vm_backend.rs` (or new `guest_channel.rs`)
- Define `GuestChannel` trait + `ChannelType` enum (vsock / unix socket)
- Add `fn guest_channel(&self, id: &VmId) -> Result<Box<dyn GuestChannel>>` to `VmBackend`

**0.3 Add `VmNetworkInfo` to mvm-core**
- File: `crates/mvm-core/src/vm_backend.rs`
- Struct with `guest_ip`, `gateway_ip`, `subnet`, `port_mappings`
- Add `fn network_info(&self, id: &VmId) -> Result<VmNetworkInfo>` to `VmBackend`

**0.4 Add `TemplateKind` to template types**
- File: `crates/mvm-core/src/template.rs`
- `Image` vs `Snapshot(SnapInfo)` — checked against backend capabilities

**0.5 Implement `From<&VmStartConfig>` for existing backend configs**
- `FlakeRunConfig::from(&VmStartConfig)` — adds kernel path, socket path, drive config
- `MicrovmNixConfig::from(&VmStartConfig)` — adds runner_dir, slot

**0.6 Unify `AnyBackend::start()`**
- File: `crates/mvm-runtime/src/vm/backend.rs`
- Single `start(&self, config: &VmStartConfig) -> Result<VmId>` method
- Remove `start_firecracker()` and `start_microvm_nix()` methods
- Update all call sites in `crates/mvm-cli/src/commands.rs` (lines ~2683, 2812, 3021, 3066)

### Phase 1 — Apple Container Backend (~1 sprint)

**1.1 Create `mvm-apple-container` Swift package + bridge crate**
- New directory: `crates/mvm-apple-container/`
- Swift package importing `Containerization` framework
- `swift-bridge` build integration in `build.rs`
- API: `is_available()`, `create_container()`, `start_container()`, `stop_container()`, `exec_shell()`
- Conditional compilation: `#[cfg(target_os = "macos")]`
- Cargo feature: `apple-container`

**1.2 Add `AppleContainerBackend` to mvm-runtime**
- File: `crates/mvm-runtime/src/vm/apple_container.rs`
- Implements `VmBackend` trait with `VmStartConfig`
- Capabilities: vsock=true, snapshots=false, pause_resume=false, tap_networking=false
- `guest_channel()` → vsock to guest agent port
- `network_info()` → vmnet subnet info
- Delegates to `mvm-apple-container` FFI

**1.3 Wire into `AnyBackend`**
- Add `#[cfg(target_os = "macos")] AppleContainer(AppleContainerBackend)` variant
- Factory: `from_hypervisor("apple-container")` + auto-detection on macOS 26+
- `--hypervisor apple-container` CLI flag

**1.4 Platform detection**
- File: `crates/mvm-core/src/platform.rs`
- Detect macOS 26+ and Containerization framework availability
- New: `has_apple_containers() -> bool`

### Phase 2 — Guest Agent + Dev Mode (~1 sprint)

**2.1 Guest agent integration**
- Launch mvm guest agent as a process via vminitd gRPC API
- Rust gRPC client for vminitd's `SandboxContext` service (protobuf, vsock:1024)
- File: `crates/mvm-runtime/src/vm/vminitd_client.rs`
- mvm guest agent health checks work over vsock (same as Firecracker)

**2.2 Dev mode backend awareness**
- `mvmctl dev` → auto-selects Apple Container on macOS 26+
- `mvmctl dev --lima` → explicit Lima fallback
- Apple Container dev: boot dev container, `exec_shell()` via vminitd gRPC
- Lima stays available for builds and as explicit fallback

**2.3 Networking parameterization**
- Update port forwarding to use `VmNetworkInfo` from backend
- Remove hardcoded `172.16.0.2` references — get from `network_info()`

**2.4 Template system updates**
- `mvmctl template build` checks `capabilities().snapshots`
- Apple Container: creates `TemplateKind::Image` (no snapshot)
- Firecracker: creates `TemplateKind::Snapshot` (unchanged)
- `mvmctl template run` handles both kinds

### Phase 3 — Docker Backend for Windows (~1 sprint)

**3.1 Add `DockerBackend`**
- File: `crates/mvm-runtime/src/vm/docker.rs`
- Implements `VmBackend` via Docker Engine API (HTTP over unix socket / named pipe)
- Capabilities: vsock=false, snapshots=false, pause_resume=false
- `guest_channel()` → unix socket (mounted as volume in container)

**3.2 Unix socket `GuestChannel` impl**
- File: `crates/mvm-guest/src/unix_socket.rs`
- Implements `GuestChannel` trait for unix socket IPC
- Docker mounts a host directory → guest agent listens on socket in that dir

**3.3 Wire into AnyBackend**
- `--hypervisor docker` flag
- Auto-detect on Windows (WSL2 + Docker)

### Phase 4 — Polish (~0.5 sprint)

**4.1 `mvmctl doctor` checks**
- Apple Container: check macOS version, `container` system status
- Docker: check Docker Engine running, WSL2 available (Windows)

**4.2 Auto-selection logic**
- macOS 26+ → Apple Container (default for runtime)
- macOS <26 → Lima + Firecracker (fallback)
- Windows → Docker
- Linux + KVM → Firecracker (direct, no Lima)
- Linux no KVM → error with helpful message

---

## Files to Create

| File | Purpose |
|------|---------|
| `crates/mvm-apple-container/` | New crate: Swift wrapper + swift-bridge |
| `crates/mvm-apple-container/Package.swift` | Swift package importing Containerization |
| `crates/mvm-apple-container/Sources/` | Swift wrapper code |
| `crates/mvm-apple-container/src/lib.rs` | Rust bridge module |
| `crates/mvm-apple-container/build.rs` | swift-bridge build script |
| `crates/mvm-runtime/src/vm/apple_container.rs` | AppleContainerBackend impl |
| `crates/mvm-runtime/src/vm/docker.rs` | DockerBackend impl |
| `crates/mvm-runtime/src/vm/vminitd_client.rs` | gRPC client for vminitd |
| `crates/mvm-guest/src/unix_socket.rs` | Unix socket GuestChannel impl |

## Files to Modify

| File | Change |
|------|--------|
| `Cargo.toml` (workspace) | Add `mvm-apple-container` to members, feature flags |
| `crates/mvm-core/src/vm_backend.rs` | `VmStartConfig`, `GuestChannel`, `VmNetworkInfo`, remove associated `type Config` |
| `crates/mvm-core/src/template.rs` | `TemplateKind` enum (Image vs Snapshot) |
| `crates/mvm-core/src/platform.rs` | `has_apple_containers()` detection |
| `crates/mvm-runtime/Cargo.toml` | Optional dep on `mvm-apple-container` (cfg macos) |
| `crates/mvm-runtime/src/vm/backend.rs` | `AppleContainer` + `Docker` variants, unified `start()` |
| `crates/mvm-runtime/src/vm/mod.rs` | Add `apple_container`, `docker`, `vminitd_client` modules |
| `crates/mvm-runtime/src/vm/network.rs` | Parameterize subnet via `VmNetworkInfo` |
| `crates/mvm-cli/src/commands.rs` | Unified `backend.start(&config)`, `--hypervisor` values, dev mode |
| `crates/mvm-cli/src/doctor.rs` | Apple Container + Docker availability checks |
| `crates/mvm-guest/src/vsock.rs` | Implement `GuestChannel` trait for vsock |
| `crates/mvm-cli/src/commands.rs` (`cmd_dev`) | Backend-aware dev mode, `--lima` flag |
| `crates/mvm-runtime/src/vm/template/` | `TemplateKind` support, capability-gated snapshot |

## Existing Code to Reuse

| What | Where | How |
|------|-------|-----|
| `VmBackend` trait | `crates/mvm-core/src/vm_backend.rs` | Refactor + implement for new backends |
| `AnyBackend` enum | `crates/mvm-runtime/src/vm/backend.rs` | Add new variants |
| `VmCapabilities` | `crates/mvm-core/src/vm_backend.rs` | Declare per-backend capabilities |
| Platform detection | `crates/mvm-core/src/platform.rs` | Extend with Apple Container check |
| Nix rootfs builder | `crates/mvm-build/src/dev_build.rs` | Rootfs output feeds into OCI wrapper |
| Guest agent vsock | `crates/mvm-guest/src/vsock.rs` | Wrap in `GuestChannel` trait |
| `--hypervisor` CLI flag | `crates/mvm-cli/src/commands.rs` | Add new values |
| Template struct | `crates/mvm-core/src/template.rs` | Add `TemplateKind` |
| `FlakeRunConfig` | `crates/mvm-runtime/src/vm/microvm.rs` | Add `From<&VmStartConfig>` |

## Limitations & Risks

- **macOS 26+ only** for Apple Containers — Lima fallback covers older macOS
- **Apple Silicon only** — no Intel Mac support for Apple Containers
- **No snapshots in Apple Container mode** — dev doesn't need fast-resume; templates are image-only
- **swift-bridge complexity** — Rust↔Swift FFI is less mature than C FFI; may hit edge cases with async
- **Containerization framework is new** — API may change between macOS releases
- **Lima still needed on macOS** — for Nix builds (not in runtime hot path)
- **Docker on Windows**: guest agent needs unix socket, not vsock (different IPC path)
- **Memory overhead**: Apple Containers don't return freed pages to host
- **Kernel compatibility**: Apple Container uses its own kernel (Kata Containers Linux 6.x with vminitd as PID 1); Nix rootfs is designed for Firecracker's kernel. See mitigation below.

## Kernel Compatibility Risk Mitigation

**The problem**: Apple Containers use their own optimized Linux kernel (from Kata Containers project) with `vminitd` (Swift) as PID 1. Our Nix rootfs is designed for Firecracker's minimal kernel with mvm's guest agent as init. Key differences:

| Concern | Firecracker | Apple Container |
|---------|------------|-----------------|
| Kernel | Custom minimal (from Nix) | Kata Containers 6.x (from Apple) |
| PID 1 | mvm guest agent | vminitd (Swift, fixed) |
| Block devices | `/dev/vda` (virtio-blk) | Likely `/dev/vda` (VZ block) |
| Network | `eth0` (virtio-net via TAP) | `eth0` or `enp0s*` (VZ net) |
| Vsock | `/dev/vhost-vsock` | Managed by Virtualization.framework |
| Console | `ttyS0` (serial) | VZ console device |

**Mitigation strategy (Phase 1 validation tasks)**:

1. **Boot test with minimal rootfs**: Before integrating, manually test booting our Nix ext4 rootfs in an Apple Container using the `cctl` reference tool. Check:
   - Does the rootfs mount correctly as a VZ block device?
   - What device names appear in `/proc/partitions`?
   - Does the network interface come up? What's it named?

2. **Init system coexistence**: Since vminitd is PID 1 in Apple Containers (non-negotiable), our rootfs doesn't need to provide its own init. Instead:
   - Strip the init/guest-agent-as-PID-1 setup from the Apple Container rootfs variant
   - Guest agent runs as a regular process launched by vminitd's `createProcess` gRPC
   - The Nix `mkGuest` function may need a `containerMode` flag that omits the init config

3. **Kernel module compatibility**: The Nix rootfs may reference kernel modules that exist in Firecracker's kernel but not in Apple's. Mitigation:
   - Our rootfs is minimal (no loadable modules, everything built-in) — low risk
   - If issues arise, make the rootfs kernel-agnostic by avoiding `/lib/modules` references

4. **Fallback**: If direct ext4 mount has kernel compatibility issues, we can fall back to mounting as `virtiofs` (shared directory) instead of block device — this avoids block device naming issues entirely.

**Validation gate**: Phase 1.1 includes a manual boot test. If it fails, we adjust the rootfs packaging before proceeding to Phase 1.2+.

## Dev vs Production Matrix

| Environment | Backend | Lima? | Startup | Snapshots | IPC | Templates |
|-------------|---------|-------|---------|-----------|-----|-----------|
| macOS 26+ dev | Apple Container | Build only | ~700ms | No | vsock | Image-only |
| macOS <26 dev | Lima + Firecracker | Yes | ~2-5s | Yes | vsock | Full (snapshot) |
| Windows dev | Docker (WSL2) | No | ~1s | No | unix socket | Image-only |
| Linux + KVM prod | Firecracker | No | ~125ms | Yes | vsock | Full (snapshot) |

## Verification

- `cargo test --workspace` — all existing tests pass (no regressions)
- `cargo clippy --workspace -- -D warnings` — zero warnings
- **Phase 0**: `backend.start(&config)` works for Firecracker + MicrovmNix (no `start_*` methods)
- **Phase 1**: `mvmctl run --hypervisor apple-container --flake . --profile minimal` boots via Apple Container
- **Phase 2**: Guest agent health check responds over vsock in Apple Container mode
- **Phase 2**: `mvmctl dev` auto-selects Apple Container; `mvmctl dev --lima` uses Lima
- **Phase 2**: `mvmctl template build base` creates image-only template on Apple Container
- **Phase 3**: `mvmctl run --hypervisor docker` boots via Docker (Windows)
- **Phase 4**: `mvmctl doctor` reports all backend availability
- Firecracker path unchanged: `mvmctl run --hypervisor firecracker` still works
- On macOS <26: Lima + Firecracker fallback works as before

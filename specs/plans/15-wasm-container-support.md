# Plan: Add WASM Container Build Support to mvm

**Status: SHELVED** — Finish the `refactor/simplify-mvm` branch first. Revisit when there's a real WASM workload and the OCI artifact format has stabilized further.

## Context

mvm currently builds Firecracker microVM images exclusively — NixOS system closures producing `vmlinux`, `initrd`, and `rootfs.ext4`. The goal is to eventually also build WASM containers from the same Nix flake infrastructure, producing both raw `.wasm` modules and OCI container images. This would enable running workloads across Firecracker microVMs and WASM runtimes (wasmtime, Spin, etc.) from a single build tool.

**Design principles:**
- Separate codebases per target (FC = full NixOS system, WASM = single binary), unified in one flake
- Flexible WASM runtime: build standard WASI modules (wasm32-wasip1) that work on any runtime
- Both raw `.wasm` and OCI artifact outputs (using WASM-specific OCI media types, not traditional Docker images)
- Incremental: existing FC pipeline untouched, WASM is additive

**Lessons from related projects:**
- **[microsandbox](https://github.com/zerocore-ai/microsandbox):** Uses libkrun microVMs (not FC). Key pattern: Rust-native OCI handling via `oci-spec` crate for pulling/pushing images. Their `Rootfs` enum (`Native(PathBuf)` vs `Overlayfs(Vec<PathBuf>)`) is a clean model for our artifact type discrimination. Their `Sandboxfile` YAML config cleanly separates sandbox definitions from build definitions.
- **[kata-containers](https://github.com/kata-containers/kata-containers):** Containers-in-VMs only (containerd shim). No WASM support — the WASM ecosystem uses separate projects: [runwasi](https://github.com/containerd/runwasi) (containerd WASM shim) and [containerd-wasm-shims](https://github.com/deislabs/containerd-wasm-shims).
- **OCI format distinction:** WASM containers should use [OCI artifact media types](https://www.cncf.io/blog/2024/03/12/webassembly-on-kubernetes-from-containers-to-wasm-part-01/) (`application/vnd.wasm.content.layer.v1+wasm`) rather than wrapping `.wasm` in a traditional Docker image with rootfs layers. This is what runwasi/SpinKube expect.

---

## Phase 1: Core Types (`mvm-core`)

### 1a. Add `BuildTarget` enum to `crates/mvm-core/src/build_env.rs`

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildTarget {
    #[default]
    Firecracker,
    Wasm,
}
```

With `Display` and `FromStr` impls. Accepts `"firecracker"`, `"fc"`, `"wasm"`, `"wasi"`.

### 1b. Add `WasmArtifactPaths` to `crates/mvm-core/src/pool.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmArtifactPaths {
    /// .wasm module filenames within the artifact directory
    pub modules: Vec<String>,
    /// Optional OCI image tarball filename
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oci_image: Option<String>,
}
```

### 1c. Add `target` field to `TemplateSpec` and `TemplateRevision` in `crates/mvm-core/src/template.rs`

Both get `#[serde(default)] pub target: BuildTarget` for backward compatibility. `TemplateRevision` also gets `#[serde(skip_serializing_if = "Option::is_none")] pub wasm_artifacts: Option<WasmArtifactPaths>`.

**Files:** `crates/mvm-core/src/build_env.rs`, `crates/mvm-core/src/pool.rs`, `crates/mvm-core/src/template.rs`

---

## Phase 2: WASM Build Pipeline (`mvm-build`)

### 2a. Add `WasmBuildResult` and `DevBuildOutput` enum to `crates/mvm-build/src/dev_build.rs`

```rust
pub struct WasmBuildResult {
    pub build_dir: String,           // /var/lib/mvm/dev/builds/wasm/<hash>/
    pub wasm_modules: Vec<String>,   // ["app.wasm"]
    pub oci_image: Option<String>,   // "image.tar.gz" if --oci
    pub revision_hash: String,
    pub cached: bool,
}

pub enum DevBuildOutput {
    Firecracker(DevBuildResult),
    Wasm(WasmBuildResult),
}
```

### 2b. Add `dev_build_wasm()` function

Parallel to existing `dev_build()`. Same structure (nix build → extract hash → check cache → copy artifacts), different:
- **Attribute resolution:** `{flake}#packages.{system}.wasm-{profile}` (prefix `wasm-` instead of `tenant-`)
- **Cache path:** `/var/lib/mvm/dev/builds/wasm/<hash>/` (separate namespace)
- **Cache check:** tests for `wasm-manifest.json` instead of `vmlinux + rootfs.ext4`
- **Artifact copy:** copies `*.wasm` files + `wasm-manifest.json` instead of kernel/rootfs

### 2c. Add `dev_build_target()` dispatcher

```rust
pub fn dev_build_target(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
    target: &BuildTarget,
) -> Result<DevBuildOutput>
```

Routes to `dev_build()` or `dev_build_wasm()` based on target. Existing callers that only need FC can continue calling `dev_build()` directly.

### 2d. Add OCI artifact packaging

After building the raw `.wasm` modules, produce an OCI artifact tarball with WASM-specific media types. Two options (decided in Phase 4b):
- **Nix-side:** A separate flake attribute `wasm-{profile}-oci` that wraps the module into an OCI layout
- **Rust-side:** A new `crates/mvm-build/src/oci.rs` module using the `oci-spec` crate to construct the OCI tarball from the `.wasm` file post-build

The `--oci` flag triggers this step after the base WASM build completes.

### 2e. Tests

Follow existing `TestEnv` mock pattern. Test attribute resolution, cache hit/miss, and artifact paths for WASM builds.

**Files:** `crates/mvm-build/src/dev_build.rs`

---

## Phase 3: CLI Integration (`mvm-cli`)

### 3a. Add `--target` flag to `Build` command

```rust
Build {
    // ... existing fields ...
    /// Build target: firecracker (default) or wasm
    #[arg(long, default_value = "firecracker")]
    target: String,
    /// Also produce an OCI container image (wasm target only)
    #[arg(long)]
    oci: bool,
},
```

### 3b. Update `cmd_build_flake()` handler

Parse `target` string into `BuildTarget`, call `dev_build_target()`, display appropriate output:
- FC: show kernel/rootfs paths (unchanged)
- WASM: show module paths, OCI tarball path if `--oci`

### 3c. Reject `mvm run --target wasm`

`mvm run` boots a Firecracker VM — it doesn't apply to WASM. Error with: "WASM modules cannot be run with `mvm run`. Use wasmtime, wasmer, or another WASI runtime."

### 3d. Add `--target` to template commands

`template create` and `template build` accept `--target`. WASM templates skip FC-specific fields (vcpus, mem, data_disk).

**Files:** `crates/mvm-cli/src/commands.rs`, `crates/mvm-cli/src/template_cmd.rs`

---

## Phase 4: Nix Flake (`nix/openclaw/`)

### 4a. Add `mkWasm` builder function to `flake.nix`

```nix
mkWasm = name: { src, wasmTarget ? "wasm32-wasip1", cargoArgs ? "" }:
  let
    rustToolchain = pkgs.rust-bin.stable.latest.default.override {
      targets = [ wasmTarget ];
    };
  in pkgs.stdenv.mkDerivation {
    name = "mvm-wasm-${name}";
    inherit src;
    nativeBuildInputs = [ rustToolchain pkgs.wasm-tools ];
    buildPhase = ''
      cargo build --release --target ${wasmTarget} ${cargoArgs}
    '';
    installPhase = ''
      mkdir -p $out
      find target/${wasmTarget}/release -maxdepth 1 -name "*.wasm" -exec cp {} $out/ \;
      # Generate manifest
      echo '{"target":"${wasmTarget}","modules":[' > $out/wasm-manifest.json
      ...
    '';
  };
```

Requires adding `rust-overlay` or `fenix` as a flake input for cross-compilation toolchain.

### 4b. Add `mkWasmOci` wrapper — WASM-native OCI artifact

**Important:** Don't use `dockerTools.buildImage` (produces traditional Docker images with rootfs layers). WASM runtimes (runwasi, SpinKube) expect **OCI artifacts** with WASM-specific media types:
- `application/vnd.wasm.content.layer.v1+wasm` for the module layer
- `application/vnd.wasm.config.v1+json` for the config

Two approaches:

**Approach A (Recommended): Use `wasm-tools` in Nix to create the OCI layout**

```nix
mkWasmOci = name: wasmDrv:
  pkgs.runCommand "mvm-wasm-oci-${name}" {
    nativeBuildInputs = [ pkgs.wasm-tools pkgs.jq ];
  } ''
    mkdir -p $out
    # Create OCI layout with proper WASM media types
    # (wasm-tools component new / oras push format)
    ...
  '';
```

**Approach B: Rust-side OCI packaging using `oci-spec` crate**

Add a small `oci.rs` module in `mvm-build` that constructs the OCI artifact tarball in Rust using the `oci-spec` crate (pattern borrowed from microsandbox). This gives us precise control over media types and is testable without Nix. The `.wasm` module from Nix is packaged into the correct OCI artifact format post-build.

Either way, the output is a tarball conforming to the OCI image layout spec with WASM-specific media types, pushable via `oras push` or `skopeo copy`.

### 4c. Add example WASM packages to flake outputs

```nix
packages = {
  # Firecracker (existing)
  tenant-gateway = mkGuest "gateway" [ ... ];
  tenant-worker  = mkGuest "worker" [ ... ];
  default        = worker;
  # WASM (new)
  wasm-worker     = mkWasm "worker" { src = ./wasm/worker; };
  wasm-worker-oci = mkWasmOci "worker" wasm-worker;
};
```

### 4d. Add example WASM source

Create `nix/openclaw/wasm/worker/` with a minimal Rust WASI hello-world (`Cargo.toml` + `src/main.rs`) as a working example.

**Files:** `nix/openclaw/flake.nix`, `nix/openclaw/wasm/worker/Cargo.toml`, `nix/openclaw/wasm/worker/src/main.rs`

---

## Phase 5: Manifest Extension (`mvm-build`)

### 5a. Add optional `wasm_profiles` section to `NixManifest`

```rust
pub struct NixManifest {
    pub meta: ManifestMeta,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileEntry>,
    #[serde(default)]
    pub roles: HashMap<String, RoleEntry>,
    #[serde(default)]
    pub wasm_profiles: HashMap<String, WasmProfileEntry>,
}

pub struct WasmProfileEntry {
    pub module: String,  // path to Rust crate directory
    #[serde(default = "default_wasm_target")]
    pub wasm_target: String,  // "wasm32-wasip1"
}
```

Uses `#[serde(default)]` so existing manifests without `wasm_profiles` parse fine.

**Files:** `crates/mvm-build/src/nix_manifest.rs`

---

## Implementation Order

1. **Phase 1** — Core types (small, no behavior change)
2. **Phase 4a-d** — Nix flake with working example (can test `nix build` independently)
3. **Phase 2** — Build pipeline in Rust (wire up to Nix)
4. **Phase 3** — CLI flags (expose to user)
5. **Phase 5** — Manifest extension (refinement)

---

## Verification

1. **Unit tests:** `cargo test` — all existing tests pass, new tests for `BuildTarget`, `WasmBuildResult`, WASM attribute resolution, WASM cache logic
2. **Clippy:** `cargo clippy -- -D warnings` passes
3. **Nix build:** `nix build ./nix/openclaw#wasm-worker` produces `.wasm` module inside Lima VM
4. **OCI build:** `nix build ./nix/openclaw#wasm-worker-oci` produces OCI tarball
5. **CLI integration:** `mvm build --flake ./nix/openclaw --profile worker --target wasm` builds and displays WASM artifact paths
6. **CLI integration:** `mvm build --flake ./nix/openclaw --profile worker --target wasm --oci` also produces OCI image
7. **Backward compat:** `mvm build --flake ./nix/openclaw --profile worker` (no --target) builds FC as before
8. **OCI verify:** `oras manifest fetch` or `skopeo inspect` confirms WASM-specific media types (`application/vnd.wasm.content.layer.v1+wasm`)
9. **Runtime verify:** `wasmtime run <build_dir>/app.wasm` executes the WASM module successfully

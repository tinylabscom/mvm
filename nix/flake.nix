{
  description = "mvm — microVM library built on microvm.nix (plan 60).";

  # ── This flake is a LIBRARY, not a project ───────────────────────────
  #
  # User projects have their OWN `flake.nix` + `mvm.toml`. Their flake
  # imports `mvm` as an input and consumes the library helpers we
  # expose under `lib.<system>.mkGuest` to declare a microVM image.
  # `mvmctl build` reads the user's `mvm.toml`, follows the `flake`
  # field to their flake.nix, and runs `nix build` against it. Users
  # never edit anything inside this repository.
  #
  # User-side example (lives in *their* project):
  #
  #   # my-app/flake.nix
  #   {
  #     inputs.mvm.url = "github:tinylabscom/mvm";
  #     outputs = { self, mvm, ... }: {
  #       packages.x86_64-linux.default = mvm.lib.x86_64-linux.mkGuest {
  #         name = "my-app";
  #         services.web = {
  #           command = [ "/usr/local/bin/web" ];
  #         };
  #       };
  #     };
  #   }
  #
  #   # my-app/mvm.toml
  #   flake = "."
  #   profile = "default"
  #   vcpus = 1
  #   memory_mib = 256
  #
  # The `mkGuest` library is being ported from the previous iteration
  # in a follow-up wave; it composes microvm.nix's
  # NixOS module with mvm's security overlay (per-service uids,
  # seccomp tier, dm-verity, read-only `/etc`). The `lib` attribute
  # below is the placeholder that future user flakes will consume.
  #
  # ── Why microvm.nix ──────────────────────────────────────────────────
  #
  # microvm.nix abstracts Firecracker, Cloud Hypervisor, QEMU, crosvm,
  # kvmtool, and stratovirt as a NixOS module — so adding a hypervisor
  # is a config change here, not a kernel rewrite. Pinned by hash in
  # flake.lock; CI re-audits on every bump (`xtask audit-flake`).
  #
  # Fallback: if a per-bump audit of microvm.nix
  # surfaces a security regression we can't accept, revert to the
  # previous iteration's hand-rolled `nix/` tree at `../mvm/nix/`.
  #
  # ── nixosConfigurations.minimal ──────────────────────────────────────
  #
  # The `minimal` configuration below is **internal** — it's the test
  # fixture our Rust smoke tests use to exercise the build/exec path
  # (`tests/nix_flake_structure.rs`, `tests/smoke_libkrun.rs`).
  # It is NOT a starter template for user projects. Users should
  # write their own flake using `lib.mkGuest`; the minimal profile
  # exists so we can boot something in CI without depending on a
  # user-side fixture.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    # microvm.nix — the foundation. MIT-licensed; pinned by hash in
    # flake.lock; CI re-audits on every bump (xtask audit-flake).
    microvm = {
      url = "github:microvm-nix/microvm.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Workspace root — the Rust crates live one level up from this
    # flake. `mvm-guest-agent.nix` reads `Cargo.lock` from `mvmSrc`,
    # so `mvmSrc = self` was wrong: `self` is the `nix/` subtree of
    # the repo, which doesn't contain `Cargo.lock`. Explicit
    # `path:..` + `flake = false` stages the whole workspace into
    # the store so cargo can see the lockfile and the crates.
    mvm-workspace = {
      url = "path:..";
      flake = false;
    };
  };

  outputs =
    { self
    , nixpkgs
    , microvm
    , mvm-workspace
    , ...
    }:
    let
      systems = [
        # microVM images build only on Linux — no macOS/Darwin output.
        # Cross-builds from macOS need a Linux builder (linux-builder
        # via nix-darwin, or remote nix-daemon). Documented in
        # `specs/runbooks/cross-platform-install.md`.
        "x86_64-linux"
        "aarch64-linux"
      ];

      hostSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      # Helper: construct a NixOS configuration for the named profile.
      mkProfile = system: profileName: nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          microvm.nixosModules.microvm
          (./profiles + "/${profileName}.nix")
        ];
      };

      forAllSystems = nixpkgs.lib.genAttrs systems;

      # ── Library output (USER-FACING) ─────────────────────────────
      #
      # User flakes consume this as `inputs.mvm.lib.<system>.mkGuest`
      # to declare a microVM image. Implementation lives under
      # `./lib/`; the entry point is `./lib/default.nix`.
      # Pass the workspace root as `mvmSrc` so
      # `nix/packages/mvm-guest-agent.nix` can resolve
      # `${mvmSrc}/Cargo.lock` — that lockfile is at the workspace
      # root, not under `nix/`, so `mvmSrc = self` (the historical
      # value) failed `nix build` with "Path 'nix/Cargo.lock' does
      # not exist".
      #
      # A local pure evaluation uses the path input. The persistent
      # builder evaluates `path:/work/nix` after Nix stages that subdirectory
      # into its store, where the locked `path:..` otherwise resolves to
      # `/nix/store` instead of the mounted repository. Its impure build
      # command supplies `MVM_WORKSPACE_PATH=/work`; use that explicit mount
      # and the shared source filter in that environment.
      workspaceSrc =
        let
          envPath = builtins.getEnv "MVM_WORKSPACE_PATH";
        in
        if envPath != "" then
          (import ./lib/workspace-filter.nix { inherit (nixpkgs) lib; }) {
            workspaceRoot = /. + envPath;
          }
        else
          mvm-workspace;

      libFor = import ./lib { inherit nixpkgs microvm; mvmSrc = workspaceSrc; };

      hostPackagesFor = system:
        import ./packages {
          pkgs = nixpkgs.legacyPackages.${system};
          mvmSrc = workspaceSrc;
        };

    in
    {
      # ── Host-installable package overlay ──────────────────────────
      #
      # This is separate from the image-building library below:
      # `overlays.default` exposes source-built host tools only, while
      # `lib.<system>.mkGuest` remains the user image API. The package
      # recipes are intentionally source-only; they do not download
      # mvm-published release artifacts.
      overlays.default = final: _prev:
        let
          hostPackages = import ./packages {
            pkgs = final;
            mvmSrc = workspaceSrc;
          };
        in
        {
          inherit (hostPackages) mvmctl;
        }
        // nixpkgs.lib.optionalAttrs final.stdenv.hostPlatform.isLinux {
          inherit (hostPackages) libkrun libkrunfw mvmctl-native-libkrun qemu-wasm-engine qemu-wasm-smoke-image qemu-wasm-smoke-pack;
        };

      # ── User-facing: lib.<system>.mkGuest ────────────────────────
      #
      # User flakes import this as `inputs.mvm.lib.<system>.mkGuest`
      # to declare a microVM image. The shape is intentionally stable
      # so user flakes don't churn when the implementation evolves.
      lib = forAllSystems (system: libFor { inherit system; });

      # ── Internal: nixosConfigurations.minimal ────────────────────
      #
      # Test fixture for our smoke tests (`tests/smoke_libkrun.rs`,
      # `tests/nix_flake_structure.rs`). NOT a starter template —
      # users write their own flake. The `internal` namespace makes
      # the boundary unambiguous so CI lints can grep for it.
      nixosConfigurations.internal-minimal-x86_64-linux =
        mkProfile "x86_64-linux" "minimal";
      nixosConfigurations.internal-minimal-aarch64-linux =
        mkProfile "aarch64-linux" "minimal";

      # Top-level package output mirroring the internal fixture so
      # `nix build .#internal-minimal-runner` works on Linux CI
      # runners. Same INTERNAL boundary — not consumed by user
      # flakes; if you find yourself running this command, you're
      # working on mvm itself, not a user project.
      packages = nixpkgs.lib.genAttrs hostSystems (system:
        let
          hostPackages = hostPackagesFor system;
        in
        {
          mvmctl = hostPackages.mvmctl;
          default = hostPackages.mvmctl;
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux" || system == "aarch64-linux") {
          inherit (hostPackages) libkrun libkrunfw mvmctl-native-libkrun qemu-wasm-engine qemu-wasm-smoke-image qemu-wasm-smoke-pack;
        }
        // nixpkgs.lib.optionalAttrs (builtins.elem system systems) {
          internal-minimal-runner =
            (mkProfile system "minimal").config.microvm.declaredRunner;
        });

      # ── CI-provable no-glibc closure gate ─────────────────────────
      #
      # The guest's `mvm-setpriv` is static-musl, which drops the
      # util-linux and glibc closures from the mkGuest rootfs. This check
      # realizes that closure and fails if glibc re-enters it — a
      # build-backed guarantee a pure `nix eval` can't provide, since
      # eval can't see a derivation's runtime closure. Wired into the
      # `nix-flake-check` CI job.
      #
      # Scope: this covers the baked rootfs tree that ships inside the
      # guest image (busybox, init, setpriv, and friends). The runtime
      # overlay bind-mounted in at boot is gated by the
      # `runtime-overlay-no-glibc` CI step, which queries the closure of the
      # executables that flake stages; the glibc SDK cdylib now lives in the
      # separately-attached sidecar, gated the same way by
      # `sdk-sidecar-carries-glibc`. Green across all three means no
      # ordinary guest carries glibc, and the workloads that need the SDK
      # get it from a disk they were admitted to mount.
      checks = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          guest = (libFor { inherit system; }).mkGuest {
            name = "lean-rootfs-probe";
            entrypoint.command = [ "/bin/true" ];
          };
        in
        {
          # The mkGuest rootfs is static-musl only. If the glibc package
          # enters its closure, this build fails — the guest privilege-drop
          # setpriv and every other rootfs binary must stay static. The grep
          # is hash-anchored (/nix/store/<hash>-glibc…) so it matches only the
          # glibc package's own store path, never a derivation whose name
          # merely contains "glibc" (e.g. the probe rootfs tree itself).
          guest-rootfs-no-glibc =
            pkgs.runCommand "guest-rootfs-no-glibc"
              { closure = pkgs.closureInfo { rootPaths = [ guest.passthru.rootfsTree ]; }; }
              ''
                if grep -Eq -- '/nix/store/[a-z0-9]+-glibc(-|$)' "$closure/store-paths"; then
                  echo "glibc present in guest rootfs closure:" >&2
                  grep -E -- '/nix/store/[a-z0-9]+-glibc(-|$)' "$closure/store-paths" >&2
                  exit 1
                fi
                echo ok > "$out"
              '';

          # The lean rootfs has exactly two registered runtime store paths:
          # static BusyBox and the static privilege-drop helper. The CA bundle
          # is copied into /etc rather than retaining its source store path.
          guest-rootfs-package-budget =
            pkgs.runCommand "guest-rootfs-package-budget"
              { closure = guest.passthru.rootfsClosureInfo; }
              ''
                package_count=$(wc -l < "$closure/store-paths")
                if [ "$package_count" -gt 2 ]; then
                  echo "lean guest rootfs closure has $package_count store paths; budget is 2:" >&2
                  cat "$closure/store-paths" >&2
                  exit 1
                fi
                echo "$package_count" > "$out"
              '';
        });
    };
}

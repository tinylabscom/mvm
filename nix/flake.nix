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
      # Pass the `mvm-workspace` flake input (the workspace root,
      # one level up from this flake) as `mvmSrc` so
      # `nix/packages/mvm-guest-agent.nix` can resolve
      # `${mvmSrc}/Cargo.lock` — that lockfile is at the workspace
      # root, not under `nix/`, so `mvmSrc = self` (the historical
      # value) failed `nix build` with "Path 'nix/Cargo.lock' does
      # not exist". The flake-input form preserves purity: nix
      # stages the workspace into the store as a regular input
      # snapshot.
      libFor = import ./lib { inherit nixpkgs microvm; mvmSrc = mvm-workspace; };

      hostPackagesFor = system:
        import ./packages {
          pkgs = nixpkgs.legacyPackages.${system};
          mvmSrc = mvm-workspace;
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
            mvmSrc = mvm-workspace;
          };
        in
        {
          inherit (hostPackages) mvmctl;
        }
        // nixpkgs.lib.optionalAttrs final.stdenv.hostPlatform.isLinux {
          inherit (hostPackages) libkrun libkrunfw mvmctl-native-libkrun;
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
          inherit (hostPackages) libkrun libkrunfw mvmctl-native-libkrun;
        }
        // nixpkgs.lib.optionalAttrs (builtins.elem system systems) {
          internal-minimal-runner =
            (mkProfile system "minimal").config.microvm.declaredRunner;
        });
    };
}

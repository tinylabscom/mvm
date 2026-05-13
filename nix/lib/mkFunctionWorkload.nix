# mkFunctionWorkload — turn a function-call workload's IR JSON into a
# microVM rootfs in one call. Plan 71.
#
# Reads the canonical workload IR JSON, validates that it describes a
# single-app, single-primary-function workload backed by a
# `nix_packages` image, then composes `mkFunctionService` (factory)
# with `mkGuest` (rootfs builder) so the caller's `flake.nix` shrinks
# to one line:
#
#   packages.${system}.default = mvm.lib.${system}.mkFunctionWorkload {
#     irFile = ./workload-ir.json;
#     appPkg = ./src;
#   };
#
# For workloads that exceed the supported shape (multi-app, multi-
# function, non-nix-packages image, network policy, mounts, …), drop
# down to `mkFunctionService` + `mkGuest` directly and compose the
# unsupported attributes by hand. Each rejected shape names the
# explicit path forward in its error message.
#
# Boot-time staging note (W5.2 backlog):
#   `mkGuest`'s `entrypoint.services` form is currently unwired — it
#   falls through to a recovery shell. Until W5.2 ports the per-
#   service supervisor, this helper composes the factory's per-call
#   wrapper-runner symlinks via `extraFiles`, but stages the user's
#   `appPkg → working_dir` symlink + idles the VM using
#   `entrypoint.command = [ <boot-script> ]`. The wrapper drops privs
#   per-call internally (see `nix/wrappers/{python,node}/oneshot.*`),
#   so it's safe to keep the boot script at uid 0 here. Once `W5.2`
#   wires services properly, the boot-script + `uids.entrypoint = 0`
#   workaround in this file goes away and the factory's own `service`
#   block takes over.
{
  nixpkgs,
  microvm,
  mvmSrc,
}:
let
  mkGuestImpl = import ./mk-guest.nix { inherit nixpkgs microvm mvmSrc; };
  mkFunctionServiceImpl = import ./factories/mkFunctionService.nix;
in
{ system }:
let
  pkgs = import nixpkgs { inherit system; };
  lib = pkgs.lib;
  mkGuest = mkGuestImpl { inherit system; };
in
{
  irFile,
  appPkg,
  hypervisor ? "firecracker",
  vcpus ? 1,
  memory_mib ? 256,
  extraPackages ? [ ],
  extraExtraFiles ? { },
}:
let
  ir = builtins.fromJSON (builtins.readFile irFile);

  failHelp = msg: throw ''
    mkFunctionWorkload: ${msg}

    mkFunctionWorkload only supports single-app, single-primary-function
    workloads backed by a `nix_packages` image. For richer shapes (multi-
    app, multi-function, non-nix-packages image, network policy, mounts,
    …), drop down to `mvm.lib.<system>.mkFunctionService` +
    `mvm.lib.<system>.mkGuest` directly. See `nix/lib/factories/README.md`.
  '';

  apps = ir.apps or (failHelp "IR has no `apps` field");
  _appsOk =
    if (builtins.isList apps) && (builtins.length apps == 1) then
      null
    else
      failHelp "IR must have exactly one app (got ${toString (builtins.length apps)})";
  app = builtins.elemAt apps 0;

  image = app.image or (failHelp "app has no `image` field");
  _imageOk =
    if (image.kind or "") == "nix_packages" then
      null
    else
      failHelp ''
        app.image.kind must be "nix_packages" (got ${image.kind or "<missing>"}).
        Other image shapes haven't been wired through this helper yet.
      '';

  imagePackages = map (p: pkgs.${p}) (image.packages or [ ]);

  entries = app.entrypoints or (failHelp "app has no `entrypoints` field");
  functionEntries = lib.filter (e: (e.kind or "") == "function") entries;
  primaryEntries = lib.filter (e: e.primary or false) functionEntries;
  primary =
    if (builtins.length primaryEntries) == 1 then
      builtins.head primaryEntries
    else if (builtins.length functionEntries) == 1 then
      builtins.head functionEntries
    else
      failHelp ''
        expected exactly one primary function entrypoint, got
        ${toString (builtins.length primaryEntries)} primary out of
        ${toString (builtins.length functionEntries)} function entries.
        Multi-function dispatch is ADR-0014 Phase 2 — until then this
        helper bakes only the primary entrypoint.
      '';

  workingDir = primary.working_dir or "/app";

  # SDK port Phase 10b. `launch.json` carries pre-merged hooks (addons
  # before app); the JSON sidecar is loaded via `irFile` here so the
  # field flows in unchanged. Default to four empty phases so legacy
  # IR documents without `hooks` keep evaluating.
  hooks = ir.hooks or {
    before_build = [ ];
    before_start = [ ];
    after_start = [ ];
    before_stop = [ ];
  };

  factory = mkFunctionServiceImpl {
    inherit pkgs appPkg;
    language = primary.language;
    workloadId = ir.id;
    inherit (primary) module function format;
    sourcePath = workingDir;
    inherit hooks;
  };

  # Boot script: stage the user's source tree at `working_dir`, run
  # the `before_start` hook (no-op when no commands declared), then
  # idle. The agent dispatches per call over vsock (RunEntrypoint), so
  # PID 1 doesn't need to *run* the workload — only keep the VM alive.
  # `_workingDirOnly` is a defensive guard: `dirname /` is `/`, but
  # `dirname /app` is `/`. We never want to recursively chmod above the
  # symlink target, so the parent we mkdir is the immediate parent only.
  #
  # `before_start.sh` runs after the appPkg symlink so user hook
  # commands see the bundled source already mounted at workingDir.
  # Failure of `before_start` aborts boot — the user explicitly
  # declared the command must succeed.
  bootScript = pkgs.writeShellScript "${ir.id}-boot" ''
    set -eu
    mkdir -p "$(${pkgs.coreutils}/bin/dirname ${lib.escapeShellArg workingDir})"
    ${pkgs.coreutils}/bin/ln -sfn ${appPkg} ${lib.escapeShellArg workingDir}
    /etc/mvm/hooks/before_start.sh
    exec ${pkgs.coreutils}/bin/sleep infinity
  '';
in
mkGuest {
  name = ir.id;
  inherit hypervisor vcpus memory_mib;
  entrypoint = {
    command = [ "${bootScript}" ];
  };
  # uid 0: the boot script symlinks into `/` which is root-only. The
  # per-call wrapper drops privs internally via setpriv (W2.3) so
  # this is the same posture the sealed function-workload path
  # already uses; W5.2 + W2.1 will replace this with a per-service
  # uid once services are wired in mkGuest.
  uids = {
    entrypoint = 0;
  };
  extraFiles = factory.extraFiles // extraExtraFiles;
  packages = factory.servicePackages ++ imagePackages ++ extraPackages;
}

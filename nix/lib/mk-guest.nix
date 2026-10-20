# mkGuest — workload root filesystem composition for the initramfs agent.
#
# Same flake the user writes is consumed in BOTH dev and production
# builds. The "sealed vs accessible" distinction is encoded by:
#
#   1. The entrypoint shape:
#        entrypoint.shell    = "/bin/sh"           # accessible (dev-style)
#        entrypoint.command  = [ "/usr/local/bin/web" ]   # sealed default
#        entrypoint.services = { … }               # multi-service supervised
#
#   2. The explicit `dev` flag (overrides the entrypoint heuristic):
#        dev = true   # always enables the console + reachable shell
#        dev = false  # never enables console regardless of entrypoint
#
# Inferred default: `dev = (entrypoint ? shell)`. mvmctl reads the
# `passthru.mvm.{accessible, sealed, entrypointKind, entrypointArgv}` to
# gate `mvmctl console <vm>` host-side; the `/etc/mvm/variant` file
# baked into the rootfs is the in-guest cross-check.
#
# The universal initramfs agent is PID 1 on both dev and sealed boots.
# This composition carries workload files and metadata, not a second init.
#
# microvm.nix is still pinned as a flake input for its
# hypervisor abstractions and kernel-config helpers, but we DO NOT
# use its NixOS module — that's the systemd-heavy path we're
# explicitly avoiding here.

{
  nixpkgs,
  microvm,
  mvmSrc,
}:
{ system }:
let
  pkgs = import nixpkgs { inherit system; };
  lib = nixpkgs.lib;

  # Static busybox — single binary, every shell utility as an applet.
  # Static utilities keep the workload's base closure small.
  busybox = pkgs.pkgsStatic.busybox;

  classifyEntrypoint =
    ep:
    let
      hasShell = ep ? shell;
      hasCommand = ep ? command;
      hasServices = ep ? services;
      forms = lib.count (b: b) [
        hasShell
        hasCommand
        hasServices
      ];
    in
    if forms == 0 then
      throw ''
        mkGuest: entrypoint must declare exactly one of:
          { shell    = "/bin/sh"; }
          { command  = [ "/usr/local/bin/x" ]; }
          { services = { web = { command = … }; … }; }
        Got: ${builtins.toJSON ep}
      ''
    else if forms > 1 then
      throw "mkGuest: entrypoint must declare exactly one form, not several"
    else if hasShell then
      "shell"
    else if hasCommand then
      "command"
    else
      "services";

  # Render a single command list as a quoted shell command line.
  renderCommand = argv: lib.concatStringsSep " " (map lib.escapeShellArg argv);

  sshNeedles = [
    "ssh"
    "sshd"
    "openssh"
    "dropbear"
    "authorized_keys"
    "known_hosts"
    "identityfile"
    "id_rsa"
    "id_ed25519"
    "private key"
  ];

  containsSshMarker =
    value:
    let
      lower = lib.toLower (toString value);
    in
    lib.any (needle: lib.hasInfix needle lower) sshNeedles;

  packageLabel =
    pkg:
    let
      asString = toString pkg;
      attrText =
        if builtins.isAttrs pkg then
          lib.concatStringsSep " " (
            lib.filter (s: s != "") [
              (pkg.pname or "")
              (pkg.name or "")
              (pkg.meta.mainProgram or "")
            ]
          )
        else
          "";
    in
    "${attrText} ${asString}";

in
{
  name,
  entrypoint,
  services ? { },
  packages ? [ ],
  hypervisor ? "firecracker",
  vcpus ? 1,
  memory_mib ? 256,
  dev ? null,
  uids ? null, # { agent = <int>; entrypoint = <int>; } — see below
  builderUid ? null, # optional uid used by an in-guest build daemon
  extraFiles ? { },
  # Whether to bake the `mvm-audit-probe` binary into the rootfs at
  # `/usr/local/bin/audit-probe`. Off by default — it is a test fixture, not a
  # production binary. A live-VM `host.audit.v1` round-trip fixture image sets
  # this `true` and runs the probe as its entrypoint; the production guest
  # closure never includes it.
  withAuditProbe ? false,
  # Whether to bake the static `mvm-setpriv` helper into the rootfs. The
  # runtime overlay carries the helper too, at `/mvm/runtime/setpriv`.
  # Workload scripts can use the baked copy outside the runtime. A builder at
  # boot ABI 2 sets this `false`: `mvmctl` hands the builder its own copy in
  # the boot payload, and the generated scripts then name that copy instead.
  withSetpriv ? true,
  # Optional kernel package. When set, mkGuest copies its module
  # tree (`/lib/modules/<kver>/`) into the rootfs.
  # Required when the kernel ships AF_VSOCK as a module (the default
  # nixpkgs `linuxPackages.kernel` config). Without it,
  # `mvm-guest-agent`'s `socket(AF_VSOCK, …)` returns EAFNOSUPPORT and
  # every host-side surface (`mvmctl console`, `dev shell`, `build`)
  # goes dark on a guest booted from that kernel.
  kernel ? null,
  # Declared-but-unenforced surface. `mvmctl generate template` emits
  # `healthChecks` into its app/web/postgres/worker scaffolds and the mkGuest
  # guide teaches all three, but the multi-service supervisor they depend on is
  # still the stub below (`entrypointKind == "services"`). Rejecting them made
  # every scaffolded project fail to evaluate; accepting them silently would be
  # worse, so they are recorded in `passthru.mvm` and warned about at eval time.
  # When the supervisor lands, wire these in and drop the warning — the
  # conformance suite fails if the docs still call them unimplemented.
  healthChecks ? { },
  volumeMounts ? { },
  serviceGroup ? null,
}:
let
  # Shape checks. `healthChecks` is consumed (rendered into the guest's probe
  # drop-in directory below); the rest are recorded only, so a typo in them
  # would otherwise be invisible.
  declaredButUnenforced =
    (
      if builtins.isAttrs healthChecks then
        [ ]
      else
        throw "mkGuest: healthChecks must be an attribute set"
    )
    ++ (
      if builtins.isAttrs volumeMounts then
        [ ]
      else
        throw "mkGuest: volumeMounts must be an attribute set"
    )
    ++ (
      if serviceGroup == null || builtins.isString serviceGroup then
        [ ]
      else
        throw "mkGuest: serviceGroup must be a string or null"
    );

  # `healthChecks.<name> = { healthCmd; healthIntervalSecs?; healthTimeoutSecs?; }`
  # becomes one `/etc/mvm/probes.d/<name>.json` drop-in per check.
  #
  # The guest agent already scans that directory at boot and runs each entry on
  # its own interval (`probes::load_probe_dropin_dir`, then `probe_health_loop`),
  # serving the results back over vsock as `ProbeStatus`. Every piece of that
  # existed; nothing wrote the drop-ins, so the directory was always empty and a
  # declared health check did nothing at all. This is the missing link.
  probeDropIns = lib.mapAttrs' (
    checkName: check:
    let
      cmd =
        if check ? healthCmd then
          check.healthCmd
        else
          throw "mkGuest: healthChecks.${checkName} must set `healthCmd`";
      interval = if check ? healthIntervalSecs then check.healthIntervalSecs else 30;
      timeout = if check ? healthTimeoutSecs then check.healthTimeoutSecs else 10;
    in
    lib.nameValuePair "/etc/mvm/probes.d/${checkName}.json" {
      content = builtins.toJSON {
        name = checkName;
        inherit cmd;
        interval_secs = interval;
        timeout_secs = timeout;
        output_format = "exit_code";
      };
      mode = "0444";
    }
  ) healthChecks;

  # The caller's own files win: a flake that hand-writes a drop-in for the same
  # path meant to, and silently replacing it would be worse than the collision.
  extraFilesWithProbes = probeDropIns // extraFiles;

  unenforcedNames =
    (if services == { } then [ ] else [ "services" ])
    ++ (if volumeMounts == { } then [ ] else [ "volumeMounts" ])
    ++ (if serviceGroup == null then [ ] else [ "serviceGroup" ]);

  # `seq` on the validation first: a shape error must surface regardless of
  # which thunk the evaluator happens to force earliest, not only when some
  # later binding drags it in.
  warnUnenforced =
    value:
    builtins.seq declaredButUnenforced (
      if unenforcedNames == [ ] then
        value
      else
        builtins.trace (
          "mkGuest: ${builtins.concatStringsSep ", " unenforcedNames} "
          + "declared but NOT enforced — the multi-service supervisor is not wired yet. "
          + "The values are recorded in passthru.mvm for the host; nothing acts on them."
        ) value
    );

  entrypointKind = classifyEntrypoint entrypoint;
  isDev = if dev == null then entrypointKind == "shell" else dev;
  isSealed = !isDev;
  # Whether this image wires the dev console transport. This is an image
  # wiring fact, not an agent-artifact variant; the agent binary is universal
  # and enforces DevOnly verbs at runtime.
  withInteractive = isDev;

  extraFileLabel =
    path:
    let
      rawSpec = extraFilesWithProbes.${path};
      spec = if builtins.isString rawSpec then { source = rawSpec; } else rawSpec;
      source = if spec ? source then toString spec.source else "";
      link = if spec ? link then toString spec.link else "";
      content = if spec ? content then toString spec.content else "";
    in
    "${path} ${source} ${link} ${content}";

  extraFileSourceRoots = lib.filter (source: source != "") (
    map (
      path:
      let
        rawSpec = extraFilesWithProbes.${path};
        spec = if builtins.isString rawSpec then { source = rawSpec; } else rawSpec;
      in
      if spec ? source then
        spec.source
      else if spec ? link then
        spec.link
      else
        ""
    ) (lib.attrNames extraFilesWithProbes)
  );

  sshClosureInfo = pkgs.closureInfo {
    rootPaths = packages ++ extraFileSourceRoots;
  };

  # External GNU ELF support is an explicit application-package opt-in, not a
  # base-image change. Match the pinned output, not an arbitrary package name.
  nativeRuntimeEnabled = lib.any (
    pkg: toString (lib.getLib pkg) == toString (lib.getLib pkgs.glibc)
  ) packages;
  nativeRuntimeRoots = lib.optional nativeRuntimeEnabled (lib.getLib pkgs.glibc);
  nativeRuntimeClosure = pkgs.closureInfo {
    rootPaths = nativeRuntimeRoots;
  };

  # `mvm-host-vm-init` loads this registration into the writable persistent
  # Nix store before an unprivileged builder starts. Without it, Nix treats
  # the read-only rootfs closure as absent and tries to substitute every path
  # again, which is both slow and unsafe when the store already contains a
  # seeded copy. The CA bundle is copied into `/etc` below, so retaining the
  # source `cacert` store path would duplicate the same certificate bytes.
  rootfsClosureInfo = pkgs.closureInfo {
    rootPaths = [
      busybox
    ]
    ++ lib.optional withSetpriv setprivPkg
    ++ packages
    ++ extraFileSourceRoots;
  };

  assertNoSshTemplateInputs =
    let
      badPackages = lib.filter (pkg: containsSshMarker (packageLabel pkg)) packages;
      badFiles = lib.filter (path: containsSshMarker (extraFileLabel path)) (
        lib.attrNames extraFilesWithProbes
      );
      badPackageNames = map (pkg: packageLabel pkg) badPackages;
      badFileNames = map (path: path) badFiles;
    in
    if badPackages != [ ] || badFiles != [ ] then
      throw ''
        mkGuest: SSH is banned in microVM templates. Do not add SSH clients,
        SSH servers, SSH config, host keys, authorized_keys, known_hosts, or
        private-key material through `packages` or `extraFiles`.
        Rejected packages: ${builtins.toJSON badPackageNames}
        Rejected extraFiles: ${builtins.toJSON badFileNames}
      ''
    else
      true;

  assertNoSshClosureScript = ''
    if ${pkgs.gnugrep}/bin/grep -E '/nix/store/[^-]+-(openssh|dropbear|ssh|sshpass|sshfs|autossh)(-|$)' \
        ${sshClosureInfo}/store-paths >/tmp/mvm-ssh-closure-deny 2>/dev/null; then
      echo "mkGuest: SSH-related Nix store paths are banned from template closures:" >&2
      cat /tmp/mvm-ssh-closure-deny >&2
      exit 1
    fi
  '';

  # ── Guest agent build ──────────────────────────────────────────
  #
  # Real Rust binary built from the workspace at `mvmSrc` via
  # `nix/packages/mvm-guest-agent.nix`. The libkrun
  # builder VM is what makes this buildable on hosts without native
  # Linux Nix.
  #
  # The agent artifact is identical for every image. The image's variant and
  # launch-provisioned grant determine which DevOnly verbs can be used.
  guestAgentPkg = pkgs.callPackage ../packages/mvm-guest-agent.nix {
    inherit mvmSrc;
  };

  # Static-musl privilege-drop helper. It replaces the much larger
  # util-linux setpriv closure while preserving the exact privilege flags
  # used by generated workload scripts.
  setprivPkg = import ../packages/mvm-setpriv.nix {
    inherit pkgs;
    rustPlatform = pkgs.pkgsStatic.rustPlatform;
    lib = pkgs.lib;
    inherit mvmSrc;
  };
  # Without a baked copy, the helper is the one the builder boot payload
  # installs at `RUNTIME_HOST_BIN_DIR` (crates/mvm-builder-guest/src/builder_guest_paths.rs).
  setpriv = if withSetpriv then "${setprivPkg}/bin/mvm-setpriv" else "/run/mvm/host-bins/mvm-setpriv";
  setprivHelperName = "mvm-setpriv";

  # In-guest host.audit.v1 driver — test fixture, baked only when
  # `withAuditProbe`. Compiled lazily (Nix only evaluates this when the
  # bake below references it) so the default path adds no build cost.
  auditProbePkg = pkgs.callPackage ../packages/mvm-audit-probe.nix {
    inherit mvmSrc;
  };

  # ── Privilege model (uids) ─────────────────────────────────────
  #
  # PID 1 must be uid 0 (kernel requirement); everything we can
  # drop is dropped via `setpriv` before exec.
  #
  # Every root names one fixed set of guest identities, the same
  # numbers the universal initramfs agent drops to:
  #
  #   0    root
  #   901  mvm-worker — the guest agent and the workload
  #   987  mvm-dns    — the local addon resolver
  #   988  mvm-crng   — the CRNG reseed helper
  #   989  mvm-egress — the FlowMux egress client
  #
  # The agent mounts every root read-only, so the names it resolves
  # are the ones baked here; it cannot add its own.
  #
  # Account overrides and workload-script privilege declarations:
  #
  #   agent       — the host-mediated tool agent (vsock RPC handler).
  #                 Account declaration; defaults to 901.
  #
  #   entrypoint  — account and direct-root-script drop declaration.
  #                 Defaults to 901 in both modes. The universal agent's
  #                 runtime identity is fixed, independent of overrides.
  #
  # Override either via `uids = { agent = N; entrypoint = M; }`. A
  # uid outside the fixed set gets its own account row. The service
  # uids 987–989 are refused.
  workloadUid = 901;
  defaultEntrypointUid = workloadUid;
  resolvedUids = {
    agent = if uids != null && uids ? agent then uids.agent else workloadUid;
    entrypoint = if uids != null && uids ? entrypoint then uids.entrypoint else defaultEntrypointUid;
  };

  # GID == UID by convention. /etc/group entries below mirror this.
  agentUid = resolvedUids.agent;
  entrypointUid = resolvedUids.entrypoint;
  # Dedicated owner for the root-provisioned FlowMux signing key. It must not
  # overlap the workload, agent, or optional builder: only the egress service
  # may read the 0400 key after init drops its mount privilege.
  egressUid = 989;
  assertDedicatedEgressUid =
    if
      egressUid == 0
      || egressUid == agentUid
      || egressUid == entrypointUid
      || (builderUid != null && egressUid == builderUid)
    then
      throw "mkGuest: uid 989 is reserved for the FlowMux egress service"
    else
      true;
  # Dedicated owner for the CRNG reseed helper, the one guest process holding
  # CAP_SYS_ADMIN. Sharing a uid with the agent or the workload would let that
  # process signal it, change its limits, or pose as it on its socket. The
  # guest agent's `CRNG_RESEED_HELPER_UID` is the same number.
  crngReseedUid = 988;
  assertDedicatedCrngReseedUid =
    if
      crngReseedUid == 0
      || crngReseedUid == agentUid
      || crngReseedUid == entrypointUid
      || crngReseedUid == egressUid
      || (builderUid != null && crngReseedUid == builderUid)
    then
      throw "mkGuest: uid 988 is reserved for the CRNG reseed helper"
    else
      true;
  # Dedicated owner for the local addon resolver. It parses every DNS query
  # the workload sends, so a compromise of it yields this uid rather than the
  # agent's. The guest agent's `ADDON_DNS_IDENTITY` is the same number.
  addonDnsUid = 987;
  assertDedicatedAddonDnsUid =
    if
      addonDnsUid == 0
      || addonDnsUid == agentUid
      || addonDnsUid == entrypointUid
      || (builderUid != null && addonDnsUid == builderUid)
    then
      throw "mkGuest: uid 987 is reserved for the addon DNS resolver"
    else
      true;

  assertDedicatedServiceUids = builtins.seq assertDedicatedEgressUid (
    builtins.seq assertDedicatedCrngReseedUid assertDedicatedAddonDnsUid
  );

  # The account rows every root carries, in uid order. `home` is created in
  # the rootfs for the rows that log in with a shell.
  fixedIdentities = [
    {
      name = "root";
      uid = 0;
      gecos = "root";
      home = "/root";
      shell = "/bin/sh";
    }
    {
      name = "mvm-worker";
      uid = workloadUid;
      gecos = "mvm workload";
      home = "/home/mvm-worker";
      shell = "/bin/sh";
    }
    {
      name = "mvm-dns";
      uid = addonDnsUid;
      gecos = "mvm addon DNS";
      home = "/var/empty";
      shell = "/bin/false";
    }
    {
      name = "mvm-crng";
      uid = crngReseedUid;
      gecos = "mvm CRNG reseed";
      home = "/var/empty";
      shell = "/bin/false";
    }
    {
      name = "mvm-egress";
      uid = egressUid;
      gecos = "mvm FlowMux egress";
      home = "/var/empty";
      shell = "/bin/false";
    }
  ];
  # Rows for an overridden uid outside the fixed set, first claim wins.
  extraIdentityCandidates = [
    {
      name = "mvm-agent";
      uid = agentUid;
      gecos = "mvm guest agent";
      home = "/var/empty";
      shell = "/bin/false";
    }
    {
      name = "mvm-entrypoint";
      uid = entrypointUid;
      gecos = "mvm workload";
      home = "/home/mvm-entrypoint";
      shell = "/bin/sh";
    }
  ]
  ++ lib.optional (builderUid != null) {
    name = "mvm-builder";
    uid = builderUid;
    gecos = "mvm build worker";
    home = "/tmp";
    shell = "/bin/sh";
  };
  guestIdentities = lib.foldl' (
    rows: candidate:
    if lib.any (row: row.uid == candidate.uid) rows then rows else rows ++ [ candidate ]
  ) fixedIdentities extraIdentityCandidates;
  passwdText = builtins.seq assertDedicatedServiceUids (
    lib.concatMapStrings (
      row: "${row.name}:x:${toString row.uid}:${toString row.uid}:${row.gecos}:${row.home}:${row.shell}\n"
    ) guestIdentities
  );
  groupText = lib.concatMapStrings (row: "${row.name}:x:${toString row.uid}:\n") guestIdentities;
  identityHomes = map (row: row.home) (
    lib.filter (row: row.uid != 0 && lib.hasPrefix "/home/" row.home) guestIdentities
  );

  # Wrap a command-line in `setpriv` when invoked as root outside the agent.
  # The agent already dispatches workload processes as uid 901.
  #
  # **mvm-setpriv, not busybox's setpriv applet.** `pkgsStatic.busybox`
  # only supports the bare `-d / --nnp / --inh-caps / --ambient-caps`
  # flags. The dedicated static helper implements the numeric uid/gid,
  # group clearing, no-new-privileges, and loopback capability operations
  # needed by workload scripts without pulling util-linux into the rootfs.
  #
  # The flag set is --reuid + --regid + --clear-groups + --no-new-privs.
  # uid==0 short-circuits to the bare command — no point setpriv-ing
  # to root.
  setprivWrap =
    uid: cmd:
    if uid == 0 then
      cmd
    else
      "\"\${MVM_SETPRIV_BIN:-${setpriv}}\" "
      + "--reuid=${toString uid} --regid=${toString uid} "
      + "--clear-groups --no-new-privs -- ${cmd}";

  # The declared workload argv, as a list rather than a rendered line.
  # Exported through passthru so the host — which cannot open a materialized
  # ext4 — can see what the image runs before it boots it. The services arm
  # reports the recovery shell it genuinely falls through to: telling the host
  # this image runs something gentler than it does would be worse than saying
  # nothing.
  entrypointArgv =
    if entrypointKind == "shell" then
      [
        entrypoint.shell
        "-i"
      ]
    else if entrypointKind == "command" then
      entrypoint.command
    else
      [
        "/bin/sh"
        "-i"
      ];

  rawEntrypointCmd =
    if entrypointKind == "shell" then
      "${lib.escapeShellArg entrypoint.shell} -i"
    else if entrypointKind == "command" then
      renderCommand entrypoint.command
    else
      "/bin/sh -i"; # services fallthrough; the supervisor isn't wired yet

  # The full /etc/mvm/entrypoint body. For shell + command forms,
  # setpriv-wrap as appropriate. For services (still stubbed),
  # bail out with a clear note + recovery shell.
  #
  # The entrypoint is invoked by the guest agent (as the workload uid).
  # When already non-root, skip the setpriv
  # drop: the agent has already applied the desired isolation and no
  # longer holds CAP_SETGID, so a second setpriv would fail on
  # setgroups(clear). Direct root invocations retain the explicit drop.
  entrypointCmd =
    if entrypointKind == "services" then
      ''
        echo "mkGuest: entrypoint.services is not yet wired in this iteration"
        echo "  (W5.2 ports the multi-service supervisor binary)"
        echo "  Falling through to a recovery shell for triage."
        if [ "$(/bin/busybox id -u)" -eq 0 ]; then
          ${setprivWrap entrypointUid "/bin/sh -i"}
        else
          /bin/sh -i
        fi
      ''
    else
      ''
        if [ "$(/bin/busybox id -u)" -eq 0 ]; then
          ${setprivWrap entrypointUid rawEntrypointCmd}
        else
          ${rawEntrypointCmd}
        fi
      '';

  # Workload script dispatched by the guest agent, never a PID 1 program.
  entrypointFile = pkgs.writeText "mvm-entrypoint" ''
    #!/bin/sh
    # Auto-generated by mkGuest at build time. Do not edit.
    ${entrypointCmd}
  '';

  # Variant marker (dev|prod). In-guest source of truth — paired
  # with passthru.mvm.{accessible,sealed} on the derivation.
  variantFile = pkgs.writeText "mvm-variant" (if isDev then "dev\n" else "prod\n");

  nameFile = pkgs.writeText "mvm-name" "${name}\n";
  baseImageContract = lib.throwIf (
    extraFiles ? "/etc/mvm/base-image-contract"
  ) "mkGuest: /etc/mvm/base-image-contract is reserved for the base image contract" 1;
  baseImageContractFile = pkgs.writeText "mvm-base-image-contract" "${toString baseImageContract}\n";

  # Verb-trust policy — baked into sealed images only (`isSealed`).
  # Present on every image. Sealed images fail closed because control RPCs
  # require a launch-provisioned grant; DevOnly verbs are additionally gated
  # by the runtime profile.
  verbTrustFile = pkgs.writeText "mvm-verb-trust" ''{"version":1,"require_grant":true,"grant_key_source":"launch_provisioned"}'';

  # Side-binaries from the guest-agent derivation. The agent, netinit,
  # addon-dns, exit-report, and egress-client the guest execs at boot now
  # come exclusively from the mounted runtime overlay at `/mvm/runtime`, so
  # mkGuest no longer bakes them into the rootfs. The seccomp helper remains
  # exported for downstream package consumers, not a shell service launcher.
  #
  # `mvm-seccomp-apply` ships in the same Cargo workspace member and
  # derivation as the agent. Exporting its store path does not apply a
  # workload seccomp filter; service supervision is not wired here.
  seccompApplyBinary = "${guestAgentPkg}/bin/mvm-seccomp-apply";

  mvmAuditProbeBinary = "${auditProbePkg}/bin/audit-probe";

  # extraFiles — accepted spec shapes per target path:
  #
  #   { "absolute/path" = { content = "..."; mode? = "0644"; }; }
  #     → write text content via `pkgs.writeText`. Default mode 0644.
  #
  #   { "absolute/path" = { source = "/nix/store/.../bin/foo"; mode? = "0755"; }; }
  #     → copy an existing file (typically a built binary) from the
  #       given store path. Default mode 0755 (executables dominate).
  #
  #   { "absolute/path" = "/nix/store/.../bin/foo"; }
  #     → shorthand for `{ source = <that string>; }`.
  #
  #   { "absolute/path" = { link = someStoreDerivation; }; }
  #     → symlink to a store path, preserving a directory tree without
  #       depending on a guest boot script to create the link.
  #
  # Binary-source variants exist so the builder-vm flake can
  # install `mvm-host-vm-init` at `/sbin/mvm-host-vm-init` without
  # inlining its bytes as a string (`writeText` is text-only).
  extraFilePopulation = lib.concatMapStringsSep "\n" (
    path:
    let
      rawSpec = extraFilesWithProbes.${path};
      spec = if builtins.isString rawSpec then { source = rawSpec; } else rawSpec;
      hasContent = spec ? content;
      hasSource = spec ? source;
      hasLink = spec ? link;
      mode =
        if spec ? mode then
          spec.mode
        else if hasSource then
          "0755"
        else
          "0644";
      src =
        if hasContent then
          pkgs.writeText "extra-${builtins.hashString "sha256" path}" spec.content
        else if hasSource then
          spec.source
        else if hasLink then
          spec.link
        else
          throw "mkGuest: extraFiles[${path}] must set `content`, `source`, or `link`";
    in
    ''
      target=${lib.escapeShellArg path}
      mkdir -p "$out$(dirname "$target")"
      ${
        if hasLink then
          ''${pkgs.coreutils}/bin/ln -s ${lib.escapeShellArg (toString src)} "$out$target"''
        else
          ''${pkgs.coreutils}/bin/install -m ${mode} ${src} "$out$target"''
      }
    ''
  ) (lib.attrNames extraFilesWithProbes);

  # ── Rootfs tree population ────────────────────────────────────
  #
  # We construct the rootfs as a real directory tree (not a NixOS
  # closure) so the boot path is a flat ext4. Every binary the
  # workload script uses resolves through /bin/* symlinks pointing
  # at /bin/busybox.
  #
  # A later layer adds the security overlay (per-service uids,
  # read-only /etc bind-mount, dm-verity) on top of this base.
  rootfsTree = pkgs.runCommand "mvm-rootfs-tree-${name}" { } ''
    set -e
    mkdir -p "$out"
    ${builtins.seq assertNoSshTemplateInputs assertNoSshClosureScript}

    # Standard FHS dirs the kernel + init expect. `/nix-store`,
    # `/job`, `/out`, `/work`, `/mvm-bins`, `/closure-seed` are mount
    # points the libkrun builder VM needs pre-created — rootfs boots
    # `ro` so `mvm-host-vm-init` can't `mkdir` them at runtime.
    # `/closure-seed` receives the optional pre-fetched toolchain closure
    # NAR (empty + unused unless the host attaches one). `/mnt`,
    # `/data` are the user-volume mount roots (MountPathPolicy allow-roots,
    # alongside `/work`) — the agent mounts `--volume` shares here and can't
    # mkdir on the ro rootfs either.
    mkdir -p "$out"/{bin,sbin,etc,proc,sys,dev,tmp,run,var,root,home,nix/store,nix-store,etc/mvm,job,out,work,mvm-bins,closure-seed,mnt,data}
    chmod 1777 "$out/tmp"
    chmod 0755 "$out/run"

    cp ${rootfsClosureInfo}/registration "$out/nix-path-registration"
    chmod 0444 "$out/nix-path-registration"

    # The mvm runtime overlay is
    # bind-mounted at /mvm/runtime by the universal initramfs agent before
    # switch_root. The directory must exist in the rootfs so the
    # bind-mount has a target. Mode 0755 (owner root); the overlay
    # itself is mounted read-only over it, so contents can't be
    # written by the guest regardless. Outside the verity-boot
    # path the directory is empty; there is no baked agent fallback.
    # `/mvm/` is reserved (an admission-time check
    # rejects OCI images that carry content under this path).
    mkdir -p "$out/mvm/runtime"
    # Mount target for the optional read-only SDK sidecar. Empty on every
    # workload that binds no SDK-served host service; a missing directory would
    # otherwise surface as an unactionable mount-time EACCES on the ones that do.
    mkdir -p "$out/mvm/sdk"
    chmod 0755 "$out/mvm"
    chmod 0755 "$out/mvm/runtime"

    # busybox + applet symlinks. busybox --install -s would do this
    # at runtime; we pre-bake the links so the rootfs has no first-
    # boot setup step.
    cp ${busybox}/bin/busybox "$out/bin/busybox"
    chmod 0755 "$out/bin/busybox"
    for applet in $(${busybox}/bin/busybox --list); do
      ln -sf /bin/busybox "$out/bin/$applet"
    done
    # mvm-setpriv is a dedicated static-musl helper used by the guest
    # PID 1 and by mvm-host-vm-init. Install it alongside busybox so it
    # is on PATH; keep the busybox "setpriv" applet available for any
    # ad-hoc use that does not need the custom flags.
    ${lib.optionalString withSetpriv ''
      cp ${setprivPkg}/bin/mvm-setpriv "$out/bin/mvm-setpriv"
      chmod 0755 "$out/bin/mvm-setpriv"
    ''}
    # Workload entrypoint, never an init. extraFiles may replace it with a
    # per-call marker or wrapper; the agent owns dispatch and exit handling.
    cp ${entrypointFile} "$out/etc/mvm/entrypoint"
    chmod 0755 "$out/etc/mvm/entrypoint"
    cp ${baseImageContractFile} "$out/etc/mvm/base-image-contract"
    chmod 0444 "$out/etc/mvm/base-image-contract"
    cp ${variantFile} "$out/etc/mvm/variant"
    chmod 0444 "$out/etc/mvm/variant"
    cp ${nameFile} "$out/etc/mvm/name"
    chmod 0444 "$out/etc/mvm/name"

    # Verb-trust policy — sealed images only. Absent on dev images so the
    # agent falls back to class-only gating (no file = permissive default
    # for interactive dev shells). Mode 0444: guest reads it at startup;
    # the dm-verity seal prevents any runtime modification.
    ${
      if isSealed then
        ''
          cp ${verbTrustFile} "$out/etc/mvm/verb-trust.json"
          chmod 0444 "$out/etc/mvm/verb-trust.json"
        ''
      else
        ""
    }

    # /etc/passwd + /etc/group name the fixed guest identities (see
    # `fixedIdentities`) plus any overridden uid outside that set. The
    # universal initramfs agent mounts the root read-only, so these files
    # are what every process on it resolves names against.
    printf '%s' ${lib.escapeShellArg passwdText} > "$out/etc/passwd"
    chmod 0644 "$out/etc/passwd"
    printf '%s' ${lib.escapeShellArg groupText} > "$out/etc/group"
    chmod 0644 "$out/etc/group"
    ${lib.concatMapStrings (home: ''
      mkdir -p "$out${home}"
      chmod 0755 "$out${home}"
    '') identityHomes}

    # Default /etc/resolv.conf and CA cert bundle — needed for any
    # guest that talks to the network over TLS (most Nix flake
    # fetches reach cache.nixos.org / api.github.com). Cloudflare +
    # Google as the canonical no-infra-of-my-own DNS defaults; the
    # cert bundle is the standard Mozilla one from `pkgs.cacert`.
    cat > "$out/etc/resolv.conf" <<EOF
    nameserver 1.1.1.1
    nameserver 8.8.8.8
    EOF
    chmod 0644 "$out/etc/resolv.conf"

    mkdir -p "$out/etc/ssl/certs"
    cp ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt "$out/etc/ssl/certs/ca-bundle.crt"
    ln -sf /etc/ssl/certs/ca-bundle.crt "$out/etc/ssl/certs/ca-certificates.crt"
    chmod 0644 "$out/etc/ssl/certs/ca-bundle.crt"

    # /usr/local/bin must exist for the audit-probe fixture cp below (and any
    # extraFiles the caller installs there). The guest-runtime binaries
    # (agent, netinit, addon-dns, exit-report, egress-client) are no longer
    # baked here — the guest sources them from the runtime overlay mounted at
    # /mvm/runtime, mounted by the universal initramfs agent.
    mkdir -p "$out/usr/local/bin"

    # In-guest host.audit.v1 driver — test fixture, baked only when the
    # caller opts in. The production guest closure never carries it.
    ${
      if withAuditProbe then
        ''
          cp ${mvmAuditProbeBinary} "$out/usr/local/bin/audit-probe"
          chmod 0555 "$out/usr/local/bin/audit-probe"
        ''
      else
        ""
    }

    # Kernel modules for callers that select a modular kernel; without
    # `/lib/modules/<kver>/` in the rootfs, modprobe has nothing to
    # load and the agent fails to open AF_VSOCK. Copy only the vsock
    # transport closure instead of the full kernel module tree; the
    # full tree is hundreds of MB and the rootfs-size contract keeps
    # growth below 10 MB.
    #
    # nixpkgs splits the aarch64-linux kernel into two derivations:
    # `kernel` ships `Image` + `System.map` + `dtbs/` (no modules),
    # while `kernel.modules` owns the `lib/modules/<kver>/` tree
    # (built with `INSTALL_MOD_PATH=$out`). Probe `kernel.modules`
    # first (modern nixpkgs), fall back to `kernel`'s own `$out` for
    # single-output kernel packages microvm.nix wraps.
    ${lib.optionalString (kernel != null) (
      let
        candidates = (if kernel ? modules then [ kernel.modules ] else [ ]) ++ [ kernel ];
        candidateRefs = lib.concatMapStringsSep " " (c: ''"${c}"'') candidates;
      in
      ''
        for cand in ${candidateRefs}; do
          if [ -d "$cand/lib/modules" ]; then
            shopt -s nullglob
            kmod_dirs=("$cand"/lib/modules/*)
            shopt -u nullglob
            copy_module_closure() {
              local src="$1"
              local dst="$2"
              local module_name="$3"
              local dep_line dep_path dep dep_base base

              while IFS= read -r dep_line; do
                dep_path="''${dep_line%%:*}"
                base=$(${pkgs.coreutils}/bin/basename "$dep_path")
                base="''${base%.xz}"
                base="''${base%.zst}"
                base="''${base%.gz}"
                base="''${base%.ko}"
                if [ "$base" = "$module_name" ]; then
                  if [ ! -e "$dst/$dep_path" ]; then
                    install -D -m 0644 "$src/$dep_path" "$dst/$dep_path"
                  fi
                  for dep in ''${dep_line#*:}; do
                    if [ -n "$dep" ]; then
                      dep_base=$(${pkgs.coreutils}/bin/basename "$dep")
                      dep_base="''${dep_base%.xz}"
                      dep_base="''${dep_base%.zst}"
                      dep_base="''${dep_base%.gz}"
                      dep_base="''${dep_base%.ko}"
                      copy_module_closure "$src" "$dst" "$dep_base"
                    fi
                  done
                  return 0
                fi
              done < "$src/modules.dep"

              echo "mkGuest: required kernel module '$module_name' not found in $src/modules.dep" >&2
              return 1
            }

            for src in "''${kmod_dirs[@]}"; do
              kver=$(${pkgs.coreutils}/bin/basename "$src")
              mkdir -p "$out/lib/modules/$kver"

              # Busybox modprobe resolves these exact names through the
              # dependency graph. The other modules.* indexes serve generic
              # alias and symbol lookup, which this image never requests.
              if [ ! -f "$src/modules.dep" ]; then
                echo "mkGuest: required kernel module metadata $src/modules.dep is missing" >&2
                exit 1
              fi
              cp -a --reflink=auto "$src/modules.dep" "$out/lib/modules/$kver/"

              copy_module_closure \
                "$src" \
                "$out/lib/modules/$kver" \
                "vmw_vsock_virtio_transport"
              # Stage 0 (`bootstrap_builder_vm_image_via_dev_image_stage0`)
              # boots this rootfs and mounts `/work`, `/out`,
              # `/job` as virtio-fs. nixpkgs ships `CONFIG_VIRTIO_FS=m`
              # and `CONFIG_FUSE_FS=m`, so without the module closure
              # `mount -t virtiofs` fails with ENODEV and the VM powers
              # down before `mvm-host-vm-init` can finalize `/job/result`.
              # An earlier change trimmed the closure to vsock-only because
              # that's all the workload microVM path needed; Stage 0's reuse
              # of this rootfs landed later and depends on virtio-fs.
              copy_module_closure \
                "$src" \
                "$out/lib/modules/$kver" \
                "virtiofs"
              copy_module_closure \
                "$src" \
                "$out/lib/modules/$kver" \
                "fuse"
            done
            break
          fi
        done
      ''
    )}

    # Extra user-supplied files.
    ${builtins.seq assertNoSshTemplateInputs extraFilePopulation}

    # Closure of additional packages — symlink each binary into
    # `/usr/local/bin` AND `/sbin` so the standard system-binary
    # paths (`/sbin/mkfs.ext4`, `/sbin/udhcpc`, etc.) resolve.
    # `mvm-host-vm-init` uses those paths verbatim and would
    # ENOENT-fail without them (e.g. e2fsprogs ships mkfs.ext4 in
    # the package's sbin subdir, not bin).
    mkdir -p "$out/usr/local/bin"
    ${lib.concatMapStringsSep "\n"
      # `lib.getBin` resolves the package's `bin` output when it is multi-output
      # (else the default). Without it, a split package's executables are missed:
      # e.g. nixpkgs e2fsprogs ships `mkfs.ext4` in its `bin` output, so iterating
      # `${pkg}/sbin` on the default (lib) output finds nothing and `/sbin/mkfs.ext4`
      # is never created — which fails OCI rootfs materialization (`exited 127`).
      (
        pkg:
        let
          binOut = lib.getBin pkg;
        in
        ''
          for srcdir in bin sbin; do
            if [ -d "${binOut}/$srcdir" ]; then
              for binpath in "${binOut}/$srcdir"/*; do
                [ -e "$binpath" ] || continue
                name=$(basename "$binpath")
                ln -sf "$binpath" "$out/usr/local/bin/$name"
                ln -sf "$binpath" "$out/sbin/$name"
              done
            fi
          done
        ''
      )
      (builtins.seq assertNoSshTemplateInputs packages)
    }

    # The existing ext4 closure materializer below retains these absolute store
    # targets. Do not copy or patch the application's upstream ELF bytes.
    ${lib.optionalString nativeRuntimeEnabled ''
      ${pkgs.python3}/bin/python3 ${./native-runtime.py} \
        --system ${lib.escapeShellArg system} \
        --closure ${nativeRuntimeClosure}/store-paths --root "$out"
    ''}
  '';

  # Package the tree as an ext4 image. nixpkgs ships a make-ext4-fs
  # derivation that handles the mkfs + populate dance correctly.
  # All arguments arrive in a single set via callPackage's auto-arg
  # injection. Reference make-ext4-fs.nix via the flake input
  # (`${nixpkgs}/...`) rather than the angle-bracket form (`<nixpkgs/...>`)
  # — the latter trips flake pure evaluation ("cannot look up
  # '<nixpkgs/...>' in pure evaluation mode").
  #
  # make-ext4-fs pins the filesystem UUID but not the directory hash seed, so
  # `mkfs.ext4` would draw a random one and two builds of the same tree would
  # differ in the superblock and every checksum that covers it. It takes no
  # extra mkfs arguments, so it gets an e2fsprogs whose `mkfs.ext4` always
  # passes the seed. The seed mirrors
  # `mvm_fs::oci_to_rootfs::ext4::Mke2fsOptions::default().hash_seed`.
  rootfsHashSeed = "00000000-0000-0000-0000-000000000002";
  e2fsprogsPinnedHashSeed =
    let
      pinned =
        pkgs.runCommand "e2fsprogs-pinned-hash-seed"
          {
            nativeBuildInputs = [ pkgs.makeWrapper ];
          }
          ''
            mkdir -p "$out/bin"
            for tool in ${pkgs.e2fsprogs.bin}/bin/*; do
              ln -s "$tool" "$out/bin/"
            done
            rm "$out/bin/mkfs.ext4"
            makeWrapper ${pkgs.e2fsprogs.bin}/bin/mkfs.ext4 "$out/bin/mkfs.ext4" \
              --add-flags "-E hash_seed=${rootfsHashSeed}"
          '';
    in
    pinned // { bin = pinned; };

  rootfsImageWithGrowthReserve = pkgs.callPackage "${nixpkgs}/nixos/lib/make-ext4-fs.nix" {
    e2fsprogs = e2fsprogsPinnedHashSeed;
    storePaths = [ rootfsTree ];
    volumeLabel = "mvm-${name}";
    populateImageCommands = ''
      cp -a --reflink=auto ${rootfsTree}/. ./files/
      # The store tree is read-only. Make only staging directories writable
      # so the image builder can replace the closure registration below;
      # changing file modes would weaken sealed entrypoint checks.
      ${pkgs.findutils}/bin/find ./files -type d -exec chmod u+w {} +
      rm -f ./files/nix-path-registration
    '';
  };

  # The generic image builder expands its minimum-sized filesystem by 16 MiB
  # so mutable images have room to grow before their first boot. mkGuest mounts
  # its rootfs read-only and puts mutable directories on tmpfs, so that reserve
  # can never be used.
  rootfsImage =
    pkgs.runCommand "mvm-rootfs-${name}.ext4"
      {
        nativeBuildInputs = [ pkgs.e2fsprogs ];
      }
      ''
        cp --reflink=auto ${rootfsImageWithGrowthReserve} "$out"
        chmod u+w "$out"
        resize2fs -M "$out"
        e2fsck -fn "$out"
        chmod 0444 "$out"
      '';

  mvmMeta = {
    inherit name hypervisor;
    accessible = isDev;
    sealed = isSealed;
    entrypointKind = entrypointKind;
    # What the workload declares, as argv. The host cannot read inside a materialized
    # ext4, so this is where admission learns what a workload runs — and the
    # only reason it can refuse to hand a shell-shaped entrypoint a stdin
    # writer.
    inherit entrypointArgv;
    # True iff this image wires the dev console transport. The agent artifact
    # itself is universal; mvmctl and admission use this image fact only for
    # transport setup and user-facing access checks.
    withInteractive = withInteractive;
    initSystem = "initramfs-agent";
    inherit baseImageContract;
    # Single 300ms boot-budget floor across
    # every backend. The initramfs agent + trimmed kernel + direct vmlinux
    # boot are the levers that keep us under it. A backend that can't
    # hit the floor is a backend we drop.
    expectedBootMs = 300;
    # Actual universal-runtime identities after privileged activation.
    uids = {
      agent = workloadUid;
      entrypoint = workloadUid;
    };
    # Account rows and the generated script's direct-root invocation drop.
    # These declarations do not change the universal runtime's identity.
    declaredUids = resolvedUids;
    # Every account row the root's /etc/passwd and /etc/group carry, as
    # { name, uid } in file order. Forcing it runs the reserved-uid checks.
    identities = builtins.seq assertDedicatedServiceUids (
      map (row: { inherit (row) name uid; }) guestIdentities
    );
    inherit builderUid;
    rootlessEntrypoint = true;
    # Agent binary kind: "real" — the cross-compiled Rust binary.
    # The previous "stub" value flagged a placeholder sh script.
    # `mvmctl status` reads this;
    # production deployments should refuse to boot a "stub" image.
    agentBinary = "real";
    setprivHelperName = setprivHelperName;
    # The rootfs carries a `/mvm/runtime`
    # bind-mount target. The initramfs agent mounts the overlay before pivot;
    # there is no baked guest-agent fallback. Admission-time gates can
    # refuse to boot a workload whose rootfs is not overlay-aware
    # (e.g. an old cached template predating overlay support).
    overlayAware = true;
    # Always true: mkGuest no longer bakes the guest-runtime binaries into
    # the rootfs, so every image depends on the runtime overlay contract at
    # boot. The required-overlay admission gate reads this to refuse a rootfs
    # that could silently degrade to a baked agent/netinit pair.
    runtimeLean = true;
    sshTemplateBan = builtins.seq assertNoSshTemplateInputs true;
    # The probe drop-ins this guest carries, as `<path> -> <decoded entry>`.
    # Exposed so a host (or a test) can see what the guest will actually run
    # without building the rootfs to go and read the files.
    #
    # Read back out of `extraFilesWithProbes` — the exact set the rootfs
    # population loop iterates — rather than out of `probeDropIns`. Deriving it
    # from the rendering instead would report drop-ins that never reached the
    # image: a first version of this did, and breaking the merge outright
    # changed no assertion at all.
    probes = lib.mapAttrs (_: spec: builtins.fromJSON spec.content) (
      lib.filterAttrs (path: _: lib.hasPrefix "/etc/mvm/probes.d/" path) extraFilesWithProbes
    );
    # Declared-but-unenforced, recorded so a host or an audit can see the gap
    # between what the flake asked for and what the guest actually does.
    unenforced = {
      inherit
        services
        healthChecks
        volumeMounts
        serviceGroup
        ;
      names = unenforcedNames;
    };
  };
in
warnUnenforced (
  rootfsImage.overrideAttrs (old: {
    passthru = (old.passthru or { }) // {
      mvm = mvmMeta;
      inherit rootfsTree;
      inherit rootfsClosureInfo;
      inherit setprivHelperName;
      # Surface the chosen hypervisor + resource defaults at the top
      # of passthru so `nix eval` is sufficient for mvmctl to drive
      # the runtime — no NixOS evaluation needed.
      inherit hypervisor;
      resources = { inherit vcpus memory_mib; };
      # Preserve the exported guest package and seccomp-helper store path
      # for downstream package consumers without baking either into the root.
      inherit guestAgentPkg seccompApplyBinary;
    };
  })
)

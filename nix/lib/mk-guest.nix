# mkGuest — busybox-as-PID-1 microVM image builder.
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
# ── Why busybox-as-PID-1, not NixOS+systemd ──
#
# The short version: NixOS+systemd boots in 1-3 s; Alpine+OpenRC in 300-500 ms;
# busybox-as-PID-1 with custom init approaches the upstream Firecracker
# reference of ~125 ms. The 200ms cold-boot target on Firecracker
# requires the busybox path. The previous iteration of mvm shipped
# this exact strategy.
#
# microvm.nix is still pinned as a flake input for its
# hypervisor abstractions and kernel-config helpers, but we DO NOT
# use its NixOS module — that's the systemd-heavy path we're
# explicitly avoiding here.

{ nixpkgs, microvm, mvmSrc }:
{ system }:
let
  pkgs = import nixpkgs { inherit system; };
  lib  = nixpkgs.lib;


  # Static busybox — single binary, every shell utility as an applet.
  # `pkgsStatic` ensures no glibc dynamic-linker hop at /init time
  # (which alone saves ~10ms vs a glibc-linked init).
  busybox = pkgs.pkgsStatic.busybox;

  classifyEntrypoint = ep:
    let
      hasShell    = ep ? shell;
      hasCommand  = ep ? command;
      hasServices = ep ? services;
      forms       = lib.count (b: b) [ hasShell hasCommand hasServices ];
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
    else if hasShell then "shell"
    else if hasCommand then "command"
    else "services";

  # Render a single command list as a quoted shell command line.
  renderCommand = argv:
    lib.concatStringsSep " " (map lib.escapeShellArg argv);

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

  containsSshMarker = value:
    let
      lower = lib.toLower (toString value);
    in
    lib.any (needle: lib.hasInfix needle lower) sshNeedles;

  packageLabel = pkg:
    let
      asString = toString pkg;
      attrText =
        if builtins.isAttrs pkg then
          lib.concatStringsSep " " (lib.filter (s: s != "") [
            (pkg.pname or "")
            (pkg.name or "")
            (pkg.meta.mainProgram or "")
          ])
        else "";
    in
    "${attrText} ${asString}";

in
{ name
, entrypoint
, services       ? { }
, packages       ? [ ]
, hypervisor     ? "firecracker"
, vcpus          ? 1
, memory_mib     ? 256
, dev            ? null
, uids           ? null   # { agent = <int>; entrypoint = <int>; } — see below
, builderUid     ? null   # optional uid used by an in-guest build daemon
, extraFiles     ? { }
# Whether to bake the `mvm-audit-probe` binary into the rootfs at
# `/usr/local/bin/audit-probe`. Off by default — it is a test fixture, not a
# production binary. A live-VM `host.audit.v1` round-trip fixture image sets
# this `true` and runs the probe as its entrypoint; the production guest
# closure never includes it.
, withAuditProbe ? false
# Optional kernel package. When set, mkGuest copies its module
# tree (`/lib/modules/<kver>/`) into the rootfs and `/init` runs
# `modprobe vmw_vsock_virtio_transport` before forking the agent.
# Required when the kernel ships AF_VSOCK as a module (the default
# nixpkgs `linuxPackages.kernel` config). Without it,
# `mvm-guest-agent`'s `socket(AF_VSOCK, …)` returns EAFNOSUPPORT and
# every host-side surface (`mvmctl console`, `dev shell`, `build`)
# goes dark on a guest booted from that kernel.
, kernel         ? null
# PID 1 boot command, distinct from the `entrypoint`. When set, mkGuest
# renders it to `/etc/mvm/boot` and `/init` sources THAT as PID 1 — while
# `/etc/mvm/entrypoint` is left for the caller's `extraFiles` to own (it
# is the guest agent's per-call marker). This separation exists
# because the two roles genuinely need different values for an
# agent-dispatched function workload: PID 1 must idle (keep the VM
# alive), while the agent's marker names the single-shot per-call wrapper.
# Baking both onto `/etc/mvm/entrypoint` made `extraFiles` clobber the
# rendered PID-1 command, so PID 1 exec'd the single-shot wrapper, which
# exits at boot → kernel panic. `null` (the default) keeps the legacy
# single-file behaviour: PID 1 runs `/etc/mvm/entrypoint`.
, bootCommand    ? null
}:
let
  entrypointKind = classifyEntrypoint entrypoint;
  isDev =
    if dev == null then entrypointKind == "shell"
    else dev;
  isSealed = !isDev;
  # Whether this image wires the dev console transport. This is an image
  # wiring fact, not an agent-artifact variant; the agent binary is universal
  # and enforces DevOnly verbs at runtime.
  withInteractive = isDev;

  extraFileLabel = path:
    let
      rawSpec = extraFiles.${path};
      spec =
        if builtins.isString rawSpec then { source = rawSpec; }
        else rawSpec;
      source = if spec ? source then toString spec.source else "";
      content = if spec ? content then toString spec.content else "";
    in
    "${path} ${source} ${content}";

  extraFileSourceRoots = lib.filter (source: source != "") (map
    (path:
      let
        rawSpec = extraFiles.${path};
        spec =
          if builtins.isString rawSpec then { source = rawSpec; }
          else rawSpec;
      in
      if spec ? source then spec.source else "")
    (lib.attrNames extraFiles));

  sshClosureInfo = pkgs.closureInfo {
    rootPaths = packages ++ extraFileSourceRoots;
  };

  # `mvm-host-vm-init` loads this registration into the writable persistent
  # Nix store before an unprivileged builder starts. Without it, Nix treats
  # the read-only rootfs closure as absent and tries to substitute every path
  # again, which is both slow and unsafe when the store already contains a
  # seeded copy. The CA bundle is copied into `/etc` below, so retaining the
  # source `cacert` store path would duplicate the same certificate bytes.
  rootfsClosureInfo = pkgs.closureInfo {
    rootPaths = [ busybox setprivPkg ] ++ packages ++ extraFileSourceRoots;
  };

  assertNoSshTemplateInputs =
    let
      badPackages = lib.filter (pkg: containsSshMarker (packageLabel pkg)) packages;
      badFiles = lib.filter (path: containsSshMarker (extraFileLabel path)) (lib.attrNames extraFiles);
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
    else true;

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
  # emitted by the generated init script.
  setprivPkg = import ../packages/mvm-setpriv.nix {
    rustPlatform = pkgs.pkgsStatic.rustPlatform;
    lib = pkgs.lib;
    inherit mvmSrc;
  };
  setpriv = "${setprivPkg}/bin/mvm-setpriv";
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
  # drop is dropped via `setpriv` before exec. Two configurable
  # uids:
  #
  #   agent       — the host-mediated tool agent (vsock RPC handler).
  #                 Always non-root; never needs privilege.
  #
  #   entrypoint  — the workload the user declared. Defaults differ
  #                 by mode:
  #                   dev = true  → uid 0 (root shell;
  #                                  apt install / mount work)
  #                   dev = false → uid 1000 (rootless workload;
  #                                  defense in depth)
  #
  # Override either via `uids = { agent = N; entrypoint = M; }` —
  # e.g. `entrypoint = 1000` forces a rootless dev shell, or
  # `entrypoint = 0` forces a rootful prod workload (rare; usually
  # a misconfiguration).
  defaultEntrypointUid = if isDev then 0 else 1000;
  resolvedUids = {
    agent = if uids != null && uids ? agent then uids.agent else 990;
    entrypoint =
      if uids != null && uids ? entrypoint
      then uids.entrypoint
      else defaultEntrypointUid;
  };

  # GID == UID by convention. /etc/group entries below mirror this.
  # Per-service derived gids come later; for now we keep it simple.
  agentUid = resolvedUids.agent;
  entrypointUid = resolvedUids.entrypoint;

  # Wrap a command-line in `setpriv` when the target uid is non-zero.
  #
  # **mvm-setpriv, not busybox's setpriv applet.** `pkgsStatic.busybox`
  # only supports the bare `-d / --nnp / --inh-caps / --ambient-caps`
  # flags. The dedicated static helper implements the numeric uid/gid,
  # group clearing, no-new-privileges, and loopback capability operations
  # needed by this init without pulling util-linux into the rootfs.
  #
  # The flag set is --reuid + --regid + --clear-groups + --no-new-privs.
  # uid==0 short-circuits to the bare command — no point setpriv-ing
  # to root.
  setprivWrap = uid: cmd:
    if uid == 0 then cmd
    else
      # No exec: PID 1 runs the workload as a child so /init can capture $?.
      # Persistent services exec `sleep infinity` inside and never return.
      "${setpriv} "
      + "--reuid=${toString uid} --regid=${toString uid} "
      + "--clear-groups --no-new-privs -- ${cmd}";

  # The argv PID 1 ends up exec'ing, as a list rather than a rendered line.
  # Exported through passthru so the host — which cannot open a materialized
  # ext4 — can see what the image runs before it boots it. The services arm
  # reports the recovery shell it genuinely falls through to: telling the host
  # this image runs something gentler than it does would be worse than saying
  # nothing.
  entrypointArgv =
    if entrypointKind == "shell" then
      [ entrypoint.shell "-i" ]
    else if entrypointKind == "command" then
      entrypoint.command
    else
      [ "/bin/sh" "-i" ];

  rawEntrypointCmd =
    if entrypointKind == "shell" then
      "${lib.escapeShellArg entrypoint.shell} -i"
    else if entrypointKind == "command" then
      renderCommand entrypoint.command
    else
      "/bin/sh -i";  # services fallthrough; the supervisor isn't wired yet

  # The full /etc/mvm/entrypoint body. For shell + command forms,
  # setpriv-wrap as appropriate. For services (still stubbed),
  # bail out with a clear note + recovery shell.
  entrypointCmd =
    if entrypointKind == "services" then
      ''
        echo "mkGuest: entrypoint.services is not yet wired in this iteration"
        echo "  (W5.2 ports the multi-service supervisor binary)"
        echo "  Falling through to a recovery shell for triage."
        ${setprivWrap entrypointUid "/bin/sh -i"}
      ''
    else
      "${setprivWrap entrypointUid rawEntrypointCmd}";

  # /init — our PID 1. Pure POSIX shell; busybox provides every
  # utility used here. Boot-time-critical path so kept terse and
  # readable. No bashisms, no externalities beyond busybox applets.
  #
  # Supervision pattern:
  #   1. Stage filesystem (proc/sys/dev + tmpfs).
  #   2. Fork the guest agent in background under setpriv→agent uid.
  #   3. Re-attach stdio (dev variant).
  #   4. setpriv→entrypoint uid + exec the workload.
  #
  # PID 1 stays uid 0 (kernel mandate); both children run rootless
  # by default in production (see uids resolution above).
  initText = ''
    #!/bin/sh
    # mvm /init — busybox PID 1.

    # Stage 1 — kernel pseudofs. Required before anything else
    # can read /proc/self or write to /dev/console.
    /bin/busybox mount -t proc     proc     /proc
    /bin/busybox mount -t sysfs    sysfs    /sys
    /bin/busybox mount -t devtmpfs devtmpfs /dev

    # devpts is required for openpty(3): the guest agent allocates a PTY per
    # interactive `dev` console session (mvm-agentd::console). devtmpfs gives
    # /dev/ptmx the node but not the /dev/pts slave fs, so without this
    # openpty() fails ("openpty() failed") and the interactive dev shell
    # can't open even from a real terminal. Harmless for sealed
    # workload guests (they never openpty); 0620,gid=5 is the standard
    # tty-group layout. Best-effort (`|| true`): a kernel without
    # CONFIG_DEVPTS_* falls back to the current non-interactive behavior
    # rather than wedging PID 1.
    /bin/busybox mkdir -p /dev/pts
    /bin/busybox mount -t devpts -o mode=0620,gid=5,nosuid,noexec devpts /dev/pts || true

    # /dev/fd → /proc/self/fd is what bash process substitution
    # (`< <(...)`, `mapfile -t x < <(...)`) needs to open the
    # subshell's pipe FD at /dev/fd/N. devtmpfs creates device
    # nodes but never these symlinks; udev/mdev/systemd-tmpfiles
    # normally do, and we run none of them. Without /dev/fd a
    # nixpkgs-style build hook fails with "/dev/fd/63: No such
    # file or directory" — same gap is fixed in mvm-host-vm-init's
    # mount_pseudofs(). The four lines are kept symmetric on both
    # sides on purpose.
    [ -e /dev/fd ]     || /bin/busybox ln -s /proc/self/fd   /dev/fd
    [ -e /dev/stdin ]  || /bin/busybox ln -s /proc/self/fd/0 /dev/stdin
    [ -e /dev/stdout ] || /bin/busybox ln -s /proc/self/fd/1 /dev/stdout
    [ -e /dev/stderr ] || /bin/busybox ln -s /proc/self/fd/2 /dev/stderr

    # Stage 2 — runtime tmpfs. /tmp + /run are RAM so the rootfs
    # stays read-only-leaning; volumes attach to fixed
    # mountpoints instead.
    /bin/busybox mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
    /bin/busybox mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run

    # Stage 2.05 — optional chained PID 1. Some images want the
    # busybox /init bootstrap (pseudofs + tmpfs + /dev/fd setup)
    # before handing control to a second static binary. The builder
    # image uses this to enter mvm-host-vm-init after the generic
    # bootstrap so backends that struggle with a direct `init=/sbin/...`
    # exec still start from the same minimal shell-known-good path.
    MVM_CHAIN_INIT=$(/bin/busybox sed -n 's/.*\bmvm\.chain_init=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$MVM_CHAIN_INIT" ]; then
      if [ ! -x "$MVM_CHAIN_INIT" ]; then
        echo "mvm-init: requested chained init $MVM_CHAIN_INIT is missing or not executable"
        exit 1
      fi
      exec "$MVM_CHAIN_INIT"
    fi

    # Stage 2.25 — vsock kernel modules. Stock nixpkgs kernel ships
    # AF_VSOCK as `=m`; without modprobe the agent's
    # `socket(AF_VSOCK, …)` returns EAFNOSUPPORT. modprobe-ing
    # `vmw_vsock_virtio_transport` pulls in `vsock` +
    # `vmw_vsock_virtio_transport_common` via modules.dep. Silently
    # skipped when `/lib/modules` is absent — e.g. on a future kernel
    # that ships VSOCK=y, or when `mkGuest` was called without the
    # `kernel` argument.
    if [ -d /lib/modules ]; then
      /bin/busybox modprobe vmw_vsock_virtio_transport 2>/dev/null || true
    fi

    # Stage 2.27 — configure the loopback interface. The kernel creates `lo`
    # administratively DOWN and without an IPv4 address; merely raising the
    # link still leaves `127.0.0.1` unavailable, so ANY guest-internal
    # loopback service is unreachable
    # (`connect()` → ENETUNREACH) — the egress forward proxy on
    # 127.0.0.1:18080, the in-guest addon-dns resolver, and any local service a
    # workload binds. Must run before the agent (which binds the forward proxy)
    # and before netinit. `ip` first (canonical), `ifconfig` fallback — both are
    # busybox applets in the defconfig this image already relies on for
    # `modprobe`. Non-fatal: a failure logs and leaves loopback down (the prior
    # behaviour), never wedges PID 1.
    if ! /bin/busybox ip addr replace 127.0.0.1/8 dev lo 2>/dev/null \
      || ! /bin/busybox ip link set lo up 2>/dev/null; then
      /bin/busybox ifconfig lo 127.0.0.1 netmask 255.0.0.0 up 2>/dev/null \
        || echo "mvm-init: WARNING could not configure loopback (no ip/ifconfig applet); guest-internal loopback (egress forward proxy, addon-dns) will be unreachable"
    fi

    # Stage 2.45 — mount the optional config/secrets drives. The host uses a
    # deterministic block order: vdb=config, vdc=secrets. These mounts are
    # best-effort and read-only; guests without one or both drives keep booting.
    /bin/busybox mkdir -p /mnt/config /mnt/secrets
    [ ! -b /dev/vdb ] || /bin/busybox mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdb /mnt/config || true
    [ ! -b /dev/vdc ] || /bin/busybox mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdc /mnt/secrets || true

    # Stage 2.3 — user-supplied volumes (`--volume` / MVM_VOLUMES).
    # The host (mvm_core::vm_backend::encode_user_volumes_cmdline) wrote
    # `mvm.uvols=<tag>:<hex(guest_path)>:<ro|rw>:<fs|blk>;...` onto the
    # kernel cmdline. Mount each virtio-fs share at its guest path;
    # best-effort so a bad mount logs and continues rather than wedging
    # PID 1. Disk (`blk`) volumes are attached as block devices for the
    # workload to mount itself (guest auto-mount of disks isn't wired).
    # The guest path is hex-encoded to survive the cmdline's
    # space/`:`/`;` delimiters; we decode it via `sed`+`printf %b`.
    MVM_UVOLS=$(/bin/busybox sed -n 's/.*\bmvm\.uvols=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$MVM_UVOLS" ]; then
      # virtio-fs may be a module on some rootfs. Load it best-effort, but
      # ONLY when user volumes are present, so a no-volume boot (every
      # core-demo workload + the dev VM) runs this entire block as a no-op
      # and is byte-identical to pre-volume behaviour. Errors swallowed —
      # `|| true` means this can never fail or wedge PID 1.
      if [ -d /lib/modules ]; then
        /bin/busybox modprobe virtiofs 2>/dev/null || true
      fi
      echo "$MVM_UVOLS" | /bin/busybox tr ';' '\n' | while IFS=: read -r utag uhex umode ukind; do
        [ -n "$utag" ] || continue
        [ -n "$uhex" ] || continue
        upath=$(printf '%b' "$(echo "$uhex" | /bin/busybox sed 's/../\\x&/g')")
        [ -n "$upath" ] || continue
        if [ "$ukind" = blk ]; then
          echo "mvm-init: user disk volume for '$upath' attached (guest auto-mount of disks not wired)"
          continue
        fi
        /bin/busybox mkdir -p "$upath" 2>/dev/null || true
        if [ "$umode" = ro ]; then
          /bin/busybox mount -t virtiofs -o ro "$utag" "$upath" \
            && echo "mvm-init: mounted user volume $utag at $upath (ro)" \
            || echo "mvm-init: user volume $utag -> $upath failed (mountpoint must exist on the ro rootfs)"
        else
          /bin/busybox mount -t virtiofs "$utag" "$upath" \
            && echo "mvm-init: mounted user volume $utag at $upath (rw)" \
            || echo "mvm-init: user volume $utag -> $upath failed (mountpoint must exist on the ro rootfs)"
        fi
      done
    fi

    # Stage 2.45 — guest-side network defense.
    # Install kernel blackhole routes for `MANDATORY_DENY_RANGES`
    # (cloud metadata, link-local, CGNAT, host loopback) BEFORE
    # any workload code runs. We're still uid 0 here — the agent
    # fork below drops to uid 901, which doesn't have
    # CAP_NET_ADMIN, so the install has to happen here. Mirrors
    # the agent-bin resolution: prefer /mvm/runtime/netinit (from
    # the runtime overlay) over the baked-in copy in
    # /usr/local/bin.
    #
    # Output of mvm-guest-netinit is a single JSON line that the
    # kernel console captures; the host scrape (firecracker.log /
    # libkrun console output) forwards it so an operator can see
    # what was installed. A future slice wires the agent to
    # forward the same JSON as a `NetworkMandatoryDeny` audit
    # event over vsock.
    #
    # On netinit failure (exit nonzero) we DO NOT abort the boot
    # — the host-side iptables defense (where it applies) is the
    # primary layer, and a hard guest-side fail-closed would
    # block any workload on a kernel without rtnetlink. Log the
    # failure and continue; an operator who needs guest-side
    # defense flagged the issue from the JSON line.
    # Stage 2.46 — trust the per-VM egress CA (https
    # substitution). A fresh FC boot attaches no secrets drive, so the host
    # delivers the per-VM name-constrained intermediate CERT on the kernel
    # cmdline as `mvm.egress_ca=pem:<body>` (cert only — the key stays host-side
    # in the terminator). Older boots may still carry the legacy hex-encoded
    # full PEM; accept both while the host-side encoder moves to the compact
    # format. We decode it to a tmpfs file (writable under the dm-verity-sealed
    # rootfs) and point the common TLS-trust env vars at a bundle = baked roots
    # + this cert, so a workload trusts host-terminated bound-host TLS. The
    # export reaches the entrypoint (setpriv preserves env).
    #
    # Honest caveat: Python `ssl` and older Node do NOT enforce X.509
    # nameConstraints client-side, so this trust is a courtesy — the real egress
    # boundary is the host-side allow-list check (claim 12), not this cert.
    #
    # Compact `pem:` tokens reconstruct the PEM body under tmpfs; the legacy
    # hex form stays accepted for older host launches. Absent token ⇒ whole
    # block is a no-op (no-secret guests boot byte-identically).
    MVM_EGRESS_CA_TOKEN=$(/bin/busybox sed -n 's/.*\bmvm\.egress_ca=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$MVM_EGRESS_CA_TOKEN" ]; then
      /bin/busybox mkdir -p /run/mvm
      if echo "$MVM_EGRESS_CA_TOKEN" | /bin/busybox grep -q '^pem:'; then
        MVM_EGRESS_CA_BODY=''${MVM_EGRESS_CA_TOKEN#pem:}
        {
          printf '%s\n' '-----BEGIN CERTIFICATE-----'
          printf '%s' "$MVM_EGRESS_CA_BODY" | /bin/busybox sed 's/.\{64\}/&\n/g'
          printf '\n%s\n' '-----END CERTIFICATE-----'
        } > /run/mvm/egress-ca.crt
      else
        printf '%b' "$(echo "$MVM_EGRESS_CA_TOKEN" | /bin/busybox sed 's/../\\x&/g')" \
          > /run/mvm/egress-ca.crt
      fi
      # Combined bundle so the per-VM cert is trusted ALONGSIDE the baked roots
      # (a workload still reaches cache.nixos.org/api.github.com etc.).
      if cat /etc/ssl/certs/ca-bundle.crt /run/mvm/egress-ca.crt \
          > /run/mvm/ca-bundle.crt 2>/dev/null; then
       :
      else
        /bin/busybox cp /run/mvm/egress-ca.crt /run/mvm/ca-bundle.crt
      fi
      # OpenSSL (curl/most), curl, python-requests → the combined bundle;
      # Node appends just the extra cert.
      export SSL_CERT_FILE=/run/mvm/ca-bundle.crt
      export CURL_CA_BUNDLE=/run/mvm/ca-bundle.crt
      export REQUESTS_CA_BUNDLE=/run/mvm/ca-bundle.crt
      export NODE_EXTRA_CA_CERTS=/run/mvm/egress-ca.crt
      echo "mvm-init: installed per-VM egress CA (https substitution trust)"
    fi

    # Stage 2.47 — inject the per-run secret PLACEHOLDER env.
    # The host minted the workload's placeholders BEFORE boot (so they can ride
    # the cmdline — a fresh FC boot has no secrets drive) and passed them as
    # `mvm.secret_env=<hex(VAR=placeholder\n…)>`. NEVER a value — only the opaque
    # `mvm-secret-…` placeholder (claim 13); the host substitutes the real
    # credential at egress. We decode + export each so an SDK-free workload reads
    # `$VAR`. Absent token ⇒ no-op (no-secret guests boot byte-identically).
    #
    # We redirect a tmpfs file into the `while` (NOT a `... | while` pipe), so the
    # `export`s land in THIS shell — a pipe would run the loop in a subshell and
    # the env would never reach the entrypoint.
    MVM_SECRET_ENV_HEX=$(/bin/busybox sed -n 's/.*\bmvm\.secret_env=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$MVM_SECRET_ENV_HEX" ]; then
      /bin/busybox mkdir -p /run/mvm
      printf '%b' "$(echo "$MVM_SECRET_ENV_HEX" | /bin/busybox sed 's/../\\x&/g')" \
        > /run/mvm/secret-env
      while IFS= read -r mvm_kv; do
        [ -n "$mvm_kv" ] || continue
        mvm_k=''${mvm_kv%%=*}
        mvm_v=''${mvm_kv#*=}
        # Reject a non-identifier name so a malformed token can't smuggle a shell
        # construct into `export`.
        case "$mvm_k" in
          ""|*[!A-Za-z0-9_]*) echo "mvm-init: skipping malformed secret env name"; continue ;;
        esac
        export "$mvm_k=$mvm_v"
      done < /run/mvm/secret-env
      /bin/busybox rm -f /run/mvm/secret-env
      echo "mvm-init: injected per-run secret placeholder env"
    fi

    # Stage 2.475 — provision the per-run verb-grant inputs.
    #
    # The launcher writes `mvm.verb_grant=<base64(JSON)>` onto the kernel
    # cmdline — base64 rather than the hex used by stages 2.46/2.47 because this
    # envelope is the largest thing on the cmdline and the kernel silently drops
    # whatever runs past COMMAND_LINE_SIZE. We decode the JSON blob
    # to `/run/mvm/verb-grant.json` (tmpfs, mode 0644). The host-signer public
    # key lands in the same tmpfs so the agent verifies the grant against an
    # out-of-band key: from the read-only config drive when one is attached,
    # otherwise from the cmdline. A vsock-only guest has no config drive, so
    # there the cmdline is the only carrier — without this the agent finds no
    # key, refuses every control RPC, and the host's readiness probe times out.
    # The host-signer anchor is provisioned UNCONDITIONALLY, not only when a
    # verb grant is present. It is host *identity*, while a grant is workload
    # *authority* -- the host ships it ungated for exactly this reason (see
    # `host_signer_pub_cmdline_token`), and the egress client needs it to pin
    # the host on a run that carries no grant at all. Nesting it inside the
    # grant check meant a grant-less run had no anchor and no egress.
    /bin/busybox mkdir -p /run/mvm
    if [ -r /mnt/config/host-signer.pub ]; then
      /bin/busybox cp /mnt/config/host-signer.pub /run/mvm/host-signer.pub
      /bin/busybox chmod 0644 /run/mvm/host-signer.pub
    else
      # The agent accepts the raw 32 bytes or this 64-char hex form.
      MVM_HOST_SIGNER_PUB_HEX=$(/bin/busybox sed -n 's/.*\bmvm\.host_signer_pub=\([^ ]*\).*/\1/p' /proc/cmdline)
      if [ -n "$MVM_HOST_SIGNER_PUB_HEX" ]; then
        printf '%s' "$MVM_HOST_SIGNER_PUB_HEX" > /run/mvm/host-signer.pub
        /bin/busybox chmod 0644 /run/mvm/host-signer.pub
      fi
    fi

    MVM_VERB_GRANT_B64=$(/bin/busybox sed -n 's/.*\bmvm\.verb_grant=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$MVM_VERB_GRANT_B64" ]; then
      printf '%s' "$MVM_VERB_GRANT_B64" | /bin/busybox base64 -d \
        > /run/mvm/verb-grant.json
      /bin/busybox chmod 0644 /run/mvm/verb-grant.json
      echo "mvm-init: provisioned verb-grant"
    fi

    # The per-boot FlowMux identity is NOT provisioned here. The host attaches
    # it as a small read-only ext4 drive labelled `mvm-identity`, and
    # `mvm-egress-client` mounts it itself before loading its keys -- one
    # implementation, in Rust, shared by every guest tier. Doing it here too
    # would mean a second copy of the superblock-label probe written in shell,
    # against busybox applets this image does not otherwise use.

    # Stage 2.476 — declared runtime-source policy. The host carries
    # the per-boot runtime contract on the kernel cmdline; when
    # omitted we keep the historical preferred-overlay compatibility
    # behavior. Resolved here, ahead of Stage 2.48, so the addon-DNS
    # activation ladder below can share the same policy gate as
    # netinit / egress-client / agent further down.
    MVM_RUNTIME_SOURCE_POLICY=$(/bin/busybox sed -n 's/.*\bmvm\.runtime_source_policy=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -z "$MVM_RUNTIME_SOURCE_POLICY" ]; then
      MVM_RUNTIME_SOURCE_POLICY=prefer_overlay
    fi

    # Stage 2.477 — runtime overlay mount for non-verity boots. A sealed
    # (verity) boot has its initramfs mount the runtime overlay at
    # /mvm/runtime before switch_root; a plain dev boot has no initramfs, so
    # the overlay rides a read-only virtio-blk device the host names on the
    # kernel cmdline as `mvm.runtime_data=/dev/vdN`. Mount it here — before the
    # addon-dns / netinit / egress-client / agent ladders below resolve any
    # /mvm/runtime/<bin> — but only when /mvm/runtime is not already a
    # mountpoint, so a verity boot that already mounted it is left untouched.
    # Absent token ⇒ legacy boot; /mvm/runtime stays as baked. Non-fatal.
    MVM_RUNTIME_DATA_DEV=$(/bin/busybox sed -n 's/.*\bmvm\.runtime_data=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$MVM_RUNTIME_DATA_DEV" ] \
      && ! /bin/busybox grep -q ' /mvm/runtime ' /proc/mounts 2>/dev/null; then
      if /bin/busybox mount -t ext4 -o ro "$MVM_RUNTIME_DATA_DEV" /mvm/runtime 2>/dev/null; then
        echo "mvm-init: mounted runtime overlay $MVM_RUNTIME_DATA_DEV at /mvm/runtime (ro)"
      else
        echo "mvm-init: warn: could not mount runtime overlay $MVM_RUNTIME_DATA_DEV at /mvm/runtime"
      fi
    fi

    # Stage 2.478 — optional SDK sidecar mount. The glibc host-services cdylib
    # the language SDKs dlopen is not in this rootfs and not in the runtime
    # overlay, so a workload that was admitted to call a host service gets it as
    # its own read-only virtio-blk device. The host names that device on the
    # cmdline as `mvm.sdk_dev=/dev/vdN`: the slot depends on whether this boot
    # carries verity, a runtime overlay, and how many user volumes precede it, so
    # the guest cannot derive it. Absent token => this workload binds no
    # SDK-served host service and /mvm/sdk stays empty.
    #
    # `noexec` is deliberately NOT set: the workload process maps the cdylib
    # executable via dlopen. `nosuid,nodev` still hold, and the device is
    # read-only at the hypervisor level as well as at the mount.
    MVM_SDK_DEV=$(/bin/busybox sed -n 's/.*\bmvm\.sdk_dev=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$MVM_SDK_DEV" ] \
      && ! /bin/busybox grep -q ' /mvm/sdk ' /proc/mounts 2>/dev/null; then
      if /bin/busybox mount -t ext4 -o ro,nosuid,nodev "$MVM_SDK_DEV" /mvm/sdk 2>/dev/null; then
        echo "mvm-init: mounted SDK sidecar $MVM_SDK_DEV at /mvm/sdk (ro)"
      else
        echo "mvm-init: warn: could not mount SDK sidecar $MVM_SDK_DEV at /mvm/sdk"
      fi
    fi

    # Stage 2.48 — local addon DNS bootstrap.
    #
    # The "always-install + no-op when zone empty" pattern from
    # `specs/contracts/local-addon-dns.md`: the addon DNS binary rides
    # the runtime overlay at /mvm/runtime/addon-dns (resolved via the
    # same ladder netinit/egress-client/agent use below), and is only
    # activated when a zone file was baked at
    # /etc/mvm/addon_dns_zone.json (via mkGuest's `extraFiles`) or
    # staged on the config-disk path before init runs. Guests without
    # addons skip this block entirely, so /etc/resolv.conf stays
    # byte-for-byte the build-time default.
    #
    # When activated, we:
    #   1. Copy the zone file into /run/mvm so reloads (SIGHUP) and
    #      runtime-only edits land on tmpfs, not in the read-only
    #      rootfs.
    #   2. Snapshot the existing /etc/resolv.conf into
    #      /run/mvm/upstream-resolv.conf BEFORE rewriting it. The
    #      addon DNS server reads this file to seed its upstream
    #      forwarders; without the snapshot, the binary would either
    #      have no upstream or (worse) recurse into itself once
    #      resolv.conf points at 127.0.0.1.
    #   3. Write a new resolv.conf into /run/mvm and bind-mount it
    #      over /etc/resolv.conf. Single-file bind-mounts survive the
    #      read-only /etc bind that will eventually land
    #      so this works on both dev and hardened images.
    #   4. Resolve the binary from the overlay-resident
    #      /mvm/runtime/addon-dns (required-overlay boots fail closed
    #      if it is absent) — then fork it under setpriv
    #      to the agent uid with CAP_NET_BIND_SERVICE preserved via
    #      ambient + inheritable caps so it can bind UDP/53 on
    #      loopback only. The server validates loopback +
    #      self-upstream constraints itself; we do not pass any
    #      other privilege.
    MVM_ADDON_DNS_ZONE_SRC=
    if [ -r /run/mvm/addon_dns_zone.json ]; then
      MVM_ADDON_DNS_ZONE_SRC=/run/mvm/addon_dns_zone.json
    elif [ -r /etc/mvm/addon_dns_zone.json ]; then
      MVM_ADDON_DNS_ZONE_SRC=/etc/mvm/addon_dns_zone.json
    fi
    MVM_ADDON_DNS_BIN=
    if [ "$MVM_RUNTIME_SOURCE_POLICY" = rootfs_only ]; then
      if [ -x /usr/local/bin/mvm-addon-dns ]; then
        MVM_ADDON_DNS_BIN=/usr/local/bin/mvm-addon-dns
      fi
    elif [ -x /mvm/runtime/addon-dns ]; then
      MVM_ADDON_DNS_BIN=/mvm/runtime/addon-dns
    elif [ "$MVM_RUNTIME_SOURCE_POLICY" = required_overlay ]; then
      echo "mvm-init: runtime overlay required but /mvm/runtime/addon-dns is missing"
      exit 1
    elif [ -x /usr/local/bin/mvm-addon-dns ]; then
      MVM_ADDON_DNS_BIN=/usr/local/bin/mvm-addon-dns
    fi
    if [ -n "$MVM_ADDON_DNS_ZONE_SRC" ] && [ -n "$MVM_ADDON_DNS_BIN" ]; then
      /bin/busybox mkdir -p /run/mvm
      /bin/busybox chmod 0755 /run/mvm
      if [ "$MVM_ADDON_DNS_ZONE_SRC" != /run/mvm/addon_dns_zone.json ]; then
        /bin/busybox cp "$MVM_ADDON_DNS_ZONE_SRC" /run/mvm/addon_dns_zone.json
      fi
      /bin/busybox chmod 0644 /run/mvm/addon_dns_zone.json

      # Snapshot the pre-rewrite resolver chain so addon-dns can
      # forward non-configured names without recursing into itself.
      if [ -r /etc/resolv.conf ]; then
        /bin/busybox cp /etc/resolv.conf /run/mvm/upstream-resolv.conf
      else
       : > /run/mvm/upstream-resolv.conf
      fi
      /bin/busybox chmod 0644 /run/mvm/upstream-resolv.conf

      # Build the new resolv.conf in /run (tmpfs, always writable)
      # and bind-mount it over /etc/resolv.conf. The:: literal is
      # written via printf so the heredoc body stays parameter-free.
      printf 'nameserver 127.0.0.1\nnameserver ::1\n' > /run/mvm/resolv.conf
      /bin/busybox chmod 0644 /run/mvm/resolv.conf
      /bin/busybox mount --bind /run/mvm/resolv.conf /etc/resolv.conf

      /bin/busybox setsid ${setpriv} \
        --reuid=${toString agentUid} --regid=${toString agentUid} \
        --clear-groups --no-new-privs \
        --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
        -- "$MVM_ADDON_DNS_BIN" &
    fi

    # Stage 2.55 — decode the vsock-egress opt-in. Backends that route outbound
    # egress through the host vsock gate set `mvm.vsock_egress=1` on the kernel
    # cmdline; export the env var Stage 2.6 keys on. Mirrors the mvm.secret_env
    # / mvm.verb_grant cmdline parsers above. Absent token ⇒ no-op.
    MVM_VSOCK_EGRESS=
    if /bin/busybox grep -qE ' mvm\.vsock_egress=1( |$)' /proc/cmdline 2>/dev/null; then
      export MVM_VSOCK_EGRESS=1
    fi

    # Stage 2.56 — guest-side netinit. MVM_RUNTIME_SOURCE_POLICY was
    # resolved earlier (ahead of the addon-DNS block, which needs it
    # too); this is its first overlay-preferred / rootfs-only ladder.
    MVM_NETINIT_BIN=
    if [ "$MVM_RUNTIME_SOURCE_POLICY" = rootfs_only ]; then
      if [ -x /usr/local/bin/mvm-guest-netinit ]; then
        MVM_NETINIT_BIN=/usr/local/bin/mvm-guest-netinit
      fi
    elif [ -x /mvm/runtime/netinit ]; then
      MVM_NETINIT_BIN=/mvm/runtime/netinit
    elif [ "$MVM_RUNTIME_SOURCE_POLICY" = required_overlay ]; then
      echo "mvm-init: runtime overlay required but /mvm/runtime/netinit is missing"
      exit 1
    elif [ -x /usr/local/bin/mvm-guest-netinit ]; then
      MVM_NETINIT_BIN=/usr/local/bin/mvm-guest-netinit
    fi
    if [ -n "$MVM_NETINIT_BIN" ]; then
      "$MVM_NETINIT_BIN" || echo "mvm-init: netinit exited nonzero; continuing without guest-side defense"
    fi

    # Stage 2.6 — vsock egress shim. Prefer the overlay-resident helper on
    # overlay-backed boots; keep the baked rootfs fallback only on
    # prefer-overlay / rootfs-only paths. On required-overlay boots, a
    # requested egress shim must come from /mvm/runtime.
    MVM_EGRESS_CLIENT_BIN=
    if [ "$MVM_RUNTIME_SOURCE_POLICY" = rootfs_only ]; then
      if [ -x /usr/local/bin/mvm-egress-client ]; then
        MVM_EGRESS_CLIENT_BIN=/usr/local/bin/mvm-egress-client
      fi
    elif [ -x /mvm/runtime/egress-client ]; then
      MVM_EGRESS_CLIENT_BIN=/mvm/runtime/egress-client
    elif [ "$MVM_RUNTIME_SOURCE_POLICY" = required_overlay ] && [ -n "''${MVM_VSOCK_EGRESS:-}" ]; then
      echo "mvm-init: runtime overlay required but /mvm/runtime/egress-client is missing"
      exit 1
    elif [ -x /usr/local/bin/mvm-egress-client ]; then
      MVM_EGRESS_CLIENT_BIN=/usr/local/bin/mvm-egress-client
    fi
    if [ -n "''${MVM_VSOCK_EGRESS:-}" ] && [ -n "$MVM_EGRESS_CLIENT_BIN" ]; then
      /bin/busybox ip addr replace 127.0.0.1/8 dev lo 2>/dev/null || true
      /bin/busybox ip link set lo up 2>/dev/null || true
      /bin/busybox mkdir -p /run/mvm
      printf 'nameserver 127.0.0.1\n' > /run/mvm/resolv.conf
      /bin/busybox chmod 0644 /run/mvm/resolv.conf
      if [ -e /etc/resolv.conf ]; then
        /bin/busybox mount --bind /run/mvm/resolv.conf /etc/resolv.conf \
          || /bin/busybox cp /run/mvm/resolv.conf /etc/resolv.conf
      else
        /bin/busybox cp /run/mvm/resolv.conf /etc/resolv.conf
      fi
      /bin/busybox setsid ${setpriv} \
        --reuid=${toString agentUid} --regid=${toString agentUid} \
        --clear-groups --no-new-privs \
        --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
        -- "$MVM_EGRESS_CLIENT_BIN" &
      export ALL_PROXY="socks5h://127.0.0.1:1080"
      export HTTP_PROXY="$ALL_PROXY"
      export HTTPS_PROXY="$ALL_PROXY"
      export http_proxy="$ALL_PROXY"
      export https_proxy="$ALL_PROXY"
    fi

    # Stage 2.5 — guest agent supervisor. Fork the agent into
    # the background under its own uid before we drop to the
    # entrypoint. The agent is responsible for vsock RPC (host
    # tool calls, lifecycle hooks); without it, the host can boot
    # us but can't talk to us. We never block on it — if the agent
    # fails to start, the entrypoint still runs and the lack of
    # agent shows up in `mvmctl status`.
    #
    # The agent rides the runtime overlay: on a verity boot
    # `mvm-verity-init` bind-mounts it at /mvm/runtime before
    # switch_root, and on a non-verity boot the overlay is mounted
    # there directly, so /mvm/runtime/agent is the canonical binary
    # location. mkGuest no longer bakes a /usr/local/bin fallback, so ANY
    # boot fails closed when no agent can be resolved (the guard after the
    # ladder) — a half-attached overlay never boots agent-less silently,
    # regardless of policy. The rootfs_only / prefer-overlay
    # /usr/local/bin lookups below are inert for current mkGuest output
    # (nothing is baked); they matter only if a future non-lean image
    # reintroduces a baked agent.
    MVM_VARIANT=$(/bin/busybox cat /etc/mvm/variant 2>/dev/null || echo prod)
    MVM_AGENT_BIN=
    if [ "$MVM_RUNTIME_SOURCE_POLICY" = rootfs_only ]; then
      if [ -x /usr/local/bin/mvm-guest-agent ]; then
        MVM_AGENT_BIN=/usr/local/bin/mvm-guest-agent
      fi
    elif [ -x /mvm/runtime/agent ]; then
      MVM_AGENT_BIN=/mvm/runtime/agent
    elif [ "$MVM_RUNTIME_SOURCE_POLICY" = required_overlay ]; then
      echo "mvm-init: runtime overlay required but no matching /mvm/runtime agent is present"
      exit 1
    elif [ -x /usr/local/bin/mvm-guest-agent ]; then
      MVM_AGENT_BIN=/usr/local/bin/mvm-guest-agent
    fi
    if [ -z "$MVM_AGENT_BIN" ]; then
      # Fail closed regardless of policy. Every mkGuest /init boot needs the
      # agent, so an empty resolution means the overlay is missing or
      # half-attached (or a future non-lean shape lost its baked agent).
      # Booting on would leave vsock 5252 unbound and the control plane
      # silently dead — refuse instead.
      echo "mvm-init: no guest agent resolved from /mvm/runtime and no baked fallback"
      exit 1
    fi
    # Static-musl mvm-setpriv — the helper applies the uid/gid, group, and
    # no-new-privileges drop before the agent exec. Without this step the
    # agent never forks and vsock port 5252 stays unbound.
    /bin/busybox setsid ${setpriv} \
      --reuid=${toString agentUid} --regid=${toString agentUid} \
      --clear-groups --securebits=keep-caps \
      --inh-caps=+kill --ambient-caps=+kill \
      --inh-caps=+sys_time --ambient-caps=+sys_time --no-new-privs \
      -- "$MVM_AGENT_BIN" &

    # Stage 3 — hostname + console. /dev/console is what the
    # hypervisor wires our virtio-console to; in dev mode we keep
    # stdio attached to it so `mvmctl console` sees output.
    /bin/busybox hostname "$(/bin/busybox cat /etc/mvm/name 2>/dev/null || echo mvm)"

    # Stage 4 — exec the entrypoint. /etc/mvm/variant (dev|prod) +
    # /etc/mvm/entrypoint are baked at build time. dev variant gets
    # stdio re-attached to /dev/console so the user can interact;
    # prod variant lets the entrypoint inherit whatever the hypervisor
    # provided (typically the same console, but the variant marker
    # is the host-side gate).
    if [ -e /etc/mvm/variant ] && [ "$(/bin/busybox cat /etc/mvm/variant)" = "dev" ]; then
      exec </dev/console >/dev/console 2>&1
      # The dev VM is long-lived, so PID 1 idles here instead of
      # running the /etc/mvm/entrypoint `/bin/sh` on /dev/console. The guest
      # agent (forked above) serves the interactive shell over vsock — it
      # openpty()s and forks its OWN `/bin/sh -i` (mvm-agentd::console),
      # independent of PID 1 — so PID 1 doesn't need to be a shell at all.
      # Running `/bin/sh` on /dev/console here is fatal wherever the serial
      # console is input-less — which is every backend that captures the
      # guest console write-only, with no host input fd: the read hits EOF,
      # the shell exits, PID 1 dies, and the VM powers off ~5 s after boot.
      # On libkrun this just swaps a blocking console read for an explicit
      # idle — same "stay alive", no change to the agent shell path. A
      # busybox-portable loop avoids depending on `sleep infinity`.
      while :; do /bin/busybox sleep 2147483647; done
    fi

    # Stage 4.5 — mvm runtime overlay env.
    # When the overlay is mounted (verity boot path), surface its
    # presence + SDK-library paths to the entrypoint via env
    # variables. Per-language path vars (PYTHONPATH, NODE_PATH)
    # are prepended so they take precedence over a user's existing
    # value; an empty existing value leaves no trailing colon.
    # Setting these unconditionally on the overlay-mounted path
    # gives a stable contract for SDK addons (vsock hooks)
    # without per-image opt-in. The dev/legacy path (no overlay)
    # leaves the env untouched so existing flakes keep their
    # current behaviour.
    if [ -d /mvm/runtime ] && [ -e /mvm/runtime/VERSION ]; then
      export MVM_RUNTIME_OVERLAY=1
      if [ -d /mvm/runtime/sdk-py ]; then
        export PYTHONPATH="/mvm/runtime/sdk-py''${PYTHONPATH:+:''${PYTHONPATH}}"
      fi
      if [ -d /mvm/runtime/sdk-ts ]; then
        export NODE_PATH="/mvm/runtime/sdk-ts''${NODE_PATH:+:''${NODE_PATH}}"
      fi
    fi

    # Source the PID 1 boot command. Rendered at build time so the
    # exec line below is final — no shell injection from runtime config.
    # `/etc/mvm/boot` (mode 0500) is the agent-dispatched-workload split:
    # when present it is PID 1's command and `/etc/mvm/entrypoint` is left
    # as the agent's per-call marker. Absent it, /etc/mvm/entrypoint is
    # both (the legacy single-file path).
    MVM_BOOT=/etc/mvm/entrypoint
    [ -e /etc/mvm/boot ] && MVM_BOOT=/etc/mvm/boot
    # Run the workload as a child (setprivWrap no longer execs) so PID 1
    # can capture its exit code. Persistent services exec `sleep infinity`
    # inside and never return here.
    # Detach the workload's stdin from the input-less serial console: a
    # write-only console hands the guest an immediate EOF, which crashes a
    # workload that reads stdin shortly after boot. /dev/null is the correct
    # stdin for a non-interactive sealed workload; stdout/stderr stay on the
    # console for capture, and the exit-code capture below is unaffected.
    . "$MVM_BOOT" </dev/null
    MVM_CODE=$?
    # Report the exit code to the host (best-effort), then power off —
    # never reboot. The host reads it from the control vsock port.
    # Resolve the binary the same overlay-preferred / rootfs-only way
    # as netinit/egress-client/agent above: prefer the overlay-resident
    # /mvm/runtime/exit-report; a required-overlay boot fails closed if
    # it is absent.
    MVM_EXIT_REPORT_BIN=
    if [ "$MVM_RUNTIME_SOURCE_POLICY" = rootfs_only ]; then
      if [ -x /usr/local/bin/mvm-exit-report ]; then
        MVM_EXIT_REPORT_BIN=/usr/local/bin/mvm-exit-report
      fi
    elif [ -x /mvm/runtime/exit-report ]; then
      MVM_EXIT_REPORT_BIN=/mvm/runtime/exit-report
    elif [ "$MVM_RUNTIME_SOURCE_POLICY" = required_overlay ]; then
      echo "mvm-init: runtime overlay required but /mvm/runtime/exit-report is missing"
      exit 1
    elif [ -x /usr/local/bin/mvm-exit-report ]; then
      MVM_EXIT_REPORT_BIN=/usr/local/bin/mvm-exit-report
    fi
    if [ -n "$MVM_EXIT_REPORT_BIN" ]; then
      "$MVM_EXIT_REPORT_BIN" "$MVM_CODE" || \
        echo "mvm: exit-report failed (code=$MVM_CODE); powering off anyway"
    else
      echo "mvm: exit-report binary missing (code=$MVM_CODE); powering off anyway"
    fi
    /bin/busybox sync
    /bin/busybox poweroff -f
  '';

  # The kernel exec()s /init directly, so `#!` must be the first two bytes of
  # the file: shift them by even one column and the boot dies with ENOEXEC
  # before any userspace runs, leaving a kernel panic as the only symptom.
  # Nix derives an indented string's baseline from its least-indented line, so
  # one under-indented line anywhere in the block above silently moves every
  # other line — including the shebang — one column right. Assert the rendered
  # bytes instead of trusting the indentation to stay uniform.
  initScript =
    lib.throwIf (!lib.hasPrefix "#!/bin/sh\n" initText) ''
      mkGuest: the rendered /init does not start with the "#!/bin/sh" shebang.
      The kernel exec()s /init and will panic with ENOEXEC. This almost always
      means a line inside the /init block of nix/lib/mk-guest.nix is indented
      less than its neighbours, which moves the whole script one or more
      columns right. Re-align that line.
    '' (pkgs.writeScript "mvm-init" initText);

  # Render the entrypoint as a shell-sourced fragment. /init does
  # `. /etc/mvm/entrypoint`, so this is just a script.
  entrypointFile = pkgs.writeText "mvm-entrypoint" ''
    #!/bin/sh
    # Auto-generated by mkGuest at build time. Do not edit.
    ${entrypointCmd}
  '';

  # PID 1 boot command, rendered to `/etc/mvm/boot` (sourced by /init
  # in preference to /etc/mvm/entrypoint). Only emitted when the caller
  # passes `bootCommand` — see that arg's doc. Same setpriv wrap as the
  # entrypoint so PID 1 drops to the entrypoint uid (a no-op at uid 0).
  bootFile =
    if bootCommand == null then null
    else pkgs.writeText "mvm-boot" ''
      #!/bin/sh
      # Auto-generated by mkGuest at build time. Do not edit.
      ${setprivWrap entrypointUid (renderCommand bootCommand)}
    '';

  # A caller that hands us a `bootCommand` has split PID 1 (idle) from
  # the agent's per-call marker, so it MUST supply that marker itself via
  # extraFiles — otherwise /etc/mvm/entrypoint would be absent and the
  # agent's RunEntrypoint would have nothing to dispatch.
  _bootContract =
    if bootCommand != null && !(extraFiles ? "/etc/mvm/entrypoint")
    then throw ''
      mkGuest: `bootCommand` is set but `extraFiles` does not provide
      "/etc/mvm/entrypoint" (the guest agent's per-call marker, ADR-005).
      The function-service factory must bake it.
    ''
    else true;

  # Variant marker (dev|prod). In-guest source of truth — paired
  # with passthru.mvm.{accessible,sealed} on the derivation.
  variantFile = pkgs.writeText "mvm-variant" (
    if isDev then "dev\n" else "prod\n"
  );

  nameFile = pkgs.writeText "mvm-name" "${name}\n";

  # Verb-trust policy — baked into sealed images only (`isSealed`).
  # Present on every image. Sealed images fail closed because control RPCs
  # require a launch-provisioned grant; DevOnly verbs are additionally gated
  # by the runtime profile.
  verbTrustFile = pkgs.writeText "mvm-verb-trust"
    ''{"version":1,"require_grant":true,"grant_key_source":"launch_provisioned"}'';

  # Side-binaries from the guest-agent derivation. The agent, netinit,
  # addon-dns, exit-report, and egress-client the guest execs at boot now
  # come exclusively from the mounted runtime overlay at `/mvm/runtime`, so
  # mkGuest no longer bakes them into the rootfs. These two are still needed
  # off the overlay path: `mvm-seccomp-apply` on the per-service launch line,
  # and `mvm-verity-init` as PID 1 of the verity initramfs.
  #
  # `mvm-seccomp-apply` ships in the same Cargo workspace member and
  # derivation as the agent. The per-service launch line in
  # `mkServiceBlock` execs it via setpriv to apply the tier's seccomp
  # filter before handing control to the workload.
  seccompApplyBinary = "${guestAgentPkg}/bin/mvm-seccomp-apply";

  # `mvm-verity-init` is the PID 1 of the verity initramfs.
  # Baked into the verity-initrd cpio.gz, not into the rootfs
  # directly — wired here as a passthru export so the initramfs
  # builder can reach it without duplicating the agent derivation.
  verityInitBinary = "${guestAgentPkg}/bin/mvm-verity-init";

  mvmAuditProbeBinary = "${auditProbePkg}/bin/audit-probe";

  # extraFiles — three accepted spec shapes per target path:
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
  # Binary-source variants exist so the builder-vm flake can
  # install `mvm-host-vm-init` at `/sbin/mvm-host-vm-init` without
  # inlining its bytes as a string (`writeText` is text-only).
  extraFilePopulation = lib.concatMapStringsSep "\n"
    (path:
      let
        rawSpec = extraFiles.${path};
        spec =
          if builtins.isString rawSpec then { source = rawSpec; }
          else rawSpec;
        hasContent = spec ? content;
        hasSource = spec ? source;
        mode =
          if spec ? mode then spec.mode
          else if hasSource then "0755"
          else "0644";
        src =
          if hasContent then
            pkgs.writeText "extra-${builtins.hashString "sha256" path}" spec.content
          else if hasSource then
            spec.source
          else
            throw "mkGuest: extraFiles[${path}] must set either `content` (text) or `source` (file path)";
      in
      # Path arrives from Nix-interpolated keys (no shell escaping
      # needed); inline via `"$out${path}"` rather than via
      # `lib.escapeShellArg` so the shell expands `$out` instead of
      # treating it as a literal in single quotes.
      ''
        mkdir -p "$out$(dirname ${lib.escapeShellArg path})"
        ${pkgs.coreutils}/bin/install -m ${mode} \
          ${src} \
          "$out${path}"
      ''
    )
    (lib.attrNames extraFiles);

  # ── Rootfs tree population ────────────────────────────────────
  #
  # We construct the rootfs as a real directory tree (not a NixOS
  # closure) so the boot path is a flat ext4. Every binary the
  # /init script touches resolves through /bin/* symlinks pointing
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
    # alongside `/work`) — `/init` mounts `--volume` shares here and can't
    # mkdir on the ro rootfs either.
    mkdir -p "$out"/{bin,sbin,etc,proc,sys,dev,tmp,run,var,root,home,nix/store,nix-store,etc/mvm,job,out,work,mvm-bins,closure-seed,mnt,data}
    chmod 1777 "$out/tmp"
    chmod 0755 "$out/run"

    cp ${rootfsClosureInfo}/registration "$out/nix-path-registration"
    chmod 0444 "$out/nix-path-registration"

    # The mvm runtime overlay is
    # bind-mounted at /mvm/runtime by `mvm-verity-init` before
    # switch_root. The directory must exist in the rootfs so the
    # bind-mount has a target. Mode 0755 (owner root); the overlay
    # itself is mounted read-only over it, so contents can't be
    # written by the guest regardless. Outside the verity-boot
    # path (dev-mode VMs that don't run `mvm-verity-init`) the
    # directory is empty — /init below falls back to the baked-in
    # agent. `/mvm/` is reserved (an admission-time check
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
    cp ${setprivPkg}/bin/mvm-setpriv "$out/bin/mvm-setpriv"
    chmod 0755 "$out/bin/mvm-setpriv"
    # /sbin/init is what the kernel actually execs at boot (when
    # there's no init=/init kernel param). We point both at our
    # custom init script so either path works.
    cp ${initScript} "$out/init"
    ${pkgs.gnused}/bin/sed -i '1s/^ *//' "$out/init"
    chmod 0500 "$out/init"
    ln -sf /init "$out/sbin/init"

    # mvm metadata. The PID 1 boot command is the load-bearing file —
    # /init sources it. Mode 0500 so non-root processes in the guest
    # can't read or replace it (a later layer makes /etc read-only as well).
    # When `bootCommand` is set it lands at /etc/mvm/boot and the caller's
    # extraFiles owns /etc/mvm/entrypoint (the agent marker); otherwise
    # the rendered entrypoint is both. `_bootContract` is forced here so
    # the misconfig throws at build time, not at boot.
    ${builtins.seq _bootContract (
      if bootCommand == null then ''
        cp ${entrypointFile} "$out/etc/mvm/entrypoint"
        chmod 0500 "$out/etc/mvm/entrypoint"
      '' else ''
        cp ${bootFile} "$out/etc/mvm/boot"
        chmod 0500 "$out/etc/mvm/boot"
      ''
    )}
    cp ${variantFile} "$out/etc/mvm/variant"
    chmod 0444 "$out/etc/mvm/variant"
    cp ${nameFile} "$out/etc/mvm/name"
    chmod 0444 "$out/etc/mvm/name"

    # Verb-trust policy — sealed images only. Absent on dev images so the
    # agent falls back to class-only gating (no file = permissive default
    # for interactive dev shells). Mode 0444: guest reads it at startup;
    # the dm-verity seal prevents any runtime modification.
    ${if isSealed then ''
      cp ${verbTrustFile} "$out/etc/mvm/verb-trust.json"
      chmod 0444 "$out/etc/mvm/verb-trust.json"
    '' else ""}

    # /etc/passwd + /etc/group provision root (mandatory for PID 1)
    # plus the agent + entrypoint uids resolved at build time.
    # These become read-only via bind-mount once the security
    # overlay lands; for now they're plain mode 0644.
    #
    # When entrypoint uid happens to be 0 (dev-mode default), the
    # entry collapses to the root row — guarded against the
    # duplicate by skipping the second cat. Same for the agent
    # uid in the unlikely override case.
    cat > "$out/etc/passwd" <<EOF
    root:x:0:0:root:/root:/bin/sh
    EOF
    if [ "${toString agentUid}" != "0" ]; then
      printf 'mvm-agent:x:${toString agentUid}:${toString agentUid}:mvm guest agent:/var/empty:/bin/false\n' >> "$out/etc/passwd"
    fi
    if [ "${toString entrypointUid}" != "0" ] && [ "${toString entrypointUid}" != "${toString agentUid}" ]; then
      printf 'mvm-worker:x:${toString entrypointUid}:${toString entrypointUid}:mvm workload:/home/mvm-worker:/bin/sh\n' >> "$out/etc/passwd"
      mkdir -p "$out/home/mvm-worker"
      chmod 0755 "$out/home/mvm-worker"
    fi
    ${lib.optionalString (builderUid != null && builderUid != 0 && builderUid != agentUid && builderUid != entrypointUid) ''
      printf 'mvm-builder:x:${toString builderUid}:${toString builderUid}:mvm build worker:/tmp:/bin/sh\n' >> "$out/etc/passwd"
    ''}
    chmod 0644 "$out/etc/passwd"

    cat > "$out/etc/group" <<EOF
    root:x:0:
    EOF
    if [ "${toString agentUid}" != "0" ]; then
      printf 'mvm-agent:x:${toString agentUid}:\n' >> "$out/etc/group"
    fi
    if [ "${toString entrypointUid}" != "0" ] && [ "${toString entrypointUid}" != "${toString agentUid}" ]; then
      printf 'mvm-worker:x:${toString entrypointUid}:\n' >> "$out/etc/group"
    fi
    ${lib.optionalString (builderUid != null && builderUid != 0 && builderUid != agentUid && builderUid != entrypointUid) ''
      printf 'mvm-builder:x:${toString builderUid}:\n' >> "$out/etc/group"
    ''}
    chmod 0644 "$out/etc/group"

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
    # /mvm/runtime; see the resolution ladders in initScript.
    mkdir -p "$out/usr/local/bin"

    # In-guest host.audit.v1 driver — test fixture, baked only when the
    # caller opts in. The production guest closure never carries it.
    ${if withAuditProbe then ''
      cp ${mvmAuditProbeBinary} "$out/usr/local/bin/audit-probe"
      chmod 0555 "$out/usr/local/bin/audit-probe"
    '' else ""}

    # Kernel modules. `/init` `modprobe`s vsock before forking the
    # agent (default nixpkgs kernel ships AF_VSOCK as `=m`); without
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
        candidates =
          (if kernel ? modules then [ kernel.modules ] else [ ])
          ++ [ kernel ];
        candidateRefs = lib.concatMapStringsSep " " (c: ''"${c}"'') candidates;
      in ''
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
      (pkg:
        let binOut = lib.getBin pkg; in ''
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
      '')
      (builtins.seq assertNoSshTemplateInputs packages)}
  '';

  # Package the tree as an ext4 image. nixpkgs ships a make-ext4-fs
  # derivation that handles the mkfs + populate dance correctly.
  # All arguments arrive in a single set via callPackage's auto-arg
  # injection. Reference make-ext4-fs.nix via the flake input
  # (`${nixpkgs}/...`) rather than the angle-bracket form (`<nixpkgs/...>`)
  # — the latter trips flake pure evaluation ("cannot look up
  # '<nixpkgs/...>' in pure evaluation mode").
  rootfsImageWithGrowthReserve = pkgs.callPackage "${nixpkgs}/nixos/lib/make-ext4-fs.nix" {
    storePaths = [ rootfsTree ];
    volumeLabel = "mvm-${name}";
    populateImageCommands = ''
      cp -a --reflink=auto ${rootfsTree}/. ./files/
      # `rootfsTree` deliberately makes the registration read-only for the
      # runtime image. The image builder copies that mode into its staging
      # tree, then rewrites the same file while assembling the closure. Leave
      # it out of the generic file copy so the closure manifest can create a
      # fresh staging file with normal build-user permissions.
      chmod -R u+w ./files
      rm -f ./files/nix-path-registration
    '';
  };

  # The generic image builder expands its minimum-sized filesystem by 16 MiB
  # so mutable images have room to grow before their first boot. mkGuest mounts
  # its rootfs read-only and puts mutable directories on tmpfs, so that reserve
  # can never be used.
  rootfsImage = pkgs.runCommand "mvm-rootfs-${name}.ext4"
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
    # What PID 1 execs, as argv. The host cannot read inside a materialized
    # ext4, so this is where admission learns what a workload runs — and the
    # only reason it can refuse to hand a shell-shaped entrypoint a stdin
    # writer.
    inherit entrypointArgv;
    # True iff this image wires the dev console transport. The agent artifact
    # itself is universal; mvmctl and admission use this image fact only for
    # transport setup and user-facing access checks.
    withInteractive = withInteractive;
    initSystem = "busybox";
    # Single 300ms boot-budget floor across
    # every backend. Custom /init + trimmed kernel + direct vmlinux
    # boot are the levers that keep us under it. A backend that can't
    # hit the floor is a backend we drop.
    expectedBootMs = 300;
    # Privilege model — the resolved uids `setpriv` drops to before
    # exec. PID 1 is uid 0 (kernel requirement); these are the
    # workload + agent uids. Surfaces here so mvmctl status can
    # verify the actual /proc/<pid>/Uid against the declared
    # intent.
    uids = {
      agent = agentUid;
      entrypoint = entrypointUid;
    };
    inherit builderUid;
    rootlessEntrypoint = entrypointUid != 0;
    # Agent binary kind: "real" — the cross-compiled Rust binary.
    # The previous "stub" value flagged a placeholder sh script.
    # `mvmctl status` reads this;
    # production deployments should refuse to boot a "stub" image.
    agentBinary = "real";
    setprivHelperName = setprivHelperName;
    # The rootfs carries a `/mvm/runtime`
    # bind-mount target and the /init script prefers the overlay
    # agent at `/mvm/runtime/agent` over the baked-in
    # `/usr/local/bin/mvm-guest-agent`. Admission-time gates can
    # refuse to boot a workload whose rootfs is not overlay-aware
    # (e.g. an old cached template predating overlay support).
    overlayAware = true;
    # Always true: mkGuest no longer bakes the guest-runtime binaries into
    # the rootfs, so every image depends on the runtime overlay contract at
    # boot. The required-overlay admission gate reads this to refuse a rootfs
    # that could silently degrade to a baked agent/netinit pair.
    runtimeLean = true;
    sshTemplateBan = builtins.seq assertNoSshTemplateInputs true;
  };
in
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
    # Expose the side-binaries from the guest-agent build so
    # downstream derivations (verity-initrd, per-service launch line
    # in `mkServiceBlock`) can reach `mvm-seccomp-apply` and
    # `mvm-verity-init` without re-running the cargo build.
    inherit guestAgentPkg seccompApplyBinary verityInitBinary;
  };
})

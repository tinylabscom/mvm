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
# `passthru.mvm.{accessible, sealed, entrypointKind}` metadata to
# gate `mvmctl console <vm>` host-side; the `/etc/mvm/variant` file
# baked into the rootfs is the in-guest cross-check.
#
# ── Why busybox-as-PID-1, not NixOS+systemd ──
#
# ADR-013 §"Boot-time budget" is the source of truth. The short
# version: NixOS+systemd boots in 1-3 s; Alpine+OpenRC in 300-500 ms;
# busybox-as-PID-1 with custom init approaches the upstream Firecracker
# reference of ~125 ms. The 200ms cold-boot target on Firecracker
# requires the busybox path. The previous iteration of mvm shipped
# this exact strategy.
#
# microvm.nix is still pinned as a flake input (per ADR-013) for its
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
, extraFiles     ? { }
# Whether to bake the `mvm-addon-dns` binary into the rootfs at
# `/usr/local/bin/mvm-addon-dns`. The default (`true`) matches the
# "always install + no-op when zone empty" contract that workload
# microVMs rely on (see `specs/contracts/local-addon-dns.md`).
# Builder/utility VMs whose `/init` doesn't run mkGuest's addon-dns
# activation block (e.g. `nix/images/builder-vm/`, which substitutes
# `mvm-host-vm-init` as PID 1) should pass `bakeAddonDns = false` to
# skip the Rust compile of `mvm-addon-dns` during their rootfs build
# — a meaningful saving in Stage 0 where the build runs on tmpfs and
# competes with the kernel compile for memory.
, bakeAddonDns   ? true
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
# is the guest agent's ADR-007 per-call marker). This separation exists
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

  # ── Guest agent build (W6.1.2) ─────────────────────────────────
  #
  # Real Rust binary built from the workspace at `mvmSrc` via
  # `nix/packages/mvm-guest-agent.nix`. Replaces the W6.1.1 sh-stub
  # that previously lived inline here. The W7.x.2 libkrun
  # builder VM is what makes this buildable on hosts without native
  # Linux Nix.
  #
  # The `dev-shell` Cargo feature gates the `do_exec` RPC handler
  # (ADR-002 §W4.3 / `prod-agent-no-exec` CI gate). We tie it to
  # `isDev` here so the same `mkGuest` call:
  #
  #   - Dev image (`entrypoint.shell = ...`, or `dev = true`)
  #     → `do_exec` compiled in → `mvmctl exec`/`mvmctl console` work
  #   - Prod/sealed image (`entrypoint.command`/`services`, or
  #     `dev = false`)
  #     → `do_exec` stripped → CI's symbol-absence gate passes
  #
  # Either way the binary is the production Rust build, not a stub.
  guestAgentPkg = pkgs.callPackage ../packages/mvm-guest-agent.nix {
    inherit mvmSrc;
    withDevShell = isDev;
  };

  # ── mvm-addon-dns — in-guest loopback DNS resolver ─────────────
  #
  # Always baked into the rootfs (the "always-install + no-op when
  # zone empty" pattern from `specs/contracts/local-addon-dns.md`);
  # /init activates it only when a zone file is present, so a guest
  # without addons keeps its baked /etc/resolv.conf byte-for-byte.
  addonDnsPkg = pkgs.callPackage ../packages/mvm-addon-dns.nix {
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
  #                                  defense in depth — ADR-002 W2.1)
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
  # Phase 6 (W2.1) introduces per-service derived gids; for the
  # Phase 1 W6.1 slice we keep it simple.
  agentUid = resolvedUids.agent;
  entrypointUid = resolvedUids.entrypoint;

  # Wrap a command-line in `setpriv` when the target uid is non-zero.
  #
  # **util-linux's setpriv, not busybox's.** `pkgsStatic.busybox`
  # ships a stripped setpriv applet that only knows the bare
  # `-d / --nnp / --inh-caps / --ambient-caps` flags — `--reuid`,
  # `--regid`, and `--clear-groups` come from util-linux's full
  # setpriv binary. Invoking `/bin/busybox setpriv --reuid=…`
  # fails with `setpriv: unrecognized option: reuid=…`, killing
  # /init at stage 2.5 before the guest agent ever forks. The
  # Nix store path to util-linux's setpriv is baked in at build
  # time and shipped in the rootfs's `/nix/store` closure.
  #
  # The flag set matches ADR-002 W2.3 (--reuid + --regid +
  # --clear-groups + --no-new-privs). uid==0 short-circuits to
  # the bare command — no point setpriv-ing to root.
  setprivWrap = uid: cmd:
    if uid == 0 then cmd
    else
      "exec ${pkgs.util-linux}/bin/setpriv "
      + "--reuid=${toString uid} --regid=${toString uid} "
      + "--clear-groups --no-new-privs -- ${cmd}";

  rawEntrypointCmd =
    if entrypointKind == "shell" then
      "${lib.escapeShellArg entrypoint.shell} -i"
    else if entrypointKind == "command" then
      renderCommand entrypoint.command
    else
      "/bin/sh -i";  # services fallthrough; W5.2 wires the supervisor

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
  # Supervision pattern (W6.1):
  #   1. Stage filesystem (proc/sys/dev + tmpfs).
  #   2. Fork the guest agent in background under setpriv→agent uid.
  #   3. Re-attach stdio (dev variant).
  #   4. setpriv→entrypoint uid + exec the workload.
  #
  # PID 1 stays uid 0 (kernel mandate); both children run rootless
  # by default in production (see uids resolution above).
  initScript = pkgs.writeScript "mvm-init" ''
    #!/bin/sh
    # mvm /init — busybox PID 1 (plan 60 / ADR-013).

    # Stage 1 — kernel pseudofs. Required before anything else
    # can read /proc/self or write to /dev/console.
    /bin/busybox mount -t proc     proc     /proc
    /bin/busybox mount -t sysfs    sysfs    /sys
    /bin/busybox mount -t devtmpfs devtmpfs /dev

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
    # stays read-only-leaning; volumes (Phase 2) attach to fixed
    # mountpoints instead.
    /bin/busybox mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp
    /bin/busybox mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run

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

    # Stage 2.45 — Plan 74 W2 — guest-side network defense.
    # Install kernel blackhole routes for `MANDATORY_DENY_RANGES`
    # (cloud metadata, link-local, CGNAT, host loopback) BEFORE
    # any workload code runs. We're still uid 0 here — the agent
    # fork below drops to uid 901, which doesn't have
    # CAP_NET_ADMIN, so the install has to happen here. Mirrors
    # the agent-bin resolution: prefer /mvm/runtime/netinit (from
    # the W1.4b runtime overlay) over the baked-in copy in
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
    MVM_NETINIT_BIN=
    if [ -x /mvm/runtime/netinit ]; then
      MVM_NETINIT_BIN=/mvm/runtime/netinit
    elif [ -x /usr/local/bin/mvm-guest-netinit ]; then
      MVM_NETINIT_BIN=/usr/local/bin/mvm-guest-netinit
    fi
    if [ -n "$MVM_NETINIT_BIN" ]; then
      "$MVM_NETINIT_BIN" || echo "mvm-init: netinit exited nonzero; continuing without guest-side defense"
    fi

    # Stage 2.48 — local addon DNS bootstrap.
    #
    # The "always-install + no-op when zone empty" pattern from
    # `specs/contracts/local-addon-dns.md`: the addon DNS binary is
    # baked into every rootfs but only activated when a zone file
    # was baked at /etc/mvm/addon_dns_zone.json (via mkGuest's
    # `extraFiles`) or staged on the config-disk path before init
    # runs. Guests without addons skip this block entirely, so
    # /etc/resolv.conf stays byte-for-byte the build-time default.
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
    #      read-only /etc bind that ADR-002 W2.2 will eventually land
    #      so this works on both dev and hardened images.
    #   4. Fork mvm-addon-dns under setpriv to the agent uid with
    #      CAP_NET_BIND_SERVICE preserved via ambient + inheritable
    #      caps so it can bind UDP/53 on loopback only. The server
    #      validates loopback + self-upstream constraints itself; we
    #      do not pass any other privilege.
    MVM_ADDON_DNS_ZONE_SRC=
    if [ -r /run/mvm/addon_dns_zone.json ]; then
      MVM_ADDON_DNS_ZONE_SRC=/run/mvm/addon_dns_zone.json
    elif [ -r /etc/mvm/addon_dns_zone.json ]; then
      MVM_ADDON_DNS_ZONE_SRC=/etc/mvm/addon_dns_zone.json
    fi
    if [ -n "$MVM_ADDON_DNS_ZONE_SRC" ] && [ -x /usr/local/bin/mvm-addon-dns ]; then
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
      # and bind-mount it over /etc/resolv.conf. The :: literal is
      # written via printf so the heredoc body stays parameter-free.
      printf 'nameserver 127.0.0.1\nnameserver ::1\n' > /run/mvm/resolv.conf
      /bin/busybox chmod 0644 /run/mvm/resolv.conf
      /bin/busybox mount --bind /run/mvm/resolv.conf /etc/resolv.conf

      /bin/busybox setsid ${pkgs.util-linux}/bin/setpriv \
        --reuid=${toString agentUid} --regid=${toString agentUid} \
        --clear-groups --no-new-privs \
        --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
        -- /usr/local/bin/mvm-addon-dns &
    fi

    # Stage 2.5 — guest agent supervisor. Fork the agent into
    # the background under its own uid before we drop to the
    # entrypoint. The agent is responsible for vsock RPC (host
    # tool calls, lifecycle hooks); without it, the host can boot
    # us but can't talk to us. We never block on it — if the agent
    # fails to start, the entrypoint still runs and the lack of
    # agent shows up in `mvmctl status`.
    #
    # Plan 74 W1.4b (ADR-051) — when the mvm runtime overlay is
    # attached, `mvm-verity-init` bind-mounts it at /mvm/runtime
    # before switch_root, so /mvm/runtime/agent is the canonical
    # binary location. Prefer it over the baked-in copy at
    # /usr/local/bin/mvm-guest-agent (which a future PR drops
    # entirely once every backend attaches the overlay). Both
    # paths are exec-tested so a half-attached overlay (directory
    # present, agent missing) still falls through to the baked-in
    # path rather than booting agent-less.
    MVM_AGENT_BIN=
    if [ -x /mvm/runtime/agent ]; then
      MVM_AGENT_BIN=/mvm/runtime/agent
    elif [ -x /usr/local/bin/mvm-guest-agent ]; then
      MVM_AGENT_BIN=/usr/local/bin/mvm-guest-agent
    fi
    if [ -n "$MVM_AGENT_BIN" ]; then
      # util-linux setpriv — busybox setpriv lacks --reuid /
      # --regid / --clear-groups; see `setprivWrap` above for
      # the full reasoning. Without this fix the agent never
      # forks and vsock port 5252 stays unbound.
      /bin/busybox setsid ${pkgs.util-linux}/bin/setpriv \
        --reuid=${toString agentUid} --regid=${toString agentUid} \
        --clear-groups --no-new-privs \
        -- "$MVM_AGENT_BIN" &
    fi

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
    fi

    # Stage 4.5 — Plan 74 W1.4b (ADR-051) — mvm runtime overlay env.
    # When the overlay is mounted (verity boot path), surface its
    # presence + SDK-library paths to the entrypoint via env
    # variables. Per-language path vars (PYTHONPATH, NODE_PATH)
    # are prepended so they take precedence over a user's existing
    # value; an empty existing value leaves no trailing colon.
    # Setting these unconditionally on the overlay-mounted path
    # gives a stable contract for SDK addons (ADR-049 vsock hooks)
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
    . "$MVM_BOOT"

    # If the boot command exits or doesn't exec, the kernel panics.
    # The fallthrough echo gives a chance to capture *why* via
    # console before that happens.
    echo "mvm: $MVM_BOOT returned without exec — kernel will panic"
    /bin/busybox sleep 5
  '';

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
      "/etc/mvm/entrypoint" (the guest agent's per-call marker, ADR-007).
      The function-service factory must bake it.
    ''
    else true;

  # Variant marker (dev|prod). In-guest source of truth — paired
  # with passthru.mvm.{accessible,sealed} on the derivation.
  variantFile = pkgs.writeText "mvm-variant" (
    if isDev then "dev\n" else "prod\n"
  );

  nameFile = pkgs.writeText "mvm-name" "${name}\n";

  # ── mvm-guest-agent — production Rust binary (W6.1.2)
  #
  # Built by `nix/packages/mvm-guest-agent.nix` from the workspace
  # source at `mvmSrc`. The W6.1.1 sh-stub that previously lived here
  # was a placeholder used while the cross-compile infrastructure
  # was being staged; the W7.x.2 libkrun builder VM made the
  # real build host-Nix-free, which unblocked this swap.
  #
  # The binary is the same one the workspace's
  # `crates/mvm-guest/src/bin/mvm-guest-agent.rs` Cargo target builds
  # — vsock RPC handler, worker-pool dispatcher, integration manifest
  # consumer, system metrics surface. ADR-002 §W4 documents the
  # attack surface; ADR-002 §W4.3 documents the `dev-shell` feature
  # gate that toggles `do_exec` between dev and prod images.
  agentBinary = "${guestAgentPkg}/bin/mvm-guest-agent";

  # `mvm-seccomp-apply` ships alongside the agent (same Cargo
  # workspace member, same derivation). The per-service launch line
  # in `mkServiceBlock` execs it via setpriv to apply the tier's
  # seccomp filter before handing control to the workload.
  seccompApplyBinary = "${guestAgentPkg}/bin/mvm-seccomp-apply";

  # `mvm-verity-init` is the PID 1 of the verity initramfs (ADR-002
  # §W3). Baked into the verity-initrd cpio.gz, not into the rootfs
  # directly — wired here as a passthru export so the initramfs
  # builder can reach it without duplicating the agent derivation.
  verityInitBinary = "${guestAgentPkg}/bin/mvm-verity-init";

  # Plan 74 W2 — guest-side network defense. `mvm-guest-netinit`
  # installs kernel blackhole routes for `MANDATORY_DENY_RANGES`
  # (cloud metadata, link-local, CGNAT, host loopback) inside the
  # guest at boot. Run as root from `/init` BEFORE the agent forks
  # under setpriv — the routes must exist before any workload code
  # can attempt egress.
  mvmGuestNetinitBinary = "${guestAgentPkg}/bin/mvm-guest-netinit";

  # In-guest addon DNS resolver. Loopback-only UDP server that serves
  # exact configured addon hostnames and forwards everything else to
  # the pre-rewrite upstream resolver snapshot. Activated by /init
  # only when a zone file is present so the no-addon path is
  # unaffected. See `crates/mvm-addon-dns` for details.
  mvmAddonDnsBinary = "${addonDnsPkg}/bin/mvm-addon-dns";

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
  # Binary-source variants exist so Plan 72's builder-vm flake can
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
  # Phase 6 layers the security overlay (per-service uids,
  # read-only /etc bind-mount, dm-verity) on top of this base.
  rootfsTree = pkgs.runCommand "mvm-rootfs-tree-${name}" { } ''
    set -e
    mkdir -p "$out"

    # Standard FHS dirs the kernel + init expect. `/nix-store`,
    # `/job`, `/out`, `/work`, `/mvm-bins` are mount points the libkrun
    # builder VM (Plan 72 W3 / ADR-065) needs pre-created — rootfs boots
    # `ro` so `mvm-host-vm-init` can't `mkdir` them at runtime.
    mkdir -p "$out"/{bin,sbin,etc,proc,sys,dev,tmp,run,var,root,home,nix/store,nix-store,etc/mvm,job,out,work,mvm-bins}
    chmod 1777 "$out/tmp"
    chmod 0755 "$out/run"

    # Plan 74 W1.4b — the mvm runtime overlay (ADR-051) is
    # bind-mounted at /mvm/runtime by `mvm-verity-init` before
    # switch_root. The directory must exist in the rootfs so the
    # bind-mount has a target. Mode 0755 (owner root); the overlay
    # itself is mounted read-only over it, so contents can't be
    # written by the guest regardless. Outside the verity-boot
    # path (dev-mode VMs that don't run `mvm-verity-init`) the
    # directory is empty — /init below falls back to the baked-in
    # agent. `/mvm/` is reserved (admission-time check in W1.4b.3d
    # rejects OCI images that carry content under this path).
    mkdir -p "$out/mvm/runtime"
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
    # /sbin/init is what the kernel actually execs at boot (when
    # there's no init=/init kernel param). We point both at our
    # custom init script so either path works.
    cp ${initScript} "$out/init"
    chmod 0500 "$out/init"
    ln -sf /init "$out/sbin/init"

    # mvm metadata. The PID 1 boot command is the load-bearing file —
    # /init sources it. Mode 0500 so non-root processes in the guest
    # can't read or replace it (W2.2 makes /etc read-only as well).
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

    # /etc/passwd + /etc/group provision root (mandatory for PID 1)
    # plus the agent + entrypoint uids resolved at build time.
    # Per ADR-002 W2.2 (Phase 6) these become read-only via bind-
    # mount once the security overlay lands; for W6.1 they're
    # plain mode 0644.
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

    # mvm-guest-agent — installed under /usr/local/bin so /init can
    # exec it. Mode 0555 so the agent can't rewrite itself; ownership
    # is the build-time user (Nix sandbox has no root) — Phase 6 W2.2
    # binds /etc + /usr read-only at boot to make this load-bearing.
    #
    # mkdir before the cp: when `packages = []` the directory-creation
    # block below is a no-op, so /usr/local/bin doesn't exist yet and
    # the cp fails with "No such file or directory". That was the
    # latent bug that broke release.yml's dev-image lane and the
    # ch-linux bootcheck before this fix.
    mkdir -p "$out/usr/local/bin"
    cp ${agentBinary} "$out/usr/local/bin/mvm-guest-agent"
    chmod 0555 "$out/usr/local/bin/mvm-guest-agent"

    # Plan 74 W2 — guest-side network defense. Same mode as the
    # agent (0555: read+exec, not writable). /init runs this as
    # uid 0 BEFORE forking the agent under setpriv, so the routes
    # exist before any workload code can attempt egress. The
    # binary itself does not need elevated capabilities at run
    # time beyond the CAP_NET_ADMIN that PID 1 already has.
    cp ${mvmGuestNetinitBinary} "$out/usr/local/bin/mvm-guest-netinit"
    chmod 0555 "$out/usr/local/bin/mvm-guest-netinit"

    # In-guest addon DNS resolver. Baked into every workload rootfs
    # so /init can spawn it without a build-time mkGuest flag;
    # activation is gated at boot on the presence of a zone file
    # (see initScript). Gated on the `bakeAddonDns` arg so VMs whose
    # `/init` doesn't run mkGuest's addon-dns activation block (e.g.
    # `nix/images/builder-vm/`) can skip the Rust compile — the
    # binary would never get invoked there, and on tmpfs-bound Stage
    # 0 builds the parallel rustc run for it pushes the kernel
    # compile into OOM territory.
    ${if bakeAddonDns then ''
      cp ${mvmAddonDnsBinary} "$out/usr/local/bin/mvm-addon-dns"
      chmod 0555 "$out/usr/local/bin/mvm-addon-dns"
    '' else ""}

    # Kernel modules. `/init` `modprobe`s vsock before forking the
    # agent (default nixpkgs kernel ships AF_VSOCK as `=m`); without
    # `/lib/modules/<kver>/` in the rootfs, modprobe has nothing to
    # load and the agent fails to open AF_VSOCK. Copy only the vsock
    # transport closure instead of the full kernel module tree; the
    # full tree is hundreds of MB and #110's contract keeps rootfs
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

              # Keep module metadata at the kver root. Busybox modprobe
              # reads modules.dep for the named module and dependency
              # paths; the other modules.* files are small enough to keep
              # and preserve compatibility with kmod-style lookup.
              shopt -s nullglob
              for metadata in "$src"/modules.*; do
                cp -a --reflink=auto "$metadata" "$out/lib/modules/$kver/"
              done
              shopt -u nullglob

              copy_module_closure \
                "$src" \
                "$out/lib/modules/$kver" \
                "vmw_vsock_virtio_transport"
              # Stage 0 (`bootstrap_builder_vm_image_via_dev_image_stage0`,
              # Plan 77 W3) boots this rootfs and mounts `/work`, `/out`,
              # `/job` as virtio-fs. nixpkgs ships `CONFIG_VIRTIO_FS=m`
              # and `CONFIG_FUSE_FS=m`, so without the module closure
              # `mount -t virtiofs` fails with ENODEV and the VM powers
              # down before `mvm-host-vm-init` can finalize `/job/result`.
              # #333 trimmed the closure to vsock-only because that's all
              # the workload microVM path needed; Stage 0's reuse of this
              # rootfs landed later and depends on virtio-fs.
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
    ${extraFilePopulation}

    # Closure of additional packages — symlink each binary into
    # `/usr/local/bin` AND `/sbin` so the standard system-binary
    # paths (`/sbin/mkfs.ext4`, `/sbin/udhcpc`, etc.) resolve.
    # `mvm-host-vm-init` uses those paths verbatim and would
    # ENOENT-fail without them (e.g. e2fsprogs ships mkfs.ext4 in
    # the package's sbin subdir, not bin).
    mkdir -p "$out/usr/local/bin"
    ${lib.concatMapStringsSep "\n"
      (pkg: ''
        for srcdir in bin sbin; do
          if [ -d "${pkg}/$srcdir" ]; then
            for binpath in "${pkg}/$srcdir"/*; do
              [ -e "$binpath" ] || continue
              name=$(basename "$binpath")
              ln -sf "$binpath" "$out/usr/local/bin/$name"
              ln -sf "$binpath" "$out/sbin/$name"
            done
          fi
        done
      '')
      packages}
  '';

  # Package the tree as an ext4 image. nixpkgs ships a make-ext4-fs
  # derivation that handles the mkfs + populate dance correctly.
  # All arguments arrive in a single set via callPackage's auto-arg
  # injection. Reference make-ext4-fs.nix via the flake input
  # (`${nixpkgs}/...`) rather than the angle-bracket form (`<nixpkgs/...>`)
  # — the latter trips flake pure evaluation ("cannot look up
  # '<nixpkgs/...>' in pure evaluation mode").
  rootfsImage = pkgs.callPackage "${nixpkgs}/nixos/lib/make-ext4-fs.nix" {
    storePaths = [ rootfsTree ];
    volumeLabel = "mvm-${name}";
    populateImageCommands = ''
      cp -a --reflink=auto ${rootfsTree}/. ./files/
    '';
  };

  mvmMeta = {
    inherit name hypervisor;
    accessible = isDev;
    sealed = isSealed;
    entrypointKind = entrypointKind;
    initSystem = "busybox";
    # ADR-013 §"Per-backend boot budgets" — single 300ms floor across
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
    rootlessEntrypoint = entrypointUid != 0;
    # Agent binary kind: "real" since W6.1.2 swapped in the cross-
    # compiled Rust binary. The previous "stub" value flagged the
    # W6.1.1 placeholder sh script. `mvmctl status` reads this;
    # production deployments should refuse to boot a "stub" image.
    agentBinary = "real";
    # Plan 74 W1.4b (ADR-051) — the rootfs carries a `/mvm/runtime`
    # bind-mount target and the /init script prefers the overlay
    # agent at `/mvm/runtime/agent` over the baked-in
    # `/usr/local/bin/mvm-guest-agent`. Admission-time gates can
    # refuse to boot a workload whose rootfs is not overlay-aware
    # (e.g. an old cached template predating W1.4b.3c).
    overlayAware = true;
  };
in
rootfsImage.overrideAttrs (old: {
  passthru = (old.passthru or { }) // {
    mvm = mvmMeta;
    inherit rootfsTree;
    # Surface the chosen hypervisor + resource defaults at the top
    # of passthru so `nix eval` is sufficient for mvmctl to drive
    # the runtime — no NixOS evaluation needed.
    inherit hypervisor;
    resources = { inherit vcpus memory_mib; };
    # W6.1.2: expose the side-binaries from the guest-agent build so
    # downstream derivations (verity-initrd, per-service launch line
    # in `mkServiceBlock`) can reach `mvm-seccomp-apply` and
    # `mvm-verity-init` without re-running the cargo build.
    inherit guestAgentPkg seccompApplyBinary verityInitBinary mvmGuestNetinitBinary;
    inherit addonDnsPkg mvmAddonDnsBinary;
  };
})

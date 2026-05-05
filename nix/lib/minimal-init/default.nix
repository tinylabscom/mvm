# Minimal PID 1 init script generator for mvm guests.
#
# Produces a shell script (using busyboxStatic) that replaces systemd
# as PID 1 inside Firecracker microVMs. No NixOS, no systemd — just
# mount, network, service respawn loops, and the guest agent.
#
# Layout:
#
#   init.sh.in                    entry point. Sources lib/* in order.
#   lib/01-mounts.sh              devtmpfs/proc/sysfs/devpts/tmpfs.
#   lib/02-nix-overlay.sh         host-backed /nix overlayfs.
#   lib/03-host-shares.sh         VirtioFS workdir + datadir.
#   lib/04-etc-and-users.sh.in    /etc/{passwd,group,hostname,…}.
#   lib/05-networking.sh          static IP / DHCP fallback.
#   lib/06-optional-drives.sh.in  config / secrets / data drives.
#   lib/07-services-and-agent.sh.in  generated loop bodies.
#   lib/08-signal-handlers.sh.in  post_restore + shutdown traps.
#
# Files ending `.sh` are pure POSIX shell — no substitutions, used
# verbatim. Files ending `.sh.in` get fed through `pkgs.replaceVars`
# with the same substitutions as `init.sh.in` so any of them can
# reference `@busybox@`, `@hostname@`, `@serviceGroup@`, the
# generated loop blocks, etc.
#
# Each rendered fragment becomes one substitution into init.sh.in
# (`@mountsLib@`, `@nixOverlayLib@`, …). The rendering function
# `renderLib` reads each file's contents at evaluation time and
# inlines the text — so the final /init is a single concatenated
# script, not a sequence of `source` calls. Keeping it single-file
# means the rootfs's read-only baked store contains exactly one
# init artifact, mode bits and all.
#
# If the generated blocks ever grow nested control flow that flat
# `@placeholder@` substitutions can't express cleanly, swap
# `replaceVars` for tera (already vendored on the host side at
# `crates/mvm-build/resources/builder_scripts/`). Today the loop
# bodies are flat string concats produced by Nix, so vanilla
# substitution is the right tool.
#
# Usage:
#   initScript = import ./minimal-init {
#     inherit pkgs;
#     hostname = "my-vm";
#     users.myuser = { uid = 1000; };
#     services.my-app = { command = "..."; };
#     healthChecks.my-app = { healthCmd = "..."; };
#     guestAgentPkg = mvm-guest-agent;
#     extraPathDirs = [ "${pkgs.git}/bin" ];
#   };

{ pkgs
, lib ? pkgs.lib
, busybox ? pkgs.pkgsStatic.busybox
, hostname ? "mvm"
, serviceGroup ? "mvm"
, users ? {}
, services ? {}
, healthChecks ? {}
, guestAgentPkg ? null
, extraPathDirs ? []
# `pkgs.util-linux` shipped to the rootfs by mkGuest. Init's service
# launches use `setpriv(1)` from this package to drop capabilities,
# clear the inheritable cap set, and set `no_new_privs` before
# handing off to the user's command. ADR-002 §W2.3.
, utilLinux ? pkgs.util-linux
}:

let
  bb = busybox;

  # ── Users ────────────────────────────────────────────────────────
  # Auto-assign UIDs starting from 1000 for users that don't specify one.
  userList = lib.mapAttrsToList (name: cfg: { inherit name; config = cfg; }) users;
  assignUids = idx: remaining:
    if remaining == [] then []
    else
      let
        head = builtins.head remaining;
        tail = builtins.tail remaining;
        uid = head.config.uid or (1000 + idx);
      in
        [{ name = head.name; uid = uid; config = head.config; }]
        ++ assignUids (idx + 1) tail;
  usersWithUids = assignUids 0 userList;

  mkUserBlock = entry:
    let
      name = entry.name;
      uid = toString entry.uid;
      group = entry.config.group or name;
      home = entry.config.home or "/home/${name}";
    in ''
      # User blocks write to /run/mvm-etc/{passwd,group} (the staging
      # tmpfs); the bind-mount onto /etc/* runs after every block has
      # appended its entries (see lib/04-etc-and-users.sh.in). The
      # group's gid matches its uid since `${group}:x:${uid}:` is the
      # entry we emit, so a numeric chown of `${uid}:${uid}` resolves
      # without needing a name-resolving /etc to be live yet.
      grep -q "^${group}:" /run/mvm-etc/group || echo '${group}:x:${uid}:' >> /run/mvm-etc/group
      grep -q "^${name}:" /run/mvm-etc/passwd || echo '${name}:x:${uid}:${uid}:${name}:${home}:${bb}/bin/sh' >> /run/mvm-etc/passwd
      mkdir -p ${home}
      chown ${uid}:${uid} ${home}
      # Add to service group so the user can read /mnt/secrets (0440 root:${serviceGroup}).
      sed -i 's/^${serviceGroup}:x:900:.*$/&,${name}/' /run/mvm-etc/group
      sed -i 's/^${serviceGroup}:x:900:,/${serviceGroup}:x:900:/' /run/mvm-etc/group
    '';
  explicitUserBlocks = lib.concatStringsSep "\n" (map mkUserBlock usersWithUids);
  # Combined: explicit user-set users first, then auto-derived
  # per-service identities. Order matters because mkServiceUserBlock
  # idempotency-checks via grep before appending.
  userBlocks = explicitUserBlocks + "\n" + serviceUserBlocks;

  # ── Services ─────────────────────────────────────────────────────
  #
  # Each service is launched with three layers of guest-side
  # confinement (ADR-002 §§W2.1, W2.3, W2.4):
  #
  #   1. Per-service uid + primary group.   Derived deterministically
  #      from the service name so two flakes that name a service
  #      identically pick identical uids — useful for cross-VM
  #      consistency. UIDs land in [1100, 9099], leaving room for the
  #      shared `serviceGroup` (uid 900) and the guest agent (uid 901)
  #      below the auto-assignment range.
  #
  #   2. `setpriv` drops capabilities, clears supplementary groups,
  #      and sets `PR_SET_NO_NEW_PRIVS`. A child process can no
  #      longer regain caps via setuid binaries.
  #
  #   3. `mvm-seccomp-apply <tier> --` installs a BPF syscall filter
  #      that returns EPERM on disallowed calls. Default tier is
  #      `standard`; per-service override via `services.<n>.seccomp`.
  #
  # Caller-supplied `services.<n>.user` skips uid auto-assignment;
  # the service runs as that named user with whatever uid the
  # `users` attrset gives it. This is the back-compat escape for
  # flakes that already coordinate uids across services.

  # Deterministic uid in [1100, 9099] keyed on the service name.
  # `builtins.hashString "sha256"` returns a 64-char hex string; we
  # take the first 8 hex chars (32 bits), parse to int, modulo 8000
  # to land in the [0, 7999] window, plus 1100 base. The base sits
  # above the dev-image's user IDs (root, default service group at
  # 900, guest-agent at 901, and the auto-assigned-1000 customs).
  hashName = name:
    let
      hex = builtins.substring 0 8 (builtins.hashString "sha256" name);
      # Convert 8-char hex to integer via byte-wise arithmetic. Nix's
      # bitwise ops are limited; this is the documented idiom.
      hexDigit = c:
        if c == "0" then 0
        else if c == "1" then 1
        else if c == "2" then 2
        else if c == "3" then 3
        else if c == "4" then 4
        else if c == "5" then 5
        else if c == "6" then 6
        else if c == "7" then 7
        else if c == "8" then 8
        else if c == "9" then 9
        else if c == "a" then 10
        else if c == "b" then 11
        else if c == "c" then 12
        else if c == "d" then 13
        else if c == "e" then 14
        else 15;  # f
      go = i: acc:
        if i >= 8 then acc
        else go (i + 1) (acc * 16 + hexDigit (builtins.substring i 1 hex));
    in
      go 0 0;

  serviceUid = name: 1100 + (lib.mod (hashName name) 8000);

  # The service-derived attrs get used by both the user-block
  # generator (so /etc/passwd has the entry) and the launch block.
  serviceIdentity = name: svc:
    if svc ? user then
      # Caller specified an explicit user — assume they also added it
      # to `users`. The setpriv launcher reads uid/gid from the live
      # /etc, so we don't need them at Nix-eval time.
      { user = svc.user; explicit = true; uid = null; gid = null; }
    else
      let uid = serviceUid name;
      in { user = "svc-${name}"; explicit = false; uid = uid; gid = uid; }
  ;

  # Per-service /etc entries. Joined into `userBlocks` alongside the
  # caller's explicit `users.*` entries. Writes target /run/mvm-etc/*
  # (staging) — the bind-mount onto /etc/* runs after every block has
  # appended; see lib/04-etc-and-users.sh.in.
  mkServiceUserBlock = name: svc:
    let id = serviceIdentity name svc; in
    if id.explicit then ""
    else ''
      # Auto-derived service identity for ${name} (ADR-002 §W2.1)
      grep -q "^${id.user}:" /run/mvm-etc/group || echo '${id.user}:x:${toString id.gid}:' >> /run/mvm-etc/group
      grep -q "^${id.user}:" /run/mvm-etc/passwd || echo '${id.user}:x:${toString id.uid}:${toString id.gid}:${id.user}:/var/empty:${bb}/bin/sh' >> /run/mvm-etc/passwd
      # Add to ${serviceGroup} so this user can read shared secrets at
      # /mnt/secrets (mode 0440 root:${serviceGroup}). Per-service
      # secrets at /run/mvm-secrets/${name}/ are mode 0400 owned by
      # this uid directly — they don't go through the group.
      sed -i 's/^${serviceGroup}:x:900:.*$/&,${id.user}/' /run/mvm-etc/group
      sed -i 's/^${serviceGroup}:x:900:,/${serviceGroup}:x:900:/' /run/mvm-etc/group
    '';

  serviceUserBlocks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList mkServiceUserBlock services
  );

  # Per-service secrets directory. Each service gets a subdir under
  # /run/mvm-secrets/ owned by its uid mode 0400 — siblings can't
  # cross-read. The legacy /run/mvm-secrets/ shared view is preserved
  # for back-compat but flagged in a deprecation notice.
  mkServiceSecretsBlock = name: svc:
    let id = serviceIdentity name svc; in
    let
      # Filter the staged secrets to those whose filename starts with
      # "<svc-name>." or matches "<svc-name>" exactly. Anything else
      # stays in the shared bucket.
      copyCmd =
        if id.explicit then ''
          mkdir -p /run/mvm-secrets/${name}
          for f in /run/mvm-secrets/${name}.* /run/mvm-secrets/${name}; do
            [ -e "$f" ] || continue
            cp "$f" /run/mvm-secrets/${name}/$(basename "$f")
          done
          chown -R ${id.user}:${id.user} /run/mvm-secrets/${name} 2>/dev/null || true
          chmod 0500 /run/mvm-secrets/${name}
          chmod 0400 /run/mvm-secrets/${name}/* 2>/dev/null || true
        '' else ''
          mkdir -p /run/mvm-secrets/${name}
          for f in /run/mvm-secrets/${name}.* /run/mvm-secrets/${name}; do
            [ -e "$f" ] || continue
            cp "$f" /run/mvm-secrets/${name}/$(basename "$f")
          done
          chown -R ${toString id.uid}:${toString id.gid} /run/mvm-secrets/${name} 2>/dev/null || true
          chmod 0500 /run/mvm-secrets/${name}
          chmod 0400 /run/mvm-secrets/${name}/* 2>/dev/null || true
        '';
    in copyCmd;

  serviceSecretsBlocks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList mkServiceSecretsBlock services
  );

  # The launch line. Layers from outside in:
  #
  #   mvm-seccomp-apply <tier> -- \
  #     setpriv --reuid=<uid> --regid=<gid> \
  #             --groups=<gid>,900 --bounding-set=-all --no-new-privs \
  #             --inh-caps=-all -- \
  #         /bin/sh -c '<command>'
  #
  # `--groups` retains membership in `serviceGroup` (gid 900) so
  # legacy shared-secret reads still work. `--groups` already replaces
  # the supplementary group set wholesale — combining it with
  # `--clear-groups` is rejected by util-linux setpriv as "mutually
  # exclusive", which is what crashlooped every service on the W3
  # verity-boot regression. Keep `--groups` alone.
  # Capabilities are dropped *before* the command runs; the bounding
  # set is empty so a setuid root binary the command might invoke
  # gets uid 0 with zero capabilities — meaningless escalation.
  mkServiceBlock = name: svc:
    let
      preStart = svc.preStart or "";
      preBlock = lib.optionalString (preStart != "") ''
        echo "[init] preStart for ${name}..." > /dev/console
        ${preStart}
      '';
      # Service env defaults: only set if not already defined (e.g. by
      # --env flags sourced globally from mvm-env.env). This lets
      # `mvmctl up --env PORT=9000` override `env.PORT = "3100"`.
      envLines = lib.concatStringsSep "\n" (
        lib.mapAttrsToList (k: v: ": \${${k}:='${v}'} ; export ${k}") (svc.env or {})
      );
      redirect = if (svc ? logFile) then
        ">> ${svc.logFile} 2>&1"
      else
        "> /dev/console 2>&1";
      logSetup = lib.optionalString (svc ? logFile) ''
        mkdir -p "$(dirname '${svc.logFile}')"
      '';
      id = serviceIdentity name svc;
      tier = svc.seccomp or "standard";
      # When the caller named an explicit user, we don't have its
      # uid at eval time — fall back to setpriv's name-resolving
      # `--reuid=<name>` form. setpriv resolves against the live
      # /etc/passwd inside the booted VM.
      setprivPrefix =
        if id.explicit then
          "${utilLinux}/bin/setpriv --reuid=${id.user} --regid=${id.user} --init-groups --bounding-set=-all --no-new-privs --inh-caps=-all"
        else
          "${utilLinux}/bin/setpriv --reuid=${toString id.uid} --regid=${toString id.gid} --groups=${toString id.gid},900 --bounding-set=-all --no-new-privs --inh-caps=-all"
      ;
      # The seccomp shim. `mvm-seccomp-apply` ships in the guest agent's
      # closure, so we look it up via guestAgentPkg's bin dir. When
      # guestAgentPkg is null (production OCI-only consumers), skip
      # the seccomp wrap — the resulting image has no `setpriv` or
      # `mvm-seccomp-apply` for service launches anyway.
      seccompPrefix =
        if guestAgentPkg == null then ""
        else "${guestAgentPkg}/bin/mvm-seccomp-apply ${tier} --"
      ;
      cmdLine =
        if seccompPrefix == "" then
          "${setprivPrefix} -- ${bb}/bin/sh -c '${svc.command}'"
        else
          "${seccompPrefix} ${setprivPrefix} -- ${bb}/bin/sh -c '${svc.command}'"
      ;
    in ''
      # --- Service: ${name} (uid=${if id.explicit then id.user else toString id.uid}, seccomp=${tier}) ---
      (
        ${envLines}
        ${logSetup}
        RUNNING=1
        trap 'RUNNING=0; kill "$CMD_PID" 2>/dev/null' TERM
        while [ "$RUNNING" = "1" ]; do
          ${preBlock}
          echo "[init] starting ${name}..." > /dev/console
          ${cmdLine} ${redirect} &
          CMD_PID=$!
          echo $CMD_PID > /run/mvm-services/${name}.pid
          wait "$CMD_PID"
          RC=$?
          [ "$RUNNING" = "0" ] && break
          echo "[init] ${name} exited ($RC), restarting in 2s..." > /dev/console
          sleep 2
        done
      ) &
      SERVICE_PIDS="$SERVICE_PIDS $!"
    '';
  serviceBlocks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList mkServiceBlock services
  );

  # ── Health checks ────────────────────────────────────────────────
  mkHealthCheckFile = name: check:
    let
      obj = {
        inherit name;
        health_cmd = check.healthCmd;
        health_interval_secs = check.healthIntervalSecs or 30;
        health_timeout_secs = check.healthTimeoutSecs or 10;
      } // lib.optionalAttrs (check ? checkpointCmd) {
        checkpoint_cmd = check.checkpointCmd;
      } // lib.optionalAttrs (check ? restoreCmd) {
        restore_cmd = check.restoreCmd;
      } // lib.optionalAttrs (check ? critical) {
        critical = check.critical;
      } // lib.optionalAttrs (check ? startupGraceSecs) {
        startup_grace_secs = check.startupGraceSecs;
      };
      json = builtins.toJSON obj;
    in ''
      cat > /etc/mvm/integrations.d/${name}.json <<'HEALTHEOF'
      ${json}
      HEALTHEOF
    '';
  healthCheckBlocks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList mkHealthCheckFile healthChecks
  );

  # ── Guest agent ──────────────────────────────────────────────────
  #
  # The agent runs as uid 901 (`mvm-agent`) — the only host-facing RPC
  # surface in the guest, so dropping privileges before the bind is
  # important. ADR-002 §W4.5.
  #
  # Why setpriv works for the agent:
  #   - vsock binds are unprivileged on Linux (the kernel validates only
  #     the family + CID, no port-range gate like AF_INET);
  #   - the agent reads drop-in configs from /etc/mvm/integrations.d/
  #     and writes its log line to /dev/console (mode 0666 by default
  #     under devtmpfs);
  #   - children spawned by ConsoleOpen/Exec (dev-mode only) inherit
  #     no_new_privs and the empty bounding capability set, so
  #     /bin/su / setuid binaries can't regain root inside a console.
  #
  # We deliberately do *not* apply mvm-seccomp-apply to the agent
  # itself: the agent is the seccomp shim's caller and excluding it
  # would otherwise need the agent's own syscall surface enumerated.
  # The standard tier is applied to every service the agent supervises;
  # the agent's own surface is reduced via setpriv only.
  guestAgentBlock = lib.optionalString (guestAgentPkg != null) ''
    # --- mvm-guest-agent ---
    # /etc/mvm/{integrations.d,probes.d} are pre-created at rootfs build
    # time (nix/rootfs-templates/populate.sh.in) with mode 0750. Only the
    # group ownership has to be set at boot — the ext4 build can't chgrp
    # to gid 900 from the nixbld sandbox, and ${serviceGroup} (gid 900) is
    # only allocated in /etc/group during lib/04-etc-and-users.sh.in.
    chgrp ${serviceGroup} /etc/mvm/integrations.d /etc/mvm/probes.d 2>/dev/null || true
    (
      RUNNING=1
      trap 'RUNNING=0; kill "$CMD_PID" 2>/dev/null' TERM
      while [ "$RUNNING" = "1" ]; do
        echo "[init] starting mvm-guest-agent (uid 901, mvm-agent)..." > /dev/console
        # `--groups=901,900` already replaces the supplementary group
        # set; combining with `--clear-groups` is rejected by setpriv
        # as mutually exclusive (regressed the agent on every W3
        # verity boot). ADR-002 §W4.5.
        ${utilLinux}/bin/setpriv \
          --reuid=901 --regid=901 --groups=901,900 \
          --bounding-set=-all --no-new-privs --inh-caps=-all \
          -- ${guestAgentPkg}/bin/mvm-guest-agent > /dev/console 2>&1 &
        CMD_PID=$!
        wait "$CMD_PID"
        RC=$?
        [ "$RUNNING" = "0" ] && break
        echo "[init] mvm-guest-agent exited ($RC), restarting in 2s..." > /dev/console
        sleep 2
      done
    ) &
    AGENT_PID=$!
  '';

  # ── PATH ─────────────────────────────────────────────────────────
  extraPathDirsRendered = lib.optionalString (extraPathDirs != [])
    (":" + lib.concatStringsSep ":" extraPathDirs);

  # ── udhcpc helper ────────────────────────────────────────────────
  # The udhcpc(8) action script must live somewhere the daemon can
  # exec. We previously heredoc'd it into /tmp at boot and chmod'd
  # +x — both unnecessary, since the script is static. Bake it into
  # the Nix store with mode 0755 set by writeShellScript and resolve
  # the path via `@udhcpcScript@` in lib/05-networking.sh.in.
  udhcpcScript = pkgs.writeShellScript "mvm-udhcpc-action" ''
    case "$1" in
      bound|renew)
        ip addr flush dev "$interface" 2>/dev/null
        ip addr add "$ip/$mask" dev "$interface" 2>/dev/null
        [ -n "$router" ] && ip route add default via "$router" 2>/dev/null
        [ -n "$dns" ] && echo "nameserver $dns" > /etc/resolv.conf
        ;;
    esac
  '';

  # ── Lib substitutions, shared by every fragment ──────────────────
  # Every `.sh.in` file gets the same substitution set so they're
  # interchangeable from the renderer's standpoint. Plain `.sh`
  # files ignore substitutions and are inlined verbatim.
  libSubsts = {
    busybox = "${bb}";
    hostname = hostname;
    serviceGroup = serviceGroup;
    extraPathDirs = extraPathDirsRendered;
    userBlocks = userBlocks;
    serviceBlocks = serviceBlocks;
    serviceSecretsBlocks = serviceSecretsBlocks;
    healthCheckBlocks = healthCheckBlocks;
    guestAgentBlock = guestAgentBlock;
    udhcpcScript = "${udhcpcScript}";
  };

  # `replaceVars` is strict: every key passed to it must appear in the
  # source file. Rather than maintain a per-file allow-list (drift-prone),
  # scan each fragment for the `@name@` tokens it actually uses and pass
  # only those — the lib's substitution table is the union, and each
  # fragment subscribes to whatever subset it references.
  pickSubsts = source:
    let
      tokens = builtins.match
        ".*"
        source;
      # `match` returns null on failure or a list of capture groups; we
      # don't use captures, so a non-null result just means "the file is
      # readable text". Token discovery uses a simple regex split.
      matches = builtins.split "@([a-zA-Z][a-zA-Z0-9_]*)@" source;
      names = lib.unique (
        builtins.filter builtins.isString (
          builtins.concatLists (
            builtins.filter builtins.isList matches
          )
        )
      );
      _ = tokens;
    in
      lib.filterAttrs (name: _: builtins.elem name names) libSubsts;

  # Render one fragment to a string. `.sh.in` files are run through
  # `replaceVars`; `.sh` files are read verbatim. We use
  # `builtins.readFile` on the rendered store path so the result is
  # an inline string that can itself be substituted into init.sh.in —
  # this keeps the final /init a single concatenated script.
  renderLib = path:
    if lib.hasSuffix ".sh.in" (toString path) then
      let
        contents = builtins.readFile path;
        substs = pickSubsts contents;
      in
        builtins.readFile (pkgs.replaceVars path substs)
    else
      builtins.readFile path;

  initLibs = {
    mountsLib            = renderLib ./lib/01-mounts.sh;
    nixOverlayLib        = renderLib ./lib/02-nix-overlay.sh;
    hostSharesLib        = renderLib ./lib/03-host-shares.sh;
    etcAndUsersLib       = renderLib ./lib/04-etc-and-users.sh.in;
    networkingLib        = renderLib ./lib/05-networking.sh.in;
    optionalDrivesLib    = renderLib ./lib/06-optional-drives.sh.in;
    servicesAndAgentLib  = renderLib ./lib/07-services-and-agent.sh.in;
    signalHandlersLib    = renderLib ./lib/08-signal-handlers.sh.in;
  };

  # Same pickSubsts treatment as the lib fragments: only pass the
  # substitutions init.sh.in actually mentions. Everything else
  # (`@hostname@`, `@userBlocks@`, …) is consumed by lib fragments
  # before they're inlined here.
  initSource = builtins.readFile ./init.sh.in;
  initSubsts = let all = libSubsts // initLibs; in
    lib.filterAttrs
      (name: _: builtins.any (s: s == name)
        (builtins.filter builtins.isString
          (builtins.concatLists
            (builtins.filter builtins.isList
              (builtins.split "@([a-zA-Z][a-zA-Z0-9_]*)@" initSource)))))
      all;
in
pkgs.replaceVars ./init.sh.in initSubsts

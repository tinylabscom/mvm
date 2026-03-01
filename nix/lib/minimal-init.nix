# Minimal PID 1 init script generator for mvm guests.
#
# Produces a shell script (using busyboxStatic) that replaces systemd
# as PID 1 inside Firecracker microVMs.  No NixOS, no systemd — just
# mount, network, service respawn loops, and the guest agent.
#
# Usage:
#   initScript = import ./minimal-init.nix {
#     inherit pkgs;
#     hostname = "my-vm";
#     users.myuser = { uid = 1000; };          # optional
#     services.my-app = {
#       command = "${pkgs.python3}/bin/python3 -m http.server 8080";
#       preStart = "mkdir -p /tmp/www";         # optional, runs as root
#       env = { FOO = "bar"; };                 # optional
#       user = "myuser";                        # optional, run as this user
#       logFile = "/var/log/my-app.log";        # optional, default: /dev/console
#     };
#     healthChecks.my-app = {
#       healthCmd = "${pkgs.curl}/bin/curl -sf http://localhost:8080/";
#       healthIntervalSecs = 5;
#       healthTimeoutSecs = 3;
#     };
#     guestAgentPkg = mvm-guest-agent;
#   };

{ pkgs
, lib ? pkgs.lib
, busybox ? pkgs.pkgsStatic.busybox
, hostname ? "mvm"
, users ? {}
, services ? {}
, healthChecks ? {}
, guestAgentPkg ? null
}:

let
  bb = busybox;

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

  # Generate /etc/passwd and /etc/group entries + home directory creation.
  mkUserBlock = entry:
    let
      name = entry.name;
      uid = toString entry.uid;
      group = entry.config.group or name;
      home = entry.config.home or "/home/${name}";
    in ''
      grep -q "^${group}:" /etc/group || echo '${group}:x:${uid}:' >> /etc/group
      grep -q "^${name}:" /etc/passwd || echo '${name}:x:${uid}:${uid}:${name}:${home}:${bb}/bin/sh' >> /etc/passwd
      mkdir -p ${home}
      chown ${name}:${group} ${home}
    '';

  userBlocks = lib.concatStringsSep "\n" (map mkUserBlock usersWithUids);

  # Generate a respawn loop for one service.
  mkServiceBlock = name: svc:
    let
      preStart = svc.preStart or "";
      preBlock = lib.optionalString (preStart != "") ''
        echo "[init] preStart for ${name}..." > /dev/console
        ${preStart}
      '';
      envLines = lib.concatStringsSep "\n" (
        lib.mapAttrsToList (k: v: "export ${k}='${v}'") (svc.env or {})
      );
      # Log redirection: logFile or /dev/console.
      redirect = if (svc ? logFile) then
        ">> ${svc.logFile} 2>&1"
      else
        "> /dev/console 2>&1";
      logSetup = lib.optionalString (svc ? logFile) ''
        mkdir -p "$(dirname '${svc.logFile}')"
      '';
      # Command: optionally run as non-root user via su.
      cmdLine = if (svc ? user) then
        "su ${svc.user} -s ${bb}/bin/sh -c '${svc.command}'"
      else
        svc.command;
    in ''
      # --- Service: ${name} ---
      (
        ${envLines}
        ${logSetup}
        ${preBlock}
        RUNNING=1
        trap 'RUNNING=0; kill "$CMD_PID" 2>/dev/null' TERM
        while [ "$RUNNING" = "1" ]; do
          echo "[init] starting ${name}..." > /dev/console
          ${cmdLine} ${redirect} &
          CMD_PID=$!
          wait "$CMD_PID"
          RC=$?
          [ "$RUNNING" = "0" ] && break
          echo "[init] ${name} exited ($RC), restarting in 2s..." > /dev/console
          sleep 2
        done
      ) &
      SERVICE_PIDS="$SERVICE_PIDS $!"
    '';

  # Generate health check JSON for the guest agent.
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
      };
      json = builtins.toJSON obj;
    in ''
      cat > /etc/mvm/integrations.d/${name}.json <<'HEALTHEOF'
      ${json}
      HEALTHEOF
    '';

  serviceBlocks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList mkServiceBlock services
  );

  healthCheckBlocks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList mkHealthCheckFile healthChecks
  );

  guestAgentBlock = lib.optionalString (guestAgentPkg != null) ''
    # --- mvm-guest-agent ---
    (
      RUNNING=1
      trap 'RUNNING=0; kill "$CMD_PID" 2>/dev/null' TERM
      while [ "$RUNNING" = "1" ]; do
        echo "[init] starting mvm-guest-agent..." > /dev/console
        ${guestAgentPkg}/bin/mvm-guest-agent > /dev/console 2>&1 &
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

in
pkgs.writeScript "mvm-minimal-init" ''
  #!${bb}/bin/sh
  # mvm minimal init — PID 1, no systemd.
  # Generated by nix/lib/minimal-init.nix

  export PATH="${bb}/bin"

  # ── 1. Mount virtual filesystems ─────────────────────────────────
  # Mount devtmpfs first so /dev/console is available for logging.
  mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
  mount -t proc proc /proc
  mount -t sysfs sys /sys

  echo "[init] mvm minimal init starting..." > /dev/console

  mkdir -p /dev/pts
  mount -t devpts devpts /dev/pts 2>/dev/null || true
  mount -t tmpfs tmpfs /tmp
  mount -t tmpfs tmpfs /run

  # ── 2. Minimal /etc ──────────────────────────────────────────────
  mkdir -p /etc/mvm/integrations.d
  echo 'root:x:0:0:root:/root:${bb}/bin/sh' > /etc/passwd
  echo 'root:x:0:' > /etc/group
  echo '${hostname}' > /etc/hostname
  hostname '${hostname}'
  cat > /etc/hosts <<'HOSTS'
  127.0.0.1 localhost
  ::1       localhost
  HOSTS
  echo 'hosts: files dns' > /etc/nsswitch.conf

  # ── 2b. Create users and groups ────────────────────────────────
  ${userBlocks}

  # ── 3. Parse kernel cmdline for network config ───────────────────
  MVM_IP="" MVM_GW=""
  for arg in $(cat /proc/cmdline); do
    case "$arg" in
      mvm.ip=*) MVM_IP="''${arg#mvm.ip=}" ;;
      mvm.gw=*) MVM_GW="''${arg#mvm.gw=}" ;;
    esac
  done

  # ── 4. Configure networking ─────────────────────────────────────
  ip link set lo up
  if [ -n "$MVM_IP" ] && [ -n "$MVM_GW" ]; then
    echo "[init] network: eth0 $MVM_IP gw $MVM_GW" > /dev/console
    ip link set eth0 up
    ip addr add "$MVM_IP" dev eth0
    ip route add default via "$MVM_GW"
    echo "nameserver $MVM_GW" > /etc/resolv.conf
  else
    echo "[init] WARNING: no mvm.ip/mvm.gw on cmdline, skipping network" > /dev/console
  fi

  # ── 5. Mount optional drives (best-effort) ──────────────────────
  mkdir -p /mnt/config /mnt/secrets /mnt/data

  mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdb /mnt/config 2>/dev/null && \
    echo "[init] mounted config drive (vdb)" > /dev/console || true

  mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdc /mnt/secrets 2>/dev/null && \
    echo "[init] mounted secrets drive (vdc)" > /dev/console || true

  mount -t ext4 -o noexec,nosuid,nodev /dev/vdd /mnt/data 2>/dev/null && \
    echo "[init] mounted data drive (vdd)" > /dev/console || true

  # ── 6. Write health check integration configs ───────────────────
  ${healthCheckBlocks}

  # ── 7. Start services (respawn loops) ───────────────────────────
  SERVICE_PIDS=""
  ${serviceBlocks}

  # ── 8. Start guest agent ────────────────────────────────────────
  AGENT_PID=""
  ${guestAgentBlock}

  echo "[init] all services started" > /dev/console

  # ── 9. Graceful shutdown handler ────────────────────────────────
  shutdown() {
    echo "[init] shutting down..." > /dev/console
    # Signal all service subshells to stop respawning.
    for pid in $SERVICE_PIDS; do
      kill -TERM "$pid" 2>/dev/null
    done
    [ -n "$AGENT_PID" ] && kill -TERM "$AGENT_PID" 2>/dev/null
    # Grace period for services to clean up.
    sleep 2
    # Force-kill any stragglers.
    for pid in $SERVICE_PIDS $AGENT_PID; do
      kill -KILL "$pid" 2>/dev/null
    done
    sync
    echo "[init] goodbye" > /dev/console
  }

  trap shutdown TERM INT

  # ── 10. PID 1 reaper: wait for children, re-enter on signal ────
  while true; do
    wait
  done
''

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
#       user = "myuser";                        # optional, default: serviceGroup
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
, serviceGroup ? "mvm"
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
      # Add to service group so the user can read /mnt/secrets (0440 root:${serviceGroup}).
      sed -i 's/^${serviceGroup}:x:900:.*$/&,${name}/' /etc/group
      sed -i 's/^${serviceGroup}:x:900:,/${serviceGroup}:x:900:/' /etc/group
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
      # Service env defaults: only set if not already defined (e.g. by
      # --env flags sourced globally from mvm-env.env).  This lets
      # `mvmctl run --env PORT=9000` override `env.PORT = "3100"`.
      envLines = lib.concatStringsSep "\n" (
        lib.mapAttrsToList (k: v: ": \${${k}:='${v}'} ; export ${k}") (svc.env or {})
      );
      # Log redirection: logFile or /dev/console.
      redirect = if (svc ? logFile) then
        ">> ${svc.logFile} 2>&1"
      else
        "> /dev/console 2>&1";
      logSetup = lib.optionalString (svc ? logFile) ''
        mkdir -p "$(dirname '${svc.logFile}')"
      '';
      # Run as the specified user, defaulting to serviceGroup (never root).
      svcUser = svc.user or serviceGroup;
      cmdLine = "su -s ${bb}/bin/sh -c '${svc.command}' ${svcUser}";
    in ''
      # --- Service: ${name} ---
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
      } // lib.optionalAttrs (check ? startupGraceSecs) {
        startup_grace_secs = check.startupGraceSecs;
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
  export SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt

  # ── 1. Mount virtual filesystems ─────────────────────────────────
  # Detect container environment (Docker) — skip kernel-level mounts
  MVM_CONTAINER=0
  if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    MVM_CONTAINER=1
  fi

  if [ "$MVM_CONTAINER" = "0" ]; then
    mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
    mount -t proc proc /proc
    mount -t sysfs sys /sys
  fi

  echo "[init] mvm minimal init starting..." > /dev/console
  [ "$MVM_CONTAINER" = "1" ] && echo "[init] container mode detected" > /dev/console

  # Allow non-root services to write to /dev/console for logging.
  chmod 666 /dev/console 2>/dev/null || true

  if [ "$MVM_CONTAINER" = "0" ]; then
    mkdir -p /dev/pts
    mount -t devpts devpts /dev/pts 2>/dev/null || true
  fi
  mount -t tmpfs tmpfs /tmp 2>/dev/null || true
  mount -t tmpfs tmpfs /run 2>/dev/null || true

  # ── 1b. VirtioFS shared directories (Apple Container dev) ────────
  # If a virtiofs "home" share is available, mount it at /host.
  # This gives dev VMs access to the host's home directory.
  if [ "$MVM_CONTAINER" = "0" ]; then
    mkdir -p /host
    mount -t virtiofs home /host 2>/dev/null && \
      echo "[init] mounted virtiofs share at /host" > /dev/console || true
  fi

  # ── 2. Minimal /etc ──────────────────────────────────────────────
  mkdir -p /etc/mvm/integrations.d
  echo 'root:x:0:0:root:/root:${bb}/bin/sh' > /etc/passwd
  echo 'root:x:0:' > /etc/group
  echo '${hostname}' > /etc/hostname
  hostname '${hostname}'
  printf '127.0.0.1 localhost\n::1 localhost\n' > /etc/hosts
  echo 'hosts: files dns' > /etc/nsswitch.conf

  # ── 2b. Create default service user and custom users ──────────
  # Default non-root user for services (uid 900, below auto-assign range).
  echo '${serviceGroup}:x:900:' >> /etc/group
  echo '${serviceGroup}:x:900:900:${serviceGroup}:/home/${serviceGroup}:${bb}/bin/sh' >> /etc/passwd
  mkdir -p /home/${serviceGroup}
  chown ${serviceGroup}:${serviceGroup} /home/${serviceGroup}
  ${userBlocks}

  # Service PID tracking for post-restore signal.
  mkdir -p /run/mvm-services

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
    # Static IP (Firecracker with TAP networking)
    echo "[init] network: eth0 $MVM_IP gw $MVM_GW" > /dev/console
    ip link set eth0 up
    ip addr add "$MVM_IP" dev eth0
    ip route add default via "$MVM_GW"
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
  else
    # DHCP fallback (Apple Container with VZ NAT, or any NAT environment).
    # Detect the first non-loopback interface (eth0, enp0s1, etc.)
    NET_IF=""
    for iface in eth0 enp0s1 enp0s2 ens1 ens2; do
      if ip link show "$iface" >/dev/null 2>&1; then
        NET_IF="$iface"
        break
      fi
    done
    if [ -z "$NET_IF" ]; then
      # Fallback: pick the first non-lo interface
      NET_IF=$(ip -o link show | grep -v "lo:" | head -1 | sed 's/^[0-9]*: \([^:@]*\).*/\1/')
    fi

    if [ -n "$NET_IF" ]; then
      echo "[init] DHCP on $NET_IF..." > /dev/console
      ip link set "$NET_IF" up 2>/dev/null || true

      # udhcpc script to configure the interface
      cat > /tmp/udhcpc.sh << 'DHCPEOF'
#!/bin/sh
case "$1" in
  bound|renew)
    ip addr flush dev "$interface" 2>/dev/null
    ip addr add "$ip/$mask" dev "$interface" 2>/dev/null
    [ -n "$router" ] && ip route add default via "$router" 2>/dev/null
    [ -n "$dns" ] && echo "nameserver $dns" > /etc/resolv.conf
    ;;
esac
DHCPEOF
      chmod +x /tmp/udhcpc.sh

      if udhcpc -i "$NET_IF" -s /tmp/udhcpc.sh -q -t 10 -n 2>/dev/null; then
        DHCP_IP=$(ip -4 addr show "$NET_IF" 2>/dev/null | grep -o 'inet [^ ]*' | head -1)
        echo "[init] DHCP: $DHCP_IP on $NET_IF" > /dev/console
      else
        echo "[init] DHCP failed on $NET_IF" > /dev/console
      fi
    else
      echo "[init] WARNING: no network interface found" > /dev/console
    fi
  fi

  # ── 5. Mount optional drives (best-effort) ──────────────────────
  mkdir -p /mnt/config /mnt/secrets /mnt/data

  mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdb /mnt/config 2>/dev/null && \
    echo "[init] mounted config drive (vdb)" > /dev/console || true

  mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdc /mnt/secrets 2>/dev/null && {
    echo "[init] mounted secrets drive (vdc)" > /dev/console
    # Copy secrets to tmpfs readable by service group (root:${serviceGroup} 0440).
    # Service users are added to the ${serviceGroup} group automatically.
    mkdir -p /run/mvm-secrets
    cp /mnt/secrets/* /run/mvm-secrets/ 2>/dev/null || true
    chown root:${serviceGroup} /run/mvm-secrets/* 2>/dev/null || true
    chmod 0440 /run/mvm-secrets/* 2>/dev/null || true
    umount /mnt/secrets
    mount --bind /run/mvm-secrets /mnt/secrets
  } || true

  mount -t ext4 -o noexec,nosuid,nodev /dev/vdd /mnt/data 2>/dev/null && \
    echo "[init] mounted data drive (vdd)" > /dev/console || true

  # ── 6. Source global environment variables from config drive ─────
  # Variables injected via `mvmctl run -e KEY=VALUE` are written to
  # mvm-env.env on the config drive.  Source them here so every
  # service inherits them automatically.
  if [ -f /mnt/config/mvm-env.env ]; then
    echo "[init] loading environment from mvm-env.env" > /dev/console
    . /mnt/config/mvm-env.env
  fi

  # ── 7. Write health check integration configs ───────────────────
  ${healthCheckBlocks}

  # ── 8. Start services (respawn loops) ───────────────────────────
  SERVICE_PIDS=""
  ${serviceBlocks}

  # ── 9. Start guest agent ────────────────────────────────────────
  AGENT_PID=""
  ${guestAgentBlock}

  echo "[init] all services started" > /dev/console

  # ── 10. Post-restore handler (SIGUSR1) ─────────────────────────
  # After snapshot restore, the host sends SIGUSR1 via the guest agent.
  # This remounts config/secrets drives (which now have fresh data from
  # -v mounts) and kills service processes so the respawn loops restart
  # them with the new config/secrets.
  post_restore() {
    echo "[init] post-restore: remounting drives..." > /dev/console
    # Kill service processes so respawn loops restart them after remount.
    for pidfile in /run/mvm-services/*.pid; do
      [ -f "$pidfile" ] || continue
      pid=$(cat "$pidfile" 2>/dev/null)
      [ -n "$pid" ] && kill "$pid" 2>/dev/null
    done
    # Remount config drive with fresh data.
    umount /mnt/config 2>/dev/null || true
    mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdb /mnt/config 2>/dev/null && \
      echo "[init] re-mounted config drive" > /dev/console || true
    # Remount secrets drive with tmpfs copy.
    umount /mnt/secrets 2>/dev/null || true
    rm -f /run/mvm-secrets/* 2>/dev/null || true
    mount -t ext4 -o ro,noexec,nosuid,nodev /dev/vdc /mnt/secrets 2>/dev/null && {
      echo "[init] re-mounted secrets drive" > /dev/console
      cp /mnt/secrets/* /run/mvm-secrets/ 2>/dev/null || true
      chown root:${serviceGroup} /run/mvm-secrets/* 2>/dev/null || true
      chmod 0440 /run/mvm-secrets/* 2>/dev/null || true
      umount /mnt/secrets
      mount --bind /run/mvm-secrets /mnt/secrets
    } || true
    # Re-source environment variables (may have changed).
    if [ -f /mnt/config/mvm-env.env ]; then
      . /mnt/config/mvm-env.env
    fi
    echo "[init] post-restore complete, services restarting" > /dev/console
  }
  trap post_restore USR1

  # ── 11. Graceful shutdown handler ───────────────────────────────
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

  # ── 12. PID 1 reaper: wait for children, re-enter on signal ────
  while true; do
    wait
  done
''

# ── 1b. VirtioFS shared directories (Apple Container dev) ────────
# Mount the host's working directory as /root (guest HOME), and
# bind-mount it again at the absolute host path so commands like
# `nix build /Users/foo/proj/...` issued from the host resolve to
# the same files inside the VM. Same treatment for $HOME/.mvm via
# the `datadir` share so dev_build artifact paths round-trip.

if [ "$MVM_CONTAINER" = "0" ]; then
  mkdir -p /root
  mount -t virtiofs workdir /root 2>/dev/null && \
    echo "[init] mounted host workdir at /root" > /dev/console || true

  HOST_WORKDIR=""
  HOST_DATADIR=""
  if [ -r /proc/cmdline ]; then
    for tok in $(cat /proc/cmdline); do
      case "$tok" in
        mvm.workdir=*) HOST_WORKDIR="${tok#mvm.workdir=}" ;;
        mvm.datadir=*) HOST_DATADIR="${tok#mvm.datadir=}" ;;
      esac
    done
  fi

  # Guard the bind-mount target hard: refusing `/`, `/root`, `/proc`,
  # `/sys`, `/dev`, `/etc` and `/nix` prevents pathological cmdlines
  # from clobbering the rootfs. The kernel-cmdline source is treated
  # as untrusted because anyone with kernel-arg access can set it.
  case "$HOST_WORKDIR" in
    ""|"/"|"/root"|"/proc"|"/sys"|"/dev"|"/etc"|"/nix") HOST_WORKDIR="" ;;
  esac
  case "$HOST_WORKDIR" in
    /*/*) ;;                       # require at least one slash beyond /
    *) HOST_WORKDIR="" ;;
  esac
  if [ -n "$HOST_WORKDIR" ]; then
    mkdir -p "$HOST_WORKDIR"
    mount --bind /root "$HOST_WORKDIR" 2>/dev/null && \
      echo "[init] bind-mounted /root at $HOST_WORKDIR" > /dev/console || \
      echo "[init] could not bind-mount /root at $HOST_WORKDIR" > /dev/console
  fi

  case "$HOST_DATADIR" in
    ""|"/"|"/root"|"/proc"|"/sys"|"/dev"|"/etc"|"/nix") HOST_DATADIR="" ;;
  esac
  case "$HOST_DATADIR" in
    /*/*) ;;
    *) HOST_DATADIR="" ;;
  esac
  if [ -n "$HOST_DATADIR" ]; then
    mkdir -p "$HOST_DATADIR"
    mount -t virtiofs datadir "$HOST_DATADIR" 2>/dev/null && \
      echo "[init] mounted host datadir at $HOST_DATADIR" > /dev/console || \
      echo "[init] could not mount datadir VirtioFS share at $HOST_DATADIR" > /dev/console
  fi
fi

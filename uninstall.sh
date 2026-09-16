#!/bin/sh
# mvmctl uninstaller. Removes an installation made by install.sh: the links it
# placed in the install dir, the `current` link, and every release directory
# carrying its marker. An install made by the older installer, which copied
# binaries straight into the install dir, is removed by its known file names.
# `mvmctl env uninstall` runs this same script.
#
# Before removing anything it asks mvmctl to refuse if a machine is running and
# to stop the per-tenant host-agent daemons, each confirmed to be running an
# installed mvm-host-agent first — a PID that names anything else aborts the
# uninstall rather than being signalled. Machines and daemon PIDs are recorded
# under the mvm state directory, so without one there is nothing to ask.
#
# The state directory is removed only with --purge or an interactive yes, and
# only when it is recognisably mvm state; that is checked before anything at all
# is removed.
#
# Exits non-zero when it finds nothing to remove.
#
# Env knobs (the same ones install.sh reads):
#   MVM_INSTALL_DIR        directory for the commands on PATH; default: the one
#                          recorded in the library dir, else ~/.local/bin
#   MVM_INSTALL_LIB_DIR    versioned release directories; default: <MVM_INSTALL_DIR>/../lib/mvm
#   MVM_HOME               the mvm state directory; default: ~/.mvm
#   MVM_UNINSTALL_CHECKER  the mvmctl to ask; `mvmctl env uninstall` sets itself
set -eu

LIB_MARKER=".mvm-lib"
RELEASE_MARKER=".mvm-release"

say() { printf '[mvm] %s\n' "$1"; }
warn() { printf '[mvm] WARN: %s\n' "$1" >&2; }
die() { printf '[mvm] ERROR: %s\n' "$1" >&2; exit 1; }

usage() {
  printf '%s\n' \
    "Usage: uninstall.sh [--purge] [--dry-run] [--force]" \
    "  --purge     also remove the mvm state directory without asking" \
    "  --dry-run   print what would be removed and change nothing" \
    "  --force     skip the running-machine check and daemon shutdown"
}

# The entries of an install made by the installer before release directories,
# in the directory $1, that are safe to treat as mvm's, one per line. That
# installer copied these names straight into the install dir. `mvmctl` must be a
# regular file that reports itself as mvmctl, or this returns 1 and prints
# nothing; `assets` counts only while it holds nothing but the two entitlement
# profiles; every other name must be a regular file. install.sh and
# uninstall.sh carry this function verbatim, and a test holds them equal.
unversioned_install_entries() {
  unversioned_dir="$1"
  if [ ! -f "$unversioned_dir/mvmctl" ] || [ -L "$unversioned_dir/mvmctl" ]; then
    return 0
  fi
  unversioned_reported="$("$unversioned_dir/mvmctl" --version 2>/dev/null || true)"
  case "$unversioned_reported" in
    "mvmctl "*) ;;
    *) return 1 ;;
  esac
  for unversioned_name in mvmctl mvm-hvf-supervisor mvm-libkrun-supervisor mvm-network-endpoint assets; do
    unversioned_entry="$unversioned_dir/$unversioned_name"
    if [ -L "$unversioned_entry" ] || [ ! -e "$unversioned_entry" ]; then
      continue
    fi
    if [ "$unversioned_name" = "assets" ]; then
      [ -d "$unversioned_entry" ] || continue
      unversioned_foreign=""
      for unversioned_asset in "$unversioned_entry"/* "$unversioned_entry"/.[!.]* "$unversioned_entry"/..?*; do
        if [ ! -e "$unversioned_asset" ] && [ ! -L "$unversioned_asset" ]; then
          continue
        fi
        case "${unversioned_asset##*/}" in
          mvmctl.entitlements|mvm-supervisor.entitlements)
            if [ -L "$unversioned_asset" ] || [ ! -f "$unversioned_asset" ]; then
              unversioned_foreign=1
            fi
            ;;
          *) unversioned_foreign=1 ;;
        esac
      done
      [ -z "$unversioned_foreign" ] || continue
    elif [ ! -f "$unversioned_entry" ]; then
      continue
    fi
    printf '%s\n' "$unversioned_name"
  done
}

is_listed() {
  case " $2 " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

PURGE=0
DRY_RUN=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $arg (expected --purge, --dry-run or --force)" ;;
  esac
done

# --- Where install.sh put things ---------------------------------------------

if [ -n "${MVM_INSTALL_LIB_DIR:-}" ]; then
  LIB_DIR="$MVM_INSTALL_LIB_DIR"
  if [ -n "${MVM_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$MVM_INSTALL_DIR"
  elif [ -f "$LIB_DIR/$LIB_MARKER" ]; then
    INSTALL_DIR="$(sed -n 's/^install_dir=//p' "$LIB_DIR/$LIB_MARKER" | head -n1)"
  else
    INSTALL_DIR=""
  fi
  if [ -z "$INSTALL_DIR" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set; set MVM_INSTALL_DIR to the directory mvmctl was installed into"
    INSTALL_DIR="$HOME/.local/bin"
  fi
else
  if [ -z "${MVM_INSTALL_DIR:-}" ] && [ -z "${HOME:-}" ]; then
    die "HOME is not set; set MVM_INSTALL_DIR to the directory mvmctl was installed into"
  fi
  INSTALL_DIR="${MVM_INSTALL_DIR:-$HOME/.local/bin}"
  LIB_DIR="$(dirname "$INSTALL_DIR")/lib/mvm"
fi

# The state directory, resolved as mvm_core::config::mvm_home does in
# crates/mvm-core/src/config.rs: a non-empty MVM_HOME wins, otherwise
# $HOME/.mvm, with /tmp standing in for an unset HOME. One deliberate
# difference: an empty HOME counts as unset here, where mvm_home would resolve
# /.mvm, so that nothing is ever removed on the strength of an empty HOME.
if [ -n "${MVM_HOME:-}" ]; then
  STATE_DIR="$MVM_HOME"
  STATE_DIR_STRICT=1
elif [ -n "${HOME:-}" ]; then
  STATE_DIR="$HOME/.mvm"
  STATE_DIR_STRICT=1
else
  STATE_DIR="/tmp/.mvm"
  STATE_DIR_STRICT=0
fi

# The state directory as written, without trailing slashes. Removing a path
# that ends in a slash follows a symlink; removing this one only unlinks it.
STATE_PATH="$STATE_DIR"
while [ "${STATE_PATH%/}" != "$STATE_PATH" ] && [ -n "${STATE_PATH%/}" ]; do
  STATE_PATH="${STATE_PATH%/}"
done

# Why the state directory must not be removed, or nothing when it may be. The
# judgement is made on the directory the path resolves to, never on the name as
# written. It must be resolvable the way mvm_home_strict resolves it (no /tmp
# stand-in) with a non-empty HOME to compare against; must not be /, the home
# directory, or any directory containing it; and must be mvm state — the
# resolved directory named .mvm, or holding a file only mvm writes: the host
# signing key or an audit chain.
state_dir_refusal() {
  if [ "$STATE_DIR_STRICT" != "1" ]; then
    echo "HOME and MVM_HOME are both unset"
    return 0
  fi
  if [ -z "${HOME:-}" ]; then
    echo "HOME is not set, so it cannot be checked against your home directory"
    return 0
  fi
  if ! state_physical="$(cd "$STATE_PATH" 2>/dev/null && pwd -P)"; then
    echo "it cannot be resolved to a directory"
    return 0
  fi
  if [ "$state_physical" = "/" ]; then
    echo "it is /"
    return 0
  fi
  if ! home_physical="$(cd "$HOME" 2>/dev/null && pwd -P)"; then
    echo "HOME cannot be resolved, so it cannot be checked against your home directory"
    return 0
  fi
  case "$home_physical/" in
    "$state_physical"/*)
      echo "it is your home directory or contains it"
      return 0
      ;;
  esac
  if [ "${state_physical##*/}" = ".mvm" ] \
    || [ -f "$state_physical/keys/host-signer.ed25519" ] \
    || [ -f "$state_physical/state/log/audit.jsonl" ]; then
    return 0
  fi
  for chain in "$state_physical"/audit/*.jsonl; do
    if [ -f "$chain" ]; then
      return 0
    fi
  done
  echo "it does not look like mvm state (not a directory named .mvm, and no host signing key or audit chain)"
}

# Remove the state directory after checking it again: it may have changed since
# the first check, or not have existed then. A symlink is only unlinked; the
# directory it points at is left in place.
remove_state_dir() {
  refusal="$(state_dir_refusal)"
  if [ -n "$refusal" ]; then
    die "refusing to remove $STATE_DIR: $refusal."
  fi
  if [ -L "$STATE_PATH" ]; then
    rm -f "$STATE_PATH"
    say "Removed the link $STATE_PATH; the directory it pointed at is left in place."
  else
    rm -rf "$STATE_PATH"
    say "Removed $STATE_PATH."
  fi
}

if [ "$PURGE" = "1" ] && [ -e "$STATE_DIR" ]; then
  refusal="$(state_dir_refusal)"
  if [ -n "$refusal" ]; then
    die "refusing --purge of $STATE_DIR: $refusal. Nothing was removed."
  fi
fi

SUDO=""
LOCK=""
cleanup() {
  if [ -n "$LOCK" ]; then
    $SUDO rmdir "$LOCK" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run() {
  if [ "$DRY_RUN" = "1" ]; then
    say "would run: $*"
  else
    $SUDO "$@"
  fi
}

# --- What is installed -------------------------------------------------------

LIB_OURS=0
if [ -d "$LIB_DIR" ]; then
  LIB_DIR="$(cd "$LIB_DIR" && pwd -P)"
  if [ -f "$LIB_DIR/$LIB_MARKER" ]; then
    LIB_OURS=1
  else
    warn "$LIB_DIR has no $LIB_MARKER marker, so install.sh did not create it; leaving it untouched."
  fi
fi

HAS_CURRENT=0
LINKS=""
RELEASES=""
if [ "$LIB_OURS" = "1" ]; then
  if [ -L "$LIB_DIR/current" ]; then
    HAS_CURRENT=1
  elif [ -e "$LIB_DIR/current" ]; then
    die "$LIB_DIR/current is not a link, so install.sh did not make it; remove the install by hand."
  fi
  # PATH entries install.sh made: links whose target is this library's
  # `current` entry of the same name. Nothing else in the install dir is touched.
  if [ -d "$INSTALL_DIR" ]; then
    for link in "$INSTALL_DIR"/* "$INSTALL_DIR"/.[!.]*; do
      [ -L "$link" ] || continue
      name="${link##*/}"
      if [ "$(readlink "$link")" = "$LIB_DIR/current/$name" ]; then
        LINKS="$LINKS $name"
      fi
    done
  fi
  for entry in "$LIB_DIR"/[1-9]*-*; do
    if [ -L "$entry" ] || [ ! -d "$entry" ] || [ ! -f "$entry/$RELEASE_MARKER" ]; then
      continue
    fi
    name="${entry##*/}"
    case "${name%%-*}" in *[!0-9]*) continue ;; esac
    case "$name" in *[!A-Za-z0-9._+-]*) continue ;; esac
    RELEASES="$RELEASES $name"
  done
fi

# An install from the installer before release directories, by its known names.
if ! UNVERSIONED="$(unversioned_install_entries "$INSTALL_DIR")"; then
  die "$INSTALL_DIR/mvmctl does not report itself as mvmctl; remove it by hand."
fi
UNVERSIONED="$(printf '%s' "$UNVERSIONED" | tr '\n' ' ')"
if [ -d "$INSTALL_DIR/assets" ] && [ ! -L "$INSTALL_DIR/assets" ] \
  && [ -n "$UNVERSIONED" ] && ! is_listed assets "$UNVERSIONED"; then
  warn "leaving $INSTALL_DIR/assets in place: it holds files mvmctl did not install"
fi

FOUND_INSTALL=0
if [ -n "$LINKS$RELEASES$UNVERSIONED" ] || [ "$HAS_CURRENT" = "1" ]; then
  FOUND_INSTALL=1
fi
if [ "$FOUND_INSTALL" = "0" ] && { [ "$PURGE" != "1" ] || [ ! -e "$STATE_DIR" ]; }; then
  die "no mvmctl installation found in $INSTALL_DIR or $LIB_DIR. Set MVM_INSTALL_DIR and MVM_INSTALL_LIB_DIR to where it was installed."
fi

if [ "$LIB_OURS" = "1" ] && [ ! -w "$LIB_DIR" ]; then
  SUDO="sudo"
fi
if [ -n "$LINKS$UNVERSIONED" ] && [ ! -w "$INSTALL_DIR" ]; then
  SUDO="sudo"
fi
if [ -n "$SUDO" ] && [ "$DRY_RUN" != "1" ]; then
  warn "$INSTALL_DIR or $LIB_DIR not writable — using sudo"
fi

if [ "$LIB_OURS" = "1" ] && [ "$DRY_RUN" != "1" ]; then
  if ! $SUDO mkdir "$LIB_DIR/.install.lock" 2>/dev/null; then
    die "an install or uninstall is in progress (remove $LIB_DIR/.install.lock if none is)"
  fi
  LOCK="$LIB_DIR/.install.lock"
fi

# --- Running machines and daemons --------------------------------------------

if [ ! -e "$STATE_DIR" ]; then
  :
elif [ "$FORCE" = "1" ]; then
  warn "--force: not checking for running machines or stopping host-agent daemons"
else
  CHECKER=""
  if [ -n "${MVM_UNINSTALL_CHECKER:-}" ] && [ -x "$MVM_UNINSTALL_CHECKER" ]; then
    CHECKER="$MVM_UNINSTALL_CHECKER"
  elif [ "$HAS_CURRENT" = "1" ] && [ -x "$LIB_DIR/current/mvmctl" ]; then
    CHECKER="$LIB_DIR/current/mvmctl"
  elif is_listed mvmctl "$UNVERSIONED"; then
    CHECKER="$INSTALL_DIR/mvmctl"
  elif command -v mvmctl >/dev/null 2>&1; then
    CHECKER="$(command -v mvmctl)"
  fi
  if [ -z "$CHECKER" ]; then
    die "no mvmctl is available to check for running machines. Stop them yourself and re-run with --force. Nothing was removed."
  fi
  quiesce_lib=""
  if [ "$LIB_OURS" = "1" ]; then
    quiesce_lib="$LIB_DIR"
  fi
  if [ "$DRY_RUN" = "1" ]; then
    set -- --quiesce --dry-run
  else
    set -- --quiesce
  fi
  if MVM_INSTALL_LIB_DIR="$quiesce_lib" "$CHECKER" env uninstall "$@"; then
    :
  else
    checked=$?
    if [ "$checked" -eq 2 ]; then
      die "$CHECKER predates the pre-uninstall check, so it cannot confirm that no machine is running. Stop any running machines ('mvmctl machine ls', then 'mvmctl machine stop <name>') and host-agent daemons, then re-run with --force. Nothing was removed."
    fi
    die "refusing to uninstall. Nothing was removed."
  fi
fi

# --- Removal ------------------------------------------------------------------

for name in $LINKS; do
  run rm -f "$INSTALL_DIR/$name"
done
if [ "$HAS_CURRENT" = "1" ]; then
  run rm -f "$LIB_DIR/current"
fi
for name in $RELEASES; do
  run rm -rf "${LIB_DIR:?}/$name"
done
for name in $UNVERSIONED; do
  run rm -rf "${INSTALL_DIR:?}/$name"
done
if [ "$LIB_OURS" = "1" ]; then
  run rm -f "$LIB_DIR/$LIB_MARKER"
fi
if [ "$DRY_RUN" != "1" ]; then
  if [ -n "$LOCK" ]; then
    $SUDO rmdir "$LOCK" 2>/dev/null || true
    LOCK=""
  fi
  if [ "$LIB_OURS" = "1" ]; then
    $SUDO rmdir "$LIB_DIR" 2>/dev/null \
      || warn "left $LIB_DIR in place: it holds files install.sh did not create"
  fi
fi
if [ "$FOUND_INSTALL" = "1" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    say "Would remove mvmctl from $INSTALL_DIR and $LIB_DIR."
  else
    say "Removed mvmctl from $INSTALL_DIR and $LIB_DIR."
  fi
fi

# --- State directory ----------------------------------------------------------

[ -e "$STATE_DIR" ] || exit 0

if [ "$PURGE" = "1" ]; then
  if [ "$DRY_RUN" = "1" ]; then
    say "would remove $STATE_PATH"
  else
    remove_state_dir
  fi
  exit 0
fi
if [ "$DRY_RUN" = "1" ]; then
  say "Would keep $STATE_DIR (pass --purge to remove it)."
  exit 0
fi

refusal="$(state_dir_refusal)"
if [ -n "$refusal" ]; then
  say "Kept $STATE_DIR: $refusal."
  exit 0
fi
answer=""
if [ -t 0 ]; then
  printf '[mvm] Also remove %s (machines, images, keys, audit logs)? [y/N] ' "$STATE_DIR"
  read -r answer || answer=""
elif [ -t 1 ] && ( exec </dev/tty ) 2>/dev/null; then
  printf '[mvm] Also remove %s (machines, images, keys, audit logs)? [y/N] ' "$STATE_DIR"
  read -r answer </dev/tty || answer=""
fi
case "$answer" in
  y|Y|yes|YES)
    remove_state_dir
    ;;
  *)
    say "Kept $STATE_DIR. Remove it with: uninstall.sh --purge"
    ;;
esac

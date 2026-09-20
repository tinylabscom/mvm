#!/bin/sh
# mvmctl installer. Downloads the released binary for this platform from
# GitHub releases, verifies its SHA-256 and tag-pinned release signature,
# installs it, and on macOS applies the required VM entitlements.
#
# Layout. Every release is unpacked whole into its own directory and the
# commands on PATH reach it through one `current` link:
#
#   $MVM_INSTALL_LIB_DIR/.mvm-lib             marks the directory as install.sh's
#   $MVM_INSTALL_LIB_DIR/<n>-<version>/       mvmctl, host binaries, assets/,
#                                             and a .mvm-release marker
#   $MVM_INSTALL_LIB_DIR/current              -> <n>-<version>
#   $MVM_INSTALL_DIR/mvmctl                   -> $MVM_INSTALL_LIB_DIR/current/mvmctl
#   $MVM_INSTALL_DIR/<host binary>            -> $MVM_INSTALL_LIB_DIR/current/<host binary>
#
# mvmctl finds its host binaries beside its own executable path. Linux reports
# that path with every link resolved (the versioned directory) and macOS reports
# it as invoked (the link in the install dir), so both places hold the full set.
# An upgrade stages and verifies the new directory, then renames `current` in a
# single step: the set is never observed half-replaced, and any failure before
# the install is reported restores the previous `current`.
#
# Only directories carrying the markers are ever listed, pruned or removed, and
# a library directory that already holds anything without the marker is refused.
#
# Env knobs:
#   MVM_VERSION            pin a release tag (e.g. v0.15.2); default: baked release
#   MVM_INSTALL_DIR        directory for the commands on PATH; default: ~/.local/bin
#   MVM_INSTALL_LIB_DIR    versioned release directories; default: <MVM_INSTALL_DIR>/../lib/mvm
#   MVM_INSTALL_KEEP       complete releases to keep, current included; default: 3
#   MVM_TRUSTED_ARCHIVE_SHA256 trusted archive hash for a non-default fresh install
#   MVM_SKIP_HASH_VERIFY   set to 1 to skip the release-manifest checksum (emergency only)
#   MVM_SKIP_CODESIGN      set to 1 to skip macOS codesign
#   MVM_SKIP_BOOTSTRAP     set to 1 to skip preparing the builder VM
#   MVM_UPDATE_API_URL     override https://api.github.com (tests)
#   MVM_UPDATE_DOWNLOAD_URL override https://github.com (tests)
set -eu

REPO="tinylabscom/mvm"
DEFAULT_VERSION="v0.17.0"
DEFAULT_ARCHIVE_SHA256_AARCH64_APPLE_DARWIN="5fdf95929a90820af6ab4c22cc1a31e5ae6bc5eae2f3b6a795a06986797d0bce"
DEFAULT_ARCHIVE_SHA256_X86_64_UNKNOWN_LINUX_GNU="8fe4115197a3c467465f4b40401e8f01fed1a837dfdf32985336975dab99213f"
DEFAULT_ARCHIVE_SHA256_AARCH64_UNKNOWN_LINUX_GNU="74d1077e6e3b6f5aa2a477f582f7de9bf69dfc48668289c501fd747450515b59"
API_BASE="${MVM_UPDATE_API_URL:-https://api.github.com}"
DL_BASE="${MVM_UPDATE_DOWNLOAD_URL:-https://github.com}"
INSTALL_DIR="${MVM_INSTALL_DIR:-$HOME/.local/bin}"
LIB_DIR="${MVM_INSTALL_LIB_DIR:-$(dirname "$INSTALL_DIR")/lib/mvm}"
KEEP="${MVM_INSTALL_KEEP:-3}"

# Payloads an archive may carry that a standard install deliberately leaves
# out. Older releases bundled the optional libkrun supervisor; installing it
# beside mvmctl would make that backend resolvable on hosts without libkrun.
EXCLUDED_PAYLOADS="mvm-libkrun-supervisor"

# Markers naming what this installer created. uninstall.sh and
# `mvmctl env update` read the same names.
LIB_MARKER=".mvm-lib"
RELEASE_MARKER=".mvm-release"

say() { printf '[mvm] %s\n' "$1"; }
warn() { printf '[mvm] WARN: %s\n' "$1" >&2; }
die() { printf '[mvm] ERROR: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

need curl
need tar

case "$KEEP" in
  ''|*[!0-9]*) die "MVM_INSTALL_KEEP must be a whole number, got: $KEEP" ;;
esac
[ "$KEEP" -ge 1 ] || die "MVM_INSTALL_KEEP must be at least 1"

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin) case "$arch" in
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        # Intel mac is deferred — no x86_64-apple-darwin asset is published
        # yet (Intel-macOS CI runners unavailable). Apple Silicon only.
        x86_64) die "Intel macOS is not supported yet — Apple Silicon macs and Linux only" ;;
        *) die "unsupported macOS arch: $arch" ;;
      esac ;;
    Linux) case "$arch" in
        x86_64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) die "unsupported Linux arch: $arch" ;;
      esac ;;
    *) die "unsupported OS: $os" ;;
  esac
}

resolve_latest_version() {
  curl -fsSL "$API_BASE/repos/$REPO/releases/latest" \
    | grep -m1 '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' \
    | grep . || die "could not resolve latest release tag"
}

download_archive() {
  url="$1"
  destination="$2"
  status="$(curl -sSL -o "$destination" -w '%{http_code}' "$url")" || return 1
  case "$status" in
    2??) return 0 ;;
    404) return 44 ;;
    *) warn "download returned HTTP $status: $url"; return 1 ;;
  esac
}

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    die "need shasum or sha256sum to verify the download"
  fi
}

# An installed mvmctl that can verify a release offline, if there is one. The
# install directory's own copy wins over whatever PATH finds first.
release_verifier() {
  for candidate in "$INSTALL_DIR/mvmctl" "$(command -v mvmctl 2>/dev/null)"; do
    [ -n "$candidate" ] && [ -x "$candidate" ] || continue
    # Match the help text, not the exit status: an mvmctl older than the verb
    # may still exit 0 for a subcommand it does not know.
    if "$candidate" env verify-release --help 2>/dev/null | grep -q -- '--tag'; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
}

default_archive_sha256() {
  case "$TARGET" in
    aarch64-apple-darwin) printf '%s\n' "$DEFAULT_ARCHIVE_SHA256_AARCH64_APPLE_DARWIN" ;;
    x86_64-unknown-linux-gnu) printf '%s\n' "$DEFAULT_ARCHIVE_SHA256_X86_64_UNKNOWN_LINUX_GNU" ;;
    aarch64-unknown-linux-gnu) printf '%s\n' "$DEFAULT_ARCHIVE_SHA256_AARCH64_UNKNOWN_LINUX_GNU" ;;
  esac
}

# A fresh host has no trusted executable capable of checking the Sigstore
# bundle. Authenticate the downloaded archive against a hash carried by this
# installer (or supplied out of band) before running its mvmctl temporarily.
trusted_archive_sha256() {
  hash="${MVM_TRUSTED_ARCHIVE_SHA256:-}"
  if [ -z "$hash" ] && [ "$VERSION" = "$DEFAULT_VERSION" ]; then
    hash="$(default_archive_sha256)"
  fi
  [ -n "$hash" ] || return 0
  printf '%s\n' "$hash" | grep -Eq '^[0-9A-Fa-f]{64}$' \
    || die "trusted archive SHA-256 must be exactly 64 hexadecimal characters"
  printf '%s\n' "$hash" | tr 'A-F' 'a-f'
}

# --- Versioned install -------------------------------------------------------

SUDO=""
LOCK=""
STAGE=""
PREVIOUS=""
LIB_CREATED=0
SWITCHED=0
COMMITTED=0
# Names whose PATH entry this run created where nothing existed.
CREATED_LINKS=""
# Unversioned entries this run preserved in a release directory, and so may
# replace with links.
ADOPTED=""
# Unversioned entries in the install dir that unversioned_install_entries vouches for.
ADOPTABLE=""

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

# Write a marker. `tee` follows a symlink, so whatever sits at the path is
# removed first and the file is always created fresh.
write_file() {
  $SUDO rm -f "$1"
  printf '%s\n' "$2" | $SUDO tee "$1" >/dev/null
}

# Point the link at `$2` to `$1` with a single rename, so a reader sees either
# the old target or the new one. `mv` follows a destination that is a link to a
# directory, so the no-follow flag is required: `-T` on GNU and BusyBox, `-h` on
# BSD and macOS.
replace_link() {
  target="$1"
  link="$2"
  staged="$link.mvm-new.$$"
  $SUDO rm -f "$staged"
  $SUDO ln -s "$target" "$staged" || return 1
  if $SUDO mv -T -f "$staged" "$link" 2>/dev/null \
    || $SUDO mv -h -f "$staged" "$link" 2>/dev/null; then
    return 0
  fi
  $SUDO rm -f "$staged"
  return 1
}

# The release directory `current` names, or nothing.
current_release() {
  if [ -L "$LIB_DIR/current" ]; then
    readlink "$LIB_DIR/current"
  fi
}

# The state a release marker records: `staging` until the release is verified,
# then `complete`. Prints nothing for a directory without the marker.
release_state() {
  if [ -f "$1/$RELEASE_MARKER" ] && [ ! -L "$1" ]; then
    cat "$1/$RELEASE_MARKER"
  fi
}

# Marked release directory names, newest first. The numeric prefix is the
# install order; version strings do not sort. Anything without the marker is
# not install.sh's and is never listed.
list_releases() {
  for entry in "$LIB_DIR"/[1-9]*-*; do
    if [ -L "$entry" ] || [ ! -d "$entry" ] || [ ! -f "$entry/$RELEASE_MARKER" ]; then
      continue
    fi
    name="${entry##*/}"
    case "${name%%-*}" in *[!0-9]*) continue ;; esac
    case "$name" in *[!A-Za-z0-9._+-]*) continue ;; esac
    printf '%s\n' "$name"
  done | sort -t- -k1,1nr
}

# Claim the next release directory and mark it as staging. Numbering follows
# marked releases only; a name already taken by anything is skipped, and `mkdir`
# without `-p` fails rather than reuse one.
claim_release_dir() {
  suffix="$1"
  newest="$(list_releases | head -n1)"
  seq=1
  if [ -n "$newest" ]; then
    seq=$((${newest%%-*} + 1))
  fi
  while [ -e "$LIB_DIR/$seq-$suffix" ] || [ -L "$LIB_DIR/$seq-$suffix" ]; do
    seq=$((seq + 1))
  done
  CLAIMED="$LIB_DIR/$seq-$suffix"
  $SUDO mkdir "$CLAIMED" || die "could not create $CLAIMED"
  write_file "$CLAIMED/$RELEASE_MARKER" "staging" || die "could not mark $CLAIMED"
}

mark_complete() {
  write_file "$1/$RELEASE_MARKER" "complete" || die "could not mark $1 complete"
}

# Top-level entries of a release that belong on PATH: every executable file,
# plus the assets directory mvmctl reads beside itself.
release_entries() {
  for entry in "$1"/*; do
    name="${entry##*/}"
    if [ -f "$entry" ] && [ -x "$entry" ]; then
      printf '%s\n' "$name"
    elif [ "$name" = "assets" ] && [ -d "$entry" ]; then
      printf '%s\n' "$name"
    fi
  done
}

# Entitlement profile for an executable, relative to assets/. Binaries with no
# profile in the release need no entitlement and keep their linker signature.
entitlement_profile() {
  case "$1" in
    mvmctl) echo "mvmctl.entitlements" ;;
    mvm-hvf-supervisor) echo "mvm-supervisor.entitlements" ;;
    *) echo "$1.entitlements" ;;
  esac
}

# Whether a missing profile is an error: the CLI and the HVF supervisor cannot
# launch a VM unsigned.
entitlement_required() {
  case "$1" in
    mvmctl|mvm-hvf-supervisor) return 0 ;;
    *) return 1 ;;
  esac
}

# The macOS entitlement key an executable's role requires — the same key its
# profile in assets/*.entitlements declares. Only defined for names
# entitlement_required knows about.
required_entitlement_key() {
  case "$1" in
    mvmctl) echo "com.apple.security.virtualization" ;;
    mvm-hvf-supervisor) echo "com.apple.security.hypervisor" ;;
  esac
}

# Whether $1 already carries a valid signature granting entitlement key $2, so
# a binary a release already entitled at build time is left alone rather than
# needlessly re-signed — checked before falling back to
# builtin_entitlement_profile below, not before find_entitlement_profile: a
# release that ships a profile is still signed with it as before.
already_entitled() {
  target="$1"
  key="$2"
  codesign --verify --strict "$target" >/dev/null 2>&1 || return 1
  case "$(codesign -d --entitlements - --xml "$target" 2>/dev/null)" in
    *"<key>$key</key>"*) return 0 ;;
    *) return 1 ;;
  esac
}

# Path to a required entitlement profile inside a staged release directory,
# checked under `assets/` first — where install.sh has always written the
# profiles it needs itself, and where a signed rebuild's runtime lookup reads
# them from beside its own executable — then `resources/`, where every
# published release through v0.17.0 shipped them. Prints nothing when the
# profile is in neither location.
find_entitlement_profile() {
  release_root="$1"
  profile_name="$2"
  if [ -f "$release_root/assets/$profile_name" ]; then
    printf '%s\n' "$release_root/assets/$profile_name"
  elif [ -f "$release_root/resources/$profile_name" ]; then
    printf '%s\n' "$release_root/resources/$profile_name"
  fi
}

# Copy a profile found under resources/ into assets/, so the release
# directory always carries it at the one path codesign — and any later
# re-sign — reads it from.
adopt_resources_entitlement() {
  release_root="$1"
  profile_name="$2"
  $SUDO mkdir -p "$release_root/assets" \
    && $SUDO cp "$release_root/resources/$profile_name" "$release_root/assets/$profile_name"
}

# The one entitlement profile install.sh carries a fallback copy of,
# byte-identical to the checked-in assets/mvm-supervisor.entitlements in this
# repo (a test holds them equal). Prints nothing and fails for any other name
# — deliberately not mvmctl.entitlements: that profile has shipped somewhere
# (resources/ or assets/) in every mvmctl release ever published, so a
# release missing it too would be a data problem worth failing closed on
# rather than papering over.
#
# Last-resort only: used when a release ships mvm-supervisor.entitlements at
# neither assets/ nor resources/ and the shipped mvm-hvf-supervisor is not
# already signed with the key it needs. Every published release through
# v0.17.0 is in that position — the file did not exist anywhere until #2322,
# a month after v0.17.0 shipped — so without this an unmodified v0.17.0
# archive cannot install on Apple Silicon no matter where install.sh looks
# for a profile that release never carried. The content is a fixed,
# non-secret, two-line capability declaration matching what install.sh's own
# ad-hoc `codesign --sign -` already grants for every other release;
# embedding it does not extend trust anywhere the local signing step does
# not already reach, and it changes nothing about how the downloaded archive
# itself is authenticated.
builtin_entitlement_profile() {
  case "$1" in
    mvm-supervisor.entitlements)
      printf '%s\n' \
        '<?xml version="1.0" encoding="UTF-8"?>' \
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
        '<plist version="1.0">' \
        '<dict>' \
        '	<key>com.apple.security.hypervisor</key>' \
        '	<true/>' \
        '</dict>' \
        '</plist>'
      ;;
    *) return 1 ;;
  esac
}

# Write install.sh's own copy of a profile into assets/, for a release that
# ships it at neither location. Fails without writing anything for a name
# builtin_entitlement_profile does not recognise.
adopt_builtin_entitlement() {
  release_root="$1"
  profile_name="$2"
  content="$(builtin_entitlement_profile "$profile_name")" || return 1
  $SUDO mkdir -p "$release_root/assets" || return 1
  printf '%s\n' "$content" | $SUDO tee "$release_root/assets/$profile_name" >/dev/null
}

prepare_dirs() {
  if [ ! -e "$LIB_DIR" ] && [ ! -L "$LIB_DIR" ]; then
    LIB_CREATED=1
  fi
  mkdir -p "$INSTALL_DIR" "$LIB_DIR" 2>/dev/null || true
  # `mkdir -p` on an existing dir returns 0 regardless of ownership, so it
  # can't double as a writability probe — test -w directly, then sudo-mkdir
  # only on the not-writable path (e.g. MVM_INSTALL_DIR=/usr/local/bin).
  if [ -d "$INSTALL_DIR" ] && [ -w "$INSTALL_DIR" ] \
    && [ -d "$LIB_DIR" ] && [ -w "$LIB_DIR" ]; then
    SUDO=""
  else
    warn "$INSTALL_DIR or $LIB_DIR not writable — using sudo"
    SUDO="sudo"
    $SUDO mkdir -p "$INSTALL_DIR" "$LIB_DIR"
  fi
  # Link targets are absolute, so resolve both directories once.
  LIB_DIR="$(cd "$LIB_DIR" && pwd -P)"
  INSTALL_DIR_PHYSICAL="$(cd "$INSTALL_DIR" && pwd -P)"

  if [ ! -f "$LIB_DIR/$LIB_MARKER" ] && [ -n "$(ls -A "$LIB_DIR")" ]; then
    die "refusing to install into $LIB_DIR: it already holds files and was not created by install.sh. Set MVM_INSTALL_LIB_DIR to a new or empty directory."
  fi
  if [ -e "$LIB_DIR/current" ] && [ ! -L "$LIB_DIR/current" ]; then
    die "refusing to install: $LIB_DIR/current is not a link, so it was not made by install.sh"
  fi
}

acquire_lock() {
  LOCK="$LIB_DIR/.install.lock"
  if ! $SUDO mkdir "$LOCK" 2>/dev/null; then
    LOCK=""
    die "another install or uninstall is in progress (remove $LIB_DIR/.install.lock if none is)"
  fi
  write_file "$LIB_DIR/$LIB_MARKER" "install_dir=$INSTALL_DIR_PHYSICAL" \
    || die "could not mark $LIB_DIR"
}

# A crashed run can leave its temporary links behind. They are this
# installer's by name, and the lock rules out a run still using one.
remove_stale_temp_links() {
  for entry in "$LIB_DIR"/*.mvm-new.[0-9]* "$INSTALL_DIR"/*.mvm-new.[0-9]*; do
    if [ -L "$entry" ]; then
      $SUDO rm -f "$entry"
    fi
  done
}

# Carry an install made before release directories existed into one, so the
# first upgrade from it can be rolled back like any other. Repeatable: a run
# that failed after adopting reuses the directory it made. Only the entries
# unversioned_install_entries vouches for are carried; anything else in the way
# was refused by check_link_conflicts before this runs.
adopt_unversioned_install() {
  [ -n "$ADOPTABLE" ] || return 0
  case "$PREVIOUS" in
    "$LIB_DIR"/[1-9]*-unversioned) adopted_dir="$PREVIOUS" ;;
    *)
      claim_release_dir "unversioned"
      adopted_dir="$CLAIMED"
      ;;
  esac
  for name in $ADOPTABLE; do
    entry="$INSTALL_DIR/$name"
    $SUDO rm -rf "${adopted_dir:?}/$name"
    $SUDO cp -Rp "$entry" "$adopted_dir/$name" \
      || die "could not preserve $entry"
    ADOPTED="$ADOPTED $name"
  done
  mark_complete "$adopted_dir"
  if [ "$PREVIOUS" != "$adopted_dir" ]; then
    replace_link "$adopted_dir" "$LIB_DIR/current" \
      || die "could not record the existing install in $LIB_DIR"
    PREVIOUS="$adopted_dir"
    say "Preserved the existing install as $adopted_dir"
  fi
}

stage_release() {
  claim_release_dir "$VERSION"
  STAGE="$CLAIMED"
  $SUDO cp -R "$SRC/." "$STAGE/" || die "could not copy the release into $STAGE"
  for payload in $EXCLUDED_PAYLOADS; do
    $SUDO rm -rf "${STAGE:?}/$payload"
  done
  [ -x "$STAGE/mvmctl" ] || die "release is missing an executable mvmctl"
}

# Refuse, before anything is adopted or staged, if a PATH entry the release
# needs is a file or directory install.sh did not make and cannot vouch for as
# the older installer's.
check_link_conflicts() {
  for name in $(release_entries "$SRC"); do
    if is_listed "$name" "$EXCLUDED_PAYLOADS"; then
      continue
    fi
    link="$INSTALL_DIR/$name"
    if [ -e "$link" ] && [ ! -L "$link" ] && ! is_listed "$name" "$ADOPTABLE"; then
      die "refusing to replace $link: install.sh did not create it. Move it aside and re-run."
    fi
  done
}

# macOS: every executable on the VM launch path must carry its role-specific
# entitlement. Treat this as part of installation integrity: a successful
# install must be ready to launch a VM without a hidden first-run repair.
sign_release() {
  [ "$(uname -s)" = "Darwin" ] || return 0
  if [ "${MVM_SKIP_CODESIGN:-}" = "1" ]; then
    warn "MVM_SKIP_CODESIGN=1 — skipping macOS VM entitlement signing"
    return 0
  fi
  command -v codesign >/dev/null 2>&1 || die "codesign is required on macOS"
  for name in $(release_entries "$STAGE"); do
    [ -f "$STAGE/$name" ] || continue
    profile_name="$(entitlement_profile "$name")"
    profile="$(find_entitlement_profile "$STAGE" "$profile_name")"
    if [ -z "$profile" ]; then
      if ! entitlement_required "$name"; then
        continue
      fi
      if already_entitled "$STAGE/$name" "$(required_entitlement_key "$name")"; then
        say "Already entitled: $name"
        continue
      fi
      if adopt_builtin_entitlement "$STAGE" "$profile_name"; then
        profile="$STAGE/assets/$profile_name"
      else
        die "missing entitlement profile: $STAGE/assets/$profile_name"
      fi
    fi
    case "$profile" in
      "$STAGE/resources/"*)
        adopt_resources_entitlement "$STAGE" "$profile_name" \
          || die "could not install $profile_name from resources/ into assets/"
        profile="$STAGE/assets/$profile_name"
        ;;
    esac
    output="$($SUDO codesign --sign - --force --entitlements "$profile" "$STAGE/$name" 2>&1)" \
      || die "codesign failed for $STAGE/$name: $output"
    say "Codesigned: $name"
  done
}

# Create the PATH entries a release needs. Each points through `current`, so
# an entry already in place survives every later upgrade untouched. A link that
# pointed elsewhere is recorded so a rollback can put it back.
link_release() {
  mkdir -p "$TMP/replaced-links"
  for name in $(release_entries "$STAGE"); do
    link="$INSTALL_DIR/$name"
    target="$LIB_DIR/current/$name"
    if [ -L "$link" ]; then
      previous_target="$(readlink "$link")"
      if [ "$previous_target" = "$target" ]; then
        continue
      fi
      printf '%s' "$previous_target" > "$TMP/replaced-links/$name"
    elif [ -d "$link" ]; then
      is_listed "$name" "$ADOPTED" || die "refusing to replace $link"
      $SUDO rm -rf "$link"
    elif [ ! -e "$link" ]; then
      CREATED_LINKS="$CREATED_LINKS $name"
    fi
    replace_link "$target" "$link" || die "could not link $link"
  done
}

# Remove PATH entries that point through `current` at a name the current
# release no longer carries, and unversioned files this run preserved but the
# release does not replace.
unlink_dropped_entries() {
  for link in "$INSTALL_DIR"/* "$INSTALL_DIR"/.[!.]*; do
    [ -L "$link" ] || continue
    name="${link##*/}"
    if [ "$(readlink "$link")" = "$LIB_DIR/current/$name" ] \
      && [ ! -e "$LIB_DIR/current/$name" ]; then
      $SUDO rm -f "$link"
    fi
  done
  for name in $ADOPTED; do
    if [ -e "$INSTALL_DIR/$name" ] && [ ! -L "$INSTALL_DIR/$name" ]; then
      $SUDO rm -rf "${INSTALL_DIR:?}/$name"
    fi
  done
}

# Keep the newest complete releases, current always among them. A marked
# directory still `staging` belongs to a run that never finished, so it is
# removed and never counted.
prune_releases() {
  active="$(current_release)"
  kept=0
  for name in $(list_releases); do
    dir="$LIB_DIR/$name"
    if [ "$dir" = "$active" ]; then
      kept=$((kept + 1))
      continue
    fi
    if [ "$(release_state "$dir")" = "complete" ] && [ "$kept" -lt "$KEEP" ]; then
      kept=$((kept + 1))
      continue
    fi
    $SUDO rm -rf "${LIB_DIR:?}/$name"
  done
}

rollback() {
  if [ "$SWITCHED" = "1" ]; then
    if [ -n "$PREVIOUS" ]; then
      replace_link "$PREVIOUS" "$LIB_DIR/current" \
        || warn "could not restore $LIB_DIR/current -> $PREVIOUS"
    else
      $SUDO rm -f "$LIB_DIR/current"
    fi
  fi
  for recorded in "$TMP/replaced-links"/*; do
    [ -f "$recorded" ] || continue
    name="${recorded##*/}"
    replace_link "$(cat "$recorded")" "$INSTALL_DIR/$name" \
      || warn "could not restore $INSTALL_DIR/$name"
  done
  for name in $CREATED_LINKS; do
    if [ -L "$INSTALL_DIR/$name" ]; then
      $SUDO rm -f "$INSTALL_DIR/$name"
    fi
  done
  if [ -n "$STAGE" ]; then
    $SUDO rm -rf "$STAGE"
  fi
  if [ -n "$PREVIOUS" ]; then
    warn "install failed — $INSTALL_DIR/mvmctl still runs the previous release ($PREVIOUS)"
  fi
}

finish() {
  status=$?
  if [ "$COMMITTED" != "1" ] && [ -n "$LOCK" ]; then
    rollback || true
  fi
  if [ -n "$LOCK" ]; then
    $SUDO rmdir "$LOCK" 2>/dev/null || true
  fi
  # A first install that failed leaves no library directory behind.
  if [ "$COMMITTED" != "1" ] && [ "$LIB_CREATED" = "1" ] && [ -n "$LOCK" ] \
    && [ ! -L "$LIB_DIR/current" ] && [ -z "$(list_releases)" ]; then
    $SUDO rm -f "$LIB_DIR/$LIB_MARKER"
    $SUDO rmdir "$LIB_DIR" 2>/dev/null || true
  fi
  rm -rf "$TMP"
  exit "$status"
}

TARGET="$(detect_target)"
VERSION="${MVM_VERSION:-$DEFAULT_VERSION}"
ARCHIVE="mvmctl-${TARGET}.tar.gz"
REL="$DL_BASE/$REPO/releases/download/$VERSION"

TMP="$(mktemp -d)"
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

say "Installing mvmctl $VERSION ($TARGET) to $INSTALL_DIR"

if download_archive "$REL/$ARCHIVE" "$TMP/$ARCHIVE"; then
  :
else
  download_status="$?"
  if [ "$download_status" -eq 44 ] && [ -z "${MVM_VERSION:-}" ]; then
    warn "baked release $VERSION was not found — resolving the latest release"
    VERSION="$(resolve_latest_version)"
    REL="$DL_BASE/$REPO/releases/download/$VERSION"
    say "Installing mvmctl $VERSION ($TARGET) to $INSTALL_DIR"
    download_archive "$REL/$ARCHIVE" "$TMP/$ARCHIVE" \
      || die "download failed: $REL/$ARCHIVE"
  else
    die "download failed: $REL/$ARCHIVE"
  fi
fi

case "$VERSION" in
  ''|*[!A-Za-z0-9._+-]*) die "release tag is not a safe directory name: $VERSION" ;;
esac

got="$(sha256_of "$TMP/$ARCHIVE")"
if [ "${MVM_SKIP_HASH_VERIFY:-}" = "1" ]; then
  warn "MVM_SKIP_HASH_VERIFY=1 — skipping checksum verification"
else
  curl -fsSL "$REL/checksums-sha256.txt" -o "$TMP/checksums.txt" \
    || die "could not download checksums-sha256.txt"
  want="$(grep " $ARCHIVE\$" "$TMP/checksums.txt" | awk '{print $1}' | head -n1)"
  [ -n "$want" ] || die "no checksum for $ARCHIVE in checksums-sha256.txt"
  if [ "$want" != "$got" ]; then
    rm -f "$TMP/$ARCHIVE"
    die "checksum mismatch for $ARCHIVE (want $want, got $got)"
  fi
  say "Checksum verified."
fi

# Signature. An installed mvmctl verifies offline against its embedded trust
# root and is preferred to cosign. A fresh host authenticates the archive
# against the installer-baked hash before running only its mvmctl as a temporary
# verifier. Every path requires the bundle; there is no unsigned fallback.
VERIFIER="$(release_verifier)"
if [ -z "$VERIFIER" ] && ! command -v cosign >/dev/null 2>&1; then
  trusted_hash="$(trusted_archive_sha256)"
  [ -n "$trusted_hash" ] \
    || die "fresh install requires a trusted archive SHA-256; use the baked default, install cosign, or set MVM_TRUSTED_ARCHIVE_SHA256 from an independent trusted source"
  [ "$got" = "$trusted_hash" ] \
    || die "trusted archive SHA-256 mismatch for $ARCHIVE (want $trusted_hash, got $got)"

  bootstrap_dir="$TMP/bootstrap-verifier"
  mkdir -p "$bootstrap_dir"
  tar xzf "$TMP/$ARCHIVE" -C "$bootstrap_dir" "mvmctl-${TARGET}/mvmctl" \
    || die "could not extract the authenticated bootstrap verifier"
  VERIFIER="$bootstrap_dir/mvmctl-${TARGET}/mvmctl"
  [ -x "$VERIFIER" ] || die "authenticated archive contains no executable mvmctl verifier"
  "$VERIFIER" env verify-release --help 2>/dev/null | grep -q -- '--tag' \
    || die "authenticated archive's mvmctl cannot verify release signatures"
fi

curl -fsSL "$REL/$ARCHIVE.bundle" -o "$TMP/$ARCHIVE.bundle" 2>/dev/null \
  || die "no signature bundle published for $ARCHIVE"

if [ -n "$VERIFIER" ]; then
  "$VERIFIER" env verify-release "$TMP/$ARCHIVE" --tag "$VERSION" >/dev/null \
    || die "signature verification failed for $ARCHIVE"
  say "Signature verified."
elif command -v cosign >/dev/null 2>&1; then
  if cosign verify-blob \
      --bundle "$TMP/$ARCHIVE.bundle" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
      "$TMP/$ARCHIVE" >/dev/null 2>&1; then
    say "Signature verified."
  else
    die "cosign signature verification failed for $ARCHIVE"
  fi
else
  die "no release signature verifier is available"
fi

tar xzf "$TMP/$ARCHIVE" -C "$TMP"
SRC="$TMP/mvmctl-${TARGET}"
[ -f "$SRC/mvmctl" ] || die "archive missing mvmctl-${TARGET}/mvmctl"

prepare_dirs
acquire_lock
remove_stale_temp_links
PREVIOUS="$(current_release)"
if ! ADOPTABLE="$(unversioned_install_entries "$INSTALL_DIR")"; then
  die "refusing to replace $INSTALL_DIR/mvmctl: it does not report itself as mvmctl. Move it aside and re-run."
fi
ADOPTABLE="$(printf '%s' "$ADOPTABLE" | tr '\n' ' ')"
check_link_conflicts
adopt_unversioned_install
stage_release
sign_release

expected_version="$("$STAGE/mvmctl" --version)" \
  || die "the new mvmctl failed to run; the previous install is unchanged"
mark_complete "$STAGE"

link_release
replace_link "$STAGE" "$LIB_DIR/current" || die "could not switch $LIB_DIR/current"
SWITCHED=1

installed_version="$("$INSTALL_DIR/mvmctl" --version)" \
  || die "$INSTALL_DIR/mvmctl failed to run after the switch"
[ "$installed_version" = "$expected_version" ] \
  || die "$INSTALL_DIR/mvmctl reports '$installed_version', expected '$expected_version'"

COMMITTED=1
unlink_dropped_entries
prune_releases

for name in $(release_entries "$STAGE"); do
  say "Installed: $INSTALL_DIR/$name"
done
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "Add to PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

# Prepare the builder VM and workload kernel ahead of the first machine run
# instead of paying their one-time download/build cost on the launch path. Opt out with
# MVM_SKIP_BOOTSTRAP=1 (bandwidth-limited, headless, or CI installs).
# `mvmctl bootstrap` also honors the finer MVM_SKIP_DEV_IMAGE_PREFETCH knob.
# Non-fatal and outside the atomic step: the binaries are already verified, and
# what bootstrap prepares lives in the mvm state directory rather than in the
# release directory, so a network failure here is no reason to roll back.
if [ "${MVM_SKIP_BOOTSTRAP:-}" != "1" ]; then
  say "Preparing the builder VM and workload kernel for your first machine run (skip with MVM_SKIP_BOOTSTRAP=1)..."
  if "$INSTALL_DIR/mvmctl" bootstrap; then
    say "Builder VM and workload kernel ready."
  else
    warn "bootstrap failed — the first machine command will retry, or re-run 'mvmctl bootstrap' now."
  fi
else
  say "Skipping bootstrap — run 'mvmctl bootstrap' before your first machine command for a ready first run."
fi

say "Run 'mvmctl doctor' to check your host."

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
#                                             guest-runtime/, and a .mvm-release
#                                             marker
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
# The release's guest runtime (mvm-guest-bins-<version>.tar.gz, the programs
# and libraries mvmctl runs inside a guest) is verified the way the mvmctl
# archive is and staged in the release directory's guest-runtime/, so the CLI
# and its own guest runtime switch together. A release that predates the asset
# installs without it.
#
# Only directories carrying the markers are ever listed, pruned or removed, and
# a library directory that already holds anything without the marker is refused.
#
# Env knobs:
#   MVM_VERSION            pin a release tag (e.g. v0.15.2); default: the newest
#                          stable CLI release, or the baked release when the
#                          releases API cannot be reached
#   MVM_INSTALL_DIR        directory for the commands on PATH; default: ~/.local/bin
#   MVM_INSTALL_LIB_DIR    versioned release directories; default: <MVM_INSTALL_DIR>/../lib/mvm
#   MVM_INSTALL_KEEP       complete releases to keep, current included; default: 3
#   MVM_INSTALL_BACKEND    backend to stage (e.g. libkrun); default: auto-detect,
#                          same as --backend
#   MVM_TRUSTED_ARCHIVE_SHA256 optional independent archive hash for a fresh install
#   MVM_TRUSTED_COSIGN_SHA256 trusted bootstrap-cosign hash override (rotation only)
#   MVM_SKIP_HASH_VERIFY   set to 1 to skip the release-manifest checksum (emergency only)
#   MVM_SKIP_CODESIGN      set to 1 to skip macOS codesign
#   MVM_SKIP_BOOTSTRAP     set to 1 to skip preparing the builder VM
#   MVM_UPDATE_API_URL     override https://api.github.com (tests)
#   MVM_UPDATE_DOWNLOAD_URL override https://github.com (tests)
#   MVM_COSIGN_DOWNLOAD_URL override the pinned cosign release base (tests)
#   MVM_INSTALL_TTY        answer file to read the backend picker's reply from
#                          instead of /dev/tty; empty means no terminal (tests)
set -eu

REPO="tinylabscom/mvm"
DEFAULT_VERSION="v0.22.0"
DEFAULT_ARCHIVE_SHA256_AARCH64_APPLE_DARWIN="1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69"
DEFAULT_ARCHIVE_SHA256_X86_64_UNKNOWN_LINUX_GNU="502e84ea3fa1ff04b0138fb6c3cb47b3a72c730d72c8f468df55e01d99c94d64"
DEFAULT_ARCHIVE_SHA256_AARCH64_UNKNOWN_LINUX_GNU="dafb1d9ebb9480b26841c772bee6322015b727b8cc2bc67d82056631101122f9"
COSIGN_VERSION="v3.1.3"
COSIGN_SHA256_AARCH64_APPLE_DARWIN="5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76"
COSIGN_SHA256_X86_64_UNKNOWN_LINUX_GNU="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_SHA256_AARCH64_UNKNOWN_LINUX_GNU="c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"
API_BASE="${MVM_UPDATE_API_URL:-https://api.github.com}"
DL_BASE="${MVM_UPDATE_DOWNLOAD_URL:-https://github.com}"
COSIGN_BASE="${MVM_COSIGN_DOWNLOAD_URL:-https://github.com/sigstore/cosign/releases/download}"
INSTALL_DIR="${MVM_INSTALL_DIR:-$HOME/.local/bin}"
LIB_DIR="${MVM_INSTALL_LIB_DIR:-$(dirname "$INSTALL_DIR")/lib/mvm}"
KEEP="${MVM_INSTALL_KEEP:-3}"

# What staging drops from the extracted archive, and the backend this host
# ends up with. Both are computed from the archive's components.tsv after
# extraction (select_backend_components); archives predating that file fall
# back to the rule they were published with: the libkrun compatibility tier
# stages on macOS hosts older than 26 and drops out on 26+ and on Linux. The
# installer-compat lane reads the legacy list by name.
PRUNE_PAYLOADS=""
SELECTED_BACKEND=""
LEGACY_LIBKRUN_TIER_PAYLOADS="mvm-libkrun-supervisor lib licenses sources SOURCE-OFFER.txt SOURCE-PINS"

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

# Options: --backend <name> stages that backend's components instead of the
# auto-detected tier (scripted installs; MVM_INSTALL_BACKEND is equivalent).
BACKEND_REQUESTED="${MVM_INSTALL_BACKEND:-}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --backend)
      shift
      BACKEND_REQUESTED="${1:-}"
      [ -n "$BACKEND_REQUESTED" ] || die "missing value for --backend"
      ;;
    --backend=*) BACKEND_REQUESTED="${1#--backend=}" ;;
    *) die "unknown argument: $1 (usage: install.sh [--backend <name>])" ;;
  esac
  shift
done

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

# The newest stable CLI release in a GitHub releases-list response on stdin
# that publishes the archive named $1, as a tag. Prints nothing when none does.
#
# Only `v<major>.<minor>.<patch>` tags are CLI releases: the repository also
# publishes other trains (`boot-image/v*`, `revocations`), and GitHub's own
# "latest" marker has pointed at one of those, so it is never consulted.
# Drafts and prereleases are skipped. A prerelease is either a release
# candidate or a stable tag the release workflow has not yet promoted, which
# it does only once a fresh install of that tag has booted a microVM; pin one
# with MVM_VERSION. The newest is decided by version, not by publication
# order, so a patch to an older line never displaces a newer release.
#
# No JSON tool can be assumed on a fresh host, so the response is split into
# tokens (strings, punctuation, literals; numbers are not needed) and walked
# by nesting depth: a release is an object at depth 2, and its assets are the
# objects at depth 4. Key order and formatting do not matter, and a quote
# escaped inside a string cannot end it.
newest_cli_release() {
  grep -oE '"([^"\\]|\\.)*"|[][{}:,]|true|false|null' \
    | awk -v archive="$1" '
        function flush() {
          if (tag ~ /^v[0-9]+[.][0-9]+[.][0-9]+$/ && draft == "false" && prerelease == "false" && published) {
            print substr(tag, 2)
          }
          tag = ""; draft = ""; prerelease = ""; published = 0
        }
        $0 == "{" || $0 == "[" {
          depth++; kind[depth] = $0; key[depth] = ""; wantkey = ($0 == "{"); next
        }
        $0 == "}" || $0 == "]" {
          if (depth == 2 && $0 == "}") flush()
          depth--; wantkey = 0; next
        }
        $0 == ":" { wantkey = 0; next }
        $0 == "," { wantkey = (kind[depth] == "{"); next }
        {
          token = $0
          if (token ~ /^"/) token = substr(token, 2, length(token) - 2)
          if (wantkey) { key[depth] = token; next }
          if (depth == 2 && key[2] == "tag_name") tag = token
          else if (depth == 2 && key[2] == "draft") draft = token
          else if (depth == 2 && key[2] == "prerelease") prerelease = token
          else if (depth == 4 && key[4] == "name" && token == archive) published = 1
        }' \
    | sort -t. -k1,1n -k2,2n -k3,3n \
    | tail -n 1 \
    | sed 's/^/v/'
}

# The newest stable CLI release publishing this platform's archive. Fails when
# the releases API cannot be reached; prints nothing when it answers without
# one.
resolve_latest_version() {
  releases="$(curl -fsSL --connect-timeout 10 --max-time 60 \
    "$API_BASE/repos/$REPO/releases?per_page=100")" || return 1
  printf '%s\n' "$releases" | newest_cli_release "$ARCHIVE"
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

cosign_asset() {
  case "$TARGET" in
    aarch64-apple-darwin) printf '%s\n' "cosign-darwin-arm64" ;;
    x86_64-unknown-linux-gnu) printf '%s\n' "cosign-linux-amd64" ;;
    aarch64-unknown-linux-gnu) printf '%s\n' "cosign-linux-arm64" ;;
  esac
}

trusted_cosign_sha256() {
  hash="${MVM_TRUSTED_COSIGN_SHA256:-}"
  if [ -z "$hash" ]; then
    case "$TARGET" in
      aarch64-apple-darwin) hash="$COSIGN_SHA256_AARCH64_APPLE_DARWIN" ;;
      x86_64-unknown-linux-gnu) hash="$COSIGN_SHA256_X86_64_UNKNOWN_LINUX_GNU" ;;
      aarch64-unknown-linux-gnu) hash="$COSIGN_SHA256_AARCH64_UNKNOWN_LINUX_GNU" ;;
    esac
  fi
  printf '%s\n' "$hash" | grep -Eq '^[0-9A-Fa-f]{64}$' \
    || die "trusted cosign SHA-256 must be exactly 64 hexadecimal characters"
  printf '%s\n' "$hash" | tr 'A-F' 'a-f'
}

bootstrap_cosign() {
  asset="$(cosign_asset)"
  path="$TMP/cosign"
  curl -fsSL "$COSIGN_BASE/$COSIGN_VERSION/$asset" -o "$path" \
    || die "could not download the pinned signature verifier"
  want_cosign="$(trusted_cosign_sha256)"
  got_cosign="$(sha256_of "$path")"
  [ "$got_cosign" = "$want_cosign" ] \
    || die "trusted cosign SHA-256 mismatch (want $want_cosign, got $got_cosign)"
  chmod 0700 "$path"
  printf '%s\n' "$path"
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
  for payload in $PRUNE_PAYLOADS; do
    $SUDO rm -rf "${STAGE:?}/$payload"
  done
  [ -x "$STAGE/mvmctl" ] || die "release is missing an executable mvmctl"
}

# Refuse, before anything is adopted or staged, if a PATH entry the release
# needs is a file or directory install.sh did not make and cannot vouch for as
# the older installer's.
check_link_conflicts() {
  for name in $(release_entries "$SRC"); do
    if is_listed "$name" "$PRUNE_PAYLOADS"; then
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
    if codesign --verify --strict "$STAGE/$name" >/dev/null 2>&1 \
        && codesign -dvv "$STAGE/$name" 2>&1 | grep -q '^Authority=Developer ID Application:'; then
      if entitlement_required "$name" \
          && ! already_entitled "$STAGE/$name" "$(required_entitlement_key "$name")"; then
        die "Developer ID signed $name is missing its required entitlement; refusing to replace its signature"
      fi
      say "Preserved Developer ID signature: $name"
      continue
    fi
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

# Hold a downloaded release asset in $TMP to the digest the release's checksum
# manifest records for it.
verify_release_checksum() {
  asset="$1"
  got="$(sha256_of "$TMP/$asset")"
  if [ "${MVM_SKIP_HASH_VERIFY:-}" = "1" ]; then
    warn "MVM_SKIP_HASH_VERIFY=1 — skipping checksum verification of $asset"
    return 0
  fi
  if [ ! -f "$TMP/checksums.txt" ]; then
    curl -fsSL "$REL/checksums-sha256.txt" -o "$TMP/checksums.txt" \
      || die "could not download checksums-sha256.txt"
  fi
  want="$(grep " $asset\$" "$TMP/checksums.txt" | awk '{print $1}' | head -n1)"
  [ -n "$want" ] || die "no checksum for $asset in checksums-sha256.txt"
  if [ "$want" != "$got" ]; then
    rm -f "$TMP/$asset"
    die "checksum mismatch for $asset (want $want, got $got)"
  fi
  say "Checksum verified: $asset"
}

# Check a downloaded release asset in $TMP against its Sigstore bundle under
# this release's workflow identity, with whichever verifier was chosen.
verify_release_signature() {
  asset="$1"
  curl -fsSL "$REL/$asset.bundle" -o "$TMP/$asset.bundle" 2>/dev/null \
    || die "no signature bundle published for $asset"

  if [ -n "$VERIFIER" ]; then
    "$VERIFIER" env verify-release "$TMP/$asset" --tag "$VERSION" >/dev/null \
      || die "signature verification failed for $asset"
    say "Signature verified: $asset"
  elif [ -n "$COSIGN" ]; then
    if "$COSIGN" verify-blob \
        --bundle "$TMP/$asset.bundle" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
        "$TMP/$asset" >/dev/null 2>&1; then
      say "Signature verified: $asset"
    else
      die "cosign signature verification failed for $asset"
    fi
  else
    die "no release signature verifier is available"
  fi
}

# Download, verify and stage the release's guest runtime beside mvmctl, so the
# release directory holds the CLI and the guest runtime of the same version.
# Only a 404 is tolerated, and only because releases before the asset existed
# have none; anything that fails to verify stops the install.
stage_guest_runtime() {
  runtime="mvm-guest-bins-${VERSION}.tar.gz"
  if download_archive "$REL/$runtime" "$TMP/$runtime"; then
    :
  else
    runtime_status="$?"
    if [ "$runtime_status" -eq 44 ]; then
      rm -f "$TMP/$runtime"
      warn "release $VERSION publishes no guest runtime ($runtime); it predates the asset"
      return 0
    fi
    die "download failed: $REL/$runtime"
  fi
  verify_release_checksum "$runtime"
  verify_release_signature "$runtime"
  mkdir -p "$SRC/guest-runtime"
  mv "$TMP/$runtime" "$SRC/guest-runtime/$runtime" \
    || die "could not stage $runtime beside mvmctl"
}

# --- Backend component selection ---------------------------------------------
#
# The archive's components.tsv is the generated form of mvmctl's per-backend
# component table; the shell reads it, it never carries a copy of the data.
# One row per backend and host window, tab-separated:
#
#   backend  target  macos_min  macos_max_exclusive  needs_kvm
#   install_default  selectable  files
#
# `-` marks an empty field; files is a space-separated `kind:path` list with
# kind one of bin/dir/file. The install-time default itself comes from the
# just-extracted mvmctl (`backend detect --plain`), so the shell never
# reimplements the macOS-version tier logic.

# Host facts for the row match: the macOS major version on Darwin (empty
# elsewhere), and 1/0 for a present /dev/kvm. The KVM probe is existence, the
# predicate the extracted mvmctl's own platform detection applies, so the
# viable set the shell computes always holds the backend its
# `backend detect --plain` answers; whether the device opens for this user is
# the runtime's question, not the installer's.
MACOS_MAJOR=""
HAS_KVM=0
if [ "$(uname -s)" = "Darwin" ]; then
  MACOS_MAJOR="$(sw_vers -productVersion | awk -F. '{print $1}')"
  case "$MACOS_MAJOR" in
    ''|*[!0-9]*) die "could not determine the macOS major version" ;;
  esac
elif [ -e /dev/kvm ]; then
  HAS_KVM=1
fi

# The selectable rows matching this host, one `backend<TAB>files` pair per
# line. A row matches on the archive target, the macOS window and the KVM
# requirement; nothing here re-derives what the table already decided.
viable_backend_rows() {
  awk -F'\t' -v target="$1" -v macos="${MACOS_MAJOR:--1}" -v kvm="$HAS_KVM" '
    /^#/ || NF == 0 { next }
    $2 != target { next }
    $3 != "-" && (macos + 0 < $3 + 0) { next }
    $4 != "-" && !(macos >= 0 && macos + 0 < $4 + 0) { next }
    $5 == "yes" && kvm != 1 { next }
    $7 != "yes" { next }
    { print $1 "\t" $8 }
  ' "$2"
}

# Every archive path owned by a backend other than $1 on this host's target —
# the set staging drops. Only the selected backend's components are placed; a
# user who never picks a backend never receives its files.
prune_payloads_from_table() {
  awk -F'\t' -v target="$TARGET" -v keep="$1" '
    /^#/ || NF == 0 { next }
    $2 != target { next }
    $1 == keep { next }
    $8 == "-" { next }
    {
      n = split($8, entries, " ")
      for (i = 1; i <= n; i++) {
        sub(/^[^:]*:/, "", entries[i])
        print entries[i]
      }
    }
  ' "$SRC/components.tsv"
}

# Offer the viable backends on a terminal and answer into PICKED. The prompt
# marks the auto choice; Enter — or a fixed 30-second timeout — takes it.
# Replies come from /dev/tty so `curl | sh` can still ask when a terminal
# exists; MVM_INSTALL_TTY overrides the reply source for tests, and an empty
# one is "no terminal". Returns 1 when there is no terminal to ask.
pick_backend() {
  picker_auto="$1"
  picker_names="$2"
  picker_tty="${MVM_INSTALL_TTY:-/dev/tty}"
  [ -n "$picker_tty" ] || return 1
  ( : < "$picker_tty" ) 2>/dev/null || return 1
  say "More than one backend can serve this host:"
  picker_i=1
  for picker_name in $picker_names; do
    picker_mark=""
    if [ "$picker_name" = "$picker_auto" ]; then
      picker_mark=" (default)"
    fi
    say "  $picker_i) $picker_name$picker_mark"
    picker_i=$((picker_i + 1))
  done
  say "Choose a backend [${picker_auto}, 30s timeout]:"
  # A user's reply is a time condition, so the wait is a timer: a background
  # reader owns the blocking read and a bounded loop gives it 30 seconds. The
  # reader records completion with a sentinel file — a finished subshell still
  # answers `kill -0` until it is reaped, so liveness cannot be the signal.
  picker_answer="$TMP/picker-answer"
  : > "$picker_answer"
  rm -f "$picker_answer.done"
  ( IFS= read -r picker_line < "$picker_tty" || true; printf '%s' "${picker_line:-}" > "$picker_answer"; : > "$picker_answer.done" ) 2>/dev/null &
  picker_reader=$!
  picker_waited=0
  while [ "$picker_waited" -lt 30 ] && [ ! -e "$picker_answer.done" ]; do
    sleep 1
    picker_waited=$((picker_waited + 1))
  done
  kill "$picker_reader" 2>/dev/null || true
  wait "$picker_reader" 2>/dev/null || true
  PICKED="$(cat "$picker_answer" 2>/dev/null || true)"
  if [ -z "$PICKED" ]; then
    PICKED="$picker_auto"
    return 0
  fi
  picker_i=1
  for picker_name in $picker_names; do
    if [ "$PICKED" = "$picker_i" ] || [ "$PICKED" = "$picker_name" ]; then
      PICKED="$picker_name"
      return 0
    fi
    picker_i=$((picker_i + 1))
  done
  warn "unrecognised choice '$PICKED' — installing the default ($picker_auto)"
  PICKED="$picker_auto"
}

# Decide the backend this install stages and the payloads it drops, from the
# archive's components.tsv: an explicit --backend / MVM_INSTALL_BACKEND wins
# and is validated against this host's viable set; otherwise a terminal with
# a real choice gets the picker; everything else takes the auto-detected
# default the extracted mvmctl computes. Sets SELECTED_BACKEND and
# PRUNE_PAYLOADS.
select_backend_components() {
  VIABLE_ROWS="$(viable_backend_rows "$TARGET" "$SRC/components.tsv")"
  VIABLE_NAMES="$(printf '%s\n' "$VIABLE_ROWS" | awk -F'\t' 'NF { print $1 }' | awk '!seen[$0]++' | tr '\n' ' ')"
  VIABLE_NAMES="${VIABLE_NAMES% }"
  if [ -n "$BACKEND_REQUESTED" ]; then
    if ! is_listed "$BACKEND_REQUESTED" "$VIABLE_NAMES"; then
      if [ -n "$VIABLE_NAMES" ]; then
        die "backend '$BACKEND_REQUESTED' is not supported on this host. Valid here: $(echo $VIABLE_NAMES | sed 's/ /, /g') (or omit --backend to auto-detect)"
      fi
      die "backend '$BACKEND_REQUESTED' is not supported on this host, and no backend is: see https://runmvm.com/reference/platform-support/"
    fi
    SELECTED_BACKEND="$BACKEND_REQUESTED"
  else
    detected="$("$SRC/mvmctl" backend detect --plain 2>"$TMP/backend-detect.err" || true)"
    if [ -z "$detected" ]; then
      cat "$TMP/backend-detect.err" >&2 || true
      die "no backend supports this host; refusing a partial install"
    fi
    if ! is_listed "$detected" "$VIABLE_NAMES"; then
      die "mvmctl backend detect answered '$detected', which components.tsv does not offer on this host"
    fi
    set -- $VIABLE_NAMES
    if [ "$#" -ge 2 ] && pick_backend "$detected" "$VIABLE_NAMES"; then
      SELECTED_BACKEND="$PICKED"
    else
      SELECTED_BACKEND="$detected"
    fi
  fi
  PRUNE_PAYLOADS="$(prune_payloads_from_table "$SELECTED_BACKEND" | tr '\n' ' ')"
  PRUNE_PAYLOADS="${PRUNE_PAYLOADS% }"
}

# The one-line summary every table-driven install ends with: what was chosen,
# and how to add another backend later.
say_selected_backend() {
  [ -n "$SELECTED_BACKEND" ] || return 0
  case "$TARGET" in
    aarch64-apple-darwin) host_detail="macOS $MACOS_MAJOR, Apple Silicon" ;;
    *)
      if [ "$HAS_KVM" = "1" ]; then
        host_detail="Linux, KVM"
      else
        host_detail="Linux, no KVM"
      fi
      ;;
  esac
  say "Installed backend: $SELECTED_BACKEND ($host_detail). Add another with \`mvmctl backend add <name>\`."
}

TARGET="$(detect_target)"
ARCHIVE="mvmctl-${TARGET}.tar.gz"

# An explicit pin wins. Otherwise install the newest stable release; the baked
# release is the fallback for a host that cannot reach the releases API (rate
# limited, or behind a proxy that only admits github.com downloads).
if [ -n "${MVM_VERSION:-}" ]; then
  VERSION="$MVM_VERSION"
elif VERSION="$(resolve_latest_version)"; then
  if [ -z "$VERSION" ]; then
    warn "no stable release publishes $ARCHIVE yet — installing the baked release $DEFAULT_VERSION"
    VERSION="$DEFAULT_VERSION"
  fi
else
  warn "could not reach $API_BASE to find the newest release — installing the baked release $DEFAULT_VERSION"
  VERSION="$DEFAULT_VERSION"
fi
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
  if [ "$download_status" -eq 44 ]; then
    die "release $VERSION publishes no $ARCHIVE (HTTP 404): $REL/$ARCHIVE"
  fi
  die "download failed: $REL/$ARCHIVE"
fi

case "$VERSION" in
  ''|*[!A-Za-z0-9._+-]*) die "release tag is not a safe directory name: $VERSION" ;;
esac

verify_release_checksum "$ARCHIVE"
got="$(sha256_of "$TMP/$ARCHIVE")"

# An explicit hash pins the exact archive bytes, not merely the bytes used to
# bootstrap a verifier. Enforce it even when a verifier is already installed
# or the release-manifest checksum check was skipped.
if [ -n "${MVM_TRUSTED_ARCHIVE_SHA256:-}" ]; then
  trusted_hash="$(trusted_archive_sha256)"
  [ "$got" = "$trusted_hash" ] \
    || die "trusted archive SHA-256 mismatch for $ARCHIVE (want $trusted_hash, got $got)"
fi

# Signature. An installed mvmctl verifies offline against its embedded trust
# root and is preferred to cosign. A fresh host authenticates the archive
# against the installer-baked hash before trying its mvmctl as a temporary
# verifier. Legacy archives predate that verb, so the installer can instead
# fetch a separately pinned cosign binary. Every path requires the bundle.
VERIFIER="$(release_verifier)"
COSIGN=""
if command -v cosign >/dev/null 2>&1; then
  COSIGN="$(command -v cosign)"
fi
if [ -z "$VERIFIER" ] && [ -z "$COSIGN" ]; then
  trusted_hash="$(trusted_archive_sha256)"
  if [ -n "$trusted_hash" ]; then
    [ "$got" = "$trusted_hash" ] \
      || die "trusted archive SHA-256 mismatch for $ARCHIVE (want $trusted_hash, got $got)"

    bootstrap_dir="$TMP/bootstrap-verifier"
    mkdir -p "$bootstrap_dir"
    tar xzf "$TMP/$ARCHIVE" -C "$bootstrap_dir" "mvmctl-${TARGET}/mvmctl" \
      || die "could not extract the authenticated bootstrap verifier"
    VERIFIER="$bootstrap_dir/mvmctl-${TARGET}/mvmctl"
    [ -x "$VERIFIER" ] || die "authenticated archive contains no executable mvmctl verifier"
    if ! "$VERIFIER" env verify-release --help 2>/dev/null | grep -q -- '--tag'; then
      VERIFIER=""
    fi
  fi
  if [ -z "$VERIFIER" ]; then
    COSIGN="$(bootstrap_cosign)"
  fi
fi

verify_release_signature "$ARCHIVE"

tar xzf "$TMP/$ARCHIVE" -C "$TMP"
SRC="$TMP/mvmctl-${TARGET}"
[ -f "$SRC/mvmctl" ] || die "archive missing mvmctl-${TARGET}/mvmctl"

# Stage what this host needs: the archive's component table decides. Archives
# predating components.tsv keep the rule they were published with.
if [ -f "$SRC/components.tsv" ]; then
  select_backend_components
else
  if [ -n "$BACKEND_REQUESTED" ]; then
    die "--backend / MVM_INSTALL_BACKEND need a release carrying components.tsv; $VERSION predates backend selection"
  fi
  # The rule the pre-table releases were published with: the libkrun
  # compatibility tier stages only on macOS hosts older than 26; macOS 26+
  # and every Linux host leave it out.
  PRUNE_PAYLOADS="$LEGACY_LIBKRUN_TIER_PAYLOADS"
  if [ "$(uname -s)" = "Darwin" ] && [ "$MACOS_MAJOR" -lt 26 ]; then
    PRUNE_PAYLOADS=""
  fi
fi
stage_guest_runtime

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
say_selected_backend
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

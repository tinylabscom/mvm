#!/usr/bin/env bash
set -euo pipefail

# Build the macOS libkrun release tier from immutable upstream source commits.
# The caller supplies an empty output directory; all downloads and build state
# stay under RUNNER_TEMP and only the relocatable runtime payload is exported.
#
# MVM_LIBKRUN_UPSTREAM_CACHE names an optional directory holding the result of
# the upstream half of the build (libkrun and libkrunfw built from the pinned
# commits, with their licences). It is adopted only when its recorded pins equal
# this script's and every file still matches the SHA-256 recorded when it was
# written; anything else is rebuilt from source. The mvm supervisor is always
# compiled from this tree and never comes from the cache. The check lives inside
# the entry, so it detects corruption, not a hostile writer: callers must only
# supply this cache for rehearsal runs, never for a release that gets signed.
#
# MVM_LIBKRUNFW_KERNEL_CACHE names a directory that may hold the kernel source
# tarball. It is verified against the SHA-256 pinned below like a download, so
# it is safe in any run.

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_DIR BUILD_TARGET" >&2
  exit 2
fi

output_dir="$1"
build_target="$2"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "$build_target" in
  aarch64-apple-darwin) ;;
  *) echo "libkrun release tier supports only aarch64-apple-darwin" >&2; exit 2 ;;
esac

libkrun_commit="b7e43f044d74b77abcfa51175055f72d7cfd6de0"
libkrunfw_commit="f6a710faaa8cfe3b67a4bcdadb082c2183a914f1"
libkrun_version="1.18.1"
libkrunfw_abi="5"
kernel_version="linux-6.12.116"
kernel_sha256="cb3ed3dfdd47e6ade49dc933db334fd86e24cadee920da612c262b0e9b6a511b"
deployment_target="13.0"
# Exported at top level, not inside build_upstream: a restored upstream cache skips
# that function, and the supervisor built below must still link at this target.
export MACOSX_DEPLOYMENT_TARGET="$deployment_target"

scratch_root="${RUNNER_TEMP:?RUNNER_TEMP is required}/mvm-libkrun-tier"
prefix="$scratch_root/prefix"
source_root="$scratch_root/source"
case "$scratch_root" in
  "$RUNNER_TEMP"/*) ;;
  *) echo "refusing unsafe scratch path: $scratch_root" >&2; exit 1 ;;
esac
if [[ -e "$output_dir" ]] && [[ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "output directory must be empty: $output_dir" >&2
  exit 1
fi
rm -rf "$scratch_root"
mkdir -p "$prefix" "$source_root" "$output_dir/lib" "$output_dir/licenses" \
  "$output_dir/sources"

make_bin="${MVM_GNU_MAKE:-gmake}"
command -v "$make_bin" >/dev/null 2>&1 || {
  echo "GNU make is required (set MVM_GNU_MAKE to its executable)" >&2
  exit 1
}

checkout_commit() {
  local repository="$1"
  local commit="$2"
  local destination="$3"
  git init -q "$destination"
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch -q --depth 1 origin "$commit"
  git -C "$destination" checkout -q --detach FETCH_HEAD
  [[ "$(git -C "$destination" rev-parse HEAD)" == "$commit" ]] || {
    echo "source checkout did not resolve the pinned commit: $repository" >&2
    exit 1
  }
}

pins_record() {
  printf '%s\n' \
    "libkrun_commit=$libkrun_commit" \
    "libkrunfw_commit=$libkrunfw_commit" \
    "libkrun_version=$libkrun_version" \
    "libkrunfw_abi=$libkrunfw_abi" \
    "kernel_version=$kernel_version" \
    "kernel_sha256=$kernel_sha256" \
    "deployment_target=$deployment_target" \
    "patch_sha256=$(shasum -a 256 "$script_dir/libkrunfw-macos-host.patch" | awk '{print $1}')" \
    "script_sha256=$(shasum -a 256 "${BASH_SOURCE[0]}" | awk '{print $1}')"
}

# Adopt the cached upstream tree into $prefix only if it is exactly what this
# script would have built: same pins, same file set, same bytes.
restore_upstream_cache() {
  local cache="$1"
  [[ -f "$cache/PINS" && -f "$cache/SHA256SUMS" && -d "$cache/prefix" ]] || return 1
  [[ "$(cat "$cache/PINS")" == "$(pins_record)" ]] || return 1
  [[ "$(cd "$cache/prefix" && find . -type f | sort)" == \
     "$(awk '{print $2}' "$cache/SHA256SUMS" | sort)" ]] || return 1
  (cd "$cache/prefix" && shasum -a 256 -c "$cache/SHA256SUMS" --quiet) || return 1
  cp -a "$cache/prefix/." "$prefix/"
  local required
  for required in lib/libkrun.$libkrun_version.dylib lib/libkrunfw.$libkrunfw_abi.dylib \
      include/libkrun.h licenses/libkrun-APACHE-2.0.txt \
      licenses/libkrunfw-LGPL-2.1-only.txt licenses/linux-GPL-2.0-only.txt; do
    [[ -f "$prefix/$required" ]] || return 1
  done
}

upstream_cache="${MVM_LIBKRUN_UPSTREAM_CACHE:-}"
case "$upstream_cache" in
  "$scratch_root"|"$scratch_root"/*) echo "cache must live outside scratch: $upstream_cache" >&2; exit 1 ;;
esac
upstream_restored=0
if [[ -n "$upstream_cache" ]]; then
  if restore_upstream_cache "$upstream_cache"; then
    upstream_restored=1
    echo "libkrun upstream tree restored from verified cache"
  else
    echo "libkrun upstream cache absent or failed verification; building from source"
    rm -rf "$prefix" && mkdir -p "$prefix"
  fi
fi

build_upstream() {
libkrunfw_src="$source_root/libkrunfw"
libkrun_src="$source_root/libkrun"
checkout_commit https://github.com/libkrun/libkrunfw.git "$libkrunfw_commit" "$libkrunfw_src"
checkout_commit https://github.com/libkrun/libkrun.git "$libkrun_commit" "$libkrun_src"
patch -p1 -d "$libkrunfw_src" < "$script_dir/libkrunfw-macos-host.patch"

kernel_tarball="$libkrunfw_src/tarballs/$kernel_version.tar.xz"
mkdir -p "$(dirname "$kernel_tarball")"
kernel_cache="${MVM_LIBKRUNFW_KERNEL_CACHE:-}"
cached_kernel="$kernel_cache/$kernel_version.tar.xz"
if [[ -n "${MVM_LIBKRUNFW_KERNEL_TARBALL:-}" ]]; then
  cp "$MVM_LIBKRUNFW_KERNEL_TARBALL" "$kernel_tarball"
elif [[ -n "$kernel_cache" && -f "$cached_kernel" ]]; then
  cp "$cached_kernel" "$kernel_tarball"
else
  curl --fail --location \
    "https://cdn.kernel.org/pub/linux/kernel/v6.x/$kernel_version.tar.xz" \
    --output "$kernel_tarball"
fi
actual_kernel_sha256="$(shasum -a 256 "$kernel_tarball" | awk '{print $1}')"
if [[ "$actual_kernel_sha256" != "$kernel_sha256" ]]; then
  echo "kernel source SHA-256 mismatch: $actual_kernel_sha256" >&2
  exit 1
fi
# Verified against the pin in this file, so the cache copy is safe in any run.
if [[ -n "$kernel_cache" && ! -f "$cached_kernel" ]]; then
  mkdir -p "$kernel_cache" && cp "$kernel_tarball" "$cached_kernel"
fi

kernel_hostcc="$(xcrun --find clang)"
macos_sdk="$(xcrun --show-sdk-path)"

# The pinned libkrunfw commit carries the native macOS LLVM kernel build. It
# produces the embedded Linux payload without bootstrapping from Homebrew's
# libkrun binaries.
"$make_bin" -C "$libkrunfw_src" -j2 MACOS_BUILDER=native PREFIX="$prefix" \
  KERNEL_HOSTCC="$kernel_hostcc"
"$make_bin" -C "$libkrunfw_src" MACOS_BUILDER=native PREFIX="$prefix" \
  KERNEL_HOSTCC="$kernel_hostcc" install

# Keep the runtime surface minimal: block and vsock/network support, no virgl,
# MoltenVK, audio, or input stack. Zig supplies the static Linux init without
# the upstream makefile's moving Debian sysroot. Disabling Cargo's intermediate
# debug stripping avoids malformed proc-macro dylibs on current macOS; the
# shipped Mach-O inventory is signed and verified after staging.
PKG_CONFIG_PATH="$prefix/lib/pkgconfig" \
LIBRARY_PATH="$prefix/lib" \
BINDGEN_EXTRA_CLANG_ARGS="-isysroot $macos_sdk" \
CARGO_PROFILE_RELEASE_STRIP=none \
"$make_bin" -C "$libkrun_src" -j2 PREFIX="$prefix" BLK=1 NET=1 \
  SYSROOT_LINUX="$scratch_root/zig-linux-sysroot" \
  CC_LINUX="zig cc -target aarch64-linux-musl"
CARGO_PROFILE_RELEASE_STRIP=none \
BINDGEN_EXTRA_CLANG_ARGS="-isysroot $macos_sdk" \
"$make_bin" -C "$libkrun_src" PREFIX="$prefix" BLK=1 NET=1 \
  SYSROOT_LINUX="$scratch_root/zig-linux-sysroot" \
  CC_LINUX="zig cc -target aarch64-linux-musl" install

mkdir -p "$prefix/licenses"
cp "$libkrun_src/LICENSE" "$prefix/licenses/libkrun-APACHE-2.0.txt"
cp "$libkrunfw_src/LICENSE-LGPL-2.1-only" \
  "$prefix/licenses/libkrunfw-LGPL-2.1-only.txt"
cp "$libkrunfw_src/LICENSE-GPL-2.0-only" "$prefix/licenses/linux-GPL-2.0-only.txt"
}

export_upstream_cache() {
  local cache="$1"
  rm -rf "$cache" && mkdir -p "$cache"
  cp -a "$prefix" "$cache/prefix"
  pins_record > "$cache/PINS"
  (cd "$cache/prefix" && find . -type f | sort | xargs shasum -a 256) > "$cache/SHA256SUMS"
}

if (( upstream_restored == 0 )); then
  build_upstream
  [[ -z "$upstream_cache" ]] || export_upstream_cache "$upstream_cache"
fi

# Cargo does not track MACOSX_DEPLOYMENT_TARGET, so a target directory restored
# from a build made without it would link this binary at the toolchain default
# (11.0) instead of the tier's deployment target. A private target directory
# keeps the supervisor's dependencies built under the exported target.
supervisor_target="$scratch_root/supervisor-target"
CARGO_TARGET_DIR="$supervisor_target" \
MVM_LIBKRUN_HEADER="$prefix/include/libkrun.h" \
LIBRARY_PATH="$prefix/lib" \
cargo build --release --target "$build_target" -p mvm-hostd \
  --bin mvm-libkrun-supervisor --features libkrun-sys

cp "$supervisor_target/$build_target/release/mvm-libkrun-supervisor" "$output_dir/"
cp "$prefix/lib/libkrun.$libkrun_version.dylib" "$output_dir/lib/libkrun.1.dylib"
cp "$prefix/lib/libkrunfw.$libkrunfw_abi.dylib" "$output_dir/lib/"

supervisor="$output_dir/mvm-libkrun-supervisor"
libkrun="$output_dir/lib/libkrun.1.dylib"
libkrunfw="$output_dir/lib/libkrunfw.$libkrunfw_abi.dylib"

install_name_tool -id '@rpath/libkrun.1.dylib' "$libkrun"
install_name_tool -id "@rpath/libkrunfw.$libkrunfw_abi.dylib" "$libkrunfw"

rewrite_dependency() {
  local binary="$1"
  local dependency
  while IFS= read -r dependency; do
    case "$dependency" in
      *libkrun.dylib|*libkrun.1.dylib|*libkrun.1.18.1.dylib)
        install_name_tool -change "$dependency" '@rpath/libkrun.1.dylib' "$binary"
        ;;
      *libkrunfw.dylib|*libkrunfw.5.dylib)
        install_name_tool -change "$dependency" \
          "@rpath/libkrunfw.$libkrunfw_abi.dylib" "$binary"
        ;;
    esac
  done < <(otool -L "$binary" | awk 'NR > 1 { print $1 }')
}

rewrite_dependency "$supervisor"
rewrite_dependency "$libkrun"

# libkrun opens libkrunfw by its base name. Its own loader-relative rpath makes
# that lookup independent of DYLD_LIBRARY_PATH, including for protected parents.
install_name_tool -add_rpath '@executable_path/lib' "$supervisor"
install_name_tool -add_rpath '@loader_path' "$libkrun"

# Keep the basename libkrun opens, but materialize it after loader fixups.
# Separate regular files survive strict archive inspection and independent signing.
cp "$libkrunfw" "$output_dir/lib/libkrunfw.dylib"

cp "$prefix"/licenses/*.txt "$output_dir/licenses/"
cp "$script_dir/libkrunfw-macos-host.patch" "$output_dir/sources/"
cat > "$output_dir/SOURCE-OFFER.txt" <<EOF
This release contains libkrun and libkrunfw built from the following exact sources:

libkrun:   https://github.com/libkrun/libkrun/tree/$libkrun_commit
libkrunfw: https://github.com/libkrun/libkrunfw/tree/$libkrunfw_commit
Linux:     https://cdn.kernel.org/pub/linux/kernel/v6.x/$kernel_version.tar.xz

The libkrunfw source names and patches the exact Linux kernel archive and carries
the complete kernel configuration used to produce libkrunfw.$libkrunfw_abi.dylib.
The archive's sources/libkrunfw-macos-host.patch is the complete mvm-side change
applied to that pinned upstream tree. It pins the repository-maintained kernel
point release and adapts libkrunfw's native macOS host-tool build.
The reproducible build entry point is scripts/release/build-libkrun-tier.sh in
this mvm release's source tree. The licence texts shipped beside this notice
govern the corresponding components.
EOF

for binary in "$supervisor" "$libkrun" "$libkrunfw" "$output_dir/lib/libkrunfw.dylib"; do
  dependencies="$(otool -L "$binary")"
  load_commands="$(otool -l "$binary")"
  if grep -E '/opt/homebrew|/usr/local|mvm-libkrun-tier' \
      <<<"$dependencies"$'\n'"$load_commands"; then
    echo "non-relocatable path in $binary" >&2
    exit 1
  fi
  minos="$(awk '
    $1 == "cmd" && $2 == "LC_BUILD_VERSION" { build = 1; next }
    build && $1 == "minos" { print $2; exit }
  ' <<<"$load_commands")"
  case "$minos" in
    13|13.*) ;;
    *) echo "unexpected macOS deployment target in $binary: ${minos:-missing}" >&2; exit 1 ;;
  esac
done

printf '%s\n' \
  "libkrun_commit=$libkrun_commit" \
  "libkrunfw_commit=$libkrunfw_commit" \
  "kernel_version=$kernel_version" \
  "kernel_sha256=$kernel_sha256" \
  "deployment_target=$deployment_target" \
  > "$output_dir/SOURCE-PINS"

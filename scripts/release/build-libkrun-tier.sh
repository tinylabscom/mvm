#!/usr/bin/env bash
set -euo pipefail

# Build the macOS libkrun release tier from immutable upstream source commits.
# The caller supplies an empty output directory; all downloads and build state
# stay under RUNNER_TEMP and only the relocatable runtime payload is exported.

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
kernel_version="linux-6.12.114"
kernel_sha256="7a8589912bd7a8adb07fed074283652cf482a35facef8954554654f0154b4af3"
deployment_target="13.0"

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

libkrunfw_src="$source_root/libkrunfw"
libkrun_src="$source_root/libkrun"
checkout_commit https://github.com/libkrun/libkrunfw.git "$libkrunfw_commit" "$libkrunfw_src"
checkout_commit https://github.com/libkrun/libkrun.git "$libkrun_commit" "$libkrun_src"
patch -p1 -d "$libkrunfw_src" < "$script_dir/libkrunfw-macos-host.patch"

kernel_tarball="$libkrunfw_src/tarballs/$kernel_version.tar.xz"
mkdir -p "$(dirname "$kernel_tarball")"
if [[ -n "${MVM_LIBKRUNFW_KERNEL_TARBALL:-}" ]]; then
  cp "$MVM_LIBKRUNFW_KERNEL_TARBALL" "$kernel_tarball"
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

export MACOSX_DEPLOYMENT_TARGET="$deployment_target"
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

MVM_LIBKRUN_HEADER="$prefix/include/libkrun.h" \
LIBRARY_PATH="$prefix/lib" \
cargo build --release --target "$build_target" -p mvm-hostd \
  --bin mvm-libkrun-supervisor --features libkrun-sys

cp "target/$build_target/release/mvm-libkrun-supervisor" "$output_dir/"
cp "$prefix/lib/libkrun.$libkrun_version.dylib" "$output_dir/lib/libkrun.1.dylib"
cp "$prefix/lib/libkrunfw.$libkrunfw_abi.dylib" "$output_dir/lib/"
ln -s "libkrunfw.$libkrunfw_abi.dylib" "$output_dir/lib/libkrunfw.dylib"

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

cp "$libkrun_src/LICENSE" "$output_dir/licenses/libkrun-APACHE-2.0.txt"
cp "$libkrunfw_src/LICENSE-LGPL-2.1-only" \
  "$output_dir/licenses/libkrunfw-LGPL-2.1-only.txt"
cp "$libkrunfw_src/LICENSE-GPL-2.0-only" \
  "$output_dir/licenses/linux-GPL-2.0-only.txt"
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

for binary in "$supervisor" "$libkrun" "$libkrunfw"; do
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

# Lightweight Rust toolchain used only by mvm-cli/build.rs for embedded
# host-VM binaries.
#
# Nixpkgs' pkgsCross Rust platform can provide the musl target, but on this
# pinned nixpkgs revision it pulls a full cross Rust/LLVM build into the
# optional mvmctl package. The build script only needs a native cargo plus a
# rustc sysroot containing the same-arch musl std target, so wrap nixpkgs'
# official prebuilt Rust bootstrap toolchain with the matching pinned
# rust-std component instead. The bootstrap rustc and rust-std component must
# stay from the same upstream Rust release; mixing nixpkgs-built rustc with the
# official rust-std tarball trips Rust metadata/lang-item compatibility errors.

{ lib
, stdenv
, fetchurl
, runCommand
, makeWrapper
, cargo
, rustc
, target
}:

let
  version = "1.91.1";
  hashes = {
    aarch64-unknown-linux-musl = "sha256-W95G9gKLSyz+ogTZiIt93mYDG3eKuEtoXrUjQ1kpt7U=";
    x86_64-unknown-linux-musl = "sha256-fcoP5fERdHCAB+tTVG6pWq2MN9/Ww8sGTF8cZS7WsPI=";
  };

  rustStd = fetchurl {
    url = "https://static.rust-lang.org/dist/rust-std-${version}-${target}.tar.gz";
    hash = hashes.${target} or (throw "unsupported embedded Rust std target: ${target}");
  };
in

runCommand "mvm-embedded-rust-toolchain-${target}"
  {
    nativeBuildInputs = [ makeWrapper ];
    passthru = {
      inherit target;
    };
    meta = with lib; {
      description = "Native Rust wrapper with ${target} std for mvm embedded host binaries";
      platforms = platforms.unix;
    };
  }
  ''
    runHook preBuild

    mkdir -p "$out/bin" "$out/lib"

    base_sysroot="$(${rustc}/bin/rustc --print sysroot)"
    cp -R "$base_sysroot/lib/rustlib" "$out/lib/rustlib"
    chmod -R u+w "$out/lib/rustlib"

    tar -xzf ${rustStd}
    std_dir="$(find . -path "*/lib/rustlib/${target}" -type d | head -n 1)"
    if [ -z "$std_dir" ]; then
      echo "rust-std component for ${target} did not contain lib/rustlib/${target}" >&2
      exit 1
    fi
    rm -rf "$out/lib/rustlib/${target}"
    cp -R "$std_dir" "$out/lib/rustlib/${target}"

    makeWrapper ${rustc}/bin/rustc "$out/bin/rustc" \
      --add-flags "--sysroot=$out"
    makeWrapper ${cargo}/bin/cargo "$out/bin/cargo"

    "$out/bin/rustc" --target ${target} --print target-libdir >/dev/null

    runHook postBuild
  ''

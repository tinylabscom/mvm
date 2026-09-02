#!/usr/bin/env bash
set -euo pipefail

# Keep Linux-only compile, filesystem, and conformance coverage in one reusable
# lane so it can run beside the workspace test lane without duplicating the
# coverage in a second workflow definition.

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

wasmtime_version="46.0.1"
wasmtime_base="wasmtime-v${wasmtime_version}-x86_64-linux"
curl -fsSL "https://github.com/bytecodealliance/wasmtime/releases/download/v${wasmtime_version}/${wasmtime_base}.tar.xz" \
  | tar -xJf - -C "$tmpdir"
mkdir -p "$HOME/.wasmtime/bin"
mv "$tmpdir/${wasmtime_base}/wasmtime" "$HOME/.wasmtime/bin/wasmtime"
rm -rf "$tmpdir"
export PATH="$HOME/.wasmtime/bin:$PATH"

cargo +1.97.1 build -p mvm-contract --target wasm32-unknown-unknown
cargo +1.97.1 build -p mvm-contract --lib \
  --target riscv32imac-unknown-none-elf
cargo +1.97.1 test -p mvm-contract --target wasm32-wasip1

# Browser wasm demo: build + wasm-opt + gzipped size budget, plus Rust
# fixture-parity tests. wasm-pack and binaryen/wabt are installed here because
# the builder VM image does not yet include the browser wasm toolchain.
cargo install wasm-pack --locked
sudo apt-get update && sudo apt-get install -y binaryen wabt
(
  cd web/mvm-demo
  ./build.sh
  cargo +1.97.1 test
)

cargo run -p mvm-fs --example write_sample -- /tmp/sample.ext4 \
  | tee /tmp/sample.out

mnt=$(mktemp -d)
sudo mount -o ro,loop /tmp/sample.ext4 "$mnt"
trap 'sudo umount "$mnt" || true; rmdir "$mnt" || true' EXIT
[ "$(cat "$mnt/etc/hosts")" = "127.0.0.1 localhost" ]
diff <(printf 'hi from pure-rust ext4\n') "$mnt/hello"
[ "$(readlink "$mnt/etc/localhost")" = "hosts" ]
[ -d "$mnt/bin" ] && [ -d "$mnt/etc" ]
[ "$(stat -c '%a' "$mnt/hello")" = "755" ]
[ "$(stat -c '%a' "$mnt/etc/hosts")" = "644" ]
[ "$(stat -c '%s' "$mnt/big")" = "716800" ]
cap=$(sudo getfattr --absolute-names -n security.capability -e hex "$mnt/bin/ping" \
  | grep '^security.capability=' | cut -d= -f2)
echo "security.capability=$cap"
[ "$cap" = "0x0000000200300000000000000000000000000000" ]
sudo umount "$mnt"
rmdir "$mnt"

cargo run -p mvm-fs --example write_multigroup -- /tmp/multigroup.ext4
[ "$(stat -c '%s' /tmp/multigroup.ext4)" -gt 134217728 ]
mnt=$(mktemp -d)
sudo mount -o ro,loop /tmp/multigroup.ext4 "$mnt"
trap 'sudo umount "$mnt" || true; rmdir "$mnt" || true' EXIT
[ "$(cat "$mnt/etc/marker")" = "multi-group marker" ]
[ "$(stat -c '%s' "$mnt/big")" = "136314880" ]
off=134000000
got=$(dd if="$mnt/big" bs=1 skip="$off" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
[ "$got" = "$((off % 251))" ]
sudo umount "$mnt"
rmdir "$mnt"

cargo run -p mvm-fs --example write_extent_tree -- /tmp/extent_tree.ext4
[ "$(stat -c '%s' /tmp/extent_tree.ext4)" -gt 536870912 ]
mnt=$(mktemp -d)
sudo mount -o ro,loop /tmp/extent_tree.ext4 "$mnt"
trap 'sudo umount "$mnt" || true; rmdir "$mnt" || true' EXIT
[ "$(cat "$mnt/etc/marker")" = "extent-tree marker" ]
[ "$(stat -c '%s' "$mnt/huge")" = "545259520" ]
off=537000000
got=$(dd if="$mnt/huge" bs=1 skip="$off" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
[ "$got" = "$((off % 251))" ]
sudo umount "$mnt"
rmdir "$mnt"

ours=$(grep '^ROOTHASH ' /tmp/sample.out | awk '{print $2}')
theirs=$(veritysetup format --no-superblock \
    --data-block-size=4096 --hash-block-size=4096 \
    --salt=0000000000000000000000000000000000000000000000000000000000000000 \
    /tmp/sample.ext4 /tmp/vs.verity \
  | awk '/^Root hash:/ {print $3}')
echo "ours=$ours theirs=$theirs"
[ -n "$ours" ] && [ "$ours" = "$theirs" ]
if ! cmp -s /tmp/sample.ext4.verity /tmp/vs.verity; then
  echo "::error::hash tree differs from veritysetup"
  ls -l /tmp/sample.ext4.verity /tmp/vs.verity
  cmp -l /tmp/sample.ext4.verity /tmp/vs.verity | head -20 || true
  exit 1
fi

cargo test -p mvm-conformance --test meta
just bdd

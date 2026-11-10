#!/usr/bin/env bash
# Hermetic test of stage-firecracker.sh: a fake upstream tarball and a lock that
# names it, served from a local directory. Nothing touches the network, and the
# real pin is not involved; the script's reading of the real lock is checked by
# `xtask check-firecracker-pin` and by the release itself.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
script="$repo/scripts/release/stage-firecracker.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
export STAGE_FIRECRACKER_RETRIES=0

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

version="v9.9.9"
arch="x86_64"
tarball="firecracker-$version-$arch.tgz"
member_dir="release-$version-$arch"
binary="$member_dir/firecracker-$version-$arch"

# build_upstream <dir> <elf|text> <with_license|no_license>
build_upstream() {
  local dir="$1" kind="$2" license="$3"
  rm -rf "$dir" "$work/pack"
  mkdir -p "$dir" "$work/pack/$member_dir"
  if [ "$kind" = elf ]; then
    printf '\177ELF fake firecracker bytes\n' > "$work/pack/$binary"
  else
    printf 'not an executable\n' > "$work/pack/$binary"
  fi
  [ "$license" = with_license ] && printf 'Apache License fake\n' > "$work/pack/$member_dir/LICENSE"
  printf 'NOTICE fake\n' > "$work/pack/$member_dir/NOTICE"
  tar -czf "$dir/$tarball" -C "$work/pack" "$member_dir"
}

# write_lock <upstream-dir> [tarball-digest] [binary-digest] [binary-size]
write_lock() {
  local dir="$1"
  local tdigest="${2:-$(sha256_of "$dir/$tarball")}"
  local bdigest="${3:-$(sha256_of "$work/pack/$binary")}"
  local bsize="${4:-$(wc -c < "$work/pack/$binary" | tr -d ' ')}"
  cat > "$work/lock.toml" <<EOF
schema_version = 1
repository = "firecracker-microvm/firecracker"
version = "$version"

[$arch]
tarball = "$tarball"
tarball_sha256 = "$tdigest"
binary = "$binary"
binary_sha256 = "$bdigest"
binary_size = $bsize

[aarch64]
tarball = "firecracker-$version-aarch64.tgz"
tarball_sha256 = "$(printf '0%.0s' {1..64})"
binary = "release-$version-aarch64/firecracker-$version-aarch64"
binary_sha256 = "$(printf '0%.0s' {1..64})"
binary_size = 1
EOF
}

run_script() { # <dest> [args...]; prints stderr, returns the script's status
  local dest="$1"; shift
  FIRECRACKER_LOCK_FILE="$work/lock.toml" "$script" "$@" "$arch" "$dest"
}

expect_refusal() { # <label> <dest> <message-fragment> [args...]
  local label="$1" dest="$2" fragment="$3"; shift 3
  local out status=0
  out="$(run_script "$dest" "$@" 2>&1)" || status=$?
  [ "$status" -ne 0 ] || fail "$label: the script staged something it must refuse"
  grep -qF -- "$fragment" <<<"$out" || fail "$label: expected '$fragment' in: $out"
  [ ! -e "$dest" ] || fail "$label: $dest exists after a refusal"
}

up="$work/upstream"

# 1. Good bytes are staged, with the right modes and contents.
build_upstream "$up" elf with_license
write_lock "$up"
out="$(run_script "$work/ok" --base-url "file://$up" 2>&1)" || fail "good bytes were refused: $out"
grep -qF "staged firecracker $version ($arch)" <<<"$out" || fail "no summary line: $out"
[ -x "$work/ok/firecracker" ] || fail "firecracker is not executable"
[[ ! -x "$work/ok/LICENSE" && ! -x "$work/ok/NOTICE" ]] || fail "a license file is executable"
cmp -s "$work/ok/firecracker" "$work/pack/$binary" || fail "the staged binary differs from the upstream one"
staged_names="$(find "$work/ok" -mindepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ')"
[ "$staged_names" = "LICENSE NOTICE firecracker " ] \
  || fail "unexpected files staged: $staged_names"

# 2. A tarball whose digest is not the locked one is refused before anything is
#    extracted.
build_upstream "$up" elf with_license
write_lock "$up" "$(printf '1%.0s' {1..64})"
expect_refusal "tampered tarball" "$work/t1" "but the lock pins" --base-url "file://$up"

# 3. A correct tarball that holds a binary other than the locked one is refused.
build_upstream "$up" elf with_license
write_lock "$up" "" "$(printf '2%.0s' {1..64})"
expect_refusal "wrong binary digest" "$work/t2" "nothing was staged" --base-url "file://$up"

# 4. A binary of another size is refused even if the digest were to match.
build_upstream "$up" elf with_license
write_lock "$up" "" "" 12345
expect_refusal "wrong binary size" "$work/t3" "bytes, but the lock pins 12345" --base-url "file://$up"

# 5. Bytes that are not an ELF executable are refused, even with matching digests.
build_upstream "$up" text with_license
write_lock "$up"
expect_refusal "not an ELF" "$work/t4" "not an ELF executable" --base-url "file://$up"

# 6. A tarball without the license text is refused: redistribution needs it.
build_upstream "$up" elf no_license
write_lock "$up"
expect_refusal "missing license" "$work/t5" "with its LICENSE and NOTICE" --base-url "file://$up"

# 7. Arguments are checked.
build_upstream "$up" elf with_license
write_lock "$up"
status=0; "$script" 2>/dev/null || status=$?
[ "$status" -ne 0 ] || fail "no arguments were accepted"
status=0; out="$("$script" riscv64 "$work/t6" 2>&1)" || status=$?
{ [ "$status" -ne 0 ] && grep -qF "must be x86_64 or aarch64" <<<"$out"; } \
  || fail "an unknown arch was not refused: $out"
[ ! -e "$work/t6" ] || fail "an unknown arch created a directory"
status=0; out="$("$script" --nope x86_64 "$work/t6" 2>&1)" || status=$?
{ [ "$status" -ne 0 ] && grep -qF "unknown option" <<<"$out"; } \
  || fail "an unknown option was not refused: $out"

# 8. A plain-http base URL is refused: only https and file are fetched.
status=0; out="$(FIRECRACKER_LOCK_FILE="$work/lock.toml" "$script" --base-url "http://127.0.0.1:9" "$arch" "$work/t7" 2>&1)" || status=$?
[ "$status" -ne 0 ] || fail "an http base URL was accepted"
[ ! -e "$work/t7" ] || fail "an http base URL left a directory"

echo "stage-firecracker.test.sh: all checks passed"

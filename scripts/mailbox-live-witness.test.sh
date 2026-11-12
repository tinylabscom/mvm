#!/usr/bin/env bash
# Hermetic test of mailbox-live-witness.sh: a fake mvmctl models the guest, its
# mailbox queue and the audit log, so the script's own logic is checked without
# booting anything. This proves the script, not the product; the live run on a
# real host is what proves the product.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

cat > "${work}/mvmctl" <<'S'
#!/usr/bin/env bash
# MODE: ok | no-token | leaks-body | no-queue
state="${FAKE_STATE:?}"; mode="${FAKE_MODE:-ok}"
case "$1 $2" in
  "--version "*) echo "mvmctl fake" ;;
  "image pull") ;;
  "machine run")
    if [ "$mode" = needs-bootstrap ]; then echo "Error: runtime not prepared; run \`mvmctl bootstrap\` first" >&2; exit 1; fi
    shift 2; name=""; granted=no
    while [ $# -gt 0 ]; do
      case "$1" in --name) name="$2"; shift ;; --mailbox) granted=yes ;; esac; shift
    done
    mkdir -p "${MVM_HOME}/vms/${name}" "${MVM_HOME}/audit"
    echo "$granted" > "${state}/granted.${name}"
    if [ "$granted" = yes ]; then sleep 600 & echo $! > "${MVM_HOME}/vms/${name}/mailbox.pid"; fi ;;
  "machine exec")
    name="$3"; shift 4
    granted="$(cat "${state}/granted.${name}")"
    case "$*" in
      true) ;;
      "cat /proc/cmdline")
        [ "$granted" = yes ] && [ "$mode" != no-token ] && echo "ro mvm.mailbox=1 quiet" || echo "ro quiet" ;;
      "test ! -e /run/mvm/mailbox") [ "$granted" = no ] ;;
      "grep -q mvm.mailbox=1 /proc/cmdline") [ "$granted" = yes ] ;;
      sh*)  # write_frame: sh -c <script> _ <fill> <body>
        fill="${@: -2:1}"; body="${@: -1}"
        [ "$mode" = no-queue ] && exit 0
        [ "$fill" = 000 ] && echo "$body" >> "${state}/queue"
        printf 'mailbox.read len=%s\n' "${#body}" >> "${MVM_HOME}/audit/t.jsonl"
        if [ "$mode" = leaks-body ]; then echo "$body" >> "${MVM_HOME}/audit/t.jsonl"; fi ;;
      *) echo "fake: unhandled exec: $*" >&2; exit 2 ;;
    esac ;;
  "machine mailbox")
    [ -s "${state}/queue" ] || exit 0
    head -n1 "${state}/queue" | tr -d '\n'; sed -i.bak 1d "${state}/queue" ;;
  "trust audit") ;;
  "machine stop") name="$3"; [ -f "${MVM_HOME}/vms/${name}/mailbox.pid" ] && kill "$(cat "${MVM_HOME}/vms/${name}/mailbox.pid")" 2>/dev/null || true ;;
  "machine rm") ;;
  *) echo "fake: unhandled: $*" >&2; exit 2 ;;
esac
S
chmod +x "${work}/mvmctl"

run() { # <mode> -> output; the script's own exit status is returned
  rm -rf "${work:?}/state" "${work:?}/home"; mkdir -p "${work}/state" "${work}/home"
  MVMCTL="${work}/mvmctl" FAKE_STATE="${work}/state" FAKE_MODE="$1" MVM_HOME="${work}/home" \
    WAIT_SECS=4 bash "${repo}/scripts/mailbox-live-witness.sh" 2>&1
}

out="$(run ok)" || fail "a correct run failed: ${out}"
grep -q '^WITNESS_RESULT=pass$' <<<"${out}" || fail "no pass line: ${out}"
[ "$(grep -c '^PASS ' <<<"${out}")" -eq 9 ] || fail "expected nine PASS lines: ${out}"

run no-token >/dev/null && fail "a guest without the token passed"
run no-queue >/dev/null && fail "a run where nothing arrives passed"
run leaks-body >/dev/null && fail "a body in the audit log passed"
out="$(run needs-bootstrap)" && fail "an install that needs bootstrap passed"
grep -q "^FINDING: the install asked for 'mvmctl bootstrap'" <<<"${out}" || fail "no bootstrap finding: ${out}"

# The frame builder below must stay the one the script runs in the guest.
# shellcheck disable=SC2016  # a literal fragment, deliberately unexpanded
grep -qF 'head -c 32 /dev/zero | tr "\\0" "\\$1"; printf "%s" "$2"' "${repo}/scripts/lib/mailbox-frame.sh" \
  || fail "the shared frame builder changed; update this test's copy"

# The frame the guest-side snippet writes: 32 recipient bytes, then the body.
d="${work}/guest"; mkdir -p "${d}"
frame() { # <fill> <body>
  { head -c 32 /dev/zero | LC_ALL=C tr "\\0" "\\$1"; printf "%s" "$2"; } > "${d}/f"
}
frame 000 hello; [ "$(head -c 32 "${d}/f" | od -An -v -tx1 | tr -d ' \n')" = "$(printf '00%.0s' $(seq 32))" ] || fail "own recipient is not 32 zero bytes"
[ "$(tail -c +33 "${d}/f")" = hello ] || fail "body not after the recipient"
frame 377 x; [ "$(head -c 32 "${d}/f" | od -An -v -tx1 | tr -d ' \n')" = "$(printf 'ff%.0s' $(seq 32))" ] || fail "other recipient is not 32 ff bytes"
[ "$(wc -c < "${d}/f")" -eq 33 ] || fail "frame length"
echo "ok"

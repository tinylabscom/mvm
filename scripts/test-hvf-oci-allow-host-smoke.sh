#!/usr/bin/env bash
set -euo pipefail
unset MVM_SKIP_COSIGN_VERIFY MVM_SKIP_HASH_VERIFY

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/mvm-hvf-smoke-test.XXXXXX)"
trap 'rm -rf "${TEST_DIR}"' EXIT
mkdir -p "${TEST_DIR}/target/debug" "${TEST_DIR}/bin"

cp /usr/bin/true "${TEST_DIR}/target/debug/mvm-hvf-supervisor"
cp /usr/bin/true "${TEST_DIR}/target/debug/mvm-network-endpoint"

cat >"${TEST_DIR}/target/debug/mvmctl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2 $3" == "machine run --hypervisor" ]]
[[ " $* " == *" --allow-host example.com:443 "* ]]
[[ " $* " == *" -- python3 -c "* ]]
[[ "${MVM_HOME}" == "${MOCK_EXPECT_HOME}" ]]
while [[ "$1" != "-c" ]]; do
  shift
done
python3 -c 'import ast, sys; ast.parse(sys.argv[1])' "$2"
case "${MOCK_RESULT:-success}" in
  success)
    printf '%s\n' HVF_PROBE_NO_NIC_OK HVF_PROBE_RUNTIME_OK HVF_PROBE_ALLOW_OK HVF_PROBE_DENY_ERROR HVF_PROBE_DENY_OK
    echo 'egress blocked: example.org:443 (not in the allow-list)' >&2
    ;;
  missing-runtime)
    printf '%s\n' HVF_PROBE_NO_NIC_OK HVF_PROBE_ALLOW_OK HVF_PROBE_DENY_ERROR HVF_PROBE_DENY_OK
    ;;
  missing-nic)
    printf '%s\n' HVF_PROBE_RUNTIME_OK HVF_PROBE_ALLOW_OK HVF_PROBE_DENY_ERROR HVF_PROBE_DENY_OK
    ;;
  missing-allow)
    printf '%s\n' HVF_PROBE_NO_NIC_OK HVF_PROBE_RUNTIME_OK HVF_PROBE_DENY_ERROR HVF_PROBE_DENY_OK
    ;;
  missing-deny)
    printf '%s\n' HVF_PROBE_NO_NIC_OK HVF_PROBE_RUNTIME_OK HVF_PROBE_ALLOW_OK
    ;;
  missing-audit)
    printf '%s\n' HVF_PROBE_NO_NIC_OK HVF_PROBE_RUNTIME_OK HVF_PROBE_ALLOW_OK HVF_PROBE_DENY_ERROR HVF_PROBE_DENY_OK
    ;;
  failure)
    exit 12
    ;;
esac
MOCK
chmod +x "${TEST_DIR}/target/debug/mvmctl"

cat >"${TEST_DIR}/bin/cargo" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${MOCK_CARGO_LOG}"
MOCK
chmod +x "${TEST_DIR}/bin/cargo"

run_smoke() {
  env \
    PATH="${TEST_DIR}/bin:${PATH}" \
    CARGO_TARGET_DIR="${TEST_DIR}/target" \
    MVM_HOME="${TEST_DIR}/state" \
    MOCK_EXPECT_HOME="${TEST_DIR}/state" \
    MOCK_CARGO_LOG="${TEST_DIR}/cargo.log" \
    MVM_HVF_ALLOW_HOST_ALLOW_UNSUPPORTED=1 \
    MVM_HVF_ALLOW_HOST_OUT_DIR="${TEST_DIR}/evidence" \
    MOCK_RESULT="${MOCK_RESULT:-success}" \
    bash "${ROOT}/scripts/check-hvf-oci-allow-host-smoke.sh"
}

run_smoke >"${TEST_DIR}/success.stdout"
grep -q 'HVF OCI allow-host smoke: PASS' "${TEST_DIR}/success.stdout"

grep -q -- '--features mvmctl/user' "${TEST_DIR}/cargo.log"
grep -q -- '--bin mvm-network-endpoint --bin mvm-hvf-supervisor' "${TEST_DIR}/cargo.log"

for result in missing-nic missing-runtime missing-allow missing-deny missing-audit failure; do
  if MOCK_RESULT="${result}" run_smoke >"${TEST_DIR}/${result}.stdout" 2>"${TEST_DIR}/${result}.stderr"; then
    echo "smoke unexpectedly passed with ${result}" >&2
    exit 1
  fi
done

if MVM_HVF_ALLOW_HOST_HOST=example.org MVM_HVF_DENY_HOST=example.org run_smoke \
  >"${TEST_DIR}/same-host.stdout" 2>"${TEST_DIR}/same-host.stderr"; then
  echo "smoke unexpectedly accepted identical allowed and denied hosts" >&2
  exit 1
fi

for bypass in MVM_SKIP_COSIGN_VERIFY MVM_SKIP_HASH_VERIFY; do
  if env MVM_HVF_ALLOW_HOST_ALLOW_UNSUPPORTED=1 "${bypass}=1" \
    bash "${ROOT}/scripts/check-hvf-oci-allow-host-smoke.sh" \
    >"${TEST_DIR}/${bypass}.stdout" 2>"${TEST_DIR}/${bypass}.stderr"; then
    echo "smoke unexpectedly accepted ${bypass}" >&2
    exit 1
  fi
  grep -q 'verification-bypass environment variables' "${TEST_DIR}/${bypass}.stderr"
done

echo "HVF OCI smoke shell tests: PASS"

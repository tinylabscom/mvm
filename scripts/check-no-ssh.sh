#!/usr/bin/env bash
# ADR-001 "no SSH in microVMs, ever" — absolute, no dev-tier carve-out.
#
# Fails if any genuine SSH-capability token appears in source: an SSH
# server/client package, a keypair or authorized_keys/known_hosts file, an
# sshd_config directive, ssh-agent forwarding, or an ssh/scp/git+ssh
# transport. A guest's only communication channel is vsock — nothing in
# this tree may install, launch, configure, or reach for SSH.
#
# Deliberately excludes a short, explicit allowlist of files that mention
# these same tokens in order to DETECT and REJECT SSH, never to enable it:
# the command-gate / threat-classifier secret-file blocklists, the inbound
# SSH-identification-banner network deny-scan (+ its test payloads), the
# secrets scanner's PEM-key-format detector comment, the Nix guest-store
# SSH-token deny-scan in mkGuest (+ its eval test), the explicit
# `services.openssh.enable = false`, and documentation prose that asserts
# the no-SSH promise. Excluding a file here is a one-way door — read the
# comment on the file you're excluding, and don't add to this list to
# paper over an actual SSH reintroduction.
set -euo pipefail

repo_root="${MVM_NO_SSH_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$repo_root"

PATTERN='sshd|openssh|ssh-keygen|ssh-keyscan|ssh-copy-id|authorized_keys|known_hosts|id_rsa|id_ed25519|id_ecdsa|id_dsa|PermitRootLogin|PubkeyAuthentication|sshd_config|SSH_AUTH_SOCK|ssh-agent|ProxyJump|\bscp\b|git\+ssh'

# Each entry below is a real, audited hit — not installed SSH capability.
ALLOWED_FILES=(
  # The gate itself: the pattern/comments above necessarily spell out
  # every banned token.
  "scripts/check-no-ssh.sh"
  # The gate's regression test includes generated-directory and source
  # fixtures to prove the scanner ignores the former and rejects the latter.
  "scripts/check-no-ssh.test.sh"
  # Command-gate + threat-classifier: blocklist/detector data that flags
  # `.ssh/id_rsa` access and `ssh-keygen` invocation as guest threats.
  "crates/mvm-core/src/crypto/command_gate.rs"
  "crates/mvm-core/src/crypto/threat_classifier.rs"
  # Capture excludes private-key-shaped project files from diagnostic
  # archives. These names are denylist data, never SSH capability.
  "crates/mvm-capture/src/collect/project.rs"
  # Host-share parser test: proves the user's SSH credential directory and a
  # private-key-shaped child path are refused as guest mount sources.
  "crates/mvm-cli/src/commands/shared/parse.rs"
  # Secrets scanner: a one-line comment naming "OpenSSH" as one of the PEM
  # private-key formats its generic BEGIN-block regex redacts.
  "crates/mvm-hostd/src/supervisor/secrets_scanner.rs"
  # Inbound network scan that drops SSH server identification banners
  # (`SSH-2.0-...`) on any TCP port; its tests construct fake banner bytes.
  "crates/mvm-hostd/src/supervisor/network/stages.rs"
  # mkGuest's own SSH deny-scan: rejects any package/extraFile/Nix-store
  # closure path that looks SSH-shaped before a guest image is built.
  "nix/lib/mk-guest.nix"
  "nix/tests/mk-guest-eval.nix"
  # Explicit `services.openssh.enable = false` on the minimal profile.
  "nix/profiles/minimal.nix"
  # Docs asserting the no-SSH promise / listing airgapped file-transfer
  # options unrelated to guest communication.
  "public/src/content/docs/guides/airgapped-bootstrap.md"
  "public/src/content/docs/guides/building-microvm-images.md"
  "public/src/content/docs/reference/cli-commands.md"
  "public/src/content/docs/guides/machine-limitations.md"
)

is_allowed() {
  local f="$1"
  local allowed
  for allowed in "${ALLOWED_FILES[@]}"; do
    [ "$f" = "$allowed" ] && return 0
  done
  return 1
}

echo "::group::Scanning for banned SSH tokens"
violations=""
while IFS= read -r match; do
  [ -z "$match" ] && continue
  file="${match%%:*}"
  if is_allowed "$file"; then
    continue
  fi
  violations+="$match"$'\n'
done < <(
  grep -rniE \
    --exclude-dir=.git \
    --exclude-dir=.mvm-test \
    --exclude-dir=.venv \
    --exclude-dir=node_modules \
    --exclude-dir=target \
    --exclude-dir=dist \
    "$PATTERN" crates/ nix/ scripts/ public/ examples/ 2>/dev/null || true
)

if [ -n "$violations" ]; then
  echo "::endgroup::"
  echo "::error::ADR-001 violation: SSH-shaped identifiers found in source." >&2
  printf '%s' "$violations" >&2
  echo "" >&2
  echo "SSH of any kind is banned by ADR-001 — guest communication is vsock only." >&2
  echo "If this is a genuine deny/detect pattern or a no-SSH assertion, add the" >&2
  echo "file to ALLOWED_FILES in scripts/check-no-ssh.sh with a comment explaining" >&2
  echo "why it isn't installed SSH capability." >&2
  exit 1
fi
echo "::endgroup::"
echo "ok: no banned SSH tokens in crates/, nix/, scripts/, public/, examples/"

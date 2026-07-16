#!/usr/bin/env bash
# ADR-001 "no SSH in microVMs, ever" — absolute, no dev-tier carve-out.
#
# The tree once carried a dev-tier ssh-agent-forwarding feature (host
# SSH_AUTH_SOCK -> vsock port 5301 -> guest /run/mvm/ssh-agent.sock) that
# handed a guest the host's whole ssh-agent, bypassing the bound-destination
# secret-substitution model. It was removed entirely. This gate is the
# regression backstop: it fails if any ssh-agent-forwarding-shaped identifier
# reappears in source.
#
# Deliberately narrow patterns — NOT a bare "ssh" grep. This repo has
# legitimate, wanted "ssh" hits unrelated to agent forwarding: BANNED_SSH_PORT
# / is_banned_ssh_port (the TCP/22 egress ban), the SSH banner protocol-deny
# scan, and the secrets/threat classifier's `.ssh/id_rsa`-shaped detectors. A
# bare "ssh" pattern would false-positive on all of those; `ssh.?agent`,
# `SSH_AUTH_SOCK`, and `SSH_AGENT_PORT` only match the forwarding feature.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PATTERN='ssh.?agent|SSH_AUTH_SOCK|SSH_AGENT_PORT'

echo "::group::Scanning crates/ for banned ssh-agent-forwarding identifiers"
if matches=$(grep -rniE "$PATTERN" crates/ --include='*.rs' 2>/dev/null); then
  echo "::endgroup::"
  echo "::error::ADR-001 violation: ssh-agent-forwarding identifiers found in crates/ source." >&2
  echo "$matches" >&2
  echo "" >&2
  echo "SSH forwarding of any kind is banned by ADR-001 — see \"Dev-VM mutation boundary\"." >&2
  echo "This feature was removed on purpose; do not reintroduce it." >&2
  exit 1
fi
echo "::endgroup::"
echo "ok: no ssh-agent-forwarding identifiers in crates/ source"

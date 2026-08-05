#!/usr/bin/env bash
# Compatibility entry point for callers of the former console symbol gate.
# The shared runtime-boundary suite covers console, exec, process-control, and
# detached requests through profile and signed-grant behavior.

set -euo pipefail
exec "$(dirname "$0")/check-prod-agent-no-exec.sh"

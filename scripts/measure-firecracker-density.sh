#!/usr/bin/env bash
set -euo pipefail

# The HVF script is also the shared density runner; keep one launch and sampling path.
export MVM_HVF_DENSITY_BACKEND=firecracker
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/measure-hvf-density.sh" "$@"

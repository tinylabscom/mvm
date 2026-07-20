# `ops/bootstrap/`

First-time host setup. Run once per machine, manually, with eyes open.

| Script | Mutates | Why elevated |
|---|---|---|
| [`install.sh`](install.sh) | Downloads + installs the `mvmctl` binary into a system path; may run `sudo install`. | Writing to `/usr/local/bin` or similar requires sudo on most hosts. Idempotent (re-running upgrades in place). |
| [`dev-setup.sh`](dev-setup.sh) | Installs Lima (via Homebrew/apt/dnf/pacman/Nix-env or binary download from GitHub releases). May run package-manager commands with sudo. | Package-manager installs need root on most hosts. Idempotent (no-op if Lima already present). |

Neither script is invoked by `mvmctl`, `nix develop`, or any flake
output. Both are intentionally outside the automated path so the user
sees exactly what runs as root.

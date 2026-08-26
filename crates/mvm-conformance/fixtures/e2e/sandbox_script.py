"""Runtime-SDK fixture for the end-to-end launch suite.

The README's runtime SDK shape, reduced to the operations the transport has to
carry: create a sandbox, write a file into it, run a command in it.

Two deliberate departures from the README's illustrative snippet, both because
this one has to actually execute on both the plan and the live path:

* `commands.start` rather than `exec`. Both are real SDK surfaces, but `exec` is
  live-only — under `MVM_SDK_MODE=record`, which `mvmctl run --mode plan` uses
  to lower a script into a signed plan without booting, it raises
  `SandboxModeError`. `commands.start` appends an op that both modes carry.

* The image is digest-pinned. Plan-mode admission refuses a mutable reference
  before any network fetch (claim 14), so `image="alpine"` cannot be admitted.
  A digest is content-addressed and immutable, so this does not rot with the
  upstream `alpine:latest` tag.
"""

import mvm

ALPINE = (
    "docker.io/library/alpine"
    "@sha256:e7a1a92a5bfeee40966aea60f0796b0e7917cc35591542701834f03a68fa3d18"
)

with mvm.Sandbox.create(image=ALPINE) as sb:
    sb.files.write("/app/main.sh", "echo hello from the runtime sdk\n")
    sb.commands.start(["uname", "-s"])

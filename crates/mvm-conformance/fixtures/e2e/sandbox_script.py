"""Runtime-SDK fixture for the end-to-end launch suite.

The README's runtime SDK shape, reduced to the operations the transport has to
carry: create a sandbox, write a file into it, and run a command.

Two deliberate departures from the README's illustrative snippet, each because
this one has to actually execute on both the plan and the live path:

* `commands.start` rather than `exec`. Both are real SDK surfaces, but `exec` is
  live-only — under `MVM_SDK_MODE=record`, which `mvmctl run --mode plan` uses
  to lower a script into a signed plan without booting, it raises
  `SandboxModeError`. `commands.start` appends an op that both modes carry.

* The image is digest-pinned. Plan-mode admission refuses a mutable reference
  before any network fetch (claim 14), so `image="alpine"` cannot be admitted.
  A digest is content-addressed, so this does not rot with the upstream
  `alpine:latest` tag.

`files.write` is back. It was removed when the whole guest-RPC `fs`/`proc` verb
family answered "Unexpected response to ... verb" against a running HVF guest
(#2887); that turned out to be a grant refusal misreported as a protocol
mismatch, and the grant half is fixed too — a `--profile dev` launch now carries
the DevOnly verbs. `/tmp` rather than the README's `/app`: the workload root is
mounted read-only, so a tmpfs path is what a reader can actually write to
without declaring a share.
"""

import mvm

ALPINE = (
    "docker.io/library/alpine"
    "@sha256:e7a1a92a5bfeee40966aea60f0796b0e7917cc35591542701834f03a68fa3d18"
)

with mvm.Sandbox.create(image=ALPINE) as sb:
    sb.files.write("/tmp/hello.txt", "hi from mvm")
    sb.commands.start(["uname", "-s"])

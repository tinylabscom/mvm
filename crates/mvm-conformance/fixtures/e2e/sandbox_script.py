"""Runtime-SDK fixture for the end-to-end launch suite.

The README's runtime SDK shape, reduced to the operations the transport has to
carry: create a sandbox and run a command in it.

Three deliberate departures from the README's illustrative snippet, each because
this one has to actually execute on both the plan and the live path:

* `commands.start` rather than `exec`. Both are real SDK surfaces, but `exec` is
  live-only — under `MVM_SDK_MODE=record`, which `mvmctl run --mode plan` uses
  to lower a script into a signed plan without booting, it raises
  `SandboxModeError`. `commands.start` appends an op that both modes carry.

* The image is digest-pinned. Plan-mode admission refuses a mutable reference
  before any network fetch (claim 14), so `image="alpine"` cannot be admitted.
  A digest is content-addressed, so this does not rot with the upstream
  `alpine:latest` tag.

* No `files.write`. The README shows one, and it is a real surface, but the
  whole guest-RPC `fs`/`proc` verb family currently answers "Unexpected response
  to ... verb" against a running HVF guest — see issue #2887, which predates
  this suite. `commands.start` below hits the same wall, which is why the
  live-mode scenario driving this fixture is tagged `@wip` on that issue. The
  plan-mode scenario needs no guest and stays green. Restore `files.write` when
  #2887 is fixed.
"""

import mvm

ALPINE = (
    "docker.io/library/alpine"
    "@sha256:e7a1a92a5bfeee40966aea60f0796b0e7917cc35591542701834f03a68fa3d18"
)

with mvm.Sandbox.create(image=ALPINE) as sb:
    sb.commands.start(["uname", "-s"])

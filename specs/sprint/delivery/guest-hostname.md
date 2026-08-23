# Guest hostname follows the machine name

Delivered 2026-08-21.

Issue #2789 is closed at the shared host/guest boundary. Every cold workload
backend now carries the validated machine name as `mvm.hostname=` in the one
shared kernel-cmdline assembler, and privileged guest bootstrap applies it with
`sethostname` before workload code starts. Shared warm parents remain
identity-free; their restored children receive the final machine name in the
existing post-restore identity handshake. Invalid names cannot inject cmdline
tokens, the guest re-validates both paths, missing optional fields preserve
legacy compatibility, and syscall errors are reported without a panic.

Focused tests cover the shared backend path, malformed input, missing input,
syscall failure, the artifact boot-argument validator, warm-parent parity, the
post-restore wire round trip, and a live BDD `/bin/hostname` scenario. The
generated protocol schema and Python and TypeScript bindings carry the optional
post-restore hostname, and the code-generation drift gate passes.

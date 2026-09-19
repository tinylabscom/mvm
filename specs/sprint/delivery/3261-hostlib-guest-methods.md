# The host library answers guest process and file methods

Issue #3261, the guest half of task 7. It stacks on the guest-operations move.

`mvm-hostlib` gains thirteen `guest.*` methods:
`guest.proc.{start,list,signal,kill,stdin,wait}` and
`guest.fs.{read,write,list,stat,mkdir,remove,rename}`. Each goes through
`mvm_client::guest`, the implementation `mvmctl machine proc`/`fs` use, so a
call made through the library records the same audit entries as the same
operation through the CLI.

- Every request names the machine by `id`, and request types refuse unknown
  fields.
- Byte payloads (stdin, file contents, process output) cross as base64. A
  payload that is not base64 is refused before anything is sent.
- `guest.proc.wait` returns once, so it buffers each output stream. Past
  8 MiB (`WAIT_OUTPUT_CAP`) the rest of a stream is dropped and the reply says
  `truncated`, rather than growing the host process without bound. Streaming
  through a handle is later work.
- These are DevOnly agent verbs. The agent refuses them on a sealed image, and
  that refusal, like any failure to reach the machine, reaches the binding as
  `BACKEND_ERROR` carrying the agent's message.
- The embedder declarations happen before a guest call too, since the
  transport probe resolves helper paths.

Internally, `mvm_hostlib_call` now takes its answers from a small `Services`
trait (a client for `machine.*`/`backend.*`, guest operations for `guest.*`),
and the guest operations sit behind a `GuestOps` trait. That lets dispatch be
tested against recording doubles without a running machine.

## Validation

- `cargo nextest run -p mvm-hostlib`: 39/39 passed. The guest tests cover
  argument pass-through for every method, base64 decoding and its refusal,
  wait output collection, the truncation cap, an agent error ending a wait,
  a failed operation's error body, unknown fields, and an invalid machine name
  through the real implementation.
- In-process from `python3` through `ctypes`: `guest.proc.list` on an absent
  machine answered status 3 with the transport's message; an unknown field and
  a non-base64 payload were each refused with status 8.

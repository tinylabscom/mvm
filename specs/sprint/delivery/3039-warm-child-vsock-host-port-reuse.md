# #3039 — a warm child's post-restore session was reset by its own guest

The last failure behind #3039. After the parent-activation fix, an HVF warm
claim still failed intermittently with

```
signaling post-restore to vm-…: guest agent transport error:
host session handshake failed: session i/o error: Broken pipe (os error 32)
```

while the parent's console logged `control peer disconnected before completing
the handshake`. Each side saw the other hang up, which pointed at the transport
rather than either endpoint. It was two defects in the vsock device, both
reproduced on macOS 26.6 / HVF and both fixed here.

## 1. Every vCPU rebound the device on the way out of a pause

`prepare_snapshot` and `resume_after_snapshot` are called from the run loop, and
every vCPU of an SMP machine runs its own copy of that loop against one shared
device. The guard that was meant to make the transition happen once was a local
in each loop. A 2-vCPU standby therefore rebound its host channels twice on
resume. The first vCPU to leave the hold runs guest code at once, so the second
rebind could land while the host was mid-handshake — and a rebind runs
`shutdown`, which cancels every live stream.

The device now tracks whether it is parked, so the hooks act once per pause.

## 2. Host ports restarted from the first port on every rebind

Host-assigned ports are the guest's identity for each host-initiated
connection. `clear_host_bindings` replaced the handler registry wholesale, and
with it both bridges' port counters, so every rebind handed out ports from the
first one again.

That collided with state the guest still held. The parent's activation session
closes just before capture; its `OP_RST` is queued, and the pause's `cancel`
drops it before the paused guest can read it. The snapshot freezes a guest that
still believes that port is connected. On claim, the reset registry reissued the
same number, and the guest kernel reset the new `OP_REQUEST` on sight. Whether a
claim failed depended only on *which* connection drew the stale number, which is
why it was intermittent.

Measured with a per-connection port trace, in both a failing and a passing run
the port the guest reset during the claim was exactly the parent's last port
before capture. In the failing run it was the post-restore session; in the
passing run it was a throwaway reachability connect.

The registry now carries a `HostPortCursor` across every rebind, and the vsock
device snapshot carries it too, so a child restored into a new process with a
fresh device continues past the parent's numbering. A snapshot cursor below
either bridge's first port is refused by `restore_state`.

## Evidence

| build | warm claims succeeding |
|---|---|
| before | 0 / 2 |
| vCPU fix only | 8 / 13 |
| both fixes, port-traced | 10 / 10, zero guest resets during any claim |
| both fixes, untraced | 10 / 10 |

Each tested with `MVM_RESIDENCY=warm`, under which a failed claim refuses rather
than falling back to a cold boot; the pool ended with no dead standbys.

## Do not diagnose this with `MVM_HVF_AGENT_DEBUG`

The full vsock trace writes a line per packet — about 22,000 across a warm and a
claim — and slows the device enough that both rebinds land before the host
connects. The claim then *succeeds*. The race is invisible under the tool built
to show it. The port trace used here logged one line per connection event and
still reproduced the failure.

## Tests

- `a_second_vcpu_leaving_the_pause_hold_keeps_the_first_ones_connections` — red
  before the fix with "the second vCPU's resume closed a connection the first
  one served".
- `a_rebind_never_reissues_a_host_port` — red before with "a rebind reissued
  host port 1048576 after 1048576 had already been handed out".
- `a_restored_device_continues_host_port_numbering_from_its_snapshot`
- `a_snapshot_with_a_host_port_cursor_out_of_range_is_refused`

## Not resolved

One run, with only the vCPU fix in place, failed differently:
`HVF parent rejected live handoff: ERR`. Its cause was not captured: the parent
replied with a bare `ERR` and recorded the reason only in the debug trace, and
the host read exactly three bytes of the reply. It did not recur in the twenty
runs after both fixes, so it is recorded here rather than claimed fixed.

The next occurrence will say why. The parent now replies `ERR <reason>` on one
bounded line and the host reads through the newline, so the claim error carries
the refusal — witnessed end to end by `a_refused_handoff_tells_the_host_why`.

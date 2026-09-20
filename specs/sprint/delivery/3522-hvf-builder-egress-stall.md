# HVF builder egress: a lost session no longer hangs the build

Backing: shipped-source
Validation: a_dead_session_after_a_reconnect_is_waited_on_not_spun_on

W4c of `specs/plans/2026-09-16-image-repository-extraction.md` recorded a build
through the HVF builder that lost its FlowMux egress session about eight minutes
in and then sat with one guest CPU busy until the 90-minute limit. The failure
reproduces at `768a3d7a3f` with the published `boot-image/v0.1.5` builder, so the
`mvm-images` builder was never the cause. Issue #3522 has the logs from both
runs.

## What ended the session

Three host-side defects each end a session, and the W4c logs show two of them:

- **Bytes dropped at the vsock bridge.** `write_nonblocking` gave up after
  10,000 `yield_now` spins on `WouldBlock` and discarded the rest of the payload,
  while the device still credited every byte to the guest. A macOS Unix stream
  socket buffers 8 KiB, so an endpoint process that the host scheduler leaves
  waiting overflows it quickly. The endpoint then parsed a stream with a hole in
  it: W4c's first session ended with `invalid handshake: timestamp not utf-8`.
  The bridges now queue what the socket refuses (`HostWriteBacklog`) and credit
  only the bytes the socket accepted. The guest's window therefore closes while
  the endpoint is stalled. The host-I/O loop retries on a 1 ms timer while
  anything is queued. The agent and console bridges shared the helper and get
  the same fix. `fwd_cnt` now wraps like the guest's own counter instead of
  saturating after 4 GiB.
- **A frame after the stream's `Reset`.** The relay checked `retired` before
  taking the session lock. That let a `HalfClose` follow the session thread's
  `Reset` onto the wire, and the guest validator ended the session over it
  (`opcode 0x15 names unopened stream 107` in the reproduction). A stream the
  relay had already reset was also reset a second time when the guest's
  in-flight data arrived. Relay frames now go through `write_stream_frame_to`,
  which checks `retired` under the session lock, and whichever side sets
  `retired` first sends the stream's only `Reset`.
- **`GoAway` for a late guest frame.** A guest `Data` or `HalfClose` naming a
  stream the host had just reset was answered with `GoAway`, which ended the
  session and every flow on it. That frame is now dropped. W4c's second session
  ended this way, four seconds after it started.

The transport's 60-second idle eviction also reset a trusted builder's session
whenever a derivation compiled for a minute without fetching. That killed any
flow open at the time. `EgressLimits::trusted_builder()` already documented the
exemption; the relay ports of a trusted builder are now exempt at the transport
too.

## Why it spun instead of failing

`FlowMuxReconnectClient::active_client` read its snapshot with `borrow()`, which
does not mark a watch value seen. Once the reconnect loop had replaced the
session one time, a dead session sent the loop back to the same dead snapshot
without ever awaiting. One tokio worker spun (31.7 minutes of user time in the
reproduction), `CALL_TIMEOUT` could not fire, and no reconnect was attempted.
It now uses `borrow_and_update`. Each reconnect attempt is bounded by
`attempt_timeout`, dial and handshake together. When the reconnect owner gives
up, `mvm-egress-client` exits with a message naming the lost session, so the
build fails at the next fetch instead of waiting out the wall clock.

## Not done

- The host session validator still records no host-originated `Reset` or
  `HalfClose`. Streams the host ends keep their validator entries for the life
  of the session, and those entries count against `MAX_TCP_FLOWS`. This comes
  from reading the code; no run has hit it. Tracked in #3522.
- Both reproductions ran at a host load average of 125 to 260, not the 20 to 50
  the investigation asked for; the host did not get quieter while this work was
  in progress. None of the defects above depends on load to fire. The
  byte-dropping one only becomes likely under load.

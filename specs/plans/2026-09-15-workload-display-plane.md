# A display plane that is view-only until a signed plan says otherwise

Backing: preview
Validation: P0 is backed by shipped source, workspace tests, `just check-gated`, and `check-single-display-path`; P1–P3 remain proposed.

**Issues:** epic [#3276](https://github.com/tinylabscom/mvm/issues/3276); [#3265](https://github.com/tinylabscom/mvm/issues/3265), [#3266](https://github.com/tinylabscom/mvm/issues/3266), [#3267](https://github.com/tinylabscom/mvm/issues/3267)

## Outcome

Two things a sandbox for AI agents needs and mvm cannot do today: watch what the
agent is doing, and let a human complete a UI step the agent cannot (an OAuth
consent screen, a "click accept", a sign-in). Both are delivered without a guest
NIC, without a listener inside the guest, and without quietly turning claim 15
into a series of retreats.

The design separates them deliberately, because they are not the same risk.
Watching is a host←guest stream and adds no path toward the guest at all.
Completing a login is a host→guest input path, and it is the one that has to be
bounded, granted, and audited.

## Constraints found in the tree

- **The HVF VMM has no display or input device, and nothing adjacent to one.**
  `crates/mvm-vmm/src/vmm/run.rs` has exactly four `RunDevice` impls — PL011,
  virtio-blk, virtio-rng, virtio-vsock. No virtio-gpu, no virtio-input, no
  ramfb, no framebuffer anywhere in `crates/mvm-vmm` or `crates/mvm-backends`.
- **Firecracker has no display device and will not get one.** Our FC driver
  (`crates/mvm-backends/src/driver/fc.rs`) configures boot source, machine
  config, drives, vsock, balloon. A device-model display is therefore HVF-only
  by construction — that is, never the Linux production backend.
- **The guest kernel removes the entire display and input stack on purpose.**
  `nix/images/kernel/base.nix` force-disables `DRM`, `FB`, `VT`, `INPUT`,
  `SERIO`, `KEYBOARD_ATKBD`, `MOUSE_PS2`, `HID_SUPPORT`, `USB_SUPPORT`, `SOUND`,
  with a comment recording that the console is `hvc0` plus vsock. Re-enabling
  them moves the per-arch ratchet in `xtask/src/check_kernel_config_budget.rs`,
  and DRM is one of the larger CVE surfaces in the kernel.
- **The control machinery we need already exists.** `InputGate::open` returns a
  single-writer lease with a TTL and a refusal ladder
  (`crates/mvm-hostd/src/stream/input_gate.rs`); vsock ports are enumerated and
  allow-listed (`crates/mvm-agentd/src/vsock/mod.rs`, W1.3); `VerbGrant`
  carries a signed, time-bound verb subset.

The consequence that shapes everything below: **a software-rendered display
needs no kernel change and no VMM change.** A headless compositor or headless
browser renders into memory, touching neither DRM nor FB, and virtual input
protocols are userspace. So frames-over-vsock works identically on HVF,
Firecracker, libkrun and QEMU today, and virtio-gpu buys us one backend at the
cost of a kernel-budget raise.

## What the adjacent project got wrong, and why it matters to us

An adjacent computer-use sandbox project ships display as a **second control
plane**: a VNC or xpra listener inside the guest, its own credential, no
relationship to policy or audit. In their tree the viewer password is printed
into a URL, a container entrypoint overrides the loopback bind with `0.0.0.0`,
and the screenshot/click/type websocket authenticates only when a cloud-only
environment variable happens to be set. The lesson is not "they forgot auth" —
it is that screenshot + click + type *is* full interactive control, and once it
is a separate plane, nothing relates it to what the workload was admitted to do.

Our non-negotiable: the display plane is the *same* plane. Vsock only, plan
gated, chain audited, no guest listener on any interface.

## Options considered

| | Mechanism | Backends | Kernel change | Verdict |
| --- | --- | --- | --- | --- |
| A | In-guest headless compositor (`cage`/`weston --backend=headless`/Xvfb), frames and input over a dedicated vsock port | all four | none | Later, when a non-browser GUI app is actually asked for |
| B | virtio-gpu 2D + virtio-input on HVF, host-owned framebuffer | HVF only | raises DRM/INPUT/HID budget | Unbuilt unless accelerated rendering becomes a requirement |
| C | Headless browser + CDP screencast over vsock | all four | none | **Prototype first** — covers OAuth, consent, CAPTCHA completely |

C's trap, and also its feature: CDP is an omnipotent debugging API
(`Runtime.evaluate`, `Fetch.fulfillRequest`, `Network.setCookie`). The host must
speak it through a method allow-list in the guest agent and never tunnel the raw
endpoint. That allow-list is what makes the auditable surface a dozen named
methods instead of "arbitrary pixels and keystrokes".

## The honest security answer on human handoff

A human typing a password into the guest does not violate claim 13 as written —
"no raw secret value crosses the broker channel", and nothing crosses the
broker. It does violate the property people believe we have.

And the password is not the real problem. The residue is: the resulting session
cookie and refresh token then live in guest memory and on guest disk, readable
by the workload, shippable to any destination its egress policy allows. Worse,
the warm-fork and checkpoint machinery (`crates/mvm-vmm/src/checkpoint.rs`,
`snapshot.rs`) would copy a live human session into every forked child. That is
an artifact class we do not reason about today.

Hence the ordering below: the host-side OAuth broker (P1) comes before
interactive input (P2), because for most flows it removes the need entirely.

Note one inversion. The stdin plane's secret scan exists to *refuse*
secret-shaped bytes (`crates/mvm-hostd/src/stream/secret_scan.rs`). Display
input deliberately carries human-typed secrets, so it must reuse the lease,
ordering and audit machinery and **not** that scan. And frames defeat text
redaction outright: `redact.rs` is line-oriented and cannot redact a JPEG.

## P0 — `display.view`, with no input path in the tree

Issue: [#3265](https://github.com/tinylabscom/mvm/issues/3265).

**Status: COMPLETE (2026-09-19).** Delivery evidence:
`specs/sprint/delivery/3265-view-only-display-plane.md`.

- [x] Add a display vsock port constant to `crates/mvm-agentd/src/vsock/mod.rs`
      and its entry in the host proxy allow-list.
- [x] Guest-side CDP screencast bridge in `crates/mvm-agentd`, speaking a fixed
      method allow-list. No raw CDP passthrough.
- [x] Host frame sink into the stream plane
      (`crates/mvm-hostd/src/stream/{fanout,journal,durable}.rs`), with frame
      digests written to the chain and bytes held under `stream_retention`.
- [x] Viewer bound to loopback only, with a one-shot per-session token.
- [x] `xtask check-single-display-path`, modelled on
      `check_single_network_path.rs`: exactly one display spawn site, no guest
      listener, no non-loopback bind, and no second frame transport.
- [x] A per-agent-step frame sample, so "watch what the agent did" is an
      observability feature rather than an interactive session.
- [x] Witnesses: `display_view_grant_opens_no_input_route`,
      `display_frames_never_leave_loopback`.

P0 adds no host→guest byte path, so claim 15 is untouched. It should ship and be
evaluated on its own.

## P1 — Host-side OAuth broker

Issue: [#3266](https://github.com/tinylabscom/mvm/issues/3266).

- [ ] Complete consent in a **host** browser; store the resulting token in the
      supervisor; inject it per request through the existing substitution
      endpoint (`crates/mvm-hostd/src/supervisor/`,
      `crates/mvm-hostd/src/bin/mvm-network-endpoint.rs`). The guest receives a
      placeholder, destination-bound exactly as claim 13 already works.
- [ ] Extend the secret binding model to cover an OAuth token's refresh, so a
      long agent run does not need a second human step.
- [ ] Witness: `oauth_token_substituted_at_endpoint_never_reaches_guest`.

This strengthens the story instead of weakening it, and covers any site with an
API behind the login — which is most of them.

## P2 — `display.input`, attended tier only

Issue: [#3267](https://github.com/tinylabscom/mvm/issues/3267).

- [ ] Two separate grants, not one: `display.view` (frames guest→host) and
      `display.input` (events host→guest), as distinct `VerbGrant` verbs and
      distinct plan grant fields, so view-only is provably input-free rather
      than input-disabled.
- [ ] Refuse `display.input` on the sealed prod tier unless the signed plan
      carries an explicit attended grant. `mvmctl doctor` and `machine ls`
      report the run as attended.
- [ ] Lease, ordering and TTL reuse `InputGate`; the secret scan is
      deliberately not reused.
- [ ] Audit `display.granted`, `display.refused`, `display.input_event` —
      event kinds and counts, never keycodes.
- [ ] Clipboard is a third grant, default off. Bidirectional clipboard is an
      unaudited byte channel in both directions.
- [ ] For a run where a human credential is entered: a signed
      `human_credential: true` marker, egress narrowed to that session's
      destinations, checkpoint and fork refused for the remainder of the run,
      and recording auto-paused between `display.credential_entry_begin` and
      `_end`.
- [ ] Witnesses: `display_input_refused_without_grant`,
      `display_refused_on_sealed_tier_without_attended_grant`,
      `fork_refused_after_human_credential_entry`.

## P3 — Generalize to a headless compositor

- [ ] Only when a non-browser GUI application is actually requested. Option B
      (virtio-gpu) stays unbuilt unless accelerated rendering becomes a hard
      requirement; it is HVF-only and re-admits DRM to a guest we spent real
      effort emptying.

## The claim this earns, and its limits

Proposed, once P0 and P2 land:

> A workload's display plane is view-only unless the signed plan grants input;
> no display transport listens on any network interface; and every frame sample
> and input lease is recorded in the chain-signed audit log.

Witnesses: `check-single-display-path`, the three P2 witnesses above, plus a
kernel-config assertion that the workload kernel still carries no `DRM`, `FB`,
`INPUT` or `HID` — which is what keeps options A and C honest.

Limits to state in the ledger row rather than the prose: a human-supplied
credential typed into a guest **is** inside that guest; frames defeat text
redaction; and an attended run is not the same security tier as an unattended
one.

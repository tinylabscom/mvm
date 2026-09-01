# Egress refusal status contract

Issue #3040 exposed that the guest loopback HTTP proxy translated every failed
FlowMux TCP open into `502 Bad Gateway`. That erased the distinction between a
host refused before any upstream connection was attempted and an admitted host
whose upstream connection actually failed.

## Delivery checklist

- [x] Add a wire-stable `ConnectFailed` FlowMux outcome for an admitted target
      whose upstream connection fails, and bump the behavior revision.
- [x] Preserve `Refused` for policy decisions and surface it to HTTP clients as
      `403 Forbidden`.
- [x] Preserve genuine upstream and transport failures as `502 Bad Gateway`.
- [x] Cover the host decision, guest decoding, status mapping, discriminant,
      direction, state-machine, and handshake-revision contracts.
- [ ] Pass workspace tests, Clippy, formatting, gated-target checks, and the
      sprint/refactor documentation gates.
- [ ] Merge the repair through the queue and close issue #3040 from the merged
      evidence.

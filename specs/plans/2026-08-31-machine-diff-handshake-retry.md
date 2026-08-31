# machine diff handshake retry

Backing: shipped-source
Validation: check-sprint-append

## Goal

Make `machine diff` tolerate a control peer that closes before completing the
authenticated session handshake without ever replaying an RPC that may have
reached the guest.

## Checklist

- [x] Trace `machine diff` through the backend-aware transport and authenticated
      session opener.
- [x] Distinguish a typed pre-authentication peer hangup from an EOF while
      reading an operational response.
- [x] Retry the former once on a fresh connection and keep the budget bounded.
- [x] Add regressions for success-after-retry, no post-request replay, and a
      peer that hangs up twice.
- [ ] Run workspace validation and merge the repair through the queue.

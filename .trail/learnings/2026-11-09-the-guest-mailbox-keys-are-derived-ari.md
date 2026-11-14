---
title: "The guest mailbox keys are derived from the host signer, not provisioned separately"
author: Ari
date: 2026-11-09
branch: main
cost: { minutes: 21, tokens: 20504 }
id: l-8df1fcfc
scope: repo
status: active
src: agent
touches:
  - crates/mvm-hostd/src/mailbox_service.rs
---

## Decided
The host-held mailbox material (encryption key, sender signing identity, sealing capability) is derived from the existing host signing key under its own domain separator. Routing and guest socket paths come from the launch request. The owner chose this because it adds nothing to provision and matches the earlier choice that the host signer is the mailbox authority.

## Tried and ruled out
- A separate mailbox keypair directory under the keys dir: cleaner separation, but more surface and a rotation story to design before the demo.
- Fleet-provisioned material from mvmd: does not fit a single-host demo.

## Watch out
The host signer key doubles as the mailbox authority, so a grant naming any other authority key is refused at serve time. The guest must never receive a derived key: not on the cmdline, not in the rootfs, not in the outbox path.

In the code: grant authority and serving in `crates/mvm-hostd/src/mailbox_service.rs` (`serve_granted_guest`, `GuestSealer::with_grant`); grant minting in `crates/mvm-client/src/admission/mailbox_grant.rs`.

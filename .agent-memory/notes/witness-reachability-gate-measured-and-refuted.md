---
title: A witness-reachability gate was measured over all 84 fn: witnesses and found nothing — do not build it
date: 2026-09-01
tags: [gates, claims-ledger, xtask, falsification, dead-code]
---

`CLAUDE.md` names the hole plainly: the claim gate "proves a named witness
*exists*, never that anything calls the code it tests". Claim 13's old witness
round-tripped an encoder no backend builds and no guest parses, so the hole is
real and it has cost us once. The obvious fix is a gate that refuses a witness
whose subject has no production caller.

**Measured before building. It finds nothing, and it cannot be made to.**

Method: `check-dormant-controls`' exact caller rule — production `.rs` under
`crates/` excluding `target`/`tests`/`fuzz`/`benches`, `#[cfg(test)]` modules
brace-stripped, `use` and `pub use` lines dropped, the defining file excluded —
applied to every `fn:` witness in the ADR-001 ledger. Subjects for a test-defined
witness were inferred as the workspace `fn` names appearing in its body.

## Results over 84 witnesses

| | count |
|---|---|
| Not found anywhere | **0** — `check-claim-catalog` is doing its job |
| Defined in production source | 10 |
| Defined only in test context | 74 |
| Production-defined with no caller | 1 |
| Test-defined with ≥1 dead subject | 20 |
| **Survivors after removing the two noise classes** | **4** |
| **Genuine findings after reading all six survivor symbols** | **0** |

## Why every hit was false, and why that is structural

- **The defining-file exclusion dominates.** A symbol used inside its own
  module reads as dead. `set_no_new_privs` — claim 2's witness — is called at
  `mvm-seccomp-apply.rs:98`, twelve lines above where it is defined, and the
  rule cannot see it. Same for `read_scope_unit`, `virtiofs_mount_flags`,
  `host_cpu_mechanism_gap`, `emit_dns_query`, `validate_guest_mount`.
  `check-dormant-controls` escapes this only because a human hand-picks each
  control, and picks cross-module ones.
- **Trait dispatch is invisible to text.** `teardown_paused` is a trait method
  called as `io.teardown_paused()`; no text rule connects that to the impl.
- **Name collisions merge distinct symbols.** Two `tier_for_vm` definitions in
  different modules become one name, and one definition's caller sits in the
  other's file.
- **Test support deliberately lives in production source.** A cross-crate test
  helper has to be `pub` and outside `#[cfg(test)]` to be visible from another
  crate. `pretend_mechanism_present`, `rendered_argv`, and the `CannedIO`
  builder `with_network_interfaces` are all correct as written and all read as
  dead.

Inferring the subject is the part that cannot be fixed. Every hit needed a
human to read six lines and say "no", which is what the gate was supposed to
replace.

## Also refuted: blanking comments in the caller haystack

`check-dormant-controls` documents the limit "a symbol named in a comment
counts as a caller", and blanking comments looked like a free improvement —
it is the same fix that closed
[[a-citation-can-resolve-to-its-own-test-fixture]]. Measured on this
population: **zero witnesses change verdict**. Not one symbol's only caller was
a comment. It may still be worth doing for the hand-declared controls in
`xtask/dormant-controls.toml`, but it is not the lever it looked like.

## What would actually close the hole

Not text analysis. Either a real call graph, or — cheaper and in this
repository's existing idiom — the ledger declaring each witness's subject
explicitly, the way `dormant-controls.toml` declares a control and its defining
file. That is 84 hand-written declarations and a decision about who maintains
them, which is a different and much larger piece of work than a gate.

Until then the hole stays open and stays documented. That is the honest state.

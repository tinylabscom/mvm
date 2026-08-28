# The back-compat shims that weren't

A keyword sweep for `back-compat` / `backwards compat` / `preserved for
compatibility` turned up about ten sites. Most of them are not legacy code.

## What the keyword was actually describing

Six of the hits are `#[serde(default)]` on a new optional field, or a test
asserting that default holds — which is the rule CLAUDE.md states outright
("No schema-version-bump ceremony — new fields = `#[serde(default)]`"). A
`PostRestore` frame without `grant_envelope`, an endpoint config without
`resolver`, a volume catalog without `kind`, a runtime volume without
`read_only`: all of these are the mandated pattern, described in their own
comments as compatibility shims. Deleting them would mean making the fields
required — adding ceremony the rule exists to prevent, and breaking on-disk
state for nothing.

Two more were mislabelled in a different way. `VmBackend::start` is a
default-argument convenience whose own comment already concedes `Detached` "is
the right default"; `TERMINATOR_PORT_BASE` is a stable numbering that live
endpoint metadata refers to, so moving it would move live endpoints.

Those eight are unchanged in behaviour. Their comments are corrected to say
what they are, because a comment calling policy "back-compat" is what made them
look like debt in the first place — and the next sweep would flag them again.

## What was genuinely legacy

**`TemplateRevision::role` / `TemplateSpec::role` / `TemplateVariant::role`.**
The doc said the field was "preserved for forward-/backward-compat with on-disk
revision JSON, but it no longer participates in build identity" —
`cache_key()` already excluded it. A dead field kept only to decode old JSON.
Gone, along with `role_does_not_affect_cache_key`, whose premise it was. None
of the three structs sets `deny_unknown_fields`, so a revision JSON that still
carries `role` parses and ignores it.

**`template_cmd::init`'s `local: bool`.** Both callers passed `true`, and the
body's only use was to `bail!` that "non-local init was a `mvmctl template init
--vm` mode that no longer exists". A parameter guarding a mode that is gone.

## Gates

`fmt --all`, `clippy --workspace --all-targets` (zero warnings),
`nextest --workspace` against an empty `MVM_HOME` (12,237 pass),
`xtask check-all` (61 gates), `just check-gated`.

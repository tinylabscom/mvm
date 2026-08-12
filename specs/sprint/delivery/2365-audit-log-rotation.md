# Audit-log rotation

The chain-signed audit log grew without bound; a full walk measured 122 ms over
4,022 entries (30.3 µs/entry, release, real log) and nothing capped it. The
chain now rotates into sequenced segments at 4 MiB. Rotation is an authenticated
handoff rather than a truncation: the retiring segment ends with a signed
`chain.sealed` record and the fresh one opens with a signed `chain.continued`
naming its predecessor and that predecessor's final chain hash, both inside the
signed body, so a forged handoff costs the signing key. `verify_segment_set`
reports a removed segment by number instead of letting the survivors read as
the whole history; `mvmctl doctor` checks the live segment plus the handoffs and
says so, while `mvmctl trust audit verify` walks every retired interior.
Retention is keep-everything by maintainer decision—rotation only splits;
deletion stays an explicit operator action. ADR-001 rows 8 and 14 are amended.

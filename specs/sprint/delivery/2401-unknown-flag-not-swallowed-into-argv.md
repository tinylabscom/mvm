# An unknown flag is named, not shipped to the guest

`machine run`, `machine exec`, and `exec` declared their trailing argv with
`allow_hyphen_values`, so clap stopped flag parsing at the first unrecognized
`--flag` and collected it — and the `--` separator behind it — as guest argv.
A typo boots a VM and dies in the guest shell with `exec: illegal option --`,
naming the separator the caller wrote correctly instead of the flag they got
wrong.

Dropping `allow_hyphen_values` from the four trailing-argv positionals makes
clap refuse the unknown flag by name before admission. Hyphenated argv after
`--` is unaffected — the escape already makes the rest of the line literal —
and the parser tests lock both halves: `--nonexistent` is an
`UnknownArgument`, `-- uname -a --all` is still three argv elements. The
network-transport test that asserted a stray `--network-mode` lands in argv now
asserts it is refused; the property it guards (the flag configures nothing) is
strictly better served.

`mvm-cli` + `mvmctl` suites (1931 tests), formatting, and `mvm-cli`
all-target Clippy pass.

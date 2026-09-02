Feature: Documented examples work

  Every `mvmctl` command printed in the README or the website docs is a promise
  to a reader who will paste it into a shell. This suite turns each one into a
  checked assertion, at one of three tiers:

    parse  the real clap tree parses the invocation, with full argument
           validation — a removed verb, renamed flag, bad value or wrong arity
           fails here, on every PR, with no VM and no network.
    exec   additionally executed for real against an isolated MVM_HOME.
    live   additionally boots a real microVM; see the @live scenarios.

  `features/suites/s29_doc_examples/tiers.toml` assigns the tier per command
  path. The assignment is total: a documented path with no entry fails the
  coverage scenario by name, so a newly documented verb cannot ship without
  someone deciding how it is proven.

  Scenario: every documented example parses against the real CLI
    Then every documented mvmctl example parses against the real CLI

  Scenario: every documented command path carries a verification tier
    Then every documented command path carries a verification tier

  # The weakest tier is the one an example reaches by nobody deciding
  # anything, so left alone it grows: 61 -> 65 during a single week of
  # unrelated documentation work. The count may fall freely; raising it
  # means editing the pin and saying why.
  Scenario: the parse tier does not grow
    Then no more command paths sit at the parse tier than the pinned count

  Scenario: the tier manifest cannot drift into fiction
    Then the tier manifest names only real CLI commands

  Scenario: no documented command is stranded outside a code fence
    # A fence closed one block early strands real commands in the prose: they
    # render as broken Markdown and vanish from extraction at the same time.
    Then no documented command is stranded outside a code fence

  Scenario: side-effect-free documented examples actually run
    Then every side-effect-free documented example executes successfully

  Scenario: placeholder templates still name real commands
    # A template is exempt from parsing. Its verb prefix is not, or writing
    # `<placeholders>` would be a way to document a command that never existed.
    Then every documented placeholder template names a real or declared command

  Scenario: nothing declared planned has quietly shipped
    Then no command declared planned has quietly shipped

  # The README is adjudicated per example. The website is 461 commands across 86
  # files, so it is ratcheted instead: coverage is computed by the same rule and
  # the partition is checked in, so a covered command cannot quietly become
  # uncovered and a newly documented one must be classified before it merges.
  Scenario: documented website commands do not lose their coverage
    Then documented website commands do not lose their coverage

  Scenario: every live-tier command has a live witness
    # A `live` tier says a real guest runs this command. Without a scenario
    # that does, the tier is a claim rather than evidence.
    Then every live-tier command is exercised by a live scenario

  Scenario: every command named in a table or a sentence exists
    # The CLI reference documents most of its surface in tables, as inline code
    # rather than fenced blocks. A stale spelling there reaches a reader
    # exactly like a stale one in a code block.
    Then every command named in the docs prose exists

  Scenario: Rust examples that skip compiling say why
    # `rust,ignore` is the only way a Rust example escapes the compiler, so an
    # unexplained opt-out is exactly how a wrong example survives.
    Then every Rust example that opts out of compiling says why

  Scenario: documented TOML and JSON parses
    Then every documented TOML and JSON block parses

  Scenario: documented Python examples name real SDK symbols
    # The Rust examples get a compiler. This is the nearest equivalent for
    # Python: parse the snippet, then resolve every `mvm.<name>` it uses
    # against the real installed SDK.
    Then every documented Python example parses and names real SDK symbols

  @node
  Scenario: documented TypeScript examples name real SDK exports
    # Resolved from the SDK's `src/` export graph, not from a built `dist/`:
    # `dist/` is absent in a fresh worktree, and depending on it would fail
    # this gate for a reason that has nothing to do with the docs.
    Then every documented TypeScript example names real SDK exports

  Scenario: documented mkGuest calls name real attributes
    # Read from `nix/lib/mk-guest.nix`'s argument set rather than evaluated:
    # the hermetic lane has no `nix` binary, and the header is a flat
    # attribute list that does not need one.
    Then every documented mkGuest call names real attributes

  @node
  Scenario: documented TypeScript examples typecheck against the local SDK
    # The Rust examples get a compiler; this is the same for TypeScript.
    # `@runmvm/mvm` is mapped to this checkout's `src/index.ts`, so the docs
    # are checked against the SDK in this tree, not the published one. Skips
    # loudly when the SDK dev toolchain is absent.
    Then every documented TypeScript example typechecks against the local SDK

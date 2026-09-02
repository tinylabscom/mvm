Feature: mvmctl's own output names real commands

  The documentation harness reads Markdown. It cannot see the other place a
  reader is told what to run: mvmctl's own strings — hints, error messages,
  "Run with:" lines. Those drift exactly like docs do, and until this scenario
  existed nothing checked them, so `mvmctl bundle install` finished by printing
  `launch with: mvmctl up --manifest <sha>` long after `up` stopped being a
  dispatched verb. A reader who followed it got "unrecognized subcommand".

  Only the leading verb chain is judged; trailing words are arguments. A phrase
  that is English rather than an invocation is declared in tiers.toml with a
  reason, so the check stays total: a `mvmctl …` string either resolves against
  the real clap tree or is written down.

  Scenario: no CLI message names a command that does not exist
    Then every command named in mvmctl's own output is a real command
